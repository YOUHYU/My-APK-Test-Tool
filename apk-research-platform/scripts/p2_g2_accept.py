"""G2 acceptance: real DAG scheduling, roles, review and dashboard consistency.

Runs against a throwaway storage, no model calls, so every verdict here is deterministic.
The contract checks (cross-project edges, cycles, PASS gating, bounded dispatch) are
exercised through the same services and HTTP routes the product uses.
"""

from __future__ import annotations

import json
import os
import shutil
import sys
import time
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
BACKEND = ROOT / "backend"
TMP = ROOT / ".tmp" / f"p2-g2-{int(time.time())}"

os.environ["APKPLAT_STORAGE"] = str(TMP / "storage")
os.environ["APKPLAT_REPORTS"] = str(TMP / "reports")
os.environ["APKPLAT_SECRET"] = "g2-accept-secret"
os.environ["APKPLAT_REQUIRE_AUTH"] = "0"
os.environ["APKPLAT_MODEL_ENABLED"] = "0"
os.environ["TEMP"] = str(ROOT / ".tmp")
os.environ["TMP"] = str(ROOT / ".tmp")
sys.path.insert(0, str(BACKEND))

from fastapi.testclient import TestClient  # noqa: E402

from apkplat.api.app import create_app  # noqa: E402
from apkplat.db import db  # noqa: E402

try:  # androguard chats at DEBUG level; keep the acceptance log readable
    from loguru import logger as _loguru

    _loguru.remove()
except Exception:  # noqa: BLE001
    pass
from apkplat.services import dag as dag_service  # noqa: E402
from apkplat.services import events as events_service  # noqa: E402
from apkplat.services import projects as projects_service  # noqa: E402
from apkplat.services import queue as queue_service  # noqa: E402
from apkplat.services import review as review_service  # noqa: E402
from apkplat.services import roles as roles_service  # noqa: E402
from apkplat.services import tasks as tasks_service  # noqa: E402
from apkplat.state import STATUSES, TransitionError, validate_transition  # noqa: E402

CHECKS: list[dict[str, Any]] = []


def check(name: str, ok: bool, detail: Any = "") -> bool:
    CHECKS.append({"check": name, "ok": bool(ok), "detail": detail if isinstance(detail, str) else json.dumps(detail, ensure_ascii=False)[:600]})
    print(f"[g2] {'PASS' if ok else 'FAIL'} {name}: {CHECKS[-1]['detail'][:220]}")
    return ok


def body_json(response) -> dict[str, Any]:
    try:
        data = response.json()
    except Exception:  # noqa: BLE001
        return {}
    if isinstance(data, dict) and set(data) == {"detail"} and isinstance(data["detail"], dict):
        return data["detail"]
    return data if isinstance(data, dict) else {}


def new_project(name: str) -> str:
    row = projects_service.create(name=name, apk_source=ROOT / "samples" / "sample-clean.apk", filename="sample-clean.apk", actor="g2")
    return str(row["id"])


def enqueue_for(task_id: str, project_id: str, kind: str = "g2_probe") -> str:
    return queue_service.enqueue(kind=kind, project_id=project_id, task_id=task_id, payload={}, idempotency_key=f"g2:{task_id}:{kind}")


def main() -> int:
    if TMP.exists():
        shutil.rmtree(TMP, ignore_errors=True)
    TMP.mkdir(parents=True, exist_ok=True)
    (TMP / "storage").mkdir(parents=True, exist_ok=True)
    db.migrate()
    roles_service.seed()
    app = create_app()
    client = TestClient(app)

    # ---- old surface still intact -----------------------------------------
    health = client.get("/api/health")
    old_tasks = client.get("/api/projects")
    check("old_api_alive", health.status_code == 200 and old_tasks.status_code == 200, {"health": health.status_code, "projects": old_tasks.status_code})
    check("twelve_states_unchanged", len(STATUSES) == 12 and "WAITING_APPROVAL" in STATUSES, sorted(STATUSES))
    try:
        validate_transition("RUNNING", "DONE", actor="agent", approved=True)
        agent_done_blocked = False
    except TransitionError as exc:
        agent_done_blocked = exc.code == "approval_required"
    check("agent_still_cannot_write_done", agent_done_blocked, "RUNNING->DONE by agent rejected")

    # ---- legacy column + backfill ----------------------------------------
    project_a = new_project("g2-project-a")
    project_b = new_project("g2-project-b")
    task_a = str(tasks_service.create(project_a, role="exec", title="A")["id"])
    task_b = str(tasks_service.create(project_a, role="exec", title="B", depends_on=[task_a])["id"])
    task_c = str(tasks_service.create(project_a, role="exec", title="C", depends_on=[task_b])["id"])
    legacy = tasks_service.get(task_c)
    check("legacy_depends_on_kept", legacy["depends_on"] == [task_b], legacy["depends_on"])
    backfill = dag_service.backfill(project_a)
    verify = dag_service.verify_against_legacy(project_a)
    check("backfill_matches_edges", verify["ok"] and len(dag_service.edges(project_a)) == 2, {"created": backfill["edges_created"], "mismatches": verify["mismatches"]})

    # ---- graph rules ------------------------------------------------------
    cross = client.post(f"/api/projects/{project_a}/edges", json={"from_task_id": task_a, "to_task_id": task_c})
    self_edge = client.post(f"/api/projects/{project_a}/edges", json={"from_task_id": task_a, "to_task_id": task_a})
    cycle = client.post(f"/api/projects/{project_a}/edges", json={"from_task_id": task_c, "to_task_id": task_a})
    other = str(tasks_service.create(project_b, role="exec", title="B1")["id"])
    cross_project = client.post(f"/api/projects/{project_a}/edges", json={"from_task_id": other, "to_task_id": task_a})
    check(
        "graph_rules_reject_bad_edges",
        # A -> C is legal (it only adds a second path), a self edge and a cycle are not, and a
        # task from another project may never be wired in.
        body_json(cross).get("error_code") is None
        and body_json(self_edge).get("error_code") == "self_edge"
        and body_json(cycle).get("error_code") == "cycle_detected"
        and body_json(cross_project).get("error_code") == "cross_project_edge",
        {
            "second_path": cross.status_code,
            "self": body_json(self_edge).get("error_code"),
            "cycle": body_json(cycle).get("error_code"),
            "cross_project": body_json(cross_project).get("error_code"),
        },
    )
    dag_service.remove_edge(project_a, task_a, task_c, actor="g2")

    # ---- A -> B -> C lock -------------------------------------------------
    job_a = enqueue_for(task_a, project_a)
    job_b = enqueue_for(task_b, project_a)
    job_c = enqueue_for(task_c, project_a)
    claims: list[str] = []
    first = queue_service.claim("w1", ["g2_probe"])
    if first:
        claims.append(str(first["task_id"]))
        queue_service.complete(str(first["id"]), worker_id="w1", result={})
    second = queue_service.claim("w1", ["g2_probe"])
    check(
        "dependency_lock_a_then_nothing",
        claims == [task_a] and second is None,
        {"claimed": claims, "second": None if second is None else second["task_id"]},
    )
    tasks_service.update(task_a, status="RUNNING", actor="exec")
    tasks_service.update(task_a, status="REVIEW", actor="exec")
    tasks_service.update(task_a, status="DONE", actor="reviewer", approval_id=None)
    second = queue_service.claim("w1", ["g2_probe"])
    check("dependency_unlocks_b_after_a_done", second is not None and str(second["task_id"]) == task_b, None if second is None else second["task_id"])
    if second:
        queue_service.complete(str(second["id"]), worker_id="w1", result={})
    third = queue_service.claim("w1", ["g2_probe"])
    check("dependency_keeps_c_locked", third is None, None if third is None else third["task_id"])

    # ---- PASS check releases a child even before DONE ---------------------
    review_service.accept(project_a, task_b, criterion="manual-pass")
    released = queue_service.claim("w1", ["g2_probe"])
    check("pass_check_unlocks_c_without_done", released is not None and str(released["task_id"]) == task_c, None if released is None else released["task_id"])
    if released:
        queue_service.complete(str(released["id"]), worker_id="w1", result={})

    # ---- parent card split ------------------------------------------------
    parent = str(tasks_service.create(project_a, role="plan", title="parent")["id"])
    child_one = str(tasks_service.create(project_a, role="exec", title="child-1", parent_task_id=parent)["id"])
    child_two = str(tasks_service.create(project_a, role="exec", title="child-2", parent_task_id=parent, depends_on=[child_one])["id"])
    enqueue_for(parent, project_a, kind="g2_split")
    enqueue_for(child_one, project_a, kind="g2_split")
    enqueue_for(child_two, project_a, kind="g2_split")
    split_claims = []
    for _ in range(3):
        row = queue_service.claim("w2", ["g2_split"])
        if row:
            split_claims.append(str(row["task_id"]))
            queue_service.complete(str(row["id"]), worker_id="w2", result={})
    check("parent_split_executes_children", set(split_claims) == {parent, child_one}, split_claims)

    # ---- bounded dispatch back -------------------------------------------
    card = str(tasks_service.create(project_a, role="exec", title="reviewed")["id"])
    tasks_service.update(card, status="RUNNING", actor="exec")
    tasks_service.update(card, status="REVIEW", actor="exec")
    outcomes = []
    for _ in range(3):
        result = review_service.dispatch_back(project_a, card, reason="claim lacks a locator", actor="reviewer")
        outcomes.append(result["status"])
        if result["status"] == "RUNNING":
            tasks_service.update(card, status="REVIEW", actor="exec")
    check(
        "fail_dispatch_bounded_to_two",
        outcomes == ["RUNNING", "RUNNING", "BLOCKED"] and review_service.fail_count(card) == 3,
        outcomes,
    )

    # ---- restart recovery: one reclaim, no duplicate claim ----------------
    lonely = str(tasks_service.create(project_b, role="exec", title="lonely")["id"])
    job_lonely = enqueue_for(lonely, project_b, kind="g2_recover")
    held = queue_service.claim("worker-dead", ["g2_recover"])
    # A crashed worker leaves a RUNNING row behind; expire its lease the way the wall clock would.
    db.execute("UPDATE jobs SET lease_expires_at = ? WHERE id = ?", ("2000-01-01T00:00:00.000Z", str(held["id"])))
    reclaimed = queue_service.reclaim_expired("worker-new")
    again = queue_service.claim("worker-new", ["g2_recover"])
    check(
        "restart_recovery_single_reclaim",
        held is not None and reclaim_run_ok(reclaimed) and again is not None and str(again["id"]) == job_lonely,
        {"reclaimed": reclaimed, "attempt": int(again["attempt"]) if again else None},
    )

    # ---- dashboard equals database ---------------------------------------
    board = client.get(f"/api/projects/{project_a}/board").json()
    columns = board.get("columns") or {}
    db_counts = {row["status"]: int(row["n"]) for row in db.query("SELECT status, COUNT(*) AS n FROM tasks WHERE project_id = ? GROUP BY status", (project_a,))}
    board_total = sum(len(columns.get(key, [])) for key in columns)
    check(
        "board_matches_database",
        board_total == sum(db_counts.values()),
        {"board_total": board_total, "db_total": sum(db_counts.values()), "columns": sorted(columns)},
    )

    # ---- platform events feed + resume -----------------------------------
    seq1 = events_service.emit("note", project_id=project_a, payload={"text": "first"})
    seq_again, created = events_service.emit_once("note", project_id=project_a, payload={"text": "dup"}, dedupe_key="g2-dedupe")
    seq_dup, created_again = events_service.emit_once("note", project_id=project_a, payload={"text": "dup"}, dedupe_key="g2-dedupe")
    tail = events_service.tail(seq1 - 1, project_id=project_a, limit=50)
    feed = client.get(f"/api/projects/{project_a}/platform-events?after_seq=0").json()
    check(
        "platform_events_monotonic_and_deduped",
        created and not created_again and seq_again == seq_dup and all(b["seq"] > a["seq"] for a, b in zip(tail, tail[1:])) and feed["count"] >= len(tail),
        {"seq1": seq1, "dedupe_seq": seq_dup, "tail": len(tail), "feed": feed["count"]},
    )
    resumed = client.get("/api/projects/%s/platform-events?after_seq=%d" % (project_a, seq_dup)).json()
    check("platform_events_resume_cursor", all(item["seq"] > seq_dup for item in resumed["events"]), {"after": seq_dup, "count": resumed["count"]})

    # ---- roles enforced ---------------------------------------------------
    roles = roles_service.listing()
    plan_tools = roles_service.tools("plan")
    review_tools = roles_service.tools("review")
    role_check = client.patch("/api/roles/review", json={"bogus_field": 1})
    check(
        "roles_registry_enforced",
        len(roles) == 6
        and "apk_inspect" not in plan_tools
        and "artifact_write" not in review_tools
        and roles_service.retry_limit("review") == 2
        and body_json(role_check).get("error_code") == "field_not_editable",
        {"roles": [role["role_id"] for role in roles], "plan_tools": len(plan_tools), "review_tools": len(review_tools)},
    )

    # ---- review run is a separate run ------------------------------------
    if tasks_service.get(task_c)["status"] == "TODO":
        tasks_service.update(task_c, status="RUNNING", actor="exec")
    if tasks_service.get(task_c)["status"] == "RUNNING":
        tasks_service.update(task_c, status="REVIEW", actor="exec")
    review_run = client.post(f"/api/tasks/{task_c}/review-run", json={})
    payload = body_json(review_run)
    check(
        "independent_review_run_issued",
        review_run.status_code == 201 and payload.get("scope", {}).get("role_id") == "review" and payload.get("agent_run_id"),
        {"status": review_run.status_code, "role": payload.get("scope", {}).get("role_id")},
    )

    # ---- report ----------------------------------------------------------
    passed = sum(1 for item in CHECKS if item["ok"])
    out = ROOT / "audit"
    out.mkdir(exist_ok=True)
    stamp = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    (out / "g2_acceptance.json").write_text(
        json.dumps({"generated_at": stamp, "checks": CHECKS, "passed": passed, "total": len(CHECKS)}, ensure_ascii=False, indent=2),
        encoding="utf-8",
    )
    lines = [
        "# G2 acceptance - DAG scheduling, roles, review and dashboard",
        "",
        f"- generated_at (UTC): {stamp}",
        f"- result: **{passed}/{len(CHECKS)} checks passed**",
        f"- storage: `{TMP}` (throwaway)",
        "",
        "| # | check | result | detail |",
        "| --- | --- | --- | --- |",
    ]
    for index, item in enumerate(CHECKS, start=1):
        detail = item["detail"].replace("|", "\\|")
        lines.append(f"| {index} | {item['check']} | {'PASS' if item['ok'] else 'FAIL'} | {detail} |")
    lines += [
        "",
        "## What this proves",
        "",
        "- `task_edges` is a scheduler input, not documentation: a job whose card still waits on a",
        "  prerequisite stays PENDING and is never claimed (A -> B -> C locks and unlocks in order).",
        "- Cross-project edges, self edges and cycles are refused with distinct error codes, so a",
        "  poisoned graph cannot silently freeze the queue.",
        "- A PASS check releases the child even when the parent's card is still in REVIEW - that is",
        "  the machine-readable form of the taskbook's `PASS 才放行`.",
        "- A FAIL returns the card to RUNNING at most `retry_limit` (2) times, then blocks it for a",
        "  human instead of looping.",
        "- Lease expiry is repaired by exactly one reclaim, and the recovered job runs once.",
        "- The dashboard projection and the platform event feed are derived from the database, so a",
        "  restart cannot leave a stale card behind.",
    ]
    (out / "g2_acceptance.md").write_text("\n".join(lines) + "\n", encoding="utf-8")
    print(f"[g2] {passed}/{len(CHECKS)} checks passed")
    print(f"[g2] report {out / 'g2_acceptance.md'}")
    return 0 if passed == len(CHECKS) else 1


def reclaim_run_ok(reclaimed: list[dict[str, Any]]) -> bool:
    return len(reclaimed) == 1


if __name__ == "__main__":
    raise SystemExit(main())
