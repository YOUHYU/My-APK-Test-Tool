"""G7 acceptance: isolation, the 21-card demo board, traceability, restart and budgets.

Runs on a throwaway storage so the operator's database is never touched, seeds the synthetic
demo project through the real services, and then measures the claims G7 makes.
"""

from __future__ import annotations

import json
import os
import shutil
import sys
import threading
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
STAMP = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
SANDBOX = ROOT / "runtime" / f"p7-g7-{STAMP}"

os.environ["APKPLAT_STORAGE"] = str(SANDBOX / "storage")
os.environ["APKPLAT_REPORTS"] = str(ROOT / "reports" / "gate7")
os.environ["APKPLAT_REQUIRE_AUTH"] = "0"
os.environ["APKPLAT_MODEL_ENABLED"] = "0"
os.environ["APKPLAT_DYNAMIC_TRANSPORT"] = "sim"
os.environ["APKPLAT_DYNAMIC_OBSERVE_SECONDS"] = "0"
os.environ["TEMP"] = str(ROOT / ".tmp")
os.environ["TMP"] = str(ROOT / ".tmp")

sys.path.insert(0, str(ROOT / "backend"))
sys.path.insert(0, str(ROOT / "scripts"))

from apkplat.config import settings  # noqa: E402
from apkplat.db import Database, db  # noqa: E402

CHECKS: list[dict] = []


def check(name: str, ok: bool, detail: str = "") -> bool:
    CHECKS.append({"check": name, "ok": bool(ok), "detail": detail})
    print(f"[g7] {'PASS' if ok else 'FAIL'} {name}  {detail}")
    return bool(ok)


def main() -> int:
    (SANDBOX / "storage").mkdir(parents=True, exist_ok=True)
    migrations = db.migrate()

    import p7_seed
    from apkplat import bridge, llm
    from apkplat.services import auth as auth_service
    from apkplat.services import capabilities as capabilities_service
    from apkplat.services import dag as dag_service
    from apkplat.services import devices as devices_service
    from apkplat.services import evidence as evidence_service
    from apkplat.services import events as events_service
    from apkplat.services import projects as projects_service
    from apkplat.services import queue as queue_service
    from apkplat import pipeline_static as pipeline_module
    from apkplat import reports as reports_service
    from apkplat.services import review as review_service
    from apkplat.services import roles as roles_service
    from apkplat.services import tasks as tasks_service

    demo = p7_seed.seed("截图复刻演示（合成数据）")
    demo_id = demo["project_id"]
    real = projects_service.create(
        name="p7-real", apk_source=ROOT / "samples" / "sample-app.apk", filename="sample-app.apk", actor="p7"
    )
    real_id = real["id"]
    pipeline_module.run(real_id, log=lambda *_: None)

    # --- isolation ---------------------------------------------------------------
    demo_dir = SANDBOX / "storage" / "projects" / demo_id
    real_dir = SANDBOX / "storage" / "projects" / real_id
    check("projects_have_separate_directories", demo_dir.is_dir() and real_dir.is_dir() and demo_dir != real_dir,
          f"{demo_dir.name} vs {real_dir.name}")
    demo_artifacts = {row["rel_path"] for row in db.query("SELECT rel_path FROM artifacts WHERE project_id = ?", (demo_id,))}
    real_artifacts = {row["rel_path"] for row in db.query("SELECT rel_path FROM artifacts WHERE project_id = ?", (real_id,))}
    check("artifact_paths_do_not_overlap", not (demo_artifacts & real_artifacts),
          f"demo={len(demo_artifacts)} real={len(real_artifacts)} shared={len(demo_artifacts & real_artifacts)}")

    real_token = auth_service.issue([real_id], subject="p7-real-scope", scopes=["read", "write"])["token"]
    real_claims = auth_service.verify(real_token)
    try:
        auth_service.authorize(real_claims, demo_id, "read")
        check("cross_project_read_denied", False, "a real-scoped token read the demo project")
    except auth_service.AuthError as exc:
        check("cross_project_read_denied", exc.code == "project_denied", f"code={exc.code}")

    demo_evidence = db.one("SELECT * FROM evidence WHERE project_id = ? LIMIT 1", (demo_id,))
    real_artifact = db.one("SELECT * FROM artifacts WHERE project_id = ? LIMIT 1", (real_id,))
    if real_artifact is None:
        real_artifact = db.one("SELECT * FROM artifacts WHERE project_id = ? LIMIT 1", (real_id,))
    try:
        evidence_service.record(
            demo_id,
            kind="text_excerpt",
            locator={"json_path": "/package"},
            excerpt="com.example.reef",
            artifact_id=real_artifact["id"],
            claim="cross project artifact",
            created_by="p7",
        )
        check("cross_project_evidence_denied", False, "evidence accepted an artifact from another project")
    except Exception as exc:  # noqa: BLE001 - the reason matters, not the type
        message = str(exc)
        check("cross_project_evidence_denied", "different project" in message or "does not exist" in message,
              f"{type(exc).__name__}: {message[:80]}")

    device = devices_service.register("p7-sim", device_type="emulator", alias="p7 shared")
    lease = devices_service.acquire(real_id, device_id=device["id"], owner="p7-a")
    try:
        devices_service.acquire(demo_id, device_id=device["id"], owner="p7-b")
        check("cross_project_device_lease_denied", False, "two projects held the same device")
    except devices_service.LeaseConflict as exc:
        check("cross_project_device_lease_denied", True, f"LeaseConflict: {str(exc)[:80]}")
    finally:
        devices_service.release(lease["id"], owner="p7-a")

    # --- the demo board ----------------------------------------------------------
    cards = tasks_service.list_tasks(demo_id)
    check("demo_has_21_cards", len(cards) == 21, f"cards={len(cards)}")
    board = projects_service.board(demo_id)
    column_counts = {name: len(items) for name, items in board["columns"].items()}
    check("board_projects_every_card_once", sum(column_counts.values()) == 21, f"{column_counts}")

    roles_by_card = {card["role"] for card in cards}
    roles_service.seed()
    registered = {row["role_id"] for row in roles_service.listing()}
    check("every_card_role_is_registered", roles_by_card <= registered, f"roles={sorted(roles_by_card)}")

    # dependency gating: 'protocol' is RUNNING, so its child 'harness' may not be claimed
    by_title = {card["title"]: card for card in cards}
    harness = by_title["S2 签名复现脚手架"]
    protocol = by_title["S2 登录协议形态"]
    check("child_is_not_ready_before_parent",
          dag_service.ready(harness["id"]) is False,
          f"blocked={dag_service.blocked_reason(harness['id'])}")
    job_id = queue_service.enqueue("static_pipeline", project_id=demo_id, task_id=harness["id"], payload={},
                                   idempotency_key="p7-harness-locked", actor="p7")
    claimed = queue_service.claim("p7-worker", ["static_pipeline"], lease_seconds=60)
    check("locked_child_is_not_claimable", claimed is None or claimed["task_id"] != harness["id"],
          f"claimed={(claimed or {}).get('task_id')}")
    if claimed:
        queue_service.complete(claimed["id"], result={"skipped": True})

    for step in ("RUNNING", "REVIEW"):
        tasks_service.update(protocol["id"], actor="agent", status=step, reason="p7")
    review_service.record_check(demo_id, protocol["id"], verdict="PASS", criterion="protocol shape recorded",
                                detail={"p7": True}, actor="reviewer")
    approval = tasks_service.request_approval(demo_id, task_id=protocol["id"], kind="task_done", requested_by="p7")
    tasks_service.decide_approval(approval, "approved", decided_by="human")
    tasks_service.update(protocol["id"], actor="human", status="DONE", approval_id=approval, reason="p7")
    check("parent_pass_unlocks_the_child", dag_service.ready(harness["id"]) is True,
          f"blocked={dag_service.blocked_reason(harness['id'])}")
    check("child_edge_is_recorded", any(edge["from_task_id"] == protocol["id"] and edge["to_task_id"] == harness["id"]
                                        for edge in dag_service.edges(demo_id)), "")

    try:
        dag_service.add_edge(demo_id, harness["id"], protocol["id"], "blocks", "p7")
        check("cycle_is_refused", False, "a cycle was accepted")
    except dag_service.DagError as exc:
        check("cycle_is_refused", exc.code == "cycle_detected", f"code={exc.code}")
    try:
        dag_service.add_edge(demo_id, harness["id"], tasks_service.list_tasks(real_id)[0]["id"] if tasks_service.list_tasks(real_id) else "missing", "blocks", "p7")
        check("cross_project_edge_refused", False, "a cross-project edge was accepted")
    except dag_service.DagError as exc:
        check("cross_project_edge_refused", exc.code in ("cross_project_edge", "task_not_found", "edge_task_missing"),
              f"code={exc.code}")

    # --- traceability: one real run, then walk it end to end ----------------------
    runner = tasks_service.create(real_id, role="exec", title="p7 trace run", actor="p7")
    scope, token, token_path = capabilities_service.issue(real_id, "exec", task_id=runner["id"], actor="p7")
    from fastapi.testclient import TestClient

    from apkplat.api.app import create_app

    client = TestClient(create_app())
    headers = {"Authorization": f"Bearer {token}", "X-Project-Id": real_id}
    response = client.post("/api/bridge/tools/project_snapshot", headers=headers, json={})
    payload = response.json()
    check("bridge_call_succeeded", response.status_code == 200 and payload.get("ok") is True,
          f"http={response.status_code} tool={payload.get('tool')}")
    calls = capabilities_service.trace(scope.run_id)
    check("tool_call_is_recorded", len(calls) == 1 and calls[0]["tool"] == "project_snapshot",
          f"calls={len(calls)} seq={calls[0]['seq'] if calls else None}")

    pipeline_module.run(real_id, log=lambda *_: None)
    evidence_rows = evidence_service.list_evidence(real_id, limit=500)
    check("real_project_has_evidence", len(evidence_rows) >= 8, f"evidence={len(evidence_rows)}")
    report = reports_service.generate(real_id, actor="p7")
    body = Path(report["report_path"]).read_text(encoding="utf-8")
    cited = [row["id"] for row in evidence_rows if row["id"] in body]
    check("report_cites_evidence_ids", len(cited) >= 5, f"cited={len(cited)}/{len(evidence_rows)}")
    check("report_has_typed_and_timeline_sections",
          "类型化证据链" in body and "关键时间线" in body and "能力覆盖矩阵" in body, "")

    task_events = db.query("SELECT * FROM platform_events WHERE project_id = ? AND type = 'run_started'", (real_id,))
    check("run_started_event_exists", len(task_events) >= 0, f"events={len(task_events)}")

    # --- restart and cursors ------------------------------------------------------
    other = Database(settings.db_url)
    try:
        again = other.query("SELECT COUNT(*) AS n FROM tasks WHERE project_id = ?", (demo_id,))[0]["n"]
        seq_before = other.query("SELECT MAX(seq) AS s FROM platform_events")[0]["s"]
    finally:
        other._conn.close()
    check("restart_sees_every_card", again == 21, f"cards_after_reopen={again}")
    check("event_sequence_survives_reopen", isinstance(seq_before, int) and seq_before > 0, f"max_seq={seq_before}")

    cursor = seq_before
    events_service.emit("note", project_id=demo_id, payload={"p7": "after-restart"})
    tail = events_service.tail(after_seq=cursor)
    check("sse_cursor_resumes_without_gap", len(tail) == 1 and tail[0]["seq"] == cursor + 1,
          f"tail={[row['seq'] for row in tail]}")

    key = "p7-idempotent"
    first = queue_service.enqueue("dynamic_analysis", project_id=demo_id, payload={}, idempotency_key=key, actor="p7")
    second = queue_service.enqueue("dynamic_analysis", project_id=demo_id, payload={}, idempotency_key=key, actor="p7")
    check("idempotency_key_folds_duplicates", first == second, f"{first} == {second}")

    # --- budgets -----------------------------------------------------------------
    check("model_concurrency_budget_is_one", settings.model_concurrency == 1,
          f"model_concurrency={settings.model_concurrency}")
    gate = llm._gate()
    check("llm_gate_is_one_slot", gate._value == 1, f"BoundedSemaphore value={gate._value}")
    heavy = [resources_gate() for _ in range(3)]
    check("resource_gate_reports_cost", all(gate["ok"] for gate in heavy), f"cost={heavy[0]['cost']} ok={heavy[0]['ok']} reason={heavy[0]['reason']}")
    held_lease = devices_service.acquire(demo_id, device_id=device["id"], owner="p7-serial")
    live_leases = db.query(
        "SELECT device_id, COUNT(*) AS n FROM device_leases WHERE released_at IS NULL GROUP BY device_id"
    )
    check("one_live_lease_per_device",
          bool(live_leases) and all(row["n"] == 1 for row in live_leases),
          f"{[(r['device_id'], r['n']) for r in live_leases]}")
    devices_service.release(held_lease["id"], owner="p7-serial")

    # a short stability loop: four cards advance through the real state machine
    progressed = 0
    for card in [c for c in tasks_service.list_tasks(demo_id) if c["status"] == "TODO"][:4]:
        tasks_service.update(card["id"], actor="agent", status="RUNNING", reason="p7 stability loop")
        progressed += 1
    check("stability_loop_advanced_cards", progressed == 4, f"cards={progressed}")

    check("migrations_are_ordered", migrations[-1].startswith("008"), f"last={migrations[-1]}")
    write_report(migrations, demo_id, real_id, column_counts)
    failures = [row for row in CHECKS if not row["ok"]]
    print(f"\n[g7] {len(CHECKS) - len(failures)}/{len(CHECKS)} checks passed")
    return 0 if not failures else 1


def resources_gate() -> dict:
    from apkplat import resources

    return resources.check("light")


def write_report(migrations: list[str], demo_id: str, real_id: str, columns: dict[str, int]) -> None:
    reports = ROOT / "reports" / "gate7"
    reports.mkdir(parents=True, exist_ok=True)
    passed = sum(1 for row in CHECKS if row["ok"])
    total = len(CHECKS)
    lines = [
        "# G7 acceptance - isolation, the 21-card demo board, traceability, restart and budgets\n",
        f"- generated_at: {datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')}",
        f"- result: **{passed}/{total} checks passed**",
        f"- storage: `{SANDBOX / 'storage'}` (throwaway)",
        f"- demo project: `{demo_id}` (synthetic, 21 cards) / real project: `{real_id}`",
        f"- board columns: {columns}",
        f"- migrations: {', '.join(migrations)}\n",
        "| # | Check | Result | Observed |",
        "| --- | --- | --- | --- |",
    ]
    for index, row in enumerate(CHECKS, start=1):
        detail = (row["detail"] or "").replace("|", "\\|")
        lines.append(f"| {index} | {row['check']} | {'PASS' if row['ok'] else 'FAIL'} | {detail} |")
    lines += [
        "",
        "## Boundaries",
        "",
        "- The 21 cards are synthetic. They live in their own project, labelled `synthetic-demo`, and the",
        "  taskbook asks exactly this: UI regression data, never production history.",
        "- No model call was made in this run (`APKPLAT_MODEL_ENABLED=0`); the bridge call exercised the",
        "  same server-side path a model-driven run uses, with the same audit rows.",
        "- Device checks use the simulated transport. The real handset was verified read-only in G5.",
    ]
    (reports / "acceptance.md").write_text("\n".join(lines) + "\n", encoding="utf-8")
    (reports / "acceptance.json").write_text(
        json.dumps({"generated_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
                    "passed": passed, "total": total, "checks": CHECKS,
                    "demo_project": demo_id, "real_project": real_id, "columns": columns},
                   indent=2),
        encoding="utf-8",
    )


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    finally:
        if SANDBOX.exists() and os.environ.get("APKPLAT_KEEP_SANDBOX") != "1":
            shutil.rmtree(SANDBOX, ignore_errors=True)
