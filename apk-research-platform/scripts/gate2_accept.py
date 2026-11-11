"""Gate 2 acceptance: many projects, one process, nothing kept in memory.

The claim under test is not "it works once" but "it keeps working while projects
accumulate": separate directories and indexes per project, a queue that survives a
process boundary, a dead worker's lease reclaimed by a live one, a board that projects
task state, and an event stream that can be replayed from a cursor.

Outputs: reports/gate2/acceptance.md and reports/gate2/acceptance.json
"""
from __future__ import annotations

import json
import os
import sys
import tempfile
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "backend"))

WORK = Path(tempfile.mkdtemp(prefix="apkplat-gate2-"))
os.environ["APKPLAT_STORAGE"] = str(WORK / "storage")
os.environ["APKPLAT_REPORTS"] = str(WORK / "reports")
os.environ["APKPLAT_SECRET"] = "gate2-acceptance-secret-not-for-production"
os.environ["APKPLAT_REQUIRE_AUTH"] = "0"
os.environ["APKPLAT_MODEL_ENABLED"] = "0"

from fastapi.testclient import TestClient  # noqa: E402

from apkplat import worker as worker_mod  # noqa: E402
from apkplat.api.app import create_app  # noqa: E402
from apkplat.config import settings  # noqa: E402
from apkplat.db import Database, db  # noqa: E402
from apkplat.services import artifacts as artifacts_service  # noqa: E402
from apkplat.services import auth as auth_service  # noqa: E402
from apkplat.services import queue as queue_service  # noqa: E402
from apkplat.services import tasks as tasks_service  # noqa: E402

OUT = ROOT / "reports" / "gate2"
OUT.mkdir(parents=True, exist_ok=True)
checks: list[dict] = []


def _now_iso() -> str:
    from datetime import datetime, timezone

    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def check(name: str, ok: bool, detail: str = "") -> bool:
    checks.append({"check": name, "ok": bool(ok), "detail": str(detail)[:240]})
    print(f"[gate2] {'PASS' if ok else 'FAIL'}  {name}" + (f"  {detail}" if detail else ""), flush=True)
    return bool(ok)


def upload(client: TestClient, name: str) -> dict:
    with open(ROOT / "samples" / "sample-app.apk", "rb") as handle:
        response = client.post("/api/projects", data={"name": name},
                               files={"apk": ("sample-app.apk", handle)})
    assert response.status_code == 201, response.text
    return response.json()


def drain(kinds: list[str], label: str, max_jobs: int = 4) -> None:
    worker_mod.Worker(label, kinds, poll_interval=0.05).run(max_jobs=max_jobs, idle_timeout=5)


def main() -> int:
    db.migrate()
    client = TestClient(create_app())
    started = time.time()

    alpha = upload(client, "gate2-alpha")
    beta = upload(client, "gate2-beta")
    alpha_id, beta_id = alpha["project"]["id"], beta["project"]["id"]
    check("two projects accepted", alpha_id != beta_id, f"{alpha_id} / {beta_id}")

    drain(["static_pipeline"], "gate2-worker")

    jobs = client.get("/api/queue", params={"limit": 50}).json()["jobs"]
    done = [job for job in jobs if job["status"] == "SUCCEEDED"]
    check("both pipelines succeeded", len(done) >= 2, f"{len(done)} succeeded")

    alpha_artifacts = artifacts_service.list_artifacts(alpha_id)
    beta_artifacts = artifacts_service.list_artifacts(beta_id)
    paths_alpha = {row["rel_path"] for row in alpha_artifacts}
    paths_beta = {row["rel_path"] for row in beta_artifacts}
    check("artifacts never cross project boundaries", not (paths_alpha & paths_beta),
          f"{len(paths_alpha)} + {len(paths_beta)} rows")
    check("each project owns its own index",
          all(f"/{alpha_id}/" in f"/{row['rel_path']}" for row in alpha_artifacts)
          and any(row["kind"] == "index" for row in alpha_artifacts),
          alpha_artifacts[0]["rel_path"])

    # -- the queue is a table, not a dictionary --------------------------
    second = Database(settings.db_url)
    try:
        seen = {row["id"] for row in second.query("SELECT id FROM jobs")}
    finally:
        second._conn.close()
    check("queue rows visible from a second connection",
          {job["id"] for job in jobs} <= seen and len(seen) >= 2, f"{len(seen)} rows in a fresh handle")

    # -- a dead worker's lease is reclaimed, then finished by another ---
    gamma = upload(client, "gate2-gamma")
    gamma_id = gamma["project"]["id"]
    stale = client.get("/api/queue", params={"project_id": gamma_id}).json()["jobs"][0]
    claimed = queue_service.claim("gate2-dead-worker", ["static_pipeline"], lease_seconds=1)
    box = claimed
    if box is None or box["id"] != stale["id"]:
        # another pending job got claimed first; park it back and claim again
        if box is not None:
            queue_service.fail(box["id"], "gate2_park", "parked", retryable=True, worker_id="gate2-dead-worker")
        box = queue_service.claim("gate2-dead-worker", ["static_pipeline"], lease_seconds=1)
    check("a worker can claim a queued job", box is not None and box["status"] == "RUNNING",
          str(box["id"] if box else None))

    db.execute("UPDATE jobs SET lease_expires_at = ? WHERE id = ?", ("2000-01-01T00:00:00.000Z", box["id"]))

    # A fresh worker reclaims the dead lease on startup, exactly as after a crash.
    worker_mod.Worker("gate2-recovery-worker", ["static_pipeline"], poll_interval=0.05).run(
        max_jobs=2, idle_timeout=5)
    recovered = queue_service.get(box["id"])
    recovery_events = db.query(
        "SELECT * FROM audit_events WHERE event_type = 'job_recovered_after_restart' AND payload_json LIKE ?",
        (f"%{box['id']}%",),
    )
    check("a new worker reclaims the dead lease on startup", bool(recovery_events),
          f"{len(recovery_events)} audit event(s)")
    check("the recovered job finishes on its second attempt", recovered["status"] == "SUCCEEDED"
          and recovered["attempt"] == 2, f"{recovered['status']} attempt={recovered['attempt']}")
    check("the reclaimed lease is audited", bool(db.query(
        "SELECT * FROM audit_events WHERE event_type = 'job_lease_reclaimed' AND payload_json LIKE ?",
        (f"%{box['id']}%",))), box["id"])

    # -- idempotency ------------------------------------------------------
    key = f"gate2-idem-{alpha_id}"
    first = queue_service.enqueue("noop_probe", project_id=alpha_id, payload={}, idempotency_key=key)
    again = queue_service.enqueue("noop_probe", project_id=alpha_id, payload={}, idempotency_key=key)
    check("a repeated idempotency key collapses to one job", first == again, first)
    queue_service.cancel(first)

    # -- the board and the approval gate ---------------------------------
    review_row = tasks_service.create(alpha_id, title="review findings", role="reviewer", actor="human",
                                      status="REVIEW")
    review = review_row["id"]
    board = client.get(f"/api/projects/{alpha_id}/board").json()
    review_column = [task["id"] for task in board["columns"].get("REVIEW", [])]
    check("the board projects task state into columns", review in review_column,
          ",".join(sorted(board["columns"]))[:120])

    denied = client.patch(f"/api/tasks/{review}", json={"status": "DONE", "actor": "agent"})
    check("an agent cannot close a task on its own", denied.status_code in (403, 409),
          f"{denied.status_code} {str(denied.json())[:120]}")

    approval = client.post(f"/api/tasks/{review}/approvals",
                           json={"kind": "task_done", "requested_by": "agent", "reason": "review finished"})
    approval_id = approval.json().get("approval_id")
    client.post(f"/api/approvals/{approval_id}/decide", json={"decision": "approved", "decided_by": "human"})
    finished = client.patch(f"/api/tasks/{review}",
                            json={"status": "DONE", "actor": "human", "approval_id": approval_id})
    finished_body = finished.json()
    finished_task = finished_body.get("task", finished_body)
    check("a human approval closes the task", finished.status_code == 200
          and finished_task.get("status") == "DONE", f"{finished.status_code} {finished_task.get('status')}")

    # -- the event stream replays from a cursor --------------------------
    events = client.get(f"/api/projects/{alpha_id}/events", params={"limit": 200}).json()["events"]
    cursor = events[-3]["seq"] if len(events) >= 3 else 0
    replayed: list[dict] = []
    with client.stream("GET", "/api/events/stream", params={"after": cursor, "project_id": alpha_id}) as response:
        for line in response.iter_lines():
            if line.startswith("data: "):
                replayed.append(json.loads(line[6:]))
                break
    check("the stream replays the backlog after a cursor", bool(replayed) and replayed[0]["seq"] > cursor,
          f"seq {replayed[0]['seq']} > {cursor}" if replayed else "no events")

    # -- token scoping (service level: the local http mode bypasses tokens)
    issued = auth_service.issue([alpha_id], subject="gate2-agent", scopes=["read"], ttl=600)
    token = issued["token"]
    allowed = True
    try:
        auth_service.authorize(auth_service.verify(token), alpha_id, "read")
    except auth_service.AuthError:
        allowed = False
    blocked = False
    try:
        auth_service.authorize(auth_service.verify(token), beta_id, "read")
    except auth_service.AuthError as error:
        blocked = error.code == "project_denied"
    check("a token reads its own project", allowed)
    check("the same token is refused another project", blocked)

    # -- metrics and audit integrity -------------------------------------
    metrics = client.get("/api/metrics").json()
    required = {"ingest_success_rate", "tool_call_schema_valid_rate", "evidence_traceability_rate",
                "project_isolation_failures", "device_lease_collision", "task_recovery_success",
                "false_confident_claims", "model_calls_per_task"}
    check("the metric surface is complete", required <= set(metrics), ",".join(sorted(required - set(metrics))) or "all keys")
    check("no isolation failures observed", metrics["project_isolation_failures"] == 0, str(metrics["project_isolation_failures"]))
    check("restart recovery is counted", metrics["task_recovery_success"] >= 1, str(metrics["task_recovery_success"]))

    total = db.scalar("SELECT COUNT(*) FROM audit_events")
    seq = db.scalar("SELECT MAX(seq) FROM audit_events")
    check("audit events are append-only and gapless", total == seq, f"{total} rows, seq {seq}")

    duration = round(time.time() - started, 1)
    failed = [item for item in checks if not item["ok"]]
    write_report({"duration_seconds": duration, "work_dir": str(WORK), "projects": 3,
                  "artifacts": len(alpha_artifacts) + len(beta_artifacts), "audit_rows": total})
    print(f"[gate2] {len(checks) - len(failed)}/{len(checks)} checks passed", flush=True)
    return 0 if not failed else 1


def write_report(data: dict) -> None:
    failed = [item for item in checks if not item["ok"]]
    lines = [
        "# Gate 2 acceptance - multi-project isolation, persistence, board, events",
        "",
        f"- Run at: {time.strftime('%Y-%m-%d %H:%M:%S')}",
        f"- Duration: {data['duration_seconds']}s",
        "- DSH NEXT and the model API were supplied by the operator and were not modified by this run.",
        f"- Result: **{'PASS' if not failed else 'FAIL'}** - {len(checks) - len(failed)}/{len(checks)} checks",
        "",
        "## Checks",
        "",
        "| check | result | detail |",
        "| --- | --- | --- |",
    ]
    for item in checks:
        lines.append(f"| {item['check']} | {'PASS' if item['ok'] else 'FAIL'} | {item['detail'].replace('|', chr(92) + '|')} |")
    lines += [
        "",
        "## Facts",
        "",
        f"- Projects: {data['projects']} (alpha, beta, gamma)",
        f"- Artifact rows across two projects: {data['artifacts']}",
        f"- Audit rows: {data['audit_rows']}",
        f"- Work directory: `{data['work_dir']}`",
    ]
    (OUT / "acceptance.md").write_text("\n".join(lines) + "\n", encoding="utf-8")
    (OUT / "acceptance.json").write_text(json.dumps({"generated_at": _now_iso(), "checks": checks, "facts": data}, indent=2, default=str),
                                         encoding="utf-8")
    print(f"[gate2] report: {OUT / 'acceptance.md'}", flush=True)


if __name__ == "__main__":
    raise SystemExit(main())
