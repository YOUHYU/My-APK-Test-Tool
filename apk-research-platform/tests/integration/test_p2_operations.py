"""P2: persistence, restart recovery, board projection and the live event stream.

The scenario the acceptance gate cares about: a worker dies mid-job, the process is
replaced, and the *same* job finishes without a human touching the queue - because the
job's lease, not the worker's memory, is the source of truth.
"""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from apkplat import db as dbmod
from apkplat import worker as worker_mod
from apkplat.db import iso_plus, utcnow
from apkplat.services import queue, tasks

ROOT = Path(__file__).resolve().parents[2]


def _upload(client, name: str, path: Path) -> dict:
    with open(path, "rb") as handle:
        resp = client.post(
            "/api/projects",
            data={"name": name, "goal": "p2 operations"},
            files={"apk": ("sample.apk", handle, "application/vnd.android.package-archive")},
        )
    assert resp.status_code == 201, resp.text
    return resp.json()


def _audit(event_type: str, project_id: str | None = None) -> list[dict]:
    sql = "SELECT * FROM audit_events WHERE event_type = ?"
    params: list = [event_type]
    if project_id:
        sql += " AND project_id = ?"
        params.append(project_id)
    return [dict(r) for r in dbmod.db.query(sql + " ORDER BY seq", params)]


def test_crashed_job_is_recovered_after_restart(app_client, sample_apk):
    created = _upload(app_client, "p2-restart", sample_apk)
    project_id = created["project"]["id"]
    job_id = created["job_id"]

    # A worker claims the job and then "dies": its lease stays behind until it expires.
    claimed = queue.claim("doomed-worker", ["static_pipeline"], lease_seconds=30)
    assert claimed and claimed["id"] == job_id
    dbmod.db.execute(
        "UPDATE jobs SET lease_expires_at = ?, status = 'RUNNING' WHERE id = ?", (iso_plus(-5), job_id)
    )
    assert queue.get(job_id)["status"] == "RUNNING"

    # The replacement worker starts; recovery is a database operation, not a memory one.
    replacement = worker_mod.Worker("replacement-worker", ["static_pipeline"], poll_interval=0.05)
    processed = replacement.run(max_jobs=1)

    job = queue.get(job_id)
    assert processed == 1
    assert job["status"] == "SUCCEEDED", job
    assert job["attempt"] == 2, "the retry counter proves this is the second run, not a fresh job"
    assert _audit("job_lease_reclaimed", project_id), "the orphaned lease must be audited"
    recovered = _audit("job_recovered_after_restart", project_id)
    assert recovered and recovered[0]["payload_json"].count(job_id) == 1

    project = app_client.get(f"/api/projects/{project_id}").json()["project"]
    assert project["status"] == "ANALYZED"
    metrics = app_client.get("/api/metrics").json()
    assert metrics["task_recovery_success"] is not None
    assert metrics["task_recovery_success"] >= 0.99


def test_exhausted_orphan_is_failed_not_looped(app_client, sample_apk):
    created = _upload(app_client, "p2-exhausted", sample_apk)
    project_id = created["project"]["id"]
    job_id = created["job_id"]
    queue.claim("doomed-worker-2", ["static_pipeline"], lease_seconds=30)
    dbmod.db.execute(
        "UPDATE jobs SET lease_expires_at = ?, attempt = max_attempts WHERE id = ?", (iso_plus(-5), job_id)
    )

    replacement = worker_mod.Worker("replacement-worker-2", ["static_pipeline"], poll_interval=0.05)
    replacement.start()

    assert queue.get(job_id)["status"] == "FAILED"
    assert _audit("job_recovery_failed", project_id)


def test_board_columns_follow_task_state(app_client, sample_apk):
    created = _upload(app_client, "p2-board", sample_apk)
    project_id = created["project"]["id"]
    worker_mod.Worker("board-worker", ["static_pipeline"], poll_interval=0.05).run(max_jobs=1)

    task = tasks.create(project_id, title="review evidence", role="reviewer", actor="human")
    board = app_client.get(f"/api/projects/{project_id}/board").json()
    assert set(board["columns"]) >= {"TODO", "RUNNING", "REVIEW", "DONE"}
    todo_ids = [t["id"] for t in board["columns"]["TODO"]]
    assert task["id"] in todo_ids

    tasks.update(task["id"], status="RUNNING", actor="agent")
    board = app_client.get(f"/api/projects/{project_id}/board").json()
    assert task["id"] in [t["id"] for t in board["columns"]["RUNNING"]]

    # an agent may not close a task on its own
    with pytest.raises(Exception):
        tasks.update(task["id"], status="DONE", actor="agent")
    tasks.update(task["id"], status="REVIEW", actor="agent")
    approval_id = tasks.request_approval(project_id, task_id=task["id"], kind="done", requested_by="agent")
    tasks.decide_approval(approval_id, "approved", "human")
    tasks.update(task["id"], status="DONE", actor="human", approval_id=approval_id)
    board = app_client.get(f"/api/projects/{project_id}/board").json()
    assert task["id"] in [t["id"] for t in board["columns"]["DONE"]]


def test_event_stream_replays_from_a_cursor(app_client, sample_apk):
    created = _upload(app_client, "p2-sse", sample_apk)
    project_id = created["project"]["id"]
    worker_mod.Worker("sse-worker", ["static_pipeline"], poll_interval=0.05).run(max_jobs=1)

    events = app_client.get(f"/api/projects/{project_id}/events", params={"limit": 500}).json()["events"]
    assert any(e["event_type"] == "project_created" for e in events)

    cursor = events[-2]["seq"] if len(events) >= 2 else 0
    with app_client.stream(
        "GET", "/api/events/stream", params={"after": cursor, "project_id": project_id}
    ) as response:
        assert response.status_code == 200
        got: list[str] = []
        for line in response.iter_lines():
            if line.startswith("data: "):
                got.append(json.loads(line[6:]))
                break
    assert got, "the stream must deliver the backlog after the cursor"
    assert got[0]["seq"] > cursor
    assert got[0]["project_id"] == project_id


def test_queue_is_persistent_across_db_handles(app_client, sample_apk):
    created = _upload(app_client, "p2-persist", sample_apk)
    job_id = created["job_id"]
    assert queue.get(job_id)["status"] == "PENDING"

    # A separate connection sees the same row: nothing about the queue lives in memory.
    from apkplat.db import Database

    other = Database()
    try:
        row = other.one("SELECT id, status, kind FROM jobs WHERE id = ?", (job_id,))
        assert row and row["status"] == "PENDING" and row["kind"] == "static_pipeline"
    finally:
        other._conn.close()  # noqa: SLF001 - explicit handle close for the assertion


def test_metrics_expose_the_p2_indicators(app_client):
    metrics = app_client.get("/api/metrics").json()
    for key in (
        "ingest_success_rate",
        "tool_call_schema_valid_rate",
        "evidence_traceability_rate",
        "project_isolation_failures",
        "device_lease_collision",
        "task_recovery_success",
        "false_confident_claims",
        "model_calls_per_task",
        "model_api_latency_ms_avg",
    ):
        assert key in metrics, key
    assert metrics["project_isolation_failures"] == 0
    assert metrics["device_lease_collision"] == 0
    assert utcnow().endswith("Z")
