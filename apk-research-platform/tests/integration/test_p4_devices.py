"""P4 acceptance: the device pool.

The point of these tests is not "a session ran" but the four invariants the taskbook
names: one device serves one task at a time, two agents never share a serial, an
unplug is a safe failure (lease released, task FAILED, nothing left running), and a
finished session leaves no residue on the device.
"""
from __future__ import annotations

import threading
import time

import pytest

from apkplat import audit, dynamic, worker
from apkplat.config import settings
from apkplat.db import db
from apkplat.services import artifacts as artifacts_service
from apkplat.services import devices as devices_service
from apkplat.services import evidence as evidence_service
from apkplat.services import projects as projects_service
from apkplat.services import queue as queue_service
from apkplat.services import tasks as tasks_service


def _project(sample_apk, name: str) -> dict:
    return projects_service.create(name, sample_apk, "sample-app.apk", actor="test")


def _active_leases(device_id: str | None = None) -> list:
    sql = "SELECT * FROM device_leases WHERE released_at IS NULL AND expires_at > ?"
    params: list = [dynamic.utcnow()]
    if device_id:
        sql += " AND device_id = ?"
        params.append(device_id)
    return db.query(sql, params)


class SlowSim(dynamic.SimTransport):
    """A simulated device that takes a beat on install, so two sessions really overlap."""

    def __init__(self, delay: float = 0.8) -> None:
        super().__init__()
        self.delay = delay

    def run(self, serial, args, *, timeout=None):  # noqa: D102
        if args and args[0] == "install":
            time.sleep(self.delay)
        return super().run(serial, args, timeout=timeout)


def test_dynamic_session_runs_end_to_end(sample_apk):
    project = _project(sample_apk, "p4-happy")
    device = devices_service.register("sim-happy", device_type="simulator", alias="sim-happy")
    task = tasks_service.create(project["id"], role="dynamic", title="Dynamic session", actor="test", status="RUNNING")

    result = dynamic.run_task(project["id"], task_id=task["id"], device_id=device["id"], transport=dynamic.SimTransport())

    steps = [item["step"] for item in result["steps"]]
    assert steps == ["probe", "install", "launch", "ui", "observe", "screenshot"], steps
    assert result["device"]["model"] == "Pixel 6 (sim)"
    assert result["device"]["sdk"] == "33"
    assert result["evidence_ids"], "a session that produces no evidence is not a session"
    assert result["cleanup"]["verified"] is True
    assert _active_leases(device["id"]) == [], "the lease must be released when the session ends"

    kinds = {row["kind"] for row in artifacts_service.list_artifacts(project["id"])}
    assert {"device_probe", "device_install", "device_launch", "device_logcat", "device_cleanup"} <= kinds

    trace = evidence_service.verify(project["id"])
    assert trace["traceability_rate"] == 1.0, trace["failures"]

    task_row = tasks_service.get(task["id"])
    assert task_row["status"] == "REVIEW"

    events = [row["event_type"] for row in audit.tail(0, project_id=project["id"], limit=200)]
    assert "dynamic_started" in events and "dynamic_completed" in events
    assert "dynamic_cleanup_verified" in events


def test_second_session_waits_for_the_single_device(sample_apk):
    project = _project(sample_apk, "p4-wait")
    device = devices_service.register("sim-wait", device_type="simulator", alias="sim-wait")
    holder = devices_service.acquire(project["id"], owner="holder", device_id=device["id"])

    task = tasks_service.create(project["id"], role="dynamic", title="Blocked session", actor="test", status="RUNNING")
    with pytest.raises(dynamic.DynamicError) as excinfo:
        dynamic.run_task(project["id"], task_id=task["id"], device_id=device["id"], transport=dynamic.SimTransport())
    assert excinfo.value.code == "device_unavailable"
    assert excinfo.value.retryable is True, "a busy pool is a wait, not a failure"

    blocked = tasks_service.get(task["id"])
    assert blocked["status"] == "WAITING_DEVICE"
    events = [row["event_type"] for row in audit.tail(0, project_id=project["id"], limit=200)]
    assert "device_wait" in events

    devices_service.release(holder["id"], owner="holder", reason="test handback")
    result = dynamic.run_task(project["id"], task_id=task["id"], device_id=device["id"], transport=dynamic.SimTransport())
    assert result["cleanup"]["verified"] is True
    assert tasks_service.get(task["id"])["status"] == "REVIEW"


def test_unplug_is_a_safe_failure(sample_apk):
    project = _project(sample_apk, "p4-unplug")
    device = devices_service.register("sim-unplug", device_type="simulator", alias="sim-unplug")
    task = tasks_service.create(project["id"], role="dynamic", title="Pulled cable", actor="test", status="RUNNING")

    with pytest.raises(dynamic.DynamicError) as excinfo:
        dynamic.run_task(
            project["id"],
            task_id=task["id"],
            device_id=device["id"],
            transport=dynamic.SimTransport(unplug_at="screencap"),
        )
    assert excinfo.value.code == "device_lost"
    assert excinfo.value.retryable is False, "a missing phone is not a transient error"

    assert _active_leases(device["id"]) == [], "an unplug must still release the lease"

    failed = tasks_service.get(task["id"])
    assert failed["status"] == "FAILED"
    assert failed["error_code"] == "device_lost"

    events = [row["event_type"] for row in audit.tail(0, project_id=project["id"], limit=200)]
    assert "device_lost" in events
    assert "dynamic_failed" in events

    # Evidence gathered before the cable went is still traceable, and the deferred
    # cleanup is recorded as such instead of being silently skipped.
    evidence_rows = evidence_service.list_evidence(project["id"])
    assert evidence_rows, "the probe/install/launch steps already produced evidence"
    assert evidence_service.verify(project["id"])["traceability_rate"] == 1.0
    cleanup = next(row for row in artifacts_service.list_artifacts(project["id"]) if row["kind"] == "device_cleanup")
    payload = artifacts_service.path_of(cleanup).read_text(encoding="utf-8")
    assert '"verified": false' in payload
    assert "device unreachable" in payload


def test_expired_lease_frees_the_device(sample_apk):
    project = _project(sample_apk, "p4-ttl")
    device = devices_service.register("sim-ttl", device_type="simulator", alias="sim-ttl")

    live = devices_service.acquire(project["id"], owner="holder", device_id=device["id"])
    with pytest.raises(devices_service.LeaseConflict):
        devices_service.acquire(project["id"], owner="other", device_id=device["id"])

    # Age the lease out the way a crashed worker would leave it: nothing released it,
    # its deadline simply passed.
    db.execute(
        "UPDATE device_leases SET expires_at = ? WHERE id = ?",
        ("2000-01-01T00:00:00.000Z", live["id"]),
    )
    second = devices_service.acquire(project["id"], owner="other", device_id=device["id"])
    assert second["id"] != live["id"]
    stale = db.one("SELECT * FROM device_leases WHERE id = ?", (live["id"],))
    assert stale["released_at"] is not None, "the stale lease is closed out, not left dangling"


def test_two_sessions_never_share_one_device(sample_apk):
    project_a = _project(sample_apk, "p4-race-a")
    project_b = _project(sample_apk, "p4-race-b")
    device = devices_service.register("sim-race", device_type="simulator", alias="sim-race")

    outcomes: dict[str, object] = {}

    def run(tag: str, project_id: str) -> None:
        try:
            outcomes[tag] = dynamic.run_task(project_id, device_id=device["id"], transport=SlowSim(delay=0.8))
        except dynamic.DynamicError as exc:
            outcomes[tag] = exc.code

    thread_a = threading.Thread(target=run, args=("a", project_a["id"]))
    thread_a.start()
    time.sleep(0.2)  # let A take the device first
    thread_b = threading.Thread(target=run, args=("b", project_b["id"]))
    thread_b.start()
    thread_a.join(timeout=30)
    thread_b.join(timeout=30)

    assert isinstance(outcomes.get("a"), dict), outcomes
    assert outcomes.get("b") == "device_unavailable", outcomes

    # No two leases on the serial ever overlapped.
    rows = db.query("SELECT * FROM device_leases WHERE device_id = ? ORDER BY heartbeat_at", (device["id"],))
    assert len(rows) == 1, "only the winning session may ever hold this serial"
    assert rows[0]["released_at"] is not None, "and it must close the lease when it is done"
    assert db.scalar("SELECT COUNT(*) FROM audit_events WHERE event_type = 'lease_collision_blocked'") == 0


def test_dynamic_job_runs_through_the_queue(app_client, sample_apk):
    project = _project(sample_apk, "p4-queue")
    devices_service.register("sim-queue", device_type="simulator", alias="sim-queue")

    response = app_client.post(f"/api/projects/{project['id']}/dynamic/run", json={"transport": "sim"})
    assert response.status_code == 202, response.text
    body = response.json()
    assert body["task"]["role"] == "dynamic"

    w = worker.Worker("p4-worker", ["dynamic_analysis"], poll_interval=0.05)
    processed = w.run(max_jobs=1)
    assert processed == 1

    job = queue_service.get(body["job_id"])
    assert job["status"] == "SUCCEEDED", job

    runs = app_client.get(f"/api/projects/{project['id']}/dynamic/runs").json()
    kinds = {row["kind"] for row in runs["artifacts"]}
    assert "device_cleanup" in kinds
    assert [row["event_type"] for row in runs["events"]].count("dynamic_completed") == 1
    assert all(lease["released_at"] for lease in runs["leases"])
