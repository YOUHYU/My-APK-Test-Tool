"""Resume after an interruption.

The queue is durable, but a worker that dies mid-job leaves a lease behind. Two
things must be true for an operator to recover without restarting anything:
the API can reclaim + re-publish (``POST /resume``), and a long-lived worker
reaps expired leases on a timer.
"""
from __future__ import annotations

import time
from pathlib import Path

from apkplat.db import db
from apkplat.services import projects as projects_service
from apkplat.services import queue as queue_service
from apkplat.services import recovery as recovery_service
from apkplat.services import tasks as tasks_service
from apkplat.worker import Worker


def _upload(client, sample_apk: Path, name: str, **data) -> dict:
    body = {"name": name, **data}
    with sample_apk.open("rb") as fh:
        response = client.post(
            "/api/projects",
            data=body,
            files={"apk": (sample_apk.name, fh, "application/vnd.android.package-archive")},
        )
    assert response.status_code == 201, response.text
    return response.json()


def test_resume_reclaims_an_expired_lease_and_finishes_the_work(app_client, sample_apk: Path) -> None:
    created = _upload(app_client, sample_apk, "resume-case")
    project_id = created["project"]["id"]
    job_id = created["job_id"]

    # A worker takes the job and then "dies": the lease stays but stops being renewed.
    claimed = queue_service.claim("dead-worker", ["static_pipeline"], 60)
    assert claimed and claimed["id"] == job_id
    db.execute("UPDATE jobs SET lease_expires_at = '2000-01-01T00:00:00.000Z' WHERE id = ?", (job_id,))

    report = app_client.get(f"/api/projects/{project_id}/recovery").json()
    assert report["live_jobs"] == 1  # still RUNNING from the API's point of view
    assert report["dead_leases"] == 1  # ... but the lease expired, so it is stalled
    assert report["stalled"] is True

    summary = app_client.post(f"/api/projects/{project_id}/resume").json()
    assert summary["ok"] is True
    assert [row["job_id"] for row in summary["reclaimed"]] == [job_id]
    assert queue_service.get(job_id)["status"] in ("RETRYING", "PENDING")

    worker = Worker(worker_id="w-resume", kinds=["static_pipeline"], poll_interval=0.05)
    # max_jobs alone would spin forever when the queue runs dry before the cap; the
    # idle timeout is what makes a bounded test run terminate.
    worker.run(max_jobs=2, idle_timeout=2)

    assert queue_service.get(job_id)["status"] == "SUCCEEDED"
    project = projects_service.get(project_id)
    assert project["status"] == "ANALYZED"
    tasks = tasks_service.list_tasks(project_id)
    assert [t["role"] for t in tasks] == ["static"]
    assert tasks[0]["status"] == "REVIEW"


def test_resume_does_not_duplicate_work_that_is_already_running(app_client, sample_apk: Path) -> None:
    created = _upload(app_client, sample_apk, "resume-noop")
    project_id = created["project"]["id"]
    job_id = created["job_id"]
    queue_service.claim("live-worker", ["static_pipeline"], 600)  # lease far in the future

    before = recovery_service.live_jobs(project_id)
    summary = recovery_service.resume_project(project_id, actor="test")
    after = recovery_service.live_jobs(project_id)

    assert summary["reclaimed"] == []
    assert summary["enqueued"] == []
    assert [row["id"] for row in after] == [row["id"] for row in before] == [job_id]


def test_worker_reaps_expired_leases_without_a_restart(sample_apk: Path) -> None:
    project = projects_service.create("reap-case", sample_apk, sample_apk.name, actor="test")
    job_id = queue_service.enqueue(
        "static_pipeline",
        project_id=project["id"],
        payload={"project_id": project["id"]},
        idempotency_key=f"reap:{project['id']}",
        actor="test",
    )
    claimed = queue_service.claim("ghost-worker", ["static_pipeline"], 60)
    assert claimed and claimed["id"] == job_id
    db.execute("UPDATE jobs SET lease_expires_at = '2000-01-01T00:00:00.000Z' WHERE id = ?", (job_id,))

    # A worker whose reaping interval elapses while it sits idle must pick the job up.
    worker = Worker(
        worker_id="w-reaper",
        kinds=["static_pipeline"],
        poll_interval=0.05,
        lease_seconds=60,
        reap_interval=0.2,
    )
    started = time.time()
    processed = worker.run(idle_timeout=5)
    assert processed >= 1, "the reaper should have requeued and then executed the orphaned job"
    assert time.time() - started < 20
    assert queue_service.get(job_id)["status"] == "SUCCEEDED"
