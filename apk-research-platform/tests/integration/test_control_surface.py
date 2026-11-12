"""The console's control surface: pause / resume / stop, the command box, and what does *not*
happen when the operator merely switches project.
"""

from __future__ import annotations

import pytest

from apkplat.db import db
from apkplat.pipeline_static import run as run_pipeline
from apkplat.services import control, queue as queue_service
from apkplat.worker import Worker


def _upload(client, sample_apk, name: str, headers) -> str:
    with sample_apk.open("rb") as fh:
        response = client.post(
            "/api/projects",
            data={"name": name},
            files={"apk": (sample_apk.name, fh, "application/vnd.android.package-archive")},
            headers=headers,
        )
    assert response.status_code == 201, response.text
    return response.json()["project"]["id"]


def test_control_endpoints_round_trip(app_client, sample_apk, local_headers):
    project_id = _upload(app_client, sample_apk, "ctl-api", local_headers)

    snap = app_client.get(f"/api/projects/{project_id}/control", headers=local_headers).json()
    assert snap["run_state"] == "RUNNING" and snap["accepting_work"] is True

    paused = app_client.post(
        f"/api/projects/{project_id}/control", json={"action": "pause", "reason": "用例暂停"}, headers=local_headers
    )
    assert paused.status_code == 200 and paused.json()["run_state"] == "PAUSED"

    # Pausing does not hide the board: cards are facts, not scheduling.
    board = app_client.get(f"/api/projects/{project_id}/board", headers=local_headers)
    assert board.status_code == 200

    status_cmd = app_client.post(
        f"/api/projects/{project_id}/command", json={"text": "状态"}, headers=local_headers
    ).json()
    assert status_cmd["action"] == "status" and "PAUSED" in status_cmd["message"]

    resumed = app_client.post(
        f"/api/projects/{project_id}/command", json={"text": "继续"}, headers=local_headers
    ).json()
    assert resumed["run_state"] == "RUNNING"

    stopped = app_client.post(
        f"/api/projects/{project_id}/command", json={"text": "停止 用例结束"}, headers=local_headers
    ).json()
    assert stopped["run_state"] == "STOPPED" and stopped["action"] == "stop"
    assert "cancelled_jobs" in stopped


def test_unknown_action_and_project_are_structured(app_client, sample_apk, local_headers):
    project_id = _upload(app_client, sample_apk, "ctl-api-2", local_headers)
    bad = app_client.post(
        f"/api/projects/{project_id}/control", json={"action": "explode"}, headers=local_headers
    )
    assert bad.status_code == 422 and bad.json()["detail"]["error_code"] == "unknown_action"

    missing = app_client.get("/api/projects/prj_missing/control", headers=local_headers)
    assert missing.status_code == 404 and missing.json()["detail"]["error_code"] == "project_not_found"

    unknown_cmd = app_client.post(
        f"/api/projects/{project_id}/command", json={"text": "重启一下"}, headers=local_headers
    )
    assert unknown_cmd.status_code == 422


def test_switching_projects_does_not_disturb_running_work(app_client, sample_apk, local_headers):
    """Looking at another project must not pause, cancel or requeue anything.

    The console's project switcher is a pure view change, so the only thing a "switch" does
    is issue reads. This test performs those reads and then proves the other project's jobs
    are byte-for-byte unchanged.
    """
    left = _upload(app_client, sample_apk, "ctl-left-view", local_headers)
    right = _upload(app_client, sample_apk, "ctl-right-view", local_headers)

    before = db.query("SELECT id, status, cancel_requested FROM jobs WHERE project_id = ? ORDER BY id", (left,))
    assert before, "the upload should have queued a static job"

    control.pause(left, actor="human", reason="still paused while the operator looks elsewhere")

    # The operator now "switches project" in the console: only GETs happen.
    for path in (
        f"/api/projects/{right}",
        f"/api/projects/{right}/board",
        f"/api/projects/{right}/artifacts",
        f"/api/projects/{right}/control",
        "/api/projects",
        "/api/metrics",
    ):
        assert app_client.get(path, headers=local_headers).status_code == 200

    after = db.query("SELECT id, status, cancel_requested FROM jobs WHERE project_id = ? ORDER BY id", (left,))
    assert [(r["id"], r["status"], r["cancel_requested"]) for r in after] == [
        (r["id"], r["status"], r["cancel_requested"]) for r in before
    ]
    assert control.state(left) == "PAUSED"
    assert control.state(right) == "RUNNING"


def test_worker_leaves_a_paused_project_alone_and_picks_it_up_after_resume(app_client, sample_apk, local_headers):
    project_id = _upload(app_client, sample_apk, "ctl-worker", local_headers)
    control.pause(project_id, actor="human", reason="hold the queue")

    worker = Worker("ctl-worker-1", kinds=["static_pipeline"], poll_interval=0.05)
    processed = worker.run(max_jobs=1, idle_timeout=1.0)
    assert processed == 0
    assert db.one("SELECT status FROM projects WHERE id = ?", (project_id,))["status"] == "INGESTED"
    assert queue_service.pending_for_project(project_id) == 1  # still queued, untouched

    control.resume(project_id, actor="human")
    processed = worker.run(max_jobs=1, idle_timeout=5.0)
    assert processed == 1
    assert db.one("SELECT status FROM projects WHERE id = ?", (project_id,))["status"] == "ANALYZED"


def test_stop_makes_the_running_stage_exit_at_the_next_boundary(app_client, sample_apk, local_headers):
    """A stop is cooperative: the handler raises at its next stage boundary.

    Here the job is claimed (so it looks RUNNING to the platform), the operator stops the
    project, and the pipeline is then started with the same checkpoint the worker would pass
    in. It must refuse to begin rather than analyse a project that was cancelled meanwhile.
    """
    project_id = _upload(app_client, sample_apk, "ctl-cancel", local_headers)
    job = queue_service.claim("ctl-cancel-worker", ["static_pipeline"])
    assert job is not None

    control.stop(project_id, actor="human", reason="操作员停止")
    fresh = queue_service.get(job["id"])
    assert int(fresh["cancel_requested"]) == 1

    with pytest.raises(control.JobCancelled):
        run_pipeline(project_id, check=control.check_callable(fresh))

    assert db.one("SELECT status FROM projects WHERE id = ?", (project_id,))["status"] == "INGESTED"
