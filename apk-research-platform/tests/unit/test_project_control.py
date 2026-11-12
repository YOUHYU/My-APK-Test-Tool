"""Project run control: pause / resume / stop, the command parser and cooperative cancel."""

from __future__ import annotations

import time

import pytest

from apkplat.db import db
from apkplat.services import capabilities, control, projects as projects_service
from apkplat.services import queue as queue_service
from apkplat.services import tasks as tasks_service


def _project(name: str, apk):
    return projects_service.create(name, apk_source=apk, filename=apk.name)


def test_pause_blocks_claim_and_resume_unblocks(sample_apk):
    project = _project("ctl-pause", sample_apk)
    job = queue_service.enqueue("static_pipeline", project_id=project["id"], payload={}, idempotency_key="ctl-1")

    paused = control.pause(project["id"], actor="human", reason="test")
    assert paused["run_state"] == "PAUSED"
    assert paused["changed"] is True
    # A paused project hands out nothing, even though a job is sitting there.
    assert queue_service.claim("w1", ["static_pipeline"]) is None

    resumed = control.resume(project["id"], actor="human")
    assert resumed["run_state"] == "RUNNING"
    claimed = queue_service.claim("w1", ["static_pipeline"])
    assert claimed is not None and claimed["id"] == job


def test_pause_is_idempotent_and_refused_once_stopped(sample_apk):
    project = _project("ctl-idem", sample_apk)
    assert control.pause(project["id"], actor="human")["changed"] is True
    again = control.pause(project["id"], actor="human")
    assert again["changed"] is False

    control.stop(project["id"], actor="human")
    with pytest.raises(control.ControlError) as exc:
        control.pause(project["id"], actor="human")
    assert exc.value.code == "project_stopped"


def test_stop_cancels_queued_work_and_flags_running_work(sample_apk):
    project = _project("ctl-stop", sample_apk)
    pending = queue_service.enqueue("static_pipeline", project_id=project["id"], payload={}, idempotency_key="ctl-2")
    running = queue_service.enqueue("report_generate", project_id=project["id"], payload={}, idempotency_key="ctl-3")
    claimed = queue_service.claim("w2", ["report_generate"])
    assert claimed is not None and claimed["id"] == running

    result = control.stop(project["id"], actor="human", reason="operator")

    assert result["run_state"] == "STOPPED"
    assert result["cancelled_jobs"] == [pending]
    assert result["cancel_requested_jobs"] == [running]
    assert queue_service.get(pending)["status"] == "CANCELLED"
    assert int(queue_service.get(running)["cancel_requested"]) == 1
    assert int(db.one("SELECT cancel_requested FROM jobs WHERE id = ?", (running,))["cancel_requested"]) == 1
    # A stopped project also refuses new claims.
    assert queue_service.claim("w2", ["static_pipeline", "report_generate"]) is None


def test_stop_cancels_open_tasks_and_closes_agent_runs(sample_apk):
    project = _project("ctl-tasks", sample_apk)
    task = tasks_service.create(project["id"], role="static", title="静态分析", actor="human", status="RUNNING")
    run_id = tasks_service.record_run(task["id"], role="static", notes="unit test")
    assert run_id

    result = control.stop(project["id"], actor="human")

    assert result["cancelled_tasks"] >= 1
    assert tasks_service.get(task["id"])["status"] == "CANCELLED"
    row = db.one("SELECT ended_at, status, notes FROM agent_runs WHERE task_id = ?", (task["id"],))
    assert row["ended_at"] and row["status"] == "cancelled"
    assert "cancelled_by_operator" in (row["notes"] or "")


def test_stop_revokes_live_run_capabilities(sample_apk):
    project = _project("ctl-runs", sample_apk)
    scope, token, _path = capabilities.issue(project["id"], "exec", actor="test")
    assert capabilities.resolve(token) is not None

    result = control.stop(project["id"], actor="human")

    assert scope.run_id in result["revoked_runs"]
    with pytest.raises(capabilities.CapabilityError) as exc:
        capabilities.resolve(token)
    assert exc.value.code == "capability_revoked"


def test_checkpoint_raises_only_when_asked_to_stop(sample_apk):
    project = _project("ctl-checkpoint", sample_apk)
    job = queue_service.enqueue("static_pipeline", project_id=project["id"], payload={}, idempotency_key="ctl-4")
    control.checkpoint({"id": job})  # no-op while nothing was requested

    db.execute("UPDATE jobs SET cancel_requested = 1 WHERE id = ?", (job,))
    with pytest.raises(control.JobCancelled):
        control.checkpoint({"id": job})


def test_command_parser_round_trip(sample_apk):
    project = _project("ctl-cmd", sample_apk)
    assert control.command(project["id"], "暂停")["run_state"] == "PAUSED"
    assert control.command(project["id"], "status")["ok"] is True
    assert control.command(project["id"], "继续")["run_state"] == "RUNNING"
    assert control.command(project["id"], "help")["action"] == "help"
    stopped = control.command(project["id"], "停止 演示结束")
    assert stopped["run_state"] == "STOPPED"
    with pytest.raises(control.ControlError) as exc:
        control.command(project["id"], "开机")
    assert exc.value.code == "unknown_command"
    with pytest.raises(control.ControlError) as empty:
        control.command(project["id"], "   ")
    assert empty.value.code == "empty_command"


def test_command_retry_and_cancel_by_id(sample_apk):
    project = _project("ctl-cmd2", sample_apk)
    task = tasks_service.create(project["id"], role="static", title="静态分析", actor="human", status="RUNNING")
    tasks_service.update(task["id"], status="REVIEW", actor="reviewer")

    retried = control.command(project["id"], f"重试 {task['id']}")
    assert retried["action"] == "retry"
    assert tasks_service.get(task["id"])["status"] == "RUNNING"
    assert queue_service.pending_for_project(project["id"]) >= 1

    cancelled = control.command(project["id"], f"取消 {task['id']}")
    assert cancelled["action"] == "cancel"
    assert tasks_service.get(task["id"])["status"] == "CANCELLED"

    with pytest.raises(control.ControlError) as exc:
        control.command(project["id"], f"重试 {task['id']}")
    assert exc.value.code == "card_cancelled"


def test_command_rejects_a_card_from_another_project(sample_apk):
    left = _project("ctl-left", sample_apk)
    right = _project("ctl-right", sample_apk)
    foreign = tasks_service.create(left["id"], role="static", title="静态分析", actor="human")
    with pytest.raises(control.ControlError) as exc:
        control.command(right["id"], f"取消 {foreign['id']}")
    assert exc.value.code == "task_project_mismatch"


def test_status_reports_counters(sample_apk):
    project = _project("ctl-status", sample_apk)
    queue_service.enqueue("static_pipeline", project_id=project["id"], payload={}, idempotency_key="ctl-5")
    snap = control.status(project["id"])
    assert snap["run_state"] == "RUNNING"
    assert snap["jobs"]["pending"] == 1
    assert snap["accepting_work"] is True
    assert snap["tasks"]["unfinished"] == 0
