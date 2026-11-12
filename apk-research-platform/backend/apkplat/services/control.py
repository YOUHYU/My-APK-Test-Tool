"""Project run control: pause / resume / stop, plus the console command box.

The three verbs exist because "stop the analysis" is not one operation:

* ``pause``  - stop handing out work. Jobs already running are *not* killed: a half-written
  artifact tree is worse than a slow one, and a worker in the middle of ``jadx`` cannot be
  interrupted safely anyway. Cards keep their status; the board shows the project as paused.
* ``resume`` - hand out work again. It deliberately does **not** resurrect jobs that a previous
  ``stop`` cancelled; that is what ``services.recovery.resume_project`` (the 「恢复未完成的工作」
  path) is for, and keeping them separate makes the audit trail readable.
* ``stop``   - cancel pending work, ask in-flight work to stop at its next stage boundary
  (``jobs.cancel_requested``), revoke live run capabilities and close leaked agent runs.

Switching the console to another project is a pure view change: it issues no control call, so
it cannot disturb anything that is running. That is asserted in
``tests/integration/test_control_surface.py``.
"""

from __future__ import annotations

import re
from typing import Any

from .. import audit, clock
from ..db import Row, db
from . import capabilities, queue as queue_service, tasks as tasks_service

RUNNING = "RUNNING"
PAUSED = "PAUSED"
STOPPED = "STOPPED"
STATES = (RUNNING, PAUSED, STOPPED)
ACTIONS = ("pause", "resume", "stop")

# Job states that still represent "somebody could be working on this".
LIVE_JOB_STATES = ("RUNNING",)
OPEN_JOB_STATES = ("PENDING", "RETRYING")


class ControlError(Exception):
    """A refused control action (unknown project, unknown action, bad command)."""

    def __init__(self, code: str, message: str, status: int = 400):
        super().__init__(message)
        self.code = code
        self.message = message
        self.status = status

    def as_error(self) -> dict[str, Any]:
        return {"error_code": self.code, "message": self.message, "retryable": False}


class JobCancelled(Exception):
    """Raised inside a handler when the operator asked the job to stop."""

    def __init__(self, job_id: str, reason: str = "cancelled_by_operator"):
        super().__init__(f"job {job_id} was cancelled ({reason})")
        self.job_id = job_id
        self.reason = reason


# -- state ------------------------------------------------------------------


def state(project_id: str) -> str:
    row = db.one("SELECT run_state FROM projects WHERE id = ?", (project_id,))
    if row is None:
        raise ControlError("project_not_found", f"project {project_id} does not exist", 404)
    return str(row["run_state"] or RUNNING)


def is_running(project_id: str | None) -> bool:
    """True when a job of this project may be claimed. Unknown/blank project ids pass.

    Jobs without a project (there are none today, but the queue tolerates it) must keep
    working, so this is deliberately permissive when the row is missing.
    """
    if not project_id:
        return True
    row = db.one("SELECT run_state FROM projects WHERE id = ?", (project_id,))
    if row is None:
        return True
    return str(row["run_state"] or RUNNING) == RUNNING


def status(project_id: str) -> dict[str, Any]:
    row = db.one(
        "SELECT id, name, run_state, run_state_changed_at, run_state_reason FROM projects WHERE id = ?",
        (project_id,),
    )
    if row is None:
        raise ControlError("project_not_found", f"project {project_id} does not exist", 404)
    jobs = {
        "pending": _count_jobs(project_id, OPEN_JOB_STATES),
        "running": _count_jobs(project_id, LIVE_JOB_STATES),
        "cancelled": _count_jobs(project_id, ("CANCELLED",)),
        "cancel_requested": _count(
            "SELECT COUNT(*) FROM jobs WHERE project_id = ? AND cancel_requested = 1 AND status = 'RUNNING'",
            project_id,
        ),
    }
    tasks = {
        "running": _count("SELECT COUNT(*) FROM tasks WHERE project_id = ? AND status = 'RUNNING'", project_id),
        "waiting": _count(
            "SELECT COUNT(*) FROM tasks WHERE project_id = ? AND status LIKE 'WAITING_%'", project_id
        ),
        "unfinished": _count(
            "SELECT COUNT(*) FROM tasks WHERE project_id = ? AND status NOT IN ('DONE','CANCELLED')", project_id
        ),
    }
    live_runs = _count(
        "SELECT COUNT(*) FROM run_capabilities WHERE project_id = ? AND revoked_at IS NULL", project_id
    )
    return {
        "project_id": project_id,
        "name": row["name"],
        "run_state": row["run_state"] or RUNNING,
        "changed_at": row["run_state_changed_at"],
        "reason": row["run_state_reason"],
        "jobs": jobs,
        "tasks": tasks,
        "live_runs": live_runs,
        "accepting_work": (row["run_state"] or RUNNING) == RUNNING,
    }


def _count(sql: str, *params: Any) -> int:
    return int(db.scalar(sql, params) or 0)


def _count_jobs(project_id: str, statuses: tuple[str, ...]) -> int:
    placeholders = ",".join("?" for _ in statuses)
    return _count(
        f"SELECT COUNT(*) FROM jobs WHERE project_id = ? AND status IN ({placeholders})",
        project_id,
        *statuses,
    )


# -- verbs ------------------------------------------------------------------


def pause(project_id: str, *, actor: str = "human", reason: str | None = None) -> dict[str, Any]:
    current = state(project_id)
    if current == PAUSED:
        return {**status(project_id), "changed": False, "message": "项目已经是暂停状态"}
    if current == STOPPED:
        raise ControlError(
            "project_stopped",
            "项目已停止；先执行「继续」把状态切回运行，再按需恢复未完成的工作",
            409,
        )
    _set_state(project_id, PAUSED, actor=actor, reason=reason, action="pause")
    fresh = status(project_id)
    return {
        **fresh,
        "changed": True,
        "message": (
            f"已暂停：不再派发新任务；正在运行的 {fresh['jobs']['running']} 个作业会先跑完"
            "（中途打断会留下半套产物）"
        ),
    }


def resume(project_id: str, *, actor: str = "human", reason: str | None = None) -> dict[str, Any]:
    current = state(project_id)
    if current == RUNNING:
        return {**status(project_id), "changed": False, "message": "项目已经在运行状态"}
    _set_state(project_id, RUNNING, actor=actor, reason=reason, action="resume")
    fresh = status(project_id)
    message = "已继续：队列恢复派发"
    if current == STOPPED:
        message = "已继续：队列恢复派发；被「停止」取消的作业不会自动复活，需要时用「恢复未完成的工作」"
    return {**fresh, "changed": True, "message": message}


def stop(project_id: str, *, actor: str = "human", reason: str | None = None) -> dict[str, Any]:
    current = state(project_id)
    if current == STOPPED:
        return {**status(project_id), "changed": False, "message": "项目已经是停止状态"}
    now = clock.now_utc()
    _set_state(project_id, STOPPED, actor=actor, reason=reason, action="stop")

    cancelled: list[str] = []
    for row in db.query(
        "SELECT id FROM jobs WHERE project_id = ? AND status IN ('PENDING','RETRYING') ORDER BY created_at",
        (project_id,),
    ):
        job_id = str(row["id"])
        queue_service.cancel(job_id, actor=actor)
        cancelled.append(job_id)

    requested: list[str] = []
    for row in db.query(
        "SELECT id FROM jobs WHERE project_id = ? AND status = 'RUNNING' AND cancel_requested = 0", (project_id,)
    ):
        job_id = str(row["id"])
        db.execute("UPDATE jobs SET cancel_requested = 1, updated_at = ? WHERE id = ?", (now, job_id))
        requested.append(job_id)

    revoked = _revoke_runs(project_id, actor=actor, reason="project_stopped")
    closed_runs = _close_agent_runs(project_id, reason="cancelled_by_operator")
    cancelled_tasks = _cancel_open_tasks(project_id, actor=actor, reason=reason or "operator stopped the project")

    audit.record(
        "project_control",
        project_id=project_id,
        actor=actor,
        payload={
            "action": "stop",
            "previous_state": current,
            "reason": reason,
            "cancelled_jobs": cancelled,
            "cancel_requested_jobs": requested,
            "revoked_runs": revoked,
            "closed_agent_runs": closed_runs,
            "cancelled_tasks": cancelled_tasks,
        },
    )
    fresh = status(project_id)
    return {
        **fresh,
        "changed": True,
        "cancelled_jobs": cancelled,
        "cancel_requested_jobs": requested,
        "revoked_runs": revoked,
        "cancelled_tasks": cancelled_tasks,
        "message": (
            f"已停止：取消 {len(cancelled)} 个待办作业，通知 {len(requested)} 个运行中作业在当前阶段结束后退出，"
            f"注销 {len(revoked)} 个智能体运行令牌，关闭 {cancelled_tasks} 张未完成卡片"
        ),
    }


def _set_state(project_id: str, target: str, *, actor: str, reason: str | None, action: str) -> None:
    if target not in STATES:
        raise ControlError("unknown_run_state", f"{target} is not a run state")
    now = clock.now_utc()
    previous = state(project_id)
    with db.tx():
        db.execute(
            "UPDATE projects SET run_state = ?, run_state_changed_at = ?, run_state_reason = ?, updated_at = ?"
            " WHERE id = ?",
            (target, now, reason, now, project_id),
        )
        audit.record(
            "project_control",
            project_id=project_id,
            actor=actor,
            payload={"action": action, "from": previous, "to": target, "reason": reason},
        )


def _revoke_runs(project_id: str, *, actor: str, reason: str) -> list[str]:
    revoked: list[str] = []
    for row in db.query(
        "SELECT run_id FROM run_capabilities WHERE project_id = ? AND revoked_at IS NULL", (project_id,)
    ):
        run_id = str(row["run_id"])
        try:
            capabilities.revoke(run_id, reason=reason, actor=actor)
            revoked.append(run_id)
        except Exception:  # noqa: BLE001 - a token that is already gone is not a stop failure
            continue
    return revoked


def _close_agent_runs(project_id: str, *, reason: str) -> int:
    """Stop the clock on every run that is still open.

    ``agent_runs`` (migration 001) has ``ended_at``/``status``/``notes`` - the taskbook's
    ``termination_reason`` column was never added, so the reason is folded into ``notes``
    rather than invented as a new column here.
    """
    now = clock.now_utc()
    closed = 0
    for row in db.query(
        "SELECT id FROM agent_runs WHERE project_id = ? AND ended_at IS NULL", (project_id,)
    ):
        db.execute(
            "UPDATE agent_runs SET ended_at = ?, status = ?,"
            " notes = COALESCE(notes || ' ', '') || ? WHERE id = ?",
            (now, "cancelled", f"[termination_reason={reason}]", row["id"]),
        )
        closed += 1
    return closed


def _cancel_open_tasks(project_id: str, *, actor: str, reason: str) -> int:
    cancelled = 0
    for row in db.query(
        "SELECT id, status FROM tasks WHERE project_id = ? AND status NOT IN ('DONE','CANCELLED') ORDER BY created_at",
        (project_id,),
    ):
        try:
            # ``states.GUARDED_TARGETS`` only lets ``human``/``reviewer`` cancel a card, and the
            # authenticated subject may be a token id ("local-operator"). The operator *is* the
            # human here, so the state machine sees "human" while the audit keeps the real
            # subject in the reason.
            tasks_service.update(
                str(row["id"]),
                status="CANCELLED",
                actor="human",
                reason=f"{reason} (operator {actor})",
                fields={"error_code": "cancelled_by_operator", "error_message": reason},
            )
            cancelled += 1
        except Exception:  # noqa: BLE001 - a card that cannot move must not abort the stop
            continue
    return cancelled


# -- cooperative cancellation ------------------------------------------------


def cancel_requested(job_id: str) -> bool:
    """True when the operator asked this job (or its whole project) to stop."""
    row = db.one("SELECT cancel_requested, status FROM jobs WHERE id = ?", (job_id,))
    if row is None:
        return False
    return int(row["cancel_requested"] or 0) == 1 or str(row["status"]) == "CANCELLED"


def state_of(project_id: Any) -> str:
    if not project_id:
        return RUNNING
    row = db.one("SELECT run_state FROM projects WHERE id = ?", (str(project_id),))
    return str(row["run_state"] or RUNNING) if row else RUNNING


def checkpoint(job: dict) -> None:
    """Called by handlers between stages. Raises ``JobCancelled`` when a stop was requested."""
    job_id = str(job.get("id") or "")
    if not job_id:
        return
    row = db.one("SELECT cancel_requested, status FROM jobs WHERE id = ?", (job_id,))
    if row is None:
        raise JobCancelled(job_id, "job_row_missing")
    if int(row["cancel_requested"] or 0) == 1 or str(row["status"]) == "CANCELLED":
        raise JobCancelled(job_id)


def check_callable(job: dict):
    """A zero-argument callable handed to long-running services (pipeline, dynamic)."""
    return lambda: checkpoint(job)


# -- command box -------------------------------------------------------------

ACTIONS_ZH = {
    "暂停": "pause",
    "pause": "pause",
    "继续": "resume",
    "恢复": "resume",
    "resume": "resume",
    "停止": "stop",
    "stop": "stop",
    "halt": "stop",
}

_HELP = (
    "可用指令：暂停 / 继续 / 停止 / 状态 / 重试 <卡片ID> / 取消 <卡片ID> / 恢复未完成 "
    "（英文也认：pause、resume、stop、status、retry <id>、cancel <id>、recover）"
)


def command(project_id: str, text: str, *, actor: str = "human") -> dict[str, Any]:
    """Parse one line from the console command box."""
    raw = (text or "").strip()
    if not raw:
        raise ControlError("empty_command", _HELP, 422)
    parts = re.split(r"\s+", raw, maxsplit=1)
    verb = parts[0]
    argument = parts[1].strip() if len(parts) > 1 else ""
    lowered = verb.lower()

    if lowered in {"help", "帮助", "?"}:
        return {"ok": True, "action": "help", "message": _HELP}

    if lowered in {"状态", "status"}:
        snap = status(project_id)
        return {
            "ok": True,
            "action": "status",
            "message": (
                f"运行状态 {snap['run_state']}；待办作业 {snap['jobs']['pending']}，运行中 {snap['jobs']['running']}，"
                f"未完成卡片 {snap['tasks']['unfinished']}"
            ),
            "result": snap,
        }

    action = ACTIONS_ZH.get(verb) or ACTIONS_ZH.get(lowered)
    if action == "pause":
        return {**pause(project_id, actor=actor, reason=argument or "console command"), "ok": True, "action": action}
    if action == "resume":
        return {**resume(project_id, actor=actor, reason=argument or "console command"), "ok": True, "action": action}
    if action == "stop":
        return {**stop(project_id, actor=actor, reason=argument or "console command"), "ok": True, "action": action}

    if lowered in {"重试", "retry"}:
        task_id = _resolve_task(project_id, argument)
        current = str(tasks_service.get(task_id)["status"])
        if current == "CANCELLED":
            # CANCELLED is terminal by design (state.py): re-running cancelled work is a new
            # card, not a state flip, otherwise the audit trail would read like the stop
            # never happened.
            raise ControlError(
                "card_cancelled",
                "该卡片已被取消（终态），如需重跑请新建卡片或上传后再分析",
                409,
            )
        # REVIEW cannot go straight back to TODO, so pick whichever "restart" edge the card
        # actually has: TODO for FAILED/BLOCKED, RUNNING for a card that was under review.
        from .. import state as state_mod

        edges = state_mod.TRANSITIONS.get(current, set())
        target = "TODO" if "TODO" in edges else ("RUNNING" if "RUNNING" in edges else None)
        if target is None:
            raise ControlError("card_not_retryable", f"卡片当前状态 {current} 不支持重试", 409)
        tasks_service.update(
            task_id,
            status=target,
            actor=actor,
            reason="console retry",
        )
        queue_service.enqueue(
            "static_pipeline",
            project_id=project_id,
            task_id=task_id,
            payload={"source": "console_retry"},
            idempotency_key=f"retry:{project_id}:{task_id}:{clock.now_utc()}",
        )
        return {"ok": True, "action": "retry", "message": f"已把卡片 {task_id} 置为 {target} 并重新入队"}

    if lowered in {"取消", "cancel"}:
        task_id = _resolve_task(project_id, argument)
        tasks_service.update(task_id, status="CANCELLED", actor=actor, reason="console cancel")
        for row in db.query(
            "SELECT id FROM jobs WHERE task_id = ? AND status IN ('PENDING','RETRYING')", (task_id,)
        ):
            queue_service.cancel(str(row["id"]), actor=actor)
        return {"ok": True, "action": "cancel", "message": f"卡片 {task_id} 已取消"}

    if lowered in {"恢复未完成", "recover"}:
        from . import recovery  # local import: recovery imports queue, which imports this module's peers

        result = recovery.resume_project(project_id, actor=actor)
        return {
            "ok": True,
            "action": "recover",
            "message": f"已回收 {len(result['reclaimed'])} 个租约，重新入队 {len(result['enqueued'])} 个作业",
            "result": result,
        }

    raise ControlError("unknown_command", f"无法识别的指令「{verb}」。{_HELP}", 422)


def _resolve_task(project_id: str, argument: str) -> str:
    candidate = argument.strip()
    if not candidate:
        raise ControlError("task_required", "这条指令需要一个卡片 ID（或唯一的标题片段）", 422)
    row = db.one("SELECT id, project_id FROM tasks WHERE id = ?", (candidate,))
    if row is not None:
        if str(row["project_id"]) != project_id:
            raise ControlError("task_project_mismatch", "该卡片属于另一个项目", 403)
        return str(row["id"])
    matches = db.query(
        "SELECT id, title FROM tasks WHERE project_id = ? AND title LIKE ? LIMIT 5", (project_id, f"%{candidate}%")
    )
    if len(matches) == 1:
        return str(matches[0]["id"])
    if not matches:
        raise ControlError("task_not_found", f"找不到卡片「{candidate}」", 404)
    raise ControlError("task_ambiguous", f"「{candidate}」匹配到 {len(matches)} 张卡片，请用完整 ID", 422)
