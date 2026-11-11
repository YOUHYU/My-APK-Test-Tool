"""Review verdicts and bounded dispatch-back (P2).

A reviewer is not allowed to "just say no": every verdict is a row in ``task_checks``
(append-only), and a FAIL moves the card back to RUNNING at most ``retry_limit`` times.
After that the card is BLOCKED with an explicit reason so a human decides - the platform
never loops forever on a task the agent cannot fix.
"""

from __future__ import annotations

from typing import Any

from .. import audit
from ..db import db, utcnow
from ..state import TransitionError, validate_transition
from ..util import dumps, new_id
from . import events as events_service
from . import tasks as tasks_service

VERDICTS = ("PASS", "FAIL")
DEFAULT_RETRY_LIMIT = 2


class ReviewError(Exception):
    def __init__(self, code: str, message: str, status: int = 422) -> None:
        super().__init__(message)
        self.code = code
        self.message = message
        self.status = status

    def as_error(self) -> dict[str, Any]:
        return {"error_code": self.code, "message": self.message}


def record_check(
    project_id: str,
    task_id: str,
    *,
    verdict: str,
    criterion: str,
    detail: dict[str, Any] | None = None,
    run_id: str | None = None,
    actor: str = "reviewer",
) -> dict[str, Any]:
    verdict = str(verdict).upper()
    if verdict not in VERDICTS:
        raise ReviewError("invalid_verdict", f"verdict must be one of {VERDICTS}")
    task = db.one("SELECT * FROM tasks WHERE id = ?", (task_id,))
    if task is None:
        raise ReviewError("task_not_found", f"task {task_id} does not exist", 404)
    if task["project_id"] != project_id:
        raise ReviewError("project_denied", "task belongs to another project", 403)
    check_id = new_id("chk")
    with db.tx():
        db.execute(
            "INSERT INTO task_checks (id, project_id, task_id, run_id, verdict, criterion, detail_json, checked_by, checked_at)"
            " VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (check_id, project_id, task_id, run_id, verdict, criterion, dumps(detail or {}), actor, utcnow()),
        )
    events_service.emit(
        "task_check",
        project_id=project_id,
        task_id=task_id,
        payload={"verdict": verdict, "criterion": criterion, "check_id": check_id, "run_id": run_id},
    )
    audit.record(
        "task_check_recorded",
        project_id=project_id,
        task_id=task_id,
        actor=actor,
        payload={"check_id": check_id, "verdict": verdict, "criterion": criterion, "run_id": run_id},
    )
    return dict(db.one("SELECT * FROM task_checks WHERE id = ?", (check_id,)))


def checks(task_id: str) -> list[dict[str, Any]]:
    return [dict(row) for row in db.query("SELECT * FROM task_checks WHERE task_id = ? ORDER BY checked_at", (task_id,))]


def fail_count(task_id: str) -> int:
    return int(db.scalar("SELECT COUNT(*) FROM task_checks WHERE task_id = ? AND verdict = 'FAIL'", (task_id,), default=0) or 0)


def latest_verdict(task_id: str) -> str | None:
    row = db.one("SELECT verdict FROM task_checks WHERE task_id = ? ORDER BY checked_at DESC, id DESC LIMIT 1", (task_id,))
    return row["verdict"] if row else None


def verdict_summary(project_id: str) -> dict[str, Any]:
    rows = db.query(
        "SELECT task_id, SUM(CASE WHEN verdict='PASS' THEN 1 ELSE 0 END) AS passes,"
        " SUM(CASE WHEN verdict='FAIL' THEN 1 ELSE 0 END) AS fails"
        " FROM task_checks WHERE project_id = ? GROUP BY task_id",
        (project_id,),
    )
    return {row["task_id"]: {"pass": int(row["passes"] or 0), "fail": int(row["fails"] or 0)} for row in rows}


def dispatch_back(
    project_id: str,
    task_id: str,
    *,
    reason: str,
    run_id: str | None = None,
    actor: str = "reviewer",
    retry_limit: int = DEFAULT_RETRY_LIMIT,
) -> dict[str, Any]:
    """FAIL a reviewed card: back to RUNNING, or BLOCKED once the retry budget is spent."""
    task = db.one("SELECT * FROM tasks WHERE id = ?", (task_id,))
    if task is None:
        raise ReviewError("task_not_found", f"task {task_id} does not exist", 404)
    if task["project_id"] != project_id:
        raise ReviewError("project_denied", "task belongs to another project", 403)
    record_check(project_id, task_id, verdict="FAIL", criterion="review", detail={"reason": reason}, run_id=run_id, actor=actor)
    attempts = fail_count(task_id)
    if attempts > retry_limit:
        target = "BLOCKED"
        message = f"review failed {attempts} times (limit {retry_limit}): {reason}"
        error_code = "review_retry_exhausted"
    else:
        target = "RUNNING"
        message = f"returned to the agent ({attempts}/{retry_limit}): {reason}"
        error_code = "review_returned"
    try:
        validate_transition(task["status"], target, actor="reviewer", approved=False)
    except TransitionError as exc:
        raise ReviewError(exc.code, exc.message, 409) from exc
    updated = tasks_service.update(
        task_id,
        expected_version=int(task["version"]),
        status=target,
        fields={"error_code": error_code, "error_message": message, "retryable": True},
        actor="reviewer",
    )
    events_service.emit(
        "review",
        project_id=project_id,
        task_id=task_id,
        payload={"verdict": "FAIL", "target": target, "attempts": attempts, "reason": reason},
    )
    audit.record(
        "review_dispatch_back",
        project_id=project_id,
        task_id=task_id,
        actor=actor,
        payload={"target": target, "attempts": attempts, "retry_limit": retry_limit, "reason": reason},
    )
    return {"task": updated, "attempts": attempts, "retry_limit": retry_limit, "status": target, "message": message}


def accept(project_id: str, task_id: str, *, criterion: str = "review", run_id: str | None = None, actor: str = "reviewer") -> dict[str, Any]:
    record_check(project_id, task_id, verdict="PASS", criterion=criterion, run_id=run_id, actor=actor)
    events_service.emit("review", project_id=project_id, task_id=task_id, payload={"verdict": "PASS", "criterion": criterion})
    return {"task_id": task_id, "verdict": "PASS", "criterion": criterion}


def gate_report(project_id: str) -> dict[str, Any]:
    rows = db.query(
        "SELECT t.id, t.role, t.status,"
        " (SELECT COUNT(*) FROM task_checks c WHERE c.task_id = t.id AND c.verdict='PASS') AS passes,"
        " (SELECT COUNT(*) FROM task_checks c WHERE c.task_id = t.id AND c.verdict='FAIL') AS fails"
        " FROM tasks t WHERE t.project_id = ? ORDER BY t.created_at",
        (project_id,),
    )
    return {
        "project_id": project_id,
        "tasks": [
            {"id": row["id"], "role": row["role"], "status": row["status"], "pass": int(row["passes"]), "fail": int(row["fails"])}
            for row in rows
        ],
    }
