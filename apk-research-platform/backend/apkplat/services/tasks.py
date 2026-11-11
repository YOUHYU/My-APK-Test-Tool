"""Task lifecycle: validated transitions, optimistic concurrency, approvals."""
from __future__ import annotations

from typing import Any, Iterable

from .. import audit
from ..db import Row, db, utcnow
from ..state import TERMINAL, TransitionError, column_of, validate_transition
from ..util import dumps, loads, new_id

EDITABLE_FIELDS = {
    "title": "title",
    "goal": "goal",
    "summary": "summary",
    "progress": "progress",
    "priority": "priority",
    "depends_on": "depends_on",
    "error_code": "error_code",
    "error_message": "error_message",
    "retryable": "retryable",
    "needs_approval": "needs_approval",
    "lease_owner": "lease_owner",
    "lease_expires_at": "lease_expires_at",
}


class TaskConflict(RuntimeError):
    def __init__(self, message: str, current: Row | None = None) -> None:
        super().__init__(message)
        self.current = current


class ApprovalNotFound(RuntimeError):
    """Raised when an approval id does not exist (mapped to HTTP 404)."""

    def __init__(self, approval_id: str) -> None:
        super().__init__(f"approval not found: {approval_id}")
        self.approval_id = approval_id


def create(
    project_id: str,
    *,
    role: str,
    title: str,
    goal: str | None = None,
    parent_task_id: str | None = None,
    depends_on: Iterable[str] | None = None,
    priority: int = 5,
    status: str = "TODO",
    actor: str = "system",
    needs_approval: bool = False,
) -> Row:
    task_id = new_id("tsk_")
    now = utcnow()
    with db.tx():
        db.execute(
            "INSERT INTO tasks(id, project_id, parent_task_id, role, title, goal, status, priority, depends_on,"
            " summary, progress, attempt, version, created_at, updated_at, needs_approval)"
            " VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (
                task_id,
                project_id,
                parent_task_id,
                role,
                title,
                goal,
                status,
                priority,
                dumps(list(depends_on or [])),
                None,
                0.0,
                0,
                1,
                now,
                now,
                1 if needs_approval else 0,
            ),
        )
    audit.record(
        "task_created",
        project_id=project_id,
        task_id=task_id,
        actor=actor,
        payload={"role": role, "title": title, "priority": priority, "depends_on": list(depends_on or [])},
    )
    # Double-write window (P2 M2): the legacy column stays authoritative for old readers,
    # and the edge table is mirrored so the scheduler can gate on it.
    if depends_on:
        from . import dag as dag_service

        dag_service.sync_depends_on(project_id, task_id, list(depends_on), actor=actor)
    from . import events as events_service

    events_service.emit(
        "task_created",
        project_id=project_id,
        task_id=task_id,
        payload={"role": role, "title": title, "status": status, "depends_on": list(depends_on or [])},
    )
    return get(task_id)  # type: ignore[return-value]


def get(task_id: str) -> Row | None:
    row = db.one("SELECT * FROM tasks WHERE id = ?", (task_id,))
    if row:
        row["depends_on"] = loads(row["depends_on"], [])
    return row


def list_tasks(project_id: str, status: str | None = None, role: str | None = None) -> list[Row]:
    sql = "SELECT * FROM tasks WHERE project_id = ?"
    params: list[Any] = [project_id]
    if status:
        sql += " AND status = ?"
        params.append(status)
    if role:
        sql += " AND role = ?"
        params.append(role)
    sql += " ORDER BY priority ASC, created_at ASC"
    rows = db.query(sql, params)
    for row in rows:
        row["depends_on"] = loads(row["depends_on"], [])
    return rows


def update(
    task_id: str,
    *,
    actor: str = "agent",
    status: str | None = None,
    fields: dict[str, Any] | None = None,
    expected_version: int | None = None,
    approval_id: str | None = None,
    reason: str | None = None,
) -> Row:
    current = get(task_id)
    if not current:
        raise KeyError(f"task {task_id} not found")
    if expected_version is not None and int(current["version"]) != int(expected_version):
        raise TaskConflict(
            f"version conflict: expected {expected_version}, current {current['version']}", current
        )
    approved = False
    if approval_id:
        approval = db.one("SELECT * FROM approvals WHERE id = ?", (approval_id,))
        if not approval or approval["decision"] != "approved":
            raise TransitionError("approval_missing", f"approval {approval_id} not approved")
        approved = True
    if status:
        validate_transition(current["status"], status, actor=actor, approved=approved)

    sets: list[str] = []
    params: list[Any] = []
    if status:
        sets.append("status = ?")
        params.append(status)
        if status in TERMINAL:
            sets.append("finished_at = ?")
            params.append(utcnow())
        if status not in ("RUNNING",):
            sets.append("lease_owner = NULL")
            sets.append("lease_expires_at = NULL")
    for key, value in (fields or {}).items():
        column = EDITABLE_FIELDS.get(key)
        if not column:
            raise ValueError(f"field {key!r} is not editable through this API")
        if key == "depends_on":
            value = dumps(value)
        elif key == "retryable" or key == "needs_approval":
            value = 1 if value else 0
        sets.append(f"{column} = ?")
        params.append(value)
    if not sets:
        return current
    sets.append("version = version + 1")
    sets.append("updated_at = ?")
    params.append(utcnow())
    if status == "RUNNING":
        sets.append("attempt = attempt + 1")
    params.append(task_id)
    with db.tx():
        db.execute(f"UPDATE tasks SET {', '.join(sets)} WHERE id = ?", params)
    updated = get(task_id)
    assert updated is not None
    audit.record(
        "task_updated" if not status else "task_status_changed",
        project_id=updated["project_id"],
        task_id=task_id,
        actor=actor,
        payload={
            "from": current["status"],
            "to": updated["status"],
            "fields": sorted((fields or {}).keys()),
            "reason": reason,
            "version": updated["version"],
            "approval_id": approval_id,
        },
    )
    if status and status != current["status"]:
        from . import events as events_service

        events_service.emit(
            "task_status",
            project_id=updated["project_id"],
            task_id=task_id,
            payload={"from": current["status"], "to": updated["status"], "reason": reason, "actor": actor},
        )
    if "depends_on" in (fields or {}):
        from . import dag as dag_service

        dag_service.sync_depends_on(updated["project_id"], task_id, list(fields.get("depends_on") or []), actor=actor)
    return updated


def record_run(
    task_id: str,
    *,
    role: str,
    model_id: str | None = None,
    dsh_session_ref: str | None = None,
    notes: str | None = None,
) -> str:
    task = get(task_id)
    run_id = new_id("run_")
    with db.tx():
        db.execute(
            "INSERT INTO agent_runs(id, project_id, task_id, role, dsh_session_ref, model_id, started_at, status, notes)"
            " VALUES(?,?,?,?,?,?,?,?,?)",
            (
                run_id,
                task["project_id"] if task else None,
                task_id,
                role,
                dsh_session_ref,
                model_id,
                utcnow(),
                "running",
                notes,
            ),
        )
        db.execute("UPDATE tasks SET model_calls = model_calls + 1, updated_at = ? WHERE id = ?", (utcnow(), task_id))
    return run_id


def close_run(run_id: str, status: str = "completed", notes: str | None = None) -> None:
    with db.tx():
        db.execute(
            "UPDATE agent_runs SET ended_at = ?, status = ?, notes = COALESCE(?, notes) WHERE id = ?",
            (utcnow(), status, notes, run_id),
        )


def incr_counters(task_id: str, *, model_calls: int = 0, tool_calls: int = 0, evidence: int = 0) -> None:
    with db.tx():
        db.execute(
            "UPDATE tasks SET model_calls = model_calls + ?, tool_calls = tool_calls + ?,"
            " evidence_count = evidence_count + ?, updated_at = ? WHERE id = ?",
            (model_calls, tool_calls, evidence, utcnow(), task_id),
        )


# ---------------------------------------------------------------------------
# approvals
# ---------------------------------------------------------------------------
def request_approval(
    project_id: str, *, task_id: str | None, kind: str, requested_by: str, reason: str | None = None
) -> str:
    approval_id = new_id("apr_")
    with db.tx():
        db.execute(
            "INSERT INTO approvals(id, project_id, task_id, kind, requested_by, reason, decision, created_at)"
            " VALUES(?,?,?,?,?,?,?,?)",
            (approval_id, project_id, task_id, kind, requested_by, reason, "pending", utcnow()),
        )
    audit.record(
        "approval_requested",
        project_id=project_id,
        task_id=task_id,
        actor=requested_by,
        payload={"approval_id": approval_id, "kind": kind, "reason": reason},
    )
    return approval_id


def decide_approval(approval_id: str, decision: str, decided_by: str, note: str | None = None) -> Row:
    if decision not in ("approved", "rejected"):
        raise ValueError("decision must be approved|rejected")
    with db.tx():
        db.execute(
            "UPDATE approvals SET decision = ?, decided_by = ?, decided_at = ? WHERE id = ? AND decision = 'pending'",
            (decision, decided_by, utcnow(), approval_id),
        )
    row = db.one("SELECT * FROM approvals WHERE id = ?", (approval_id,))
    if not row:
        raise ApprovalNotFound(approval_id)
    audit.record(
        "approval_decided",
        project_id=row["project_id"],
        task_id=row["task_id"],
        actor=decided_by,
        payload={"approval_id": approval_id, "decision": decision, "note": note},
    )
    return row


def pending_approvals(project_id: str) -> list[Row]:
    return db.query(
        "SELECT * FROM approvals WHERE project_id = ? AND decision = 'pending' ORDER BY created_at ASC",
        (project_id,),
    )


def board_column(status: str) -> str:
    return column_of(status)
