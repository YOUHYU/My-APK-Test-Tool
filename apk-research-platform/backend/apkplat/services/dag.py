"""Dependency DAG for tasks (P2).

`tasks.depends_on` (a JSON list of task ids) remains the input format the old API accepts;
this module keeps an edge table in sync and answers the only question the scheduler asks:
*are all of this task's prerequisites finished?*

Design rules that came from the taskbook and from what the P0 audit found:

* an edge lives inside one project - a cross-project edge is a security error, not a
  modelling one;
* self loops and cycles are refused at insert time, so a poisoned graph cannot freeze the
  queue later;
* ``ready()`` is derived, never stored: a task is ready when it is in a claimable state and
  every parent is DONE (or has an explicit PASS check). Storing readiness would let it
  drift away from the truth after a restart.
"""

from __future__ import annotations

from typing import Any, Iterable, Sequence

from .. import audit
from ..db import db, utcnow
from ..state import STATUSES, TERMINAL
from ..util import dumps, loads, new_id

CLAIMABLE = ("TODO", "RETRYING", "STALE")
SATISFIED = ("DONE",)


class DagError(Exception):
    def __init__(self, code: str, message: str, status: int = 422) -> None:
        super().__init__(message)
        self.code = code
        self.message = message
        self.status = status

    def as_error(self) -> dict[str, Any]:
        return {"error_code": self.code, "message": self.message}


def _task(task_id: str):
    row = db.one("SELECT * FROM tasks WHERE id = ?", (task_id,))
    if row is None:
        raise DagError("task_not_found", f"task {task_id} does not exist", 404)
    return row


def add_edge(project_id: str, from_task_id: str, to_task_id: str, kind: str = "blocks", actor: str = "system") -> dict[str, Any]:
    """Record that ``from_task_id`` must finish before ``to_task_id`` may start."""
    if from_task_id == to_task_id:
        raise DagError("self_edge", "a task cannot depend on itself")
    source = _task(from_task_id)
    target = _task(to_task_id)
    for label, row in (("from", source), ("to", target)):
        if row["project_id"] != project_id:
            raise DagError("cross_project_edge", f"{label} task {row['id']} belongs to another project", 403)
    if kind != "blocks":
        raise DagError("unsupported_edge_kind", f"edge kind {kind!r} is not supported")
    if would_cycle(project_id, from_task_id, to_task_id):
        raise DagError("cycle_detected", f"{from_task_id} -> {to_task_id} closes a cycle")
    existing = db.one(
        "SELECT * FROM task_edges WHERE project_id = ? AND from_task_id = ? AND to_task_id = ? AND kind = ?",
        (project_id, from_task_id, to_task_id, kind),
    )
    if existing:
        return dict(existing)
    edge_id = new_id("edg")
    with db.tx():
        db.execute(
            "INSERT INTO task_edges (id, project_id, from_task_id, to_task_id, kind, created_at)"
            " VALUES (?, ?, ?, ?, ?, ?)",
            (edge_id, project_id, from_task_id, to_task_id, kind, utcnow()),
        )
    audit.record(
        "task_edge_added",
        project_id=project_id,
        task_id=to_task_id,
        actor=actor,
        payload={"from": from_task_id, "to": to_task_id, "kind": kind},
    )
    return dict(db.one("SELECT * FROM task_edges WHERE id = ?", (edge_id,)))


def remove_edge(project_id: str, from_task_id: str, to_task_id: str, kind: str = "blocks", actor: str = "system") -> bool:
    with db.tx():
        changed = db.execute(
            "DELETE FROM task_edges WHERE project_id = ? AND from_task_id = ? AND to_task_id = ? AND kind = ?",
            (project_id, from_task_id, to_task_id, kind),
        )
    changed = int(changed or 0)
    if changed:
        audit.record(
            "task_edge_removed",
            project_id=project_id,
            task_id=to_task_id,
            actor=actor,
            payload={"from": from_task_id, "to": to_task_id, "kind": kind},
        )
    return bool(changed)


def parents(task_id: str) -> list[str]:
    return [row["from_task_id"] for row in db.query("SELECT from_task_id FROM task_edges WHERE to_task_id = ?", (task_id,))]


def children(task_id: str) -> list[str]:
    return [row["to_task_id"] for row in db.query("SELECT from_task_id, to_task_id FROM task_edges WHERE from_task_id = ?", (task_id,))]


def edges(project_id: str) -> list[dict[str, Any]]:
    return [dict(row) for row in db.query("SELECT * FROM task_edges WHERE project_id = ? ORDER BY created_at", (project_id,))]


def would_cycle(project_id: str, from_task_id: str, to_task_id: str) -> bool:
    """True when adding from->to would close a loop (walk forward from ``to``)."""
    seen: set[str] = set()
    stack = [to_task_id]
    while stack:
        node = stack.pop()
        if node == from_task_id:
            return True
        if node in seen:
            continue
        seen.add(node)
        stack.extend(
            row["to_task_id"]
            for row in db.query(
                "SELECT to_task_id FROM task_edges WHERE project_id = ? AND from_task_id = ?", (project_id, node)
            )
        )
    return False


def unmet_parents(task_id: str) -> list[dict[str, str]]:
    """Parents that are not finished yet, with the reason each one blocks.

    A parent counts as finished when its card is DONE or when a reviewer recorded a PASS
    check for it: the taskbook wants "PASS 才放行", and a PASS is the machine-readable form
    of that decision.
    """
    blocking: list[dict[str, str]] = []
    for parent_id in parents(task_id):
        row = db.one("SELECT id, role, status, title FROM tasks WHERE id = ?", (parent_id,))
        if row is None:
            blocking.append({"task_id": parent_id, "status": "MISSING", "reason": "parent task was deleted"})
            continue
        if row["status"] in SATISFIED:
            continue
        if _has_pass(parent_id):
            continue
        blocking.append({"task_id": parent_id, "status": row["status"], "reason": f"parent {parent_id} is {row['status']}"})
    return blocking


def _has_pass(task_id: str) -> bool:
    row = db.one(
        "SELECT verdict FROM task_checks WHERE task_id = ? ORDER BY checked_at DESC, id DESC LIMIT 1",
        (task_id,),
    )
    return bool(row and row["verdict"] == "PASS")


def ready(task_id: str) -> bool:
    row = db.one("SELECT status FROM tasks WHERE id = ?", (task_id,))
    if row is None or row["status"] not in CLAIMABLE:
        return False
    return not unmet_parents(task_id)


def blocked_reason(task_id: str) -> str | None:
    unmet = unmet_parents(task_id)
    if not unmet:
        return None
    return "waiting_on:" + ",".join(sorted(item["task_id"] for item in unmet))


def graph(project_id: str) -> dict[str, Any]:
    tasks = [dict(row) for row in db.query("SELECT id, role, status, title, parent_task_id FROM tasks WHERE project_id = ?", (project_id,))]
    known = {task["id"] for task in tasks}
    relations = []
    dangling = []
    for edge in edges(project_id):
        if edge["from_task_id"] not in known or edge["to_task_id"] not in known:
            dangling.append(edge)
            continue
        relations.append(edge)
    return {
        "project_id": project_id,
        "nodes": tasks,
        "edges": relations,
        "dangling_edges": dangling,
        "ready": sorted(task["id"] for task in tasks if ready(task["id"])),
        "blocked": {task["id"]: blocked_reason(task["id"]) for task in tasks if blocked_reason(task["id"])},
    }


def sync_depends_on(project_id: str, task_id: str, depends_on: Iterable[str] | None, actor: str = "system") -> None:
    """Mirror a ``depends_on`` list into edges (the double-write window of M2).

    The legacy column stays authoritative for readers that have not been upgraded, so we
    never rewrite it here - we only add or drop edges until both agree.
    """
    wanted = {str(value) for value in (depends_on or []) if str(value)}
    current = set(parents(task_id))
    for parent_id in sorted(wanted - current):
        add_edge(project_id, parent_id, task_id, actor=actor)
    for parent_id in sorted(current - wanted):
        remove_edge(project_id, parent_id, task_id, actor=actor)


def backfill(project_id: str | None = None, actor: str = "migration:p2") -> dict[str, Any]:
    """M1: build edges from the legacy column and verify nothing was lost."""
    sql = "SELECT id, project_id, depends_on FROM tasks"
    params: Sequence[Any] = ()
    if project_id:
        sql += " WHERE project_id = ?"
        params = (project_id,)
    created = 0
    skipped = 0
    invalid: list[dict[str, str]] = []
    for row in db.query(sql, params):
        depends = loads(row["depends_on"], []) or []
        if isinstance(depends, str):
            depends = [depends]
        if not isinstance(depends, list):
            invalid.append({"task_id": row["id"], "reason": "depends_on is not a list"})
            continue
        for parent_id in depends:
            parent = db.one("SELECT id, project_id FROM tasks WHERE id = ?", (str(parent_id),))
            if parent is None:
                invalid.append({"task_id": row["id"], "parent": str(parent_id), "reason": "parent not found"})
                continue
            if parent["project_id"] != row["project_id"]:
                invalid.append({"task_id": row["id"], "parent": str(parent_id), "reason": "parent in another project"})
                continue
            before = len(edges(row["project_id"]))
            try:
                add_edge(row["project_id"], str(parent_id), row["id"], actor=actor)
            except DagError as exc:
                invalid.append({"task_id": row["id"], "parent": str(parent_id), "reason": exc.code})
                continue
            created += len(edges(row["project_id"])) - before
        skipped += 1
    result = {"tasks_scanned": skipped, "edges_created": created, "invalid": invalid}
    audit.record("dag_backfill", project_id=project_id, actor=actor, payload=result)
    return result


def verify_against_legacy(project_id: str) -> dict[str, Any]:
    """Compare edges with ``depends_on`` for every task; used by the M1 gate."""
    mismatches = []
    for row in db.query("SELECT id, depends_on FROM tasks WHERE project_id = ?", (project_id,)):
        declared = {str(value) for value in (loads(row["depends_on"], []) or [])}
        actual = set(parents(row["id"]))
        if declared != actual:
            mismatches.append({"task_id": row["id"], "depends_on": sorted(declared), "edges": sorted(actual)})
    return {"project_id": project_id, "tasks": len(db.query("SELECT id FROM tasks WHERE project_id = ?", (project_id,))), "mismatches": mismatches, "ok": not mismatches}


def status_index() -> dict[str, int]:
    return {status: int(db.scalar("SELECT COUNT(*) FROM tasks WHERE status = ?", (status,), default=0) or 0) for status in STATUSES}


def check_statuses() -> list[str]:
    return sorted({row["status"] for row in db.query("SELECT status FROM tasks")})


def terminal_statuses() -> list[str]:
    return sorted(TERMINAL)
