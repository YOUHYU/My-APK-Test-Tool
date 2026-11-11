"""Append-only audit trail. Rows are never updated or deleted."""
from __future__ import annotations

from typing import Any

from .db import Row, db, utcnow
from .util import dumps, loads, new_id


def record(
    event_type: str,
    *,
    project_id: str | None = None,
    task_id: str | None = None,
    actor: str = "system",
    payload: Any = None,
) -> dict:
    with db.tx():
        seq = db.alloc_seq("audit")
        event_id = new_id("ev_")
        db.execute(
            "INSERT INTO audit_events(id, seq, project_id, task_id, event_type, actor, payload_json, created_at)"
            " VALUES(?,?,?,?,?,?,?,?)",
            (event_id, seq, project_id, task_id, event_type, actor, dumps(payload or {}), utcnow()),
        )
    return {
        "id": event_id,
        "seq": seq,
        "project_id": project_id,
        "task_id": task_id,
        "event_type": event_type,
        "actor": actor,
        "payload": payload or {},
        "created_at": utcnow(),
    }


def tail(after_seq: int = 0, project_id: str | None = None, limit: int = 200) -> list[Row]:
    if project_id:
        rows = db.query(
            "SELECT * FROM audit_events WHERE seq > ? AND project_id = ? ORDER BY seq ASC LIMIT ?",
            (after_seq, project_id, limit),
        )
    else:
        rows = db.query("SELECT * FROM audit_events WHERE seq > ? ORDER BY seq ASC LIMIT ?", (after_seq, limit))
    for row in rows:
        row["payload"] = loads(row.get("payload_json"), {})
    return rows


def last_seq() -> int:
    return int(db.scalar("SELECT COALESCE(MAX(seq),0) FROM audit_events", default=0) or 0)
