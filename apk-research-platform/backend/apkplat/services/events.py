"""Append-only platform event log (P2).

The audit log records *who did what to the platform*; this log is the dashboard feed:
one row per visible transition, with a monotonic ``seq`` so an SSE client can resume with
``Last-Event-ID`` and never miss or duplicate a card change.

Dedupe keys exist because a worker may be retried after a crash: the same logical event
("job 12 finished") must appear once even if two attempts race.
"""

from __future__ import annotations

import sqlite3
from typing import Any, Iterable

from ..db import db, utcnow
from ..util import dumps, loads

EVENT_TYPES = (
    "project_created",
    "task_created",
    "task_status",
    "task_edge",
    "task_check",
    "job_status",
    "run_started",
    "run_finished",
    "evidence",
    "review",
    "device",
    "note",
)


def emit(
    event_type: str,
    *,
    project_id: str | None = None,
    task_id: str | None = None,
    payload: dict[str, Any] | None = None,
    dedupe_key: str | None = None,
) -> int:
    """Append one event; returns its seq. A duplicate dedupe_key is a no-op."""
    row = db.one(
        "INSERT INTO platform_events (project_id, task_id, type, dedupe_key, payload_json, created_at)"
        " VALUES (?, ?, ?, ?, ?, ?) RETURNING seq",
        (project_id, task_id, event_type, dedupe_key, dumps(payload or {}), utcnow()),
    )
    return int(row["seq"]) if row else 0


def emit_once(
    event_type: str,
    *,
    project_id: str | None = None,
    task_id: str | None = None,
    payload: dict[str, Any] | None = None,
    dedupe_key: str,
) -> tuple[int, bool]:
    """Append unless the dedupe_key was already used. Returns (seq, created)."""
    existing = db.one("SELECT seq FROM platform_events WHERE dedupe_key = ?", (dedupe_key,))
    if existing:
        return int(existing["seq"]), False
    try:
        return emit(event_type, project_id=project_id, task_id=task_id, payload=payload, dedupe_key=dedupe_key), True
    except sqlite3.IntegrityError:  # lost a race with another writer; the first one wins
        row = db.one("SELECT seq FROM platform_events WHERE dedupe_key = ?", (dedupe_key,))
        return int(row["seq"]), False


def _row_to_event(row) -> dict[str, Any]:
    return {
        "seq": int(row["seq"]),
        "type": row["type"],
        "project_id": row["project_id"],
        "task_id": row["task_id"],
        "payload": loads(row["payload_json"], {}),
        "created_at": row["created_at"],
    }


def tail(after_seq: int = 0, project_id: str | None = None, limit: int = 200) -> list[dict[str, Any]]:
    if project_id:
        rows = db.query(
            "SELECT * FROM platform_events WHERE seq > ? AND project_id = ? ORDER BY seq LIMIT ?",
            (int(after_seq), project_id, int(limit)),
        )
    else:
        rows = db.query("SELECT * FROM platform_events WHERE seq > ? ORDER BY seq LIMIT ?", (int(after_seq), int(limit)))
    return [_row_to_event(row) for row in rows]


def last_seq() -> int:
    return int(db.scalar("SELECT COALESCE(MAX(seq), 0) FROM platform_events", default=0) or 0)


def count(event_type: str | None = None, project_id: str | None = None) -> int:
    sql = "SELECT COUNT(*) FROM platform_events WHERE 1=1"
    params: list[Any] = []
    if event_type:
        sql += " AND type = ?"
        params.append(event_type)
    if project_id:
        sql += " AND project_id = ?"
        params.append(project_id)
    return int(db.scalar(sql, tuple(params), default=0) or 0)


def types_seen(project_id: str | None = None) -> Iterable[str]:
    rows = db.query(
        "SELECT DISTINCT type FROM platform_events" + (" WHERE project_id = ?" if project_id else "") + " ORDER BY type",
        (project_id,) if project_id else (),
    )
    return [row["type"] for row in rows]
