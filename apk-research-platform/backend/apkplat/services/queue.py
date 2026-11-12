"""Durable outbox queue with per-job leases (no in-process job scheduler).

A job is a row. Workers claim rows inside ``BEGIN IMMEDIATE`` so two processes
can never own the same job; leases expire and are reclaimed, which is what makes
"kill the worker mid-task and restart" observable and testable.
"""
from __future__ import annotations

from typing import Any, Iterable, Sequence

from .. import audit
from ..config import settings
from ..db import Row, db
from .. import clock
from ..util import dumps, loads, new_id

PENDING, RUNNING, SUCCEEDED, FAILED, RETRYING, CANCELLED = (
    "PENDING",
    "RUNNING",
    "SUCCEEDED",
    "FAILED",
    "RETRYING",
    "CANCELLED",
)


def enqueue(
    kind: str,
    *,
    project_id: str | None = None,
    task_id: str | None = None,
    payload: dict | None = None,
    idempotency_key: str | None = None,
    priority: int = 5,
    max_attempts: int = 3,
    delay_seconds: float = 0,
    actor: str = "system",
) -> str:
    with db.tx():
        if idempotency_key:
            existing = db.one("SELECT id, status FROM jobs WHERE idempotency_key = ?", (idempotency_key,))
            if existing:
                return str(existing["id"])
        job_id = new_id("job_")
        now = clock.now_utc()
        db.execute(
            "INSERT INTO jobs(id, project_id, task_id, kind, payload_json, status, idempotency_key, priority,"
            " attempt, max_attempts, available_at, created_at, updated_at)"
            " VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (
                job_id,
                project_id,
                task_id,
                kind,
                dumps(payload or {}),
                PENDING,
                idempotency_key or new_id("idem_"),
                priority,
                0,
                max_attempts,
                clock.iso_plus(delay_seconds),
                now,
                now,
            ),
        )
    audit.record(
        "job_enqueued",
        project_id=project_id,
        task_id=task_id,
        actor=actor,
        payload={"job_id": job_id, "kind": kind, "priority": priority, "idempotency_key": idempotency_key},
    )
    return job_id


def claim(worker_id: str, kinds: Sequence[str], lease_seconds: int | None = None) -> Row | None:
    lease = lease_seconds or settings.job_lease_seconds
    now = clock.now_utc()
    placeholders = ",".join("?" for _ in kinds)
    with db.tx():
        candidates = db.query(
            "SELECT j.* FROM jobs j LEFT JOIN projects p ON p.id = j.project_id"
            f" WHERE j.status IN ('PENDING','RETRYING') AND j.kind IN ({placeholders})"
            " AND j.available_at <= ? AND (p.id IS NULL OR p.run_state = 'RUNNING')"
            " ORDER BY j.priority ASC, j.available_at ASC, j.created_at ASC LIMIT 25",
            (*kinds, now),
        )
        row = None
        for candidate in candidates:
            task_id = candidate["task_id"]
            # Dependency gate (P2): a job whose card still waits on a prerequisite is not
            # claimable. It stays PENDING, so it runs by itself once the parent finishes -
            # no extra "wake up" path to keep in sync.
            if task_id and not _dependencies_satisfied(str(task_id), str(candidate["project_id"] or "")):
                continue
            row = candidate
            break
        if not row:
            return None
        db.execute(
            "UPDATE jobs SET status = ?, lease_owner = ?, lease_expires_at = ?, heartbeat_at = ?,"
            " attempt = attempt + 1, updated_at = ? WHERE id = ? AND status IN ('PENDING','RETRYING')",
            (RUNNING, worker_id, clock.iso_plus(lease), now, now, row["id"]),
        )
    claimed = get(str(row["id"]))
    if claimed:
        audit.record(
            "job_claimed",
            project_id=claimed["project_id"],
            task_id=claimed["task_id"],
            actor=worker_id,
            payload={"job_id": claimed["id"], "kind": claimed["kind"], "attempt": claimed["attempt"]},
        )
    return claimed


def _dependencies_satisfied(task_id: str, project_id: str) -> bool:
    """True when the card's prerequisites are all finished (see ``services.dag``).

    Only the *dependencies* are checked here - not the card's own status, which the worker
    legitimately flips to RUNNING before it does the work.
    """
    from . import dag as dag_service

    try:
        return dag_service.blocked_reason(task_id) is None
    except Exception:  # noqa: BLE001 - a broken graph must not wedge the queue
        audit.record(
            "dag_gate_error",
            project_id=project_id or None,
            task_id=task_id,
            actor="queue.claim",
            payload={"note": "dependency check raised; job released this round"},
        )
        return True


def get(job_id: str) -> Row | None:
    row = db.one("SELECT * FROM jobs WHERE id = ?", (job_id,))
    if row:
        row["payload"] = loads(row["payload_json"], {})
        row["result"] = loads(row["result_json"], {})
    return row


def heartbeat(job_id: str, worker_id: str, lease_seconds: int | None = None) -> None:
    lease = lease_seconds or settings.job_lease_seconds
    with db.tx():
        db.execute(
            "UPDATE jobs SET heartbeat_at = ?, lease_expires_at = ?, updated_at = ?"
            " WHERE id = ? AND lease_owner = ? AND status = ?",
            (clock.now_utc(), clock.iso_plus(lease), clock.now_utc(), job_id, worker_id, RUNNING),
        )


def attach_task(job_id: str, task_id: str) -> None:
    """Bind a job to a task created *by* the handler (auto-created tasks).

    Without this the job row keeps ``task_id = NULL``, so a later failure cannot mark
    the task it just created, and the card would sit in RUNNING forever.
    """
    if not task_id:
        return
    db.execute("UPDATE jobs SET task_id = ?, updated_at = ? WHERE id = ?", (task_id, clock.now_utc(), job_id))


def complete(job_id: str, result: dict | None = None, worker_id: str | None = None) -> None:
    with db.tx():
        db.execute(
            "UPDATE jobs SET status = ?, result_json = ?, lease_owner = NULL, lease_expires_at = NULL,"
            " updated_at = ? WHERE id = ?",
            (SUCCEEDED, dumps(result or {}), clock.now_utc(), job_id),
        )
    row = get(job_id)
    audit.record(
        "job_succeeded",
        project_id=row["project_id"] if row else None,
        task_id=row["task_id"] if row else None,
        actor=worker_id or "system",
        payload={"job_id": job_id, "attempt": row["attempt"] if row else None, "result": result or {}},
    )


def fail(
    job_id: str,
    error_code: str,
    error_message: str,
    *,
    retryable: bool = True,
    worker_id: str | None = None,
) -> str:
    """Return the resulting status (RETRYING or FAILED)."""
    with db.tx():
        row = db.one("SELECT * FROM jobs WHERE id = ?", (job_id,))
        if not row:
            raise KeyError(job_id)
        will_retry = retryable and int(row["attempt"]) < int(row["max_attempts"])
        backoff = min(5 * (2 ** max(int(row["attempt"]) - 1, 0)), 300)
        new_status = RETRYING if will_retry else FAILED
        db.execute(
            "UPDATE jobs SET status = ?, error_code = ?, error_message = ?, available_at = ?,"
            " lease_owner = NULL, lease_expires_at = NULL, updated_at = ? WHERE id = ?",
            (
                new_status,
                error_code,
                error_message[:2000],
                clock.iso_plus(backoff if will_retry else 0),
                clock.now_utc(),
                job_id,
            ),
        )
    audit.record(
        "job_failed" if not will_retry else "job_retry_scheduled",
        project_id=row["project_id"],
        task_id=row["task_id"],
        actor=worker_id or "system",
        payload={
            "job_id": job_id,
            "error_code": error_code,
            "error_message": error_message[:500],
            "attempt": row["attempt"],
            "max_attempts": row["max_attempts"],
            "backoff_seconds": backoff if will_retry else 0,
        },
    )
    return new_status


def reclaim_expired(worker_id: str = "reaper") -> list[dict]:
    now = clock.now_utc()
    reclaimed: list[dict] = []
    with db.tx():
        rows = db.query(
            "SELECT * FROM jobs WHERE status = ? AND lease_expires_at IS NOT NULL AND lease_expires_at < ?",
            (RUNNING, now),
        )
        for row in rows:
            exhausted = int(row["attempt"]) >= int(row["max_attempts"])
            status = FAILED if exhausted else RETRYING
            db.execute(
                "UPDATE jobs SET status = ?, lease_owner = NULL, lease_expires_at = NULL,"
                " available_at = ?, updated_at = ?, error_code = ?, error_message = ? WHERE id = ?",
                (
                    status,
                    clock.iso_plus(0),
                    now,
                    "lease_expired",
                    f"worker {row['lease_owner']} stopped heartbeating",
                    row["id"],
                ),
            )
            reclaimed.append({"job_id": row["id"], "status": status, "previous_owner": row["lease_owner"]})
    for item in reclaimed:
        job = get(item["job_id"])
        audit.record(
            "job_lease_reclaimed",
            project_id=job["project_id"] if job else None,
            task_id=job["task_id"] if job else None,
            actor=worker_id,
            payload=item,
        )
    return reclaimed


def cancel(job_id: str, actor: str = "human") -> None:
    with db.tx():
        db.execute("UPDATE jobs SET status = ?, updated_at = ? WHERE id = ?", (CANCELLED, clock.now_utc(), job_id))
    job = get(job_id)
    audit.record(
        "job_cancelled",
        project_id=job["project_id"] if job else None,
        task_id=job["task_id"] if job else None,
        actor=actor,
        payload={"job_id": job_id},
    )


def list_jobs(project_id: str | None = None, status: str | None = None, limit: int = 100) -> list[Row]:
    sql = "SELECT * FROM jobs WHERE 1=1"
    params: list[Any] = []
    if project_id:
        sql += " AND project_id = ?"
        params.append(project_id)
    if status:
        sql += " AND status = ?"
        params.append(status)
    sql += " ORDER BY created_at DESC LIMIT ?"
    params.append(limit)
    rows = db.query(sql, params)
    for row in rows:
        row["payload"] = loads(row["payload_json"], {})
        row["result"] = loads(row["result_json"], {})
    return rows


def stats() -> dict[str, int]:
    rows = db.query("SELECT status, COUNT(*) AS n FROM jobs GROUP BY status")
    return {row["status"]: int(row["n"]) for row in rows}


def pending_for_project(project_id: str) -> int:
    return int(
        db.scalar(
            "SELECT COUNT(*) FROM jobs WHERE project_id = ? AND status IN ('PENDING','RUNNING','RETRYING')",
            (project_id,),
            default=0,
        )
        or 0
    )
