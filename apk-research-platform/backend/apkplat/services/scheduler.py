"""The only scheduler: periodic jobs, test identities, and a single daily window.

Design notes that matter for the acceptance run:

* the scheduler is *pull* based - `tick()` looks at `next_due_at` and does the work, so a
  crash simply means the next tick does it (and the window uniqueness makes "twice" impossible);
* the run row is claimed **before** the task is created. A crash in between leaves
  `result='pending'` for a human to inspect instead of a duplicated task;
* refusals (identity busy, resources) are recorded as attempts and do *not* consume the day;
* test identities are references, never secrets: the row stores `secret_ref` only.
"""

from __future__ import annotations

from typing import Any

from .. import audit, clock, resources
from ..config import settings
from ..db import Row, db
from ..util import dumps, new_id
from . import queue as queue_service
from . import tasks as tasks_service


class SchedulerError(Exception):
    def __init__(self, code: str, message: str, status: int = 400, detail: dict | None = None) -> None:
        super().__init__(message)
        self.code = code
        self.message = message
        self.status = status
        self.detail = detail or {}

    def as_error(self) -> dict[str, Any]:
        return {"error_code": self.code, "message": self.message}


IDENTITY_KINDS = ("test_account", "fixture")
TRIGGERED = "triggered"
BLOCKED = "RESOURCE_BLOCKED"
IDENTITY_BUSY = "IDENTITY_BUSY"
DUPLICATE = "DUPLICATE_WINDOW"


# -- test identities ----------------------------------------------------


def add_identity(
    project_id: str,
    label: str,
    *,
    kind: str = "test_account",
    secret_ref: str | None = None,
    note: str | None = None,
    actor: str = "human",
) -> Row:
    """Register a test identity by reference.

    Only identities the operator owns or created on their own test backend are allowed;
    there is deliberately no bulk-registration path and no third-party account handling.
    """
    if kind not in IDENTITY_KINDS:
        raise SchedulerError("unsupported_identity_kind", f"identity kind must be one of {IDENTITY_KINDS}", 422)
    if not label.strip():
        raise SchedulerError("label_required", "label is required", 422)
    identity_id = new_id("tid_")
    with db.tx():
        db.execute(
            "INSERT INTO test_identities(id, project_id, label, kind, secret_ref, status, note, created_at)"
            " VALUES(?,?,?,?,?,?,?,?)",
            (identity_id, project_id, label.strip(), kind, secret_ref, "active", note, clock.now_utc()),
        )
    audit.record(
        "test_identity_registered",
        project_id=project_id,
        actor=actor,
        payload={"identity_id": identity_id, "kind": kind, "has_secret_ref": bool(secret_ref)},
    )
    return get_identity(identity_id)  # type: ignore[return-value]


def get_identity(identity_id: str) -> Row | None:
    return db.one("SELECT * FROM test_identities WHERE id = ?", (identity_id,))


def list_identities(project_id: str | None = None) -> list[Row]:
    if project_id:
        return db.query("SELECT * FROM test_identities WHERE project_id = ? ORDER BY created_at", (project_id,))
    return db.query("SELECT * FROM test_identities ORDER BY created_at")


def acquire_identity(
    identity_id: str, *, project_id: str, owner: str, task_id: str | None = None, ttl: int | None = None
) -> Row:
    """One live lease per identity; the partial unique index is the real enforcement."""
    ttl = ttl or settings.device_lease_seconds
    now = clock.now_utc()
    with db.tx():
        db.execute("UPDATE test_identity_leases SET released_at = ? WHERE released_at IS NULL AND expires_at <= ?", (now, now))
        live = db.one("SELECT * FROM test_identity_leases WHERE identity_id = ? AND released_at IS NULL", (identity_id,))
        if live:
            raise SchedulerError("identity_busy", f"identity {identity_id} is leased to {live['owner']}", 409)
        lease_id = new_id("tidl_")
        db.execute(
            "INSERT INTO test_identity_leases(id, identity_id, project_id, task_id, owner, acquired_at, expires_at)"
            " VALUES(?,?,?,?,?,?,?)",
            (lease_id, identity_id, project_id, task_id, owner, now, clock.iso_plus(ttl)),
        )
    audit.record(
        "identity_leased",
        project_id=project_id,
        task_id=task_id,
        actor=owner,
        payload={"identity_id": identity_id, "lease_id": lease_id},
    )
    return db.one("SELECT * FROM test_identity_leases WHERE id = ?", (lease_id,))  # type: ignore[return-value]


def release_identity(lease_id: str, *, owner: str | None = None, reason: str = "released") -> Row:
    lease = db.one("SELECT * FROM test_identity_leases WHERE id = ?", (lease_id,))
    if lease is None:
        raise SchedulerError("lease_not_found", f"unknown identity lease {lease_id}", 404)
    if owner and lease["owner"] != owner:
        raise SchedulerError("lease_owner_mismatch", f"lease is held by {lease['owner']}", 409)
    if not lease["released_at"]:
        with db.tx():
            db.execute("UPDATE test_identity_leases SET released_at = ? WHERE id = ?", (clock.now_utc(), lease_id))
        audit.record(
            "identity_released",
            project_id=lease["project_id"],
            task_id=lease["task_id"],
            actor=owner or "system",
            payload={"identity_id": lease["identity_id"], "lease_id": lease_id, "reason": reason},
        )
    return db.one("SELECT * FROM test_identity_leases WHERE id = ?", (lease_id,))  # type: ignore[return-value]


def active_lease(identity_id: str) -> Row | None:
    now = clock.now_utc()
    return db.one(
        "SELECT * FROM test_identity_leases WHERE identity_id = ? AND released_at IS NULL AND expires_at > ?",
        (identity_id, now),
    )


# -- schedules ----------------------------------------------------------


def create_schedule(
    project_id: str,
    *,
    schedule_id: str,
    title: str,
    role: str = "static",
    goal: str | None = None,
    hour: int = 9,
    minute: int = 0,
    tz: str = "UTC",
    test_identity_id: str | None = None,
    enabled: bool = True,
    actor: str = "human",
) -> Row:
    if not (0 <= hour <= 23 and 0 <= minute <= 59):
        raise SchedulerError("invalid_schedule_time", "hour must be 0-23 and minute 0-59", 422)
    if tz not in clock.TZ_OFFSETS:
        raise SchedulerError("unsupported_timezone", f"timezone must be one of {sorted(clock.TZ_OFFSETS)}", 422)
    if test_identity_id:
        identity = get_identity(test_identity_id)
        if identity is None or identity["project_id"] != project_id:
            raise SchedulerError("identity_not_found", "the test identity does not belong to this project", 404)
    due = clock.next_due(clock.now(), hour=hour, minute=minute, tz=tz)
    job_id = new_id("prj_")
    now = clock.now_utc()
    with db.tx():
        db.execute(
            "INSERT INTO periodic_jobs(id, project_id, schedule_id, role, title, goal, test_identity_id, tz, hour,"
            " minute, enabled, next_due_at, created_at, updated_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (job_id, project_id, schedule_id, role, title.strip(), goal, test_identity_id, tz, hour, minute,
             1 if enabled else 0, due, now, now),
        )
    audit.record(
        "periodic_schedule_created",
        project_id=project_id,
        actor=actor,
        payload={"periodic_job_id": job_id, "schedule_id": schedule_id, "next_due_at": due, "tz": tz},
    )
    return get_schedule(job_id)  # type: ignore[return-value]


def get_schedule(periodic_job_id: str) -> Row | None:
    return db.one("SELECT * FROM periodic_jobs WHERE id = ?", (periodic_job_id,))


def list_schedules(project_id: str | None = None) -> list[Row]:
    if project_id:
        return db.query("SELECT * FROM periodic_jobs WHERE project_id = ? ORDER BY schedule_id", (project_id,))
    return db.query("SELECT * FROM periodic_jobs ORDER BY project_id, schedule_id")


def set_enabled(periodic_job_id: str, enabled: bool, *, actor: str = "human") -> Row:
    job = get_schedule(periodic_job_id)
    if job is None:
        raise SchedulerError("schedule_not_found", f"unknown periodic job {periodic_job_id}", 404)
    with db.tx():
        db.execute(
            "UPDATE periodic_jobs SET enabled = ?, updated_at = ? WHERE id = ?",
            (1 if enabled else 0, clock.now_utc(), periodic_job_id),
        )
    audit.record(
        "periodic_schedule_toggled",
        project_id=job["project_id"],
        actor=actor,
        payload={"periodic_job_id": periodic_job_id, "enabled": bool(enabled)},
    )
    return get_schedule(periodic_job_id)  # type: ignore[return-value]


def runs(periodic_job_id: str | None = None, limit: int = 50) -> list[Row]:
    if periodic_job_id:
        return db.query(
            "SELECT * FROM periodic_runs WHERE periodic_job_id = ? ORDER BY triggered_at DESC LIMIT ?",
            (periodic_job_id, limit),
        )
    return db.query("SELECT * FROM periodic_runs ORDER BY triggered_at DESC LIMIT ?", (limit,))


def attempts(periodic_job_id: str | None = None, limit: int = 50) -> list[Row]:
    if periodic_job_id:
        return db.query(
            "SELECT * FROM periodic_attempts WHERE periodic_job_id = ? ORDER BY attempted_at DESC LIMIT ?",
            (periodic_job_id, limit),
        )
    return db.query("SELECT * FROM periodic_attempts ORDER BY attempted_at DESC LIMIT ?", (limit,))


# -- the tick -----------------------------------------------------------


def _record_attempt(job: Row, period: dict[str, Any], result: str, error_code: str | None, detail: Any) -> dict[str, Any]:
    with db.tx():
        db.execute(
            "INSERT INTO periodic_attempts(id, periodic_job_id, project_id, period_key, attempted_at, result,"
            " error_code, detail_json) VALUES(?,?,?,?,?,?,?,?)",
            (new_id("pat_"), job["id"], job["project_id"], period["period_key"], clock.now_utc(), result,
             error_code, dumps(detail) if detail is not None else None),
        )
    return {
        "periodic_job_id": job["id"],
        "schedule_id": job["schedule_id"],
        "period_key": period["period_key"],
        "result": result,
        "error_code": error_code,
        "detail": detail,
    }


#: How long a refused schedule waits before the next look. Short on purpose: the refusal is a
#: statement about this instant (memory, a held identity), not about the day.
RETRY_AFTER_SECONDS = 300


def _retry_later(job: Row, seconds: int = RETRY_AFTER_SECONDS) -> str:
    due = clock.iso_plus(seconds)
    with db.tx():
        db.execute("UPDATE periodic_jobs SET next_due_at = ?, updated_at = ? WHERE id = ?", (due, clock.now_utc(), job["id"]))
    return due


def _advance(job: Row) -> str:
    due = clock.next_due(clock.now(), hour=int(job["hour"]), minute=int(job["minute"]), tz=job["tz"])
    with db.tx():
        db.execute("UPDATE periodic_jobs SET next_due_at = ?, updated_at = ? WHERE id = ?", (due, clock.now_utc(), job["id"]))
    return due


def tick(*, now: str | None = None, limit: int = 20, actor: str = "scheduler") -> dict[str, Any]:
    """One scheduler pass. Returns what happened, including the refusals."""
    moment = now or clock.now_utc()
    due_jobs = db.query(
        "SELECT * FROM periodic_jobs WHERE enabled = 1 AND next_due_at <= ? ORDER BY next_due_at LIMIT ?",
        (moment, limit),
    )
    outcomes: list[dict[str, Any]] = []
    for job in due_jobs:
        period = clock.window_for(clock.now(), job["tz"])
        schedule_title = f"{job['title']} [{period['period_key']}]"

        # 1. identity must be free (a refusal must not burn the day, so it comes before the claim)
        identity_lease = None
        if job["test_identity_id"]:
            identity = get_identity(job["test_identity_id"])
            if identity is None or identity["status"] != "active":
                outcomes.append(_record_attempt(job, period, IDENTITY_BUSY, "identity_inactive", None))
                _retry_later(job)
                continue
            try:
                identity_lease = acquire_identity(
                    job["test_identity_id"], project_id=job["project_id"], owner=actor, ttl=900
                )
            except SchedulerError as exc:
                outcomes.append(_record_attempt(job, period, IDENTITY_BUSY, exc.code, exc.detail))
                _retry_later(job)
                continue

        # 2. resources: refuse heavy work instead of starting it, and check again next pass
        gate = resources.check("heavy" if job["role"] in ("static", "dynamic") else "light")
        if not gate["ok"]:
            if identity_lease:
                release_identity(identity_lease["id"], owner=actor, reason="resource_blocked")
            outcomes.append(_record_attempt(job, period, BLOCKED, gate["reason"], gate["detail"]))
            _retry_later(job)
            continue

        # 3. claim the window; a second pass in the same day is a no-op by construction
        run_id = new_id("pru_")
        try:
            with db.tx():
                db.execute(
                    "INSERT INTO periodic_runs(id, periodic_job_id, project_id, test_identity_id, period_key,"
                    " window_start, window_end, tz, triggered_at, result) VALUES(?,?,?,?,?,?,?,?,?,?)",
                    (run_id, job["id"], job["project_id"], job["test_identity_id"], period["period_key"],
                     period["window_start"], period["window_end"], job["tz"], clock.now_utc(), "pending"),
                )
        except Exception:  # unique violation = this window was already triggered
            if identity_lease:
                release_identity(identity_lease["id"], owner=actor, reason="duplicate_window")
            _advance(job)
            outcomes.append(
                {
                    "periodic_job_id": job["id"],
                    "schedule_id": job["schedule_id"],
                    "period_key": period["period_key"],
                    "result": DUPLICATE,
                    "error_code": "window_already_triggered",
                    "detail": None,
                }
            )
            continue

        # 4. create the task, then hand it to the queue with a window-scoped idempotency key
        try:
            task = tasks_service.create(
                job["project_id"],
                role=job["role"],
                title=schedule_title,
                goal=job["goal"],
                actor=actor,
                status="TODO",
            )
            if identity_lease:
                with db.tx():
                    db.execute(
                        "UPDATE test_identity_leases SET task_id = ? WHERE id = ?",
                        (task["id"], identity_lease["id"]),
                    )
            job_id = queue_service.enqueue(
                "static_pipeline",
                project_id=job["project_id"],
                task_id=task["id"],
                payload={
                    "periodic_job_id": job["id"],
                    "period_key": period["period_key"],
                    "identity_lease_id": identity_lease["id"] if identity_lease else None,
                },
                idempotency_key=f"periodic:{job['id']}:{period['period_key']}",
                actor=actor,
            )
        except Exception as exc:  # noqa: BLE001 - the window stays consumed on purpose
            with db.tx():
                db.execute(
                    "UPDATE periodic_runs SET result = ?, error_code = ? WHERE id = ?",
                    ("failed", "trigger_failed", run_id),
                )
            if identity_lease:
                release_identity(identity_lease["id"], owner=actor, reason="trigger_failed")
            audit.record(
                "periodic_trigger_failed",
                project_id=job["project_id"],
                actor=actor,
                payload={"periodic_job_id": job["id"], "period_key": period["period_key"], "error": str(exc)[:300]},
            )
            outcomes.append({"periodic_job_id": job["id"], "period_key": period["period_key"],
                             "result": "failed", "error_code": "trigger_failed", "detail": str(exc)[:200]})
            _advance(job)
            continue

        with db.tx():
            db.execute("UPDATE periodic_runs SET result = ?, task_id = ?, job_id = ? WHERE id = ?",
                       (TRIGGERED, task["id"], job_id, run_id))
            db.execute("UPDATE periodic_jobs SET last_result_json = ?, updated_at = ? WHERE id = ?",
                       (dumps({"period_key": period["period_key"], "task_id": task["id"], "job_id": job_id}),
                        clock.now_utc(), job["id"]))
        audit.record(
            "periodic_triggered",
            project_id=job["project_id"],
            task_id=task["id"],
            actor=actor,
            payload={"periodic_job_id": job["id"], "period_key": period["period_key"], "job_id": job_id,
                     "identity_lease": identity_lease["id"] if identity_lease else None},
        )
        outcomes.append({"periodic_job_id": job["id"], "schedule_id": job["schedule_id"],
                         "period_key": period["period_key"], "result": TRIGGERED, "task_id": task["id"],
                         "job_id": job_id, "error_code": None, "detail": None})
        _advance(job)

    return {"at": moment, "due": len(due_jobs), "outcomes": outcomes,
            "triggered": sum(1 for row in outcomes if row["result"] == TRIGGERED)}
