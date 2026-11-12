"""Recovery: pick a project back up after the platform was interrupted.

The queue is durable (SQLite), so nothing is lost when a worker or the API dies -
leases simply expire. This module turns that into one explicit operator action:

* ``reclaim``  - expired leases go back to PENDING/RETRYING (the same path a fresh
  worker takes on startup, but callable for a single project at any time);
* ``requeue``  - every task that is still unfinished and has no live job gets a
  fresh ``static_pipeline`` job with a new idempotency key;
* ``report``   - what was reclaimed, what was requeued, and what is still running.

Nothing here invents work: it only re-publishes jobs for tasks that already exist,
so a resumed project never gains cards or duplicated side effects.
"""
from __future__ import annotations

from typing import Any

from .. import audit
from ..db import db
from . import projects as projects_service
from . import queue as queue_service
from . import tasks as tasks_service

UNFINISHED = ("TODO", "RUNNING", "RETRYING", "STALE", "WAITING_MODEL", "WAITING_DEVICE")
LIVE_JOB_STATUSES = ("PENDING", "RUNNING", "RETRYING")


def live_jobs(project_id: str) -> list[dict[str, Any]]:
    rows = db.query(
        "SELECT id, kind, task_id, status, attempt, lease_expires_at FROM jobs"
        " WHERE project_id = ? AND status IN (?,?,?) ORDER BY created_at",
        (project_id, *LIVE_JOB_STATUSES),
    )
    return [dict(row) for row in rows]


def resume_project(project_id: str, *, actor: str = "api", reclaim: bool = True) -> dict[str, Any]:
    project = projects_service.get(project_id)
    if not project:
        return {"ok": False, "error_code": "project_not_found", "project_id": project_id}

    reclaimed: list[dict[str, Any]] = []
    if reclaim:
        reclaimed = queue_service.reclaim_expired(f"resume:{project_id}")

    live = live_jobs(project_id)
    live_tasks = {row["task_id"] for row in live if row["task_id"]}
    enqueued: list[dict[str, Any]] = []

    def publish(task_id: str | None, role: str, key_suffix: str) -> None:
        key = f"resume:{project_id}:{key_suffix}:{audit.last_seq()}"
        job_id = queue_service.enqueue(
            "static_pipeline",
            project_id=project_id,
            task_id=task_id,
            payload={"project_id": project_id, "task_id": task_id, "role": role, "resumed": True},
            idempotency_key=key,
            actor=actor,
        )
        enqueued.append({"job_id": job_id, "task_id": task_id, "role": role})

    tasks = [t for t in tasks_service.list_tasks(project_id) if t["status"] in UNFINISHED]
    for task in tasks:
        if task["id"] in live_tasks:
            continue
        # A RUNNING card whose job vanished is the interesting case: it is unfinished,
        # nothing is working on it, and only the queue can move it forward again.
        publish(task["id"], task["role"] or "static", task["id"])

    if not tasks and not live and project["status"] in ("INGESTED", "INGESTING"):
        # No cards yet and nothing in flight: the ingest job itself was lost.
        publish(None, "static", f"project:{project['status']}")

    summary = {
        "ok": True,
        "project_id": project_id,
        "project_status": project["status"],
        "reclaimed": reclaimed,
        "live_jobs": live,
        "unfinished_tasks": [{"id": t["id"], "role": t["role"], "status": t["status"]} for t in tasks],
        "enqueued": enqueued,
    }
    audit.record("project_resumed", project_id=project_id, actor=actor, payload={
        "reclaimed": len(reclaimed),
        "enqueued": len(enqueued),
        "unfinished": len(tasks),
    })
    return summary


def recovery_report(project_id: str) -> dict[str, Any]:
    """Read-only view used by the UI banner: is anything waiting for a worker?

    ``stalled`` covers both shapes of trouble: unfinished cards with nothing in
    flight, and jobs whose lease expired (the owning process stopped
    heartbeating). The second one is invisible to a plain "any live job?" check,
    because a dead job still looks RUNNING until someone reaps it.
    """
    from .. import clock

    now = clock.now_utc()
    tasks = tasks_service.list_tasks(project_id)
    live = live_jobs(project_id)
    unfinished = [t for t in tasks if t["status"] in UNFINISHED]
    dead = [j for j in live if j["status"] == "RUNNING" and (j.get("lease_expires_at") or "") < now]
    return {
        "project_id": project_id,
        "unfinished": len(unfinished),
        "live_jobs": len(live),
        "dead_leases": len(dead),
        "stalled": bool(unfinished) and not live or bool(dead),
        "tasks": [{"id": t["id"], "role": t["role"], "status": t["status"]} for t in unfinished],
        "jobs": [{"id": j["id"], "status": j["status"], "attempt": j["attempt"]} for j in live],
    }
