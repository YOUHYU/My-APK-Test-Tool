"""P6 surfaces: the scheduler tick, test identities, periodic runs and the resource probe."""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query

from .. import audit, clock, resources
from ..services import projects as projects_service
from ..services import scheduler as scheduler_service
from .security import require

router = APIRouter(prefix="/api", tags=["p6"])


def _guard_project(claims: dict[str, Any], project_id: str, scope: str = "read") -> None:
    scopes = claims.get("scp") or []
    if scope not in scopes and "*" not in scopes:
        raise HTTPException(status_code=403, detail={"error_code": "scope_denied", "message": f"{scope} scope is required"})
    projects = claims.get("prj") or []
    if project_id and "*" not in projects and project_id not in projects:
        raise HTTPException(
            status_code=403,
            detail={"error_code": "project_denied", "message": f"token is not scoped to project {project_id}"},
        )


def _project_or_404(project_id: str) -> None:
    if projects_service.get(project_id) is None:
        raise HTTPException(status_code=404, detail={"error_code": "project_not_found", "message": "unknown project"})


@router.post("/projects/{project_id}/test-identities", status_code=201)
def add_identity(project_id: str, payload: dict, claims: dict = Depends(require("write"))) -> dict[str, Any]:
    _guard_project(claims, project_id, "write")
    _project_or_404(project_id)
    try:
        row = scheduler_service.add_identity(
            project_id,
            str(payload.get("label") or ""),
            kind=str(payload.get("kind") or "test_account"),
            secret_ref=payload.get("secret_ref"),
            note=payload.get("note"),
            actor=claims.get("sub", "human"),
        )
    except scheduler_service.SchedulerError as exc:
        raise HTTPException(status_code=exc.status, detail=exc.as_error()) from exc
    item = dict(row)
    item.pop("secret_ref", None)  # the reference never leaves the server
    item["has_secret_ref"] = bool(row["secret_ref"])
    return {"identity": item}


@router.get("/projects/{project_id}/test-identities")
def list_identities(project_id: str, claims: dict = Depends(require("read"))) -> dict[str, Any]:
    _guard_project(claims, project_id)
    rows = []
    for row in scheduler_service.list_identities(project_id):
        item = dict(row)
        item.pop("secret_ref", None)
        item["has_secret_ref"] = bool(row["secret_ref"])
        lease = scheduler_service.active_lease(row["id"])
        item["active_lease"] = dict(lease) if lease else None
        rows.append(item)
    return {"identities": rows, "count": len(rows)}


@router.post("/projects/{project_id}/periodic", status_code=201)
def create_schedule(project_id: str, payload: dict, claims: dict = Depends(require("write"))) -> dict[str, Any]:
    _guard_project(claims, project_id, "write")
    _project_or_404(project_id)
    schedule_id = str(payload.get("schedule_id") or "").strip()
    if not schedule_id:
        raise HTTPException(status_code=422, detail={"error_code": "schedule_id_required", "message": "schedule_id is required"})
    try:
        row = scheduler_service.create_schedule(
            project_id,
            schedule_id=schedule_id,
            title=str(payload.get("title") or schedule_id),
            role=str(payload.get("role") or "static"),
            goal=payload.get("goal"),
            hour=int(payload.get("hour", 9)),
            minute=int(payload.get("minute", 0)),
            tz=str(payload.get("tz") or "UTC"),
            test_identity_id=payload.get("test_identity_id"),
            enabled=bool(payload.get("enabled", True)),
            actor=claims.get("sub", "human"),
        )
    except scheduler_service.SchedulerError as exc:
        raise HTTPException(status_code=exc.status, detail=exc.as_error()) from exc
    return {"schedule": dict(row)}


@router.get("/projects/{project_id}/periodic")
def list_schedules(project_id: str, claims: dict = Depends(require("read"))) -> dict[str, Any]:
    _guard_project(claims, project_id)
    rows = [dict(row) for row in scheduler_service.list_schedules(project_id)]
    return {"schedules": rows, "count": len(rows)}


@router.patch("/periodic/{periodic_job_id}")
def patch_schedule(periodic_job_id: str, payload: dict, claims: dict = Depends(require("write"))) -> dict[str, Any]:
    job = scheduler_service.get_schedule(periodic_job_id)
    if job is None:
        raise HTTPException(status_code=404, detail={"error_code": "schedule_not_found", "message": "unknown schedule"})
    _guard_project(claims, job["project_id"], "write")
    allowed = {"enabled"}
    unknown = sorted(set(payload) - allowed)
    if unknown:
        raise HTTPException(
            status_code=422,
            detail={"error_code": "field_not_editable", "message": f"not editable: {unknown}", "editable": sorted(allowed)},
        )
    row = scheduler_service.set_enabled(periodic_job_id, bool(payload["enabled"]), actor=claims.get("sub", "human"))
    return {"schedule": dict(row)}


@router.get("/periodic/{periodic_job_id}/runs")
def periodic_runs(periodic_job_id: str, claims: dict = Depends(require("read"))) -> dict[str, Any]:
    job = scheduler_service.get_schedule(periodic_job_id)
    if job is None:
        raise HTTPException(status_code=404, detail={"error_code": "schedule_not_found", "message": "unknown schedule"})
    _guard_project(claims, job["project_id"])
    rows = [dict(row) for row in scheduler_service.runs(periodic_job_id)]
    return {"runs": rows, "count": len(rows)}


@router.get("/periodic/{periodic_job_id}/attempts")
def periodic_attempts(periodic_job_id: str, claims: dict = Depends(require("read"))) -> dict[str, Any]:
    job = scheduler_service.get_schedule(periodic_job_id)
    if job is None:
        raise HTTPException(status_code=404, detail={"error_code": "schedule_not_found", "message": "unknown schedule"})
    _guard_project(claims, job["project_id"])
    rows = [dict(row) for row in scheduler_service.attempts(periodic_job_id)]
    return {"attempts": rows, "count": len(rows)}


@router.post("/periodic/tick")
def periodic_tick(payload: dict | None = None, claims: dict = Depends(require("write"))) -> dict[str, Any]:
    """Run one scheduler pass.

    There is exactly one scheduler owner: the Python platform. DSH's own reminders are not
    wired to these cards, so a tick here can never race a tick from the model side.
    """
    body = payload or {}
    actor = claims.get("sub", "scheduler")
    result = scheduler_service.tick(now=body.get("now"), limit=int(body.get("limit", 20)), actor=actor)
    audit.record("periodic_tick", actor=actor, payload={"due": result["due"], "triggered": result["triggered"]})
    return result


@router.get("/resources")
def resource_snapshot(claims: dict = Depends(require("read"))) -> dict[str, Any]:
    probe_snapshot = resources.snapshot()
    gate_heavy = resources.check("heavy")
    return {
        "snapshot": probe_snapshot,
        "gate_heavy": gate_heavy,
        "clock": {"name": clock.get_clock().name, "now": clock.now_utc()},
    }
