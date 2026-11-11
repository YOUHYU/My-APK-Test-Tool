"""P4 surface: analysis cache and the capture correlation layer."""
from __future__ import annotations

from typing import Any

from fastapi import APIRouter, BackgroundTasks, Body, Depends, HTTPException

from ..services import cache as cache_service
from ..services import capture as capture_service
from ..services import projects as projects_service
from .security import claims_for, require

router = APIRouter(prefix="/api")

READ = Depends(require("read"))
WRITE = Depends(require("write"))


def _project_or_404(project_id: str) -> dict[str, Any]:
    project = projects_service.get(project_id)
    if project is None:
        raise HTTPException(status_code=404, detail={"error_code": "project_not_found", "message": project_id})
    return dict(project)


@router.get("/cache/stats")
def cache_stats(_: dict = READ) -> dict[str, Any]:
    return cache_service.stats()


@router.get("/cache/entries")
def cache_entries(limit: int = 50, _: dict = READ) -> dict[str, Any]:
    rows = cache_service.listing(limit=limit)
    return {"entries": rows, "count": len(rows)}


@router.get("/capture/probe")
def capture_probe(directory: str | None = None, _: dict = READ) -> dict[str, Any]:
    return capture_service.probe_proxy_pin(directory)


@router.post("/projects/{project_id}/capture/import", status_code=201)
def capture_import(project_id: str, payload: dict[str, Any] = Body(...), _: dict = WRITE) -> dict[str, Any]:
    _project_or_404(project_id)
    path = payload.get("path")
    if not path:
        raise HTTPException(status_code=422, detail={"error_code": "path_required", "message": "path is required"})
    try:
        return capture_service.import_source(
            project_id,
            path=path,
            kind=str(payload.get("kind") or "har"),
            label=payload.get("label"),
            actor=(payload.get("actor") or "operator"),
        )
    except capture_service.CaptureError as exc:
        raise HTTPException(status_code=exc.status, detail=exc.as_error()) from exc


@router.post("/projects/{project_id}/capture/correlate")
def capture_correlate(project_id: str, payload: dict[str, Any] | None = Body(default=None), _: dict = WRITE) -> dict[str, Any]:
    _project_or_404(project_id)
    body = payload or {}
    return capture_service.correlate(project_id, run_id=body.get("run_id"))


@router.get("/projects/{project_id}/capture/flows")
def capture_flows(
    project_id: str,
    host: str | None = None,
    method: str | None = None,
    matched_only: bool = False,
    limit: int = 100,
    _: dict = READ,
) -> dict[str, Any]:
    _project_or_404(project_id)
    return capture_service.query(project_id, host=host, method=method, matched_only=matched_only, limit=limit)


@router.get("/projects/{project_id}/capture/sources")
def capture_sources(project_id: str, _: dict = READ) -> dict[str, Any]:
    _project_or_404(project_id)
    rows = capture_service.sources(project_id)
    return {"sources": rows, "count": len(rows), "summary": capture_service.summarize(project_id)}


@router.post("/projects/{project_id}/capture/steps", status_code=201)
def capture_step(project_id: str, payload: dict[str, Any] = Body(...), _: dict = WRITE) -> dict[str, Any]:
    _project_or_404(project_id)
    step = str(payload.get("step") or "").strip()
    started_at = str(payload.get("started_at") or "").strip()
    if not step or not started_at:
        raise HTTPException(
            status_code=422, detail={"error_code": "step_and_started_at_required", "message": "step and started_at are required"}
        )
    row = capture_service.record_step(
        project_id,
        step=step,
        started_at=started_at,
        ended_at=payload.get("ended_at"),
        run_id=payload.get("run_id"),
        task_id=payload.get("task_id"),
        device_serial=payload.get("device_serial"),
        note=payload.get("note"),
    )
    return {"step": row}


@router.get("/projects/{project_id}/capture/steps")
def capture_steps(project_id: str, _: dict = READ) -> dict[str, Any]:
    _project_or_404(project_id)
    rows = capture_service.steps(project_id)
    return {"steps": rows, "count": len(rows)}
