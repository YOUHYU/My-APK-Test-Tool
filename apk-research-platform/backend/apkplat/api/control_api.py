"""Project run control surfaces: pause / resume / stop and the console command box.

The board's control bar and its input field talk to these three endpoints:

* ``GET  /api/projects/{id}/control``  - current run state plus the job/task counters
* ``POST /api/projects/{id}/control``  - ``{"action": "pause" | "resume" | "stop"}``
* ``POST /api/projects/{id}/command``  - ``{"text": "暂停"}`` etc., parsed server-side

Control is deliberately *not* triggered by navigation: switching the console to another
project issues no request here, so a running analysis is unaffected by what the operator is
looking at. Only an explicit pause/stop/命令 changes scheduling.
"""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends, HTTPException

from ..services import control as control_service
from ..services import projects as projects_service
from .security import require

router = APIRouter(prefix="/api", tags=["control"])


def _guard_project(claims: dict[str, Any], project_id: str, scope: str = "write") -> None:
    scopes = claims.get("scp") or []
    if scope not in scopes and "*" not in scopes:
        raise HTTPException(
            status_code=403, detail={"error_code": "scope_denied", "message": f"{scope} scope is required"}
        )
    projects = claims.get("prj") or []
    if project_id and "*" not in projects and project_id not in projects:
        raise HTTPException(
            status_code=403,
            detail={"error_code": "project_denied", "message": f"token is not scoped to project {project_id}"},
        )


def _project_or_404(project_id: str) -> None:
    if projects_service.get(project_id) is None:
        raise HTTPException(status_code=404, detail={"error_code": "project_not_found", "message": "unknown project"})


def _control_error(exc: control_service.ControlError) -> HTTPException:
    return HTTPException(status_code=exc.status, detail=exc.as_error())


@router.get("/projects/{project_id}/control")
def get_control(project_id: str, claims: dict = Depends(require("read"))) -> dict[str, Any]:
    _guard_project(claims, project_id, "read")
    _project_or_404(project_id)
    try:
        return control_service.status(project_id)
    except control_service.ControlError as exc:
        raise _control_error(exc) from exc


@router.post("/projects/{project_id}/control")
def post_control(project_id: str, payload: dict, claims: dict = Depends(require("write"))) -> dict[str, Any]:
    _guard_project(claims, project_id, "write")
    _project_or_404(project_id)
    action = str(payload.get("action") or "").strip().lower()
    reason = payload.get("reason")
    actor = claims.get("sub", "human")
    try:
        if action == "pause":
            return control_service.pause(project_id, actor=actor, reason=reason)
        if action == "resume":
            return control_service.resume(project_id, actor=actor, reason=reason)
        if action == "stop":
            return control_service.stop(project_id, actor=actor, reason=reason)
        raise HTTPException(
            status_code=422,
            detail={
                "error_code": "unknown_action",
                "message": f"action must be one of {list(control_service.ACTIONS)}",
            },
        )
    except control_service.ControlError as exc:
        raise _control_error(exc) from exc


@router.post("/projects/{project_id}/command")
def post_command(project_id: str, payload: dict, claims: dict = Depends(require("write"))) -> dict[str, Any]:
    _guard_project(claims, project_id, "write")
    _project_or_404(project_id)
    text = str(payload.get("text") or "")
    try:
        return control_service.command(project_id, text, actor=claims.get("sub", "human"))
    except control_service.ControlError as exc:
        raise _control_error(exc) from exc
