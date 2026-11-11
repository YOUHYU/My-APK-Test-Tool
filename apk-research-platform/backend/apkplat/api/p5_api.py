"""P5 device surfaces: composite health, quarantine, and the cleanup policy catalogue.

The point of these endpoints is honesty: a device is not "ready" because `adb get-state`
said `device`. Readiness is a set of measured states, and anything that could not be
measured is reported as unknown instead of being assumed true.
"""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query

from .. import audit
from ..db import utcnow
from ..services import device_ui
from ..services import devices as devices_service
from ..services import projects as projects_service
from .. import dynamic as dynamic_module
from .security import claims_for, require

router = APIRouter(prefix="/api", tags=["p5"])


def _allowed(claims: dict[str, Any], project_id: str | None) -> bool:
    if not project_id:
        return True
    projects = claims.get("prj") or []
    return "*" in projects or project_id in projects


def _guard(claims: dict[str, Any], project_id: str | None, scope: str = "read") -> None:
    scopes = claims.get("scp") or []
    if scope not in scopes and "*" not in scopes:
        raise HTTPException(status_code=403, detail={"error_code": "scope_denied", "message": f"{scope} scope is required"})
    if not _allowed(claims, project_id):
        raise HTTPException(
            status_code=403,
            detail={"error_code": "project_denied", "message": f"token is not scoped to project {project_id}"},
        )


@router.get("/devices/live")
def live_devices(claims: dict = Depends(require("read"))) -> dict[str, Any]:
    """What adb can see right now, merged across transports by ro.serialno.

    The same handset is often reachable over USB and Wi-Fi at once; those are one device, not
    two, otherwise the single-device guarantee is broken before the lease is even taken.
    """
    probe = devices_service.adb_devices()
    rows = devices_service.parse_adb_devices(probe.get("raw") or "")
    merged = devices_service.merge_transports(rows)
    return {"merged": merged, "raw": probe, "serial_count": len({r.get("merge_key") for r in merged}),
            "measured_at": utcnow()}


@router.get("/devices/{serial}/health")
def device_health(
    serial: str,
    package: str | None = Query(default=None),
    project_id: str | None = Query(default=None),
    transport: str = Query(default="adb"),
    claims: dict = Depends(require("read")),
) -> dict[str, Any]:
    _guard(claims, project_id)
    if project_id and not package:
        project = projects_service.get(project_id)
        package = (project["package_name"] if project else None) or None
    sim = None
    if transport == "sim":
        sim = dynamic_module.make_transport("sim")
    report = devices_service.health(serial, package=package, transport=sim)
    audit.record(
        "device_health_checked",
        project_id=project_id,
        actor=claims.get("sub", "unknown"),
        payload={"serial": serial, "ready": report.get("ready"), "blocked": report.get("blocked")},
    )
    return report


@router.post("/devices/{serial}/quarantine")
def quarantine_device(
    serial: str,
    payload: dict | None = None,
    claims: dict = Depends(require("write")),
) -> dict[str, Any]:
    body = payload or {}
    device = None
    for row in devices_service.list_devices():
        if row["adb_serial"] == serial:
            device = row
            break
    if device is None:
        raise HTTPException(status_code=404, detail={"error_code": "device_not_found", "message": f"unknown device {serial}"})
    _guard(claims, body.get("project_id"), scope="write")
    reason = str(body.get("reason") or "manual quarantine").strip()
    row = devices_service.quarantine(device["id"], reason=reason, actor=claims.get("sub", "human"))
    return {"device": dict(row), "reason": reason}


@router.post("/devices/{serial}/quarantine/clear")
def clear_quarantine_device(
    serial: str,
    payload: dict | None = None,
    claims: dict = Depends(require("write")),
) -> dict[str, Any]:
    body = payload or {}
    device = None
    for row in devices_service.list_devices():
        if row["adb_serial"] == serial:
            device = row
            break
    if device is None:
        raise HTTPException(status_code=404, detail={"error_code": "device_not_found", "message": f"unknown device {serial}"})
    _guard(claims, body.get("project_id"), scope="write")
    row = devices_service.clear_quarantine(device["id"], actor=claims.get("sub", "human"), note=body.get("note"))
    return {"device": dict(row)}


@router.get("/cleanup/modes")
def cleanup_modes(claims: dict = Depends(require("read"))) -> dict[str, Any]:
    """The four cleanup policies and what each one is allowed to do, per package state."""
    modes = {}
    for mode in dynamic_module.CLEANUP_MODES:
        modes[mode] = {
            "installed_by_us": dynamic_module.cleanup_plan(mode, package="p", installed_by_us=True),
            "pre_existing": dynamic_module.cleanup_plan(mode, package="p", installed_by_us=False),
        }
    return {"modes": modes, "actions": list(dynamic_module.CLEANUP_ACTIONS)}
