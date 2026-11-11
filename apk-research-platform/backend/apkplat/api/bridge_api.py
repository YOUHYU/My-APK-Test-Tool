"""P1 bridge HTTP surface.

Two audiences share this router:

* the operator / tests create capabilities (``POST /api/projects/{id}/runs``);
* the DSH-side plugin speaks the bridge protocol with the opaque run token.

Rule that never bends: the platform decides. Every tool call is re-authorised here
even though the plugin only registered the tools the handshake handed it, and every
call - allowed or refused - lands in ``run_tool_calls`` so G1 can audit the decision.
"""

from __future__ import annotations

import json
import time
from typing import Any

from fastapi import APIRouter, Body, Depends, Header, HTTPException
from fastapi.responses import JSONResponse

from .. import audit, bridge
from ..db import utcnow
from ..services import capabilities
from ..services import projects as projects_service
from ..services import tasks as tasks_service
from ..util import new_id
from .security import require

router = APIRouter()


def _bearer(authorization: str | None) -> str:
    if not authorization or not authorization.lower().startswith("bearer "):
        raise HTTPException(status_code=401, detail={"error_code": "missing_token", "message": "Authorization: Bearer <run capability>"})
    return authorization.split(" ", 1)[1].strip()


def _scope(authorization: str | None, claimed_project: str | None = None) -> capabilities.Scope:
    token = _bearer(authorization)
    try:
        scope = capabilities.resolve(token)
    except capabilities.CapabilityError as exc:
        raise HTTPException(status_code=exc.status, detail={"error_code": exc.code, "message": exc.message}) from exc
    if claimed_project and claimed_project != scope.project_id:
        # A caller naming a different project is either confused or probing: refuse and
        # leave a trail, because "which project was asked for" is part of the audit story.
        audit.record(
            "bridge_cross_project_denied",
            project_id=scope.project_id,
            task_id=scope.task_id,
            actor=f"bridge:{scope.run_id}",
            payload={"claimed_project": claimed_project, "run_id": scope.run_id},
        )
        raise HTTPException(
            status_code=403,
            detail={"error_code": "project_denied", "message": f"capability is bound to {scope.project_id}"},
        )
    return scope


# ------------------------------------------------------------------ operator side


@router.post("/api/projects/{project_id}/runs", status_code=201)
def create_run(
    project_id: str,
    payload: dict[str, Any] = Body(default={}),
    claims: dict = Depends(require("write")),
) -> dict[str, Any]:
    if not projects_service.get(project_id):
        raise HTTPException(status_code=404, detail={"error_code": "project_not_found", "message": project_id})
    try:
        scope, token, path = capabilities.issue(
            project_id,
            str(payload.get("role") or "exec"),
            task_id=payload.get("task_id"),
            ttl_seconds=int(payload.get("ttl_seconds") or 3600),
            tools=payload.get("tools"),
            max_tool_calls=payload.get("max_tool_calls"),
            max_model_calls=payload.get("max_model_calls"),
            actor=str(payload.get("actor") or "operator"),
        )
    except capabilities.CapabilityError as exc:
        raise HTTPException(status_code=exc.status, detail={"error_code": exc.code, "message": exc.message}) from exc
    return {
        "run_id": scope.run_id,
        "token_path": str(path),
        "scope": scope.as_dict(),
        "note": "the plaintext token is in token_path only; it is never returned over HTTP",
    }


@router.get("/api/runs/{run_id}")
def describe_run(run_id: str, claims: dict = Depends(require("read"))) -> dict[str, Any]:
    data = capabilities.describe(run_id)
    if data is None:
        raise HTTPException(status_code=404, detail={"error_code": "run_not_found", "message": run_id})
    return data


@router.get("/api/runs/{run_id}/trace")
def run_trace(run_id: str, after_seq: int = 0, claims: dict = Depends(require("read"))) -> dict[str, Any]:
    rows = [dict(r) for r in capabilities.trace(run_id, after_seq=after_seq)]
    return {"run_id": run_id, "count": len(rows), "calls": rows}


@router.post("/api/runs/{run_id}/revoke")
def revoke_run(run_id: str, payload: dict[str, Any] = Body(default={}), claims: dict = Depends(require("write"))) -> dict[str, Any]:
    changed = capabilities.revoke(run_id, reason=str(payload.get("reason") or "operator revoked"), actor="operator")
    if not changed:
        raise HTTPException(status_code=404, detail={"error_code": "run_not_found_or_already_revoked", "message": run_id})
    return {"run_id": run_id, "revoked": True}


# -------------------------------------------------------------------- bridge side


@router.get("/api/bridge/tools")
def bridge_tools(authorization: str | None = Header(default=None)) -> dict[str, Any]:
    scope = _scope(authorization)
    return {"ok": True, "run_id": scope.run_id, "role_id": scope.role_id, "tools": bridge.tool_catalogue(scope)}


@router.post("/api/bridge/handshake")
def handshake(payload: dict[str, Any] = Body(default={}), authorization: str | None = Header(default=None)) -> dict[str, Any]:
    scope = _scope(authorization)
    dsh_session = str(payload.get("dsh_session_id") or "").strip() or None
    model_id = str(payload.get("model_id") or "").strip() or None
    agent_run_id = None
    if scope.task_id:
        agent_run_id = tasks_service.record_run(
            scope.task_id,
            role=scope.role_id,
            model_id=model_id,
            dsh_session_ref=dsh_session,
            notes=f"bridge handshake plugin={payload.get('plugin_version')}",
        )
        capabilities.bind_agent_run(scope.run_id, agent_run_id)
    audit.record(
        "bridge_run_assigned",
        project_id=scope.project_id,
        task_id=scope.task_id,
        actor=f"bridge:{scope.run_id}",
        payload={
            "run_id": scope.run_id,
            "agent_run_id": agent_run_id,
            "dsh_session_id": dsh_session,
            "role_id": scope.role_id,
            "plugin_version": payload.get("plugin_version"),
            "allowed_tools": scope.tools,
        },
    )
    return {
        "ok": True,
        "run": {
            "run_id": scope.run_id,
            "project_id": scope.project_id,
            "task_id": scope.task_id,
            "role_id": scope.role_id,
            "policy_version": scope.policy_version,
            "expires_at": scope.expires_at,
            "max_tool_calls": scope.max_tool_calls,
            "max_model_calls": scope.max_model_calls,
            "agent_run_id": agent_run_id,
        },
        "tools": bridge.tool_catalogue(scope),
    }


@router.get("/api/bridge/state")
def bridge_state(authorization: str | None = Header(default=None)) -> dict[str, Any]:
    scope = _scope(authorization)
    used = capabilities.tool_calls_used(scope.run_id)
    return {
        "ok": True,
        "run_id": scope.run_id,
        "revoked": False,
        "tool_calls_used": used,
        "tool_calls_left": max(0, scope.max_tool_calls - used),
        "expires_at": scope.expires_at,
    }


@router.post("/api/bridge/tools/{tool}")
def bridge_tool(
    tool: str,
    payload: dict[str, Any] = Body(default={}),
    authorization: str | None = Header(default=None),
    x_project_id: str | None = Header(default=None, alias="X-Project-Id"),
) -> JSONResponse:
    scope = _scope(authorization, x_project_id)
    args = payload.get("arguments") if isinstance(payload, dict) and isinstance(payload.get("arguments"), dict) else payload
    args = dict(args or {})
    request_id = str(payload.get("request_id") or new_id("req")) if isinstance(payload, dict) else new_id("req")
    started_at = utcnow()
    t0 = time.perf_counter()
    ok = False
    error_code = None
    status = 200
    body: dict[str, Any]
    try:
        capabilities.authorize(scope, tool, args)
        body = bridge.call(scope, tool, args)
        ok = True
    except capabilities.CapabilityError as exc:
        error_code, status = exc.code, exc.status
        body = {"ok": False, **exc.as_error()}
    except bridge.BridgeFault as exc:
        error_code, status = exc.code, 200
        body = {"ok": False, **exc.as_error()}
    except Exception as exc:  # noqa: BLE001 - a crash must still leave a trace
        # A broken handler used to escape as a plain-text 500: the agent got "Internal
        # Server Error", lost the call from its trace, and could not tell what happened.
        # Now the run keeps a record and the model gets a readable, retryable refusal.
        error_code, status = "internal_error", 200
        body = {"ok": False, "error_code": "internal_error", "message": str(exc), "retryable": False}
        audit.record(
            "bridge_tool_crashed",
            project_id=scope.project_id,
            task_id=scope.task_id,
            actor=f"bridge:{scope.run_id}",
            payload={"run_id": scope.run_id, "tool": tool, "error": f"{type(exc).__name__}: {exc}"},
        )
    duration_ms = int((time.perf_counter() - t0) * 1000)
    preview = None
    if ok:
        try:
            preview = json.dumps(body.get("result"), ensure_ascii=False)
        except Exception:  # noqa: BLE001
            preview = str(body.get("result"))[:2000]
    seq = capabilities.record_call(
        scope.run_id,
        tool=tool,
        args=args,
        ok=ok,
        error_code=error_code,
        duration_ms=duration_ms,
        request_id=request_id,
        result_preview=preview,
    )
    audit.record(
        "bridge_tool_call",
        project_id=scope.project_id,
        task_id=scope.task_id,
        actor=f"bridge:{scope.run_id}",
        payload={
            "run_id": scope.run_id,
            "seq": seq,
            "tool": tool,
            "ok": ok,
            "error_code": error_code,
            "duration_ms": duration_ms,
            "request_id": request_id,
            "args_keys": sorted(args.keys()),
        },
    )
    if scope.task_id:
        tasks_service.incr_counters(scope.task_id, tool_calls=1)
    envelope = {
        **body,
        "project_id": scope.project_id,
        "task_id": scope.task_id,
        "run_id": scope.run_id,
        "tool": tool,
        "tool_version": bridge.TOOL_VERSION,
        "started_at": started_at,
        "duration_ms": duration_ms,
        "request_id": request_id,
        "seq": seq,
    }
    return JSONResponse(status_code=status, content=envelope)


@router.post("/api/bridge/heartbeat")
def heartbeat(payload: dict[str, Any] = Body(default={}), authorization: str | None = Header(default=None)) -> dict[str, Any]:
    scope = _scope(authorization)
    return {"ok": True, "run_id": scope.run_id, "expires_at": scope.expires_at, "server_time": utcnow()}


@router.post("/api/bridge/finish")
def finish(payload: dict[str, Any] = Body(default={}), authorization: str | None = Header(default=None)) -> dict[str, Any]:
    """Land a run. The agent may only ask for REVIEW or BLOCKED - never DONE."""
    scope = _scope(authorization)
    requested = str(payload.get("status") or "review").strip().lower()
    if requested not in {"review", "blocked"}:
        raise HTTPException(
            status_code=422,
            detail={"error_code": "invalid_finish_status", "message": "status must be 'review' or 'blocked'; DONE is written by the platform only"},
        )
    claims = payload.get("claims") or []
    unverified = payload.get("unverified") or []
    model_calls = int(payload.get("model_calls") or 0)
    target = "REVIEW" if requested == "review" else "BLOCKED"
    agent_run_id = capabilities.agent_run_of(scope.run_id)
    if scope.task_id:
        fields = {"blocked_reason": str(payload.get("reason") or "agent reported blocked")} if target == "BLOCKED" else None
        try:
            tasks_service.update(scope.task_id, status=target, actor="agent", fields=fields, reason=str(payload.get("summary") or "")[:500] or None)
        except Exception as exc:  # noqa: BLE001 - a finished run must still be closed
            audit.record(
                "bridge_finish_status_failed",
                project_id=scope.project_id,
                task_id=scope.task_id,
                actor=f"bridge:{scope.run_id}",
                payload={"error": str(exc), "target": target},
            )
        if model_calls:
            tasks_service.incr_counters(scope.task_id, model_calls=model_calls)
    if agent_run_id:
        tasks_service.close_run(agent_run_id, status="completed" if target == "REVIEW" else "blocked", notes=str(payload.get("summary") or "")[:500] or None)
    capabilities.revoke(scope.run_id, reason=f"run finished as {target}")
    audit.record(
        "bridge_run_finished",
        project_id=scope.project_id,
        task_id=scope.task_id,
        actor=f"bridge:{scope.run_id}",
        payload={
            "run_id": scope.run_id,
            "agent_run_id": agent_run_id,
            "requested_status": requested,
            "target_status": target,
            "claims": claims[:50],
            "unverified": unverified[:50],
            "model_calls": model_calls,
        },
    )
    return {
        "ok": True,
        "run_id": scope.run_id,
        "task_id": scope.task_id,
        "task_status": target,
        "note": "DONE requires human approval through the platform; a review run must verify this first",
    }
