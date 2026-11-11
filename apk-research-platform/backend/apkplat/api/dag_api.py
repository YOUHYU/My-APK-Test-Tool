"""P2 API: dependency graph, checks, review runs, roles and the platform event feed."""

from __future__ import annotations

import asyncio
import json
from typing import Any

from fastapi import APIRouter, Body, Depends, Header, HTTPException, Query
from fastapi.responses import StreamingResponse

from .. import audit
from ..db import db
from ..services import auth as auth_service
from ..services import capabilities, dag, events, projects as projects_service, review as review_service, roles as roles_service, tasks as tasks_service
from .security import claims_for, require

router = APIRouter(tags=["dag"])


def _guard(claims: dict, project_id: str, scope: str = "read") -> None:
    projects_service.get(project_id)  # 404 when the project is gone
    auth_service.authorize(claims, project_id, scope)


@router.get("/api/projects/{project_id}/graph")
def project_graph(project_id: str, claims: dict = Depends(require("read"))) -> dict[str, Any]:
    _guard(claims, project_id)
    payload = dag.graph(project_id)
    payload["checks"] = review_service.verdict_summary(project_id)
    payload["legacy"] = dag.verify_against_legacy(project_id)
    return payload


@router.post("/api/projects/{project_id}/edges", status_code=201)
def add_edge(project_id: str, payload: dict[str, Any] = Body(default={}), claims: dict = Depends(require("write"))) -> dict[str, Any]:
    _guard(claims, project_id, "write")
    try:
        edge = dag.add_edge(
            project_id,
            str(payload.get("from_task_id") or ""),
            str(payload.get("to_task_id") or ""),
            str(payload.get("kind") or "blocks"),
            actor=str(claims.get("sub") or "operator"),
        )
    except dag.DagError as exc:
        raise HTTPException(status_code=exc.status, detail=exc.as_error()) from exc
    events.emit("task_edge", project_id=project_id, task_id=edge["to_task_id"], payload={"from": edge["from_task_id"], "to": edge["to_task_id"]})
    return {"edge": edge, "graph": dag.graph(project_id)}


@router.delete("/api/projects/{project_id}/edges")
def delete_edge(
    project_id: str,
    from_task_id: str = Query(...),
    to_task_id: str = Query(...),
    kind: str = Query("blocks"),
    claims: dict = Depends(require("write")),
) -> dict[str, Any]:
    _guard(claims, project_id, "write")
    removed = dag.remove_edge(project_id, from_task_id, to_task_id, kind, actor=str(claims.get("sub") or "operator"))
    return {"removed": removed, "graph": dag.graph(project_id)}


@router.get("/api/tasks/{task_id}/checks")
def task_checks(task_id: str, claims: dict = Depends(require("read"))) -> dict[str, Any]:
    task = tasks_service.get(task_id)
    if task is None:
        raise HTTPException(status_code=404, detail={"error_code": "task_not_found", "message": f"task {task_id} does not exist"})
    _guard(claims, task["project_id"])
    return {"task_id": task_id, "checks": review_service.checks(task_id), "fails": review_service.fail_count(task_id)}


@router.post("/api/tasks/{task_id}/checks", status_code=201)
def add_check(task_id: str, payload: dict[str, Any] = Body(default={}), claims: dict = Depends(require("write"))) -> dict[str, Any]:
    task = tasks_service.get(task_id)
    if task is None:
        raise HTTPException(status_code=404, detail={"error_code": "task_not_found", "message": f"task {task_id} does not exist"})
    _guard(claims, task["project_id"], "write")
    try:
        check = review_service.record_check(
            task["project_id"],
            task_id,
            verdict=str(payload.get("verdict") or ""),
            criterion=str(payload.get("criterion") or "manual"),
            detail=payload.get("detail") or {},
            run_id=payload.get("run_id"),
            actor=str(claims.get("sub") or "operator"),
        )
    except review_service.ReviewError as exc:
        raise HTTPException(status_code=exc.status, detail=exc.as_error()) from exc
    return {"check": check}


@router.post("/api/tasks/{task_id}/review")
def review_task(task_id: str, payload: dict[str, Any] = Body(default={}), claims: dict = Depends(require("write"))) -> dict[str, Any]:
    """Operator or reviewer verdict: PASS holds the card in REVIEW, FAIL dispatches it back."""
    task = tasks_service.get(task_id)
    if task is None:
        raise HTTPException(status_code=404, detail={"error_code": "task_not_found", "message": f"task {task_id} does not exist"})
    _guard(claims, task["project_id"], "write")
    decision = str(payload.get("decision") or payload.get("verdict") or "").lower()
    actor = str(claims.get("sub") or "operator")
    try:
        if decision in ("pass", "approve", "approved"):
            result = review_service.accept(task["project_id"], task_id, criterion=str(payload.get("criterion") or "review"), run_id=payload.get("run_id"), actor=actor)
        elif decision in ("fail", "reject", "rejected"):
            role = roles_service.get(task["role"])
            result = review_service.dispatch_back(
                task["project_id"],
                task_id,
                reason=str(payload.get("reason") or "review failed"),
                run_id=payload.get("run_id"),
                actor=actor,
                retry_limit=int(role["retry_limit"]) if role else review_service.DEFAULT_RETRY_LIMIT,
            )
        else:
            raise HTTPException(status_code=422, detail={"error_code": "invalid_decision", "message": "decision must be pass or fail"})
    except review_service.ReviewError as exc:
        raise HTTPException(status_code=exc.status, detail=exc.as_error()) from exc
    return {"task_id": task_id, "decision": decision, "result": result}


@router.post("/api/tasks/{task_id}/review-run", status_code=201)
def open_review_run(task_id: str, payload: dict[str, Any] = Body(default={}), claims: dict = Depends(require("write"))) -> dict[str, Any]:
    """Start an independent review run for a card (its own capability, own agent_run)."""
    task = tasks_service.get(task_id)
    if task is None:
        raise HTTPException(status_code=404, detail={"error_code": "task_not_found", "message": f"task {task_id} does not exist"})
    _guard(claims, task["project_id"], "write")
    if task["status"] != "REVIEW":
        raise HTTPException(
            status_code=409,
            detail={"error_code": "not_in_review", "message": f"task {task_id} is {task['status']}, not REVIEW"},
        )
    scope, _token, token_path = capabilities.issue(
        task["project_id"],
        "review",
        task_id=task_id,
        ttl_seconds=int(payload.get("ttl_seconds") or 1800),
        actor=str(claims.get("sub") or "operator"),
    )
    run_id = scope.run_id
    agent_run_id = tasks_service.record_run(
        task_id,
        role="review",
        notes="independent review run",
        dsh_session_ref=run_id,
    )
    capabilities.bind_agent_run(run_id, agent_run_id)
    events.emit("run_started", project_id=task["project_id"], task_id=task_id, payload={"run_id": run_id, "role": "review"})
    return {
        "run_id": run_id,
        "agent_run_id": agent_run_id,
        "token_path": str(token_path),
        "scope": scope.as_dict(),
        "review_of": task_id,
    }


@router.get("/api/roles")
def list_roles(claims: dict = Depends(require("read"))) -> dict[str, Any]:
    return {"roles": roles_service.listing(), "coverage": roles_service.coverage()}


@router.patch("/api/roles/{role_id}")
def patch_role(role_id: str, payload: dict[str, Any] = Body(default={}), claims: dict = Depends(require("admin"))) -> dict[str, Any]:
    try:
        role = roles_service.update(role_id, fields=payload, actor=str(claims.get("sub") or "operator"))
    except KeyError as exc:
        raise HTTPException(status_code=404, detail={"error_code": "role_not_found", "message": f"role {role_id} does not exist"}) from exc
    except review_service.ReviewError as exc:
        raise HTTPException(status_code=exc.status, detail=exc.as_error()) from exc
    except ValueError as exc:
        raise HTTPException(status_code=422, detail={"error_code": "field_not_editable", "message": str(exc)}) from exc
    return {"role": role}


@router.get("/api/projects/{project_id}/platform-events")
def project_events(
    project_id: str,
    after_seq: int = Query(0, ge=0),
    limit: int = Query(200, ge=1, le=1000),
    claims: dict = Depends(require("read")),
) -> dict[str, Any]:
    _guard(claims, project_id)
    rows = events.tail(after_seq, project_id=project_id, limit=limit)
    return {"project_id": project_id, "count": len(rows), "last_seq": rows[-1]["seq"] if rows else after_seq, "events": rows}


@router.get("/api/platform-events/stream")
async def platform_stream(
    after_seq: int = Query(0, ge=0),
    project_id: str | None = Query(None),
    last_event_id: str | None = Header(default=None, alias="Last-Event-ID"),
):
    """SSE feed with resume: a reconnecting client sends Last-Event-ID and misses nothing."""
    cursor = int(last_event_id) if last_event_id and last_event_id.isdigit() else int(after_seq)

    async def generator():
        nonlocal cursor
        idle = 0
        while True:
            rows = events.tail(cursor, project_id=project_id, limit=200)
            for row in rows:
                cursor = int(row["seq"])
                yield f"id: {row['seq']}\nevent: {row['type']}\ndata: {json.dumps(row, ensure_ascii=False)}\n\n"
            if rows:
                idle = 0
            else:
                idle += 1
                if idle % 30 == 0:
                    yield ": keep-alive\n\n"
            await asyncio.sleep(0.5)

    return StreamingResponse(
        generator(),
        media_type="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no", "Connection": "keep-alive"},
    )


@router.post("/api/projects/{project_id}/dag/backfill")
def dag_backfill(project_id: str, claims: dict = Depends(require("write"))) -> dict[str, Any]:
    _guard(claims, project_id, "write")
    result = dag.backfill(project_id, actor=str(claims.get("sub") or "operator"))
    result["verification"] = dag.verify_against_legacy(project_id)
    return result


@router.get("/api/dag/state")
def dag_state(claims: dict = Depends(require("read"))) -> dict[str, Any]:
    return {
        "status_index": dag.status_index(),
        "statuses_in_use": dag.check_statuses(),
        "terminal": dag.terminal_statuses(),
        "edges": int(db.scalar("SELECT COUNT(*) FROM task_edges", default=0) or 0),
        "checks": int(db.scalar("SELECT COUNT(*) FROM task_checks", default=0) or 0),
        "events": events.last_seq(),
        "roles": [role["role_id"] for role in roles_service.listing()],
        "audit_seq": audit.last_seq(),
    }
