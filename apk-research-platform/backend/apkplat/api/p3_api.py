"""P3 API surface: sandbox execution, typed evidence, and the HTML report view.

Two rules carried over from P1/P2 and worth restating, because they are what makes the
numbers in the report mean something:

* an artifact that changed on disk can never keep a VERIFIED verdict (integrity is
  recomputed from the bytes, never taken from a stored hash);
* anything the platform cannot observe is reported as ``not_observed`` /
  ``strong_isolation_unavailable`` instead of being papered over.
"""
from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Body, Depends, Header, HTTPException, Query
from fastapi.responses import HTMLResponse

from .. import audit, reports
from ..services import artifacts as artifacts_service
from ..services import evidence_types
from ..services import sandbox as sandbox_service
from ..services import tasks as tasks_service
from .security import require

router = APIRouter(prefix="/api", tags=["p3"])


def _allowed(claims: dict, project_id: str) -> None:
    """Id-scoped routes carry no project in the path, so check ownership here.

    Without this, a token minted for project A could read an evidence id or sandbox run
    that belongs to project B just by guessing the id - the exact isolation hole the
    taskbook asks to be closed at the API boundary, not only in the UI.
    """
    projects = claims.get("prj") or []
    if "*" in projects or project_id in projects:
        return
    raise HTTPException(
        status_code=403, detail={"error_code": "project_denied", "message": "token is not scoped to this project"}
    )

def _payload(payload: dict[str, Any] | None) -> dict[str, Any]:
    return dict(payload or {})


def _task_belongs(task_id: str | None, project_id: str) -> None:
    if not task_id:
        return
    task = tasks_service.get(task_id)
    if task is None:
        raise HTTPException(status_code=404, detail={"error_code": "task_not_found", "message": f"{task_id} does not exist"})
    if task["project_id"] != project_id:
        raise HTTPException(
            status_code=422, detail={"error_code": "task_project_mismatch", "message": "task belongs to another project"}
        )


@router.post("/projects/{project_id}/sandbox/run", status_code=201)
def sandbox_run(
    project_id: str,
    payload: dict[str, Any] = Body(default_factory=dict),
    claims: dict = Depends(require("write")),
) -> dict[str, Any]:
    body = _payload(payload)
    script_artifact_id = str(body.get("script_artifact_id") or "").strip()
    if not script_artifact_id:
        raise HTTPException(
            status_code=422, detail={"error_code": "script_required", "message": "script_artifact_id is required"}
        )
    task_id = body.get("task_id")
    _task_belongs(task_id, project_id)
    argv = body.get("argv") or []
    if not isinstance(argv, list):
        raise HTTPException(status_code=422, detail={"error_code": "invalid_argv", "message": "argv must be a list"})
    try:
        run = sandbox_service.run_script(
            project_id,
            script_artifact_id=script_artifact_id,
            argv=[str(item) for item in argv],
            task_id=task_id,
            run_id=body.get("run_id"),
            timeout=int(body.get("timeout") or sandbox_service.DEFAULT_TIMEOUT),
            network=str(body.get("network") or "none"),
            isolation=str(body.get("isolation") or "cooperative"),
            replay_of=body.get("replay_of"),
            actor=str(claims.get("sub") or "api"),
        )
    except sandbox_service.SandboxError as exc:
        raise HTTPException(status_code=exc.status, detail=exc.as_error()) from exc
    return {"sandbox_run": run}


@router.get("/projects/{project_id}/sandbox/runs")
def sandbox_runs(
    project_id: str,
    limit: int = Query(default=100, ge=1, le=500),
    claims: dict = Depends(require("read")),
) -> dict[str, Any]:
    rows = sandbox_service.listing(project_id, limit=limit)
    return {"project_id": project_id, "runs": [dict(row) for row in rows], "count": len(rows)}


@router.get("/sandbox/runs/{run_id}")
def sandbox_run_get(run_id: str, claims: dict = Depends(require("read"))) -> dict[str, Any]:
    run = sandbox_service.get(run_id)
    if run is None:
        raise HTTPException(status_code=404, detail={"error_code": "sandbox_run_not_found", "message": run_id})
    _allowed(claims, run["project_id"])
    return {"sandbox_run": run}


@router.post("/sandbox/runs/{run_id}/replay", status_code=201)
def sandbox_replay(
    run_id: str, payload: dict[str, Any] = Body(default_factory=dict), claims: dict = Depends(require("write"))
) -> dict[str, Any]:
    original = sandbox_service.get(run_id)
    if original is None:
        raise HTTPException(status_code=404, detail={"error_code": "sandbox_run_not_found", "message": run_id})
    _allowed(claims, original["project_id"])
    body = _payload(payload)
    try:
        run = sandbox_service.replay(
            original["project_id"], run_id, actor=str(claims.get("sub") or "api"), run_ref=body.get("run_ref")
        )
    except sandbox_service.SandboxError as exc:
        raise HTTPException(status_code=exc.status, detail=exc.as_error()) from exc
    return {"sandbox_run": run}


@router.post("/projects/{project_id}/evidence/typed", status_code=201)
def typed_evidence_record(
    project_id: str,
    payload: dict[str, Any] = Body(default_factory=dict),
    x_actor: str | None = Header(default=None, alias="X-Actor"),
    claims: dict = Depends(require("write")),
) -> dict[str, Any]:
    body = _payload(payload)
    task_id = body.get("task_id")
    _task_belongs(task_id, project_id)
    try:
        row = evidence_types.record(
            project_id,
            evidence_type=str(body.get("evidence_type") or ""),
            locator=body.get("locator") or {},
            artifact_id=str(body.get("artifact_id") or ""),
            claim=body.get("claim"),
            task_id=task_id,
            run_id=body.get("run_id"),
            expected=body.get("expected"),
            observed=body.get("observed"),
            confidence=str(body.get("confidence") or "medium"),
            supersedes_id=body.get("supersedes_id"),
            producer=str(x_actor or claims.get("sub") or "api"),
            source_tool=body.get("source_tool"),
            tool_version=body.get("tool_version"),
            provenance=body.get("provenance"),
        )
    except evidence_types.EvidenceTypeError as exc:
        raise HTTPException(status_code=exc.status, detail=exc.as_error()) from exc
    return {"evidence": row}


@router.get("/projects/{project_id}/evidence/typed")
def typed_evidence_list(
    project_id: str,
    evidence_type: str | None = Query(default=None),
    task_id: str | None = Query(default=None),
    limit: int = Query(default=200, ge=1, le=1000),
    claims: dict = Depends(require("read")),
) -> dict[str, Any]:
    rows = evidence_types.listing(project_id, evidence_type=evidence_type, task_id=task_id, limit=limit)
    return {"project_id": project_id, "evidence": rows, "count": len(rows)}


@router.get("/evidence/typed/{evidence_id}")
def typed_evidence_get(evidence_id: str, claims: dict = Depends(require("read"))) -> dict[str, Any]:
    row = evidence_types.get(evidence_id)
    if row is None:
        raise HTTPException(status_code=404, detail={"error_code": "evidence_not_found", "message": evidence_id})
    _allowed(claims, row["project_id"])
    return {"evidence": row}


@router.post("/evidence/typed/{evidence_id}/reproduce")
def typed_evidence_reproduce(
    evidence_id: str,
    payload: dict[str, Any] = Body(default_factory=dict),
    claims: dict = Depends(require("write")),
) -> dict[str, Any]:
    body = _payload(payload)
    run_id = body.get("run_id")
    if not run_id:
        raise HTTPException(status_code=422, detail={"error_code": "run_required", "message": "run_id is required"})
    current = evidence_types.get(evidence_id)
    if current is None:
        raise HTTPException(status_code=404, detail={"error_code": "evidence_not_found", "message": evidence_id})
    _allowed(claims, current["project_id"])
    try:
        row = evidence_types.mark_reproduced(evidence_id, by_run=str(run_id), note=str(body.get("note") or ""))
    except evidence_types.EvidenceTypeError as exc:
        raise HTTPException(status_code=exc.status, detail=exc.as_error()) from exc
    return {"evidence": row}


@router.get("/projects/{project_id}/evidence/summary")
def typed_evidence_summary(project_id: str, claims: dict = Depends(require("read"))) -> dict[str, Any]:
    return {"project_id": project_id, "summary": evidence_types.summary(project_id)}


@router.get("/projects/{project_id}/report.html", response_class=HTMLResponse)
def report_html(project_id: str, claims: dict = Depends(require("read"))) -> HTMLResponse:
    """Render the latest report artifact for this project.

    The markdown artifact is the source of truth; this view only re-renders it. It reads
    through the artifact registry (project-scoped) rather than any filesystem path the
    caller supplies, so a project token cannot pull another project's report.
    """
    rows = [row for row in artifacts_service.list_artifacts(project_id, limit=200) if row["kind"] == "report"]
    if not rows:
        raise HTTPException(status_code=404, detail={"error_code": "report_not_found", "message": "generate a report first"})
    latest = max(rows, key=lambda row: row["created_at"])
    payload = artifacts_service.read_text(latest["id"], limit=4_000_000)
    markdown = str(payload.get("text") or "")
    audit.record("report_viewed", project_id=project_id, actor=str(claims.get("sub") or "api"), payload={"artifact_id": latest["id"]})
    return HTMLResponse(reports.render_html(markdown, title=f"APK report 閳?{project_id}"))
