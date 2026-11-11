"""HTTP API (FastAPI). One process, loopback only, token-scoped.

Everything the MCP server and the Kanban UI need is here; nothing here pretends
to be more than a thin, validated shell over :mod:`apkplat.services`.
"""
from __future__ import annotations

import asyncio
import json
import shutil
import sqlite3
import time
from pathlib import Path
from typing import Any

from fastapi import Body, Depends, FastAPI, File, Form, HTTPException, Query, Request, UploadFile
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, HTMLResponse, JSONResponse, StreamingResponse
from fastapi.staticfiles import StaticFiles

from .. import agents as agents_module
from .. import audit, dynamic as dynamic_module, indexer, pipeline_static, reports, toolchain
from ..apkfile import ApkError
from ..config import settings
from ..db import db, utcnow
from ..services import artifacts as artifacts_service
from ..services import auth as auth_service
from ..services import devices as devices_service
from ..services import evidence as evidence_service
from ..services import projects as projects_service
from ..services import queue as queue_service
from ..services import tasks as tasks_service
from ..state import TransitionError, column_of
from ..util import dumps, new_id
from .security import admin_guard, claims_for, require

FRONTEND = settings.root / "frontend" / "dist"
STARTED_AT = time.time()


def create_app() -> FastAPI:
    app = FastAPI(title="APK Research Platform", version="1.0.0", docs_url="/api/docs", openapi_url="/api/openapi.json")
    app.add_middleware(
        CORSMiddleware,
        allow_origins=["http://127.0.0.1", "http://localhost", settings.public_base_url],
        allow_origin_regex=r"http://(127\.0\.0\.1|localhost)(:\d+)?",
        allow_credentials=False,
        allow_methods=["*"],
        allow_headers=["*"],
    )
    applied: list[str] = []

    @app.on_event("startup")
    def _startup() -> None:
        settings.ensure_dirs()
        applied.extend(db.migrate())
        # Roles live in the database so a policy change is auditable; seed them once the
        # schema exists (importing this module must not require a migrated database).
        from ..services import roles as roles_service

        roles_service.seed()

    # -- error mapping -----------------------------------------------------
    @app.exception_handler(TransitionError)
    async def _transition_error(_: Request, exc: TransitionError) -> JSONResponse:
        return JSONResponse(status_code=409, content={"error_code": exc.code, "message": exc.message})

    @app.exception_handler(tasks_service.TaskConflict)
    async def _conflict(_: Request, exc: tasks_service.TaskConflict) -> JSONResponse:
        return JSONResponse(status_code=409, content={"error_code": "version_conflict", "message": str(exc)})

    @app.exception_handler(tasks_service.ApprovalNotFound)
    async def _approval_missing(_: Request, exc: tasks_service.ApprovalNotFound) -> JSONResponse:
        return JSONResponse(
            status_code=404,
            content={"error_code": "approval_not_found", "message": f"no approval {exc.approval_id}"},
        )

    @app.exception_handler(evidence_service.EvidenceError)
    async def _evidence_error(_: Request, exc: evidence_service.EvidenceError) -> JSONResponse:
        return JSONResponse(status_code=422, content={"error_code": "evidence_rejected", "message": str(exc)})

    @app.exception_handler(devices_service.LeaseConflict)
    async def _lease_error(_: Request, exc: devices_service.LeaseConflict) -> JSONResponse:
        audit.record("lease_collision_blocked", actor="api", payload={"message": str(exc)})
        return JSONResponse(status_code=409, content={"error_code": "lease_conflict", "message": str(exc)})

    @app.exception_handler(indexer.IndexError_)
    async def _index_missing(_: Request, exc: indexer.IndexError_) -> JSONResponse:
        """A project that has not run the static stage has no index yet.

        This is a client-visible state, not a server fault: answer 409 so the
        console can say "run the static stage first" instead of showing 500.
        """
        return JSONResponse(status_code=409, content={"error_code": "index_unavailable", "message": str(exc)})

    @app.exception_handler(pipeline_static.StageError)
    async def _stage_error(_: Request, exc: pipeline_static.StageError) -> JSONResponse:
        return JSONResponse(
            status_code=500,
            content={"error_code": exc.code, "message": exc.message, "stage": exc.stage, "detail": exc.detail},
        )

    # -- health / system ---------------------------------------------------
    @app.get("/api/health")
    def health() -> dict[str, Any]:
        db_ok, db_error = True, None
        try:
            db.scalar("SELECT 1", default=1)
        except Exception as exc:  # noqa: BLE001
            db_ok, db_error = False, str(exc)
        usage = shutil.disk_usage(str(settings.storage))
        return {
            "ok": db_ok,
            "version": "1.0.0",
            "uptime_seconds": int(time.time() - STARTED_AT),
            "auth_mode": "token" if settings.require_auth else "local",
            "migrations_applied": applied,
            "db": {"url": settings.db_url, "ok": db_ok, "error": db_error},
            "storage": {"path": str(settings.storage), "free_bytes": usage.free, "total_bytes": usage.total},
            "queue": queue_service.stats(),
            "audit_seq": audit.last_seq(),
            "concurrency": {
                "static_workers": settings.static_workers,
                "model_concurrency": settings.model_concurrency,
                "model_concurrency_source": "config default (taskbook section concurrency initial values)",
            },
            "tools": toolchain.probe_versions(),
            "worker_policy": {
                "path": toolchain.policy()["policy_path"],
                "loaded": toolchain.policy()["policy_loaded"],
                "error": toolchain.policy()["policy_error"],
                "allowed_executables": toolchain.policy()["allowed_executables"],
                "max_timeout_seconds": toolchain.policy()["max_timeout_seconds"],
            },
        }

    @app.post("/api/auth/token")
    def issue_token(
        payload: dict = Body(default_factory=dict), _: None = Depends(admin_guard)
    ) -> dict[str, Any]:
        projects = payload.get("projects") or []
        scopes = payload.get("scopes") or ["read", "write"]
        subject = payload.get("subject") or "agent"
        if not projects:
            raise HTTPException(status_code=422, detail={"error_code": "projects_required", "message": "at least one project id"})
        if "*" in projects:
            raise HTTPException(
                status_code=422,
                detail={"error_code": "wildcard_forbidden", "message": "a token may not span every project"},
            )
        return auth_service.issue(projects, subject=subject, scopes=scopes, ttl=payload.get("ttl"))

    @app.get("/api/metrics")
    def metrics(_: dict = Depends(require("read"))) -> dict[str, Any]:
        return _compute_metrics()

    # -- projects ----------------------------------------------------------
    @app.post("/api/projects", status_code=201)
    async def create_project(
        name: str = Form(...),
        apk: UploadFile = File(...),
        goal: str | None = Form(None),
        ground_truth: str | None = Form(None),
        policy_id: str = Form("default"),
        claims: dict = Depends(require("write")),
    ) -> dict[str, Any]:
        truth = None
        if ground_truth:
            try:
                truth = json.loads(ground_truth)
            except json.JSONDecodeError as exc:
                raise HTTPException(
                    status_code=422,
                    detail={"error_code": "invalid_ground_truth", "message": f"ground_truth is not JSON: {exc}"},
                ) from exc
        upload_dir = settings.storage / "tmp"
        upload_dir.mkdir(parents=True, exist_ok=True)
        tmp = upload_dir / f"upload-{new_id()}.apk"
        written = 0
        cap = settings.max_upload_mb * 1024 * 1024
        try:
            with open(tmp, "wb") as fh:
                while chunk := await apk.read(1 << 20):
                    written += len(chunk)
                    if written > cap:
                        raise HTTPException(
                            status_code=413,
                            detail={"error_code": "upload_too_large", "message": f"limit {settings.max_upload_mb} MB"},
                        )
                    fh.write(chunk)
        except Exception:
            tmp.unlink(missing_ok=True)
            raise
        try:
            project = projects_service.create(
                name,
                tmp,
                apk.filename or "app.apk",
                goal=goal,
                ground_truth=truth,
                policy_id=policy_id,
                actor="api",
            )
        except ApkError as exc:
            tmp.unlink(missing_ok=True)
            return JSONResponse(status_code=422, content={"error_code": exc.code, "message": exc.message})
        job_id = queue_service.enqueue(
            "static_pipeline",
            project_id=project["id"],
            payload={"project_id": project["id"]},
            idempotency_key=f"static:{project['id']}",
            actor="api",
        )
        return {"project": project, "job_id": job_id}

    @app.get("/api/projects")
    def list_projects(_: dict = Depends(require("read"))) -> dict[str, Any]:
        return {"projects": projects_service.list_projects()}

    @app.get("/api/projects/{project_id}")
    def get_project(project_id: str, _: dict = Depends(require("read"))) -> dict[str, Any]:
        project = projects_service.get(project_id)
        if not project:
            raise HTTPException(status_code=404, detail={"error_code": "project_not_found"})
        return {"project": project, "manifest": projects_service.manifest(project_id)}

    @app.get("/api/projects/{project_id}/board")
    def get_board(project_id: str, _: dict = Depends(require("read"))) -> dict[str, Any]:
        _ensure_project(project_id)
        board = projects_service.board(project_id)
        board["approvals"] = tasks_service.pending_approvals(project_id)
        return board

    # -- tasks -------------------------------------------------------------
    @app.get("/api/projects/{project_id}/tasks")
    def list_tasks(
        project_id: str, status: str | None = None, role: str | None = None, _: dict = Depends(require("read"))
    ) -> dict[str, Any]:
        _ensure_project(project_id)
        return {"tasks": tasks_service.list_tasks(project_id, status=status, role=role)}

    @app.post("/api/projects/{project_id}/tasks", status_code=201)
    def create_task(project_id: str, payload: dict = Body(...), _: dict = Depends(require("write"))) -> dict[str, Any]:
        _ensure_project(project_id)
        if not str(payload.get("title") or "").strip():
            raise HTTPException(status_code=422, detail={"error_code": "title_required", "message": "title is required"})
        return tasks_service.create(
            project_id,
            role=payload.get("role", "static"),
            title=payload["title"],
            goal=payload.get("goal"),
            parent_task_id=payload.get("parent_task_id"),
            depends_on=payload.get("depends_on") or [],
            priority=int(payload.get("priority", 5)),
            actor=payload.get("actor", "agent"),
            needs_approval=bool(payload.get("needs_approval")),
        )

    @app.get("/api/tasks/{task_id}")
    def get_task(task_id: str, _: dict = Depends(require("read"))) -> dict[str, Any]:
        task = tasks_service.get(task_id)
        if not task:
            raise HTTPException(status_code=404, detail={"error_code": "task_not_found"})
        return task

    @app.patch("/api/tasks/{task_id}")
    def patch_task(task_id: str, payload: dict = Body(...), _: dict = Depends(require("write"))) -> dict[str, Any]:
        reserved = {"status", "expected_version", "approval_id", "reason", "actor"}
        fields = {k: v for k, v in payload.items() if k not in reserved}
        unknown = sorted(key for key in fields if key not in tasks_service.EDITABLE_FIELDS)
        if unknown:
            raise HTTPException(
                status_code=422,
                detail={
                    "error_code": "field_not_editable",
                    "message": f"not editable: {', '.join(unknown)}",
                    "editable": sorted(tasks_service.EDITABLE_FIELDS),
                },
            )
        return tasks_service.update(
            task_id,
            actor=payload.get("actor", "agent"),
            status=payload.get("status"),
            fields=fields,
            expected_version=payload.get("expected_version"),
            approval_id=payload.get("approval_id"),
            reason=payload.get("reason"),
        )

    @app.get("/api/tasks/{task_id}/runs")
    def list_runs(task_id: str, limit: int = 100, _: dict = Depends(require("read"))) -> dict[str, Any]:
        task = tasks_service.get(task_id)
        if not task:
            raise HTTPException(status_code=404, detail={"error_code": "task_not_found"})
        rows = db.query(
            "SELECT * FROM agent_runs WHERE task_id = ? ORDER BY started_at ASC LIMIT ?", (task_id, limit)
        )
        return {"task_id": task_id, "runs": [dict(row) for row in rows]}

    @app.post("/api/tasks/{task_id}/runs", status_code=201)
    def record_run(task_id: str, payload: dict = Body(default_factory=dict), _: dict = Depends(require("write"))) -> dict:
        if not tasks_service.get(task_id):
            raise HTTPException(status_code=404, detail={"error_code": "task_not_found"})
        run_id = tasks_service.record_run(
            task_id,
            role=payload.get("role", "agent"),
            model_id=payload.get("model_id"),
            dsh_session_ref=payload.get("dsh_session_ref"),
            notes=payload.get("notes"),
        )
        return {"run_id": run_id}

    @app.post("/api/tasks/{task_id}/approvals", status_code=201)
    def request_approval_endpoint(
        task_id: str, payload: dict = Body(...), _: dict = Depends(require("write"))
    ) -> dict[str, Any]:
        task = tasks_service.get(task_id)
        if not task:
            raise HTTPException(status_code=404, detail={"error_code": "task_not_found"})
        approval_id = tasks_service.request_approval(
            task["project_id"],
            task_id=task_id,
            kind=payload.get("kind", "manual"),
            requested_by=payload.get("requested_by", "agent"),
            reason=payload.get("reason"),
        )
        return {"approval_id": approval_id}

    @app.post("/api/approvals/{approval_id}/decide")
    def decide_approval_endpoint(
        approval_id: str, payload: dict = Body(...), _: dict = Depends(require("write"))
    ) -> dict[str, Any]:
        decision = str(payload.get("decision") or "").strip().lower()
        if decision not in {"approved", "rejected"}:
            raise HTTPException(
                status_code=422,
                detail={"error_code": "invalid_decision", "message": "decision must be 'approved' or 'rejected'"},
            )
        row = tasks_service.decide_approval(
            approval_id,
            decision,
            payload.get("decided_by", "human"),
            payload.get("note"),
        )
        return dict(row)

    # -- artifacts ---------------------------------------------------------
    @app.get("/api/projects/{project_id}/artifacts")
    def list_artifacts(
        project_id: str, kind: str | None = None, task_id: str | None = None, _: dict = Depends(require("read"))
    ) -> dict[str, Any]:
        _ensure_project(project_id)
        kinds = [k.strip() for k in kind.split(",")] if kind else None
        return {"artifacts": artifacts_service.list_artifacts(project_id, kinds=kinds, task_id=task_id)}

    @app.get("/api/artifacts/{artifact_id}")
    def get_artifact(artifact_id: str, _: dict = Depends(require("read"))) -> dict[str, Any]:
        row = artifacts_service.get(artifact_id)
        if not row:
            raise HTTPException(status_code=404, detail={"error_code": "artifact_not_found"})
        return row

    @app.get("/api/artifacts/{artifact_id}/text")
    def artifact_text(
        artifact_id: str,
        limit: int = Query(20000, ge=100, le=2_000_000),
        tail: bool = False,
        _: dict = Depends(require("read")),
    ) -> dict[str, Any]:
        try:
            return artifacts_service.read_text(artifact_id, limit=limit, tail=tail)
        except KeyError:
            raise HTTPException(status_code=404, detail={"error_code": "artifact_not_found"})
        except artifacts_service.ArtifactError as exc:
            raise HTTPException(status_code=410, detail={"error_code": "artifact_bytes_missing", "message": str(exc)})

    @app.get("/api/artifacts/{artifact_id}/download")
    def artifact_download(artifact_id: str, _: dict = Depends(require("read"))) -> FileResponse:
        row = artifacts_service.get(artifact_id)
        if not row:
            raise HTTPException(status_code=404, detail={"error_code": "artifact_not_found"})
        path = artifacts_service.path_of(row)
        if not path.exists():
            raise HTTPException(status_code=410, detail={"error_code": "artifact_bytes_missing"})
        return FileResponse(path, filename=path.name)

    # -- evidence ----------------------------------------------------------
    @app.get("/api/projects/{project_id}/evidence")
    def list_evidence(
        project_id: str, task_id: str | None = None, kind: str | None = None, _: dict = Depends(require("read"))
    ) -> dict[str, Any]:
        _ensure_project(project_id)
        return {"evidence": evidence_service.list_evidence(project_id, task_id=task_id, kind=kind)}

    @app.post("/api/projects/{project_id}/evidence", status_code=201)
    def record_evidence(project_id: str, payload: dict = Body(...), claims: dict = Depends(require("write"))) -> dict:
        _ensure_project(project_id)
        return evidence_service.record(
            project_id,
            kind=payload.get("kind", "note"),
            locator=payload.get("locator") or {},
            excerpt=payload.get("excerpt") or "",
            artifact_id=payload.get("artifact_id"),
            task_id=payload.get("task_id"),
            claim=payload.get("claim"),
            confidence=payload.get("confidence", "medium"),
            created_by=payload.get("created_by") or claims.get("sub", "agent"),
        )

    @app.get("/api/evidence/{evidence_id}")
    def get_evidence(evidence_id: str, _: dict = Depends(require("read"))) -> dict[str, Any]:
        row = evidence_service.get(evidence_id)
        if not row:
            raise HTTPException(status_code=404, detail={"error_code": "evidence_not_found"})
        return row

    # -- verification / reports -------------------------------------------
    @app.get("/api/projects/{project_id}/verify")
    def verify_project(project_id: str, _: dict = Depends(require("read"))) -> dict[str, Any]:
        _ensure_project(project_id)
        chain = artifacts_service.verify_chain(project_id)
        ev = evidence_service.verify(project_id)
        return {
            "project_id": project_id,
            "artifacts": chain,
            "evidence": ev,
            "ok": not chain["failures"] and not ev["failures"],
            "checked_at": utcnow(),
        }

    @app.post("/api/projects/{project_id}/report", status_code=201)
    def generate_report(project_id: str, payload: dict = Body(default_factory=dict), _: dict = Depends(require("write"))) -> dict:
        _ensure_project(project_id)
        return reports.generate(project_id, task_id=payload.get("task_id"), actor=payload.get("actor", "api"))

    # -- agents ------------------------------------------------------------
    @app.post("/api/projects/{project_id}/agents/run", status_code=202)
    def agents_run(project_id: str, payload: dict = Body(default_factory=dict), _: dict = Depends(require("write"))) -> dict:
        """Queue the orchestrator (static -> review -> report) as a durable job."""
        _ensure_project(project_id)
        job_id = queue_service.enqueue(
            "agent_orchestrate",
            project_id=project_id,
            payload={"project_id": project_id, "use_model": payload.get("use_model")},
            idempotency_key=f"agents:{project_id}:{payload.get('nonce') or 'default'}",
            actor="api",
        )
        return {"job_id": job_id, "job": queue_service.get(job_id)}

    @app.get("/api/projects/{project_id}/agents/runs")
    def agents_runs(project_id: str, limit: int = 100, _: dict = Depends(require("read"))) -> dict:
        _ensure_project(project_id)
        rows = db.query(
            "SELECT * FROM agent_runs WHERE project_id = ? ORDER BY started_at DESC LIMIT ?", (project_id, limit)
        )
        return {"runs": [dict(row) for row in rows]}

    @app.get("/api/projects/{project_id}/agent-runs")
    def project_agent_runs(project_id: str, limit: int = 200, _: dict = Depends(require("read"))) -> dict:
        """Run history, newest first (the UI reads this; it used to be write-only)."""
        _ensure_project(project_id)
        rows = db.query(
            "SELECT * FROM agent_runs WHERE project_id = ? ORDER BY started_at DESC LIMIT ?", (project_id, limit)
        )
        return {"project_id": project_id, "runs": [dict(row) for row in rows], "count": len(rows)}

    @app.post("/api/projects/{project_id}/review", status_code=201)
    def project_review(project_id: str, payload: dict = Body(default_factory=dict), _: dict = Depends(require("write"))) -> dict:
        """Run the reviewer now (claims default to the project's evidence rows)."""
        _ensure_project(project_id)
        task_id = payload.get("task_id")
        claims = payload.get("claims")
        if task_id:
            result = agents_module.review_task(project_id, task_id, claims=claims, use_model=payload.get("use_model"))
        else:
            result = agents_module.review_claims(project_id, claims or agents_module.claims_from_evidence(project_id),
                                                 use_model=payload.get("use_model"))
        return {
            "verdict": result["verdict"],
            "accepted": len(result["accepted"]),
            "rejected": result["rejected"],
            "traceability": result["traceability"],
        }

    # -- dynamic stage (P4) ------------------------------------------------
    @app.post("/api/projects/{project_id}/dynamic/run", status_code=202)
    def dynamic_run(project_id: str, payload: dict = Body(default_factory=dict), claims: dict = Depends(require("write"))) -> dict:
        """Create a dynamic task (unless one is named) and queue the device session."""
        _ensure_project(project_id)
        task_id = payload.get("task_id")
        if task_id:
            task = tasks_service.get(task_id)
            if not task or task["project_id"] != project_id:
                raise HTTPException(status_code=404, detail={"error_code": "task_not_found", "message": task_id})
        else:
            task = tasks_service.create(
                project_id,
                title=payload.get("title") or "Dynamic session",
                role="dynamic",
                actor=claims.get("sub", "api"),
            )
            task_id = task["id"]
        job_id = dynamic_module.enqueue(
            project_id,
            task_id=task_id,
            transport_name=payload.get("transport"),
            device_id=payload.get("device_id"),
            idempotency_key=payload.get("idempotency_key"),
        )
        return {"task": task, "job_id": job_id, "job": queue_service.get(job_id)}

    @app.get("/api/projects/{project_id}/dynamic/runs")
    def dynamic_runs(project_id: str, _: dict = Depends(require("read"))) -> dict:
        _ensure_project(project_id)
        rows = artifacts_service.list_artifacts(project_id, kinds=None, limit=200)
        dynamic_artifacts = [row for row in rows if str(row["kind"]).startswith("device_")]
        wanted = {
            "dynamic_started",
            "dynamic_completed",
            "dynamic_failed",
            "device_lost",
            "device_wait",
            "dynamic_cleanup_verified",
            "dynamic_cleanup_incomplete",
        }
        events = [row for row in audit.tail(0, project_id=project_id, limit=400) if row["event_type"] in wanted]
        return {
            "artifacts": dynamic_artifacts,
            "leases": devices_service.list_leases(project_id=project_id, active_only=False),
            "events": events,
        }

    # -- events ------------------------------------------------------------
    @app.get("/api/projects/{project_id}/events")
    def project_events(project_id: str, after: int = 0, limit: int = 200, _: dict = Depends(require("read"))) -> dict:
        _ensure_project(project_id)
        return {"events": audit.tail(after_seq=after, project_id=project_id, limit=limit)}

    @app.get("/api/events/stream")
    async def event_stream(after: int = 0, project_id: str | None = None, token: str | None = None) -> StreamingResponse:
        if settings.require_auth:
            claims_for(f"Bearer {token}" if token else None, project_id, "read")

        async def gen():
            seq = after
            idle = 0.0
            while True:
                rows = audit.tail(after_seq=seq, project_id=project_id, limit=100)
                if rows:
                    for row in rows:
                        seq = max(seq, int(row["seq"]))
                        yield f"id: {row['seq']}\ndata: {dumps(dict(row))}\n\n"
                    idle = 0.0
                else:
                    idle += 1.0
                    if idle >= 15:
                        yield ": keep-alive\n\n"
                        idle = 0.0
                await asyncio.sleep(1.0)

        return StreamingResponse(gen(), media_type="text/event-stream")

    # -- queue -------------------------------------------------------------
    @app.get("/api/queue")
    def queue_list(project_id: str | None = None, status: str | None = None, _: dict = Depends(require("read"))) -> dict:
        return {"stats": queue_service.stats(), "jobs": queue_service.list_jobs(project_id=project_id, status=status)}

    @app.post("/api/jobs/{job_id}/cancel")
    def job_cancel(job_id: str, _: dict = Depends(require("write"))) -> dict:
        queue_service.cancel(job_id)
        return {"job": queue_service.get(job_id)}

    # -- devices -----------------------------------------------------------
    @app.get("/api/devices")
    def device_list(_: dict = Depends(require("read"))) -> dict[str, Any]:
        return {"devices": devices_service.list_devices(), "leases": devices_service.list_leases(active_only=True)}

    @app.post("/api/devices/register", status_code=201)
    def device_register(payload: dict = Body(...), _: dict = Depends(require("write"))) -> dict[str, Any]:
        serial = str(payload.get("adb_serial") or "").strip()
        if not serial:
            raise HTTPException(
                status_code=422, detail={"error_code": "adb_serial_required", "message": "adb_serial is required"}
            )
        return devices_service.register(
            serial,
            device_type=payload.get("type", "emulator"),
            capabilities=payload.get("capabilities") or {},
            alias=payload.get("alias"),
        )

    @app.post("/api/projects/{project_id}/devices/lease", status_code=201)
    def lease_device(project_id: str, payload: dict = Body(default_factory=dict), _: dict = Depends(require("write"))) -> dict:
        _ensure_project(project_id)
        return devices_service.acquire(
            project_id,
            task_id=payload.get("task_id"),
            owner=payload.get("owner", "dynamic-worker"),
            device_id=payload.get("device_id"),
            ttl=payload.get("ttl"),
        )

    @app.post("/api/leases/{lease_id}/heartbeat")
    def lease_heartbeat(lease_id: str, payload: dict = Body(default_factory=dict), _: dict = Depends(require("write"))) -> dict:
        return devices_service.heartbeat(lease_id, owner=payload.get("owner"), ttl=payload.get("ttl"))

    @app.post("/api/leases/{lease_id}/release")
    def lease_release(lease_id: str, payload: dict = Body(default_factory=dict), _: dict = Depends(require("write"))) -> dict:
        return devices_service.release(lease_id, owner=payload.get("owner"), reason=payload.get("reason", "released"))

    # -- read-only index probes (used by the UI and by tests) --------------
    @app.get("/api/projects/{project_id}/search")
    def index_search(
        project_id: str,
        q: str = Query(..., min_length=1),
        kind: str | None = None,
        limit: int = Query(50, ge=1, le=500),
        _: dict = Depends(require("read")),
    ) -> dict[str, Any]:
        _ensure_project(project_id)
        return {"query": q, "results": indexer.search_code(project_id, q, kind=kind, limit=limit)}

    @app.get("/api/projects/{project_id}/packages")
    def index_packages(project_id: str, _: dict = Depends(require("read"))) -> dict[str, Any]:
        _ensure_project(project_id)
        return {"packages": indexer.list_packages(project_id), "stats": indexer.stats(project_id)}

    # -- P1 bridge (run capabilities + scoped tools) -----------------------
    from . import bridge_api

    app.include_router(bridge_api.router)

    # -- P2 dependency DAG, checks, roles, platform events -----------------
    from . import dag_api

    app.include_router(dag_api.router)

    # -- P3 sandbox, typed evidence, HTML report ---------------------------
    from . import p3_api
    from . import p4_api
    from . import p5_api
    from . import p6_api

    app.include_router(p3_api.router)
    app.include_router(p4_api.router)
    app.include_router(p5_api.router)
    app.include_router(p6_api.router)

    # -- static UI ---------------------------------------------------------
    if FRONTEND.exists():
        app.mount("/static", StaticFiles(directory=str(FRONTEND)), name="static")

        @app.get("/", response_class=HTMLResponse)
        def index() -> HTMLResponse:
            return HTMLResponse((FRONTEND / "index.html").read_text(encoding="utf-8"))

    return app


def _ensure_project(project_id: str) -> None:
    if not db.one("SELECT id FROM projects WHERE id = ?", (project_id,)):
        raise HTTPException(status_code=404, detail={"error_code": "project_not_found"})


def _compute_metrics() -> dict[str, Any]:
    def count(event_type: str) -> int:
        return int(db.scalar("SELECT COUNT(*) FROM audit_events WHERE event_type = ?", (event_type,), 0) or 0)

    projects = int(db.scalar("SELECT COUNT(*) FROM projects", default=0) or 0)
    rejects = count("apk_ingest_rejected")
    tool_calls = [row for row in db.query("SELECT payload_json FROM audit_events WHERE event_type = 'mcp_tool_call'")]
    schema_ok = sum(1 for row in tool_calls if '"schema_ok":true' in (row["payload_json"] or "").replace(" ", ""))
    tasks_total = int(db.scalar("SELECT COUNT(*) FROM tasks", default=0) or 0)
    model_calls = float(db.scalar("SELECT COALESCE(AVG(model_calls),0) FROM tasks", default=0) or 0)
    latencies = [
        int(json.loads(row["payload_json"]).get("latency_ms", 0))
        for row in db.query("SELECT payload_json FROM audit_events WHERE event_type = 'model_call'")
        if row["payload_json"]
    ]
    reclaimed = [row for row in db.query("SELECT payload_json FROM audit_events WHERE event_type = 'job_lease_reclaimed'")]
    recovered = count("job_recovered_after_restart")
    isolated = count("project_isolation_violation")
    collisions = count("lease_collision_blocked")
    reviewer_returns = count("review_returned_no_evidence")
    evidence_rate = 1.0
    projects_all = [row["id"] for row in db.query("SELECT id FROM projects")]
    if projects_all:
        rates = []
        for pid in projects_all:
            try:
                rates.append(evidence_service.verify(pid)["traceability_rate"])
            except Exception:  # noqa: BLE001
                continue
        if rates:
            evidence_rate = round(sum(rates) / len(rates), 4)
    return {
        "ingest_success_rate": round(projects / (projects + rejects), 4) if (projects + rejects) else None,
        "ingest_attempts": projects + rejects,
        "tool_call_schema_valid_rate": round(schema_ok / len(tool_calls), 4) if tool_calls else None,
        "tool_calls": len(tool_calls),
        "evidence_traceability_rate": evidence_rate,
        "project_isolation_failures": isolated,
        "device_lease_collision": collisions,
        "task_recovery_success": round(recovered / len(reclaimed), 4) if reclaimed else None,
        "reclaimed_leases": len(reclaimed),
        "false_confident_claims": reviewer_returns,
        "model_calls_per_task": round(model_calls, 2) if tasks_total else 0,
        "model_api_latency_ms_avg": round(sum(latencies) / len(latencies), 1) if latencies else None,
        "tasks_total": tasks_total,
        "projects_total": projects,
        "generated_at": utcnow(),
    }


app = create_app()
