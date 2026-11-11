"""MCP server (stdio, JSON-RPC 2.0) exposing the APK analysis tool whitelist.

Design constraints from the taskbook:

* **whitelist only** — the sixteen tools below are the entire surface; there is no
  "run shell", "read arbitrary file" or "execute jadx with my flags" tool;
* **uniform envelope** — every call returns ``ok``, ``project_id``, ``task_id``,
  ``tool``, ``tool_version``, ``started_at``, ``duration_ms``, stdout/stderr
  artifact ids, ``produced_artifact_ids``, ``error_code``, ``retryable``;
* **big results land in files** — a payload over ``INLINE_MAX_BYTES`` is written to
  an artifact and the response carries the artifact id plus a truncated preview;
* **project scoping** — the server is launched with ``APKPLAT_MCP_PROJECTS``; a call
  naming a project outside that list is refused before it touches the database.

Protocol: newline-delimited JSON-RPC over stdin/stdout (MCP 2024-11-05). Diagnostics
go to stderr so the transport stays clean.
"""
from __future__ import annotations

import json
import os
import sys
import time
import traceback
from pathlib import Path
from typing import Any, Callable

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "backend"))

from apkplat import audit, indexer, reports  # noqa: E402
from apkplat.apkfile import write_json  # noqa: E402
from apkplat.config import settings  # noqa: E402
from apkplat.db import db, utcnow  # noqa: E402
from apkplat.services import artifacts as artifacts_service  # noqa: E402
from apkplat.services import evidence as evidence_service  # noqa: E402
from apkplat.services import projects as projects_service  # noqa: E402
from apkplat.services import queue as queue_service  # noqa: E402
from apkplat.services import tasks as tasks_service  # noqa: E402
from apkplat.state import TransitionError  # noqa: E402

TOOL_VERSION = "1.0.0"
PROTOCOL_VERSION = "2024-11-05"
INLINE_MAX_BYTES = 24 * 1024

ALLOWED_PROJECTS = [p.strip() for p in os.environ.get("APKPLAT_MCP_PROJECTS", "*").split(",") if p.strip()]
ACTOR = os.environ.get("APKPLAT_MCP_ACTOR", "dsh-agent")
# Tool surface filtering. The full 16-tool surface is fine for a headless worker, but a
# hosted agent should only see the few tools its current stage needs: an LLM with 16
# schemas spends context on tools it will never call. "*" keeps the historical behaviour.
ALLOWED_TOOLS = [t.strip() for t in os.environ.get("APKPLAT_MCP_ALLOW_TOOLS", "*").split(",") if t.strip()]


def enabled_tools() -> dict[str, dict]:
    """SCHEMAS restricted to APKPLAT_MCP_ALLOW_TOOLS (unknown names are dropped)."""
    if ALLOWED_TOOLS == ["*"]:
        return SCHEMAS
    return {name: spec for name, spec in SCHEMAS.items() if name in ALLOWED_TOOLS}


READ_ONLY_TOOLS = frozenset({
    "project_get", "apk_get_metadata", "apk_list_packages", "apk_search_code", "apk_read_method",
    "apk_read_manifest", "apk_search_resources", "artifact_list", "evidence_read", "task_get",
    "task_list",
})


# ---------------------------------------------------------------------------
# JSON schemas (kept next to the handlers so the two cannot drift)
# ---------------------------------------------------------------------------
SCHEMAS: dict[str, dict] = {
    "project_create": {
        "description": "Register an APK that is already inside the platform inbox as a new project.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "name": {"type": "string"},
                "apk_path": {"type": "string", "description": "Path inside storage/inbox (never an absolute host path)"},
                "goal": {"type": "string"},
                "policy_id": {"type": "string"},
            },
            "required": ["name", "apk_path"],
            "additionalProperties": False,
        },
    },
    "project_get": {
        "description": "Project record + manifest summary.",
        "inputSchema": {
            "type": "object",
            "properties": {"project_id": {"type": "string"}},
            "required": ["project_id"],
            "additionalProperties": False,
        },
    },
    "apk_get_metadata": {
        "description": "Package, version, SDK levels, permissions, components, signature digest.",
        "inputSchema": {
            "type": "object",
            "properties": {"project_id": {"type": "string"}},
            "required": ["project_id"],
            "additionalProperties": False,
        },
    },
    "apk_list_packages": {
        "description": "Packages present in the decompiled code, with class/method counts.",
        "inputSchema": {
            "type": "object",
            "properties": {"project_id": {"type": "string"}, "limit": {"type": "integer", "minimum": 1, "maximum": 500}},
            "required": ["project_id"],
            "additionalProperties": False,
        },
    },
    "apk_search_code": {
        "description": "Full-text search over classes, methods and fields. Returns file:line locators.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "project_id": {"type": "string"},
                "query": {"type": "string"},
                "kind": {"type": "string", "enum": ["class", "method", "field"]},
                "limit": {"type": "integer", "minimum": 1, "maximum": 200},
            },
            "required": ["project_id", "query"],
            "additionalProperties": False,
        },
    },
    "apk_read_method": {
        "description": "Return the decompiled body of one method (or a whole class) with a file:line locator.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "project_id": {"type": "string"},
                "class_name": {"type": "string"},
                "method": {"type": "string"},
                "max_lines": {"type": "integer", "minimum": 1, "maximum": 2000},
            },
            "required": ["project_id", "class_name", "method"],
            "additionalProperties": False,
        },
    },
    "apk_read_manifest": {
        "description": "Decoded manifest facts (package, sdk, permissions, components, signature).",
        "inputSchema": {
            "type": "object",
            "properties": {"project_id": {"type": "string"}},
            "required": ["project_id"],
            "additionalProperties": False,
        },
    },
    "apk_search_resources": {
        "description": "Search decoded resource names and values (strings, colors, dimen).",
        "inputSchema": {
            "type": "object",
            "properties": {
                "project_id": {"type": "string"},
                "query": {"type": "string"},
                "limit": {"type": "integer", "minimum": 1, "maximum": 200},
            },
            "required": ["project_id", "query"],
            "additionalProperties": False,
        },
    },
    "artifact_list": {
        "description": "List artifacts of a project (optionally filtered by kind or task).",
        "inputSchema": {
            "type": "object",
            "properties": {
                "project_id": {"type": "string"},
                "kind": {"type": "string"},
                "task_id": {"type": "string"},
                "limit": {"type": "integer", "minimum": 1, "maximum": 500},
            },
            "required": ["project_id"],
            "additionalProperties": False,
        },
    },
    "evidence_read": {
        "description": "Read evidence rows (with locators and artifact ids) for a project.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "project_id": {"type": "string"},
                "evidence_id": {"type": "string"},
                "task_id": {"type": "string"},
                "kind": {"type": "string"},
                "limit": {"type": "integer", "minimum": 1, "maximum": 500},
            },
            "required": ["project_id"],
            "additionalProperties": False,
        },
    },
    "evidence_record": {
        "description": "Record one evidence row. The excerpt must be quoted verbatim from the cited artifact.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "project_id": {"type": "string"},
                "kind": {"type": "string"},
                "artifact_id": {"type": "string"},
                "locator": {"type": "object"},
                "excerpt": {"type": "string"},
                "claim": {"type": "string"},
                "confidence": {"type": "string", "enum": ["low", "medium", "high"]},
                "task_id": {"type": "string"},
            },
            "required": ["project_id", "kind", "artifact_id", "excerpt"],
            "additionalProperties": False,
        },
    },
    "task_create": {
        "description": "Create a task on a project's board.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "project_id": {"type": "string"},
                "title": {"type": "string"},
                "role": {"type": "string", "enum": ["main", "static", "dynamic", "review", "report"]},
                "goal": {"type": "string"},
                "parent_task_id": {"type": "string"},
                "priority": {"type": "integer", "minimum": 0, "maximum": 9},
                "needs_approval": {"type": "boolean"},
            },
            "required": ["project_id", "title"],
            "additionalProperties": False,
        },
    },
    "task_get": {
        "description": "Read one task, including its version (needed for optimistic updates).",
        "inputSchema": {
            "type": "object",
            "properties": {"task_id": {"type": "string"}},
            "required": ["task_id"],
            "additionalProperties": False,
        },
    },
    "task_update": {
        "description": "Update a task. Moving to DONE requires an approval; pass expected_version to avoid lost updates.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "task_id": {"type": "string"},
                "status": {"type": "string"},
                "expected_version": {"type": "integer"},
                "approval_id": {"type": "string"},
                "reason": {"type": "string"},
                "fields": {"type": "object"},
            },
            "required": ["task_id"],
            "additionalProperties": False,
        },
    },
    "task_list": {
        "description": "List tasks of a project, optionally by status or role.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "project_id": {"type": "string"},
                "status": {"type": "string"},
                "role": {"type": "string"},
            },
            "required": ["project_id"],
            "additionalProperties": False,
        },
    },
    "report_generate": {
        "description": "Render the evidence-first Markdown report and return its path.",
        "inputSchema": {
            "type": "object",
            "properties": {"project_id": {"type": "string"}, "task_id": {"type": "string"}},
            "required": ["project_id"],
            "additionalProperties": False,
        },
    },
}


class ToolFault(Exception):
    def __init__(self, code: str, message: str, *, retryable: bool = False) -> None:
        super().__init__(message)
        self.code = code
        self.message = message
        self.retryable = retryable


def _check_scope(project_id: str | None) -> None:
    if project_id and ALLOWED_PROJECTS != ["*"] and project_id not in ALLOWED_PROJECTS:
        raise ToolFault("project_denied", f"project {project_id} is outside this server's allowlist")


def _validate(name: str, args: dict) -> None:
    schema = SCHEMAS[name]["inputSchema"]
    props = schema.get("properties", {})
    for required in schema.get("required", []):
        if required not in args or args[required] in (None, ""):
            raise ToolFault("schema_invalid", f"missing required argument {required!r}")
    if schema.get("additionalProperties") is False:
        unknown = [key for key in args if key not in props]
        if unknown:
            raise ToolFault("schema_invalid", f"unknown arguments: {unknown}")
    for key, value in args.items():
        spec = props.get(key) or {}
        if value is None:
            continue
        expected = spec.get("type")
        if expected == "string" and not isinstance(value, str):
            raise ToolFault("schema_invalid", f"{key!r} must be a string")
        if expected == "integer" and not isinstance(value, int):
            raise ToolFault("schema_invalid", f"{key!r} must be an integer")
        if expected == "boolean" and not isinstance(value, bool):
            raise ToolFault("schema_invalid", f"{key!r} must be a boolean")
        if expected == "object" and not isinstance(value, dict):
            raise ToolFault("schema_invalid", f"{key!r} must be an object")
        if "enum" in spec and value not in spec["enum"]:
            raise ToolFault("schema_invalid", f"{key!r} must be one of {spec['enum']}")


# ---------------------------------------------------------------------------
# handlers
# ---------------------------------------------------------------------------
def _project(project_id: str) -> dict:
    _check_scope(project_id)
    project = projects_service.get(project_id)
    if not project:
        raise ToolFault("project_not_found", f"no project {project_id}")
    return project


def _facts(project_id: str) -> dict:
    path = settings.project_dir(project_id) / "artifacts" / "facts.json"
    if not path.exists():
        raise ToolFault("artifact_missing", "metadata artifact not produced yet (static stage pending)", retryable=True)
    return json.loads(path.read_text(encoding="utf-8"))


def h_project_create(args: dict) -> dict:
    inbox = settings.storage / "inbox"
    inbox.mkdir(parents=True, exist_ok=True)
    candidate = Path(args["apk_path"])
    if candidate.is_absolute():
        raise ToolFault("path_rejected", "apk_path must be relative to storage/inbox")
    source = (inbox / candidate).resolve()
    if not str(source).startswith(str(inbox.resolve())):
        raise ToolFault("path_rejected", "apk_path escapes storage/inbox")
    if not source.exists():
        raise ToolFault("apk_missing", f"{source} does not exist (upload first)")
    try:
        project = projects_service.create(
            args["name"], source, source.name, goal=args.get("goal"), policy_id=args.get("policy_id") or "default", actor=ACTOR
        )
    except Exception as exc:  # noqa: BLE001
        raise ToolFault("ingest_failed", f"{type(exc).__name__}: {exc}") from exc
    job_id = queue_service.enqueue(
        "static_pipeline",
        project_id=project["id"],
        payload={"project_id": project["id"]},
        idempotency_key=f"static:{project['id']}",
        actor=ACTOR,
    )
    _check_scope(project["id"])
    return {"project": project, "job_id": job_id}


def h_project_get(args: dict) -> dict:
    project = _project(args["project_id"])
    manifest = projects_service.manifest(project["id"])
    return {"project": project, "manifest": manifest}


def h_apk_get_metadata(args: dict) -> dict:
    _project(args["project_id"])
    facts = _facts(args["project_id"])
    return {
        "package": facts.get("package"),
        "version_name": facts.get("version_name"),
        "version_code": facts.get("version_code"),
        "min_sdk": facts.get("min_sdk"),
        "target_sdk": facts.get("target_sdk"),
        "permissions": facts.get("permissions", []),
        "activities": facts.get("activities", []),
        "services": facts.get("services", []),
        "receivers": facts.get("receivers", []),
        "providers": facts.get("providers", []),
        "certificate_sha256": facts.get("certificate_sha256"),
        "dex_inventory": facts.get("dex_inventory"),
    }


def h_apk_list_packages(args: dict) -> dict:
    _project(args["project_id"])
    return {"packages": indexer.list_packages(args["project_id"], limit=args.get("limit", 200))}


def h_apk_search_code(args: dict) -> dict:
    _project(args["project_id"])
    rows = indexer.search_code(args["project_id"], args["query"], kind=args.get("kind"), limit=args.get("limit", 50))
    return {"query": args["query"], "count": len(rows), "results": rows}


def h_apk_read_method(args: dict) -> dict:
    _project(args["project_id"])
    row = indexer.get_method(
        args["project_id"], args["class_name"], args["method"], max_lines=args.get("max_lines", 400)
    )
    if not row:
        raise ToolFault("not_found", f"{args['class_name']}#{args['method']} is not indexed")
    return row


def h_apk_read_manifest(args: dict) -> dict:
    _project(args["project_id"])
    facts = _facts(args["project_id"])
    decoded = settings.project_dir(args["project_id"]) / "artifacts" / "apktool" / "AndroidManifest.xml"
    return {
        "facts": facts,
        "decoded_manifest_present": decoded.exists(),
        "decoded_manifest_path": str(decoded.relative_to(settings.storage)) if decoded.exists() else None,
    }


def h_apk_search_resources(args: dict) -> dict:
    _project(args["project_id"])
    rows = indexer.search_resources(args["project_id"], args["query"], limit=args.get("limit", 50))
    return {"query": args["query"], "count": len(rows), "results": rows}


def h_artifact_list(args: dict) -> dict:
    _project(args["project_id"])
    kinds = [args["kind"]] if args.get("kind") else None
    rows = artifacts_service.list_artifacts(
        args["project_id"], kinds=kinds, task_id=args.get("task_id"), limit=args.get("limit", 200)
    )
    return {"count": len(rows), "artifacts": rows}


def h_evidence_read(args: dict) -> dict:
    _project(args["project_id"])
    if args.get("evidence_id"):
        row = evidence_service.get(args["evidence_id"])
        if not row or row["project_id"] != args["project_id"]:
            raise ToolFault("evidence_not_found", args["evidence_id"])
        return {"evidence": [row]}
    rows = evidence_service.list_evidence(args["project_id"], task_id=args.get("task_id"), kind=args.get("kind"))
    return {"count": len(rows), "evidence": rows[: args.get("limit", 200)]}


def h_evidence_record(args: dict) -> dict:
    _project(args["project_id"])
    try:
        row = evidence_service.record(
            args["project_id"],
            kind=args["kind"],
            locator=args.get("locator") or {},
            excerpt=args["excerpt"],
            artifact_id=args["artifact_id"],
            task_id=args.get("task_id"),
            claim=args.get("claim"),
            confidence=args.get("confidence", "medium"),
            created_by=ACTOR,
        )
    except evidence_service.EvidenceError as exc:
        raise ToolFault("evidence_rejected", str(exc)) from exc
    return {"evidence": row}


def h_task_create(args: dict) -> dict:
    _project(args["project_id"])
    return tasks_service.create(
        args["project_id"],
        role=args.get("role", "static"),
        title=args["title"],
        goal=args.get("goal"),
        parent_task_id=args.get("parent_task_id"),
        priority=args.get("priority", 5),
        actor=ACTOR,
        needs_approval=bool(args.get("needs_approval")),
    )


def h_task_get(args: dict) -> dict:
    task = tasks_service.get(args["task_id"])
    if not task:
        raise ToolFault("task_not_found", args["task_id"])
    _check_scope(task["project_id"])
    return task


def h_task_update(args: dict) -> dict:
    task = tasks_service.get(args["task_id"])
    if not task:
        raise ToolFault("task_not_found", args["task_id"])
    _check_scope(task["project_id"])
    try:
        return tasks_service.update(
            args["task_id"],
            actor=ACTOR,
            status=args.get("status"),
            fields=args.get("fields") or None,
            expected_version=args.get("expected_version"),
            approval_id=args.get("approval_id"),
            reason=args.get("reason"),
        )
    except TransitionError as exc:
        raise ToolFault(exc.code if hasattr(exc, "code") else "transition_denied", str(exc)) from exc


def h_task_list(args: dict) -> dict:
    _project(args["project_id"])
    rows = tasks_service.list_tasks(args["project_id"], status=args.get("status"), role=args.get("role"))
    return {"count": len(rows), "tasks": rows}


def h_report_generate(args: dict) -> dict:
    _project(args["project_id"])
    result = reports.generate(args["project_id"], task_id=args.get("task_id"), actor=ACTOR)
    return {
        "artifact_id": result["artifact_id"],
        "report_path": result["report_path"],
        "evidence_rows": result["evidence_rows"],
        "traceability_rate": result["traceability_rate"],
        "verification_ok": result["verification_ok"],
        "markdown": result["markdown"][:INLINE_MAX_BYTES],
    }


HANDLERS: dict[str, Callable[[dict], dict]] = {
    "project_create": h_project_create,
    "project_get": h_project_get,
    "apk_get_metadata": h_apk_get_metadata,
    "apk_list_packages": h_apk_list_packages,
    "apk_search_code": h_apk_search_code,
    "apk_read_method": h_apk_read_method,
    "apk_read_manifest": h_apk_read_manifest,
    "apk_search_resources": h_apk_search_resources,
    "artifact_list": h_artifact_list,
    "evidence_read": h_evidence_read,
    "evidence_record": h_evidence_record,
    "task_create": h_task_create,
    "task_get": h_task_get,
    "task_update": h_task_update,
    "task_list": h_task_list,
    "report_generate": h_report_generate,
}


# ---------------------------------------------------------------------------
# envelope
# ---------------------------------------------------------------------------
def _spill(project_id: str | None, tool: str, payload: dict) -> tuple[dict, list[str]]:
    """Write oversized results to an artifact and return a reference-sized copy."""
    blob = json.dumps(payload, ensure_ascii=False, default=str)
    if len(blob.encode("utf-8")) <= INLINE_MAX_BYTES or not project_id:
        return payload, []
    out_dir = settings.project_dir(project_id) / "artifacts" / "mcp"
    out_dir.mkdir(parents=True, exist_ok=True)
    path = out_dir / f"{tool}-{utcnow().replace(':', '').replace('-', '')[:15]}-{os.getpid()}.json"
    write_json(path, payload)
    artifact = artifacts_service.register(project_id, kind="mcp_result", path=path, tool=f"mcp.{tool}")
    return (
        {
            "spilled": True,
            "artifact_id": artifact["id"],
            "bytes": artifact["bytes"],
            "preview": blob[:2000],
            "hint": "call artifact_list / read the artifact for the full payload",
        },
        [artifact["id"]],
    )


def call_tool(name: str, args: dict, request_id: Any) -> dict:
    started_at = utcnow()
    started = time.perf_counter()
    project_id = args.get("project_id") or None
    task_id = args.get("task_id") or None
    envelope: dict[str, Any] = {
        "ok": False,
        "project_id": project_id,
        "task_id": task_id,
        "tool": name,
        "tool_version": TOOL_VERSION,
        "started_at": started_at,
        "duration_ms": 0,
        "stdout_artifact_id": None,
        "stderr_artifact_id": None,
        "produced_artifact_ids": [],
        "error_code": None,
        "retryable": False,
        "request_id": request_id,
    }
    schema_ok = True
    try:
        if name not in enabled_tools():
            schema_ok = False
            if name in SCHEMAS:
                raise ToolFault("tool_disabled", f"{name} is not exposed by this server instance")
            raise ToolFault("unknown_tool", f"{name} is not in the whitelist")
        _validate(name, args)
        result = HANDLERS[name](args)
        if name == "task_get" and "project_id" in result:
            envelope["project_id"] = result["project_id"]
        payload, produced = _spill(envelope["project_id"], name, result)
        if name == "report_generate" and result.get("artifact_id"):
            produced = [*produced, result["artifact_id"]]
        envelope.update(
            ok=True,
            produced_artifact_ids=sorted({*envelope["produced_artifact_ids"], *produced}),
            result=payload,
        )
    except ToolFault as fault:
        envelope.update(ok=False, error_code=fault.code, retryable=fault.retryable, error=fault.message)
    except Exception as exc:  # noqa: BLE001
        envelope.update(
            ok=False,
            error_code="internal_error",
            retryable=True,
            error=f"{type(exc).__name__}: {exc}",
            trace=traceback.format_exc()[-2000:],
        )
    envelope["duration_ms"] = int((time.perf_counter() - started) * 1000)
    try:
        audit.record(
            "mcp_tool_call",
            project_id=envelope["project_id"],
            task_id=envelope["task_id"],
            actor=ACTOR,
            payload={
                "tool": name,
                "ok": envelope["ok"],
                "schema_ok": schema_ok and envelope["error_code"] != "schema_invalid",
                "error_code": envelope["error_code"],
                "duration_ms": envelope["duration_ms"],
            },
        )
    except Exception:  # noqa: BLE001
        pass
    return envelope


# ---------------------------------------------------------------------------
# JSON-RPC loop
# ---------------------------------------------------------------------------
def _respond(obj: dict) -> None:
    sys.stdout.write(json.dumps(obj, ensure_ascii=False, default=str) + "\n")
    sys.stdout.flush()


def handle(message: dict) -> dict | None:
    method = message.get("method")
    msg_id = message.get("id")
    params = message.get("params") or {}
    if method == "initialize":
        return {
            "jsonrpc": "2.0",
            "id": msg_id,
            "result": {
                "protocolVersion": PROTOCOL_VERSION,
                "capabilities": {"tools": {"listChanged": False}, "resources": {}},
                "serverInfo": {"name": "apkplat-mcp", "version": TOOL_VERSION},
                "instructions": (
                    "APK static analysis. Read metadata first, then search code, then record evidence "
                    "with a verbatim excerpt and the artifact id you read it from. Every claim in the "
                    "final report must carry an evidence id."
                ),
            },
        }
    if method in {"notifications/initialized", "initialized", "notifications/cancelled"}:
        return None
    if method == "ping":
        return {"jsonrpc": "2.0", "id": msg_id, "result": {}}
    if method == "tools/list":
        return {
            "jsonrpc": "2.0",
            "id": msg_id,
            "result": {
                "tools": [
                    {"name": name, "description": spec["description"], "inputSchema": spec["inputSchema"]}
                    for name, spec in enabled_tools().items()
                ]
            },
        }
    if method == "tools/call":
        name = params.get("name")
        args = params.get("arguments") or {}
        envelope = call_tool(name, args, msg_id)
        return {
            "jsonrpc": "2.0",
            "id": msg_id,
            "result": {
                "content": [{"type": "text", "text": json.dumps(envelope, ensure_ascii=False, indent=2)}],
                "isError": not envelope["ok"],
            },
        }
    if method == "resources/list":
        return {"jsonrpc": "2.0", "id": msg_id, "result": {"resources": []}}
    if method == "prompts/list":
        return {"jsonrpc": "2.0", "id": msg_id, "result": {"prompts": []}}
    return {
        "jsonrpc": "2.0",
        "id": msg_id,
        "error": {"code": -32601, "message": f"method {method} not found"},
    }


def main() -> int:
    settings.ensure_dirs()
    db.migrate()
    sys.stderr.write(
        f"[apkplat-mcp] ready v{TOOL_VERSION} tools={len(enabled_tools())}/{len(SCHEMAS)} "
        f"projects={ALLOWED_PROJECTS} actor={ACTOR} storage={settings.storage}\n"
    )
    sys.stderr.flush()
    for raw in sys.stdin:
        line = raw.strip()
        if not line:
            continue
        try:
            message = json.loads(line)
        except json.JSONDecodeError as exc:
            _respond({"jsonrpc": "2.0", "id": None, "error": {"code": -32700, "message": f"parse error: {exc}"}})
            continue
        try:
            response = handle(message)
        except Exception as exc:  # noqa: BLE001
            sys.stderr.write(f"[apkplat-mcp] handler crash: {exc}\n{traceback.format_exc()}\n")
            response = {
                "jsonrpc": "2.0",
                "id": message.get("id"),
                "error": {"code": -32603, "message": f"internal error: {type(exc).__name__}"},
            }
        if response is not None:
            _respond(response)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
