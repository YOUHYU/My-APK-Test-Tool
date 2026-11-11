"""P1 bridge tools: the twelve-item contract from taskbook 搂2.3.

Every handler here is a *real* implementation over the existing services - the bridge
does not re-implement JADX, it reads the index the static pipeline already built. A
tool that cannot be honestly supported yet (sandboxed test execution, device actions,
packet capture) answers with a structured ``capability_unavailable`` / ``not_observed``
instead of pretending, which is what keeps G1 meaningful.

Handlers receive a :class:`ToolContext` that carries the *already authorised* run
scope; they must never look up a capability themselves.
"""

from __future__ import annotations

import json
import re
import shutil
import subprocess
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable

from . import audit, indexer, toolchain
from .db import db, utcnow
from .util import dumps, new_id, project_layout, project_root, safe_segment, sha256_bytes, sha256_file
from .services import artifacts as artifacts_service
from .services import capture as capture_service
from .services import device_ui
from .services import devices as devices_service
from .services import evidence as evidence_service
from .services import projects as projects_service
from .services import queue as queue_service
from .services import tasks as tasks_service
from .services.capabilities import Scope

TOOL_VERSION = "1.0.0"

# Artifact kinds a run may write itself. Everything else is produced by the platform's
# own stages, so an agent cannot forge a "validation" or "metadata" artifact.
WRITABLE_KINDS = ("notes", "script", "capture", "network", "ui", "log", "evidence_note")

TEXT_KINDS = ("validation", "metadata", "findings", "summary", "notes", "network", "log", "capture", "ui", "evidence_note")


class BridgeFault(Exception):
    """A structured tool failure that travels back to the agent unchanged."""

    def __init__(self, code: str, message: str, *, retryable: bool = False, detail: Any = None) -> None:
        super().__init__(message)
        self.code = code
        self.message = message
        self.retryable = retryable
        self.detail = detail

    def as_error(self) -> dict[str, Any]:
        return {"error_code": self.code, "message": self.message, "retryable": self.retryable, "detail": self.detail}


@dataclass
class ToolContext:
    scope: Scope
    actor: str
    log: Callable[[str], None] | None = None
    produced: list[str] = field(default_factory=list)

    @property
    def project_id(self) -> str:
        return self.scope.project_id

    @property
    def run_id(self) -> str:
        return self.scope.run_id

    def require_project(self) -> dict[str, Any]:
        project = projects_service.get(self.project_id)
        if not project:
            raise BridgeFault("project_not_found", f"project {self.project_id} does not exist")
        return dict(project)


def _artifact_by_kind(project_id: str, kind: str) -> dict[str, Any] | None:
    rows = artifacts_service.list_artifacts(project_id, kinds=[kind], limit=20)
    if not rows:
        return None
    row = dict(rows[0])
    row["path"] = str(artifacts_service.path_of(rows[0]))
    return row


def _read_json(path: str | Path) -> Any:
    return json.loads(Path(path).read_text(encoding="utf-8"))


# --------------------------------------------------------------------------- handlers


def platform_health(ctx: ToolContext, args: dict[str, Any]) -> dict[str, Any]:
    stats = queue_service.stats()
    return {
        "version": TOOL_VERSION,
        "policy_version": ctx.scope.policy_version,
        "role_id": ctx.scope.role_id,
        "project_id": ctx.project_id,
        "tools_available": list(ctx.scope.tools),
        "capabilities": {
            "apk_inspect": {"available": True, "note": "reads the static index built by the platform"},
            "artifact_write": {"available": True, "kinds": list(WRITABLE_KINDS)},
            "evidence_submit": {"available": True, "note": "excerpt must be a verbatim slice of the artifact"},
            "test_run": {"available": True, "isolation": "cooperative", "note": "P3 sandbox: static screen + scrubbed env + timeout; no container on this host"},
            "device_action": {
                "available": True,
                "actions": list(DEVICE_ACTIONS),
                "requires": "an active device lease for the project; package must match the analysed app",
                "ui_backend": device_ui.driver_status(),
            },
            "capture_query": capture_service.probe_proxy_pin(),
        },
        "queue": stats,
        "tool_calls_used": ctx.scope.extra.get("tool_calls_used", 0),
    }


def project_snapshot(ctx: ToolContext, args: dict[str, Any]) -> dict[str, Any]:
    project = ctx.require_project()
    manifest = projects_service.manifest(ctx.project_id) or {}
    artifacts = [dict(r) for r in artifacts_service.list_artifacts(ctx.project_id, limit=200)]
    kinds: dict[str, int] = {}
    for row in artifacts:
        kinds[row["kind"]] = kinds.get(row["kind"], 0) + 1
    evidence_rows = evidence_service.list_evidence(ctx.project_id, limit=500)
    tasks = [dict(r) for r in tasks_service.list_tasks(ctx.project_id)]
    ingest = manifest.get("ingest") or {}
    metadata_path = _artifact_by_kind(ctx.project_id, "metadata")
    metadata: dict[str, Any] = {}
    if metadata_path:
        try:
            metadata = _read_json(metadata_path["path"])
        except Exception:  # noqa: BLE001 - a missing/corrupt artifact must not kill the snapshot
            metadata = {}
    try:
        index_stats = indexer.stats(ctx.project_id)
    except Exception:  # noqa: BLE001
        index_stats = {}
    return {
        "project": {
            "id": project["id"],
            "name": project["name"],
            "status": project["status"],
            "goal": project.get("goal"),
            "created_at": project.get("created_at"),
        },
        "ingest": {
            "sha256": ingest.get("sha256"),
            "bytes": ingest.get("bytes"),
            "filename": ingest.get("filename"),
        },
        "apk": {
            "package": metadata.get("package") or project.get("package_name"),
            "version_name": metadata.get("version_name"),
            "version_code": metadata.get("version_code"),
            "min_sdk": metadata.get("min_sdk"),
            "target_sdk": metadata.get("target_sdk"),
            "permissions": metadata.get("permissions") or [],
            "certificate_sha256": metadata.get("certificate_sha256"),
        },
        "artifacts": {"count": len(artifacts), "kinds": kinds},
        "evidence": {"count": len(evidence_rows), "kinds": sorted({r["kind"] for r in evidence_rows})},
        "tasks": [
            {"id": t["id"], "role": t["role"], "status": t["status"], "title": t["title"], "evidence_count": t.get("evidence_count", 0)}
            for t in tasks
        ],
        "index": index_stats,
        "hint": "use apk_inspect(action=...) to look inside; artifact_find to grep produced artifacts",
    }


def artifact_find(ctx: ToolContext, args: dict[str, Any]) -> dict[str, Any]:
    query = str(args.get("query") or "").strip()
    kind = args.get("kind")
    limit = int(args.get("limit") or 20)
    rows = [dict(r) for r in artifacts_service.list_artifacts(ctx.project_id, kinds=[kind] if kind else None, limit=200)]
    if not rows:
        raise BridgeFault("no_artifacts", "this project has no artifacts yet; run the static pipeline first")
    matches: list[dict[str, Any]] = []
    needle = query.lower()
    for row in rows:
        if row["kind"] not in TEXT_KINDS:
            continue
        path = artifacts_service.path_of(artifacts_service.get(row["id"]))
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        if not needle:
            matches.append({"artifact_id": row["id"], "kind": row["kind"], "rel_path": row["rel_path"], "lines": text.count("\n") + 1})
            continue
        for i, line in enumerate(text.splitlines(), 1):
            if needle in line.lower():
                matches.append({"artifact_id": row["id"], "kind": row["kind"], "rel_path": row["rel_path"], "line": i, "text": line.strip()[:240]})
                if len(matches) >= limit:
                    break
        if len(matches) >= limit:
            break
    if not matches and needle:
        raise BridgeFault("no_match", f"no artifact line contains {query!r}", retryable=False)
    return {"query": query, "count": len(matches), "matches": matches}


APK_ACTIONS = ("metadata", "manifest", "packages", "code", "method", "resources", "strings", "components")


def apk_inspect(ctx: ToolContext, args: dict[str, Any]) -> dict[str, Any]:
    action = str(args.get("action") or "").strip()
    if action not in APK_ACTIONS:
        raise BridgeFault("bad_action", f"action must be one of {list(APK_ACTIONS)}", detail={"got": action})
    target = args.get("target")
    limit = int(args.get("limit") or 20)
    ctx.require_project()

    if action in {"metadata", "manifest"}:
        row = _artifact_by_kind(ctx.project_id, "metadata")
        if not row:
            raise BridgeFault("apk_not_indexed", "metadata artifact missing; the static pipeline has not run")
        data = _read_json(row["path"])
        if action == "manifest":
            keep = {k: data.get(k) for k in ("package", "version_name", "version_code", "min_sdk", "target_sdk", "permissions", "activities", "services", "receivers", "providers")}
            return {"action": action, "artifact_id": row["id"], "manifest": keep}
        return {"action": action, "artifact_id": row["id"], "metadata": data}

    try:
        if action == "packages":
            return {"action": action, "packages": indexer.list_packages(ctx.project_id, limit=limit)}
        if action == "components":
            return {"action": action, "components": indexer.components(ctx.project_id, kind=target or None)}
        if action == "strings":
            if not target:
                raise BridgeFault("missing_target", "strings requires target=<substring>")
            return {"action": action, "strings": indexer.search_strings(ctx.project_id, str(target), limit=limit)}
        if action == "resources":
            if not target:
                raise BridgeFault("missing_target", "resources requires target=<substring>")
            return {"action": action, "resources": indexer.search_resources(ctx.project_id, str(target), limit=limit)}
        if action == "code":
            if not target:
                raise BridgeFault("missing_target", "code requires target=<class or method substring>")
            return {"action": action, "results": indexer.search_code(ctx.project_id, str(target), limit=limit)}
        if action == "method":
            if not target or "." not in str(target):
                raise BridgeFault("missing_target", "method requires target=<class>.<method>")
            class_name, _, method = str(target).rpartition(".")
            found = indexer.get_method(ctx.project_id, class_name, method)
            if not found:
                raise BridgeFault("method_not_found", f"{target} is not in the index")
            return {"action": action, "method": found}
    except BridgeFault:
        raise
    except Exception as exc:  # noqa: BLE001 - index errors must be legible to the model
        raise BridgeFault("index_error", f"index query failed: {exc}", retryable=True) from exc
    raise BridgeFault("bad_action", "unreachable")


def task_propose(ctx: ToolContext, args: dict[str, Any]) -> dict[str, Any]:
    title = str(args.get("title") or "").strip()
    if not title:
        raise BridgeFault("title_required", "title is required")
    role = str(args.get("role") or "exec").strip()
    goal = args.get("goal")
    parent = ctx.scope.task_id
    created = tasks_service.create(
        ctx.project_id,
        role=role,
        title=title[:200],
        goal=str(goal)[:2000] if goal else None,
        parent_task_id=parent,
        actor=ctx.actor,
        status="TODO",
    )
    audit.record(
        "task_proposed",
        project_id=ctx.project_id,
        task_id=created["id"],
        actor=ctx.actor,
        payload={"run_id": ctx.run_id, "parent_task_id": parent, "title": title[:200], "role": role},
    )
    return {"task_id": created["id"], "status": created["status"], "parent_task_id": parent, "note": "proposal accepted; a worker must still claim it"}


def task_status_get(ctx: ToolContext, args: dict[str, Any]) -> dict[str, Any]:
    task_id = str(args.get("task_id") or ctx.scope.task_id or "").strip()
    if not task_id:
        raise BridgeFault("no_task", "this run is not attached to a task")
    task = tasks_service.get(task_id)
    if not task:
        raise BridgeFault("task_not_found", f"task {task_id} does not exist")
    if task["project_id"] != ctx.project_id:
        raise BridgeFault("project_denied", "task belongs to another project")
    row = dict(task)
    try:
        depends = json.loads(row.get("depends_on") or "[]")
    except Exception:  # noqa: BLE001
        depends = []
    return {
        "task": {
            "id": row["id"],
            "title": row.get("title"),
            "role": row.get("role"),
            "status": row.get("status"),
            "blocked_reason": row.get("blocked_reason"),
            "error_code": row.get("error_code"),
            "evidence_count": row.get("evidence_count", 0),
            "version": row.get("version"),
        },
        "depends_on": depends,
    }


def artifact_write(ctx: ToolContext, args: dict[str, Any]) -> dict[str, Any]:
    kind = str(args.get("kind") or "notes").strip()
    if kind not in WRITABLE_KINDS:
        raise BridgeFault("kind_not_writable", f"kind must be one of {list(WRITABLE_KINDS)}", detail={"got": kind})
    name = safe_segment(str(args.get("name") or f"bridge-{kind}.txt"))
    content = args.get("content")
    if content is None:
        raise BridgeFault("content_required", "content is required")
    body = content if isinstance(content, str) else dumps(content)
    target = project_root(ctx.project_id) / "artifacts" / "bridge" / name
    target.parent.mkdir(parents=True, exist_ok=True)
    payload = body.encode("utf-8")
    if target.exists() and sha256_file(target) == sha256_bytes(payload):
        row = artifacts_service.register(
            ctx.project_id, kind=kind, path=target, task_id=ctx.scope.task_id, tool="apkplat-bridge", tool_version=TOOL_VERSION, actor=ctx.actor
        )
        return {"artifact_id": row["id"], "rel_path": row["rel_path"], "idempotent": True, "sha256": sha256_bytes(payload)}
    target.write_bytes(payload)
    row = artifacts_service.register(
        ctx.project_id, kind=kind, path=target, task_id=ctx.scope.task_id, tool="apkplat-bridge", tool_version=TOOL_VERSION, actor=ctx.actor
    )
    ctx.produced.append(row["id"])
    return {"artifact_id": row["id"], "rel_path": row["rel_path"], "bytes": len(payload), "sha256": sha256_bytes(payload), "idempotent": False}


def test_run(ctx: ToolContext, args: dict[str, Any]) -> dict[str, Any]:
    """Run a project-owned test script in the cooperative sandbox and record the result."""
    from .services import sandbox as sandbox_service

    artifact_id = str(args.get("script_artifact_id") or "").strip()
    if not artifact_id:
        raise BridgeFault("artifact_required", "test_run needs script_artifact_id (from artifact_write)")
    argv = args.get("argv") or []
    if not isinstance(argv, list):
        raise BridgeFault("invalid_argv", "argv must be a list of strings")
    try:
        run = sandbox_service.run_script(
            ctx.project_id,
            script_artifact_id=artifact_id,
            argv=[str(a) for a in argv],
            task_id=ctx.scope.task_id,
            run_id=ctx.scope.run_id,
            timeout=int(args.get("timeout") or sandbox_service.DEFAULT_TIMEOUT),
            network=str(args.get("network") or "none"),
            isolation=str(args.get("isolation") or "cooperative"),
            actor=ctx.actor,
        )
    except sandbox_service.SandboxError as exc:
        raise BridgeFault(exc.code, exc.message, retryable=False, detail=exc.as_error()) from exc
    ctx.produced.extend(
        [
            run["stdout_artifact_id"],
            run["stderr_artifact_id"],
            run["result_artifact_id"],
        ]
    )
    return {
        "sandbox_run_id": run["id"],
        "status": run["status"],
        "exit_code": run["exit_code"],
        "timed_out": run["timed_out"],
        "duration_ms": run["duration_ms"],
        "isolation": run["isolation"],
        "network": run["network_policy"],
        "stdout_artifact_id": run["stdout_artifact_id"],
        "stderr_artifact_id": run["stderr_artifact_id"],
        "result_artifact_id": run["result_artifact_id"],
        "replay_of": run["replay_of"],
        "note": "cooperative isolation only: no kernel-level network or filesystem confinement on this host",
    }


def test_result_read(ctx: ToolContext, args: dict[str, Any]) -> dict[str, Any]:
    from .services import artifacts as artifacts_service
    from .services import sandbox as sandbox_service

    run_id = str(args.get("sandbox_run_id") or "").strip()
    if not run_id:
        raise BridgeFault("run_required", "test_result_read needs sandbox_run_id")
    run = sandbox_service.get(run_id)
    if run is None:
        raise BridgeFault("sandbox_run_not_found", f"{run_id} does not exist")
    if run["project_id"] != ctx.project_id:
        raise BridgeFault("project_denied", "sandbox run belongs to another project")
    tail = int(args.get("tail") or 40)
    stdout = ""
    stderr = ""
    if run["stdout_artifact_id"]:
        artifact = artifacts_service.get(run["stdout_artifact_id"])
        stdout = artifacts_service.read_text(artifact, tail=tail, redact=True) if artifact else ""
    if run["stderr_artifact_id"]:
        artifact = artifacts_service.get(run["stderr_artifact_id"])
        stderr = artifacts_service.read_text(artifact, tail=tail, redact=True) if artifact else ""
    return {
        "sandbox_run_id": run_id,
        "status": run["status"],
        "exit_code": run["exit_code"],
        "timed_out": run["timed_out"],
        "duration_ms": run["duration_ms"],
        "stdout": stdout,
        "stderr": stderr,
    }


def device_observe(ctx: ToolContext, args: dict[str, Any]) -> dict[str, Any]:
    paths = toolchain.paths()
    adb = paths.get("adb")
    if not adb:
        raise BridgeFault("tool_missing", "adb is not installed in the project toolchain")
    try:
        proc = subprocess.run([str(adb), "devices", "-l"], capture_output=True, text=True, timeout=20, env=toolchain.child_env())
    except (OSError, subprocess.SubprocessError) as exc:
        raise BridgeFault("adb_error", f"adb devices failed: {exc}", retryable=True) from exc
    lines = [ln.strip() for ln in (proc.stdout or "").splitlines() if ln.strip() and not ln.startswith("List of devices")]
    devices = []
    for line in lines:
        parts = line.split()
        serial, state = parts[0], parts[1] if len(parts) > 1 else "unknown"
        devices.append({"serial": serial, "state": state, "detail": " ".join(parts[2:])})
    observed = any(d["state"] == "device" for d in devices)
    project = projects_service.get(ctx.project_id)
    package = (project["package_name"] if project else None) or None
    gate: dict[str, Any] | None = None
    if observed and package:
        serial = next(d["serial"] for d in devices if d["state"] == "device")
        try:
            gate = devices_service.health(serial, package=package, adb=str(adb))
        except Exception as exc:  # a health probe must never hide the device list
            gate = {"serial": serial, "ready": None, "error": f"{type(exc).__name__}: {exc}"}
    return {
        "observed": observed,
        "devices": devices,
        "health": gate,
        "note": "read-only probe; device actions need a lease and go through device_action",
        "reason": None if observed else "no authorised device attached (WAITING_USER_ADB_AUTH)",
    }


DEVICE_ACTIONS = ("launch", "stop", "tap", "key", "screenshot", "dump", "unlock")


def _lease_serial(ctx: ToolContext) -> tuple[str, str, str]:
    """Return (lease_id, device_id, adb_serial) for this project's active lease."""
    leases = devices_service.list_leases(ctx.project_id, active_only=True)
    if not leases:
        raise BridgeFault(
            "lease_required",
            "a device action needs an active device lease for this project",
            detail={"project_id": ctx.project_id},
        )
    lease = dict(leases[0])
    device = devices_service.get(lease["device_id"])
    if device is None:
        raise BridgeFault("device_unknown", f"lease {lease['id']} points at a missing device")
    return lease["id"], device["id"], device["adb_serial"]


def device_action(ctx: ToolContext, args: dict[str, Any]) -> dict[str, Any]:
    """Whitelisted device actions, gated by an active lease and by the project package."""
    action = str(args.get("action") or "").strip().lower()
    if action not in DEVICE_ACTIONS:
        raise BridgeFault(
            "unsupported_action",
            f"action must be one of {', '.join(DEVICE_ACTIONS)}",
            detail={"action": action, "allowed": list(DEVICE_ACTIONS)},
        )
    lease_id, device_id, serial = _lease_serial(ctx)
    project = projects_service.get(ctx.project_id)
    project_package = (project["package_name"] if project else None) or ""
    requested_package = str(args.get("package") or "").strip()
    if requested_package and project_package and requested_package != project_package:
        raise BridgeFault(
            "package_denied",
            "the package is not the one under analysis for this project",
            detail={"requested": requested_package, "project_package": project_package},
        )
    package = requested_package or project_package
    driver = device_ui.AdbUi(serial, timeout=60)
    result: dict[str, Any] = {"action": action, "serial": serial, "package": package, "lease_id": lease_id}
    if action in ("launch", "stop"):
        if not package:
            raise BridgeFault("package_required", "launch/stop need a package for this project")
        result["command"] = driver.launch(package) if action == "launch" else driver.force_stop(package)
    elif action == "tap":
        if args.get("x") is None or args.get("y") is None:
            raise BridgeFault("coordinates_required", "tap needs integer x and y")
        result["tap"] = driver.tap(int(args["x"]), int(args["y"]))
    elif action == "key":
        code = str(args.get("key") or "").strip()
        if not code:
            raise BridgeFault("key_required", "key needs a key name or keycode")
        result["key"] = driver.press(code)
    elif action == "dump":
        nodes, digest = driver.hierarchy()
        result.update(
            {
                "nodes": len(nodes),
                "hierarchy_sha256": digest,
                "dialogs": driver.dialogs(nodes),
                "screen": driver.screen_state(),
            }
        )
    elif action == "screenshot":
        name = str(args.get("name") or "device-action-screenshot.png")
        target = project_layout(ctx.project_id)["artifacts"] / safe_segment(name)
        shot = driver.screenshot(target)
        artifact_id = artifacts_service.register(
            ctx.project_id, kind="device_screenshot", path=target, tool="bridge:device_action"
        )
        ctx.produced.append(artifact_id)
        result["screenshot"] = {**shot, "artifact_id": artifact_id}
    elif action == "unlock":
        result["unlock"] = driver.unlock()
    audit.record(
        "bridge_device_action",
        project_id=ctx.project_id,
        task_id=ctx.scope.task_id,
        actor=ctx.actor,
        payload={"action": action, "serial": serial, "lease_id": lease_id, "run_id": ctx.scope.run_id},
    )
    result["actions"] = driver.actions[-5:]
    return result


def capture_query(ctx: ToolContext, args: dict[str, Any]) -> dict[str, Any]:
    """Query captured traffic for this project; say NOT_OBSERVED when nothing was captured."""
    result = capture_service.query(
        ctx.project_id,
        host=args.get("host"),
        method=args.get("method"),
        matched_only=bool(args.get("matched_only")),
        limit=int(args.get("limit") or 50),
    )
    if result["state"] == capture_service.NOT_OBSERVED:
        probe = capture_service.probe_proxy_pin()
        raise BridgeFault(
            "not_observed",
            result.get("reason") or "no capture source is attached for this project",
            detail={"state": "NOT_OBSERVED", "proxy_pin": probe},
        )
    return result


def evidence_submit(ctx: ToolContext, args: dict[str, Any]) -> dict[str, Any]:
    artifact_id = str(args.get("artifact_id") or "").strip()
    if not artifact_id:
        raise BridgeFault("artifact_id_required", "artifact_id is required")
    claim = str(args.get("claim") or "").strip()
    excerpt = args.get("excerpt")
    pointer = args.get("pointer")
    confidence = str(args.get("confidence") or "medium")
    artifact = artifacts_service.get(artifact_id)
    if not artifact:
        raise BridgeFault("artifact_missing", f"artifact {artifact_id} does not exist")
    if artifact["project_id"] != ctx.project_id:
        raise BridgeFault("project_denied", "artifact belongs to another project")
    artifact_path = artifacts_service.path_of(artifact)
    try:
        text = artifact_path.read_text(encoding="utf-8", errors="replace")
    except OSError as exc:
        raise BridgeFault("artifact_unreadable", f"cannot read artifact: {exc}") from exc
    if not excerpt:
        if pointer is None:
            raise BridgeFault("excerpt_required", "supply an excerpt (verbatim slice) or a pointer")
        lines = text.splitlines()
        idx = int(pointer) if str(pointer).isdigit() else None
        if idx is None or not (1 <= idx <= len(lines)):
            raise BridgeFault("bad_pointer", f"pointer must be a line number within 1..{len(lines)}")
        excerpt = lines[idx - 1]
    excerpt = str(excerpt)
    if excerpt not in text:
        raise BridgeFault(
            "excerpt_not_found",
            "the excerpt is not a verbatim slice of the artifact; copy it exactly (the platform re-checks the hash later)",
            detail={"artifact_id": artifact_id},
        )
    locator = {"artifact_id": artifact_id, "rel_path": artifact["rel_path"], "pointer": pointer, "run_id": ctx.run_id}
    row = evidence_service.record(
        ctx.project_id,
        kind=str(args.get("kind") or "bridge_observation"),
        locator=locator,
        excerpt=excerpt,
        artifact_id=artifact_id,
        task_id=ctx.scope.task_id,
        claim=claim or None,
        confidence=confidence,
        created_by=ctx.actor,
    )
    audit.record(
        "bridge_evidence_submitted",
        project_id=ctx.project_id,
        task_id=ctx.scope.task_id,
        actor=ctx.actor,
        payload={"run_id": ctx.run_id, "evidence_id": row["id"], "artifact_id": artifact_id, "claim": claim[:200]},
    )
    return {
        "evidence_id": row["id"],
        "traceability": "excerpt matched verbatim at submit time",
        "note": "a review run will re-verify this against the artifact",
    }


HANDLERS: dict[str, Callable[[ToolContext, dict[str, Any]], dict[str, Any]]] = {
    "platform_health": platform_health,
    "project_snapshot": project_snapshot,
    "artifact_find": artifact_find,
    "apk_inspect": apk_inspect,
    "task_propose": task_propose,
    "task_status_get": task_status_get,
    "artifact_write": artifact_write,
    "test_run": test_run,
    "test_result_read": test_result_read,
    "device_observe": device_observe,
    "device_action": device_action,
    "capture_query": capture_query,
    "evidence_submit": evidence_submit,
}


# JSON-schema fragments mirroring the handler inputs. The plugin turns these into its
# typed tool definitions, so the model sees the same contract the platform enforces.
SCHEMAS: dict[str, dict[str, Any]] = {
    "platform_health": {
        "type": "object",
        "additionalProperties": False,
        "properties": {},
    },
    "project_snapshot": {"type": "object", "additionalProperties": False, "properties": {}},
    "artifact_find": {
        "type": "object",
        "additionalProperties": False,
        "properties": {
            "query": {"type": "string", "description": "case-insensitive substring searched in produced text artifacts"},
            "kind": {"type": "string", "description": "restrict to one artifact kind, e.g. metadata, findings, summary"},
            "limit": {"type": "number", "description": "max matches (default 20)"},
        },
    },
    "apk_inspect": {
        "type": "object",
        "additionalProperties": False,
        "properties": {
            "action": {
                "type": "string",
                "required": True,
                "enum": list(APK_ACTIONS),
                "description": "metadata|manifest|packages|code|method|resources|strings|components",
            },
            "target": {"type": "string", "description": "substring or <class>.<method>, depending on action"},
            "limit": {"type": "number", "description": "max rows (default 20)"},
        },
    },
    "task_propose": {
        "type": "object",
        "additionalProperties": False,
        "properties": {
            "title": {"type": "string", "required": True, "description": "one-line task title"},
            "role": {"type": "string", "description": "role for the proposed task (default exec)"},
            "goal": {"type": "string", "description": "what the task should achieve"},
        },
    },
    "task_status_get": {
        "type": "object",
        "additionalProperties": False,
        "properties": {"task_id": {"type": "string", "description": "defaults to this run's task"}},
    },
    "artifact_write": {
        "type": "object",
        "additionalProperties": False,
        "properties": {
            "kind": {"type": "string", "required": True, "enum": list(WRITABLE_KINDS)},
            "name": {"type": "string", "description": "file name inside artifacts/bridge/"},
            "content": {"type": "string", "required": True, "description": "full text content"},
        },
    },
    "test_run": {
        "type": "object",
        "additionalProperties": False,
        "properties": {
            "script_artifact_id": {"type": "string", "required": True, "description": "artifact_id of a script written with artifact_write"},
            "argv": {"type": "array", "description": "arguments passed to the script"},
            "timeout": {"type": "number", "description": "wall-clock seconds (1-120)"},
            "network": {"type": "string", "enum": ["none", "allowlist"], "description": "default none"},
            "isolation": {"type": "string", "enum": ["cooperative", "container"], "description": "container is refused on this host"},
        },
    },
    "test_result_read": {
        "type": "object",
        "additionalProperties": False,
        "properties": {
            "sandbox_run_id": {"type": "string", "required": True},
            "tail": {"type": "number"},
        },
    },
    "device_observe": {"type": "object", "additionalProperties": False, "properties": {}},
    "device_action": {
        "type": "object",
        "additionalProperties": False,
        "required": ["action"],
        "properties": {
            "action": {"type": "string", "enum": list(DEVICE_ACTIONS)},
            "package": {"type": "string"},
            "x": {"type": "number"},
            "y": {"type": "number"},
            "key": {"type": "string"},
            "name": {"type": "string"},
        },
    },
    "capture_query": {
        "type": "object",
        "additionalProperties": False,
        "properties": {
            "host": {"type": "string"},
            "method": {"type": "string"},
            "matched_only": {"type": "boolean"},
            "limit": {"type": "number"},
        },
    },
    "evidence_submit": {
        "type": "object",
        "additionalProperties": False,
        "properties": {
            "artifact_id": {"type": "string", "required": True},
            "claim": {"type": "string", "description": "what the excerpt proves"},
            "excerpt": {"type": "string", "description": "verbatim slice of the artifact"},
            "pointer": {"type": "number", "description": "1-based line number, alternative to excerpt"},
            "kind": {"type": "string"},
            "confidence": {"type": "string", "enum": ["low", "medium", "high"]},
        },
    },
}

DESCRIPTIONS: dict[str, str] = {
    "platform_health": "Read platform version, allowed tools and which capabilities are unavailable in this stage.",
    "project_snapshot": "Read this project's digest: APK identity, artifact kinds, evidence count, task list, index stats.",
    "artifact_find": "Grep the project's produced artifacts by substring; returns artifact ids and line numbers.",
    "apk_inspect": "Inspect the already-built static index: metadata, manifest facts, packages, code, a single method, resources, strings, components.",
    "task_propose": "Propose a follow-up task. The platform validates it; a worker still has to claim it.",
    "task_status_get": "Read the status, blocked reason and dependencies of this run's task.",
    "artifact_write": "Write a text artifact into the project workspace (idempotent by content hash).",
    "test_run": "Run a project-owned .py script in the cooperative sandbox (no network, scrubbed env, timeout, capped output).",
    "test_result_read": "Read the stdout/stderr and exit code of a recorded sandbox run.",
    "device_observe": "Read-only ADB probe: attached devices and their state.",
    "device_action": "Perform a whitelisted device action; needs an active device lease and the analysed package.",
    "capture_query": "Query captured network traffic (requires ProxyPin; NOT_OBSERVED otherwise).",
    "evidence_submit": "Submit evidence pointing at an artifact and a verbatim excerpt; the platform stores and re-verifies it.",
}


def tool_catalogue(scope: Scope) -> list[dict[str, Any]]:
    """The exact tool surface this run is allowed to see."""
    return [
        {"name": name, "description": DESCRIPTIONS[name], "parameters": SCHEMAS[name]}
        for name in scope.tools
        if name in HANDLERS
    ]


def call(scope: Scope, tool: str, args: dict[str, Any], *, actor: str | None = None) -> dict[str, Any]:
    """Dispatch one authorised tool call and return the platform envelope."""
    handler = HANDLERS.get(tool)
    if handler is None:
        raise BridgeFault("unknown_tool", f"tool {tool!r} is not implemented by the bridge")
    ctx = ToolContext(scope=scope, actor=actor or f"bridge:{scope.run_id}")
    started = utcnow()
    value = handler(ctx, dict(args or {}))
    return {
        "ok": True,
        "project_id": scope.project_id,
        "task_id": scope.task_id,
        "run_id": scope.run_id,
        "tool": tool,
        "tool_version": TOOL_VERSION,
        "started_at": started,
        "produced_artifact_ids": ctx.produced,
        "result": value,
    }
