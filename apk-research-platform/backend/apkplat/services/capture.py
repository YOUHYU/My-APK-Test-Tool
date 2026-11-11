"""Capture correlation (P4): attach a capture source, import its flows, correlate to code.

The platform never fabricates traffic. Three honest states exist and the report says which
one applies:

* ``NOT_OBSERVED`` - no capture source is attached for this project (the situation on this
  host: the test device has no ProxyPin build installed).
* ``IMPORTED`` - flows were read from a real export (ProxyPin directory / HAR) or an offline
  fixture file, and stored with their own timestamps.
* ``CORRELATED`` - imported flows that line up with a captured step window *and* with a URL
  or host literal found in the static evidence.

Correlation is evidence-backed on both sides: a flow only claims a code link when the host
or URL literal was produced by the static scan, and it only claims a step link when it falls
inside a recorded step window.
"""
from __future__ import annotations

import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable

from .. import audit
from ..db import db, utcnow
from ..util import dumps, loads, new_id, project_layout
from . import artifacts as artifacts_service
from . import projects as projects_service

NOT_OBSERVED = "NOT_OBSERVED"
IMPORTED = "IMPORTED"
CORRELATED = "CORRELATED"

SOURCE_KINDS = ("proxy_pin", "har", "pcap", "fixture")

_URL_RE = re.compile(r"https?://[^\s\"',)]+")


class CaptureError(Exception):
    def __init__(self, code: str, message: str, status: int = 422) -> None:
        super().__init__(message)
        self.code = code
        self.message = message
        self.status = status

    def as_error(self) -> dict[str, Any]:
        return {"error_code": self.code, "message": self.message}


@dataclass(frozen=True)
class Flow:
    method: str
    url: str
    status_code: int | None
    request_at: str | None
    response_at: str | None
    request_bytes: int | None
    response_bytes: int | None
    headers: dict[str, Any]

    @property
    def host(self) -> str:
        from urllib.parse import urlsplit

        try:
            return (urlsplit(self.url).hostname or "").lower()
        except ValueError:
            return ""

    @property
    def path(self) -> str:
        from urllib.parse import urlsplit

        try:
            return urlsplit(self.url).path or "/"
        except ValueError:
            return "/"

    @property
    def scheme(self) -> str:
        from urllib.parse import urlsplit

        try:
            return urlsplit(self.url).scheme or "http"
        except ValueError:
            return "http"


def _iso(value: Any) -> str | None:
    """Har timestamps are ISO strings; tolerate missing or odd values without inventing one."""
    if isinstance(value, str) and value.strip():
        text = value.strip().replace(" ", "T")
        return text if text.endswith("Z") or "+" in text else text + "Z"
    return None


def _flow_from_har_entry(entry: dict[str, Any]) -> Flow | None:
    request = entry.get("request") or {}
    response = entry.get("response") or {}
    url = request.get("url")
    if not isinstance(url, str) or "://" not in url:
        return None
    content = response.get("content") or {}
    size = content.get("size")
    headers = request.get("headers") or []
    header_map = {}
    if isinstance(headers, list):
        for item in headers:
            if isinstance(item, dict) and item.get("name"):
                header_map[str(item["name"]).lower()] = str(item.get("value", ""))[:400]
    return Flow(
        method=str(request.get("method") or "GET").upper(),
        url=url,
        status_code=int(response.get("status") or 0) or None,
        request_at=_iso(entry.get("startedDateTime")),
        response_at=_iso(response.get("_at") or entry.get("startedDateTime")),
        request_bytes=int((request.get("bodySize") or 0)) or None,
        response_bytes=int(size) if isinstance(size, int) else None,
        headers=header_map,
    )


def load_flows(path: Path) -> list[Flow]:
    """Read flows from a HAR-like file. Any other format is refused, never guessed."""
    if not path.exists() or not path.is_file():
        raise CaptureError("capture_file_missing", f"{path} does not exist", 404)
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise CaptureError("capture_unreadable", f"not a HAR/JSON capture: {type(exc).__name__}", 422) from exc
    entries = (payload.get("log") or {}).get("entries") if isinstance(payload, dict) else None
    if entries is None and isinstance(payload, dict) and isinstance(payload.get("entries"), list):
        entries = payload["entries"]
    if not isinstance(entries, list):
        raise CaptureError("capture_shape_unknown", "expected log.entries or entries[]", 422)
    flows: list[Flow] = []
    for entry in entries:
        if isinstance(entry, dict):
            flow = _flow_from_har_entry(entry)
            if flow:
                flows.append(flow)
    return flows


def import_source(
    project_id: str,
    *,
    path: str | Path,
    kind: str = "har",
    label: str | None = None,
    actor: str = "operator",
) -> dict[str, Any]:
    """Import a capture file into this project. Idempotent per (project, file bytes, kind)."""
    if projects_service.get(project_id) is None:
        raise CaptureError("project_not_found", project_id, 404)
    if kind not in SOURCE_KINDS:
        raise CaptureError("unsupported_source_kind", f"kind must be one of {SOURCE_KINDS}", 422)
    source_path = Path(path)
    if kind == "pcap":
        raise CaptureError(
            "pcap_not_parseable",
            "a pcap container is stored as evidence; flow extraction needs a ProxyPin/HAR export",
            422,
        )
    flows = load_flows(source_path)
    from ..util import sha256_file

    digest = sha256_file(source_path)
    existing = db.one(
        "SELECT * FROM capture_sources WHERE project_id = ? AND meta_json LIKE ?", (project_id, f"%{digest}%")
    )
    if existing is not None:
        return {"source": dict(existing), "flows_imported": 0, "duplicate": True}

    layout = project_layout(project_id)
    stored = Path(layout["artifacts"]) / "capture" / f"{digest[:12]}-{source_path.name}"
    stored.parent.mkdir(parents=True, exist_ok=True)
    stored.write_bytes(source_path.read_bytes())
    artifact = artifacts_service.register(
        project_id, kind="capture", path=stored, tool="apkplat.capture", tool_version="1.0.0", actor=actor
    )

    source_id = new_id("cap_")
    now = utcnow()
    with db.tx():
        db.execute(
            "INSERT INTO capture_sources(id, project_id, kind, label, path, status, note, meta_json, created_at)"
            " VALUES(?,?,?,?,?,?,?,?,?)",
            (
                source_id,
                project_id,
                kind,
                label or source_path.name,
                str(stored),
                NOT_OBSERVED if not flows else IMPORTED,
                None if flows else "capture parsed but contained no flows",
                dumps({"sha256": digest, "artifact_id": artifact["id"], "flows": len(flows)}),
                now,
            ),
        )
        for flow in flows:
            db.execute(
                "INSERT INTO capture_flows(id, project_id, source_id, method, scheme, host, path, status_code,"
                " request_at, response_at, request_bytes, response_bytes, headers_json, body_artifact_id, step, run_id,"
                " matched_artifact_id, matched_line, matched_literal, created_at)"
                " VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                (
                    new_id("flw_"),
                    project_id,
                    source_id,
                    flow.method,
                    flow.scheme,
                    flow.host,
                    flow.path,
                    flow.status_code,
                    flow.request_at,
                    flow.response_at,
                    flow.request_bytes,
                    flow.response_bytes,
                    dumps(flow.headers),
                    artifact["id"],
                    None,
                    None,
                    None,
                    None,
                    None,
                    now,
                ),
            )
    audit.record(
        "capture_imported",
        project_id=project_id,
        payload={"source_id": source_id, "kind": kind, "flows": len(flows), "sha256": digest},
        actor=actor,
    )
    row = db.one("SELECT * FROM capture_sources WHERE id = ?", (source_id,))
    return {"source": dict(row) if row else None, "flows_imported": len(flows), "duplicate": False}


def record_step(
    project_id: str,
    *,
    step: str,
    started_at: str,
    ended_at: str | None = None,
    run_id: str | None = None,
    task_id: str | None = None,
    device_serial: str | None = None,
    note: str | None = None,
) -> dict[str, Any]:
    step_id = new_id("stp_")
    db.execute(
        "INSERT INTO capture_steps(id, project_id, run_id, task_id, step, device_serial, started_at, ended_at, note)"
        " VALUES(?,?,?,?,?,?,?,?,?)",
        (step_id, project_id, run_id, task_id, step, device_serial, started_at, ended_at, note),
    )
    audit.record(
        "capture_step_recorded",
        project_id=project_id,
        task_id=task_id,
        payload={"step_id": step_id, "step": step, "started_at": started_at, "ended_at": ended_at, "run_id": run_id},
        actor="system",
    )
    return {"step_id": step_id, "step": step, "started_at": started_at, "ended_at": ended_at}


def _static_literals(project_id: str) -> list[dict[str, Any]]:
    """URL/host literals the static scan actually produced, with their artifact and line.

    The static pipeline records an endpoint in the claim text ("Endpoint <url> at file:line")
    and keeps the structured url in the excerpt; either is authoritative, a guess is not.
    """
    rows = db.query(
        "SELECT artifact_id, locator, claim FROM evidence WHERE project_id = ? AND kind IN ('network_endpoint')",
        (project_id,),
    )
    literals: list[dict[str, Any]] = []
    for row in rows:
        locator = loads(row["locator"], {}) or {}
        url = locator.get("url") or locator.get("literal")
        if not isinstance(url, str) or not url:
            match = _URL_RE.search(row["claim"] or "")
            url = match.group(0).rstrip(".,;") if match else None
        if isinstance(url, str) and url:
            literals.append({"url": url, "artifact_id": row["artifact_id"], "line": locator.get("line")})
    return literals


def correlate(project_id: str, *, run_id: str | None = None) -> dict[str, Any]:
    """Match imported flows against static URL literals and recorded step windows.

    Writes the match back onto the flow rows so the correlation itself is auditable, and
    returns counts plus the state word (``NOT_OBSERVED`` when nothing was captured).
    """
    sources = db.query("SELECT * FROM capture_sources WHERE project_id = ?", (project_id,))
    if not sources:
        return {
            "state": NOT_OBSERVED,
            "reason": "no capture source attached for this project",
            "flows": 0,
            "correlated": 0,
        }
    flows = db.query(
        "SELECT * FROM capture_flows WHERE project_id = ?" + (" AND (run_id = ? OR run_id IS NULL)" if run_id else ""),
        (project_id, run_id) if run_id else (project_id,),
    )
    if not flows:
        return {"state": NOT_OBSERVED, "reason": "capture sources present but no flows imported", "flows": 0, "correlated": 0}

    steps = db.query("SELECT * FROM capture_steps WHERE project_id = ?", (project_id,))
    literals = _static_literals(project_id)
    matched = 0
    details: list[dict[str, Any]] = []
    for flow in flows:
        host = (flow["host"] or "").lower()
        literal = next(
            (item for item in literals if host and (host in (item["url"] or "").lower())), None
        )
        window = None
        for step in steps:
            start = step["started_at"] or ""
            end = step["ended_at"] or start
            when = flow["request_at"] or ""
            if start and when and start <= when <= (end or start):
                window = step
                break
        if literal or window:
            matched += 1
            db.execute(
                "UPDATE capture_flows SET matched_artifact_id = ?, matched_line = ?, matched_literal = ?,"
                " step = COALESCE(step, ?), run_id = COALESCE(run_id, ?) WHERE id = ?",
                (
                    literal["artifact_id"] if literal else None,
                    literal["line"] if literal else None,
                    literal["url"] if literal else None,
                    window["step"] if window else None,
                    window["run_id"] if window else None,
                    flow["id"],
                ),
            )
        details.append(
            {
                "flow_id": flow["id"],
                "method": flow["method"],
                "url": f"{flow['scheme']}://{flow['host']}{flow['path']}",
                "status_code": flow["status_code"],
                "matched_literal": literal["url"] if literal else None,
                "matched_artifact_id": literal["artifact_id"] if literal else None,
                "step": window["step"] if window else None,
            }
        )
    state = CORRELATED if matched else IMPORTED
    audit.record(
        "capture_correlated",
        project_id=project_id,
        payload={"flows": len(flows), "correlated": matched, "state": state, "run_id": run_id},
        actor="system",
    )
    return {"state": state, "flows": len(flows), "correlated": matched, "details": details[:200]}


def query(
    project_id: str,
    *,
    host: str | None = None,
    method: str | None = None,
    matched_only: bool = False,
    limit: int = 100,
) -> dict[str, Any]:
    clauses = ["project_id = ?"]
    params: list[Any] = [project_id]
    if host:
        clauses.append("host LIKE ?")
        params.append(f"%{host}%")
    if method:
        clauses.append("UPPER(method) = ?")
        params.append(method.upper())
    if matched_only:
        clauses.append("(matched_artifact_id IS NOT NULL OR step IS NOT NULL)")
    rows = db.query(
        "SELECT * FROM capture_flows WHERE " + " AND ".join(clauses) + " ORDER BY request_at DESC LIMIT ?",
        (*params, limit),
    )
    sources = db.query("SELECT id, kind, label, status, created_at FROM capture_sources WHERE project_id = ?", (project_id,))
    if not sources:
        return {"state": NOT_OBSERVED, "reason": "no capture source attached for this project", "flows": [], "sources": []}
    state = CORRELATED if any(row["matched_artifact_id"] or row["step"] for row in rows) else IMPORTED
    return {"state": state, "flows": [dict(row) for row in rows], "sources": [dict(row) for row in sources]}


def sources(project_id: str) -> list[dict[str, Any]]:
    return [dict(row) for row in db.query("SELECT * FROM capture_sources WHERE project_id = ?", (project_id,))]


def steps(project_id: str) -> list[dict[str, Any]]:
    return [dict(row) for row in db.query("SELECT * FROM capture_steps WHERE project_id = ?", (project_id,))]


def probe_proxy_pin(directory: str | None = None) -> dict[str, Any]:
    """Look for a ProxyPin export. Never claims availability that the host does not have."""
    from ..config import settings

    target = Path(directory or settings.capture_dir or "")
    if not directory and not settings.capture_dir:
        return {"available": False, "reason": "APKPLAT_CAPTURE_DIR is not configured; no ProxyPin export attached"}
    if not target.exists():
        return {"available": False, "reason": f"{target} does not exist"}
    candidates = sorted(target.glob("*.har")) + sorted(target.glob("*.json"))
    return {
        "available": bool(candidates),
        "reason": None if candidates else f"no .har/.json export under {target}",
        "candidates": [item.name for item in candidates[:20]],
    }


def summarize(project_id: str) -> dict[str, Any]:
    flows = db.scalar("SELECT COUNT(*) FROM capture_flows WHERE project_id = ?", (project_id,)) or 0
    matched = db.scalar(
        "SELECT COUNT(*) FROM capture_flows WHERE project_id = ? AND (matched_artifact_id IS NOT NULL OR step IS NOT NULL)",
        (project_id,),
    ) or 0
    src = sources(project_id)
    return {
        "state": NOT_OBSERVED if not src else (CORRELATED if matched else IMPORTED),
        "sources": len(src),
        "flows": flows,
        "correlated": matched,
    }
