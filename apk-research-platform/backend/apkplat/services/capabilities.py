"""P1 run capabilities: the only credential a DSH agent ever holds.

Design rules taken from the taskbook (鎼?.1/鎼?.2):

- the platform alone decides whether a call is allowed; the plugin's filtering is a
  convenience, never the boundary;
- the plaintext token exists once, on disk, and is read by the plugin from a file the
  platform wrote with owner-only permissions - it is never a tool argument, never in a
  prompt, never in the audit payload (only ``token_hash`` is stored);
- a capability binds ``run_id / project_id / role_id / allowed_tools / expiry /
  policy_version``; device actions additionally require a live device lease;
- ``role`` is a permission template, not a second model session.

The tools a role may call are the intersection of the role template and the caller's
explicit allow-list, so a future role cannot silently inherit a new tool.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import secrets
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterable

from ..config import settings
from ..db import Row, db, iso_plus, utcnow
from ..util import dumps, new_id

POLICY_VERSION = "p1.0"
TOKEN_PREFIX = "runcap_"

ALL_TOOLS: tuple[str, ...] = (
    "platform_health",
    "project_snapshot",
    "artifact_find",
    "apk_inspect",
    "task_propose",
    "task_status_get",
    "artifact_write",
    "test_run",
    "test_result_read",
    "device_observe",
    "device_action",
    "capture_query",
    "evidence_submit",
)

ROLE_TEMPLATES: dict[str, set[str]] = {
    "plan": {"platform_health", "project_snapshot", "artifact_find", "task_propose", "task_status_get"},
    "exec": {
        "platform_health",
        "project_snapshot",
        "artifact_find",
        "apk_inspect",
        "task_status_get",
        "artifact_write",
        "test_run",
        "test_result_read",
        "device_observe",
        "device_action",
        "capture_query",
        "evidence_submit",
    },
    "review": {
        "platform_health",
        "project_snapshot",
        "artifact_find",
        "apk_inspect",
        "task_status_get",
        "device_observe",
        "capture_query",
        "test_run",
        "evidence_submit",
    },
    "ship": {"platform_health", "project_snapshot", "artifact_find", "task_status_get", "artifact_write", "test_run", "test_result_read"},
    "evidence": {"platform_health", "project_snapshot", "artifact_find", "task_status_get", "capture_query", "evidence_submit"},
    "report": {"platform_health", "project_snapshot", "artifact_find", "task_status_get"},
}

# ``re-`` prefixed spellings appear in the taskbook prose; accept both so a caller
# does not have to guess which one the platform canonicalises to.
ROLE_ALIASES = {
    "re-plan": "plan",
    "replan": "plan",
    "re-exec": "exec",
    "reexec": "exec",
    "re-review": "review",
    "rereview": "review",
    "re-ship": "ship",
    "reship": "ship",
    "re-evidence": "evidence",
    "reevidence": "evidence",
    "re-report": "report",
    "rereport": "report",
}

# The taskbook's starting figure was 12 tool calls per task. The P1 acceptance run
# showed why that is too tight for one evidence-complete investigation: the model
# spent 12 calls orienting itself (health -> snapshot -> manifest -> packages ->
# findings -> components -> three failed `apk_inspect` attempts that taught it the
# `target` argument -> strings/code probes) and hit the cap exactly as it was about
# to submit its first piece of evidence. Exhaustion is still enforced (429
# `tool_budget_exhausted`), so the ceiling stays a real gate, only a realistic one.
DEFAULT_BUDGET = {"max_tool_calls": 32, "max_model_calls": 10}


class CapabilityError(Exception):
    """A refused capability operation. ``status`` maps to the HTTP status."""

    def __init__(self, code: str, message: str, *, status: int = 403, retryable: bool = False) -> None:
        super().__init__(message)
        self.code = code
        self.message = message
        self.status = status
        self.retryable = retryable

    def as_error(self) -> dict[str, Any]:
        """The refusals the bridge returns must look like every other tool envelope."""
        return {"error_code": self.code, "message": self.message, "retryable": self.retryable}


@dataclass
class Scope:
    run_id: str
    project_id: str
    task_id: str | None
    role_id: str
    tools: list[str]
    max_tool_calls: int = DEFAULT_BUDGET["max_tool_calls"]
    max_model_calls: int = DEFAULT_BUDGET["max_model_calls"]
    policy_version: str = POLICY_VERSION
    expires_at: str | None = None
    extra: dict[str, Any] = field(default_factory=dict)

    def as_dict(self) -> dict[str, Any]:
        return {
            "run_id": self.run_id,
            "project_id": self.project_id,
            "task_id": self.task_id,
            "role_id": self.role_id,
            "allowed_tools": list(self.tools),
            "max_tool_calls": self.max_tool_calls,
            "max_model_calls": self.max_model_calls,
            "policy_version": self.policy_version,
            "expires_at": self.expires_at,
            **self.extra,
        }


def canonical_role(role_id: str) -> str:
    value = (role_id or "").strip().lower()
    value = ROLE_ALIASES.get(value, value)
    if value not in ROLE_TEMPLATES:
        raise CapabilityError(
            "unknown_role",
            f"role {role_id!r} is not one of {sorted(ROLE_TEMPLATES)}",
            status=422,
        )
    return value


def role_tools(role_id: str) -> list[str]:
    role = canonical_role(role_id)
    return [t for t in ALL_TOOLS if t in ROLE_TEMPLATES[role]]


def _hash_token(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def token_path(run_id: str) -> Path:
    return settings.storage / "runs" / run_id / "capability.token"


def _write_token_file(run_id: str, token: str) -> Path:
    path = token_path(run_id)
    path.parent.mkdir(parents=True, exist_ok=True)
    # Owner-only where the OS supports it; Windows honours the read-only bit only, so
    # the directory itself is also kept out of any static mount.
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as fh:
        fh.write(token)
    try:
        os.chmod(path, 0o600)
    except OSError:  # pragma: no cover - best effort on Windows
        pass
    return path


def issue(
    project_id: str,
    role_id: str,
    *,
    task_id: str | None = None,
    ttl_seconds: int = 3600,
    tools: Iterable[str] | None = None,
    max_tool_calls: int | None = None,
    max_model_calls: int | None = None,
    extra: dict[str, Any] | None = None,
    actor: str = "platform",
    write_file: bool = True,
) -> tuple[Scope, str, Path | None]:
    """Create a capability. Returns ``(scope, token, token_file)``.

    The token is returned to the caller only so an operator CLI can hand the file to
    the plugin; it is hashed for storage before this function returns.
    """
    role = canonical_role(role_id)
    allowed = [t for t in role_tools(role) if tools is None or t in set(tools)]
    if task_id:
        row = db.one("SELECT project_id FROM tasks WHERE id = ?", (task_id,))
        if not row:
            raise CapabilityError("task_not_found", f"task {task_id} does not exist", status=404)
        if row["project_id"] != project_id:
            raise CapabilityError("task_project_mismatch", "task belongs to another project", status=403)

    run_id = new_id("run")
    token = TOKEN_PREFIX + secrets.token_hex(24)
    scope = Scope(
        run_id=run_id,
        project_id=project_id,
        task_id=task_id,
        role_id=role,
        tools=allowed,
        max_tool_calls=int(max_tool_calls if max_tool_calls is not None else DEFAULT_BUDGET["max_tool_calls"]),
        max_model_calls=int(max_model_calls if max_model_calls is not None else DEFAULT_BUDGET["max_model_calls"]),
        policy_version=POLICY_VERSION,
        extra=dict(extra or {}),
    )
    now = utcnow()
    expires_at = iso_plus(ttl_seconds)
    scope.expires_at = expires_at
    db.execute(
        """
        INSERT INTO run_capabilities
            (run_id, project_id, task_id, role_id, scope_json, token_hash, policy_version,
             issued_at, expires_at, revoked_at, last_seen_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, NULL, NULL)
        """,
        (run_id, project_id, task_id, role, dumps(scope.as_dict()), _hash_token(token), POLICY_VERSION, now, expires_at),
    )
    path = _write_token_file(run_id, token) if write_file else None
    from .. import audit  # local import keeps the service importable in isolation

    audit.record(
        "capability_issued",
        project_id=project_id,
        task_id=task_id,
        actor=actor,
        payload={
            "run_id": run_id,
            "role_id": role,
            "allowed_tools": allowed,
            "expires_at": expires_at,
            "policy_version": POLICY_VERSION,
            "token_hash_prefix": _hash_token(token)[:12],
        },
    )
    return scope, token, path


def _row_to_scope(row: Row) -> Scope:
    payload = json.loads(row["scope_json"])
    return Scope(
        run_id=row["run_id"],
        project_id=row["project_id"],
        task_id=row["task_id"],
        role_id=row["role_id"],
        tools=list(payload.get("allowed_tools") or []),
        max_tool_calls=int(payload.get("max_tool_calls") or DEFAULT_BUDGET["max_tool_calls"]),
        max_model_calls=int(payload.get("max_model_calls") or DEFAULT_BUDGET["max_model_calls"]),
        policy_version=row["policy_version"],
        expires_at=row["expires_at"],
        extra={k: v for k, v in payload.items() if k not in {"run_id", "project_id", "task_id", "role_id", "allowed_tools", "max_tool_calls", "max_model_calls", "policy_version", "expires_at"}},
    )


def resolve(token: str) -> Scope:
    """Look a capability up by plaintext token. Never logs the token."""
    if not token:
        raise CapabilityError("missing_token", "Authorization: Bearer <run capability> is required", status=401)
    digest = _hash_token(token)
    row = db.one("SELECT * FROM run_capabilities WHERE token_hash = ?", (digest,))
    if row is None:
        raise CapabilityError("invalid_token", "run capability not recognised", status=401)
    # constant-time confirmation of the hash we just matched on
    if not hmac.compare_digest(row["token_hash"], digest):  # pragma: no cover - defensive
        raise CapabilityError("invalid_token", "run capability not recognised", status=401)
    if row["revoked_at"]:
        raise CapabilityError("capability_revoked", "run capability was revoked", status=401)
    now = utcnow()
    if row["expires_at"] <= now:
        raise CapabilityError("capability_expired", f"run capability expired at {row['expires_at']}", status=401)
    db.execute("UPDATE run_capabilities SET last_seen_at = ? WHERE run_id = ?", (now, row["run_id"]))
    return _row_to_scope(row)


def get(run_id: str) -> Scope | None:
    row = db.one("SELECT * FROM run_capabilities WHERE run_id = ?", (run_id,))
    return _row_to_scope(row) if row else None


def revoke(run_id: str, *, reason: str, actor: str = "platform") -> bool:
    changed = db.execute(
        "UPDATE run_capabilities SET revoked_at = ? WHERE run_id = ? AND revoked_at IS NULL",
        (utcnow(), run_id),
    )
    if changed:
        from .. import audit

        audit.record("capability_revoked", project_id=get(run_id).project_id if get(run_id) else None, actor=actor, payload={"run_id": run_id, "reason": reason})
    return bool(changed)


def tool_calls_used(run_id: str) -> int:
    return int(db.scalar("SELECT COUNT(*) FROM run_tool_calls WHERE run_id = ?", (run_id,), default=0) or 0)


def bind_agent_run(run_id: str, agent_run_id: str) -> None:
    """Tie the capability to the ``agent_runs`` row created at handshake."""
    db.execute("UPDATE run_capabilities SET agent_run_id = ? WHERE run_id = ?", (agent_run_id, run_id))


def agent_run_of(run_id: str) -> str | None:
    row = db.one("SELECT agent_run_id FROM run_capabilities WHERE run_id = ?", (run_id,))
    return row["agent_run_id"] if row else None


def authorize(scope: Scope, tool: str, args: dict[str, Any]) -> None:
    """Refuse a call the capability does not cover. Ordered from cheapest to costliest."""
    if tool not in ALL_TOOLS:
        raise CapabilityError("unknown_tool", f"tool {tool!r} is not part of the p1 contract", status=404)
    if tool not in scope.tools:
        raise CapabilityError(
            "tool_not_in_scope",
            f"role {scope.role_id!r} may not call {tool!r} (allowed: {scope.tools})",
            status=403,
        )
    requested_project = str(args.get("project_id") or scope.project_id)
    if requested_project != scope.project_id:
        from .. import audit

        audit.record(
            "bridge_cross_project_denied",
            project_id=scope.project_id,
            task_id=scope.task_id,
            actor=f"bridge:{scope.run_id}",
            payload={"requested_project_id": requested_project, "tool": tool},
        )
        raise CapabilityError("project_denied", "run capability is bound to another project", status=403)
    if tool_calls_used(scope.run_id) >= scope.max_tool_calls:
        raise CapabilityError(
            "tool_budget_exhausted",
            f"run already used {scope.max_tool_calls} tool calls; stop and report NEEDS_MORE_EVIDENCE",
            status=429,
            retryable=False,
        )


def record_call(
    run_id: str,
    *,
    tool: str,
    args: dict[str, Any],
    ok: bool,
    error_code: str | None,
    duration_ms: int,
    request_id: str,
    result_preview: str | None = None,
) -> int:
    """Append one trace row. Returns the per-run sequence number."""
    args_hash = hashlib.sha256(dumps(args).encode("utf-8")).hexdigest()
    with db.tx():
        seq = int(db.scalar("SELECT COALESCE(MAX(seq), 0) + 1 FROM run_tool_calls WHERE run_id = ?", (run_id,), default=1) or 1)
        db.execute(
            """
            INSERT INTO run_tool_calls
                (run_id, seq, tool, args_hash, ok, error_code, duration_ms, request_id, result_preview, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                run_id,
                seq,
                tool,
                args_hash,
                1 if ok else 0,
                error_code,
                int(duration_ms),
                request_id,
                # 12k keeps a long code listing's class names in the trace, so a reviewer
                # can still see which result an agent's next argument came from.
                (result_preview or "")[:12000] or None,
                utcnow(),
            ),
        )
    return seq


def trace(run_id: str, after_seq: int = 0, limit: int = 500) -> list[Row]:
    return db.query(
        "SELECT seq, tool, args_hash, ok, error_code, duration_ms, request_id, result_preview, created_at "
        "FROM run_tool_calls WHERE run_id = ? AND seq > ? ORDER BY seq LIMIT ?",
        (run_id, int(after_seq), int(limit)),
    )


def describe(run_id: str) -> dict[str, Any] | None:
    scope = get(run_id)
    if scope is None:
        return None
    row = db.one("SELECT * FROM run_capabilities WHERE run_id = ?", (run_id,))
    return {
        **scope.as_dict(),
        "issued_at": row["issued_at"],
        "revoked_at": row["revoked_at"],
        "last_seen_at": row["last_seen_at"],
        "tool_calls_used": tool_calls_used(run_id),
    }
