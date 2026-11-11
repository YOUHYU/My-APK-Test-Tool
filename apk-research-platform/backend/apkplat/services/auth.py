"""Project-scoped capability tokens.

Tokens are HMAC-SHA256 signed by a per-deployment secret that never leaves
``storage/secret.key`` (or ``APKPLAT_SECRET``). A token names the projects it may
touch and the scopes it may use; the API rejects any project outside that list
*before* it looks at the database, so "agent queried another project" is a 403,
not a silent row filter.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import time
from typing import Any, Iterable

from ..config import settings
from ..util import new_id


class AuthError(Exception):
    def __init__(self, code: str, message: str, status: int = 401) -> None:
        super().__init__(message)
        self.code = code
        self.message = message
        self.status = status


def _b64(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def _unb64(text: str) -> bytes:
    pad = "=" * (-len(text) % 4)
    return base64.urlsafe_b64decode(text + pad)


def _sign(payload: str) -> str:
    return _b64(hmac.new(settings.signing_secret(), payload.encode("ascii"), hashlib.sha256).digest())


def issue(
    project_ids: Iterable[str],
    *,
    subject: str = "agent",
    scopes: Iterable[str] = ("read",),
    ttl: int | None = None,
) -> dict[str, Any]:
    now = int(time.time())
    claims = {
        "sub": subject,
        "prj": sorted(set(project_ids)),
        "scp": sorted(set(scopes)),
        "iat": now,
        "exp": now + (ttl or settings.token_ttl_seconds),
        "jti": new_id("tok_"),
    }
    payload = _b64(json.dumps(claims, separators=(",", ":")).encode("utf-8"))
    token = f"v1.{payload}.{_sign(payload)}"
    return {"token": token, "expires_at": claims["exp"], "claims": claims}


def verify(token: str) -> dict[str, Any]:
    if not token or token.count(".") != 2:
        raise AuthError("bad_token", "malformed token")
    version, payload, signature = token.split(".")
    if version != "v1":
        raise AuthError("bad_token", "unsupported token version")
    if not hmac.compare_digest(_sign(payload), signature):
        raise AuthError("bad_signature", "token signature mismatch")
    try:
        claims = json.loads(_unb64(payload))
    except Exception as exc:  # noqa: BLE001
        raise AuthError("bad_token", f"payload unreadable: {exc}") from exc
    if int(claims.get("exp", 0)) < int(time.time()):
        raise AuthError("token_expired", "token expired")
    return claims


def authorize(claims: dict[str, Any], project_id: str | None, scope: str) -> None:
    if scope not in claims.get("scp", []):
        raise AuthError("scope_denied", f"token lacks scope {scope!r}", status=403)
    projects = claims.get("prj", [])
    # "*" is the local-operator claim set; minted tokens may never carry it (the token endpoint
    # rejects it with wildcard_forbidden), but the loopback operator needs it for routes whose
    # path does not contain a project id.
    if project_id and "*" not in projects and project_id not in projects:
        raise AuthError(
            "project_denied",
            f"token is not scoped to project {project_id} (projects: {projects})",
            status=403,
        )
