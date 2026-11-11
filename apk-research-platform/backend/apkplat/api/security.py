"""Auth wiring for the HTTP API.

Two modes, both explicit:

* token mode (default): ``Authorization: Bearer v1.<payload>.<sig>`` minted by
  :mod:`apkplat.services.auth`; the token's project list is enforced here, before
  any handler runs.
* local mode (``APKPLAT_REQUIRE_AUTH=0``): every request is treated as the human
  operator with full scope. Only sane on a single-user loopback deployment, and
  the health endpoint advertises which mode is active so nobody has to guess.
"""
from __future__ import annotations

import hmac
import os
from typing import Any

from fastapi import Depends, Header, HTTPException, Request

from ..config import settings
from ..services import auth as auth_service


def _admin_secret() -> str:
    return settings.signing_secret().hex()


def _bearer(authorization: str | None) -> str | None:
    if not authorization:
        return None
    parts = authorization.split(" ", 1)
    if len(parts) == 2 and parts[0].lower() == "bearer":
        return parts[1].strip()
    return authorization.strip()


def claims_for(authorization: str | None, project_id: str | None, scope: str) -> dict[str, Any]:
    if not settings.require_auth:
        return {"sub": "local-operator", "prj": [project_id] if project_id else ["*"], "scp": ["read", "write", "admin"]}
    token = _bearer(authorization)
    if not token:
        raise HTTPException(status_code=401, detail={"error_code": "missing_token", "message": "Authorization header required"})
    try:
        claims = auth_service.verify(token)
        if project_id and "*" in claims.get("prj", []):
            claims["prj"] = [*claims["prj"], project_id]
        auth_service.authorize(claims, project_id, scope)
    except auth_service.AuthError as exc:
        raise HTTPException(status_code=exc.status, detail={"error_code": exc.code, "message": exc.message}) from exc
    return claims


def require(scope: str):
    """Dependency factory: ``Depends(require("read"))``."""

    def _dep(request: Request, authorization: str | None = Header(default=None)) -> dict[str, Any]:
        project_id = request.path_params.get("project_id")
        return claims_for(authorization, project_id, scope)

    return _dep


def admin_guard(x_admin_secret: str | None = Header(default=None)) -> None:
    if not settings.require_auth and os.environ.get("APKPLAT_ALLOW_LOCAL_TOKEN", "1") == "1":
        return
    if not x_admin_secret or not hmac.compare_digest(x_admin_secret, _admin_secret()):
        raise HTTPException(status_code=403, detail={"error_code": "admin_denied", "message": "X-Admin-Secret required"})
