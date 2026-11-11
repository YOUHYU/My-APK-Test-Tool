"""Auth: tokens are project-scoped, scope-checked and signature-checked.

These tests flip ``settings.require_auth`` on for the duration of the module, because
the rest of the suite deliberately runs in local-operator mode.
"""
from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from apkplat.config import settings
from apkplat.services import auth


@pytest.fixture(scope="module")
def secured_client():
    previous = settings.require_auth
    settings.require_auth = True
    from apkplat.api.app import create_app

    with TestClient(create_app()) as client:
        yield client
    settings.require_auth = previous


@pytest.mark.parametrize("path", ["/api/projects", "/api/metrics", "/api/queue"])
def test_missing_token_is_401(secured_client, path):
    resp = secured_client.get(path)
    assert resp.status_code == 401
    assert resp.json()["detail"]["error_code"] == "missing_token"


def test_token_roundtrip_and_scope_enforcement(secured_client):
    # a bootstrap token with no project list may create projects, nothing else
    bootstrap = auth.issue([], subject="bootstrap", scopes=["write"])["token"]
    project = secured_client.post(
        "/api/projects",
        data={"name": "auth-probe"},
        files={"apk": ("sample.apk", open(_sample(), "rb"), "application/vnd.android.package-archive")},
        headers={"Authorization": f"Bearer {bootstrap}"},
    )
    assert project.status_code == 201, project.text
    project_id = project.json()["project"]["id"]

    read_only = auth.issue([project_id], subject="probe", scopes=["read"])["token"]
    ok = secured_client.get(f"/api/projects/{project_id}", headers={"Authorization": f"Bearer {read_only}"})
    assert ok.status_code == 200

    # read scope cannot write
    denied = secured_client.post(
        f"/api/projects/{project_id}/tasks",
        json={"title": "nope"},
        headers={"Authorization": f"Bearer {read_only}"},
    )
    assert denied.status_code == 403
    assert denied.json()["detail"]["error_code"] == "scope_denied"

    # a token for another project cannot read this one
    other = auth.issue(["prj_someone_else"], subject="probe", scopes=["read", "write"])["token"]
    crossed = secured_client.get(f"/api/projects/{project_id}", headers={"Authorization": f"Bearer {other}"})
    assert crossed.status_code == 403
    assert crossed.json()["detail"]["error_code"] == "project_denied"


def test_tampered_token_rejected(secured_client, tmp_path):
    token = auth.issue(["prj_x"], scopes=["read"])["token"]
    head, payload, sig = token.split(".")
    forged = f"{head}.{payload}.{'A' * len(sig)}"
    resp = secured_client.get("/api/projects/prj_x", headers={"Authorization": f"Bearer {forged}"})
    assert resp.status_code == 401
    assert resp.json()["detail"]["error_code"] == "bad_signature"


def test_expired_token_rejected():
    token = auth.issue(["prj_x"], scopes=["read"], ttl=-10)["token"]
    with pytest.raises(auth.AuthError) as exc:
        auth.verify(token)
    assert exc.value.code == "token_expired"


def test_wildcard_token_request_refused(secured_client, admin_headers):
    resp = secured_client.post(
        "/api/auth/token", json={"sub": "greedy", "projects": ["*"], "scopes": ["read"]}, headers=admin_headers
    )
    assert resp.status_code in {400, 422}
    assert resp.json()["detail"]["error_code"] == "wildcard_forbidden"


def test_minting_a_token_requires_the_admin_secret(secured_client):
    resp = secured_client.post("/api/auth/token", json={"sub": "x", "projects": ["prj_1"], "scopes": ["read"]})
    assert resp.status_code == 403
    assert resp.json()["detail"]["error_code"] == "admin_denied"


def _sample():
    from pathlib import Path

    return Path(__file__).resolve().parents[2] / "samples" / "sample-app.apk"
