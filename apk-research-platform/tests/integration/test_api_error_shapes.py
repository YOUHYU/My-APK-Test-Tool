"""Bad requests must come back as structured 4xx, never as a plain 500.

The frontend and the MCP server both branch on ``error_code``, so a malformed
payload that reaches a service and dies on a KeyError is a real defect - it hides
the cause behind a stack trace and makes the caller retry blindly.
"""
from __future__ import annotations

import pytest


@pytest.fixture(scope="module")
def project_id(app_client, sample_apk) -> str:
    with open(sample_apk, "rb") as handle:
        response = app_client.post(
            "/api/projects",
            data={"name": "error-shapes"},
            files={"apk": ("sample-app.apk", handle, "application/vnd.android.package-archive")},
        )
    assert response.status_code == 201, response.text
    return response.json()["project"]["id"]


def _code(response) -> str:
    body = response.json()
    if isinstance(body.get("detail"), dict):
        return body["detail"].get("error_code", "")
    return body.get("error_code", "")


def test_task_without_title_is_422(app_client, project_id):
    response = app_client.post(f"/api/projects/{project_id}/tasks", json={"role": "static"})
    assert response.status_code == 422
    assert _code(response) == "title_required"


def test_patch_of_a_non_editable_field_is_422(app_client, project_id):
    created = app_client.post(
        f"/api/projects/{project_id}/tasks", json={"title": "editable check", "actor": "human"}
    )
    assert created.status_code == 201
    task_id = created.json()["id"]
    response = app_client.patch(f"/api/tasks/{task_id}", json={"last_error": "nope"})
    assert response.status_code == 422
    assert _code(response) == "field_not_editable"
    body = response.json()["detail"]
    assert "error_message" in body["editable"]


def test_run_on_a_missing_task_is_404(app_client):
    response = app_client.post("/api/tasks/tsk_missing/runs", json={"role": "agent"})
    assert response.status_code == 404
    assert _code(response) == "task_not_found"


def test_bad_decision_is_422_and_missing_approval_is_404(app_client):
    bad = app_client.post("/api/approvals/apv_missing/decide", json={"decision": "maybe"})
    assert bad.status_code == 422
    assert _code(bad) == "invalid_decision"

    missing = app_client.post("/api/approvals/apv_missing/decide", json={"decision": "approved"})
    assert missing.status_code == 404
    assert _code(missing) == "approval_not_found"


def test_device_registration_without_serial_is_422(app_client):
    response = app_client.post("/api/devices/register", json={"type": "emulator"})
    assert response.status_code == 422
    assert _code(response) == "adb_serial_required"


def test_malformed_ground_truth_is_422(app_client, sample_apk):
    with open(sample_apk, "rb") as handle:
        response = app_client.post(
            "/api/projects",
            data={"name": "bad-truth", "ground_truth": "{not json"},
            files={"apk": ("sample-app.apk", handle, "application/vnd.android.package-archive")},
        )
    assert response.status_code == 422
    assert _code(response) == "invalid_ground_truth"
