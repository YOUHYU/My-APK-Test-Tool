"""P6 integration: the scheduler endpoints, with time supplied by a fake clock."""

from __future__ import annotations

import pytest

from apkplat import clock, resources


@pytest.fixture()
def fake_time():
    fake = clock.FakeClock("2026-02-01T06:00:00.000Z")
    previous = clock.use(fake)
    probe_previous = resources.use(resources.FakeResourceProbe(memory_available_mb=4000))
    try:
        yield fake
    finally:
        resources.use(probe_previous)
        clock.use(previous)


def _new_project(app_client, sample_apk, name: str) -> str:
    with sample_apk.open("rb") as handle:
        response = app_client.post(
            "/api/projects",
            data={"name": name, "goal": "periodic smoke"},
            files={"apk": ("sample-app.apk", handle, "application/vnd.android.package-archive")},
        )
    assert response.status_code == 201, response.text
    return response.json()["project"]["id"]


def test_identity_registration_keeps_the_secret_on_the_server(app_client, sample_apk) -> None:
    project_id = _new_project(app_client, sample_apk, "p6-api-identity")
    created = app_client.post(
        f"/api/projects/{project_id}/test-identities",
        json={"label": "fixture-account-7", "kind": "fixture", "secret_ref": "vault://fixtures/7"},
    )
    assert created.status_code == 201, created.text
    identity = created.json()["identity"]
    assert identity["has_secret_ref"] is True
    assert "secret_ref" not in identity, identity

    listed = app_client.get(f"/api/projects/{project_id}/test-identities")
    assert listed.status_code == 200
    body = listed.json()
    assert body["count"] == 1 and body["identities"][0]["active_lease"] is None


def test_unknown_identity_kind_is_refused(app_client, sample_apk) -> None:
    project_id = _new_project(app_client, sample_apk, "p6-api-bad-kind")
    response = app_client.post(
        f"/api/projects/{project_id}/test-identities",
        json={"label": "third-party", "kind": "third_party"},
    )
    assert response.status_code == 422
    assert response.json()["detail"]["error_code"] == "unsupported_identity_kind"


def test_schedule_fires_once_per_day_through_the_api(app_client, sample_apk, fake_time) -> None:
    project_id = _new_project(app_client, sample_apk, "p6-api-schedule")
    created = app_client.post(
        f"/api/projects/{project_id}/periodic",
        json={"schedule_id": "nightly", "title": "nightly sweep", "hour": 9, "tz": "UTC"},
    )
    assert created.status_code == 201, created.text
    schedule = created.json()["schedule"]
    assert schedule["next_due_at"].startswith("2026-02-01T09:00:00")

    early = app_client.post("/api/periodic/tick", json={})
    assert early.status_code == 200 and early.json()["triggered"] == 0

    fake_time.advance(3 * 3600)
    first = app_client.post("/api/periodic/tick", json={})
    assert first.json()["triggered"] == 1, first.text
    # A crash between the window claim and the bookkeeping leaves next_due_at in the past;
    # the unique index must still stop a second run for the same day.
    from apkplat.db import db
    from apkplat import clock as clock_module

    db.execute("UPDATE periodic_jobs SET next_due_at = ? WHERE id = ?", (clock_module.now_utc(), schedule["id"]))
    second = app_client.post("/api/periodic/tick", json={})
    assert second.json()["triggered"] == 0
    assert second.json()["outcomes"][0]["result"] == "DUPLICATE_WINDOW"

    runs = app_client.get(f"/api/periodic/{schedule['id']}/runs").json()
    assert runs["count"] == 1
    assert runs["runs"][0]["period_key"] == "2026-02-01"
    assert runs["runs"][0]["task_id"]

    board = app_client.get(f"/api/projects/{project_id}/board").json()
    titles = [task["title"] for tasks in board["columns"].values() for task in tasks]
    assert any(title.startswith("nightly sweep [2026-02-01]") for title in titles), titles


def test_patching_an_unknown_field_is_a_422(app_client, sample_apk, fake_time) -> None:
    project_id = _new_project(app_client, sample_apk, "p6-api-patch")
    schedule = app_client.post(
        f"/api/projects/{project_id}/periodic",
        json={"schedule_id": "patchable", "title": "patchable", "hour": 9, "tz": "UTC"},
    ).json()["schedule"]

    bad = app_client.patch(f"/api/periodic/{schedule['id']}", json={"hour": 11})
    assert bad.status_code == 422
    assert bad.json()["detail"]["error_code"] == "field_not_editable"

    off = app_client.patch(f"/api/periodic/{schedule['id']}", json={"enabled": False})
    assert off.status_code == 200 and off.json()["schedule"]["enabled"] == 0
    fake_time.advance(3 * 3600)
    assert app_client.post("/api/periodic/tick", json={}).json()["triggered"] == 0


def test_resources_endpoint_publishes_the_clock_and_the_gate(app_client, fake_time) -> None:
    body = app_client.get("/api/resources").json()
    assert body["clock"]["name"] == "fake"
    assert body["snapshot"]["source"] == "fake"
    assert body["gate_heavy"]["ok"] is True


def test_scheduler_surfaces_are_scoped_to_the_project(app_client, sample_apk, fake_time) -> None:
    mine = _new_project(app_client, sample_apk, "p6-api-mine")
    other = _new_project(app_client, sample_apk, "p6-api-other")
    schedule = app_client.post(
        f"/api/projects/{mine}/periodic",
        json={"schedule_id": "private", "title": "private", "hour": 9, "tz": "UTC"},
    ).json()["schedule"]

    from apkplat.config import settings
    from apkplat.services import auth as auth_service

    token = auth_service.issue([other], subject="scoped", scopes=["read", "write"])["token"]
    headers = {"Authorization": f"Bearer {token}"}
    previous = settings.require_auth
    settings.require_auth = True
    try:
        denied = app_client.get(f"/api/periodic/{schedule['id']}/runs", headers=headers)
        assert denied.status_code == 403
        assert denied.json()["detail"]["error_code"] == "project_denied"
        allowed = app_client.get(f"/api/projects/{other}/periodic", headers=headers)
        assert allowed.status_code == 200
    finally:
        settings.require_auth = previous
