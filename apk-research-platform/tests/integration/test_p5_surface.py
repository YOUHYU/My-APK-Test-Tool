"""P5 surface tests: the device endpoints report measured state, never optimistic state."""

from __future__ import annotations

from apkplat import dynamic
from apkplat.services import devices as devices_service
from apkplat.services import projects as projects_service


SERIAL = "192.168.43.1:5555"


def _project(sample_apk) -> str:
    project = projects_service.create(name="p5-surface", apk_source=sample_apk, filename="sample-app.apk", actor="test")
    return project["id"]


def test_cleanup_modes_expose_the_matrix(app_client) -> None:
    response = app_client.get("/api/cleanup/modes")
    assert response.status_code == 200, response.text
    body = response.json()
    assert set(body["modes"]) == set(dynamic.CLEANUP_MODES)
    for mode, plans in body["modes"].items():
        assert "installed_by_us" in plans and "pre_existing" in plans, mode
    session = body["modes"]["PRESERVE_SESSION"]["installed_by_us"]
    assert [row["action"] for row in session if row["allowed"]] == ["clear_scratch"]


def test_live_devices_merges_transports(app_client) -> None:
    response = app_client.get("/api/devices/live")
    assert response.status_code == 200, response.text
    body = response.json()
    assert "merged" in body and "raw" in body
    assert isinstance(body["merged"], list)
    assert body["serial_count"] == len({row.get("merge_key") for row in body["merged"]})


def test_health_endpoint_measures_through_the_simulator(app_client, sample_apk) -> None:
    project_id = _project(sample_apk)
    response = app_client.get(
        f"/api/devices/{SERIAL}/health",
        params={"project_id": project_id, "transport": "sim"},
    )
    assert response.status_code == 200, response.text
    body = response.json()
    assert body["states"]["ADB_ONLINE"] is True
    assert body["states"]["APP_INSTALLED"] is False
    assert body["ready"] is False
    assert body["blocked"] == ["APP_INSTALLED"]


def test_quarantine_flow_round_trips(app_client) -> None:
    devices_service.register(adb_serial=SERIAL, device_type="phone", alias="e74398f9")

    listed = app_client.get("/api/devices").json()
    assert any(d["adb_serial"] == SERIAL for d in listed["devices"])

    missing = app_client.post("/api/devices/nope:1/quarantine", json={"reason": "x"})
    assert missing.status_code == 404
    assert missing.json()["detail"]["error_code"] == "device_not_found"

    quarantined = app_client.post(f"/api/devices/{SERIAL}/quarantine", json={"reason": "cracked screen"})
    assert quarantined.status_code == 200, quarantined.text
    assert quarantined.json()["device"]["health"] == "QUARANTINED"

    cleared = app_client.post(f"/api/devices/{SERIAL}/quarantine/clear", json={})
    assert cleared.status_code == 200, cleared.text
    assert cleared.json()["device"]["health"] != "QUARANTINED"


def test_device_action_requires_a_lease(app_client, sample_apk) -> None:
    project_id = _project(sample_apk)
    response = app_client.post(
        f"/api/bridge/tools/device_action",
        json={"action": "launch", "package": "com.example.reef"},
        headers={"Authorization": "Bearer runcap_missing"},
    )
    # The gateway rejects unknown capabilities before any device work happens.
    assert response.status_code == 401
    detail = response.json().get("detail")
    code = detail.get("error_code") if isinstance(detail, dict) else None
    assert code in ("capability_not_found", "capability_invalid", "invalid_token")
