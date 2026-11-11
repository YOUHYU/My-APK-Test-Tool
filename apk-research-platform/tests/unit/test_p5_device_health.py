"""P5 unit tests: readiness is measured, quarantine removes a device from the pool."""

from __future__ import annotations

import pytest

from apkplat import dynamic
from apkplat.services import devices as devices_service


def _device(serial: str = "192.168.43.1:5555", alias: str = "e74398f9"):
    return devices_service.register(
        adb_serial=serial,
        device_type="phone",
        capabilities={"model": "Mi 10", "api_level": 33, "ro.serialno": alias},
        alias=alias,
    )


def test_health_measures_every_state_and_refuses_the_missing_package() -> None:
    sim = dynamic.make_transport("sim")
    report = devices_service.health("192.168.43.1:5555", package="com.example.reef", transport=sim)
    assert report["states"]["ADB_ONLINE"] is True
    assert report["states"]["PACKAGE_MANAGER_READY"] is True
    assert report["states"]["UI_READY"] is True
    assert report["states"]["APP_INSTALLED"] is False
    assert report["ready"] is False
    assert report["blocked"] == ["APP_INSTALLED"]
    assert report["metrics"]["battery_level"] == 76


def test_health_turns_ready_once_the_package_is_there() -> None:
    sim = dynamic.make_transport("sim")
    sim.installed.add("com.example.reef")
    report = devices_service.health("192.168.43.1:5555", package="com.example.reef", transport=sim)
    assert report["ready"] is True, report
    assert report["blocked"] == []
    assert report["states"]["SCREEN_UNLOCKED"] is True


def test_locked_screen_is_reported_but_not_fatal_for_install_work() -> None:
    sim = dynamic.make_transport("sim") if False else dynamic.SimTransport(screen_locked=True)
    sim.installed.add("com.example.reef")
    report = devices_service.health("192.168.43.1:5555", package="com.example.reef", transport=sim)
    assert report["states"]["SCREEN_UNLOCKED"] is False
    assert report["ready"] is True  # unlock is a UI concern, not an install concern


def test_unauthorised_adb_is_not_ready() -> None:
    sim = dynamic.SimTransport(authorized=False)
    report = devices_service.health("192.168.43.1:5555", package="com.example.reef", transport=sim)
    assert report["states"]["ADB_ONLINE"] is False
    assert report["ready"] is False
    assert "ADB_ONLINE" in report["blocked"]


def test_quarantine_removes_the_device_from_the_pool() -> None:
    device = _device()
    lease = devices_service.acquire("prj_test", owner="tester")
    assert lease["device_id"] == device["id"]
    devices_service.release(lease["id"], owner="tester")

    devices_service.quarantine(device["id"], reason="cracked screen", actor="tester")
    # Ask for this device specifically: other tests may have registered devices of their own.
    with pytest.raises(devices_service.LeaseConflict):
        devices_service.acquire("prj_test", owner="tester", device_id=device["id"])
    assert devices_service.quarantined()

    devices_service.clear_quarantine(device["id"], actor="tester")
    again = devices_service.acquire("prj_test", owner="tester", device_id=device["id"])
    assert again["device_id"] == device["id"]


def test_health_states_are_the_taskbook_set() -> None:
    assert devices_service.HEALTH_STATES == (
        "ADB_ONLINE",
        "PACKAGE_MANAGER_READY",
        "UI_READY",
        "SCREEN_UNLOCKED",
        "APP_INSTALLED",
        "APP_FOREGROUND",
        "CAPTURE_READY",
    )
