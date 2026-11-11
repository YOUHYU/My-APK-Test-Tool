"""P6 unit tests: low resources refuse the work instead of trying and thrashing."""

from __future__ import annotations

import pytest

from apkplat import resources


@pytest.fixture()
def restore_probe():
    previous = resources.use(None)
    resources.use(previous)
    yield
    resources.use(previous)


def test_fake_probe_low_memory_blocks_heavy_work() -> None:
    probe = resources.FakeResourceProbe(low_memory=True)
    gate = resources.check("heavy", probe=probe)
    assert gate["ok"] is False
    assert gate["reason"] == "RESOURCE_BLOCKED"
    assert "memory_available_mb=120" in gate["detail"]
    assert gate["snapshot"]["source"] == "fake"


def test_same_memory_is_enough_for_a_light_task() -> None:
    probe = resources.FakeResourceProbe(low_memory=True, memory_available_mb=300)
    assert resources.check("heavy", probe=probe)["ok"] is False
    assert resources.check("light", probe=probe)["ok"] is True


def test_a_healthy_probe_passes() -> None:
    gate = resources.check("heavy", probe=resources.FakeResourceProbe(memory_available_mb=1900))
    assert gate["ok"] is True and gate["reason"] is None


def test_disk_floor_is_enforced() -> None:
    gate = resources.check("light", probe=resources.FakeResourceProbe(memory_available_mb=4000, disk_free_mb=10))
    assert gate["ok"] is False and "disk_free_mb=10" in gate["detail"]


def test_the_real_probe_measures_the_host() -> None:
    snap = resources.ResourceProbe().snapshot()
    assert snap.source == "real"
    assert snap.memory_total_mb is None or snap.memory_total_mb > 0
    assert snap.disk_free_mb is None or snap.disk_free_mb > 0


def test_swapping_the_probe_is_visible_to_check() -> None:
    previous = resources.use(resources.FakeResourceProbe(low_memory=True))
    try:
        assert resources.check("heavy")["ok"] is False
    finally:
        resources.use(previous)
