"""P6 unit tests: one clock, two time semantics, no `datetime.now()` hiding in a decision."""

from __future__ import annotations

import pytest

from apkplat import clock


@pytest.fixture()
def fake_clock():
    fake = clock.FakeClock("2026-01-01T00:00:00.000Z")
    previous = clock.use(fake)
    try:
        yield fake
    finally:
        clock.use(previous)


def test_fake_clock_advance_moves_wall_and_monotonic_time(fake_clock) -> None:
    start = clock.now_utc()
    assert start.startswith("2026-01-01T00:00:00")
    fake_clock.advance(90)
    assert clock.now_utc().startswith("2026-01-01T00:01:30")
    assert clock.monotonic() == pytest.approx(90.0)


def test_sleep_advances_the_fake_clock(fake_clock) -> None:
    clock.sleep(5)
    assert fake_clock.sleeps == [5]
    assert clock.now_utc().startswith("2026-01-01T00:00:05")


def test_iso_plus_is_relative_to_the_injected_clock(fake_clock) -> None:
    assert clock.iso_plus(600).startswith("2026-01-01T00:10:00")


def test_daily_window_is_the_business_day_in_the_declared_zone(fake_clock) -> None:
    fake_clock.set("2026-03-04T22:30:00.000Z")  # already 2026-03-05 in Shanghai
    utc = clock.window_for(clock.now(), "UTC")
    shanghai = clock.window_for(clock.now(), "Asia/Shanghai")
    assert utc["period_key"] == "2026-03-04"
    assert shanghai["period_key"] == "2026-03-05"
    assert shanghai["window_start"].startswith("2026-03-04T16:00:00")
    assert shanghai["window_end"].startswith("2026-03-05T16:00:00")


def test_next_due_rolls_to_tomorrow_when_the_slot_has_passed(fake_clock) -> None:
    fake_clock.set("2026-01-01T10:00:00.000Z")
    assert clock.next_due(clock.now(), hour=9, minute=0, tz="UTC").startswith("2026-01-02T09:00:00")
    fake_clock.set("2026-01-01T08:00:00.000Z")
    assert clock.next_due(clock.now(), hour=9, minute=0, tz="UTC").startswith("2026-01-01T09:00:00")


def test_unknown_timezone_is_refused_rather_than_guessed() -> None:
    with pytest.raises(ValueError):
        clock.tz_offset_hours("Mars/Olympus")
