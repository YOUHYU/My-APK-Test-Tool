"""One clock for leases, backoff and business windows.

The taskbook draws a line between two kinds of time:

* safety-critical lease timing wants a monotonic or database-backed source;
* business periodicity wants a UTC timestamp plus a timezone.

Both go through this module so a test can move time without waiting three days
(AT-09) and so no scheduler decision is quietly taken against `datetime.now()`.
"""

from __future__ import annotations

import threading
import time
from datetime import datetime, timedelta, timezone
from typing import Any


ISO_FMT = "%Y-%m-%dT%H:%M:%S.%f"
TZ_OFFSETS = {"UTC": 0, "Asia/Shanghai": 8, "Asia/Tokyo": 9, "Europe/London": 0}


class Clock:
    """The minimal adapter: wall time, monotonic time, sleep."""

    name = "real"

    def now(self) -> datetime:
        return datetime.now(timezone.utc)

    def monotonic(self) -> float:
        return time.monotonic()

    def sleep(self, seconds: float) -> None:
        time.sleep(max(0.0, seconds))

    # -- convenience ----------------------------------------------------
    def now_utc(self) -> str:
        return self.now().strftime(ISO_FMT) + "Z"

    def iso_plus(self, seconds: float) -> str:
        return (self.now() + timedelta(seconds=seconds)).strftime(ISO_FMT) + "Z"


class FakeClock(Clock):
    """Deterministic clock for the acceptance runs.

    `advance()` moves wall and monotonic time together, so a lease that expires and a
    daily window that opens can both be exercised without sleeping.
    """

    name = "fake"

    def __init__(self, start: str = "2026-01-01T00:00:00.000Z") -> None:
        self._lock = threading.Lock()
        self._now = _parse(start)
        self._mono = 0.0
        self.sleeps: list[float] = []

    def now(self) -> datetime:
        with self._lock:
            return self._now

    def monotonic(self) -> float:
        with self._lock:
            return self._mono

    def sleep(self, seconds: float) -> None:
        with self._lock:
            self.sleeps.append(seconds)
        self.advance(seconds)

    def advance(self, seconds: float) -> datetime:
        with self._lock:
            self._now = self._now + timedelta(seconds=seconds)
            self._mono += max(0.0, seconds)
            return self._now

    def set(self, moment: str) -> datetime:
        with self._lock:
            self._now = _parse(moment)
            return self._now


def _parse(value: str) -> datetime:
    text = value.strip().replace("Z", "+00:00")
    parsed = datetime.fromisoformat(text)
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


_clock: Clock = Clock()
_guard = threading.Lock()


def get_clock() -> Clock:
    return _clock


def use(clock: Clock | None) -> Clock:
    """Swap the process clock; returns the previous one so callers can restore it."""
    global _clock
    with _guard:
        previous = _clock
        _clock = clock or Clock()
    return previous


def now_utc() -> str:
    return _clock.now_utc()


def now() -> datetime:
    return _clock.now()


def monotonic() -> float:
    return _clock.monotonic()


def sleep(seconds: float) -> None:
    _clock.sleep(seconds)


def iso_plus(seconds: float) -> str:
    return _clock.iso_plus(seconds)


# -- business windows ---------------------------------------------------


def tz_offset_hours(tz: str) -> int:
    if tz not in TZ_OFFSETS:
        raise ValueError(f"unsupported timezone {tz!r}; known: {sorted(TZ_OFFSETS)}")
    return TZ_OFFSETS[tz]


def local_now(tz: str = "UTC") -> datetime:
    return _clock.now() + timedelta(hours=tz_offset_hours(tz))


def window_for(moment: datetime, tz: str = "UTC") -> dict[str, Any]:
    """The daily window a moment belongs to, as a period key plus UTC bounds."""
    offset = timedelta(hours=tz_offset_hours(tz))
    local = moment + offset
    start_local = local.replace(hour=0, minute=0, second=0, microsecond=0)
    end_local = start_local + timedelta(days=1)
    return {
        "period_key": start_local.strftime("%Y-%m-%d"),
        "tz": tz,
        "window_start": (start_local - offset).strftime(ISO_FMT) + "Z",
        "window_end": (end_local - offset).strftime(ISO_FMT) + "Z",
    }


def next_due(moment: datetime, *, hour: int, minute: int, tz: str = "UTC") -> str:
    """The first instant at or after `moment` that matches the daily schedule."""
    offset = timedelta(hours=tz_offset_hours(tz))
    local = moment + offset
    candidate = local.replace(hour=hour, minute=minute, second=0, microsecond=0)
    if candidate <= local:
        candidate = candidate + timedelta(days=1)
    return (candidate - offset).strftime(ISO_FMT) + "Z"
