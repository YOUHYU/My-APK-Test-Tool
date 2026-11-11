"""Resource probe: refuse heavy work before it starts, and say why.

The host runs on ~1.9 GB free RAM, so "just try it and see" is how the machine gets
thrashing instead of answers. The probe is injectable (AT-10) so the refusal path can be
proven without actually exhausting memory: `FakeResourceProbe(low_memory=True)` makes
`RESOURCE_BLOCKED` deterministic, and the same code path re-checks later.
"""

from __future__ import annotations

import ctypes
import shutil
from dataclasses import asdict, dataclass, field
from typing import Any

from .config import settings


@dataclass
class Snapshot:
    memory_total_mb: int | None = None
    memory_available_mb: int | None = None
    disk_free_mb: int | None = None
    devices_leased: int = 0
    model_inflight: int = 0
    heavy_tools: int = 0
    source: str = "real"
    extra: dict[str, Any] = field(default_factory=dict)

    def as_dict(self) -> dict[str, Any]:
        return asdict(self)


class ResourceProbe:
    name = "real"

    def snapshot(self) -> Snapshot:  # pragma: no cover - exercised on the real host
        total = available = None
        try:
            class MemoryStatus(ctypes.Structure):
                _fields_ = [
                    ("dwLength", ctypes.c_ulong),
                    ("dwMemoryLoad", ctypes.c_ulong),
                    ("ullTotalPhys", ctypes.c_ulonglong),
                    ("ullAvailPhys", ctypes.c_ulonglong),
                    ("ullTotalPageFile", ctypes.c_ulonglong),
                    ("ullAvailPageFile", ctypes.c_ulonglong),
                    ("ullTotalVirtual", ctypes.c_ulonglong),
                    ("ullAvailVirtual", ctypes.c_ulonglong),
                    ("ullAvailExtendedVirtual", ctypes.c_ulonglong),
                ]

            status = MemoryStatus()
            status.dwLength = ctypes.sizeof(MemoryStatus)
            if ctypes.windll.kernel32.GlobalMemoryStatusEx(ctypes.byref(status)):  # type: ignore[attr-defined]
                total = int(status.ullTotalPhys // (1024 * 1024))
                available = int(status.ullAvailPhys // (1024 * 1024))
        except Exception:  # noqa: BLE001 - a probe that dies must not fail the caller
            total = available = None
        try:
            disk_free = int(shutil.disk_usage(settings.storage).free // (1024 * 1024))
        except OSError:
            disk_free = None
        return Snapshot(
            memory_total_mb=total,
            memory_available_mb=available,
            disk_free_mb=disk_free,
            devices_leased=_leased_devices(),
            model_inflight=_model_inflight(),
            heavy_tools=0,
            source=self.name,
        )


class FakeResourceProbe(ResourceProbe):
    """A probe with fixed numbers, so the refusal path is testable."""

    name = "fake"

    def __init__(
        self,
        *,
        low_memory: bool = False,
        memory_total_mb: int = 16000,
        memory_available_mb: int | None = None,
        disk_free_mb: int = 500_000,
        devices_leased: int = 0,
        model_inflight: int = 0,
    ) -> None:
        self.low_memory = low_memory
        self.memory_total_mb = memory_total_mb
        self.memory_available_mb = memory_available_mb if memory_available_mb is not None else (120 if low_memory else 8000)
        self.disk_free_mb = disk_free_mb
        self.devices_leased = devices_leased
        self.model_inflight = model_inflight
        self.calls = 0

    def snapshot(self) -> Snapshot:
        self.calls += 1
        return Snapshot(
            memory_total_mb=self.memory_total_mb,
            memory_available_mb=self.memory_available_mb,
            disk_free_mb=self.disk_free_mb,
            devices_leased=self.devices_leased,
            model_inflight=self.model_inflight,
            heavy_tools=0,
            source=self.name,
            extra={"low_memory": self.low_memory},
        )


def _leased_devices() -> int:
    from .db import db
    from . import clock

    row = db.one(
        "SELECT COUNT(*) AS n FROM device_leases WHERE released_at IS NULL AND expires_at > ?",
        (clock.now_utc(),),
    )
    return int(row["n"]) if row else 0


def _model_inflight() -> int:
    try:
        from . import llm

        return int(getattr(llm, "inflight", lambda: 0)() or 0)
    except Exception:  # noqa: BLE001
        return 0


# -- the decision -------------------------------------------------------

#: Minimum free memory for a heavy java analysis (jadx + apktool on a large APK).
HEAVY_MEMORY_MIN_MB = 700
#: Minimum free memory for a light task (report render, evidence verify).
LIGHT_MEMORY_MIN_MB = 150
#: Free disk floor for writing artifacts.
DISK_MIN_MB = 512


def check(cost: str = "light", *, probe: ResourceProbe | None = None) -> dict[str, Any]:
    """`{"ok": bool, "reason": ..., "snapshot": {...}}` - deterministic, no guessing."""
    active = probe or _probe()
    snap = active.snapshot()
    needed = HEAVY_MEMORY_MIN_MB if cost == "heavy" else LIGHT_MEMORY_MIN_MB
    reasons: list[str] = []
    if snap.memory_available_mb is not None and snap.memory_available_mb < needed:
        reasons.append(f"memory_available_mb={snap.memory_available_mb} < {needed}")
    if snap.disk_free_mb is not None and snap.disk_free_mb < DISK_MIN_MB:
        reasons.append(f"disk_free_mb={snap.disk_free_mb} < {DISK_MIN_MB}")
    return {
        "ok": not reasons,
        "cost": cost,
        "reason": "RESOURCE_BLOCKED" if reasons else None,
        "detail": "; ".join(reasons) or None,
        "snapshot": snap.as_dict(),
    }


_probe_instance: ResourceProbe = ResourceProbe()


def _probe() -> ResourceProbe:
    return _probe_instance


def use(probe: ResourceProbe | None) -> ResourceProbe:
    global _probe_instance
    previous = _probe_instance
    _probe_instance = probe or ResourceProbe()
    return previous


def snapshot() -> dict[str, Any]:
    return _probe().snapshot().as_dict()
