"""Device registry and leases for the dynamic stage (P4).

Invariants enforced here (not in a worker's head):
* one active lease per device  — a second acquire for a live lease raises
  ``LeaseConflict`` (device_lease_collision metric must stay 0);
* one active lease per project+task pair;
* a lease is only valid until ``expires_at``; expired leases are reclaimable and
  ``release`` is idempotent, which is what makes unplug-a-device safe.
"""
from __future__ import annotations

import subprocess
from typing import Any

from .. import audit
from ..config import settings
from ..db import Row, db, iso_plus, utcnow
from ..util import dumps, loads, new_id


class LeaseConflict(RuntimeError):
    pass


def register(
    adb_serial: str, *, device_type: str = "emulator", capabilities: dict | None = None, alias: str | None = None
) -> Row:
    existing = db.one("SELECT * FROM devices WHERE adb_serial = ?", (adb_serial,))
    if existing:
        with db.tx():
            db.execute(
                "UPDATE devices SET last_seen = ?, capabilities = ?, type = ? WHERE id = ?",
                (utcnow(), dumps(capabilities or {}), device_type, existing["id"]),
            )
        return db.one("SELECT * FROM devices WHERE id = ?", (existing["id"],))  # type: ignore[return-value]
    device_id = new_id("dev_")
    with db.tx():
        db.execute(
            "INSERT INTO devices(id, serial_alias, adb_serial, type, capabilities, health, last_seen)"
            " VALUES(?,?,?,?,?,?,?)",
            (device_id, alias or adb_serial, adb_serial, device_type, dumps(capabilities or {}), "unknown", utcnow()),
        )
    audit.record("device_registered", actor="system", payload={"device_id": device_id, "serial": adb_serial})
    return db.one("SELECT * FROM devices WHERE id = ?", (device_id,))  # type: ignore[return-value]


def list_devices() -> list[Row]:
    rows = db.query("SELECT * FROM devices ORDER BY serial_alias")
    for row in rows:
        row["capabilities"] = loads(row["capabilities"], {})
        row["active_lease"] = active_lease_for_device(row["id"])
    return rows


def get(device_id: str) -> Row | None:
    row = db.one("SELECT * FROM devices WHERE id = ?", (device_id,))
    if row:
        row["capabilities"] = loads(row["capabilities"], {})
    return row


def active_lease_for_device(device_id: str) -> dict | None:
    row = db.one(
        "SELECT * FROM device_leases WHERE device_id = ? AND released_at IS NULL AND expires_at > ?"
        " ORDER BY expires_at DESC LIMIT 1",
        (device_id, utcnow()),
    )
    return dict(row) if row else None


def acquire(
    project_id: str,
    *,
    task_id: str | None = None,
    owner: str = "worker",
    device_id: str | None = None,
    ttl: int | None = None,
) -> Row:
    ttl = ttl or settings.device_lease_seconds
    now = utcnow()
    with db.tx():
        db.execute("UPDATE device_leases SET released_at = ? WHERE released_at IS NULL AND expires_at <= ?", (now, now))
        candidates: list[Row]
        if device_id:
            candidates = db.query("SELECT * FROM devices WHERE id = ? AND health != 'QUARANTINED'", (device_id,))
        else:
            candidates = db.query(
                "SELECT * FROM devices WHERE health != 'QUARANTINED' AND id NOT IN ("
                "  SELECT device_id FROM device_leases WHERE released_at IS NULL AND expires_at > ?"
                ") ORDER BY last_seen DESC",
                (now,),
            )
        if not candidates:
            raise LeaseConflict("no idle device available")
        device = candidates[0]
        live = db.one(
            "SELECT * FROM device_leases WHERE device_id = ? AND released_at IS NULL AND expires_at > ?",
            (device["id"], now),
        )
        if live:
            raise LeaseConflict(
                f"device {device['serial_alias']} already leased to {live['owner']} until {live['expires_at']}"
            )
        duplicate = db.one(
            "SELECT * FROM device_leases WHERE released_at IS NULL AND expires_at > ? AND project_id = ? AND task_id IS ?",
            (now, project_id, task_id),
        )
        if duplicate:
            raise LeaseConflict("task already holds a device lease")
        lease_id = new_id("lea_")
        expires = iso_plus(ttl)
        db.execute(
            "INSERT INTO device_leases(id, project_id, task_id, device_id, owner, expires_at, heartbeat_at)"
            " VALUES(?,?,?,?,?,?,?)",
            (lease_id, project_id, task_id, device["id"], owner, expires, now),
        )
        db.execute("UPDATE devices SET health = ?, last_seen = ? WHERE id = ?", ("busy", now, device["id"]))
    audit.record(
        "device_lease_acquired",
        project_id=project_id,
        task_id=task_id,
        actor=owner,
        payload={"lease_id": lease_id, "device_id": device["id"], "serial": device["serial_alias"], "ttl": ttl},
    )
    return db.one("SELECT * FROM device_leases WHERE id = ?", (lease_id,))  # type: ignore[return-value]


def heartbeat(lease_id: str, owner: str | None = None, ttl: int | None = None) -> Row:
    ttl = ttl or settings.device_lease_seconds
    now = utcnow()
    lease = db.one("SELECT * FROM device_leases WHERE id = ?", (lease_id,))
    if not lease:
        raise KeyError(lease_id)
    if lease["released_at"]:
        raise LeaseConflict("lease already released")
    if owner and lease["owner"] != owner:
        raise LeaseConflict(f"lease owned by {lease['owner']}")
    with db.tx():
        db.execute(
            "UPDATE device_leases SET heartbeat_at = ?, expires_at = ? WHERE id = ?",
            (now, iso_plus(ttl), lease_id),
        )
        db.execute("UPDATE devices SET last_seen = ? WHERE id = ?", (now, lease["device_id"]))
    return db.one("SELECT * FROM device_leases WHERE id = ?", (lease_id,))  # type: ignore[return-value]


def release(lease_id: str, *, owner: str | None = None, reason: str = "released") -> Row:
    lease = db.one("SELECT * FROM device_leases WHERE id = ?", (lease_id,))
    if not lease:
        raise KeyError(lease_id)
    if owner and lease["owner"] != owner:
        raise LeaseConflict(f"lease owned by {lease['owner']}")
    if not lease["released_at"]:
        with db.tx():
            db.execute("UPDATE device_leases SET released_at = ? WHERE id = ?", (utcnow(), lease_id))
            # Releasing a lease returns the device to the pool, but a quarantined device stays
            # quarantined: it was taken out of service on purpose, not because it was busy.
            db.execute(
                "UPDATE devices SET health = CASE WHEN health = 'QUARANTINED' THEN health ELSE ? END,"
                " last_seen = ? WHERE id = ?",
                ("idle", utcnow(), lease["device_id"]),
            )
        audit.record(
            "device_lease_released",
            project_id=lease["project_id"],
            task_id=lease["task_id"],
            actor=owner or "system",
            payload={"lease_id": lease_id, "reason": reason},
        )
    return db.one("SELECT * FROM device_leases WHERE id = ?", (lease_id,))  # type: ignore[return-value]


def list_leases(project_id: str | None = None, active_only: bool = True) -> list[Row]:
    sql = "SELECT * FROM device_leases WHERE 1=1"
    params: list[Any] = []
    if active_only:
        sql += " AND released_at IS NULL AND expires_at > ?"
        params.append(utcnow())
    if project_id:
        sql += " AND project_id = ?"
        params.append(project_id)
    sql += " ORDER BY heartbeat_at DESC"
    return db.query(sql, params)


def adb_devices(adb_path: str | None = None) -> dict[str, Any]:
    """Best-effort `adb devices -l` probe (read-only; never mutates a device)."""
    exe = adb_path or "adb"
    try:
        proc = subprocess.run(
            [exe, "devices", "-l"], capture_output=True, text=True, timeout=20, errors="replace"
        )
        lines = [line.strip() for line in proc.stdout.splitlines() if line.strip()]
        devices = [line for line in lines[1:] if "\t" in line or " " in line]
        return {"ok": proc.returncode == 0, "adb": exe, "devices": devices, "raw": proc.stdout[:2000]}
    except FileNotFoundError:
        return {"ok": False, "adb": exe, "devices": [], "error": "adb_not_found"}
    except Exception as exc:  # noqa: BLE001
        return {"ok": False, "adb": exe, "devices": [], "error": str(exc)}

# ---------------------------------------------------------------------------
# P5: device identity, composite health gate, quarantine
# ---------------------------------------------------------------------------

HEALTH_STATES = (
    "ADB_ONLINE",
    "PACKAGE_MANAGER_READY",
    "UI_READY",
    "SCREEN_UNLOCKED",
    "APP_INSTALLED",
    "APP_FOREGROUND",
    "CAPTURE_READY",
)


def _settings():
    return settings


def parse_adb_devices(raw: str) -> list[dict[str, str]]:
    """Parse `adb devices -l` into rows. A device with two transports is still one device."""
    rows: list[dict[str, str]] = []
    for line in (raw or "").splitlines():
        line = line.strip()
        if not line or line.startswith("List of devices") or line.startswith("*"):
            continue
        parts = line.split()
        if len(parts) < 2:
            continue
        row = {"serial": parts[0], "state": parts[1]}
        for token in parts[2:]:
            if ":" in token:
                key, _, value = token.partition(":")
                row[key] = value
        rows.append(row)
    return rows


def identity(adb_serial: str, *, adb: str | None = None, timeout: int = 20) -> dict[str, Any]:
    """Read the hardware identity. `ro.serialno` is the merge key across transports."""
    from .. import toolchain
    from ..util import loads as _loads

    exe = adb or toolchain.paths().get("adb") or "adb"
    props = ["ro.serialno", "ro.product.model", "ro.product.device", "ro.build.version.sdk", "ro.build.version.release"]
    try:
        proc = subprocess.run(
            [exe, "-s", adb_serial, "shell", "; ".join(f"getprop {p}" for p in props)],
            capture_output=True,
            text=True,
            timeout=timeout,
            errors="replace",
            env=toolchain.child_env(),
        )
    except (FileNotFoundError, subprocess.TimeoutExpired) as exc:
        return {"ok": False, "adb_serial": adb_serial, "error": type(exc).__name__}
    values = [line.strip() for line in proc.stdout.splitlines() if line.strip()]
    values += [""] * (len(props) - len(values))
    facts = dict(zip(props, values[: len(props)]))
    facts["ok"] = proc.returncode == 0 and bool(facts.get("ro.serialno"))
    facts["adb_serial"] = adb_serial
    facts["merge_key"] = facts.get("ro.serialno") or adb_serial
    return facts


def merge_transports(rows: list[dict[str, str]], *, adb: str | None = None) -> list[dict[str, Any]]:
    """Collapse two transports of the same handset into one logical device entry."""
    merged: dict[str, dict[str, Any]] = {}
    for row in rows:
        if row.get("state") != "device":
            continue
        facts = identity(row["serial"], adb=adb)
        key = facts.get("merge_key") or row["serial"]
        entry = merged.setdefault(
            key,
            {"merge_key": key, "transports": [], "model": facts.get("ro.product.model"), "sdk": facts.get("ro.build.version.sdk")},
        )
        entry["transports"].append(row["serial"])
    return list(merged.values())


def health(
    adb_serial: str,
    *,
    package: str | None = None,
    adb: str | None = None,
    transport: Any = None,
    check_capture: bool = True,
) -> dict[str, Any]:
    """Composite readiness, not a single `get-state`.

    Every state is measured; a state that was not measured is reported as unknown rather than
    assumed true.
    """
    from . import capture as capture_service
    from . import device_ui

    states: dict[str, Any] = {name: None for name in HEALTH_STATES}
    detail: dict[str, Any] = {}
    metrics: dict[str, Any] = {}

    def run(args: list[str]) -> tuple[int, str]:
        if transport is not None:
            code, out, err = transport.run(adb_serial, args)
            return code, (out or "") + (err or "")
        from .. import toolchain

        exe = adb or toolchain.paths().get("adb") or "adb"
        try:
            proc = subprocess.run(
                [exe, "-s", adb_serial] + args,
                capture_output=True,
                text=True,
                timeout=30,
                errors="replace",
                env=toolchain.child_env(),
            )
            return proc.returncode, proc.stdout + proc.stderr
        except (FileNotFoundError, subprocess.TimeoutExpired) as exc:
            return 127, type(exc).__name__

    code, out = run(["get-state"])
    states["ADB_ONLINE"] = code == 0 and "device" in out

    code, out = run(["shell", "pm list packages"])
    states["PACKAGE_MANAGER_READY"] = code == 0 and "package:" in out
    if package and states["PACKAGE_MANAGER_READY"]:
        states["APP_INSTALLED"] = f"package:{package}" in out

    code, out = run(["shell", "wm size"])
    states["UI_READY"] = code == 0 and "x" in out.lower()

    code, out = run(["shell", "dumpsys window policy"])
    if code == 0:
        locked = "mShowingLockscreen=true" in out or "isStatusBarKeyguard=true" in out
        states["SCREEN_UNLOCKED"] = not locked
        awake = "mAwake=true" in out or "mScreenOn=true" in out
        detail["screen"] = {"locked": locked, "awake": awake}

    if package:
        code, out = run(["shell", "dumpsys activity activities"])
        if code == 0:
            resumed = ""
            for line in out.splitlines():
                if "mResumedActivity" in line or "topResumedActivity" in line:
                    resumed = line.strip()
                    break
            states["APP_FOREGROUND"] = f"{package}/" in resumed
            detail["resumed"] = resumed[:200]

    if check_capture:
        probe = capture_service.probe_proxy_pin()
        states["CAPTURE_READY"] = bool(probe.get("available"))
        detail["capture"] = probe

    code, out = run(["shell", "dumpsys battery"])
    if code == 0:
        for line in out.splitlines():
            line = line.strip()
            if line.startswith("level:"):
                metrics["battery_level"] = _to_int(line.split(":", 1)[1])
            elif line.startswith("temperature:"):
                raw_temp = _to_int(line.split(":", 1)[1])
                metrics["battery_temperature_c"] = round(raw_temp / 10, 1) if raw_temp is not None else None

    code, out = run(["shell", "df /data"])
    if code == 0:
        for line in out.splitlines()[1:]:
            parts = line.split()
            if len(parts) >= 4:
                metrics["data_free_bytes"] = _to_int(parts[3])
                break

    required = ["ADB_ONLINE", "PACKAGE_MANAGER_READY", "UI_READY"]
    if package:
        required += ["APP_INSTALLED"]
    blocked = [name for name in required if states.get(name) is False]
    return {
        "serial": adb_serial,
        "states": states,
        "detail": detail,
        "metrics": metrics,
        "required": required,
        "ready": not blocked,
        "blocked": blocked,
        "measured_at": utcnow(),
        "ui_backend": device_ui.driver_status(),
        "adb": adb,
    }


def _to_int(value: str) -> int | None:
    try:
        return int(str(value).strip())
    except (TypeError, ValueError):
        return None


def record_health(device_id: str, report: dict[str, Any]) -> None:
    db.execute(
        "UPDATE devices SET health = ?, last_seen = ? WHERE id = ?",
        ("ready" if report.get("ready") else "blocked", utcnow(), device_id),
    )
    audit.record(
        "device_health",
        project_id=None,
        actor="system",
        payload={
            "device_id": device_id,
            "ready": report.get("ready"),
            "blocked": report.get("blocked"),
            "states": {k: v for k, v in (report.get("states") or {}).items() if v is not None},
        },
    )


def quarantine(device_id: str, *, reason: str, actor: str = "system") -> Row:
    """Lock a device out of the pool without touching it. A human has to clear this."""
    db.execute("UPDATE devices SET health = ? WHERE id = ?", ("QUARANTINED", device_id))
    audit.record(
        "device_quarantined",
        project_id=None,
        actor=actor,
        payload={"device_id": device_id, "reason": reason[:400]},
    )
    return db.one("SELECT * FROM devices WHERE id = ?", (device_id,))


def clear_quarantine(device_id: str, *, actor: str = "human", note: str | None = None) -> Row:
    db.execute("UPDATE devices SET health = ?, last_seen = ? WHERE id = ?", ("idle", utcnow(), device_id))
    audit.record(
        "device_quarantine_cleared",
        project_id=None,
        actor=actor,
        payload={"device_id": device_id, "note": (note or "")[:400]},
    )
    return db.one("SELECT * FROM devices WHERE id = ?", (device_id,))


def quarantined() -> list[Row]:
    return db.query("SELECT * FROM devices WHERE health = ?", ("QUARANTINED",))
