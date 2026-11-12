"""Dynamic stage (P4): run an APK on a pooled device, one device at a time.

The rules the taskbook cares about are enforced here, not in a worker's memory:

* a device is leased before use and released in a ``finally`` block, so a crash or
  an unplug can never hand the same serial to two tasks;
* a lost device is a *safe* failure: the run stops, the lease is released, the
  task is marked FAILED with ``device_lost`` and nothing else keeps running;
* cleanup (force-stop, uninstall, delete the app's scratch dir) is attempted even
  when the device disappears, and the attempt is recorded. "No residue" is a claim
  the audit trail can check, not a promise.

The transport is pluggable so the same code path can be exercised on a host with
no phone attached: ``adb`` talks to a real device, ``sim`` answers deterministically
and can be told to drop the cable at a chosen step.
"""
from __future__ import annotations

import base64
import json
import subprocess
import time
from pathlib import Path
from typing import Any, Callable, Protocol

from . import audit, toolchain
from .config import settings
from .db import utcnow
from .services import artifacts as artifacts_service
from .services import device_ui as ui_module
from .services import devices as devices_service
from .services import evidence as evidence_service
from .services import projects as projects_service
from .services import queue as queue_service
from .services import tasks as tasks_service
from .util import dumps, project_layout

TOOL_VERSION = "1.0.0"
REMOTE_SCRATCH = "/sdcard/apkplat"
DEVICE_LOSS_MARKERS = (
    "device offline",
    "device not found",
    "no devices/emulators found",
    "no devices found",
    "error: closed",
    "device unauthorized",
    "cannot connect to",
    "more than one device",
)


class DeviceLost(RuntimeError):
    """The device stopped answering mid-run (cable pulled, adb killed, emulator down)."""


class DynamicError(RuntimeError):
    def __init__(self, code: str, message: str, *, retryable: bool = False, detail: dict | None = None) -> None:
        super().__init__(message)
        self.code = code
        self.message = message
        self.retryable = retryable
        self.detail = detail or {}


# --------------------------------------------------------------------------- transports
class Transport(Protocol):
    name: str

    def run(self, serial: str | None, args: list[str], *, timeout: int | None = None) -> tuple[int, str, str]:
        ...


class AdbTransport:
    """Real adb. Every call is bounded and loss is detected from the output."""

    name = "adb"

    def __init__(self, adb: str | None = None) -> None:
        self.adb = adb or str(toolchain.paths()["adb"])

    def run(self, serial: str | None, args: list[str], *, timeout: int | None = None) -> tuple[int, str, str]:
        cmd = [self.adb] + (["-s", serial] if serial else []) + list(args)
        creation = getattr(subprocess, "CREATE_NO_WINDOW", 0)
        try:
            proc = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                errors="replace",
                timeout=timeout or settings.dynamic_step_timeout,
                env=toolchain.child_env(),
                creationflags=creation,
            )
        except subprocess.TimeoutExpired as exc:
            raise DynamicError(
                "dynamic_timeout", f"adb {' '.join(args)} exceeded {timeout or settings.dynamic_step_timeout}s", retryable=True
            ) from exc
        except FileNotFoundError as exc:
            raise DynamicError("tool_missing", f"adb not found at {self.adb}", retryable=False) from exc
        out = proc.stdout or ""
        err = proc.stderr or ""
        if proc.returncode != 0:
            blob = f"{out}\n{err}".lower()
            if any(marker in blob for marker in DEVICE_LOSS_MARKERS):
                raise DeviceLost(f"adb {' '.join(args)}: {err.strip() or out.strip()}"[:500])
        return proc.returncode, out, err


class SimTransport:
    """A deterministic stand-in device.

    It models just enough Android surface for the harness to be honest: package install/remove
    state, screen lock, battery and storage. ``unplug_at`` pulls the cable when the joined argv
    contains that token, which is how the "device lost" paths are exercised.
    """

    name = "sim"

    def __init__(
        self,
        *,
        unplug_at: str | None = None,
        authorized: bool = True,
        package: str = "com.example.reef",
        preinstalled: tuple[str, ...] = ("com.android.settings",),
        screen_locked: bool = False,
        battery_level: int = 76,
    ) -> None:
        self.calls: list[list[str]] = []
        self.unplug_at = unplug_at
        self.authorized = authorized
        self.package = package
        self.installed: set[str] = set(preinstalled)
        self.screen_locked = screen_locked
        self.battery_level = battery_level
        self.foreground = "com.android.launcher3"

    def run(self, serial: str | None, args: list[str], *, timeout: int | None = None):
        self.calls.append(list(args))
        if args[:1] == ["shell"]:
            # adb accepts both `shell pm list packages` and the single-argument
            # `shell "pm list packages"` form; normalise so both hit the same branch.
            args = ["shell"] + " ".join(args[1:]).split()
        joined = " ".join(args)
        if self.unplug_at and self.unplug_at in joined:
            raise DeviceLost(f"simulated cable pull before `{joined}`")
        if not self.authorized:
            return 1, "", "error: device unauthorized"
        if args[:1] == ["get-state"]:
            return 0, "device\n", ""
        if args[:2] == ["shell", "getprop"]:
            prop = args[2]
            table = {
                "ro.product.model": "Pixel 6 (sim)",
                "ro.product.manufacturer": "Google",
                "ro.build.version.release": "13",
                "ro.build.version.sdk": "33",
                "ro.serialno": serial or "emulator-sim",
            }
            return 0, table.get(prop, "") + "\n", ""
        if args[0] == "install":
            self.installed.add(self.package)
            return 0, "Performing Streamed Install\nSuccess\n", ""
        if args[:4] == ["shell", "pm", "list", "packages"]:
            wanted = args[4] if len(args) > 4 else ""
            rows = [f"package:{pkg}" for pkg in sorted(self.installed) if not wanted or pkg == wanted]
            return 0, "\n".join(rows) + ("\n" if rows else ""), ""
        if args[:3] == ["shell", "pm", "uninstall"]:
            self.installed.discard(args[3])
            return 0, "Success\n", ""
        if args[:3] == ["shell", "am", "start"]:
            self.foreground = self.package
            return 0, "Starting: Intent { cmp=com.example.reef/.MainActivity }\n", ""
        if args[:2] == ["shell", "logcat"]:
            return 0, "\n".join(
                [
                    "11-10 19:30:01.101  1201  1201 I ActivityManager: Start proc com.example.reef",
                    "11-10 19:30:01.220  2233  2233 D ReefMain: onCreate",
                    "11-10 19:30:01.340  2233  2240 I ReefSync: token request queued",
                    "11-10 19:30:01.480  2233  2240 W ReefNet : plaintext fallback for https://api.example-reef.test/v1",
                ]
            ) + "\n", ""
        if args[:2] == ["shell", "screencap"]:
            return 0, "", ""
        if args[0] == "pull":
            return 0, "1 file pulled, 0 files skipped.\n", ""
        if args[:3] == ["shell", "wm", "size"]:
            return 0, "Physical size: 1080x2340\n", ""
        if args[:3] == ["shell", "dumpsys", "window"]:
            parked = "true" if self.screen_locked else "false"
            return 0, f"mShowingLockscreen={parked}\nmScreenOn=true\n", ""
        if args[:3] == ["shell", "dumpsys", "activity"]:
            return 0, f"  mResumedActivity: ActivityRecord{{9f2a u0 {self.foreground}/.MainActivity t42}}\n", ""
        if args[:3] == ["shell", "dumpsys", "power"]:
            return 0, "mWakefulness=Awake\nmScreenOn=true\n", ""
        if args[:3] == ["shell", "dumpsys", "battery"]:
            return 0, f"  level: {self.battery_level}\n  temperature: 291\n", ""
        if args[:1] == ["exec-out"] and "screencap" in " ".join(args[1:]):
            return 0, SIM_PNG, b""
        if args[:3] == ["shell", "uiautomator", "dump"]:
            return 0, "UI hierchary dumped to: /data/local/tmp/apkplat_ui.xml\n", ""
        if args[:3] == ["shell", "cat", REMOTE_UI_XML]:
            return 0, SIM_HIERARCHY, ""
        if args[:3] == ["shell", "input", "tap"]:
            return 0, "", ""
        if args[:3] == ["shell", "input", "keyevent"]:
            self.screen_locked = False
            return 0, "", ""
        if args[:2] == ["shell", "df"]:
            return 0, "Filesystem     1K-blocks     Used Available Use% Mounted on\n/dev/block/dm-4 115343360 45000000  70343360  39% /data\n", ""
        if args[:2] == ["shell", "am"] and "force-stop" in args:
            self.foreground = "com.android.launcher3"
            return 0, "", ""
        if args[:3] == ["shell", "rm", "-rf"]:
            return 0, "", ""
        if args[:3] == ["shell", "ls", REMOTE_SCRATCH]:
            return 1, "", f"ls: {REMOTE_SCRATCH}: No such file or directory\n"
        return 0, "", ""

REMOTE_UI_XML = "/data/local/tmp/apkplat_ui.xml"

# A real 1x1 PNG so the simulator can hand back screenshot bytes instead of an empty stream.
SIM_PNG = base64.b64decode(
    "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mP8z8BQDwAEhQGAhKmMIQAAAABJRU5ErkJggg=="
)

SIM_HIERARCHY = """<?xml version='1.0' encoding='UTF-8' standalone='yes' ?>
<hierarchy rotation="0">
  <node index="0" text="" resource-id="" class="android.widget.FrameLayout" package="com.example.reef" content-desc="" clickable="false" enabled="true" bounds="[0,0][1080,2340]">
    <node index="0" text="Allow Reef to send notifications?" resource-id="com.android.permissioncontroller:id/permission_message" class="android.widget.TextView" package="com.android.permissioncontroller" content-desc="" clickable="false" enabled="true" bounds="[60,900][1020,1010]" />
    <node index="1" text="Allow" resource-id="com.android.permissioncontroller:id/permission_allow_button" class="android.widget.Button" package="com.android.permissioncontroller" content-desc="" clickable="true" enabled="true" bounds="[560,1030][1020,1130]" />
    <node index="2" text="Don&#39;t allow" resource-id="com.android.permissioncontroller:id/permission_deny_button" class="android.widget.Button" package="com.android.permissioncontroller" content-desc="" clickable="true" enabled="true" bounds="[60,1030][520,1130]" />
  </node>
</hierarchy>
"""

CLEANUP_MODES = ("EPHEMERAL", "PRESERVE_APP", "PRESERVE_SESSION", "QUARANTINE")

CLEANUP_ACTIONS = ("stop_app", "uninstall_app", "clear_scratch", "quarantine")


def cleanup_plan(
    mode: str,
    *,
    package: str,
    installed_by_us: bool,
    scratch: str = REMOTE_SCRATCH,
) -> list[dict[str, Any]]:
    """What a cleanup mode is allowed to do, as data - the executor only runs `allowed` rows.

    This replaces the old unconditional `finally: force-stop; uninstall; delete scratch`. The
    matrix is the taskbook's 6.4 table, and a mode that is not listed refuses to run at all.
    """
    if mode not in CLEANUP_MODES:
        raise DynamicError("unknown_cleanup_mode", f"cleanup mode must be one of {CLEANUP_MODES}", retryable=False)
    plan: list[dict[str, Any]] = []
    if mode == "EPHEMERAL":
        plan.append({"action": "stop_app", "allowed": True, "argv": ["shell", "am", "force-stop", package]})
        plan.append(
            {
                "action": "uninstall_app",
                "allowed": bool(installed_by_us),
                "argv": ["shell", "pm", "uninstall", package],
                "skip_reason": None if installed_by_us else "package existed before this run; not ours to remove",
            }
        )
        plan.append({"action": "clear_scratch", "allowed": True, "argv": ["shell", "rm", "-rf", scratch]})
    elif mode == "PRESERVE_APP":
        plan.append({"action": "stop_app", "allowed": True, "argv": ["shell", "am", "force-stop", package]})
        plan.append(
            {"action": "uninstall_app", "allowed": False, "argv": ["shell", "pm", "uninstall", package],
             "skip_reason": "PRESERVE_APP keeps the installation and its data"}
        )
        plan.append({"action": "clear_scratch", "allowed": True, "argv": ["shell", "rm", "-rf", scratch]})
    elif mode == "PRESERVE_SESSION":
        plan.append(
            {"action": "stop_app", "allowed": False, "argv": ["shell", "am", "force-stop", package],
             "skip_reason": "PRESERVE_SESSION must not force-stop the app"}
        )
        plan.append(
            {"action": "uninstall_app", "allowed": False, "argv": ["shell", "pm", "uninstall", package],
             "skip_reason": "PRESERVE_SESSION must not uninstall the app"}
        )
        plan.append({"action": "clear_scratch", "allowed": True, "argv": ["shell", "rm", "-rf", scratch],
                     "note": "worker scratch only; app data and login state stay"})
    else:  # QUARANTINE
        plan.append({"action": "quarantine", "allowed": True, "argv": [],
                     "note": "leave the device untouched and lock it for a human"})
        for action, argv, why in (
            ("stop_app", ["shell", "am", "force-stop", package], "QUARANTINE performs no destructive cleanup"),
            ("uninstall_app", ["shell", "pm", "uninstall", package], "QUARANTINE performs no destructive cleanup"),
            ("clear_scratch", ["shell", "rm", "-rf", scratch], "QUARANTINE leaves the device state untouched"),
        ):
            plan.append({"action": action, "allowed": False, "argv": argv, "skip_reason": why})
    return plan


def make_transport(name: str | None = None, **kwargs: Any) -> Transport:
    kind = (name or settings.dynamic_transport or "adb").lower()
    if kind == "sim":
        return SimTransport(**kwargs)
    if kind == "adb":
        return AdbTransport()
    raise DynamicError("unknown_transport", f"transport {kind!r} is neither 'adb' nor 'sim'")


# --------------------------------------------------------------------------- helpers
def _log_sink(log: Callable[[str], None] | None) -> Callable[[str], None]:
    return log or (lambda message: print(f"[dynamic] {message}", flush=True))


def _append(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8", newline="\n") as handle:
        handle.write(text if text.endswith("\n") else text + "\n")


def _set_task(task_id: str | None, status: str, *, actor: str = "agent:dynamic", fields: dict | None = None,
              reason: str | None = None) -> None:
    if not task_id:
        return
    task = tasks_service.get(task_id)
    if not task:
        return
    try:
        tasks_service.update(task_id, actor=actor, status=status, fields=fields, reason=reason)
    except Exception as exc:  # noqa: BLE001  (a task in an unexpected state must not abort the run)
        audit.record(
            "task_update_skipped",
            task_id=task_id,
            actor=actor,
            payload={"target": status, "reason": f"{type(exc).__name__}: {exc}"[:400]},
        )


def _evidence(project_id: str, *, kind: str, locator: dict, excerpt: str, claim: str,
              artifact_id: str | None, task_id: str | None, confidence: str = "high") -> str:
    row = evidence_service.record(
        project_id,
        kind=kind,
        locator=locator,
        excerpt=excerpt,
        artifact_id=artifact_id,
        task_id=task_id,
        claim=claim,
        confidence=confidence,
        created_by="agent:dynamic",
    )
    return row["id"] if isinstance(row, dict) else row["id"]


def _register(project_id: str, kind: str, path: Path, *, task_id: str | None, tool: str) -> str:
    row = artifacts_service.register(
        project_id,
        kind=kind,
        path=path,
        task_id=task_id,
        tool=tool,
        tool_version=TOOL_VERSION,
        actor="agent:dynamic",
    )
    return row["id"] if isinstance(row, dict) else row["id"]


# --------------------------------------------------------------------------- stage
def run_task(
    project_id: str,
    *,
    task_id: str | None = None,
    worker_id: str = "dynamic-worker",
    transport_name: str | None = None,
    device_id: str | None = None,
    transport: Transport | None = None,
    log: Callable[[str], None] | None = None,
    observe_seconds: int | None = None,
    cleanup_mode: str = "PRESERVE_APP",
    health_gate: bool = True,
    check: Callable[[], None] | None = None,
) -> dict[str, Any]:
    say = _log_sink(log)
    project = projects_service.get(project_id)
    if not project:
        raise DynamicError("project_missing", f"project {project_id} does not exist", retryable=True)
    apk = projects_service.apk_path(project_id)
    if not apk.is_file():
        raise DynamicError("apk_missing", f"{apk.name} is not on disk", retryable=False)
    manifest = projects_service.manifest(project_id)
    package = manifest.get("package") or ""
    activity = manifest.get("main_activity") or (f"{package}.MainActivity" if package else "")

    layout = project_layout(project_id)
    transcript = layout["logs"] / "dynamic.log"
    started = time.time()
    started_at = utcnow()

    _set_task(task_id, "RUNNING", reason="dynamic stage started")
    move = transport or make_transport(transport_name)

    try:
        lease = devices_service.acquire(project_id, task_id=task_id, owner=worker_id, device_id=device_id)
    except devices_service.LeaseConflict as exc:
        say(f"no device available: {exc}")
        audit.record(
            "device_wait",
            project_id=project_id,
            task_id=task_id,
            actor=worker_id,
            payload={"reason": str(exc)[:400]},
        )
        _set_task(
            task_id,
            "WAITING_DEVICE",
            actor="system",
            fields={"error_code": "device_unavailable", "error_message": str(exc)[:500], "retryable": True},
            reason="waiting for a free device",
        )
        raise DynamicError("device_unavailable", str(exc), retryable=True) from exc

    device = devices_service.get(lease["device_id"])
    serial = device["adb_serial"] if device else None
    say(f"leased device {serial} (lease {lease['id']})")

    if health_gate and serial:
        report = devices_service.health(serial, package=None, transport=move)
        devices_service.record_health(lease["device_id"], report)
        if not report.get("ready"):
            say(f"device health gate failed: {report.get('blocked')}")
            audit.record(
                "device_health_blocked",
                project_id=project_id,
                task_id=task_id,
                actor=worker_id,
                payload={"lease_id": lease["id"], "serial": serial, "blocked": report.get("blocked"),
                         "states": {k: v for k, v in (report.get("states") or {}).items() if v is not None}},
            )
            _set_task(
                task_id,
                "WAITING_DEVICE",
                actor="system",
                fields={"error_code": "device_not_ready", "error_message": ",".join(report.get("blocked") or []),
                        "retryable": True},
                reason="device health gate",
            )
            devices_service.release(lease["id"], owner=worker_id, reason="device_not_ready")
            raise DynamicError("device_not_ready", f"blocked states: {report.get('blocked')}", retryable=True)
    audit.record(
        "dynamic_started",
        project_id=project_id,
        task_id=task_id,
        actor=worker_id,
        payload={"lease_id": lease["id"], "serial": serial, "transport": move.name, "package": package},
    )

    evidence_ids: list[str] = []
    artifact_ids: list[str] = []
    steps: list[dict] = []
    pre_installed = False
    installed_by_us = False
    cleanup: dict[str, Any] = {"attempted": False, "verified": False, "reason": None}

    def step(name: str, fn: Callable[[], dict]) -> dict:
        # Cooperative cancellation: only between steps, never mid-command - a half-finished
        # install would leave the device in a state the cleanup step does not model.
        if check is not None:
            check()
        devices_service.heartbeat(lease["id"], owner=worker_id)
        began = time.time()
        detail = fn()
        detail.setdefault("step", name)
        detail["duration_ms"] = int((time.time() - began) * 1000)
        steps.append(detail)
        _append(
            transcript,
            json.dumps({"step": name, "ok": True, "duration_ms": detail["duration_ms"]}, ensure_ascii=False),
        )
        say(f"step {name} ok in {detail['duration_ms']}ms")
        return detail

    ctx: dict[str, Any] = {
        "project_id": project_id,
        "task_id": task_id,
        "layout": layout,
        "serial": serial,
        "package": package,
        "activity": activity,
        "transport": move,
        "apk": apk,
        "evidence_ids": evidence_ids,
        "artifact_ids": artifact_ids,
    }

    def do_probe() -> dict:
        props = {}
        for prop in ("ro.product.model", "ro.product.manufacturer", "ro.build.version.release", "ro.build.version.sdk"):
            code, out, err = move.run(serial, ["shell", "getprop", prop])
            props[prop.split(".")[-1]] = (out.strip() or err.strip()) if code == 0 else ""
        facts = {
            "serial": serial,
            "transport": move.name,
            "model": props["model"],
            "manufacturer": props["manufacturer"],
            "android_release": props["release"],
            "sdk": props["sdk"],
            "probed_at": utcnow(),
        }
        path = layout["artifacts"] / "device.json"
        path.write_text(json.dumps(facts, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
        artifact_ids.append(_register(project_id, "device_probe", path, task_id=task_id, tool=f"adb:{move.name}"))
        excerpt = "\n".join(line for line in path.read_text(encoding="utf-8").splitlines() if '"' in line).strip()
        evidence_ids.append(
            _evidence(
                project_id,
                kind="device_fact",
                locator={"artifact": str(path.relative_to(layout["base"])), "field": "model", "serial": serial},
                excerpt=excerpt,
                claim=f"Device {facts['model']} on Android {facts['android_release']} (SDK {facts['sdk']}), serial {serial}",
                artifact_id=artifact_ids[-1],
                task_id=task_id,
            )
        )
        ctx["device"] = facts
        return {"device": facts}

    def do_install() -> dict:
        nonlocal pre_installed, installed_by_us
        code, listing, _ = move.run(serial, ["shell", "pm", "list", "packages", package])
        pre_installed = f"package:{package}" in (listing or "")
        code, out, err = move.run(serial, ["install", "-r", "-g", str(apk)], timeout=max(120, settings.dynamic_step_timeout))
        text = (out + err).strip()
        path = layout["artifacts"] / "install.txt"
        path.write_text(f"$ adb -s {serial} install -r -g {apk.name}\nexit={code}\n{text}\n", encoding="utf-8")
        artifact_ids.append(_register(project_id, "device_install", path, task_id=task_id, tool=f"adb:{move.name}"))
        if code != 0 or "Success" not in text:
            raise DynamicError("install_failed", text[:500] or "adb install failed", retryable=False)
        installed_by_us = not pre_installed
        evidence_ids.append(
            _evidence(
                project_id,
                kind="install_result",
                locator={"artifact": str(path.relative_to(layout["base"])), "package": package, "serial": serial},
                excerpt=path.read_text(encoding="utf-8").strip(),
                claim=f"Installed {package} on {serial}: {text.splitlines()[-1]}",
                artifact_id=artifact_ids[-1],
                task_id=task_id,
            )
        )
        return {
            "package": package,
            "install_verdict": text.splitlines()[-1],
            "pre_installed": pre_installed,
            "installed_by_us": installed_by_us,
        }

    def do_launch() -> dict:
        if not activity:
            raise DynamicError("no_launcher_activity", "manifest has no launcher activity", retryable=False)
        code, out, err = move.run(serial, ["shell", "am", "start", "-W", "-n", f"{package}/{activity}"])
        text = (out + err).strip()
        path = layout["artifacts"] / "launch.txt"
        path.write_text(f"$ adb shell am start -W -n {package}/{activity}\nexit={code}\n{text}\n", encoding="utf-8")
        artifact_ids.append(_register(project_id, "device_launch", path, task_id=task_id, tool=f"adb:{move.name}"))
        if code != 0:
            raise DynamicError("launch_failed", text[:500], retryable=False)
        evidence_ids.append(
            _evidence(
                project_id,
                kind="launch_result",
                locator={"artifact": str(path.relative_to(layout["base"])), "activity": activity},
                excerpt=path.read_text(encoding="utf-8").strip(),
                claim=f"Launched {package}/{activity} ({text.splitlines()[0][:120]})",
                artifact_id=artifact_ids[-1],
                task_id=task_id,
            )
        )
        return {"activity": activity, "launch_verdict": text.splitlines()[0][:200]}

    def do_observe() -> dict:
        wait = settings.dynamic_observe_seconds if observe_seconds is None else observe_seconds
        if wait:
            time.sleep(wait)
        code, out, err = move.run(serial, ["shell", "logcat", "-d", "-t", str(settings.dynamic_max_tail)])
        text = out or err
        path = layout["artifacts"] / "logcat.txt"
        path.write_text(text, encoding="utf-8")
        artifact_ids.append(_register(project_id, "device_logcat", path, task_id=task_id, tool=f"adb:{move.name}"))
        lines = [line for line in text.splitlines() if line.strip()]
        keys = [line for line in lines if package and package in line][:5] or lines[:5]
        excerpt = "\n".join(keys).strip()
        if excerpt:
            evidence_ids.append(
                _evidence(
                    project_id,
                    kind="runtime_log",
                    locator={"artifact": str(path.relative_to(layout["base"])), "lines": len(lines)},
                    excerpt=excerpt,
                    claim=f"Runtime log from {package}: {len(lines)} lines captured; first matching line: {keys[0][:160] if keys else 'n/a'}",
                    artifact_id=artifact_ids[-1],
                    task_id=task_id,
                    confidence="medium",
                )
            )
        return {"log_lines": len(lines), "package_lines": len([l for l in lines if package and package in l])}

    def do_screenshot() -> dict:
        remote = f"{REMOTE_SCRATCH}/screen.png"
        local = layout["artifacts"] / "screenshot.png"
        move.run(serial, ["shell", "mkdir", "-p", REMOTE_SCRATCH])
        code, out, err = move.run(serial, ["shell", "screencap", "-p", remote])
        if code != 0:
            raise DynamicError("screencap_failed", (out + err)[:400], retryable=False)
        code, out, err = move.run(serial, ["pull", remote, str(local)])
        if code != 0 or not local.is_file():
            # A screenshot is nice-to-have; the run's evidence does not depend on it.
            return {"screenshot": None, "skipped": f"pull exit {code}: {(out + err)[:200]}"}
        artifact_ids.append(_register(project_id, "device_screenshot", local, task_id=task_id, tool=f"adb:{move.name}"))
        return {"screenshot": str(local.relative_to(layout["base"])), "bytes": local.stat().st_size}

    def run_cleanup(*, device_alive: bool) -> dict:
        """Execute only what the cleanup policy allows, and log every command separately."""
        cleanup["attempted"] = True
        layout["artifacts"].mkdir(parents=True, exist_ok=True)
        path = layout["artifacts"] / "cleanup.json"
        record: dict[str, Any] = {
            "serial": serial,
            "package": package,
            "mode": cleanup_mode,
            "device_alive": device_alive,
            "pre_installed": pre_installed,
            "installed_by_us": installed_by_us,
            "actions": [],
            "verified": False,
        }
        plan = cleanup_plan(cleanup_mode, package=package, installed_by_us=installed_by_us)
        for entry in plan:
            action = entry["action"]
            row: dict[str, Any] = {"action": action, "allowed": entry["allowed"], "argv": entry.get("argv")}
            if not entry["allowed"]:
                row["skipped"] = entry.get("skip_reason") or "not permitted by policy"
                record["actions"].append(row)
                continue
            if action == "quarantine":
                devices_service.quarantine(
                    lease["device_id"],
                    reason=f"dynamic run {task_id or project_id} needs a human",
                    actor=worker_id,
                )
                row["quarantined"] = True
                record["quarantined"] = True
                record["actions"].append(row)
                continue
            if not device_alive:
                row["skipped"] = "device unreachable; deferred to the device pool"
                record["actions"].append(row)
                continue
            try:
                code, out, err = move.run(serial, entry["argv"])
            except DeviceLost as exc:
                row["note"] = f"device lost: {exc}"[:200]
                record["device_alive"] = False
                record["actions"].append(row)
                break
            except DynamicError as exc:
                row["note"] = exc.code
                record["actions"].append(row)
                break
            row.update({"exit": code, "output": (out + err).strip()[:200]})
            record["actions"].append(row)

        if device_alive and not record.get("quarantined"):
            checks: dict[str, bool] = {}
            code, listing, _ = move.run(serial, ["shell", "pm", "list", "packages", package])
            present = f"package:{package}" in (listing or "")
            if cleanup_mode == "EPHEMERAL" and installed_by_us:
                checks["app_uninstalled"] = not present
            else:
                checks["app_preserved"] = present
            code, listing, _ = move.run(serial, ["shell", "ls", REMOTE_SCRATCH])
            checks["scratch_removed"] = code != 0
            record["verification"] = checks
            record["verified"] = bool(checks) and all(checks.values())
        elif record.get("quarantined"):
            record["verification"] = {"device_untouched": True}
            record["verified"] = True
        else:
            record["reason"] = "device unreachable; cleanup deferred to the device pool"
            record["verified"] = False

        path.write_text(json.dumps(record, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
        artifact_ids.append(_register(project_id, "device_cleanup", path, task_id=task_id, tool=f"adb:{move.name}"))
        cleanup.update(
            {
                "mode": cleanup_mode,
                "verified": record["verified"],
                "reason": record.get("reason"),
                "artifact": str(path.relative_to(layout["base"])),
            }
        )
        audit.record(
            "dynamic_cleanup_verified" if record["verified"] else "dynamic_cleanup_incomplete",
            project_id=project_id,
            task_id=task_id,
            actor=worker_id,
            payload={
                "lease_id": lease["id"],
                "mode": cleanup_mode,
                "verified": record["verified"],
                "reason": record.get("reason"),
                "actions": [
                    {"action": item["action"], "allowed": item["allowed"], "exit": item.get("exit")}
                    for item in record["actions"]
                ],
            },
        )
        return record

    failure: DynamicError | None = None
    def do_ui() -> dict:
        """Drive the UI: dump the hierarchy, settle system dialogs, keep before/after shots."""
        driver = ui_module.AdbUi(serial, transport=move, timeout=max(30, settings.dynamic_step_timeout))
        before = layout["artifacts"] / "ui-before.png"
        shot_before = driver.screenshot(before)
        nodes, digest = driver.hierarchy()
        dialogs = driver.dialogs(nodes)
        handled: list[dict] = []
        for dialog in (dialogs.get("dialogs") or [])[:3]:
            node = ui_module.pick(
                nodes,
                resource_id=dialog.get("allow_resource_id"),
                text="Allow" if dialog.get("kind") == "permission" else None,
            )
            if node is not None:
                handled.append({"kind": dialog.get("kind"), "action": "tap", "node": node.text or node.resource_id})
                driver.tap_node(node)
                nodes, digest = driver.hierarchy()
        after = layout["artifacts"] / "ui-after.png"
        shot_after = driver.screenshot(after)
        screen = driver.screen_state()
        facts = {
            "serial": serial,
            "ui_backend": driver.backend,
            "nodes": len(nodes),
            "hierarchy_sha256": digest,
            "dialogs": dialogs,
            "handled": handled,
            "screen": screen,
            "foreground": driver.current_package(),
            "screenshots": {"before": shot_before, "after": shot_after},
            "actions": driver.actions,
            "measured_at": utcnow(),
        }
        path = layout["artifacts"] / "ui.json"
        path.write_text(json.dumps(facts, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
        ui_artifact = _register(project_id, "device_ui", path, task_id=task_id, tool=f"ui:{driver.backend}")
        artifact_ids.append(ui_artifact)
        for shot, name in ((before, "ui_before"), (after, "ui_after")):
            if shot.is_file() and shot.stat().st_size > 0:
                artifact_ids.append(_register(project_id, name, shot, task_id=task_id, tool=f"ui:{driver.backend}"))
        # The excerpt must be a contiguous slice of the artifact: evidence verification compares
        # the stored excerpt with the raw bytes, so a re-joined subset would never match.
        excerpt = path.read_text(encoding="utf-8").strip()[:3000]
        evidence_ids.append(
            _evidence(
                project_id,
                kind="ui_state",
                locator={"artifact": str(path.relative_to(layout["base"])), "serial": serial,
                         "hierarchy_sha256": digest},
                excerpt=excerpt,
                claim=(
                    f"UI on {serial}: {len(nodes)} nodes, foreground {facts['foreground'] or 'unknown'}, "
                    f"dialogs={dialogs.get('count', 0)}, handled={len(handled)}"
                ),
                artifact_id=ui_artifact,
                task_id=task_id,
            )
        )
        return {"nodes": len(nodes), "hierarchy_sha256": digest, "dialogs": dialogs.get("count", 0),
                "handled": len(handled), "foreground": facts["foreground"], "ui_backend": driver.backend}

    try:
        step("probe", do_probe)
        step("install", do_install)
        step("launch", do_launch)
        step("ui", do_ui)
        step("observe", do_observe)
        step("screenshot", do_screenshot)
    except DeviceLost as exc:
        say(f"device lost: {exc}")
        audit.record(
            "device_lost",
            project_id=project_id,
            task_id=task_id,
            actor=worker_id,
            payload={"lease_id": lease["id"], "serial": serial, "message": str(exc)[:400], "steps_done": len(steps)},
        )
        failure = DynamicError("device_lost", str(exc), retryable=False)
    except DynamicError as exc:
        say(f"dynamic stage failed: {exc.code}: {exc.message}")
        failure = exc
    finally:
        try:
            run_cleanup(device_alive=failure is None or failure.code != "device_lost")
        except DynamicError as exc:  # cleanup problems never mask the real failure
            audit.record(
                "dynamic_cleanup_error",
                project_id=project_id,
                task_id=task_id,
                actor=worker_id,
                payload={"code": exc.code, "message": exc.message[:400]},
            )
        finally:
            devices_service.release(lease["id"], owner=worker_id, reason="failed" if failure else "completed")

    duration_ms = int((time.time() - started) * 1000)
    if failure is not None:
        audit.record(
            "dynamic_failed",
            project_id=project_id,
            task_id=task_id,
            actor=worker_id,
            payload={
                "code": failure.code,
                "message": failure.message[:400],
                "retryable": failure.retryable,
                "duration_ms": duration_ms,
                "cleanup_verified": cleanup["verified"],
            },
        )
        _set_task(
            task_id,
            "RETRYING" if failure.retryable else "FAILED",
            actor="system",
            fields={
                "error_code": failure.code,
                "error_message": failure.message[:1000],
                "retryable": failure.retryable,
            },
            reason=f"dynamic stage failed: {failure.code}",
        )
        raise failure

    _set_task(task_id, "REVIEW", actor="system", reason="dynamic session finished; awaiting review")
    audit.record(
        "dynamic_completed",
        project_id=project_id,
        task_id=task_id,
        actor=worker_id,
        payload={
            "lease_id": lease["id"],
            "serial": serial,
            "steps": [item["step"] for item in steps],
            "evidence_rows": len(evidence_ids),
            "cleanup_verified": cleanup["verified"],
            "duration_ms": duration_ms,
        },
    )
    if task_id:
        tasks_service.incr_counters(task_id, evidence=len(evidence_ids), tool_calls=len(steps))

    return {
        "project_id": project_id,
        "task_id": task_id,
        "started_at": started_at,
        "duration_ms": duration_ms,
        "device": ctx.get("device", {}),
        "steps": steps,
        "evidence_ids": evidence_ids,
        "artifact_ids": artifact_ids,
        "cleanup": cleanup,
        "package": package,
    }


def enqueue(
    project_id: str,
    *,
    task_id: str | None = None,
    transport_name: str | None = None,
    device_id: str | None = None,
    idempotency_key: str | None = None,
) -> str:
    """Queue a dynamic session as a durable job (outbox, survives restarts)."""
    return queue_service.enqueue(
        "dynamic_analysis",
        project_id=project_id,
        task_id=task_id,
        payload={"project_id": project_id, "transport": transport_name, "device_id": device_id},
        idempotency_key=idempotency_key or f"dynamic:{project_id}:{task_id or 'default'}",
    )
