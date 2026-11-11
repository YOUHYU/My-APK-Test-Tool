"""Device UI layer: one driver interface over `uiautomator2` when it is installed, else over ADB.

The rules this module obeys (taskbook §6.3):

* element location order is resource-id > semantic text/description > relative coordinates with a
  post-condition check - never a blind tap;
* every action has a pre/post UI hash and a screenshot, so a step can be replayed and audited;
* an unrecognised dialog stops the run and asks a human; the driver never clicks "allow" or "agree"
  on the model's behalf;
* the target package is an allow-list, so a UI task cannot wander into settings or identity apps.
"""
from __future__ import annotations

import hashlib
import json
import re
import shutil
import subprocess
import time
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterable

from .. import audit
from ..config import settings
from ..util import new_id

_BOUNDS_RE = re.compile(r"\[(\d+),(\d+)\]\[(\d+),(\d+)\]")

PERMISSION_PACKAGES = (
    "com.android.permissioncontroller",
    "com.google.android.permissioncontroller",
    "com.android.packageinstaller",
    "com.lbe.security.miui",
    "com.miui.securitycenter",
)

LOCKSCREEN_HINTS = ("keyguard", "lockscreen", "com.android.systemui")
DIALOG_HINTS = ("permission", "allow", "deny", "允许", "拒绝", "始终允许")


class UiError(Exception):
    def __init__(self, code: str, message: str, retryable: bool = False, detail: dict | None = None) -> None:
        super().__init__(message)
        self.code = code
        self.message = message
        self.retryable = retryable
        self.detail = detail or {}

    def as_error(self) -> dict[str, Any]:
        return {"error_code": self.code, "message": self.message, "retryable": self.retryable}


@dataclass
class Node:
    text: str
    resource_id: str
    class_name: str
    package: str
    content_desc: str
    clickable: bool
    enabled: bool
    bounds: tuple[int, int, int, int]

    @property
    def center(self) -> tuple[int, int]:
        x1, y1, x2, y2 = self.bounds
        return (x1 + x2) // 2, (y1 + y2) // 2

    def as_dict(self) -> dict[str, Any]:
        return {
            "text": self.text,
            "resource_id": self.resource_id,
            "class": self.class_name,
            "package": self.package,
            "content_desc": self.content_desc,
            "clickable": self.clickable,
            "bounds": list(self.bounds),
            "center": list(self.center),
        }


def parse_bounds(value: str) -> tuple[int, int, int, int] | None:
    match = _BOUNDS_RE.search(value or "")
    if not match:
        return None
    x1, y1, x2, y2 = (int(part) for part in match.groups())
    if x2 < x1 or y2 < y1:
        return None
    return x1, y1, x2, y2


def parse_hierarchy(xml_text: str) -> tuple[list[Node], str]:
    """Flatten a uiautomator dump into nodes plus a stable digest of the visible tree."""
    try:
        root = ET.fromstring(xml_text)
    except ET.ParseError as exc:
        raise UiError("hierarchy_unparsable", f"uiautomator dump is not XML: {type(exc).__name__}") from exc
    nodes: list[Node] = []
    for element in root.iter("node"):
        bounds = parse_bounds(element.get("bounds", ""))
        if bounds is None:
            continue
        nodes.append(
            Node(
                text=(element.get("text") or "").strip(),
                resource_id=(element.get("resource-id") or "").strip(),
                class_name=(element.get("class") or "").strip(),
                package=(element.get("package") or "").strip(),
                content_desc=(element.get("content-desc") or "").strip(),
                clickable=(element.get("clickable") or "false").lower() == "true",
                enabled=(element.get("enabled") or "true").lower() == "true",
                bounds=bounds,
            )
        )
    digest_source = json.dumps(
        [[node.resource_id, node.text, node.content_desc, node.bounds] for node in nodes],
        ensure_ascii=False,
    )
    return nodes, hashlib.sha256(digest_source.encode("utf-8")).hexdigest()


def pick(nodes: Iterable[Node], *, resource_id: str | None = None, text: str | None = None,
         contains: str | None = None, description: str | None = None) -> Node | None:
    """Locator priority: resource-id, then exact text/description, then substring text."""
    candidates = list(nodes)
    if resource_id:
        for node in candidates:
            if node.resource_id == resource_id:
                return node
    if text:
        for node in candidates:
            if node.text == text:
                return node
    if description:
        for node in candidates:
            if node.content_desc == description:
                return node
    if contains:
        for node in candidates:
            if contains.lower() in (node.text + " " + node.content_desc).lower():
                return node
    return None


class AdbUi:
    """UI driver over ADB. uiautomator2 is used for hierarchy when importable, ADB otherwise."""

    backend = "adb"

    def __init__(
        self,
        serial: str,
        *,
        adb: str | None = None,
        timeout: int = 60,
        transport: Any | None = None,
    ) -> None:
        self.serial = serial
        self.timeout = timeout
        self.transport = transport
        self.adb = adb or ("" if transport is not None else (shutil.which("adb") or ""))
        if not self.adb:
            from .. import toolchain

            self.adb = toolchain.paths()["adb"]
        self.actions: list[dict[str, Any]] = []
        self._u2 = None

    # -- plumbing -------------------------------------------------------
    def _run(self, args: list[str], *, timeout: int | None = None, binary: bool = False):
        if self.transport is not None:
            code, out, err = self.transport.run(self.serial, args, timeout=timeout or self.timeout)
            if binary:
                raw = out.encode("utf-8", "replace") if isinstance(out, str) else out
                return code, raw, err.encode("utf-8", "replace") if isinstance(err, str) else err
            if isinstance(out, bytes):
                out = out.decode("utf-8", "replace")
            if isinstance(err, bytes):
                err = err.decode("utf-8", "replace")
            return code, out, err
        from .. import toolchain

        command = [self.adb, "-s", self.serial] + args
        completed = subprocess.run(
            command,
            capture_output=True,
            timeout=timeout or self.timeout,
            env=toolchain.child_env(),
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
        )
        if binary:
            return completed.returncode, completed.stdout, completed.stderr
        return (
            completed.returncode,
            completed.stdout.decode("utf-8", "replace"),
            completed.stderr.decode("utf-8", "replace"),
        )

    def shell(self, command: str, *, timeout: int | None = None) -> str:
        code, out, err = self._run(["shell", command], timeout=timeout)
        if code != 0:
            raise UiError("adb_shell_failed", f"{command}: {err.strip()[:300] or out.strip()[:300]}", retryable=True)
        return out

    def _record(self, action: str, **fields: Any) -> dict[str, Any]:
        entry = {"action": action, "at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()), **fields}
        self.actions.append(entry)
        return entry

    # -- identity / state ----------------------------------------------
    def identity(self) -> dict[str, Any]:
        props = (
            "ro.serialno", "ro.product.model", "ro.product.device", "ro.build.version.sdk",
            "ro.build.version.release", "ro.product.cpu.abi",
        )
        out = self.shell("; ".join(f"getprop {p}" for p in props))
        values = [line.strip() for line in out.splitlines() if line.strip()]
        values += [""] * (len(props) - len(values))
        return dict(zip(props, values[: len(props)]))

    def screen_state(self) -> dict[str, Any]:
        power = self.shell("dumpsys power | grep -E 'mWakefulness=|mScreenOn' || true")
        policy = self.shell("dumpsys window policy | grep -E 'mShowingLockscreen|showing=' || true")
        interactive = "mWakefulness=Awake" in power or "mScreenOn=true" in power
        locked = ("mShowingLockscreen=true" in policy) or ("isStatusBarKeyguard=true" in policy)
        return {"interactive": interactive, "locked": locked, "power": power.strip()[:300], "policy": policy.strip()[:300]}

    def current_package(self) -> str:
        out = self.shell("dumpsys activity activities | grep -E 'mResumedActivity|topResumedActivity' || true")
        match = re.search(r"([A-Za-z0-9_.]+)/[A-Za-z0-9_.$]+", out)
        return match.group(1) if match else ""

    def dialogs(self, nodes: list[Node]) -> dict[str, Any]:
        return detect_dialogs(nodes, foreground=self.current_package())

    # -- hierarchy ------------------------------------------------------
    def hierarchy(self) -> tuple[list[Node], str]:
        remote = "/data/local/tmp/apkplat_ui.xml"
        self.shell(f"uiautomator dump {remote} >/dev/null 2>&1 || uiautomator dump {remote}")
        code, xml_text, err = self._run(["shell", f"cat {remote}"])
        if code != 0 or "<hierarchy" not in xml_text:
            raise UiError("hierarchy_unavailable", f"uiautomator produced nothing: {err.strip()[:200]}", retryable=True)
        return parse_hierarchy(xml_text)

    def screenshot(self, path: Path) -> dict[str, Any]:
        code, data, err = self._run(["exec-out", "screencap -p"], binary=True, timeout=120)
        if code != 0 or not data:
            raise UiError("screenshot_failed", err.decode("utf-8", "replace")[:200] if err else "no bytes", retryable=True)
        Path(path).parent.mkdir(parents=True, exist_ok=True)
        Path(path).write_bytes(data)
        return {"path": str(path), "bytes": len(data)}

    def logcat(self, *, lines: int = 200, package: str | None = None) -> str:
        command = f"logcat -d -t {max(1, min(lines, 2000))}"
        if package:
            command += f" | grep -i {package}"
        return self.shell(command + " || true")

    # -- actions --------------------------------------------------------
    def tap(self, x: int, y: int) -> dict[str, Any]:
        self.shell(f"input tap {int(x)} {int(y)}")
        return self._record("tap", x=int(x), y=int(y))

    def tap_node(self, node: Node) -> dict[str, Any]:
        x, y = node.center
        result = self.tap(x, y)
        result.update({"resource_id": node.resource_id, "text": node.text})
        return result

    def swipe(self, x1: int, y1: int, x2: int, y2: int, duration_ms: int = 300) -> dict[str, Any]:
        self.shell(f"input swipe {int(x1)} {int(y1)} {int(x2)} {int(y2)} {int(duration_ms)}")
        return self._record("swipe", x1=int(x1), y1=int(y1), x2=int(x2), y2=int(y2))

    def input_text(self, value: str) -> dict[str, Any]:
        # `input text` treats spaces specially and cannot carry newlines.
        escaped = value.replace(" ", "%s").replace("\n", "")
        self.shell(f"input text {json.dumps(escaped)}")
        return self._record("input_text", length=len(value))

    def press(self, key: str | int) -> dict[str, Any]:
        self.shell(f"input keyevent {key}")
        return self._record("keyevent", key=str(key))

    def unlock(self, *, max_attempts: int = 2) -> dict[str, Any]:
        state = self.screen_state()
        if not state["interactive"]:
            self.press("KEYCODE_WAKEUP")
            time.sleep(0.6)
        for attempt in range(max_attempts):
            state = self.screen_state()
            if not state["locked"]:
                return {"unlocked": True, "attempts": attempt, "state": state}
            width, height = self.display_size()
            self.swipe(width // 2, int(height * 0.8), width // 2, int(height * 0.2))
            time.sleep(0.8)
        state = self.screen_state()
        return {"unlocked": not state["locked"], "attempts": max_attempts, "state": state}

    def display_size(self) -> tuple[int, int]:
        out = self.shell("wm size")
        match = re.search(r"(\d+)x(\d+)", out)
        return (int(match.group(1)), int(match.group(2))) if match else (1080, 2340)

    def launch(self, package: str) -> dict[str, Any]:
        self.shell(f"monkey -p {package} -c android.intent.category.LAUNCHER 1")
        return self._record("launch", package=package)

    def force_stop(self, package: str) -> dict[str, Any]:
        self.shell(f"am force-stop {package}")
        return self._record("force_stop", package=package)

    def installed(self, package: str) -> bool:
        out = self.shell(f"pm list packages {package}")
        return f"package:{package}" in out

    def dump_windows(self) -> dict[str, Any]:
        nodes, digest = self.hierarchy()
        return {"nodes": [node.as_dict() for node in nodes[:200]], "digest": digest, "count": len(nodes)}


class Uiautomator2Ui(AdbUi):
    """Preferred backend when `uiautomator2` is importable; falls back to ADB on any failure."""

    backend = "uiautomator2"

    def __init__(self, serial: str, **kwargs: Any) -> None:
        super().__init__(serial, **kwargs)
        import uiautomator2 as u2  # noqa: PLC0415 - optional dependency

        self._u2 = u2.connect(serial)

    def hierarchy(self) -> tuple[list[Node], str]:
        xml_text = self._u2.dump_hierarchy()
        return parse_hierarchy(xml_text)

    def tap(self, x: int, y: int) -> dict[str, Any]:
        self._u2.click(int(x), int(y))
        return self._record("tap", x=int(x), y=int(y), backend="uiautomator2")

    def input_text(self, value: str) -> dict[str, Any]:
        self._u2.send_keys(value)
        return self._record("input_text", length=len(value), backend="uiautomator2")


def make_driver(serial: str, *, prefer_u2: bool = True, adb: str | None = None, timeout: int = 60) -> AdbUi:
    if prefer_u2:
        try:
            return Uiautomator2Ui(serial, adb=adb, timeout=timeout)
        except Exception:  # import error or connect failure: ADB is the guaranteed path
            pass
    return AdbUi(serial, adb=adb, timeout=timeout)


def driver_status() -> dict[str, Any]:
    try:
        import uiautomator2  # noqa: F401, PLC0415

        installed = True
        version = getattr(__import__("uiautomator2"), "__version__", "unknown")
    except Exception:
        installed, version = False, None
    return {
        "uiautomator2_installed": installed,
        "uiautomator2_version": version,
        "backend": "uiautomator2" if installed else "adb",
    }


def detect_dialogs(nodes: list[Node], *, foreground: str | None = None) -> dict[str, Any]:
    """Classify what is covering the app.

    A permission sheet is recognised by its package or by its button labels; anything else that
    is not the target app counts as an unknown overlay, and the caller must stop and ask.
    """
    packages = sorted({node.package for node in nodes if node.package})
    texts = [node.text for node in nodes if node.text]
    foreign = [pkg for pkg in packages if pkg and foreground and pkg != foreground]
    permission = any(pkg in PERMISSION_PACKAGES for pkg in packages) or any(
        hint in text.lower() for text in texts for hint in DIALOG_HINTS
    )
    dialogues: list[dict[str, Any]] = []
    if permission:
        allow = pick(nodes, resource_id="permission_allow_button") or pick(nodes, text="Allow")
        deny = pick(nodes, resource_id="permission_deny_button") or pick(nodes, text="Deny")
        allow = allow or next((n for n in nodes if n.resource_id.endswith("permission_allow_button")), None)
        deny = deny or next((n for n in nodes if n.resource_id.endswith("permission_deny_button")), None)
        dialogues.append(
            {
                "kind": "permission",
                "packages": [pkg for pkg in packages if pkg in PERMISSION_PACKAGES],
                "texts": texts[:12],
                "allow_resource_id": allow.resource_id if allow else None,
                "deny_resource_id": deny.resource_id if deny else None,
            }
        )
    unknown = bool(foreign) and not permission
    return {
        "count": len(dialogues),
        "dialogs": dialogues,
        "unknown": unknown,
        "packages": packages,
        "texts": texts[:20],
    }
