"""Restricted execution of external tooling (jadx, apktool, aapt2, java).

Rules this module enforces for *every* child process:

* argv list only, never a shell string — no quoting bugs, no command injection;
* cwd pinned inside the project directory (callers pass the project root, and it
  is verified here);
* a hard wall-clock timeout, after which the whole process tree is killed;
* output goes straight to files (no pipes to deadlock), then is capped;
* the child sees a whitelisted environment: no DSH_*, no API keys, no tokens.

Every invocation is returned as a ``RunResult`` so the caller can turn stdout and
stderr into artifacts with hashes instead of trusting prose.
"""
from __future__ import annotations

import os
import shutil
import subprocess
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Sequence

from .config import settings

CREATE_NO_WINDOW = 0x08000000
CREATE_NEW_PROCESS_GROUP = 0x00000200

ENV_ALLOW = (
    "SystemRoot",
    "SystemDrive",
    "windir",
    "TEMP",
    "TMP",
    "PATHEXT",
    "COMSPEC",
    "NUMBER_OF_PROCESSORS",
    "PROCESSOR_ARCHITECTURE",
    "LOCALAPPDATA",
    "USERPROFILE",
    "HOMEDRIVE",
    "HOMEPATH",
)
ENV_DROP_PATTERN = ("DSH_", "KEY", "SECRET", "TOKEN", "PASSWORD")


class ToolError(RuntimeError):
    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code
        self.message = message


# ---------------------------------------------------------------------------
# declarative policy (config/worker-policy.yml)
# ---------------------------------------------------------------------------
_POLICY_CACHE: dict | None = None

DEFAULT_POLICY: dict = {
    "version": 1,
    "allowed_executables": ["java.exe", "aapt2.exe", "adb.exe", "node.exe"],
    "max_timeout_seconds": 900,
    "max_output_bytes": 16 * 1024 * 1024,
    "environ_allow": list(ENV_ALLOW),
    "environ_drop_patterns": list(ENV_DROP_PATTERN),
    "cwd_root": "storage",
}


def policy_path() -> Path:
    return settings.root / "config" / "worker-policy.yml"


def policy(refresh: bool = False) -> dict:
    """Load the worker policy, falling back to the built-in defaults.

    A missing or unreadable policy file is not fatal — the defaults are the same
    restrictions — but a malformed one is reported through ``policy_error`` so the
    health endpoint can surface it.
    """
    global _POLICY_CACHE
    if _POLICY_CACHE is not None and not refresh:
        return _POLICY_CACHE
    data = dict(DEFAULT_POLICY)
    error = None
    path = policy_path()
    if path.exists():
        try:
            import yaml

            loaded = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
            if isinstance(loaded, dict):
                for key in DEFAULT_POLICY:
                    if key in loaded and loaded[key] is not None:
                        data[key] = loaded[key]
            else:
                error = "policy root is not a mapping"
        except Exception as exc:  # noqa: BLE001
            error = f"{type(exc).__name__}: {exc}"
    data["policy_path"] = str(path)
    data["policy_loaded"] = path.exists() and error is None
    data["policy_error"] = error
    _POLICY_CACHE = data
    return data


def check_executable(command: Sequence[str]) -> None:
    """Refuse to launch anything the policy does not list."""
    if not command:  # pragma: no cover - defensive
        raise ToolError("empty_command", "no executable in argv")
    name = Path(str(command[0])).name.lower()
    allowed = {str(item).lower() for item in policy().get("allowed_executables") or []}
    if allowed and name not in allowed:
        raise ToolError(
            "tool_not_allowed",
            f"{name} is not in config/worker-policy.yml allowed_executables",
        )


@dataclass
class RunResult:
    command: list[str]
    exit_code: int
    duration_ms: int
    timed_out: bool
    stdout_path: Path
    stderr_path: Path
    stdout_bytes: int
    stderr_bytes: int
    truncated: bool = False
    error_code: str | None = None
    error_message: str | None = None
    extra: dict = field(default_factory=dict)

    @property
    def ok(self) -> bool:
        return self.exit_code == 0 and not self.timed_out


# ---------------------------------------------------------------------------
# layout / environment
# ---------------------------------------------------------------------------
def tool_root() -> Path:
    return settings.tools


def paths() -> dict[str, Path]:
    root = tool_root()
    return {
        "node": root / "node" / "node.exe",
        "java": root / "jdk" / "bin" / "java.exe",
        "jadx": root / "jadx" / "bin" / "jadx.bat",
        "jadx_lib": root / "jadx" / "lib",
        "apktool": root / "apktool" / "apktool.jar",
        "apktool_bat": root / "apktool" / "apktool.bat",
        "aapt2": root / "android-sdk" / "build-tools" / "34.0.0" / "aapt2.exe",
        "adb": root / "android-sdk" / "platform-tools" / "adb.exe",
        "android_sdk": root / "android-sdk",
    }


def child_env(extra: dict[str, str] | None = None) -> dict[str, str]:
    rules = policy()
    allow = [str(name) for name in (rules.get("environ_allow") or ENV_ALLOW)]
    drop = tuple(str(p).upper() for p in (rules.get("environ_drop_patterns") or ENV_DROP_PATTERN))
    env: dict[str, str] = {}
    for name in allow:
        value = os.environ.get(name)
        if value:
            env[name] = value
    p = paths()
    env["JAVA_HOME"] = str(tool_root() / "jdk")
    env["ANDROID_HOME"] = str(p["android_sdk"])
    env["ANDROID_SDK_ROOT"] = str(p["android_sdk"])
    env["PATH"] = os.pathsep.join(
        [str(tool_root() / "jdk" / "bin"), str(p["android_sdk"] / "platform-tools"), str(tool_root() / "node")]
    )
    env.setdefault("TEMP", str(settings.storage / "tmp"))
    env.setdefault("TMP", env["TEMP"])
    Path(env["TEMP"]).mkdir(parents=True, exist_ok=True)
    for key, value in (extra or {}).items():
        if any(token in key.upper() for token in drop):
            continue
        env[key] = value
    return env


def _kill_tree(pid: int) -> None:
    if os.name == "nt":
        subprocess.run(["taskkill", "/PID", str(pid), "/T", "/F"], capture_output=True, check=False)
    else:  # pragma: no cover
        import signal

        try:
            os.killpg(pid, signal.SIGKILL)
        except Exception:  # noqa: BLE001
            pass


def run(
    command: Sequence[str],
    *,
    cwd: Path,
    stdout_path: Path,
    stderr_path: Path,
    timeout: int,
    env_extra: dict[str, str] | None = None,
    max_output_bytes: int = 16 * 1024 * 1024,
) -> RunResult:
    exe = Path(command[0])
    check_executable(command)
    if exe.is_absolute() and not exe.exists():
        raise ToolError("tool_missing", f"executable not found: {exe}")
    rules = policy()
    ceiling = int(rules.get("max_timeout_seconds") or 0)
    if ceiling:
        timeout = min(int(timeout), ceiling)
    max_output_bytes = min(int(max_output_bytes), int(rules.get("max_output_bytes") or max_output_bytes))
    if not str(cwd.resolve()).startswith(str(settings.storage.resolve())):
        raise ToolError("cwd_outside_storage", f"refusing to run a tool with cwd={cwd} outside storage")
    cwd.mkdir(parents=True, exist_ok=True)
    stdout_path.parent.mkdir(parents=True, exist_ok=True)
    stderr_path.parent.mkdir(parents=True, exist_ok=True)
    started = time.perf_counter()
    timed_out = False
    with open(stdout_path, "wb") as out, open(stderr_path, "wb") as err:
        proc = subprocess.Popen(
            [str(c) for c in command],
            cwd=str(cwd),
            env=child_env(env_extra),
            stdin=subprocess.DEVNULL,
            stdout=out,
            stderr=err,
            creationflags=(CREATE_NO_WINDOW | CREATE_NEW_PROCESS_GROUP) if os.name == "nt" else 0,
            start_new_session=os.name != "nt",
        )
        try:
            proc.wait(timeout=timeout)
        except subprocess.TimeoutExpired:
            timed_out = True
            _kill_tree(proc.pid)
            try:
                proc.wait(timeout=15)
            except subprocess.TimeoutExpired:  # pragma: no cover
                pass
    duration_ms = int((time.perf_counter() - started) * 1000)
    truncated = False
    for path in (stdout_path, stderr_path):
        if path.exists() and path.stat().st_size > max_output_bytes:
            with open(path, "rb") as fh:
                head = fh.read(max_output_bytes)
            path.write_bytes(head + b"\n... [truncated by apkplat output cap]\n")
            truncated = True
    exit_code = proc.returncode if proc.returncode is not None else -9
    return RunResult(
        command=[str(c) for c in command],
        exit_code=exit_code,
        duration_ms=duration_ms,
        timed_out=timed_out,
        stdout_path=stdout_path,
        stderr_path=stderr_path,
        stdout_bytes=stdout_path.stat().st_size if stdout_path.exists() else 0,
        stderr_bytes=stderr_path.stat().st_size if stderr_path.exists() else 0,
        truncated=truncated,
        error_code="timeout" if timed_out else None,
        error_message=f"killed after {timeout}s" if timed_out else None,
    )


# ---------------------------------------------------------------------------
# tool wrappers
# ---------------------------------------------------------------------------
def _jadx_entrypoint() -> tuple[str, str]:
    """Return (classpath, main-class) for the bundled jadx.

    jadx renamed its CLI entry point over time: 1.4.x used ``jadx.cli.JADXMain``,
    1.5.x ships ``jadx.cli.JadxCLI``. Probe the jar instead of guessing, and prefer
    the single fat jar when it exists (no classpath wildcard involved).
    """
    p = paths()
    lib = p["jadx_lib"]
    probe_dir = settings.storage / "tmp"
    probe_dir.mkdir(parents=True, exist_ok=True)
    fat = sorted(lib.glob("jadx-*-all.jar"))
    candidates = ["jadx.cli.JadxCLI", "jadx.cli.JADXMain"]
    if fat:
        jar = fat[-1]
        for entry in candidates:
            probe = run(
                [str(p["java"]), "-cp", str(jar), entry, "--version"],
                cwd=settings.storage,
                stdout_path=settings.storage / "tmp" / "jadx-probe.out",
                stderr_path=settings.storage / "tmp" / "jadx-probe.err",
                timeout=60,
            )
            if probe.exit_code == 0:
                return str(jar), entry
    return str(lib) + os.sep + "*", "jadx.cli.JadxCLI"


def jadx_command(apk: Path, out_dir: Path, *, threads: int = 2, deobf: bool = False) -> list[str]:
    p = paths()
    classpath, entry = _jadx_entrypoint()
    cmd = [
        str(p["java"]),
        settings.jadx_heap,
        "-XX:+UseSerialGC",
        "-Dfile.encoding=UTF-8",
        "-cp",
        classpath,
        entry,
        "--no-res",
        "--threads-count",
        str(max(1, threads)),
        "--output-dir",
        str(out_dir),
    ]
    if deobf:
        cmd.append("--deobf")
    cmd.append(str(apk))
    return cmd


def jadx_decompile(apk: Path, out_dir: Path, log_dir: Path, *, timeout: int | None = None, threads: int = 2) -> RunResult:
    return run(
        jadx_command(apk, out_dir, threads=threads),
        cwd=log_dir,
        stdout_path=log_dir / "jadx.stdout.log",
        stderr_path=log_dir / "jadx.stderr.log",
        timeout=timeout or settings.jadx_timeout,
        max_output_bytes=4 * 1024 * 1024,
    )


def apktool_command(apk: Path, out_dir: Path, *, no_src: bool = False, force: bool = True) -> list[str]:
    p = paths()
    cmd = [str(p["java"]), "-Xmx768m", "-Dfile.encoding=UTF-8", "-jar", str(p["apktool"]), "decode", str(apk), "-o", str(out_dir)]
    if force:
        cmd.append("-f")
    if no_src:
        cmd.append("--no-src")
    return cmd


def apktool_decode(apk: Path, out_dir: Path, log_dir: Path, *, timeout: int | None = None, no_src: bool = False) -> RunResult:
    return run(
        apktool_command(apk, out_dir, no_src=no_src),
        cwd=log_dir,
        stdout_path=log_dir / "apktool.stdout.log",
        stderr_path=log_dir / "apktool.stderr.log",
        timeout=timeout or settings.apktool_timeout,
        max_output_bytes=4 * 1024 * 1024,
    )


def aapt2_dump(apk: Path, what: str, log_dir: Path, *, timeout: int = 180) -> RunResult:
    p = paths()
    if not p["aapt2"].exists():
        raise ToolError("tool_missing", f"aapt2 not found at {p['aapt2']}")
    safe = what if what in {"badging", "permissions", "configurations", "packagename", "strings", "resources"} else "badging"
    return run(
        [str(p["aapt2"]), "dump", safe, str(apk)],
        cwd=log_dir,
        stdout_path=log_dir / f"aapt2.{safe}.stdout.txt",
        stderr_path=log_dir / f"aapt2.{safe}.stderr.txt",
        timeout=timeout,
    )


def adb_command(*args: str) -> list[str]:
    return [str(paths()["adb"]), *args]


def probe_versions() -> dict[str, dict]:
    """Version probes used by the health endpoint and the P0 report."""
    out: dict[str, dict] = {}
    jadx_cp, jadx_entry = _jadx_entrypoint()
    checks = {
        "java": [str(paths()["java"]), "-version"],
        "jadx": [str(paths()["java"]), "-cp", jadx_cp, jadx_entry, "--version"],
        "apktool": [str(paths()["java"]), "-jar", str(paths()["apktool"]), "--version"],
        "aapt2": [str(paths()["aapt2"]), "version"],
    }
    for name, cmd in checks.items():
        exe = Path(cmd[0])
        if not exe.exists():
            out[name] = {"ok": False, "error": "not_installed", "path": str(exe)}
            continue
        try:
            proc = subprocess.run(cmd, capture_output=True, text=True, timeout=120, errors="replace", env=child_env())
            text = (proc.stdout or "") + (proc.stderr or "")
            out[name] = {"ok": proc.returncode == 0, "version": _first_line(text), "path": str(exe)}
        except Exception as exc:  # noqa: BLE001
            out[name] = {"ok": False, "error": str(exc), "path": str(exe)}
    adb = paths()["adb"]
    out["adb"] = {"ok": adb.exists(), "path": str(adb) if adb.exists() else (shutil.which("adb") or None)}
    return out


def _first_line(text: str) -> str:
    for line in text.splitlines():
        line = line.strip()
        if line:
            return line[:200]
    return ""
