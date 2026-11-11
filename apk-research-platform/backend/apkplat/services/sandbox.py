"""A deliberately small code executor for project-owned test scripts.

What this is: a host-side runner that (a) only accepts scripts that already live in the
project as artifacts, (b) refuses scripts whose source reaches for process, network or
filesystem escape hatches, (c) runs them in a fixed working directory with a scrubbed
environment, a wall-clock timeout and capped output, and (d) records every run as an
artifact pair plus an append-only `sandbox_runs` row.

What this is *not*: a kernel-enforced sandbox. On this Windows host there is no container
runtime, so network denial is cooperative (an import guard plus an in-process socket stub)
and filesystem isolation is "we only hand it a working directory". That is stated in the
run row (`isolation = "cooperative"`) and in the report; callers that need strong isolation
get `strong_isolation_unavailable` instead of a false promise.
"""
from __future__ import annotations

import ast
import json
import os
import subprocess
import sys
import threading
import time
from pathlib import Path
from typing import Any

from .. import audit, toolchain
from ..db import Row, db, utcnow
from ..util import dumps, new_id, project_root, sha256_bytes, sha256_file

MAX_STDOUT = 256 * 1024
MAX_STDERR = 256 * 1024
DEFAULT_TIMEOUT = 30
MAX_TIMEOUT = 120

# Imports that can reach outside the working directory or the machine.
BANNED_IMPORTS = {
    "socket",
    "ssl",
    "subprocess",
    "multiprocessing",
    "ctypes",
    "http",
    "urllib",
    "urllib2",
    "urllib3",
    "requests",
    "httpx",
    "ftplib",
    "telnetlib",
    "smtplib",
    "paramiko",
    "shutil",
    "winreg",
    "win32api",
    "win32con",
}

# Bare names that build or launch code at runtime. `eval("...")` never shows up as
# `builtins.eval` in the AST, so the qualified-name list above is not enough on its own.
BANNED_NAMES = {
    "eval",
    "exec",
    "compile",
    "__import__",
    "breakpoint",
}
BANNED_CALLS = {
    "os.system",
    "os.popen",
    "os.execv",
    "os.spawnv",
    "os.remove",
    "os.rmdir",
    "os.removedirs",
    "os.chmod",
    "os.chown",
    "shutil.rmtree",
    "shutil.move",
    "shutil.copy",
    "socket.socket",
    "builtins.eval",
}

RUNNER = r'''"""Sandbox runner: installs the policy guard, then executes the script as __main__."""
import os, runpy, sys

BASEDIR = os.path.realpath(os.getcwd())


def _inside(path):
    real = os.path.realpath(path if os.path.isabs(path) else os.path.join(BASEDIR, path))
    return real == BASEDIR or real.startswith(BASEDIR + os.sep)


def _guard(event, args):
    """Block writes and deletes that resolve outside the run directory.

    Reads stay allowed (the run needs the stdlib and the script itself). This is a
    cooperative boundary: it stops a script from quietly editing the project tree or the
    platform's storage, and the run is recorded either way.
    """
    if event == "open":
        path, mode = args[0], args[1]
        if isinstance(path, (str, bytes, os.PathLike)) and mode and any(ch in str(mode) for ch in "wax+"):
            if not _inside(os.fspath(path)):
                raise PermissionError("sandbox path escape blocked: %s" % (path,))
    elif event in ("os.remove", "os.rename", "os.rmdir", "os.mkdir", "os.chmod", "os.truncate"):
        for candidate in args[:2]:
            if isinstance(candidate, (str, bytes, os.PathLike)) and not _inside(os.fspath(candidate)):
                raise PermissionError("sandbox path escape blocked: %s" % (candidate,))


sys.addaudithook(_guard)

if os.environ.get("APKPLAT_SANDBOX_NETWORK") == "none":
    import socket

    class SandboxNetworkDenied(OSError):
        pass

    def _deny(*args, **kwargs):
        raise SandboxNetworkDenied("network access is denied by sandbox policy")

    socket.socket = _deny
    socket.create_connection = _deny
    socket.getaddrinfo = _deny
    socket.socketpair = _deny

target = sys.argv[1]
sys.argv = [target] + sys.argv[2:]
runpy.run_path(target, run_name="__main__")
'''


class SandboxError(Exception):
    def __init__(self, code: str, message: str, status: int = 422) -> None:
        super().__init__(message)
        self.code = code
        self.message = message
        self.status = status

    def as_error(self) -> dict[str, Any]:
        return {"error_code": self.code, "message": self.message}


def static_check(source: str) -> dict[str, Any]:
    """Refuse scripts that can obviously leave the sandbox, with line numbers."""
    findings: list[dict[str, Any]] = []
    try:
        tree = ast.parse(source)
    except SyntaxError as exc:
        return {"ok": False, "findings": [{"kind": "syntax_error", "line": exc.lineno or 0, "detail": str(exc)}]}
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                root = alias.name.split(".")[0]
                if root in BANNED_IMPORTS:
                    findings.append({"kind": "banned_import", "line": node.lineno, "detail": alias.name})
        elif isinstance(node, ast.ImportFrom):
            root = (node.module or "").split(".")[0]
            if root in BANNED_IMPORTS:
                findings.append({"kind": "banned_import", "line": node.lineno, "detail": node.module})
        elif isinstance(node, ast.Call):
            name = _call_name(node.func)
            if name in BANNED_CALLS or name in BANNED_NAMES:
                findings.append({"kind": "banned_call", "line": node.lineno, "detail": name})
    return {"ok": not findings, "findings": findings}


def _call_name(func: ast.AST) -> str:
    if isinstance(func, ast.Name):
        return func.id
    if isinstance(func, ast.Attribute):
        base = _call_name(func.value)
        return f"{base}.{func.attr}" if base else func.attr
    return ""


def _script_artifact(project_id: str, artifact_id: str) -> Row:
    artifact = db.one("SELECT * FROM artifacts WHERE id = ?", (artifact_id,))
    if artifact is None:
        raise SandboxError("script_not_found", f"artifact {artifact_id} does not exist", 404)
    if artifact["project_id"] != project_id:
        raise SandboxError("project_denied", "script belongs to another project", 403)
    return artifact


def artifact_path(artifact: Row) -> Path:
    from . import artifacts as artifacts_service

    return artifacts_service.path_of(artifact)


def run_script(
    project_id: str,
    *,
    script_artifact_id: str,
    argv: list[str] | None = None,
    task_id: str | None = None,
    run_id: str | None = None,
    timeout: int = DEFAULT_TIMEOUT,
    network: str = "none",
    isolation: str = "cooperative",
    max_output_bytes: int = MAX_STDOUT,
    replay_of: str | None = None,
    actor: str = "agent",
    env_extra: dict[str, str] | None = None,
) -> dict[str, Any]:
    if isolation not in ("cooperative", "container"):
        raise SandboxError("invalid_isolation", "isolation must be cooperative or container")
    if isolation == "container":
        # No container runtime on this host: say so instead of pretending.
        raise SandboxError(
            "strong_isolation_unavailable",
            "a container runtime is not available on this host; high-risk code must not run",
            409,
        )
    if network not in ("none", "allowlist"):
        raise SandboxError("invalid_network_policy", "network must be none or allowlist")
    timeout = max(1, min(int(timeout), MAX_TIMEOUT))

    artifact = _script_artifact(project_id, script_artifact_id)
    script_path = artifact_path(artifact)
    source = script_path.read_bytes().decode("utf-8", "replace")
    if not script_path.name.endswith(".py"):
        raise SandboxError("unsupported_script_type", "only .py scripts can run in the cooperative sandbox")
    check = static_check(source)
    if not check["ok"]:
        _record_refusal(project_id, artifact, task_id, run_id, check, actor, isolation, network)
        raise SandboxError(
            "static_check_failed",
            "script reaches outside the sandbox: " + ", ".join(f"{f['kind']}:{f['detail']}" for f in check["findings"][:5]),
            409,
        )

    run_key = new_id("sbx_")
    workdir = project_root(project_id) / "sandbox" / run_key
    workdir.mkdir(parents=True, exist_ok=True)
    runner_path = workdir / "_apkplat_runner.py"
    runner_path.write_text(RUNNER, encoding="utf-8")
    staged = workdir / "script.py"
    staged.write_bytes(script_path.read_bytes())

    env = toolchain.child_env()
    env.update({"APKPLAT_SANDBOX_NETWORK": network, "PYTHONUNBUFFERED": "1", "PYTHONDONTWRITEBYTECODE": "1"})
    env["HOME"] = str(workdir)
    env["TMP"] = str(workdir)
    env["TEMP"] = str(workdir)
    for key, value in (env_extra or {}).items():
        env[str(key)] = str(value)
    env_hash = sha256_bytes(dumps(sorted(env.items())).encode("utf-8"))

    command = [sys.executable, "-I", "-B", str(runner_path), str(staged), *(argv or [])]
    started = time.monotonic()
    timed_out = False
    with open(os.devnull, "wb"):
        proc = subprocess.Popen(
            command,
            cwd=str(workdir),
            env=env,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
        )
        try:
            out, err = proc.communicate(timeout=timeout)
        except subprocess.TimeoutExpired:
            timed_out = True
            _kill_tree(proc)
            out, err = proc.communicate()
    duration_ms = int((time.monotonic() - started) * 1000)
    out = (out or b"")[:max_output_bytes]
    err = (err or b"")[:max_output_bytes]

    out_path = workdir / "stdout.txt"
    err_path = workdir / "stderr.txt"
    out_path.write_bytes(out)
    err_path.write_bytes(err)

    from . import artifacts as artifacts_service

    stdout_art = artifacts_service.register(
        project_id,
        kind="tool_stdout",
        path=out_path,
        task_id=task_id,
        tool="sandbox",
        tool_version="p3",
        actor=actor,
    )
    stderr_art = artifacts_service.register(
        project_id,
        kind="tool_stderr",
        path=err_path,
        task_id=task_id,
        tool="sandbox",
        tool_version="p3",
        actor=actor,
    )
    summary_path = workdir / "result.json"
    summary = {
        "run_key": run_key,
        "command_template": "python -I -B _apkplat_runner.py script.py [args]",
        "isolation": isolation,
        "network": network,
        "timeout_seconds": timeout,
        "timed_out": timed_out,
        "exit_code": None if timed_out else proc.returncode,
        "duration_ms": duration_ms,
        "script_sha256": sha256_file(staged),
        "stdout_sha256": sha256_bytes(out),
        "stderr_sha256": sha256_bytes(err),
        "stdout_artifact_id": stdout_art["id"],
        "stderr_artifact_id": stderr_art["id"],
        "EXIT_CODE": None if timed_out else proc.returncode,
    }
    summary_path.write_text(json.dumps(summary, indent=2), encoding="utf-8")
    summary_art = artifacts_service.register(
        project_id,
        kind="test_result",
        path=summary_path,
        task_id=task_id,
        tool="sandbox",
        tool_version="p3",
        actor=actor,
    )

    status = "TIMEOUT" if timed_out else ("SUCCEEDED" if proc.returncode == 0 else "FAILED")
    run_row = {
        "id": run_key,
        "project_id": project_id,
        "task_id": task_id,
        "run_id": run_id,
        "script_artifact_id": artifact["id"],
        "script_sha256": summary["script_sha256"],
        "argv_json": dumps(list(argv or [])),
        "env_hash": env_hash,
        "command_template": summary["command_template"],
        "network_policy": network,
        "isolation": isolation,
        "limits_json": dumps({"timeout_seconds": timeout, "max_output_bytes": max_output_bytes}),
        "static_check_json": dumps(check),
        "status": status,
        "exit_code": None if timed_out else proc.returncode,
        "timed_out": int(timed_out),
        "duration_ms": duration_ms,
        "stdout_artifact_id": stdout_art["id"],
        "stderr_artifact_id": stderr_art["id"],
        "stdout_sha256": summary["stdout_sha256"],
        "stderr_sha256": summary["stderr_sha256"],
        "replay_of": replay_of,
        "error_code": "sandbox_timeout" if timed_out else None,
        "created_by": actor,
        "created_at": utcnow(),
    }
    with db.tx():
        db.execute(
            "INSERT INTO sandbox_runs(id, project_id, task_id, run_id, script_artifact_id, script_sha256,"
            " argv_json, env_hash, command_template, network_policy, isolation, limits_json, static_check_json,"
            " status, exit_code, timed_out, duration_ms, stdout_artifact_id, stderr_artifact_id, stdout_sha256,"
            " stderr_sha256, replay_of, error_code, created_by, created_at)"
            " VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
            tuple(run_row.values()),
        )
    audit.record(
        "sandbox_run",
        project_id=project_id,
        task_id=task_id,
        actor=actor,
        payload={
            "sandbox_run_id": run_key,
            "status": status,
            "exit_code": run_row["exit_code"],
            "timed_out": timed_out,
            "network": network,
            "isolation": isolation,
            "replay_of": replay_of,
        },
    )
    result = dict(run_row)
    result["result_artifact_id"] = summary_art["id"]
    result["summary"] = summary
    return result


def _record_refusal(
    project_id: str,
    artifact: Row,
    task_id: str | None,
    run_id: str | None,
    check: dict[str, Any],
    actor: str,
    isolation: str,
    network: str,
) -> None:
    run_key = new_id("sbx_")
    with db.tx():
        db.execute(
            "INSERT INTO sandbox_runs(id, project_id, task_id, run_id, script_artifact_id, script_sha256,"
            " argv_json, env_hash, command_template, network_policy, isolation, limits_json, static_check_json,"
            " status, exit_code, timed_out, duration_ms, stdout_artifact_id, stderr_artifact_id, stdout_sha256,"
            " stderr_sha256, replay_of, error_code, created_by, created_at)"
            " VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (
                run_key,
                project_id,
                task_id,
                run_id,
                artifact["id"],
                artifact["sha256"],
                "[]",
                "",
                "refused",
                network,
                isolation,
                "{}",
                dumps(check),
                "REFUSED",
                None,
                0,
                0,
                None,
                None,
                None,
                None,
                None,
                "static_check_failed",
                actor,
                utcnow(),
            ),
        )
    audit.record(
        "sandbox_refused",
        project_id=project_id,
        task_id=task_id,
        actor=actor,
        payload={"sandbox_run_id": run_key, "findings": check.get("findings", [])[:8]},
    )


def _kill_tree(proc: subprocess.Popen) -> None:
    if proc.poll() is not None:
        return
    try:
        subprocess.run(
            ["taskkill", "/PID", str(proc.pid), "/T", "/F"],
            capture_output=True,
            timeout=15,
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
        )
    except Exception:  # noqa: BLE001
        proc.kill()


def get(run_id: str) -> dict[str, Any] | None:
    row = db.one("SELECT * FROM sandbox_runs WHERE id = ?", (run_id,))
    if row is None:
        return None
    data = dict(row)
    data["argv"] = json.loads(data.pop("argv_json") or "[]")
    data["limits"] = json.loads(data.pop("limits_json") or "{}")
    data["static_check"] = json.loads(data.pop("static_check_json") or "{}")
    data["timed_out"] = bool(data["timed_out"])
    return data


def listing(project_id: str, *, task_id: str | None = None, limit: int = 200) -> list[dict[str, Any]]:
    sql = "SELECT id FROM sandbox_runs WHERE project_id = ?"
    params: list[Any] = [project_id]
    if task_id:
        sql += " AND task_id = ?"
        params.append(task_id)
    sql += " ORDER BY created_at DESC LIMIT ?"
    params.append(limit)
    return [get(row["id"]) for row in db.query(sql, params) if row]


def replay(project_id: str, run_id: str, *, actor: str = "reviewer", run_ref: str | None = None) -> dict[str, Any]:
    """Re-run a recorded script. Refuses when the original run's side effects are unknown."""
    original = get(run_id)
    if original is None:
        raise SandboxError("sandbox_run_not_found", f"{run_id} does not exist", 404)
    if original["project_id"] != project_id:
        raise SandboxError("project_denied", "sandbox run belongs to another project", 403)
    if original["network_policy"] != "none":
        raise SandboxError(
            "side_effect_risk",
            "the original run was allowed network access; automatic replay is refused",
            409,
        )
    return run_script(
        project_id,
        script_artifact_id=original["script_artifact_id"],
        argv=original["argv"],
        task_id=original.get("task_id"),
        run_id=run_ref or original.get("run_id"),
        timeout=int(original["limits"].get("timeout_seconds") or DEFAULT_TIMEOUT),
        network="none",
        isolation="cooperative",
        replay_of=run_id,
        actor=actor,
    )
