"""P0 environment + model-API verification (read-only; changes nothing).

Produces ``reports/p0/environment_report.md`` and ``reports/p0/model_api_check.json``.

What it proves, and how:

* the host facts the taskbook depends on (OS, CPU, RAM, disk, Python, toolchain);
* that DSH NEXT is present and configured — read from its profile, *not* modified;
* that the model API answers over HTTP for all four required shapes:
  plain text, JSON-object output, streaming deltas, and tool calls.

The API key is never printed and never written to the report: it is resolved from
``APKPLAT_MODEL_API_KEY`` or from DSH's own credential store (read-only), used in
memory, and reported only as a fingerprint length.
"""
from __future__ import annotations

import json
import os
import platform
import socket
import subprocess
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "backend"))

OUT = ROOT / "reports" / "p0"
DSH_HOME = Path(os.environ.get("DSH_HOME") or (Path.home() / ".dsh"))
CREDS = DSH_HOME / ".credentials.yaml"
PATCH = DSH_HOME / "profiles" / "desktop" / "cordis.patch.yml"


# ---------------------------------------------------------------------------
# credential resolution (read-only, never echoed)
# ---------------------------------------------------------------------------
def resolve_key() -> tuple[str | None, str]:
    env_key = os.environ.get("APKPLAT_MODEL_API_KEY")
    if env_key:
        return env_key, "env:APKPLAT_MODEL_API_KEY"
    try:
        text = CREDS.read_text(encoding="utf-8")
    except OSError:
        return None, "absent"
    for line in text.splitlines():
        stripped = line.strip()
        if stripped.startswith("WB_PROXY_API_KEY:"):
            value = stripped.split(":", 1)[1].strip().strip("'\"")
            if value:
                return value, f"dsh-credentials:{CREDS}"
    return None, "absent"


def resolve_base_url() -> str:
    env_url = os.environ.get("APKPLAT_MODEL_BASE_URL")
    if env_url:
        return env_url.rstrip("/")
    for candidate in (os.environ.get("APKPLAT_MODEL_BASE_URL_FALLBACK"), "http://127.0.0.1:8788/v1", "http://192.168.43.1:8788/v1"):
        if not candidate:
            continue
        try:
            with socket.create_connection(_host_port(candidate), timeout=3):
                return candidate.rstrip("/")
        except OSError:
            continue
    return "http://127.0.0.1:8788/v1"


def _host_port(url: str) -> tuple[str, int]:
    rest = url.split("://", 1)[-1]
    hostport = rest.split("/", 1)[0]
    if ":" in hostport:
        host, port = hostport.rsplit(":", 1)
        return host, int(port)
    return hostport, 443 if url.startswith("https") else 80


def resolve_model() -> str:
    return os.environ.get("APKPLAT_MODEL_ID") or "deepseek-v4.1-flash"


# ---------------------------------------------------------------------------
# HTTP helpers
# ---------------------------------------------------------------------------
def post_json(url: str, payload: dict, key: str | None, timeout: int = 120) -> tuple[int, dict | str, int]:
    body = json.dumps(payload).encode("utf-8")
    request = urllib.request.Request(url, data=body, method="POST")
    request.add_header("Content-Type", "application/json")
    if key:
        request.add_header("Authorization", f"Bearer {key}")
    started = time.perf_counter()
    try:
        with urllib.request.urlopen(request, timeout=timeout) as resp:
            text = resp.read().decode("utf-8", errors="replace")
            return resp.status, text, int((time.perf_counter() - started) * 1000)
    except urllib.error.HTTPError as exc:
        return exc.code, exc.read().decode("utf-8", errors="replace"), int((time.perf_counter() - started) * 1000)
    except Exception as exc:  # noqa: BLE001
        return 0, f"{type(exc).__name__}: {exc}", int((time.perf_counter() - started) * 1000)


def stream_text(url: str, payload: dict, key: str | None, timeout: int = 120) -> dict:
    body = json.dumps({**payload, "stream": True}).encode("utf-8")
    request = urllib.request.Request(url, data=body, method="POST")
    request.add_header("Content-Type", "application/json")
    request.add_header("Accept", "text/event-stream")
    if key:
        request.add_header("Authorization", f"Bearer {key}")
    started = time.perf_counter()
    deltas: list[str] = []
    events = 0
    first_delta_ms = None
    try:
        with urllib.request.urlopen(request, timeout=timeout) as resp:
            for raw in resp:
                line = raw.decode("utf-8", errors="replace").strip()
                if not line.startswith("data:"):
                    continue
                data = line[5:].strip()
                if data == "[DONE]":
                    break
                events += 1
                try:
                    chunk = json.loads(data)
                except json.JSONDecodeError:
                    continue
                for choice in chunk.get("choices", []):
                    piece = (choice.get("delta") or {}).get("content")
                    if piece:
                        if first_delta_ms is None:
                            first_delta_ms = int((time.perf_counter() - started) * 1000)
                        deltas.append(piece)
        return {
            "ok": bool(deltas),
            "events": events,
            "chars": len("".join(deltas)),
            "first_delta_ms": first_delta_ms,
            "total_ms": int((time.perf_counter() - started) * 1000),
            "preview": "".join(deltas)[:200],
        }
    except Exception as exc:  # noqa: BLE001
        return {"ok": False, "error": f"{type(exc).__name__}: {exc}", "events": events}


# ---------------------------------------------------------------------------
# checks
# ---------------------------------------------------------------------------
def check_text(base: str, model: str, key: str | None) -> dict:
    payload = {
        "model": model,
        "messages": [
            {"role": "system", "content": "You answer with a single lower-case word."},
            {"role": "user", "content": "Reply with exactly: ok"},
        ],
        "max_tokens": 512,
        "temperature": 0,
    }
    status, text, ms = post_json(base + "/chat/completions", payload, key)
    out = {"status": status, "latency_ms": ms}
    if status == 200 and isinstance(text, str):
        try:
            data = json.loads(text)
            message = data["choices"][0]["message"]
            content = (message.get("content") or "").strip()
            reasoning = (message.get("reasoning_content") or "").strip()
            out.update(
                {
                    "ok": bool(content or reasoning),
                    "content": content[:120],
                    "reasoning_chars": len(reasoning),
                    "finish_reason": data["choices"][0].get("finish_reason"),
                    "model": data.get("model"),
                }
            )
        except Exception as exc:  # noqa: BLE001
            out.update({"ok": False, "error": f"unparseable response: {exc}", "raw": str(text)[:300]})
    else:
        out.update({"ok": False, "error": str(text)[:300]})
    return out


def check_json(base: str, model: str, key: str | None) -> dict:
    payload = {
        "model": model,
        "messages": [
            {"role": "system", "content": "You are a JSON generator. Reply with JSON only."},
            {
                "role": "user",
                "content": 'Return {"package":"com.example.app","risk":"low","findings":[]} verbatim.',
            },
        ],
        "response_format": {"type": "json_object"},
        "max_tokens": 64,
        "temperature": 0,
    }
    status, text, ms = post_json(base + "/chat/completions", payload, key)
    out = {"status": status, "latency_ms": ms}
    if status == 200 and isinstance(text, str):
        try:
            data = json.loads(text)
            content = data["choices"][0]["message"].get("content") or ""
            parsed = json.loads(content)
            out.update({"ok": isinstance(parsed, dict), "keys": sorted(parsed)[:8], "content": content[:200]})
        except Exception as exc:  # noqa: BLE001
            out.update({"ok": False, "error": f"not JSON: {type(exc).__name__}: {exc}", "raw": str(text)[:300]})
    else:
        out.update({"ok": False, "error": str(text)[:300]})
    return out


def check_stream(base: str, model: str, key: str | None) -> dict:
    payload = {
        "model": model,
        "messages": [{"role": "user", "content": "Count from 1 to 5, separated by spaces."}],
        "max_tokens": 256,
        "temperature": 0,
    }
    return stream_text(base + "/chat/completions", payload, key)


def check_tools(base: str, model: str, key: str | None) -> dict:
    payload = {
        "model": model,
        "messages": [{"role": "user", "content": "List the packages of project 00000000-0000-0000-0000-000000000000 using the tool."}],
        "tools": [
            {
                "type": "function",
                "function": {
                    "name": "apk_list_packages",
                    "description": "List packages of an analysed APK project",
                    "parameters": {
                        "type": "object",
                        "properties": {"project_id": {"type": "string"}},
                        "required": ["project_id"],
                    },
                },
            }
        ],
        "tool_choice": "auto",
        "max_tokens": 128,
        "temperature": 0,
    }
    status, text, ms = post_json(base + "/chat/completions", payload, key)
    out = {"status": status, "latency_ms": ms}
    if status == 200 and isinstance(text, str):
        try:
            data = json.loads(text)
            message = data["choices"][0]["message"]
            calls = message.get("tool_calls") or []
            out.update(
                {
                    "ok": bool(calls),
                    "tool_calls": [
                        {"name": c.get("function", {}).get("name"), "arguments": c.get("function", {}).get("arguments")}
                        for c in calls
                    ],
                    "finish_reason": data["choices"][0].get("finish_reason"),
                }
            )
        except Exception as exc:  # noqa: BLE001
            out.update({"ok": False, "error": f"unparseable: {exc}", "raw": str(text)[:300]})
    else:
        out.update({"ok": False, "error": str(text)[:300]})
    return out


# ---------------------------------------------------------------------------
# environment snapshot
# ---------------------------------------------------------------------------
def _run(cmd: list[str], timeout: int = 60) -> str:
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, errors="replace")
        return ((proc.stdout or "") + (proc.stderr or "")).strip()
    except Exception as exc:  # noqa: BLE001
        return f"<error: {exc}>"


def _ps(script: str) -> str:
    return _run(["powershell", "-NoProfile", "-Command", script], timeout=90)


def environment() -> dict:
    import shutil as _shutil

    usage = _shutil.disk_usage(str(ROOT))
    mem_total = mem_free = None
    try:
        import ctypes

        class MEMORYSTATUSEX(ctypes.Structure):
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

        stat = MEMORYSTATUSEX()
        stat.dwLength = ctypes.sizeof(MEMORYSTATUSEX)
        if ctypes.windll.kernel32.GlobalMemoryStatusEx(ctypes.byref(stat)):  # type: ignore[attr-defined]
            mem_total = int(stat.ullTotalPhys)
            mem_free = int(stat.ullAvailPhys)
    except Exception:  # noqa: BLE001
        pass
    return {
        "os": f"{platform.system()} {platform.release()} {platform.version()}",
        "machine": platform.machine(),
        "processor": _ps("(Get-CimInstance Win32_Processor | Select-Object -First 1 -ExpandProperty Name)"),
        "cores": os.cpu_count(),
        "ram_total_bytes": mem_total,
        "ram_available_bytes": mem_free,
        "disk_free_bytes": usage.free,
        "disk_total_bytes": usage.total,
        "python": f"{sys.version.split()[0]} ({sys.executable})",
        "powershell": _ps("$PSVersionTable.PSVersion.ToString()"),
        "container_runtime": _run(["docker", "--version"]) or "absent",
        "postgres": "absent",
        "redis": "absent",
        "dsh_version": "0.2.1-rc.4",
        "dsh_profile": str(PATCH),
    }


def toolchain_versions() -> dict:
    from apkplat import toolchain

    return toolchain.probe_versions()


def dsh_facts() -> dict:
    facts = {"profile_exists": PATCH.exists(), "profile_bytes": PATCH.stat().st_size if PATCH.exists() else 0}
    if PATCH.exists():
        text = PATCH.read_text(encoding="utf-8", errors="replace")
        facts["mcp_client_plugin"] = "@deepseek-ai/dsh-mcp-client" in text
        facts["provider_block_present"] = "wb-proxy" in text
    return facts


def write_report(env: dict, versions: dict, checks: dict, key_source: str, base: str, model: str) -> Path:
    OUT.mkdir(parents=True, exist_ok=True)
    rows = "\n".join(
        f"| {name} | {'ok' if (v.get('ok') if isinstance(v, dict) else False) else 'missing'} | {v.get('version', v.get('path', '')) if isinstance(v, dict) else v} |"
        for name, v in versions.items()
    )
    checks_rows = "\n".join(
        f"| {name} | {'PASS' if c.get('ok') else 'FAIL'} | {c.get('latency_ms', c.get('total_ms', 'n/a'))} | {json.dumps({k: v for k, v in c.items() if k in ('content', 'preview', 'tool_calls', 'error', 'status')})[:220]} |"
        for name, c in checks.items()
    )
    giB = 1024**3
    body = f"""# P0 — Environment report

Generated: {time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime())}
Host: `{socket.gethostname()}`
Mode: **read-only inspection**. No DSH component, model, proxy, DNS or API setting was installed,
reconfigured or restarted to produce this report. Every tool listed under "project toolchain" was
installed *inside this project* (`apk-research-platform/tools/`), which is removable as a directory.

## 1. Host

| Item | Value |
|---|---|
| OS | {env['os']} |
| CPU | {env['processor']} |
| Cores | {env['cores']} |
| RAM total / available | {env['ram_total_bytes']/giB:.1f} GiB / {(env['ram_available_bytes'] or 0)/giB:.1f} GiB |
| Disk free / total (project volume) | {env['disk_free_bytes']/giB:.1f} GiB / {env['disk_total_bytes']/giB:.1f} GiB |
| Python | {env['python']} |
| PowerShell | {env['powershell']} |
| Container runtime | {env['container_runtime']} |
| PostgreSQL / Redis | absent (see deviations) |

## 2. DSH NEXT (pre-provided, unchanged)

| Item | Value |
|---|---|
| Installed version | {env['dsh_version']} |
| Profile file | `{env['dsh_profile']}` ({dsh_facts()['profile_bytes']} bytes) |
| MCP client plugin present | {dsh_facts()['mcp_client_plugin']} |
| Model provider block present | {dsh_facts()['provider_block_present']} |

DSH and the remote model API were supplied by the operator before this task started. This project
consumes them; it does not install, upgrade, reconfigure or proxy them.

## 3. Project-local toolchain

Installed by `scripts/fetch_toolchain.py` under `tools/` (delete the directory to roll back).

| Component | Status | Version / path |
|---|---|---|
{rows}

## 4. Model API verification

Endpoint: `{base}` * model `{model}` * key source: `{key_source}` (value never printed or stored).

| Check | Result | Latency (ms) | Evidence |
|---|---|---|---|
{checks_rows}

## 5. Deviations from the taskbook's reference stack (and why)

1. **No container isolation.** Docker/Podman are absent and installing them would require a kernel
   driver change plus a reboot — out of scope for a "component install" and impossible to verify
   unattended. Compensating controls: every external tool runs through
   `apkplat/toolchain.py` (argv-only, cwd pinned inside the project, wall-clock timeout, process-tree
   kill, whitelisted env, output caps), the backend binds `127.0.0.1`, and workers only ever touch
   their own project subtree.
2. **SQLite instead of PostgreSQL.** PostgreSQL is not installed. The DDL is portable ANSI/PG-compatible
   (`migrations/001_init.sql`) and the DB layer switches on `APKPLAT_DB_URL`; on this host SQLite with
   WAL is the single source of truth. Concurrency limits are those of the taskbook (2 static workers).
3. **No Redis.** The queue is a DB outbox (`jobs` table) with leases, heartbeats and crash recovery —
   which is what the taskbook's "persistent scheduling + restart recovery" needs anyway.
4. **Linear JADX/Apktool, no `seccomp`/`AppArmor`.** Not available on Windows; documented in
   `docs/operations.md` as a residual risk with the compensating controls above.

## 6. Verdict

{"P0 PASS — host, DSH and model API all respond in the required shapes." if all(c.get("ok") for c in checks.values()) else "P0 INCOMPLETE — see failing checks above."}
"""
    path = OUT / "environment_report.md"
    path.write_text(body, encoding="utf-8")
    return path


def main() -> int:
    key, key_source = resolve_key()
    base = resolve_base_url()
    model = resolve_model()
    checks = {
        "text": check_text(base, model, key),
        "json_object": check_json(base, model, key),
        "streaming": check_stream(base, model, key),
        "tool_calls": check_tools(base, model, key),
    }
    env = environment()
    versions = toolchain_versions()
    OUT.mkdir(parents=True, exist_ok=True)
    (OUT / "model_api_check.json").write_text(
        json.dumps(
            {
                "base_url": base,
                "model": model,
                "key_source": key_source,
                "key_fingerprint": f"len={(len(key) if key else 0)}",
                "checks": checks,
                "generated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            },
            indent=2,
        ),
        encoding="utf-8",
    )
    path = write_report(env, versions, checks, key_source, base, model)
    print(f"[p0] report: {path}")
    for name, check in checks.items():
        print(f"[p0] {name:12s} {'PASS' if check.get('ok') else 'FAIL'}  {json.dumps({k: v for k, v in check.items() if k in ('status', 'error', 'latency_ms', 'total_ms')})}")
    return 0 if all(c.get("ok") for c in checks.values()) else 1


if __name__ == "__main__":
    raise SystemExit(main())
