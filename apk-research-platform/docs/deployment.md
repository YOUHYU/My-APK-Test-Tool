# Deployment

This document describes how the APK research platform is started, supervised, and wired into
DSH NEXT on this host. It assumes the machine already has DSH NEXT installed and a working
model endpoint; the platform never installs, upgrades, or reconfigures either of those.

## 1. What the platform needs

| Requirement | Where it comes from | Notes |
| --- | --- | --- |
| Python 3.13 | `C:\Users\YHY\AppData\Local\Programs\Python\Python313\python.exe` | The repository `.venv` is built from it; no system-level installs. |
| JDK 21, JADX 1.5.6, Apktool 3.0.3, aapt2 2.19, adb | `tools/` (portable, project-local) | Installed by `scripts/fetch_toolchain.py`; the whole folder can be deleted. |
| Node 22.23.4 | `tools/node` | Only used for `node --check` on the browser bundle. |
| SQLite | Python stdlib | The database is a single file at `storage/platform.db` (WAL). |
| Model endpoint | `http://192.168.43.1:8788/v1` (operator-provided) | The key is read from the environment or from the DSH credential store, never written to disk. |

Nothing is installed outside the project directory. Deleting `tools/` and `.venv/` returns the
machine to its previous state.

## 2. First run

```powershell
$root = "D:\ADeespseekSH\REA\apk-research-platform"
$env:TEMP = "$root\.tmp"; $env:TMP = "$root\.tmp"   # the system temp dir is unusable on this host

# toolchain (idempotent; verifies checksums recorded in tools/MANIFEST.json)
& "$root\.venv\Scripts\python.exe" "$root\scripts\fetch_toolchain.py" --verify

# configuration: copy the template, then edit only what you must
Copy-Item "$root\.env.example" "$root\.env"

# schema + storage layout
& "$root\.venv\Scripts\python.exe" "$root\scripts\apkplat_cli.py" init

# API + static workers (supervised by the script below)
pwsh -File "$root\scripts\platform.ps1" start
```

`platform.ps1 start` launches the API on `127.0.0.1:8765` and two static workers, waits for
`/api/health`, and stores pids and logs under `storage/run/`. `platform.ps1 status`, `check`,
`stop`, and `restart` operate on the same pid files.

## 3. Processes and their responsibilities

| Process | Command | Role |
| --- | --- | --- |
| API | `apkplat_cli.py serve --port 8765` | Owns every state transition, leases, budgets; serves the board. |
| Static worker | `workers/static_worker.py` | Runs `static_pipeline` and `agent_orchestrate` jobs. |
| Dynamic worker | `workers/dynamic_worker.py` | Runs `dynamic_analysis` jobs against a leased device. |
| Report worker | `workers/report_worker.py` | Runs `report_generate` jobs. |
| Scheduler | `apkplat_cli.py scheduler --interval 60` | Only component allowed to trigger periodic jobs (P6). |
| MCP server | `mcp-server/mcp_server/server.py` (stdio) | 13 typed tools for DSH; spawned by DSH on demand. |
| Bridge plugin | `plugins/apkplat-bridge/index.js` | Registers per-run tools inside DSH and forwards them to the API. |

Workers never write final states. They claim a job under a lease, do the work, and ask the API
for `REVIEW`; only the platform's acceptance path can write `DONE`.

## 4. Wiring the MCP server into DSH

```powershell
& "$root\.venv\Scripts\python.exe" "$root\scripts\render_mcp_registration.py" --server-name apkplat
```

This writes `config/dsh-mcp.registration.yml` and the plugin bundle under `dsh-plugin/`. DSH
0.2.1-rc.4 treats a patch entry as *insert* only when it is spelled that way:

```yaml
- insert:
    - id: mcp-apkplat
      name: '@deepseek-ai/dsh-mcp-client'
      config:
        serverName: apkplat
        transport: stdio
        command: <root>/.venv/Scripts/python.exe
        args: [<root>/mcp-server/mcp_server/server.py]
        cwd: <root>
        env:
          APKPLAT_STORAGE: <root>/storage
          APKPLAT_MCP_ALLOW_TOOLS: project_get,artifact_list,evidence_read
```

A bare `- id: ...` entry in an overlay is rejected with `patch: entry "mcp-apkplat" not found`
because the overlay can only patch entries that already exist. The evidence for this is in
`audit/mcp_registration_proof.md`.

## 5. Wiring the bridge plugin into DSH

```yaml
- insert:
    - id: apkplat-bridge
      name: file:///<root>/plugins/apkplat-bridge/index.js
      config:
        platform_url: http://127.0.0.1:8765
        token_file: <root>/storage/run/token.txt
        trace_file: <root>/storage/run/bridge-trace.jsonl
        timeout_ms: 120000
        fail_on_error: false
```

The plugin resolves `@deepseek-ai/dsh-tools` from the DSH installation (or from
`APKPLAT_DSH_ASAR`), reads the run token from `token_file`, calls `/api/bridge/handshake`, and
registers one typed tool per scope entry. The token stays inside the plugin closure: it is not a
tool argument, not a prompt line, and not printed. See `docs/bridge.md` for the full protocol.

## 6. Configuration surface

Every setting is an `APKPLAT_*` environment variable; see `.env.example` for the annotated list.
The ones that change behaviour most:

| Variable | Default | Effect |
| --- | --- | --- |
| `APKPLAT_REQUIRE_AUTH` | `1` | `0` is the local-operator mode used by the board on this host. |
| `APKPLAT_MODEL_CONCURRENCY` | `1` | Global single-flight gate for model calls (taskbook 10). |
| `APKPLAT_CACHE_ENABLED` / `APKPLAT_CACHE_MAX_MB` | `1` / `2048` | Static analysis cache keyed by APK digest. |
| `APKPLAT_DYNAMIC_TRANSPORT` | `adb` | `sim` swaps in the deterministic transport used by the gate scripts. |
| `APKPLAT_CAPTURE_DIR` | empty | Directory holding a ProxyPin export; empty means capture is honestly `NOT_OBSERVED`. |

## 7. Health and routine checks

```powershell
pwsh -File "$root\scripts\platform.ps1" check          # toolchain verdicts, queue depth, audit seq
curl http://127.0.0.1:8765/api/health                   # version, auth mode, worker policy, capabilities
curl http://127.0.0.1:8765/api/resources                # memory / disk / leases / model in flight
```

`/api/health` reports what is *not* available as well: `test_run.isolation = cooperative`,
`device_action.requires = "an active device lease ..."`, and `capture_query` pointing at the
capture probe. The platform never claims a capability it cannot back with an artifact.

## 8. Known operating limits on this host

- No container runtime: the sandbox is cooperative (audit hook + banned imports), and
  `isolation: container` returns `strong_isolation_unavailable` instead of pretending.
- No ProxyPin or mitm proxy is installed on the handset, so `capture_query` answers
  `NOT_OBSERVED` until an export is dropped into `APKPLAT_CAPTURE_DIR`.
- One physical device (Mi 10, `e74398f9`) is reachable over both USB and Wi-Fi; the device pool
  merges transports by `ro.serialno`, so both channels count as one device.
- Free memory sits around 1.9 GB; heavy Java work is gated at one concurrent run.
