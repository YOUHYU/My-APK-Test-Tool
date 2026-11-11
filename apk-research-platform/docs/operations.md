# Operations

How this deployment is installed, started, fed work, backed up and re-verified. Every value
below is measured on this host or read from the code named in the sentence; where the
repository does not ship something, the text says so instead of assuming.

Scope: one operator, one loopback port, one SQLite file, one portable toolchain tree inside the
repository — no container runtime, no PostgreSQL, no Redis
([p0 report](../reports/p0/environment_report.md)).

## 1. Host as measured

| Item | Value |
| --- | --- |
| OS | Windows 11, build 10.0.26200 |
| CPU / RAM | AMD Ryzen 7 5800H, 16 cores; 15.4 GiB RAM (2.1 GiB free when measured) |
| Disk | 620.6 GiB free of 1406.2 GiB |
| Base interpreter | `C:\Users\YHY\AppData\Local\Programs\Python\Python313\python.exe` → 3.13.12 |
| Project interpreter | `.venv\Scripts\python.exe` → 3.13.12 (MSC v.1944, 64 bit) |
| Shell | PowerShell 5.1.26100.7920 |
| Container runtime | absent (`[WinError 2]` when probed) |
| PostgreSQL / Redis | absent |
| Toolchain | portable under `tools/`: jdk 21.0.13, jadx 1.5.6, apktool 3.0.3, aapt2 2.19, adb |
| Model API | `http://192.168.43.1:8788/v1`, model `deepseek-v4.1-flash` |

```powershell
cd D:\ADeespseekSH\REA\apk-research-platform
.\.venv\Scripts\python.exe -c "import sys; print(sys.version)"
.\.venv\Scripts\python.exe scripts\apkplat_cli.py versions
```

`versions` prints one JSON object with `java`, `jadx`, `apktool`, `aapt2`, `adb`; each entry is
`{ok, version, path}` or `{ok:false, error:"not_installed", path}`. For the jar-based tools
(`jadx`, `apktool`) the reported `path` is the JVM that runs them (`tools\jdk\bin\java.exe`);
the jars live in `tools\jadx\lib\` and `tools\apktool\`.

## 2. Bootstrap from zero

### 2.1 Virtual environment and dependencies

```powershell
C:\Users\YHY\AppData\Local\Programs\Python\Python313\python.exe -m venv .venv
.\.venv\Scripts\python.exe -m pip install --upgrade pip
.\.venv\Scripts\python.exe -m pip install -r requirements.lock   # exact rebuild of this host
.\.venv\Scripts\python.exe -m pip install -r requirements.txt    # direct dependencies only
```

`requirements.txt` pins the nine direct dependencies: `fastapi==0.162.2`, `uvicorn==0.54.0`,
`pydantic==2.14.3`, `python-multipart==0.0.33`, `python-dotenv==1.2.4`, `PyYAML==6.0.3`,
`androguard==4.1.4`, `httpx==0.28.1`, `pytest==9.2.0`. `requirements.lock` is `pip freeze` of the
working `.venv` — 60 pins, incl. `loguru==0.7.3`, `SQLAlchemy==2.1.8`, `alembic==1.20.1`. There
is no `pyproject.toml` or `setup.cfg`: the code runs from `backend/` on `sys.path` (the CLI
inserts it), never as an installed package. After adding a dependency, re-freeze the lock
(`pip freeze > requirements.lock`). `psycopg` is imported only on the PostgreSQL path
(`APKPLAT_DB_URL` starting with `postgres`), which is untested here.

### 2.2 Portable toolchain (`scripts/fetch_toolchain.py`)

Everything installs inside `tools/`; no system PATH, registry entry or global package is
touched, and `--clean` removes the tree again. `tools/MANIFEST.json` records each component's
version, URL, sha256 and probe result.

```powershell
.\.venv\Scripts\python.exe scripts\fetch_toolchain.py --list
.\.venv\Scripts\python.exe scripts\fetch_toolchain.py                  # install all
.\.venv\Scripts\python.exe scripts\fetch_toolchain.py --only jdk,node  # subset
.\.venv\Scripts\python.exe scripts\fetch_toolchain.py --verify         # probe only, exit 1 on failure
.\.venv\Scripts\python.exe scripts\fetch_toolchain.py --clean          # remove tools/{jdk,node,jadx,apktool,android-sdk,_cache}
```

Components: `node` 22.23.4, `jdk` 21-ga-temurin, `jadx` 1.5.6, `apktool` 3.0.3, `android`
(cmdline-tools 13114758 plus `platform-tools`, `build-tools;34.0.0`, `platforms;android-34`).
The Android step runs `sdkmanager --sdk_root=<path> --licenses` feeding it `y` sixty times,
then installs the three packages; the flag is passed as a single argument (see
[troubleshooting.md](troubleshooting.md)).

### 2.3 Sample APK

```powershell
.\.venv\Scripts\python.exe scripts\build_sample_apk.py                        # samples\sample-app.apk, ground_truth.json, hostile-*.apk
.\.venv\Scripts\python.exe scripts\build_sample_apk.py --out samples\sample-app.apk --no-hostile
```

The builder signs and zips on every run, so `samples/ground_truth.json` must be regenerated
together with the APK — its `rebuild_note` says exactly that, and `apk_sha256` is a snapshot of
one build.

### 2.4 Database

```powershell
.\.venv\Scripts\python.exe scripts\apkplat_cli.py init
```

`init` creates the storage/reports/projects directories, applies every `migrations/*.sql` not
yet in `schema_migrations`, and prints `storage`, `db`, `migrations_applied`. `serve` runs the
same migration step at startup; `scripts\platform.ps1 init` does `init` + `versions`.

## 3. Daily operations

### 3.1 Start, stop, inspect (`scripts/platform.ps1`)

```powershell
.\scripts\platform.ps1 init
.\scripts\platform.ps1 start                       # API + 2 static workers
.\scripts\platform.ps1 start -Port 8765 -StaticWorkers 2 -WithModel -WithDynamic
.\scripts\platform.ps1 status | check | logs | stop | restart | cleanup
```

`start` launches `apkplat_cli.py serve --host 127.0.0.1 --port <Port>`, waits up to 30 s for
`/api/health`, then starts `worker-static-1..N` with `--kinds static_pipeline --idle 0`;
`-WithDynamic` adds `worker-dynamic` (`--kinds dynamic_analysis`), `-WithModel` adds
`worker-report` (`--kinds agent_orchestrate,report_generate`). Pids and logs live in
`storage\run\` (`api.pid`, `api.log`, `api.log.err`, `worker-static-1.log`, …); `stop` uses
`taskkill /PID <pid> /T /F` on the pid files; `check` prints the health document, the tool
table, `apkplat_cli.py queue` and `apkplat_cli.py list`.

Manual equivalents, one shell per process:

```powershell
.\.venv\Scripts\python.exe scripts\apkplat_cli.py serve --host 127.0.0.1 --port 8765
.\.venv\Scripts\python.exe scripts\apkplat_cli.py worker --id static-1 --kinds static_pipeline --idle 0
.\.venv\Scripts\python.exe scripts\apkplat_cli.py worker --id report-1 --kinds agent_orchestrate,report_generate --idle 0
.\.venv\Scripts\python.exe scripts\apkplat_cli.py worker --id dynamic-1 --kinds dynamic_analysis --idle 0
.\.venv\Scripts\python.exe scripts\apkplat_cli.py worker --once --max-jobs 5
```

`--kinds` defaults to every handler (`static_pipeline,report_generate,agent_orchestrate,
dynamic_analysis`). `--idle 0` disables the idle stop; `--once` without `--max-jobs` forces a
3 s idle timeout so the command always returns.

### 3.2 MCP server (separate process)

The MCP surface is a stdio JSON-RPC server, not part of the API process:

```powershell
$env:PYTHONPATH = "D:\ADeespseekSH\REA\apk-research-platform\backend"
$env:APKPLAT_MCP_PROJECTS = "prj_6cd77a33712947b4b876c67f6c04a36f"
$env:APKPLAT_MCP_ACTOR = "mcp-agent"
.\.venv\Scripts\python.exe mcp-server\mcp_server\server.py
```

It reads newline-delimited JSON-RPC on stdin and writes answers on stdout; diagnostics go to
stderr. `APKPLAT_MCP_PROJECTS` defaults to `*` (any project, trusted workstation) and accepts a
comma list. `config/dsh-mcp.registration.yml` registers exactly this command with DSH. See
[mcp.md](mcp.md).

### 3.3 Submitting work

HTTP — mint a token (local mode: omit the `Authorization` header everywhere):

```powershell
$base = "http://127.0.0.1:8765"
$env:PYTHONPATH = "D:\ADeespseekSH\REA\apk-research-platform\backend"   # only for the next line
$admin = @{ "X-Admin-Secret" = (& .\.venv\Scripts\python.exe -c "from apkplat.config import settings; print(settings.signing_secret().hex())") }
$token = (Invoke-RestMethod -Method Post -Uri "$base/api/auth/token" -Headers $admin -ContentType "application/json" -Body '{"subject":"operator","projects":["prj_6cd77a33712947b4b876c67f6c04a36f"],"scopes":["read","write"]}').token
```

The admin secret is the hex of the same bytes `APKPLAT_SECRET` or `storage/secret.key` holds.
`projects` is required (`422 projects_required`) and `["*"]` is refused (`422
wildcard_forbidden`). Upload — PowerShell 5.1 has no `-Form`, so use `curl.exe`:

```powershell
curl.exe -s -X POST "$base/api/projects" -H "Authorization: Bearer $token" `
  -F "name=reef" -F "goal=static review" -F "apk=@samples\sample-app.apk"
```

Uploads stream in 1 MB chunks, are rejected with `413 upload_too_large` past
`APKPLAT_MAX_UPLOAD_MB`, and enqueue `static_pipeline` with idempotency key `static:<id>`.

CLI — same work without HTTP:

```powershell
.\.venv\Scripts\python.exe scripts\apkplat_cli.py create --name reef --apk samples\sample-app.apk --goal "static review"
.\.venv\Scripts\python.exe scripts\apkplat_cli.py worker --once
.\.venv\Scripts\python.exe scripts\apkplat_cli.py list | show <project_id> | verify <project_id>
.\.venv\Scripts\python.exe scripts\apkplat_cli.py report <project_id>
.\.venv\Scripts\python.exe scripts\apkplat_cli.py search <project_id> validateLicense --kind class
.\.venv\Scripts\python.exe scripts\apkplat_cli.py evidence <project_id>
.\.venv\Scripts\python.exe scripts\apkplat_cli.py dynamic <project_id> --transport sim
```

`verify` re-hashes every artifact and re-checks every evidence row, exit code 1 on any failure.
`queue --reclaim` expires dead leases; `job-reset <job_id> --reason "..."` returns a job to
PENDING and audits `job_reset_by_operator`.

## 4. Environment variables

Defaults come from `backend/apkplat/config.py` — an unset variable gives the value in the
Default column.

| Variable | Default | Effect |
| --- | --- | --- |
| `APKPLAT_STORAGE` | `<repo>/storage` | Root for database, projects, inbox, tmp scratch |
| `APKPLAT_REPORTS` | `<repo>/reports` | Where gate/p0 acceptance output is written |
| `APKPLAT_TOOLS` | `<repo>/tools` | Portable toolchain root |
| `APKPLAT_DB_URL` | empty → `sqlite:///<storage>/platform.db` | Database URL; `postgres…` switches driver (untested here) |
| `APKPLAT_HOST` / `APKPLAT_PORT` | `127.0.0.1` / `8765` | Bind defaults used by `serve` |
| `APKPLAT_PUBLIC_URL` | `http://127.0.0.1:8765` | Extra CORS origin |
| `APKPLAT_REQUIRE_AUTH` | `True` | `1` = bearer tokens required; `0` = local single-operator mode |
| `APKPLAT_SECRET` | empty → `storage/secret.key` (48 random bytes, written once) | Token signing key and admin secret |
| `APKPLAT_TOKEN_TTL` | `43200` | Token lifetime (s), 12 h |
| `APKPLAT_STATIC_WORKERS` / `APKPLAT_DYNAMIC_WORKERS` / `APKPLAT_REPORT_WORKERS` | `2` / `1` / `1` | Advertised in `/api/health.concurrency`; workers are started as processes |
| `APKPLAT_MODEL_CONCURRENCY` | `1` | Size of the model-call `BoundedSemaphore` |
| `APKPLAT_JOB_LEASE_SECONDS` | `300` | Queue lease; heartbeat every `max(5, lease//3)` s |
| `APKPLAT_DEVICE_LEASE_SECONDS` | `900` | Dynamic device lease TTL |
| `APKPLAT_MAX_UPLOAD_MB` / `APKPLAT_MAX_UNZIPPED_MB` | `512` / `2048` | Upload cap, unpacked-size budget |
| `APKPLAT_JADX_TIMEOUT` / `APKPLAT_APKTOOL_TIMEOUT` | `900` / `900` | Wall-clock caps before the process tree is killed |
| `APKPLAT_JADX_HEAP` | `-Xmx1200m` | JVM heap for jadx |
| `APKPLAT_MODEL_BASE_URL` | empty → probe `127.0.0.1:8788/v1`, then `192.168.43.1:8788/v1` | Model endpoint |
| `APKPLAT_MODEL_API_KEY` | empty → `refs.WB_PROXY_API_KEY` in `~/.dsh/.credentials.yaml` | Bearer key; never printed |
| `APKPLAT_MODEL_ID` | empty → `deepseek-v4.1-flash` | Model name in the request body |
| `APKPLAT_MODEL_TIMEOUT` | `180` | Per-request timeout (s) |
| `APKPLAT_MODEL_ENABLED` | `True` | `0` disables model calls (`model_disabled`) |
| `APKPLAT_MODEL_MAX_TOKENS` | `3000` | Default generation cap |
| `APKPLAT_DYNAMIC_TRANSPORT` | `adb` | `sim` = deterministic simulator; `adb` = device pool |
| `APKPLAT_DYNAMIC_STEP_TIMEOUT` | `120` | Per-step cap (install uses `max(120, this)`) |
| `APKPLAT_DYNAMIC_OBSERVE_SECONDS` | `5` | Logcat observation window |
| `APKPLAT_DYNAMIC_LOG_TAIL` | `400` | `logcat -d -t` line count |
| `APKPLAT_MCP_PROJECTS` / `APKPLAT_MCP_ACTOR` | `*` / `dsh-agent` | Read by the MCP server only |
| `APKPLAT_ALLOW_LOCAL_TOKEN` | `1` | In local mode, mint tokens without `X-Admin-Secret` |

Script switches: `APKPLAT_KEEP_GATE_TMP=1` keeps a gate's temp work directory,
`APKPLAT_KEEP_TEST_TMP=1` keeps `tests/.tmp`. `.env.example` is a template, not a transcript of
the code defaults: it sets `APKPLAT_REQUIRE_AUTH=0` and `APKPLAT_DYNAMIC_TRANSPORT=sim`, which
differ from the defaults `True` and `adb`.

## 5. Concurrency policy

- **Static workers: 2.** `platform.ps1 -StaticWorkers` defaults to 2, `APKPLAT_STATIC_WORKERS`
  is 2; each worker is a separate process with its own `--id`.
- **Model calls: one at a time.** `llm.py` gates every request through a module-level
  `BoundedSemaphore(max(1, APKPLAT_MODEL_CONCURRENCY))`.
- **One SQLite writer.** `db.py` keeps a single connection behind a re-entrant lock, WAL
  journal mode, `busy_timeout=30000`; `tx()` opens `BEGIN IMMEDIATE`. Workers run in parallel,
  their writes serialise.
- **Jobs are leased, not owned.** `claim()` is exclusive inside `BEGIN IMMEDIATE`; a stale
  lease is reclaimed by `reclaim_expired()` at worker start, so a crashed worker's job is
  retried rather than lost.
- **Devices serialise dynamic work.** `devices.acquire()` refuses a second live lease on the
  same device and a second lease for the same (project, task); a waiting task goes to
  `WAITING_DEVICE` with retryable `device_unavailable`.

Raise worker counts with the SQLite writer in mind; raise `APKPLAT_MODEL_CONCURRENCY` only if the upstream endpoint tolerates it.

## 6. Backup and restore

Stop the API and every worker first (`.\scripts\platform.ps1 stop`). Copy the three SQLite files
together — `platform.db`, `platform.db-wal`, `platform.db-shm`. Measured: a copy of `platform.db`
alone lost the newest migration's schema (still in the WAL), so its triggers went missing.

```powershell
$src = "D:\ADeespseekSH\REA\apk-research-platform\storage"
$dst = "D:\backup\apkplat-$(Get-Date -Format yyyyMMdd-HHmm)"
New-Item -ItemType Directory -Force -Path $dst | Out-Null
Copy-Item "$src\platform.db*" -Destination $dst -Force
Copy-Item "$src\projects"     -Destination $dst -Recurse -Force
Copy-Item "$src\secret.key"   -Destination $dst -Force
```

Restore is the reverse with the platform stopped, then `apkplat_cli.py init` (applies missing
migrations) and `apkplat_cli.py verify <project_id>` (re-hashes artifacts and evidence).

`secret.key` matters: tokens and the admin secret derive from it, so restoring without it
invalidates every issued token and mints a new key. `storage\run|tmp|inbox\` are disposable.

## 7. Upgrade and rollback

**Migrations are additive and recorded.** `db.migrate()` applies any `migrations/*.sql` whose
name is not in `schema_migrations` and returns what it applied; the API runs it at startup. Two
migrations are applied on this host:

```powershell
.\.venv\Scripts\python.exe -c "import sqlite3;print(sqlite3.connect(r'storage\platform.db').execute('select name, applied_at from schema_migrations order by name').fetchall())"
# [('001_init.sql', '2026-11-10T10:39:43.910Z'), ('002_audit_appendonly.sql', '2026-11-10T12:08:19.441Z')]
```

There is no down-migration path: to roll a schema change back, restore the database from
backup (section 6). Tables after both migrations: `agent_runs`, `approvals`, `artifacts`,
`audit_events`, `counters`, `device_leases`, `devices`, `evidence`, `jobs`, `model_requests`,
`projects`, `schema_migrations`, `tasks`.

**Roll back one tool component** by deleting its directory and re-fetching it:

```powershell
Remove-Item tools\jadx -Recurse -Force
.\.venv\Scripts\python.exe scripts\fetch_toolchain.py --only jadx
.\.venv\Scripts\python.exe scripts\apkplat_cli.py versions
```

Full toolchain rollback: `scripts\fetch_toolchain.py --clean` removes
`tools\{jdk,node,jadx,apktool,android-sdk,_cache}` and `tools\MANIFEST.json`; the host
environment was never modified. Python dependencies roll back with
`.\.venv\Scripts\python.exe -m pip install -r requirements.lock` (then `pip check`).

## 8. Retention and cleanup

`storage\tmp\` (upload staging, `jadx-probe.out/.err`, the `TEMP`/`TMP` of every child process),
`storage\inbox\` (CLI copy of an APK source) and `storage\run\` (pids, logs) are disposable.
`storage\projects\<id>\inputs\quarantine\` exists only during ingest and is removed by ingest
itself. Project `artifacts|indexes|logs|reports` carry the bytes evidence points at — delete
them only with the project.

```powershell
.\scripts\platform.ps1 cleanup     # clears storage\tmp and storage\inbox only, never project data
```

**Removing a project is manual**: there is no delete endpoint and no delete subcommand
(`services/projects.py` exposes create/get/list/manifest/apk_path/set_status/board only). With
the platform stopped:

```powershell
Remove-Item "storage\projects\<project_id>" -Recurse -Force
```

then delete the `projects`, `tasks`, `jobs`, `artifacts`, `evidence` rows for that id. Warning:
`audit_events` and `evidence` carry `BEFORE UPDATE` / `BEFORE DELETE` triggers that raise
`RAISE(ABORT, …)`, so evidence rows cannot be deleted while the triggers exist. Deleting a
project directory while its evidence rows remain makes `verify` report `artifact_unreadable`.

## 9. Acceptance reruns

Run from the repository root with the project interpreter; each script writes into `reports/`.

```powershell
$py = "D:\ADeespseekSH\REA\apk-research-platform\.venv\Scripts\python.exe"

& $py scripts\p0_check.py        # reports\p0\environment_report.md + model_api_check.json
& $py scripts\gate1_accept.py    # reports\gate1\acceptance.md + acceptance.json
& $py scripts\gate2_accept.py    # reports\gate2\...
& $py scripts\gate4_accept.py    # reports\gate4\...
& $py scripts\gate5_accept.py    # reports\gate5\...
& $py scripts\gate3_accept.py    # gate3 needs the live model endpoint
& $py -m pytest tests -q         # 111 tests, 100 s measured on this host
```

`scripts\platform.ps1 gates` runs `p0_check` and gates 1, 2, 4, 5 with `APKPLAT_MODEL_ENABLED=0`,
then prints the gate3 command. Every gate builds its own throwaway storage under `%TEMP%` and
points `APKPLAT_STORAGE`/`APKPLAT_REPORTS` there, so a rerun never touches `storage\`.

## 10. Residual risk on this host

From `reports/p0/environment_report.md`, deviation 4: no container isolation and no
seccomp/AppArmor sandbox, because the host is Windows without Docker/Podman. Compensating
controls, declared in `config/worker-policy.yml` and enforced by `toolchain.run()`: argument
vectors only; an executable allow-list (`java.exe`, `aapt2.exe`, `adb.exe`, `node.exe` — anything
else raises `ToolError("tool_not_allowed")` before spawn); `cwd` pinned inside `storage/`; a
wall-clock timeout capped at 900 s that kills the whole process tree (`taskkill /PID … /T /F`);
output capped at 16 MB; a child env whitelist dropping `DSH_*`, `KEY`, `SECRET`, `TOKEN`,
`PASSWORD`. The API binds `127.0.0.1`; workers write only inside their own project subtree.
