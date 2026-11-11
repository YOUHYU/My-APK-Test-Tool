# Architecture

Everything below is taken from the code in this repository. File references are
relative to the repo root; constants, paths and error codes are quoted verbatim.

## 1. Processes on this host

| Process | Launched by | Owns | Notes |
| --- | --- | --- | --- |
| HTTP API | `python scripts\apkplat_cli.py serve` | FastAPI app from `backend/apkplat/api/app.py`, bound to `127.0.0.1:8765` | `uvicorn.run(create_app(), settings.host, settings.port, log_level="info")`; title `APK Research Platform`, version `1.0.0`; OpenAPI at `/api/openapi.json`, Swagger at `/api/docs`. Startup runs `settings.ensure_dirs()` then `db.migrate()`; the applied migration names are returned by `GET /api/health`. |
| Worker(s) | `python scripts\apkplat_cli.py worker --kinds ... --once` | `backend/apkplat/worker.py` | The API process never executes jobs. A worker claims rows from the `jobs` table, holds a lease, and calls one of four handlers: `static_pipeline`, `report_generate`, `agent_orchestrate`, `dynamic_analysis`. |
| MCP server | DSH NEXT, per `config/dsh-mcp.registration.yml` / `dsh-plugin/` | `mcp-server/mcp_server/server.py` | Newline-delimited JSON-RPC 2.0 on stdin/stdout, protocol `2024-11-05`, 16 whitelisted tools. See `docs/mcp.md`. |
| SQLite | opened inside every process | `storage/platform.db` (+ `-wal`, `-shm`) | WAL, `synchronous=NORMAL`, `foreign_keys=ON`, `busy_timeout=30000`, one writer connection per process, outer transactions issued as `BEGIN IMMEDIATE`. |

`backend/apkplat/db.py` states the invariant in its module docstring: "The database
is the single source of truth for project/task/queue state. No worker holds state
in memory that cannot be rebuilt from these tables." A worker restart calls
`queue_service.reclaim_expired()`, so killing every process loses nothing but the
tasks that were mid-execution.

The UI is static: `frontend/dist/{index.html,app.js,styles.css}`. When that
directory exists, `create_app()` mounts it at `/static` and returns `index.html`
from `/`.

## 2. Operator-provided dependencies (not installed or reconfigured here)

| Dependency | Identity on this host | How this project uses it |
| --- | --- | --- |
| DSH NEXT | `0.2.1-rc.4`, profile `C:\Users\YHY\.dsh\profiles\desktop\cordis.patch.yml` | Loads the MCP server as a subprocess. The platform ships the registration fragment (`config/dsh-mcp.registration.yml`, `dsh-plugin/cordis.patch.yml`); it does not install or patch DSH. |
| Remote model API | `http://192.168.43.1:8788/v1`, model `deepseek-v4.1-flash` | `backend/apkplat/llm.py` is a client only. `resolve()` prefers `APKPLAT_MODEL_BASE_URL`, else probes `http://127.0.0.1:8788/v1`, else falls back to the LAN candidate `http://192.168.43.1:8788/v1`; the key comes from `APKPLAT_MODEL_API_KEY`, else `~/.dsh/.credentials.yaml` (`WB_PROXY_API_KEY`, `APKPLAT_MODEL_API_KEY`, `DEEPSEEK_API_KEY`). |
| Python runtime | `3.13.12` at `.venv\Scripts\python.exe` | Virtualenv inside the repo; nothing global is installed. |

`reports/p0/environment_report.md` records this explicitly: "No DSH component,
model, proxy, DNS or API setting was installed, reconfigured or restarted to
produce this report"; the whole toolchain lives inside
`apk-research-platform/tools/` and is removable as a directory.

## 3. Portable toolchain under `tools/`

| Path | Purpose | Version seen at runtime |
| --- | --- | --- |
| `tools/jdk/bin/java.exe` | runs jadx and apktool | `openjdk 21.0.13 2026-10-20 LTS` |
| `tools/jadx/lib/jadx-1.5.6-all.jar`, `tools/jadx/bin/jadx.bat` | Java decompiler | `1.5.6` (`_jadx_entrypoint()` probes `jadx.cli.JadxCLI`, then `jadx.cli.JADXMain`) |
| `tools/apktool/apktool.jar` | resource decode | `3.0.3` |
| `tools/android-sdk/build-tools/34.0.0/aapt2.exe` | manifest/badging dumps | `2.19-10229193` |
| `tools/android-sdk/platform-tools/adb.exe` | device transport | present |
| `tools/node/node.exe` | available to tool runs | present |
| `tools/keystore/debug.keystore` | test APK signing | — |

`toolchain.paths()` returns these absolute paths; no tool is resolved through
`PATH` and no tool is invoked through a shell.

## 4. Storage layout

```
storage/
  platform.db, platform.db-wal, platform.db-shm   SQLite (WAL)
  secret.key                                      HMAC key for capability tokens
  tmp/                                            upload-<id>.apk staging, tool TEMP/TMP, jadx probe logs
  inbox/                                          MCP project_create staging (apk_path resolved here)
  projects/<project_id>/
    inputs/quarantine/<name>  ->  inputs/base-<sha256[:12]>.apk
    manifests/manifest.json
    artifacts/  indexes/  evidence/  logs/  reports/
```

`util.project_layout(project_id)` creates all seven subdirectories and returns
them as `{base, inputs, manifests, artifacts, indexes, evidence, logs, reports}`.
What actually lands where:

| Directory | Contents | Written by |
| --- | --- | --- |
| `inputs/` | `quarantine/<safe_segment(filename)>` during ingest, then `base-<sha256[:12]>.apk`; the original file is copied, never moved | `services/projects.py:create` |
| `manifests/` | `manifest.json`: `validation` block plus `ingest {filename, sha256, bytes, ingested_at}` — written at ingest, before any tool runs | `services/projects.py:create` |
| `artifacts/` | `validation.json`, `extracted/` (unzipped APK), `apktool/` (decoded resources + binary manifest), `jadx/` (`sources/`, res), `facts.json`, `findings.json`, `static_summary.json`, `device.json`, `install.txt`, `launch.txt`, `logcat.txt`, `screenshot.png`, `cleanup.json`, `mcp/<tool>-<ts>-<pid>.json` | static pipeline, dynamic layer, MCP spill |
| `indexes/` | `index.db`: per-project SQLite with FTS tables for code, strings, resources, components | `indexer.build()` |
| `evidence/` | Directory reserved by the layout; evidence rows themselves live in the `evidence` table, not here | `util.project_layout` only |
| `logs/` | `apktool.stdout.log`, `apktool.stderr.log`, `jadx.stdout.log`, `jadx.stderr.log`, `aapt2.<what>.{stdout,stderr}.txt`, `dynamic.log` (one JSON line per dynamic step) | `toolchain.run()`, `dynamic.py` |
| `reports/` | `report-<YYYY-MM-DDTHH-MM-SS>.md` — the evidence appendix report | `reports.generate()` |

Repo-level `reports/` (separate from per-project reports) holds the P0 and gate
acceptance records: `reports/p0/environment_report.md`,
`reports/gate1..gate5/acceptance.{md,json}`.

## 5. Data model (`migrations/001_init.sql`)

Conventions from the file header: `TEXT` UUID-style ids, `TEXT` ISO-8601 UTC
timestamps, `INTEGER` counters/booleans, JSON stored as `TEXT`.

| Table | Purpose | Key columns |
| --- | --- | --- |
| `counters` | monotonic sequence source (audit `seq`) | `name` (PK), `value` |
| `projects` | one row per ingested APK | `id`, `name`, `apk_sha256`, `apk_filename`, `package_name`, `status`, `policy_id` (default `'default'`), `goal`, `ground_truth`, `blocked_reason` |
| `artifacts` | every file the platform produced and can cite | `id`, `project_id`, `task_id`, `kind`, `rel_path`, `sha256`, `bytes`, `tool`, `tool_version` |
| `tasks` | Kanban cards / work units | `id`, `project_id`, `parent_task_id`, `role`, `title`, `status`, `priority` (5), `depends_on`, `progress`, `lease_owner`, `lease_expires_at`, `attempt`, `version` (1), `model_calls`, `tool_calls`, `evidence_count`, `error_code`, `error_message`, `retryable` (1), `needs_approval` |
| `agent_runs` | one row per agent/model invocation | `id`, `project_id`, `task_id`, `role`, `dsh_session_ref`, `model_id`, `started_at`, `ended_at`, `status`, `notes` |
| `evidence` | quoted proof, tied to an artifact | `id`, `project_id`, `task_id`, `kind`, `artifact_id`, `locator`, `excerpt`, `excerpt_hash`, `claim`, `confidence`, `created_by` |
| `audit_events` | append-only event log | `id`, `seq`, `project_id`, `task_id`, `event_type`, `actor`, `payload_json`, `created_at` |
| `devices` | known ADB targets | `id`, `serial_alias`, `adb_serial`, `type`, `capabilities`, `health`, `last_seen` |
| `device_leases` | exclusive device ownership | `id`, `project_id`, `task_id`, `device_id`, `owner`, `expires_at`, `heartbeat_at`, `released_at` |
| `approvals` | human gate records | `id`, `project_id`, `task_id`, `kind`, `requested_by`, `reason`, `decision`, `decided_by`, `decided_at` |
| `jobs` | durable outbox | `id`, `kind`, `payload_json`, `status`, `idempotency_key`, `priority`, `attempt`, `max_attempts` (3), `lease_owner`, `lease_expires_at`, `heartbeat_at`, `available_at`, `error_code`, `result_json` |
| `model_requests` | one row per model HTTP call | `id`, `project_id`, `task_id`, `model_id`, `purpose`, `status`, `http_status`, `latency_ms`, `prompt_tokens`, `output_tokens`, `error_type` |

Indexes: `UNIQUE ix_jobs_idem (idempotency_key)`, `ix_jobs_claim
(status, available_at, priority)`, `ix_tasks_project (project_id, status)`,
`ix_evidence_project`, `ix_audit_seq`, `ix_audit_project (project_id, seq)`,
`ix_artifacts_project (project_id, kind)`, `ix_leases_device (device_id,
released_at)`, `ix_model_req_task`.

`migrations/002_audit_appendonly.sql` adds four `BEFORE UPDATE`/`BEFORE DELETE`
triggers — `trg_audit_events_no_update`, `trg_audit_events_no_delete`,
`trg_evidence_no_update`, `trg_evidence_no_delete` — that `RAISE(ABORT, ...)` with
messages such as `audit_events is append-only: UPDATE is forbidden` and `evidence
is immutable: re-record instead of editing`. History cannot be rewritten by a stray
migration, a manual sqlite session, or a future refactor; correcting evidence means
recording a new row.

## 6. Task state machine (`backend/apkplat/state.py`)

Twelve statuses map onto four Kanban columns via `COLUMN_OF`:

| Status | Column | Notes |
| --- | --- | --- |
| `TODO` | TODO | created state; also the fallback for unknown statuses |
| `RETRYING` | TODO | job will be retried, work item returns to the backlog |
| `STALE` | TODO | lease lost / stale worker |
| `RUNNING` | RUNNING | |
| `WAITING_MODEL` | RUNNING | blocked on the model API |
| `WAITING_DEVICE` | RUNNING | blocked on a device lease |
| `WAITING_APPROVAL` | RUNNING | blocked on a human decision |
| `BLOCKED` | RUNNING | |
| `REVIEW` | REVIEW | the only state that can be approved into `DONE` |
| `FAILED` | REVIEW | surfaced for a human, not silently dropped |
| `DONE` | DONE | terminal |
| `CANCELLED` | DONE | terminal |

`TRANSITIONS` is an explicit adjacency map (`DONE` and `CANCELLED` have empty
successor sets; `REVIEW -> {DONE, RUNNING, BLOCKED, FAILED, CANCELLED}`;
`RUNNING -> {REVIEW, DONE, FAILED, BLOCKED, CANCELLED, RETRYING, STALE,
WAITING_MODEL, WAITING_DEVICE, WAITING_APPROVAL}`; and so on).

Guards are layered on top of adjacency:

- `GUARDED_TARGETS = {"DONE": {"human","reviewer"}, "CANCELLED":
  {"human","reviewer"}, "BLOCKED": {"human","reviewer","agent","system"}}` — an
  `agent` actor can set `BLOCKED` but can never set `DONE` or `CANCELLED`.
- `APPROVABLE_FROM = {"REVIEW"}` — an approved approval lets an otherwise-guarded
  actor through only when the task is currently in `REVIEW`. A task in `RUNNING`
  cannot be approved straight to `DONE`; it has to pass through `REVIEW` first.
- `validate_transition()` raises `TransitionError` with codes `unknown_status`,
  `illegal_transition` (`"%s -> %s is not allowed (allowed: %s)"`) and
  `approval_required` (`"actor %r may not move a task to %s without human
  approval"`, plus `" (only from ['REVIEW'])"` when the target is guarded but the
  state is not approvable).
- `services/tasks.py:update()` additionally raises
  `TransitionError("approval_missing", ...)` unless the supplied `approval_id`
  exists with `decision = "approved"`, and enforces optimistic concurrency on
  `expected_version` (`TaskConflict` → 409 `version_conflict`).

Agents therefore cannot close work: `agents.py` leaves the static and report tasks
in `REVIEW` and comments that "No agent can put a task in DONE".

## 7. Job queue (transactional outbox, `services/queue.py` + `worker.py`)

1. `enqueue(kind, project_id=..., task_id=..., payload=..., idempotency_key=...)`
   inserts `status=PENDING`, `attempt=0`, `available_at=now(+delay)`. If the
   `idempotency_key` already exists it returns the existing job id unchanged — the
   `UNIQUE ix_jobs_idem` index is the dedupe point. Keys in use:
   `static:{project_id}`, `agents:{project_id}:{nonce|default}`,
   `dynamic:{project_id}:{task_id|default}`.
2. `claim(worker_id, kinds, lease_seconds)` runs inside `BEGIN IMMEDIATE`: it picks
   one row with `status IN ('PENDING','RETRYING')`, matching kinds,
   `available_at <= now`, ordered by `priority, available_at, created_at`, flips it
   to `RUNNING`, sets `lease_owner`/`lease_expires_at`, and increments `attempt`.
   The `UPDATE` repeats the status predicate, so two workers cannot both win.
3. A daemon thread in the worker sends `heartbeat()` every `max(5, lease//3)`
   seconds, extending `lease_expires_at` during multi-minute jadx runs.
4. `fail()` computes `backoff = min(5 * 2**max(attempt-1, 0), 300)` seconds and sets
   `RETRYING` with `available_at = now + backoff`, or `FAILED` when
   `attempt >= max_attempts` (default 3) or the failure is not retryable.
   `worker.RETRYABLE_CODES` = `timeout, jadx_timeout, apktool_timeout, tool_missing,
   project_missing, lease_lost, zip_locked, os_error, device_unavailable,
   dynamic_timeout`.
5. On start, every worker calls `reclaim_expired()`: rows still `RUNNING` with
   `lease_expires_at < now` go back to `RETRYING` (or `FAILED` when the attempt
   budget is spent) with `error_code = "lease_expired"` and
   `error_message = "worker <owner> stopped heartbeating"`.
6. `attach_task(job_id, task_id)` binds a job to the task its handler created. The
   comment names the failure it prevents: without it a job row keeps `task_id`
   NULL, a later failure cannot mark the task it just created, and the card sits in
   `RUNNING` forever. `worker._fail()` re-reads the job precisely because a handler
   may have attached a task mid-flight.

## 8. Static pipeline — seven stages (`pipeline_static.py`)

| # | Stage | Work | Artifacts produced (kind) | Failure behaviour |
| --- | --- | --- | --- | --- |
| 1 | validate + extract | `apkfile.validate_apk()` (stdlib only), then `safe_extract()` into `artifacts/extracted` | `artifacts/validation.json` (`validation`), `logs/*` for later stages | `StageError("validate", <apk error code>)` before any tool runs |
| 2 | apktool decode | `toolchain.apktool_decode(..., no_src=True)` | `artifacts/apktool/`, `logs/apktool.stdout.log`, `logs/apktool.stderr.log` (`tool_stdout`/`tool_stderr`, tool `apktool` 3.0.3) | hard fail `StageError("apktool","apktool_failed")` only when exit≠0 **and** `artifacts/apktool/AndroidManifest.xml` is missing; partial decode is tolerated |
| 3 | jadx decompile | `toolchain.jadx_decompile()` into `artifacts/jadx` | `artifacts/jadx/sources/`, `logs/jadx.stdout.log`, `logs/jadx.stderr.log` (tool `jadx` 1.5.6) | `StageError("jadx","jadx_failed"|"jadx_timeout")` |
| 4 | metadata | androguard `parse_metadata()` + `dex_inventory()` + tool exit codes | `artifacts/facts.json` (`metadata`, tool `androguard` 4.1.4) | `StageError` |
| 5 | inventory | dex string literals + source scan for URLs and secret-shaped literals (`SECRET_RES`: aws/google keys, generic secrets, named credential literals, prefixed keys, bearer tokens, private-key blocks) | `artifacts/findings.json` (`findings`, tool `apkplat.scan`), max 200 URLs / 100 secrets | non-fatal |
| 6 | index build | `indexer.build()` → per-project FTS database | `indexes/index.db` (`index`, tool `apkplat.indexer`) | `StageError` |
| 7 | evidence | one row per fact, excerpt quoted verbatim from the artifact; `manifest_fact`, `permission`, `network_endpoint`, `secret_candidate` | `evidence` rows + `artifacts/static_summary.json` (`summary`, tool `apkplat.static`) | a fact whose excerpt cannot be located is skipped, never paraphrased |

On completion the project status becomes `ANALYZED`; the summary records
`apktool/jadx` exit codes, `java_files`, index stats and `evidence_ids`. The
Markdown report (`reports.generate()`) is a separate step: `report_generate` job or
`POST /api/projects/{id}/report`, producing `reports/report-<stamp>.md` with ten
sections (校验结果 / 身份信息 / 权限 / 组件 / 网络端点 / 疑似密钥字面量 / 代码索引 /
无证据的断言 / 复现步骤 / 证据附录). The P3 surface adds ten more sections (摘要 /
能力覆盖矩阵 / 任务依赖图 / 关键时间线 / 类型化证据链 / 媒体与抓包会话 / 电脑端与真机
结果 / 无法核验的条目 / 审查意见 / 脚本与构建产物) plus an HTML twin (`report.html`).

## 9. Evidence and verification

- `artifacts.register()` refuses any path outside the project root
  (`"outside project root"`), stores `sha256`+`bytes`, and keeps one row per
  `(project, rel_path)` — re-registering refreshes hash and tool in place so
  evidence that cites the artifact id keeps resolving.
- `evidence.record()` requires a non-empty `locator` object, an `artifact_id` that
  belongs to the same project (`"artifact belongs to a different project (isolation
  violation blocked)"`), a non-empty excerpt (CRLF normalised, max 4000 chars,
  `sha256` stored), and a claim of at least 8 characters. Empty quotation is
  rejected with "an unquoted assertion is not evidence".
- `GET /api/projects/{id}/verify` runs `verify_chain()` (recomputes every artifact
  hash; failures `missing_file`, `hash_mismatch`) and `evidence.verify()` (failures
  `dangling_artifact`, `cross_project_artifact`, `excerpt_hash_mismatch`,
  `artifact_unreadable`, `excerpt_not_found_in_artifact`) and reports
  `traceability_rate`.

## 10. Sandboxing actually implemented

No container on this host — the controls are in-process and filesystem-level
(`backend/apkplat/toolchain.py`):

- **Environment whitelist.** `child_env()` copies only `SystemRoot, SystemDrive,
  windir, TEMP, TMP, PATHEXT, COMSPEC, NUMBER_OF_PROCESSORS,
  PROCESSOR_ARCHITECTURE, LOCALAPPDATA, USERPROFILE, HOMEDRIVE, HOMEPATH`, then sets
  `JAVA_HOME=tools/jdk`, `ANDROID_HOME`/`ANDROID_SDK_ROOT=tools/android-sdk` and a
  fixed `PATH` of `jdk/bin;platform-tools;node`. Any extra key containing `DSH_`,
  `KEY`, `SECRET`, `TOKEN` or `PASSWORD` is dropped. The model API key therefore
  never reaches java, jadx, apktool or adb.
- **Working directory pin.** `run()` refuses to start a tool whose `cwd` is not
  under `storage` — `ToolError("cwd_outside_storage", "refusing to run a tool with
  cwd=... outside storage")`.
- **argv only, no shell.** Commands are lists; there is no string interpolation
  path into a shell, and `stdin` is `DEVNULL`.
- **Wall-clock timeout with tree kill.** `timeout` is mandatory; on
  `TimeoutExpired` the process tree is killed with `taskkill /PID <pid> /T /F`
  (`CREATE_NEW_PROCESS_GROUP` on Windows, `start_new_session` elsewhere), then the
  runner waits 15 s. The result carries `timed_out=True`,
  `error_code="timeout"`, `error_message="killed after <n>s"`.
- **Output caps.** stdout/stderr go straight to files; jadx and apktool are capped
  at 4 MB (default 16 MB) and the tail is replaced with `"... [truncated by apkplat
  output cap]"`.
- **Network exposure.** The API binds `127.0.0.1` and CORS allows only
  `http://127.0.0.1`, `http://localhost` and `settings.public_base_url`, with a
  regex for loopback ports.
- **Project isolation.** Every artifact path must resolve inside
  `storage/projects/<id>`; the index is a separate SQLite file per project, not a
  filtered shared table; MCP refuses a `project_id` outside `APKPLAT_MCP_PROJECTS`
  before opening the database.

## 11. Multi-agent layer (`agents.py`)

| Role | Constant | Responsibility |
| --- | --- | --- |
| orchestrator | `ROLE_ORCHESTRATOR` | creates the three tasks and drives the run |
| static | `ROLE_STATIC` | reuses or produces the static artefacts, may draft a narrative |
| reviewer | `ROLE_REVIEWER` | runs the evidence gate and the advisory model pass |
| reporter | `ROLE_REPORTER` | renders the Markdown report with citations filtered to known evidence ids |

The gate is deterministic and runs **before** the model sees anything. For each
claim, in this order: missing `evidence_id` → `no_evidence`; id not among the
project's evidence rows → `evidence_unknown`; row's `project_id` differs from the
requested project → `evidence_cross_project`; id listed in a failed verification →
`excerpt_not_verifiable`; otherwise accepted.

Only after that, and only if the model is enabled and a key resolved, the accepted
claims (first 12, excerpts truncated to 500 chars) go to `_REVIEW_SYSTEM`, which
must answer `{"verdicts":[{evidence_id, supported, reason}]}`. A
`supported=false` verdict degrades the claim to rejected with
`reason = "model_veto:<reason>"`. The model can subtract trust and can never add
it. Every rejection writes `review_returned_no_evidence` (the
`false_confident_claims` metric) and one `review_completed` event records the
counts. A rejected review moves the task back to `RUNNING` with
`error_code="review_no_evidence"`; an accepted run leaves tasks in `REVIEW`, where
only a human or a reviewer can move them to `DONE`.

## 12. Dynamic layer (`dynamic.py`)

Transports: `AdbTransport` (spawns `adb -s <serial> ...` under `child_env()` and
`CREATE_NO_WINDOW`, timeout `settings.dynamic_step_timeout`) and `SimTransport`
(deterministic simulator; optional `unplug_at` substring to inject device loss).
`make_transport()` accepts only `adb` or `sim`.

A run takes a single-device lease first (`devices.acquire`); `LeaseConflict` puts
the task in `WAITING_DEVICE`, audits `device_wait` and fails the job as retryable
`device_unavailable`. Then five steps, each heartbeating the lease and appending a
JSON line to `logs/dynamic.log`:

| Step | Command | Artifact | Evidence |
| --- | --- | --- | --- |
| `probe` | `getprop` | `artifacts/device.json` (`device_probe`) | `device_fact` |
| `install` | `adb install -r -g` | `artifacts/install.txt` (`device_install`) | `install_result` |
| `launch` | `am start -W -n <pkg>/<activity>` | `artifacts/launch.txt` (`device_launch`) | `launch_result` |
| `observe` | `sleep dynamic_observe_seconds`, `logcat -d -t <tail>` | `artifacts/logcat.txt` (`device_logcat`) | `runtime_log`, confidence `medium` |
| `screenshot` | `screencap -p /sdcard/apkplat/screen.png` + `adb pull` | `artifacts/screenshot.png` (`device_screenshot`) | — (failure is recorded as `skipped`, not fatal) |

Cleanup runs in `finally`: `am force-stop`, `pm uninstall`, `rm -rf
/sdcard/apkplat`, then `ls /sdcard/apkplat` — a non-zero exit proves removal, and
`cleanup.json` (`device_cleanup`) records `verified` with the audit event
`dynamic_cleanup_verified` or `dynamic_cleanup_incomplete`. The lease is released
in a nested `finally` (`completed`/`failed`).

Device loss: `AdbTransport` maps outputs matching `device offline`, `device not
found`, `no devices/emulators found`, `error: closed`, `device unauthorized`,
`cannot connect to`, `more than one device` onto `DeviceLost`. The run audits
`device_lost` with `steps_done`, marks cleanup `verified=false` and reason "device
unreachable; cleanup deferred to the device pool", and raises
`DynamicError("device_lost", retryable=False)` — so the job fails rather than
retrying into the same missing device.

## 13. MCP server

`mcp-server/mcp_server/server.py` is stdlib-only. Transport: newline-delimited
JSON-RPC 2.0 over stdin/stdout, protocol `2024-11-05`, diagnostics on stderr only.
Methods implemented: `initialize`, `ping`, `tools/list`, `tools/call`,
`resources/list` (empty), `prompts/list` (empty); unknown methods return `-32601`,
malformed JSON `-32700`. Sixteen tools, no shell tool, no arbitrary file read.
Every `tools/call` returns the same envelope (`ok, project_id, task_id, tool,
tool_version, started_at, duration_ms, stdout_artifact_id, stderr_artifact_id,
produced_artifact_ids, error_code, retryable, request_id`); a payload over
`INLINE_MAX_BYTES = 24*1024` is written to
`storage/projects/<id>/artifacts/mcp/<tool>-<ts>-<pid>.json`, registered as kind
`mcp_result`, and replaced by `{spilled, artifact_id, bytes, preview, hint}`.
Each call appends an `mcp_tool_call` audit event carrying `schema_ok`. Details and
the DSH registration snippet: `docs/mcp.md`.

## 14. What this host cannot do

`reports/p0/environment_report.md` lists four deviations; the first is the one that
matters for safety.

| Missing capability | Substituted with | Residual risk |
| --- | --- | --- |
| Container isolation (no Docker/Podman; installing one needs a kernel driver change and a reboot) | argv-only tool runs, `child_env()` whitelist, `cwd` pinned inside `storage`, mandatory wall-clock timeout with process-tree kill, output caps, 4 MB/16 MB truncation, API bound to loopback, per-project subtrees | A malicious APK is processed by the same user account as the platform; jadx/apktool parse hostile input in-process-tree without a kernel boundary. Hostile input is rejected before any tool runs (`validate_apk`: zip bomb, zip slip, encrypted entries, >200 000 entries, >512 MB upload, >2 GB unzipped, corrupt dex, non-Android manifest), which narrows but does not eliminate the surface. |
| seccomp / AppArmor | none | No syscall filtering; "Linear JADX/Apktool" is named as residual risk in the P0 report |
| PostgreSQL | SQLite in WAL mode; DDL kept portable and `db.Database` switches on `APKPLAT_DB_URL` | Single writer; `APKPLAT_STATIC_WORKERS` defaults to 2 and the busy timeout is 30 s, so heavy concurrent writes serialise |
| Redis / external broker | the `jobs` table is the broker (leases, heartbeats, crash recovery, idempotency) | No cross-host workers; recovery granularity is one lease |

## 15. Entry points and configuration

`scripts/apkplat_cli.py` is the operator surface and uses the same service layer as
the API and the MCP server: `init`, `versions`, `create`, `list`, `show`, `verify`,
`report`, `search`, `method`, `packages`, `evidence`, `board`, `queue --reclaim`,
`job-reset`, `dynamic`, `worker`, `serve`.

Settings come from `backend/apkplat/config.py` (env var → default):
`APKPLAT_DB_URL` → `sqlite:///<storage>/platform.db`; `APKPLAT_HOST` `127.0.0.1`;
`APKPLAT_PORT` `8765`; `APKPLAT_STORAGE`, `APKPLAT_TOOLS`, `APKPLAT_REPORTS`;
`APKPLAT_STATIC_WORKERS` `2`; `APKPLAT_MODEL_CONCURRENCY` `1`;
`APKPLAT_JOB_LEASE_SECONDS` `300`; `APKPLAT_DEVICE_LEASE_SECONDS` `900`;
`APKPLAT_MAX_UPLOAD_MB` `512`; `APKPLAT_MAX_UNZIPPED_MB` `2048`;
`APKPLAT_REQUIRE_AUTH` `true`; `APKPLAT_TOKEN_TTL` `12*3600`;
`APKPLAT_JADX_TIMEOUT` `900`; `APKPLAT_APKTOOL_TIMEOUT` `900`;
`APKPLAT_JADX_HEAP` `-Xmx1200m`; `APKPLAT_MODEL_TIMEOUT` `180`;
`APKPLAT_DYNAMIC_TRANSPORT` `adb`; `APKPLAT_DYNAMIC_STEP_TIMEOUT` `120`;
`APKPLAT_DYNAMIC_OBSERVE_SECONDS` `5`; `APKPLAT_DYNAMIC_LOG_TAIL` `400`;
`APKPLAT_MCP_PROJECTS` `*`; `APKPLAT_MCP_ACTOR` `dsh-agent`.
`Settings` also carries `seccomp: bool = False` with the comment "windows host: no
seccomp/AppArmor, documented deviation".
