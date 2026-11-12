# API reference

Generated from `backend/apkplat/api/app.py` (632 lines, `create_app()`), the
service layer it calls, and `mcp-server/mcp_server/server.py`. Nothing here is
aspirational: a route appears only if it is registered in that file.

## Conventions

| Item | Value |
| --- | --- |
| Base URL | `http://127.0.0.1:8765` (`APKPLAT_HOST`, `APKPLAT_PORT`) |
| Content types | `application/json` except file upload (`multipart/form-data`), `/download` (binary) and `/api/events/stream` (`text/event-stream`) |
| Timestamps | `YYYY-MM-DDTHH:MM:SS.mmmZ` (`db.utcnow()`) |
| Id prefixes | `prj_` project, `tsk_` task, `run_` agent run, `apr_` approval, `art_` artifact, `evd_` evidence, `ev_` audit event, `job_` job, `dev_` device, `lea_` lease, `mdl_` model request, `tok_` token id |
| Success codes | `200` reads/updates, `201` creations, `202` enqueued jobs |
| OpenAPI | `/api/openapi.json`, Swagger UI `/api/docs`, ReDoc `/redoc` (FastAPI defaults for the two unset URLs) |

### Auth modes

`security.claims_for()` has exactly two modes, reported by `GET /api/health` as
`auth_mode`:

| Mode | When | Behaviour |
| --- | --- | --- |
| `token` (default) | `APKPLAT_REQUIRE_AUTH` unset/`1` | `Authorization: Bearer v1.<b64url payload>.<b64url hmac>`; the token names `prj` (project ids) and `scp` (`read`/`write`/`admin`). Missing header → 401 `missing_token`; bad signature → 401 `bad_signature`; expired → 401 `token_expired`; scope short → 403 `scope_denied`; project not listed → 403 `project_denied`. |
| `local` | `APKPLAT_REQUIRE_AUTH=0` | Every request is `{"sub":"local-operator","prj":["*"],"scp":["read","write","admin"]}`. |

Scope is enforced by `Depends(require("read"|"write"))`. Routes whose path contains
`{project_id}` also enforce the project allowlist; routes without it (`/api/tasks/{task_id}`,
`/api/artifacts/{artifact_id}`, `/api/evidence/{evidence_id}`, `/api/jobs/{job_id}/*`,
`/api/leases/{lease_id}/*`, `/api/approvals/{approval_id}/decide`, `/api/devices*`,
`/api/queue`) check the scope only.

Admin scope is a separate header: `POST /api/auth/token` requires
`X-Admin-Secret: <hex of settings.signing_secret()>` (`storage/secret.key`, or
`APKPLAT_SECRET`). In local mode the guard returns early unless
`APKPLAT_ALLOW_LOCAL_TOKEN=0`.

### Part 5 - project control: pause / resume / stop (`control_api.py`)

Every project carries a dispatch state (`projects.run_state`): `RUNNING` (default), `PAUSED`, `STOPPED`.

| Method | Path | Body | Notes |
| --- | --- | --- | --- |
| GET | `/api/projects/{id}/control` | - | `{project_id,name,run_state,changed_at,reason,jobs:{pending,running,cancelled,cancel_requested},tasks:{running,waiting,unfinished},live_runs,accepting_work}` |
| POST | `/api/projects/{id}/control` | `{action, reason?}` | `action` ∈ `pause` / `resume` / `stop`; idempotent, returns `{ok,changed,state}` |
| POST | `/api/projects/{id}/command` | `{text}` | Natural-language-ish operator command; returns `{ok,handled,message,state}` |

What each action does, and does **not** do:

- **pause** - `queue.claim()` joins `projects` and skips rows whose `run_state` is not `RUNNING`, so no new job is dispatched. A job already running is **not** killed: it finishes and lands its normal result. Killing mid-pipeline leaves half a set of artifacts, which is worse than a slower answer.
- **resume** - dispatch starts again. It does **not** resurrect jobs that `stop` cancelled; that is `POST /api/projects/{id}/resume` (`services/recovery.py`, "恢复未完成的工作"), which re-enqueues unfinished cards.
- **stop** - cancels pending jobs (`jobs.status=CANCELLED`), sets `jobs.cancel_requested=1` on running ones (cooperative: the handler checks at stage boundaries and raises `control.JobCancelled`), revokes live run capabilities, closes open `agent_runs` rows, and moves non-terminal cards to `CANCELLED`.
- **switching project in the UI is a view change only** - it issues no control request, so nothing that is running gets disturbed. This is asserted by `tests/integration/test_control_surface.py::test_switching_projects_does_not_disturb_running_work`.

Commands understood by `/command` (Chinese or English): `暂停`/`pause`, `继续`/`resume`, `停止`/`stop`, `状态`/`status`, `重试 <card-id|标题>`, `取消 <card-id>`, `恢复未完成`/`recover`, `help`.

Errors: `unknown_action` 422, `project_not_found` 404, `project_stopped` 409 (pause on a stopped project), `task_project_mismatch` 403 (a card that belongs to another project).

## Error shapes — flat vs nested

| Source | Status | Body |
| --- | --- | --- |
| APK validation failure on upload (`ApkError` handler, returns `JSONResponse` directly) | 422 | flat: `{"error_code": "not_a_zip", "message": "..."}` |
| `TransitionError` handler | 409 | flat: `{"error_code": "illegal_transition", "message": "RUNNING -> DONE is not allowed (allowed: [...])"}` |
| `TaskConflict` handler | 409 | flat: `{"error_code": "version_conflict", "message": "..."}` |
| `EvidenceError` handler | 422 | flat: `{"error_code": "evidence_rejected", "message": "..."}` |
| `LeaseConflict` handler (also audits `lease_collision_blocked`) | 409 | flat: `{"error_code": "lease_conflict", "message": "..."}` |
| `StageError` handler | 500 | flat plus extra keys: `{"error_code", "message", "stage", "detail"}` |
| Any `HTTPException` (404s, 401/403 auth, 413 upload, 410 artifact bytes) | varies | nested: `{"detail": {"error_code": "...", "message": "..."}}` |

Consequence for clients: read `body.error_code` for domain failures and
`body.detail.error_code` for transport failures. `error_code` values emitted:
`missing_token`, `bad_token`, `bad_signature`, `token_expired`, `scope_denied`,
`project_denied`, `admin_denied`, `projects_required`, `wildcard_forbidden`,
`upload_too_large`, `project_not_found`, `task_not_found`, `artifact_not_found`,
`artifact_bytes_missing`, `evidence_not_found`, plus every `ApkError` code
(`missing_file`, `apk_too_small`, `apk_too_large`, `not_a_zip`, `corrupt_zip`,
`too_many_entries`, `encrypted_entry`, `zip_bomb`, `zip_slip`, `corrupt_dex`,
`missing_manifest`, `missing_dex`, `manifest_not_android`).

## System

| Method & path | Scope | Request | OK | Response | Errors |
| --- | --- | --- | --- | --- | --- |
| `GET /api/health` | none | — | 200 | `ok, version, uptime_seconds, auth_mode, migrations_applied[], db{url,ok,error}, storage{path,free_bytes,total_bytes}, queue{<status>:count}, audit_seq, concurrency{static_workers,model_concurrency,model_concurrency_source}, tools{java,jadx,apktool,aapt2,adb}` | — |
| `POST /api/auth/token` | admin | `{projects[], scopes[]=["read","write"], subject="agent", ttl}` | 200 | `{token, expires_at, claims{sub,prj,scp,iat,exp,jti}}` | 422 `projects_required`, `wildcard_forbidden`; 403 `admin_denied` |
| `GET /api/metrics` | read | — | 200 | `ingest_success_rate, ingest_attempts, tool_call_schema_valid_rate, tool_calls, evidence_traceability_rate, project_isolation_failures, device_lease_collision, task_recovery_success, reclaimed_leases, false_confident_claims, model_calls_per_task, model_api_latency_ms_avg, tasks_total, projects_total, generated_at` | — |
| `GET /api/events/stream` | read (query `token`) | `after=0`, `project_id`, `token` | 200 | SSE: `id: <seq>` + `data: <audit row json>` per event, `: keep-alive` after 15 idle seconds, 1 s poll | 401/403 as auth |
| `GET /api/queue` | read | `project_id`, `status` | 200 | `{stats{<status>:count}, jobs[]}` | — |
| `POST /api/jobs/{job_id}/cancel` | write | — | 200 | `{job}` | — |

## Projects

| Method & path | Scope | Request | OK | Response | Errors |
| --- | --- | --- | --- | --- | --- |
| `POST /api/projects` | write | multipart: `name` (req), `apk` file (req), `goal`, `ground_truth` (JSON string), `policy_id="default"`, `storage_root` (absolute directory, optional) | 201 | `{project, job_id}`; enqueues `static_pipeline` with key `static:{project_id}` | 413 `upload_too_large` (over `APKPLAT_MAX_UPLOAD_MB`=512); 422 flat `ApkError`; 422 `invalid_ground_truth` when the `ground_truth` form field is not JSON (validated before the upload is read); 422 `storage_root_not_absolute` / `storage_root_inside_storage` / `storage_root_not_a_directory` / `storage_root_not_empty` / `storage_root_unusable` |
| `GET /api/projects` | read | — | 200 | `{projects[]}` (limit 100); each row includes `storage_root` (absolute path or `null`) | — |
| `GET /api/projects/{project_id}` | read | — | 200 | `{project, manifest}` | 404 `project_not_found` |
| `GET /api/projects/{project_id}/board` | read | — | 200 | `{project, columns{TODO,RUNNING,REVIEW,DONE}, generated_at, approvals[]}`; each card carries `id,title,role,status,priority,progress,version,summary,evidence_count,model_calls,updated_at,depends_on,needs_approval,error_code` | 404 |
| `GET /api/projects/{project_id}/events` | read | `after=0`, `limit=200` | 200 | `{events[]}` (seq ascending) | 404 |
| `GET /api/projects/{project_id}/recovery` | read | — | 200 | `{project_id, unfinished, live_jobs, stalled, tasks[], jobs[]}`; `stalled=true` means cards are unfinished and no job is running | 404 |
| `POST /api/projects/{project_id}/resume` | write | — | 202 | `{ok, project_status, reclaimed[], live_jobs[], unfinished_tasks[], enqueued[]}`; reclaims expired leases, then re-publishes `static_pipeline` for every unfinished card without a live job (idempotency key `resume:<pid>:<task>:<seq>`) | 404 `project_not_found` |
| `GET /` and `/static/*` | none | — | 200 | `frontend/dist/index.html` and assets, mounted only when `frontend/dist` exists | — |

## Tasks and approvals

| Method & path | Scope | Request | OK | Response | Errors |
| --- | --- | --- | --- | --- | --- |
| `GET /api/projects/{project_id}/tasks` | read | `status`, `role` | 200 | `{tasks[]}` | 404 |
| `POST /api/projects/{project_id}/tasks` | write | `{title (req), role="static", goal, parent_task_id, depends_on[], priority=5, actor="agent", needs_approval}` | 201 | task row | 404; 422 `title_required` when `title` is empty or absent |
| `GET /api/tasks/{task_id}` | read | — | 200 | task row | 404 `task_not_found` |
| `PATCH /api/tasks/{task_id}` | write | `{status, expected_version, approval_id, reason, actor}` + any `EDITABLE_FIELDS` key (`title, goal, summary, progress, priority, depends_on, error_code, error_message, retryable, needs_approval, lease_owner, lease_expires_at`) | 200 | updated task row (version incremented) | 409 `version_conflict`; 409 transition (`illegal_transition`, `approval_required`, `approval_missing`); 422 `field_not_editable` (with the allowed `editable` list) for any key outside `EDITABLE_FIELDS` |
| `GET /api/tasks/{task_id}/runs` | read | `limit=100` | 200 | `{task_id, runs[]}` (oldest first) | 404 `task_not_found` |
| `POST /api/tasks/{task_id}/runs` | write | `{role="agent", model_id, dsh_session_ref, notes}` | 201 | `{run_id}` | 404 `task_not_found` (checked before the run row is written) |
| `POST /api/tasks/{task_id}/approvals` | write | `{kind="manual", requested_by="agent", reason}` | 201 | `{approval_id}` | 404 `task_not_found` |
| `POST /api/approvals/{approval_id}/decide` | write | `{decision: "approved"\|"rejected", decided_by="human", note}` | 200 | approval row | 422 `invalid_decision` when `decision` is neither `approved` nor `rejected`; 404 `approval_not_found` for an unknown id |

## Artifacts and evidence

| Method & path | Scope | Request | OK | Response | Errors |
| --- | --- | --- | --- | --- | --- |
| `GET /api/projects/{project_id}/artifacts` | read | `kind` (comma separated), `task_id` | 200 | `{artifacts[]}` (id, kind, rel_path, sha256, bytes, tool, tool_version) | 404 |
| `GET /api/artifacts/{artifact_id}` | read | — | 200 | artifact row | 404 `artifact_not_found` |
| `GET /api/artifacts/{artifact_id}/text` | read | `limit=20000` (100…2 000 000), `tail=false` | 200 | `{artifact_id, kind, sha256, bytes, text, truncated}`; text is redacted and clamped | 404 `artifact_not_found`; 410 `artifact_bytes_missing` |
| `GET /api/artifacts/{artifact_id}/download` | read | — | 200 | file bytes (`FileResponse`, original filename) | 404; 410 `artifact_bytes_missing` |
| `GET /api/projects/{project_id}/evidence` | read | `task_id`, `kind` | 200 | `{evidence[]}` | 404 |
| `POST /api/projects/{project_id}/evidence` | write | `{kind="note", locator (object, non-empty), excerpt (required), artifact_id, task_id, claim, confidence="medium" (low\|medium\|high), created_by=<token sub>}` | 201 | evidence row (`excerpt_hash` = sha256 of excerpt) | 404; 422 flat `evidence_rejected` |
| `GET /api/evidence/{evidence_id}` | read | — | 200 | evidence row | 404 `evidence_not_found` |

## Verification and reports

| Method & path | Scope | Request | OK | Response | Errors |
| --- | --- | --- | --- | --- | --- |
| `GET /api/projects/{project_id}/verify` | read | — | 200 | `{project_id, artifacts{checked,ok,failures[]}, evidence{total,failures[],traceability_rate}, ok, checked_at}` | 404 |
| `POST /api/projects/{project_id}/report` | write | `{task_id, actor="api"}` | 201 | `{project_id, report_path, artifact_id, evidence_rows, traceability_rate, verification_ok, markdown}` | 404 |

## Agents, review, dynamic

| Method & path | Scope | Request | OK | Response | Errors |
| --- | --- | --- | --- | --- | --- |
| `POST /api/projects/{project_id}/agents/run` | write | `{use_model, nonce}` | 202 | `{job_id, job}`; kind `agent_orchestrate`, key `agents:{project_id}:{nonce\|default}` | 404 |
| `GET /api/projects/{project_id}/agents/runs` | read | `limit=100` | 200 | `{runs[]}` | 404 |
| `GET /api/projects/{project_id}/agent-runs` | read | `limit=200` | 200 | `{project_id, runs[], count}` | 404 |
| `POST /api/projects/{project_id}/review` | write | `{task_id, claims[], use_model}`; claims default to the project's evidence | 201 | `{verdict ("accepted"\|"rejected"), accepted (int), rejected (list of {evidence_id, reason}), traceability}` | 404 |
| `POST /api/projects/{project_id}/dynamic/run` | write | `{task_id, title="Dynamic session", transport (adb\|sim), device_id, idempotency_key}` | 202 | `{task, job_id, job}`; creates a `role="dynamic"` task when `task_id` is omitted | 404 `task_not_found` |
| `GET /api/projects/{project_id}/dynamic/runs` | read | — | 200 | `{artifacts[] (kind starts with device_), leases[] (all), events[] (dynamic_* and device_* audit types)}` | 404 |

## Devices and leases

| Method & path | Scope | Request | OK | Response | Errors |
| --- | --- | --- | --- | --- | --- |
| `GET /api/devices` | read | — | 200 | `{devices[], leases[] (active only)}` | — |
| `POST /api/devices/register` | write | `{adb_serial (req), type="emulator", capabilities{}, alias}` | 201 | device row | 422 `adb_serial_required` when `adb_serial` is empty |
| `POST /api/projects/{project_id}/devices/lease` | write | `{task_id, owner="dynamic-worker", device_id, ttl}` | 201 | lease row | 409 flat `lease_conflict` |
| `POST /api/leases/{lease_id}/heartbeat` | write | `{owner, ttl}` | 200 | lease row | — |
| `POST /api/leases/{lease_id}/release` | write | `{owner, reason="released"}` | 200 | lease row | — |

## Code index probes

| Method & path | Scope | Request | OK | Response | Errors |
| --- | --- | --- | --- | --- | --- |
| `GET /api/projects/{project_id}/search` | read | `q` (required, min 1), `kind` (`class`\|`method`\|`field`), `limit=50` (1…500) | 200 | `{query, results[]}` | 404 |
| `GET /api/projects/{project_id}/packages` | read | — | 200 | `{packages[], stats}` | 404 |

### Framework-level error shapes

The five handlers above cover domain exceptions only. Three framework paths produce
bodies that are *not* the envelope above, and a client that blindly reads
`detail.error_code` will crash on them:

| Situation | Status | Body |
| --- | --- | --- |
| Unmatched path or method | 404 / 405 | `{"detail": "Not Found"}` — `detail` is a string |
| Request validation (missing multipart field, wrong query type) | 422 | `{"detail": [{"loc": [...], "msg": "...", "type": "..."}]}` — `detail` is a list |
| Any other uncaught Python exception | 500 | plain-text `Internal Server Error`, no JSON |

The named failure modes a caller is most likely to hit — missing `title`, a
non-editable PATCH key, an invalid approval decision, a missing `adb_serial`, a
malformed `ground_truth` blob, a run recorded against an unknown task — are
validated at the route and return the structured envelope instead
(`tests/integration/test_api_error_shapes.py` pins each one). What remains in the
500 row is genuinely unexpected: a bug, not bad input.

CORS: `allow_origins` is exactly `http://127.0.0.1`, `http://localhost`,
`settings.public_base_url`, plus the regex `http://(127\.0\.0\.1|localhost)(:\d+)?`;
credentials are not allowed. Browsers on any other origin get no CORS headers, so
the UI must be served from loopback (it is, from `frontend/dist`).

The SSE endpoint is a raw `StreamingResponse` with a manual `claims_for()` check —
it bypasses `Depends`, carries the token in the query string, and will buffer
behind a proxy that does not disable response buffering.

## MCP tools

Transport and envelope are documented in `docs/mcp.md`; the table below is the
argument surface enforced by `_validate()` (`additionalProperties: False` on every
schema, violations return `error_code = "schema_invalid"`).

| Tool | Required arguments | Optional arguments |
| --- | --- | --- |
| `project_create` | `name`, `apk_path` (relative to `storage/inbox`) | `goal`, `policy_id` |
| `project_get` | `project_id` | — |
| `apk_get_metadata` | `project_id` | — |
| `apk_list_packages` | `project_id` | `limit` (1…500) |
| `apk_search_code` | `project_id`, `query` | `kind` (`class`\|`method`\|`field`), `limit` (1…200) |
| `apk_read_method` | `project_id`, `class_name`, `method` | `max_lines` (1…2000) |
| `apk_read_manifest` | `project_id` | — |
| `apk_search_resources` | `project_id`, `query` | `limit` (1…200) |
| `artifact_list` | `project_id` | `kind`, `task_id`, `limit` (1…500) |
| `evidence_read` | `project_id` | `evidence_id`, `task_id`, `kind`, `limit` (1…500) |
| `evidence_record` | `project_id`, `kind`, `artifact_id`, `excerpt` | `locator`, `claim`, `confidence` (`low`\|`medium`\|`high`), `task_id` |
| `task_create` | `project_id`, `title` | `role` (`main`\|`static`\|`dynamic`\|`review`\|`report`), `goal`, `parent_task_id`, `priority` (0…9), `needs_approval` |
| `task_get` | `task_id` | — |
| `task_update` | `task_id` | `status`, `expected_version`, `approval_id`, `reason`, `fields` |
| `task_list` | `project_id` | `status`, `role` |
| `report_generate` | `project_id` | `task_id` |

Tool-level errors reuse the same codes as the HTTP layer plus `unknown_tool`,
`project_denied`, `apk_missing`, `artifact_missing` (retryable),
`path_rejected`, `ingest_failed`, `internal_error` (retryable).

## Worked examples (PowerShell)

All examples assume local mode (`APKPLAT_REQUIRE_AUTH=0`). In token mode add
`-H "Authorization: Bearer $token"` to every call and mint the token first:

```powershell
$root = 'D:\ADeespseekSH\REA\apk-research-platform'
$hex  = & "$root\.venv\Scripts\python.exe" -c "import sys;sys.path.insert(0,r'$root\backend');from apkplat.config import settings;print(settings.signing_secret().hex())"
$tok  = curl.exe -s -X POST http://127.0.0.1:8765/api/auth/token -H "X-Admin-Secret: $hex" -H 'Content-Type: application/json' -d '{"projects":["prj_REPLACE"],"scopes":["read","write"]}' | ConvertFrom-Json
$token = $tok.token
```

### 1. Upload and ingest

```powershell
$r = curl.exe -s -X POST http://127.0.0.1:8765/api/projects `
  -F "name=reef" `
  -F "apk=@D:\samples\base.apk" `
  -F "goal=identify network endpoints" | ConvertFrom-Json
$r.project.id; $r.job_id
```

Expect `201` with `{"project": {...}, "job_id": "job_..."}`. A rejected file
returns `422 {"error_code":"not_a_zip","message":"..."}` — a flat body, no
`detail` wrapper.

### 2. Run the worker and watch the queue

```powershell
& "$root\.venv\Scripts\python.exe" "$root\scripts\apkplat_cli.py" worker --once --kinds static_pipeline
curl.exe -s "http://127.0.0.1:8765/api/queue?status=SUCCEEDED" | ConvertFrom-Json | Select-Object -Expand jobs | Select-Object -First 1
```

`worker --once` reclaims expired leases on start, drains one batch, prints the
worker report and exits. Delete `--kinds` to run all four handlers. Without an API
process, the same work is available as
`python scripts\apkplat_cli.py create --name reef --apk D:\samples\base.apk`
followed by `... worker --once`.

### 3. Verify and render the report

```powershell
$projectId = $r.project.id
curl.exe -s "http://127.0.0.1:8765/api/projects/$projectId/verify" | ConvertFrom-Json |
  Select-Object ok, @{n='trace';e={$_.evidence.traceability_rate}}
$rep = curl.exe -s -X POST "http://127.0.0.1:8765/api/projects/$projectId/report" `
  -H 'Content-Type: application/json' -d '{"actor":"api"}' | ConvertFrom-Json
$rep.report_path; $rep.verification_ok
```

`verify` returns `ok=false` plus the failing evidence ids when a quoted excerpt no
longer matches its artifact. `report` writes
`storage/projects/<id>/reports/report-<stamp>.md`, registers it as an artifact
(`kind="report"`) and returns the full Markdown in `markdown`.

---

# Part 2 - the V3 surfaces (P1-P4)

The endpoints below were added by the incremental upgrade. They are grouped the way the taskbook
groups the work, and every one of them is covered by an acceptance script under `scripts/`.

## Bridge: run capabilities and scoped tools (`backend/apkplat/api/bridge_api.py`)

| Method | Path | Notes |
|--------|------|-------|
| POST | `/api/projects/{project_id}/runs` | 201. Issues a run capability. Returns `run_id`, `token_path`, `scope` - never the plaintext token. |
| POST | `/api/bridge/handshake` | Called by the DSH plugin at boot; opens the `agent_runs` row and binds it to the capability. |
| GET | `/api/bridge/tools` | Catalogue filtered by the capability's role. |
| POST | `/api/bridge/tools/{tool}` | The gateway. Re-authorises on every call, records `run_tool_calls` + audit. |
| POST | `/api/bridge/heartbeat` | Refreshes `last_seen_at`. |
| POST | `/api/bridge/finish` | Accepts `review` or `blocked` only; `DONE` is `422 invalid_finish_status`. |
| GET | `/api/bridge/state` | Live runs, budgets used, expiry. |
| GET | `/api/runs/{run_id}` / `/trace` | Capability description and the ordered tool-call trace. |
| POST | `/api/runs/{run_id}/revoke` | Immediate invalidation (`401 capability_revoked` afterwards). |

Full protocol, role matrix and the two error layers: `docs/bridge.md`.

## Dependency DAG, checks, roles, platform events (`dag_api.py`)

| Method | Path | Notes |
|--------|------|-------|
| GET | `/api/projects/{id}/graph` | Nodes, edges, `ready`, `blocked`, dangling edges, legacy `depends_on` comparison. |
| POST / DELETE | `/api/projects/{id}/edges` | `blocks` edges. Self-edge `422 self_edge`, cycle `422 cycle_detected`, cross-project `403 cross_project_edge`. |
| GET / POST | `/api/tasks/{id}/checks` | PASS/FAIL checks with criterion + detail, append-only. |
| POST | `/api/tasks/{id}/review` | `pass` accepts (records a PASS check), `fail` dispatches back; the third failure is `BLOCKED review_retry_exhausted`. |
| POST | `/api/tasks/{id}/review-run` | Opens an **independent** review run (own capability, role `review`) for a card in `REVIEW`. |
| GET / PATCH | `/api/roles` / `/api/roles/{role_id}` | `role_registry`; unknown field `422 field_not_editable`, unknown role `404`. |
| GET | `/api/projects/{id}/platform-events` | Monotonic `seq` cursor read. |
| GET | `/api/platform-events/stream` | SSE; honours `Last-Event-ID` and `?after_seq=`. |
| POST | `/api/projects/{id}/dag/backfill` | M1 migration step: mirror `depends_on` into edges, audited. |
| GET | `/api/dag/state` | Global counts (edges, checks, ready/blocked). |

## Sandbox, typed evidence, HTML report (`p3_api.py`)

| Method | Path | Notes |
|--------|------|-------|
| POST | `/api/projects/{id}/sandbox/run` | 201. `{script_artifact_id, argv, timeout, network, isolation}`. Refused scripts leave a `REFUSED` row. |
| GET | `/api/projects/{id}/sandbox/runs`, `/api/sandbox/runs/{run_id}` | Run listing / detail with hashes. |
| POST | `/api/sandbox/runs/{run_id}/replay` | Independent re-run. Refused with `side_effect_risk` when the original had network access. |
| POST / GET | `/api/projects/{id}/evidence/typed` | Typed evidence (text/json/image/video/capture_flow/pcap/device_observation/test_result). |
| GET | `/api/evidence/typed/{id}` | One row with verdict, integrity/assertion flags, failure reason. |
| POST | `/api/evidence/typed/{id}/reproduce` | Marks reproduction by a **different** run; same run is `422 same_run`. |
| GET | `/api/projects/{id}/evidence/summary` | Totals by verdict level. |
| GET | `/api/projects/{id}/report.html` | HTML rendering of the latest report artifact. |

## Analysis cache and capture correlation (`p4_api.py`)

| Method | Path | Notes |
|--------|------|-------|
| GET | `/api/cache/stats`, `/api/cache/entries` | Entries, bytes, hit counter, limit, whether the cache is enabled. |
| GET | `/api/capture/probe` | ProxyPin availability. On this host: `available=false`, reason names the missing `APKPLAT_CAPTURE_DIR`. |
| POST | `/api/projects/{id}/capture/import` | 201. HAR import; idempotent per file digest. `pcap` is refused with `pcap_not_parseable`. |
| POST | `/api/projects/{id}/capture/correlate` | Matches flows to static endpoint evidence and to recorded step windows. |
| GET | `/api/projects/{id}/capture/flows` | Filters: `host`, `method`, `matched_only`, `limit`. |
| GET / POST | `/api/projects/{id}/capture/sources`, `/steps` | Imported sources and device step windows. |

## Part 3 - the device layer (P5)

Readiness is a measurement, not a claim: `GET /api/devices/{serial}/health` returns a state
map where anything that could not be measured stays `null` instead of being assumed true.

| Method | Path | Notes |
| --- | --- | --- |
| GET | `/api/devices/live` | `adb devices -l` parsed and merged by `ro.serialno`, so one handset reachable over USB and Wi-Fi counts once. |
| GET | `/api/devices/{serial}/health` | Query: `package`, `project_id`, `transport=adb\|sim`. Returns `states`, `detail`, `metrics`, `required`, `ready`, `blocked`. |
| POST | `/api/devices/{serial}/quarantine` | Body `{reason, project_id?}`. Takes the device out of the pool; the lease release does not undo it. |
| POST | `/api/devices/{serial}/quarantine/clear` | Returns the device to the pool. Audited as `device_cleared`. |
| GET | `/api/cleanup/modes` | The four cleanup policies evaluated for both `installed_by_us` and `pre_existing` packages. |

The health states are `ADB_ONLINE`, `PACKAGE_MANAGER_READY`, `UI_READY`, `SCREEN_UNLOCKED`,
`APP_INSTALLED`, `APP_FOREGROUND`, `CAPTURE_READY`. `required` lists the subset that must be
true before a session starts; a `false` in that subset fills `blocked` and the session is
handed back as `WAITING_DEVICE` with `error_code=device_not_ready`.

Cleanup policies (the matrix is data, `dynamic.cleanup_plan`):

| Mode | stop | uninstall | scratch | quarantine |
| --- | --- | --- | --- | --- |
| `EPHEMERAL` | yes | only when we installed it | yes | no |
| `PRESERVE_APP` | yes | no | yes | no |
| `PRESERVE_SESSION` | no | no | yes | no |
| `QUARANTINE` | no | no | no | yes |

`device_action` in the gateway only runs whitelisted actions (`launch`, `stop`, `tap`, `key`,
`screenshot`, `dump`, `unlock`), only with an active lease, and only against the package under
analysis; everything else is `lease_required`, `package_denied` or `unsupported_action`.

## Error shapes

These added surfaces follow the same two-layer contract described in Part 1: capability and
validation refusals are HTTP 4xx with a flat `{"error_code", "message"}` body, while tool-level
failures inside the gateway are HTTP 200 with `ok=false` and an `error_code` the model can read.

`GET /api/health` also grows two blocks that the acceptance scripts assert on:

* `worker_policy` - path, whether it loaded, the executable allow-list and the timeout ceiling;
* `tools` - the probed versions of java / jadx / apktool / aapt2 / adb (a missing tool is reported,
  not hidden).


---

## Part 4 - periodic scheduling and test identities (P6)

Only the Python platform triggers periodic work: the model has no scheduling tool, and no
scheduler endpoint accepts a model-supplied instant.

| Method | Path | Purpose |
| --- | --- | --- |
| POST | `/api/projects/{project_id}/test-identities` | register an identity reference (`kind` is `test_account` or `fixture`) |
| GET | `/api/projects/{project_id}/test-identities` | list identities with their live lease, never their secret |
| POST | `/api/projects/{project_id}/periodic` | create a daily schedule (`schedule_id`, `hour`, `minute`, `tz`, optional identity) |
| GET | `/api/projects/{project_id}/periodic` | list schedules |
| PATCH | `/api/periodic/{periodic_job_id}` | enable/disable; any other field is `422 field_not_editable` |
| GET | `/api/periodic/{periodic_job_id}/runs` | one row per business window |
| GET | `/api/periodic/{periodic_job_id}/attempts` | refusals (`RESOURCE_BLOCKED`, `IDENTITY_BUSY`, `DUPLICATE_WINDOW`) |
| POST | `/api/periodic/tick` | run one scheduler pass (the same call the CLI and tests use) |
| GET | `/api/resources` | snapshot, heavy-work gate and the name of the clock in use |

Guarantees:

* One run per business window, enforced by the unique index `ux_periodic_run_window` - not by
  Python bookkeeping alone.
* A refusal (`RESOURCE_BLOCKED`, `IDENTITY_BUSY`) does not consume the day: the schedule
  re-checks after `RETRY_AFTER_SECONDS` (300s).
* Test identities are leased for the duration of a run and released when the job finishes; the
  secret itself never leaves the operator's store (`secret_ref` only, `has_secret_ref` in responses).
* `APKPLAT_SCHEDULER_CLOCK=fake` style time travel is a test concern: `clock.use(FakeClock(...))`
  in-process, never an API parameter.
