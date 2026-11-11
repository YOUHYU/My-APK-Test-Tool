# DSH bridge: run capabilities and the model-facing tool gateway

This document describes the P1 layer. It is deliberately small: the bridge does not give the
model a shell, and it does not let the model decide when a task is done.

```
DSH NEXT agent  ──tool call──▶  apkplat-bridge plugin (in-process, DSH)
                                        │  HTTP + Bearer runcap_…
                                        ▼
                              APK tool gateway (/api/bridge/tools/{tool})
                                        │  capability check, then handler
                                        ▼
                        projects / indexer / sandbox / evidence / capture
```

## 1. What the bridge is, and what it is not

* It **is** an in-process DSH plugin (`plugins/apkplat-bridge/index.js`) that registers a handful of
  typed tools into the live agent's tool registry (`ctx.tools.register(defineTool(...))`), and
  forwards each call to this platform over HTTP.
* It **is not** a modification of DSH NEXT. Nothing under `resources/app.asar` is patched; the plugin
  is added through an overlay, and the `~/.dsh` profile is never written.
* It **is not** a scheduling mechanism. The Python platform owns claims, leases, states, acceptance and
  re-dispatch (see `docs/architecture.md`). An agent can only *propose* work and *submit* evidence;
  `DONE` is written by the platform's acceptance path, never by a tool call.

## 2. Run capability lifecycle

| Step | Call | What happens |
|------|------|--------------|
| 1 | `POST /api/projects/{id}/runs` | A `run_capabilities` row is written with a scope (project, role, tool list, budgets, expiry) and a token `runcap_<48 hex>`. Only the SHA-256 of the token is stored in the database; the plaintext is written once to `storage/runs/<run_id>/capability.token` (mode 0600 on POSIX). |
| 2 | plugin boot | The plugin reads that file and `POST`s `/api/bridge/handshake`. The platform creates the `agent_runs` row, binds it to the capability, and returns the catalogue the *scope* allows. |
| 3 | each tool call | `POST /api/bridge/tools/{tool}` with `Authorization: Bearer runcap_…` and `X-Project-Id`. The capability is re-checked on **every** call — scope, project, expiry, revocation, budget — and the call is written to `run_tool_calls` plus an `audit_events` row (`bridge_tool_call`) with an `args_hash`, `result_preview` (12 kB) and the observed error code. |
| 4 | heartbeat | `POST /api/bridge/heartbeat` refreshes `last_seen_at` so a long tool run does not look dead. |
| 5 | finish | `POST /api/bridge/finish` accepts only `review` or `blocked`. `DONE` is rejected with `invalid_finish_status` (422): acceptance belongs to the platform. |

The token is **never** passed as a tool argument, never written into a prompt, never echoed in a
response body, and never logged. `trace` and `describe` expose the capability hash prefix only.

Default TTL is 3600 s. `POST /api/runs/{run_id}/revoke` invalidates it immediately; a revoked token
answers `401 capability_revoked` on the next call.

## 3. The tool catalogue

Thirteen tools, and nothing else. There is no `shell`, no `run_command`, no `jadx` passthrough: the
decompiler only runs inside the static pipeline, with the restricted toolchain in
`backend/apkplat/toolchain.py` (executable allow-list from `config/worker-policy.yml`).

| Tool | Arguments (required first) | Purpose |
|------|---------------------------|---------|
| `platform_health` | – | Version, project counts, and which capabilities this host really has (see §5). |
| `project_snapshot` | – | Project row, ingest summary, artifact kinds, evidence counts, tasks, index stats. |
| `artifact_find` | `query` | Verbatim line search across text artifacts; returns artifact id + line + text. |
| `apk_inspect` | `action` (`metadata`/`manifest`/`packages`/`code`/`method`/`resources`/`strings`/`components`), plus `target`/`query` where relevant | Read-only queries over the per-project index. |
| `task_propose` | `title` (plus optional goal/role/parent) | Creates a `TODO` card, audited as `task_proposed`. |
| `task_status_get` | `task_id` | State, counters and error code for one card. |
| `artifact_write` | `name`, `content` | Writes a note/script/capture into the project's artifact tree (idempotent on content hash). |
| `test_run` | `script_artifact_id` | Runs a Python script in the cooperative sandbox (`docs/architecture.md` §6). |
| `test_result_read` | `sandbox_run_id` | Tail of a sandbox run's stdout/stderr. |
| `device_observe` | – | `adb devices -l` view; reports `WAITING_USER_ADB_AUTH` when nothing is attached. |
| `device_action` | `action` | Requires a device lease; unavailable until the P5 device chain is enabled. |
| `capture_query` | optional `host`/`method`/`matched_only` | Correlated capture flows, or `not_observed` with the reason. |
| `evidence_submit` | `artifact_id`, `excerpt`, `claim` | Records evidence whose excerpt must be a verbatim slice of that artifact. |

### Role matrix (seeded into `role_registry`)

| Role | Tools | Budget |
|------|-------|--------|
| `plan` | platform_health, project_snapshot, artifact_find, task_propose, task_status_get | 24 calls / 8 model turns |
| `exec` | all except `task_propose` | 24 / 8 |
| `review` | platform_health, project_snapshot, artifact_find, apk_inspect, test_run, device_observe, capture_query, evidence_submit, task_status_get | 24 / 8 |
| `ship` | platform_health, project_snapshot, artifact_find, artifact_write, test_run, test_result_read, task_status_get | 24 / 8 |
| `evidence` | platform_health, project_snapshot, artifact_find, capture_query, evidence_submit, task_status_get | 24 / 8 |
| `report` | platform_health, project_snapshot, artifact_find, task_status_get | 24 / 8 |

Budgets are enforced server-side (`tool_budget_exhausted`, 429). The 24/8 split was measured on the
real sample APK: a competent run needs roughly a dozen calls just to orient (health, snapshot,
manifest, packages, findings, components, strings, code) before it submits its first piece of
evidence.

## 4. Two error layers, on purpose

| Layer | Shape | Codes | Why |
|-------|-------|-------|-----|
| Capability / scope | HTTP 4xx | `missing_capability_token`, `invalid_capability_token`, `capability_expired`, `capability_revoked`, `unknown_tool` (404), `tool_not_in_scope` (403), `project_denied` (403), `tool_budget_exhausted` (429) | The caller is not allowed to make this call at all; retrying the same call with the same arguments cannot succeed. |
| Tool execution | HTTP **200** with `ok: false` and `error_code` | `excerpt_not_found`, `artifact_missing`, `not_observed`, `lease_required`, `capability_unavailable`, `static_check_failed`, `sandbox_timeout`, … | The model must be able to *read* the reason and change its arguments. A 500 would hide the reason and lose the audit row. |

Anything unexpected inside a handler is caught and turned into `internal_error` (200, `ok: false`)
with an `audit_events` row `bridge_tool_crashed` carrying the exception type — so a tool crash can
never be both invisible and untraceable.

## 5. Honest capability reporting

`platform_health` reports what the host actually has rather than what the taskbook wishes for:

```json
{"capabilities": {
  "test_run":      {"available": true,  "isolation": "cooperative"},
  "device_action": {"available": false, "reason": "requires a device lease (P5)"},
  "capture_query": {"available": false, "reason": "APKPLAT_CAPTURE_DIR is not configured; no ProxyPin export attached"}
}}
```

`capture_query` with no capture attached answers `not_observed` with that same reason, and the state
word `NOT_OBSERVED` is stored on the project summary. Absence of evidence is recorded as absence.

## 6. Registering the bridge with DSH NEXT

`config/dsh/p0-headless-probe.yml` shows the working shape; the plugin entry must be an `insert`
(a bare `- id:` patch only overrides an existing entry and fails with `patch: entry … not found`):

```yaml
- id: llm-pi-ai
  config:
    providers:
      wb-proxy:
        baseURL: http://192.168.43.1:8788/v1
        api: openai-completions
        apiKeyEnv: WB_PROXY_API_KEY
- id: agent-default-model
  config:
    provider: wb-proxy
    model: deepseek-v4.1-flash
- insert:
    - id: apkplat-bridge
      name: file:///D:/ADeespseekSH/REA/apk-research-platform/plugins/apkplat-bridge/index.js
      config:
        platform_url: http://127.0.0.1:8765
        token_file: D:/ADeespseekSH/REA/apk-research-platform/storage/runs/<run_id>/capability.token
        trace_file: D:/ADeespseekSH/REA/apk-research-platform/runtime/trace.jsonl
```

Caveats that cost time and are worth keeping:

* The plugin path must be a `file:///` URL or a `./`-relative path — the loader resolves bare
  specifiers from inside `app.asar`, not from the working directory.
* DSH scrubs `/KEY|PASSWORD|SECRET|TOKEN/i` and every `DSH_*` variable from a child process
  environment; anything the plugin needs must come from `config`, not from the parent env.
* `defineTool` comes from `@deepseek-ai/dsh-tools`; the plugin resolves it through `createRequire`
  against the installed `app.asar` because it is not a published package.

## 7. What G1 actually verified

`scripts/p1_g1_accept.py` runs a headless DSH agent twice (two different APKs) against a real gateway
and a real model, then audits the trace:

* the model chose ≥2 distinct tools itself (`apk_inspect`, `project_snapshot`, `artifact_find`,
  `artifact_write`, `evidence_submit`);
* every call made by the plugin appears in `run_tool_calls` and `audit_events` — 27/27 paired, 0
  unreachable;
* the second call was driven by the first result: 15 derived arguments whose values appear verbatim
  in an earlier `result_preview` (e.g. `target="MainActivity"` after a `code` listing);
* both runs ended in `REVIEW`, never `DONE`;
* six negative cases: expired (401), revoked (401), cross-project (403), role-denied (403),
  finish-DONE (422), and an allowed read (200).

Evidence: `audit/g1_acceptance.md`, `audit/p1_real_tool_trace.jsonl`.
