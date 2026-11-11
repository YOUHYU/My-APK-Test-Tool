# Evaluation

What `/api/metrics` actually measures, the values this build recorded, which acceptance gate
demonstrates which property, and what none of them cover.

```powershell
Invoke-RestMethod http://127.0.0.1:8765/api/metrics | ConvertTo-Json -Depth 4
```

## 1. Where the numbers come from

`GET /api/metrics` (`require("read")`) returns `_compute_metrics()` from
`backend/apkplat/api/app.py:582-629`. Nothing is sampled, cached or modelled: every value is
derived from four tables plus one per-project verification pass.

| Source | Used for |
| --- | --- |
| `audit_events` (`event_type`, `payload_json`) | every ratio whose numerator is an event count |
| `projects` | `projects_total`, `ingest_success_rate` denominator |
| `tasks` | `tasks_total`, `model_calls_per_task` |
| `evidence` + `artifacts` on disk | `evidence_traceability_rate` via `evidence_service.verify()` |

## 2. Metric definitions

| Metric | How it is computed | Reading it |
| --- | --- | --- |
| `ingest_success_rate` | `projects / (projects + count("apk_ingest_rejected"))`, 4 dp; `null` when the denominator is 0 | Share of ingest attempts that became projects. Refusals include the hostile corpus, so gate5's 0.6 is a **good** number. |
| `ingest_attempts` | `projects + count("apk_ingest_rejected")` | Denominator above. |
| `tool_call_schema_valid_rate` | rows with `event_type='mcp_tool_call'` whose `payload_json` contains `"schema_ok":true` (whitespace stripped) divided by all such rows, 4 dp; `null` when there are none | Only non-null once MCP calls run through the API in the same database. |
| `evidence_traceability_rate` | mean of `evidence_service.verify(pid)["traceability_rate"]` over every project, 4 dp; `1.0` when there are no projects or no evidence rows | Each row is re-checked: artifact exists, artifact belongs to the project, `sha256(excerpt) == excerpt_hash`, and the excerpt text occurs in the artifact bytes. Failures are `dangling_artifact`, `cross_project_artifact`, `excerpt_hash_mismatch`, `artifact_unreadable`, `excerpt_not_found_in_artifact`. **Must be 1.0.** |
| `project_isolation_failures` | `count("project_isolation_violation")` | Any non-zero value is a defect, not a trend. **Must be 0.** |
| `device_lease_collision` | `count("lease_collision_blocked")` — audited by the API's `LeaseConflict` handler | Counts *refused* collisions; a device being handed to two owners would show up here. **Must be 0.** |
| `task_recovery_success` | `count("job_recovered_after_restart") / count("job_lease_reclaimed")`, 4 dp; `null` when nothing was reclaimed | Of the leases the reaper expired, the share a worker picked up and completed. |
| `reclaimed_leases` | number of `job_lease_reclaimed` events | Denominator above. |
| `false_confident_claims` | `count("review_returned_no_evidence")` | Claims the reviewer sent back for citing no usable evidence. A count of refusals, not a hallucination rate. |
| `model_calls_per_task` | `AVG(tasks.model_calls)`, 2 dp; `0` when there are no tasks | Every `model_requests` insert increments the task counter. |
| `model_api_latency_ms_avg` | mean of `latency_ms` in `model_call` audit payloads, 1 dp; `null` when there are none | Wall-clock around the HTTP call, measured in `llm._record()`; failures are recorded too. |
| `tasks_total` / `projects_total` / `tool_calls` / `generated_at` | direct counts / UTC timestamp | Context for the ratios. |

Ratios return `null` rather than 0 when their denominator is empty — `null` means "not
exercised in this database", not "zero".

## 3. Measured values

Snapshots are embedded in each gate's `acceptance.json` (gate3 nests them under `data.metrics`;
gate2 has no metrics block at all, so its recovery evidence is quoted from the checks). Every
figure below was read from those files at 2026-11-10 20:25 local time — re-running a gate
overwrites its report, so re-read them after a rerun instead of trusting this page.

| Metric | Gate 3 (multi-agent, live model) | Gate 4 (device pool, sim) | Gate 5 (stability) |
| --- | --- | --- | --- |
| `ingest_success_rate` | 1.0 | 1.0 | **0.6** |
| `ingest_attempts` | 1 | 4 | 15 |
| `tool_call_schema_valid_rate` | `null` | `null` | `null` |
| `tool_calls` | 0 | 0 | 0 |
| `evidence_traceability_rate` | 1.0 | 1.0 | 1.0 |
| `project_isolation_failures` | 0 | 0 | 0 |
| `device_lease_collision` | 0 | 0 | 0 |
| `task_recovery_success` | `null` | `null` | **0.5** |
| `reclaimed_leases` | 0 | 0 | 2 |
| `false_confident_claims` | **1** | 0 | **2** |
| `model_calls_per_task` | 0.8 | 0.0 | 0.0 |
| `model_api_latency_ms_avg` | **8119.0** | `null` | `null` |
| `tasks_total` / `projects_total` | 5 / 1 | 8 / 4 | 13 / 9 |

Supporting measurements from the same runs:

- **Gate 1** (single-APK static loop, 24/24): 12 evidence rows, "every claim traces to an
  artifact — rate 1.0", report verification `True`, 6360-character report naming the package and
  all four planted secret literals.
- **Gate 2** (isolation/persistence, 20/20): no isolation failures (0); "restart recovery is
  counted 1.0" after a new worker reclaimed a dead lease and the job finished `SUCCEEDED
  attempt=2`; audit trail append-only and gapless (73 rows, seq 73); artifacts 18 rows with
  no cross-project collision (9 + 9).
- **Gate 3** (19/19, live model, 40.9 s): four model calls, "4 ok of 4 requests", **model latency
  "avg 8119ms max 10680ms"**, traceability 100% on 12 rows, `model_calls_per_task` 0.8 over 5
  tasks, reviewer refused the unevidenced claim (`no_evidence`) and the task went back to
  RUNNING, report cited 24 evidence ids.
- **Gate 4** (30/30): 0 physical devices, dynamic session over `SimTransport` completed
  `probe, install, launch, observe, screenshot`, 16 evidence rows verified at rate 1.0, cleanup
  verified (`{"attempted": true, "verified": true, "reason": null}`), unplug escalated to
  `device_lost` with the lease released, "no overlapping leases — 0 overlap(s)".
- **Gate 5** (36/36): 6/6 hostile archives refused and each refusal audited
  (`6 apk_ingest_rejected`), oversized upload 413 with 0 partial files, 2/2 append-only writes
  blocked, orphaned job recovered and an expired-orphan retired `FAILED`, claims without
  evidence rejected (`evidence_unknown`, `no_evidence`), `worker --once` on an empty queue
  "exit=0 in 0.3s".
- **P0** (`reports/p0/model_api_check.json`, `generated_at 2026-11-10T12:23:59Z`): endpoint
  `http://192.168.43.1:8788/v1`, model `deepseek-v4.1-flash`, `key_fingerprint: "len=36"`, four
  checks passing — text 2615 ms, json_object 1869 ms, streaming 1894 ms total (56 events, first
  delta 1391 ms), tool_calls 2241 ms.

The P0 latencies (1.9–2.6 s) and the gate3 figure (8119 ms) come from different prompts and
output budgets — one-line probes versus four agent roles writing analysis — so they are not
comparable. Both are the same per-call `latency_ms` that `model_api_latency_ms_avg` averages.

## 4. Which gate demonstrates which property

| Property | Evidence |
| --- | --- |
| Toolchain and model API respond in the required shapes | P0: four checks, all PASS |
| Ingest → static pipeline → index → MCP → evidence → report closes without a human | Gate 1 (24/24), pytest `tests/integration/test_p1_closed_loop.py` |
| Every claim is reproducible | Gate 1 rate 1.0 on 12 rows; gate3 12 rows; gate4 16 rows; gate5 24 rows — all 1.0 |
| Projects cannot leak into each other | Gate 2 (9 + 9 artifacts, no failures), `tests/isolation/test_project_isolation.py` |
| A crashed worker's job is recovered, not lost or looped | Gate 2 (recovery 1.0), Gate 5 (`task_recovery_success` 0.5 with 2 reclaimed leases), `tests/integration/test_p2_operations.py` |
| The board is a projection of real task state | Gate 2 columns `DONE, REVIEW, RUNNING, TODO`, `tests/unit/test_state_machine.py` |
| Agents may not close their own work | Gate 2 `409 approval_required` then human approval → DONE; gate5 deterministic review still ends in `review_ready` |
| Model-backed review refuses unevidenced claims | Gate 3 (`false_confident_claims` 1, task returned to RUNNING); gate5 (2, without a model) |
| One device serves one task at a time | Gate 4 (`device_lease_collision` 0, waiting task `WAITING_DEVICE`, resumed to REVIEW) |
| Device loss is a safe failure | Gate 4 (`FAILED/device_lost`, lease released, deferred cleanup recorded) |
| Hostile input is refused with a reason and without residue | Gate 5 (6/6, no project row, 6 audit events) |
| History cannot be rewritten | Gate 5 (2/2 blocked), `migrations/002_audit_appendonly.sql` |
| Queue semantics: leases, retries, idempotency, cancel | `tests/unit/test_queue.py` (11 tests) |
| Token scoping and admin secret | Gate 5 (401 / 403 / 422), `tests/unit/test_auth.py` |
| A worker may only launch allow-listed executables | `config/worker-policy.yml` enforced by `check_executable()` in `backend/apkplat/toolchain.py` (`ToolError("tool_not_allowed")`), `tests/unit/test_toolchain_policy.py`, `/api/health.worker_policy` |
| Malformed API input is a structured 4xx, never a 500 | `tests/integration/test_api_error_shapes.py` (422 `invalid_ground_truth` / `title_required` / `field_not_editable` / `invalid_decision`, 404 `task_not_found` / `approval_not_found`, 422 `adb_serial_required`) |

Test inventory — **113 passed in 97 s** measured on this host with
`.\.venv\Scripts\python.exe -m pytest tests -q`: `tests/unit/` — `test_apk_validation`,
`test_auth`, `test_evidence`, `test_queue`, `test_state_machine`, `test_toolchain_policy`;
`tests/isolation/test_project_isolation.py`; `tests/integration/` — `test_p1_closed_loop`,
`test_p2_operations`, `test_p3_agents`, `test_p4_devices`, `test_p5_stability`,
`test_api_error_shapes`; `tests/e2e/test_live_http.py` — the API served by uvicorn in a
child process plus a separate worker process, uploading and analysing over real HTTP
(no model, no device, no browser).

## 5. What is not covered

- **No real Android device.** `adb devices -l` lists nothing on this host and gate4 records
  `physical_devices: 0`. The dynamic stage is exercised through `SimTransport`, whose replies
  are canned (`Pixel 6 (sim)`, `Performing Streamed Install\nSuccess`, four fixed logcat lines).
  That proves the orchestration, the lease protocol, evidence capture, cleanup verification and
  failure handling — it does **not** prove that `adb install`, `am start -W` or `screencap`
  behave on a real OEM build, nor that logcat parsing survives real volume. `AdbTransport` is
  the class used with `APKPLAT_DYNAMIC_TRANSPORT=adb`, but only its wiring was exercised.
- **No container isolation.** Docker/Podman are absent (P0 deviation 1), and there is no
  seccomp/AppArmor profile (deviation 4). Containment rests on the toolchain rules in
  `backend/apkplat/toolchain.py` (argv-only, cwd pinned inside `storage/`, wall-clock timeout,
  process-tree kill, whitelisted child env, 16 MB output cap) plus loopback-only binding. The
  `allowed_executables` list (`java.exe`, `aapt2.exe`, `adb.exe`, `node.exe`) narrows *what* may
  start; it is a whitelist in the launcher, not kernel-enforced confinement of a running tool.
- **`tool_call_schema_valid_rate` is unmeasured in every snapshot.** Gates 3, 4 and 5 report
  `tool_calls: 0`, so the ratio is `null`. Gate 1 drives the MCP server (16 tools, envelope
  `tool_version: 1.0.0`, `"schema_ok":true` envelopes) but writes no metrics block. To measure
  it, call MCP tools against a running API database and re-read `/api/metrics`.
- **`evidence_traceability_rate` is 1.0 also for a project with zero evidence rows.** It proves
  recorded rows verify; it does not prove that a task made any claims.
- **`false_confident_claims` counts reviewer refusals**, i.e. claims returned with
  `no_evidence`. A model claim that cites a real artifact whose excerpt does not actually
  support it is caught by a different path and is not counted here.
- **Crash recovery is simulated, not a kill -9.** Gate 5 expires a lease on a live database
  (`reclaim_expired`); the process is never killed mid-write. Gate 5 states this in its own
  honest-limits section, pointing at the same code path and
  `tests/integration/test_p2_operations.py`.
- **Model behaviour is only measured where the model was enabled.** Gates 4 and 5 run with
  `APKPLAT_MODEL_ENABLED=0` (gate5 states this explicitly), so `model_calls_per_task` is 0.0
  there; gate3 is the single live-model datapoint.
- **SQLite only.** The PostgreSQL code path (`APKPLAT_DB_URL` starting with `postgres`) is
  untested on this host; `.env.example` says as much.
- **Single operator, single host.** No multi-tenant load test, no soak run beyond gate5's 53.6 s,
  and no measurement of behaviour when several humans drive the board at once.
