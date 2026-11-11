# Troubleshooting

Symptom → cause → fix, for failures this build actually hit. Quotes are copied from the code
or from the reports in `reports/`; where no literal string exists in the repository the failure
mode is described without inventing one.

Run everything with the project interpreter from the repository root:

```powershell
cd D:\ADeespseekSH\REA\apk-research-platform
$py = ".\.venv\Scripts\python.exe"
```

## 1. jadx: "could not find or load main class jadx.cli.JADXMain"

**Symptom.** `apkplat_cli.py versions` reports jadx as unavailable, `/api/health` shows an error
string for `tools.jadx`, and every static pipeline that reaches decompilation fails with
`jadx_timeout` / `tool_missing`. `reports/p0/environment_report.md` recorded the literal probe
output:

```
错误: 找不到或无法加载主类 jadx.cli.JADXMain
```

**Cause.** jadx renamed its CLI entry point: 1.4.x shipped `jadx.cli.JADXMain`, 1.5.x ships
`jadx.cli.JadxCLI`. A wrapper that hard-codes the old class cannot start the 1.5.6 jar.

**Fix.** `toolchain._jadx_entrypoint()` probes `jadx.cli.JadxCLI` first and falls back to
`jadx.cli.JADXMain` by running `java -cp <tools\jadx\lib\jadx-1.5.6-all.jar> <entry> --version`
(writing `storage\tmp\jadx-probe.out` / `.err`), so a correct install needs no action:

```powershell
$py scripts\apkplat_cli.py versions        # jadx: {"ok": true, "version": "1.5.6"}
```

If it still fails, the jar is missing or a second, older jar shadows it — the probe always uses
the highest-sorted `jadx-*-all.jar` in `tools\jadx\lib`:

```powershell
Remove-Item tools\jadx -Recurse -Force
$py scripts\fetch_toolchain.py --only jadx
```

## 2. androguard 4: `APK(path)` versus `raw=True`

**Symptom.** Metadata extraction returns empty or nonsense values (no package, no certificate
digests) instead of raising.

**Cause.** In androguard ≥ 4 the first argument's type decides the API: `raw=True` means "the
first argument is the bytes of the APK", not a path. Passing a path with `raw=True` silently
feeds filename characters to the parser.

**Fix.** `apkfile.parse_metadata()` uses the path form and says why in a comment:

```python
# androguard >= 4: ``raw=True`` means the first argument is bytes, not a path.
apk = APK(str(path))
```

Pass `raw=True` only together with `path.read_bytes()`.

## 3. androguard floods the worker output with loguru DEBUG lines

**Symptom.** Worker stdout/stderr fills with `DEBUG` records from androguard while a pipeline
runs, drowning the worker's own lines.

**Cause.** androguard pipes its logging through loguru, which installs a stderr sink by default.

**Fix.** `pipeline_static.silence_library_logging()` — "androguard pipes DEBUG chatter through
loguru; it pollutes worker stdout" — removes the sink before parsing:

```python
from loguru import logger as _lg
_lg.remove()
```

`scripts/build_sample_apk.py` does the same in `main()` before importing `apkfile`. If you add
a new entry point that imports androguard, call this first.

## 4. sdkmanager: `--sdk_root` and the licence prompt

**Symptom.** `scripts\fetch_toolchain.py` stops at the Android component: sdkmanager either
ignores the SDK location (installing into a default path) or waits forever on
`Review licenses that have not been accepted (y/N)`.

**Cause.** Two separate traps. `--sdk_root` must be a *single* argv element
(`--sdk_root=C:\...\tools\android-sdk`); passed as two tokens the tool treats the path as a
package name. And `--licenses` reads answers from stdin — with `stdin` closed or inherited from
a terminal, the run blocks.

**Fix.** `install_android_packages()` does exactly this, and nothing else:

```python
run([sdkmanager, f"--sdk_root={sdk_root}", "--licenses"], input_text="y\n" * 60)
run([sdkmanager, f"--sdk_root={sdk_root}", "platform-tools", "build-tools;34.0.0", "platforms;android-34"])
```

with `JAVA_HOME=tools\jdk`, `PATH` prefixed by the JDK, and `ANDROID_SDK_ROOT=ANDROID_HOME=tools\android-sdk`.
A non-zero exit is logged with the tail of sdkmanager's output and raised as
`sdkmanager failed`.

## 5. No adb / no device: dynamic tests fall back to the simulator

**Symptom.** `adb devices -l` prints only the `List of devices attached` header, dynamic work
fails with `tool_missing` or `device_unavailable`, and `GET /api/devices` is empty.

**Cause.** This host has no phone and no emulator; `reports/gate4/acceptance.json` records
`physical_devices: 0`. On the real transport a missing binary raises
`DynamicError("tool_missing", "adb not found at <path>")` and an absent device raises
`device_unavailable`.

**Fix.** Use the simulator for anything that is not a real-device test:

```powershell
$env:APKPLAT_DYNAMIC_TRANSPORT = "sim"
$py scripts\apkplat_cli.py dynamic <project_id> --transport sim
```

`SimTransport` answers the same argv with canned output (`Pixel 6 (sim)`, Google, API 13) and
can simulate a cable pull with `--unplug` / `unplug_at`, which is how gate4 proves the failure
path (`simulated cable pull before \`shell screencap -p /sdcard/apkplat/screen.png\``).
`.env.example` already defaults to `sim`; the code default is `adb`.

## 6. HTTP 401 from the model API (or `model_disabled`)

**Symptom.** Agent/report jobs fail with `model_disabled` ("no model API key available to the
platform") or with `model_http_error` whose message starts `model API returned 401:`.

**Cause.** The platform resolves its key in this order (`llm._dsh_credentials_key`): the
credentials file `C:\Users\YHY\.dsh\.credentials.yaml`, key `refs.WB_PROXY_API_KEY`, then
`APKPLAT_MODEL_API_KEY`, then `DEEPSEEK_API_KEY`. No key at all → `model_disabled` before any
request is sent. A stale or rejected key → the endpoint's own 401, wrapped as
`model_http_error` (recorded in `model_requests` with `http_status` 401 and audited as
`model_call` with `error_type`). The key is never printed: the p0 check writes only
`key_fingerprint: "len=36"`.

**Fix.** Confirm resolution without leaking the secret:

```powershell
$py -c "import sys; sys.path.insert(0, 'backend'); from apkplat import llm; print(llm.resolve()['key_source'], llm.resolve()['base_url'], llm.resolve()['enabled'])"
```

`key_source` is `dsh-credentials:<path>`, `env:APKPLAT_MODEL_API_KEY` or `missing`. If it says
`missing`, either add `refs.WB_PROXY_API_KEY` to the credentials file or export
`APKPLAT_MODEL_API_KEY`. If the key resolves but the API answers 401, the endpoint rotation is
the thing to fix — re-run `scripts\p0_check.py`, which exercises text, JSON mode, streaming and
tool calls and exits 1 on any failure.

## 7. `httpx` ValueError on the bracketed `NO_PROXY` entry `[::1]`

**Symptom.** Every model call dies with `model_transport_error` whose text is a `ValueError`
raised inside httpx before the request leaves the process.

**Cause.** This host exports `NO_PROXY` containing the bracketed IPv6 literal `[::1]`, which
httpx cannot parse when it builds its proxy environment.

**Fix.** `llm.complete()` builds its client with `trust_env=False` on purpose:

```python
# trust_env=False on purpose: this host exports NO_PROXY with a bracketed
# IPv6 literal that httpx cannot parse, and the model API is on the LAN.
with httpx.Client(timeout=..., trust_env=False) as client:
```

The same host quirk breaks PowerShell process launching: `scripts\platform.ps1` starts children
through `cmd.exe /s /c` because `Start-Process` "dies when the parent exports both `NO_PROXY` and
`no_proxy` (which this host does)". Do not replace that wrapper with `Start-Process`.

## 8. Tests: "cannot delete `tests\.tmp\storage\platform.db`"

**Symptom.** A test run inherits the previous run's queue, or `tests\.tmp` cannot be removed.

**Cause.** On Windows an open file cannot be deleted. Test modules import `apkplat.db` during
collection, which opens the SQLite file; a cleanup step after collection fails silently and every
run would inherit the previous run's pending jobs.

**Fix.** `tests/conftest.py` wipes the tree *while it is being imported*, before any `apkplat`
import, and pins the environment first:

```python
os.environ.setdefault("APKPLAT_STORAGE", str(TMP / "storage"))
os.environ["APKPLAT_REQUIRE_AUTH"] = "0"
if TMP.exists():
    shutil.rmtree(TMP, ignore_errors=True)
```

To inspect a failed run, set `APKPLAT_KEEP_TEST_TMP=1` — but delete `tests\.tmp` yourself before
the next run, with no test process alive.

## 9. Tasks stuck in RUNNING after a crash

**Symptom.** The board shows a card in RUNNING forever; `apkplat_cli.py queue` shows a job in
RUNNING whose worker no longer exists.

**Cause.** The worker died without completing the job. Nothing polls; recovery happens when a
worker starts, or when an operator asks for it.

**Fix.** `Worker.start()` calls `queue_service.reclaim_expired()` before claiming anything: rows
whose lease expired move to RETRYING (attempt below `max_attempts`) or FAILED, with
`error_code=lease_expired` and message `worker <owner> stopped heartbeating`, audited as
`job_lease_reclaimed`. Manually:

```powershell
$py scripts\apkplat_cli.py queue            # stats + rows
$py scripts\apkplat_cli.py queue --reclaim  # expire dead leases now, prints reclaimed ids
$py scripts\apkplat_cli.py job-reset <job_id> --reason "operator retry"
```

`job-reset` puts the row back to PENDING, clears the lease and audits `job_reset_by_operator`.
The `/api/metrics` `task_recovery_success` ratio counts `job_recovered_after_restart` over
`job_lease_reclaimed`.

## 9b. The card never left RUNNING although the job SUCCEEDED

**Symptom.** `apkplat_cli.py queue` shows the job SUCCEEDED, the project is ANALYZED, evidence
rows exist — yet the board still shows the static card in RUNNING and nothing ever moves it to
REVIEW.

**Cause (found on this build, fixed).** `worker._merge_task_result()` moved the card to REVIEW
through `tasks_service.update(..., fields={"evidence_count": n})`, but `evidence_count` is not in
`EDITABLE_FIELDS`; the update raised `ValueError: field 'evidence_count' is not editable through
this API`, and the surrounding `except Exception: pass` swallowed it. `evidence_service.record()`
had already incremented `evidence_count` per row, so the merge was both illegal and redundant.

**Fix.** `_merge_task_result()` only performs the status transition and audits
`task_status_update_failed` (with the job id and the exception text) if the update does not go
through, so this class of failure can no longer disappear. `tests/integration/test_p1_closed_loop.py`
asserts the card is in REVIEW with `evidence_count >= 8` and the RUNNING column is empty;
`tests/e2e/test_live_http.py` asserts the same over real HTTP.

```powershell
$py -c "import sqlite3;db=sqlite3.connect('storage/platform.db');print(db.execute('select role,status,evidence_count from tasks').fetchall())"
```

## 10. `worker --once` hangs on an empty queue

**Symptom.** `apkplat_cli.py worker --once` never returns when there is nothing to claim.

**Cause.** `Worker.run(max_jobs, idle_timeout)` only returns from an empty queue when
`idle_timeout` is set; a bounded run with `idle_timeout=None` waits for a job that may never
come.

**Fix.** The CLI closes the hole: `--once` without `--max-jobs` forces `idle_timeout=3.0`, and
the run prints `[worker <id>] idle for 3.0s; stopping`. Gate 5 measures it as
`exit=0 in 0.3s`. If you drive `Worker` from your own code, always pass `idle_timeout`
(`gate2_accept.py` uses `.run(max_jobs=n, idle_timeout=5)`), and remember `--idle 0` disables
the stop entirely — which is what a long-running worker wants. Two entry points, two spellings:
`scripts/apkplat_cli.py worker --idle` and `python -m apkplat.worker --idle-timeout`.

## 11. The kanban is empty although work was "queued"

**Symptom.** Projects exist, the board has no cards, the queue is empty.

**Cause.** Only the API (and the CLI's `create`) enqueues work — `services/projects.py` writes
rows, `services/queue.py` stores jobs, and no service calls `enqueue()` itself, so a project made
through `projects_service.create()` without a following `queue_service.enqueue()` never runs. A
job whose `task_id` was never attached keeps the card out of RUNNING — `attach_task()` does that.

**Fix.** Submit through the API or the CLI, then run a worker:

```powershell
$py scripts\apkplat_cli.py create --name reef --apk samples\sample-app.apk
$py scripts\apkplat_cli.py worker --once
$py scripts\apkplat_cli.py board
```

## 12. `/api/health` shows a jadx version that is an error string

**Symptom.** `GET /api/health` returns `tools.jadx` as `{"ok": false, ...}` or carries probe
text instead of a version, while the rest of the platform looks healthy.

**Cause.** `probe_versions()` returns `{ok, version, path}` on success and `{ok:false,
error:"not_installed", path}` when the binary is absent; if the jar exists but the entry-point
probe fails, the probe's own message surfaces. Health reports; it does not repair.

**Fix.**

```powershell
Invoke-RestMethod http://127.0.0.1:8765/api/health | ConvertTo-Json -Depth 6
$py scripts\fetch_toolchain.py --verify
```

`--verify` probes every component and exits 1 on failure; re-fetch the failing one with `--only`.

## 13. APPEND-ONLY triggers did not fire

**Symptom.** An `UPDATE`/`DELETE` against `audit_events` or `evidence` "succeeded" although the
append-only triggers exist.

**Cause.** Both protections are `BEFORE UPDATE` / `BEFORE DELETE` **row** triggers, so they run
only for rows that match. `UPDATE audit_events SET actor='x' WHERE id='nonexistent'` changes
nothing and raises nothing.

**Fix.** Nothing to change in the schema; test with a row that exists (output below is what
sqlite3 raises on this database):

```sql
UPDATE audit_events SET actor='x' WHERE id=(SELECT id FROM audit_events LIMIT 1);
-- IntegrityError: audit_events is append-only: UPDATE is forbidden
DELETE FROM evidence WHERE id=(SELECT id FROM evidence LIMIT 1);
-- IntegrityError: evidence is immutable: DELETE is forbidden
UPDATE audit_events SET actor='x' WHERE id='nonexistent';
-- no error: zero rows matched, so no row trigger ran
```

The four messages, verbatim from `migrations/002_audit_appendonly.sql`:
`audit_events is append-only: UPDATE is forbidden`, `audit_events is append-only: DELETE is
forbidden`, `evidence is immutable: re-record instead of editing`, `evidence is immutable:
DELETE is forbidden`. The trigger names are `trg_audit_events_no_update`,
`trg_audit_events_no_delete`, `trg_evidence_no_update`, `trg_evidence_no_delete`.

## 14. GBK console eats em dashes and other non-ASCII output

**Symptom.** A report or CLI line that should read `Gate 3 acceptance — multi-agent chain`
prints or is written as `Gate 3 acceptance -?multi-agent chain`; `reports/gate3/acceptance.md`
carries exactly that `-?`, and the same artefact appears in the `tests/conftest.py` docstring
and in the first docstring lines of `scripts/apkplat_cli.py`.

**Cause.** The console code page on this host is GBK (936); characters outside it are replaced
during printing, and the replacement is then captured into the written file.

**Fix.** Work in UTF-8 for the session before running the scripts:

```powershell
chcp 65001 > $null
$OutputEncoding = [System.Text.Encoding]::UTF8
```

JSON is written with `ensure_ascii=False` into UTF-8 files, so numbers are unaffected — only the
human-readable text degrades. Read reports with `Get-Content -Encoding UTF8`.

## 15. A job dies with `tool_not_allowed` (or health shows `worker_policy.error`)

**Symptom.** `jobs.error_code` is `tool_not_allowed`, or `/api/health` reports
`worker_policy.loaded: false` plus a `worker_policy.error` string.

**Cause.** `config/worker-policy.yml` is the executable allow-list `toolchain.run()` consults
before spawning: `java.exe`, `aapt2.exe`, `adb.exe`, `node.exe`. Anything else is refused with
`ToolError("tool_not_allowed")` — `<name> is not in config/worker-policy.yml
allowed_executables`. The same file sets `max_timeout_seconds: 900` and
`max_output_bytes: 16777216`, which **clamp** per-call values downward and never raise them.

**Fix.** Add the basename to `allowed_executables`, then restart the worker. A missing file is
not fatal (`toolchain.policy()` falls back to `DEFAULT_POLICY` with identical values); malformed
YAML shows up in `worker_policy.error` while the defaults stay in force.
`tests/unit/test_toolchain_policy.py` pins the load, the refusal and the env scrub.

## 16. Auth, upload and artifact errors at a glance

| Response | Meaning | Fix |
| --- | --- | --- |
| `401 missing_token` | token mode on, no `Authorization` header | mint a token or set `APKPLAT_REQUIRE_AUTH=0` on a loopback workstation |
| `403 admin_denied` | wrong/missing `X-Admin-Secret` on `/api/auth/token` | use the hex of `settings.signing_secret()` |
| `422 projects_required` / `422 wildcard_forbidden` | token request without project ids, or with `*` | name the project ids explicitly |
| `403 project_denied` | token does not cover that project | mint a token for it |
| `403 scope_denied` | read-only token used for a write | mint with the write scope |
| `409 approval_required` | actor `agent` tried to close a task | human approval decides DONE |
| `409 lease_conflict` | device already leased / task already holds a lease | wait for the lease or release it |
| `409 version_conflict` | PATCH with a stale task `version` | re-read the task |
| `413 upload_too_large` | upload above `APKPLAT_MAX_UPLOAD_MB` | raise the cap or split the file |
| `422 evidence_rejected` | evidence cites no locatable quote / unknown artifact | attach an artifact excerpt that exists |
| `410 artifact_bytes_missing` | artifact row survived its file | restore from backup or re-run the pipeline |
| `422 invalid_ground_truth` | `ground_truth` form field is not JSON | send a JSON object or leave the field empty |
| `422 title_required` | task created without `title` | include `title` in the body |
| `422 field_not_editable` | PATCH sent a key outside `tasks_service.EDITABLE_FIELDS` (`title`, `goal`, `summary`, `progress`, …) and not one of the reserved ones (`status`, `expected_version`, `approval_id`, `reason`, `actor`) | the response carries the `editable` list — use it, or move the task through a transition |
| `422 invalid_decision` | approval decision was not `approved` / `rejected` | send one of the two literals |
| `404 task_not_found` / `404 approval_not_found` | id does not exist in this database | re-read the board / project |
| `422 adb_serial_required` | `POST /api/devices/register` without `adb_serial` | pass the serial `adb devices` prints |

Every one of these is audited: `lease_collision_blocked`, `apk_ingest_rejected`,
`review_returned_no_evidence`, `job_failed` and friends are the events `/api/metrics` counts.
