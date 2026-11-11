# Demo walkthrough (no video)

The referenced screenshot shows a 21-card board. This walkthrough reproduces it with the real
services on this host, and records what each step printed. It is scripted, not narrated; every
command below can be pasted into PowerShell.

The demo project is synthetic by design: taskbook 13 forbids presenting synthetic cards as a
production history, so the project carries the marker `synthetic-demo` in its goal text and the
seeded checks are stamped `p7-seed`.

## 0. Environment

```powershell
$root = "D:\ADeespseekSH\REA\apk-research-platform"
$env:TEMP = "$root\.tmp"; $env:TMP = "$root\.tmp"
$env:APKPLAT_STORAGE = "$root\runtime\p7-demo\storage"
$env:APKPLAT_REPORTS = "$root\runtime\p7-demo\reports"
$env:APKPLAT_MODEL_ENABLED = "0"; $env:APKPLAT_REQUIRE_AUTH = "0"
```

## 1. Schema and seed

```powershell
& "$root\.venv\Scripts\python.exe" "$root\scripts\apkplat_cli.py" init
& "$root\.venv\Scripts\python.exe" "$root\scripts\p7_seed.py" --json
```

Observed: `migrations applied: 001_init.sql ... 008_p6_runs_transition.sql`, then

```json
{"project_id": "prj_12d9c0dbdddf489480af9d2856dfae4c",
 "cards": 21,
 "columns": {"TODO": 10, "RUNNING": 1, "REVIEW": 1, "DONE": 9}}
```

The nine DONE cards went through the approval path (`request_approval` -> `decide_approval`), so
`agent` could not have written them.

## 2. Serve

```powershell
& "$root\.venv\Scripts\python.exe" -m uvicorn "apkplat.api.app:create_app" --factory --host 127.0.0.1 --port 8792
```

Observed `/api/health`: `{"status": "ok", "version": "1.0.0", "auth_mode": "local"}`.

## 3. Board

Open `http://127.0.0.1:8792/`. Screenshot: `reports/ui/gate7-board.png`.

- Four columns render 10 / 1 / 1 / 9, matching the database exactly (`board_matches_database` in
  `reports/gate2`).
- Each card shows a role avatar (PL / EX / RE / SH / EV), the role, priority `p5`, version, and
  the evidence counter.
- The metrics strip reads: projects 1, tasks 21, ingest success rate 1, evidence traceability
  rate 1, project isolation failures 0, device lease collision 0.

## 4. Card drawer

Click *S0 Scope the engagement*. Screenshot: `reports/ui/gate7-drawer.png`.

- Header: status DONE, task id, role `plan`, priority, attempt, version, counters.
- **AGENT RUNS** table comes from `GET /api/tasks/{id}/runs`.
- **REVIEW CHECKS** shows `PASS · S0 Scope the engagement produced the artifacts it promised ·
  16:27:22 · p7-seed`, i.e. a row from `task_checks`, written by the reviewer path, not by the
  author.

## 5. Real analysis on the sample APK

```powershell
& "$root\.venv\Scripts\python.exe" "$root\scripts\apkplat_cli.py" create --name reef-demo --apk "$root\samples\sample-app.apk"
& "$root\.venv\Scripts\python.exe" "$root\scripts\apkplat_cli.py" worker --once
& "$root\.venv\Scripts\python.exe" "$root\scripts\apkplat_cli.py" verify <project_id>
& "$root\.venv\Scripts\python.exe" "$root\scripts\apkplat_cli.py" report <project_id>
```

Observed: pipeline `validated: 6 entries` -> `apktool exit 0` -> `jadx: 7 java files` ->
`index {'units': 43, 'strings': 134, ...}` -> `evidence rows: 12`; `verify` reports
`artifacts {checked: 9, ok: 9, failures: []}` and `traceability_rate 1.0`; `report` writes both
`.md` and `.html` with a `Verification` block containing `PASS`.

## 6. Agent loop with the real model

```powershell
& "$root\.venv\Scripts\python.exe" "$root\scripts\p1_g1_accept.py"
```

Observed: `orchestrate status=review_ready`, 27-28 tool calls paired between the plugin trace and
the server audit, `second_call_informed_by_first_result` listing derivations such as
`call#8 apk_inspect target='SyncService' <- call#1`. Report: `audit/g1_acceptance.md` (17/17).

## 7. Device chain

```powershell
& "$root\.venv\Scripts\python.exe" "$root\scripts\p5_g5_accept.py"
```

Observed: steps `probe -> install -> launch -> ui -> observe -> screenshot`, one permission dialog
handled, evidence traceability 1.0, and the four cleanup modes behaving as their names promise
(`PRESERVE_SESSION` issues zero stop/uninstall calls). The real handset probe in the same run took
a 15197-byte PNG and read 2 nodes, then stopped - no destructive call was made on the phone.

## 8. What this walkthrough does not show

- No screen recording exists; the images above are the only visual record.
- The synthetic cards are UI fixtures. They are not a production history and the platform marks
  them as such.
- Capture remains `NOT_OBSERVED` until a ProxyPin export is placed in `APKPLAT_CAPTURE_DIR`.
