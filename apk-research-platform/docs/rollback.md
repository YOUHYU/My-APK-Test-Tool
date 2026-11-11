# Rollback

Two different things get rolled back: the platform (ours) and the host configuration (not ours).
The host was never modified - nothing was installed outside the project directory and the DSH
profile was copied, never edited.

## 1. Backups that exist

| Backup | Contents | Created by |
| --- | --- | --- |
| `backups/p0-<stamp>/db/platform.db` | Byte-exact snapshot of the live database (sqlite backup API) | `scripts/p0_snapshot.py` |
| `backups/p0-<stamp>/config/` | `worker-policy.yml`, `.env`, both DSH profile files | same |
| `backups/p0-<stamp>/MANIFEST.json` | sha256 of every file, row counts, schema fingerprints | same |

The drill that proves these restore correctly is `scripts/p0_rollback_drill.py`; its output
(`audit/rollback_drill.json`) records `integrity_check = ok` plus identical row counts and id
hashes for all 13 tables.

## 2. Rolling back application code

```powershell
pwsh -File "$root\scripts\platform.ps1" stop
git -C "$root" checkout <previous-tag>      # or restore the folder copy you kept
& "$root\.venv\Scripts\python.exe" "$root\scripts\apkplat_cli.py" init
pwsh -File "$root\scripts\platform.ps1" start
```

Migrations 001-008 are additive. Downgrading past a schema change therefore needs the database
restored as well, not just the code.

## 3. Rolling back the database

Copying `platform.db` while the API is running is **not** a safe restore: WAL pages live in
`platform.db-wal` and triggers added by migration 002 forward-reference the schema. Restore with
the sqlite backup API and then verify:

```powershell
pwsh -File "$root\scripts\platform.ps1" stop
& "$root\.venv\Scripts\python.exe" -c "import sqlite3,shutil,pathlib; src=pathlib.Path(r'backups/p0-<stamp>/db/platform.db'); dst=pathlib.Path(r'storage/platform.db'); [p.unlink() for p in (dst.with_suffix('.db-wal'), dst.with_suffix('.db-shm')) if p.exists()]; s=sqlite3.connect(src); d=sqlite3.connect(dst); s.backup(d); d.close(); s.close(); print('restored')"
& "$root\.venv\Scripts\python.exe" -c "import sqlite3; c=sqlite3.connect(r'storage/platform.db'); print(c.execute('pragma integrity_check').fetchone()[0]); print(c.execute(\"select count(*) from audit_events\").fetchone()[0])"
pwsh -File "$root\scripts\platform.ps1" start
```

## 4. Rolling back individual capabilities

| Capability | How to switch it off |
| --- | --- |
| Static cache | `APKPLAT_CACHE_ENABLED=0`, or delete `storage/cache` (misses are logged, never fatal). |
| Model narration | `APKPLAT_MODEL_ENABLED=0`; every agent path has a deterministic branch. |
| Bridge tools | Revoke the run: `POST /api/runs/<run_id>/revoke`, or do not register the plugin. |
| Periodic jobs | `PATCH /api/periodic/<id>` with `{"enabled": false}`; the scheduler skips it next tick. |
| Device work | Quarantine the device: `POST /api/devices/<serial>/quarantine`; the pool stops leasing it. |
| MCP server | Remove the `insert` entry from the DSH overlay and restart DSH. |

## 5. What cannot be rolled back

- Rows in `audit_events`, `task_checks`, `platform_events`, `evidence_objects`, and
  `sandbox_runs` are append-only; triggers abort `UPDATE` and `DELETE`. Their value is precisely
  that they cannot be rewritten. Restoring an older database copy is the only way to remove them,
  and that also discards everything recorded after the snapshot.
- A device quarantine is a statement about hardware state; clear it with
  `POST /api/devices/<serial>/quarantine/clear` only after a human has looked at the device.

## 6. Verification after a rollback

```powershell
pwsh -File "$root\scripts\platform.ps1" check
& "$root\.venv\Scripts\python.exe" -m pytest "$root\tests" -q
& "$root\.venv\Scripts\python.exe" "$root\scripts\p0_g0_accept.py"
```

The first command must report the toolchain verdicts and a non-empty audit sequence; the second
must end with the same pass count recorded in `reports/README.md`.
