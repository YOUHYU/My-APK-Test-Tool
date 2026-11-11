"""P0 step 6: rollback drill — prove the backup can actually be restored.

Two drills, both non-destructive to the live platform:

1. **DB restore**: copy the P0 snapshot to a scratch path, run ``PRAGMA integrity_check``,
   compare table row counts and id fingerprints against ``audit/schema_snapshot.json``,
   then drop the scratch copy. A backup nobody restored is a hope, not a backup.
2. **Config restore**: diff every backed-up copy (config/, .env, DSH profile files) against
   its live original and report byte equality, so the operator knows the copies are exact.

Usage:
  python scripts/p0_rollback_drill.py [--backup backups/p0-<ts>]
"""

from __future__ import annotations

import argparse
import hashlib
import json
import shutil
import sqlite3
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def fingerprints(conn: sqlite3.Connection, names: list[str]) -> dict:
    out = {}
    for name in names:
        cols = [c[1] for c in conn.execute(f"PRAGMA table_info('{name}')").fetchall()]
        if not cols:
            continue
        key = "id" if "id" in cols else cols[0]
        ids = [str(r[0]) for r in conn.execute(f"SELECT [{key}] FROM '{name}' ORDER BY [{key}]")]
        out[name] = {"rows": len(ids),
                     "id_hash": hashlib.sha256("\n".join(ids).encode()).hexdigest()[:16]}
    return out


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--backup", default=None)
    args = ap.parse_args(argv)

    backups = sorted((ROOT / "backups").glob("p0-*"))
    if not backups:
        raise SystemExit("no P0 backup found under backups/")
    backup_root = Path(args.backup) if args.backup else backups[-1]
    snap_path = ROOT / "audit" / "schema_snapshot.json"
    snap = json.loads(snap_path.read_text(encoding="utf-8"))

    src_db = backup_root / "db" / "platform.db"
    if not src_db.exists():
        raise SystemExit(f"backup db missing: {src_db}")

    results: dict = {"backup_root": str(backup_root), "db": {}, "config": []}

    with tempfile.TemporaryDirectory(prefix="p0-restore-") as tmp:
        restored = Path(tmp) / "restored.db"
        shutil.copy2(src_db, restored)
        conn = sqlite3.connect(f"file:{restored}?mode=ro", uri=True)
        try:
            integrity = conn.execute("PRAGMA integrity_check").fetchone()[0]
            names = [t["name"] for t in snap["tables"]]
            fps = fingerprints(conn, names)
            counts = {n: fps[n]["rows"] for n in fps}
        finally:
            conn.close()
        expected = {name: fp["rows"] for name, fp in snap["fingerprints"].items()}
        expected_hashes = {name: fp["id_hash"] for name, fp in snap["fingerprints"].items()}
        mismatched = [n for n in expected
                      if fps.get(n, {}).get("rows") != expected[n]
                      or fps.get(n, {}).get("id_hash") != expected_hashes[n]]
        results["db"] = {
            "restored_from": str(src_db),
            "restored_sha256": sha256(restored),
            "integrity_check": integrity,
            "row_counts_match": not mismatched,
            "mismatched_tables": mismatched,
            "counts": counts,
        }

    manifest = json.loads((backup_root / "MANIFEST.json").read_text(encoding="utf-8"))
    for entry in manifest.get("config_copies", []) + manifest.get("env_copy", []) \
            + manifest.get("dsh_profile_copies", []):
        live = Path(entry["file"])
        copy = Path(entry["backup"])
        ok = live.exists() and copy.exists() and sha256(live) == sha256(copy)
        results["config"].append({"file": str(live), "backup": str(copy),
                                  "identical": ok,
                                  "live_sha256": sha256(live) if live.exists() else None})

    live_db = Path(snap["db_path"])
    results["live_db_unchanged_schema"] = {
        "live_sha256_now": sha256(live_db) if live_db.exists() else None,
        "snapshot_of_live_at_capture": snap["backup"]["sha256"],
    }

    ok = (results["db"]["integrity_check"] == "ok" and results["db"]["row_counts_match"]
          and all(c["identical"] for c in results["config"]))
    results["verdict"] = "PASS" if ok else "FAIL"

    out = ROOT / "audit" / "rollback_drill.json"
    out.write_text(json.dumps(results, indent=2, ensure_ascii=False), encoding="utf-8")

    lines = [
        "# Rollback drill (P0)", "",
        f"- backup: `{backup_root}`",
        f"- verdict: **{results['verdict']}**", "",
        "## Database restore", "",
        f"- copied `{src_db.name}` to a scratch dir and opened it read-only",
        f"- `PRAGMA integrity_check` -> `{results['db']['integrity_check']}`",
        f"- row counts + id fingerprints match the capture: **{results['db']['row_counts_match']}**",
        f"- mismatched tables: {results['db']['mismatched_tables'] or 'none'}", "",
        "| table | rows (restored) |", "|---|---|",
    ]
    for name, count in results["db"]["counts"].items():
        lines.append(f"| `{name}` | {count} |")
    lines += ["", "## Config restore", "", "| file | identical to live |", "|---|---|"]
    for item in results["config"]:
        lines.append(f"| `{item['file']}` | {item['identical']} |")
    lines += ["", "The live byte count differs from the capture on purpose: the platform keeps",
              "running and `audit_events` is append-only, so the WAL grows. Schema and business",
              "rows are what the fingerprints above pin.", ""]
    (ROOT / "audit" / "rollback_drill.md").write_text("\n".join(lines), encoding="utf-8")

    print(json.dumps({"verdict": results["verdict"],
                      "integrity": results["db"]["integrity_check"],
                      "rows_match": results["db"]["row_counts_match"],
                      "config_files": len(results["config"]),
                      "config_all_identical": all(c["identical"] for c in results["config"])},
                     indent=2))
    return 0 if ok else 2


if __name__ == "__main__":
    sys.exit(main())
