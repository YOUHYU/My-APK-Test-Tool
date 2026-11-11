"""P0 step 1+2: back up state, then dump the real schema of the platform DB.

Writes:
  backups/p0-<ts>/...            (db snapshot via sqlite backup API, schema.sql, config copies, manifest)
  audit/schema_snapshot.json     (machine-readable: tables/columns/indexes/triggers/fks/row counts)
  audit/schema_snapshot.md       (human-readable, generated from the JSON)

Read-only with respect to the platform DB: it opens a second connection and uses
sqlite3's online backup API, so the live platform keeps running.

Usage:
  python scripts/p0_snapshot.py [--label p0-YYYYmmdd-HHMMSS]
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
import sqlite3
import subprocess
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
BACKEND = ROOT / "backend"
sys.path.insert(0, str(BACKEND))

os.environ.setdefault("APKPLAT_STORAGE", str(ROOT / "storage"))
os.environ.setdefault("APKPLAT_REPORTS", str(ROOT / "reports"))
os.environ.setdefault("APKPLAT_TOOLS", str(ROOT / "tools"))

from apkplat import state as state_mod  # noqa: E402

DSH_PROFILE_DIR = Path(os.path.expanduser("~")) / ".dsh" / "profiles" / "desktop"
DSH_PROFILE_FILES = ("cordis.patch.yml", "cordis.yml")


def sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def db_url_to_path(url: str) -> Path:
    if not url.startswith("sqlite:///"):
        raise SystemExit(f"only sqlite URLs are supported here, got {url!r}")
    return Path(url[len("sqlite:///"):])


def backup_db(src: Path, dest: Path) -> dict:
    dest.parent.mkdir(parents=True, exist_ok=True)
    if dest.exists():
        dest.unlink()
    source = sqlite3.connect(f"file:{src}?mode=ro", uri=True, timeout=30)
    target = sqlite3.connect(str(dest))
    try:
        source.backup(target)
        target.execute("PRAGMA wal_checkpoint(TRUNCATE)")
    finally:
        target.close()
        source.close()
    verify = sqlite3.connect(f"file:{dest}?mode=ro", uri=True)
    try:
        integrity = verify.execute("PRAGMA integrity_check").fetchone()[0]
        tables = verify.execute(
            "SELECT count(*) FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'"
        ).fetchone()[0]
    finally:
        verify.close()
    return {"path": str(dest), "bytes": dest.stat().st_size, "sha256": sha256(dest),
            "integrity_check": integrity, "tables": tables}


def dump_schema(conn: sqlite3.Connection) -> dict:
    tables = []
    rows = conn.execute(
        "SELECT name, sql FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%' "
        "ORDER BY name"
    ).fetchall()
    for name, sql in rows:
        cols = [
            {"name": r[1], "type": r[2], "notnull": bool(r[3]), "default": r[4], "pk": bool(r[5])}
            for r in conn.execute(f"PRAGMA table_info('{name}')").fetchall()
        ]
        idx = [
            {"name": r[1], "unique": bool(r[2]), "origin": r[3], "partial": bool(r[4]),
             "columns": [c[2] for c in conn.execute(f"PRAGMA index_info('{r[1]}')").fetchall()]}
            for r in conn.execute(f"PRAGMA index_list('{name}')").fetchall()
        ]
        fks = [
            {"from": r[3], "table": r[2], "to": r[4], "on_delete": r[6]}
            for r in conn.execute(f"PRAGMA foreign_key_list('{name}')").fetchall()
        ]
        count = conn.execute(f"SELECT count(*) FROM '{name}'").fetchone()[0]
        tables.append({"name": name, "columns": cols, "indexes": idx,
                       "foreign_keys": fks, "row_count": count, "ddl": sql})
    triggers = [
        {"name": r[0], "table": r[1], "ddl": r[2]}
        for r in conn.execute(
            "SELECT name, tbl_name, sql FROM sqlite_master WHERE type='trigger' ORDER BY name"
        ).fetchall()
    ]
    views = [r[0] for r in conn.execute(
        "SELECT name FROM sqlite_master WHERE type='view' ORDER BY name").fetchall()]
    migrations = []
    if any(t["name"] == "schema_migrations" for t in tables):
        migrations = [r[0] for r in conn.execute(
            "SELECT name FROM schema_migrations ORDER BY name").fetchall()]
    return {"tables": tables, "triggers": triggers, "views": views, "migrations": migrations}


def fingerprints(conn: sqlite3.Connection, table_names: list[str]) -> dict:
    """Row-level fingerprint per table: count + ordered id hash, to prove data stability."""
    out = {}
    for name in table_names:
        cols = [c[1] for c in conn.execute(f"PRAGMA table_info('{name}')").fetchall()]
        key = "id" if "id" in cols else cols[0]
        rows = conn.execute(f"SELECT [{key}] FROM '{name}' ORDER BY [{key}]").fetchall()
        ids = [str(r[0]) for r in rows]
        h = hashlib.sha256("\n".join(ids).encode()).hexdigest()[:16]
        out[name] = {"rows": len(ids), "id_hash": h}
    return out


def copy_tree_files(src_dir: Path, dest_dir: Path, names) -> list[dict]:
    dest_dir.mkdir(parents=True, exist_ok=True)
    copied = []
    for name in names:
        src = src_dir / name
        if not src.exists():
            continue
        dest = dest_dir / name
        shutil.copy2(src, dest)
        copied.append({"file": str(src), "backup": str(dest), "bytes": dest.stat().st_size,
                       "sha256": sha256(dest)})
    return copied


def cmd_output(cmd: list[str], timeout: int = 20) -> str:
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout,
                              encoding="utf-8", errors="replace")
        return (proc.stdout or "") + (proc.stderr or "")
    except Exception as exc:  # noqa: BLE001 - diagnostics only
        return f"<error: {exc}>"


def markdown(snapshot: dict) -> str:
    lines = ["# Schema snapshot (P0)", "",
             f"- generated_at: `{snapshot['generated_at']}`",
             f"- database: `{snapshot['db_path']}`",
             f"- migrations applied: {', '.join(snapshot['migrations']) or '(none)'}",
             f"- tables: {len(snapshot['tables'])}",
             f"- triggers: {len(snapshot['triggers'])}",
             "", "## Tables", "",
             "| table | rows | columns | indexes | fkeys |",
             "|---|---|---|---|---|"]
    for t in snapshot["tables"]:
        lines.append(f"| `{t['name']}` | {t['row_count']} | {len(t['columns'])} | "
                     f"{len(t['indexes'])} | {len(t['foreign_keys'])} |")
    lines += ["", "## Columns per table", ""]
    for t in snapshot["tables"]:
        cols = ", ".join(
            f"`{c['name']}`" + ("" if not c["type"] else f" {c['type']}")
            + (" PK" if c["pk"] else "") + (" NOT NULL" if c["notnull"] else "")
            for c in t["columns"])
        lines.append(f"### `{t['name']}` ({t['row_count']} rows)")
        lines.append("")
        lines.append(cols)
        lines.append("")
        if t["foreign_keys"]:
            lines.append("foreign keys: " + ", ".join(
                f"`{fk['from']} -> {fk['table']}.{fk['to']}`" for fk in t["foreign_keys"]))
            lines.append("")
        if t["indexes"]:
            lines.append("indexes: " + ", ".join(
                f"`{i['name']}`({', '.join(i['columns'])})" + (" unique" if i["unique"] else "")
                for i in t["indexes"]))
            lines.append("")
    lines += ["## Triggers", ""]
    for trg in snapshot["triggers"]:
        lines.append(f"- `{trg['name']}` on `{trg['table']}`")
    lines += ["", "## Task status state machine (12 states, unchanged)", "",
              "| status | kanban column | terminal |",
              "|---|---|---|"]
    for status in state_mod.STATUSES:
        lines.append(f"| `{status}` | {state_mod.column_of(status)} | "
                     f"{'yes' if status in state_mod.TERMINAL else 'no'} |")
    lines += ["", "## Row fingerprints (for the data-unchanged proof)", "",
              "| table | rows | id_hash |", "|---|---|---|"]
    for name, fp in snapshot["fingerprints"].items():
        lines.append(f"| `{name}` | {fp['rows']} | `{fp['id_hash']}` |")
    lines.append("")
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--label", default=None)
    args = ap.parse_args(argv)

    ts = time.strftime("%Y%m%d-%H%M%S")
    label = args.label or f"p0-{ts}"
    backup_root = ROOT / "backups" / label
    audit_dir = ROOT / "audit"
    audit_dir.mkdir(parents=True, exist_ok=True)

    from apkplat.config import settings

    db_path = db_url_to_path(settings.db_url)
    if not db_path.exists():
        raise SystemExit(f"platform db not found: {db_path}")

    before_sha = sha256(db_path)
    db_snapshot = backup_db(db_path, backup_root / "db" / "platform.db")

    conn = sqlite3.connect(f"file:{db_snapshot['path']}?mode=ro", uri=True)
    conn.row_factory = sqlite3.Row
    try:
        schema = dump_schema(conn)
        fps = fingerprints(conn, [t["name"] for t in schema["tables"]])
    finally:
        conn.close()

    config_copies = copy_tree_files(ROOT / "config", backup_root / "config",
                                    sorted(p.name for p in (ROOT / "config").glob("*") if p.is_file()))
    env_file = ROOT / ".env"
    env_copy = None
    if env_file.exists():
        env_copy = copy_tree_files(ROOT, backup_root / "env", [".env"])
    dsh_copies = copy_tree_files(DSH_PROFILE_DIR, backup_root / "dsh", DSH_PROFILE_FILES)

    tools_versions = cmd_output([sys.executable, str(ROOT / "scripts" / "apkplat_cli.py"), "versions"])
    adb_devices = cmd_output([str(ROOT / "tools" / "android-sdk" / "platform-tools" / "adb.exe"),
                              "devices", "-l"])

    manifest = {
        "label": label,
        "generated_at": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
        "source_db": {"path": str(db_path), "bytes_before": db_path.stat().st_size,
                      "sha256_before": before_sha},
        "db_snapshot": db_snapshot,
        "config_copies": config_copies,
        "env_copy": env_copy,
        "dsh_profile_copies": dsh_copies,
        "tools_versions": tools_versions.strip(),
        "adb_devices": adb_devices.strip(),
        "python": sys.version.split()[0],
        "cwd": str(Path.cwd()),
    }
    (backup_root).mkdir(parents=True, exist_ok=True)
    (backup_root / "MANIFEST.json").write_text(json.dumps(manifest, indent=2), encoding="utf-8")

    snapshot = {
        "generated_at": manifest["generated_at"],
        "label": label,
        "db_path": str(db_path),
        "backup": db_snapshot,
        "migrations": schema["migrations"],
        "tables": schema["tables"],
        "triggers": schema["triggers"],
        "views": schema["views"],
        "fingerprints": fps,
        "state_machine": {
            "statuses": list(state_mod.STATUSES),
            "columns": list(state_mod.KANBAN_COLUMNS),
            "column_of": {s: state_mod.column_of(s) for s in state_mod.STATUSES},
            "terminal": sorted(state_mod.TERMINAL),
            "transitions": {k: sorted(v) for k, v in state_mod.TRANSITIONS.items()},
            "guarded_targets": {k: sorted(v) for k, v in state_mod.GUARDED_TARGETS.items()},
        },
        "tools_versions": manifest["tools_versions"],
        "adb_devices": manifest["adb_devices"],
    }
    (audit_dir / "schema_snapshot.json").write_text(json.dumps(snapshot, indent=2), encoding="utf-8")
    (audit_dir / "schema_snapshot.md").write_text(markdown(snapshot), encoding="utf-8")

    print(json.dumps({
        "backup_root": str(backup_root),
        "db_sha256_before": before_sha,
        "snapshot_sha256": db_snapshot["sha256"],
        "tables": len(snapshot["tables"]),
        "triggers": len(snapshot["triggers"]),
        "migrations": snapshot["migrations"],
        "row_counts": {t["name"]: t["row_count"] for t in snapshot["tables"]},
    }, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
