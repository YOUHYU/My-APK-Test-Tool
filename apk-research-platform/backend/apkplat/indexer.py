"""Per-project code index (SQLite + FTS5) and the queries built on it.

The index lives at ``storage/projects/<id>/indexes/index.db`` — one file per
project, opened by path. There is no global index, so a query for project A can
never return a row from project B even if it wanted to: the isolation is in the
filesystem layout, not in a WHERE clause.
"""
from __future__ import annotations

import json
import re
import sqlite3
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Any, Iterable

from .config import settings

MAX_UNITS = 200_000
MAX_STRINGS = 100_000

# unit kind -> counter key
_PLURAL = {"class": "classes", "method": "methods", "field": "fields"}

SCHEMA = """
CREATE TABLE IF NOT EXISTS meta(key TEXT PRIMARY KEY, value TEXT);
CREATE TABLE IF NOT EXISTS units(
  id INTEGER PRIMARY KEY,
  kind TEXT NOT NULL,            -- class | method | field
  class_name TEXT NOT NULL,
  member TEXT,
  signature TEXT,
  package TEXT,
  source_kind TEXT NOT NULL,     -- java | smali
  file TEXT NOT NULL,
  start_line INTEGER,
  end_line INTEGER,
  preview TEXT
);
CREATE TABLE IF NOT EXISTS units_fts(class_name, member, signature, preview);
CREATE TABLE IF NOT EXISTS strings(id INTEGER PRIMARY KEY, value TEXT, source TEXT);
CREATE TABLE IF NOT EXISTS strings_fts(value);
CREATE TABLE IF NOT EXISTS resources(id INTEGER PRIMARY KEY, rtype TEXT, name TEXT, value TEXT, file TEXT);
CREATE TABLE IF NOT EXISTS resources_fts(name, value);
CREATE TABLE IF NOT EXISTS components(id INTEGER PRIMARY KEY, kind TEXT, name TEXT, exported INTEGER, permission TEXT, extra TEXT);
CREATE TABLE IF NOT EXISTS packages(name TEXT PRIMARY KEY, classes INTEGER, methods INTEGER, source TEXT);
CREATE INDEX IF NOT EXISTS units_class ON units(class_name);
CREATE INDEX IF NOT EXISTS units_member ON units(member);
CREATE INDEX IF NOT EXISTS components_name ON components(name);
"""


class IndexError_(RuntimeError):
    pass


def index_path(project_id: str) -> Path:
    path = settings.project_dir(project_id) / "indexes" / "index.db"
    path.parent.mkdir(parents=True, exist_ok=True)
    return path


def connect(project_id: str, *, create: bool = False) -> sqlite3.Connection:
    path = index_path(project_id)
    if not create and not path.exists():
        raise IndexError_(f"project {project_id} has no index yet (run the static stage first)")
    conn = sqlite3.connect(str(path), timeout=30)
    conn.row_factory = sqlite3.Row
    if create:
        conn.executescript(SCHEMA)
        conn.execute("PRAGMA journal_mode=WAL")
    return conn


# ---------------------------------------------------------------------------
# building
# ---------------------------------------------------------------------------
_PACKAGE_RE = re.compile(r"^\s*package\s+([\w.]+)\s*;")
_CLASS_RE = re.compile(
    r"^\s*(?:@[\w.]+(?:\([^)]*\))?\s*)*"
    r"(?:(?:public|private|protected|static|final|abstract|synchronized|native|default|strictfp|sealed|non-sealed)\s+)*"
    r"(class|interface|enum|record)\s+([\w$]+)"
)
_METHOD_RE = re.compile(
    r"^\s*(?:@[\w.]+(?:\([^)]*\))?\s*)*"
    r"(?:(?:public|private|protected|static|final|abstract|synchronized|native|default|strictfp)\s+)*"
    r"([\w$.\[\]<>, ?]+?)\s+([\w$]+)\s*\(([^;{}]*?)\)\s*(?:throws\s+[\w.,\s]+)?\{"
)
_FIELD_RE = re.compile(
    r"^\s*(?:(?:public|private|protected|static|final|volatile|transient)\s+)+([\w$.\[\]<>, ?]+?)\s+([\w$]+)\s*(?:=|;)",
)


def _brace_end(lines: list[str], start: int) -> int:
    depth = 0
    seen = False
    for i in range(start, min(len(lines), start + 4000)):
        line = lines[i]
        depth += line.count("{")
        if "{" in line:
            seen = True
        depth -= line.count("}")
        if seen and depth <= 0:
            return i
    return min(len(lines) - 1, start + 4000)


def index_java_tree(root: Path, rel_base: Path) -> Iterable[dict]:
    count = 0
    for path in sorted(root.rglob("*.java")):
        if count >= MAX_UNITS:
            return
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        lines = text.splitlines()
        package = ""
        current_class: str | None = None
        current_pkg = ""
        for i, line in enumerate(lines):
            m = _PACKAGE_RE.match(line)
            if m:
                package = m.group(1)
                continue
            m = _CLASS_RE.match(line)
            if m and "(" not in line.split("{")[0]:
                current_class = m.group(2)
                current_pkg = package
                class_name = f"{package}.{current_class}" if package else current_class
                end = _brace_end(lines, i)
                yield {
                    "kind": "class",
                    "class_name": class_name,
                    "member": current_class,
                    "signature": line.strip()[:300],
                    "package": package,
                    "source_kind": "java",
                    "file": path.relative_to(rel_base).as_posix(),
                    "start_line": i + 1,
                    "end_line": end + 1,
                    "preview": "\n".join(lines[i : min(i + 3, len(lines))])[:400],
                }
                count += 1
                if count >= MAX_UNITS:
                    return
                continue
            if current_class is None:
                continue
            m = _METHOD_RE.match(line)
            if m:
                ret, name, params = m.group(1).strip(), m.group(2), m.group(3).strip()
                class_name = f"{current_pkg}.{current_class}" if current_pkg else current_class
                end = _brace_end(lines, i)
                yield {
                    "kind": "method",
                    "class_name": class_name,
                    "member": name,
                    "signature": f"{ret} {name}({params})"[:500],
                    "package": current_pkg,
                    "source_kind": "java",
                    "file": path.relative_to(rel_base).as_posix(),
                    "start_line": i + 1,
                    "end_line": end + 1,
                    "preview": "\n".join(lines[i : min(i + 6, len(lines))])[:600],
                }
                count += 1
                if count >= MAX_UNITS:
                    return
                continue
            m = _FIELD_RE.match(line)
            if m and "(" not in line:
                class_name = f"{current_pkg}.{current_class}" if current_pkg else current_class
                yield {
                    "kind": "field",
                    "class_name": class_name,
                    "member": m.group(2),
                    "signature": line.strip()[:300],
                    "package": current_pkg,
                    "source_kind": "java",
                    "file": path.relative_to(rel_base).as_posix(),
                    "start_line": i + 1,
                    "end_line": i + 1,
                    "preview": line.strip()[:400],
                }
                count += 1
                if count >= MAX_UNITS:
                    return


def index_resources(res_dir: Path, rel_base: Path) -> tuple[list[dict], list[dict]]:
    resources: list[dict] = []
    for path in sorted(res_dir.rglob("*.xml"))[:5000]:
        if path.name != "strings.xml" and "values" not in path.parts:
            continue
        try:
            tree = ET.parse(path)
        except Exception:  # noqa: BLE001
            continue
        for node in tree.getroot():
            rtype = node.tag
            name = node.attrib.get("name")
            value = (node.text or "").strip()
            if not name:
                continue
            resources.append(
                {
                    "rtype": rtype,
                    "name": name,
                    "value": value[:1000],
                    "file": path.relative_to(rel_base).as_posix(),
                }
            )
    return resources, []


def build(
    project_id: str,
    *,
    apk: Path,
    java_root: Path | None,
    apktool_dir: Path | None,
    metadata: dict,
    dex_strings: list[str] | None = None,
    log=None,
) -> dict[str, Any]:
    path = index_path(project_id)
    if path.exists():
        path.unlink()
    conn = connect(project_id, create=True)
    counts = {"units": 0, "classes": 0, "methods": 0, "fields": 0, "strings": 0, "resources": 0, "components": 0}
    try:
        cur = conn.cursor()
        if java_root and java_root.exists():
            batch: list[tuple] = []
            fts: list[tuple] = []
            for unit in index_java_tree(java_root, java_root):
                cur.execute(
                    "INSERT INTO units(kind, class_name, member, signature, package, source_kind, file, start_line,"
                    " end_line, preview) VALUES(?,?,?,?,?,?,?,?,?,?)",
                    (
                        unit["kind"],
                        unit["class_name"],
                        unit["member"],
                        unit["signature"],
                        unit["package"],
                        unit["source_kind"],
                        unit["file"],
                        unit["start_line"],
                        unit["end_line"],
                        unit["preview"],
                    ),
                )
                fts.append((unit["class_name"], unit["member"], unit["signature"], unit["preview"]))
                counts["units"] += 1
                # kind is singular ("class"/"method"/"field"); the counter key is plural and
                # irregular for "class" — map it explicitly rather than appending "s".
                counts[_PLURAL[unit["kind"]]] = counts.get(_PLURAL[unit["kind"]], 0) + 1
                if log and counts["units"] % 2000 == 0:
                    log(f"indexed {counts['units']} units")
            cur.executemany("INSERT INTO units_fts(rowid, class_name, member, signature, preview) VALUES(?,?,?,?,?)",
                            [(i + 1, *row) for i, row in enumerate(fts)])
            batch.clear()

        for value in (dex_strings or [])[:MAX_STRINGS]:
            cur.execute("INSERT INTO strings(value, source) VALUES(?, ?)", (value, "dex"))
        cur.execute("INSERT INTO strings_fts(rowid, value) SELECT id, value FROM strings")
        counts["strings"] = cur.execute("SELECT COUNT(*) FROM strings").fetchone()[0]

        resources: list[dict] = []
        if apktool_dir and (apktool_dir / "res").exists():
            resources, _ = index_resources(apktool_dir / "res", apktool_dir)
        for res in resources[:20000]:
            cur.execute(
                "INSERT INTO resources(rtype, name, value, file) VALUES(?,?,?,?)",
                (res["rtype"], res["name"], res["value"], res["file"]),
            )
        cur.execute("INSERT INTO resources_fts(rowid, name, value) SELECT id, name, value FROM resources")
        counts["resources"] = len(resources)

        for kind, key in (("activity", "activities"), ("service", "services"), ("receiver", "receivers"), ("provider", "providers")):
            for name in metadata.get(key) or []:
                cur.execute(
                    "INSERT INTO components(kind, name, exported, permission, extra) VALUES(?,?,?,?,?)",
                    (kind, name, None, None, None),
                )
                counts["components"] += 1

        pkg_counts: dict[str, list[int]] = {}
        for row in cur.execute("SELECT package, kind, COUNT(*) FROM units GROUP BY package, kind"):
            bucket = pkg_counts.setdefault(row[0] or "", [0, 0])
            bucket[0 if row[1] == "class" else 1] += int(row[2])
        for pkg, (classes, methods) in pkg_counts.items():
            cur.execute(
                "INSERT OR REPLACE INTO packages(name, classes, methods, source) VALUES(?,?,?,?)",
                (pkg, classes, methods, "java"),
            )
        for key, value in {
            "project_id": project_id,
            "package": metadata.get("package") or "",
            "version_name": metadata.get("version_name") or "",
            **{k: str(v) for k, v in counts.items()},
        }.items():
            cur.execute("INSERT OR REPLACE INTO meta(key, value) VALUES(?,?)", (key, value))
        conn.commit()
    finally:
        conn.close()
    return counts


# ---------------------------------------------------------------------------
# queries
# ---------------------------------------------------------------------------
def _fts_query(value: str) -> str:
    cleaned = re.sub(r'["\']', " ", value).strip()
    if not cleaned:
        raise ValueError("empty query")
    tokens = [t for t in re.split(r"\s+", cleaned) if t]
    return " ".join(f'"{t}"*' if len(t) >= 3 else f'"{t}"' for t in tokens)


def search_code(
    project_id: str,
    query: str,
    *,
    kind: str | None = None,
    limit: int = 50,
    mode: str = "fts",
) -> list[dict]:
    conn = connect(project_id)
    try:
        sql_kind = " AND u.kind = ?" if kind else ""
        params: list[Any] = []
        if mode == "like":
            sql = (
                "SELECT u.* FROM units u WHERE (u.class_name LIKE ? OR u.member LIKE ? OR u.signature LIKE ?"
                " OR u.preview LIKE ?)" + sql_kind + " ORDER BY u.id LIMIT ?"
            )
            pattern = f"%{query}%"
            params = [pattern, pattern, pattern, pattern] + ([kind] if kind else []) + [limit]
        else:
            sql = (
                "SELECT u.* FROM units_fts f JOIN units u ON u.id = f.rowid"
                " WHERE units_fts MATCH ?" + sql_kind + " ORDER BY rank LIMIT ?"
            )
            params = [_fts_query(query)] + ([kind] if kind else []) + [limit]
        try:
            rows = conn.execute(sql, params).fetchall()
        except sqlite3.OperationalError:
            return search_code(project_id, query, kind=kind, limit=limit, mode="like")
        return [dict(row) for row in rows]
    finally:
        conn.close()


def get_method(project_id: str, class_name: str, method: str, *, max_lines: int = 400) -> dict | None:
    conn = connect(project_id)
    try:
        row = conn.execute(
            "SELECT * FROM units WHERE kind IN ('method','class') AND class_name = ? AND member = ?"
            " ORDER BY CASE kind WHEN 'method' THEN 0 ELSE 1 END LIMIT 1",
            (class_name, method),
        ).fetchone()
        if not row:
            row = conn.execute(
                "SELECT * FROM units WHERE kind = 'method' AND class_name LIKE ? AND member = ? LIMIT 1",
                (f"%{class_name}", method),
            ).fetchone()
        if not row:
            return None
        unit = dict(row)
        root = settings.project_dir(project_id) / "artifacts" / "jadx"
        candidate = root / unit["file"]
        if not candidate.exists():
            candidate = _find_file(project_id, unit["file"])
        if not candidate or not candidate.exists():
            return {**unit, "source": None, "note": "source file not found on disk"}
        lines = candidate.read_text(encoding="utf-8", errors="replace").splitlines()
        start = max((unit["start_line"] or 1) - 1, 0)
        end = min(unit["end_line"] or start + 1, len(lines), start + max_lines)
        return {
            **unit,
            "source": "\n".join(lines[start:end]),
            "abs_file": str(candidate),
            "line_start": start + 1,
            "line_end": end,
            "truncated": end < (unit["end_line"] or end),
        }
    finally:
        conn.close()


def _find_file(project_id: str, rel: str) -> Path | None:
    base = settings.project_dir(project_id) / "artifacts"
    target = base / rel
    if target.exists():
        return target
    name = Path(rel).name
    for hit in base.rglob(name):
        return hit
    return None


def list_packages(project_id: str, limit: int = 200) -> list[dict]:
    conn = connect(project_id)
    try:
        rows = conn.execute("SELECT * FROM packages ORDER BY classes DESC, name LIMIT ?", (limit,)).fetchall()
        return [dict(row) for row in rows]
    finally:
        conn.close()


def search_resources(project_id: str, query: str, limit: int = 50) -> list[dict]:
    conn = connect(project_id)
    try:
        rows = conn.execute(
            "SELECT * FROM resources WHERE name LIKE ? OR value LIKE ? ORDER BY name LIMIT ?",
            (f"%{query}%", f"%{query}%", limit),
        ).fetchall()
        return [dict(row) for row in rows]
    finally:
        conn.close()


def search_strings(project_id: str, query: str, limit: int = 50) -> list[dict]:
    conn = connect(project_id)
    try:
        rows = conn.execute(
            "SELECT id, value FROM strings WHERE value LIKE ? ORDER BY id LIMIT ?", (f"%{query}%", limit)
        ).fetchall()
        return [dict(row) for row in rows]
    finally:
        conn.close()


def components(project_id: str, kind: str | None = None) -> list[dict]:
    conn = connect(project_id)
    try:
        sql = "SELECT * FROM components" + (" WHERE kind = ?" if kind else "") + " ORDER BY kind, name"
        rows = conn.execute(sql, ((kind,) if kind else ())).fetchall()
        return [dict(row) for row in rows]
    finally:
        conn.close()


def stats(project_id: str) -> dict[str, Any]:
    conn = connect(project_id)
    try:
        meta = {row["key"]: row["value"] for row in conn.execute("SELECT * FROM meta")}
        meta["index_bytes"] = index_path(project_id).stat().st_size
        return meta
    finally:
        conn.close()


def dump_json(project_id: str) -> str:
    return json.dumps(stats(project_id), indent=2)
