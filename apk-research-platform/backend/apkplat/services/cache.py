"""Content-addressed analysis cache for APKs (P4).

Keyed by the APK digest, because a filename proves nothing: the same bytes uploaded twice
must not pay for jadx and apktool again. The cache stores the *derived* trees (decoded
resources, decompiled sources, facts, findings, index) plus the artifact manifest needed to
re-register them in a fresh project, so a cache hit is a copy, not a re-analysis.

Deliberate limits: the extracted zip is not cached (it is cheap to reproduce), and entries
larger than ``settings.cache_max_mb`` are simply not stored - a cache that silently fills
the disk is worse than no cache.
"""
from __future__ import annotations

import shutil
from pathlib import Path
from typing import Any

from .. import audit
from ..db import db, utcnow
from ..util import dumps, loads, project_layout, rel_to_storage, sha256_file

# Directories/files worth copying back. Paths are relative to the project root, which is
# also how the index and the findings files refer to them (e.g. "com/example/Reef.java"
# inside artifacts/jadx/sources), so a straight copy keeps every reference valid.
CACHED_PARTS = (
    "artifacts/apktool",
    "artifacts/jadx",
    "artifacts/facts.json",
    "artifacts/findings.json",
    "indexes",
)

# Artifact kinds to re-register on restore, with the tool label used originally.
RESTORE_KINDS = {
    "facts.json": ("metadata", "androguard", "4.1.4"),
    "findings.json": ("findings", "apkplat.scan", "1.0"),
}


def _settings():
    from ..config import settings  # local import keeps the module importable in tests

    return settings


def digest(apk: Path) -> str:
    return sha256_file(apk)


def cache_root() -> Path:
    root = Path(_settings().storage) / "cache" / "apk"
    root.mkdir(parents=True, exist_ok=True)
    return root


def entry_dir(sha256: str) -> Path:
    return cache_root() / sha256[:2] / sha256


def get(sha256: str) -> dict[str, Any] | None:
    row = db.one("SELECT * FROM apk_cache WHERE sha256 = ?", (sha256,))
    if row is None:
        return None
    data = dict(row)
    root = Path(data["cache_root"])
    if not root.exists():
        # A row without bytes is a lie the pipeline would trip over; drop it loudly.
        audit.record("cache_entry_missing", payload={"sha256": sha256, "cache_root": str(root)}, actor="system")
        db.execute("DELETE FROM apk_cache WHERE sha256 = ?", (sha256,))
        return None
    data["artifacts"] = loads(data["artifacts_json"], []) or []
    return data


def put(project_id: str, sha256: str, *, metadata: dict[str, Any] | None = None) -> dict[str, Any] | None:
    """Copy this project's derived trees into the cache. Returns the row or None if too big."""
    settings = _settings()
    layout = project_layout(project_id)
    base = Path(layout["base"])
    target = entry_dir(sha256)
    if target.exists():
        shutil.rmtree(target, ignore_errors=True)
    target.mkdir(parents=True, exist_ok=True)

    copies: list[dict[str, str]] = []
    total = 0
    for part in CACHED_PARTS:
        source = base / part
        if not source.exists():
            continue
        destination = target / part
        destination.parent.mkdir(parents=True, exist_ok=True)
        if source.is_dir():
            shutil.copytree(source, destination, dirs_exist_ok=True)
            total += sum(item.stat().st_size for item in destination.rglob("*") if item.is_file())
        else:
            shutil.copy2(source, destination)
            total += destination.stat().st_size
        copies.append({"rel": part})

    limit = int(settings.cache_max_mb) * 1024 * 1024
    if total > limit:
        shutil.rmtree(target, ignore_errors=True)
        audit.record(
            "cache_entry_skipped",
            project_id=project_id,
            payload={"sha256": sha256, "bytes": total, "limit_bytes": limit},
            actor="system",
        )
        return None

    metadata = metadata or {}
    artifact_rows: list[dict[str, str]] = []
    for part in ("artifacts/facts.json", "artifacts/findings.json"):
        if (target / part).exists():
            kind, tool, version = RESTORE_KINDS[Path(part).name]
            artifact_rows.append({"rel": part, "kind": kind, "tool": tool, "tool_version": version})
    if (target / "indexes/index.db").exists():
        artifact_rows.append({"rel": "indexes/index.db", "kind": "index", "tool": "apkplat.indexer", "tool_version": "1.0"})

    apk_size = 0
    apk = Path(layout["inputs"]) / f"base-{sha256[:12]}.apk"
    if apk.exists():
        apk_size = apk.stat().st_size

    now = utcnow()
    existing = db.one("SELECT sha256 FROM apk_cache WHERE sha256 = ?", (sha256,))
    if existing:
        db.execute(
            "UPDATE apk_cache SET package_name=?, version_name=?, version_code=?, size_bytes=?, cache_root=?,"
            " artifacts_json=?, index_rel_path=?, last_used_at=? WHERE sha256=?",
            (
                metadata.get("package"),
                metadata.get("version_name"),
                str(metadata.get("version_code") or ""),
                apk_size,
                str(target),
                dumps(artifact_rows),
                "indexes/index.db" if (target / "indexes/index.db").exists() else None,
                now,
                sha256,
            ),
        )
    else:
        db.execute(
            "INSERT INTO apk_cache(sha256, package_name, version_name, version_code, size_bytes, cache_root,"
            " artifacts_json, index_rel_path, evidence_template_json, created_at, last_used_at, hits)"
            " VALUES(?,?,?,?,?,?,?,?,?,?,?,0)",
            (
                sha256,
                metadata.get("package"),
                metadata.get("version_name"),
                str(metadata.get("version_code") or ""),
                apk_size,
                str(target),
                dumps(artifact_rows),
                "indexes/index.db" if (target / "indexes/index.db").exists() else None,
                None,
                now,
                now,
            ),
        )
    audit.record(
        "cache_stored",
        project_id=project_id,
        payload={"sha256": sha256, "bytes": total, "parts": [item["rel"] for item in copies]},
        actor="system",
    )
    return get(sha256)


def restore(project_id: str, sha256: str, *, task_id: str | None = None) -> dict[str, Any] | None:
    """Copy a cache entry into this project and re-register its artifacts.

    Returns ``{"entry": row, "registered": [...]}`` on success, ``None`` when there is no
    usable entry. Nothing is inferred: a missing piece of the tree means a miss, not a
    partially restored project.
    """
    entry = get(sha256)
    if entry is None:
        return None
    root = Path(entry["cache_root"])
    required = [root / "artifacts/facts.json", root / "artifacts/findings.json"]
    if not all(item.exists() for item in required):
        audit.record("cache_incomplete", project_id=project_id, payload={"sha256": sha256}, actor="system")
        return None

    layout = project_layout(project_id)
    base = Path(layout["base"])
    for part in CACHED_PARTS:
        source = root / part
        if not source.exists():
            continue
        destination = base / part
        destination.parent.mkdir(parents=True, exist_ok=True)
        if source.is_dir():
            shutil.copytree(source, destination, dirs_exist_ok=True)
        else:
            shutil.copy2(source, destination)

    from . import artifacts as artifacts_service  # local import avoids an import cycle

    registered: list[dict[str, Any]] = []
    for item in entry.get("artifacts", []):
        path = base / item["rel"]
        if not path.exists():
            continue
        registered.append(
            artifacts_service.register(
                project_id,
                kind=item["kind"],
                path=path,
                task_id=task_id,
                tool=item.get("tool"),
                tool_version=item.get("tool_version"),
                actor="system",
            )
        )
    db.execute("UPDATE apk_cache SET hits = hits + 1, last_used_at = ? WHERE sha256 = ?", (utcnow(), sha256))
    audit.record(
        "cache_restored",
        project_id=project_id,
        task_id=task_id,
        payload={"sha256": sha256, "artifacts": [row["id"] for row in registered]},
        actor="system",
    )
    return {"entry": entry, "registered": registered}


def stats() -> dict[str, Any]:
    row = db.one("SELECT COUNT(*) AS entries, COALESCE(SUM(size_bytes), 0) AS apk_bytes, COALESCE(SUM(hits), 0) AS hits FROM apk_cache")
    root = cache_root()
    on_disk = 0
    for item in root.rglob("*"):
        if item.is_file():
            try:
                on_disk += item.stat().st_size
            except OSError:
                continue
    settings_ = _settings()
    return {
        "entries": row["entries"] if row else 0,
        "apk_bytes": row["apk_bytes"] if row else 0,
        "hits": row["hits"] if row else 0,
        "cache_bytes": on_disk,
        "cache_root": rel_to_storage(root) if str(root).startswith(str(settings_.storage)) else str(root),
        "enabled": settings_.cache_enabled,
        "limit_mb": settings_.cache_max_mb,
    }


def listing(limit: int = 50) -> list[dict[str, Any]]:
    rows = db.query(
        "SELECT sha256, package_name, version_name, size_bytes, hits, created_at, last_used_at"
        " FROM apk_cache ORDER BY last_used_at DESC LIMIT ?",
        (limit,),
    )
    return [dict(row) for row in rows]
