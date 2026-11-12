"""Artifact registry: every byte a tool produced is addressable by id + hash."""
from __future__ import annotations

from pathlib import Path
from typing import Any, Iterable

from ..config import settings
from ..db import Row, db, utcnow
from ..util import clamp, is_within, new_id, project_root, redact, rel_to_storage, sha256_file


class ArtifactError(ValueError):
    pass


def register(
    project_id: str,
    *,
    kind: str,
    path: Path,
    task_id: str | None = None,
    tool: str | None = None,
    tool_version: str | None = None,
    actor: str = "system",
) -> Row:
    base = project_root(project_id)
    if not is_within(path, base):
        raise ArtifactError(f"artifact path {path} is outside project root {base}")
    if not path.exists():
        raise ArtifactError(f"artifact file missing: {path}")
    digest = sha256_file(path) if path.is_file() else None
    size = path.stat().st_size if path.is_file() else None
    rel_path = rel_to_storage(path)
    # One row per (project, path): a re-run of a stage rewrites the same file, and a second
    # row for the same bytes path would leave the first one holding a hash that no longer
    # matches the file. Re-registering therefore refreshes the row, keeping its id stable
    # so evidence recorded against it still resolves.
    existing = db.one("SELECT * FROM artifacts WHERE project_id = ? AND rel_path = ?", (project_id, rel_path))
    if existing:
        with db.tx():
            db.execute(
                "UPDATE artifacts SET task_id = ?, kind = ?, sha256 = ?, bytes = ?, tool = ?, tool_version = ?,"
                " created_at = ? WHERE id = ?",
                (task_id or existing["task_id"], kind, digest, size, tool, tool_version, utcnow(), existing["id"]),
            )
        return get(existing["id"])  # type: ignore[return-value]
    artifact_id = new_id("art_")
    with db.tx():
        db.execute(
            "INSERT INTO artifacts(id, project_id, task_id, kind, rel_path, sha256, bytes, tool, tool_version, created_at)"
            " VALUES(?,?,?,?,?,?,?,?,?,?)",
            (artifact_id, project_id, task_id, kind, rel_path, digest, size, tool, tool_version, utcnow()),
        )
    return get(artifact_id)  # type: ignore[return-value]


def get(artifact_id: str) -> Row | None:
    return db.one("SELECT * FROM artifacts WHERE id = ?", (artifact_id,))


def list_artifacts(
    project_id: str, kinds: Iterable[str] | None = None, limit: int = 200, task_id: str | None = None
) -> list[Row]:
    sql = "SELECT * FROM artifacts WHERE project_id = ?"
    params: list[Any] = [project_id]
    kinds = list(kinds or [])
    if kinds:
        sql += f" AND kind IN ({','.join('?' for _ in kinds)})"
        params.extend(kinds)
    if task_id:
        sql += " AND task_id = ?"
        params.append(task_id)
    sql += " ORDER BY created_at ASC LIMIT ?"
    params.append(limit)
    return db.query(sql, params)


def path_of(artifact: Row) -> Path:
    from ..util import abs_from_storage

    return abs_from_storage(artifact["rel_path"])


def read_text(artifact_id: str, *, limit: int = 20000, tail: bool = False) -> dict[str, Any]:
    artifact = get(artifact_id)
    if not artifact:
        raise KeyError(artifact_id)
    path = path_of(artifact)
    if not path.exists():
        raise ArtifactError(f"artifact bytes missing on disk: {path}")
    data = path.read_bytes()
    if len(data) > 8 * 1024 * 1024:
        data = data[-4 * 1024 * 1024 :] if tail else data[: 4 * 1024 * 1024]
    text = data.decode("utf-8", "replace")
    if tail:
        text = text[-limit:]
    return {
        "artifact_id": artifact_id,
        "kind": artifact["kind"],
        "sha256": artifact["sha256"],
        "bytes": artifact["bytes"],
        "text": clamp(redact(text), limit),
        "truncated": len(text) > limit,
    }


def verify_chain(project_id: str) -> dict[str, Any]:
    """Re-hash every artifact of a project; used by audits and P5 checks."""
    rows = list_artifacts(project_id, limit=5000)
    ok, bad = 0, []
    for row in rows:
        path = path_of(row)
        if not path.exists():
            bad.append({"artifact_id": row["id"], "reason": "missing_file"})
            continue
        if row["sha256"] and sha256_file(path) != row["sha256"]:
            bad.append({"artifact_id": row["id"], "reason": "hash_mismatch"})
            continue
        ok += 1
    return {"checked": len(rows), "ok": ok, "failures": bad}
