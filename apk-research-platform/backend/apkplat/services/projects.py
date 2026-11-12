"""Project lifecycle: ingest, isolation layout, metadata manifest, board."""
from __future__ import annotations

import json
import shutil
from pathlib import Path
from typing import Any

from .. import audit
from ..apkfile import ApkError, parse_metadata, validate_apk
from ..config import settings
from ..db import Row, db, utcnow
from ..state import COLUMN_OF
from ..util import (
    abs_from_storage,
    dumps,
    forget_project_base,
    is_within,
    loads,
    new_id,
    project_layout,
    project_root,
    rel_to_storage,
    safe_segment,
    sha256_file,
)

DEFAULT_COLUMNS = ("TODO", "RUNNING", "REVIEW", "DONE")
LAYOUT_DIRS = ("inputs", "manifests", "artifacts", "indexes", "evidence", "logs", "reports")


class ProjectError(Exception):
    """Input problem on project creation (mapped to 4xx by the API)."""

    def __init__(self, code: str, message: str, status: int = 422) -> None:
        super().__init__(message)
        self.code = code
        self.message = message
        self.status = status

    def as_error(self) -> dict[str, Any]:
        return {"error_code": self.code, "message": self.message}


def resolve_storage_root(project_id: str, value: str | Path | None) -> Path | None:
    """Validate an operator-supplied project directory.

    Returns the absolute directory (created on demand) or None for the default
    ``<storage>/projects/<project_id>``. Refuses paths that would nest inside the
    platform storage area or inside another project, because both make the
    one-directory-per-project isolation rule impossible to verify afterwards.
    """
    if value is None:
        return None
    raw = str(value).strip()
    if not raw:
        return None
    path = Path(raw)
    if not path.is_absolute():
        raise ProjectError("storage_root_not_absolute", "storage_root must be an absolute path")
    target = path.resolve()
    storage = settings.storage.resolve()
    if is_within(target, storage):
        raise ProjectError(
            "storage_root_inside_storage",
            f"storage_root must live outside the platform storage area ({storage})",
        )
    if target.exists() and not target.is_dir():
        raise ProjectError("storage_root_not_a_directory", f"{target} exists and is not a directory")
    if target.exists():
        stray = sorted(p.name for p in target.iterdir() if p.name not in LAYOUT_DIRS)
        if stray:
            raise ProjectError(
                "storage_root_not_empty",
                f"{target} already contains unrelated entries: {', '.join(stray[:5])}",
            )
    try:
        for name in LAYOUT_DIRS:
            (target / name).mkdir(parents=True, exist_ok=True)
    except OSError as exc:
        raise ProjectError("storage_root_unusable", f"cannot create {target}: {exc}") from exc
    return target


def create(
    name: str,
    apk_source: Path | str,
    filename: str,
    *,
    goal: str | None = None,
    ground_truth: dict | str | None = None,
    policy_id: str = "default",
    storage_root: str | Path | None = None,
    actor: str = "human",
) -> Row:
    apk_source = Path(apk_source)
    if isinstance(ground_truth, str):
        # callers hand over the JSON text they stored; keep it exactly, just don't double-encode
        try:
            ground_truth = json.loads(ground_truth) if ground_truth.strip() else None
        except json.JSONDecodeError:
            ground_truth = {"raw": ground_truth}
    project_id = new_id("prj_")
    pinned = resolve_storage_root(project_id, storage_root)
    layout = project_layout(project_id, base=pinned) if pinned else project_layout(project_id)
    safe_name = safe_segment(filename or "app.apk", "app.apk")
    quarantined = layout["inputs"] / "quarantine" / safe_name
    quarantined.parent.mkdir(parents=True, exist_ok=True)
    # Copy, never move: the caller's file is not ours to consume. A staging upload looks
    # like ``storage/tmp/...`` and is removed once its bytes live inside the project.
    shutil.copy2(str(apk_source), quarantined)
    try:
        apk_source.resolve().relative_to((settings.storage / "tmp").resolve())
        staged = True
    except ValueError:
        staged = False
    if staged:
        try:
            apk_source.unlink()
        except OSError:
            pass
    try:
        validation = validate_apk(quarantined)
        if not validation.ok:
            raise ApkError(validation.error_code or "invalid_apk", validation.message or "APK rejected")
    except ApkError as exc:
        audit.record(
            "apk_ingest_rejected",
            project_id=project_id,
            actor=actor,
            payload={"error_code": exc.code, "message": exc.message, "filename": safe_name},
        )
        shutil.rmtree(layout["base"], ignore_errors=True)
        raise

    sha = sha256_file(quarantined)
    final_path = layout["inputs"] / f"base-{sha[:12]}.apk"
    shutil.move(str(quarantined), final_path)
    (layout["inputs"] / "quarantine").rmdir()

    metadata = parse_metadata(final_path)
    metadata["validation"] = validation.to_dict()
    metadata["ingest"] = {
        "filename": safe_name,
        "sha256": sha,
        "bytes": final_path.stat().st_size,
        "ingested_at": utcnow(),
    }
    (layout["manifests"] / "manifest.json").write_text(dumps(metadata), encoding="utf-8")

    now = utcnow()
    with db.tx():
        db.execute(
            "INSERT INTO projects(id, name, apk_sha256, apk_filename, package_name, created_at, updated_at,"
            " status, policy_id, goal, ground_truth, blocked_reason, storage_root)"
            " VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (
                project_id,
                name,
                sha,
                safe_name,
                metadata.get("package"),
                now,
                now,
                "INGESTED",
                policy_id,
                goal,
                dumps(ground_truth) if ground_truth else None,
                None,
                str(pinned) if pinned else None,
            ),
        )
    forget_project_base(project_id)
    audit.record(
        "project_created",
        project_id=project_id,
        actor=actor,
        payload={
            "name": name,
            "apk_sha256": sha,
            "package": metadata.get("package"),
            "version_name": metadata.get("version_name"),
            "entries": validation.entries,
            "bytes": final_path.stat().st_size,
            "policy_id": policy_id,
            "storage_root": str(pinned) if pinned else None,
        },
    )
    return get(project_id)  # type: ignore[return-value]


def get(project_id: str) -> Row | None:
    row = db.one("SELECT * FROM projects WHERE id = ?", (project_id,))
    if row:
        row["ground_truth"] = loads(row.get("ground_truth"))
        row["metadata"] = manifest(project_id)
    return row


def list_projects(limit: int = 100) -> list[Row]:
    return db.query("SELECT * FROM projects ORDER BY created_at DESC LIMIT ?", (limit,))


def manifest(project_id: str) -> dict[str, Any]:
    path = project_root(project_id) / "manifests" / "manifest.json"
    if not path.exists():
        return {}
    return loads(path.read_text(encoding="utf-8"), {})


def apk_path(project_id: str) -> Path:
    layout = project_layout(project_id)
    found = sorted(layout["inputs"].glob("base-*.apk"))
    if not found:
        raise FileNotFoundError(f"no ingested apk for project {project_id}")
    return found[0]


def set_status(project_id: str, status: str, *, actor: str = "system", reason: str | None = None) -> None:
    with db.tx():
        db.execute(
            "UPDATE projects SET status = ?, updated_at = ?, blocked_reason = ? WHERE id = ?",
            (status, utcnow(), reason, project_id),
        )
    audit.record("project_status", project_id=project_id, actor=actor, payload={"status": status, "reason": reason})


def board(project_id: str) -> dict[str, Any]:
    tasks = db.query("SELECT * FROM tasks WHERE project_id = ? ORDER BY priority ASC, created_at ASC", (project_id,))
    columns: dict[str, list[dict]] = {c: [] for c in DEFAULT_COLUMNS}
    for task in tasks:
        column = COLUMN_OF.get(task["status"], "TODO")
        columns.setdefault(column, []).append(
            {
                "id": task["id"],
                "title": task["title"],
                "role": task["role"],
                "status": task["status"],
                "priority": task["priority"],
                "progress": task["progress"],
                "version": task["version"],
                "summary": task["summary"],
                "evidence_count": task["evidence_count"],
                "model_calls": task["model_calls"],
                "updated_at": task["updated_at"],
                "depends_on": loads(task["depends_on"], []),
                "needs_approval": task["needs_approval"],
                "error_code": task["error_code"],
            }
        )
    project = db.one("SELECT id, name, status, package_name, apk_sha256 FROM projects WHERE id = ?", (project_id,))
    return {
        "project": dict(project) if project else None,
        "columns": columns,
        "generated_at": utcnow(),
    }


def artifact_path(rel_path: str) -> Path:
    return abs_from_storage(rel_path)


def relative(path: Path) -> str:
    return rel_to_storage(path)
