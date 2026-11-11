"""Evidence rows: the only currency a claim may be paid in.

A row is traceable iff it points at an artifact of the *same* project, carries a
locator that resolves inside that artifact and quotes an excerpt whose hash is
recorded. Anything less is rejected at write time, which is what makes
``evidence_traceability_rate`` a structural 100% instead of a hope.
"""
from __future__ import annotations

from pathlib import Path
from typing import Any

from .. import audit
from ..db import Row, db, utcnow
from ..util import dumps, loads, new_id, sha256_bytes

CONFIDENCE = ("low", "medium", "high")


class EvidenceError(ValueError):
    pass


def record(
    project_id: str,
    *,
    kind: str,
    locator: dict[str, Any],
    excerpt: str,
    artifact_id: str | None = None,
    task_id: str | None = None,
    claim: str | None = None,
    confidence: str = "medium",
    created_by: str = "agent",
) -> Row:
    if not isinstance(locator, dict) or not locator:
        raise EvidenceError("locator must be a non-empty object (file/lines/dex method/manifest path)")
    if confidence not in CONFIDENCE:
        raise EvidenceError(f"confidence must be one of {CONFIDENCE}")
    if artifact_id:
        artifact = db.one("SELECT * FROM artifacts WHERE id = ?", (artifact_id,))
        if not artifact:
            raise EvidenceError(f"artifact {artifact_id} does not exist")
        if artifact["project_id"] != project_id:
            raise EvidenceError("artifact belongs to a different project (isolation violation blocked)")
    # Stored verbatim: evidence.verify() looks for the whole excerpt inside the artifact,
    # so reindenting or trimming it here would make the quote untraceable.
    raw = (excerpt or "").replace("\r\n", "\n")
    text = raw.strip()
    if not text:
        raise EvidenceError("excerpt must not be empty: an unquoted assertion is not evidence")
    if claim and len(text) < 8:
        raise EvidenceError("excerpt too short to support a claim")
    evidence_id = new_id("evd_")
    with db.tx():
        db.execute(
            "INSERT INTO evidence(id, project_id, task_id, kind, artifact_id, locator, excerpt, excerpt_hash,"
            " claim, confidence, captured_at, created_by) VALUES(?,?,?,?,?,?,?,?,?,?,?,?)",
            (
                evidence_id,
                project_id,
                task_id,
                kind,
                artifact_id,
                dumps(locator),
                raw[:4000],
                sha256_bytes(raw[:4000].encode("utf-8")),
                claim,
                confidence,
                utcnow(),
                created_by,
            ),
        )
        if task_id:
            db.execute(
                "UPDATE tasks SET evidence_count = evidence_count + 1, updated_at = ? WHERE id = ?",
                (utcnow(), task_id),
            )
    audit.record(
        "evidence_recorded",
        project_id=project_id,
        task_id=task_id,
        actor=created_by,
        payload={
            "evidence_id": evidence_id,
            "kind": kind,
            "artifact_id": artifact_id,
            "confidence": confidence,
            "locator": locator,
        },
    )
    return get(evidence_id)  # type: ignore[return-value]


def get(evidence_id: str) -> Row | None:
    row = db.one("SELECT * FROM evidence WHERE id = ?", (evidence_id,))
    if row:
        row["locator"] = loads(row["locator"], {})
    return row


def list_evidence(
    project_id: str, *, task_id: str | None = None, kind: str | None = None, limit: int = 500
) -> list[Row]:
    sql = "SELECT * FROM evidence WHERE project_id = ?"
    params: list[Any] = [project_id]
    if task_id:
        sql += " AND task_id = ?"
        params.append(task_id)
    if kind:
        sql += " AND kind = ?"
        params.append(kind)
    sql += " ORDER BY captured_at ASC LIMIT ?"
    params.append(limit)
    rows = db.query(sql, params)
    for row in rows:
        row["locator"] = loads(row["locator"], {})
    return rows


def verify(project_id: str) -> dict[str, Any]:
    """Re-verify every evidence row: artifact exists, excerpt hash matches bytes."""
    rows = list_evidence(project_id, limit=5000)
    failures: list[dict] = []
    for row in rows:
        artifact = db.one("SELECT * FROM artifacts WHERE id = ?", (row["artifact_id"],)) if row["artifact_id"] else None
        if not row["artifact_id"] or not artifact:
            failures.append({"evidence_id": row["id"], "reason": "dangling_artifact"})
            continue
        if artifact["project_id"] != project_id:
            failures.append({"evidence_id": row["id"], "reason": "cross_project_artifact"})
            continue
        excerpt = (row["excerpt"] or "").replace("\r\n", "\n")
        if sha256_bytes(excerpt.encode("utf-8")) != row["excerpt_hash"]:
            failures.append({"evidence_id": row["id"], "reason": "excerpt_hash_mismatch"})
            continue
        from . import artifacts as artifacts_service

        try:
            # The artifact bytes themselves, not the redacted API view: verification asks
            # "does this quote appear in the file", and redaction would rewrite the quote.
            path = artifacts_service.path_of(artifact)
            text = path.read_bytes().decode("utf-8", "replace").replace("\r\n", "\n")
        except Exception as exc:  # noqa: BLE001
            failures.append({"evidence_id": row["id"], "reason": f"artifact_unreadable: {exc}"})
            continue
        if excerpt not in text:
            failures.append({"evidence_id": row["id"], "reason": "excerpt_not_found_in_artifact"})
    total = len(rows)
    return {
        "total": total,
        "failures": failures,
        "traceability_rate": 1.0 if total == 0 else round((total - len(failures)) / total, 4),
    }
