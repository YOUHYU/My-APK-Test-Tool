"""Evidence integrity: an assertion without a locatable quote is not evidence."""
from __future__ import annotations

import sqlite3

import json
from pathlib import Path

import pytest

from apkplat import db as dbmod
from apkplat.services import artifacts, evidence, projects

ROOT = Path(__file__).resolve().parents[2]
SAMPLE = ROOT / "samples" / "sample-app.apk"


@pytest.fixture(scope="module")
def project(tmp_path_factory):
    """A real ingested project, so artifact rows are real files on disk."""
    work = tmp_path_factory.mktemp("evd") / "sample.apk"
    work.write_bytes(SAMPLE.read_bytes())
    return projects.create("evidence-unit", work, "sample.apk", actor="pytest")


@pytest.fixture(scope="module")
def artifact(project):
    """One real artifact file, registered the same way the pipeline registers them."""
    from apkplat.util import project_layout

    layout = project_layout(project["id"])
    path = layout["artifacts"] / "unit-facts.json"
    path.write_text(
        json.dumps(
            {
                "package": "com.example.reef",
                "version_name": "1.2.3",
                "note": "a line long enough to be quoted as evidence",
            },
            indent=2,
        ),
        encoding="utf-8",
    )
    return artifacts.register(project["id"], kind="facts", path=path, actor="pytest", tool="unit-test")


def test_empty_locator_rejected(project):
    with pytest.raises(evidence.EvidenceError):
        evidence.record(project["id"], kind="note", locator={}, excerpt="something quotable")


def test_empty_excerpt_rejected(project):
    with pytest.raises(evidence.EvidenceError):
        evidence.record(project["id"], kind="note", locator={"file": "x"}, excerpt="   ")


def test_short_excerpt_cannot_support_a_claim(project):
    with pytest.raises(evidence.EvidenceError):
        evidence.record(
            project["id"], kind="note", locator={"file": "x"}, excerpt="tiny", claim="the app is malicious"
        )


def test_bad_confidence_rejected(project):
    with pytest.raises(evidence.EvidenceError):
        evidence.record(
            project["id"], kind="note", locator={"file": "x"}, excerpt="a long enough quote", confidence="certain"
        )


def test_cross_project_artifact_is_refused(project, tmp_path):
    other = tmp_path / "other.apk"
    other.write_bytes(SAMPLE.read_bytes())
    other_project = projects.create("evidence-unit-other", other, "other.apk", actor="pytest")
    # the other project's artifact must not be quotable from this project
    from apkplat.util import project_layout

    layout = project_layout(other_project["id"])
    foreign_path = layout["artifacts"] / "foreign.json"
    foreign_path.write_text(json.dumps({"package": "com.example.other"}), encoding="utf-8")
    artifacts.register(other_project["id"], kind="facts", path=foreign_path, actor="pytest", tool="unit-test")
    foreign = artifacts.list_artifacts(other_project["id"], limit=5)
    with pytest.raises(evidence.EvidenceError):
        evidence.record(
            project["id"],
            kind="note",
            locator={"file": "x"},
            excerpt="a long enough quote",
            artifact_id=foreign[0]["id"],
        )


def test_verify_detects_a_tampered_excerpt(project, artifact):
    art = artifact
    text = artifacts.read_text(art["id"], limit=2000)["text"]
    line = next((ln.strip() for ln in text.splitlines() if len(ln.strip()) > 12), None)
    assert line, "artifact had no usable line"
    row = evidence.record(
        project["id"],
        kind="unit",
        locator={"file": art["rel_path"]},
        excerpt=line,
        artifact_id=art["id"],
        claim="quoted from an artifact",
    )
    assert evidence.verify(project["id"])["failures"] == [] or all(
        f["evidence_id"] != row["id"] for f in evidence.verify(project["id"])["failures"]
    )
    # The table itself refuses rewrites (migrations/002_audit_appendonly.sql) ...
    with pytest.raises(sqlite3.DatabaseError):
        dbmod.db.execute("UPDATE evidence SET excerpt = ? WHERE id = ?", ("a fabricated quote", row["id"]))

    # ... and a row forged through INSERT is still caught by the hash check.
    forged = row["excerpt_hash"][:-1] + ("0" if row["excerpt_hash"][-1] != "0" else "1")
    dbmod.db.execute(
        "INSERT INTO evidence(id, project_id, task_id, kind, artifact_id, locator, excerpt, excerpt_hash,"
        " claim, confidence, captured_at, created_by)"
        " VALUES(?, ?, NULL, 'unit', ?, '{}', ?, ?, 'forged', 'medium', ?, 'test')",
        ("evd_forged", project["id"], art["id"], row["excerpt"], forged, "2026-01-01T00:00:00Z"),
    )
    failures = evidence.verify(project["id"])["failures"]
    assert any(f["evidence_id"] == "evd_forged" and f["reason"] == "excerpt_hash_mismatch" for f in failures)


def test_excerpt_must_exist_in_the_artifact(project, artifact):
    art = artifact
    row = evidence.record(
        project["id"],
        kind="unit",
        locator={"file": art["rel_path"]},
        excerpt="this text is definitely not inside that artifact",
        artifact_id=art["id"],
        claim="unbacked claim",
    )
    failures = evidence.verify(project["id"])["failures"]
    assert any(f["evidence_id"] == row["id"] and f["reason"] == "excerpt_not_found_in_artifact" for f in failures)


def test_task_counter_increments(project, artifact):
    art = artifact
    text = artifacts.read_text(art["id"], limit=1000)["text"]
    line = next(ln.strip() for ln in text.splitlines() if len(ln.strip()) > 12)
    from apkplat.services import tasks

    task = tasks.create(project["id"], title="evidence counter", role="static", actor="pytest")
    evidence.record(
        project["id"],
        kind="unit",
        locator={"file": art["rel_path"]},
        excerpt=line,
        artifact_id=art["id"],
        task_id=task["id"],
        claim="counted",
    )
    assert tasks.get(task["id"])["evidence_count"] == 1
