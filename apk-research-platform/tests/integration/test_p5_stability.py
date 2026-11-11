"""P5 acceptance: what happens when the input is bad and the process is hostile.

Five properties, each one a way a naive pipeline loses:
1. a malformed APK is refused at the door, with the reason that actually applies;
2. an oversized upload is cut off before it eats the disk;
3. a caller-supplied filename cannot steer storage outside the project;
4. a token issued for project A cannot read project B;
5. the audit trail and the evidence table cannot be rewritten, and one bad job does
   not wedge the worker for the jobs behind it.
"""
from __future__ import annotations

import json
import sqlite3
from pathlib import Path

import pytest

from apkplat import audit, worker
from apkplat.config import settings
from apkplat.db import db
from apkplat.services import artifacts as artifacts_service
from apkplat.services import evidence as evidence_service
from apkplat.services import projects as projects_service
from apkplat.services import queue as queue_service
from apkplat.services import tasks as tasks_service

HOSTILE = [
    ("hostile-not-zip.apk", "not_a_zip"),
    ("hostile-truncated.apk", "corrupt_zip"),
    ("hostile-zip-slip.apk", "zip_slip"),
    ("hostile-no-manifest.apk", "missing_manifest"),
    ("hostile-no-dex.apk", "missing_dex"),
    ("hostile-bomb.apk", "zip_bomb"),
]


def _enqueue_static(project_id: str, key: str | None = None) -> str:
    """Services do not enqueue; the API does. Tests that drive a worker enqueue here."""
    return queue_service.enqueue(
        "static_pipeline", project_id=project_id, payload={}, idempotency_key=key or f"static:{project_id}"
    )


def _upload(client, path: Path, name: str, filename: str | None = None):
    with open(path, "rb") as handle:
        return client.post(
            "/api/projects",
            data={"name": name, "goal": "p5 stability"},
            files={"apk": (filename or path.name, handle, "application/vnd.android.package-archive")},
        )


def _error_code(response) -> str:
    """The API reports failures flat (``{"error_code": ...}``) or nested under ``detail``."""
    body = response.json()
    if isinstance(body, dict):
        if "error_code" in body:
            return str(body["error_code"])
        detail = body.get("detail")
        if isinstance(detail, dict) and "error_code" in detail:
            return str(detail["error_code"])
        if isinstance(detail, str):
            return detail
    return json.dumps(body)[:200]


@pytest.mark.parametrize("filename,expected", HOSTILE)
def test_hostile_apk_is_refused_with_its_own_reason(app_client, filename, expected):
    path = Path(__file__).resolve().parents[2] / "samples" / filename
    response = _upload(app_client, path, f"p5-{expected}")

    assert response.status_code == 422, response.text
    assert _error_code(response) == expected, response.text

    rejected = [
        row for row in audit.tail(0, limit=4000) if row["event_type"] == "apk_ingest_rejected"
    ]
    assert any(json.loads(row["payload_json"] or "{}").get("error_code") == expected for row in rejected)

    row = db.one("SELECT * FROM projects WHERE name = ?", (f"p5-{expected}",))
    assert row is None, "a rejected APK must not leave a project behind"


def test_oversized_upload_is_cut_off(app_client, monkeypatch):
    monkeypatch.setattr(settings, "max_upload_mb", 1)
    blob = b"PK\x03\x04" + b"A" * (2 * 1024 * 1024)
    response = app_client.post(
        "/api/projects",
        data={"name": "p5-too-large"},
        files={"apk": ("big.apk", blob, "application/vnd.android.package-archive")},
    )

    assert response.status_code == 413, response.text
    assert _error_code(response) == "upload_too_large"
    leftovers = list((Path(settings.storage) / "tmp").glob("upload-*.apk"))
    assert leftovers == [], f"partial upload kept: {leftovers}"


def test_filename_cannot_escape_the_project(app_client, sample_apk):
    response = _upload(app_client, sample_apk, "p5-traversal", filename="../../evil.apk")

    assert response.status_code == 201, response.text
    project_id = response.json()["project"]["id"]
    apk = projects_service.apk_path(project_id)
    project_dir = Path(settings.project_dir(project_id)).resolve()
    assert apk.resolve().is_relative_to(project_dir), apk
    assert not (Path(settings.storage).parent / "evil.apk").exists()
    assert not (Path(settings.storage) / "evil.apk").exists()


def test_token_is_bound_to_one_project(app_client, admin_headers, sample_apk, monkeypatch):
    first = _upload(app_client, sample_apk, "p5-token-a")
    second = _upload(app_client, sample_apk, "p5-token-b")
    assert first.status_code == 201 and second.status_code == 201
    a_id = first.json()["project"]["id"]
    b_id = second.json()["project"]["id"]

    issued = app_client.post(
        "/api/auth/token",
        headers=admin_headers,
        json={"subject": "p5", "projects": [a_id], "scopes": ["read", "write"]},
    )
    assert issued.status_code == 200, issued.text
    headers = {"Authorization": f"Bearer {issued.json()['token']}"}

    monkeypatch.setattr(settings, "require_auth", True)
    assert app_client.get(f"/api/projects/{a_id}", headers=headers).status_code == 200

    denied = app_client.get(f"/api/projects/{b_id}", headers=headers)
    assert denied.status_code == 403, denied.text
    assert _error_code(denied) == "project_denied"

    leaked = app_client.get(f"/api/projects/{b_id}?project_id={a_id}", headers=headers)
    assert leaked.status_code == 403

    monkeypatch.setattr(settings, "require_auth", False)


def test_audit_and_evidence_cannot_be_rewritten(app_client, sample_apk):
    project = projects_service.create("p5-immutable", sample_apk, "sample-app.apk", actor="test")
    _enqueue_static(project["id"])
    worker.Worker("p5-immutable", ["static_pipeline"], poll_interval=0.05).run(max_jobs=1)

    before = audit.last_seq()
    with pytest.raises(sqlite3.DatabaseError):
        db.execute("UPDATE audit_events SET event_type = 'rewritten' WHERE seq = 1")
    with pytest.raises(sqlite3.DatabaseError):
        db.execute("DELETE FROM audit_events")
    assert audit.last_seq() == before

    evidence_rows = evidence_service.list_evidence(project["id"])
    assert evidence_rows, "the pipeline should have recorded evidence"
    with pytest.raises(sqlite3.DatabaseError):
        db.execute("UPDATE evidence SET excerpt = 'made up'")
    with pytest.raises(sqlite3.DatabaseError):
        db.execute("DELETE FROM evidence")
    assert evidence_service.verify(project["id"])["failures"] == []


def test_one_bad_job_does_not_wedge_the_worker(app_client, sample_apk):
    broken = projects_service.create("p5-broken", sample_apk, "sample-app.apk", actor="test")
    apk = projects_service.apk_path(broken["id"])
    apk.write_bytes(b"not an apk at all")

    bad_job = queue_service.enqueue(
        "static_pipeline", project_id=broken["id"], payload={}, idempotency_key="p5-broken"
    )
    good = projects_service.create("p5-good", sample_apk, "sample-app.apk", actor="test")
    good_job = queue_service.enqueue(
        "static_pipeline", project_id=good["id"], payload={}, idempotency_key="p5-good"
    )

    worker.Worker("p5-survivor", ["static_pipeline"], poll_interval=0.05).run(max_jobs=2)

    broken_job = queue_service.get(bad_job)
    assert broken_job["status"] in {"FAILED", "RETRYING"}, broken_job["status"]
    assert broken_job["error_code"] in {"not_a_zip", "apk_too_small"}, broken_job["error_code"]
    assert queue_service.get(good_job)["status"] == "SUCCEEDED"
    failed_task = db.one("SELECT * FROM tasks WHERE project_id = ?", (broken["id"],))
    assert failed_task is not None and failed_task["status"] == "FAILED", failed_task


def test_rerunning_a_pipeline_is_idempotent(app_client, sample_apk):
    project = projects_service.create("p5-rerun", sample_apk, "sample-app.apk", actor="test")
    _enqueue_static(project["id"], "p5-rerun-1")
    worker.Worker("p5-rerun-1", ["static_pipeline"], poll_interval=0.05).run(max_jobs=1)
    first = {row["rel_path"]: row["sha256"] for row in artifacts_service.list_artifacts(project["id"])}
    first_evidence = len(evidence_service.list_evidence(project["id"]))

    _enqueue_static(project["id"], "p5-rerun-2")
    worker.Worker("p5-rerun-2", ["static_pipeline"], poll_interval=0.05).run(max_jobs=1)
    second = {row["rel_path"]: row["sha256"] for row in artifacts_service.list_artifacts(project["id"])}

    assert set(first) == set(second), "a rerun must not add or drop artifact rows"
    chain = artifacts_service.verify_chain(project["id"])
    assert chain["failures"] == [] and chain["ok"] == chain["checked"], chain
    assert len(evidence_service.list_evidence(project["id"])) >= first_evidence
    assert evidence_service.verify(project["id"])["traceability_rate"] >= 1.0


def test_bad_requests_are_client_errors_not_crashes(app_client, sample_apk):
    project = projects_service.create("p5-errors", sample_apk, "sample-app.apk", actor="test")
    _enqueue_static(project["id"])
    worker.Worker("p5-errors", ["static_pipeline"], poll_interval=0.05).run(max_jobs=1)

    missing = app_client.get("/api/projects/prj_does_not_exist")
    assert missing.status_code == 404

    bad_evidence = app_client.post(
        f"/api/projects/{project['id']}/evidence",
        json={"kind": "manifest_fact", "locator": {}, "excerpt": "x"},
    )
    assert bad_evidence.status_code == 422, bad_evidence.text

    bad_transition = app_client.patch(
        "/api/tasks/" + tasks_service.list_tasks(project["id"])[0]["id"],
        json={"status": "DONE", "actor": "agent", "expected_version": 1},
    )
    assert bad_transition.status_code == 409, bad_transition.text

    unknown_artifact = app_client.get("/api/artifacts/art_does_not_exist/text")
    assert unknown_artifact.status_code == 404
