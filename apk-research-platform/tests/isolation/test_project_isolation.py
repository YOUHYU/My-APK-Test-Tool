"""Project isolation: no artifact, index row or evidence row may cross a project boundary."""
from __future__ import annotations

import json
import threading
from pathlib import Path

import pytest

from apkplat import db as dbmod
from apkplat.pipeline_static import run as run_pipeline
from apkplat.services import artifacts, evidence, queue, projects
from apkplat.state import validate_transition
from apkplat.util import project_layout

ROOT = Path(__file__).resolve().parents[2]
SAMPLE = ROOT / "samples" / "sample-app.apk"


@pytest.fixture(scope="module")
def two_projects(tmp_path_factory):
    made = []
    for label in ("iso-alpha", "iso-beta"):
        work = tmp_path_factory.mktemp(label) / "app.apk"
        work.write_bytes(SAMPLE.read_bytes())
        made.append(projects.create(label, work, "app.apk", actor="pytest"))
    return made


def test_each_project_owns_its_directory(two_projects):
    a, b = two_projects
    root_a = project_layout(a["id"])["base"].resolve()
    root_b = project_layout(b["id"])["base"].resolve()
    assert root_a != root_b
    assert a["id"] in str(root_a) and b["id"] in str(root_b)
    for layout in (project_layout(a["id"]), project_layout(b["id"])):
        for key in ("inputs", "artifacts", "indexes", "evidence", "logs", "reports"):
            assert layout[key].resolve().is_relative_to(layout["base"].resolve())


@pytest.mark.parametrize("label", ["alpha", "beta"])
def test_artifact_registration_cannot_escape_the_project(two_projects, label, tmp_path):
    project = two_projects[0 if label == "alpha" else 1]
    outside = tmp_path / "outside.json"
    outside.write_text(json.dumps({"leak": True}), encoding="utf-8")
    with pytest.raises(Exception) as exc:
        artifacts.register(project["id"], kind="evidence", path=outside, actor="pytest")
    assert "outside" in str(exc.value).lower() or "artifact" in str(exc.value).lower()


def test_pipeline_writes_only_inside_its_project(two_projects):
    a, b = two_projects
    for project in (a, b):
        run_pipeline(project["id"])
    for project in (a, b):
        rows = artifacts.list_artifacts(project["id"], limit=200)
        assert rows, f"no artifacts for {project['id']}"
        for row in rows:
            assert row["project_id"] == project["id"]
        rows_other = artifacts.list_artifacts((b if project is a else a)["id"], limit=200)
        overlap = {r["rel_path"] for r in rows} & {r["rel_path"] for r in rows_other}
        assert not overlap, f"artifact paths shared across projects: {overlap}"


def test_index_queries_stay_inside_the_project(two_projects):
    from apkplat import indexer

    a, b = two_projects
    hits_a = indexer.search_code(a["id"], "validateLicense", limit=50)
    assert hits_a, "expected the sample method in alpha"
    for hit in hits_a:
        assert "com.example.reef" in json.dumps(hit)
    # a package that does not exist in either project returns nothing, not an error
    assert indexer.search_code(a["id"], "com.example.definitely_absent", limit=10) == []


def test_evidence_cannot_quote_another_projects_artifact(two_projects):
    a, b = two_projects
    foreign = artifacts.list_artifacts(b["id"], limit=1)[0]
    with pytest.raises(evidence.EvidenceError):
        evidence.record(
            a["id"],
            kind="unit",
            locator={"file": foreign["rel_path"]},
            excerpt="a quoted line from another project",
            artifact_id=foreign["id"],
        )


def test_verify_reports_no_cross_project_evidence(two_projects):
    for project in two_projects:
        report = evidence.verify(project["id"])
        assert all(f["reason"] != "cross_project_artifact" for f in report["failures"])


def test_concurrent_workers_never_claim_the_same_job(two_projects):
    kinds = ["iso_job"]
    ids = [queue.enqueue(kinds[0], idempotency_key=f"iso-{i}", project_id=two_projects[0]["id"]) for i in range(8)]
    claimed: list[str] = []
    failures: list[str] = []
    lock = threading.Lock()

    def worker(name: str) -> None:
        try:
            while True:
                job = queue.claim(name, kinds, lease_seconds=30)
                if job is None:
                    return
                with lock:
                    claimed.append(job["id"])
        except BaseException as exc:  # noqa: BLE001 - surfaced in the assertion message
            with lock:
                failures.append(f"{name}: {type(exc).__name__}: {exc}")

    threads = [threading.Thread(target=worker, args=(f"iso-worker-{i}",)) for i in range(4)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()

    diag = dbmod.db.query("SELECT id, status, available_at FROM jobs WHERE kind = 'iso_job'")
    assert not failures, failures
    assert sorted(claimed) == sorted(ids), f"claimed={claimed} jobs={[dict(r) for r in diag]}"
    assert len(claimed) == len(set(claimed)), "a job was claimed twice (lease collision)"


def test_task_transition_guard_is_project_agnostic_but_audited(two_projects):
    from apkplat.services import tasks

    project = two_projects[0]
    task = tasks.create(project["id"], title="iso task", role="static", actor="pytest")
    with pytest.raises(Exception):
        tasks.update(task["id"], status="DONE", actor="agent")
    before = dbmod.db.scalar("SELECT COUNT(*) FROM audit_events WHERE event_type = 'task_status_changed'") or 0
    tasks.update(task["id"], status="RUNNING", actor="agent")
    after = dbmod.db.scalar("SELECT COUNT(*) FROM audit_events WHERE event_type = 'task_status_changed'") or 0
    assert after >= before + 1
    validate_transition("RUNNING", "REVIEW", actor="agent")
