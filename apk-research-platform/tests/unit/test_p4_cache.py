"""P4: the APK analysis cache must actually short-circuit the tools, and prove it."""
from __future__ import annotations

from pathlib import Path

import pytest

from apkplat import pipeline_static
from apkplat.config import settings
from apkplat.db import db
from apkplat.services import artifacts as artifacts_service
from apkplat.services import cache as cache_service
from apkplat.services import projects as projects_service
from apkplat.services import tasks as tasks_service
from apkplat.util import abs_from_storage, project_layout


@pytest.fixture(autouse=True)
def _empty_cache():
    """Cache state must not leak between tests: every test starts from a cold cache."""
    import shutil

    db.execute("DELETE FROM apk_cache")
    shutil.rmtree(Path(settings.storage) / "cache", ignore_errors=True)
    yield


def _import(apk: Path, name: str) -> tuple[str, str]:
    project = projects_service.create(name=name, apk_source=apk, filename=apk.name, actor="test")
    task = tasks_service.create(project["id"], role="static", title="Static", actor="test", status="RUNNING")
    return project["id"], task["id"]


def test_second_import_of_the_same_bytes_is_served_from_cache(sample_apk):
    pipeline_static.silence_library_logging()
    first_pid, first_task = _import(sample_apk, "cache-first")
    first = pipeline_static.run(first_pid, task_id=first_task)
    assert first["cache_hit"] is False

    sha = first["apk_sha256"]
    entry = cache_service.get(sha)
    assert entry is not None and entry["hits"] == 0
    assert (Path(entry["cache_root"]) / "indexes" / "index.db").exists()

    second_pid, second_task = _import(sample_apk, "cache-second")
    second = pipeline_static.run(second_pid, task_id=second_task)
    assert second["cache_hit"] is True
    assert second["package"] == first["package"]
    assert len(second["evidence_ids"]) == len(first["evidence_ids"]) >= 8
    # No tool ran: the tool blocks carry the values recorded during the first analysis.
    assert second["tools"]["jadx"]["exit"] == first["tools"]["jadx"]["exit"]

    kinds = {row["kind"] for row in artifacts_service.list_artifacts(second_pid, limit=100)}
    assert {"metadata", "findings", "index", "summary"} <= kinds
    assert cache_service.get(sha)["hits"] == 1

    events = [
        row["event_type"]
        for row in db.query("SELECT event_type FROM audit_events WHERE project_id = ? ORDER BY seq", (second_pid,))
    ]
    assert "cache_restored" in events
    assert "cache_stored" not in events


def test_force_reruns_the_tools_and_refreshes_the_entry(sample_apk):
    pipeline_static.silence_library_logging()
    pid, task_id = _import(sample_apk, "cache-force")
    pipeline_static.run(pid, task_id=task_id)
    forced = pipeline_static.run(pid, task_id=task_id, force=True)
    assert forced["cache_hit"] is False
    stored = [
        row["event_type"]
        for row in db.query("SELECT event_type FROM audit_events WHERE project_id = ? ORDER BY seq", (pid,))
    ]
    assert stored.count("cache_stored") >= 2


def test_cache_respects_the_size_limit(sample_apk, monkeypatch):
    pipeline_static.silence_library_logging()
    pid, task_id = _import(sample_apk, "cache-limit")
    monkeypatch.setattr(settings, "cache_max_mb", 0)
    summary = pipeline_static.run(pid, task_id=task_id)
    assert summary["cache_hit"] is False
    events = [
        row["event_type"] for row in db.query("SELECT event_type FROM audit_events WHERE project_id = ?", (pid,))
    ]
    assert "cache_entry_skipped" in events
    assert cache_service.get(summary["apk_sha256"]) is None


def test_cache_entry_survives_a_deleted_directory_as_a_miss(sample_apk):
    pipeline_static.silence_library_logging()
    pid, task_id = _import(sample_apk, "cache-missing")
    summary = pipeline_static.run(pid, task_id=task_id)
    entry = cache_service.get(summary["apk_sha256"])
    assert entry is not None

    import shutil

    shutil.rmtree(entry["cache_root"])
    assert cache_service.get(summary["apk_sha256"]) is None  # row dropped, not silently reused
    events = [row["event_type"] for row in db.query("SELECT event_type FROM audit_events ORDER BY seq")]
    assert "cache_entry_missing" in events


def test_cache_is_project_scoped_and_keeps_artifact_paths_valid(sample_apk):
    pipeline_static.silence_library_logging()
    pid, task_id = _import(sample_apk, "cache-scope")
    summary = pipeline_static.run(pid, task_id=task_id)
    entry = cache_service.get(summary["apk_sha256"])

    other_pid, other_task = _import(sample_apk, "cache-scope-other")
    restored = cache_service.restore(other_pid, summary["apk_sha256"], task_id=other_task)
    assert restored is not None
    for row in restored["registered"]:
        path = abs_from_storage(row["rel_path"])
        assert str(path).startswith(other_pid) or other_pid in str(path), f"{path} leaked outside the project"
        assert path.exists()
