"""Per-project storage roots (migration 009).

A project may pin its own absolute directory; everything the pipeline writes -
inputs, artifacts, indexes, evidence, logs, reports - then lives there, while the
platform database still records one row per project.
"""
from __future__ import annotations

from pathlib import Path

import pytest

from apkplat.config import settings
from apkplat.services import artifacts as artifacts_service
from apkplat.services import projects as projects_service
from apkplat.util import project_layout, project_root


def test_project_can_live_outside_the_default_storage(tmp_path: Path, sample_apk: Path) -> None:
    target = tmp_path / "case-a"
    project = projects_service.create("pinned", sample_apk, "sample-app.apk", storage_root=target, actor="test")

    assert project["storage_root"] == str(target.resolve())
    assert project_root(project["id"]) == target.resolve()
    layout = project_layout(project["id"])
    assert layout["base"] == target.resolve()
    assert (target / "inputs").is_dir()
    assert list((target / "inputs").glob("base-*.apk")), "the APK should be ingested inside the pinned directory"
    # nothing was left behind in the default location
    assert not settings.project_dir(project["id"]).exists()


def test_manifest_and_artifacts_follow_the_pinned_root(tmp_path: Path, sample_apk: Path) -> None:
    target = tmp_path / "case-b"
    project = projects_service.create("pinned-b", sample_apk, "sample-app.apk", storage_root=target, actor="test")

    manifest = projects_service.manifest(project["id"])
    assert manifest["package"] == "com.example.reef"

    layout = project_layout(project["id"])
    note = layout["artifacts"] / "note.txt"
    note.write_text("hello\n", encoding="utf-8")
    row = artifacts_service.register(project["id"], kind="notes", path=note, tool="test")
    # A pinned project sits outside the storage area, so its artifacts are recorded by
    # absolute path; abs_from_storage() must round-trip both shapes.
    assert Path(row["rel_path"]).is_absolute(), row["rel_path"] or ""
    assert Path(row["rel_path"]).resolve() == note.resolve()


def test_two_projects_can_pin_different_directories(tmp_path: Path, sample_apk: Path) -> None:
    a = projects_service.create("case-a", sample_apk, "sample-app.apk", storage_root=tmp_path / "a", actor="test")
    b = projects_service.create("case-b", sample_apk, "sample-app.apk", storage_root=tmp_path / "b", actor="test")

    assert project_root(a["id"]) != project_root(b["id"])
    assert project_root(a["id"]).is_dir() and project_root(b["id"]).is_dir()


def test_relative_root_is_refused(sample_apk: Path) -> None:
    with pytest.raises(projects_service.ProjectError) as exc:
        projects_service.create("bad", sample_apk, "sample-app.apk", storage_root="relative/dir", actor="test")
    assert exc.value.code == "storage_root_not_absolute"
    assert exc.value.status == 422


def test_root_inside_the_storage_area_is_refused(sample_apk: Path) -> None:
    nested = settings.storage / "nested-case"
    with pytest.raises(projects_service.ProjectError) as exc:
        projects_service.create("bad", sample_apk, "sample-app.apk", storage_root=nested, actor="test")
    assert exc.value.code == "storage_root_inside_storage"


def test_non_empty_directory_is_refused(tmp_path: Path, sample_apk: Path) -> None:
    target = tmp_path / "occupied"
    target.mkdir()
    (target / "keep.txt").write_text("do not clobber\n", encoding="utf-8")
    with pytest.raises(projects_service.ProjectError) as exc:
        projects_service.create("bad", sample_apk, "sample-app.apk", storage_root=target, actor="test")
    assert exc.value.code == "storage_root_not_empty"
    assert (target / "keep.txt").exists(), "an existing directory must not be touched"


def test_a_file_is_not_a_directory(tmp_path: Path, sample_apk: Path) -> None:
    target = tmp_path / "notadir"
    target.write_text("x", encoding="utf-8")
    with pytest.raises(projects_service.ProjectError) as exc:
        projects_service.create("bad", sample_apk, "sample-app.apk", storage_root=target, actor="test")
    assert exc.value.code == "storage_root_not_a_directory"


def test_default_root_when_omitted(sample_apk: Path) -> None:
    project = projects_service.create("plain", sample_apk, "sample-app.apk", actor="test")
    assert project["storage_root"] is None
    assert project_root(project["id"]) == settings.project_dir(project["id"])
