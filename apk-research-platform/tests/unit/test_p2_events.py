"""Platform event feed: monotonic seq, dedupe keys, resumable cursors."""
from __future__ import annotations

import pytest

from apkplat.services import events, projects


@pytest.fixture()
def project(sample_apk):
    row = projects.create(
        name="events-unit",
        apk_source=sample_apk,
        filename="sample-app.apk",
        goal="events unit",
        actor="test",
    )
    return str(row["id"])


def _seq_signature(rows):
    return [row["seq"] for row in rows]


def test_emit_assigns_monotonic_sequence(project):
    first = events.emit("note", project_id=project, payload={"text": "one"})
    second = events.emit("note", project_id=project, payload={"text": "two"})
    assert isinstance(first, int) and isinstance(second, int)
    assert second > first
    tail = events.tail(first)
    assert _seq_signature(tail) == [second]


def test_emit_tolerates_unknown_event_type(project):
    """The type column is free text; typos must not break the feed."""
    seq = events.emit("some_new_thing", project_id=project, payload={})
    rows = events.tail(seq - 1, project)
    assert rows and rows[-1]["type"] == "some_new_thing"


def test_dedupe_key_collapses_duplicates(project):
    first, created_first = events.emit_once("run_started", project_id=project, dedupe_key="run-1")
    second, created_second = events.emit_once("run_started", project_id=project, dedupe_key="run-1")
    assert created_first is True
    assert created_second is False
    assert first == second
    assert events.count("run_started", project) == 1


def test_cursor_is_resumable_and_project_scoped(project, sample_apk):
    other = projects.create(
        name="events-other",
        apk_source=sample_apk,
        filename="sample-app.apk",
        goal="other",
        actor="test",
    )
    other_id = str(other["id"])
    a = events.emit("note", project_id=project, payload={"n": 1})
    b = events.emit("note", project_id=other_id, payload={"n": 2})
    c = events.emit("note", project_id=project, payload={"n": 3})
    assert b > a and c > b
    mine = events.tail(0, project)
    assert [row["seq"] for row in mine] == [a, c]
    assert [row["seq"] for row in events.tail(a, project)] == [c]


def test_last_seq_and_types_seen(project):
    events.emit("task_status", project_id=project, payload={"status": "RUNNING"})
    top = events.last_seq()
    assert top >= 1
    assert "task_status" in set(events.types_seen(project))


def test_payload_round_trips_as_structure(project):
    seq = events.emit("review", project_id=project, payload={"verdict": "FAIL", "nested": {"k": [1, 2]}})
    row = events.tail(seq - 1, project)[-1]
    assert row["payload"]["verdict"] == "FAIL"
    assert row["payload"]["nested"]["k"] == [1, 2]
    assert row["project_id"] == project
