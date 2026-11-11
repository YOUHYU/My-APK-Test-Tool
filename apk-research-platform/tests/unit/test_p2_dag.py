"""Dependency-graph rules: what may be wired, what counts as satisfied, what may be claimed.

These are the invariants the P2 claim gate depends on. They are unit tests, so they build
their own projects and cards through the services rather than through HTTP.
"""
from __future__ import annotations

import pytest

from apkplat.services import dag, projects, tasks  # noqa: F401
from apkplat.services.dag import DagError


@pytest.fixture()
def project(sample_apk):
    row = projects.create(
        name="dag-unit",
        apk_source=sample_apk,
        filename="sample-app.apk",
        goal="dag unit test",
        actor="test",
    )
    return str(row["id"])


def _card(project_id: str, title: str, **kwargs) -> str:
    return str(tasks.create(project_id, role="exec", title=title, **kwargs)["id"])


def test_edge_rules_reject_self_cross_project_and_cycles(project, sample_apk):
    a = _card(project, "a")
    b = _card(project, "b")
    c = _card(project, "c")
    other = projects.create(
        name="dag-other",
        apk_source=sample_apk,
        filename="sample-app.apk",
        goal="other",
        actor="test",
    )
    foreign = _card(str(other["id"]), "foreign")

    with pytest.raises(DagError) as self_edge:
        dag.add_edge(project, a, a)
    assert self_edge.value.code == "self_edge"

    with pytest.raises(DagError) as cross:
        dag.add_edge(project, foreign, a)
    assert cross.value.code == "cross_project_edge"
    assert cross.value.status == 403

    dag.add_edge(project, a, b)
    dag.add_edge(project, b, c)

    with pytest.raises(DagError) as cycle:
        dag.add_edge(project, c, a)
    assert cycle.value.code == "cycle_detected"

    with pytest.raises(DagError) as kind:
        dag.add_edge(project, c, a, kind="informs")
    assert kind.value.code == "unsupported_edge_kind"


def test_duplicate_edge_is_idempotent(project):
    a = _card(project, "a")
    b = _card(project, "b")
    first = dag.add_edge(project, a, b)
    second = dag.add_edge(project, a, b)
    assert first["id"] == second["id"]
    assert len(dag.edges(project)) == 1


def test_second_path_is_legal(project):
    """A -> C on top of A -> B -> C is a shortcut, not a cycle."""
    a = _card(project, "a")
    b = _card(project, "b")
    c = _card(project, "c")
    dag.add_edge(project, a, b)
    dag.add_edge(project, b, c)
    shortcut = dag.add_edge(project, a, c)
    assert shortcut["from_task_id"] == a
    assert not dag.would_cycle(project, a, c)


def test_parent_is_satisfied_by_done_or_a_pass_check(project):
    parent = _card(project, "parent")
    child = _card(project, "child")
    dag.add_edge(project, parent, child)
    assert [p["task_id"] for p in dag.unmet_parents(child)] == [parent]
    assert dag.blocked_reason(child) == f"waiting_on:{parent}"
    assert not dag.ready(child)

    # A PASS check unlocks the child even before the parent is closed out.
    from apkplat.services import review

    review.record_check(project, parent, verdict="PASS", criterion="unit")
    assert dag.unmet_parents(child) == []
    assert dag.ready(child) is True
    assert dag.blocked_reason(child) is None


def test_done_parent_also_unlocks(project):
    parent = _card(project, "parent")
    child = _card(project, "child")
    dag.add_edge(project, parent, child)
    tasks.update(parent, status="RUNNING", actor="exec")
    tasks.update(parent, status="REVIEW", actor="exec")
    tasks.update(parent, status="DONE", actor="reviewer")
    assert dag.ready(child) is True


def test_backfill_mirrors_legacy_depends_on(project):
    parent = _card(project, "parent")
    # depends_on is written at creation time; sync_depends_on mirrors it into task_edges.
    child = _card(project, "child", depends_on=[parent])
    assert dag.parents(child) == [parent]
    report = dag.backfill(project)
    assert report["edges_created"] == 0  # already mirrored, so nothing new
    assert dag.verify_against_legacy(project)["ok"] is True


def test_graph_reports_dangling_and_ready(project):
    a = _card(project, "a")
    b = _card(project, "b")
    dag.add_edge(project, a, b)
    graph = dag.graph(project)
    assert graph["edges"] and graph["dangling_edges"] == []
    assert a in graph["ready"]
    assert b in graph["blocked"]


def test_remove_edge_restores_readiness(project):
    a = _card(project, "a")
    b = _card(project, "b")
    dag.add_edge(project, a, b)
    assert not dag.ready(b)
    assert dag.remove_edge(project, a, b) is True
    assert dag.ready(b)
    assert dag.remove_edge(project, a, b) is False
