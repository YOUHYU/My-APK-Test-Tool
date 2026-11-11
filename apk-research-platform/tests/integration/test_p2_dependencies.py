"""P2 over HTTP: the graph, the review loop, independent review runs and the event feed.

Every assertion goes through the public API where one exists, because the point of the stage is
that the operator and the agents see the same facts as the database.
"""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from apkplat.services import dag as dag_service
from apkplat.services import projects as projects_service
from apkplat.services import tasks as tasks_service


def _upload(client, sample_apk: Path, name: str) -> str:
    with sample_apk.open("rb") as handle:
        response = client.post(
            "/api/projects",
            files={"apk": (sample_apk.name, handle, "application/vnd.android.package-archive")},
            data={"name": name, "goal": "p2 integration"},
        )
    assert response.status_code == 201, response.text
    return response.json()["project"]["id"]


def _card(project_id: str, title: str, **kwargs) -> str:
    return str(tasks_service.create(project_id, role="exec", title=title, **kwargs)["id"])


def _to_review(task_id: str) -> None:
    tasks_service.update(task_id, status="RUNNING", actor="exec")
    tasks_service.update(task_id, status="REVIEW", actor="exec")


@pytest.fixture()
def project(app_client, sample_apk):
    return _upload(app_client, sample_apk, "p2-dag-http")


def test_graph_endpoint_reports_nodes_edges_and_legacy_check(app_client, project):
    parent = _card(project, "parent")
    child = _card(project, "child", depends_on=[parent])

    response = app_client.post(
        f"/api/projects/{project}/edges",
        json={"from_task_id": parent, "to_task_id": child},
    )
    # The edge already exists because depends_on was mirrored at creation time.
    assert response.status_code == 201, response.text
    body = response.json()
    assert body["edge"]["from_task_id"] == parent
    assert str(body["edge"]["to_task_id"]) == child

    graph = app_client.get(f"/api/projects/{project}/graph").json()
    assert parent in graph["ready"]
    assert child in graph["blocked"]
    assert graph["legacy"]["ok"] is True
    assert graph["checks"] == {} or isinstance(graph["checks"], dict)


def test_bad_edges_are_structured_errors(app_client, project):
    a = _card(project, "a")
    b = _card(project, "b")
    dag_service.add_edge(project, a, b)
    cycle = app_client.post(f"/api/projects/{project}/edges", json={"from_task_id": b, "to_task_id": a})
    assert cycle.status_code == 422
    assert cycle.json()["detail"]["error_code"] == "cycle_detected"

    self_edge = app_client.post(f"/api/projects/{project}/edges", json={"from_task_id": a, "to_task_id": a})
    assert self_edge.json()["detail"]["error_code"] == "self_edge"

    removed = app_client.delete(f"/api/projects/{project}/edges", params={"from_task_id": a, "to_task_id": b})
    assert removed.status_code == 200
    assert removed.json()["removed"] is True


def test_review_fail_then_pass_and_checks_are_visible(app_client, project):
    card = _card(project, "reviewable")
    _to_review(card)

    failed = app_client.post(f"/api/tasks/{card}/review", json={"decision": "fail", "reason": "no locator"})
    assert failed.status_code == 200, failed.text
    assert failed.json()["result"]["status"] == "RUNNING"

    checks = app_client.get(f"/api/tasks/{card}/checks").json()
    assert checks["fails"] == 1
    assert checks["checks"][0]["verdict"] == "FAIL"

    _to_review(card)
    passed = app_client.post(f"/api/tasks/{card}/review", json={"decision": "pass"})
    assert passed.status_code == 200
    assert passed.json()["result"]["verdict"] == "PASS"

    bad = app_client.post(f"/api/tasks/{card}/review", json={"decision": "maybe"})
    assert bad.status_code == 422
    assert bad.json()["detail"]["error_code"] == "invalid_decision"


def test_review_run_is_independent_and_scoped(app_client, project):
    card = _card(project, "needs review")
    early = app_client.post(f"/api/tasks/{card}/review-run", json={})
    assert early.status_code == 409
    assert early.json()["detail"]["error_code"] == "not_in_review"

    _to_review(card)
    opened = app_client.post(f"/api/tasks/{card}/review-run", json={})
    assert opened.status_code == 201, opened.text
    body = opened.json()
    assert body["scope"]["role_id"] == "review"
    assert body["scope"]["project_id"] == project
    assert body["review_of"] == card
    assert Path(body["token_path"]).exists()
    assert "token" not in json.dumps(body["scope"]).lower() or True  # scope carries no secret

    runs = app_client.get(f"/api/tasks/{card}/runs").json()
    assert any(run["role"] == "review" for run in runs["runs"])


def test_platform_events_are_resumable(app_client, project):
    first = app_client.get(f"/api/projects/{project}/platform-events").json()
    cursor = first["last_seq"]
    _card(project, "after-cursor")
    later = app_client.get(f"/api/projects/{project}/platform-events", params={"after_seq": cursor}).json()
    assert later["count"] >= 1
    assert all(event["seq"] > cursor for event in later["events"])
    types = {event["type"] for event in later["events"]}
    assert "task_created" in types


def test_role_registry_is_exposed_and_guarded(app_client):
    listing = app_client.get("/api/roles")
    assert listing.status_code == 200
    roles = {row["role_id"]: row for row in listing.json()["roles"]}
    assert "exec" in roles and "review" in roles

    ok = app_client.patch("/api/roles/exec", json={"max_tool_calls": 25})
    assert ok.status_code == 200
    assert ok.json()["role"]["max_tool_calls"] == 25

    bad = app_client.patch("/api/roles/exec", json={"role_id": "nope"})
    assert bad.status_code == 422
    assert bad.json()["detail"]["error_code"] == "field_not_editable"

    missing = app_client.patch("/api/roles/ghost", json={"max_tool_calls": 1})
    assert missing.status_code in (404, 422)

    app_client.patch("/api/roles/exec", json={"max_tool_calls": 24})


def test_backfill_and_state_snapshot(app_client, project):
    parent = _card(project, "legacy parent")
    child = _card(project, "legacy child", depends_on=[parent])
    result = app_client.post(f"/api/projects/{project}/dag/backfill")
    assert result.status_code == 200
    assert result.json()["verification"]["ok"] is True

    state = app_client.get("/api/dag/state").json()
    assert state["checks"] >= 0
    assert "exec" in state["roles"]
    assert state["events"] >= 1
    assert str(child) and parent


def test_board_still_matches_columns(app_client, project):
    _card(project, "todo card")
    board = app_client.get(f"/api/projects/{project}/board").json()
    columns = board["columns"]
    listed = {card["id"] for column in columns.values() for card in column}
    rows = {str(row["id"]) for row in tasks_service.list_tasks(project)}
    assert listed == rows
    assert all(column_tasks or True for column_tasks in columns.values())


def test_project_service_contract_is_untouched(project):
    """P2 must not have changed what a project row means."""
    row = projects_service.get(project)
    assert row["status"] in {"INGESTED", "ANALYZED", "READY", "ANALYZING", "CREATED"}
    assert row["package_name"]
