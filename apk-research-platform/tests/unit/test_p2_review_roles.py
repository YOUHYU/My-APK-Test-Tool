"""Review checks, bounded dispatch-back, and the editable role registry."""
from __future__ import annotations

import pytest

from apkplat.services import projects, review, roles, tasks
from apkplat.services.review import ReviewError


@pytest.fixture()
def project(sample_apk):
    row = projects.create(
        name="review-unit",
        apk_source=sample_apk,
        filename="sample-app.apk",
        goal="review unit",
        actor="test",
    )
    return str(row["id"])


def _reviewing(project_id: str, title: str = "card") -> str:
    task_id = str(tasks.create(project_id, role="exec", title=title)["id"])
    tasks.update(task_id, status="RUNNING", actor="exec")
    tasks.update(task_id, status="REVIEW", actor="exec")
    return task_id


def test_record_check_validates_verdict(project):
    card = _reviewing(project)
    with pytest.raises(ReviewError) as bad:
        review.record_check(project, card, verdict="maybe", criterion="unit")
    assert bad.value.code == "invalid_verdict"
    ok = review.record_check(project, card, verdict="pass", criterion="unit", detail={"n": 1})
    assert ok["verdict"] == "PASS"
    assert review.latest_verdict(card) == "PASS"
    assert review.fail_count(card) == 0


def test_check_for_unknown_task_is_404(project):
    with pytest.raises(ReviewError) as missing:
        review.record_check(project, "tsk_missing", verdict="PASS", criterion="unit")
    assert missing.value.code == "task_not_found"
    assert missing.value.status == 404


def test_dispatch_back_returns_to_running_then_blocks(project):
    card = _reviewing(project)
    first = review.dispatch_back(project, card, reason="no locator", retry_limit=2)
    assert first["status"] == "RUNNING"
    assert first["task"]["error_code"] == "review_returned"

    tasks.update(card, status="REVIEW", actor="exec")
    second = review.dispatch_back(project, card, reason="still no locator", retry_limit=2)
    assert second["status"] == "RUNNING"

    tasks.update(card, status="REVIEW", actor="exec")
    third = review.dispatch_back(project, card, reason="third strike", retry_limit=2)
    assert third["status"] == "BLOCKED"
    assert third["task"]["error_code"] == "review_retry_exhausted"
    assert review.fail_count(card) == 3


def test_dispatch_back_is_scoped_to_the_project(project, sample_apk):
    other = projects.create(
        name="review-other",
        apk_source=sample_apk,
        filename="sample-app.apk",
        goal="other",
        actor="test",
    )
    card = _reviewing(project)
    with pytest.raises(ReviewError) as denied:
        review.dispatch_back(str(other["id"]), card, reason="wrong project")
    assert denied.value.code == "project_denied"
    assert denied.value.status == 403


def test_accept_records_pass(project):
    card = _reviewing(project)
    review.dispatch_back(project, card, reason="missing evidence")
    if tasks.get(card)["status"] == "RUNNING":
        tasks.update(card, status="REVIEW", actor="exec")
    verdict = review.accept(project, card)
    assert verdict["verdict"] == "PASS"
    summary = review.verdict_summary(project)
    assert summary[card]["pass"] == 1
    assert summary[card]["fail"] == 1


def test_role_registry_seeds_six_roles_and_edits_are_allowlisted():
    seeded = roles.seed()
    assert seeded >= 0  # idempotent: a second call may update in place
    names = {row["role_id"] for row in roles.listing()}
    assert {"plan", "exec", "review", "ship", "evidence", "report"} <= names
    assert "apk_inspect" not in roles.tools("plan")
    assert "apk_inspect" in roles.tools("exec")
    original = roles.budget("exec")["max_tool_calls"]
    assert roles.budget("review")["max_tool_calls"] >= 1
    assert roles.retry_limit("exec") >= 1

    with pytest.raises(Exception) as unknown:
        roles.get("nope")
    assert "role" in str(unknown.value).lower()

    updated = roles.update("exec", fields={"max_tool_calls": 33}, actor="test")
    assert updated["max_tool_calls"] == 33
    with pytest.raises(ReviewError) as bad_field:
        roles.update("exec", fields={"role_id": "hacked"}, actor="test")
    assert bad_field.value.code == "field_not_editable"
    roles.update("exec", fields={"max_tool_calls": original}, actor="test")


def test_coverage_reports_every_role_mapping():
    roles.seed()
    cov = roles.coverage()
    assert isinstance(cov, dict)
    assert "roles" in cov and "retry_limits" in cov
    assert {"plan", "exec", "review"} <= set(cov["roles"])
    assert all(isinstance(v, list) for v in cov["roles"].values())
