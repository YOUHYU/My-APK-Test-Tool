"""P3 HTTP surface: sandbox, typed evidence, HTML report, and cross-project refusals."""
from __future__ import annotations

from pathlib import Path

import pytest

from apkplat import pipeline_static
from apkplat.services import artifacts as artifacts_service
from apkplat.services import projects as projects_service
from apkplat.services import tasks as tasks_service
from apkplat.util import project_layout


@pytest.fixture(scope="module")
def analysed(sample_apk):
    pipeline_static.silence_library_logging()
    project = projects_service.create(name="p3-api", apk_source=sample_apk, filename=sample_apk.name, actor="test")
    pid = project["id"]
    task = tasks_service.create(pid, role="exec", title="Exec", actor="test", status="RUNNING")
    pipeline_static.run(pid, task_id=task["id"])

    layout = project_layout(pid)
    script = Path(layout["artifacts"]) / "probe.py"
    script.write_text("import sys\nprint('args', sys.argv[1:])\nprint('EXIT_CODE=0')\n", encoding="utf-8")
    row = artifacts_service.register(pid, kind="script", path=script, tool="test", tool_version="1.0.0")
    kinds = {item["kind"]: item for item in artifacts_service.list_artifacts(pid, limit=100)}
    return {"id": pid, "task_id": task["id"], "script": row["id"], "kinds": kinds}


def test_sandbox_endpoints_round_trip(app_client, analysed):
    pid = analysed["id"]
    run = app_client.post(
        f"/api/projects/{pid}/sandbox/run",
        json={"script_artifact_id": analysed["script"], "argv": ["x"], "task_id": analysed["task_id"]},
    )
    assert run.status_code == 201, run.text
    body = run.json()["sandbox_run"]
    assert body["status"] == "SUCCEEDED" and body["exit_code"] == 0
    assert body["network_policy"] == "none"

    listing = app_client.get(f"/api/projects/{pid}/sandbox/runs")
    assert listing.status_code == 200
    assert listing.json()["count"] >= 1

    fetched = app_client.get(f"/api/sandbox/runs/{body['id']}")
    assert fetched.status_code == 200 and fetched.json()["sandbox_run"]["id"] == body["id"]

    replay = app_client.post(f"/api/sandbox/runs/{body['id']}/replay", json={})
    assert replay.status_code == 201
    assert replay.json()["sandbox_run"]["replay_of"] == body["id"]

    missing = app_client.post(f"/api/projects/{pid}/sandbox/run", json={})
    assert missing.status_code == 422 and missing.json()["detail"]["error_code"] == "script_required"

    container = app_client.post(
        f"/api/projects/{pid}/sandbox/run",
        json={"script_artifact_id": analysed["script"], "isolation": "container"},
    )
    assert container.status_code == 409
    assert container.json()["detail"]["error_code"] == "strong_isolation_unavailable"


def test_typed_evidence_endpoints(app_client, analysed):
    pid = analysed["id"]
    metadata = analysed["kinds"]["metadata"]["id"]
    created = app_client.post(
        f"/api/projects/{pid}/evidence/typed",
        json={
            "evidence_type": "JSON_FIELD",
            "artifact_id": metadata,
            "locator": {"pointer": "/package"},
            "expected": "com.example.reef",
            "claim": "package is com.example.reef",
            "task_id": analysed["task_id"],
        },
    )
    assert created.status_code == 201, created.text
    evidence = created.json()["evidence"]
    assert evidence["verdict"] == "VERIFIED"
    assert evidence["integrity_verified"] == 1

    listed = app_client.get(f"/api/projects/{pid}/evidence/typed")
    assert listed.status_code == 200 and listed.json()["count"] >= 1
    filtered = app_client.get(f"/api/projects/{pid}/evidence/typed", params={"evidence_type": "JSON_FIELD"})
    assert all(item["evidence_type"] == "JSON_FIELD" for item in filtered.json()["evidence"])

    detail = app_client.get(f"/api/evidence/typed/{evidence['id']}")
    assert detail.status_code == 200

    summary = app_client.get(f"/api/projects/{pid}/evidence/summary")
    assert summary.status_code == 200
    assert summary.json()["summary"]["total"] >= 1

    # Reproduction must come from a *different* run; replaying the same one is refused.
    scoped = app_client.post(
        f"/api/projects/{pid}/evidence/typed",
        json={
            "evidence_type": "JSON_FIELD",
            "artifact_id": metadata,
            "locator": {"pointer": "/version_name"},
            "expected": "1.2.3",
            "claim": "version 1.2.3",
            "run_id": "run_same",
        },
    )
    assert scoped.status_code == 201
    scoped_id = scoped.json()["evidence"]["id"]
    same_run = app_client.post(f"/api/evidence/typed/{scoped_id}/reproduce", json={"run_id": "run_same"})
    assert same_run.status_code == 422
    assert same_run.json()["detail"]["error_code"] == "same_run"
    other_run = app_client.post(f"/api/evidence/typed/{scoped_id}/reproduce", json={"run_id": "run_other"})
    assert other_run.status_code == 200
    assert other_run.json()["evidence"]["reproduced"] == 1


def test_report_gains_the_p3_sections(app_client, analysed):
    pid = analysed["id"]
    report = app_client.post(f"/api/projects/{pid}/report")
    assert report.status_code in (200, 201), report.text
    body = report.json()
    assert body["html_path"] and Path(body["html_path"]).exists()
    text = Path(body["report_path"]).read_text(encoding="utf-8")
    for heading in ("## 11. 摘要", "## 12. 能力覆盖矩阵", "## 13. 任务依赖图"):
        assert heading in text
    for heading in ("## 14. 关键时间线", "## 15. 类型化证据链", "## 17. 电脑端与真机结果"):
        assert heading in text
    assert "## 18. 无法核验的条目" in text and "## 19. 审查意见" in text

    html = app_client.get(f"/api/projects/{pid}/report.html")
    assert html.status_code == 200
    assert "<table>" in html.text and "摘要" in html.text


def test_cross_project_reading_is_refused(app_client, analysed, sample_apk, admin_headers):
    from apkplat.config import settings

    pid = analysed["id"]
    created = app_client.post(
        f"/api/projects/{pid}/evidence/typed",
        json={
            "evidence_type": "JSON_FIELD",
            "artifact_id": analysed["kinds"]["metadata"]["id"],
            "locator": {"pointer": "/package"},
            "expected": "com.example.reef",
            "claim": "package",
        },
    )
    assert created.status_code == 201, created.text
    evidence_id = created.json()["evidence"]["id"]

    # Local-operator mode deliberately bypasses tokens, so this check only means anything
    # with auth switched on - flip it for the duration of the test.
    previous = settings.require_auth
    settings.require_auth = True
    try:
        assert _cross_project_checks(app_client, analysed, sample_apk, admin_headers, evidence_id)
    finally:
        settings.require_auth = previous


def _cross_project_checks(app_client, analysed, sample_apk, admin_headers, evidence_id: str) -> bool:
    other = projects_service.create(name="p3-api-other", apk_source=sample_apk, filename=sample_apk.name, actor="test")
    token = app_client.post(
        "/api/auth/token",
        json={"projects": [other["id"]], "subject": "p3-other", "scopes": ["read", "write"]},
        headers=admin_headers,
    )
    assert token.status_code == 200, token.text
    headers = {"Authorization": f"Bearer {token.json()['token']}"}
    denied = app_client.get(f"/api/projects/{analysed['id']}/evidence/typed", headers=headers)
    assert denied.status_code == 403
    assert denied.json()["detail"]["error_code"] == "project_denied"

    allowed = app_client.get(f"/api/projects/{other['id']}/evidence/typed", headers=headers)
    assert allowed.status_code == 200

    # Id-scoped routes must refuse too: the id alone is not an authorisation.
    blocked = app_client.get(f"/api/evidence/typed/{evidence_id}", headers=headers)
    assert blocked.status_code == 403
    assert blocked.json()["detail"]["error_code"] == "project_denied"
    return True


def test_typed_evidence_rejects_very_bad_input(app_client, analysed):
    pid = analysed["id"]
    bad_type = app_client.post(
        f"/api/projects/{pid}/evidence/typed",
        json={"evidence_type": "TELEPATHY", "artifact_id": analysed["kinds"]["metadata"]["id"], "locator": {"x": 1}},
    )
    assert bad_type.status_code == 422 and bad_type.json()["detail"]["error_code"] == "invalid_evidence_type"

    no_locator = app_client.post(
        f"/api/projects/{pid}/evidence/typed",
        json={"evidence_type": "JSON_FIELD", "artifact_id": analysed["kinds"]["metadata"]["id"], "locator": {}},
    )
    assert no_locator.status_code == 422 and no_locator.json()["detail"]["error_code"] == "locator_required"

    foreign_task = app_client.post(
        f"/api/projects/{pid}/evidence/typed",
        json={
            "evidence_type": "JSON_FIELD",
            "artifact_id": analysed["kinds"]["metadata"]["id"],
            "locator": {"pointer": "/package"},
            "task_id": "tsk_does_not_exist",
        },
    )
    assert foreign_task.status_code == 404 and foreign_task.json()["detail"]["error_code"] == "task_not_found"
