"""The bridge gateway is the only door an agent has into the platform.

Each test here talks HTTP the way the DSH plugin does: read the run token from the
file the platform wrote, then call typed tools. What matters is not that the tools
work, but that they refuse the right things and leave a trace when they refuse.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from apkplat.db import db


def _drain_worker(kinds: str = "static_pipeline") -> int:
    from apkplat import worker

    drain = worker.Worker("pytest-bridge-worker", [k.strip() for k in kinds.split(",") if k.strip()], poll_interval=0.2)
    return drain.run(max_jobs=0)


def _upload(client, sample_apk: Path, name: str = "bridge-demo", *, analyse: bool = False) -> str:
    with sample_apk.open("rb") as handle:
        response = client.post(
            "/api/projects",
            files={"apk": (sample_apk.name, handle, "application/vnd.android.package-archive")},
            data={"name": name, "goal": "bridge gateway test"},
        )
    assert response.status_code == 201, response.text
    project_id = response.json()["project"]["id"]
    if analyse:
        _drain_worker()
    return project_id


def _first_task(client, project_id: str) -> str:
    tasks = client.get(f"/api/projects/{project_id}/tasks").json()["tasks"]
    return tasks[0]["id"]


def _run(client, project_id: str, role: str = "exec", **extra) -> tuple[str, str]:
    response = client.post(f"/api/projects/{project_id}/runs", json={"role": role, **extra})
    assert response.status_code == 201, response.text
    body = response.json()
    token = Path(body["token_path"]).read_text(encoding="utf-8")
    assert token.startswith("runcap_")
    return body["run_id"], token


def _call(client, token: str, tool: str, payload: dict | None = None, headers: dict | None = None):
    return client.post(
        f"/api/bridge/tools/{tool}",
        json=payload or {},
        headers={"Authorization": f"Bearer {token}", **(headers or {})},
    )


def test_handshake_and_snapshot_tools(app_client, sample_apk):
    project_id = _upload(app_client, sample_apk)
    run_id, token = _run(app_client, project_id, "exec")

    handshake = app_client.post(
        "/api/bridge/handshake",
        json={"run_id": run_id, "client": "pytest", "instructions_version": "p1"},
        headers={"Authorization": f"Bearer {token}"},
    )
    assert handshake.status_code == 200, handshake.text
    payload = handshake.json()
    assert payload["run"]["run_id"] == run_id
    assert payload["run"]["role_id"] == "exec"
    assert len(payload["tools"]) >= 5

    health = _call(app_client, token, "platform_health")
    assert health.status_code == 200
    body = health.json()
    assert body["ok"] is True
    assert body["tool"] == "platform_health"
    assert body["tool_version"] == "1.0.0"
    # Unimplemented phases must announce themselves instead of failing later.
    caps = body["result"]["capabilities"]
    # test_run became real in P3 (cooperative sandbox); the tool advertises that limitation
    # instead of claiming container-grade isolation.
    assert caps["test_run"]["available"] is True
    assert caps["test_run"]["isolation"] == "cooperative"
    # P5 landed the device actions; what must stay true is that they are leased and whitelisted.
    assert caps["device_action"]["available"] is True
    assert "active device lease" in caps["device_action"]["requires"]
    assert caps["capture_query"]["available"] is False

    snapshot = _call(app_client, token, "project_snapshot")
    assert snapshot.status_code == 200
    assert snapshot.json()["result"]["project"]["id"] == project_id


def test_every_call_is_traced_with_args_hash(app_client, sample_apk):
    project_id = _upload(app_client, sample_apk)
    run_id, token = _run(app_client, project_id, "exec")

    _call(app_client, token, "platform_health")
    _call(app_client, token, "task_status_get")

    trace = app_client.get(f"/api/runs/{run_id}/trace")
    assert trace.status_code == 200
    rows = trace.json()["calls"]
    assert [row["tool"] for row in rows] == ["platform_health", "task_status_get"]
    assert [row["seq"] for row in rows] == [1, 2]
    assert all(len(row["args_hash"]) == 64 for row in rows)
    # The raw token must never end up in the trace.
    assert token not in trace.text


def test_missing_token_is_refused(app_client, sample_apk):
    project_id = _upload(app_client, sample_apk)
    response = app_client.post("/api/bridge/tools/platform_health", json={})
    assert response.status_code == 401
    assert response.json()["detail"]["error_code"] == "missing_token"
    assert project_id


def test_role_scope_is_enforced_over_http(app_client, sample_apk):
    project_id = _upload(app_client, sample_apk)
    _run_id, token = _run(app_client, project_id, "plan")

    response = _call(app_client, token, "apk_inspect", {"action": "packages"})
    assert response.status_code == 403
    assert response.json()["error_code"] == "tool_not_in_scope"

    allowed = _call(app_client, token, "artifact_find", {"query": "reef"})
    assert allowed.status_code == 200


def test_capability_of_one_project_cannot_read_another(app_client, sample_apk):
    first = _upload(app_client, sample_apk, "alpha")
    second = _upload(app_client, sample_apk, "beta")
    _run_id, token = _run(app_client, first, "exec")

    response = _call(app_client, token, "task_status_get", {"project_id": second})
    assert response.status_code == 403
    assert response.json()["error_code"] == "project_denied"

    events = db.query("SELECT payload_json FROM audit_events WHERE event_type = 'bridge_cross_project_denied'")
    assert events, "refusals must be auditable"


def test_finish_may_request_review_but_never_done(app_client, sample_apk):
    project_id = _upload(app_client, sample_apk, analyse=True)
    task_id = _first_task(app_client, project_id)
    run_id, token = _run(app_client, project_id, "exec", task_id=task_id)

    done = app_client.post(
        "/api/bridge/finish",
        json={"run_id": run_id, "status": "DONE"},
        headers={"Authorization": f"Bearer {token}"},
    )
    assert done.status_code == 422
    assert done.json()["detail"]["error_code"] == "invalid_finish_status"

    review = app_client.post(
        "/api/bridge/finish",
        json={"run_id": run_id, "status": "review", "summary": "looked around"},
        headers={"Authorization": f"Bearer {token}"},
    )
    assert review.status_code == 200
    assert review.json()["task_status"] == "REVIEW"

    task = db.one("SELECT status FROM tasks WHERE id = ?", (review.json()["task_id"],))
    assert task["status"] == "REVIEW"


def test_revoked_token_stops_working(app_client, sample_apk):
    project_id = _upload(app_client, sample_apk)
    run_id, token = _run(app_client, project_id, "exec")
    assert _call(app_client, token, "platform_health").status_code == 200

    revoke = app_client.post(f"/api/runs/{run_id}/revoke", json={"reason": "test"})
    assert revoke.status_code == 200

    after = _call(app_client, token, "platform_health")
    assert after.status_code == 401
    assert after.json()["detail"]["error_code"] == "capability_revoked"


def test_evidence_submit_requires_a_verbatim_quote(app_client, sample_apk):
    project_id = _upload(app_client, sample_apk, analyse=True)
    _run_id, token = _run(app_client, project_id, "evidence")

    listing = _call(app_client, token, "artifact_find", {"query": "com.example.reef"})
    assert listing.status_code == 200
    hits = listing.json()["result"]["matches"]
    if not hits:
        pytest.skip("static pipeline has not produced a matching artifact yet")
    artifact_id = hits[0]["artifact_id"]

    invented = _call(
        app_client,
        token,
        "evidence_submit",
        {"artifact_id": artifact_id, "excerpt": "this text is not in the artifact", "claim": "invented"},
    )
    # A tool-level refusal is a *result* (HTTP 200, ok=false) so the agent can read it
    # and retry; only authorisation failures travel as HTTP errors.
    assert invented.status_code == 200
    assert invented.json()["ok"] is False
    assert invented.json()["error_code"] == "excerpt_not_found"

    quoted = _call(
        app_client,
        token,
        "evidence_submit",
        {"artifact_id": artifact_id, "excerpt": hits[0]["text"], "claim": "package name from the manifest"},
    )
    assert quoted.status_code == 200, quoted.text
    assert quoted.json()["ok"] is True
    assert quoted.json()["result"]["evidence_id"].startswith("evd_")
