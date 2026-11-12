"""Run capabilities are the only thing standing between an agent and the platform.

These tests pin the rules the taskbook makes non-negotiable: the token is opaque and
hashed at rest, the scope is the sole authority on which tools a role may call, and
budgets/cross-project attempts are refused with a structured code rather than a 500.
"""

from __future__ import annotations

import json

import pytest

from apkplat.db import db as database, utcnow
from apkplat.services import capabilities as caps


def _project(name: str) -> str:
    pid = f"prj_{name}"
    database.execute(
        "INSERT INTO projects (id, name, apk_sha256, apk_filename, status, policy_id, created_at, updated_at)"
        " VALUES (?, ?, ?, ?, 'ANALYZED', 'default', ?, ?)",
        (pid, name, f"sha-{name}", f"{name}.apk", utcnow(), utcnow()),
    )
    return pid


def _task(project_id: str, title: str = "cap task") -> str:
    tid = f"tsk_{title.replace(' ', '_')}_{project_id[-4:]}"
    database.execute(
        "INSERT INTO tasks (id, project_id, role, title, status, created_at, updated_at, evidence_count,"
        " model_calls, tool_calls, attempt, version)"
        " VALUES (?, ?, 'static', ?, 'TODO', ?, ?, 0, 0, 0, 0, 1)",
        (tid, project_id, title, utcnow(), utcnow()),
    )
    return tid


def test_issue_hashes_the_token_and_never_stores_it(monkeypatch):
    project = _project("caps001")
    scope, token, path = caps.issue(project, "exec", actor="test")

    assert token.startswith(caps.TOKEN_PREFIX)
    assert scope.project_id == project
    row = database.one("SELECT token_hash, scope_json FROM run_capabilities WHERE run_id = ?", (scope.run_id,))
    assert row["token_hash"] == caps._hash_token(token)
    assert token not in row["scope_json"]
    # The token file is the plugin's only copy of the secret.
    assert path is not None and path.read_text(encoding="utf-8") == token
    stored = json.loads(row["scope_json"])
    assert stored["role_id"] == "exec"
    assert "apk_inspect" in stored["allowed_tools"]


def test_resolve_round_trips_and_rejects_unknown_tokens():
    project = _project("caps002")
    scope, token, _ = caps.issue(project, "plan")

    resolved = caps.resolve(token)
    assert resolved.run_id == scope.run_id
    assert resolved.project_id == project

    with pytest.raises(caps.CapabilityError) as missing:
        caps.resolve("runcap_deadbeef")
    assert missing.value.code == "invalid_token"

    with pytest.raises(caps.CapabilityError) as empty:
        caps.resolve("")
    assert empty.value.code == "missing_token"


def test_expired_capability_is_refused():
    project = _project("caps003")
    scope, token, _ = caps.issue(project, "exec", ttl_seconds=0)
    database.execute("UPDATE run_capabilities SET expires_at = ? WHERE run_id = ?", ("2000-01-01T00:00:00.000Z", scope.run_id))

    with pytest.raises(caps.CapabilityError) as expired:
        caps.resolve(token)
    assert expired.value.code == "capability_expired"
    assert expired.value.status == 401


def test_revoke_is_idempotent_and_blocks_later_use():
    project = _project("caps004")
    scope, token, _ = caps.issue(project, "exec")
    caps.revoke(scope.run_id, reason="operator stop", actor="test")
    caps.revoke(scope.run_id, reason="operator stop", actor="test")

    with pytest.raises(caps.CapabilityError) as revoked:
        caps.resolve(token)
    assert revoked.value.code == "capability_revoked"


def test_plan_role_may_not_call_apk_inspect():
    project = _project("caps005")
    scope, _token, _ = caps.issue(project, "plan")
    assert "apk_inspect" not in scope.tools

    with pytest.raises(caps.CapabilityError) as denied:
        caps.authorize(scope, "apk_inspect", {})
    assert denied.value.code == "tool_not_in_scope"
    assert denied.value.status == 403
    # The refusal has to survive the API layer unchanged, so it carries a body shape.
    assert denied.value.as_error()["error_code"] == "tool_not_in_scope"


def test_unknown_tool_is_a_404_not_a_500():
    project = _project("caps006")
    scope, _token, _ = caps.issue(project, "exec")
    with pytest.raises(caps.CapabilityError) as unknown:
        caps.authorize(scope, "shell_exec", {})
    assert unknown.value.code == "unknown_tool"
    assert unknown.value.status == 404


def test_cross_project_arguments_are_refused(monkeypatch):
    project = _project("caps007")
    other = _project("caps008")
    scope, _token, _ = caps.issue(project, "evidence")

    with pytest.raises(caps.CapabilityError) as denied:
        caps.authorize(scope, "artifact_find", {"project_id": other})
    assert denied.value.code == "project_denied"
    # The denial is auditable, not just a return value.
    events = database.query("SELECT event_type FROM audit_events WHERE event_type = 'bridge_cross_project_denied'")
    assert events


def test_budget_is_enforced_by_call_count():
    project = _project("caps009")
    scope, _token, _ = caps.issue(project, "exec", max_tool_calls=2)
    for index in range(2):
        caps.record_call(scope.run_id, tool="task_status_get", args={"task_id": None}, ok=True, error_code=None, duration_ms=1, request_id=f"req{index}")

    with pytest.raises(caps.CapabilityError) as exhausted:
        caps.authorize(scope, "task_status_get", {})
    assert exhausted.value.code == "tool_budget_exhausted"
    assert exhausted.value.status == 429


def test_record_call_writes_monotonic_sequence():
    project = _project("caps010")
    scope, _token, _ = caps.issue(project, "exec")
    for index in range(3):
        caps.record_call(scope.run_id, tool="platform_health", args={}, ok=True, error_code=None, duration_ms=5, request_id=f"r{index}")

    rows = caps.trace(scope.run_id)
    assert [row["seq"] for row in rows] == [1, 2, 3]
    assert all(row["tool"] == "platform_health" for row in rows)


def test_tool_call_log_is_append_only():
    project = _project("caps011")
    scope, _token, _ = caps.issue(project, "exec")
    caps.record_call(scope.run_id, tool="platform_health", args={}, ok=True, error_code=None, duration_ms=1, request_id="once")

    with pytest.raises(Exception):
        database.execute("DELETE FROM run_tool_calls WHERE run_id = ?", (scope.run_id,))


def test_task_must_belong_to_the_capability_project():
    project = _project("caps012")
    other = _project("caps013")
    foreign_task = _task(other)

    with pytest.raises(caps.CapabilityError) as mismatch:
        caps.issue(project, "exec", task_id=foreign_task)
    assert mismatch.value.code == "task_project_mismatch"


def test_agent_run_binding_round_trips():
    project = _project("caps014")
    scope, _token, _ = caps.issue(project, "exec")
    caps.bind_agent_run(scope.run_id, "agn_roundtrip")
    assert caps.agent_run_of(scope.run_id) == "agn_roundtrip"


def test_role_aliases_map_to_the_six_templates():
    assert caps.canonical_role("re-plan") == "plan"
    assert caps.canonical_role("RE-EXEC") == "exec"
    with pytest.raises(caps.CapabilityError) as bad:
        caps.canonical_role("god-mode")
    assert bad.value.code == "unknown_role"
