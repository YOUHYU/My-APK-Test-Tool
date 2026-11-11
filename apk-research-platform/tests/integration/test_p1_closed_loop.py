"""P1 - single-APK static closed loop, driven only through the public surfaces.

The taskbook's acceptance condition is that a full analysis happens *without manual
commands*: upload ->validation ->restricted JADX/Apktool ->index ->MCP call ->evidence ->Markdown report. This test does exactly that over HTTP + the MCP server,
then asserts the artifacts are self-consistent.
"""
from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent.parent
MCP_SERVER = ROOT / "mcp-server" / "mcp_server" / "server.py"


def _drain_worker(kinds: str = "static_pipeline") -> int:
    from apkplat import worker

    w = worker.Worker("pytest-worker", [k.strip() for k in kinds.split(",") if k.strip()], poll_interval=0.2)
    return w.run(max_jobs=0)


def _upload(client, local_headers, sample_apk: Path, name: str):
    with open(sample_apk, "rb") as fh:
        resp = client.post(
            "/api/projects",
            headers=local_headers,
            files={"apk": (sample_apk.name, fh, "application/vnd.android.package-archive")},
            data={"name": name, "goal": "pytest closed loop", "policy_id": "default"},
        )
    assert resp.status_code == 201, resp.text
    return resp.json()


def test_p1_upload_pipeline_report(app_client, local_headers, sample_apk, ground_truth):
    created = _upload(app_client, local_headers, sample_apk, "p1-closed-loop")
    project_id = created["project"]["id"]
    assert created["job_id"]

    processed = _drain_worker()
    assert processed >= 1

    detail = app_client.get(f"/api/projects/{project_id}", headers=local_headers)
    assert detail.status_code == 200, detail.text
    body = detail.json()
    manifest = body["manifest"]
    assert manifest["package"] == ground_truth["package"]
    assert manifest["ingest"]["sha256"] == ground_truth["apk_sha256"]
    assert manifest["certificate_sha256"] == ground_truth["certificate_sha256"]

    # artifacts: validation, apktool logs, jadx logs, metadata, findings, index, summary
    arts = app_client.get(f"/api/projects/{project_id}/artifacts", headers=local_headers).json()["artifacts"]
    kinds = {a["kind"] for a in arts}
    assert {"validation", "metadata", "findings", "index", "tool_stdout", "tool_stderr"} <= kinds

    # verification: chain intact + every excerpt traceable
    verify = app_client.get(f"/api/projects/{project_id}/verify", headers=local_headers).json()
    assert verify["artifacts"]["failures"] == []
    assert verify["evidence"]["traceability_rate"] == 1.0

    # the auto-created static card must leave RUNNING and land in REVIEW; a silent
    # exception in the worker used to leave it RUNNING for ever (regression guard)
    board = app_client.get(f"/api/projects/{project_id}/board", headers=local_headers).json()
    review = [card for card in board["columns"]["REVIEW"] if card["role"] == "static"]
    assert review, board["columns"]
    assert board["columns"]["RUNNING"] == []
    assert review[0]["evidence_count"] >= 8, review[0]
    assert board["columns"]["DONE"] == []

    # evidence must cover the ground-truth facts exactly
    ev = app_client.get(f"/api/projects/{project_id}/evidence", headers=local_headers).json()["evidence"]
    claims = " ".join((row.get("claim") or "") for row in ev)
    for package_hint in (ground_truth["package"], ground_truth["version_name"]):
        assert package_hint in claims
    for permission in ground_truth["permissions"]:
        assert permission in claims
    for literal in ground_truth["secret_literals"]:
        assert any(literal in (row.get("claim") or "") for row in ev), f"missing evidence for {literal}"

    # code index answers queries
    search = app_client.get(
        f"/api/projects/{project_id}/search",
        params={"q": "validateLicense"},
        headers=local_headers,
    )
    assert search.status_code == 200
    hits = search.json()["results"]
    assert hits and any(h["member"] == "validateLicense" for h in hits)

    method = app_client.get(
        f"/api/projects/{project_id}/search",
        params={"q": "SecurityHelper", "kind": "method"},
        headers=local_headers,
    ).json()["results"]
    assert method, "expected at least one method in SecurityHelper"

    # report
    report = app_client.post(f"/api/projects/{project_id}/report", headers=local_headers)
    assert report.status_code == 201, report.text
    payload = report.json()
    assert payload["verification_ok"] is True
    assert payload["traceability_rate"] == 1.0
    md = Path(payload["report_path"]).read_text(encoding="utf-8")
    assert "校验结果" in md
    assert "产物链：通过" in md
    assert "证据可追溯：通过" in md
    assert "无证据的断言" in md
    for literal in ground_truth["secret_literals"]:
        assert literal in md


def test_p1_mcp_tool_surface(app_client, local_headers, sample_apk):
    """The MCP server answers the whitelist over stdio, and big results spill to artifacts."""
    created = _upload(app_client, local_headers, sample_apk, "p1-mcp")
    project_id = created["project"]["id"]
    _drain_worker()

    env = {
        "PYTHONPATH": str(ROOT / "backend"),
        "APKPLAT_STORAGE": str(ROOT / "tests" / ".tmp" / "storage"),
        "APKPLAT_MCP_PROJECTS": "*",
        "APKPLAT_MCP_ACTOR": "pytest-mcp",
    }
    import os

    full_env = {**os.environ, **env}
    requests = [
        {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {"protocolVersion": "2024-11-05"}},
        {"jsonrpc": "2.0", "id": 2, "method": "tools/list"},
        {"jsonrpc": "2.0", "id": 3, "method": "tools/call", "params": {"name": "apk_get_metadata", "arguments": {"project_id": project_id}}},
        {"jsonrpc": "2.0", "id": 4, "method": "tools/call", "params": {"name": "apk_search_code", "arguments": {"project_id": project_id, "query": "REEF"}}},
        {"jsonrpc": "2.0", "id": 5, "method": "tools/call", "params": {"name": "apk_get_metadata", "arguments": {"project_id": "prj_does_not_exist"}}},
        {"jsonrpc": "2.0", "id": 6, "method": "tools/call", "params": {"name": "apk_search_code", "arguments": {"project_id": project_id}}},
        {"jsonrpc": "2.0", "id": 7, "method": "tools/call", "params": {"name": "shell_exec", "arguments": {"cmd": "whoami"}}},
    ]
    stdin = "".join(json.dumps(r) + "\n" for r in requests)
    proc = subprocess.run(
        [sys.executable, str(MCP_SERVER)],
        input=stdin,
        capture_output=True,
        text=True,
        timeout=300,
        env=full_env,
        cwd=str(ROOT),
    )
    assert proc.returncode == 0, proc.stderr[-2000:]
    responses = [json.loads(line) for line in proc.stdout.splitlines() if line.strip()]
    by_id = {r["id"]: r for r in responses}

    init = by_id[1]["result"]
    assert init["serverInfo"]["name"] == "apkplat-mcp"
    assert init["protocolVersion"] == "2024-11-05"

    tools = {t["name"] for t in by_id[2]["result"]["tools"]}
    assert len(tools) == 16
    assert {"project_create", "apk_get_metadata", "apk_search_code", "evidence_record", "task_update", "report_generate"} <= tools
    assert "shell_exec" not in tools

    def envelope(msg_id: int) -> dict:
        return json.loads(by_id[msg_id]["result"]["content"][0]["text"])

    ok = envelope(3)
    assert ok["ok"] is True
    assert ok["tool"] == "apk_get_metadata"
    assert ok["tool_version"] == "1.0.0"
    assert ok["duration_ms"] >= 0
    assert set(ok) >= {
        "ok",
        "project_id",
        "task_id",
        "tool",
        "tool_version",
        "started_at",
        "duration_ms",
        "stdout_artifact_id",
        "stderr_artifact_id",
        "produced_artifact_ids",
        "error_code",
        "retryable",
    }
    assert ok["result"]["package"] == "com.example.reef"

    search = envelope(4)
    assert search["ok"] and search["result"]["count"] >= 1

    missing = envelope(5)
    assert missing["ok"] is False and missing["error_code"] == "project_not_found"

    invalid = envelope(6)
    assert invalid["ok"] is False and invalid["error_code"] == "schema_invalid"

    unknown = envelope(7)
    assert unknown["ok"] is False and unknown["error_code"] == "unknown_tool"

    # every call is audited with a schema verdict (metric: tool_call_schema_valid_rate)
    from apkplat import audit

    events = [e for e in audit.tail(0, limit=200) if e["event_type"] == "mcp_tool_call"]
    assert len(events) >= 5
    assert any(e["payload"].get("schema_ok") is False for e in events)
