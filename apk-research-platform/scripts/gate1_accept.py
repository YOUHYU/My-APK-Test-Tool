"""Gate 1 acceptance: one APK, one closed loop, zero manual steps.

The promise of P1 is narrow and checkable: a single APK goes in through the API, the
restricted static tools run, the code index is built, an MCP client can query it, every
claim points at an artifact, and a Markdown report comes out - without a human typing a
jadx or apktool command.

Outputs: reports/gate1/acceptance.md and reports/gate1/acceptance.json
"""
from __future__ import annotations

import json
import re
import os
import subprocess
import sys
import tempfile
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "backend"))

WORK = Path(tempfile.mkdtemp(prefix="apkplat-gate1-"))
os.environ["APKPLAT_STORAGE"] = str(WORK / "storage")
os.environ["APKPLAT_REPORTS"] = str(WORK / "reports")
os.environ["APKPLAT_SECRET"] = "gate1-acceptance-secret-not-for-production"
os.environ["APKPLAT_REQUIRE_AUTH"] = "0"
os.environ["APKPLAT_MODEL_ENABLED"] = "0"

from fastapi.testclient import TestClient  # noqa: E402

from apkplat import toolchain, worker  # noqa: E402
from apkplat import db as dbmod  # noqa: E402
from apkplat.api.app import create_app  # noqa: E402
from apkplat.services import artifacts as artifacts_service  # noqa: E402
from apkplat.pipeline_static import silence_library_logging  # noqa: E402
from apkplat.services import evidence as evidence_service  # noqa: E402

OUT = ROOT / "reports" / "gate1"
OUT.mkdir(parents=True, exist_ok=True)
checks: list[dict] = []


def _now_iso() -> str:
    from datetime import datetime, timezone

    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def check(name: str, ok: bool, detail: str = "") -> bool:
    checks.append({"check": name, "ok": bool(ok), "detail": str(detail)[:240]})
    print(f"[gate1] {'PASS' if ok else 'FAIL'}  {name}" + (f"  {detail}" if detail else ""), flush=True)
    return bool(ok)


def mcp_call(process, request_id: int, method: str, params: dict | None = None) -> dict:
    payload = {"jsonrpc": "2.0", "id": request_id, "method": method}
    if params is not None:
        payload["params"] = params
    process.stdin.write(json.dumps(payload) + "\n")
    process.stdin.flush()
    return json.loads(process.stdout.readline())


def main() -> int:
    silence_library_logging()
    dbmod.db.migrate()
    client = TestClient(create_app())
    ground_truth = json.loads((ROOT / "samples" / "ground_truth.json").read_text(encoding="utf-8"))

    versions = toolchain.probe_versions()
    tools_ok = all(item.get("ok") for item in versions.values())
    check("restricted toolchain answers", tools_ok,
          ", ".join(f"{name} {item.get('version', '?')}" for name, item in versions.items()))

    started = time.time()
    with open(ROOT / "samples" / "sample-app.apk", "rb") as handle:
        response = client.post(
            "/api/projects",
            data={"name": "gate1-sample", "goal": "P1 closed loop"},
            files={"apk": ("sample-app.apk", handle, "application/vnd.android.package-archive")},
        )
    check("upload accepted", response.status_code == 201, str(response.status_code))
    project_id = response.json()["project"]["id"]
    job_id = response.json()["job_id"]

    worker.Worker("gate1-worker", ["static_pipeline"], poll_interval=0.05).run(max_jobs=1, idle_timeout=60)
    elapsed = round(time.time() - started, 1)

    job = client.get("/api/queue", params={"project_id": project_id}).json()["jobs"][0]
    check("static pipeline job succeeded", job["status"] == "SUCCEEDED", f"{job['status']} in {elapsed}s")

    detail = client.get(f"/api/projects/{project_id}").json()
    manifest = detail["manifest"]
    check("sha256 of the stored APK matches the source", manifest["ingest"]["sha256"] == ground_truth["apk_sha256"],
          manifest["ingest"]["sha256"][:16])

    facts = json.loads(
        artifacts_service.path_of(
            artifacts_service.get(
                [row for row in artifacts_service.list_artifacts(project_id) if row["kind"] == "metadata"][0]["id"]
            )
        ).read_text(encoding="utf-8")
    )
    check("package name recovered", facts["package"] == ground_truth["package"], facts["package"])
    check("version recovered", facts["version_name"] == ground_truth["version_name"]
          and str(facts["version_code"]) == str(ground_truth["version_code"]),
          f"{facts['version_name']} ({facts['version_code']})")
    check("signing certificate matches", (facts.get("certificate_sha256") or "").lower()
          == ground_truth["certificate_sha256"].lower(), str(facts.get("certificate_sha256"))[:16])
    check("signature schemes agree with androguard", facts.get("signing", {}).get("agrees_with_androguard") is True,
          ",".join(facts.get("signing", {}).get("schemes", [])))

    summary_row = [row for row in artifacts_service.list_artifacts(project_id) if row["kind"] == "summary"][0]
    summary = json.loads(artifacts_service.path_of(artifacts_service.get(summary_row["id"])).read_text(encoding="utf-8"))
    units = int(summary["index"].get("units", "0"))
    check("decompiled sources are indexed", units >= 20, json.dumps(summary["index"]))

    kinds = {row["kind"] for row in artifacts_service.list_artifacts(project_id)}
    check("every pipeline stage left an artifact",
          {"validation", "metadata", "findings", "index", "summary"} <= kinds, ",".join(sorted(kinds)))

    rows = evidence_service.list_evidence(project_id)
    verification = evidence_service.verify(project_id)
    check("evidence rows exist", len(rows) >= 8, f"{len(rows)} rows")
    check("every claim traces to an artifact", verification["failures"] == [] and verification["traceability_rate"] >= 1.0,
          f"rate {verification['traceability_rate']}")
    # the claim text is localized, so read the literal from the locator (and fall back to a token scan)
    found = set()
    for row in rows:
        if row["kind"] != "secret_candidate":
            continue
        try:
            locator = json.loads(row["locator"]) if isinstance(row["locator"], str) else row["locator"]
        except ValueError:
            locator = {}
        literal = (locator or {}).get("literal")
        if literal:
            found.add(literal)
        else:
            found.update(re.findall(r"[A-Z][A-Z0-9]+(?:-[A-Z0-9]+)+", row["claim"] or ""))
    check("the planted secrets are found", set(ground_truth["secret_literals"]) <= found,
          ",".join(sorted(set(ground_truth["secret_literals"]) - found)) or "all four")

    search = client.get(f"/api/projects/{project_id}/search", params={"q": "validateLicense"}).json()
    check("code search answers", len(search["results"]) >= 1, f"{len(search['results'])} hit(s)")
    method = client.get(f"/api/projects/{project_id}/search", params={"q": "sha256Hex", "kind": "method"}).json()
    members = [row["member"] for row in method["results"]]
    check("method lookup answers", bool(method["results"]), ",".join(members[:4]))

    report = client.post(f"/api/projects/{project_id}/report", json={"actor": "gate1"})
    check("report generated", report.status_code == 201, str(report.status_code))
    report_row = report.json()
    text = artifacts_service.path_of(artifacts_service.get(report_row["artifact_id"])).read_text(encoding="utf-8")
    check("report passes its own verification", report_row["verification_ok"] is True, str(report_row["verification_ok"]))
    check("report names the package and the secrets",
          ground_truth["package"] in text and all(item in text for item in ground_truth["secret_literals"]),
          f"{len(text)} chars")

    # -- the same loop through MCP, the way an agent sees it ---------------
    env = {**os.environ, "APKPLAT_MCP_PROJECTS": project_id, "APKPLAT_MCP_ACTOR": "gate1-mcp",
           "PYTHONPATH": str(ROOT / "backend")}
    requests = [
        {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {"protocolVersion": "2024-11-05"}},
        {"jsonrpc": "2.0", "id": 2, "method": "tools/list"},
        {"jsonrpc": "2.0", "id": 3, "method": "tools/call",
         "params": {"name": "apk_get_metadata", "arguments": {"project_id": project_id}}},
        {"jsonrpc": "2.0", "id": 4, "method": "tools/call",
         "params": {"name": "apk_search_code", "arguments": {"project_id": project_id, "query": "validateLicense"}}},
        {"jsonrpc": "2.0", "id": 5, "method": "tools/call",
         "params": {"name": "evidence_read", "arguments": {"project_id": project_id, "limit": 50}}},
    ]
    completed = subprocess.run(
        [sys.executable, str(ROOT / "mcp-server" / "mcp_server" / "server.py")],
        input="".join(json.dumps(item) + "\n" for item in requests),
        capture_output=True, encoding="utf-8", errors="replace",
        text=True,
        timeout=300,
        env=env,
        cwd=str(ROOT),
    )
    if completed.returncode != 0:
        check("MCP server exits cleanly", False, completed.stderr.strip().splitlines()[-1][:200])
    answers = {item["id"]: item for item in
               (json.loads(line) for line in completed.stdout.splitlines() if line.strip())}

    def envelope(msg_id: int) -> dict:
        return json.loads(answers[msg_id]["result"]["content"][0]["text"])

    init = answers[1]["result"]
    names = [item["name"] for item in answers[2]["result"]["tools"]]
    check("MCP server initialises", init["serverInfo"]["name"] == "apkplat-mcp", init["protocolVersion"])
    check("MCP exposes the whitelisted surface", len(names) == 16 and "shell_exec" not in names, f"{len(names)} tools")
    meta_env = envelope(3)
    check("MCP tool returns the standard envelope",
          {"ok", "project_id", "tool", "tool_version", "duration_ms", "request_id"} <= set(meta_env),
          f"tool_version {meta_env['tool_version']}")
    meta_body = meta_env.get("result", {})
    check("MCP metadata agrees with the pipeline", meta_body.get("package") == ground_truth["package"],
          str(meta_body.get("package")))
    hits_env = envelope(4)
    hits_body = hits_env.get("result", {})
    check("MCP search returns hits", hits_env["ok"] is True and len(hits_body.get("results", [])) >= 1,
          f"{len(hits_body.get('results', []))} hit(s)")
    evidence_env = envelope(5)
    ledger = evidence_env.get("result", {})
    check("MCP reads the evidence ledger", evidence_env["ok"] is True and ledger.get("count") == len(rows),
          f"{ledger.get('count')} of {len(rows)} rows")

    duration = round(time.time() - started, 1)
    failed = [item for item in checks if not item["ok"]]
    write_report({"work_dir": str(WORK), "duration_seconds": duration, "project_id": project_id,
                  "evidence_rows": len(rows), "elapsed_pipeline": elapsed})
    print(f"[gate1] {len(checks) - len(failed)}/{len(checks)} checks passed", flush=True)
    return 0 if not failed else 1


def write_report(data: dict) -> None:
    failed = [item for item in checks if not item["ok"]]
    lines = [
        "# Gate 1 acceptance - single APK static loop",
        "",
        f"- Run at: {time.strftime('%Y-%m-%d %H:%M:%S')}",
        f"- Duration: {data['duration_seconds']}s (pipeline {data['elapsed_pipeline']}s)",
        "- The DSH NEXT install and the model API were provided by the operator and were not modified by this run.",
        "- No jadx/apktool command was typed by hand: the pipeline invoked them inside its sandboxed toolchain.",
        f"- Result: **{'PASS' if not failed else 'FAIL'}** - {len(checks) - len(failed)}/{len(checks)} checks",
        "",
        "## Checks",
        "",
        "| check | result | detail |",
        "| --- | --- | --- |",
    ]
    for item in checks:
        lines.append(f"| {item['check']} | {'PASS' if item['ok'] else 'FAIL'} | {item['detail'].replace('|', chr(92) + '|')} |")
    lines += [
        "",
        "## Facts",
        "",
        f"- Project: `{data['project_id']}`",
        f"- Evidence rows: {data['evidence_rows']}",
        f"- Work directory: `{data['work_dir']}`",
    ]
    (OUT / "acceptance.md").write_text("\n".join(lines) + "\n", encoding="utf-8")
    (OUT / "acceptance.json").write_text(json.dumps({"generated_at": _now_iso(), "checks": checks, "facts": data}, indent=2, default=str),
                                         encoding="utf-8")
    print(f"[gate1] report: {OUT / 'acceptance.md'}", flush=True)


if __name__ == "__main__":
    raise SystemExit(main())
