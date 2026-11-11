"""G4 acceptance: analysis cache, ProxyPin/HAR capture correlation, tool surface discipline.

Every check prints the value it observed. The ProxyPin side is reported as NOT_OBSERVED
rather than simulated: the host has no ProxyPin export attached, so claiming live capture
would be a false statement.
"""
from __future__ import annotations

import json
import os
import shutil
import sys
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
STAMP = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
TMP = ROOT / "runtime" / f"p4-g4-{STAMP}"
if TMP.exists():
    shutil.rmtree(TMP, ignore_errors=True)
TMP.mkdir(parents=True, exist_ok=True)

os.environ["APKPLAT_STORAGE"] = str(TMP / "storage")
os.environ["APKPLAT_REPORTS"] = str(TMP / "reports")
os.environ["APKPLAT_REQUIRE_AUTH"] = "0"
os.environ["APKPLAT_MODEL_ENABLED"] = "0"
os.environ["APKPLAT_CAPTURE_DIR"] = ""
os.environ["TEMP"] = str(ROOT / ".tmp")
os.environ["TMP"] = str(ROOT / ".tmp")
sys.path.insert(0, str(ROOT / "backend"))

from fastapi.testclient import TestClient  # noqa: E402

from apkplat import bridge, pipeline_static  # noqa: E402
from apkplat.api.app import create_app  # noqa: E402
from apkplat.config import settings  # noqa: E402
from apkplat.db import db  # noqa: E402
from apkplat.services import artifacts as artifacts_service  # noqa: E402
from apkplat.services import cache as cache_service  # noqa: E402
from apkplat.services import capabilities  # noqa: E402
from apkplat.services import capture as capture_service  # noqa: E402
from apkplat.services import evidence as evidence_service  # noqa: E402
from apkplat.services import projects as projects_service  # noqa: E402
from apkplat.services import roles as roles_service  # noqa: E402
from apkplat.services import tasks as tasks_service  # noqa: E402

CHECKS: list[dict] = []


def check(name: str, ok: bool, detail: str = "") -> bool:
    CHECKS.append({"check": name, "ok": bool(ok), "detail": str(detail)[:400]})
    print(f"[g4] {'PASS' if ok else 'FAIL'}  {name}  {detail}")
    return ok


def call_tool(scope, name: str, args: dict) -> dict:
    """bridge.call raises on refusals; the acceptance script inspects the envelope instead."""
    try:
        return bridge.call(scope, name, args)
    except (bridge.BridgeFault, capabilities.CapabilityError) as exc:
        return {"ok": False, "error_code": exc.code, "message": exc.message, "result": {}}


def audit_types(project_id: str) -> list[str]:
    return [
        row["event_type"]
        for row in db.query("SELECT event_type FROM audit_events WHERE project_id = ? ORDER BY seq", (project_id,))
    ]


def har(entries: list[dict]) -> dict:
    return {"log": {"version": "1.2", "creator": {"name": "g4"}, "entries": entries}}


def har_entry(url: str, *, method: str = "GET", at: str = "2026-11-10T10:00:00.000Z") -> dict:
    return {
        "startedDateTime": at,
        "request": {"method": method, "url": url, "headers": [{"name": "X-Reef-Key", "value": "REEF-API-KEY-7781"}]},
        "response": {"status": 200, "content": {"size": 256, "_at": at}},
    }


def import_project(name: str, apk: Path) -> tuple[str, str]:
    project = projects_service.create(name=name, apk_source=apk, filename=apk.name, actor="g4")
    task = tasks_service.create(project["id"], role="static", title="Static", actor="g4", status="RUNNING")
    return project["id"], task["id"]


def main() -> int:
    db.migrate()
    roles_service.seed()
    pipeline_static.silence_library_logging()
    client = TestClient(create_app())

    health = client.get("/api/health")
    check("platform_api_healthy", health.status_code == 200, f"status={health.status_code}")

    reef_apk = ROOT / "samples" / "sample-app.apk"
    clean_apk = ROOT / "samples" / "sample-clean.apk"

    # ---------------- cache ----------------
    pid, task_id = import_project("g4-reef", reef_apk)
    first = pipeline_static.run(pid, task_id=task_id)
    check(
        "first_analysis_runs_the_tools",
        first["cache_hit"] is False,
        f"apk_sha256={first['apk_sha256'][:12]} duration_ms={first.get('duration_ms')}",
    )
    entry = cache_service.get(first["apk_sha256"])
    check(
        "cache_entry_written",
        entry is not None and entry["hits"] == 0,
        f"entries={(1 if entry else 0)} cache_root={Path(entry['cache_root']).name if entry else '-'}",
    )

    pid2, task2 = import_project("g4-reef-again", reef_apk)
    second = pipeline_static.run(pid2, task_id=task2)
    check("second_import_is_a_cache_hit", second["cache_hit"] is True, f"cache_hit={second['cache_hit']}")
    check(
        "cache_hit_skips_the_tools",
        second.get("duration_ms", 10**9) * 3 < max(first.get("duration_ms", 0), 1),
        f"cold={first.get('duration_ms')}ms warm={second.get('duration_ms')}ms",
    )
    check(
        "cache_hit_keeps_the_evidence_equivalent",
        len(second["evidence_ids"]) == len(first["evidence_ids"]) >= 8,
        f"cold_evidence={len(first['evidence_ids'])} warm_evidence={len(second['evidence_ids'])}",
    )
    verify = evidence_service.verify(pid2)
    check(
        "cache_hit_evidence_still_verifies",
        verify["traceability_rate"] == 1.0 and not verify["failures"],
        f"total={verify['total']} rate={verify['traceability_rate']}",
    )
    events = audit_types(pid2)
    check(
        "cache_hit_is_audited",
        "cache_restored" in events and "cache_stored" not in events,
        f"events={sorted(set(events))}",
    )

    forced = pipeline_static.run(pid, task_id=task_id, force=True)
    check(
        "force_bypasses_the_cache",
        forced["cache_hit"] is False and audit_types(pid).count("cache_stored") >= 2,
        f"cache_hit={forced['cache_hit']} stores={audit_types(pid).count('cache_stored')}",
    )

    settings.cache_max_mb = 0
    try:
        pid3, task3 = import_project("g4-clean", clean_apk)
        limited = pipeline_static.run(pid3, task_id=task3)
    finally:
        settings.cache_max_mb = 2048
    check(
        "size_limit_is_reported_not_silently_ignored",
        "cache_entry_skipped" in audit_types(pid3) and cache_service.get(limited["apk_sha256"]) is None,
        f"skipped={'cache_entry_skipped' in audit_types(pid3)}",
    )

    # ---------------- capture ----------------
    probe = client.get("/api/capture/probe").json()
    check(
        "proxypin_probe_reports_absence",
        probe["available"] is False and "APKPLAT_CAPTURE_DIR" in probe["reason"],
        f"reason={probe['reason']}",
    )

    scope, _token, _path = capabilities.issue(pid2, "exec", task_id=task2, actor="g4")
    before = call_tool(scope, "capture_query", {})
    check(
        "capture_query_tool_says_not_observed",
        before.get("ok") is False and before.get("error_code") == "not_observed",
        f"error_code={before.get('error_code')} state={(before.get('result') or {}).get('state')}",
    )

    endpoints = [
        json.loads(row["locator"]) for row in
        db.query("SELECT locator FROM evidence WHERE project_id = ? AND kind = 'network_endpoint'", (pid2,))
    ]
    urls = []
    for locator in endpoints:
        row = db.one(
            "SELECT claim FROM evidence WHERE project_id = ? AND kind = 'network_endpoint' AND locator = ? LIMIT 1",
            (pid2, json.dumps(locator, separators=(",", ":"))),
        )
        if row:
            urls.append(row["claim"])
    claims = [row["claim"] for row in db.query("SELECT claim FROM evidence WHERE project_id = ? AND kind = 'network_endpoint'", (pid2,))]
    static_urls = []
    for claim in claims:
        for token in claim.split():
            if token.startswith("https://"):
                static_urls.append(token)
    check(
        "static_run_recorded_endpoints",
        len(static_urls) >= 2,
        f"endpoints={static_urls}",
    )

    capture_file = TMP / "session.har"
    capture_file.write_text(
        json.dumps(
            har(
                [
                    har_entry(static_urls[0] + "?probe=1"),
                    har_entry(static_urls[1], method="POST", at="2026-11-10T10:00:02.000Z"),
                    har_entry("https://unrelated.example.test/ping.js"),
                ]
            )
        ),
        encoding="utf-8",
    )
    imported = capture_service.import_source(pid2, path=capture_file, label="g4-session", actor="g4")
    check(
        "har_import_extracts_flows",
        imported["flows_imported"] == 3 and imported["duplicate"] is False,
        f"flows={imported['flows_imported']}",
    )
    duplicate = capture_service.import_source(pid2, path=capture_file, actor="g4")
    check(
        "har_import_is_idempotent",
        duplicate["duplicate"] is True and duplicate["flows_imported"] == 0,
        f"duplicate={duplicate['duplicate']}",
    )

    correlated = capture_service.correlate(pid2)
    check(
        "capture_correlates_with_static_evidence",
        correlated["state"] == "CORRELATED" and correlated["correlated"] >= 2,
        f"state={correlated['state']} correlated={correlated['correlated']}/{correlated['flows']}",
    )
    matched = [item for item in correlated["details"] if item["matched_literal"]]
    check(
        "correlated_flow_points_at_a_real_artifact",
        bool(matched) and all(item["matched_artifact_id"] for item in matched),
        f"matched={[item['matched_literal'] for item in matched]}",
    )

    after = call_tool(scope, "capture_query", {"matched_only": True})
    flows = (after.get("result") or {}).get("flows") or []
    check(
        "model_facing_capture_query_sees_the_capture",
        after.get("ok") is True and (after.get("result") or {}).get("state") == "CORRELATED" and len(flows) >= 2,
        f"state={(after.get('result') or {}).get('state')} flows={len(flows)}",
    )

    pcap = TMP / "session.pcap"
    pcap.write_bytes(b"\xd4\xc3\xb2\xa1not-really")
    try:
        capture_service.import_source(pid2, path=pcap, kind="pcap", actor="g4")
        pcap_refused = False
        pcap_detail = "accepted"
    except capture_service.CaptureError as exc:
        pcap_refused = True
        pcap_detail = exc.code
    check("pcap_is_refused_with_a_reason", pcap_refused, f"error_code={pcap_detail}")

    surface = client.get(f"/api/projects/{pid2}/capture/flows", params={"matched_only": True}).json()
    check(
        "capture_surface_filters_matched_flows",
        len(surface["flows"]) == correlated["correlated"],
        f"flows={len(surface['flows'])} state={surface['state']}",
    )

    # ---------------- discipline ----------------
    catalogue = bridge.tool_catalogue(scope)
    names = sorted(tool["name"] for tool in catalogue)
    check(
        "tool_surface_did_not_expand",
        set(names) <= set(capabilities.ALL_TOOLS) and "shell_exec" not in names and len(names) >= 12,
        f"tools={len(names)} of {len(capabilities.ALL_TOOLS)} names={names}",
    )
    device = call_tool(scope, "device_action", {"action": "tap", "x": 10, "y": 20})
    check(
        "device_action_still_gated",
        device.get("ok") is False and device.get("error_code") in {"lease_required", "capability_unavailable"},
        f"error_code={device.get('error_code')}",
    )
    requirements = (ROOT / "requirements.txt").read_text(encoding="utf-8").lower()
    check(
        "no_new_python_dependencies",
        "pillow" not in requirements,
        f"requirements_lines={len(requirements.strip().splitlines())}",
    )

    passed = sum(1 for item in CHECKS if item["ok"])
    total = len(CHECKS)
    report_dir = ROOT / "reports" / "gate4-v3"
    report_dir.mkdir(parents=True, exist_ok=True)
    stamp = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%SZ")
    payload = {
        "gate": "G4",
        "generated_at": stamp,
        "passed": passed,
        "total": total,
        "checks": CHECKS,
        "facts": {
            "cache_cold_ms": first.get("duration_ms"),
            "cache_warm_ms": second.get("duration_ms"),
            "evidence_rows": len(first["evidence_ids"]),
            "apk_sha256": first["apk_sha256"],
            "capture_state": correlated["state"],
            "capture_flows": correlated["flows"],
            "capture_correlated": correlated["correlated"],
            "static_endpoints": static_urls,
        },
    }
    (report_dir / "acceptance.json").write_text(json.dumps(payload, indent=2), encoding="utf-8")

    lines = [
        "# Gate G4 acceptance - analysis cache and capture correlation",
        "",
        f"- Generated: {stamp}",
        f"- Result: **{passed}/{total} checks passed**",
        f"- Storage: `{TMP}`",
        "",
        "| # | Check | Result | Observed |",
        "|---|-------|--------|----------|",
    ]
    for index, item in enumerate(CHECKS, start=1):
        detail = item["detail"].replace("|", "\\|")
        lines.append(f"| {index} | `{item['check']}` | {'PASS' if item['ok'] else 'FAIL'} | {detail} |")
    lines += [
        "",
        "## Facts",
        "",
        f"- Cold analysis: {first.get('duration_ms')} ms; warm (cache hit): {second.get('duration_ms')} ms",
        f"- Evidence rows reproduced from cache: {len(second['evidence_ids'])} (traceability {verify['traceability_rate']})",
        f"- Static endpoints: {', '.join(static_urls)}",
        f"- Capture correlation: {correlated['correlated']}/{correlated['flows']} flows "
        f"matched to artifacts backed by evidence",
        "- ProxyPin: NOT_OBSERVED. The host has no ProxyPin export and `APKPLAT_CAPTURE_DIR` is empty, so the "
        "capture path is exercised with an offline HAR export and every claim about it names that file.",
        "",
        "## Reproduce",
        "",
        "```",
        ".venv/Scripts/python.exe scripts/p4_g4_accept.py",
        "```",
        "",
    ]
    (report_dir / "acceptance.md").write_text("\n".join(lines), encoding="utf-8")

    print(f"[g4] {passed}/{total} checks passed -> reports/gate4-v3/acceptance.md")
    return 0 if passed == total else 1


if __name__ == "__main__":
    raise SystemExit(main())
