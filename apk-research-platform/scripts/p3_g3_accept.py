"""G3 acceptance: typed/binary evidence, the cooperative sandbox, independent re-runs, report.

Every check prints the concrete value it observed, so the report can be audited without
re-running anything. Nothing here claims a capability the host does not have: container
isolation is reported as unavailable rather than pretended.
"""
from __future__ import annotations

import json
import os
import shutil
import sys
import time
import zlib
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
STAMP = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
TMP = ROOT / "runtime" / f"p3-g3-{STAMP}"
if TMP.exists():
    shutil.rmtree(TMP, ignore_errors=True)
TMP.mkdir(parents=True, exist_ok=True)

os.environ["APKPLAT_STORAGE"] = str(TMP / "storage")
os.environ["APKPLAT_REPORTS"] = str(TMP / "reports")
os.environ["APKPLAT_REQUIRE_AUTH"] = "0"
os.environ["APKPLAT_MODEL_ENABLED"] = "0"
os.environ["TEMP"] = str(ROOT / ".tmp")
os.environ["TMP"] = str(ROOT / ".tmp")
sys.path.insert(0, str(ROOT / "backend"))

from fastapi.testclient import TestClient  # noqa: E402

from apkplat import pipeline_static, reports  # noqa: E402
from apkplat.api.app import create_app  # noqa: E402
from apkplat.config import settings  # noqa: E402
from apkplat.db import db  # noqa: E402
from apkplat.services import artifacts as artifacts_service  # noqa: E402
from apkplat.services import capabilities  # noqa: E402
from apkplat.services import evidence_types as et  # noqa: E402
from apkplat.services import projects as projects_service  # noqa: E402
from apkplat.services import roles as roles_service  # noqa: E402
from apkplat.services import sandbox as sandbox_service  # noqa: E402
from apkplat.services import tasks as tasks_service  # noqa: E402
from apkplat.util import project_layout  # noqa: E402

CHECKS: list[dict] = []


def check(name: str, ok: bool, detail: str = "") -> bool:
    CHECKS.append({"check": name, "ok": bool(ok), "detail": str(detail)[:400]})
    print(f"[g3] {'PASS' if ok else 'FAIL'}  {name}  {detail}")
    return ok


def png(width: int, height: int) -> bytes:
    def chunk(kind: bytes, payload: bytes) -> bytes:
        import struct

        return struct.pack(">I", len(payload)) + kind + payload + struct.pack(">I", zlib.crc32(kind + payload) & 0xFFFFFFFF)

    ihdr = (
        width.to_bytes(4, "big")
        + height.to_bytes(4, "big")
        + bytes([8, 2, 0, 0, 0])
    )
    raw = b"".join(b"\x00" + b"\x10\x20\x30" * width for _ in range(height))
    return b"\x89PNG\r\n\x1a\n" + chunk(b"IHDR", ihdr) + chunk(b"IDAT", zlib.compress(raw)) + chunk(b"IEND", b"")


def main() -> int:
    db.migrate()
    roles_service.seed()
    pipeline_static.silence_library_logging()
    client = TestClient(create_app())

    health = client.get("/api/health")
    check("platform_api_healthy", health.status_code == 200 and health.json().get("ok") is not False, f"status={health.status_code}")

    apk = ROOT / "samples" / "sample-app.apk"
    project = projects_service.create(name="g3-reef", apk_source=apk, filename=apk.name, actor="g3")
    pid = project["id"]
    task = tasks_service.create(pid, role="exec", title="Exec", actor="g3", status="RUNNING")
    pipeline_static.run(pid, task_id=task["id"])
    kinds = {row["kind"]: row for row in artifacts_service.list_artifacts(pid, limit=200)}
    check(
        "project_ingested_and_indexed",
        {"metadata", "findings", "index"} <= set(kinds),
        f"kinds={sorted(kinds)}",
    )
    metadata_id = kinds["metadata"]["id"]

    # -- typed evidence -----------------------------------------------------
    text_path = Path(project_layout(pid)["artifacts"]) / "note.txt"
    text_path.write_text("REEF-API-KEY-7781 appears verbatim\nsecond line\n", encoding="utf-8")
    text_art = artifacts_service.register(pid, kind="notes", path=text_path, tool="g3", tool_version="1.0.0")

    misquote = et.record(
        pid,
        evidence_type=et.TEXT_EXCERPT,
        locator={"excerpt": "REEF-API-KEY-9999 appears verbatim"},
        artifact_id=text_art["id"],
        claim="a literal that is not in the file",
    )
    check(
        "text_misquote_still_fails",
        misquote["verdict"] == "FAILED" and misquote["failure_reason"] == "excerpt_not_found_in_artifact",
        f"verdict={misquote['verdict']} reason={misquote['failure_reason']}",
    )
    verbatim = et.record(
        pid,
        evidence_type=et.TEXT_EXCERPT,
        locator={"excerpt": "REEF-API-KEY-7781 appears verbatim"},
        artifact_id=text_art["id"],
        claim="literal present",
    )
    check("text_verbatim_verifies", verbatim["verdict"] == "VERIFIED", f"verdict={verbatim['verdict']}")

    json_ok = et.record(
        pid, evidence_type=et.JSON_FIELD, locator={"pointer": "/package"}, expected="com.example.reef",
        artifact_id=metadata_id, claim="package name",
    )
    json_bad = et.record(
        pid, evidence_type=et.JSON_FIELD, locator={"pointer": "/package"}, expected="com.example.nope",
        artifact_id=metadata_id, claim="package name",
    )
    check("json_field_verified", json_ok["verdict"] == "VERIFIED", f"verdict={json_ok['verdict']}")
    check("json_mismatch_failed", json_bad["verdict"] == "FAILED" and json_bad["failure_reason"] == "expected_value_mismatch",
          f"verdict={json_bad['verdict']} reason={json_bad['failure_reason']}")

    shot = Path(project_layout(pid)["artifacts"]) / "screen.png"
    shot.write_bytes(png(48, 32))
    shot_art = artifacts_service.register(pid, kind="capture", path=shot, tool="g3", tool_version="1.0.0")
    image = et.record(
        pid, evidence_type=et.IMAGE, locator={"width": 48, "height": 32, "device_serial": "e74398f9", "step": "observe"},
        artifact_id=shot_art["id"], claim="screenshot of the launch screen",
    )
    check("image_bytes_verified_semantics_partial", image["verdict"] == "PARTIAL" and image["integrity_verified"] == 1,
          f"verdict={image['verdict']} integrity={image['integrity_verified']}")
    image_bad = et.record(
        pid, evidence_type=et.IMAGE, locator={"width": 1080, "height": 32, "step": "observe"},
        artifact_id=shot_art["id"], claim="screenshot at phone resolution",
    )
    check("image_dimension_mismatch_failed", image_bad["verdict"] == "FAILED" and image_bad["failure_reason"].startswith("dimensions_mismatch"),
          f"reason={image_bad['failure_reason']}")

    video_no_step = et.record(
        pid, evidence_type=et.VIDEO, locator={"duration_ms": 4200}, artifact_id=shot_art["id"], claim="recording"
    )
    check("video_requires_step_association", video_no_step["verdict"] == "FAILED" and video_no_step["failure_reason"] == "step_association_missing",
          f"reason={video_no_step['failure_reason']}")

    flow_no_window = et.record(
        pid, evidence_type=et.CAPTURE_FLOW, locator={"history_id": "h-1"}, artifact_id=text_art["id"], claim="capture flow"
    )
    check("capture_flow_requires_reference_and_window",
          flow_no_window["verdict"] == "FAILED" and flow_no_window["failure_reason"] == "time_window_missing",
          f"reason={flow_no_window['failure_reason']}")

    pcap = et.record(
        pid,
        evidence_type=et.PCAP,
        locator={"capture_scope": "192.168.43.1:8788", "started_at": "2026-11-10T10:00:00Z", "ended_at": "2026-11-10T10:05:00Z"},
        artifact_id=text_art["id"],
        claim="decrypted HTTPS body shows the licence call",
    )
    check("pcap_decryption_claim_requires_evidence",
          pcap["verdict"] == "FAILED" and pcap["failure_reason"] == "decryption_evidence_required",
          f"reason={pcap['failure_reason']}")

    device = et.record(
        pid, evidence_type=et.DEVICE_OBSERVATION,
        locator={"device_serial": "e74398f9", "package": "com.example.reef"},
        artifact_id=text_art["id"], claim="package observed on device",
    )
    check("device_observation_checks_package",
          device["verdict"] == "FAILED" and device["failure_reason"] == "package_not_in_observation",
          f"reason={device['failure_reason']}")

    # -- sandbox ------------------------------------------------------------
    script = Path(project_layout(pid)["artifacts"]) / "probe.py"
    script.write_text(
        "import sys\nprint('argv', sys.argv[1:])\nprint('sum', sum(range(100)))\nprint('EXIT_CODE=0')\n", encoding="utf-8"
    )
    script_art = artifacts_service.register(pid, kind="script", path=script, tool="g3", tool_version="1.0.0")
    run1 = sandbox_service.run_script(pid, script_artifact_id=script_art["id"], argv=["alpha"], task_id=task["id"], run_id="run_g3_primary", actor="g3")
    stdout1 = artifacts_service.read_text(run1["stdout_artifact_id"], limit=2000)["text"]
    check("sandbox_runs_a_pure_script", run1["status"] == "SUCCEEDED" and "argv ['alpha']" in stdout1 and "sum 4950" in stdout1,
          f"status={run1['status']} exit={run1['exit_code']} duration={run1['duration_ms']}ms")

    banned = Path(project_layout(pid)["artifacts"]) / "banned.py"
    banned.write_text("import subprocess\nsubprocess.run(['whoami'])\n", encoding="utf-8")
    banned_art = artifacts_service.register(pid, kind="script", path=banned, tool="g3", tool_version="1.0.0")
    try:
        sandbox_service.run_script(pid, script_artifact_id=banned_art["id"], actor="g3")
        refused_code = "not-refused"
    except sandbox_service.SandboxError as exc:
        refused_code = exc.code
    refused_rows = db.scalar("SELECT COUNT(*) FROM sandbox_runs WHERE project_id = ? AND status = 'REFUSED'", (pid,))
    check("sandbox_refuses_banned_imports", refused_code == "static_check_failed" and refused_rows >= 1,
          f"code={refused_code} refused_rows={refused_rows}")

    net = Path(project_layout(pid)["artifacts"]) / "net.py"
    net.write_text(
        "import importlib\nmod = importlib.import_module('so' + 'cket')\n"
        "try:\n    mod.socket()\n    print('network available')\nexcept Exception as exc:\n    print('blocked', type(exc).__name__)\n",
        encoding="utf-8",
    )
    net_art = artifacts_service.register(pid, kind="script", path=net, tool="g3", tool_version="1.0.0")
    run_net = sandbox_service.run_script(pid, script_artifact_id=net_art["id"], actor="g3")
    net_out = artifacts_service.read_text(run_net["stdout_artifact_id"], limit=1000)["text"]
    check("sandbox_blocks_network_without_permission", "blocked" in net_out and "network available" not in net_out,
          f"stdout={net_out.strip()[:120]}")

    escape = Path(project_layout(pid)["artifacts"]) / "escape.py"
    escape.write_text(
        "try:\n    open('../../escape_probe.txt', 'w').write('escaped')\n    print('write allowed')\n"
        "except PermissionError as exc:\n    print('blocked', exc)\n",
        encoding="utf-8",
    )
    escape_art = artifacts_service.register(pid, kind="script", path=escape, tool="g3", tool_version="1.0.0")
    run_escape = sandbox_service.run_script(pid, script_artifact_id=escape_art["id"], actor="g3")
    escape_out = artifacts_service.read_text(run_escape["stdout_artifact_id"], limit=1000)["text"]
    escaped_file = Path(project_layout(pid)["base"]) / "escape_probe.txt"
    check("sandbox_blocks_path_escape", "blocked" in escape_out and not escaped_file.exists(),
          f"stdout={escape_out.strip()[:100]} file_exists={escaped_file.exists()}")

    sleeper = Path(project_layout(pid)["artifacts"]) / "sleeper.py"
    sleeper.write_text(
        "import time\nfor i in range(200):\n    open('heartbeat.txt', 'w').write(str(i))\n    time.sleep(0.1)\n", encoding="utf-8"
    )
    sleeper_art = artifacts_service.register(pid, kind="script", path=sleeper, tool="g3", tool_version="1.0.0")
    run_slow = sandbox_service.run_script(pid, script_artifact_id=sleeper_art["id"], timeout=2, actor="g3")
    beat = next(Path(project_layout(pid)["base"]).glob("sandbox/*/heartbeat.txt"), None)
    first = beat.read_text() if beat else ""
    time.sleep(1.5)
    second = beat.read_text() if beat else ""
    check("sandbox_timeout_kills_process_tree",
          run_slow["status"] == "TIMEOUT" and run_slow["timed_out"] == 1 and beat is not None and first == second,
          f"status={run_slow['status']} heartbeat_frozen={first == second} last_beat={first}")

    try:
        sandbox_service.run_script(pid, script_artifact_id=script_art["id"], isolation="container", actor="g3")
        container_code = "not-refused"
    except sandbox_service.SandboxError as exc:
        container_code = exc.code
    check("sandbox_container_isolation_unavailable", container_code == "strong_isolation_unavailable", f"code={container_code}")

    # -- independent review run reproduces the script ------------------------
    scope, token, _ = capabilities.issue(pid, "review", task_id=task["id"], actor="g3-reviewer")
    tasks_service.record_run(task["id"], role="review", dsh_session_ref=scope.run_id, notes="g3 independent reviewer")
    replay = sandbox_service.replay(pid, run1["id"], actor="g3-reviewer", run_ref=scope.run_id)
    same_code = replay["script_sha256"] == run1["script_sha256"] and replay["status"] == run1["status"]
    result_ev = et.record(
        pid,
        evidence_type=et.TEST_RESULT,
        locator={"expected_exit_code": 0, "command_template": "python -I -B _apkplat_runner.py script.py", "step": "test_run"},
        artifact_id=run1["result_artifact_id"],
        claim="probe script exits 0",
        run_id=scope.run_id,
        provenance={"run_id": scope.run_id, "tool": "test_run", "step": "test_run"},
        source_tool="test_run",
    )
    reproduced = et.mark_reproduced(result_ev["id"], by_run=replay["id"], note="independent review run")
    check(
        "independent_review_run_reproduces_script",
        replay["replay_of"] == run1["id"] and same_code and reproduced["reproduced"] == 1,
        f"replay_of={replay['replay_of']} same_script={same_code} script_sha256={replay['script_sha256'][:12]}",
    )
    capabilities.revoke(scope.run_id, reason="g3 complete", actor="g3")

    verify = et.verify_all(pid)
    check("typed_evidence_chain_verifies", verify["failures"] == [] and verify["total"] >= 8,
          f"total={verify['total']} failures={len(verify['failures'])} levels={verify['levels']}")

    # -- report -------------------------------------------------------------
    report = reports.generate(pid, task_id=task["id"])
    text = Path(report["report_path"]).read_text(encoding="utf-8")
    required = [
        "## 11. 摘要",
        "## 12. 能力覆盖矩阵",
        "## 13. 任务依赖图",
        "## 14. 关键时间线",
        "## 15. 类型化证据链",
        "## 16. 媒体与抓包会话",
        "## 17. 电脑端与真机结果",
        "## 18. 无法核验的条目",
        "## 19. 审查意见",
        "## 20. 脚本与构建产物",
    ]
    missing = [item for item in required if item not in text]
    check("report_has_all_sections", not missing, f"missing={missing}")

    image_link = f"/api/projects/{pid}/artifacts/{shot_art['id']}/download"
    check("report_links_original_image", image_link in text, f"link={'present' if image_link in text else 'absent'}")

    html = client.get(f"/api/projects/{pid}/report.html")
    check("report_html_renders", html.status_code == 200 and "<table>" in html.text and "摘要" in html.text,
          f"status={html.status_code} bytes={len(html.text)}")

    # -- isolation ----------------------------------------------------------
    other = projects_service.create(name="g3-other", apk_source=ROOT / "samples" / "sample-clean.apk",
                                    filename="sample-clean.apk", actor="g3")
    admin = {"X-Admin-Secret": settings.signing_secret().hex()}
    token_resp = client.post(
        "/api/auth/token", json={"projects": [other["id"]], "subject": "g3-other", "scopes": ["read"]}, headers=admin
    )
    previous = settings.require_auth
    settings.require_auth = True
    try:
        headers = {"Authorization": f"Bearer {token_resp.json()['token']}"}
        denied = client.get(f"/api/evidence/typed/{image['id']}", headers=headers)
        denied_project = client.get(f"/api/projects/{pid}/evidence/typed", headers=headers)
    finally:
        settings.require_auth = previous
    check(
        "cross_project_evidence_denied",
        denied.status_code == 403 and denied_project.status_code == 403,
        f"by_id={denied.status_code} by_project={denied_project.status_code}",
    )

    write_report()
    passed = sum(1 for item in CHECKS if item["ok"])
    print(f"[g3] {passed}/{len(CHECKS)} checks passed")
    return 0 if passed == len(CHECKS) else 1


def write_report() -> None:
    out_dir = ROOT / "audit"
    out_dir.mkdir(parents=True, exist_ok=True)
    passed = sum(1 for item in CHECKS if item["ok"])
    lines = [
        "# G3 acceptance 鈥?typed evidence, sandbox, independent re-run, report",
        "",
        f"- generated_at: {datetime.now(timezone.utc).isoformat(timespec='seconds').replace('+00:00', 'Z')}",
        f"- checks: **{passed}/{len(CHECKS)} passed**",
        f"- storage: `{TMP}`",
        "",
        "| # | check | result | detail |",
        "|---|---|---|---|",
    ]
    for index, item in enumerate(CHECKS, start=1):
        lines.append(f"| {index} | `{item['check']}` | {'PASS' if item['ok'] else 'FAIL'} | {item['detail']} |")
    lines += [
        "",
        "## Notes",
        "",
        "- The sandbox on this host is *cooperative*: static screen, scrubbed environment, write guard,",
        "  wall-clock timeout and capped output. Container isolation is reported as unavailable (409)",
        "  rather than silently degraded.",
        "- Image evidence can only prove its own bytes and dimensions; the verdict stops at PARTIAL and",
        "  the report says so. A pcap that claims a decrypted body without naming the decryption artefact",
        "  is refused.",
        "- Reproduction requires a *different* run: the review run id is issued by the platform and the",
        "  replay is linked through `replay_of`.",
    ]
    (out_dir / "g3_acceptance.md").write_text("\n".join(lines) + "\n", encoding="utf-8")
    (out_dir / "g3_acceptance.json").write_text(
        json.dumps(
            {
                "generated_at": datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z"),
                "storage": str(TMP),
                "passed": passed,
                "total": len(CHECKS),
                "checks": CHECKS,
            },
            indent=2,
        ),
        encoding="utf-8",
    )


if __name__ == "__main__":
    raise SystemExit(main())
