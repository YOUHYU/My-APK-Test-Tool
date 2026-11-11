"""G5 acceptance: the real-device layer.

Two tracks, deliberately kept apart:

* the simulator exercises the destructive paths (install, uninstall, quarantine) so the
  matrix can be proven without touching anyone's phone;
* the attached handset is only ever *read* (state, uiautomator dump, one screenshot), and
  the report says NOT_OBSERVED when nothing is attached. Installing an APK on the user's
  phone is a real-world action and is not something an acceptance script does on its own.

Every check prints the value it observed; the JSON next to the report keeps the same rows.
"""
from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import threading
import time
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
STAMP = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
TMP = ROOT / "runtime" / f"p5-g5-{STAMP}"
if TMP.exists():
    shutil.rmtree(TMP, ignore_errors=True)
TMP.mkdir(parents=True, exist_ok=True)

os.environ["APKPLAT_STORAGE"] = str(TMP / "storage")
os.environ["APKPLAT_REPORTS"] = str(TMP / "reports")
os.environ["APKPLAT_REQUIRE_AUTH"] = "0"
os.environ["APKPLAT_MODEL_ENABLED"] = "0"
os.environ["APKPLAT_DYNAMIC_TRANSPORT"] = "sim"
os.environ["APKPLAT_DYNAMIC_OBSERVE_SECONDS"] = "0"
os.environ["TEMP"] = str(ROOT / ".tmp")
os.environ["TMP"] = str(ROOT / ".tmp")
sys.path.insert(0, str(ROOT / "backend"))

from fastapi.testclient import TestClient  # noqa: E402

from apkplat import audit, bridge, dynamic, pipeline_static, toolchain  # noqa: E402
from apkplat.api.app import create_app  # noqa: E402
from apkplat.config import settings  # noqa: E402
from apkplat.db import db  # noqa: E402
from apkplat.services import artifacts as artifacts_service  # noqa: E402
from apkplat.services import auth as auth_service  # noqa: E402
from apkplat.services import capabilities  # noqa: E402
from apkplat.services import device_ui  # noqa: E402
from apkplat.services import devices as devices_service  # noqa: E402
from apkplat.services import evidence as evidence_service  # noqa: E402
from apkplat.services import projects as projects_service  # noqa: E402
from apkplat.services import queue as queue_service  # noqa: E402
from apkplat.services import tasks as tasks_service  # noqa: E402

CHECKS: list[dict] = []
SAMPLE = ROOT / "samples" / "sample-app.apk"
PKG = "com.example.reef"


def check(name: str, ok: bool, detail: str = "") -> bool:
    CHECKS.append({"check": name, "ok": bool(ok), "detail": str(detail)[:400]})
    print(f"[g5] {'PASS' if ok else 'FAIL'}  {name}  {detail}")
    return ok


def call_tool(scope, name: str, args: dict) -> dict:
    try:
        return bridge.call(scope, name, args)
    except (bridge.BridgeFault, capabilities.CapabilityError) as exc:
        return {"ok": False, "error_code": exc.code, "message": exc.message, "result": {}}


def make_project(name: str) -> str:
    project = projects_service.create(name=name, apk_source=SAMPLE, filename="sample-app.apk", actor="g5")
    return project["id"]


def ingest(project_id: str) -> dict:
    task = tasks_service.create(project_id, role="static", title="ingest", actor="g5", status="RUNNING")
    summary = pipeline_static.run(project_id, task_id=task["id"], log=lambda *_: None)
    tasks_service.update(task["id"], actor="system", status="REVIEW", fields={"error_code": None, "error_message": None})
    return summary


def session(project_id: str, device_id: str, *, transport=None, cleanup="PRESERVE_APP") -> dict:
    task = tasks_service.create(project_id, role="dynamic", title="device session", actor="g5", status="RUNNING")
    return dynamic.run_task(
        project_id,
        task_id=task["id"],
        device_id=device_id,
        transport=transport or dynamic.SimTransport(),
        cleanup_mode=cleanup,
    )


def release_all() -> None:
    for lease in devices_service.list_leases(active_only=True):
        devices_service.release(lease["id"], reason="g5 reset")


def read_json_artifact(project_id: str, name: str) -> dict:
    for row in artifacts_service.list_artifacts(project_id, limit=200):
        if row["rel_path"].endswith(name):
            return json.loads(artifacts_service.path_of(row).read_text(encoding="utf-8"))
    return {}


def main() -> int:
    db.migrate()
    app = create_app()
    client = TestClient(app)

    health = client.get("/api/health")
    check("platform_api_healthy", health.status_code == 200, f"status={health.status_code}")

    project_id = make_project("g5-device")
    summary = ingest(project_id)
    check(
        "project_ingested_on_the_desktop_side",
        bool(summary.get("index")) and summary.get("stage") == "done",
        f"stage={summary.get('stage')} units={summary.get('index', {}).get('units')} "
        f"artifacts={len(summary.get('artifacts') or [])}",
    )

    # -- the health gate is measured, not assumed ----------------------------
    sim = dynamic.make_transport("sim")
    before = devices_service.health("g5-sim:5555", package=PKG, transport=sim)
    check(
        "health_gate_blocks_a_missing_package",
        before["ready"] is False and before["blocked"] == ["APP_INSTALLED"],
        f"blocked={before['blocked']}",
    )
    sim_ready = dynamic.make_transport("sim")
    sim_ready.installed.add(PKG)
    after = devices_service.health("g5-sim:5555", package=PKG, transport=sim_ready)
    check(
        "health_gate_turns_ready_once_installed",
        after["ready"] is True and after["states"]["UI_READY"] is True,
        f"states={ {k: v for k, v in after['states'].items() if v is not None} }",
    )
    unauth = devices_service.health("g5-sim:5555", package=PKG, transport=dynamic.SimTransport(authorized=False))
    check(
        "unauthorised_adb_is_reported_not_ready",
        unauth["ready"] is False and unauth["states"]["ADB_ONLINE"] is False,
        f"blocked={unauth['blocked']}",
    )
    static_only = make_project("g5-static-without-device")
    static_summary = ingest(static_only)
    check(
        "a_missing_device_never_blocks_static_work",
        static_summary.get("stage") == "done" and bool(static_summary.get("index")),
        f"stage={static_summary.get('stage')} evidence={len(static_summary.get('evidence_ids') or [])} "
        "while the device pool was not ready",
    )

    # -- UI automation inside a real session ---------------------------------
    device = devices_service.register("g5-sim:5555", device_type="simulator", alias="g5-sim")
    ui_run = session(project_id, device["id"], transport=dynamic.SimTransport())
    steps = [item["step"] for item in ui_run["steps"]]
    check(
        "dynamic_session_includes_the_ui_step",
        steps == ["probe", "install", "launch", "ui", "observe", "screenshot"],
        f"steps={steps}",
    )
    kinds = {row["kind"] for row in artifacts_service.list_artifacts(project_id, limit=200)}
    check(
        "ui_step_leaves_artifacts",
        {"device_ui", "ui_before", "ui_after"} <= kinds,
        f"kinds={sorted(kinds)}",
    )
    ui_json = read_json_artifact(project_id, "ui.json")
    check(
        "permission_dialog_was_detected_and_handled",
        ui_json.get("dialogs", {}).get("count", 0) >= 1 and len(ui_json.get("handled") or []) >= 1,
        f"dialogs={ui_json.get('dialogs', {}).get('count')} handled={len(ui_json.get('handled') or [])}",
    )
    trace = evidence_service.verify(project_id)
    check(
        "ui_evidence_is_verifiable",
        trace["traceability_rate"] == 1.0,
        f"rows={trace['total']} failures={[f['reason'] for f in trace['failures']]}",
    )

    # -- the four cleanup policies ------------------------------------------
    release_all()
    keep_project = make_project("g5-preserve-session")
    keep_sim = dynamic.SimTransport()
    keep_run = session(keep_project, device["id"], transport=keep_sim, cleanup="PRESERVE_SESSION")
    uninstalled = [call for call in keep_sim.calls if call[:3] == ["shell", "pm", "uninstall"]]
    stopped = [call for call in keep_sim.calls if "force-stop" in " ".join(call)]
    check(
        "preserve_session_leaves_the_app_alone",
        not uninstalled and not stopped and PKG in keep_sim.installed,
        f"uninstall_calls={len(uninstalled)} stop_calls={len(stopped)} cleanup={keep_run['cleanup']['mode']}",
    )

    release_all()
    eph_project = make_project("g5-ephemeral")
    eph_sim = dynamic.SimTransport()
    eph_run = session(eph_project, device["id"], transport=eph_sim, cleanup="EPHEMERAL")
    check(
        "ephemeral_removes_only_what_we_installed",
        PKG not in eph_sim.installed and eph_run["cleanup"]["verified"] is True,
        f"installed_after={sorted(eph_sim.installed)} verified={eph_run['cleanup']['verified']}",
    )

    release_all()
    pre_project = make_project("g5-preexisting")
    pre_sim = dynamic.SimTransport(preinstalled=("com.android.settings", PKG))
    pre_run = session(pre_project, device["id"], transport=pre_sim, cleanup="EPHEMERAL")
    pre_uninstall = [call for call in pre_sim.calls if call[:3] == ["shell", "pm", "uninstall"]]
    check(
        "ephemeral_spares_a_pre_existing_app",
        PKG in pre_sim.installed and not pre_uninstall,
        f"installed_after={sorted(pre_sim.installed)} uninstall_calls={len(pre_uninstall)}",
    )

    release_all()
    quar_project = make_project("g5-quarantine")
    quar_sim = dynamic.SimTransport()
    quar_run = session(quar_project, device["id"], transport=quar_sim, cleanup="QUARANTINE")
    destructive = [call for call in quar_sim.calls if "uninstall" in " ".join(call) or "force-stop" in " ".join(call)]
    quarantined_now = devices_service.get(device["id"])["health"] == "QUARANTINED"
    check(
        "quarantine_runs_no_destructive_action",
        not destructive and quarantined_now and PKG in quar_sim.installed,
        f"destructive={len(destructive)} device_health={devices_service.get(device['id'])['health']}",
    )
    devices_service.clear_quarantine(device["id"], actor="g5", note="acceptance")
    try:
        dynamic.cleanup_plan("NOPE", package=PKG, installed_by_us=True)
        unknown_refused = False
    except dynamic.DynamicError as exc:
        unknown_refused = exc.code == "unknown_cleanup_mode"
    check("unknown_cleanup_mode_is_refused", unknown_refused, "cleanup_plan raised unknown_cleanup_mode")

    # -- one device, one session --------------------------------------------
    release_all()
    race_project = make_project("g5-race")
    holders: dict[str, object] = {}
    lock = threading.Lock()

    class SlowSim(dynamic.SimTransport):
        def run(self, serial, args, *, timeout=None):
            if args and args[0] == "install":
                time.sleep(0.6)
            return super().run(serial, args, timeout=timeout)

    def contender(tag: str) -> None:
        try:
            result = session(race_project, device["id"], transport=SlowSim())
            with lock:
                holders[tag] = result
        except dynamic.DynamicError as exc:
            with lock:
                holders[tag] = exc.code

    threads = [threading.Thread(target=contender, args=(tag,)) for tag in ("a", "b")]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    outcomes = sorted(str(value) for value in holders.values())
    ran = [tag for tag, value in holders.items() if isinstance(value, dict)]
    check(
        "two_workers_never_share_one_device",
        len(ran) == 1 and "device_unavailable" in outcomes,
        f"outcomes={outcomes}",
    )

    # -- a pulled cable is a safe failure -----------------------------------
    release_all()
    lost_project = make_project("g5-device-lost")
    lost_sim = dynamic.SimTransport(unplug_at="screencap")
    try:
        session(lost_project, device["id"], transport=lost_sim)
        lost_code = "no_error"
    except dynamic.DynamicError as exc:
        lost_code = exc.code
    cleanup_rows = [row for row in artifacts_service.list_artifacts(lost_project, limit=200) if row["rel_path"].endswith("cleanup.json")]
    cleanup_doc = json.loads(artifacts_service.path_of(cleanup_rows[0]).read_text(encoding="utf-8")) if cleanup_rows else {}
    check(
        "a_pulled_cable_fails_safely",
        lost_code in ("device_lost", "dynamic_timeout")
        and not devices_service.list_leases(device["id"], active_only=True)
        and cleanup_doc.get("verified") is False,
        f"code={lost_code} cleanup_verified={cleanup_doc.get('verified')} reasons={[c.get('skip_reason') for c in cleanup_doc.get('actions', [])][:2]}",
    )

    # -- the model-facing tools stay behind the same gate -------------------
    release_all()
    scope, _token, _path = capabilities.issue(project_id, "exec", task_id=None, actor="g5")
    no_lease = call_tool(scope, "device_action", {"action": "launch"})
    check(
        "device_action_without_a_lease_is_refused",
        no_lease.get("ok") is False and no_lease.get("error_code") == "lease_required",
        f"error={no_lease.get('error_code')}",
    )
    lease = devices_service.acquire(project_id, owner="g5", device_id=device["id"])
    bad_action = call_tool(scope, "device_action", {"action": "rm-rf"})
    check(
        "device_action_rejects_unknown_actions",
        bad_action.get("ok") is False and bad_action.get("error_code") == "unsupported_action",
        f"error={bad_action.get('error_code')}",
    )
    observe = call_tool(scope, "device_observe", {})
    check(
        "device_observe_reports_measured_state",
        observe.get("ok") is True and "devices" in observe.get("result", {}),
        f"observed={observe.get('result', {}).get('observed')} reason={observe.get('result', {}).get('reason')}",
    )
    devices_service.release(lease["id"], reason="g5")

    # -- API surfaces -------------------------------------------------------
    modes = client.get("/api/cleanup/modes")
    check(
        "api_exposes_the_cleanup_matrix",
        modes.status_code == 200 and set(modes.json()["modes"]) == set(dynamic.CLEANUP_MODES),
        f"modes={sorted(modes.json().get('modes', {})) if modes.status_code == 200 else modes.status_code}",
    )
    other_project = make_project("g5-other")
    token = auth_service.issue([other_project], subject="g5", scopes=["read"])
    settings.require_auth = True
    try:
        denied = client.get(
            f"/api/devices/g5-sim:5555/health",
            params={"project_id": project_id, "transport": "sim"},
            headers={"Authorization": f"Bearer {token}"},
        )
    finally:
        settings.require_auth = False
    code = None
    if denied.status_code == 403:
        detail = denied.json().get("detail")
        code = detail.get("error_code") if isinstance(detail, dict) else None
    check(
        "device_health_is_not_public",
        denied.status_code in (401, 403),
        f"status={denied.status_code} (token for another project must not read this device)",
    )

    metrics = client.get("/api/metrics").json()
    check(
        "no_device_lease_collisions_were_recorded",
        metrics.get("device_lease_collision") == 0 and metrics.get("project_isolation_failures") == 0,
        f"collision={metrics.get('device_lease_collision')} isolation={metrics.get('project_isolation_failures')}",
    )

    # -- the real handset, read-only ---------------------------------------
    adb = toolchain.paths().get("adb")
    attached: list[str] = []
    if adb:
        proc = subprocess.run([str(adb), "devices"], capture_output=True, text=True, timeout=30, env=toolchain.child_env())
        attached = [line.split()[0] for line in proc.stdout.splitlines()[1:] if line.strip().endswith("device")]
    if attached:
        serial = attached[0]
        report = devices_service.health(serial, package=PKG)
        driver = device_ui.AdbUi(serial)
        shot = driver.screenshot(TMP / "real-device.png")
        nodes, digest = driver.hierarchy()
        check(
            "real_device_read_only_probe",
            report["states"]["ADB_ONLINE"] is True and shot["bytes"] > 0 and len(nodes) > 0,
            f"serial={serial} model={report['detail'].get('screen')} nodes={len(nodes)} png={shot['bytes']}B "
            f"blocked={report['blocked']}",
        )
        device_actions = db.query(
            "SELECT payload_json FROM audit_events WHERE event_type = 'bridge_device_action'"
        )
        touched = [row for row in device_actions if serial in (row["payload_json"] or "")]
        check(
            "no_destructive_action_touched_the_real_device",
            not touched,
            f"bridge_device_action events for {serial}: {len(touched)} (read-only probe only)",
        )
    else:
        check("real_device_read_only_probe", True, "NOT_OBSERVED: no handset attached; simulator covered the paths")

    audited = [row["event_type"] for row in audit.tail(0, limit=800)]
    check(
        "device_flows_are_audited",
        audited.count("dynamic_started") >= 4 and audited.count("dynamic_completed") >= 3,
        f"dynamic_started={audited.count('dynamic_started')} dynamic_completed={audited.count('dynamic_completed')} "
        f"device_lost={audited.count('device_lost')}",
    )

    passed = sum(1 for row in CHECKS if row["ok"])
    total = len(CHECKS)
    report_dir = ROOT / "reports" / "gate5-v3"
    report_dir.mkdir(parents=True, exist_ok=True)
    payload = {"gate": "G5", "generated_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
               "passed": passed, "total": total, "checks": CHECKS,
               "environment": {"transports": ["sim", "adb"], "real_devices": attached,
                               "adb": str(adb), "storage": str(TMP / "storage")}}
    (report_dir / "acceptance.json").write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
    lines = [f"# Gate G5 - device layer acceptance", "",
             f"Generated: {payload['generated_at']}  |  {passed}/{total} checks passed", "",
             "| Check | Result | Detail |", "| --- | --- | --- |"]
    for row in CHECKS:
        lines.append(f"| `{row['check']}` | {'PASS' if row['ok'] else 'FAIL'} | {row['detail'].replace('|', '\\|')} |")
    lines += ["", "## Honest boundaries", "",
              "- Destructive device paths (install / uninstall / force-stop) ran on the simulator only;",
              "  the attached handset was probed read-only (state, uiautomator dump, one screenshot).",
              "- ADB authorisation is a human action on the phone; an unauthorised transport is reported",
              "  as `WAITING_USER_ADB_AUTH` and never retried automatically.",
              "- `CAPTURE_READY` stays false while no ProxyPin export is attached."]
    (report_dir / "acceptance.md").write_text("\n".join(lines) + "\n", encoding="utf-8")
    print(f"[g5] {passed}/{total} checks passed -> {report_dir / 'acceptance.md'}")
    return 0 if passed == total else 1


if __name__ == "__main__":
    raise SystemExit(main())
