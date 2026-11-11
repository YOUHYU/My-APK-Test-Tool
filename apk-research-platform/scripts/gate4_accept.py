"""Gate 4 acceptance: the dynamic stage on a device pool.

Runs the platform in-process against a throwaway storage tree and checks the four
promises the taskbook makes about dynamic analysis:

* a device is leased before use, and released when the session ends or dies;
* one device serves one task at a time - a second session waits (WAITING_DEVICE);
* pulling the cable is a safe failure: task FAILED, lease released, nothing running;
* a finished session leaves no residue (cleanup verified) and its claims are traceable.

The transport is the simulated device, because this host has no phone attached; the
script probes adb for a real device and records the answer either way, so "no device"
is a reported fact, not a hidden skip.

Outputs: reports/gate4/acceptance.md and reports/gate4/acceptance.json
"""
from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
import threading
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "backend"))

WORK = Path(tempfile.mkdtemp(prefix="apkplat-gate4-"))
os.environ["APKPLAT_STORAGE"] = str(WORK / "storage")
os.environ["APKPLAT_REPORTS"] = str(WORK / "reports")
os.environ["APKPLAT_SECRET"] = "gate4-acceptance-secret-not-for-production"
os.environ["APKPLAT_REQUIRE_AUTH"] = "0"
os.environ["APKPLAT_DYNAMIC_OBSERVE_SECONDS"] = "0"

from fastapi.testclient import TestClient  # noqa: E402

from apkplat import audit, dynamic, toolchain  # noqa: E402
from apkplat import db as dbmod  # noqa: E402
from apkplat.api.app import create_app  # noqa: E402
from apkplat.services import artifacts as artifacts_service  # noqa: E402
from apkplat.services import devices as devices_service  # noqa: E402
from apkplat.services import evidence as evidence_service  # noqa: E402
from apkplat.services import projects as projects_service  # noqa: E402
from apkplat.services import queue, tasks  # noqa: E402
from apkplat.worker import Worker  # noqa: E402

OUT = ROOT / "reports" / "gate4"
OUT.mkdir(parents=True, exist_ok=True)
checks: list[dict] = []


def _now_iso() -> str:
    from datetime import datetime, timezone

    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def check(name: str, ok: bool, detail: str = "") -> bool:
    checks.append({"check": name, "ok": bool(ok), "detail": detail})
    print(f"[gate4] {'PASS' if ok else 'FAIL'}  {name}" + (f"  {detail}" if detail else ""))
    return bool(ok)



def ingest(client: TestClient, name: str) -> str:
    with open(ROOT / "samples" / "sample-app.apk", "rb") as handle:
        response = client.post(
            "/api/projects",
            data={"name": name, "goal": "gate4 dynamic acceptance"},
            files={"apk": ("sample-app.apk", handle, "application/vnd.android.package-archive")},
        )
    if response.status_code != 201:
        raise SystemExit(f"ingest failed: {response.status_code} {response.text[:300]}")
    project_id = response.json()["project"]["id"]
    Worker("gate4-ingest", ["static_pipeline"], poll_interval=0.05).run(max_jobs=1)
    return project_id


def main() -> int:
    dbmod.db.migrate()
    client = TestClient(create_app())

    adb = toolchain.paths()["adb"]
    probe = subprocess.run(
        [str(adb), "devices", "-l"], capture_output=True, text=True, timeout=30, env=toolchain.child_env()
    )
    real_devices = [line for line in (probe.stdout or "").splitlines() if line.endswith("device") or "\tdevice " in line]
    check(
        "adb probed for physical devices",
        probe.returncode == 0,
        f"exit={probe.returncode}; attached={len(real_devices)}; simulated transport used for the run",
    )

    device = devices_service.register("gate4-sim", device_type="simulator", alias="gate4-sim")
    check("device registered", bool(device["id"]), f"{device['adb_serial']} ({device['id']})")

    project_id = ingest(client, "gate4-dynamic")
    manifest = projects_service.manifest(project_id)
    check("project ingested and indexed", bool(manifest.get("package")), manifest.get("package", ""))

    # -- happy path ---------------------------------------------------------
    task = tasks.create(project_id, role="dynamic", title="Gate4 session", actor="gate4", status="RUNNING")
    started = time.time()
    result = dynamic.run_task(project_id, task_id=task["id"], device_id=device["id"], transport=dynamic.SimTransport())
    duration = round(time.time() - started, 1)
    steps = [item["step"] for item in result["steps"]]
    check("session completed every step", steps == ["probe", "install", "launch", "ui", "observe", "screenshot"], ",".join(steps))
    check("device facts captured", result["device"].get("model", "").startswith("Pixel"), str(result["device"].get("model")))

    kinds = {row["kind"] for row in artifacts_service.list_artifacts(project_id)}
    expected = {"device_probe", "device_install", "device_launch", "device_logcat", "device_cleanup"}
    check("dynamic artifacts stored", expected <= kinds, ",".join(sorted(k for k in kinds if k.startswith("device_"))))

    rows = evidence_service.list_evidence(project_id)
    dynamic_rows = [row for row in rows if row["kind"] in {"device_fact", "install_result", "launch_result", "runtime_log"}]
    check("session produced evidence", len(dynamic_rows) >= 4, f"{len(dynamic_rows)} dynamic rows of {len(rows)}")
    verification = evidence_service.verify(project_id)
    check(
        "all evidence verifies",
        not verification["failures"] and verification["traceability_rate"] >= 1.0,
        f"{verification['total']} rows, rate {verification['traceability_rate']}",
    )

    check("cleanup verified (no residue)", result["cleanup"]["verified"] is True, json.dumps(result["cleanup"])[:160])
    active = dbmod.db.query(
        "SELECT * FROM device_leases WHERE device_id = ? AND released_at IS NULL", (device["id"],)
    )
    check("lease released after the session", active == [], f"{len(active)} active")
    check("task moved to REVIEW", tasks.get(task["id"])["status"] == "REVIEW", tasks.get(task["id"])["status"])

    # -- one device, one task ----------------------------------------------
    blocked_project = ingest(client, "gate4-blocked")
    holder = devices_service.acquire(blocked_project, owner="gate4-holder", device_id=device["id"])
    blocked_task = tasks.create(blocked_project, role="dynamic", title="Waits for the device", actor="gate4", status="RUNNING")
    waited = None
    try:
        dynamic.run_task(blocked_project, task_id=blocked_task["id"], device_id=device["id"], transport=dynamic.SimTransport())
    except dynamic.DynamicError as exc:
        waited = exc
    check("second session waits for the device", waited is not None and waited.code == "device_unavailable", str(waited)[:120])
    check("waiting task parked in WAITING_DEVICE", tasks.get(blocked_task["id"])["status"] == "WAITING_DEVICE",
          tasks.get(blocked_task["id"])["status"])
    devices_service.release(holder["id"], owner="gate4-holder", reason="gate4 handback")
    resumed = dynamic.run_task(blocked_project, task_id=blocked_task["id"], device_id=device["id"], transport=dynamic.SimTransport())
    check("waiting session resumes when the device frees up", resumed["cleanup"]["verified"] is True,
          tasks.get(blocked_task["id"])["status"])

    # -- cable pull --------------------------------------------------------
    unplug_project = ingest(client, "gate4-unplug")
    unplug_task = tasks.create(unplug_project, role="dynamic", title="Cable pulled", actor="gate4", status="RUNNING")
    lost = None
    try:
        dynamic.run_task(
            unplug_project,
            task_id=unplug_task["id"],
            device_id=device["id"],
            transport=dynamic.SimTransport(unplug_at="screencap"),
        )
    except dynamic.DynamicError as exc:
        lost = exc
    check("unplug fails safely", lost is not None and lost.code == "device_lost" and lost.retryable is False, str(lost)[:120])
    failed_task = tasks.get(unplug_task["id"])
    check("unplugged task is FAILED", failed_task["status"] == "FAILED" and failed_task["error_code"] == "device_lost",
          f"{failed_task['status']}/{failed_task['error_code']}")
    active_after = dbmod.db.query(
        "SELECT * FROM device_leases WHERE device_id = ? AND released_at IS NULL", (device["id"],)
    )
    check("lease released even on device loss", active_after == [], f"{len(active_after)} active")
    cleanup_row = dbmod.db.one(
        "SELECT * FROM artifacts WHERE project_id = ? AND kind = 'device_cleanup'", (unplug_project,)
    )
    cleanup_text = artifacts_service.path_of(cleanup_row).read_text(encoding="utf-8") if cleanup_row else ""
    check(
        "deferred cleanup is recorded, not hidden",
        '"verified": false' in cleanup_text and "device unreachable" in cleanup_text,
        "cleanup.json records device loss",
    )
    lost_evidence = evidence_service.verify(unplug_project)
    check("evidence gathered before the unplug still verifies", lost_evidence["traceability_rate"] >= 1.0,
          f"{lost_evidence['total']} rows")

    # -- no overlapping leases anywhere ------------------------------------
    overlaps = 0
    for row in devices_service.list_devices():
        leases = dbmod.db.query(
            "SELECT * FROM device_leases WHERE device_id = ? ORDER BY heartbeat_at", (row["id"],)
        )
        for previous, current in zip(leases, leases[1:]):
            if previous["released_at"] is None:
                overlaps += 1
            elif previous["released_at"] > current["heartbeat_at"] and current["released_at"] is None:
                overlaps += 1
    check("no overlapping leases on any device", overlaps == 0, f"{overlaps} overlap(s)")

    # -- through the durable queue ----------------------------------------
    queue_project = ingest(client, "gate4-queue")
    response = client.post(f"/api/projects/{queue_project}/dynamic/run", json={"transport": "sim", "device_id": device["id"]})
    check("dynamic run accepted by the API", response.status_code == 202, str(response.status_code))
    job_id = response.json()["job_id"]
    Worker("gate4-dynamic", ["dynamic_analysis"], poll_interval=0.05).run(max_jobs=1)
    job = queue.get(job_id)
    check("dynamic job succeeded through the queue", job["status"] == "SUCCEEDED", job["status"])
    runs = client.get(f"/api/projects/{queue_project}/dynamic/runs").json()
    check("run history exposed to the UI", len(runs["artifacts"]) >= 4 and len(runs["leases"]) >= 1,
          f"{len(runs['artifacts'])} artifacts, {len(runs['leases'])} leases")

    metrics = client.get("/api/metrics").json()
    check("no device lease collisions", metrics["device_lease_collision"] == 0, str(metrics["device_lease_collision"]))
    check("no project isolation failures", metrics["project_isolation_failures"] == 0, str(metrics["project_isolation_failures"]))

    events = [row["event_type"] for row in audit.tail(0, limit=2000)]
    for expected_event in ("dynamic_started", "dynamic_completed", "device_lost", "device_wait", "dynamic_cleanup_verified"):
        check(f"audit records {expected_event}", events.count(expected_event) >= 1, str(events.count(expected_event)))

    write_report(
        {
            "work_dir": str(WORK),
            "adb": str(adb),
            "physical_devices": len(real_devices),
            "device": device["adb_serial"],
            "project_id": project_id,
            "session_seconds": duration,
            "steps": steps,
            "evidence_rows": verification["total"],
            "traceability_rate": verification["traceability_rate"],
            "metrics": metrics,
        }
    )
    failed = [item for item in checks if not item["ok"]]
    print(f"[gate4] {len(checks) - len(failed)}/{len(checks)} checks passed")
    return 0 if not failed else 1


def write_report(data: dict) -> None:
    failed = [item for item in checks if not item["ok"]]
    lines = [
        "# Gate 4 acceptance - dynamic stage on the device pool",
        "",
        f"- Run at: {time.strftime('%Y-%m-%d %H:%M:%S')}",
        f"- Transport: simulated device (this host has {data['physical_devices']} physical device(s) attached)",
        f"- adb: `{data['adb']}`",
        "- The DSH NEXT install and the model API were provided by the operator and were not modified by this run.",
        f"- Result: **{'PASS' if not failed else 'FAIL'}** - {len(checks) - len(failed)}/{len(checks)} checks",
        "",
        "## Checks",
        "",
        "| check | result | detail |",
        "| --- | --- | --- |",
    ]
    for item in checks:
        detail = str(item["detail"]).replace("|", "\\|")[:160]
        lines.append(f"| {item['check']} | {'PASS' if item['ok'] else 'FAIL'} | {detail} |")
    lines += [
        "",
        "## Facts",
        "",
        f"- Session wall time: {data['session_seconds']}s, steps: {', '.join(data['steps'])}",
        f"- Evidence: {data['evidence_rows']} rows, traceability {data['traceability_rate']}",
        f"- device_lease_collision: {data['metrics']['device_lease_collision']}",
        f"- Work directory: `{data['work_dir']}`",
        "",
        "## Honest limits",
        "",
        "- No phone or emulator is attached to this host, so the run uses `SimTransport`.",
        "  The adb code path is the same code object (`AdbTransport`) that the CLI/worker use",
        "  with `APKPLAT_DYNAMIC_TRANSPORT=adb`; the check above records that adb itself answers.",
        "- A real device run is a one-line command once hardware exists:",
        "  `python scripts/apkplat_cli.py dynamic <project_id> --device <device_id>`.",
    ]
    (OUT / "acceptance.md").write_text("\n".join(lines) + "\n", encoding="utf-8")
    (OUT / "acceptance.json").write_text(
        json.dumps({"generated_at": _now_iso(), "checks": checks, "facts": data}, indent=2, default=str), encoding="utf-8"
    )
    print(f"[gate4] report: {OUT / 'acceptance.md'}")


if __name__ == "__main__":
    raise SystemExit(main())
