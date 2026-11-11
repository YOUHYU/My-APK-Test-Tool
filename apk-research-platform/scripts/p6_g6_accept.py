"""G6 acceptance: one scheduler, a fake clock for three days, and a fake probe for low memory.

Every check prints the value it observed, so the report can be audited without re-running it.
Run: `.venv/Scripts/python.exe scripts/p6_g6_accept.py`
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
SANDBOX = ROOT / "runtime" / f"p6-g6-{STAMP}"


def local_env() -> None:
    os.environ["APKPLAT_STORAGE"] = str(SANDBOX / "storage")
    os.environ["APKPLAT_REPORTS"] = str(ROOT / "reports" / "gate6")
    os.environ["APKPLAT_REQUIRE_AUTH"] = "0"
    os.environ["APKPLAT_MODEL_ENABLED"] = "0"
    os.environ["APKPLAT_DYNAMIC_TRANSPORT"] = "sim"
    os.environ["APKPLAT_DYNAMIC_OBSERVE_SECONDS"] = "0"
    os.environ["TEMP"] = str(ROOT / ".tmp")
    os.environ["TMP"] = str(ROOT / ".tmp")


local_env()
sys.path.insert(0, str(ROOT / "backend"))

from apkplat import clock, resources  # noqa: E402
from apkplat import dynamic as dynamic_module  # noqa: E402
from apkplat.db import db  # noqa: E402

CHECKS: list[dict] = []


def check(name: str, ok: bool, detail: str = "") -> bool:
    CHECKS.append({"check": name, "ok": bool(ok), "detail": detail})
    print(f"[g6] {'PASS' if ok else 'FAIL'} {name}  {detail}")
    return bool(ok)


def main() -> int:
    for folder in (SANDBOX / "storage", SANDBOX / "reports"):
        folder.mkdir(parents=True, exist_ok=True)
    migrations = db.migrate()

    from apkplat.bridge import tool_catalogue
    from apkplat.services import devices as devices_service
    from apkplat.services import projects as projects_service
    from apkplat.services import queue as queue_service
    from apkplat.services import scheduler as scheduler_service
    from apkplat.services import tasks as tasks_service

    fake = clock.FakeClock("2026-05-01T06:00:00.000Z")
    clock.use(fake)
    probe = resources.FakeResourceProbe(memory_available_mb=4000)
    resources.use(probe)

    check("schema_has_periodic_tables",
          {"periodic_jobs", "periodic_runs", "periodic_attempts", "test_identities",
           "test_identity_leases"} <= {row["name"] for row in db.query("SELECT name FROM sqlite_master WHERE type='table'")},
          f"migrations={migrations}")

    project = projects_service.create(
        name="g6-periodic", apk_source=ROOT / "samples" / "sample-app.apk", filename="sample-app.apk", actor="g6"
    )
    project_id = project["id"]
    identity = scheduler_service.add_identity(
        project_id, "fixture-g6", kind="fixture", secret_ref="vault://g6/fixture", actor="g6"
    )
    check("identity_stored_by_reference", identity["secret_ref"] == "vault://g6/fixture" and identity["kind"] == "fixture",
          f"kind={identity['kind']} has_secret_ref={bool(identity['secret_ref'])}")
    try:
        scheduler_service.add_identity(project_id, "x", kind="third_party")
        check("third_party_identity_refused", False, "a third-party kind was accepted")
    except scheduler_service.SchedulerError as exc:
        check("third_party_identity_refused", exc.code == "unsupported_identity_kind", f"code={exc.code}")

    schedule = scheduler_service.create_schedule(
        project_id, schedule_id="g6-daily", title="g6 daily sweep", hour=9, tz="UTC",
        test_identity_id=identity["id"], actor="g6",
    )
    check("schedule_has_a_next_due_instant", schedule["next_due_at"].startswith("2026-05-01T09:00:00"),
          f"next_due_at={schedule['next_due_at']}")

    # --- three business days, one trigger each ------------------------------------
    per_day: list[list[str]] = []
    for _ in range(3):
        fake.advance(3 * 3600)          # -> 09:00
        first = scheduler_service.tick(actor="g6")
        same_day = scheduler_service.tick(actor="g6")   # must not fire again
        per_day.append([row["period_key"] for row in first["outcomes"] if row["result"] == "triggered"])
        check(f"day_{first['outcomes'][0]['period_key']}_triggered_once",
              len(per_day[-1]) == 1 and same_day["triggered"] == 0,
              f"triggered={len(per_day[-1])} same_day_triggered={same_day['triggered']}")
        fake.advance(21 * 3600)         # -> next day 06:00

    fired = [key for day in per_day for key in day]
    check("three_windows_three_triggers", fired == ["2026-05-01", "2026-05-02", "2026-05-03"], f"fired={fired}")
    runs = scheduler_service.runs(schedule["id"])
    check("runs_match_the_windows", len(runs) == 3 and len({row["job_id"] for row in runs}) == 3,
          f"runs={[(r['period_key'], r['result']) for r in runs]}")

    # --- a crash between claim and bookkeeping must not double-fire ----------------
    fake.set("2026-05-03T10:00:00.000Z")  # rewind into the third window
    db.execute(
        "UPDATE periodic_jobs SET next_due_at = ? WHERE id = ?", ("2026-05-03T10:00:00.000000Z", schedule["id"])
    )
    replay = scheduler_service.tick(actor="g6")
    check("replayed_window_is_a_no_op",
          replay["triggered"] == 0 and replay["outcomes"][0]["result"] == scheduler_service.DUPLICATE,
          f"outcomes={[row['result'] for row in replay['outcomes']]}")
    check("run_rows_never_duplicated", len(scheduler_service.runs(schedule["id"])) == 3,
          f"runs={len(scheduler_service.runs(schedule['id']))}")

    # --- identity exclusivity (and a refusal that does not burn the day) ------------
    fake.advance(24 * 3600)  # next day, 09:00
    held = scheduler_service.acquire_identity(identity["id"], project_id=project_id, owner="g6-manual", ttl=7200)
    try:
        scheduler_service.acquire_identity(identity["id"], project_id=project_id, owner="g6-rival", ttl=3600)
        check("identity_is_exclusive", False, "a second holder got the same identity")
    except scheduler_service.SchedulerError as exc:
        check("identity_is_exclusive", exc.code == "identity_busy", f"code={exc.code}")

    blocked = scheduler_service.tick(actor="g6")
    check("busy_identity_blocks_without_burning_the_day",
          blocked["triggered"] == 0 and blocked["outcomes"][0]["result"] == scheduler_service.IDENTITY_BUSY,
          f"outcomes={[row['result'] for row in blocked['outcomes']]}")
    scheduler_service.release_identity(held["id"], owner="g6-manual")
    fake.advance(scheduler_service.RETRY_AFTER_SECONDS + 1)
    recovered = scheduler_service.tick(actor="g6")
    check("identity_freed_the_window_still_runs",
          recovered["triggered"] == 1, f"triggered={recovered['triggered']}")
    scheduler_lease = scheduler_service.active_lease(identity["id"])
    check("identity_leased_while_the_task_lives", scheduler_lease is not None,
          f"lease={scheduler_lease['id'] if scheduler_lease else None}")

    # --- low memory refuses work instead of starting it ---------------------------
    scheduler_service.set_enabled(schedule["id"], False)  # isolate the resource scenario
    heavy = scheduler_service.create_schedule(
        project_id, schedule_id="g6-heavy", title="g6 heavy sweep", role="static", hour=9, tz="UTC", actor="g6"
    )
    tasks_before = len(tasks_service.list_tasks(project_id))
    low = resources.FakeResourceProbe(low_memory=True)
    resources.use(low)
    fake.advance(24 * 3600)
    refused = scheduler_service.tick(actor="g6")
    tasks_after = len(tasks_service.list_tasks(project_id))
    check("low_memory_returns_resource_blocked",
          refused["triggered"] == 0 and refused["outcomes"][0]["result"] == "RESOURCE_BLOCKED",
          f"result={refused['outcomes'][0]['result']} detail={refused['outcomes'][0]['detail']}")
    check("low_memory_started_nothing", tasks_after == tasks_before, f"tasks {tasks_before} -> {tasks_after}")
    attempts = scheduler_service.attempts(heavy["id"])
    check("refusal_is_recorded_as_an_attempt", bool(attempts) and attempts[0]["error_code"] == "RESOURCE_BLOCKED",
          f"attempts={len(attempts)}")
    resources.use(resources.FakeResourceProbe(memory_available_mb=4000))
    fake.advance(scheduler_service.RETRY_AFTER_SECONDS + 1)
    check("resources_returning_unblocks_the_same_window", scheduler_service.tick(actor="g6")["triggered"] == 1, "")

    # --- the device path keeps a session when asked to ----------------------------
    device = devices_service.register("sim-g6", device_type="emulator", alias="g6 sim")
    transport = dynamic_module.SimTransport()
    task = tasks_service.create(project_id, role="dynamic", title="g6 preserve session", actor="g6")
    result = dynamic_module.run_task(
        project_id, task_id=task["id"], worker_id="g6-worker", transport_name="sim",
        device_id=device["id"], transport=transport, log=lambda *args, **kwargs: None,
        observe_seconds=0, cleanup_mode="PRESERVE_SESSION",
    )
    cleanup = result["cleanup"]
    record = json.loads((SANDBOX / "storage" / "projects" / project_id / cleanup["artifact"]).read_text(encoding="utf-8"))
    destructive = [
        call for call in transport.calls
        if any(token in " ".join(call) for token in ("force-stop", "uninstall"))
    ]
    check("preserve_session_stops_nothing",
          not destructive and cleanup["mode"] == "PRESERVE_SESSION",
          f"destructive_calls={len(destructive)} verified={cleanup['verified']}")
    check("preserve_session_keeps_the_app_installed",
          result["package"] in transport.installed
          and any(row["action"] == "clear_scratch" and row["allowed"] for row in record["actions"]),
          f"installed={sorted(transport.installed)} actions={[(r['action'], r['allowed']) for r in record['actions']]}")

    # --- one scheduler owner, and no account-limit machinery ----------------------
    from apkplat.services import capabilities as capabilities_service

    tools = list(capabilities_service.ALL_TOOLS)
    check("model_tool_surface_has_no_scheduler_tool",
          not any("periodic" in name or "schedule" in name for name in tools), f"tools={tools}")
    routes = [getattr(route, "path", "") for route in __import__("apkplat.api.app", fromlist=["x"]).create_app().routes]
    check("no_bulk_or_rotation_endpoints",
          not any(("bulk" in path or "rotate" in path or "register-batch" in path) for path in routes),
          f"routes={len(routes)}")
    stats = queue_service.stats()
    check("queue_still_persisted", sum(stats.values()) >= 4, f"stats={stats}")

    write_report(migrations)
    failures = [row for row in CHECKS if not row["ok"]]
    print(f"\n[g6] {len(CHECKS) - len(failures)}/{len(CHECKS)} checks passed")
    return 0 if not failures else 1


def write_report(migrations: list[str]) -> None:
    reports = ROOT / "reports" / "gate6"
    reports.mkdir(parents=True, exist_ok=True)
    total = len(CHECKS)
    passed = sum(1 for row in CHECKS if row["ok"])
    lines = [
        "# G6 acceptance - periodic scheduling, test identities, fake clock and fake resources\n",
        f"- generated_at: {datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')}",
        f"- result: **{passed}/{total} checks passed**",
        f"- storage: `{SANDBOX / 'storage'}` (created fresh for this run)",
        f"- migrations applied: {', '.join(migrations)}",
        "- clock: `FakeClock` started 2026-05-01T06:00Z, advanced day by day; no real waiting",
        "- resource probe: `FakeResourceProbe`; low memory is simulated, not induced\n",
        "| # | Check | Result | Observed |",
        "| --- | --- | --- | --- |",
    ]
    for index, row in enumerate(CHECKS, start=1):
        detail = (row["detail"] or "").replace("|", "\\|")
        lines.append(f"| {index} | {row['check']} | {'PASS' if row['ok'] else 'FAIL'} | {detail} |")
    lines += [
        "",
        "## What this run does not claim",
        "",
        "- It does not wait three real days. `FakeClock` moves the schedule's own notion of time;",
        "  a production run is the same `tick()` against the real clock.",
        "- Low memory is injected. The refusal path is real code (`RESOURCE_BLOCKED` attempt, no task),",
        "  but no physical memory was exhausted to produce it.",
        "- No third-party account was touched: identities are references to operator-owned fixtures, and",
        "  the only kinds accepted are `test_account` and `fixture`.",
    ]
    (reports / "acceptance.md").write_text("\n".join(lines) + "\n", encoding="utf-8")
    (reports / "acceptance.json").write_text(
        json.dumps(
            {
                "generated_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
                "passed": passed,
                "total": total,
                "checks": CHECKS,
                "migrations": migrations,
            },
            indent=2,
        ),
        encoding="utf-8",
    )


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    finally:
        if SANDBOX.exists() and os.environ.get("APKPLAT_KEEP_SANDBOX") != "1":
            shutil.rmtree(SANDBOX, ignore_errors=True)
