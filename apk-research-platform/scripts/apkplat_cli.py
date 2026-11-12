"""Operator CLI: the same service layer the HTTP API and the MCP server use.

Nothing here re-implements behaviour 鈥?every subcommand calls ``apkplat`` services,
so a bug fixed in the service is fixed in all three entry points at once.
"""
from __future__ import annotations

import argparse
import json
import shutil
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "backend"))

from apkplat import dynamic, indexer, reports, toolchain, worker  # noqa: E402
from apkplat.config import settings  # noqa: E402
from apkplat.db import db  # noqa: E402
from apkplat.services import artifacts as artifacts_service  # noqa: E402
from apkplat.services import evidence as evidence_service  # noqa: E402
from apkplat.services import projects as projects_service  # noqa: E402
from apkplat.services import queue as queue_service
from apkplat.services import recovery as recovery_service  # noqa: E402
from apkplat.services import tasks as tasks_service  # noqa: E402


def _out(data) -> None:
    print(json.dumps(data, ensure_ascii=False, indent=2, default=str))


def cmd_init(_args) -> int:
    settings.ensure_dirs()
    applied = db.migrate()
    _out({"storage": str(settings.storage), "db": settings.db_url, "migrations_applied": applied})
    return 0


def cmd_versions(_args) -> int:
    _out(toolchain.probe_versions())
    return 0


def cmd_create(args) -> int:
    source = Path(args.apk).resolve()
    inbox = settings.storage / "inbox"
    inbox.mkdir(parents=True, exist_ok=True)
    staged = inbox / source.name
    if source != staged:
        shutil.copy2(source, staged)
    project = projects_service.create(
        args.name,
        staged,
        source.name,
        goal=args.goal,
        policy_id=args.policy or "default",
        storage_root=getattr(args, "storage_root", None),
        actor="cli",
    )
    job = queue_service.enqueue(
        "static_pipeline",
        project_id=project["id"],
        payload={"project_id": project["id"]},
        idempotency_key=f"static:{project['id']}",
        actor="cli",
    )
    _out({"project": project, "job_id": job})
    return 0


def cmd_resume(args) -> int:
    """Reclaim expired leases and re-publish jobs for unfinished cards."""
    summary = recovery_service.resume_project(args.project_id, actor="cli")
    _out(summary)
    return 0 if summary.get("ok") else 2


def cmd_list(_args) -> int:
    rows = projects_service.list_projects()
    columns = ("id", "name", "status", "package_name", "apk_sha256", "created_at")
    _out([{key: row[key] for key in columns if key in row.keys()} for row in rows])
    return 0


def cmd_show(args) -> int:
    project = projects_service.get(args.project_id)
    if not project:
        print(f"project {args.project_id} not found", file=sys.stderr)
        return 2
    _out({"project": project, "manifest": projects_service.manifest(args.project_id)})
    return 0


def cmd_verify(args) -> int:
    chain = artifacts_service.verify_chain(args.project_id)
    trace = evidence_service.verify(args.project_id)
    _out({"artifacts": chain, "evidence": trace})
    ok = not chain["failures"] and not trace["failures"]
    return 0 if ok else 1


def cmd_report(args) -> int:
    result = reports.generate(args.project_id, task_id=args.task_id, actor="cli")
    print(json.dumps({k: v for k, v in result.items() if k != "markdown"}, ensure_ascii=False, indent=2))
    print(result["markdown"])
    return 0


def cmd_search(args) -> int:
    _out(indexer.search_code(args.project_id, args.query, kind=args.kind, limit=args.limit))
    return 0


def cmd_method(args) -> int:
    row = indexer.get_method(args.project_id, args.class_name, args.method)
    if not row:
        print("not found", file=sys.stderr)
        return 2
    _out(row)
    return 0


def cmd_packages(args) -> int:
    _out(indexer.list_packages(args.project_id))
    return 0


def cmd_evidence(args) -> int:
    _out(evidence_service.list_evidence(args.project_id))
    return 0


def cmd_board(_args) -> int:
    _out(tasks_service.board_all() if hasattr(tasks_service, "board_all") else {"columns": {}})
    return 0


def cmd_queue(args) -> int:
    reclaimed = []
    if getattr(args, "reclaim", False):
        reclaimed = queue_service.reclaim_expired()
    _out({"stats": queue_service.stats(), "reclaimed": [r["id"] for r in reclaimed]})
    return 0


def cmd_job_reset(args) -> int:
    """Operator escape hatch: put a job back to PENDING (audited)."""
    from apkplat import audit
    from apkplat.db import utcnow

    row = db.one("SELECT * FROM jobs WHERE id = ?", (args.job_id,))
    if not row:
        print(f"job {args.job_id} not found", file=sys.stderr)
        return 2
    db.execute(
        "UPDATE jobs SET status = 'PENDING', lease_owner = NULL, lease_expires_at = NULL,"
        " available_at = ?, updated_at = ? WHERE id = ?",
        (utcnow(), utcnow(), args.job_id),
    )
    audit.record(
        "job_reset_by_operator",
        project_id=row["project_id"],
        task_id=row["task_id"],
        actor="cli",
        payload={"job_id": args.job_id, "previous_status": row["status"], "reason": args.reason},
    )
    _out({"job_id": args.job_id, "status": "PENDING"})
    return 0


def cmd_dynamic(args) -> int:
    task_id = args.task
    if not task_id:
        task = tasks_service.create(
            args.project_id,
            role="dynamic",
            title="Dynamic session",
            actor="cli",
            status="RUNNING",
        )
        task_id = task["id"]
    transport = None
    if args.transport == "sim":
        transport = dynamic.SimTransport(unplug_at=args.unplug)
    result = dynamic.run_task(
        args.project_id,
        task_id=task_id,
        worker_id=args.id or "cli-dynamic",
        transport_name=args.transport,
        transport=transport,
        device_id=args.device,
        observe_seconds=args.observe,
    )
    _out(result)
    return 0


def cmd_worker(args) -> int:
    kinds = [k.strip() for k in args.kinds.split(",") if k.strip()]
    w = worker.Worker(args.id or "cli-worker", kinds, poll_interval=args.poll)
    processed = w.run(max_jobs=args.max_jobs, idle_timeout=args.idle or None)
    _out({"processed": processed})
    return 0


def cmd_scheduler(args) -> int:
    """Run ``tick()`` once, or keep ticking until interrupted."""
    from apkplat import clock
    from apkplat.services import scheduler as scheduler_service

    if args.once:
        _out(scheduler_service.tick(actor=args.actor))
        return 0
    print(f"[scheduler] ticking every {args.interval}s (clock={clock.get_clock().name})", flush=True)
    try:
        while True:
            outcome = scheduler_service.tick(actor=args.actor)
            if outcome["triggered"]:
                print(f"[scheduler] {json.dumps(outcome['outcomes'], ensure_ascii=False)}", flush=True)
            clock.sleep(args.interval)
    except KeyboardInterrupt:
        print("[scheduler] stopped", flush=True)
        return 0


def cmd_periodic(args) -> int:
    from apkplat.services import scheduler as scheduler_service

    if args.action == "list":
        _out({"schedules": scheduler_service.list_schedules(args.project)})
    elif args.action == "runs":
        _out({"runs": scheduler_service.runs(args.schedule), "attempts": scheduler_service.attempts(args.schedule)})
    else:
        _out({"unsupported": args.action})
        return 2
    return 0


def cmd_serve(args) -> int:
    import uvicorn

    from apkplat.api.app import create_app

    db.migrate()
    uvicorn.run(create_app(), host=args.host, port=args.port, log_level="info")
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="apkplat", description="APK analysis platform operator CLI")
    sub = parser.add_subparsers(dest="command", required=True)

    sub.add_parser("init", help="create directories and apply migrations").set_defaults(func=cmd_init)
    sub.add_parser("versions", help="probe the project toolchain").set_defaults(func=cmd_versions)

    p = sub.add_parser("create", help="ingest an APK and enqueue the static pipeline")
    p.add_argument("--storage-root", default=None, help="absolute directory that owns this project")
    p = sub.add_parser("resume", help="reclaim leases and re-publish unfinished work")
    p.add_argument("project_id")
    p.set_defaults(func=cmd_resume)
    p.add_argument("--name", required=True)
    p.add_argument("--apk", required=True)
    p.add_argument("--goal", default=None)
    p.add_argument("--policy", default="default")
    p.set_defaults(func=cmd_create)

    sub.add_parser("list", help="list projects").set_defaults(func=cmd_list)

    p = sub.add_parser("show", help="show one project")
    p.add_argument("project_id")
    p.set_defaults(func=cmd_show)

    p = sub.add_parser("verify", help="re-hash artifacts and evidence excerpts")
    p.add_argument("project_id")
    p.set_defaults(func=cmd_verify)

    p = sub.add_parser("report", help="render the Markdown report")
    p.add_argument("project_id")
    p.add_argument("--task-id", default=None)
    p.set_defaults(func=cmd_report)

    p = sub.add_parser("search", help="full-text search the code index")
    p.add_argument("project_id")
    p.add_argument("query")
    p.add_argument("--kind", choices=["class", "method", "field"], default=None)
    p.add_argument("--limit", type=int, default=25)
    p.set_defaults(func=cmd_search)

    p = sub.add_parser("method", help="print one method body")
    p.add_argument("project_id")
    p.add_argument("class_name")
    p.add_argument("method")
    p.set_defaults(func=cmd_method)

    p = sub.add_parser("packages", help="list indexed packages")
    p.add_argument("project_id")
    p.set_defaults(func=cmd_packages)

    p = sub.add_parser("evidence", help="list evidence rows")
    p.add_argument("project_id")
    p.set_defaults(func=cmd_evidence)

    sub.add_parser("board", help="kanban board").set_defaults(func=cmd_board)

    p = sub.add_parser("queue", help="queue statistics")
    p.add_argument("--reclaim", action="store_true", help="reclaim expired leases first")
    p.set_defaults(func=cmd_queue)

    p = sub.add_parser("job-reset", help="put one job back to PENDING (audited)")
    p.add_argument("job_id")
    p.add_argument("--reason", default="operator reset")
    p.set_defaults(func=cmd_job_reset)

    p = sub.add_parser("worker", help="run the outbox worker")
    p.add_argument("--kinds", default=",".join(worker.HANDLERS))
    p.add_argument("--once", action="store_true")
    p.add_argument("--max-jobs", type=int, default=None)
    p.add_argument("--idle", type=float, default=3.0, help="stop after N idle seconds (0 disables)")
    p.add_argument("--poll", type=float, default=1.0)
    p.add_argument("--id", default=None)
    p.set_defaults(func=cmd_worker)

    p = sub.add_parser("dynamic", help="run a dynamic session on the device pool")
    p.add_argument("project_id")
    p.add_argument("--task", default=None, help="existing task id (a new one is created when omitted)")
    p.add_argument("--device", default=None, help="device id (any idle device when omitted)")
    p.add_argument("--transport", default=None, choices=["adb", "sim"], help="adb (default) or the simulated device")
    p.add_argument("--unplug", default=None, help="sim transport only: drop the cable on this command fragment")
    p.add_argument("--observe", type=int, default=None, help="seconds to let the app run before reading logcat")
    p.set_defaults(func=cmd_dynamic)

    p = sub.add_parser("scheduler", help="tick the periodic scheduler (P6)")
    p.add_argument("--once", action="store_true", help="one tick and exit")
    p.add_argument("--interval", type=float, default=60.0, help="seconds between ticks when looping")
    p.add_argument("--actor", default="scheduler-cli")
    p.set_defaults(func=cmd_scheduler)

    p = sub.add_parser("periodic", help="inspect periodic schedules and their runs")
    p.add_argument("action", choices=["list", "runs"], nargs="?", default="list")
    p.add_argument("project_id", nargs="?", default=None, help="project id for `list`")
    p.add_argument("--schedule", default=None, help="periodic job id for `runs`")
    p.set_defaults(func=cmd_periodic)

    p = sub.add_parser("serve", help="run the HTTP API")
    p.add_argument("--host", default=settings.host)
    p.add_argument("--port", type=int, default=settings.port)
    p.set_defaults(func=cmd_serve)
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if args.command == "worker" and getattr(args, "once", False) and args.max_jobs is None:
        args.max_jobs = 0
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
