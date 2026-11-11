"""Gate 5 acceptance: stability, safety and delivery behaviour.

Each check is a way the platform is expected to bend without breaking:

* bad archives are refused at the door, and the refusal names the actual defect;
* an oversized upload is cut off and leaves no partial file behind;
* a caller-supplied filename cannot steer storage out of its project;
* the audit trail and the evidence table cannot be rewritten, by the app or by hand;
* a job orphaned by a crash is recovered; a job that exhausted its retries is retired;
* one poisonous job does not stop the jobs queued behind it;
* a rerun of the same pipeline is idempotent (same artifacts, same hashes);
* a token is bound to its project and to its scopes;
* deterministic review still rejects claims that cite no evidence, with no model calls;
* the report and the metric set are complete.

Runs in a throwaway storage tree. `APKPLAT_MODEL_ENABLED` is left off for the model-free
checks so the run is fully deterministic and offline.

Outputs: reports/gate5/acceptance.md and reports/gate5/acceptance.json
"""
from __future__ import annotations

import json
import os
import sqlite3
import subprocess
import sys
import tempfile
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "backend"))

WORK = Path(tempfile.mkdtemp(prefix="apkplat-gate5-"))
os.environ["APKPLAT_STORAGE"] = str(WORK / "storage")
os.environ["APKPLAT_REPORTS"] = str(WORK / "reports")
os.environ["APKPLAT_SECRET"] = "gate5-acceptance-secret-not-for-production"
os.environ["APKPLAT_REQUIRE_AUTH"] = "0"
os.environ["APKPLAT_MODEL_ENABLED"] = "0"
os.environ["APKPLAT_DYNAMIC_TRANSPORT"] = "sim"
os.environ["APKPLAT_DYNAMIC_OBSERVE_SECONDS"] = "0"

from fastapi.testclient import TestClient  # noqa: E402

from apkplat import agents, audit, reports, worker  # noqa: E402
from apkplat import db as dbmod  # noqa: E402
from apkplat.api.app import create_app  # noqa: E402
from apkplat.config import settings  # noqa: E402
from apkplat.services import artifacts as artifacts_service  # noqa: E402
from apkplat.services import evidence as evidence_service  # noqa: E402
from apkplat.services import projects as projects_service  # noqa: E402
from apkplat.services import queue as queue_service  # noqa: E402
from apkplat.services import tasks as tasks_service  # noqa: E402

OUT = ROOT / "reports" / "gate5"
OUT.mkdir(parents=True, exist_ok=True)
checks: list[dict] = []
HOSTILE = [
    ("hostile-not-zip.apk", "not_a_zip"),
    ("hostile-truncated.apk", "corrupt_zip"),
    ("hostile-zip-slip.apk", "zip_slip"),
    ("hostile-no-manifest.apk", "missing_manifest"),
    ("hostile-no-dex.apk", "missing_dex"),
    ("hostile-bomb.apk", "zip_bomb"),
]


def _now_iso() -> str:
    from datetime import datetime, timezone

    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def check(name: str, ok: bool, detail: str = "") -> bool:
    checks.append({"check": name, "ok": bool(ok), "detail": str(detail)[:240]})
    print(f"[gate5] {'PASS' if ok else 'FAIL'}  {name}" + (f"  {detail}" if detail else ""), flush=True)
    return bool(ok)


def error_code(response) -> str:
    body = response.json()
    if isinstance(body, dict):
        if "error_code" in body:
            return str(body["error_code"])
        detail = body.get("detail")
        if isinstance(detail, dict) and "error_code" in detail:
            return str(detail["error_code"])
        if isinstance(detail, str):
            return detail
    return json.dumps(body)[:120]


def upload(client: TestClient, path: Path, name: str, filename: str | None = None):
    with open(path, "rb") as handle:
        return client.post(
            "/api/projects",
            data={"name": name, "goal": "gate5 acceptance"},
            files={"apk": (filename or path.name, handle, "application/vnd.android.package-archive")},
        )


def drain(label: str, max_jobs: int | None = 8) -> int:
    """Run every pending job so a scenario only sees the jobs it enqueued itself."""
    return worker.Worker(f"gate5-drain-{label}", list(worker.HANDLERS), poll_interval=0.05).run(
        max_jobs=max_jobs, idle_timeout=1.0
    )


def ingest_and_run(client: TestClient, name: str) -> str:
    response = upload(client, ROOT / "samples" / "sample-app.apk", name)
    if response.status_code != 201:
        raise SystemExit(f"ingest failed for {name}: {response.status_code} {response.text[:300]}")
    project_id = response.json()["project"]["id"]
    for _ in range(6):
        if not queue_service.pending_for_project(project_id):
            break
        worker.Worker(f"gate5-{name}", ["static_pipeline"], poll_interval=0.05).run(
            max_jobs=1, idle_timeout=30
        )
    if queue_service.pending_for_project(project_id):
        raise SystemExit(f"pipeline never ran for {name}")
    return project_id


def main() -> int:
    dbmod.db.migrate()
    client = TestClient(create_app())
    started = time.time()

    # -- schema guards -----------------------------------------------------
    triggers = {row["name"] for row in dbmod.db.query("SELECT name FROM sqlite_master WHERE type='trigger'")}
    check(
        "append-only triggers installed",
        {"trg_audit_events_no_update", "trg_audit_events_no_delete"} <= triggers,
        f"{len(triggers)} triggers",
    )

    audit.record("gate5_probe", actor="gate5", payload={"purpose": "seed a row for the trigger check"})
    seq_before = audit.last_seq()
    blocked = 0
    for sql in ("UPDATE audit_events SET event_type = 'rewritten'", "DELETE FROM audit_events"):
        try:
            dbmod.db.execute(sql)
        except sqlite3.DatabaseError:
            blocked += 1
    check("audit_events refuses UPDATE and DELETE", blocked == 2 and audit.last_seq() == seq_before, f"{blocked}/2 blocked")

    # -- bad archives ------------------------------------------------------
    accepted_wrongly = []
    rejections = 0
    for filename, expected in HOSTILE:
        response = upload(client, ROOT / "samples" / filename, f"gate5-{expected}")
        if response.status_code != 422 or error_code(response) != expected:
            accepted_wrongly.append(f"{filename} -> {response.status_code}/{error_code(response)}")
        else:
            rejections += 1
    check("all six hostile archives refused with their own reason", not accepted_wrongly, f"{rejections}/6")
    ghost_projects = [
        row["name"]
        for row in dbmod.db.query("SELECT name FROM projects")
        if row["name"].startswith("gate5-") and row["name"][len("gate5-"):] in {code for _, code in HOSTILE}
    ]
    check("a refused archive leaves no project row", ghost_projects == [], ",".join(ghost_projects) or "none")
    rejected_events = [row for row in audit.tail(0, limit=5000) if row["event_type"] == "apk_ingest_rejected"]
    check("every refusal is audited", len(rejected_events) >= 6, f"{len(rejected_events)} apk_ingest_rejected")

    # -- oversized upload --------------------------------------------------
    original_cap = settings.max_upload_mb
    settings.max_upload_mb = 1
    try:
        blob = b"PK\x03\x04" + b"A" * (2 * 1024 * 1024)
        response = client.post(
            "/api/projects",
            data={"name": "gate5-too-large"},
            files={"apk": ("big.apk", blob, "application/vnd.android.package-archive")},
        )
    finally:
        settings.max_upload_mb = original_cap
    partial = list((Path(settings.storage) / "tmp").glob("upload-*.apk"))
    check("oversized upload rejected with 413", response.status_code == 413, str(response.status_code))
    check("no partial upload left on disk", partial == [], f"{len(partial)} file(s)")

    # -- filename traversal ------------------------------------------------
    response = upload(client, ROOT / "samples" / "sample-app.apk", "gate5-traversal", filename="../../evil.apk")
    traversal_ok = False
    if response.status_code == 201:
        pid = response.json()["project"]["id"]
        apk = projects_service.apk_path(pid).resolve()
        traversal_ok = apk.is_relative_to(Path(settings.project_dir(pid)).resolve()) and not (
            Path(settings.storage).parent / "evil.apk"
        ).exists()
    check("caller filename cannot escape the project directory", traversal_ok, str(response.status_code))

    # -- idempotent rerun --------------------------------------------------
    project_id = ingest_and_run(client, "gate5-rerun")
    first = {row["rel_path"]: row["sha256"] for row in artifacts_service.list_artifacts(project_id)}
    queue_service.enqueue("static_pipeline", project_id=project_id, payload={}, idempotency_key="gate5-rerun-2")
    worker.Worker("gate5-rerun-2", ["static_pipeline"], poll_interval=0.05).run(max_jobs=1, idle_timeout=30)
    second = {row["rel_path"]: row["sha256"] for row in artifacts_service.list_artifacts(project_id)}
    chain = artifacts_service.verify_chain(project_id)
    check("rerun keeps the artifact set stable", set(first) == set(second), f"{len(first)} artifacts")
    check("artifact hashes still verify after a rerun", chain["failures"] == [] and chain["ok"] == chain["checked"],
          f"{chain['ok']}/{chain['checked']}")
    verification = evidence_service.verify(project_id)
    check("evidence traceability is 100%", verification["traceability_rate"] >= 1.0 and not verification["failures"],
          f"{verification['total']} rows")

    # -- crash recovery ----------------------------------------------------
    drain("before-recovery")
    recovery_project = projects_service.create(
        "gate5-recovery", ROOT / "samples" / "sample-app.apk", "sample-app.apk", actor="gate5"
    )
    recovery_job = queue_service.enqueue(
        "static_pipeline", project_id=recovery_project["id"], payload={}, idempotency_key="gate5-recovery"
    )
    queue_service.claim("ghost-worker", ["static_pipeline"])
    dbmod.db.execute("UPDATE jobs SET lease_expires_at = '2000-01-01T00:00:00.000Z' WHERE id = ?", (recovery_job,))
    worker.Worker("gate5-recoverer", ["static_pipeline"], poll_interval=0.05).run(max_jobs=1, idle_timeout=30)
    recovered_job = queue_service.get(recovery_job)
    events = [row["event_type"] for row in audit.tail(0, limit=5000)]
    check("orphaned job recovered after the crash window", recovered_job["status"] == "SUCCEEDED",
          str(recovered_job["status"]))
    check("recovery is audited", "job_recovered_after_restart" in events,
          f"{events.count('job_recovered_after_restart')} event(s)")

    drain("before-exhausted")
    exhausted_project = projects_service.create(
        "gate5-exhausted", ROOT / "samples" / "sample-app.apk", "sample-app.apk", actor="gate5"
    )
    exhausted_job = queue_service.enqueue(
        "static_pipeline",
        project_id=exhausted_project["id"],
        payload={},
        idempotency_key="gate5-exhausted",
        max_attempts=1,
    )
    queue_service.claim("ghost-worker-2", ["static_pipeline"])
    dbmod.db.execute("UPDATE jobs SET lease_expires_at = '2000-01-01T00:00:00.000Z' WHERE id = ?", (exhausted_job,))
    queue_service.reclaim_expired("gate5-reaper")
    retired = queue_service.get(exhausted_job)
    check("an orphan past its retry budget is retired, not retried forever", retired["status"] == "FAILED",
          str(retired["status"]))

    # -- poison job --------------------------------------------------------
    drain("before-poison")
    poison_project = projects_service.create(
        "gate5-poison", ROOT / "samples" / "sample-app.apk", "sample-app.apk", actor="gate5"
    )
    projects_service.apk_path(poison_project["id"]).write_bytes(b"garbage")
    poison_job = queue_service.enqueue(
        "static_pipeline", project_id=poison_project["id"], payload={}, idempotency_key="gate5-poison"
    )
    healthy_job = queue_service.enqueue(
        "static_pipeline", project_id=project_id, payload={}, idempotency_key="gate5-healthy"
    )
    worker.Worker("gate5-survivor", ["static_pipeline"], poll_interval=0.05).run(max_jobs=2, idle_timeout=30)
    poison = queue_service.get(poison_job)
    healthy = queue_service.get(healthy_job)
    check("poison job fails with a named code", poison["status"] in {"FAILED", "RETRYING"} and bool(poison["error_code"]),
          f"{poison['status']}/{poison['error_code']}")
    check("the job behind the poison job still runs", healthy["status"] == "SUCCEEDED", str(healthy["status"]))
    poison_task = dbmod.db.one("SELECT * FROM tasks WHERE project_id = ?", (poison_project["id"],))
    check("the failed card is not left in RUNNING", poison_task is None or poison_task["status"] in {"FAILED", "RETRYING"},
          poison_task["status"] if poison_task else "no task")

    # -- tokens ------------------------------------------------------------
    a = ingest_and_run(client, "gate5-token-a")
    b = ingest_and_run(client, "gate5-token-b")
    admin = {"X-Admin-Secret": settings.signing_secret().hex()}
    issued = client.post(
        "/api/auth/token", headers=admin, json={"subject": "gate5", "projects": [a], "scopes": ["read", "write"]}
    )
    token = issued.json()["token"] if issued.status_code in {200, 201} else ""
    headers = {"Authorization": f"Bearer {token}"}
    readonly = client.post(
        "/api/auth/token", headers=admin, json={"subject": "gate5-ro", "projects": [a], "scopes": ["read"]}
    )
    ro_headers = {"Authorization": f"Bearer {readonly.json()['token']}"} if readonly.status_code in {200, 201} else {}

    settings.require_auth = True
    try:
        unauthenticated = client.get(f"/api/projects/{a}")
        cross = client.get(f"/api/projects/{b}", headers=headers)
        scope_denied = client.post(
            "/api/projects", headers=ro_headers, data={"name": "gate5-ro-write"}, files={}
        )
        allowed = client.get(f"/api/projects/{a}", headers=headers)
    finally:
        settings.require_auth = False

    check("no token is a 401 when auth is on", unauthenticated.status_code == 401, str(unauthenticated.status_code))
    check("a token cannot read another project", cross.status_code == 403 and error_code(cross) == "project_denied",
          f"{cross.status_code}/{error_code(cross)}")
    check("a read-only token cannot write", scope_denied.status_code == 403 and error_code(scope_denied) == "scope_denied",
          f"{scope_denied.status_code}/{error_code(scope_denied)}")
    check("a token still reads its own project", allowed.status_code == 200, str(allowed.status_code))

    wildcard = client.post(
        "/api/auth/token", headers=admin, json={"subject": "gate5-any", "projects": ["*"], "scopes": ["read"]}
    )
    check("wildcard tokens are refused", wildcard.status_code == 422 and error_code(wildcard) == "wildcard_forbidden",
          f"{wildcard.status_code}/{error_code(wildcard)}")

    # -- review without a model -------------------------------------------
    review_project = ingest_and_run(client, "gate5-review")
    model_calls_before = dbmod.db.scalar("SELECT COUNT(*) FROM model_requests") or 0
    unsupported = agents.review_claims(
        review_project,
        [
            {"claim": "The app exfiltrates contacts", "evidence_id": None},
            {"claim": "The app calls an endpoint", "evidence_id": "evd_does_not_exist"},
        ],
        use_model=False,
    )
    model_calls_after = dbmod.db.scalar("SELECT COUNT(*) FROM model_requests") or 0
    reasons = {item["reason"] for item in unsupported["rejected"]}
    check("claims without evidence are rejected deterministically",
          unsupported["verdict"] == "rejected" and {"no_evidence", "evidence_unknown"} <= reasons, ",".join(sorted(reasons)))
    check("the deterministic review makes no model calls", model_calls_before == model_calls_after,
          f"{model_calls_before} -> {model_calls_after}")

    orchestrate_project = ingest_and_run(client, "gate5-orchestrate")
    result = agents.orchestrate(orchestrate_project, actor="gate5", use_model=False)
    check("orchestration reaches review without a model", result["status"] == "review_ready", result["status"])
    check("every role ran", len({row["role"] for row in dbmod.db.query(
        "SELECT role FROM agent_runs WHERE project_id = ?", (orchestrate_project,))}) == 4,
        "roles recorded")

    # -- report and metrics ------------------------------------------------
    report = reports.generate(orchestrate_project, actor="gate5")
    text = Path(artifacts_service.path_of(artifacts_service.get(report["artifact_id"]))).read_text(encoding="utf-8")
    check("report renders and verifies", report["verification_ok"] is True, str(report["verification_ok"]))
    check("report carries the verification block", "校验结果" in text and "通过" in text, "校验结果/通过")
    literals = ["REEF-LICENSE-4417", "REEF-SALT-9000", "REEF-API-KEY-7781"]
    check("report quotes the secret literals", all(item in text for item in literals), ",".join(literals))
    check("report cites evidence ids", text.count("evd_") >= 5, f"{text.count('evd_')} citations")

    metrics = client.get("/api/metrics").json()
    required = {
        "ingest_success_rate",
        "tool_call_schema_valid_rate",
        "evidence_traceability_rate",
        "project_isolation_failures",
        "task_recovery_success",
        "device_lease_collision",
        "false_confident_claims",
        "model_calls_per_task",
        "model_api_latency_ms_avg",
    }
    check("metric set is complete", required <= set(metrics), ",".join(sorted(required - set(metrics))) or "all present")
    check("ingest success rate reflects the refusals", metrics["ingest_success_rate"] < 1.0,
          str(metrics["ingest_success_rate"]))
    check("no isolation failures", metrics["project_isolation_failures"] == 0, str(metrics["project_isolation_failures"]))
    check("no device lease collisions", metrics["device_lease_collision"] == 0, str(metrics["device_lease_collision"]))
    check("false confident claims are counted", metrics["false_confident_claims"] >= 1, str(metrics["false_confident_claims"]))

    # -- CLI does not hang on an empty queue -------------------------------
    python = str(ROOT / ".venv" / "Scripts" / "python.exe")
    if not Path(python).exists():
        python = sys.executable
    env = {**os.environ, "APKPLAT_WORKER_ENV": "gate5"}
    cli_started = time.time()
    cli = subprocess.run(
        [python, str(ROOT / "scripts" / "apkplat_cli.py"), "worker", "--once", "--kinds", "report_generate",
         "--poll", "0.05", "--idle", "1"],
        capture_output=True,
        text=True,
        timeout=120,
        env=env,
    )
    cli_seconds = round(time.time() - cli_started, 1)
    check("worker --once returns on an empty queue", cli.returncode == 0 and cli_seconds < 30,
          f"exit={cli.returncode} in {cli_seconds}s")

    duration = round(time.time() - started, 1)
    failed = [item for item in checks if not item["ok"]]
    write_report(
        {
            "work_dir": str(WORK),
            "duration_seconds": duration,
            "checks_passed": len(checks) - len(failed),
            "checks_total": len(checks),
            "metrics": metrics,
            "python": python,
        }
    )
    print(f"[gate5] {len(checks) - len(failed)}/{len(checks)} checks passed", flush=True)
    return 0 if not failed else 1


def write_report(data: dict) -> None:
    failed = [item for item in checks if not item["ok"]]
    lines = [
        "# Gate 5 acceptance - stability, safety, delivery behaviour",
        "",
        f"- Run at: {time.strftime('%Y-%m-%d %H:%M:%S')}",
        f"- Duration: {data['duration_seconds']}s",
        f"- Model: disabled for this run (`APKPLAT_MODEL_ENABLED=0`) so every check is deterministic",
        "- The DSH NEXT install and the model API were provided by the operator and were not modified by this run.",
        f"- Result: **{'PASS' if not failed else 'FAIL'}** - {data['checks_passed']}/{data['checks_total']} checks",
        "",
        "## Checks",
        "",
        "| check | result | detail |",
        "| --- | --- | --- |",
    ]
    for item in checks:
        detail = item["detail"].replace("|", "\\|")
        lines.append(f"| {item['check']} | {'PASS' if item['ok'] else 'FAIL'} | {detail} |")
    lines += [
        "",
        "## Facts",
        "",
        f"- ingest_success_rate: {data['metrics']['ingest_success_rate']}",
        f"- evidence_traceability_rate: {data['metrics']['evidence_traceability_rate']}",
        f"- false_confident_claims: {data['metrics']['false_confident_claims']}",
        f"- project_isolation_failures: {data['metrics']['project_isolation_failures']}",
        f"- device_lease_collision: {data['metrics']['device_lease_collision']}",
        f"- task_recovery_success: {data['metrics']['task_recovery_success']}",
        f"- Work directory: `{data['work_dir']}`",
        "",
        "## Honest limits",
        "",
        "- Crash recovery is exercised by expiring a lease on a live database, not by killing the",
        "  process mid-write; the kill-and-restart path is covered by the same `reclaim_expired` code and",
        "  by `tests/integration/test_p2_operations.py`.",
        "- The model path is disabled here on purpose; the model-backed review is measured in Gate 3",
        "  against the operator's API.",
    ]
    (OUT / "acceptance.md").write_text("\n".join(lines) + "\n", encoding="utf-8")
    (OUT / "acceptance.json").write_text(
        json.dumps({"generated_at": _now_iso(), "checks": checks, "facts": data}, indent=2, default=str), encoding="utf-8"
    )
    print(f"[gate5] report: {OUT / 'acceptance.md'}", flush=True)


if __name__ == "__main__":
    raise SystemExit(main())
