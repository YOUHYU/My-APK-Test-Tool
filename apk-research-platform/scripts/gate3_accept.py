"""Gate 3 acceptance: four agent roles against the *real* model API.

This script is evidence, not a demo. It runs the platform in-process against a
throwaway storage tree, dispatches the orchestrator with ``use_model=True`` so the
pre-provisioned model endpoint is actually called, and then checks the acceptance

* four roles present in ``agent_runs`` (orchestrator, static, reviewer, reporter);
* the reviewer accepted every claim, and the report's verification block passes;
* ``false_confident_claims`` behaves: an injected unevidenced claim is refused and the
  task returns to RUNNING;
* every claim in the report traces to an evidence row (traceability rate 1.0).

Outputs: reports/gate3/acceptance.md and reports/gate3/acceptance.json
"""
from __future__ import annotations

import json
import os
import shutil
import sys
import tempfile
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "backend"))

WORK = Path(tempfile.mkdtemp(prefix="apkplat-gate3-"))
os.environ["APKPLAT_STORAGE"] = str(WORK / "storage")
os.environ["APKPLAT_REPORTS"] = str(WORK / "reports")
os.environ["APKPLAT_SECRET"] = "gate3-acceptance-secret-not-for-production"
os.environ["APKPLAT_REQUIRE_AUTH"] = "0"

from fastapi.testclient import TestClient  # noqa: E402

from apkplat import agents, llm  # noqa: E402
from apkplat import db as dbmod  # noqa: E402
from apkplat.api.app import create_app  # noqa: E402
from apkplat.services import evidence as evidence_service  # noqa: E402
from apkplat.services import projects as projects_service  # noqa: E402
from apkplat.services import queue, tasks  # noqa: E402

OUT = ROOT / "reports" / "gate3"
OUT.mkdir(parents=True, exist_ok=True)
checks: list[dict] = []


def _now_iso() -> str:
    from datetime import datetime, timezone

    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def check(name: str, ok: bool, detail: str = "") -> bool:
    checks.append({"check": name, "ok": bool(ok), "detail": detail})
    print(f"[gate3] {'PASS' if ok else 'FAIL'}  {name}" + (f"  {detail}" if detail else ""))
    return bool(ok)


def main() -> int:
    dbmod.db.migrate()
    app = create_app()
    client = TestClient(app)
    model = llm.status()
    print(f"[gate3] model: {model}")
    if not check("model endpoint reachable", model.get("enabled", False), str(model.get("base_url"))):
        write_report(model, None)
        return 1

    with open(ROOT / "samples" / "sample-app.apk", "rb") as handle:
        resp = client.post(
            "/api/projects",
            data={"name": "gate3-live", "goal": "prove the agent chain against the real model"},
            files={"apk": ("sample-app.apk", handle, "application/vnd.android.package-archive")},
        )
    if not check("apk ingested", resp.status_code == 201, resp.text[:200]):
        write_report(model, None)
        return 1
    project_id = resp.json()["project"]["id"]
    job_id = resp.json()["job_id"]
    print(f"[gate3] project={project_id} job={job_id}")

    from apkplat.worker import Worker

    started = time.time()
    Worker("gate3-worker", ["static_pipeline"], poll_interval=0.1).run(max_jobs=1)
    check("static pipeline job succeeded", queue.get(job_id)["status"] == "SUCCEEDED", f"{queue.get(job_id)['status']}")
    check("static pipeline produced evidence", len(evidence_service.list_evidence(project_id)) >= 8)

    outcome = agents.orchestrate(project_id, use_model=True)
    duration = round(time.time() - started, 1)
    print(f"[gate3] orchestrate status={outcome.get('status')} in {duration}s")
    check("orchestrator reached review_ready", outcome.get("status") == "review_ready", str(outcome.get("status")))

    runs = client.get(f"/api/projects/{project_id}/agents/runs").json()["runs"]
    roles = {run["role"] for run in runs}
    check("four roles recorded", {"orchestrator", "static", "reviewer", "reporter"} <= roles, ",".join(sorted(roles)))
    check("every run terminated", all(run["ended_at"] for run in runs), f"{len(runs)} runs")

    model_rows = dbmod.db.query("SELECT * FROM model_requests WHERE project_id = ?", (project_id,))
    ok_rows = [row for row in model_rows if row["status"] == "ok"]
    latencies = [int(row["latency_ms"] or 0) for row in ok_rows]
    check("model API actually called", bool(ok_rows), f"{len(ok_rows)} ok of {len(model_rows)} requests")
    if latencies:
        check(
            "model latency recorded",
            max(latencies) < 180_000,
            f"avg {round(sum(latencies) / len(latencies))}ms max {max(latencies)}ms",
        )

    verification = evidence_service.verify(project_id)
    check(
        "evidence traceability is 100%",
        not verification["failures"] and verification["traceability_rate"] >= 1.0,
        f"{verification['total']} rows, rate {verification['traceability_rate']}",
    )

    # The reviewer must refuse a claim the static agent could not back with evidence.
    task = tasks.create(project_id, role="static", title="gate3 return test", actor="agent")
    tasks.update(task["id"], actor="agent", status="RUNNING")
    tasks.update(task["id"], actor="system", status="REVIEW")
    good = agents.claims_from_evidence(project_id)[0]
    rejected = agents.review_task(
        project_id,
        task["id"],
        claims=[good, {"claim": "the app phones home to 8.8.8.8 with contacts", "evidence_id": None}],
        use_model=False,
    )
    check("reviewer refused the unevidenced claim", rejected["verdict"] == "rejected", rejected["rejected"][0]["reason"])
    check("returned task is back in RUNNING", tasks.get(task["id"])["status"] == "RUNNING")

    metrics = client.get("/api/metrics").json()
    check("false_confident_claims counts the refusal", metrics["false_confident_claims"] >= 1,
          str(metrics["false_confident_claims"]))
    check("no isolation failures", metrics["project_isolation_failures"] == 0)

    report_path = None
    report_row = dbmod.db.one(
        "SELECT * FROM artifacts WHERE project_id = ? AND kind = 'report' ORDER BY created_at DESC LIMIT 1", (project_id,)
    )
    if report_row:
        report_path = projects_service.artifact_path(report_row["rel_path"])
        text = Path(report_path).read_text(encoding="utf-8", errors="replace")
        check("report verification block passes", "证据可追溯：PASS" in text and "产物链：PASS" in text)
        check("report cites evidence ids", text.count("`evd_") >= 5, f"{text.count('`evd_')} citations")
        for literal in ("REEF-LICENSE-4417", "REEF-SALT-9000", "REEF-API-KEY-7781"):
            check(f"report contains {literal}", literal in text)
    else:
        check("report artifact exists", False)

    write_report(model, {
        "project_id": project_id,
        "job_id": job_id,
        "duration_s": duration,
        "roles": sorted(roles),
        "model_requests": len(model_rows),
        "model_ok": len(ok_rows),
        "model_latency_avg_ms": round(sum(latencies) / len(latencies)) if latencies else None,
        "evidence_rows": verification["total"],
        "traceability_rate": verification["traceability_rate"],
        "metrics": metrics,
        "report_path": str(report_path) if report_path else None,
        "work_dir": str(WORK),
    })
    failed = [c for c in checks if not c["ok"]]
    print(f"[gate3] {len(checks) - len(failed)}/{len(checks)} checks passed")
    return 0 if not failed else 1


def write_report(model: dict, data: dict | None) -> None:
    failed = [c for c in checks if not c["ok"]]
    lines = [
        "# Gate 3 acceptance - multi-agent chain",
        "",
        f"- Run at: {time.strftime('%Y-%m-%d %H:%M:%S')}",
        f"- Model endpoint: `{model.get('base_url')}` | model `{model.get('model')}` / key source `{model.get('key_source')}`",
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
    if data:
        lines += [
            "",
            "## Facts",
            "",
            f"- Project: `{data['project_id']}`",
            f"- Orchestrator wall time: {data['duration_s']}s",
            f"- Roles seen: {', '.join(data['roles'])}",
            f"- Model requests: {data['model_requests']} ({data['model_ok']} ok, avg {data['model_latency_avg_ms']}ms)",
            f"- Evidence rows: {data['evidence_rows']} / traceability {data['traceability_rate']}",
            f"- Report: `{data['report_path']}`",
            "",
            "```json",
            json.dumps(data["metrics"], indent=2)[:4000],
            "```",
        ]
    (OUT / "acceptance.md").write_text("\n".join(lines) + "\n", encoding="utf-8")
    (OUT / "acceptance.json").write_text(json.dumps({"generated_at": _now_iso(), "checks": checks, "data": data}, indent=2), encoding="utf-8")
    print(f"[gate3] wrote {OUT / 'acceptance.md'}")


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    finally:
        if os.environ.get("APKPLAT_KEEP_GATE_TMP") != "1":
            shutil.rmtree(WORK, ignore_errors=True)
