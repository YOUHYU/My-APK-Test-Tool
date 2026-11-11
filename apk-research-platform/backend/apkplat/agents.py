"""Multi-agent layer: orchestrator, static analyst, reviewer and reporter.

The rule that shapes this module is the one the acceptance gate cares about: **a claim
without evidence never survives review**. Two mechanisms enforce it, in this order:

1. a deterministic gate - every claim must name an evidence row that belongs to this
   project, re-hashes correctly, and whose excerpt is still verbatim inside its artifact;
2. an advisory model pass - for claims that pass the gate, the reviewer may still say
   "the excerpt does not support this sentence", which also returns the task.

Rejections are audited as ``review_returned_no_evidence`` (counted by the
``false_confident_claims`` indicator) and move the task back to RUNNING so the agent
has to do the work again. No agent can put a task in DONE: only a human (or the
reviewer role with an approval) may.
"""
from __future__ import annotations

import json
from typing import Any, Callable

from . import audit, llm, pipeline_static, reports
from .config import settings
from .db import db, utcnow
from .services import evidence as evidence_service
from .services import tasks as tasks_service
from .util import dumps, new_id

ROLE_ORCHESTRATOR = "orchestrator"
ROLE_STATIC = "static"
ROLE_REVIEWER = "reviewer"
ROLE_REPORTER = "reporter"

Predictor = Callable[..., dict]


# -- agent run bookkeeping ---------------------------------------------------
def _start_run(project_id: str, task_id: str | None, role: str, notes: str | None = None) -> str:
    run_id = new_id("run_")
    db.execute(
        "INSERT INTO agent_runs(id, project_id, task_id, role, dsh_session_ref, model_id, started_at, ended_at,"
        " status, notes) VALUES(?,?,?,?,?,?,?,?,?,?)",
        (run_id, project_id, task_id, role, None, llm.status().get("model"), utcnow(), None, "running", notes),
    )
    audit.record(
        "agent_run_started",
        project_id=project_id,
        task_id=task_id,
        actor=f"agent:{role}",
        payload={"run_id": run_id, "role": role},
    )
    return run_id


def _end_run(run_id: str, status: str, notes: str | None = None) -> None:
    row = db.one("SELECT project_id, task_id FROM agent_runs WHERE id = ?", (run_id,))
    db.execute("UPDATE agent_runs SET ended_at = ?, status = ?, notes = COALESCE(?, notes) WHERE id = ?",
               (utcnow(), status, notes, run_id))
    audit.record(
        "agent_run_finished",
        project_id=row["project_id"] if row else None,
        task_id=row["task_id"] if row else None,
        actor="agent",
        payload={"run_id": run_id, "status": status},
    )


def _model_on(predictor: Predictor | None) -> bool:
    if predictor is not None:
        return True
    if not settings.model_enabled:
        return False
    try:
        return bool(llm.resolve()["enabled"])
    except llm.ModelError:
        return False


# -- static analyst ----------------------------------------------------------
_STATIC_SYSTEM = (
    "You are the static-analysis agent of an APK research platform. You may only state facts that are "
    "backed by one of the provided evidence rows. Reply with one JSON object: "
    '{"summary": "<3 sentences>", "highlights": [{"claim": "<sentence>", "evidence_id": "<id>"}]}. '
    "Never invent ids. If you cannot back a sentence with an evidence row, leave it out."
)


def _artifacts_present(project_id: str) -> bool:
    """True when the static stage already produced its three load-bearing artifacts."""
    from .services import artifacts as artifacts_service

    kinds = {row["kind"] for row in artifacts_service.list_artifacts(project_id, limit=200)}
    return {"metadata", "findings", "index"} <= kinds


def static_analysis(
    project_id: str,
    *,
    task_id: str | None = None,
    predictor: Predictor | None = None,
    use_model: bool | None = None,
) -> dict[str, Any]:
    run_id = _start_run(project_id, task_id, ROLE_STATIC)
    try:
        existing = evidence_service.list_evidence(project_id)
        if existing and _artifacts_present(project_id):
            # Already analysed (the queue worker ran the pipeline on ingest). Re-running it
            # would rewrite the artifacts under evidence that already cites them, so the
            # static agent reuses what is on disk unless asked to start over.
            audit.record(
                "static_reused",
                project_id=project_id,
                task_id=task_id,
                actor="agent:static",
                payload={"evidence_rows": len(existing)},
            )
            summary = {"stages": ["reused"], "project_id": project_id}
        else:
            summary = pipeline_static.run(project_id, task_id=task_id)
        evidence = evidence_service.list_evidence(project_id)
        narrative = None
        wants_model = _model_on(predictor) if use_model is None else bool(use_model) and _model_on(predictor)
        if wants_model:
            narrative = _static_narrative(project_id, task_id, evidence, predictor)
        _end_run(run_id, "ok", notes=dumps({"stages": list(summary.get("stages", []))})[:2000])
        return {
            "run_id": run_id,
            "summary": summary,
            "evidence_ids": [row["id"] for row in evidence],
            "narrative": narrative,
        }
    except Exception as exc:
        _end_run(run_id, "error", notes=f"{type(exc).__name__}: {exc}"[:2000])
        raise


def _static_narrative(
    project_id: str, task_id: str | None, evidence: list[dict], predictor: Predictor | None
) -> dict[str, Any]:
    catalogue = [
        {"evidence_id": row["id"], "kind": row["kind"], "claim": row.get("claim"), "locator": row.get("locator")}
        for row in evidence[:120]
    ]
    messages = [
        {"role": "system", "content": _STATIC_SYSTEM},
        {
            "role": "user",
            "content": "Evidence rows:\n"
            + json.dumps(catalogue, ensure_ascii=False, indent=1)[:24000]
            + "\nWrite the summary and highlights.",
        },
    ]
    known = {row["id"] for row in evidence}
    raw = (
        predictor(messages, purpose="static_narrative", project_id=project_id, task_id=task_id)
        if predictor
        else llm.complete_json(
            messages,
            purpose="static_narrative",
            project_id=project_id,
            task_id=task_id,
            max_tokens=settings.model_max_tokens,
        )
    )
    highlights: list[dict] = []
    dropped: list[dict] = []
    for item in raw.get("highlights") or []:
        claim = str(item.get("claim") or "").strip()
        evidence_id = str(item.get("evidence_id") or "").strip()
        if not claim or evidence_id not in known:
            dropped.append({"claim": claim[:200], "evidence_id": evidence_id, "reason": "unknown_evidence_id"})
            continue
        highlights.append({"claim": claim, "evidence_id": evidence_id})
    for item in dropped:
        audit.record(
            "agent_claim_dropped",
            project_id=project_id,
            task_id=task_id,
            actor="agent:static",
            payload=item,
        )
    return {"summary": str(raw.get("summary") or "").strip(), "highlights": highlights, "dropped": dropped}


# -- reviewer ----------------------------------------------------------------
_REVIEW_SYSTEM = (
    "You are the reviewer agent. Each item is a claim plus a verbatim excerpt copied from the artifact it "
    "cites; the excerpt is the ground truth and the claim only restates fields that appear in it. "
    "Mark supported=true when every fact in the claim appears in the excerpt, false only when the excerpt "
    "lacks or contradicts a fact in the claim. "
    "Answer only with JSON, no analysis text: {\"verdicts\": [{\"evidence_id\": \"<id>\", \"supported\": true|false, "
    "\"reason\": \"<short>\"}]}."
)


def claims_from_evidence(project_id: str, *, task_id: str | None = None) -> list[dict]:
    rows = evidence_service.list_evidence(project_id, task_id=task_id) if task_id else evidence_service.list_evidence(project_id)
    return [
        {
            "claim": row.get("claim") or f"evidence {row['id']} ({row['kind']})",
            "evidence_id": row["id"],
            "kind": row["kind"],
            "locator": row.get("locator"),
        }
        for row in rows
    ]


def review_claims(
    project_id: str,
    claims: list[dict],
    *,
    task_id: str | None = None,
    predictor: Predictor | None = None,
    use_model: bool | None = None,
) -> dict[str, Any]:
    """Gate claims on evidence; the model may veto, never rescue, a claim."""
    verification = evidence_service.verify(project_id)
    broken = {f.get("evidence_id") for f in verification["failures"] if f.get("evidence_id")}
    by_id = {row["id"]: row for row in evidence_service.list_evidence(project_id)}

    accepted: list[dict] = []
    rejected: list[dict] = []
    for claim in claims:
        evidence_id = claim.get("evidence_id")
        if not evidence_id:
            rejected.append({**claim, "reason": "no_evidence"})
            continue
        row = by_id.get(evidence_id)
        if not row:
            rejected.append({**claim, "reason": "evidence_unknown"})
            continue
        if row["project_id"] != project_id:
            rejected.append({**claim, "reason": "evidence_cross_project"})
            continue
        if evidence_id in broken:
            rejected.append({**claim, "reason": "excerpt_not_verifiable"})
            continue
        accepted.append({**claim, "evidence": row})

    model_review = None
    want_model = _model_on(predictor) if use_model is None else bool(use_model) and _model_on(predictor)
    if accepted and want_model:
        model_review = _model_review(project_id, task_id, accepted, predictor)
        vetoed = {item["evidence_id"] for item in model_review.get("verdicts", []) if item.get("supported") is False}
        if vetoed:
            still_ok: list[dict] = []
            for claim in accepted:
                if claim["evidence_id"] in vetoed:
                    reason = next(
                        (
                            item.get("reason") or "excerpt_does_not_support_claim"
                            for item in model_review["verdicts"]
                            if item.get("evidence_id") == claim["evidence_id"]
                        ),
                        "excerpt_does_not_support_claim",
                    )
                    rejected.append({**claim, "reason": f"model_veto:{reason}"[:300]})
                else:
                    still_ok.append(claim)
            accepted = still_ok

    for claim in rejected:
        audit.record(
            "review_returned_no_evidence",
            project_id=project_id,
            task_id=task_id,
            actor="agent:reviewer",
            payload={"claim": str(claim.get("claim"))[:300], "evidence_id": claim.get("evidence_id"), "reason": claim["reason"]},
        )
    audit.record(
        "review_completed",
        project_id=project_id,
        task_id=task_id,
        actor="agent:reviewer",
        payload={
            "accepted": len(accepted),
            "rejected": len(rejected),
            "model_reviewed": bool(model_review),
        },
    )
    return {
        "project_id": project_id,
        "task_id": task_id,
        "accepted": accepted,
        "rejected": rejected,
        "verdict": "accepted" if not rejected else "rejected",
        "model_review": model_review,
        "traceability": verification["traceability_rate"],
    }


def _model_review(
    project_id: str, task_id: str | None, accepted: list[dict], predictor: Predictor | None
) -> dict:
    payload = [
        {
            "evidence_id": claim["evidence_id"],
            "claim": claim.get("claim"),
            "excerpt": (claim["evidence"].get("excerpt") or "")[:500],
        }
        for claim in accepted[:12]
    ]
    messages = [
        {"role": "system", "content": _REVIEW_SYSTEM},
        {"role": "user", "content": json.dumps({"claims": payload}, ensure_ascii=False)[:24000]},
    ]
    if predictor:
        return predictor(messages, purpose="review_verdicts", project_id=project_id, task_id=task_id)
    return llm.complete_json(
        messages, purpose="review_verdicts", project_id=project_id, task_id=task_id, max_tokens=settings.model_max_tokens
    )


def review_task(
    project_id: str,
    task_id: str,
    *,
    claims: list[dict] | None = None,
    predictor: Predictor | None = None,
    use_model: bool | None = None,
) -> dict[str, Any]:
    """Review a task in REVIEW: pass keeps it in REVIEW for a human, fail reopens it."""
    run_id = _start_run(project_id, task_id, ROLE_REVIEWER)
    try:
        task = tasks_service.get(task_id)
        if task and task["status"] != "REVIEW":
            tasks_service.update(task_id, actor="system", status="REVIEW", reason="review requested")
        result = review_claims(
            project_id,
            claims if claims is not None else claims_from_evidence(project_id, task_id=None),
            task_id=task_id,
            predictor=predictor,
            use_model=use_model,
        )
        if result["verdict"] == "rejected":
            tasks_service.update(
                task_id,
                actor="system",
                status="RUNNING",
                fields={
                    "error_code": "review_no_evidence",
                    "error_message": f"review rejected {len(result['rejected'])} unevidenced claim(s)",
                },
                reason="reviewer returned the task: claims without verifiable evidence",
            )
            _end_run(run_id, "rejected", notes=f"{len(result['rejected'])} rejected")
        else:
            _end_run(run_id, "ok", notes=f"{len(result['accepted'])} accepted")
        return result
    except Exception as exc:
        _end_run(run_id, "error", notes=f"{type(exc).__name__}: {exc}"[:2000])
        raise


# -- reporter ----------------------------------------------------------------
def report(project_id: str, *, task_id: str | None = None, use_model: bool | None = None) -> dict[str, Any]:
    run_id = _start_run(project_id, task_id, ROLE_REPORTER)
    try:
        result = reports.generate(project_id, task_id=task_id, actor="agent:reporter")
        brief = None
        wants_model = _model_on(None) if use_model is None else bool(use_model)
        if wants_model:
            brief = _report_brief(project_id, task_id)
        _end_run(run_id, "ok", notes=f"verification_ok={result.get('verification_ok')}")
        return {"run_id": run_id, **result, "brief": brief}
    except Exception as exc:
        _end_run(run_id, "error", notes=f"{type(exc).__name__}: {exc}"[:2000])
        raise


def _report_brief(project_id: str, task_id: str | None) -> dict | None:
    evidence = evidence_service.list_evidence(project_id)
    catalogue = [{"id": row["id"], "kind": row["kind"], "claim": row.get("claim")} for row in evidence[:80]]
    messages = [
        {
            "role": "system",
            "content": (
                "Write a terse executive brief for an analyst. Every sentence must be traceable to one of the "
                'evidence ids. Reply as JSON: {"brief": "<markdown>", "citations": ["<evidence id>", ...]}'
            ),
        },
        {"role": "user", "content": json.dumps(catalogue, ensure_ascii=False)[:20000]},
    ]
    try:
        raw = llm.complete_json(messages, purpose="report_brief", project_id=project_id, task_id=task_id)
    except llm.ModelError:
        return None
    known = {row["id"] for row in evidence}
    citations = [cid for cid in raw.get("citations") or [] if cid in known]
    return {"brief": str(raw.get("brief") or "")[:8000], "citations": citations}


# -- orchestrator ------------------------------------------------------------
def orchestrate(
    project_id: str,
    *,
    actor: str = "agent",
    predictor: Predictor | None = None,
    use_model: bool | None = None,
) -> dict[str, Any]:
    """Drive one project through static ->review ->report, one audited task each."""
    from .services import projects as projects_service

    project = projects_service.get(project_id)
    if not project:
        raise KeyError(project_id)
    run_id = _start_run(project_id, None, ROLE_ORCHESTRATOR)
    created = {
        "static": tasks_service.create(
            project_id, title="static analysis", role=ROLE_STATIC, actor=actor, goal="index the APK and collect evidence"
        ),
        "review": tasks_service.create(
            project_id, title="evidence review", role=ROLE_REVIEWER, actor=actor, goal="reject unverifiable claims"
        ),
        "report": tasks_service.create(
            project_id, title="report", role=ROLE_REPORTER, actor=actor, goal="produce the markdown report"
        ),
    }
    outcome: dict[str, Any] = {"project_id": project_id, "tasks": created, "steps": []}
    try:
        static_task = created["static"]["id"]
        tasks_service.update(static_task, actor="agent", status="RUNNING", reason="orchestrator dispatch")
        static_result = static_analysis(project_id, task_id=static_task, predictor=predictor, use_model=use_model)
        tasks_service.update(
            static_task,
            actor="system",
            status="REVIEW",
            fields={"summary": (static_result.get("narrative") or {}).get("summary") or "static pipeline finished"},
            reason="static stage finished",
        )
        outcome["steps"].append({"stage": "static", "task_id": static_task, "ok": True,
                                 "evidence": len(static_result["evidence_ids"])})

        review_task_id = created["review"]["id"]
        tasks_service.update(review_task_id, actor="agent", status="RUNNING", reason="orchestrator dispatch")
        tasks_service.update(review_task_id, actor="system", status="REVIEW", reason="claims ready for review")
        claims = claims_from_evidence(project_id)
        narrative = static_result.get("narrative") or {}
        for highlight in narrative.get("highlights") or []:
            claims.append({"claim": highlight["claim"], "evidence_id": highlight["evidence_id"], "kind": "agent_claim"})
        review_result = review_task(
            project_id, review_task_id, claims=claims, predictor=predictor, use_model=use_model
        )
        outcome["steps"].append(
            {
                "stage": "review",
                "task_id": review_task_id,
                "ok": review_result["verdict"] == "accepted",
                "accepted": len(review_result["accepted"]),
                "rejected": len(review_result["rejected"]),
            }
        )
        outcome["review"] = {
            "verdict": review_result["verdict"],
            "rejected": review_result["rejected"],
            "traceability": review_result["traceability"],
        }
        if review_result["verdict"] != "accepted":
            tasks_service.update(
                static_task, actor="system", status="RUNNING", reason="reviewer returned the static task"
            )
            outcome["status"] = "returned"
            _end_run(run_id, "returned", notes="reviewer rejected unevidenced claims")
            return outcome

        report_task = created["report"]["id"]
        tasks_service.update(report_task, actor="agent", status="RUNNING", reason="orchestrator dispatch")
        report_result = report(project_id, task_id=report_task, use_model=use_model)
        tasks_service.update(
            report_task,
            actor="system",
            status="REVIEW",
            fields={"summary": f"report artifact {report_result['artifact_id']}"},
            reason="report written; awaiting human approval",
        )
        tasks_service.update(static_task, actor="system", status="REVIEW", reason="awaiting human approval")
        outcome["steps"].append({"stage": "report", "task_id": report_task, "ok": True,
                                 "artifact_id": report_result["artifact_id"]})
        outcome["report"] = {"artifact_id": report_result["artifact_id"],
                             "verification_ok": report_result.get("verification_ok")}
        outcome["status"] = "review_ready"
        _end_run(run_id, "ok", notes="static, review and report stages completed")
        return outcome
    except Exception as exc:
        _end_run(run_id, "error", notes=f"{type(exc).__name__}: {exc}"[:2000])
        raise
