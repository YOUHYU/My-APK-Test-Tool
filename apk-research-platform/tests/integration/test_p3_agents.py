"""P3: four roles, and a reviewer that actually refuses to rubber-stamp.

Two claims are put in front of the reviewer:

* one that cites a real evidence row whose excerpt is still verbatim in its artifact;
* one asserted by the "static agent" with no evidence id at all.

The second must come back — the task must leave REVIEW, the rejection must be audited
(``review_returned_no_evidence``, which is what ``false_confident_claims`` counts), and
the model must never be able to rescue it. Conversely a model *veto* on a claim that
does pass the evidence gate must also be honoured.
"""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from apkplat import agents
from apkplat import db as dbmod
from apkplat.services import evidence as evidence_service
from apkplat.services import queue, tasks
from apkplat.worker import Worker

ROOT = Path(__file__).resolve().parents[2]


def _project(client, name: str, sample: Path) -> str:
    with open(sample, "rb") as handle:
        resp = client.post(
            "/api/projects",
            data={"name": name},
            files={"apk": ("sample.apk", handle, "application/vnd.android.package-archive")},
        )
    assert resp.status_code == 201, resp.text
    return resp.json()["project"]["id"]


def _audit_count(event_type: str, project_id: str) -> int:
    return int(
        dbmod.db.scalar(
            "SELECT COUNT(*) FROM audit_events WHERE event_type = ? AND project_id = ?", (event_type, project_id), 0
        )
        or 0
    )


def _fake_accepts_all(messages, **kwargs):
    return {"verdicts": [{"evidence_id": "none", "supported": True, "reason": "ok"}]}


def _fake_veto(messages, **kwargs):
    # veto the first claim the reviewer asks about, whatever it is
    user = messages[-1]["content"]
    claims = json.loads(user)["claims"]
    return {
        "verdicts": [
            {"evidence_id": claim["evidence_id"], "supported": False, "reason": "excerpt does not state this"}
            for claim in claims[:1]
        ]
    }


def test_reviewer_rejects_a_claim_that_cites_no_evidence(app_client, sample_apk):
    project_id = _project(app_client, "p3-no-evidence", sample_apk)
    Worker("p3-worker", ["static_pipeline"], poll_interval=0.05).run(max_jobs=1)

    real = evidence_service.list_evidence(project_id)[0]
    claims = [
        {"claim": "the APK declares the INTERNET permission", "evidence_id": real["id"]},
        {"claim": "the app exfiltrates contacts to 8.8.8.8", "evidence_id": None},
    ]
    result = agents.review_claims(project_id, claims, use_model=False)

    assert result["verdict"] == "rejected"
    assert [c["reason"] for c in result["rejected"]] == ["no_evidence"]
    assert result["accepted"][0]["evidence_id"] == real["id"]
    assert _audit_count("review_returned_no_evidence", project_id) == 1


def test_reviewer_vetoes_claims_whose_excerpt_does_not_support_them(app_client, sample_apk):
    project_id = _project(app_client, "p3-model-veto", sample_apk)
    Worker("p3-worker-2", ["static_pipeline"], poll_interval=0.05).run(max_jobs=1)
    claims = agents.claims_from_evidence(project_id)[:3]
    assert len(claims) >= 2

    result = agents.review_claims(project_id, claims, predictor=_fake_veto)
    assert result["verdict"] == "rejected"
    assert result["rejected"][0]["reason"].startswith("model_veto:")
    assert result["model_review"] is not None
    assert len(result["accepted"]) == len(claims) - 1


def test_review_task_moves_the_card_back_and_is_audited(app_client, sample_apk):
    project_id = _project(app_client, "p3-return", sample_apk)
    Worker("p3-worker-3", ["static_pipeline"], poll_interval=0.05).run(max_jobs=1)
    task = tasks.create(project_id, role="static", title="static pass", actor="agent")
    tasks.update(task["id"], actor="agent", status="RUNNING")
    tasks.update(task["id"], actor="system", status="REVIEW")

    good = agents.claims_from_evidence(project_id)[0]
    bad = {"claim": "unbacked claim", "evidence_id": None}
    result = agents.review_task(project_id, task["id"], claims=[good, bad], use_model=False)

    assert result["verdict"] == "rejected"
    reloaded = tasks.get(task["id"])
    assert reloaded["status"] == "RUNNING"
    assert reloaded["error_code"] == "review_no_evidence"
    metrics = app_client.get("/api/metrics").json()
    assert metrics["false_confident_claims"] >= 1


def test_pass_keeps_the_task_in_review_for_a_human(app_client, sample_apk):
    project_id = _project(app_client, "p3-pass", sample_apk)
    Worker("p3-worker-4", ["static_pipeline"], poll_interval=0.05).run(max_jobs=1)
    task = tasks.create(project_id, role="static", title="static pass", actor="agent")
    tasks.update(task["id"], actor="agent", status="RUNNING")
    tasks.update(task["id"], actor="system", status="REVIEW")

    claims = agents.claims_from_evidence(project_id)
    result = agents.review_task(project_id, task["id"], claims=claims, use_model=False)

    assert result["verdict"] == "accepted"
    assert tasks.get(task["id"])["status"] == "REVIEW"
    with pytest.raises(Exception):
        tasks.update(task["id"], actor="agent", status="DONE")


def test_orchestrator_runs_four_roles_and_leaves_human_approval(app_client, sample_apk):
    project_id = _project(app_client, "p3-orchestrate", sample_apk)

    outcome = agents.orchestrate(project_id, use_model=False)

    assert outcome["status"] == "review_ready", outcome
    assert [step["stage"] for step in outcome["steps"]] == ["static", "review", "report"]
    runs = app_client.get(f"/api/projects/{project_id}/agents/runs").json()["runs"]
    roles = {run["role"] for run in runs}
    assert {"orchestrator", "static", "reviewer", "reporter"} <= roles
    assert all(run["status"] in {"ok", "rejected", "error"} for run in runs)

    board = app_client.get(f"/api/projects/{project_id}/board").json()
    review_titles = {t["title"] for t in board["columns"]["REVIEW"]}
    assert {"static analysis", "evidence review", "report"} <= review_titles
    assert board["columns"]["DONE"] == [], "no agent may close a card on its own"

    for task in outcome["tasks"].values():
        assert tasks.get(task["id"])["status"] in {"REVIEW", "RUNNING"}


def test_orchestrate_can_be_dispatched_as_a_durable_job(app_client, sample_apk):
    project_id = _project(app_client, "p3-job", sample_apk)
    resp = app_client.post(f"/api/projects/{project_id}/agents/run", json={"use_model": False})
    assert resp.status_code == 202, resp.text
    job_id = resp.json()["job_id"]
    assert queue.get(job_id)["kind"] == "agent_orchestrate"

    Worker("p3-orch-worker", ["agent_orchestrate"], poll_interval=0.05).run(max_jobs=1)
    job = queue.get(job_id)
    assert job["status"] == "SUCCEEDED", job
    assert job["result"]["status"] == "review_ready"
