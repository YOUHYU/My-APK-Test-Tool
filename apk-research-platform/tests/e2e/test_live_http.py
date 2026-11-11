"""End-to-end over real HTTP: the API as its own process, a worker as another.

Everything else in the suite talks to the app through ``TestClient``, which never
exercises uvicorn, the on-disk SQLite file, the process boundary or the static
frontend mount. This test starts the served app, uploads the sample APK over the
network, lets a *separate* worker process do the analysis, and then asks the API to
verify the evidence chain and render a report.

It is deliberately small: no model calls, no device, no browser.
"""
from __future__ import annotations

import json
import os
import socket
import subprocess
import sys
import time
from pathlib import Path

import httpx
import pytest

# trust_env=False on purpose: this host exports a proxy plus a NO_PROXY list that
# contains "[::1]", which makes httpx raise ValueError while parsing it. Talking to
# 127.0.0.1 must never go through a proxy anyway.
CLIENT_ARGS = {"trust_env": False}

ROOT = Path(__file__).resolve().parent.parent.parent
PYTHON = ROOT / ".venv" / "Scripts" / "python.exe"
CLI = ROOT / "scripts" / "apkplat_cli.py"
SAMPLE = ROOT / "samples" / "sample-app.apk"

pytestmark = pytest.mark.skipif(not PYTHON.exists(), reason="project venv missing")


def _free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


def _child_env(storage: Path) -> dict:
    env = dict(os.environ)
    env.update(
        {
            "APKPLAT_STORAGE": str(storage / "storage"),
            "APKPLAT_REPORTS": str(storage / "reports"),
            "APKPLAT_SECRET": "e2e-secret-not-for-production",
            "APKPLAT_REQUIRE_AUTH": "0",
            "APKPLAT_MODEL_ENABLED": "0",
            "APKPLAT_DYNAMIC_TRANSPORT": "sim",
            "PYTHONUNBUFFERED": "1",
        }
    )
    env.pop("APKPLAT_DB_URL", None)
    return env


@pytest.fixture()
def live_server(tmp_path):
    port = _free_port()
    env = _child_env(tmp_path)
    log = open(tmp_path / "api.log", "wb")
    process = subprocess.Popen(
        [str(PYTHON), str(CLI), "serve", "--port", str(port)],
        cwd=str(ROOT),
        env=env,
        stdout=log,
        stderr=subprocess.STDOUT,
        creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
    )
    base = f"http://127.0.0.1:{port}"
    deadline = time.time() + 40
    ready = False
    while time.time() < deadline:
        if process.poll() is not None:
            break
        try:
            if httpx.get(base + "/api/health", timeout=2, **CLIENT_ARGS).status_code == 200:
                ready = True
                break
        except Exception:
            time.sleep(0.4)
    if not ready:
        process.terminate()
        log.close()
        pytest.fail(f"server did not become healthy; see {tmp_path / 'api.log'}")
    try:
        yield base, env, tmp_path
    finally:
        process.terminate()
        try:
            process.wait(timeout=15)
        except subprocess.TimeoutExpired:
            process.kill()
        log.close()


def _run_worker(env: dict, kinds: str, timeout: float = 120) -> subprocess.CompletedProcess:
    return subprocess.run(
        [str(PYTHON), str(CLI), "worker", "--once", "--kinds", kinds, "--poll", "0.2", "--idle", "3"],
        cwd=str(ROOT),
        env=env,
        capture_output=True,
        text=True,
        timeout=timeout,
        creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
    )


def test_upload_analyse_verify_report_over_http(live_server):
    base, env, tmp_path = live_server
    with open(SAMPLE, "rb") as handle:
        upload = httpx.post(
            base + "/api/projects",
            data={"name": "e2e-reef", "ground_truth": json.dumps({"package": "com.example.reef"})},
            files={"apk": ("sample-app.apk", handle, "application/vnd.android.package-archive")},
            timeout=60,
            **CLIENT_ARGS,
        )
    assert upload.status_code == 201, upload.text
    project_id = upload.json()["project"]["id"]

    worker = _run_worker(env, "static_pipeline")
    assert worker.returncode == 0, worker.stderr[-2000:]
    # the CLI prints its summary as JSON: {"processed": 1}
    assert '"processed": 1' in (worker.stdout or ""), worker.stdout

    detail = httpx.get(f"{base}/api/projects/{project_id}", timeout=20, **CLIENT_ARGS).json()
    assert detail["project"]["status"] == "ANALYZED", detail["project"]["status"]
    assert detail["manifest"]["ingest"]["sha256"] == json.loads(
        (ROOT / "samples" / "ground_truth.json").read_text(encoding="utf-8")
    )["apk_sha256"]

    verify = httpx.get(f"{base}/api/projects/{project_id}/verify", timeout=30, **CLIENT_ARGS).json()
    # verify_chain reports counts, not a boolean: {"checked", "ok", "failures"}
    assert verify["artifacts"]["failures"] == [], verify["artifacts"]
    assert verify["artifacts"]["ok"] == verify["artifacts"]["checked"] > 0, verify["artifacts"]
    assert verify["evidence"]["traceability_rate"] == 1.0, verify["evidence"]

    evidence = httpx.get(f"{base}/api/projects/{project_id}/evidence", timeout=20, **CLIENT_ARGS).json()
    assert len(evidence["evidence"]) >= 8, evidence

    report = httpx.post(f"{base}/api/projects/{project_id}/report", json={}, timeout=60, **CLIENT_ARGS)
    assert report.status_code == 201, report.text
    body = report.json()
    assert body["verification_ok"] is True, body
    report_path = Path(body["report_path"])
    assert report_path.exists(), report_path
    text = report_path.read_text(encoding="utf-8")
    assert "REEF-API-KEY-7781" in text
    assert "校验结果" in text

    # The queue is drained and the board projects the card into REVIEW, not DONE:
    # only a human or the reviewer role may close a task.
    queue = httpx.get(f"{base}/api/queue", timeout=10, **CLIENT_ARGS).json()
    # stats only lists statuses that exist right now
    assert queue["stats"].get("PENDING", 0) == 0
    board = httpx.get(f"{base}/api/projects/{project_id}/board", timeout=10, **CLIENT_ARGS).json()
    assert any(card["status"] == "REVIEW" for card in board["columns"]["REVIEW"])
    assert board["columns"]["DONE"] == []


def _error_code(response) -> str:
    """Domain errors are flat; HTTPException(detail={...}) nests under ``detail``."""
    body = response.json()
    if isinstance(body.get("detail"), dict):
        return body["detail"].get("error_code", "")
    return body.get("error_code", "")


def test_api_survives_an_unknown_project(live_server):
    base, _, _ = live_server
    missing = httpx.get(base + "/api/projects/prj_does_not_exist", timeout=10, **CLIENT_ARGS)
    assert missing.status_code == 404
    assert _error_code(missing) == "project_not_found"
    # still alive
    assert httpx.get(base + "/api/health", timeout=5, **CLIENT_ARGS).status_code == 200
