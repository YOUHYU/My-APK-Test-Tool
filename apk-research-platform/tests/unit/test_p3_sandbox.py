"""P3 sandbox: what it does, and - more importantly - what it refuses to pretend.

The executor on this host is *cooperative*: a static screen, a scrubbed environment, a
wall-clock timeout and capped output. There is no container, so a request for container
isolation must fail loudly instead of silently degrading.
"""
from __future__ import annotations

from pathlib import Path

import pytest

from apkplat import audit
from apkplat.db import db
from apkplat.services import artifacts as artifacts_service
from apkplat.services import projects as projects_service
from apkplat.services import sandbox as sandbox_service
from apkplat.services import tasks as tasks_service
from apkplat.util import project_layout


@pytest.fixture(scope="module")
def project(sample_apk):
    row = projects_service.create(name="p3-sandbox", apk_source=sample_apk, filename=sample_apk.name, actor="test")
    task = tasks_service.create(row["id"], role="exec", title="Sandbox", actor="test", status="RUNNING")
    return {"id": row["id"], "task_id": task["id"]}


def _script(project_id: str, name: str, source: str) -> str:
    layout = project_layout(project_id)
    path = Path(layout["artifacts"]) / name
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(source, encoding="utf-8")
    row = artifacts_service.register(project_id, kind="script", path=path, tool="test", tool_version="1.0.0")
    return row["id"]


def test_static_screen_names_what_it_found():
    ok = sandbox_service.static_check("print('hello')\n")
    assert ok["ok"] is True and ok["findings"] == []

    banned_import = sandbox_service.static_check("import socket\nsocket.socket()\n")
    assert banned_import["ok"] is False
    assert any(item["kind"] == "banned_import" and "socket" in item["detail"] for item in banned_import["findings"])

    banned_call = sandbox_service.static_check("import os\nos.system('calc')\n")
    assert banned_call["ok"] is False
    assert any(item["kind"] == "banned_call" for item in banned_call["findings"])

    dynamic = sandbox_service.static_check("eval(\"1+1\")\n")
    assert dynamic["ok"] is False


def test_successful_run_records_everything(project):
    artifact_id = _script(project["id"], "ok.py", "import sys\nprint('argv', sys.argv[1:])\nprint('done')\n")
    run = sandbox_service.run_script(
        project["id"], script_artifact_id=artifact_id, argv=["alpha", "beta"], task_id=project["task_id"], actor="test"
    )
    assert run["status"] == "SUCCEEDED"
    assert run["exit_code"] == 0
    assert run["timed_out"] == 0
    assert run["network_policy"] == "none"
    assert run["isolation"] == "cooperative"

    stdout = artifacts_service.read_text(run["stdout_artifact_id"], limit=1000)["text"]
    assert "argv ['alpha', 'beta']" in stdout and "done" in stdout
    result = artifacts_service.read_text(run["result_artifact_id"], limit=2000)["text"]
    assert '"exit_code": 0' in result

    events = [row for row in audit.tail(0, project_id=project["id"], limit=200) if row["event_type"] == "sandbox_run"]
    assert any(item["payload"].get("sandbox_run_id") == run["id"] for item in events)


def test_failed_exit_code_is_reported_not_hidden(project):
    artifact_id = _script(project["id"], "fail.py", "import sys\nsys.exit(3)\n")
    run = sandbox_service.run_script(project["id"], script_artifact_id=artifact_id, actor="test")
    assert run["status"] == "FAILED"
    assert run["exit_code"] == 3


def test_timeout_kills_the_process_tree(project):
    artifact_id = _script(
        project["id"], "sleepy.py", "import time\ntime.sleep(30)\nprint('never printed')\n"
    )
    run = sandbox_service.run_script(project["id"], script_artifact_id=artifact_id, timeout=1, actor="test")
    assert run["status"] == "TIMEOUT"
    assert run["timed_out"] == 1
    assert run["error_code"] == "sandbox_timeout"
    assert run["exit_code"] is None
    stdout = artifacts_service.read_text(run["stdout_artifact_id"], limit=1000)["text"]
    assert "never printed" not in stdout


def test_network_none_blocks_sockets(project):
    artifact_id = _script(
        project["id"],
        "net.py",
        "import socket\ntry:\n    socket.socket()\nexcept Exception as exc:\n    print('blocked', type(exc).__name__)\n",
    )
    # static_check already refuses `import socket`; go around it the way a determined script
    # would (importlib) so the runtime stub is exercised rather than the screen.
    # The static screen matches literal names, so a composed module name slips past it -
    # which is exactly the case the runtime stub exists for.
    source = (
        "import importlib\n"
        "mod = importlib.import_module('so' + 'cket')\n"
        "try:\n"
        "    mod.socket()\n"
        "    print('network available')\n"
        "except Exception as exc:\n"
        "    print('blocked', type(exc).__name__)\n"
    )
    layout = project_layout(project["id"])
    path = Path(layout["artifacts"]) / "net2.py"
    path.write_text(source, encoding="utf-8")
    row = artifacts_service.register(project["id"], kind="script", path=path, tool="test", tool_version="1.0.0")
    assert artifact_id  # silence unused warning; both scripts document the intent
    run = sandbox_service.run_script(project["id"], script_artifact_id=row["id"], actor="test")
    stdout = artifacts_service.read_text(run["stdout_artifact_id"], limit=1000)["text"]
    assert "blocked" in stdout
    assert "network available" not in stdout


def test_container_isolation_is_refused(project):
    artifact_id = _script(project["id"], "ok2.py", "print('hi')\n")
    with pytest.raises(sandbox_service.SandboxError) as excinfo:
        sandbox_service.run_script(project["id"], script_artifact_id=artifact_id, isolation="container", actor="test")
    assert excinfo.value.code == "strong_isolation_unavailable"
    assert excinfo.value.status == 409


def test_static_check_refusal_is_recorded_then_raised(project):
    artifact_id = _script(project["id"], "bad.py", "import subprocess\nsubprocess.run(['whoami'])\n")
    before = db.scalar("SELECT COUNT(*) FROM sandbox_runs WHERE project_id = ? AND status = 'REFUSED'", (project["id"],))
    with pytest.raises(sandbox_service.SandboxError) as excinfo:
        sandbox_service.run_script(project["id"], script_artifact_id=artifact_id, actor="test")
    assert excinfo.value.code == "static_check_failed"
    after = db.scalar("SELECT COUNT(*) FROM sandbox_runs WHERE project_id = ? AND status = 'REFUSED'", (project["id"],))
    assert after == before + 1


def test_only_python_scripts_run(project):
    layout = project_layout(project["id"])
    path = Path(layout["artifacts"]) / "shell.ps1"
    path.write_text("Write-Host hi\n", encoding="utf-8")
    row = artifacts_service.register(project["id"], kind="script", path=path, tool="test", tool_version="1.0.0")
    with pytest.raises(sandbox_service.SandboxError) as excinfo:
        sandbox_service.run_script(project["id"], script_artifact_id=row["id"], actor="test")
    assert excinfo.value.code == "unsupported_script_type"


def test_script_from_another_project_is_refused(project, sample_apk):
    other = projects_service.create(name="p3-sandbox-other", apk_source=sample_apk, filename=sample_apk.name, actor="test")
    foreign = _script(other["id"], "foreign.py", "print('other project')\n")
    with pytest.raises(sandbox_service.SandboxError) as excinfo:
        sandbox_service.run_script(project["id"], script_artifact_id=foreign, actor="test")
    assert excinfo.value.code == "project_denied"


def test_replay_of_a_networked_run_is_refused(project):
    artifact_id = _script(project["id"], "allowlist.py", "print('no-op with network policy')\n")
    run = sandbox_service.run_script(
        project["id"], script_artifact_id=artifact_id, network="allowlist", actor="test"
    )
    with pytest.raises(sandbox_service.SandboxError) as excinfo:
        sandbox_service.replay(project["id"], run["id"], actor="test")
    assert excinfo.value.code == "side_effect_risk"


def test_replay_of_a_pure_run_is_allowed_and_linked(project):
    artifact_id = _script(project["id"], "pure.py", "print('pure')\n")
    run = sandbox_service.run_script(project["id"], script_artifact_id=artifact_id, actor="test")
    replay = sandbox_service.replay(project["id"], run["id"], actor="test")
    assert replay["replay_of"] == run["id"]
    assert replay["status"] == "SUCCEEDED"
    assert replay["script_sha256"] == run["script_sha256"]

def test_writes_outside_the_run_directory_are_blocked(project):
    source = (
        "import os\n"
        "print('cwd', os.getcwd())\n"
        "try:\n"
        "    open('../../escape_probe.txt', 'w').write('escaped')\n"
        "    print('write allowed')\n"
        "except PermissionError as exc:\n"
        "    print('blocked', exc)\n"
    )
    artifact_id = _script(project["id"], "escape.py", source)
    run = sandbox_service.run_script(project["id"], script_artifact_id=artifact_id, actor="test")
    stdout = artifacts_service.read_text(run["stdout_artifact_id"], limit=2000)["text"]
    assert "blocked" in stdout
    assert "write allowed" not in stdout
    layout = project_layout(project["id"])
    assert not (Path(layout["base"]) / "escape_probe.txt").exists()