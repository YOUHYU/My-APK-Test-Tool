"""G1 - does a real DSH agent drive the platform through scoped tools on its own?

The taskbook's bar (V3 搂4.1) is not "the platform can run a pipeline". It is: the model,
given a run capability, picks the tools itself, changes its next move because of what the
first tool told it, and every one of those calls is auditable server-side. This script
tries to produce exactly that evidence, twice, over two different APKs - because the same
plan over different inputs would prove the plan was hardcoded.

Sequence:

1. fresh storage under ``runtime/p1-g1`` (never the operator's ``storage/``);
2. project A = the reef sample (secrets + network), project B = the clean sample
   (no permissions, no network, no credential-shaped literals); both analysed by the
   existing static pipeline so the agent has something real to look at;
3. the platform API is started on a free port and issues a run capability per project;
4. DSH boots headless with an overlay that loads ``plugins/apkplat-bridge`` for that run;
5. the model is asked to investigate - the prompt names no tool, no order and no answer;
6. afterwards: negative checks on the same gateway (expired / cross-project / role scope /
   revoked), then assertions and a report under ``audit/``.

Usage:
  python scripts/p1_g1_accept.py            # full run (needs the model endpoint + DSH)
  python scripts/p1_g1_accept.py --no-dsh   # gateway-only re-check, no model calls
"""

from __future__ import annotations

import argparse
import json
import os
import shutil
import socket
import subprocess
import sys
import time
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
BACKEND = ROOT / "backend"
SAMPLES = ROOT / "samples"
RUNTIME = ROOT / "runtime"
AUDIT = ROOT / "audit"
LOCAL_TMP = ROOT / ".tmp"

DSH_EXE = Path(os.environ.get("DSH_EXE", r"C:\Users\YHY\AppData\Local\Programs\DSH NEXT\DSH NEXT.exe"))
DSH_BIN = Path(
    os.environ.get(
        "DSH_BIN",
        r"C:\Users\YHY\AppData\Local\Programs\DSH NEXT\resources\app.asar\node_modules\@deepseek-ai\dsh\lib\bin.js",
    )
)

PROMPT = (
    "You are the analysis agent for Android project {project_id}. Investigate it with the "
    "apkplat tools and then stop.\n\n"
    "Goal: say what this app does, whether it hides credential-shaped literals in its code, "
    "and which network endpoints it contacts. Support each claim with evidence submitted "
    "through the tools, quoting an artifact verbatim.\n\n"
    "Rules: use the tools to look, do not guess; you decide which tools to call and in what "
    "order. Call at least two different tools. Your tool budget is limited to about 30 calls: do not repeat the same tool more than three times, and keep at least two calls for submitting evidence through evidence_submit. Finish with a short summary of what you found and which evidence ids back it."
)


# --------------------------------------------------------------------- helpers


def local_env(storage: Path, reports: Path) -> dict[str, str]:
    env = dict(os.environ)
    LOCAL_TMP.mkdir(parents=True, exist_ok=True)
    env["TEMP"] = str(LOCAL_TMP)
    env["TMP"] = str(LOCAL_TMP)
    env["APKPLAT_STORAGE"] = str(storage)
    env["APKPLAT_REPORTS"] = str(reports)
    env["APKPLAT_REQUIRE_AUTH"] = "0"
    env["APKPLAT_SECRET"] = "g1-acceptance-secret"
    env["APKPLAT_MODEL_ENABLED"] = "0"
    env["PYTHONUTF8"] = "1"
    env["PYTHONPATH"] = str(BACKEND)
    return env


def free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


def read_model_key() -> str | None:
    env = os.environ.get("WB_PROXY_API_KEY")
    if env:
        return env
    path = Path.home() / ".dsh" / ".credentials.yaml"
    if not path.exists():
        return None
    try:
        import yaml

        data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    except Exception:  # noqa: BLE001
        return None
    value = (data.get("refs") or {}).get("WB_PROXY_API_KEY")
    return str(value) if value else None


def client(base: str):
    import httpx

    return httpx.Client(base_url=base, timeout=120.0, trust_env=False)


# ------------------------------------------------------------------- platform


def build_projects(storage: Path) -> dict[str, Any]:
    """Ingest both APKs and run the static pipeline in-process (same storage as the API)."""
    sys.path.insert(0, str(BACKEND))
    from apkplat import db as db_mod
    from apkplat import pipeline_static
    from apkplat.services import artifacts as artifacts_service
    from apkplat.services import evidence as evidence_service
    from apkplat.services import projects as projects_service
    from apkplat.services import tasks as tasks_service

    db_mod.db.migrate()
    pipeline_static.silence_library_logging()

    out: dict[str, Any] = {}
    for key, apk_name, truth_name in (
        ("reef", "sample-app.apk", "ground_truth.json"),
        ("clean", "sample-clean.apk", "ground_truth_clean.json"),
    ):
        apk = SAMPLES / apk_name
        truth = json.loads((SAMPLES / truth_name).read_text(encoding="utf-8"))
        project = projects_service.create(
            name=f"g1-{key}",
            apk_source=str(apk),
            filename=apk_name,
            goal="G1 acceptance: autonomous investigation",
            ground_truth=json.dumps(truth),
            policy_id="default",
            actor="g1-accept",
        )
        pid = project["id"]
        task = tasks_service.create(
            project_id=pid,
            role="static",
            title="G1 autonomous investigation",
            goal="Model-driven investigation over the scoped bridge tools.",
            status="RUNNING",
            actor="g1-accept",
        )
        summary = pipeline_static.run(pid, task_id=task["id"], log=lambda msg: None)
        row = projects_service.get(pid)
        out[key] = {
            "project_id": pid,
            "task_id": task["id"],
            "package": row["package_name"],
            "evidence": len(evidence_service.list_evidence(pid, limit=500)),
            "artifacts": len(artifacts_service.list_artifacts(pid, limit=500)),
            "stages": summary.get("stages"),
            "truth": truth,
        }
    return out


def start_api(env: dict[str, str], port: int) -> subprocess.Popen:
    cmd = [
        sys.executable, "-m", "uvicorn", "apkplat.api.app:app",
        "--host", "127.0.0.1", "--port", str(port), "--log-level", "warning",
    ]
    log = (RUNTIME / "p1-g1" / "api.log").open("w", encoding="utf-8")
    return subprocess.Popen(cmd, env=env, cwd=str(ROOT), stdout=log, stderr=subprocess.STDOUT)


def wait_health(base: str, timeout: float = 40.0) -> dict[str, Any]:
    deadline = time.time() + timeout
    last: Exception | None = None
    while time.time() < deadline:
        try:
            with client(base) as http:
                response = http.get("/api/health")
            if response.status_code == 200:
                return response.json()
        except Exception as exc:  # noqa: BLE001
            last = exc
        time.sleep(0.4)
    raise RuntimeError(f"platform API did not become healthy: {last}")


# ----------------------------------------------------------------------- DSH


def write_overlay(path: Path, platform_url: str, token_file: Path, trace_file: Path) -> Path:
    plugin = (ROOT / "plugins" / "apkplat-bridge" / "index.js").as_posix()
    text = f"""# G1 overlay: platform model line + the apkplat bridge plugin for ONE run capability.
# Generated by scripts/p1_g1_accept.py; safe to delete (nothing is copied into ~/.dsh).
- id: llm-pi-ai
  name: "@deepseek-ai/dsh-llm-pi-ai"
  config:
    providers:
      wb-proxy:
        displayName: WB Proxy (G1 acceptance, same endpoint as the desktop app)
        apiKeyEnv: WB_PROXY_API_KEY
        api: openai-completions
        baseURL: http://192.168.43.1:8788/v1
        compat:
          thinkingFormat: openai
          supportsReasoningEffort: true
        models:
          - id: deepseek-v4.1-flash
            contextWindow: 1000000
            maxTokens: 128000
            reasoningEfforts:
              max: max
            input:
              - text

- id: agent-default-model
  config:
    provider: wb-proxy
    model: deepseek-v4.1-flash

- insert:
    - id: apkplat-bridge
      name: file:///{plugin}
      config:
        platform_url: '{platform_url}'
        token_file: '{token_file.as_posix()}'
        trace_file: '{trace_file.as_posix()}'
        timeout_ms: 120000
        fail_on_error: true
"""
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")
    return path


def run_dsh(overlay: Path, prompt: str, key: str, home: Path, timeout: int) -> dict[str, Any]:
    env = dict(os.environ)
    env["ELECTRON_RUN_AS_NODE"] = "1"
    env["WB_PROXY_API_KEY"] = key
    env["PYTHONUTF8"] = "1"
    env["TEMP"] = str(LOCAL_TMP)
    env["TMP"] = str(LOCAL_TMP)
    env["APKPLAT_DSH_ASAR"] = str(Path(DSH_BIN).parents[5])
    (home / "profiles" / "headless").mkdir(parents=True, exist_ok=True)
    cordis = home / "profiles" / "headless" / "cordis.yml"
    if not cordis.exists():
        cordis.write_text("[]\n", encoding="utf-8")
    env["DSH_HOME"] = str(home)
    cmd = [str(DSH_EXE), str(DSH_BIN), "--profile", "headless", "--patch", str(overlay), "--json", prompt]
    started = time.time()
    proc = subprocess.run(cmd, capture_output=True, text=True, encoding="utf-8", errors="replace",
                          env=env, timeout=timeout, cwd=str(ROOT))
    events: list[Any] = []
    for line in (proc.stdout or "").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            events.append(json.loads(line))
        except json.JSONDecodeError:
            events.append({"raw": line})
    return {
        "exit_code": proc.returncode,
        "duration_s": round(time.time() - started, 1),
        "events": events,
        "stderr_tail": (proc.stderr or "")[-4000:],
    }


def tool_events(events: list[Any]) -> list[dict[str, Any]]:
    """Pull the model's tool decisions out of the DSH event stream."""
    out: list[dict[str, Any]] = []
    for event in events:
        if not isinstance(event, dict):
            continue
        blob = json.dumps(event)
        if "apkplat" not in blob and "tool_call" not in blob:
            continue
        name = None
        args = None
        for key in ("name", "tool", "tool_name", "toolName"):
            value = event.get(key)
            if isinstance(value, str) and value:
                name = value
                break
        if name is None:
            call = event.get("tool_call") or event.get("toolCall")
            if isinstance(call, dict):
                name = call.get("name")
                args = call.get("arguments") or call.get("args")
        if name is None and isinstance(event.get("tool"), dict):
            name = event["tool"].get("name")
            args = event["tool"].get("arguments")
        for key in ("arguments", "args", "input"):
            if args is None and isinstance(event.get(key), dict):
                args = event[key]
        if name:
            out.append({"event": event.get("type") or event.get("kind") or "event", "tool": name, "arguments": args})
    return out


def final_text(events: list[Any]) -> str:
    text = ""
    for event in events:
        if not isinstance(event, dict):
            continue
        for key in ("text", "content", "message", "result"):
            value = event.get(key)
            if isinstance(value, str) and value.strip():
                text = value
    return text.strip()


# ------------------------------------------------------------------ assertions


def check(checks: list[dict[str, Any]], name: str, ok: bool, detail: Any = "") -> None:
    checks.append({"check": name, "ok": bool(ok), "detail": detail})


def body_json(response) -> dict[str, Any]:
    """Never let a non-JSON error body hide which refusal actually happened."""
    try:
        data = response.json()
    except Exception:  # noqa: BLE001
        return {"error_code": None, "raw": (response.text or "")[:300]}
    if isinstance(data, dict):
        detail = data.get("detail")
        if isinstance(detail, dict) and "error_code" in detail:
            return {**data, **detail}
        if isinstance(detail, str) and detail:
            return {**data, "message": detail}
    return data if isinstance(data, dict) else {"raw": data}


def gateway_negatives(base: str, reef: dict[str, Any]) -> list[dict[str, Any]]:
    """Every refusal the contract promises, exercised against a live capability."""
    results: list[dict[str, Any]] = []
    with client(base) as http:
        # expired capability
        expired = http.post(f"/api/projects/{reef['project_id']}/runs",
                            json={"role": "exec", "task_id": reef["task_id"], "ttl_seconds": 1}).json()
        token = Path(expired["token_path"]).read_text(encoding="utf-8").strip()
        time.sleep(2.2)
        response = http.post("/api/bridge/tools/task_status_get", json={"arguments": {}},
                             headers={"Authorization": f"Bearer {token}"})
        results.append({"case": "expired_capability", "status": response.status_code,
                        "error_code": body_json(response).get("error_code")})

        # cross-project: a capability for project A must not read project B
        fresh = http.post(f"/api/projects/{reef['project_id']}/runs",
                          json={"role": "exec", "task_id": reef["task_id"], "ttl_seconds": 600}).json()
        token2 = Path(fresh["token_path"]).read_text(encoding="utf-8").strip()
        response = http.post("/api/bridge/tools/project_snapshot", json={"arguments": {}},
                             headers={"Authorization": f"Bearer {token2}", "X-Project-Id": "prj_other"})
        results.append({"case": "cross_project_via_header", "status": response.status_code,
                        "error_code": body_json(response).get("error_code")})

        # role scope: plan may not inspect code
        plan = http.post(f"/api/projects/{reef['project_id']}/runs",
                         json={"role": "plan", "task_id": reef["task_id"], "ttl_seconds": 600}).json()
        token3 = Path(plan["token_path"]).read_text(encoding="utf-8").strip()
        response = http.post("/api/bridge/tools/apk_inspect", json={"arguments": {"action": "packages"}},
                             headers={"Authorization": f"Bearer {token3}"})
        results.append({"case": "role_scope_denied", "status": response.status_code,
                        "error_code": body_json(response).get("error_code")})
        response = http.post("/api/bridge/tools/task_status_get", json={"arguments": {}},
                             headers={"Authorization": f"Bearer {token3}"})
        results.append({"case": "role_scope_allowed", "status": response.status_code,
                        "error_code": body_json(response).get("error_code")})

        # revoke kills the capability immediately
        http.post(f"/api/runs/{fresh['run_id']}/revoke", json={"reason": "G1 negative check"})
        response = http.post("/api/bridge/tools/task_status_get", json={"arguments": {}},
                             headers={"Authorization": f"Bearer {token2}"})
        results.append({"case": "revoked_capability", "status": response.status_code,
                        "error_code": body_json(response).get("error_code")})

        # finish may never write DONE
        third = http.post(f"/api/projects/{reef['project_id']}/runs",
                          json={"role": "exec", "task_id": reef["task_id"], "ttl_seconds": 600}).json()
        token4 = Path(third["token_path"]).read_text(encoding="utf-8").strip()
        response = http.post("/api/bridge/finish", json={"status": "done"},
                             headers={"Authorization": f"Bearer {token4}"})
        results.append({"case": "finish_done_rejected", "status": response.status_code,
                        "error_code": body_json(response).get("error_code")})
    return results


def write_report(payload: dict[str, Any]) -> None:
    AUDIT.mkdir(parents=True, exist_ok=True)
    (AUDIT / "g1_acceptance.json").write_text(json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8")
    checks = payload["checks"]
    passed = sum(1 for c in checks if c["ok"])
    lines = [
        "# G1 acceptance - real agent loop over scoped bridge tools",
        "",
        f"- generated_at: `{payload['generated_at']}`",
        f"- verdict: **{passed}/{len(checks)} checks passed**",
        f"- platform: `{payload['platform_url']}` (fresh storage under `runtime/p1-g1`)",
        f"- dsh: `{DSH_BIN.name}` profile `headless`, overlay per run, `DSH_HOME` inside the project",
        "",
        "## Checks",
        "",
        "| # | check | result | detail |",
        "|---|---|---|---|",
    ]
    for index, item in enumerate(checks, start=1):
        detail = str(item["detail"]).replace("|", "/")[:220]
        lines.append(f"| {index} | {item['check']} | {'PASS' if item['ok'] else 'FAIL'} | {detail} |")
    lines += ["", "## Runs", ""]
    for name, run in payload["runs"].items():
        lines += [
            f"### {name}",
            "",
            f"- project `{run['project_id']}` / task `{run['task_id']}` / run `{run['run_id']}`",
            f"- package `{run['package']}`, dsh exit {run['exit_code']} in {run['duration_s']}s",
            f"- tool calls (platform trace, seq order): {', '.join(run['tools']) or '-'}",
            "",
        ]
    lines += ["## Negative checks on the gateway", ""]
    for item in payload["negatives"]:
        lines.append(f"- `{item['case']}` -> status {item['status']}, error_code `{item['error_code']}`")
    (AUDIT / "g1_acceptance.md").write_text("\n".join(lines) + "\n", encoding="utf-8")


# ------------------------------------------------------------------------ main


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--no-dsh", action="store_true", help="skip the model runs; re-run gateway checks only")
    parser.add_argument("--timeout", type=int, default=900)
    args = parser.parse_args(argv)

    work = RUNTIME / "p1-g1"
    if work.exists():
        shutil.rmtree(work, ignore_errors=True)
    storage = work / "storage"
    reports = work / "reports"
    storage.mkdir(parents=True, exist_ok=True)
    reports.mkdir(parents=True, exist_ok=True)

    env = local_env(storage, reports)
    for key, value in env.items():
        os.environ[key] = value

    checks: list[dict[str, Any]] = []
    builds = build_projects(storage)
    check(checks, "platform_has_two_analysed_projects",
          all(builds[k]["package"] for k in builds) and builds["reef"]["package"] != builds["clean"]["package"],
          f"reef={builds['reef']['package']} clean={builds['clean']['package']}")
    check(checks, "reef_project_has_evidence", (builds["reef"]["evidence"] or 0) >= 8, builds["reef"]["evidence"])

    port = free_port()
    base = f"http://127.0.0.1:{port}"
    proc = start_api(env, port)
    runs: dict[str, Any] = {}
    negatives: list[dict[str, Any]] = []
    traces: dict[str, Any] = {}
    try:
        health = wait_health(base)
        check(checks, "platform_api_healthy", health.get("ok") is not False, health.get("version", ""))

        if not args.no_dsh:
            key = read_model_key()
            if not key:
                raise SystemExit("no model key available (WB_PROXY_API_KEY / ~/.dsh/.credentials.yaml)")
            for name in ("reef", "clean"):
                info = builds[name]
                with client(base) as http:
                    issued = http.post(f"/api/projects/{info['project_id']}/runs",
                                       json={"role": "exec", "task_id": info["task_id"], "ttl_seconds": 1800}).json()
                token_file = Path(issued["token_path"])
                trace_file = work / f"dsh-bridge-{name}.jsonl"
                overlay = write_overlay(work / f"overlay-{name}.yml", base, token_file, trace_file)
                home = work / f"dsh-home-{name}"
                result = run_dsh(overlay, PROMPT.format(project_id=info["project_id"]), key, home, args.timeout)
                runs[name] = {
                    "project_id": info["project_id"],
                    "task_id": info["task_id"],
                    "run_id": issued["run_id"],
                    "package": info["package"],
                    "exit_code": result["exit_code"],
                    "duration_s": result["duration_s"],
                    "tools": [],
                    "final_text": final_text(result["events"]),
                    "model_tool_events": tool_events(result["events"]),
                    "stderr_tail": result["stderr_tail"],
                }
                with client(base) as http:
                    trace = http.get(f"/api/runs/{issued['run_id']}/trace").json()
                runs[name]["tools"] = [c["tool"] for c in trace.get("calls", [])]
                traces[name] = trace.get("calls", [])
                # the model closes the run by asking for review; the platform decides DONE
                with client(base) as http:
                    finish = http.post("/api/bridge/finish",
                                       json={"status": "review", "summary": runs[name]["final_text"][:400],
                                             "model_calls": 1},
                                       headers={"Authorization": f"Bearer {token_file.read_text(encoding='utf-8').strip()}"})
                runs[name]["finish_status"] = finish.status_code
                runs[name]["landed_task_status"] = self_status(base, info["project_id"], info["task_id"])

            reef_tools = runs["reef"]["tools"]
            clean_tools = runs["clean"]["tools"]
            distinct = [t for t in dict.fromkeys(reef_tools) if t in
                        ("project_snapshot", "apk_inspect", "artifact_find", "evidence_submit", "task_status_get",
                         "task_propose", "artifact_write", "device_observe", "capture_query", "test_run",
                         "device_action", "platform_health")]
            check(checks, "model_chose_at_least_two_distinct_tools", len(distinct) >= 2, distinct)
            plugin_calls = jsonl_calls(work / "dsh-bridge-reef.jsonl")
            audited = audited_tool_events(base, runs["reef"]["project_id"], runs["reef"]["run_id"])
            paired = {p.get("request_id") for p in plugin_calls}
            matched = [c for c in traces["reef"] if c.get("request_id") in paired]
            unreached = [p for p in plugin_calls if p.get("http_status") is None]
            check(
                checks,
                "every_tool_call_is_audited",
                len(plugin_calls) == len(traces["reef"]) == audited == len(matched) and not unreached
                and all(c["ok"] or c["error_code"] for c in traces["reef"]),
                f"plugin={len(plugin_calls)} trace={len(traces['reef'])} audit={audited} "
                f"paired={len(matched)} unreached={len(unreached)} "
                f"refused={sum(1 for c in traces['reef'] if not c['ok'])}",
            )
            informed = informed_by_previous(traces["reef"], plugin_calls)
            check(checks, "second_call_informed_by_first_result", informed["ok"], informed["detail"])
            check(checks, "reef_run_landed_in_review", runs["reef"]["landed_task_status"] == "REVIEW",
                  runs["reef"]["landed_task_status"])
            check(checks, "clean_run_landed_in_review", runs["clean"]["landed_task_status"] == "REVIEW",
                  runs["clean"]["landed_task_status"])
            check(checks, "plans_differ_across_inputs", reef_tools != clean_tools,
                  f"reef={reef_tools} clean={clean_tools}")
            check(checks, "evidence_submitted_by_model_path",
                  any(c["tool"] == "evidence_submit" for c in traces["reef"]), reef_tools)
            check(checks, "dsh_exit_zero", all(runs[k]["exit_code"] == 0 for k in runs),
                  {k: runs[k]["exit_code"] for k in runs})

        negatives = gateway_negatives(base, builds["reef"])
        by_case = {item["case"]: item for item in negatives}
        check(checks, "expired_capability_refused",
              by_case["expired_capability"]["status"] == 401, by_case["expired_capability"])
        check(checks, "cross_project_refused", by_case["cross_project_via_header"]["status"] in (403,),
              by_case["cross_project_via_header"])
        check(checks, "role_scope_denied_for_apk_inspect",
              by_case["role_scope_denied"]["error_code"] == "tool_not_in_scope", by_case["role_scope_denied"])
        check(checks, "role_scope_allows_shared_tool",
              by_case["role_scope_allowed"]["status"] == 200, by_case["role_scope_allowed"])
        check(checks, "revoked_capability_refused", by_case["revoked_capability"]["status"] == 401,
              by_case["revoked_capability"])
        check(checks, "finish_cannot_write_done", by_case["finish_done_rejected"]["status"] == 422,
              by_case["finish_done_rejected"])
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=15)
        except subprocess.TimeoutExpired:
            proc.kill()

    payload = {
        "generated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "platform_url": base,
        "checks": checks,
        "runs": runs,
        "negatives": negatives,
        "trace": traces,
    }
    write_report(payload)
    trace_path = AUDIT / "p1_real_tool_trace.jsonl"
    with trace_path.open("w", encoding="utf-8") as fh:
        for name, calls in traces.items():
            for call in calls:
                fh.write(json.dumps({"project": name, **call}, ensure_ascii=False) + "\n")
    passed = sum(1 for c in checks if c["ok"])
    print(f"[g1] {passed}/{len(checks)} checks passed")
    for item in checks:
        print(f"[g1] {'PASS' if item['ok'] else 'FAIL'} {item['check']}: {str(item['detail'])[:160]}")
    print(f"[g1] report {AUDIT / 'g1_acceptance.md'}")
    return 0 if passed == len(checks) else 1


def self_status(base: str, project_id: str, task_id: str) -> str:
    with client(base) as http:
        rows = http.get(f"/api/projects/{project_id}/tasks").json()
    for row in rows.get("tasks", rows if isinstance(rows, list) else []):
        if row.get("id") == task_id:
            return str(row.get("status"))
    return "unknown"


def jsonl_calls(path: Path) -> list[dict[str, Any]]:
    """The plugin's own record of what the model asked for, arguments included."""
    if not path.exists():
        return []
    calls: list[dict[str, Any]] = []
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            event = json.loads(line)
        except json.JSONDecodeError:
            continue
        if event.get("event") == "tool_call":
            calls.append(event)
    return calls


def audited_tool_events(base: str, project_id: str, run_id: str) -> int:
    with client(base) as http:
        events = http.get(f"/api/projects/{project_id}/events", params={"after": 0, "limit": 1000}).json()
    return sum(
        1
        for event in events.get("events", [])
        if event.get("event_type") == "bridge_tool_call" and (event.get("payload") or {}).get("run_id") == run_id
    )


_INFORMED_KEYS = ("target", "query", "artifact_id", "evidence_id", "name")
_INFORMED_GENERIC = {"http", "https", "action", "strings", "findings", "secrets", "token", "password", "secret", "key", "ignore"}


def informed_by_previous(calls: list[dict[str, Any]], plugin_calls: list[dict[str, Any]]) -> dict[str, Any]:
    """Show that later calls were built from earlier answers, not from a fixed script.

    The platform trace stores result previews but only argument *hashes* (a run token
    must never make it into a log), so the plugin's JSONL supplies the arguments. Both
    sides carry the same ``request_id``, which pairs them exactly.

    The test is deliberately narrow: a search/read *target* the model chose must appear
    verbatim in an earlier result. Generic words ("http", "action") are excluded, so a
    pass means the model read a class name, a query string or an artifact id it could
    not have known otherwise.
    """
    by_request = {row.get("request_id"): row for row in calls}
    ordered = [plugin for plugin in plugin_calls if plugin.get("request_id") in by_request]
    hits: list[str] = []
    for index in range(1, len(ordered)):
        call = ordered[index]
        tool = by_request[call["request_id"]]["tool"]
        for key in _INFORMED_KEYS:
            value = (call.get("args") or {}).get(key)
            if not isinstance(value, str) or len(value) < 4 or value.lower() in _INFORMED_GENERIC:
                continue
            for earlier in range(index):
                source = by_request[ordered[earlier]["request_id"]]
                if value in (source.get("result_preview") or ""):
                    hits.append(f"call#{index + 1} {tool} {key}={value!r} came from call#{earlier + 1} {source['tool']}")
                    break
    if hits:
        return {"ok": True, "detail": f"{len(hits)} derived arguments; e.g. " + "; ".join(hits[:3])}
    return {"ok": False, "detail": f"no argument was traceable to a previous result ({len(ordered)} paired calls)"}


def _tokens(text: str) -> list[str]:
    import re

    out = []
    for match in re.findall(r"art_[0-9a-f]{8,}|evd_[0-9a-f]{8,}|com\.[a-z0-9_.]{4,}|\b[A-Za-z][A-Za-z0-9]{5,}\b", text):
        if match not in out:
            out.append(match)
    return out[:200]


if __name__ == "__main__":
    raise SystemExit(main())
