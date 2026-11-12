#!/usr/bin/env python3
"""Shape checks for every endpoint the APK-platform web UI (frontend/dist) calls.

The UI is plain vanilla JS with no build step, so nothing type-checks the contract
between frontend/dist/app.js and the FastAPI app. This script is that contract test:
it hits each endpoint the UI uses and asserts the exact keys/types the JS reads,
printing PASS/FAIL per endpoint.

Usage (against a scratch storage server):

    .venv\\Scripts\\python.exe scripts\\ui_smoke.py --base http://127.0.0.1:8791
    .venv\\Scripts\\python.exe scripts\\ui_smoke.py --base http://127.0.0.1:8791 --mutate
    .venv\\Scripts\\python.exe scripts\\ui_smoke.py --base http://127.0.0.1:8765 --token "$TOKEN"

Options:
    --base URL      server root (default http://127.0.0.1:8765)
    --project ID    project to inspect; default = newest project from /api/projects
    --token TOKEN   send Authorization: Bearer TOKEN (token auth mode)
    --mutate        also exercise the task lifecycle (POST task, GET task, PATCH to
                    BLOCKED) and assert the board projection; creates one probe task
    --skip-ingest   skip the hostile-APK 422 envelope check
Exit code 0 when every check passes, 1 otherwise.
"""

from __future__ import annotations

import argparse
import json
import os
import socket
import sys
import urllib.error
import urllib.parse
import urllib.request

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
HOSTILE = os.path.join(ROOT, "samples", "hostile-zip-slip.apk")

METRIC_KEYS = [
    "ingest_success_rate",
    "ingest_attempts",
    "tool_call_schema_valid_rate",
    "tool_calls",
    "evidence_traceability_rate",
    "project_isolation_failures",
    "device_lease_collision",
    "task_recovery_success",
    "reclaimed_leases",
    "false_confident_claims",
    "model_calls_per_task",
    "model_api_latency_ms_avg",
    "tasks_total",
    "projects_total",
    "generated_at",
]

BOARD_COLUMNS = ["TODO", "RUNNING", "REVIEW", "DONE"]

ARGS = None
RESULTS = []


class Fail(AssertionError):
    pass


def need(cond, msg):
    if not cond:
        raise Fail(msg)


# ---------------------------------------------------------------- http helpers


def _request(method, path, body=None, headers=None, timeout=60):
    url = ARGS.base.rstrip("/") + path
    req = urllib.request.Request(url, method=method)
    for key, value in (headers or {}).items():
        req.add_header(key, value)
    if ARGS.token:
        req.add_header("Authorization", "Bearer " + ARGS.token)
    data = None
    if body is not None:
        if isinstance(body, (dict, list)):
            data = json.dumps(body).encode("utf-8")
            req.add_header("Content-Type", "application/json")
        elif isinstance(body, bytes):
            data = body
        else:
            data = str(body).encode("utf-8")
    try:
        with urllib.request.urlopen(req, data=data, timeout=timeout) as resp:
            return resp.status, dict(resp.headers), resp.read()
    except urllib.error.HTTPError as exc:
        return exc.code, dict(exc.headers or {}), exc.read()
    except urllib.error.URLError as exc:
        raise Fail("connection error for %s: %s" % (url, exc.reason)) from exc


def jrequest(method, path, body=None, expect=200):
    status, headers, payload = _request(method, path, body=body)
    ctype = headers.get("Content-Type", headers.get("content-type", ""))
    text = payload.decode("utf-8", "replace")
    if status != expect:
        raise Fail("%s %s -> %s (expected %s); body=%r" % (method, path, status, expect, text[:400]))
    try:
        return json.loads(text)
    except json.JSONDecodeError as exc:
        raise Fail("%s %s -> %s but body is not JSON (%s): %r"
                   % (method, path, status, ctype, text[:200])) from exc


def get(path, expect=200):
    return jrequest("GET", path, expect=expect)


def is_num(value):
    return isinstance(value, (int, float)) and not isinstance(value, bool)


# --------------------------------------------------------------------- checks


def check_health():
    data = get("/api/health")
    for key in ("ok", "version", "auth_mode", "db", "storage", "queue", "tools", "uptime_seconds"):
        need(key in data, "missing key %r" % key)
    need(data["ok"] is True, "ok is %r" % (data["ok"],))
    need(data["auth_mode"] in ("local", "token"), "auth_mode %r" % (data["auth_mode"],))
    need(isinstance(data["db"], dict) and "ok" in data["db"], "db block lacks ok")
    need(isinstance(data["storage"], dict) and "path" in data["storage"], "storage block lacks path")
    need(isinstance(data["queue"], dict), "queue is not an object")
    return "auth_mode=%s queue=%s" % (data["auth_mode"], data["queue"])


def list_projects():
    data = get("/api/projects")
    need(isinstance(data, dict) and isinstance(data.get("projects"), list), "body lacks projects[]")
    rows = data["projects"]
    for row in rows:
        for key in ("id", "name", "status", "package_name", "apk_sha256", "created_at"):
            need(key in row, "project row missing %r: %s" % (key, sorted(row)[:8]))
    return rows


def check_projects():
    rows = list_projects()
    if not rows:
        raise Fail("no projects on this server (ingest one first: apkplat_cli.py create ...)")
    first = rows[0]
    need(isinstance(first["id"], str) and first["id"].startswith("prj_"), "bad id %r" % (first["id"],))
    return "%d project(s); newest=%s (%s)" % (len(rows), first["id"], first["name"])


def check_project(project_id):
    data = get("/api/projects/%s" % project_id)
    need(isinstance(data.get("project"), dict), "body lacks project{}")
    need(isinstance(data.get("manifest"), dict), "body lacks manifest{}")
    project, manifest = data["project"], data["manifest"]
    need(project.get("id") == project_id, "project.id mismatch")
    for key in ("package", "version_name", "version_code", "certificate_sha256"):
        need(key in manifest, "manifest missing %r" % key)
    need(isinstance(manifest.get("ingest"), dict) and "sha256" in manifest["ingest"],
         "manifest.ingest.sha256 missing (project detail sha256 row)")
    need(isinstance(manifest.get("signing"), dict), "manifest.signing missing")
    need(isinstance(manifest.get("permissions"), list), "manifest.permissions missing")
    return "pkg=%s v%s cert=%s..." % (
        manifest["package"], manifest["version_name"], str(manifest["certificate_sha256"])[:12])


def check_board(project_id, expect_status=None, expected_task=None):
    data = get("/api/projects/%s/board" % project_id)
    need(isinstance(data.get("columns"), dict), "body lacks columns{}")
    need(sorted(data["columns"]) == sorted(BOARD_COLUMNS),
         "columns are %s, expected %s" % (sorted(data["columns"]), sorted(BOARD_COLUMNS)))
    need(isinstance(data.get("approvals"), list), "body lacks approvals[]")
    if data.get("project") is not None:
        for key in ("id", "name", "status", "package_name", "apk_sha256"):
            need(key in data["project"], "board.project missing %r" % key)
    total = 0
    for column, cards in data["columns"].items():
        need(isinstance(cards, list), "column %s is not a list" % column)
        for card in cards:
            for key in ("id", "status", "title", "role", "priority", "version"):
                need(key in card, "card in %s missing %r: %s" % (column, key, sorted(card)[:8]))
            total += 1
    note = "%d card(s), %d pending approval(s)" % (total, len(data["approvals"]))
    if expected_task:
        found = [(col, card["status"]) for col, cards in data["columns"].items()
                 for card in cards if card["id"] == expected_task]
        need(found, "probe task %s not on the board" % expected_task)
        note += "; probe task folds into %s with status %s" % found[0]
        if expect_status:
            need(found[0][1] == expect_status,
                 "probe task status is %r, expected %r" % (found[0][1], expect_status))
    return note


def check_artifacts(project_id):
    data = get("/api/projects/%s/artifacts" % project_id)
    need(isinstance(data.get("artifacts"), list), "body lacks artifacts[]")
    rows = data["artifacts"]
    need(rows, "artifacts[] is empty - did the static_pipeline worker run?")
    for row in rows:
        for key in ("id", "kind", "rel_path", "bytes", "sha256", "created_at"):
            need(key in row, "artifact row missing %r" % key)
        need(isinstance(row["bytes"], int), "artifact %s bytes is not an int" % row["id"])
    kinds = sorted({row["kind"] for row in rows})
    return "%d artifact(s): %s" % (len(rows), ", ".join(kinds))


def pick_artifact(project_id, kinds=("metadata", "validation", "summary")):
    rows = get("/api/projects/%s/artifacts" % project_id)["artifacts"]
    for kind in kinds:
        for row in rows:
            if row["kind"] == kind and row["bytes"]:
                return row
    need(rows, "no artifacts to read")
    return rows[0]


def check_artifact_text(artifact_id, tail=False):
    limit = 4000
    data = get("/api/artifacts/%s/text?limit=%d&tail=%s" % (artifact_id, limit, "true" if tail else "false"))
    for key in ("artifact_id", "kind", "sha256", "bytes", "text", "truncated"):
        need(key in data, "artifact text response missing %r" % key)
    need(data["artifact_id"] == artifact_id, "artifact_id mismatch")
    need(isinstance(data["text"], str), "text is not a string")
    need(isinstance(data["truncated"], bool), "truncated is not a bool")
    need(isinstance(data["bytes"], int), "bytes is not an int")
    return "kind=%s bytes=%s text=%dch tail=%s" % (data["kind"], data["bytes"], len(data["text"]), tail)


def check_evidence(project_id):
    data = get("/api/projects/%s/evidence" % project_id)
    need(isinstance(data.get("evidence"), list), "body lacks evidence[]")
    rows = data["evidence"]
    need(rows, "evidence[] is empty - did the static_pipeline worker run?")
    for row in rows:
        for key in ("id", "kind", "claim", "artifact_id", "confidence", "locator", "excerpt"):
            need(key in row, "evidence row missing %r" % key)
        need(row["confidence"] in ("low", "medium", "high"), "confidence %r" % (row["confidence"],))
        need(isinstance(row["locator"], dict),
             "locator is %s, expected object" % type(row["locator"]).__name__)
    kinds = sorted({row["kind"] for row in rows})
    return "%d row(s): %s" % (len(rows), ", ".join(kinds))


def check_verify(project_id):
    data = get("/api/projects/%s/verify" % project_id)
    need(isinstance(data.get("artifacts"), dict), "body lacks artifacts{}")
    need(isinstance(data.get("evidence"), dict), "body lacks evidence{}")
    for key in ("checked", "ok", "failures"):
        need(key in data["artifacts"], "artifacts missing %r" % key)
    for key in ("total", "failures", "traceability_rate"):
        need(key in data["evidence"], "evidence missing %r" % key)
    need(isinstance(data["artifacts"]["failures"], list), "artifacts.failures is not a list")
    need(isinstance(data["evidence"]["traceability_rate"], (int, float)),
         "evidence.traceability_rate is not numeric")
    need(isinstance(data["ok"], bool), "ok is not a bool")
    return "artifacts %s/%s ok, traceability=%s overall_ok=%s" % (
        data["artifacts"]["ok"], data["artifacts"]["checked"],
        data["evidence"]["traceability_rate"], data["ok"])


def check_report(project_id):
    status, _headers, payload = _request("POST", "/api/projects/%s/report" % project_id, body={})
    text = payload.decode("utf-8", "replace")
    if status != 201:
        raise Fail("POST report -> %s (expected 201); body=%r" % (status, text[:400]))
    data = json.loads(text)
    for key in ("project_id", "report_path", "artifact_id", "evidence_rows",
                "traceability_rate", "verification_ok", "markdown"):
        need(key in data, "report response missing %r" % key)
    md = data["markdown"]
    need(isinstance(md, str) and md.startswith("# APK ")
    and ("静态分析报告" in md or "static analysis report" in md),
         "markdown does not start with a report heading: %r" % md[:60])
    need("|" in md, "markdown has no table (renderMarkdown table path untested)")
    need("```" in md, "markdown has no fenced block")
    return "artifact=%s rows=%s markdown=%dch" % (data["artifact_id"], data["evidence_rows"], len(md))


def check_search(project_id, query="onCreate"):
    data = get("/api/projects/%s/search?q=%s&limit=10" % (project_id, query))
    need(data.get("query") == query, "echoed query is %r" % (data.get("query"),))
    need(isinstance(data.get("results"), list), "body lacks results[]")
    rows = data["results"]
    need(rows, "search for %r returned nothing - index missing?" % query)
    for row in rows:
        for key in ("id", "kind", "class_name", "file", "start_line", "end_line"):
            need(key in row, "search row missing %r" % key)
        need(isinstance(row["start_line"], int), "start_line is not an int")
    return "%d hit(s); first=%s:%s" % (len(rows), rows[0]["file"], rows[0]["start_line"])


def check_packages(project_id):
    data = get("/api/projects/%s/packages" % project_id)
    need(isinstance(data.get("packages"), list), "body lacks packages[]")
    need(isinstance(data.get("stats"), dict), "body lacks stats{}")
    need(data["packages"], "packages[] is empty for an analyzed project")
    for row in data["packages"]:
        for key in ("name", "classes", "methods", "source"):
            need(key in row, "package row missing %r" % key)
    stats = data["stats"]
    for key in ("project_id", "package", "version_name", "classes", "methods", "index_bytes"):
        need(key in stats, "stats missing %r" % key)
    return "%d package(s); classes=%s index=%sB" % (len(data["packages"]), stats["classes"], stats["index_bytes"])


def check_metrics():
    data = get("/api/metrics")
    missing = [key for key in METRIC_KEYS if key not in data]
    need(not missing, "metrics missing %s" % missing)
    for key in METRIC_KEYS:
        value = data[key]
        if key == "generated_at":
            need(isinstance(value, str) and value, "generated_at is not a string")
        else:
            need(value is None or is_num(value), "%s is %s (%r)" % (key, type(value).__name__, value))
    numeric = [key for key in METRIC_KEYS if key != "generated_at" and is_num(data[key])]
    nulls = [key for key in METRIC_KEYS if key != "generated_at" and data[key] is None]
    return "%d numeric, %d null (rendered as 'no data')" % (len(numeric), len(nulls))


def check_queue(project_id):
    data = get("/api/queue?project_id=%s" % project_id)
    need(isinstance(data.get("stats"), dict), "body lacks stats{}")
    need(isinstance(data.get("jobs"), list), "body lacks jobs[]")
    statuses = {"PENDING", "RUNNING", "SUCCEEDED", "FAILED", "RETRYING", "CANCELLED"}
    for job in data["jobs"]:
        for key in ("id", "status", "kind", "project_id"):
            need(key in job, "job row missing %r" % key)
        need(job["status"] in statuses, "unknown job status %r" % (job["status"],))
    live = [job for job in data["jobs"] if job["status"] in ("PENDING", "RUNNING", "RETRYING")]
    return "stats=%s live=%d of %d" % (data["stats"], len(live), len(data["jobs"]))


def check_sse(project_id):
    """Read SSE frames; EventSource in the UI relies on `data:` being JSON."""
    url = ARGS.base.rstrip("/") + "/api/events/stream?after=0&project_id=%s" % project_id
    if ARGS.token:
        url += "&token=" + urllib.parse.quote(ARGS.token, safe="")
    req = urllib.request.Request(url)
    old = socket.getdefaulttimeout()
    socket.setdefaulttimeout(1.0)
    frames = 0
    try:
        resp = urllib.request.urlopen(req, timeout=8)
        need(str(resp.headers.get("Content-Type", "")).startswith("text/event-stream"),
             "content-type is %r" % resp.headers.get("Content-Type"))
        buf = b""
        while frames < 8:
            try:
                chunk = resp.read(2048)
            except socket.timeout:
                break
            if not chunk:
                break
            buf += chunk
            while b"\n\n" in buf:
                block, buf = buf.split(b"\n\n", 1)
                data_line = None
                for line in block.decode("utf-8", "replace").splitlines():
                    if line.startswith("data: "):
                        data_line = line[6:]
                if data_line is None:
                    continue  # keep-alive comment
                event = json.loads(data_line)
                for key in ("seq", "event_type", "actor", "created_at"):
                    need(key in event, "SSE event missing %r: %s" % (key, sorted(event)[:8]))
                need(isinstance(event["seq"], int), "SSE seq is not an int")
                frames += 1
        resp.close()
    finally:
        socket.setdefaulttimeout(old)
    need(frames > 0, "no SSE data frames within 8s (UI log would stay empty)")
    return "%d frame(s) parsed as JSON with id/seq/event_type" % frames


def check_error_envelope():
    status, _headers, payload = _request("GET", "/api/projects/prj_00000000000000000000000000000000")
    text = payload.decode("utf-8", "replace")
    need(status == 404, "missing project returned %s, expected 404" % status)
    detail = json.loads(text)
    need(isinstance(detail.get("detail"), dict) and "error_code" in detail["detail"],
         "404 body is not {detail:{error_code,...}}: %r" % text[:200])
    return "404 detail.error_code=%r" % detail["detail"]["error_code"]


def check_hostile():
    if not os.path.exists(HOSTILE):
        return "SKIP (samples/hostile-zip-slip.apk not present)"
    boundary = "----uismoke" + os.urandom(8).hex()
    with open(HOSTILE, "rb") as fh:
        blob = fh.read()
    head = (
        "--%s\r\nContent-Disposition: form-data; name=\"name\"\r\n\r\nui-smoke-hostile\r\n"
        "--%s\r\nContent-Disposition: form-data; name=\"apk\"; filename=\"hostile-zip-slip.apk\"\r\n"
        "Content-Type: application/vnd.android.package-archive\r\n\r\n"
    ) % (boundary, boundary)
    body = head.encode() + blob + ("\r\n--%s--\r\n" % boundary).encode()
    status, _headers, payload = _request(
        "POST", "/api/projects", body=body,
        headers={"Content-Type": "multipart/form-data; boundary=%s" % boundary},
    )
    text = payload.decode("utf-8", "replace")
    need(status == 422, "hostile APK returned %s, expected 422; body=%r" % (status, text[:300]))
    data = json.loads(text)
    need(isinstance(data.get("error_code"), str) and data["error_code"],
         "422 body has no top-level error_code: %r" % text[:200])
    need(isinstance(data.get("message"), str) and data["message"],
         "422 body has no top-level message: %r" % text[:200])
    return "422 error_code=%r message=%r" % (data["error_code"], data["message"][:60])


def check_static():
    notes = []
    status, headers, payload = _request("GET", "/")
    need(status == 200, "GET / -> %s" % status)
    html = payload.decode("utf-8", "replace")
    need("/static/app.js" in html, "/ does not reference /static/app.js")
    need("/static/styles.css" in html, "/ does not reference /static/styles.css")
    notes.append("/ -> 200, %dB" % len(html))

    for path, want in (("/static/app.js", "javascript"), ("/static/styles.css", "css")):
        status, headers, payload = _request("GET", path)
        ctype = headers.get("Content-Type", headers.get("content-type", ""))
        need(status == 200, "GET %s -> %s" % (path, status))
        need(want in ctype.lower(), "%s content-type is %r" % (path, ctype))
        need(len(payload) > 1000, "%s is suspiciously small (%dB)" % (path, len(payload)))
        notes.append("%s -> 200, %dB, %s" % (path, len(payload), ctype.split(";")[0]))
    return "; ".join(notes)


def check_task_lifecycle(project_id):
    created = jrequest("POST", "/api/projects/%s/tasks" % project_id,
                       body={"title": "ui-smoke: probe task", "role": "static",
                             "goal": "exercise task drawer shape", "priority": 5},
                       expect=201)
    task_id = created.get("id")
    need(isinstance(task_id, str), "created task has no id: %s" % created)
    need(created.get("status") == "TODO", "new task status is %r" % (created.get("status"),))

    detail = get("/api/tasks/%s" % task_id)
    need(detail.get("id") == task_id, "GET /api/tasks/{id} did not return the task row directly")
    for key in ("title", "role", "status", "priority", "version", "model_calls",
                "tool_calls", "evidence_count", "depends_on", "attempt"):
        need(key in detail, "task row missing %r" % key)

    patched = jrequest("PATCH", "/api/tasks/%s" % task_id,
                       body={"status": "BLOCKED", "expected_version": created.get("version", 1),
                             "actor": "agent", "reason": "ui-smoke probe"})
    need(patched.get("status") == "BLOCKED", "patch left status %r" % (patched.get("status"),))

    board_note = check_board(project_id, expect_status="BLOCKED", expected_task=task_id)
    return "task %s TODO->BLOCKED; %s" % (task_id, board_note)


def check_control(project_id):
    """Board control bar: GET /control, and (with --mutate) a pause/resume round trip."""
    data = get("/api/projects/%s/control" % project_id)
    for key in ("run_state", "jobs", "tasks", "live_runs", "accepting_work"):
        if key not in data:
            raise CheckFailed("control payload has no %r" % key)
    for key in ("pending", "running", "cancelled", "cancel_requested"):
        if key not in data["jobs"]:
            raise CheckFailed("control jobs has no %r" % key)
    note = "state=%s pending=%d unfinished=%d" % (
        data["run_state"], data["jobs"]["pending"], data["tasks"]["unfinished"])
    if not ARGS.mutate:
        return note

    if data["run_state"] == "RUNNING":
        jrequest("POST", "/api/projects/%s/control" % project_id,
                 body={"action": "pause", "reason": "ui-smoke 往返"})
        paused = get("/api/projects/%s/control" % project_id)
        if paused["run_state"] != "PAUSED":
            raise CheckFailed("pause did not take: %r" % paused["run_state"])
        jrequest("POST", "/api/projects/%s/control" % project_id,
                 body={"action": "resume", "reason": "ui-smoke 往返"})
        resumed = get("/api/projects/%s/control" % project_id)
        if resumed["run_state"] != "RUNNING":
            raise CheckFailed("resume did not take: %r" % resumed["run_state"])
        note += "; paused/resumed"
    cmd = jrequest("POST", "/api/projects/%s/command" % project_id, body={"text": "状态"})
    if not cmd.get("ok"):
        raise CheckFailed("command '状态' failed: %r" % cmd)
    return note


CHECKS = [
    ("GET /api/health", lambda ctx: check_health()),
    ("GET /api/projects", lambda ctx: check_projects()),
    ("GET /api/projects/{id}", lambda ctx: check_project(ctx["project"])),
    ("GET /api/projects/{id}/board", lambda ctx: check_board(ctx["project"])),
    ("GET /api/projects/{id}/artifacts", lambda ctx: check_artifacts(ctx["project"])),
    ("GET /api/artifacts/{id}/text?limit&tail=false",
     lambda ctx: check_artifact_text(ctx["artifact"]["id"], tail=False)),
    ("GET /api/artifacts/{id}/text?limit&tail=true",
     lambda ctx: check_artifact_text(ctx["artifact"]["id"], tail=True)),
    ("GET /api/projects/{id}/evidence", lambda ctx: check_evidence(ctx["project"])),
    ("GET /api/projects/{id}/verify", lambda ctx: check_verify(ctx["project"])),
    ("POST /api/projects/{id}/report", lambda ctx: check_report(ctx["project"])),
    ("GET /api/projects/{id}/search?q=", lambda ctx: check_search(ctx["project"])),
    ("GET /api/projects/{id}/packages", lambda ctx: check_packages(ctx["project"])),
    ("GET /api/metrics", lambda ctx: check_metrics()),
    ("GET /api/queue?project_id=", lambda ctx: check_queue(ctx["project"])),
    ("GET+POST /api/projects/{id}/control|command", lambda ctx: check_control(ctx["project"])),
    ("GET /api/events/stream (SSE)", lambda ctx: check_sse(ctx["project"])),
    ("GET /  +  /static/*", lambda ctx: check_static()),
    ("404 error envelope", lambda ctx: check_error_envelope()),
    ("POST /api/projects (hostile APK -> 422)", lambda ctx: check_hostile()),
]


def main():
    global ARGS
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--base", default=os.environ.get("APKPLAT_UI_BASE", "http://127.0.0.1:8765"))
    parser.add_argument("--project", default=None)
    parser.add_argument("--token", default=os.environ.get("APKPLAT_UI_TOKEN"))
    parser.add_argument("--mutate", action="store_true")
    parser.add_argument("--skip-ingest", action="store_true")
    ARGS = parser.parse_args()
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

    print("base: %s" % ARGS.base)
    if ARGS.token:
        print("auth: bearer token from argument/env")

    ctx = {}
    checks = list(CHECKS)
    if ARGS.mutate:
        checks.append(("POST/GET/PATCH /api/tasks (lifecycle)",
                       lambda ctx: check_task_lifecycle(ctx["project"])))
    if ARGS.skip_ingest:
        checks = [c for c in checks if "hostile" not in c[0]]

    for name, fn in checks:
        try:
            if name == "GET /api/projects/{id}" and "project" not in ctx:
                ctx["project"] = ARGS.project or list_projects()[0]["id"]
                print("project: %s" % ctx["project"])
            if "artifacts/{id}/text" in name and "artifact" not in ctx:
                ctx["artifact"] = pick_artifact(ctx["project"])
            detail = fn(ctx)
            RESULTS.append((name, True, detail or ""))
        except Fail as exc:
            RESULTS.append((name, False, str(exc)))
        except Exception as exc:  # noqa: BLE001 - report, never crash the run
            RESULTS.append((name, False, "%s: %s" % (type(exc).__name__, exc)))

    width = max(len(name) for name, _ok, _detail in RESULTS)
    print()
    for name, ok, detail in RESULTS:
        print("%s  %s  %s" % ("PASS" if ok else "FAIL", name.ljust(width), detail))
    failed = [name for name, ok, _d in RESULTS if not ok]
    print()
    print("%d/%d passed" % (len(RESULTS) - len(failed), len(RESULTS)))
    if failed:
        print("failed: " + "; ".join(failed))
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
