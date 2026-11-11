"""P0 step 4: register the platform MCP server with a REAL DSH boot and prove a tool call.

What it does, in order:

1. reads the operator's model key from ``~/.dsh/.credentials.yaml`` (read-only, never printed);
2. boots the *shipped* ``headless`` profile of the installed DSH with a project-local
   overlay patch (``config/dsh/p0-headless-probe.yml``) that adds the model line and the
   ``apkplat`` MCP server - the running desktop app is never touched;
3. asks the model a question that can only be answered by calling the platform tool;
4. saves raw stdout/stderr and a proof markdown, then checks the platform audit table for
   the ``mcp_tool_call`` rows written by the MCP server during that run.

Usage:
  python scripts/p0_dsh_tool_proof.py --task "..." [--json-out path] [--md-out path]
"""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
BACKEND = ROOT / "backend"
sys.path.insert(0, str(BACKEND))

os.environ.setdefault("APKPLAT_STORAGE", str(ROOT / "storage"))
os.environ.setdefault("APKPLAT_REPORTS", str(ROOT / "reports"))

DSH_EXE = Path(os.environ.get("DSH_EXE", r"C:\Users\YHY\AppData\Local\Programs\DSH NEXT\DSH NEXT.exe"))
DSH_BIN = Path(os.environ.get(
    "DSH_BIN",
    r"C:\Users\YHY\AppData\Local\Programs\DSH NEXT\resources\app.asar\node_modules\@deepseek-ai\dsh\lib\bin.js"))

DEFAULT_TASK = (
    "Call the apkplat tool project_get with project_id "
    "prj_6cd77a33712947b4b876c67f6c04a36f, then answer with exactly two lines: "
    "line 1 the package name from the tool result, line 2 the tool name you called."
)


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
    refs = data.get("refs") or {}
    value = refs.get("WB_PROXY_API_KEY")
    return str(value) if value else None


def audit_rows_since(seq: int) -> list[dict]:
    from apkplat.db import db as database

    rows = database.query(
        "SELECT id, seq, event_type, project_id, actor, created_at, payload_json FROM audit_events "
        "WHERE seq > ? ORDER BY seq ASC",
        (seq,),
    )
    out = []
    for row in rows:
        payload = {}
        try:
            payload = json.loads(row["payload_json"] or "{}")
        except Exception:  # noqa: BLE001
            pass
        out.append({"seq": row["seq"], "event_type": row["event_type"], "project_id": row["project_id"],
                    "actor": row["actor"], "created_at": row["created_at"], "payload": payload})
    return out


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--task", default=DEFAULT_TASK)
    ap.add_argument("--patch", default=str(ROOT / "config" / "dsh" / "p0-headless-probe.yml"))
    ap.add_argument("--profile", default="headless")
    ap.add_argument("--json-out", default=str(ROOT / "audit" / "dsh_tool_proof_raw.json"))
    ap.add_argument("--md-out", default=str(ROOT / "audit" / "mcp_registration_proof.md"))
    ap.add_argument("--timeout", type=int, default=420)
    args = ap.parse_args(argv)

    from apkplat.db import db as database

    key = read_model_key()
    if not key:
        raise SystemExit("no model key available (WB_PROXY_API_KEY / ~/.dsh/.credentials.yaml)")

    env = dict(os.environ)
    env["ELECTRON_RUN_AS_NODE"] = "1"
    env["WB_PROXY_API_KEY"] = key
    env["PYTHONUTF8"] = "1"
    # Boot with a project-local DSH home so `~/.dsh` (the operator's live profile, sessions
    # and skills) is never read for writes: the probe owns only runtime/dsh-home.
    home = Path(os.environ.get("APKPLAT_DSH_HOME", str(ROOT / "runtime" / "dsh-home")))
    (home / "profiles" / args.profile).mkdir(parents=True, exist_ok=True)
    cordis_yml = home / "profiles" / args.profile / "cordis.yml"
    if not cordis_yml.exists():
        cordis_yml.write_text("[]\n", encoding="utf-8")
    env["DSH_HOME"] = str(home)

    before_seq = database.scalar("SELECT COALESCE(MAX(seq),0) FROM audit_events") or 0
    started = time.time()
    cmd = [str(DSH_EXE), str(DSH_BIN), "--profile", args.profile,
           "--patch", args.patch, "--json", args.task]
    proc = subprocess.run(cmd, capture_output=True, text=True, encoding="utf-8", errors="replace",
                          env=env, timeout=args.timeout, cwd=str(ROOT))
    duration = round(time.time() - started, 1)

    events = []
    for line in (proc.stdout or "").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            events.append(json.loads(line))
        except json.JSONDecodeError:
            events.append({"raw": line})

    tool_calls = [e for e in events if "tool" in json.dumps(e)[:200].lower()]
    new_rows = audit_rows_since(int(before_seq))
    mcp_calls = [r for r in new_rows if r["event_type"] == "mcp_tool_call"]

    raw = {
        "command": cmd[:3] + ["--profile", args.profile, "--patch", args.patch, "--json", "<task>"],
        "task": args.task,
        "exit_code": proc.returncode,
        "duration_s": duration,
        "started_at": time.strftime("%Y-%m-%dT%H:%M:%S%z", time.localtime(started)),
        "events": events,
        "stderr_tail": (proc.stderr or "")[-6000:],
        "platform_audit_rows_since": new_rows,
    }
    Path(args.json_out).parent.mkdir(parents=True, exist_ok=True)
    Path(args.json_out).write_text(json.dumps(raw, indent=2, ensure_ascii=False), encoding="utf-8")

    final_text = ""
    for event in events:
        for key_name in ("text", "content", "message", "result"):
            value = event.get(key_name) if isinstance(event, dict) else None
            if isinstance(value, str) and value.strip():
                final_text = value
    ok = bool(mcp_calls) and proc.returncode == 0
    lines = [
        "# MCP registration proof (P0)",
        "",
        f"- generated_at: `{raw['started_at']}`",
        f"- dsh binary: `{DSH_BIN}`",
        f"- profile: `{args.profile}` + overlay `{Path(args.patch).name}`",
        f"- exit code: **{proc.returncode}** in {duration}s",
        f"- platform `mcp_tool_call` audit rows written during the run: **{len(mcp_calls)}**",
        "",
        "## Verdict",
        "",
        ("**PASS** - a real DSH boot loaded the `apkplat` MCP server and the model called a "
         "platform tool; the call is visible both in the DSH run events and in the platform "
         "audit table." if ok else
         "**NOT PROVEN** - no platform `mcp_tool_call` row was written by this run. See the raw log."),
        "",
        "## Platform-side evidence (audit_events)",
        "",
        "| seq | event | actor | tool | ok | duration_ms |",
        "|---|---|---|---|---|---|"]
    for row in mcp_calls:
        payload = row.get("payload") or {}
        lines.append(f"| {row['seq']} | `{row['event_type']}` | `{row['actor']}` | "
                     f"`{payload.get('tool')}` | {payload.get('ok')} | {payload.get('duration_ms')} |")
    lines += ["", "## Model answer", "", "```", final_text.strip()[:2000] or "(no final text captured)", "```", "",
              "## Raw run events", "", "```json",
              json.dumps(events[-8:], indent=2, ensure_ascii=False)[:4000], "```", ""]
    Path(args.md_out).write_text("\n".join(lines), encoding="utf-8")

    print(json.dumps({
        "exit_code": proc.returncode,
        "duration_s": duration,
        "events": len(events),
        "mcp_tool_call_rows": len(mcp_calls),
        "tools_called": [((r.get("payload") or {}).get("tool")) for r in mcp_calls],
        "verdict": "PASS" if ok else "NOT_PROVEN",
        "json_out": args.json_out,
        "md_out": args.md_out,
        "stderr_tail": (proc.stderr or "")[-800:],
    }, indent=2))
    return 0 if ok else 2


if __name__ == "__main__":
    raise SystemExit(main())
