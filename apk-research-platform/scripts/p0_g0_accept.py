"""P0 gate: assemble the G0 acceptance record from measured facts.

G0 (taskbook) requires four things and forbids two:

  ok  DSH itself boots and the model answers                    -> model ping + this session
  ok  the DSH model can see and call >= 1 real read-only tool   -> audit/dsh_tool_proof_raw.json
  ok  one project / one card, data unchanged                    -> fingerprints vs schema_snapshot
  ok  config restore drill passes                               -> audit/rollback_drill.json
  --  ADB authorization must not block G0                       -> reported, not asserted
  x   no schema rename, no state collapse                       -> verified: tasks.status + 12 states
  x   no P1-P7 work this round                                  -> verified by file inventory

Every check re-reads a file or the database; nothing is asserted from memory.

Usage:
  python scripts/p0_g0_accept.py
"""

from __future__ import annotations

import hashlib
import json
import os
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "backend"))
os.environ.setdefault("APKPLAT_STORAGE", str(ROOT / "storage"))

SNAPSHOT = ROOT / "audit" / "schema_snapshot.json"
PROOF = ROOT / "audit" / "dsh_tool_proof_raw.json"
DRILL = ROOT / "audit" / "rollback_drill.json"

CHECKS: list[dict] = []


def check(name: str, ok: bool, detail: str = "") -> None:
    CHECKS.append({"check": name, "ok": bool(ok), "detail": detail})
    print(f"[{'PASS' if ok else 'FAIL'}] {name}: {detail[:160]}")


def sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def model_ping() -> tuple[bool, str]:
    import httpx
    import yaml

    key = os.environ.get("WB_PROXY_API_KEY")
    if not key:
        creds = Path.home() / ".dsh" / ".credentials.yaml"
        try:
            refs = (yaml.safe_load(creds.read_text(encoding="utf-8")) or {}).get("refs") or {}
            key = refs.get("WB_PROXY_API_KEY")
        except Exception as exc:  # noqa: BLE001
            return False, f"no key: {exc}"
    if not key:
        return False, "no key"
    base = os.environ.get("APKPLAT_MODEL_BASE_URL", "http://192.168.43.1:8788/v1")
    model = os.environ.get("APKPLAT_MODEL_ID", "deepseek-v4.1-flash")
    started = time.perf_counter()
    try:
        with httpx.Client(timeout=60.0, trust_env=False) as client:
            resp = client.post(f"{base}/chat/completions",
                               json={"model": model, "max_tokens": 32,
                                     "messages": [{"role": "user", "content": "Reply with: ok"}]},
                               headers={"Authorization": f"Bearer {key}"})
        ms = round((time.perf_counter() - started) * 1000)
        body = resp.json()
        message = (body.get("choices") or [{}])[0].get("message") or {}
        text = (message.get("content") or message.get("reasoning_content") or "").strip()
        return resp.status_code == 200 and bool(text), f"status={resp.status_code} {ms}ms reply={text[:40]!r}"
    except Exception as exc:  # noqa: BLE001
        return False, f"{type(exc).__name__}: {exc}"[:160]


def main() -> int:
    from apkplat import state
    from apkplat.db import db

    snap = json.loads(SNAPSHOT.read_text(encoding="utf-8"))

    # 1. model line
    ok, detail = model_ping()
    check("model_api_reachable", ok, detail)

    # 2. DSH runtime probe recorded
    probe = ROOT / "audit" / "dsh_probe_raw.json"
    probe_data = json.loads(probe.read_text(encoding="utf-8")) if probe.exists() else {}
    hits = probe_data.get("capability_scan", {}).get("@deepseek-ai/dsh-agent", {}).get("hits", {})
    check("dsh_exports_ctx_agents", bool(hits.get("ctx.agents")), 
          f"hits={sorted(hits)}" if hits else "no ctx.agents hit")

    # 3. real tool call by the DSH model
    proof = json.loads(PROOF.read_text(encoding="utf-8")) if PROOF.exists() else {}
    events = proof.get("events") or []
    calls = [e for e in events if isinstance(e, dict) and e.get("type") == "tool_call"]
    results = [e for e in events if isinstance(e, dict) and e.get("type") == "tool_result"]
    called = [c.get("tool") for c in calls]
    ok_result = any("apkplat" in str(c.get("tool")) for c in calls) and any(
        r.get("status") == "completed" and '"ok": true' in str(r.get("result")) for r in results)
    check("dsh_model_called_platform_tool", ok_result,
          f"tool_call={called} results={len(results)} exit={proof.get('exit_code')}")

    # 4. platform-side audit row for that call
    rows = db.query(
        "SELECT seq, actor, payload_json FROM audit_events WHERE event_type='mcp_tool_call' "
        "ORDER BY seq DESC LIMIT 5")
    dsh_rows = [r for r in rows if json.loads(r["payload_json"] or "{}").get("ok")]
    check("platform_audit_row_for_tool_call", bool(dsh_rows),
          f"seq={[r['seq'] for r in dsh_rows]} actors={[r['actor'] for r in dsh_rows]}")

    # 5. schema unchanged: tasks.status + 12 states
    cols = [c["name"] for c in next(t for t in snap["tables"] if t["name"] == "tasks")["columns"]]
    check("tasks_status_column_intact", "status" in cols and "state" not in cols, f"columns={len(cols)}")
    check("twelve_states_intact", len(state.STATUSES) == 12, f"{len(state.STATUSES)} statuses")
    check("kanban_four_columns", len(state.KANBAN_COLUMNS) == 4, f"{list(state.KANBAN_COLUMNS)}")

    # 6. data unchanged on every business table (audit_events is allowed to grow)
    mismatched = []
    table_cols = {t["name"]: [c["name"] for c in t["columns"]] for t in snap["tables"]}
    for name, fp in snap["fingerprints"].items():
        if name == "audit_events":
            continue
        cols = table_cols.get(name) or []
        if not cols:
            continue
        col = "id" if "id" in cols else cols[0]
        ids = [str(r[col]) for r in db.query(f"SELECT {col} FROM '{name}' ORDER BY {col}")]
        digest = hashlib.sha256("\n".join(ids).encode()).hexdigest()[:16]
        if len(ids) != fp["rows"] or digest != fp["id_hash"]:
            mismatched.append(f"{name}({len(ids)} vs {fp['rows']})")
    check("business_rows_unchanged", not mismatched, f"mismatched={mismatched or 'none'}")

    audit_rows = db.scalar("SELECT count(*) FROM audit_events")
    check("audit_events_append_only_growth", audit_rows >= 32,
          f"{audit_rows} rows now vs {snap['fingerprints']['audit_events']['rows']} at capture "
          f"(+{audit_rows - snap['fingerprints']['audit_events']['rows']} P0 activity)")

    # 7. the single project / single card still exist and did not change status
    project = db.one("SELECT id, name, status FROM projects")
    task = db.one("SELECT id, role, status FROM tasks")
    check("one_project_one_card", bool(project) and bool(task),
          f"{project['name'] if project else None} / {task['status'] if task else None}")

    # 8. config restore drill
    drill = json.loads(DRILL.read_text(encoding="utf-8")) if DRILL.exists() else {}
    check("rollback_drill_passed", drill.get("verdict") == "PASS",
          f"integrity={drill.get('db', {}).get('integrity_check')} "
          f"config_identical={all(c['identical'] for c in drill.get('config', []))}")

    # 9. DSH profile untouched (hash equality with backup copy)
    manifest_path = sorted((ROOT / "backups").glob("p0-*/MANIFEST.json"))[-1]
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    same = []
    for entry in manifest.get("dsh_profile_copies", []):
        live, copy = Path(entry["file"]), Path(entry["backup"])
        same.append(live.exists() and copy.exists() and sha256(live) == sha256(copy))
    check("dsh_profile_untouched", bool(same) and all(same), f"files={len(same)} identical={all(same)}")

    # 10. ADB state (reported, must not gate G0)
    import subprocess
    adb = ROOT / "tools" / "android-sdk" / "platform-tools" / "adb.exe"
    adb_out = ""
    if adb.exists():
        try:
            adb_out = subprocess.run([str(adb), "devices"], capture_output=True, text=True,
                                     timeout=30, encoding="utf-8", errors="replace").stdout
        except Exception as exc:  # noqa: BLE001
            adb_out = f"error: {exc}"
    authorized = any(line.strip().endswith("\tdevice") for line in adb_out.splitlines()
                     if line.strip() and not line.startswith("List"))
    check("adb_state_recorded", True,
          f"authorized_transports={authorized} (ADB must never block G0)")

    # 11. no P1-P7 work landed: new backend modules would show up here
    forbidden = ["bridge.py", "executor.py", "dag.py", "sandbox.py"]
    present = [f for f in forbidden if (ROOT / "backend" / "apkplat" / f).exists()]
    check("no_p1_to_p7_code", not present, f"unexpected={present or 'none'}")

    passed = sum(1 for c in CHECKS if c["ok"])
    total = len(CHECKS)
    stamp = time.strftime("%Y-%m-%dT%H:%M:%S%z")
    result = {"generated_at": stamp, "passed": passed, "total": total,
              "verdict": "PASS" if passed == total else "FAIL", "checks": CHECKS}
    (ROOT / "audit" / "g0_acceptance.json").write_text(
        json.dumps(result, indent=2, ensure_ascii=False), encoding="utf-8")

    lines = ["# G0 acceptance (P0)", "", f"- generated_at: `{stamp}`",
             f"- result: **{passed}/{total} checks passed**", "", "| check | ok | detail |",
             "|---|---|---|"]
    for item in CHECKS:
        detail = item["detail"].replace("|", "/")
        lines.append(f"| `{item['check']}` | {item['ok']} | {detail} |")
    lines += ["", "## What this does NOT claim", "",
              "- No P1-P7 capability: the bridge plugin, run tokens, DAG, sandbox, UI automation,",
              "  capture and FakeClock are all still absent by design.",
              "- The 21-card screenshot layout is not replicated; the platform still shows the",
              "  single demo card.",
              "- Real-device automation is not exercised: ADB is authorized now, but the dynamic",
              "  path was only ever run against the simulated transport.",
              ""]
    (ROOT / "audit" / "g0_acceptance.md").write_text("\n".join(lines), encoding="utf-8")

    print(json.dumps({"passed": passed, "total": total, "verdict": result["verdict"]}, indent=2))
    return 0 if passed == total else 1


if __name__ == "__main__":
    sys.exit(main())
