"""Ad-hoc: test candidate 'informed by previous result' rules against real runs."""
import json
import re
import sqlite3
from pathlib import Path

root = Path(r"D:\ADeespseekSH\REA\apk-research-platform")
db = sqlite3.connect(str(root / "runtime/p1-g1/storage/platform.db"))
db.row_factory = sqlite3.Row

calls = {}
for path in sorted((root / "runtime/p1-g1").glob("dsh-bridge-*.jsonl")):
    for line in path.read_text(encoding="utf-8").splitlines():
        event = json.loads(line)
        if event.get("event") == "tool_call":
            calls[event.get("request_id")] = event

GENERIC = {"http", "https", "action", "strings", "findings", "secrets", "token", "password", "secret", "key", "ignore"}
KEYS = {"target", "query", "artifact_id", "evidence_id", "name"}

runs = db.execute(
    "SELECT run_id, COUNT(*) n FROM run_tool_calls GROUP BY run_id HAVING n >= 5 ORDER BY n DESC"
).fetchall()
for run in runs:
    rows = db.execute(
        "SELECT seq, tool, request_id, result_preview FROM run_tool_calls WHERE run_id=? ORDER BY seq",
        (run["run_id"],),
    ).fetchall()
    ordered = [calls.get(r["request_id"]) for r in rows]
    hits = []
    for j in range(1, len(rows)):
        call = ordered[j]
        if not call:
            continue
        for key in KEYS:
            value = (call.get("args") or {}).get(key)
            if not isinstance(value, str) or len(value) < 4 or value.lower() in GENERIC:
                continue
            for i in range(j):
                preview = rows[i]["result_preview"] or ""
                if value in preview:
                    hits.append((j + 1, call["tool"], key, value, rows[i]["tool"]))
                    break
    print(f"run {run['run_id'][:12]} rows={run['n']} paired={sum(1 for c in ordered if c)} hits={len(hits)}")
    for hit in hits[:6]:
        print(f"   call#{hit[0]} {hit[1]} {hit[2]}={hit[3]!r} <- {hit[4]}")
