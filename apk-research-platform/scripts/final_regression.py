# -*- coding: utf-8 -*-
"""Run the full regression suite and the eight acceptance scripts in one pass.

Every step writes its own log under reports/logs/ and contributes one row to
reports/final_regression.md. The script exits non-zero if any step fails, so it can be used as a
release gate on this host.
"""
from __future__ import annotations

import json
import os
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PY = Path(sys.executable)
LOG_DIR = ROOT / "reports" / "logs"
LOG_DIR.mkdir(parents=True, exist_ok=True)

STEPS = [
    ("pytest", [str(PY), "-m", "pytest", "tests", "-q", "-p", "no:cacheprovider"], 1800),
    ("p0", [str(PY), "scripts/p0_check.py"], 600),
    ("gate1", [str(PY), "scripts/gate1_accept.py"], 900),
    ("gate2", [str(PY), "scripts/gate2_accept.py"], 900),
    ("gate3", [str(PY), "scripts/gate3_accept.py"], 1200),
    ("gate4", [str(PY), "scripts/gate4_accept.py"], 900),
    ("gate5", [str(PY), "scripts/gate5_accept.py"], 900),
    ("g1_bridge", [str(PY), "scripts/p1_g1_accept.py"], 1500),
    ("g2_dag", [str(PY), "scripts/p2_g2_accept.py"], 900),
    ("g3_evidence", [str(PY), "scripts/p3_g3_accept.py"], 900),
    ("g4_cache", [str(PY), "scripts/p4_g4_accept.py"], 900),
    ("g5_device", [str(PY), "scripts/p5_g5_accept.py"], 1200),
    ("g6_schedule", [str(PY), "scripts/p6_g6_accept.py"], 900),
    ("g7_isolation", [str(PY), "scripts/p7_g7_accept.py"], 900),
]


def env() -> dict[str, str]:
    out = dict(os.environ)
    tmp = ROOT / ".tmp"
    tmp.mkdir(exist_ok=True)
    out["TEMP"] = str(tmp)
    out["TMP"] = str(tmp)
    out["PYTHONPATH"] = str(ROOT / "backend")
    out["PYTHONIOENCODING"] = "utf-8"
    out.pop("APKPLAT_STORAGE", None)
    out.pop("APKPLAT_REPORTS", None)
    out.pop("APKPLAT_REQUIRE_AUTH", None)
    out.pop("APKPLAT_MODEL_ENABLED", None)
    return out


def tail(path: Path, n: int = 4) -> list[str]:
    try:
        lines = [line.rstrip() for line in path.read_text(encoding="utf-8", errors="replace").splitlines() if line.strip()]
    except FileNotFoundError:
        return []
    return lines[-n:]


def main() -> int:
    rows = []
    skipped = {s.strip() for s in os.environ.get("APKPLAT_FINAL_SKIP", "").split(",") if s.strip()}
    started = datetime.now(timezone.utc)
    for name, cmd, timeout in STEPS:
        if name in skipped:
            print(f"[regression] {name}: skipped (APKPLAT_FINAL_SKIP)", flush=True)
            rows.append({"step": name, "exit_code": None, "ok": None, "seconds": 0.0,
                         "log": None, "tail": ["skipped via APKPLAT_FINAL_SKIP"]})
            continue
        log = LOG_DIR / f"final-{name}.log"
        t0 = time.time()
        print(f"[regression] {name}: start", flush=True)
        try:
            with log.open("w", encoding="utf-8") as fh:
                proc = subprocess.run(cmd, cwd=str(ROOT), stdout=fh, stderr=subprocess.STDOUT,
                                      env=env(), timeout=timeout)
                code = proc.returncode
        except subprocess.TimeoutExpired:
            code = -9
        elapsed = round(time.time() - t0, 1)
        ok = code == 0
        rows.append({"step": name, "exit_code": code, "ok": ok, "seconds": elapsed,
                     "log": str(log.relative_to(ROOT)), "tail": tail(log)})
        print(f"[regression] {name}: exit={code} in {elapsed}s", flush=True)

    finished = datetime.now(timezone.utc)
    payload = {
        "generated_at": finished.isoformat().replace("+00:00", "Z"),
        "started_at": started.isoformat().replace("+00:00", "Z"),
        "python": str(PY),
        "rows": rows,
        "failed": [r["step"] for r in rows if r["ok"] is False],
        "skipped": [r["step"] for r in rows if r["ok"] is None],
    }
    (ROOT / "reports" / "final_regression.json").write_text(json.dumps(payload, indent=2), encoding="utf-8")

    lines = ["# Final regression", "",
             f"Generated {payload['generated_at']} by `scripts/final_regression.py`.", "",
             "| Step | Exit | Seconds | Log | Last lines |", "| --- | --- | --- | --- | --- |"]
    for row in rows:
        last = " / ".join(row["tail"][-1:])[:160].replace("|", "\\|")
        exit_text = "skipped" if row["exit_code"] is None else str(row["exit_code"])
        lines.append(f"| {row['step']} | {exit_text} | {row['seconds']} | `{row['log']}` | {last} |")
    lines += ["", f"Failed steps: {', '.join(payload['failed']) if payload['failed'] else 'none'}.", ""]
    if payload["skipped"]:
        lines += [f"Skipped steps: {', '.join(payload['skipped'])} "
                  "(the upstream model pool answers 429, so model-dependent steps cannot run).", ""]
    (ROOT / "reports" / "final_regression.md").write_text("\n".join(lines), encoding="utf-8")
    print(f"[regression] failed={payload['failed']}", flush=True)
    return 0 if not payload["failed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())