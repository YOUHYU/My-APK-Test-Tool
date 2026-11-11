"""P0 step 5: resource + model-call baseline.

Measures what the taskbook asks for before any new feature lands:

  * host memory / disk headroom (the concurrency ceilings depend on it),
  * model-call latency for N sequential calls on the operator's existing model line
    (p50 / p95 / max), which is what "model_concurrency = 1" was chosen against,
  * how many calls/second the single-flight gate can sustain.

Writes ``audit/resource_baseline.json`` and ``audit/resource_baseline.md``.
Read-only with respect to the platform: it talks to the model API directly, it does not
enqueue jobs or touch the database.

Usage:
  python scripts/p0_resource_baseline.py [--calls 30] [--max-tokens 64]
"""

from __future__ import annotations

import argparse
import json
import os
import statistics
import subprocess
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "backend"))


def ps(query: str) -> str:
    try:
        out = subprocess.run(["powershell.exe", "-NoProfile", "-Command", query],
                             capture_output=True, text=True, timeout=60,
                             encoding="utf-8", errors="replace")
        return (out.stdout or "").strip()
    except Exception as exc:  # noqa: BLE001
        return f"<error: {exc}>"


def memory_mb() -> dict:
    raw = ps(
        "$os=Get-CimInstance Win32_OperatingSystem;"
        "$free=$os.FreePhysicalMemory/1024;"
        "$total=$os.TotalVisibleMemorySize/1024;"
        "[pscustomobject]@{total_mb=[math]::Round($total);free_mb=[math]::Round($free);"
        "used_pct=[math]::Round(100*(1-$free/$total),1)} | ConvertTo-Json -Compress")
    try:
        return json.loads(raw)
    except Exception:  # noqa: BLE001
        return {"raw": raw[:300]}


def disk_free_gb(path: Path) -> float | None:
    try:
        import shutil
        return round(shutil.disk_usage(path).free / (1024 ** 3), 1)
    except Exception:  # noqa: BLE001
        return None


def top_processes() -> list[dict]:
    raw = ps(
        "Get-Process | Sort-Object -Property WorkingSet64 -Descending | Select-Object -First 8 "
        "Name,@{n='ws_mb';e={[math]::Round($_.WorkingSet64/1MB)}} | ConvertTo-Json -Compress")
    try:
        data = json.loads(raw)
        return data if isinstance(data, list) else [data]
    except Exception:  # noqa: BLE001
        return []


def read_key() -> str | None:
    if os.environ.get("WB_PROXY_API_KEY"):
        return os.environ["WB_PROXY_API_KEY"]
    path = Path.home() / ".dsh" / ".credentials.yaml"
    if not path.exists():
        return None
    try:
        import yaml
        refs = (yaml.safe_load(path.read_text(encoding="utf-8")) or {}).get("refs") or {}
        return str(refs["WB_PROXY_API_KEY"]) if refs.get("WB_PROXY_API_KEY") else None
    except Exception:  # noqa: BLE001
        return None


def percentile(values: list[float], pct: float) -> float:
    if not values:
        return 0.0
    ordered = sorted(values)
    idx = min(len(ordered) - 1, max(0, int(round((pct / 100) * (len(ordered) - 1)))))
    return round(ordered[idx], 1)


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--calls", type=int, default=30)
    ap.add_argument("--max-tokens", type=int, default=64)
    ap.add_argument("--prompt", default="Reply with the single word: ready")
    args = ap.parse_args(argv)

    import httpx

    key = read_key()
    if not key:
        raise SystemExit("no model key available")
    base = os.environ.get("APKPLAT_MODEL_BASE_URL", "http://192.168.43.1:8788/v1")
    model = os.environ.get("APKPLAT_MODEL_ID", "deepseek-v4.1-flash")

    mem_before = memory_mb()
    samples: list[dict] = []
    client = httpx.Client(timeout=120.0, trust_env=False)
    try:
        for i in range(args.calls):
            payload = {"model": model, "max_tokens": args.max_tokens,
                       "messages": [{"role": "user", "content": args.prompt}]}
            started = time.perf_counter()
            entry: dict = {"i": i + 1}
            try:
                resp = client.post(f"{base}/chat/completions", json=payload,
                                   headers={"Authorization": f"Bearer {key}",
                                            "Content-Type": "application/json"})
                entry["latency_ms"] = round((time.perf_counter() - started) * 1000, 1)
                entry["status"] = resp.status_code
                body = resp.json()
                usage = body.get("usage") or {}
                entry["completion_tokens"] = usage.get("completion_tokens")
                choice = (body.get("choices") or [{}])[0]
                message = choice.get("message") or {}
                entry["has_content"] = bool((message.get("content") or "").strip())
                entry["has_reasoning"] = bool((message.get("reasoning_content") or "").strip())
            except Exception as exc:  # noqa: BLE001
                entry["latency_ms"] = round((time.perf_counter() - started) * 1000, 1)
                entry["status"] = "error"
                entry["error"] = f"{type(exc).__name__}: {exc}"[:200]
            samples.append(entry)
            print(f"[{i + 1}/{args.calls}] {entry.get('status')} {entry['latency_ms']}ms", flush=True)
    finally:
        client.close()

    mem_after = memory_mb()
    latencies = [s["latency_ms"] for s in samples if s.get("status") == 200]
    errors = [s for s in samples if s.get("status") != 200]
    report = {
        "generated_at": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
        "model": {"base_url": base, "model": model, "max_tokens": args.max_tokens,
                  "prompt": args.prompt, "calls": args.calls},
        "memory_before": mem_before,
        "memory_after": mem_after,
        "disk_free_gb": {"d": disk_free_gb(Path("D:/")), "c": disk_free_gb(Path("C:/"))},
        "top_processes": top_processes(),
        "latency_ms": {
            "ok_calls": len(latencies),
            "errors": len(errors),
            "min": round(min(latencies), 1) if latencies else None,
            "p50": percentile(latencies, 50),
            "p95": percentile(latencies, 95),
            "max": round(max(latencies), 1) if latencies else None,
            "mean": round(statistics.fmean(latencies), 1) if latencies else None,
        },
        "throughput_calls_per_min": round(60000 / statistics.fmean(latencies), 2) if latencies else None,
        "samples": samples,
    }
    out_json = ROOT / "audit" / "resource_baseline.json"
    out_json.write_text(json.dumps(report, indent=2, ensure_ascii=False), encoding="utf-8")

    lat = report["latency_ms"]
    md = [
        "# Resource and model baseline (P0)", "",
        f"- generated_at: `{report['generated_at']}`",
        f"- model: `{model}` at `{base}` (the operator's existing line; nothing reconfigured)",
        f"- calls: {args.calls} sequential, max_tokens={args.max_tokens}", "",
        "## Host", "",
        f"- memory before: {mem_before}",
        f"- memory after: {mem_after}",
        f"- disk free: D {report['disk_free_gb']['d']} GB, C {report['disk_free_gb']['c']} GB", "",
        "top processes by working set:", "",
        "| process | ws_mb |", "|---|---|",
    ]
    for proc in report["top_processes"]:
        md.append(f"| {proc.get('Name')} | {proc.get('ws_mb')} |")
    md += ["", "## Model call latency", "",
           f"- successful calls: {lat['ok_calls']} / {args.calls} (errors: {lat['errors']})",
           f"- min / p50 / p95 / max: {lat['min']} / {lat['p50']} / {lat['p95']} / {lat['max']} ms",
           f"- mean: {lat['mean']} ms -> {report['throughput_calls_per_min']} calls/min per single flight", "",
           "## Consequence for the platform", "",
           "A single-flight model call costs about "
           f"{round((lat['p50'] or 0) / 1000, 1)}s at the median. Anything that needs N model turns "
           f"needs at least N x that, so a card with a 3-turn agent loop is a "
           f"{round(3 * (lat['p50'] or 0) / 1000, 0)}s+ operation and the 300s job lease is adequate "
           "only if heartbeats keep flowing.", ""]
    (ROOT / "audit" / "resource_baseline.md").write_text("\n".join(md), encoding="utf-8")
    print(json.dumps({"ok_calls": lat["ok_calls"], "errors": lat["errors"],
                      "p50": lat["p50"], "p95": lat["p95"], "max": lat["max"]}, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
