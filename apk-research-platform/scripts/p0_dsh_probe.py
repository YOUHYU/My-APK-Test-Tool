"""P0 step 3: probe the installed DSH NEXT runtime (read-only).

Answers the taskbook's blocking question: does DSH 0.2.1-rc.4 export a plugin API
that lets a bridge plugin observe/drive agents (``ctx.agents`` / agent loop)?

The app ships as a single ``app.asar``. We parse the asar index directly (no
repacking, nothing written into the install), then search the plugin-facing
packages for capability names.

Usage:
  python scripts/p0_dsh_probe.py [--json <path>] [--md <path>]
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import struct
import subprocess
import sys
from pathlib import Path

DSH_HOME = Path(os.environ.get("DSH_INSTALL", r"C:\Users\YHY\AppData\Local\Programs\DSH NEXT"))
ASAR = DSH_HOME / "resources" / "app.asar"
PROFILE_DIR = Path(os.path.expanduser("~")) / ".dsh" / "profiles" / "desktop"

CAPABILITY_TOKENS = [
    "ctx.agents",
    "ctx.agent",
    "agentLoop",
    "agent-loop",
    "agents.create",
    "createAgent",
    "defineAgent",
    "registerAgent",
    "agentSession",
    "agent_session",
    "service('agents')",
    'service("agents")',
    "ctx.tools",
    "registerTool",
    "ctx.mcp",
    "mcpManager",
    "mcp-manager",
]


def read_asar_index(asar: Path) -> tuple[dict, int]:
    with asar.open("rb") as fh:
        header = fh.read(16)
        (_, _, _, json_len) = struct.unpack("<4I", header)
        payload = fh.read(json_len)
    files = json.loads(payload.decode("utf-8"))
    return files, 16 + json_len


def iter_files(node: dict, prefix: str = ""):
    for name, meta in node.get("files", {}).items():
        path = f"{prefix}/{name}" if prefix else name
        if "files" in meta:
            yield from iter_files(meta, path)
        else:
            yield path, meta


def read_entry(asar: Path, base: int, meta: dict) -> bytes:
    with asar.open("rb") as fh:
        fh.seek(base + int(meta["offset"]))
        return fh.read(int(meta["size"]))


def find_plugin_packages(entries: dict[str, dict]) -> dict[str, dict]:
    """Map package name -> its package.json metadata for @deepseek-ai/* bundles."""
    out = {}
    for path, meta in entries.items():
        if not path.endswith("/package.json"):
            continue
        pkg_dir = path[: -len("/package.json")]
        if "node_modules" not in pkg_dir:
            continue
        name = pkg_dir.rsplit("node_modules/", 1)[-1]
        if name.startswith("@deepseek-ai/") or name in {"cordis", "cordis-plugin-loader"}:
            out[name] = {"path": path, "meta": meta, "dir": pkg_dir}
    return out


def scan_tokens(asar: Path, base: int, entries: dict[str, dict], pkg_dir: str,
                tokens: list[str], limit_bytes: int = 4_000_000) -> dict:
    hits: dict[str, list[dict]] = {t: [] for t in tokens}
    scanned = 0
    total = 0
    for path, meta in entries.items():
        if not path.startswith(pkg_dir + "/"):
            continue
        if not re.search(r"\.(js|cjs|mjs|json|d\.ts|ts)$", path):
            continue
        size = int(meta.get("size", 0))
        if size > limit_bytes:
            continue
        try:
            data = read_entry(asar, base, meta)
        except Exception:  # noqa: BLE001
            continue
        scanned += 1
        text = data.decode("utf-8", "replace")
        for token in tokens:
            idx = text.find(token)
            while idx >= 0 and len(hits[token]) < 6:
                line_no = text.count("\n", 0, idx) + 1
                line = text.splitlines()[line_no - 1][:240]
                hits[token].append({"file": path, "line": line_no, "text": line.strip()})
                idx = text.find(token, idx + len(token))
        total += 1
    return {"files_scanned": scanned, "hits": {k: v for k, v in hits.items() if v},
            "packages_scanned_total": total}


def ps_list() -> list[str]:
    try:
        out = subprocess.run(
            ["powershell.exe", "-NoProfile", "-Command",
             "Get-CimInstance Win32_Process | Where-Object { $_.Name -match 'DSH|electron' } "
             "| Select-Object ProcessId,Name,CommandLine | Format-List"],
            capture_output=True, text=True, timeout=40, encoding="utf-8", errors="replace")
        return [ln for ln in (out.stdout or "").splitlines() if ln.strip()]
    except Exception as exc:  # noqa: BLE001
        return [f"<error: {exc}>"]


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--json", default=None)
    ap.add_argument("--md", default=None)
    args = ap.parse_args(argv)

    if not ASAR.exists():
        raise SystemExit(f"app.asar not found: {ASAR}")

    files, base = read_asar_index(ASAR)
    entries = dict(iter_files(files))
    packages = find_plugin_packages(entries)

    report: dict = {
        "asar": {"path": str(ASAR), "bytes": ASAR.stat().st_size,
                 "sha256": hashlib.sha256(ASAR.read_bytes()).hexdigest(),
                 "header_bytes": base, "entries": len(entries)},
        "packages": {},
        "capability_scan": {},
        "processes": ps_list(),
        "profile": {},
    }

    for name, info in sorted(packages.items()):
        try:
            pkg = json.loads(read_entry(ASAR, base, info["meta"]).decode("utf-8", "replace"))
        except Exception:  # noqa: BLE001
            pkg = {}
        report["packages"][name] = {
            "version": pkg.get("version"),
            "main": pkg.get("main") or pkg.get("exports"),
            "dsh": pkg.get("dsh"),
            "cordis": pkg.get("cordis"),
            "peer": pkg.get("peerDependencies"),
            "dir": info["dir"],
        }

    focus = ["@deepseek-ai/dsh-agent-preset", "@deepseek-ai/dsh-mcp-client", "@deepseek-ai/dsh-core",
             "@deepseek-ai/dsh-agent", "@deepseek-ai/dsh-agent-loop", "cordis"]
    for name in focus:
        info = packages.get(name)
        if not info:
            continue
        report["capability_scan"][name] = scan_tokens(ASAR, base, entries, info["dir"],
                                                      CAPABILITY_TOKENS)

    # Broader sweep: any @deepseek-ai package that mentions ctx.agents at all.
    broad = []
    for name, info in sorted(packages.items()):
        if not name.startswith("@deepseek-ai/"):
            continue
        res = scan_tokens(ASAR, base, entries, info["dir"], ["ctx.agents", "agentLoop", "registerTool"])
        if res["hits"]:
            broad.append({"package": name, "hits": res["hits"]})
    report["broad_capability_hits"] = broad

    if PROFILE_DIR.exists():
        for name in ("cordis.patch.yml", "cordis.yml"):
            path = PROFILE_DIR / name
            if path.exists():
                text = path.read_text(encoding="utf-8", errors="replace")
                report["profile"][name] = {
                    "bytes": len(text.encode("utf-8")),
                    "sha256": hashlib.sha256(text.encode("utf-8")).hexdigest(),
                    "mentions_apkplat": "apkplat" in text.lower(),
                    "mcp_entries": len(re.findall(r"dsh-mcp-client", text)),
                }

    out_json = Path(args.json) if args.json else None
    if out_json:
        out_json.parent.mkdir(parents=True, exist_ok=True)
        out_json.write_text(json.dumps(report, indent=2, ensure_ascii=False), encoding="utf-8")

    print(json.dumps({
        "asar_bytes": report["asar"]["bytes"],
        "entries": report["asar"]["entries"],
        "packages": {k: v.get("version") for k, v in report["packages"].items()},
        "capability_hits": {k: sorted(v["hits"].keys()) for k, v in report["capability_scan"].items()},
        "broad_hit_packages": [b["package"] for b in broad],
        "profile": report["profile"],
        "dsh_processes": [ln for ln in report["processes"] if "DSH NEXT" in ln or "electron" in ln][:12],
    }, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
