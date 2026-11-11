"""P0 step 3b: extract the agent-related plugin surface from DSH's asar.

Read-only. Answers, with code evidence:
  * which package provides the ``agents`` service (and under what name),
  * what a cordis plugin can do with it (observe? create? drive a session?),
  * whether type declarations exist that document the plugin context.

Usage:
  python scripts/p0_dsh_probe2.py --pkg @deepseek-ai/dsh-agent-loop --out audit/_dsh_agent_loop.txt
"""

from __future__ import annotations

import argparse
import json
import os
import re
import struct
import sys
from pathlib import Path

DSH_HOME = Path(os.environ.get("DSH_INSTALL", r"C:\Users\YHY\AppData\Local\Programs\DSH NEXT"))
ASAR = DSH_HOME / "resources" / "app.asar"

PATTERNS = [
    r"ctx\.agents",
    r"ctx\.agent\b",
    r"\bagents\b\s*[:=]",
    r"provide\(['\"]agents",
    r"Service\.(?:define|defineProperty|implements)",
    r"\bcreateAgent\b",
    r"\bagentLoop\b",
    r"interface\s+Context",
    r"interface\s+Agents",
]


def read_index(asar: Path):
    with asar.open("rb") as fh:
        _, _, _, json_len = struct.unpack("<4I", fh.read(16))
        payload = fh.read(json_len)
    return json.loads(payload.decode("utf-8")), 16 + json_len


def walk(node, prefix=""):
    for name, meta in node.get("files", {}).items():
        path = f"{prefix}/{name}" if prefix else name
        if "files" in meta:
            yield from walk(meta, path)
        else:
            yield path, meta


def entry_bytes(asar: Path, base: int, meta: dict) -> bytes:
    with asar.open("rb") as fh:
        fh.seek(base + int(meta["offset"]))
        return fh.read(int(meta["size"]))


def parse_lenient(raw: str) -> dict:
    """asar entries occasionally carry a slightly short size; fall back to regex."""
    for candidate in (raw, raw + "}", raw + "\n}", raw.rsplit(",", 1)[0] + "}"):
        try:
            return json.loads(candidate)
        except Exception:  # noqa: BLE001
            continue
    out: dict = {}
    for key in ("name", "version", "main", "module", "types"):
        m = re.search(rf'"{key}"\s*:\s*"([^"]+)"', raw)
        if m:
            out[key] = m.group(1)
    return out


def pkg_dir_of(entries: dict[str, dict], pkg: str) -> str | None:
    marker = f"node_modules/{pkg}/package.json"
    for path in entries:
        if path.endswith(marker):
            return path[: -len("/package.json")]
    return None


def main(argv=None) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--pkg", action="append", default=None)
    ap.add_argument("--out", default=None)
    ap.add_argument("--context", type=int, default=3)
    ap.add_argument("--max-hits", type=int, default=40)
    args = ap.parse_args(argv)

    pkgs = args.pkg or ["@deepseek-ai/dsh-agent-loop", "@deepseek-ai/dsh-agent"]
    files, base = read_index(ASAR)
    entries = dict(walk(files))

    lines_out: list[str] = []
    summary = {}

    for pkg in pkgs:
        pdir = pkg_dir_of(entries, pkg)
        if not pdir:
            lines_out.append(f"## {pkg}: NOT FOUND")
            continue
        # package.json first
        pj = entries.get(f"{pdir}/package.json")
        raw = entry_bytes(ASAR, base, pj).decode("utf-8", "replace") if pj else "{}"
        meta = parse_lenient(raw)
        own = {k: meta.get(k) for k in ("name", "version", "main", "module", "types", "exports",
                                        "dsh", "cordis", "peerDependencies") if k in meta}
        lines_out.append(f"## {pkg}\n\n```json\n{json.dumps(own, indent=2)[:4000]}\n```\n")

        pkg_files = sorted(
            ((p, m) for p, m in entries.items() if p.startswith(pdir + "/")),
            key=lambda kv: -int(kv[1].get("size", 0)),
        )
        lines_out.append("files: " + ", ".join(
            f"{p[len(pdir) + 1:]}={int(m.get('size', 0))}B" for p, m in pkg_files[:40]) + "\n")

        hits = 0
        for path, m in pkg_files:
            if not re.search(r"\.(js|cjs|mjs|d\.ts|ts)$", path):
                continue
            size = int(m.get("size", 0))
            if size > 3_000_000:
                continue
            text = entry_bytes(ASAR, base, m).decode("utf-8", "replace")
            src_lines = text.splitlines()
            for idx, line in enumerate(src_lines):
                if not any(re.search(p, line) for p in PATTERNS):
                    continue
                if hits >= args.max_hits:
                    break
                lo = max(0, idx - args.context)
                hi = min(len(src_lines), idx + args.context + 1)
                lines_out.append(f"--- {path}:{idx + 1}\n" + "\n".join(
                    f"{i + 1:>6}: {src_lines[i][:220]}" for i in range(lo, hi)) + "\n")
                hits += 1
            if hits >= args.max_hits:
                break
        summary[pkg] = {"files": len(pkg_files), "hit_snippets": hits,
                        "main": own.get("main") or (own.get("exports") or {})}

    report = "\n".join(lines_out)
    if args.out:
        Path(args.out).parent.mkdir(parents=True, exist_ok=True)
        Path(args.out).write_text(report, encoding="utf-8")
    print(json.dumps({"packages": summary, "out": args.out, "chars": len(report)}, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
