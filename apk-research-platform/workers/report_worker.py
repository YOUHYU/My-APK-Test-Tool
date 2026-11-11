"""Report worker entry point.

Claims ``report_generate`` jobs only: Markdown rendering is cheap but it is the step
that touches the evidence ledger, so keeping it on its own worker makes report
latency and report failures observable in isolation.

    python workers/report_worker.py --once
"""
from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "backend"))

from apkplat import worker  # noqa: E402

KINDS = ("report_generate",)


def main() -> int:
    return worker.main(["--kinds", ",".join(KINDS), *sys.argv[1:]])


if __name__ == "__main__":
    raise SystemExit(main())
