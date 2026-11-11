"""Dynamic-analysis worker entry point.

Only claims ``dynamic_analysis`` jobs, so a device pool can be sized independently
from the static pipeline (one worker per device group in practice). Device
serialisation itself is enforced by the lease table, not by this process.

    python workers/dynamic_worker.py --once
    APKPLAT_DYNAMIC_TRANSPORT=adb python workers/dynamic_worker.py
"""
from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "backend"))

from apkplat import worker  # noqa: E402

KINDS = ("dynamic_analysis",)


def main() -> int:
    return worker.main(["--kinds", ",".join(KINDS), *sys.argv[1:]])


if __name__ == "__main__":
    raise SystemExit(main())
