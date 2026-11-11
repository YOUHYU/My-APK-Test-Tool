"""Static-analysis worker entry point.

Runs the ingestion/decompilation pipeline jobs (``static_pipeline``) plus the
multi-agent orchestration job, which starts from a finished static pipeline. It is
a thin wrapper over ``apkplat.worker.main`` so that the CLI, the service layer and
this script can never drift apart: the kind list is the only thing pinned here.

    python workers/static_worker.py --once
    python workers/static_worker.py --poll 0.5 --max-jobs 20
"""
from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "backend"))

from apkplat import worker  # noqa: E402

KINDS = ("static_pipeline", "agent_orchestrate")


def main() -> int:
    return worker.main(["--kinds", ",".join(KINDS), *sys.argv[1:]])


if __name__ == "__main__":
    raise SystemExit(main())
