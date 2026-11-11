"""Test bootstrap.

The settings object is built at import time, so the storage/db environment has to be
pinned *before* any ``apkplat`` import. Every test session therefore runs against a
throwaway storage tree under ``tests/.tmp`` - never against the live ``storage/``.

Auth defaults to local-operator mode (``APKPLAT_REQUIRE_AUTH=0``) so the closed-loop
tests exercise business logic; ``tests/unit/test_auth.py`` flips the setting back on
to prove tokens are actually enforced.
"""
from __future__ import annotations

import os
import shutil
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
BACKEND = ROOT / "backend"
TMP = Path(__file__).resolve().parent / ".tmp"

if str(BACKEND) not in sys.path:
    sys.path.insert(0, str(BACKEND))

os.environ.setdefault("APKPLAT_STORAGE", str(TMP / "storage"))
os.environ.setdefault("APKPLAT_REPORTS", str(TMP / "reports"))
os.environ.setdefault("APKPLAT_SECRET", "test-secret-not-for-production")
os.environ["APKPLAT_REQUIRE_AUTH"] = "0"
os.environ.setdefault("APKPLAT_MODEL_ENABLED", "0")  # tests stub the model; no network in unit paths
os.environ.setdefault("APKPLAT_DYNAMIC_TRANSPORT", "sim")  # no phone attached on CI/hosts
os.environ.setdefault("APKPLAT_DYNAMIC_OBSERVE_SECONDS", "0")  # do not sleep inside tests
os.environ.pop("APKPLAT_DB_URL", None)

# The wipe has to happen while conftest is being imported: test modules import
# ``apkplat.db`` during collection, which opens the SQLite file, and on Windows an
# open file cannot be removed (rmtree would silently fail and every run would inherit
# the previous run's queue state).
if TMP.exists():
    shutil.rmtree(TMP, ignore_errors=True)
(TMP / "storage").mkdir(parents=True, exist_ok=True)
(TMP / "reports").mkdir(parents=True, exist_ok=True)

import pytest  # noqa: E402


@pytest.fixture(scope="session", autouse=True)
def _fresh_storage():
    from apkplat.db import db

    db.migrate()
    yield
    # keep the tree for post-mortem when a test fails
    if os.environ.get("APKPLAT_KEEP_TEST_TMP") == "1":
        return


@pytest.fixture(autouse=True)
def _drain_queue():
    """No test may inherit another test's pending jobs.

    Modules share one SQLite file for speed, so a leftover PENDING row would be claimed
    by the *next* test's worker instead of the job that test just enqueued.
    """
    from apkplat.db import db

    db.migrate()
    db.execute("DELETE FROM jobs")
    yield


@pytest.fixture(autouse=True)
def _cold_cache():
    """Every test starts with an empty analysis cache.

    A warm cache is a legitimate production path, but tests that assert on the artifacts a
    cold analysis produces must not silently ride a cache entry left by a previous test.
    """
    import shutil

    from apkplat.config import settings
    from apkplat.db import db

    db.execute("DELETE FROM apk_cache")
    shutil.rmtree(os.path.join(settings.storage, "cache"), ignore_errors=True)
    yield


@pytest.fixture(scope="session")
def app_client():
    from fastapi.testclient import TestClient

    from apkplat.api.app import create_app

    with TestClient(create_app()) as client:
        yield client


@pytest.fixture(scope="session")
def admin_headers() -> dict:
    from apkplat.config import settings

    return {"X-Admin-Secret": settings.signing_secret().hex()}


@pytest.fixture(scope="session")
def local_headers() -> dict:
    """In local-operator mode no header is needed; kept explicit for readability."""
    return {}


@pytest.fixture(scope="session")
def sample_apk() -> Path:
    path = ROOT / "samples" / "sample-app.apk"
    assert path.exists(), "run scripts/build_sample_apk.py first"
    return path


@pytest.fixture(scope="session")
def ground_truth() -> dict:
    import json

    return json.loads((ROOT / "samples" / "ground_truth.json").read_text(encoding="utf-8"))
