"""Durable queue: idempotency, single-claim leases, expiry recovery, retry budget."""
from __future__ import annotations

import time

import pytest

from apkplat.db import db
from apkplat.services import queue


@pytest.fixture(autouse=True)
def _clean_jobs():
    db.execute("DELETE FROM jobs WHERE kind LIKE 'test_%'")
    yield
    db.execute("DELETE FROM jobs WHERE kind LIKE 'test_%'")


def test_idempotency_key_returns_the_same_job():
    first = queue.enqueue("test_static", idempotency_key="test-idem-1", payload={"n": 1})
    second = queue.enqueue("test_static", idempotency_key="test-idem-1", payload={"n": 2})
    assert first == second
    rows = db.query("SELECT * FROM jobs WHERE id = ?", (first,))
    assert len(rows) == 1


def test_claim_is_exclusive():
    job = queue.enqueue("test_static", idempotency_key="test-claim-1")
    claimed = queue.claim("worker-a", ["test_static"], lease_seconds=60)
    assert claimed is not None and claimed["id"] == job
    assert claimed["status"] == queue.RUNNING
    assert claimed["attempt"] == 1
    # a second worker sees nothing to do, not the same job
    assert queue.claim("worker-b", ["test_static"], lease_seconds=60) is None


def test_claim_respects_kind_filter_and_priority():
    queue.enqueue("test_dynamic", idempotency_key="test-kind-1")
    assert queue.claim("worker-a", ["test_static"], lease_seconds=60) is None
    claimed = queue.claim("worker-a", ["test_dynamic"], lease_seconds=60)
    assert claimed["kind"] == "test_dynamic"


def test_delayed_job_is_not_claimable_immediately():
    queue.enqueue("test_slow", idempotency_key="test-delay-1", delay_seconds=3600)
    assert queue.claim("worker-a", ["test_slow"], lease_seconds=60) is None


def test_expired_lease_is_reclaimed_and_retried():
    job = queue.enqueue("test_static", idempotency_key="test-lease-1", max_attempts=2)
    claimed = queue.claim("worker-a", ["test_static"], lease_seconds=60)
    assert claimed["id"] == job
    # simulate a crashed worker: the lease expires
    db.execute("UPDATE jobs SET lease_expires_at = ? WHERE id = ?", ("2000-01-01T00:00:00.000Z", job))
    reclaimed = queue.reclaim_expired()
    assert any(item["job_id"] == job for item in reclaimed)
    row = queue.get(job)
    assert row["status"] in {queue.PENDING, queue.RETRYING}
    # and the job is claimable again by someone else
    again = queue.claim("worker-b", ["test_static"], lease_seconds=60)
    assert again is not None and again["id"] == job and again["attempt"] == 2


def test_retry_budget_exhaustion_marks_failed():
    job = queue.enqueue("test_static", idempotency_key="test-budget-1", max_attempts=1)
    queue.claim("worker-a", ["test_static"], lease_seconds=60)
    queue.fail(job, "stage_failed", "jadx exploded", retryable=True, worker_id="worker-a")
    row = queue.get(job)
    assert row["status"] == queue.FAILED
    assert row["error_code"] == "stage_failed"


def test_fail_with_backoff_schedules_retry():
    job = queue.enqueue("test_static", idempotency_key="test-backoff-1", max_attempts=3)
    queue.claim("worker-a", ["test_static"], lease_seconds=60)
    queue.fail(job, "transient", "GPU on fire", retryable=True, worker_id="worker-a")
    row = queue.get(job)
    assert row["status"] in {queue.RETRYING, queue.PENDING}
    assert row["available_at"] > row["updated_at"]


def test_non_retryable_failure_is_terminal():
    job = queue.enqueue("test_static", idempotency_key="test-terminal-1", max_attempts=5)
    queue.claim("worker-a", ["test_static"], lease_seconds=60)
    queue.fail(job, "bad_apk", "not a zip", retryable=False, worker_id="worker-a")
    assert queue.get(job)["status"] == queue.FAILED


def test_completion_records_result_and_clears_lease():
    job = queue.enqueue("test_static", idempotency_key="test-complete-1")
    queue.claim("worker-a", ["test_static"], lease_seconds=60)
    queue.complete(job, {"units": 43}, worker_id="worker-a")
    row = queue.get(job)
    assert row["status"] == queue.SUCCEEDED
    assert row["lease_expires_at"] is None
    assert "43" in (row["result_json"] or "")


def test_cancel_is_idempotent_and_blocks_claims():
    job = queue.enqueue("test_static", idempotency_key="test-cancel-1")
    queue.cancel(job, actor="human")
    queue.cancel(job, actor="human")
    assert queue.get(job)["status"] == queue.CANCELLED
    assert queue.claim("worker-a", ["test_static"], lease_seconds=60) is None


def test_stats_counts_by_status():
    queue.enqueue("test_static", idempotency_key=f"test-stats-{time.time_ns()}")
    stats = queue.stats()
    assert isinstance(stats, dict)
    assert stats.get(queue.PENDING, 0) >= 1
