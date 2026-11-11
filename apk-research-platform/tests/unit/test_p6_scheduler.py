"""P6 unit tests: three windows fire three times, never twice in one day, never twice over.

The clock is fake, so a three-day cadence costs microseconds; the uniqueness lives in the
schema, so a second scheduler pass cannot duplicate the work even if it wanted to.
"""

from __future__ import annotations

import pytest

from apkplat import clock, resources
from apkplat.db import db
from apkplat.services import projects as projects_service
from apkplat.services import scheduler
from apkplat.services import tasks as tasks_service


@pytest.fixture()
def fake_time():
    fake = clock.FakeClock("2026-01-01T08:00:00.000Z")
    previous = clock.use(fake)
    probe_previous = resources.use(resources.FakeResourceProbe(memory_available_mb=4000))
    try:
        yield fake
    finally:
        resources.use(probe_previous)
        clock.use(previous)


def _project(sample_apk, name: str) -> str:
    return projects_service.create(name=name, apk_source=sample_apk, filename="sample-app.apk", actor="test")["id"]


def test_three_days_trigger_three_times_and_at_most_once_a_day(fake_time, sample_apk) -> None:
    project_id = _project(sample_apk, "p6-three-days")
    schedule = scheduler.create_schedule(
        project_id, schedule_id="daily-reef", title="daily reef sweep", hour=9, tz="UTC"
    )

    fired: list[str] = []
    for day in range(3):
        fake_time.advance(3600)  # 09:00 on day 1, then +24h each loop
        first = scheduler.tick()
        fired.extend(row["period_key"] for row in first["outcomes"] if row["result"] == scheduler.TRIGGERED)
        # a second pass the same day must be a no-op
        again = scheduler.tick()
        assert again["triggered"] == 0, again
        assert all(row["result"] in (scheduler.DUPLICATE,) for row in again["outcomes"]), again
        fake_time.advance(24 * 3600 - 3600)

    assert fired == ["2026-01-01", "2026-01-02", "2026-01-03"]
    runs = scheduler.runs(schedule["id"])
    assert len(runs) == 3
    assert {row["period_key"] for row in runs} == set(fired)
    assert len({row["job_id"] for row in runs}) == 3
    assert all(row["job_id"] for row in runs)


def test_a_busy_identity_does_not_consume_the_window(fake_time, sample_apk) -> None:
    project_id = _project(sample_apk, "p6-identity-busy")
    identity = scheduler.add_identity(project_id, "fixture-user-1", kind="fixture", secret_ref="vault://fixture-1")
    schedule = scheduler.create_schedule(
        project_id, schedule_id="with-identity", title="identity run", hour=9, tz="UTC",
        test_identity_id=identity["id"],
    )
    # long enough to still be live at 09:00, when the schedule is due
    held = scheduler.acquire_identity(identity["id"], project_id=project_id, owner="someone-else", ttl=7200)

    fake_time.advance(3600)
    blocked = scheduler.tick()
    assert blocked["triggered"] == 0
    assert blocked["outcomes"][0]["result"] == scheduler.IDENTITY_BUSY
    assert scheduler.runs(schedule["id"]) == []

    scheduler.release_identity(held["id"], owner="someone-else")
    fake_time.advance(scheduler.RETRY_AFTER_SECONDS + 1)  # the refusal re-checks after a short wait
    allowed = scheduler.tick()
    assert allowed["triggered"] == 1
    run = scheduler.runs(schedule["id"])[0]
    assert run["test_identity_id"] == identity["id"]
    lease = scheduler.active_lease(identity["id"])
    assert lease is not None, "the identity stays leased while its task runs"


def test_low_memory_blocks_instead_of_starting_heavy_work(fake_time, sample_apk) -> None:
    project_id = _project(sample_apk, "p6-low-memory")
    schedule = scheduler.create_schedule(project_id, schedule_id="heavy", title="heavy sweep", role="static", hour=9, tz="UTC")
    resources.use(resources.FakeResourceProbe(low_memory=True))

    fake_time.advance(3600)
    result = scheduler.tick()
    assert result["triggered"] == 0
    assert result["outcomes"][0]["result"] == scheduler.BLOCKED
    assert scheduler.runs(schedule["id"]) == []
    attempts = scheduler.attempts(schedule["id"])
    assert attempts and attempts[0]["error_code"] == "RESOURCE_BLOCKED"

    resources.use(resources.FakeResourceProbe(memory_available_mb=4000))
    fake_time.advance(scheduler.RETRY_AFTER_SECONDS + 1)
    recovered = scheduler.tick()
    assert recovered["triggered"] == 1, "the same window must still be runnable once resources return"


def test_a_duplicate_window_cannot_be_forced_by_a_second_row(fake_time, sample_apk) -> None:
    project_id = _project(sample_apk, "p6-unique")
    schedule = scheduler.create_schedule(project_id, schedule_id="once", title="once", hour=9, tz="UTC")
    fake_time.advance(3600)
    assert scheduler.tick()["triggered"] == 1

    with pytest.raises(Exception):
        db.execute(
            "INSERT INTO periodic_runs(id, periodic_job_id, project_id, period_key, window_start, window_end, tz,"
            " triggered_at, result) VALUES(?,?,?,?,?,?,?,?,?)",
            ("pru_dup", schedule["id"], project_id, "2026-01-01", "a", "b", "UTC", clock.now_utc(), "pending"),
        )


def test_periodic_runs_are_append_only(fake_time, sample_apk) -> None:
    project_id = _project(sample_apk, "p6-append-only")
    scheduler.create_schedule(project_id, schedule_id="ro", title="ro", hour=9, tz="UTC")
    fake_time.advance(3600)
    scheduler.tick()
    with pytest.raises(Exception):
        db.execute("UPDATE periodic_runs SET result = 'tampered'")


def test_a_due_task_is_a_real_task_on_the_board(fake_time, sample_apk) -> None:
    project_id = _project(sample_apk, "p6-board")
    scheduler.create_schedule(project_id, schedule_id="board", title="board sweep", hour=9, tz="UTC")
    fake_time.advance(3600)
    scheduler.tick()
    rows = tasks_service.list_tasks(project_id)
    assert any(row["title"].startswith("board sweep [2026-01-01]") for row in rows), [r["title"] for r in rows]


def test_third_party_identity_kinds_are_refused(fake_time, sample_apk) -> None:
    project_id = _project(sample_apk, "p6-kinds")
    with pytest.raises(scheduler.SchedulerError) as excinfo:
        scheduler.add_identity(project_id, "someone-elses-account", kind="third_party")
    assert excinfo.value.code == "unsupported_identity_kind"
