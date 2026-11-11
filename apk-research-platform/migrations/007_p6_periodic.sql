-- P6: periodic schedules, test identities, and the uniqueness that makes them safe.
--
-- Two rules live in the schema rather than in prose:
--   * one trigger per schedule per business day (`UNIQUE(periodic_job_id, period_key)`);
--   * one live lease per test identity at a time (partial unique index).
-- A crashed scheduler therefore cannot double-book a day, and a retry cannot duplicate a
-- side effect: the run row is claimed first, then the task is created.

CREATE TABLE IF NOT EXISTS test_identities (
    id           TEXT PRIMARY KEY,
    project_id   TEXT NOT NULL,
    label        TEXT NOT NULL,
    kind         TEXT NOT NULL DEFAULT 'test_account',
    secret_ref   TEXT,
    status       TEXT NOT NULL DEFAULT 'active',
    note         TEXT,
    created_at   TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS ix_test_identities_project ON test_identities(project_id);

CREATE TABLE IF NOT EXISTS test_identity_leases (
    id           TEXT PRIMARY KEY,
    identity_id  TEXT NOT NULL,
    project_id   TEXT NOT NULL,
    task_id      TEXT,
    owner        TEXT NOT NULL,
    acquired_at  TEXT NOT NULL,
    expires_at   TEXT NOT NULL,
    released_at  TEXT
);
CREATE UNIQUE INDEX IF NOT EXISTS ux_identity_lease_live
    ON test_identity_leases(identity_id) WHERE released_at IS NULL;

CREATE TABLE IF NOT EXISTS periodic_jobs (
    id                TEXT PRIMARY KEY,
    project_id        TEXT NOT NULL,
    schedule_id       TEXT NOT NULL,
    role              TEXT NOT NULL DEFAULT 'static',
    title             TEXT NOT NULL,
    goal              TEXT,
    test_identity_id  TEXT,
    tz                TEXT NOT NULL DEFAULT 'UTC',
    hour              INTEGER NOT NULL,
    minute            INTEGER NOT NULL DEFAULT 0,
    enabled           INTEGER NOT NULL DEFAULT 1,
    next_due_at       TEXT NOT NULL,
    last_result_json  TEXT,
    created_at        TEXT NOT NULL,
    updated_at        TEXT NOT NULL
);
CREATE UNIQUE INDEX IF NOT EXISTS ux_periodic_schedule ON periodic_jobs(project_id, schedule_id);

-- One row per (schedule, business day) that actually triggered. Inserted before the task is
-- created, so a crash between the two leaves a row with result='pending' rather than a
-- second side effect.
CREATE TABLE IF NOT EXISTS periodic_runs (
    id                TEXT PRIMARY KEY,
    periodic_job_id   TEXT NOT NULL,
    project_id        TEXT NOT NULL,
    test_identity_id  TEXT,
    period_key        TEXT NOT NULL,
    window_start      TEXT NOT NULL,
    window_end        TEXT NOT NULL,
    tz                TEXT NOT NULL,
    triggered_at      TEXT NOT NULL,
    task_id           TEXT,
    job_id            TEXT,
    result            TEXT NOT NULL DEFAULT 'pending',
    error_code        TEXT
);
CREATE UNIQUE INDEX IF NOT EXISTS ux_periodic_run_window ON periodic_runs(periodic_job_id, period_key);
CREATE INDEX IF NOT EXISTS ix_periodic_runs_project ON periodic_runs(project_id, triggered_at);

-- Every scheduler pass that was refused (resources, identity busy) is kept, but does not
-- consume the day: the window stays open so the next pass can still run it once.
CREATE TABLE IF NOT EXISTS periodic_attempts (
    id               TEXT PRIMARY KEY,
    periodic_job_id  TEXT NOT NULL,
    project_id       TEXT NOT NULL,
    period_key       TEXT NOT NULL,
    attempted_at     TEXT NOT NULL,
    result           TEXT NOT NULL,
    error_code       TEXT,
    detail_json      TEXT
);
CREATE INDEX IF NOT EXISTS ix_periodic_attempts_job ON periodic_attempts(periodic_job_id, attempted_at);

CREATE TRIGGER IF NOT EXISTS trg_periodic_runs_no_update
BEFORE UPDATE ON periodic_runs
BEGIN
    SELECT RAISE(ABORT, 'periodic_runs is append-only: UPDATE is forbidden');
END;

CREATE TRIGGER IF NOT EXISTS trg_periodic_runs_no_delete
BEFORE DELETE ON periodic_runs
BEGIN
    SELECT RAISE(ABORT, 'periodic_runs is append-only: DELETE is forbidden');
END;

CREATE TRIGGER IF NOT EXISTS trg_periodic_attempts_no_update
BEFORE UPDATE ON periodic_attempts
BEGIN
    SELECT RAISE(ABORT, 'periodic_attempts is append-only: UPDATE is forbidden');
END;

CREATE TRIGGER IF NOT EXISTS trg_periodic_attempts_no_delete
BEFORE DELETE ON periodic_attempts
BEGIN
    SELECT RAISE(ABORT, 'periodic_attempts is append-only: DELETE is forbidden');
END;
