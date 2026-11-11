-- P3: typed evidence objects and sandboxed test runs.
--
-- The P1/P2 `evidence` table stays exactly as it is: it is the TEXT_EXCERPT currency that
-- Gate 3 verified. Everything else (images, JSON fields, captures, test results) lands in
-- `evidence_objects`, which carries the level split the taskbook asks for: integrity is a
-- file fact, provenance is a run fact, assertion is a method fact, and reproduction is a
-- second-run fact. They are stored separately so "hash matches" can never be read as PASS.

CREATE TABLE IF NOT EXISTS evidence_objects (
    id                  TEXT PRIMARY KEY,
    project_id          TEXT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    task_id             TEXT,
    run_id              TEXT,
    artifact_id         TEXT REFERENCES artifacts(id) ON DELETE SET NULL,
    evidence_type       TEXT NOT NULL,
    artifact_sha256     TEXT,
    locator_json        TEXT NOT NULL,
    claim               TEXT,
    expected_json       TEXT,
    observed_json       TEXT,
    integrity_verified  INTEGER NOT NULL DEFAULT 0,
    provenance_verified INTEGER NOT NULL DEFAULT 0,
    assertion_verified  INTEGER NOT NULL DEFAULT 0,
    reproduced          INTEGER NOT NULL DEFAULT 0,
    verdict             TEXT NOT NULL DEFAULT 'UNVERIFIED',
    failure_reason      TEXT,
    supersedes_id       TEXT REFERENCES evidence_objects(id),
    source_tool         TEXT,
    tool_version        TEXT,
    policy_version      TEXT,
    producer            TEXT,
    confidence          TEXT NOT NULL DEFAULT 'medium',
    created_at          TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS ix_evidence_objects_project ON evidence_objects(project_id, evidence_type, created_at);
CREATE INDEX IF NOT EXISTS ix_evidence_objects_task ON evidence_objects(task_id);
CREATE INDEX IF NOT EXISTS ix_evidence_objects_run ON evidence_objects(run_id);

CREATE TRIGGER IF NOT EXISTS trg_evidence_objects_no_update
BEFORE UPDATE ON evidence_objects
BEGIN
    SELECT RAISE(ABORT, 'evidence_objects is append-only: UPDATE is forbidden');
END;

CREATE TRIGGER IF NOT EXISTS trg_evidence_objects_no_delete
BEFORE DELETE ON evidence_objects
BEGIN
    SELECT RAISE(ABORT, 'evidence_objects is append-only: DELETE is forbidden');
END;

CREATE TABLE IF NOT EXISTS sandbox_runs (
    id                 TEXT PRIMARY KEY,
    project_id         TEXT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    task_id            TEXT,
    run_id             TEXT,
    script_artifact_id TEXT NOT NULL,
    script_sha256      TEXT NOT NULL,
    argv_json          TEXT NOT NULL,
    env_hash           TEXT NOT NULL,
    command_template   TEXT NOT NULL,
    network_policy     TEXT NOT NULL,
    isolation          TEXT NOT NULL,
    limits_json        TEXT NOT NULL,
    static_check_json  TEXT,
    status             TEXT NOT NULL,
    exit_code          INTEGER,
    timed_out          INTEGER NOT NULL DEFAULT 0,
    duration_ms        INTEGER NOT NULL DEFAULT 0,
    stdout_artifact_id TEXT,
    stderr_artifact_id TEXT,
    stdout_sha256      TEXT,
    stderr_sha256      TEXT,
    replay_of          TEXT,
    error_code         TEXT,
    created_by         TEXT NOT NULL,
    created_at         TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS ix_sandbox_runs_project ON sandbox_runs(project_id, created_at);
CREATE INDEX IF NOT EXISTS ix_sandbox_runs_task ON sandbox_runs(task_id);

CREATE TRIGGER IF NOT EXISTS trg_sandbox_runs_no_update
BEFORE UPDATE ON sandbox_runs
BEGIN
    SELECT RAISE(ABORT, 'sandbox_runs is append-only: UPDATE is forbidden');
END;

CREATE TRIGGER IF NOT EXISTS trg_sandbox_runs_no_delete
BEFORE DELETE ON sandbox_runs
BEGIN
    SELECT RAISE(ABORT, 'sandbox_runs is append-only: DELETE is forbidden');
END;
