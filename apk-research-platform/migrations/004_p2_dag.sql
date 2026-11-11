-- P2: dependency DAG, checks, platform events, role registry.
--
-- The 12 task states stay exactly as they were (migration 001). Nothing here rewrites
-- `tasks.status`, and `tasks.depends_on` / `tasks.parent_task_id` are kept: the edge
-- table is an additive view that the scheduler reads, so an old reader still works.

CREATE TABLE IF NOT EXISTS task_edges (
    id           TEXT PRIMARY KEY,
    project_id   TEXT NOT NULL,
    from_task_id TEXT NOT NULL,
    to_task_id   TEXT NOT NULL,
    kind         TEXT NOT NULL DEFAULT 'blocks',
    created_at   TEXT NOT NULL,
    UNIQUE (project_id, from_task_id, to_task_id, kind)
);

CREATE INDEX IF NOT EXISTS ix_task_edges_to ON task_edges (project_id, to_task_id);
CREATE INDEX IF NOT EXISTS ix_task_edges_from ON task_edges (project_id, from_task_id);

CREATE TABLE IF NOT EXISTS task_checks (
    id          TEXT PRIMARY KEY,
    project_id  TEXT NOT NULL,
    task_id     TEXT NOT NULL,
    run_id      TEXT,
    verdict     TEXT NOT NULL,              -- PASS | FAIL
    criterion   TEXT NOT NULL,
    detail_json TEXT,
    checked_by  TEXT NOT NULL,
    checked_at  TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS ix_task_checks_task ON task_checks (task_id, checked_at);

CREATE TRIGGER IF NOT EXISTS trg_task_checks_no_update BEFORE UPDATE ON task_checks
BEGIN
    SELECT RAISE(ABORT, 'task_checks is append-only: UPDATE is forbidden');
END;

CREATE TRIGGER IF NOT EXISTS trg_task_checks_no_delete BEFORE DELETE ON task_checks
BEGIN
    SELECT RAISE(ABORT, 'task_checks is append-only: DELETE is forbidden');
END;

-- One monotonic, append-only event log for the dashboard. `seq` is a rowid alias so
-- SSE clients can resume with Last-Event-ID without gaps.
CREATE TABLE IF NOT EXISTS platform_events (
    seq          INTEGER PRIMARY KEY AUTOINCREMENT,
    project_id   TEXT,
    task_id      TEXT,
    type         TEXT NOT NULL,
    dedupe_key   TEXT,
    payload_json TEXT,
    created_at   TEXT NOT NULL
);

CREATE UNIQUE INDEX IF NOT EXISTS ux_platform_events_dedupe
    ON platform_events (dedupe_key) WHERE dedupe_key IS NOT NULL;
CREATE INDEX IF NOT EXISTS ix_platform_events_project ON platform_events (project_id, seq);

CREATE TRIGGER IF NOT EXISTS trg_platform_events_no_update BEFORE UPDATE ON platform_events
BEGIN
    SELECT RAISE(ABORT, 'platform_events is append-only: UPDATE is forbidden');
END;

CREATE TRIGGER IF NOT EXISTS trg_platform_events_no_delete BEFORE DELETE ON platform_events
BEGIN
    SELECT RAISE(ABORT, 'platform_events is append-only: DELETE is forbidden');
END;

CREATE TABLE IF NOT EXISTS role_registry (
    role_id              TEXT PRIMARY KEY,
    title                TEXT NOT NULL,
    allowed_tools_json   TEXT NOT NULL,
    max_model_calls      INTEGER NOT NULL DEFAULT 8,
    max_tool_calls       INTEGER NOT NULL DEFAULT 24,
    review_requirement   TEXT NOT NULL DEFAULT 'required',
    approval_class       TEXT NOT NULL DEFAULT 'none',
    resource_class       TEXT NOT NULL DEFAULT 'light',
    retry_limit          INTEGER NOT NULL DEFAULT 2,
    instructions_version TEXT NOT NULL DEFAULT 'v1',
    updated_at           TEXT NOT NULL
);
