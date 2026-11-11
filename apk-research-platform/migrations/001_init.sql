-- 001_init.sql — portable DDL (SQLite + PostgreSQL)
-- Conventions: TEXT uuid identifiers, TEXT ISO-8601 UTC timestamps,
-- INTEGER for counters/booleans, JSON stored as TEXT.

CREATE TABLE IF NOT EXISTS counters(
  name  TEXT PRIMARY KEY,
  value INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS projects(
  id            TEXT PRIMARY KEY,
  name          TEXT NOT NULL,
  apk_sha256    TEXT,
  apk_filename  TEXT,
  package_name  TEXT,
  created_at    TEXT NOT NULL,
  updated_at    TEXT NOT NULL,
  status        TEXT NOT NULL,
  policy_id     TEXT NOT NULL DEFAULT 'default',
  goal          TEXT,
  ground_truth  TEXT,
  blocked_reason TEXT
);

CREATE TABLE IF NOT EXISTS artifacts(
  id           TEXT PRIMARY KEY,
  project_id   TEXT NOT NULL,
  task_id      TEXT,
  kind         TEXT NOT NULL,
  rel_path     TEXT NOT NULL,
  sha256       TEXT,
  bytes        INTEGER,
  tool         TEXT,
  tool_version TEXT,
  created_at   TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS tasks(
  id              TEXT PRIMARY KEY,
  project_id      TEXT NOT NULL,
  parent_task_id  TEXT,
  role            TEXT NOT NULL,
  title           TEXT NOT NULL,
  goal            TEXT,
  status          TEXT NOT NULL,
  priority        INTEGER NOT NULL DEFAULT 5,
  depends_on      TEXT,
  summary         TEXT,
  progress        REAL NOT NULL DEFAULT 0,
  lease_owner     TEXT,
  lease_expires_at TEXT,
  attempt         INTEGER NOT NULL DEFAULT 0,
  version         INTEGER NOT NULL DEFAULT 1,
  model_calls     INTEGER NOT NULL DEFAULT 0,
  tool_calls      INTEGER NOT NULL DEFAULT 0,
  evidence_count  INTEGER NOT NULL DEFAULT 0,
  error_count     INTEGER NOT NULL DEFAULT 0,
  error_code      TEXT,
  error_message   TEXT,
  retryable       INTEGER NOT NULL DEFAULT 1,
  heartbeat_at    TEXT,
  created_at      TEXT NOT NULL,
  updated_at      TEXT NOT NULL,
  finished_at     TEXT,
  needs_approval  INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS agent_runs(
  id              TEXT PRIMARY KEY,
  project_id      TEXT NOT NULL,
  task_id         TEXT,
  role            TEXT NOT NULL,
  dsh_session_ref TEXT,
  model_id        TEXT,
  started_at      TEXT NOT NULL,
  ended_at        TEXT,
  status          TEXT NOT NULL,
  notes           TEXT
);

CREATE TABLE IF NOT EXISTS evidence(
  id           TEXT PRIMARY KEY,
  project_id   TEXT NOT NULL,
  task_id      TEXT,
  kind         TEXT NOT NULL,
  artifact_id  TEXT,
  locator      TEXT NOT NULL,
  excerpt      TEXT,
  excerpt_hash TEXT,
  claim        TEXT,
  confidence   TEXT NOT NULL,
  captured_at  TEXT NOT NULL,
  created_by   TEXT NOT NULL DEFAULT 'agent'
);

CREATE TABLE IF NOT EXISTS audit_events(
  id           TEXT PRIMARY KEY,
  seq          INTEGER NOT NULL,
  project_id   TEXT,
  task_id      TEXT,
  event_type   TEXT NOT NULL,
  actor        TEXT NOT NULL,
  payload_json TEXT,
  created_at   TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS devices(
  id           TEXT PRIMARY KEY,
  serial_alias TEXT NOT NULL,
  adb_serial   TEXT NOT NULL,
  type         TEXT NOT NULL,
  capabilities TEXT,
  health       TEXT NOT NULL DEFAULT 'unknown',
  last_seen    TEXT
);

CREATE TABLE IF NOT EXISTS device_leases(
  id           TEXT PRIMARY KEY,
  project_id   TEXT NOT NULL,
  task_id      TEXT,
  device_id    TEXT NOT NULL,
  owner        TEXT NOT NULL,
  expires_at   TEXT NOT NULL,
  heartbeat_at TEXT NOT NULL,
  released_at  TEXT
);

CREATE TABLE IF NOT EXISTS approvals(
  id          TEXT PRIMARY KEY,
  project_id  TEXT NOT NULL,
  task_id     TEXT,
  kind        TEXT NOT NULL,
  requested_by TEXT NOT NULL,
  reason      TEXT,
  decision    TEXT NOT NULL,
  decided_by  TEXT,
  created_at  TEXT NOT NULL,
  decided_at  TEXT
);

CREATE TABLE IF NOT EXISTS jobs(
  id             TEXT PRIMARY KEY,
  project_id     TEXT,
  task_id        TEXT,
  kind           TEXT NOT NULL,
  payload_json   TEXT,
  status         TEXT NOT NULL,
  idempotency_key TEXT,
  priority       INTEGER NOT NULL DEFAULT 5,
  attempt        INTEGER NOT NULL DEFAULT 0,
  max_attempts   INTEGER NOT NULL DEFAULT 3,
  lease_owner    TEXT,
  lease_expires_at TEXT,
  heartbeat_at   TEXT,
  available_at   TEXT NOT NULL,
  created_at     TEXT NOT NULL,
  updated_at     TEXT NOT NULL,
  error_code     TEXT,
  error_message  TEXT,
  result_json    TEXT
);

CREATE TABLE IF NOT EXISTS model_requests(
  id            TEXT PRIMARY KEY,
  project_id    TEXT,
  task_id       TEXT,
  model_id      TEXT,
  purpose       TEXT,
  status        TEXT NOT NULL,
  http_status   INTEGER,
  latency_ms    INTEGER,
  prompt_tokens INTEGER,
  output_tokens INTEGER,
  error_type    TEXT,
  created_at    TEXT NOT NULL
);

CREATE UNIQUE INDEX IF NOT EXISTS ix_jobs_idem ON jobs(idempotency_key);
CREATE INDEX IF NOT EXISTS ix_jobs_claim ON jobs(status, available_at, priority);
CREATE INDEX IF NOT EXISTS ix_tasks_project ON tasks(project_id, status);
CREATE INDEX IF NOT EXISTS ix_evidence_project ON evidence(project_id);
CREATE INDEX IF NOT EXISTS ix_audit_seq ON audit_events(seq);
CREATE INDEX IF NOT EXISTS ix_audit_project ON audit_events(project_id, seq);
CREATE INDEX IF NOT EXISTS ix_artifacts_project ON artifacts(project_id, kind);
CREATE INDEX IF NOT EXISTS ix_leases_device ON device_leases(device_id, released_at);
CREATE INDEX IF NOT EXISTS ix_model_req_task ON model_requests(task_id);
