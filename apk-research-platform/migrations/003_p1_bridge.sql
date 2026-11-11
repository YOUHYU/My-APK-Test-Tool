-- P1: run capabilities and the bridge tool-call trace.
--
-- run_capabilities stores only the SHA-256 of the opaque run token; the plaintext
-- exists once, on disk under storage/runs/<run_id>/capability.token, and is read by
-- the DSH-side plugin. It must never reach a model prompt, a tool argument or a log.
--
-- run_tool_calls is the append-only per-run trace the bridge writes for every tool
-- call it authorises; it is what G1 inspects when it asks "did the model choose the
-- tool, and can the call be tied to a run/task/session".

CREATE TABLE IF NOT EXISTS run_capabilities (
  run_id         TEXT PRIMARY KEY,
  project_id     TEXT NOT NULL,
  task_id        TEXT,
  role_id        TEXT NOT NULL,
  scope_json     TEXT NOT NULL,
  token_hash     TEXT NOT NULL,
  policy_version TEXT NOT NULL,
  issued_at      TEXT NOT NULL,
  expires_at     TEXT NOT NULL,
  revoked_at     TEXT,
  last_seen_at   TEXT,
  agent_run_id   TEXT
);

CREATE UNIQUE INDEX IF NOT EXISTS ux_run_capabilities_token ON run_capabilities(token_hash);
CREATE INDEX IF NOT EXISTS ix_run_capabilities_project ON run_capabilities(project_id);

CREATE TABLE IF NOT EXISTS run_tool_calls (
  id          INTEGER PRIMARY KEY AUTOINCREMENT,
  run_id      TEXT NOT NULL,
  seq         INTEGER NOT NULL,
  tool        TEXT NOT NULL,
  args_hash   TEXT NOT NULL,
  ok          INTEGER NOT NULL,
  error_code  TEXT,
  duration_ms INTEGER NOT NULL,
  request_id  TEXT NOT NULL,
  result_preview TEXT,
  created_at  TEXT NOT NULL,
  UNIQUE (run_id, seq)
);

CREATE INDEX IF NOT EXISTS ix_run_tool_calls_run ON run_tool_calls(run_id, seq);

CREATE TRIGGER IF NOT EXISTS trg_run_tool_calls_no_update
BEFORE UPDATE ON run_tool_calls
BEGIN
  SELECT RAISE(ABORT, 'run_tool_calls is append-only: UPDATE is forbidden');
END;

CREATE TRIGGER IF NOT EXISTS trg_run_tool_calls_no_delete
BEFORE DELETE ON run_tool_calls
BEGIN
  SELECT RAISE(ABORT, 'run_tool_calls is append-only: DELETE is forbidden');
END;
