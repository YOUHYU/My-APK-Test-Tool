-- P4: content-addressed APK analysis cache, capture sources, capture flows, step windows.
-- The cache is keyed by the APK digest because that is the only identity that survives a
-- rename; a second identical upload must not pay for jadx/apktool again.

CREATE TABLE IF NOT EXISTS apk_cache (
    sha256 TEXT PRIMARY KEY,
    package_name TEXT,
    version_name TEXT,
    version_code TEXT,
    size_bytes INTEGER NOT NULL,
    cache_root TEXT NOT NULL,
    artifacts_json TEXT NOT NULL,
    index_rel_path TEXT,
    evidence_template_json TEXT,
    created_at TEXT NOT NULL,
    last_used_at TEXT NOT NULL,
    hits INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS capture_sources (
    id TEXT PRIMARY KEY,
    project_id TEXT NOT NULL,
    kind TEXT NOT NULL CHECK (kind IN ('proxy_pin', 'har', 'pcap', 'fixture')),
    label TEXT NOT NULL,
    path TEXT,
    status TEXT NOT NULL,
    note TEXT,
    meta_json TEXT,
    created_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS ix_capture_sources_project ON capture_sources(project_id, created_at);

CREATE TABLE IF NOT EXISTS capture_flows (
    id TEXT PRIMARY KEY,
    project_id TEXT NOT NULL,
    source_id TEXT NOT NULL,
    method TEXT,
    scheme TEXT,
    host TEXT,
    path TEXT,
    status_code INTEGER,
    request_at TEXT,
    response_at TEXT,
    request_bytes INTEGER,
    response_bytes INTEGER,
    headers_json TEXT,
    body_artifact_id TEXT,
    step TEXT,
    run_id TEXT,
    matched_artifact_id TEXT,
    matched_line INTEGER,
    matched_literal TEXT,
    created_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS ix_capture_flows_project ON capture_flows(project_id, request_at);
CREATE INDEX IF NOT EXISTS ix_capture_flows_host ON capture_flows(project_id, host);

CREATE TABLE IF NOT EXISTS capture_steps (
    id TEXT PRIMARY KEY,
    project_id TEXT NOT NULL,
    run_id TEXT,
    task_id TEXT,
    step TEXT NOT NULL,
    device_serial TEXT,
    started_at TEXT NOT NULL,
    ended_at TEXT,
    note TEXT
);

CREATE INDEX IF NOT EXISTS ix_capture_steps_project ON capture_steps(project_id, started_at);

CREATE TRIGGER IF NOT EXISTS trg_capture_flows_no_delete
BEFORE DELETE ON capture_flows
BEGIN
    SELECT RAISE(ABORT, 'capture_flows is append-only: DELETE is forbidden');
END;

CREATE TRIGGER IF NOT EXISTS trg_capture_sources_no_delete
BEFORE DELETE ON capture_sources
BEGIN
    SELECT RAISE(ABORT, 'capture_sources is append-only: DELETE is forbidden');
END;
