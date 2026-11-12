-- P8-lite: project run control.
--
-- A project is either RUNNING (jobs may be claimed), PAUSED (nothing new is claimed, work
-- already in flight finishes) or STOPPED (pending work is cancelled, in-flight work is asked
-- to stop at its next stage boundary).
--
-- ``jobs.cancel_requested`` is the cooperative half of STOPPED: a worker that is already
-- inside a handler cannot be interrupted from the outside, so the operator sets a flag and the
-- handler checks it between stages. The column is deliberately separate from ``jobs.status``
-- so "asked to stop" and "actually stopped" stay distinguishable in the queue table.

ALTER TABLE projects ADD COLUMN run_state TEXT NOT NULL DEFAULT 'RUNNING';
ALTER TABLE projects ADD COLUMN run_state_changed_at TEXT;
ALTER TABLE projects ADD COLUMN run_state_reason TEXT;

ALTER TABLE jobs ADD COLUMN cancel_requested INTEGER NOT NULL DEFAULT 0;

CREATE INDEX IF NOT EXISTS ix_jobs_project_status ON jobs(project_id, status);
