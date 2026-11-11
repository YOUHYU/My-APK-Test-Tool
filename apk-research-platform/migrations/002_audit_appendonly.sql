-- Append-only guarantees for the two tables that carry the audit story.
--
-- The application never issues UPDATE/DELETE against these tables, and now the
-- database will not either: a stray migration, a manual sqlite session or a future
-- refactor that "cleans up" rows fails loudly instead of quietly rewriting history.

CREATE TRIGGER IF NOT EXISTS trg_audit_events_no_update
BEFORE UPDATE ON audit_events
BEGIN
  SELECT RAISE(ABORT, 'audit_events is append-only: UPDATE is forbidden');
END;

CREATE TRIGGER IF NOT EXISTS trg_audit_events_no_delete
BEFORE DELETE ON audit_events
BEGIN
  SELECT RAISE(ABORT, 'audit_events is append-only: DELETE is forbidden');
END;

CREATE TRIGGER IF NOT EXISTS trg_evidence_no_update
BEFORE UPDATE ON evidence
BEGIN
  SELECT RAISE(ABORT, 'evidence is immutable: re-record instead of editing');
END;

CREATE TRIGGER IF NOT EXISTS trg_evidence_no_delete
BEFORE DELETE ON evidence
BEGIN
  SELECT RAISE(ABORT, 'evidence is immutable: DELETE is forbidden');
END;
