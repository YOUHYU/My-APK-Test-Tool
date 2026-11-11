-- P6 refinement: a run row is claimed before the task exists, so it must be allowed to
-- record its outcome exactly once. After that it is frozen: no second transition, no delete.
--
-- The invariant that matters is "one trigger per schedule per business day"; immutability of
-- the *outcome* is enforced from the moment the outcome is written.

DROP TRIGGER IF EXISTS trg_periodic_runs_no_update;

CREATE TRIGGER trg_periodic_runs_no_update
BEFORE UPDATE ON periodic_runs
WHEN OLD.result != 'pending'
BEGIN
    SELECT RAISE(ABORT, 'periodic_runs is append-only once resolved: UPDATE is forbidden');
END;

CREATE TRIGGER IF NOT EXISTS trg_periodic_runs_no_reopen
BEFORE UPDATE ON periodic_runs
WHEN NEW.result = 'pending' AND OLD.result != 'pending'
BEGIN
    SELECT RAISE(ABORT, 'periodic_runs cannot be reopened');
END;
