-- The server's scheduled tasks (ferritor-server `schedule`): one row per
-- task, shared by every server, so a task runs once per interval however
-- many servers there are. A server claims a run in one UPDATE (due, not
-- paused, no live lease), which moves `next_due` an interval on and takes
-- the lease; the run extends the lease between batches and clears it when
-- it ends. A server that dies leaves a lease that runs out. Every time is
-- the database's clock, never a server's.
--
-- The tasks themselves are safe to run twice and concurrently, so a lease
-- that runs out early costs work, never data. A new task is a migration
-- adding its row (and its name to the CHECK).
CREATE TABLE scheduled_tasks (
    task          TEXT PRIMARY KEY CHECK (task IN ('purge', 'rewrap')),
    -- Seeded with now(): a new deployment runs each task at its first start.
    next_due      TIMESTAMPTZ NOT NULL DEFAULT now(),
    -- Set by `ferritor schedule pause`: no server claims it until resumed,
    -- and a run under way ends at its next batch.
    paused        BOOLEAN NOT NULL DEFAULT false,
    -- The run holding the lease, and until when. Both or neither.
    run_id        UUID,
    lease_until   TIMESTAMPTZ,
    -- Runs failed or cut short in a row: the retry's delay doubles with it.
    failures      INTEGER NOT NULL DEFAULT 0 CHECK (failures >= 0),
    last_started  TIMESTAMPTZ,
    last_finished TIMESTAMPTZ,
    last_result   TEXT CHECK (last_result IN ('ok', 'failed', 'interrupted')),
    last_success  TIMESTAMPTZ,
    CHECK ((run_id IS NULL) = (lease_until IS NULL))
);
INSERT INTO scheduled_tasks (task) VALUES ('purge'), ('rewrap');
