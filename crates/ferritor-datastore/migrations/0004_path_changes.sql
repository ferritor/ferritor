-- What changed since when, for the watch stream (SecretsService.
-- WatchSecrets): every change of a path's live version records the
-- transaction that made it, and each server polls for the rows changed
-- between two of its snapshots (Datastore::changes_since): visible in the
-- new one, made by a transaction the old one didn't see. Exact under
-- concurrent commits (a transaction committing late is in the next poll),
-- and nothing is lost across a reconnect: a poll resumes from the last
-- snapshot. A restart or failover of this database is told as a resync
-- instead: its transaction ids may be given again, so the snapshot taken
-- before means nothing after. Not NOTIFY: its commit-time lock serializes
-- every committing writer (puts fell from about 5,400/s to 1,100/s); this
-- costs a column the row update writes anyway.
--
-- A put (its insert takes the default), a delete, a restore to a newer
-- version: whatever moves current_version, whichever server or tool makes
-- it; a write that leaves it (a restore of an older version, a trim, a
-- purge, a label change) isn't a change.
ALTER TABLE paths ADD COLUMN changed_xid xid8 NOT NULL DEFAULT pg_current_xact_id();
CREATE INDEX paths_changed ON paths (changed_xid);

CREATE FUNCTION paths_mark_change() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
    IF NEW.current_version IS DISTINCT FROM OLD.current_version THEN
        NEW.changed_xid := pg_current_xact_id();
    END IF;
    RETURN NEW;
END
$$;

CREATE TRIGGER paths_mark_change
    BEFORE UPDATE OF current_version ON paths
    FOR EACH ROW EXECUTE FUNCTION paths_mark_change();
