-- Commitments to the root key, one or more per generation: an HMAC over
-- the generation under a subkey of that generation's root key (HKDF,
-- ferritor.v1.root-commitment). An unseal accepts a root key only if a
-- commitment for its generation verifies under it, and its generation
-- isn't below root_generation_floor. So a root key substituted in the keys
-- database alone (its own root_check and KEKs, even wrapped by a KMS key
-- the servers may use) is refused: substituting the root key takes write
-- access to both databases.
--
-- Insert-only: init and every rekey insert the new generation's commitment
-- before the keys database commits, so an attempt that never commits leaves
-- a commitment nobody holds the root key of, which is harmless; a retry
-- inserts its own. Never updated or deleted (a trigger refuses both, FR004),
-- so the only write is an INSERT.
CREATE TABLE root_commitments (
    generation  INTEGER NOT NULL CHECK (generation > 0),
    mac         BYTEA NOT NULL CHECK (octet_length(mac) = 32),
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (generation, mac)
);

CREATE FUNCTION root_commitments_insert_only() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    RAISE EXCEPTION 'root commitments are insert-only'
        USING ERRCODE = 'FR004';
END
$$;
CREATE TRIGGER root_commitments_insert_only BEFORE UPDATE OR DELETE ON root_commitments
    FOR EACH ROW EXECUTE FUNCTION root_commitments_insert_only();
CREATE TRIGGER root_commitments_no_truncate BEFORE TRUNCATE ON root_commitments
    FOR EACH STATEMENT EXECUTE FUNCTION root_commitments_insert_only();

-- The highest root-key generation known to have committed in the keys
-- database (an init, a rekey), raised after each commit. A root key below it
-- is refused: an older keys database put back with its genuine root key
-- would bring back shares a rekey retired. Only ever raised by the server;
-- lowering it is the deliberate path in
-- docs/src/content/docs/operations/backup-restore.md. 0: no init has ever
-- committed, and only then may one run.
CREATE TABLE root_generation_floor (
    singleton   BOOLEAN PRIMARY KEY DEFAULT true CHECK (singleton),
    generation  INTEGER NOT NULL CHECK (generation >= 0)
);
INSERT INTO root_generation_floor (generation) VALUES (0);
