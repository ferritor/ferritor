-- The highest revision of the workload-identity issuing keys (the keys
-- database's issuing_set) any server wrote or verified, like
-- policy_revision_floor for the stored policies. The set is tagged under
-- the root key, but a tagged set can be written back from an older copy:
-- one from before a revoking rotation brings a revoked (stolen) key back.
-- A running server remembers the newer revision; with the floor here, out
-- of reach of a keys-database writer, a restarted one refuses it too, so a
-- rollback needs write access to both databases. Only ever raised.
CREATE TABLE issuing_revision_floor (
    singleton  BOOLEAN PRIMARY KEY DEFAULT true CHECK (singleton),
    revision   BIGINT NOT NULL CHECK (revision >= 0)
);
INSERT INTO issuing_revision_floor (revision) VALUES (0);
