-- The workload-identity issuing CA (ferritor-server `identity`): the key that
-- signs the short-lived client certificates workloads get in exchange for a
-- platform token. One active at a time; a rotation retires the old one.
--
-- Only the active key's private part is stored, wrapped by the root key
-- (purpose ferritor.v1.issuing-key, bound to its version), like a KEK: re-
-- wrapped by a rekey, never readable without the root key. A retired or
-- revoked key keeps only its certificate (public), which is all verifying
-- the certificates it issued needs; its wrapped key is erased at the
-- rotation (from the live table: the old row version remains until
-- vacuumed, and in WAL archives and backups until they age out).
CREATE TABLE issuing_keys (
    version      INTEGER PRIMARY KEY CHECK (version > 0),
    -- The CA certificate (DER): self-signed, public.
    certificate  BYTEA NOT NULL,
    -- active: signs, and its certificates are trusted.
    -- retired: replaced by a rotation; its certificates stay trusted until
    --   they've all expired (at most the longest lifetime after retired_at).
    -- revoked: cut off at once by a rotation (the active key it replaced,
    --   and every retired one); nothing it signed is trusted any more.
    state        TEXT NOT NULL CHECK (state IN ('active', 'retired', 'revoked')),
    wrapped_key  BYTEA,
    created_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
    retired_at   TIMESTAMPTZ,
    -- The active key, and only it, has a wrapped key and no retirement.
    CONSTRAINT issuing_keys_active CHECK (
        (state = 'active') = (wrapped_key IS NOT NULL)
        AND (state = 'active') = (retired_at IS NULL)
    )
);

-- At most one active issuing key.
CREATE UNIQUE INDEX issuing_keys_one_active ON issuing_keys ((true)) WHERE state = 'active';

-- The issuing keys as a set: a revision every change raises, and a MAC
-- under the root key (purpose ferritor.v1.issuing-set) over the revision and
-- every key's version, certificate, state and retired_at. A key added or
-- changed without the root key fails the MAC, so writing these tables
-- can't make a CA; an older set written back whole (from a backup, before
-- a revoking rotation) has an older revision, refused by the floor in the
-- data database (issuing_revision_floor) and by every server that saw the
-- newer one. No row: no key was ever created (a key without it isn't
-- trusted). Re-tagged by a rekey.
CREATE TABLE issuing_set (
    singleton  BOOLEAN PRIMARY KEY DEFAULT true CHECK (singleton),
    revision   BIGINT NOT NULL CHECK (revision > 0),
    tag        BYTEA NOT NULL
);
