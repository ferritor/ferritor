-- Auto-unseal: the root key wrapped by a key management service (KMS) the
-- server config names, so a server can unseal itself at start. The Shamir
-- shares stay shares of the same root key (the recovery shares); this is a
-- second way to open it, not a replacement. The provider's key comes from
-- the config, never from here: every unwrap names it, so a row pointing
-- elsewhere can't make a server accept a root key of someone's choosing,
-- and the root commitments in the data database refuse one anyway.
--
-- One row per provider and key, for the generation it wraps: a rekey stores
-- the new generation's and deletes every other in the same transaction. A
-- table rather than a column, for moving between keys (and later a second
-- key in another region).
CREATE TABLE seal_wraps (
    provider    TEXT NOT NULL CHECK (provider IN ('awskms')),
    -- The key as the provider names it (for AWS KMS, the key's ARN).
    key_id      TEXT NOT NULL CHECK (length(key_id) BETWEEN 1 AND 2048),
    -- The root key generation it wraps; always the seal config's (a rekey
    -- replaces it in its own transaction).
    generation  INTEGER NOT NULL CHECK (generation > 0),
    -- The provider's ciphertext.
    ciphertext  BYTEA NOT NULL CHECK (octet_length(ciphertext) BETWEEN 1 AND 65536),
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (provider, key_id)
);

-- The auto-unseal hold, this database's half (the data database keeps the
-- other): an explicit seal raises `hold`, an explicit release sets
-- `released` to the hold it read, both only ever with GREATEST. A server
-- auto-unseals only if both databases show released >= hold, so clearing it
-- takes write access to both. A table of its own, not seal_config's columns:
-- a seal's write mustn't queue behind every rotation, destroy, namespace
-- change and policy write holding seal_config FOR SHARE (or a rekey's FOR
-- UPDATE).
CREATE TABLE auto_unseal_hold (
    singleton  BOOLEAN PRIMARY KEY DEFAULT true CHECK (singleton),
    hold       BIGINT NOT NULL DEFAULT 0 CHECK (hold >= 0),
    released   BIGINT NOT NULL DEFAULT 0 CHECK (released >= 0)
);
INSERT INTO auto_unseal_hold DEFAULT VALUES;
