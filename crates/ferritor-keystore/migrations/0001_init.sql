-- Keys database: the seal configuration, the namespaces, the KEK keyring and
-- the stored policies (later migrations add the workload-identity issuing
-- keys and auto-unseal's wraps). Every KEK is stored wrapped by the root
-- key, which exists only in server memory after unseal: reconstructed from
-- the Shamir shares, or, with auto-unseal, unwrapped by a key management
-- service (0003).
--
-- Postgres has no unsigned integers. Counters are INTEGER with CHECKs keeping
-- them positive, and this crate exposes them as u8/u32.

CREATE TABLE seal_config (
    -- Singleton row.
    id                  BOOLEAN PRIMARY KEY DEFAULT TRUE CHECK (id),
    shares              INTEGER NOT NULL CHECK (shares BETWEEN 2 AND 255),
    -- Shamir needs at least 2 shares to reconstruct.
    threshold           INTEGER NOT NULL CHECK (threshold BETWEEN 2 AND shares),
    -- A known plaintext encrypted under the root key. Decrypting it proves a
    -- reconstructed root key is correct before any KEK is touched.
    root_check          BYTEA NOT NULL,
    -- Bumped on every rekey; stale shares from an older generation are
    -- rejected.
    generation          INTEGER NOT NULL DEFAULT 1 CHECK (generation > 0),
    created_at          TIMESTAMPTZ NOT NULL DEFAULT now(),
    rekeyed_at          TIMESTAMPTZ,
    -- The policy key, wrapped by the root key (purpose
    -- ferritor.v1.policy-key). NULL until the first policy write creates it;
    -- re-wrapped by a rekey.
    wrapped_policy_key  BYTEA
);

-- Every secret belongs to the namespace named by its path's first segment,
-- and each namespace has its own KEKs, numbered from 1. There is no default
-- namespace: init creates no KEK, and nothing outside a namespace can be
-- stored.
CREATE TABLE namespaces (
    -- One secret-path segment (ferritor_core::path::Namespace), byte order.
    name               TEXT COLLATE "C" PRIMARY KEY CHECK (
                           length(name) BETWEEN 1 AND 512
                           AND name ~ '^[A-Za-z0-9._-]+$'
                           AND name NOT IN ('.', '..')
                       ),
    state              TEXT NOT NULL CHECK (state IN ('active', 'deleted')),
    created_at         TIMESTAMPTZ NOT NULL DEFAULT now(),
    deleted_at         TIMESTAMPTZ,
    -- Labels: plain metadata, never secret (ferritor_core::labels).
    labels             JSONB NOT NULL DEFAULT '{}' CHECK (jsonb_typeof(labels) = 'object'),
    labels_updated_at  TIMESTAMPTZ,
    CHECK ((state = 'deleted') = (deleted_at IS NOT NULL))
);

-- A KEK belongs to one namespace and is numbered within it. A deleted
-- namespace keeps its row and its (destroyed) KEK rows: re-created, it
-- continues the numbering past them, so a number is never reused for a
-- different key, and its first KEK lands exactly on the floor deleting it
-- raised (highest + 1), never below it.
--
-- Destroying a retired KEK erases its wrapped key, and the row stays (state
-- 'destroyed', when), so the version number is never reused and the
-- keyring's history stays readable. Only a retired KEK is destroyed, and
-- only once the data database's KEK floor is past it and no row uses it
-- (the server checks both). Erased from the live table, that is: the old
-- row version remains in the table file until vacuumed, and in WAL archives
-- and backups until they age out.
CREATE TABLE keks (
    namespace     TEXT COLLATE "C" NOT NULL REFERENCES namespaces (name),
    version       INTEGER NOT NULL CHECK (version > 0),
    -- AES-256-GCM(root_key, kek) with the nonce prepended; the AAD binds the
    -- namespace and the version. NULL once destroyed.
    wrapped_key   BYTEA,
    state         TEXT NOT NULL
                      CHECK (state IN ('active', 'decrypt_only', 'retired', 'destroyed')),
    created_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    destroyed_at  TIMESTAMPTZ,
    PRIMARY KEY (namespace, version),
    -- A destroyed KEK has no key and a time; any other has a key and no time.
    CONSTRAINT keks_destroyed CHECK (
        (state = 'destroyed') = (wrapped_key IS NULL)
        AND (state = 'destroyed') = (destroyed_at IS NOT NULL)
    )
);

-- Exactly one KEK per active namespace encrypts new DEKs.
CREATE UNIQUE INDEX keks_one_active ON keks (namespace) WHERE state = 'active';

-- Stored policies: the applications' grants, managed over the API. They
-- grant secret actions only (the config rules in ferritor.toml grant admin
-- actions), and every row, and the set as a whole, carries an HMAC under the
-- policy key, so writing this database can't grant anyone access: the server
-- verifies them, with the key it unwraps using the root key, before they're
-- in force (see ferritor-server `policy_store`). Nothing here is checked
-- against the MACs by the database itself; the CHECKs only keep the rows in
-- the shape the server writes.
CREATE TABLE policies (
    -- Secret-path rules (ferritor_core::path), e.g. apps/billing-read.
    name         TEXT COLLATE "C" PRIMARY KEY CHECK (
                     length(name) BETWEEN 1 AND 512
                     AND name ~ '^[A-Za-z0-9._-]+(/[A-Za-z0-9._-]+)*$'
                 ),
    -- The <name> of a ferritor://<name> client certificate identity.
    identity     TEXT NOT NULL CHECK (length(identity) BETWEEN 1 AND 512),
    -- Action names, sorted (ferritor_core::policy::SecretAction).
    actions      TEXT[] NOT NULL CHECK (cardinality(actions) > 0),
    -- Path prefixes, sorted; exactly one of paths and all_paths.
    paths        TEXT[] NOT NULL DEFAULT '{}' CHECK (cardinality(paths) <= 64),
    all_paths    BOOLEAN NOT NULL DEFAULT false,
    description  TEXT NOT NULL DEFAULT '' CHECK (octet_length(description) <= 1024),
    -- Per policy, bumped on every change.
    version      INTEGER NOT NULL CHECK (version > 0),
    mac          BYTEA NOT NULL,
    created_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
    CHECK (all_paths <> (cardinality(paths) > 0))
);
CREATE INDEX policies_identity ON policies (identity);

-- The set: one row. Its revision goes up with every write, and its MAC
-- covers the revision and every row (name, version, MAC), so a row added or
-- removed behind the server's back doesn't verify. Writes lock it FOR
-- UPDATE, so they serialize.
CREATE TABLE policy_state (
    singleton   BOOLEAN PRIMARY KEY DEFAULT true CHECK (singleton),
    revision    BIGINT NOT NULL CHECK (revision >= 0),
    -- NULL only while no policy was ever written.
    mac         BYTEA,
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);
INSERT INTO policy_state (revision) VALUES (0);
