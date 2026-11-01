-- Data database: secret ciphertexts and their wrapped DEKs, one relation per
-- thing: the namespaces (for their KEK floors), the paths (version counter,
-- times, labels), and every stored version. Each secret version gets its own
-- DEK, wrapped by a KEK of its namespace; `kek_version` points into the keys
-- database, so it can't be a foreign key: the server enforces it.
--
-- Postgres has no unsigned integers. Versions are INTEGER with CHECKs
-- keeping them positive, and this crate exposes them as u32. Keys are
-- UUIDv7 (time-ordered, so inserts stay at the end of the index; no
-- sequence to fall out of step after a restore), never shown outside this
-- database.

-- Every namespace a row was ever written to, or a floor raised for. Which
-- namespaces exist is the keys database's business; this holds what the
-- data database must enforce itself: the KEK floor (and, since 0003, the
-- version floor).
CREATE TABLE namespaces (
    id         UUID PRIMARY KEY DEFAULT uuidv7(),
    -- One secret-path segment (ferritor_core::path::Namespace), byte order.
    name       TEXT COLLATE "C" NOT NULL UNIQUE CHECK (
                   length(name) BETWEEN 1 AND 512
                   AND name ~ '^[A-Za-z0-9._-]+$'
                   AND name NOT IN ('.', '..')
               ),
    -- No row of this namespace may be written with its DEK wrapped by a KEK
    -- version below it (the trigger below). Only raised (destroying a KEK,
    -- deleting the namespace, a recovery past lost KEKs), never above the
    -- active version but in those last two (the server checks); 1 until
    -- then.
    kek_floor  INTEGER NOT NULL DEFAULT 1 CHECK (kek_floor > 0),
    -- For paths' composite foreign key.
    UNIQUE (id, name)
);

-- Every path ever written: its version counter, its times, its labels.
-- Kept after purge removed every version, so a version number is never
-- reused: the AAD binds path + version, and a check-and-set's expected
-- version must not match a different secret. Deleted only with its
-- namespace, whose version_floor (0003) keeps the numbering past it.
CREATE TABLE paths (
    id                 UUID PRIMARY KEY DEFAULT uuidv7(),
    namespace_id       UUID NOT NULL,
    -- Canonical form only (ferritor_core::path::SecretPath): the AAD binds
    -- these exact bytes, so `a/b`, `/a/b` and `a//b` must not coexist.
    -- COLLATE "C" (byte order) makes prefix listing a range scan; see
    -- SecretPath::descendant_range.
    path               TEXT COLLATE "C" NOT NULL UNIQUE CHECK (
                           length(path) <= 512
                           AND path ~ '^[A-Za-z0-9._-]+(/[A-Za-z0-9._-]+)*$'
                           AND path !~ '(^|/)\.\.?(/|$)'
                       ),
    -- The path's first segment, derived (callers never set it), so the
    -- composite key below makes `namespace_id` the namespace the path's
    -- text names: a path can't be filed under another namespace's KEK
    -- floor.
    namespace          TEXT COLLATE "C" NOT NULL
                           GENERATED ALWAYS AS (split_part(path, '/', 1)) STORED,
    -- The highest version this path ever had; a put takes one past it (or
    -- past the rows' own highest, if higher), under the path's lock.
    highest            INTEGER NOT NULL CHECK (highest > 0),
    -- The latest live version, NULL if none: what listings read, so they
    -- skip paths with nothing live without visiting them. Kept by the
    -- writes that change it, under the path's lock: a put (its own version),
    -- a delete (NULL), a restore (the higher of it and the restored one).
    -- A trim never deletes the latest, and purge only deleted versions.
    current_version    INTEGER CHECK (current_version BETWEEN 1 AND highest),
    -- When it was first written, and last written by a put.
    created_at         TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at         TIMESTAMPTZ NOT NULL DEFAULT now(),
    -- Plain metadata, never secret (ferritor_core::labels); '{}': none. A
    -- path with nothing stored has none (purge clears them).
    labels             JSONB NOT NULL DEFAULT '{}' CHECK (jsonb_typeof(labels) = 'object'),
    -- When the labels last changed; NULL without labels.
    labels_updated_at  TIMESTAMPTZ,
    FOREIGN KEY (namespace_id, namespace) REFERENCES namespaces (id, name),
    -- For secret_versions' composite foreign key.
    UNIQUE (id, namespace_id)
);
-- Listing: paths with a live version, in byte order (a prefix is a range).
CREATE INDEX paths_live ON paths (path) WHERE current_version IS NOT NULL;
-- Listing by label (`labels @> '{"team": "a"}'`), only paths that have any.
CREATE INDEX paths_labels ON paths USING GIN (labels jsonb_path_ops) WHERE labels <> '{}';

-- Every stored version of a secret, live or deleted (`deleted_at`, until
-- purged).
CREATE TABLE secret_versions (
    path_id       UUID NOT NULL,
    -- The path's namespace, repeated so the per-namespace KEK queries
    -- (rewrap, the KEK check, the rotate guard, deleting a namespace) and
    -- the floor trigger needn't join; the composite key below keeps it
    -- equal to the path's.
    namespace_id  UUID NOT NULL,
    version       INTEGER NOT NULL CHECK (version > 0),
    -- AES-256-GCM(dek, value), nonce prepended; AAD: the path's text and
    -- this version, so ciphertexts can't be swapped between rows.
    ciphertext    BYTEA NOT NULL,
    -- AES-256-GCM(kek, dek), nonce prepended.
    wrapped_dek   BYTEA NOT NULL,
    -- A KEK of this namespace, in the keys database.
    kek_version   INTEGER NOT NULL CHECK (kek_version > 0),
    created_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    deleted_at    TIMESTAMPTZ,
    PRIMARY KEY (path_id, version),
    FOREIGN KEY (path_id, namespace_id) REFERENCES paths (id, namespace_id)
);
-- Live versions only (reads, listings, the trim in each put, delete,
-- metadata): a path's deleted versions stay until purged and outnumber its
-- live ones, and a query over live versions would otherwise filter them out
-- one row at a time (docs/src/content/docs/operations/performance.md,
-- "Deleted versions").
CREATE INDEX secret_versions_live ON secret_versions (path_id, version DESC)
    WHERE deleted_at IS NULL;
-- The rows of one namespace wrapped by one KEK, in keyset order (rewrap's
-- paging, the per-version probes and counts).
CREATE INDEX secret_versions_kek
    ON secret_versions (namespace_id, kek_version, path_id, version);
-- Purge: deleted rows past their retention, by deletion time.
CREATE INDEX secret_versions_deleted ON secret_versions (deleted_at)
    WHERE deleted_at IS NOT NULL;

-- The triggers here raise SQLSTATEs of ferritor's own class, FR (FR001 to
-- FR004), which no Postgres class uses, so the server tells them apart.
--
-- A path's text never changes, nor a namespace's name: the AAD binds the
-- path's text (renamed, every version under it stops decrypting), and the
-- composite key relies on a path staying in its namespace.
CREATE FUNCTION immutable_identity() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    RAISE EXCEPTION '% is immutable: its rows'' AAD binds it', TG_ARGV[0]
        USING ERRCODE = 'FR003';
END
$$;
CREATE TRIGGER paths_immutable BEFORE UPDATE OF path, namespace_id ON paths
    FOR EACH ROW EXECUTE FUNCTION immutable_identity('a path');
CREATE TRIGGER namespaces_immutable BEFORE UPDATE OF name ON namespaces
    FOR EACH ROW EXECUTE FUNCTION immutable_identity('a namespace name');

-- The KEK floor. What makes destroying a retired KEK safe: a server whose
-- keyring is stale (it hasn't reloaded since another server rotated) keeps
-- wrapping new DEKs with its old active KEK, possibly one retired
-- meanwhile, and a row written with a destroyed KEK could never be read.
-- Destroying version v first raises the floor past v, then checks that no
-- row uses v; once the raise has committed, no write can add one, from any
-- server or binary version, however late.
--
-- Every write of a kek_version (a put's insert, a rewrap's update) takes
-- its namespace's floor lock shared, so writers don't wait for each other;
-- a raise takes it exclusive, so it waits for the namespace's writes in
-- flight, and the writes after it wait for the raise to commit. An advisory
-- lock (class 2, object a hash of the name: two-key, so it can't collide
-- with the per-path write locks, class 1; a collision between namespaces
-- only means their raises pause each other's writes), not a row lock, so a
-- write writes nothing to `namespaces`. The floor is read after the lock:
-- in READ COMMITTED, a statement in a volatile function sees what committed
-- before it began, so a write that waited for a raise sees the raised
-- floor. Under REPEATABLE READ or SERIALIZABLE it would read the
-- transaction's snapshot instead, possibly from before a raise, so such
-- writes are refused outright (ferritor writes in READ COMMITTED; this only
-- stops other tooling).
CREATE FUNCTION secret_versions_kek_floor() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE
    ns_name  TEXT;
    floor    INTEGER;
BEGIN
    IF current_setting('transaction_isolation') <> 'read committed' THEN
        RAISE EXCEPTION 'writes to secret_versions must run in READ COMMITTED (the KEK floor relies on it), not %',
            current_setting('transaction_isolation')
            USING ERRCODE = 'FR002';
    END IF;
    -- The name is immutable, so reading it before the lock is safe; the
    -- floor is read after it.
    SELECT name INTO ns_name FROM namespaces WHERE id = NEW.namespace_id;
    PERFORM pg_advisory_xact_lock_shared(2, hashtext(ns_name));
    SELECT kek_floor INTO floor FROM namespaces WHERE id = NEW.namespace_id;
    IF NEW.kek_version < floor THEN
        RAISE EXCEPTION 'KEK version % of namespace % is below its KEK floor %',
            NEW.kek_version, ns_name, floor
            USING ERRCODE = 'FR001';
    END IF;
    RETURN NEW;
END
$$;
CREATE TRIGGER secret_versions_kek_floor
    BEFORE INSERT OR UPDATE OF kek_version ON secret_versions
    FOR EACH ROW EXECUTE FUNCTION secret_versions_kek_floor();

-- The highest stored-policy revision any server wrote. The stored policies
-- live in the keys database and are signed there, but a signed set can be
-- written back from an older copy (or wiped back to revision 0): a running
-- server remembers the newer revision and refuses it, a restarted one
-- couldn't tell. With the floor kept here, out of reach of a keys-database
-- writer, every server refuses a set below it, so a rollback needs write
-- access to both databases. Only ever raised: by a write, after the keys
-- database commits it, and by any server whose verified set is above it,
-- so a missed raise (a failure, a failover that lost it) is caught up by
-- the next server to verify the set.
CREATE TABLE policy_revision_floor (
    singleton  BOOLEAN PRIMARY KEY DEFAULT true CHECK (singleton),
    revision   BIGINT NOT NULL CHECK (revision >= 0)
);
INSERT INTO policy_revision_floor (revision) VALUES (0);
