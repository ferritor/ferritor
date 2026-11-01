-- A put as ferritor-datastore sends it (Datastore::lock_path, begin_put,
-- PendingPut::insert, StagedPut::commit): the same statements, one round
-- trip each, under the path's lock, with max_versions = 10 (OFFSET 9) and
-- the bind parameters as literals. Paths under `pg/`, a namespace of their
-- own, whose row must exist (bench/README.md creates it): a namespace's very
-- first put takes a detour this leaves out. Keep it in step with those.
\set n random(1, 2000000000)
BEGIN;
SELECT set_config('lock_timeout', '2000ms', true);
SELECT 1 FROM pg_advisory_xact_lock(1, hashtext('pg/' || :n));
WITH stored AS (
    SELECT COALESCE(MAX(version), 0) AS highest FROM secret_versions
    WHERE path_id = (SELECT id FROM paths WHERE path = 'pg/' || :n)
)
INSERT INTO paths (namespace_id, path, highest, current_version)
SELECT n.id, 'pg/' || :n, GREATEST(stored.highest, n.version_floor) + 1,
       GREATEST(stored.highest, n.version_floor) + 1
FROM namespaces n, stored
WHERE n.name = 'pg' AND GREATEST(stored.highest, n.version_floor) < 2147483647
ON CONFLICT (path) DO UPDATE
    SET highest = GREATEST(paths.highest, EXCLUDED.highest - 1) + 1,
        current_version = GREATEST(paths.highest, EXCLUDED.highest - 1) + 1,
        updated_at = now()
    WHERE GREATEST(paths.highest, EXCLUDED.highest - 1) < 2147483647
RETURNING id AS path_id, namespace_id, highest
\gset
SELECT MAX(version) FROM secret_versions WHERE path_id = :path_id AND deleted_at IS NULL;
INSERT INTO secret_versions (path_id, namespace_id, version, ciphertext, wrapped_dek, kek_version)
  VALUES (:path_id, :namespace_id, :highest, '\x000102030405060708090a0b0c0d0e0f000102030405060708090a0b0c0d0e0f000102030405060708090a0b0c0d0e0f000102030405060708090a0b0c0d0e0f', '\x000102030405060708090a0b0c0d0e0f000102030405060708090a0b0c0d0e0f', 1)
  RETURNING created_at;
UPDATE secret_versions SET deleted_at = now() WHERE path_id = :path_id AND deleted_at IS NULL
  AND version < (SELECT version FROM secret_versions WHERE path_id = :path_id AND deleted_at IS NULL ORDER BY version DESC OFFSET 9 LIMIT 1);
COMMIT;
