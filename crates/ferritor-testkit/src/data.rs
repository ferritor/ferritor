//! Rows written into the data database by hand, around the store, as a hand
//! repair or a restored backup would leave them: for tests of what the
//! server makes of rows it didn't write.

use sqlx::PgConnection;

use crate::TestResult;

/// Writes version `version` of `path` with its DEK "wrapped" by KEK
/// `kek_version` (placeholder bytes for both the ciphertext and the DEK),
/// creating the path's namespace and `paths` row if they're missing, a new
/// path's `highest` and `current_version` set to `version`. An existing
/// path's row is left alone (a row written behind the counter's back), and
/// no row is locked but the new one, so an uncommitted call in a
/// transaction blocks only a write of the same version.
pub async fn insert_version(
    conn: &mut PgConnection,
    path: &str,
    version: i32,
    kek_version: i32,
) -> TestResult<()> {
    sqlx::query(
        "INSERT INTO namespaces (name) VALUES (split_part($1, '/', 1))
         ON CONFLICT (name) DO NOTHING",
    )
    .bind(path)
    .execute(&mut *conn)
    .await?;
    sqlx::query(
        "INSERT INTO paths (namespace_id, path, highest, current_version)
         SELECT id, $1, $2, $2 FROM namespaces WHERE name = split_part($1, '/', 1)
         ON CONFLICT (path) DO NOTHING",
    )
    .bind(path)
    .bind(version)
    .execute(&mut *conn)
    .await?;
    sqlx::query(
        "INSERT INTO secret_versions
             (path_id, namespace_id, version, ciphertext, wrapped_dek, kek_version)
         SELECT id, namespace_id, $2, '\\x00', '\\x00', $3 FROM paths WHERE path = $1",
    )
    .bind(path)
    .bind(version)
    .bind(kek_version)
    .execute(&mut *conn)
    .await?;
    Ok(())
}
