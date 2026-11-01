---
title: 'Backup and restore'
description: 'Backing up two databases that must match, restoring them, the checks after an unseal, and what not to do until the pair matches.'
seo:
  title: 'Backing up and restoring ferritor''s two databases'
---

ferritor keeps its keys and its secrets in two separate databases, backed up
separately. Rows in the data database name the KEK that wraps their data
key (the row's namespace, its path's first segment, and
`secrets.kek_version`), and that KEK lives in the keys database. So a
pair of backups must **match**: a row whose KEK isn't in the keys database
can't be read, and with no other copy of the keys database, never
(`UNKNOWN_KEK`, here for good).

Neither database holds a usable key on its own: the keys database's KEKs
are wrapped by the root key, which only the operators' shares rebuild.

Replication is a separate matter: a standby isn't a backup (it replays a
mistake as faithfully as anything else), and a failover that loses commits
breaks ferritor in worse ways than an old backup does. See
[high availability](/operations/high-availability).

## Taking backups

- **Back up the keys database after the data database**, or at least after
  every rotation and every namespace creation. KEKs are only ever added
  (rotate, namespace create) or erased on purpose (`destroy-kek`, namespace
  delete), so a keys-database backup newer than the data database's has
  every KEK the data rows use.
- The one intended exception: rows a data-database backup still has wrapped
  by a KEK destroyed since (the backup was taken before the rewrap that
  moved them off it) stay unreadable with any later keys database. That's
  crypto-shredding working: destroying a KEK also takes old backups' ability
  to decrypt those rows, which is the point of it.
- **Deleting a namespace crypto-shreds its backups.** It destroys every KEK
  of the namespace, so no data-database backup's rows of that namespace can
  be decrypted again, with any keys database from after the delete. That's
  why it needs `destroy_kek` as well as `namespace` (see
  [policy](/guides/policy)). Keep an older keys-database backup only if you
  mean to keep that ability.
- **Shares go with the keys database's generation.** A keys-database backup
  taken before a rekey needs the **old** shares to unseal: its seal
  configuration has the old root check, and its KEKs are wrapped under the
  old root key. Keep the old shares for as long as you keep keys-database
  backups from before the rekey.
- The stored policies live in the keys database, so its backups carry
  them, as of the backup (see step 4 of restoring).
- The data database's KEK floors (one per namespace) travel with it: a
  restored data backup has the floors it had when it was taken. So do the
  root commitments and the root-generation floor (see
  [key management](/operations/key-management#the-root-commitment)).
- Nothing in either backup is usable without a threshold of shares, but
  treat them as sensitive anyway: with the shares of their generation, they
  are every secret.

## Restoring

1. Restore both databases, the keys database from a backup **at least as
   new** as the data database's.
2. Start the server and unseal it with the shares of the restored keys
   database's generation.
3. Watch the server log after the unseal: it checks, in the background,
   that every KEK a row uses is in the keyring.
4. **Re-apply the stored policies from their source of truth** (git, CI:
   `ferritor policy apply --prune -f policies.toml`) **before routing
   traffic.** The restored keys database holds the policies as they were
   when the backup was taken, validly signed: a revocation since (a
   compromised application cut off) would be undone. Every server refuses
   that set as a rollback, a restarted one too, by the highest revision
   the data database keeps (`policy_revision_floor`), so no stored policy
   is in force (`POLICY_UNVERIFIED`) until it's re-applied; a data
   database restored from a backup as old as the keys database's keeps an
   equally old floor, which can't tell. Either way, re-applying makes the
   set what it should be now.
5. **With workload identity, `ferritor identity rotate --now`** if the
   issuing keys changed since the backup (a rotation, above all a revoking
   one): the restored set is below the issuing revision floor, so no
   workload certificate is trusted or issued until then, and the rotation,
   the only one allowed, revokes every key in it. A data database as old as
   the keys database can't tell: rotate with `--now` anyway if a key was
   revoked since.

### The root commitment after a restore

An unseal checks the root key against the data database's commitments
(see [key management](/operations/key-management#the-root-commitment)), so a
pair that doesn't match by generation is refused before anything loads:

- **A data database older than the last rekey** (or than init) has no
  commitment to the keys database's root key: `ROOT_UNCOMMITTED`. Unseal
  with `ferritor unseal --recommit` and the restored keys database's shares:
  once a stored secret opens under the key, the commitment is stored again
  and the server serves. With no secret stored at all there's nothing to
  prove the key with, and the re-commit is refused; then the deliberate
  path below applies.
- **A keys database older than the last rekey the data database knows
  of**: `ROOT_BELOW_FLOOR`, naming both generations. Restore the keys
  database that matches (and use its shares). To go back to the older one
  on purpose, which brings back the shares that rekey retired, lower the
  floor by hand: the deliberate path.

**The deliberate path** takes write access to the data database, on top
of the keys database the restore already wrote, so the bar of both
databases holds:

```sql
-- in the data database: let generation N (the keys database's) unseal
UPDATE root_generation_floor SET generation = N;
```

Then unseal with generation N's shares; add `--recommit` if the data
database has no commitment for N either. An empty deployment that lost its
commitments and has no secret to prove continuity can instead be set back
to the start (`UPDATE root_generation_floor SET generation = 0` and an
empty keys database) and initialized again.

The check reports four kinds of problem, per namespace, logged and audited
(`"event": "kek_check"`), and nothing at all when everything matches:

| Found | Meaning | What to do |
|---|---|---|
| `lost_namespaces` (an error) | rows under a namespace the keys database doesn't have at all | the keys database is older than the namespace (or lost its creation): restore a newer keys-database backup, then seal and unseal |
| `missing` (an error) | rows use a KEK version of their namespace the keys database doesn't have | the keys database is older than the data database's backup: restore a newer keys-database backup, then seal and unseal |
| `deleted_namespaces` (a warning) | rows under a deleted namespace | the data backup predates the namespace's delete: those rows are gone for good, as intended |
| `destroyed` (a warning) | rows use a destroyed KEK version | the data backup predates a rewrap and destroy: those rows are gone for good, as intended |

A version the keys database has but this server hasn't loaded yet (another
server rotated since) isn't reported: the next refresh loads it.

## Until the pair matches, don't rotate, init or create the namespace

All three are refused while the databases don't match (`FAILED_PRECONDITION`,
reason `KEYS_DATABASE_MISMATCH`), because going ahead would make a
recoverable mistake permanent:

- **Rotate** with a namespace's rows using a version the keys database
  doesn't have for it would
  create a different key under a version those rows already use. No keys
  database could then open both the old rows and the new ones. (Keys-
  database versions are contiguous, so a rotation can't skip ahead.)
- **Init** on an empty keys database next to stored rows (the keys database
  lost entirely) would start over at version 1, colliding with the rows'
  own versions. Restore that keys database, or, to start over for real,
  empty the data database first.
- **Creating a namespace** the data database already has rows under (the
  keys database lost it) would start its KEKs at 1 again, colliding the same
  way. Restore the keys database that has it. Only if none does,
  `--past-lost-keks` skips past the lost versions (see
  [high availability](/operations/high-availability#a-lost-namespace-still-in-memory)).

If the matching keys-database backup is truly gone, the rows that use the
lost versions can't be read; rotation stays refused until they're removed.
