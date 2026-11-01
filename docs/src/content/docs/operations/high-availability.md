---
title: 'High availability'
description: 'Several servers, why both databases need synchronous replication, what ferritor notices after a lost commit, and failover.'
seo:
  title: 'High availability for ferritor: replication, failover'
---

## Run more than one server

Several ferritor servers can share the two databases. Each unseals separately
(with the same shares), follows the others' rotations, retirements and
destroyed KEKs by refreshing its keyring, and reports readiness separately,
so a load balancer only routes to unsealed ones (see
[operations](/operations/running)). A rekey on one can't be followed by the
others: seal and unseal them with the new shares.

## Both databases need synchronous replication

> [!IMPORTANT]
> If a database fails over to a standby, the standby must have **every
> commit the old primary acknowledged**. ferritor relies on that.

A lost commit
doesn't look like an error, it looks like history that never happened, and
ferritor notices only some of them (see
[What ferritor notices](#what-ferritor-notices)). With asynchronous replication,
a failover can lose the last commits:

**Keys database:**

- **A lost rotation loses a KEK for good.** The rotation to KEK v3 commits,
  servers wrap new data keys with v3, and then the keys database fails over
  to a standby without v3. Every row written with v3 can never be decrypted
  again: it's the [mismatched backup](/operations/backup-restore) case, but with no
  newer backup to restore. Servers still holding v3 in memory lose it at
  their next keyring refresh.
- **A lost rekey commit can lose the root key.** After a rekey, operators
  hold the new shares and may destroy the old ones. A failover back to the
  previous generation needs the old shares; without them, nothing can be
  unsealed again.
- **A lost destroy brings a destroyed KEK back:** what destroy-kek promised
  to make undecryptable is decryptable again.
- **A lost init** leaves the shares handed out matching nothing.
- **A lost `identity rotate --now`**: the keys database is back at the set
  before it, below the issuing revision floor the rotation raised in the
  data database, so every server refuses it as a rollback (running ones
  keep the keys they have; restarted ones trust none, and issue nothing).
  Fail closed, as long as the data database kept the raise: run `rotate
  --now` again once the failover is done. Lost in both, the revoked key
  (a stolen one, perhaps) is trusted again.

**Data database:**

- **A lost put reuses its version number.** A put acknowledged as version 5
  is lost, and the next put on the promoted standby gets version 5 again:
  a different secret under a number a client already saw. Check-and-set and
  clients pinned to a version then act on the wrong value.
- **A lost KEK floor raise reopens a destroyed KEK to writes.** destroy-kek
  committed in the keys database, but the floor that keeps stale servers
  from writing with that KEK is back at its old value: rows written with
  the destroyed KEK can't be read.
- **A lost write can bring a revoked credential back.** A lost delete makes
  a deleted secret readable again; a lost put brings back the value it
  replaced, the old password a rotation was meant to retire. Whoever still
  holds that credential can use it again, and nothing says so.
- **A lost policy write can bring revoked access back.** A stored policy
  deleted or narrowed on the old primary, lost in the failover: the older,
  validly signed set is back. Every server refuses it (rollback alarm), a
  restarted one too, by the floor in the data database, unless the data
  database lost the floor's raise as well.
- Any other acknowledged write (a restore) can silently revert too.

### What to configure

- `synchronous_commit = on` (Postgres's default; never turn it off for these
  databases, not per role, database or transaction), and
  `synchronous_standby_names` naming at least one standby, so a commit is
  acknowledged only once a standby has it.
- Prefer two standbys with `synchronous_standby_names = 'ANY 1 (s1, s2)'`:
  with a single synchronous standby, losing it blocks every write until it's
  back.
- Failover must promote **only a synchronous standby**. Whatever manages
  failover (a failover manager, a Kubernetes operator, a managed service)
  must never promote a standby that may lack acknowledged commits, and
  decides what happens when no synchronous standby is left: writes stop
  (still protected), or replication falls back to asynchronous and the
  guarantee lapses until a standby is back. Prefer stopping, and check
  that a failover can't lose acknowledged commits.
- Point `keys_database_url` and `data_database_url` at the failover
  endpoint that always reaches the current primary (a virtual IP, a
  Kubernetes service, a proxy that follows the primary), never at a standby.

The cost is one round trip to a standby per commit. ferritor commits little
(writes are rare next to reads, and the keys database almost never
changes), so it's small.

The two databases fail over independently; each needs this on its own. The
keys database matters most: what it loses can't be recovered at all.

### A cancelled commit is committed on the primary only

Synchronous replication has one gap, and ferritor's own timeouts open it.
Postgres commits a transaction locally first, then waits for a synchronous
standby to confirm. If that wait is interrupted, the transaction **stays
committed and visible on the primary**, but isn't on any standby; Postgres
warns "canceling wait for synchronous replication … The transaction has
already committed locally, but might not have been replicated to the
standby". Two things in ferritor interrupt the wait:

- `statement_timeout`, which the server sets to `database_timeout_ms` (5 s
  by default) and which covers `COMMIT` too;
- the server's client-side timeout around every database call, which gives
  up on the connection (a lost connection has the same effect).

So while every synchronous standby is unreachable, writes don't block
indefinitely, even when failover is set to stop writes without a
synchronous standby: each commit is cancelled after the timeout, lands on
the primary only, and is reported to the caller as an **unknown outcome**. Later writes build on it (the next put takes its
version number from such a commit). If the primary then fails over, those
writes are lost, with the consequences above. ferritor can't prevent this;
it's how Postgres works.

The rule: **after an outage of the synchronous standbys, don't fail over
until a standby has caught up** with the primary (`pg_stat_replication`
shows it streaming and in sync again). A failover manager that promotes
only standbys known to be in sync won't promote one that's behind, but a
manual promotion can still lose those commits.

## What ferritor notices

- **A lost rotation (keys database)** is caught: after the next unseal, the
  KEK check reports the version as `missing` (see
  [backup and restore](/operations/backup-restore)), and the rotate guard refuses to
  rotate (`KEYS_DATABASE_MISMATCH`), so the lost version number isn't
  handed to a second, different KEK. The rows it wrapped stay unreadable.

  It shows earlier still, before any reseal: each running server's next
  periodic refresh (within `keyring_refresh_secs`) succeeds and writes a
  `keyring_refresh` audit entry whose `active` version is **lower** than the
  one before it for that namespace (a `rotate_kek` outcome or an earlier
  refresh; `active` maps each namespace to its active version). An active
  version never goes down otherwise, so that's an unambiguous sign the keys
  database went back in time, and the entry also lists the KEK as
  `vanished`. It comes within a minute, from the refresh that starts
  keeping that KEK for reading only (see below), and the rescue needs the
  server that holds it, so **alert on it** as the audit log arrives rather
  than finding it afterwards.
- **A lost namespace creation (keys database)** is caught the same way: the
  refresh's `active` no longer names the namespace and `vanished` lists its
  KEKs, which servers that loaded it keep for reading only (the namespace
  has no active KEK there any more, so new writes under it are refused with
  `NO_NAMESPACE`); after the next unseal, the KEK check reports it in
  `lost_namespaces`; and creating it again is refused while its rows exist
  (`KEYS_DATABASE_MISMATCH`), so its KEK 1 isn't handed to a different key.
  Rescue its rows as in [a lost namespace](#a-lost-namespace-still-in-memory)
  below. A **lost namespace delete** goes unnoticed in the keys
  database, but the data database's raised floor still fences its old KEKs
  off from writes.
- **A lost rekey commit (keys database)** stops every unseal. Servers
  that were running the newer generation fail their keyring refresh,
  because the stored generation no longer matches theirs (logged and
  audited; the message reads as if another server had rekeyed). At the next
  unseal the new shares are refused (they carry their generation), and so
  are the old ones: the data database's root-generation floor was raised to
  the new generation after the commit, and the keys database is now one
  below it (`ROOT_BELOW_FLOOR`, naming both). The server can't tell this
  from a rollback meant to bring back retired shares, which is what the
  floor stops, so a person decides:
  1. the old shares are the right ones again; the new ones were never
     stored, so set them aside;
  2. lower the floor to the keys database's generation (in the data
     database: `UPDATE root_generation_floor SET generation = N`). That's a
     write to the data database alone, since the keys database is already
     back at N: the both-databases bar is met, not dropped;
  3. unseal with the old shares, and rekey again.
- **A lost root commitment (data database)**: the rekey stored the new
  generation's commitment, the keys database committed, and the data
  database then failed over without it. Every unseal is refused
  (`ROOT_UNCOMMITTED`); `ferritor unseal --recommit` with the new shares
  stores it again, once a stored secret opens under the key (see
  [key management](/operations/key-management#the-root-commitment)).
- **A lost init** is obvious: `ferritor status` says not initialized, and the
  shares handed out unseal nothing. (A lost init can't hide behind an
  earlier one: init refuses on an initialized keys database.)
- **A lost policy write** (keys database) is caught by every server: one
  that loaded the newer set keeps it in force and raises the rollback alarm
  (`policy_reload` with result `rollback`, and `ferritor.policy.revision`
  differing between servers), and one restarted since has none in force,
  by the highest revision the data database keeps
  (`policy_revision_floor`). The fix: re-apply the set from its source of
  truth (`ferritor policy apply --prune`, which lands above the floor), then
  find out what else was lost.
- **A lost destroy**, and **anything else lost from the data database** (a
  put, a delete, a restore, a KEK floor raise, a root-generation floor
  raise) go unnoticed.

### A lost rotation's KEK, still in memory

After a lost rotation, a server that's still running holds the lost KEK:
the only copy left. Its next keyring refresh (within
`keyring_refresh_secs`, 60 s by default, or at once on SIGHUP) sees that
the keys database no longer has a KEK it holds, without having destroyed
it, and **keeps it, for reading only**:

- it isn't dropped: rows it wrapped stay readable on this server;
- it no longer wraps anything: new data keys are wrapped with the active
  version the keys database has, so no new row depends on it;
- the refresh logs an error and is audited: `keyring_refresh` with the
  lower `active` version and `"vanished": [{"namespace": …, "version": …}]`. The
  `ferritor.kek.vanished` gauge goes above 0 on that server. Alert on either.

It lives only in this server's memory, until it seals or restarts. So
**after a keys-database failover that may have lost a rotation**:

1. **Don't seal or restart any server** until this is done: a server
   holding the vanished KEK has the last copy.
2. **Make every server refresh**: send each one SIGHUP (or wait one
   `keyring_refresh_secs`). That's safe: a refresh keeps the KEK. Until a
   server's own refresh, the lost KEK is still its *active* one and it
   keeps writing new rows with it; after it, no server wraps with it any
   more, so one rescue can move every row. **Do this before any rotate or
   namespace create**: until a server refreshes, it may still write with a
   lost KEK, and a rotate or create could give that KEK's number to a new
   key. The guards only see rows that exist when they run, so a lost
   rotation (or namespace creation) that no row used yet passes them, and a
   stale server's later row then carries a number that means a different
   key: unreadable. (`--past-lost-keks` is safe here: it raises the floor
   first.)
3. **Find the holders**: ask each server directly, `ferritor status --addr
   <that server>`, which counts the vanished KEKs it holds, and `ferritor
   namespace list --addr <that server>`, which names them (or look for the
   audit entry or the gauge).
4. **Run `ferritor rewrap` against every server that reports vanished
   versions**, each with `--addr` pointing at that server, not through a
   load balancer. On the first, rewrap moves every row off older and
   vanished versions onto the active one, using the in-memory copy to
   unwrap, so those rows become readable from the keys database again:
   that's the rescue. Once no row uses a vanished KEK, rewrap **releases**
   it ("released vanished KEKs"): the keyring is back to what's
   stored, and the gauge back to 0. On the other holders it finds no rows
   left and just releases. Don't leave a holder unreleased: if a rotation
   later reuses the number, that holder still has the old key under it
   until its next refresh, and its reads of rows wrapped by the new one
   fail.
5. **Check**: `ferritor status --addr` on each server shows no vanished
   KEKs, a freshly unsealed server reads every secret, and the unseal
   check reports nothing missing.

### A lost namespace, still in memory

A lost creation leaves rows under a namespace the keys database doesn't
have, readable only on servers that loaded its KEKs (kept as vanished, as
above), and it has no active KEK, so rewrap has nothing to move them onto.
If a keys-database backup has the namespace, restore it. After a failover
there usually isn't one (the creation was the newest change), so recreate
it past its lost KEKs:

1. **Don't seal or restart any server**, and **make every server refresh**
   (SIGHUP), as above: afterwards no server writes with the lost KEKs.
2. **Find a holder**: `ferritor namespace list --addr <that server>` names the
   namespace's vanished versions.
3. **Recreate it there**: `ferritor namespace create <name> --past-lost-keks
   --addr <that holder>`. Plain create stays refused (`KEYS_DATABASE_MISMATCH`),
   so skipping ahead is a deliberate choice. It's allowed only while the
   namespace isn't live and the data database has rows under it; its first
   KEK goes one past every version still in use (its rows', its floor, the
   keys database's own, and those the holder still has), so no number goes
   to a second key, and the namespace's floor is raised to it first, so a
   server still writing with a lost KEK is refused from then on (it
   refreshes and uses the new one). If one wrote meanwhile, the command is
   refused (`ABORTED`): refresh every server and run it again.
4. **Rewrap on every holder**: `ferritor rewrap --namespace <name> --addr <each
   holder>`, as in step 4 above: the first moves the rows onto the new KEK
   and releases the lost ones; the others just release.
5. **Check** as above. The KEK check after an unseal reports the lost
   versions as `missing` until no row uses them.

Rows can still be lost: any that only a server which has since sealed or
restarted could read, such as rows written with the lost KEK by a server
that crashed before its refresh. Nothing can write the lost KEK itself
back into the keys database; once rescued, it isn't needed.

## During a failover

Calls in flight when the primary goes away fail: reads with a database
error or timeout (`UNAVAILABLE`), writes with an **unknown outcome** (the
commit may or may not have landed). The usual rules for unclear outcomes
apply: a put retried may create an extra version, a check-and-set put is
safe to retry, a delete or restore is safe to retry, and for admin calls
check `ferritor namespace get` before repeating one (a rotation retried
blindly adds two KEK versions). The connection pools reconnect on their own once the
endpoint reaches the new primary.

[Watch streams](/guides/secrets#watching) stay open through it: each server's
change feed retries from where it was, and once it reaches the new primary
it tells every stream to `resync` (a transaction id from the old primary
means nothing on the new one, so the changes since can't be told one by
one; the same after any restart of the data database). Their clients read
everything again.

### Auto-unseal and a KMS outage

With auto-unseal ([key management](/operations/key-management#auto-unseal)), KMS
is a dependency of **starting**, not of running: a server unseals itself
with one `Decrypt` at start, then holds the root key in memory. A KMS
outage in the key's region (or the servers' route to it cut) leaves
running servers serving, and keeps every server that starts, or reseals
itself, sealed and retrying (`ferritor.seal.auto_unseal` with result
`kms_unavailable`). Meanwhile the recovery shares unseal any server with
`ferritor unseal`, as without KMS. A failover of either database during a
start is retried the same way; an unseal never takes a hold it can't read
for released.

## Finding what was lost

The audit log is the record of what ferritor acknowledged. Shipped off the
host as it's written (see [audit](/operations/audit)), it survives a database
failover, and still has a `succeeded` outcome for every write the database
then lost. After a failover that may have lost commits (an asynchronous
standby promoted, or a manual promotion after a standby outage), compare
the two: each write outcome since the last point the standby surely had
(`put` with its version, `delete`, `restore`, `rotate_kek`, `destroy_kek`,
…) should be in the database. What isn't was lost: redo it (a delete, a
put of the current value, a destroy-kek), and for a lost put whose version
number was since reused, tell the clients that read it. Include `unknown`
outcomes: those are the writes most likely committed on the primary only.

## Read replicas

Not supported: every query goes to the primary. Don't point either URL at a
read replica. Writes would fail there, and the reads that decide what to
write (the next version number, check-and-set, the KEK floor, the
rotate and init guards) must see every commit.

If ferritor ever reads from standbys, the synchronous ones can serve reads
without going stale: with `synchronous_commit = remote_apply`, the primary
acknowledges a commit only once the standby has applied it (not just
written it), which gives read-your-writes on that standby. The reads that
decide what to write would still go to the primary.
