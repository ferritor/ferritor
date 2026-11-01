---
title: 'Key management'
description: 'Init, unseal and seal, the root commitment, auto-unseal with AWS KMS, namespaces, rekey, KEK rotation, rewrap and destroying KEKs.'
seo:
  title: 'Key management in ferritor: unseal, rekey, rotate'
---

See [architecture](/concepts/architecture) for the key hierarchy. Every operation
here is an admin call (`SystemService`), authorized by its own action (see
[policy](/guides/policy)) and audited with its outcome.

## Init

```sh
ferritor init --shares 5 --threshold 3
```

Generates the root key, splits it into shares, and prints them **once**. It
creates no KEK: KEKs belong to namespaces, and there's none until one is
created (below). Give each to a different operator; the server is
still sealed. Init is refused if the data database already holds secrets
(their KEKs were in a keys database that's gone; see
[backup and restore](/operations/backup-restore)).

Init also stores a **root commitment** in the data database (below), and
is refused once one has committed (`root_generation_floor` above 0), even
if the keys database looks uninitialized: a wiped keys database doesn't
start a deployment over the data database's.

If the reply carrying the shares is lost (a timeout, a dropped connection),
the init may have been stored with nobody holding shares; see
[operations](/operations/running) for how to tell and recover.

## Unseal and seal

```sh
ferritor unseal          # once per share, until the threshold is reached
ferritor unseal --reset  # discard the shares submitted so far
ferritor seal
ferritor status          # sealed or not, progress, generation, how many namespaces
```

**Seal is the emergency stop.** Once permitted it never fails (a failed call
would read as "still unsealed"). It drops the keyring at once, before even
waiting for the admin lock, so an admin call stuck on the database can't
delay it; anything in flight fails and keeps nothing. It also discards a
rekey in progress, and reports in its reply whether a rekey commit had
already landed (then the *new* shares are the ones to keep).

`ferritor status` shows totals only (how many namespaces, how many vanished
KEKs this server holds), never names: namespace names are often customer or
team names, so they're behind the `namespace` action (`ferritor namespace list`
and `get`).

After every unseal the server checks, in the background, that every KEK a
row in the data database uses is in its keyring; see
[backup and restore](/operations/backup-restore).

### The root commitment

The shares reconstruct whatever root key the keys database's `root_check`
names. So someone who can write the keys database could replace the seal
configuration and the KEKs with a root key of their own, split into shares
of their own, and unseal a server with it: every new secret would then be
wrapped by KEKs they know. To stop that, the **data database** keeps a
commitment to each generation's root key (an HMAC over the generation,
under a key derived from the root key), and an unseal is refused unless
one verifies, and unless the generation is at least the
`root_generation_floor` there (the highest generation known to have
committed):

- **`ROOT_UNCOMMITTED`**: no commitment matches. Either the data database
  lost it (restored from before a rekey, or a failover lost the write), or
  the keys database holds a root key that isn't this deployment's. Submit
  the shares again with `ferritor unseal --recommit`: it stores the
  commitment only if a secret stored in the data database opens under the
  key, proof it's the one the data was written under (shares alone prove
  *a* root key, not that one). A key that's not this deployment's opens
  nothing and is refused, and with no secret stored at all there's
  nothing to prove it with (see [backup and restore](/operations/backup-restore)).
  A re-commit is an alarm in the log and the audit log (`"recommitted":
  true`).
- **`ROOT_BELOW_FLOOR`**: the keys database is older than the last rekey
  the data database knows of (a restore, or a failover that lost the
  rekey's commit); the message names both generations. A re-commit never
  lowers the floor: that would bring back shares a rekey retired. See
  [backup and restore](/operations/backup-restore) and
  [high availability](/operations/high-availability).

Commitments are insert-only (a trigger refuses any update or delete), and
init and every rekey store theirs **before** the keys database commits,
then raise the floor after (retried in the background until it lands,
`ferritor.seal.floor_pending`). An attempt that fails leaves a commitment to
a key nobody holds, which is harmless.

## Auto-unseal

By default every start ends sealed, and a threshold of operators unseals
each server with their shares. With auto-unseal a server unseals itself
at start through a key management service, AWS KMS for now:

```toml
[seal]
provider = "awskms"

[seal.awskms]
key_id = "arn:aws:kms:ap-southeast-1:111122223333:key/1234abcd-12ab-34cd-56ef-1234567890ab"
```

The keys database then also holds the root key wrapped by that KMS key
(`kms:Encrypt`, bound to `{"ferritor:purpose": "root-key",
"ferritor:generation": "<n>"}`), and at start the server has KMS decrypt it,
checks it as a shares unseal is checked (`root_check`, the
[root commitment](#the-root-commitment), the floor) and unseals. Settings
are in [configuration](/reference/configuration#seal); credentials come from the AWS
SDK's usual chain (`AWS_PROFILE`, EKS Pod Identity or IRSA, an instance
profile), never from ferritor's config.

- **The shares stay**, as the **recovery shares**: shares of the same root
  key, which unseal any server as before. If the KMS key is disabled,
  deleted, unreachable, or its account lost, they're the way in: an
  outage, never lost data. Keep them as carefully as before.
- **What it trades:** with auto-unseal, whoever can read the keys database
  *and* use the KMS key (`Decrypt`) has the root key, so the key's access
  control becomes part of ferritor's. See [security](/concepts/security) for
  what that implies and how to keep it narrow, and
  [production](/getting-started/production) for the key policy.
- **The key comes from the config, never the database:** every `Decrypt`
  names it, so a row pointing at another key is never followed. Use the
  key's ARN in production rather than an alias: whoever can retarget an
  alias decides which key the next rekey wraps under.

**Init** on a server configured for it wraps the new root key first (if
that fails, nothing is stored anywhere), prints the shares as recovery
shares, and leaves the server unsealed. **At start**, and whenever it's
sealed, a server tries to unseal itself: retried while KMS or a database is
unreachable (1 s doubling to 60 s), with `ferritor unseal` and the shares
working meanwhile. KMS refusing by policy (`denied`) is looked at again
every minute, and so are a missing root commitment and a generation below
the floor (`ROOT_UNCOMMITTED`, `ROOT_BELOW_FLOOR`: an alarm in the log and
the audit log), so a `--recommit` or a floor fix on one server brings the
others up too. A wrap that isn't this deployment's key (`mismatch`) stops
the attempts until the server is unsealed some other way. The KMS calls
run without the server's admin lock: `ferritor status` answers while KMS is
slow. `ferritor status` shows it:

```
auto-unseal: awskms arn:aws:kms:…            # the key: only to callers who may unseal
auto-unseal wrap for this generation: yes
auto-unseal last attempt: ok                  # or kms_unavailable, denied, mismatch, held, …
auto-unseal hold: released (held here: no; keys database: hold 3, released 3; data database: hold 3, released 3)
```

### The hold: a seal that stays sealed

Seal is still the emergency stop, but a server that unseals itself would
undo it at its next restart. So `ferritor seal` (in both modes, and on a
server already sealed) also sets the **hold**, which stops every server's
next auto-unseal; servers already unsealed keep running (seal is per
server, as always). A plain shutdown sets no hold: a rolling restart
unseals.

The server that was sealed holds itself at once, in memory, in the same
step that drops its keys, so its own loop can't undo the seal in the
moment before the hold reaches the databases (or if it never does); only
an unseal on that server ends its own hold (`ferritor status`: `held here`).
Every other server is held by the databases' hold, and looks at it every
minute without calling KMS: a release brings them up within a minute.

The hold is a pair of counters kept in **both** databases, and a server
auto-unseals only if each shows the hold released; a database that can't
be read counts as held. So undoing an emergency seal takes write access to
both databases, or an explicit release:

```sh
ferritor unseal --auto           # release the hold, then unseal this server through KMS
ferritor unseal --release-hold   # with the shares: release it once this server is unsealed
```

Both take the `unseal` permission, nothing more: `--release-hold` on a
server already unsealed releases at once. Unsealing one server with plain
shares (for forensics, say) does *not* release it. `--auto` on a server configured for the shares alone is
refused.

> [!WARNING]
> If `ferritor seal` can't write the hold to both databases, the server
> *is* sealed, but a restart could unseal it: the reply says so
> (`hold_set: false`, printed as a warning), and the server retries the
> write until it lands (`ferritor.seal.hold_pending`).

> [!TIP]
> For a lockout that holds even against someone with both databases, seal
> every server and disable the KMS key, or remove the servers' permission
> to use it.

### Changing mode, or key: a rekey

A rekey wraps its new root key under the configured key (once the new
shares are verified, before anything is stored) and stores that wrap with
its commit, deleting every other: whatever the answering server's config
says becomes every server's. So a rekey keeps the deployment's protection
unless asked to change it, and refuses up front, before any share is asked
for, through a server configured otherwise (config drift, a debugging
node). The shares holders then approve the change knowingly, and the
audit entry records it (`"seal"`: `kept`, `shamir` or `awskms`):

- **Shamir → KMS:** configure `[seal]` on the servers, restart them (they
  stay sealed: there's no wrap yet), unseal one with the shares, and
  `ferritor rekey start --seal awskms`. From then on every server with that
  config unseals itself.
- **KMS → Shamir:** remove `[seal]` from a server, unseal it, `ferritor rekey
  start --seal shamir`: the commit stores no wrap, so the new shares are
  needed again.
- **Another KMS key:** change `key_id`, then `ferritor rekey start --seal
  awskms`.

AWS's automatic key rotation keeps the old key material, so existing wraps
keep working without one. A rekey on one server makes the others fail
their next refresh, as without KMS: seal each of them, then `ferritor unseal
--auto` (which releases the hold that seal set and unseals through KMS
with the new generation's wrap), or unseal them with the new shares.
Following a rekey elsewhere on their own is still to come.

## Namespaces

A secret's namespace is its path's first segment: `billing/db` and
`billing/api/key` are in `billing`. Each namespace has its own KEKs,
numbered from 1, rotated, rewrapped and destroyed on its own; a KEK is
named by namespace and version (`billing/2`), and its wrapped key is bound
to both, so a KEK row moved to another namespace doesn't open. There's no
default namespace: a put under a first segment that isn't one is refused
(`NO_NAMESPACE`), only ever after the caller is authorized for the path, so
the answer can't be used to find out which namespaces exist.

```sh
ferritor namespace create billing --label team=payments   # with its first KEK
ferritor namespace list                                   # every namespace, its KEKs and floor
ferritor namespace get billing                            # one, with its labels
ferritor namespace label billing tier=1                   # set labels (plain metadata, never secret)
ferritor namespace unlabel billing team
ferritor namespace delete billing                         # only when empty; destroys its KEKs
```

All need the `namespace` action. Creating one is refused while the data
database already has rows under the name (`KEYS_DATABASE_MISMATCH`: the keys
database lost it; restore that one instead, or the new KEK 1 would collide
with the rows' own). If no backup has it (a failover lost its creation),
`ferritor namespace create <name> --past-lost-keks` recreates it with its first
KEK past every lost version, for a rewrap to move the rows onto; see
[high availability](/operations/high-availability#a-lost-namespace-still-in-memory).

> [!CAUTION]
> **Deleting** a namespace destroys all its KEKs, so every data-database
> backup of its secrets becomes undecryptable (crypto-shredding, as with
> `destroy-kek`). It can't be undone, and it also needs the `destroy_kek`
> action.

It's allowed only
once the namespace has no row at all, deleted ones included, so it takes at
least the deletion retention: delete its secrets, wait out
`purge_deleted_after_days`, `ferritor purge`, then delete it (else
`NAMESPACE_NOT_EMPTY`, with the counts). Like destroying a KEK, it raises
the namespace's KEK floor past its highest version first, so a stale server
that still holds the namespace can't write there any more (its put is
refused, it refreshes, finds the namespace deleted and answers
`NO_NAMESPACE`), then checks again that no row exists and removes every
path it ever had (their records: version counters, labels), then destroys
the KEKs and marks the namespace deleted. Safe to repeat. The namespace
keeps its row and its destroyed KEK rows: created again, its numbering
continues, so its first KEK lands exactly on the floor the delete raised,
and no number is ever reused for a different key. Its secrets' version
numbers continue too: the highest any of its paths reached is kept, and
every path of the re-created namespace numbers on past it, so a version
number never names two different secrets. The outcome's audit entry says
how many paths went (`paths_reclaimed`).

Creating and deleting a namespace lock the seal config `FOR SHARE`, like a
rotation, so they serialize with a rekey commit (which must re-wrap every
stored KEK).

## Rekey: new root key, new shares

Two phases, so a lost reply can never lose the root key:

```sh
ferritor rekey start --shares 5 --threshold 3   # prints a nonce
ferritor rekey submit --nonce N                 # once per *current* share, up to the threshold; the last prints the new shares
ferritor rekey verify --nonce N                 # once per *new* share, up to the new threshold; the last commits
ferritor rekey cancel --nonce N                 # abandon: the current shares keep working
```

The new root key is held in memory, **not committed**, until a threshold of
the new shares comes back. Only then does the server store the new
generation's root commitment in the data database, and one keys-database
transaction re-wrap every KEK, the policy key and the root check and bump
the generation; the root-generation floor is raised after. Until then,
cancelling or sealing drops the pending key and the current shares keep
working. Secrets aren't touched.

A failed commit call doesn't prove nothing was stored (the connection can
drop after Postgres commits): the server re-reads the stored state and
checks whether it opens under the pending key before discarding anything,
and an unclear outcome keeps the pending key. `ferritor status` shows a rekey
in progress (nonce, for callers allowed to rekey; phase; progress) and,
while verifying, the new shares' generation: if the status's own
generation already equals it, the commit landed unconfirmed and a further
`rekey verify` finishes it.

**The policy key.** The stored policies (see [policy](/guides/policy)) are
authenticated with an HMAC key, wrapped by the root key like a KEK
(`seal_config.wrapped_policy_key`), created by the first policy write. A
rekey commit re-reads it under its lock and re-wraps it under the new root
key, so one created by another server is covered too. A stored key that
doesn't open under the current root key (changed or corrupted in the
database) would make the commit fail, so a rekey checks it at `rekey start`
and again before committing, and refuses (`POLICY_UNVERIFIED`) with nothing
changed: repair the stored policies first (`ferritor policy apply --prune`,
which creates a new key), then rekey.

**The issuing key** (workload identity, [identity](/guides/workload-identity)) likewise:
a rekey commit re-reads the active issuing key under its lock and re-wraps
it, refusing (`FAILED_PRECONDITION`, nothing changed) if it doesn't open,
also checked at `rekey start`; rotate it first (`ferritor identity rotate
--now`). The issuing set's MAC is re-made under the new root key, same
revision; a set the current root key doesn't vouch for keeps its old MAC,
and stays untrusted.

Shares carry their generation; only shares of the current one unseal. A
keys-database backup from before a rekey needs the *old* shares.

## Rotate: a new KEK

```sh
ferritor rotate --namespace billing
```

Adds a new active KEK version to the namespace; its previous one becomes
decrypt-only. Other namespaces are untouched. The
server that rotated wraps new DEKs with the new KEK at once; other servers
sharing the databases keep using the old one until their keyring refreshes
(within `keyring_refresh_secs`, default 60, or on SIGHUP), so rows wrapped by
the old KEK keep appearing for a while after a rotation. Not idempotent:
each call adds another version. Refused for a namespace that doesn't exist
(`NO_NAMESPACE`; a server that doesn't know it yet refreshes first), and
while the namespace's rows use a KEK version the keys database doesn't have (`KEYS_DATABASE_MISMATCH`: it was
restored from an older backup, and a rotation would reuse that version for a
different key).

After a keys-database failover, make every server refresh (SIGHUP) before
any rotate or namespace create: until a server refreshes, it may still write
with a lost KEK, and a rotate or create could give that KEK's number to a
new key. The guard only sees rows that exist when it runs, so it can't catch
that (see [high availability](/operations/high-availability)).

## Rewrap and retire

```sh
ferritor rewrap                       # every namespace
ferritor rewrap --namespace billing   # just one
```

Moves DEKs still wrapped by older KEK versions of their namespace to its
active one, deleted rows included, then **retires** each decrypt-only version no row uses any
more. Bounded per call; the CLI repeats it until done. Safe to repeat,
interrupt or run concurrently (rows move compare-and-set). A row whose DEK
doesn't unwrap (corruption, tampering) is left as it is, logged, counted, and
keeps its own version from being retired.

Retiring is bookkeeping: a retired KEK stays stored and loaded. A server
whose keyring is stale (it hasn't reloaded since another server rotated)
keeps wrapping new DEKs with its old active KEK, possibly one retired
meanwhile; those rows stay readable, and the next rewrap moves them.

## Destroy a retired KEK

```sh
ferritor namespace get billing                 # check the version's state: only a retired one can go
ferritor destroy-kek --namespace billing 1
```

> [!CAUTION]
> Erases the KEK's wrapped key for good: nothing it wrapped can be
> decrypted any more, from any copy of the data database
> (crypto-shredding). Irreversible, but only an unused, retired version can
> be destroyed, so live data is never at risk; what goes is the ability to
> decrypt old data-database backups taken before the rewrap.

No timing rule could rule out a stale server still writing with the KEK (a
paused process, an older binary during a rolling deploy), so the data
database does: its **KEK floor**, one per namespace, refuses, by trigger, any
write of a DEK wrapped by a KEK of that namespace below its floor, from any
server or binary. A namespace without a floor row has floor 1; a raise
creates the row, only ever upwards. Raises lock per namespace, so destroying
one namespace's KEK pauses only that namespace's writes. Destroying version
v:

1. v must be retired (else `NOT_RETIRED`; rewrap first, and for the active
   version, rotate first).
2. The floor is raised past v. The raise waits for the writes in flight, and
   writes pause briefly behind it; once it returns, no write can use v.
3. No row may use v any more (else `KEK_IN_USE`: a stale server wrote with it
   after it was retired; rewrap moves it, then destroy again).
4. The keys database erases the key; the row stays, `destroyed`, so the
   version number is never reused.

Safe to repeat: an already destroyed version answers "already destroyed". A
stale server whose put is refused by the floor refreshes its keyring and
retries once.

"Erased" means from the live table. The old row version stays in the keys
database's files until vacuumed, and in its WAL, WAL archives and backups
until they age out. `VACUUM FULL keks` after a destroy is a best effort (a
new file; the old one is unlinked, not shredded).

Finish a rolling upgrade before destroying anything. An older binary can't
start once a newer server has migrated the databases, but one still running
can't refresh its keyring after a destroy and its writes are refused: it
stops writing until upgraded. Nothing is lost.

## Keyring refresh

An unsealed server reloads its KEKs with the root key it holds, so a
rotation, retirement or destroy by another server is picked up without
shares:

- when a read meets a KEK version it doesn't have (then it retries once),
- when a put is refused by the KEK floor,
- periodically (`keyring_refresh_secs`, default 60),
- on SIGHUP.

Refreshes on behalf of calls happen at most once per 5 s, so a row naming a
KEK that truly doesn't exist can't make every call reload the keyring.

A refresh only ever drops a KEK the keys database **destroyed**, or a
namespace it marked **deleted** (with all its KEKs). Three cases per
namespace:

- **present**: each KEK the keys database has is loaded; one it destroyed
  is dropped; one simply gone from it (a failover lost a rotation, an older
  backup was restored) is kept, as below;
- **deleted**: dropped, with its KEKs (its floor fences off stale writes);
- **absent altogether** (a failover lost its creation, an older backup):
  its KEKs are all kept, as below, and it has no active KEK, so nothing new
  is stored there.

A KEK kept that way is held in memory for reading only, as **vanished**, and
new data keys are wrapped with the namespace's stored active version; the
refresh logs an error and audits the KEK as `vanished`; `ferritor status`
against that server counts it, `ferritor namespace list` names it, and the
`ferritor.kek.vanished` gauge counts it. That server's copy is then the
last one: see [high availability](/operations/high-availability) for rescuing its
rows with a rewrap before the server seals. The rewrap releases the
vanished KEK once no row uses it.

A **rekey elsewhere can't be followed**: it re-wraps the same KEKs under a
new root key, so the ones this server holds keep working, but it can't load
any KEK rotated in after the rekey (its refresh fails, logged and audited),
and rows wrapped by those get `UNKNOWN_KEK`. Seal it and unseal with the new
shares.
