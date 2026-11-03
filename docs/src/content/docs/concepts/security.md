---
title: 'Security model'
description: 'What ferritor defends against and what it doesn''t: the actors and trust boundaries, each attacker''s reach, and the known gaps.'
seo:
  title: 'ferritor security model: threats, boundaries, gaps'
---

What ferritor protects, from whom, and where its protection ends. Each claim
points to the doc with the details; "Known gaps" at the end lists
what's open.

To report a vulnerability, privately:
[SECURITY.md](https://github.com/ferritor/ferritor/blob/main/SECURITY.md)
(GitHub's private vulnerability reporting). Never in a public issue.

## What it protects

- **Secret values**: confidential and authentic. Each version is encrypted
  under its own data key (DEK), wrapped by its namespace's KEK, wrapped by
  the root key ([architecture](/concepts/architecture)).
- **The root key**: never stored. Rebuilt in the server's memory from a
  threshold of Shamir shares at unseal, dropped at seal.
- **Who may do what**: the policy decides every request, by the caller's
  certificate identity ([policy](/guides/policy)).
- **What happened**: every decision and every change's outcome, in a signed,
  hash-chained audit log ([audit](/operations/audit)).

Not protected as secrets: **metadata**. Paths, namespaces, labels, version
numbers, timestamps and identities are plaintext in the data database, its
backups, the audit log and the server's logs. Name secrets and label them
accordingly.

## Actors and trust boundaries

```
 operators (shares, admin identities) ──┐
 applications (client certificates) ────┼── TLS + client certificate ──► ferritor server ──► keys database
 browsers holding a client certificate ─┘   (per-request identity,       (root key and      (wrapped KEKs,
                                             expiry, revocation)          KEKs in memory)    policies)
                                                                              │          ──► data database
                                                                              │              (ciphertexts,
                                                                              ▼               wrapped DEKs)
                                                                 audit log (stdout) ──► shipped off the host
```

| Who | Holds | Trusted with |
|---|---|---|
| The server host (root, or the server's user) | the process's memory; `ferritor.toml` with both database URLs and their passwords (write access to both databases); the server's TLS key; the audit signing key | **everything**: see "What it doesn't defend against" |
| The client CA's key holder | the ability to mint any `ferritor://<name>` | **everything**: an identity named in an admin config rule is an admin |
| A trusted token issuer (`[[identity.issuer]]`), and whoever can make it sign a token with ferritor's audience (a cluster's admins create service accounts; a CI repository's maintainers run workflows) | certificates for the identities its mappings allow ([workload identity](/guides/workload-identity)) | what stored policies grant identities under its name, nothing more: never an admin, an operator's name or another issuer's |
| A threshold of share holders | the root key, together | every secret, given the databases |
| Operators, one at a time | one share; their admin identity's actions | what their config rules grant; a share alone reveals nothing |
| Holders of `policy` | the stored policies | any secret action for **any identity, their own included**: in effect, reading every secret (never an admin action) |
| Holders of `destroy_kek` (with `namespace`) | destroying a retired KEK; deleting an empty namespace | every backup of the rows a destroyed KEK or deleted namespace covered becomes unreadable, for good; live data is never touched (the KEK must be unused, the namespace empty) ([key management](/operations/key-management)) |
| Holders of `purge` | removing deleted versions past `purge_deleted_after_days` | losing those versions for good: once purged, a deleted secret can't be restored |
| Holders of `seal` | the emergency stop | stopping service on that server until a threshold unseals it; sealing everything means sealing each server |
| Applications | their client certificate | their stored policies' grants, nothing more |
| Client hosts (where the CLI or an application runs) | the values they read, the shares typed into them, their certificate's key | what that identity may do, and the shares entered there |
| Database administrators, backups | one database each, or both | wrapped keys only, never a usable one; integrity and availability (below) |
| The network | | nothing: TLS with a client certificate on every connection |

The boundaries that matter: the server process (keys exist in usable form
only inside it), the client CA (it decides who exists), the shares (they
decide who can unseal), and the two databases (each alone useless).

## What it defends against

**A stolen database or backup.** The keys database holds KEKs wrapped by the
root key; the data database holds ciphertexts and DEKs wrapped by KEKs.
Either alone, or both together, opens nothing without a threshold of the
shares of that backup's generation ([backup and restore](/operations/backup-restore)).
Destroying a KEK, or deleting a namespace, makes every backup of the rows
it wrapped undecryptable for good (crypto-shredding); "erased" means from
the live table, not from Postgres's WAL or older backups
([key management](/operations/key-management)).

**Write access to the keys database**, for confidentiality and new access.
Stored policies carry an HMAC under a key wrapped by the root key, so a
policy inserted, changed or deleted, the key cleared, or the whole set
wiped makes the set fail to verify: a running server keeps the last
verified set and alarms, a starting one has none in force
([policy](/guides/policy#integrity)). Admin rights can't be created at all: they
come from the config alone. Swapping wrapped KEKs between versions or
namespaces fails to open: the wrapping binds both. Nor can it roll the
set back: an older, validly signed set (saved earlier, or read from any
backup) written back, or everything wiped to revision 0, is below the
highest revision any server wrote, which the data database keeps
(`policy_revision_floor`, raised by every policy write), so every server
refuses it, a restarted one too, and has none in force. Rolling the
stored policies back takes write access to both databases, the bar the
rest of the design sets.

Nor can it **substitute the root key**: a seal configuration, `root_check`
and KEKs of a root key of the writer's own making, with shares they split
themselves, would unseal a server and have every new secret wrapped by
KEKs they know. An unseal accepts a root key only if the data database
holds a commitment to it (an HMAC under a key derived from it, insert-only)
at a generation not below the floor kept there, so that key is refused
(`ROOT_UNCOMMITTED`). Re-committing with shares (`ferritor unseal
--recommit`, for a data database that lost its commitment) also needs a
secret stored in the data database to open under the key, which a key of
the writer's own can't do. And a keys database put back from before a
rekey, with the shares that rekey retired, is below the floor
(`ROOT_BELOW_FLOOR`). Substituting or rolling back the root key takes
write access to both databases.

**Rows swapped in the data database.** The AAD binds each ciphertext and
wrapped DEK to its exact path and version, and paths have one spelling
only, so a row copied to another path or version doesn't decrypt
([architecture](/concepts/architecture)).

**A compromised application certificate.** It reaches only what that
identity's policies grant. Cut it off by revoking it (a CRL, checked on
every request, also on open connections: [TLS](/guides/tls#revocation-crls)),
by deleting its stored policies (in force on every server within
`policy_refresh_secs`, default 5 s), or at once, for everything, by
sealing.
A [watch stream](/guides/secrets#watching) it opened ends too: before each
change it would send, its permissions are asked again (a deleted policy
stops it there), and every 30 s the certificate is checked as a request's
is (a CRL, its issuing CA); it ends when the certificate expires. A stream
tells versions, never values, and only of paths its caller may read (or
list).

**A stolen share.** A share alone is useless; unsealing takes a threshold.
Rekey replaces every share, keeping secrets as they are, and a share of an
older generation no longer unseals ([key management](/operations/key-management#rekey-new-root-key-new-shares)).

**A stale server** (paused, partitioned, an older binary mid-deploy). It
can't write with a destroyed KEK: the data database's KEK floor refuses it,
whatever the server holds. It follows rotations, destroys and policy
changes by refreshing; once sealed, nothing in flight keeps using the keys
(epochs). A rekey elsewhere it can't follow: it seals and unseals with the
new shares.

**A tampered audit log**, within a chain. Lines are hash-chained and
checkpoints signed with an Ed25519 key, so an edit, deletion, insertion or
reordering inside a chain, and anything appended after a chain's signed
end, is caught by `ferritor audit verify` ([audit](/operations/audit)); its limits are
below. The log fails closed: an allowed request whose entry can't be
written isn't served. Every call that changes state records its outcome
even if its client disconnects first.

**The network.** TLS 1.2 or 1.3 (rustls's safe defaults) with a client
certificate, required on every connection in secured mode; the identity,
expiry and revocation are checked again on every request, not only at the
handshake ([TLS](/guides/tls)). Handshakes are bounded in time and number.

**Browsers.** A client certificate in a browser is an ambient credential;
cross-site requests can't change anything (every state change needs a CORS
preflight the server never grants) nor read an answer
([HTTP API](/reference/http-api#browsers)). Dev mode, plaintext and allowing
everything, answers only requests addressed to loopback, against DNS
rebinding.

**Another process of the server's user, and crashes.** The server marks
itself undumpable first thing at startup (`PR_SET_DUMPABLE` 0), before it
reads anything secret: a crash leaves no core dump with the root key and
the KEKs in it, and no other process of its user can attach to it (ptrace)
or read its memory (`/proc/<pid>/mem`), whatever `kernel.yama.ptrace_scope`
says. The example systemd unit keeps its memory out of swap
(`MemorySwapMax=0`) and adds `LimitCORE=0` and sandboxing
([production](/getting-started/production#6-run-it)). Root still can; gap 1 is what's
left of swap.

**Enumeration.** A caller learns whether a namespace exists only for paths
it's authorized for (`NO_NAMESPACE`); `status` shows totals, never names.

**The supply chain**, as far as the build goes. Dependencies come from
crates.io only, through committed lockfiles (`--locked` everywhere), and CI
fails on a RUSTSEC advisory, an unmaintained or yanked crate (`cargo
deny`); the CI's actions are pinned by commit, and the parsers of outside
input are fuzzed ([development](/contributing/development)). Releases are tagged
only from a commit CI passed, and their container images are signed with
cosign, keyless: the signature's certificate names the workflow that built
them, `release-plz.yml` on `main` of `ferritor/ferritor`, and the signing
is recorded in Sigstore's public transparency log. Verifying it
([Kubernetes](/getting-started/kubernetes#what-you-need)) proves an image is
one that workflow built and pushed, not that its code is sound: whoever
can merge to `main` (a release pull request included) can have an image
signed, and GitHub and Sigstore are trusted for the identity. The release
archives (the same static binaries, for x86_64 and aarch64 Linux) are
signed the same way, each with a cosign bundle beside it, and `SHA256SUMS`
lists their checksums; a published release is immutable, so its assets
can't be swapped afterwards.

## What it doesn't defend against

**Root on the server host**, or anyone who can act as the server's user.
The unsealed server holds the root key and every KEK in memory: whoever can
read that memory (ptrace, `/proc/<pid>/mem`, a debugger, a core dump, swap,
a VM snapshot) has every secret, past backups included. The same access
reads the audit signing key (so it can sign forged checkpoints for the local
file), the server's TLS key, and `ferritor.toml`: the database passwords in it
give write access to both databases, and editing it grants any admin
action at the next reload. Defend the host, keep the audit log shipped off
it as it's written, and keep the server's memory out of swap (gap 1).

**The client CA's key.** Whoever has it can issue a certificate for any
identity, an operator's included. Keep it off the ferritor host, ideally
offline, and issue client certificates from an intermediate that's the only
CA in `client_ca` ([production](/getting-started/production#3-certificates)).

**A trusted token issuer**, and whoever can get a token from it with
ferritor's audience: they get certificates for the identities its mappings
allow, an hour at a time ([workload identity](/guides/workload-identity)). Bounded by
the issuer's prefix (no config rule may name an identity under it, so never
an admin) and by `require`; a mapping that fills a segment from a claim
the token's holder controls (a branch name, a job's own input) lets them
choose that segment. So does whoever controls its keys: the JWKS file, or
its URL's server, or a CA trusted for that URL (the public web PKI by
default; `jwks_ca` narrows it). A token copied from a workload is good for
a certificate until its `exp`, and the certificate for its lifetime after
that: cut either off with a cutoff ([revoking](/guides/workload-identity#revoking)).
Grant issuers' identities what their workloads need, under narrow
prefixes.

**A threshold of share holders acting together**, with the databases: that
is the root key, by design.

**Holders of `policy`**: they can give any identity, their own included,
any secret action on any path, so `policy` is in effect "read everything".
Grant it as narrowly as `destroy_kek`, and keep the stored set under review
in a source of truth applied with `--prune`.

**Write access to the data database**, for integrity. Each row decrypts
only at its own path and version, but nothing authenticates a path's set of
versions: whoever can write the data database can delete a path's newer
versions (its latest becomes an older value, a password that was meant to
be retired), clear a version's `deleted_at` (a deleted secret comes back),
delete rows or labels, or corrupt them. It can also block the stored
policies: raising the policy revision floor (`policy_revision_floor`) past
the stored revision makes every server refuse the set until a repair, and
near BIGINT's maximum even the repair fails (its revision wouldn't fit)
until the floor is fixed by hand; deleting the floor's row makes the set
unreadable everywhere and refuses policy writes. Both fail closed
([operations](/operations/running#fixing-the-policy-revision-floor) has the
fix). Confidentiality holds; integrity and availability are the database's
(gap 2). The audit log's outcomes record every version a put stored, so a
comparison would show it; nothing checks this automatically.

The same writer can lower the issuing keys' revision floor
(`issuing_revision_floor`), which alone does nothing (a running server
remembers the revision, and the set's MAC still holds), but with write
access to the keys database too lets a restarted server accept an older
set: a revoked issuing key back. Raising it past the stored revision makes
every server distrust the issuing keys (fail closed) until `ferritor identity
rotate --now`, which writes past it.

**Write access to the keys database**, for availability. It can delete KEK
rows or mark them destroyed (servers drop destroyed KEKs at their next
refresh, and the rows they wrapped can't be read), wipe or corrupt the
stored policies (applications lose access until a repair), or change the
seal configuration (nothing unseals). A set rolled back or wiped to
revision 0 is refused too (above), with the same effect: no stored grant
in force until the set is re-applied. It can delete or corrupt the issuing
keys (a restarted server then trusts none, and no workload certificate is
issued or accepted until `ferritor identity rotate --now`), but not add one
or bring a revoked one back: the set carries a MAC under the root key over
every key's certificate, state and retirement and the set's revision, a
set that doesn't verify isn't trusted, and an older one written back whole
is below the floor in the data database ([workload
identity](/guides/workload-identity#revoking)). None of
it reveals a secret; all of it stops service until a backup is restored or
the policies re-applied.

**Auto-unseal's KMS key**, when it's configured
([key management](/operations/key-management#auto-unseal)). With it, the root key
can be had two ways: a threshold of shares, as always, or **read access to
the keys database plus `Decrypt` on the KMS key** (the servers' role, and
anyone who can act as it or change the key's policy). That second way is
what lets a server start unattended, and what it costs: the key's access
control becomes part of ferritor's. With **write** access to the keys database
plus `Decrypt`, the root key also gives:

- **forged stored policies**: the root key opens the policy key, so any
  secret action for any identity, through the normal API, with no
  data-database access at all (admin actions still come from the config
  alone, so no admin);
- **a forged issuing set**: an issuing CA of their own, and workload
  certificates for any configured issuer's identities;
- **passing the root commitment's continuity check**: they can unwrap the
  genuine KEKs, wrap them under a root key of their own and re-commit it
  with its shares, which gains little they didn't have (persistence past
  losing KMS access, until the next genuine rekey).

Keep that access narrow ([production](/getting-started/production)): `Encrypt`,
`Decrypt` and `DescribeKey` for the servers' role alone, with the
`ferritor:purpose` encryption context and an `aws:SourceVpce` (or
`aws:SourceVpc`) condition, so stolen role credentials don't work outside
the deployment's network; no broad `kms:*` admin on the key; the key ARN,
not an alias; CloudTrail alarms on calls from elsewhere or more often than
servers start. A keys-database backup is readable by whoever also has
`Decrypt`. Disabling the key stops future auto-unseals, not running
servers: seal them too.

What auto-unseal doesn't change: substituting or rolling back the root
key still takes write access to both databases (the root commitment, the
floor), and so does undoing an emergency seal behind ferritor's back (the
hold is kept in both); the shares still unseal without KMS. Undoing it
through ferritor takes the `unseal` permission alone: `ferritor unseal --auto`
or `--release-hold` releases the hold for every server, so grant `unseal`
as narrowly as `seal`.

**Secrets delivered as files** ([the agent](/guides/agent)). The files are the
secret once written: whoever can read them (the application's user or
group, root, the node's or host's administrators) has the values, and the
audit log records the agent's reads, not the application's use of the
files. Revoking an identity's access, or deleting a secret, stops the agent
fetching new values but doesn't take back the ones it delivered: with
`on_revoked = "keep"` (the default, for availability), the application
keeps a value its identity may no longer read for as long as it runs. To
cut a workload off, rotate the secret itself, restart the workload, or set
`on_revoked = "remove"`. The agent's own certificate is mounted into its
container only, so a compromised application has the values it was given,
not the means to fetch more, as long as its identity's policies grant no
more than the agent renders. Its output directory must be in memory
(tmpfs), but tmpfs pages can be swapped out (gap 1), and writable by the
agent alone: the agent refuses to follow a planted `..data` out of it,
but a writer there can make renders fail or swap files under the
application.

**The CSI provider** ([CSI](/guides/csi)), one per Kubernetes node, reads each
pod's secrets with that pod's identity, from the token the kubelet hands
the driver, never with one of its own, so a compromised node exposes what
the pods on it may read and their tokens, not every workload's. It shares
a read only between pods whose own tokens exchanged to the same identity.
Its socket is the boundary: whatever reaches it can mount any volume with
any token it holds, so it's root's (`0600`, in the driver's provider
directory) and no workload may mount that directory. The driver's sync
into Kubernetes Secrets (`secretObjects`) copies values into etcd, outside
ferritor's audit log; the provider can't see it, so keep it off by admission
policy.

**The audit log's limits.** A whole chain (one server run) removed from a
file holding several can't be detected, and a cut at the end of the last,
still open chain, back past its last checkpoint, reads as unterminated
("unproven"), not as broken ([audit](/operations/audit#limits)). Both are covered
only by shipping the log off the host as it's written, so a copy outside
the host's reach has every line.

**Lost commits.** A database failover that loses acknowledged commits can
reuse version numbers, bring back a destroyed KEK or a revoked policy, or
lose a KEK for good. Both databases need synchronous replication and a
failover that promotes only a synchronous standby
([high availability](/operations/high-availability)). A restored keys-database
backup brings back its policies as they were: re-apply them from their
source of truth before serving.

**A compromised server's issuing key.** Whoever read the unsealed
server's memory has the active issuing key and can sign workload
certificates for any name under any issuer, until `ferritor identity rotate
--now` revokes it with every retired key (send every server SIGHUP after).
Only the rotation ends them: the thief picks each certificate's
`notBefore`, after any cutoff, so cutoffs don't help against a stolen key;
certificates longer-lived than ferritor issues (a day) are refused whatever
signed them. A keys-database writer can't undo the rotation: the issuing
keys are one set, MACed under the root key at a revision every change
raises, with the highest revision written kept in the data database
(`issuing_revision_floor`), so an older set put back (the stolen key
active again, from a backup) is a rollback, refused like a set that
doesn't verify; undoing it takes write access to both databases. For
certificates ferritor issued (not a stolen key), the cutoffs and removing an
issuer end them sooner too; none of them is covered by the CRLs, and they
expire within `lifetime_secs`.

**A stale CRL.** One past its `nextUpdate` is still used, so a stalled CRL
publisher can't lock everyone out; removing the CRL setting un-revokes
everything ([TLS](/guides/tls#revocation-crls)). Alert on the
`ferritor.tls.crl.next_update` gauge.

**An authenticated client using more than its share** is held to its
[rate limits](/operations/running#rate-limits): calls in flight (on by default),
requests per second (off by default), and an always-on budget of denied
requests, so a client probing or retrying what it may not do can't flood
the audit log either; all calls together wait under a server-wide cap
sized to the data pool. Operators' admin calls are never limited. The
limits are per server, so behind a load balancer an identity gets them
once per server, and the cap protects each server, not the shared
databases: size the pools and the caps for every server together.
[Watch streams](/guides/secrets#watching) aren't calls in flight once open,
so they have caps of their own: 256 per identity (`max_watch_streams`) and
4,096 per server for every identity together. It takes 16 identities at
their cap (or one whose cap was raised) to fill a server; then no one else
can watch (`WATCH_FULL`), and the agents and providers fall back to reading
on their intervals, at the cost the watch was saving.

**Denial of service** by anyone who controls a database, the network path
or the host: ferritor fails closed (`UNAVAILABLE`, `SEALED`), it doesn't fail
open.

**Side channels**: timing and cache attacks on the host, and traffic
analysis (who reads which path, how often) weren't analyzed.

## Known gaps

None of these is fixed yet.

1. **Swap without cgroup v2, and hibernation.** The kernel may write any
   page to swap, the root key's and the KEKs' included, where they outlive
   the process and a seal, and a stolen disk has them. The example unit's
   `MemorySwapMax=0` prevents it on cgroup v2, but not on hosts without it,
   and hibernation writes all of memory to disk whatever the cgroup says.
   ferritor doesn't lock its memory (`mlock`): its keys live in ordinary,
   scattered heap allocations, so locking them would take an allocator of
   its own for key material. The deployment covers the rest: no swap, or
   swap encrypted under a key that doesn't survive a reboot, and no
   hibernation ([production](/getting-started/production#6-run-it)).
2. **No integrity for a path's versions** against a data-database writer
   (above). Closing it would take a MAC over each path's version history
   under a root-wrapped key, as the stored policies have, checked on every
   read: a design change.
3. **Values outside `Zeroizing`.** Keys, shares and a decrypted value are
   wiped when dropped, but the messages that carry a value are not: a put's
   plaintext in the gRPC request and the JSON body (as base64), a read's in
   the response, and both in the TLS buffers. Those copies stay in freed
   heap until reused, which matters only to whoever can read the process's
   memory (root) or its swap (gap 1). The clients are no different: in the
   CLI, the encoded request (a put's value, an unseal's share) is in
   tonic's buffers, and a copy is kept for the call's one retry after a
   short rate limit, until the call ends; in the agent, its own copies of a
   value are wiped, but the decoded responses and the transport's buffers
   aren't.

## Checklist

What a deployment must get right for the above to hold
([production](/getting-started/production)):

- secured mode only: dev mode (plaintext, everyone may do everything) never
  outside a developer's machine;
- the client CA key off the host; only the issuing CA in `client_ca`; a CRL
  or short-lived client certificates;
- with `[identity]`: issuers whose tokens only the workloads they name can
  get, mappings from claims those workloads can't choose, their keys from a
  source only the issuer controls, and their identities granted no more
  than the workloads need;
- the audit signing key readable by the server's user only, and the audit
  log shipped off the host as it's written, then verified;
- config rules for operators only, applications' grants in stored policies
  applied from a reviewed source of truth (`--prune`); `policy`,
  `destroy_kek`, `purge` and `seal` granted narrowly;
- shares with different people, never on the server host; a rekey when one
  may be exposed;
- both databases with synchronous replication, backed up in the right
  order; a separate database role and password for each database, so one
  leaked URL isn't both;
- the host itself defended: the example unit's hardening
  (`MemorySwapMax=0` included), or no swap or encrypted swap where cgroup v2
  is missing, and no hibernation.
