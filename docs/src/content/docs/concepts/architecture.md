---
title: 'Architecture'
description: 'How ferritor is built: the crates, the key hierarchy, the two databases, the seal states, and how a request flows.'
seo:
  title: 'ferritor architecture: keys, databases, requests'
---

## Crates

| Crate | What it is |
|---|---|
| `ferritor-core` | Shared library: the generated gRPC bindings (`ferritor_core::proto::v1`), crypto (`crypto`: `RootKey`, `Kek`, `Dek`, AES-256-GCM with purpose-labelled AAD, Shamir shares via `vsss-rs`), canonical secret paths (`path::SecretPath`), the audit log's hash chain (`audit_chain`), and the machine-readable error reasons (`messages`). |
| `ferritor-keystore` | Owns the **keys** database (seal configuration, the KEK keyring, the workload-identity issuing keys): its migrations and every query against it. |
| `ferritor-datastore` | Owns the **data** database (ciphertexts, wrapped DEKs, the KEK floor, the change feed's query): its migrations and every query against it. |
| `ferritor-server` | The server: a library (so tests can drive it) and a thin binary. |
| `ferritor-client` | Talking to a server over gRPC, for every client ferritor ships: the channel with its TLS preflight, the rate-limit retry, the server's errors and reasons, the token exchange (`exchange`). |
| `ferritor-cli` | The `ferritor` CLI: operators and clients, over gRPC only, through `ferritor-client`. |
| `ferritor-agent` | Secrets as files: the agent next to an application ([agent](/guides/agent)), and the CSI provider, once per Kubernetes node ([CSI](/guides/csi)). |
| `ferritor-testkit` | Dev-only test helpers: a throwaway Postgres database per test, a test CA, a token issuer. |

The gRPC contract is `proto/ferritor/v1/ferritor.proto`: `SystemService` for the
seal lifecycle and key management (operators), `SecretsService` for secrets,
`PolicyService` for the stored policies, and `IdentityService` for the token
exchange, served on its own listener ([workload identity](/guides/workload-identity)).

## Key hierarchy

```
Shamir shares (default 5, threshold 3) --reconstruct--> root key   (memory only, never persisted)
root key  wraps  KEKs, per namespace                   -> keys DB  (keks table, versioned per namespace)
KEK       wraps  one DEK per secret version            -> data DB  (secret_versions.wrapped_dek)
DEK       encrypts the secret value                    -> data DB  (secret_versions.ciphertext)
```

- **Root key.** Generated at `init`, split into Shamir shares, and never
  stored. Unsealing reconstructs it in memory from a threshold of shares; a
  known plaintext encrypted under it (`seal_config.root_check`) proves the
  reconstruction is right before any KEK is touched.
- **Namespaces.** A path's first segment is its namespace, which must be
  created first (there's no default). Each has its own KEKs.
- **KEKs.** Versioned within their namespace; exactly one per namespace is
  *active* and wraps that namespace's new DEKs. Older ones are
  *decrypt-only* after a rotation, *retired* once no row uses them, and may
  finally be *destroyed* (see [key management](/operations/key-management)). A
  wrapped KEK is bound to its namespace and version.
- **DEKs.** One per secret version, generated for that put alone.
- **Next to the KEKs**, also wrapped by the root key in the keys database:
  the stored policies' MAC key, and the workload-identity issuing key (the
  active one only). The issuing keys as a set carry a MAC under the root
  key and a revision, held to a floor in the data database like the
  stored policies', so none is trusted that the root key didn't vouch for,
  and an older set isn't either.
- **AAD binds the path and version** into both ciphertexts (the value and the
  wrapped DEK), so rows can't be swapped between paths or versions. Because
  it binds the exact bytes, paths must be canonical: everything goes through
  `SecretPath`, which rejects (never normalizes) anything else, and the
  crypto API only accepts a `&SecretPath`.

## Two databases

The keys database holds wrapped KEKs; the data database holds ciphertexts
and wrapped DEKs. Compromising one alone yields wrapped keys, never usable
ones. They stay separate, and each is touched only by its own store crate.
`secrets.kek_version` points from one into the other, so the server
enforces it rather than a foreign key, and backups of the two must match
(see [backup and restore](/operations/backup-restore)).

Several servers can share the two databases: each follows the others'
rotations by refreshing its keyring, and a load balancer takes sealed ones
out of rotation (see [operations](/operations/running)).

## Seal states

The server starts **sealed**: nothing that needs a key works until the root
key is reconstructed. **Unsealed**, it holds the root key and every KEK in
memory (the keyring). **Seal** drops them at once; it's the emergency stop
and never fails once permitted.

Every seal bumps an epoch. Secret operations record the epoch when they
start and take the keyring only right before their crypto, refused if any
seal happened since (even if the server was unsealed again meanwhile), and
never hold a keyring across an await. Writes re-check right before
committing. So once a seal returns, no request uses the keys, and anything
in flight fails with `SEALED` and keeps nothing; the only window left is the
commit round trip itself.

## How a request flows

1. **Transport.** One port serves gRPC and the JSON API. In secured mode,
   TLS with a client certificate from the client CA; dev mode is plaintext
   and loopback only (see [TLS](/guides/tls), [configuration](/reference/configuration)).
2. **Identity.** The certificate's `ferritor://<name>` URI SAN is the caller,
   checked on every request, along with expiry and revocation.
3. **Path.** Parsed as a canonical `SecretPath`, or refused. Its first
   segment is its namespace.
4. **Admission.** At the first authorization, the [rate
   limits](/operations/running#rate-limits), per identity in this order: the
   denial budget, calls in flight, the rate; then a slot under the
   server-wide cap, waited for while the client stays. Refused with
   `RATE_LIMITED` (or `UNAVAILABLE` at the cap) before the policy is asked,
   so nothing is recorded per request. Admin calls the config rules allow
   pass freely.
5. **Authorization.** The [policy](/guides/policy) decides: the config rules,
   then for a secret action the stored policies (verified, in force only
   while unsealed). The decision is written to the [audit log](/operations/audit)
   before anything else happens (an allowed request whose entry can't be
   written is refused). A secret request only a stored policy could allow,
   while none is in force, is answered `SEALED` (or `POLICY_UNVERIFIED`),
   not denied.
6. **Seal check.** Refused with `SEALED` while sealed. Only now, after
   authorization, does the namespace matter: a write under one that doesn't
   exist is `NO_NAMESPACE`, an answer only an authorized caller gets.
7. **Data.** The data database, through `ferritor-datastore`; writes to one
   path take a per-path lock (see [secrets](/guides/secrets)).
8. **Outcome.** Every allowed call that changes something also records what
   it did in the audit log.

Admin calls (`SystemService`) ask the authorizer first of all, before
reading the seal epoch or waiting for the admin lock, so a refused caller
never waits behind admin work.

## Changes

A [watch stream](/guides/secrets#watching) learns of changes from the data
database, so it hears of every server's writes. Every `paths` row carries
`changed_xid`, the transaction that last moved its live version (a trigger
on `current_version`, migration 0004). Each server runs one change feed
(`watch::Watch`), which every 250 ms reads, in one snapshot, the snapshot
itself (`pg_current_snapshot()`) and the rows whose `changed_xid` the
previous snapshot didn't see. A transaction that commits late (it began
before the previous snapshot) is caught: it was in progress then, so
invisible to it. Each poll's snapshot is the mark for the next, a failed
poll is retried from the same mark, and so no change is lost or told twice
while the feed runs. The feed broadcasts each change to this server's
streams, which send only what their caller watches. Postgres
`NOTIFY` was the other way, and was measured out: it serializes every
committing transaction that notifies ([performance](/operations/performance)).

## Errors

Where the gRPC status code alone is ambiguous (`FAILED_PRECONDITION` can be
a sealed server, a check-and-set mismatch, an unloaded KEK, …), the server
attaches a `google.rpc.ErrorInfo` with domain `ferritor` and a reason from
`ferritor_core::messages::reason`:

| Reason | Meaning |
|---|---|
| `SEALED` | the server is sealed: unseal it, then retry |
| `UNAUDITED` | the decision couldn't be written to the audit log; nothing was done |
| `RATE_LIMITED` | refused by one of the caller's rate limits, named in the `ErrorInfo` metadata `limit` (`rate`, `in_flight`, `denied`), with a `RetryInfo`: nothing was done, retry then. HTTP 429 `rate_limited` with `Retry-After` |
| `BUSY` | too many concurrent writes to one path, or a KEK floor raise waited too long: retry as is |
| `VERSION_MISMATCH` | a check-and-set found another latest version: read again, then decide |
| `UNKNOWN_KEK` | the secret's KEK isn't loaded even after a refresh (a rekey elsewhere?) |
| `LIVE_VERSION` | a restore without a version while one is live |
| `NOT_RETIRED` | destroying a KEK version that isn't retired |
| `KEK_IN_USE` | destroying a KEK version rows still use |
| `KEYS_DATABASE_MISMATCH` | a rotate, init or namespace creation refused: the keys database doesn't match the data database |
| `NO_NAMESPACE` | the path's first segment isn't a namespace (or a rotate named none): create it first. HTTP 409 `no_namespace` |
| `NAMESPACE_NOT_EMPTY` | deleting a namespace that still has rows, deleted ones included: purge them first |
| `TOKEN_REFUSED` | the token exchange refused the token, or found no mapping for its claims; the message says why ([workload identity](/guides/workload-identity)) |
| `ROOT_UNCOMMITTED` | an unseal refused: no root commitment in the data database matches the root key the shares rebuild (a data database restored from before a rekey, a failover that lost the write, or a substituted keys database). `ferritor unseal --recommit` decides which ([key management](/operations/key-management#the-root-commitment)) |
| `ROOT_BELOW_FLOOR` | an unseal refused: the keys database's root key is a generation below the data database's floor (restored, or failed over, past a rekey); `ErrorInfo` metadata `generation` and `floor` |
| `WATCH_FULL` | a watch stream refused: the identity has as many open as it may (`max_watch_streams`; `ErrorInfo` metadata `limit: identity`), or the server serves as many as it can (4,096, `limit: server`). Not a rate limit: no retry time. Close a stream, watch through another server, or poll meanwhile |
| `POLICY_UNVERIFIED` | the stored policies don't verify (changed in the keys database, rolled back, their key cleared): a request only they would allow, a policy put or delete, or a rekey is refused; re-apply them with `ferritor policy apply --prune`. HTTP 503 `policy_unverified` |

Programs match on the reason, never the message. The JSON API's error
`code` is the same reason, lowercased. Internal errors are logged, never
sent.
