---
title: 'Audit log'
description: 'What ferritor records, the hash chain and its signatures, failing closed, and verifying a log with ferritor audit verify.'
seo:
  title: 'The ferritor audit log: hash chain, signatures, verify'
---

The server writes its audit log to **stdout**, one JSON line per entry, and
nothing else goes there (its own logs go to stderr). Ship it off the host as
it's written: see [Limits](#limits).

## What's recorded

- **Every authorization decision**: time, caller, action, target, `allowed`
  or `denied`, or (a secret request only a stored policy could allow, while
  none is in force) `sealed` or `unverified`. Written where the policy is
  asked, so asking always records.
- **What every allowed change did** (`"event": "outcome"`), once done: every
  admin call but `status`, and every secret write from either API. The
  operation, then `succeeded` with details (versions stored or trimmed,
  generations, phases, counts), `failed`, or `unknown` when it may have taken
  effect anyway (a write the database didn't confirm in time, a rewrap cut
  short). A failed call that still changed something says so in its details.
  A label change (`"label"`, or `labels_set` on a put) lists the keys set
  and removed, never their values. A call runs to its end, and records its
  outcome, even if its client disconnects or times out first.
- **Failed authentication** (`"event": "authentication"`): a certificate that
  passed the handshake but names no caller now (expired, revoked, no valid
  identity), with peer, action and reason.
- **Token exchanges** (`"event": "exchange"`, [workload
  identity](/guides/workload-identity)): every certificate issued (`"outcome":
  "issued"`: peer, issuer, identity, the claims the mapping read, serial,
  `not_after`), written before the certificate is returned, so one that
  can't be recorded isn't issued; and every refusal (`"outcome":
  "refused"`: peer, the issuer if known, the reason), queued. Never the
  token. Refusals from one peer address past 1 a second (a burst of 5) are
  an episode instead (`limit: exchange_refused`, keyed by `peer`), and
  exchanges for one identity past 1 a second (a burst of 10) are refused
  and an episode (`limit: exchanges`, the identity as `caller`).
- **Rate-limit episodes** (`"event": "rate_limited"`), not each refused
  request: `state: "started"` when a caller (or, `limit: unauthenticated`,
  a certificate naming no caller, by `certificate` fingerprint) starts
  being refused by a limit (`limit`: `rate`, `in_flight`, `denied`,
  `unauthenticated`, `exchanges`, `exchange_refused`), and `state: "ended"` once that limit has refused it
  nothing for 10 s, with `refused`, the number refused in between. At most
  two entries per caller and limit per quiet period, however hard it
  pushes. A rate-limited request is refused before the policy is asked, so
  it leaves no decision entry; a request over the server-wide cap that
  times out waiting is no episode either (metrics only:
  `ferritor.rate_limit.refused`, see [operations](/operations/running#rate-limits)).
- **Lifecycle**: the policy, server certificate and CRLs in force, by
  fingerprint, at startup and on every reload attempt (`policy_reload` with
  `source`: `config`, `database` with the stored set's revision and
  fingerprint, or `seal`; a stored set that doesn't verify is a
  `policy_reload` with result `integrity` or `rollback`); every `[identity]`
  reload (`identity_reload`: the issuers and cutoffs now in force, or why
  not); keyring refreshes
  that changed something or failed; KEK versions rows use that the keyring
  lacks (`kek_check`, after an unseal); auto-unseal (`auto_unseal`: every
  unseal through KMS, with the key's ARN, and a failure when it starts or
  changes, never every retry). An unseal's outcome says when it
  re-committed the root key (`"recommitted": true`, an alarm) or released
  the auto-unseal hold (`hold_released`), a seal's whether the hold landed
  in both databases (`hold_set`).

Never values, shares or nonces.

Not recorded: failed TLS handshakes (refused before any request exists),
requests refused for malformed input before the policy is asked (an invalid
path or page token), and the health checks. A
[watch stream](/guides/secrets#watching)'s opening is recorded (a decision
per path and prefix), but the stream's checks after it (before each change
it sends, and every 30 s) are recorded only when one fails, as a `denied`
decision that ends the stream: recording each would add a line per change
per stream.

## Fails closed

An allowed request whose entry isn't written and flushed within 2 s is
**refused** (`UNAVAILABLE`, reason `UNAUDITED`), before it touches any data.
Seal is the exception, as the emergency stop: its entry is queued without
waiting. Outcomes are queued too, since nothing can be refused by then, and
so are the rate-limit episodes, so a flood never waits on the audit
timeout (a refused request touches no data, so nothing unaudited happens).

A dedicated thread does the writing, so a stalled stdout stalls neither the
request workers nor a seal. At shutdown the server waits briefly for it to
write what's queued, and logs loudly if it can't.

## Tamper evidence

Every line is linked into a **hash chain**: it ends with `seq` and `prev`,
the SHA-256 of the previous line as written. Each server start begins a new
chain (`chain_start`: a random chain id, the signing key's fingerprint).

With `audit_signing_key` (Ed25519, required in secured mode), the server
also writes **signed checkpoints**: after every 256 entries and at least
every 10 s while entries arrive, and a signed `chain_end` at shutdown.
Without it (dev mode), the log is chained but unsigned, so edits can't be
proven.

```sh
openssl genpkey -algorithm ed25519 -out audit-key.pem && chmod 600 audit-key.pem
openssl pkey -in audit-key.pem -pubout -out audit.pub.pem   # for verifiers
```

Keep the private key readable by the server's user only (startup warns
otherwise): whoever can read it can sign forged checkpoints.

## Verifying

```sh
ferritor audit verify --public-key audit.pub.pem < audit.log
```

Offline: no server involved. For a log spanning a key change, repeat
`--public-key`; each chain is checked with the key its `chain_start` names.
Each chain is reported as:

| State | Meaning |
|---|---|
| complete | ends in a valid signed `chain_end`: every entry proven |
| open | the file's last chain, not ended: a running or crashed server |
| unterminated | any other chain without an end: a crash, a failed write, a cut, an append |
| unverifiable | unsigned, or signed with a key not given |
| broken | a link or a signature doesn't check out |

Exit status: **0** if every entry is covered by a signature, **2** if
something is unproven but nothing broken, **1** if broken. Scripts read the
status, not stderr.

## Limits

- `chain_start` isn't signed and the key fingerprint is public, so anyone
  who can write the file can append a forged run. That's why only a chain
  ending in a valid `chain_end` counts as proven.
- A genuine writer never leaves more than 256 lines unsigned, so a longer
  run counts as appended.
- The verifier can't notice a whole chain (one server run) removed from a
  file holding several. Ship the log off the host as it's written.
- Lines are capped at 1 MiB; a longer one is damage.
- A write that fails ends its chain: the writer finishes any partial line
  with a newline and starts a new chain, and the verifier tolerates a
  damaged line only as a chain's last. A failure costs one unterminated
  chain, not the rest of the run. After a `chain_end` the chain is over:
  damage there (a later run's `chain_start` that failed mid-write, or
  anything appended) is outside any chain, so the log is unproven, never
  proven, and an entry there breaks the chain.
- If fd 1 is closed when the server starts, Rust reopens it as `/dev/null`,
  the same as `>/dev/null`, which nothing can detect.
