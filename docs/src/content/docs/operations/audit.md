---
title: 'Audit log'
description: 'What ferritor records, the hash chain and its signatures, failing closed, and verifying a log with ferritor audit verify.'
seo:
  title: 'The ferritor audit log: hash chain, signatures, verify'
---

The server writes its audit log, one JSON line per entry, to **a file of
its own** (`audit_file`), to **an OpenTelemetry collector** (`[audit_otlp]`),
or to both; secured mode needs at least one. Its own logs go to stderr.
Ship the log off the host as it's written: see [Limits](#limits). In dev
mode without either, the audit log goes to stdout, and nothing else does
(`ferritor-server > audit.log`).

## The file

```toml
audit_file = "/var/log/ferritor/audit.log"
```

The server appends to it, creating it `0600` if it doesn't exist (startup
warns if an existing one is readable by group or others: it names every
caller, path and decision). It refuses to start if it can't open it, and
refuses requests while it can't write to it ([it fails
closed](#fails-closed)). Keep the disk it's on big enough: the log grows
with every request, and a full disk refuses them all.

**Rotating.** On SIGHUP the server ends the current chain with a signed
`chain_end`, closes the file, opens the path again (creating it) and starts
a new chain there. So rename the file, then send SIGHUP: each file holds
whole chains and verifies on its own. With logrotate:

```
/var/log/ferritor/audit.log {
    daily
    rotate 90
    missingok
    notifempty
    nocreate
    compress
    delaycompress
    postrotate
        systemctl reload ferritor
    endscript
}
```

`nocreate`: the server creates the new file itself. `delaycompress`: the
reopen happens shortly after the signal, and the old file's `chain_end` is
written to it then, so compressing it at once could cut it off.
`systemctl reload` returns once the signal is sent, not once the file is
reopened: the server logs `reopened the audit log file` when it has (and
counts `ferritor_reloads_total{kind="audit_log"}`). If its queue is full
(the file stalled) the reopen isn't queued: it logs `AUDIT LOG NOT
REOPENED` and keeps writing to the renamed file, so send SIGHUP again once
it has caught up. Never
`copytruncate`: lines written between the copy and the truncate are lost.
SIGHUP also reloads the policy, the certificate, the CRLs and the keyring
([operations](/operations/running)), which is harmless when nothing
changed.

If the path can't be opened at a reopen (its directory removed, the
permissions changed), nothing more goes to the old file: requests are
refused until it can be opened, tried again at every entry, and the server
logs `AUDIT LOG NOT REOPENED`.

**Rotating by size**, where nothing else rotates the file (a pod, a host
without logrotate):

```toml
audit_file_max_bytes = 104857600   # 100 MiB
audit_file_keep = 5                # audit.log.1 … audit.log.5
```

Once the file holds `audit_file_max_bytes`, the server ends its chain,
renames it `audit.log.1` (the older ones moving up, `audit.log.5` dropped)
and starts a new file with a new chain. So the log never takes much more
than `(audit_file_keep + 1) × audit_file_max_bytes` of disk, and each file
verifies on its own. A rename that fails (say, the directory's
permissions) keeps writing to the file as it is, logs `AUDIT LOG FILE NOT
ROTATED`, and tries again once it has grown as much again: refusing every
request for want of a rename would be worse. Ship the files before the
oldest is dropped.

## Over OTLP

```toml
[audit_otlp]
endpoint = "https://otel-collector.internal:4317"   # OTLP over gRPC
ca = "/etc/ferritor/collector-ca.pem"               # optional: a private CA
cert = "/etc/ferritor/audit-client.pem"             # optional: mTLS, with key
key = "/etc/ferritor/audit-client-key.pem"
```

Every line becomes one OTLP log record: its body the line exactly as
written (without the newline), the instrumentation scope `ferritor.audit`,
the resource `service.name = ferritor-server` and a `service.instance.id`
of its own per server process. An entry counts as recorded only once the
collector has acknowledged it (and, with `audit_file` too, once it's in the
file): a collector that's down, refuses the export or takes longer than the
audit timeout refuses the requests waiting on it ([it fails
closed](#fails-closed)), and the server logs `AUDIT LOG NOT DELIVERED`.

Acknowledged means the collector has taken the batch into its pipeline,
not that it's stored: with the collector's default sending queue it's in
the collector's memory. It's stored only once the collector writes it out,
so give the collector a persistent queue (the `file_storage` extension on
its exporter's `sending_queue`) if an acknowledged entry must survive the
collector restarting, and run it off the server's node: a collector on the
same node goes when the node does. The persistent queue must be the first
thing to hold a record: an asynchronous `batch` processor ahead of it
acknowledges the batch while it's still in that processor's memory, so put
none in the audit records' pipeline (batch in the exporter's sending queue
instead, after the persistent store). It connects when first used, so a collector that isn't up yet doesn't stop the
server starting. The writer sends what's queued in one export, so a busy
server costs one round trip per batch, not per request. `https://`, or
`http://` on loopback only: the log names every caller and path.

After a refused export the next line starts a new chain, so what the
collector missed shows as an unterminated chain, never a seam, as long as
some of that chain reached it. A chain lost whole (its start and
everything after it refused, at startup say) leaves no trace in the
collector, and the chains after it still verify: detecting every loss
takes more than the collector's records, such as `audit_file` next to
them, or the server's `AUDIT LOG NOT DELIVERED` and
`ferritor_audit_failures_total`.

The verifier needs each chain's lines in order. Each record carries
`ferritor.audit.chain` (its chain's id, as the chain's `chain_start` has
it) and `ferritor.audit.seq` (its line's `seq`), so records from a backend
that returns them by time (whose timestamps follow the wall clock, which
can step back) sort back into place within their chain: group by chain,
order by `seq`. That's all verifying needs, since each chain verifies on
its own. The order of the chains among themselves can't be recovered
reliably once the clock has stepped back: the time of a chain's first
record is a hint, not a proof. The collector's file exporter writes them as they arrived,
already in order. To verify one server's records from it (OTLP JSON):

```sh
jq -r --arg id "$INSTANCE" '.resourceLogs[]
  | select(any(.resource.attributes[]; .key == "service.instance.id" and .value.stringValue == $id))
  | .scopeLogs[] | select(.scope.name == "ferritor.audit") | .logRecords[].body.stringValue' \
  otlp.jsonl | ferritor audit verify --public-key audit.pub.pem
```

Route records by the `ferritor.audit` scope to storage of their own:
whoever can read them sees who asked for what, and the collector's other
pipelines (metrics, application logs) needn't keep them.

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

A dedicated thread does the writing, so a stalled file (or stdout) stalls
neither the request workers nor a seal. Written means handed to the file
system: a host crash can still lose the last entries the disk hadn't
stored. At shutdown the server waits briefly for it to
write what's queued, and logs loudly if it can't.

## Tamper evidence

Every line is linked into a **hash chain**: it ends with `seq` and `prev`,
the SHA-256 of the previous line as written. Each server start, and each
reopen of the file, begins a new chain (`chain_start`: a random chain id,
the signing key's fingerprint).

With `audit_signing_key` (Ed25519, required in secured mode), the server
also writes **signed checkpoints**: after every 256 entries and at least
every 10 s while entries arrive, and a signed `chain_end` at shutdown and
before each reopen.
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
Rotated files verify one by one, or together in order (`zcat -f
audit.log.3.gz audit.log.2.gz audit.log.1 audit.log | ferritor audit verify
…`).
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
- In dev mode, if fd 1 is closed when the server starts, Rust reopens it
  as `/dev/null`, the same as `>/dev/null`, which nothing can detect.
