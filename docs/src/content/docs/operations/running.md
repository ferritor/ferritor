---
title: 'Operations'
description: 'Running ferritor day to day: health and readiness, signals and shutdown, metrics and alerts, rate limits, routine and recovery tasks.'
seo:
  title: 'Operating ferritor: health, metrics, limits, recovery'
---

## Health and readiness

The server serves the standard `grpc.health.v1` service, needing no
authorization and writing no audit entry:

| Service | Status |
|---|---|
| `""` (overall) | always SERVING while the process runs: for liveness checks and the CLI's preflight |
| `ferritor.v1.SecretsService` | SERVING only while **ready**: unsealed and not shutting down |

Point a load balancer's readiness check at `ferritor.v1.SecretsService`, so a
sealed or shutting-down server leaves the rotation. Use **Check**, not
Watch: a Watch stream stays open until the client hangs up, and would hold
every shutdown's drain open for its full limit (Kubernetes' gRPC probes and
Envoy use Check).

The token exchange's listener (`[identity] listen_addr`) serves no health
service: check the main listener; the exchange answers `SEALED` while the
server is.

For HTTP-only load balancers, `GET /v1/health` answers the same: 200
`{"ready": true, "sealed": false}`, else 503 (with `sealed` false, the
server is shutting down). In secured mode the TLS handshake still needs a
client certificate, so the checker needs one too.

## Signals and shutdown

| Signal | |
|---|---|
| SIGINT, SIGTERM (first) | not ready at once; after `shutdown_delay_secs` (default 0), drain: in-flight calls finish, no new connections, HTTP/2 clients get a GOAWAY, HTTP/1.1 keep-alives close |
| SIGINT, SIGTERM (second) | exit at once, after at most a second's wait for the audit log |
| SIGHUP | reload the policy, server certificate, CRLs, keyring and `[identity]` (see [configuration](/reference/configuration)) |

With auto-unseal, a SIGTERM sets no hold: the server unseals itself again
when it comes back, which is what a rolling restart wants. `ferritor seal` is
what keeps servers sealed (see [key management](/operations/key-management#the-hold-a-seal-that-stays-sealed)).

Watch streams end when the drain starts (`UNAVAILABLE`), so they don't
hold it open; their clients reconnect to another server. A signal during
startup, before serving, exits at once. The drain is
bounded at 15 s (a client stalled mid-request would otherwise hold it open
forever), then the audit log gets up to 5 s to write what's queued.

On **Kubernetes**, a pod's removal from the endpoints reaches the proxies
at about the same time as SIGTERM, so for a few seconds new connections
still arrive. Set `shutdown_delay_secs` to a few seconds: the server reports
not ready but keeps serving that long before draining. Startup warns if the
delay plus the drain and the audit drain could exceed the default 30 s
`terminationGracePeriodSeconds`.

## Metrics

The same instruments leave the server one of two ways, chosen by
`[metrics] exporter` ([configuration](/reference/configuration#metrics),
read at startup): pushed over OTLP, or scraped by Prometheus. One at a
time.

**OTLP** (`exporter = "otlp"`, or no `[metrics]` section): OpenTelemetry,
pushed over OTLP/gRPC to the collector `OTEL_EXPORTER_OTLP_ENDPOINT` (or
`OTEL_EXPORTER_OTLP_METRICS_ENDPOINT`) names. Without the section and
without that variable, metrics are off; `exporter = "otlp"` without it
refuses to start. The other standard variables apply too
(`OTEL_METRIC_EXPORT_INTERVAL`, default 60 s; `OTEL_RESOURCE_ATTRIBUTES`;
`OTEL_SERVICE_NAME`, default `ferritor-server`). `https://` (or no scheme,
unless `OTEL_EXPORTER_OTLP_INSECURE=true`) is TLS with the public roots,
plus `OTEL_EXPORTER_OTLP_CERTIFICATE` for a private CA and
`OTEL_EXPORTER_OTLP_CLIENT_CERTIFICATE`/`_CLIENT_KEY` for mTLS; `http://`
is plaintext, for a local agent.

**Prometheus** (`exporter = "prometheus"`): `GET /metrics` in the text
format, on a listener of its own (`listen_addr`, default `127.0.0.1:9464`),
never the main one: a scraper needs no client certificate, and a scrape
is no request (no audit entry, no rate limit, not counted in
`ferritor.in_flight`). It answers while sealed too. On a loopback
address it's plaintext, answering only requests addressed to loopback (as
dev mode does, against DNS rebinding); anywhere else it's TLS with the
server's certificate (secured mode; renewed with it on SIGHUP), and with
`client_ca` a scraper must present a certificate from that CA. Plaintext
off loopback only with `tls = false`, which warns at startup. The `OTEL_*`
variables are ignored then (a set endpoint warns).

```sh
curl -s http://127.0.0.1:9464/metrics | grep ferritor_sealed
```

Names follow OpenTelemetry's Prometheus conventions: dots become
underscores, a unit adds its suffix (`_seconds`), a counter ends in
`_total`, and a histogram is its `_bucket`, `_sum` and `_count` series.
The table gives both names; a test holds it to what a scrape returns.
Request durations are bucketed from 1 ms to 10 s, the wait for a slot
from 0 to 10 s.

| Instrument | Prometheus | Kind | Attributes |
|---|---|---|---|
| `ferritor.secret.requests` | `ferritor_secret_requests_total` | counter | `operation`, `result` |
| `ferritor.secret.request.duration` | `ferritor_secret_request_duration_seconds` | histogram (s) | `operation`, `result` |
| `ferritor.admin.outcomes` | `ferritor_admin_outcomes_total` | counter | `operation`, `result` (succeeded, failed, unknown) |
| `ferritor.authorization.decisions` | `ferritor_authorization_decisions_total` | counter | `action`, `decision` (allowed, denied, sealed, unverified) |
| `ferritor.audit.failures` | `ferritor_audit_failures_total` | counter | `kind` (refused, lost) |
| `ferritor.versions.trimmed` | `ferritor_versions_trimmed_total` | counter | |
| `ferritor.versions.purged` | `ferritor_versions_purged_total` | counter | |
| `ferritor.deks.rewrapped` | `ferritor_deks_rewrapped_total` | counter | |
| `ferritor.tls.handshake.failures` | `ferritor_tls_handshake_failures_total` | counter | `listener` (api, exchange, metrics: a scraper without the right certificate counts here, not as an API client), `reason` (failed, timed_out) |
| `ferritor.rate_limit.refused` | `ferritor_rate_limit_refused_total` | counter | `limit` (rate, in_flight, denied, unauthenticated; exchanges: a token exchange refused, too many for its identity; exchange_refused: a refused exchange's audit entry left out; server: no slot under the server-wide cap in time) |
| `ferritor.identity.exchanges` | `ferritor_identity_exchanges_total` | counter | `issuer` (a configured issuer's name, or unknown), `result` (issued, refused, unavailable, rate_limited) |
| `ferritor.rate_limit.waited` | `ferritor_rate_limit_waited_seconds` | histogram (s) | the wait for a slot under the server-wide cap |
| `ferritor.reloads` | `ferritor_reloads_total` | counter | `kind` (policy, certificate, crl, keyring, policy_store, identity), `result` (policy_store: changed, unchanged, failed, integrity, rollback, recovered; counted on every attempt, while a failure is logged and audited only when it starts, changes or ends) |
| `ferritor.policy.revision` | `ferritor_policy_revision` | gauge | the stored policies' verified revision in force; absent unless one is |
| `ferritor.policies` | `ferritor_policies` | gauge | stored policies in force; absent unless verified |
| `ferritor.audit.queue.depth` | `ferritor_audit_queue_depth` | gauge | entries waiting for the writer |
| `ferritor.in_flight` | `ferritor_in_flight` | gauge | calls in flight, every one (exempt admin calls too, which the server-wide cap doesn't count) |
| `ferritor.sealed` | `ferritor_sealed` | gauge | 1 sealed, 0 unsealed |
| `ferritor.namespaces` | `ferritor_namespaces` | gauge | namespaces this server holds KEKs of; absent while sealed (a count, never names) |
| `ferritor.seal.auto_unseal` | `ferritor_seal_auto_unseal_total` | counter | `result`: ok, kms_unavailable, denied, mismatch, root_commitment, below_floor, no_wrap, held, failed (see [key management](/operations/key-management#auto-unseal)) |
| `ferritor.seal.hold_pending` | `ferritor_seal_hold_pending` | gauge | auto-unseal hold (or release) writes being retried after a seal; 0 normally |
| `ferritor.seal.floor_pending` | `ferritor_seal_floor_pending` | gauge | root-generation floor raises being retried after an init or a rekey; 0 normally (see [key management](/operations/key-management#the-root-commitment)) |
| `ferritor.kek.vanished` | `ferritor_kek_vanished` | gauge | KEKs held for reading only because the keys database lost them; 0 normally (see [high availability](/operations/high-availability)) |
| `ferritor.server_certificate.expiry` | `ferritor_server_certificate_expiry_seconds` | gauge (unix s) | secured mode |
| `ferritor.tls.crl.next_update` | `ferritor_tls_crl_next_update_seconds` | gauge (unix s) | the earliest `nextUpdate` of the CRLs in force |
| `ferritor.watch.streams` | `ferritor_watch_streams` | gauge | [watch streams](/guides/secrets#watching) open (at most 4,096 per server) |
| `ferritor.watch.feed.live` | `ferritor_watch_feed_live` | gauge | 1 while the change feed polls the data database, 0 while it can't |
| `ferritor.watch.feed.held_back` | `ferritor_watch_feed_held_back_seconds` | gauge (s) | how long one open transaction has held the change feed back (below); 0 normally |
| `ferritor.watch.resyncs` | `ferritor_watch_resyncs_total` | counter | `reason` (too_many, restarted: every stream told at once; lagged: one stream fell behind) |

Attributes are small fixed sets: never secret paths, identities or values.
Worth alerting on: `ferritor.seal.hold_pending` above 0 (a sealed server a
restart could unseal again), `ferritor.seal.auto_unseal` with any result but
`ok` and `held` (a server that can't unseal itself; `root_commitment` and
`below_floor` need a person), `ferritor.kek.vanished` above 0 (urgent: see [high
availability](/operations/high-availability)), `ferritor.sealed`, `ferritor.audit.queue.depth` rising (stdout
stalling, before requests are refused), `ferritor.audit.failures`, the two
expiry gauges, `ferritor.policy.revision` differing between servers for longer
than `policy_refresh_secs` (a rollback of the stored policies: one server
still has the newer set), and `ferritor.reloads` with `kind = policy_store` and
`result` `integrity` or `rollback` (the stored policies don't verify: see
[policy](/guides/policy), then re-apply them from their source of truth with
`ferritor policy apply --prune` and find out who changed the keys database).
`ferritor.watch.feed.live` at 0 for more than a few seconds (the data
database unreachable for the feed: no new watch streams, and the agents
and providers fall back to their intervals), and `ferritor.watch.streams`
near 4,096 (new streams refused with `WATCH_FULL`; an identity's own cap,
256 by default, is `max_watch_streams` in [configuration](/reference/configuration)),
and `ferritor.watch.feed.held_back` above a few minutes. For the rate limits,
see below.

**A transaction left open slows the change feed.** Each server's feed
asks the data database, four times a second, for the changes since the
oldest transaction still running at its last poll: that one may yet
commit a change. Transaction ids are the Postgres server's, not one
database's, so a transaction open in any database there counts. ferritor's
own are short, but a `psql` session left inside `BEGIN` after a write, or
a long migration, holds the feed's starting point back, and every poll on
every server reads every change since that transaction began, more with
each write, until it ends. `ferritor.watch.feed.held_back` says how long,
and past 5 minutes each server logs a warning naming its transaction id;
find it in `pg_stat_activity` by `backend_xid` and end it (only a
transaction that has written something counts: a read-only one has no
id). `idle_in_transaction_session_timeout` on the database ends idle ones
for you.

**The process is closed to its own user.** The server marks itself
undumpable at startup (see [security](/concepts/security)), so `/proc/<pid>/`
belongs to root: a monitoring agent that reads it as an unprivileged user
(a process exporter, some APM agents) gets nothing for ferritor, and neither
do debuggers and profilers. Use the metrics above, or run such an agent as
root. There are no core dumps either: a crash leaves its panic message and
backtrace on stderr, in the journal.

## Rate limits

Settings in [configuration](/reference/configuration); what's limited, per server:

| Limit | Default | Over it |
|---|---|---|
| calls in flight per identity | a quarter of the server-wide cap | refused: `RESOURCE_EXHAUSTED`, reason `RATE_LIMITED`, `limit: in_flight`, retry in 1 s (429 over the JSON API, `Retry-After: 1`) |
| requests per second per identity | off | refused likewise, `limit: rate`, with the time the next request would pass |
| denied requests per identity | 10 a second, a burst of 50, always | refused likewise, `limit: denied`: all of the identity's requests, allowed ones too, until the budget refills |
| calls in flight, server-wide | `2 × data_database_max_connections + 16` | waits for a slot, up to `database_timeout_ms`, then `UNAVAILABLE` (503) |

A request is admitted at its first authorization, in that order: the
denial budget, the identity's calls in flight, its rate, then the
server-wide slot; it holds its slots until it ends. Admin calls the config
rules allow are never limited (an operator can always seal, rekey or
apply policies, however busy the server); everything else is: every
secret call, and any call the config rules don't allow. A refused request was refused
before anything ran, so retrying it is always safe; the CLI waits out a
retry time of up to 3 s once by itself.

**Sizing.** Calls in flight are rate × latency: an identity doing 500
puts a second at 2 ms each holds about one at a time, so the default
(9 with the default pool) refuses only a client running many slow calls at
once, which is what it's for. A batch job that runs many in parallel, or a
load test, gets an entry of its own (`[[rate_limit.identity]]`). The
server-wide cap is about the data pool: well above it, calls only wait
for a connection inside the server instead; well below it, the pool sits
idle. Every server counts on its own, so behind a load balancer spreading
calls over N servers an identity gets N times its limits; size them per
server.

**What to watch.** `ferritor.rate_limit.refused` by `limit`, and each
episode in the audit log (`rate_limited`, below): who and which limit.

- `limit: denied` usually means a missing grant, not an attack: an
  application retrying a read its policies lack, whose allowed reads are
  then refused too. Check its policies (`ferritor policy list`, and the
  `denied` decisions in the audit log) before anything else.
- `limit: in_flight` or `rate`: one application's load, or a loop; raise
  its own limits if the load is legitimate.
- `limit: server`, or `ferritor.rate_limit.waited` climbing towards
  `database_timeout_ms`: the server as a whole is full. Add servers, or
  look at the database (`ferritor.secret.request.duration`).
- `limit: unauthenticated`: a client with a certificate naming no caller
  (no valid `ferritor://` identity) retrying in a loop.

The audit log has one `rate_limited` entry when an identity (or such a
certificate) starts being refused by a limit, and another once it has been
quiet for 10 s, with the number refused in between; a refused request has
no entry of its own (see [audit](/operations/audit)).

## Routine tasks

```sh
ferritor purge                 # remove deleted versions past their retention (and labels of paths left empty); cron or a timer
ferritor rotate --namespace <ns>                # a new KEK version for one namespace
ferritor rewrap                                 # move DEKs to it, retire old versions (after every server has refreshed)
ferritor destroy-kek --namespace <ns> <version> # once `ferritor namespace get <ns>` shows it retired
ferritor identity rotate                        # a new workload-identity issuing key (yearly, say; the CA lives 5 years)
```

- `purge` and `rewrap` are bounded passes: the CLI repeats them until done,
  and they're safe to rerun, interrupt or run concurrently.
- `rotate` is a single call, and **not** idempotent: each run adds another
  KEK version. If its outcome is unclear, check `ferritor namespace get <ns>`
  before running it again.
- `destroy-kek` is a single call, safe to repeat (an already destroyed
  version says so).
- `identity rotate` isn't idempotent either: check `ferritor identity status`
  before repeating one whose outcome is unclear. Rotate before the CA's
  expiry (`ferritor identity status` shows it); the old key's certificates stay
  trusted for a day. `--now` is for a compromise ([workload
  identity](/guides/workload-identity#revoking)).
- Other servers pick up a rotation at their next keyring refresh (within
  `keyring_refresh_secs`, default 60); until then they keep wrapping new
  DEKs with the old KEK. A rewrap run before that misses their rows, so
  run it again later (or wait a refresh interval first).

All of them need the server unsealed. A seal stops purge and rewrap between
batches; a rotation already under way is still stored, and the next unseal
loads it.

## Recovering from a lost init

If `ferritor init`'s reply never arrived (a timeout, a dropped connection), the
init may be stored with nobody holding its shares. `ferritor status` then says
initialized. Nothing secret exists yet, so starting over is safe, **unless
the init is someone else's**.

Find the init outcome in the audit log and tell whose it is by **identity
and time**, not by result (a client-side timeout leaves the server's own
outcome `succeeded`). From your identity at the time of your call, succeeded
or unknown: it's yours, so empty the keys database and run init again. From
another caller: they hold valid shares, so change nothing. Dev mode logs
every caller as null, so there only the time tells them apart.

```sh
docker compose exec -T keys-db psql -U ferritor -d ferritor_keys \
  -c 'TRUNCATE seal_config, keks, namespaces, policies' \
  -c 'UPDATE policy_state SET revision = 0, mac = NULL'
```

That starts the stored policies' revision at 0 again (their key went with
`seal_config`). A server that wasn't restarted remembers a higher revision
and raises the rollback alarm until it is: harmless here, since no policies
exist yet, but restart it. The data database's policy revision floor is
still 0 after a lost first init; if it isn't (policies were written under
an earlier one), every server refuses revision 0 as a rollback, and the
first policy write must be `ferritor policy apply --prune`.

## Fixing the policy revision floor

The data database's `policy_revision_floor` holds the highest stored-policy
revision any server wrote, and every server refuses a stored set below it
(see [policy](/guides/policy#integrity)). Written by someone with access to the
data database, it can block the stored policies everywhere: set past the
stored revision, every server refuses the set (`policy_reload` with result
`rollback`, `POLICY_UNVERIFIED`), and near BIGINT's maximum even the repair
fails, its revision not fitting; with its row deleted, every load is
unreadable and policy writes are refused.

1. Check that the stored set is the one you want: compare it with its
   source of truth, and read its revision in the keys database:
   `SELECT revision FROM policy_state`.
2. Set the floor to that revision, in the data database:

   ```sql
   INSERT INTO policy_revision_floor (revision) VALUES (<the stored revision>)
     ON CONFLICT (singleton) DO UPDATE SET revision = EXCLUDED.revision;
   ```

3. Restart every server: a running one remembers the highest revision it
   read, the wrong floor's too, and only a restart forgets it.
4. Find out who changed the data database. Lowering the floor is what a
   rollback of the stored policies needs, so do it only after step 1.

## Several servers and failover

See [high availability](/operations/high-availability): running several servers,
and why both databases need synchronous replication.
