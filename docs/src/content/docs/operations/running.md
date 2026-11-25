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
| SIGHUP | reopen the audit log's file (rotation), reload the policy, server certificate, CRLs, keyring and `[identity]` (see [configuration](/reference/configuration)) |

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

Metrics, the server's and the agents' and providers', what to alert on,
and the Grafana dashboards are on their own page:
[monitoring](/operations/monitoring).

## A transaction left open

A transaction left open slows the change feed. Each server's feed
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

## Scheduled tasks

The servers run two tasks on their own, so nothing needs scheduling outside
ferritor (no cron, no timer):

| Task | Default interval | What it does |
|---|---|---|
| purge | daily (`purge_interval_minutes = 1440`) | removes deleted versions past `purge_deleted_after_days`, and the labels of paths left with nothing stored |
| rewrap | hourly (`rewrap_interval_minutes = 60`) | moves DEKs to each namespace's active KEK and retires the KEK versions no row uses any more |

**One schedule for every server.** It's kept in the data database: each
server looks every 30 s or so, and the first to find a task due claims it,
in one statement that moves it an interval on, so it runs once per interval
however many servers there are. A run holds a lease (5 minutes, extended
while it works), so no other server starts the same task beside it; a
server that dies mid-run leaves a lease that runs out, and the task is due
again as its claim set it. Every time is the database's clock. Both tasks
are safe to run twice or concurrently anyway (as `ferritor purge` and
`ferritor rewrap` always were), so nothing depends on the claim but the
work it saves.

- **A missed run is caught up once**: with every server down for a week, the
  first to come back runs each task once, not once per missed interval.
  Tasks due together (after an outage) drift apart by a random part of up
  to a tenth of their interval (at most 10 minutes).
- **Only unsealed servers run them**: a sealed server claims nothing, and a
  seal ends a run at its next batch, so sealing stops deleting too. A sealed
  deployment purges nothing until it's unsealed, then catches up.
- **A failed or cut-short run** (an error, a seal, a pause, a shutdown) is
  due again after a minute, doubling with each one in a row, up to the
  interval.
- **Pausing**, for every server at once: `ferritor schedule pause purge`
  (the `schedule` action) stops every purge, scheduled or by hand: none is
  claimed, `ferritor purge` is refused (`TASK_PAUSED`), and one under way
  ends at its next batch. The same for rewrap. `ferritor schedule resume
  purge` lets them run again. For an incident: deleted versions are the
  only way to restore, so stop the purge first. Pausing purge returns only
  once no purge batch is in flight (each one reads the pause in its own
  transaction), so from then on nothing deletes, by hand or on the
  schedule, a stalled server included: restoring is safe as soon as it
  returns. The schedule (next due, last run, how it ended, paused,
  running) is in `ferritor status`.
- **Audited** like a request, as `ferritor:scheduler` where a caller would
  be (no identity can be that name): a run's `scheduled` entry is written
  before its first batch, or it doesn't run (and is retried); its outcome
  when it ends ([audit](/operations/audit)).
- **Watch** `ferritor.schedule.last_success` ([monitoring](/operations/monitoring#the-server)):
  every server reports the same time, from the database.

## Routine tasks

```sh
ferritor rotate --namespace <ns>                # a new KEK version for one namespace
ferritor rewrap                                 # move DEKs to it now (the servers do it hourly)
ferritor destroy-kek --namespace <ns> <version> # once `ferritor namespace get <ns>` shows it retired
ferritor identity rotate                        # a new workload-identity issuing key (yearly, say; the CA lives 5 years)
ferritor purge                                  # purge now (the servers do it daily)
```

- `purge` and `rewrap` by hand are bounded passes: the CLI repeats them
  until done, and they're safe to rerun, interrupt or run beside the
  scheduled ones.
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
  DEKs with the old KEK. A rewrap, scheduled or by hand, refreshes its own
  server's keyring first; rows other servers write with the old KEK until they
  refresh wait for a later run (not while rewrap is paused or every server
  is sealed; and a row whose DEK doesn't unwrap stays where it is, its run
  failing).

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
