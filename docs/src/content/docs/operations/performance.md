---
title: 'Performance'
description: 'Load test results, where a request''s time goes, the change feed''s cost, and sizing the pools and limits.'
seo:
  title: 'ferritor performance: load tests and sizing'
---

What one server does under load, where the limits are, and what to size.
Measured with the load tests in a `--release` server with TLS, client
certificates, a stored policy and the signed audit log on, as in production.

## Setup

- One desktop machine with a local NVMe SSD.
- Both databases: `postgres:18` from `compose.yaml`, in Podman on the same
  host, untuned (defaults: `synchronous_commit = on`, `shared_buffers =
  128MB`, `max_connections = 100`). The load generator (`oha`), the server
  and Postgres share the machine.
- Server defaults (`max_versions = 10`), but `data_database_max_connections
  = 32`. Values of 100 bytes, over the JSON API (HTTP/1.1, keep-alive).
- 30 s per scenario, in `bench/scenarios.sh`'s order, on fresh databases.

## Results

Over the JSON API (`oha`, one HTTP/1.1 connection per client):

| Scenario | 10 connections | 50 connections |
|---|---|---|
| `get_100`: reads | 61,500/s; mean 0.16 ms, p99 0.29 ms | 83,700/s; mean 0.60 ms, p99 0.93 ms |
| `put_distinct`: puts to new paths | 5,310/s; mean 1.88 ms, p99 2.34 ms | 10,900/s; mean 4.56 ms, p99 14.1 ms |
| `put_100`: puts to 100 paths | 5,020/s; mean 1.99 ms, p99 3.92 ms | 9,190/s; mean 5.44 ms, p99 14.3 ms |
| `put_one`: puts to one path | 823/s; mean 12.1 ms | 778/s; mean 64.3 ms |
| `list`: a page of 100 paths | 19,600/s; mean 0.51 ms, p99 0.83 ms | 25,300/s; mean 1.98 ms, p99 2.89 ms |

Over gRPC (`ghz`, all workers on one HTTP/2 connection, as an application's
one channel):

| Scenario | 10 workers | 50 workers |
|---|---|---|
| `grpc_get_100`: reads | 32,200/s; mean 0.25 ms, p99 0.66 ms | 50,400/s; mean 0.86 ms, p99 2.03 ms |
| `grpc_put_distinct`: puts to new paths | 5,240/s; mean 1.84 ms, p99 2.82 ms | 10,400/s; mean 4.69 ms, p99 14.5 ms |

The 50-connection puts vary from run to run by more than the gap between
`put_100` and `put_distinct` (`put_100` measured 9,200/s to 11,800/s on
this code). Every request
succeeded, except a few gRPC calls still in flight when `ghz` stopped: it
closes its connection at the deadline, and reports them as `Unavailable` or
`Canceled` ("use of closed network connection"; at most 43 of 311,000). The
server still finished them (see "The audit log isn't the limit", below).
gRPC puts match the JSON API's; gRPC reads measured lower, and spreading
them over 10 connections didn't change that (50 workers: 47,500/s on one
connection, 46,100/s on 10), so the limit is likely the client (`ghz`
renders a template per call), not investigated further. A `list`'s page is `put_100`'s 100 paths,
with up to 10 live versions each, of which it reads one per path (the
current one).

## Where the time goes

**A put is a Postgres commit.** `bench/pg/` measures Postgres alone, over
the same connection:

| `pgbench` script | 1 connection | 10 connections |
|---|---|---|
| one round trip (`SELECT 1`) | 0.014 ms | 0.027 ms |
| one durable commit | 0.98 ms | 1.78 ms (5,620/s) |
| a put's 8 statements, as ferritor sends them | 1.14 ms | 1.88 ms (5,320/s) |

A ferritor put at 10 connections (1.88 ms) costs no more than Postgres alone
does: the TLS, the request, the crypto, the policy check and the audit
entry hide inside the commit's wait for the WAL flush. Round trips are cheap (14 µs,
port forwarding included), so the put's 8 statements add 0.1 to 0.2 ms over
a bare commit. So, for writes:

- **Concurrency is what scales them.** Postgres flushes many waiting
  commits at once (group commit), so throughput grows with the writes in
  flight, up to `data_database_max_connections`. At the default of 10, puts
  stop at about 5,300/s: 5,320/s at 10 connections, 5,310/s at 36 (the
  default server-wide cap of calls in flight at that pool) at a mean of
  6.8 ms, waiting for a connection. At 32, about 11,000/s.
- **The disk sets the floor**: about 1 ms per flush here (other disks and
  filesystems weren't compared). A disk with power-loss protection
  acknowledges a flush sooner. `synchronous_commit = off` would too, but an
  acknowledged put could then be lost, which ferritor's version numbers and
  KEK floors rule out (see [high availability](/operations/high-availability)).
- **Puts to one path are serialized** by its lock: one commit after
  another (about 1.2 ms each here, 840/s, however many clients wait). Spread
  hot writes over paths.

**Reads don't touch the disk**: one query on a cached index, the decryption
in memory, the audit entry. At 50 connections they're bound by the CPU the
server, Postgres and the load generator share.

**The audit log isn't the limit.** Each allowed request waits until its
entry is written to the log's file: one `write` of the line by the writer
thread, no `fsync` ("written" means the kernel has it, as with any log
file). That costs microseconds, far below a commit, and reads at 83,700/s
include it. Every write is audited under load too: the 50-connection run
above allowed 938,972 writes, recorded as many put outcomes, and stored as
many rows,
including the calls `ghz` cut off at its deadlines (every request runs to
its end in a task of its own, whether its client waits or not).

## Deleted versions

A deleted version stays in `secret_versions` until `purge` removes it,
after `purge_deleted_after_days` (30 by default), and every put past
`max_versions` deletes one, so a busy path's rows are mostly deleted ones.
Every query over a path's live versions uses the partial index
`secret_versions_live` (`path_id, version DESC`, live rows only), so it
reads only live rows, at most `max_versions` per path, however much history
piles up: reads (latest or a given version), the latest-version lookup in
a put, the trim, delete, and restore. Listings and metadata's current
version don't read versions for it at all: they read
`paths.current_version`. One part of metadata reads the whole history on
purpose: `versions` counts every stored version, deleted ones included (a
metadata request on a path with 50,670 versions: 3.0 ms).

Without the index, those queries filter deleted rows out one at a time on
the primary key. Measured on a path `put_one` gave 26,000 to 46,000
versions (10 live), the index dropped and created again by hand (a
separate run from the results above):

| (10 connections) | Without `secret_versions_live` | With it |
|---|---|---|
| `put_one` on that path | 148/s, mean 68 ms | 834/s, mean 12.0 ms |
| a read of its latest version | 1,320/s, mean 7.6 ms | 57,700/s, mean 0.17 ms |
| the trim on that path, under its lock | 14 ms | 0.10 ms |
| `put_distinct` (the index's cost on a put) | 5,300/s | 5,220/s |

So a query over live versions must keep `deleted_at IS NULL` as a plain
condition next to the `path_id`: one made optional (`… OR …`), or moved
into an expression, can't use the index and is back to reading every
deleted row.

## Listings and paths with nothing live

Every path ever written keeps its `paths` row (its version counter must
outlive its versions), so a prefix can hold many paths whose versions are
all deleted or purged. A listing never visits them: it walks `paths_live`,
an index of the paths with a current version (`paths.current_version`, the
latest live one), and reads one version row per path listed. A prefix where
99 paths in 100 have nothing live (`list_dead`) lists like any other: at
50 connections, after the JSON API scenarios above (a separate run, 20 s
each), 22,700/s, next to `list`'s 24,200/s in the same run; 32,000/s on a
database holding only those paths. Vacuuming `paths` made no difference to
the first. Without `paths_live` (a probe of every path in the range for its
latest live version) it was 920/s: a page read past all the dead paths.

The price is on writes. Every put sets its path's `current_version`, and
deletes and restores change it, and since the column is in `paths_live`'s
predicate, the update can't be HOT: each one writes a new version of the
`paths` row with new entries in every index on the table, leaving the old
ones for vacuum. A put to an existing path pays that on top of its version
row's.

`paths` keeps a row for every path ever written, so workloads that create
many short-lived paths grow it; it's reclaimed when its namespace is
deleted ([key management](/operations/key-management)), so short-lived paths belong
in a namespace of their own.

## The change feed

[Watch streams](/guides/secrets#watching) cost the writes nothing measurable.
A put's `paths` update also sets `changed_xid` (by a trigger, when the
live version moves), which is in the same row write: `bench/pg/put.sql`
at 10 connections, alternating runs, 5,409/s without the column and
trigger, 5,372/s with them, within the runs' spread. Each server then asks
the data database every 250 ms what changed (an index range on
`changed_xid`), whether or not anyone watches: one small query per server,
however many streams.

Postgres `NOTIFY` from the put's transaction, the obvious way to push
changes, was measured and rejected: 1,099/s instead of 5,366/s in the same
run, with or without a listener. A notifying transaction takes a
database-wide lock from the queue insert until its commit is flushed, so
the commits that flush together in groups otherwise (above) flush one at a
time.

On the read side, a [CSI provider](/guides/csi) with a stream open reads a
secret only once it changed, instead of at every refresh past its shared
window; an [agent](/guides/agent) hears of a change sooner, and keeps its
rounds as the fallback, but ten times further apart while its stream is up
(at most ten minutes), so it reads up to ten times less.

## Sizing

- **`data_database_max_connections`**: the writes in flight. The default of
  10 caps one server at about 5,000 puts/s on a disk like this one. Raise it
  for write-heavy loads, keeping the sum over all servers (plus the keys
  pools, and anything else) below Postgres's `max_connections`.
- **The rate limits' caps on calls in flight** follow the pool: by
  default `2 × data_database_max_connections + 16` per server, a quarter
  of that per identity (9 at the default pool). Calls in flight are rate ×
  latency, so the per-identity default carries about 4,500 puts/s at 2 ms
  each; one application meant to use a whole server, as in these
  benchmarks (`bench/setup.sh` gives `apps/bench` the whole cap), needs an
  entry of its own ([operations](/operations/running#rate-limits)). Their cost
  per call (one lock for the identity's entry, a semaphore permit, and two
  atomic updates when it ends) didn't show up against the server without
  limits: at 50 connections, alternating runs of each on fresh databases,
  reads 62,700/s and 69,000/s without, 62,500/s and 71,800/s with;
  `put_distinct` 10,900/s and 11,500/s without, 11,000/s and 13,400/s
  with. The run-to-run spread is wider than any difference.
- **Several servers** share one data database, so more servers add read
  capacity and TLS capacity, not commit capacity: that's the database's.
- **Client connections**: reuse them (keep-alive, one gRPC channel). The
  numbers above are with reused connections; a new TLS handshake per request
  wasn't measured, but it adds round trips and signatures to every request.

## The images

The images ([development](/contributing/development#images)) are static
builds against musl, whose allocator made the server much slower. Measured
on the same machine and bench databases, at 50 connections for 10 s
each, alternating runs, the image's server on the host network:

| Build | `get_100` | `put_distinct` |
|---|---|---|
| glibc (`cargo build --release` on the host) | 80,300/s, 79,600/s | 10,790/s, 10,680/s |
| musl, musl's allocator | 28,200/s, 28,400/s | 8,990/s, 8,820/s |
| glibc (again, beside the next row) | 78,700/s, 78,700/s | 10,860/s, 10,920/s |
| musl with mimalloc (the image) | 76,400/s, 74,900/s | 10,640/s, 9,450/s |

So the server's static build allocates with mimalloc: reads within a few
percent of glibc's, puts within the runs' spread (the second musl run's
puts had a 28 ms p99 the others didn't).

## Running them again

Write the results here with the hardware and settings; numbers from another
machine aren't comparable, only their ratios are.
