# Load tests

End-to-end load tests against a `--release` server with TLS, client
certificates, a stored policy and the signed audit log on, as in production:
dev mode skips the handshake and the per-request checks, so its numbers
would mislead. Results, and what they mean for sizing:
[docs/src/content/docs/operations/performance.md](../docs/src/content/docs/operations/performance.md).

Needs the compose databases (`docker compose up -d`), `openssl`, `oha` (HTTP
load), `ghz` (gRPC load), `pgbench` and `psql` (the Postgres-only scripts),
and `python3`.

```sh
POOL=32 bench/setup.sh   # throwaway PKI, keys, ferritor.toml and databases under bench/run/
bench/start.sh           # builds --release and serves (foreground; Ctrl-C stops it)
bench/init.sh            # in another terminal: init, unseal, namespace `bench`, stored policy
bench/scenarios.sh       # every scenario, 30 s each, 10 connections
C=50 DURATION=10s bench/scenarios.sh put_distinct get_100
```

`setup.sh` starts over: it drops and recreates `ferritor_bench_keys` and
`ferritor_bench_data` (never the development databases) and everything in
`bench/run/`, shares included. After restarting the server (it starts
sealed), `bench/init.sh unseal`. `POOL` sets `data_database_max_connections`
(default 10, the server's default); `PORT` the port (7171). The
`ferritor.toml` it writes lets `apps/bench` hold the whole server-wide cap in
flight (`[[rate_limit.identity]]`), since the default, a quarter of it,
would refuse a load test's connections. The cap itself is `2 × POOL + 16`
(36 at the default pool, 80 at 32): a `C` above it is mostly refused (429),
not measured.

## Scenarios (`scenarios.sh`)

Over the JSON API, with the application's certificate (`apps/bench`, granted
by a stored policy, so every request goes through the stored-policy check).
Values are 100 bytes. Each prints one line (count, rate, mean and
percentiles, success); the raw `oha` JSON is in `run/results/`.

| Scenario | Requests | What it shows |
|---|---|---|
| `put_100` | `PUT` to 100 paths at random | writes, with some waits on the path lock |
| `put_distinct` | `PUT` to (nearly always) a new path | writes without contention: the commit rate |
| `put_one` | `PUT` to one path | the path lock: puts to one path are serialized |
| `get_100` | `GET` of `put_100`'s paths | reads |
| `list` | `GET /v1/secrets?prefix=bench` (first page, 100 paths) | listings |
| `list_dead` | `GET /v1/secrets?prefix=bench/dead` (first page), where 99 paths in 100 have no live version | a listing reading past paths with nothing live (every path ever written stays in `paths`). Not in the default run: its first run writes the paths (10,000 puts, 9,900 deletes), and they change `list`'s page after it |
| `grpc_put_distinct`, `grpc_get_100` | `PutSecret` and `GetSecret` over gRPC (`ghz`), all workers on one HTTP/2 connection | the same, as an application's one channel |

The order matters: `list` runs over what the puts left, and `put_one` over
its path's history (see docs/src/content/docs/operations/performance.md, "Deleted versions").

## Postgres alone (`pg/`)

`pgbench` scripts against the bench data database, to tell ferritor's cost
from Postgres's:

```sh
export PGPASSWORD=ferritor
psql -h localhost -p 5434 -U ferritor -d ferritor_bench_data \
  -c 'CREATE TABLE IF NOT EXISTS bench_commit (id bigserial PRIMARY KEY, v bytea)' \
  -c "INSERT INTO namespaces (name) VALUES ('pg') ON CONFLICT (name) DO NOTHING"
for s in rtt commit put; do
  pgbench -h localhost -p 5434 -U ferritor -n -M prepared -c 10 -j 10 -T 10 -f bench/pg/$s.sql ferritor_bench_data
done
```

- `rtt.sql`: one round trip (`SELECT 1`).
- `commit.sql`: one durable commit (a WAL flush).
- `put.sql`: a put's statements, one round trip each, as `ferritor-datastore`
  sends them (path lock, version, latest, insert, trim, commit), in the
  namespace `pg` (its row created above). Keep it in step with
  `Datastore::begin_put` and `PendingPut::insert`.
