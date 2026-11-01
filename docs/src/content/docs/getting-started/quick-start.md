---
title: 'Quick start'
description: 'Run ferritor on your machine in dev mode in about ten minutes: a server, the CLI, your first secrets, the JSON API, the agent and the audit log.'
seo:
  title: 'Quick start: ferritor in dev mode in ten minutes'
---

ferritor running on your machine in about ten minutes: the two databases,
a server, the first init and unseal, a namespace and a few secrets through
the CLI and the JSON API, and an agent keeping them current as files.

> [!CAUTION]
> It runs in **dev mode**: plaintext, everyone allowed to do everything,
> and only reachable on loopback. That's for trying ferritor out and for
> development, never for real secrets. For a real deployment, follow the
> [production deployment guide](/getting-started/production) or, in a
> cluster, the [Kubernetes guide](/getting-started/kubernetes).

## What you need

- Rust (edition 2024) and `protoc` on your `PATH`, to build ferritor;
- Docker or Podman with compose, for the two Postgres databases;
- `curl`, for the JSON API;
- a clone of the repository; every command below runs from its root.

## 1. The databases

ferritor keeps its keys and its secrets in two separate databases, so that
neither one alone opens anything (see [architecture](/concepts/architecture)).
`compose.yaml` starts both, and `.env.example` points at them:

```sh
cp .env.example .env
docker compose up -d          # keys database on 5433, data database on 5434
```

## 2. The server

```sh
cargo run -p ferritor-server > audit.log
```

A debug build reads `.env`, so it finds the databases, applies their
migrations and serves gRPC and the JSON API on `127.0.0.1:7070`. Its log goes
to stderr; stdout carries the [audit log](/operations/audit) and nothing else,
hence the redirect. Without a `ferritor.toml` it's in dev mode, and says so:

```
WARN dev mode without audit_signing_key: the audit log is chained but unsigned, so edits to it can't be proven
INFO serving gRPC and the JSON API; sealed addr=127.0.0.1:7070 mode="dev mode: plaintext, everyone allowed, loopback only"
```

It starts **sealed**: nothing that needs a key works until it's unsealed.

## 3. The CLI

In another shell, install the `ferritor` CLI:

```sh
cargo install --path crates/ferritor-cli     # or every command as: cargo run -p ferritor-cli -- <args>
ferritor status                              # not initialized
```

It talks to `http://127.0.0.1:7070` unless told otherwise (`--addr`, or
`FERRITOR_ADDR`).

## 4. Initialize and unseal

`init` creates the root key, the one key every other key is wrapped under,
and splits it into shares. Any three of the five rebuild it:

```sh
ferritor init --shares 5 --threshold 3
```

```
share 1 (generation 1): 010000000101e96d…
share 2 (generation 1): 010000000102a789…
…
Initialized: 5 shares, any 3 unseal. The server is still sealed.
```

The shares are printed **once** and stored nowhere. In a real deployment
each goes to a different operator. Unseal with three of them, one call each,
giving only the hex after the colon. On a terminal the share is read at a
hidden prompt; it's never a command-line argument:

```sh
ferritor unseal        # paste a share; three times, a different one each time
```

```
unsealed
shares: 5, threshold: 3
generation: 1
```

The server now holds the root key in memory, and only there. A restart
starts it sealed again, and so does `ferritor seal`, the emergency stop (see
[key management](/operations/key-management)).

## 5. A namespace and a secret

Every secret's path starts with its **namespace** (`app/db` is in `app`), and
each namespace has its own keys. There's no default one, so create it first:

```sh
ferritor namespace create app
echo -n 's3cret' | ferritor put app/db
ferritor get app/db
```

```
created namespace app
active KEK version: 1
app/db version 1
s3cret
```

Values are read from stdin, byte for byte (or at a hidden prompt on a
terminal), and printed raw: never a command-line argument.

## 6. Versions, labels, delete and restore

Every put is a new version, and the older ones stay readable:

```sh
echo -n 'n3w' | ferritor put app/db
ferritor versions app/db
ferritor get app/db --version 1
```

```
app/db version 2
version 2	created 2026-10-28T07:31:47Z	live
version 1	created 2026-10-28T07:31:47Z	live
s3cret
```

Labels are plain metadata for finding secrets (never put a secret in one),
and a listing covers everything below a prefix:

```sh
ferritor metadata set app/db team=billing
echo -n 'x' | ferritor put app/api-key
ferritor list app
```

```
app/api-key	version 1
app/db	version 2
```

Only the secrets with a label:

```sh
ferritor list app --label team=billing
```

```
app/db	version 2
```

A delete is soft: every version is kept, restorable until the server's
retention (30 days by default) lets `ferritor purge` remove it:

```sh
ferritor delete app/db
ferritor get app/db          # error: secret `app/db` not found
ferritor restore app/db      # app/db version 2 restored
```

More in [secrets](/guides/secrets): check-and-set, the version limit,
purging.

## 7. The JSON API

The same server answers JSON on the same port, with values in base64:

```sh
curl -s localhost:7070/v1/secrets/app/db
curl -s -X PUT localhost:7070/v1/secrets/app/db \
  -H 'content-type: application/json' \
  -d "{\"value\": \"$(echo -n from-http | base64)\"}"
curl -s 'localhost:7070/v1/secrets?prefix=app'
```

```json
{"path":"app/db","version":2,"created_at":"2026-10-28T07:31:47Z","value":"bjN3"}
{"path":"app/db","version":3,"created_at":"2026-10-28T07:31:56Z"}
{"secrets":[{"path":"app/api-key","version":1,…},{"path":"app/db","version":3,…}],"next_page_token":""}
```

Every endpoint and error code is in the [HTTP API](/reference/http-api)
reference.

## 8. Secrets as files

Most applications read their configuration from files. `ferritor-agent`
keeps secrets current as files next to them:

```sh
cargo build -p ferritor-agent
cat > agent.toml <<'EOF'
server = "http://127.0.0.1:7070"

[[output]]
dir = "/dev/shm/ferritor-quickstart"    # in memory: the agent refuses a disk unless allow_disk = true

[[output.secret]]
path = "app/db"

[[output.secret]]
path = "app/api-key"
EOF
./target/debug/ferritor-agent run --config agent.toml
```

```
INFO files written dir=/dev/shm/ferritor-quickstart files=2
INFO watching for changes paths=2
```

`/dev/shm` is in memory on Linux; elsewhere, use any directory and add
`allow_disk = true` under `[[output]]`. Each secret is a file named after
its path's last segment, swapped in atomically as a set:

```sh
cat /dev/shm/ferritor-quickstart/db              # from-http
echo -n 'rotated' | ferritor put app/db
cat /dev/shm/ferritor-quickstart/db              # rotated, within a moment
```

The agent heard of the change through a watch stream and rewrote the file
at once; it also reads everything again on an interval, as a fallback. See
[the agent](/guides/agent) for notifying the application, refusals, and
running it as a Kubernetes sidecar or a systemd service. Stop it with
Ctrl-C; the files stay.

## 9. The audit log

Every decision and every change the server made is a line in `audit.log`:

```sh
tail -n 2 audit.log
```

```json
{"time":"…","event":"outcome","caller":null,"action":"write","target":{"kind":"path","path":"app/db"},"operation":"put","result":"succeeded","details":{"trimmed":0,"version":4},"seq":36,"prev":"21b2…"}
{"time":"…","event":"authorization","caller":null,"action":"list","target":{"kind":"below","path":"app"},"decision":"allowed","seq":37,"prev":"55cc…"}
```

`caller` is `null` because dev mode has no identities. The lines are
hash-chained; with a signing key (secured mode) the chain is signed too,
and `ferritor audit verify` proves nothing was changed (see
[audit](/operations/audit)). Never a value, a share or a nonce.

## What dev mode leaves out

Everything that makes ferritor safe to use:

- **Identity and policy.** In secured mode every caller presents a client
  certificate naming it (`ferritor://apps/billing`), and the
  [policy](/guides/policy) decides what each may do, on which paths. Dev
  mode allows everything.
- **TLS.** Dev mode is plaintext and answers only requests addressed to
  loopback.
- **A signed audit log.** Without a signing key the chain can't be proven.
- **Operators holding the shares,** each a different person, or a key
  management service unsealing the servers by themselves
  ([auto-unseal](/operations/key-management#auto-unseal)).

The [production deployment guide](/getting-started/production) sets all of it up: two
databases, a small PKI, a `ferritor.toml`, the first init and unseal, and an
application reading its secret over mTLS.

## Starting over

```sh
docker compose down -v        # both databases, and everything in them
```
