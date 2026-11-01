---
title: 'Configuration'
description: 'Dev and secured mode, every setting in ferritor.toml with its default, environment variables, and what reloads on SIGHUP.'
seo:
  title: 'ferritor configuration reference: every setting'
---

The server reads an optional `ferritor.toml` in its working directory,
overridden by `FERRITOR_*` environment variables (nested keys with `__`, e.g.
`FERRITOR_TLS__CERT`). Policies can only come from `ferritor.toml`. It
takes no arguments: `--version` and `--help` print and exit, and any other
is refused (exit code 2) before anything is read, rather than ignored.

**`ferritor.example.toml`** documents every setting with its default: copy it
to `ferritor.toml` (gitignored) and edit. As shipped it's a dev-mode config;
uncommenting `[tls]`, the `[[policy]]` entries and `audit_signing_key`
together makes it secured. A test loads it in both forms, so it stays
accurate.

In production you need only this file and/or the `FERRITOR_*` variables. The
`.env` file is for development, and only a **debug build** of the server
loads it (dotenvy searches the working directory and then every parent
directory for one, so a release build could otherwise pick up another
application's `.env`). Its `KEYS_DATABASE_URL`/`DATA_DATABASE_URL` are for
the build and the tests (see [development](/contributing/development)), not the
server.

## Two modes, nothing in between

| | dev | secured |
|---|---|---|
| Configured by | no `[tls]`, no `[[policy]]` | `[tls]`, at least one `[[policy]]`, and `audit_signing_key` |
| Transport | plaintext | TLS, client certificate required |
| Authorization | everyone may do everything | the policy |
| Listens on | loopback only | any address |
| Audit log | chained, signed only with `audit_signing_key` | chained and signed |

Anything in between (TLS without a policy, a policy without TLS, secured
without a signing key) refuses to start. Dev mode is for trying ferritor out
and for development: anyone who can reach it can seal it, rotate, start a
rekey or submit fake shares, and real shares cross it in plaintext. Plaintext
serving also answers only requests *addressed* to `localhost` or a loopback
IP (421 otherwise), since listening on loopback alone doesn't stop DNS
rebinding from a browser on the same machine.

## Settings

| Key | Default | |
|---|---|---|
| `listen_addr` | `127.0.0.1:7070` | gRPC and the JSON API, one port. Loopback only in dev mode. |
| `keys_database_url` | (required) | The keys database. |
| `data_database_url` | (required) | The data database. |
| `keys_database_max_connections`, `data_database_max_connections` | 10 each | The most connections each pool opens (at least 1). A put holds a data-database connection for its whole transaction, so the data pool caps the writes in flight; past it, requests wait for a connection, up to `database_timeout_ms`, then `UNAVAILABLE`. Every server opens its own pools: keep the sum over all servers below Postgres's `max_connections` (100 by default). |
| `database_timeout_ms` | 5000 | Upper bound on any one database call (client side), the pool's acquire timeout and Postgres's `statement_timeout`. |
| `lock_timeout_ms` | 2000 | How long to wait for a lock another transaction holds (a put to the same path, an unconfirmed rekey commit, a KEK floor raise). Must be above 0 and below `database_timeout_ms`. |
| `purge_deleted_after_days` | 30 | How long a deleted version can still be restored before `ferritor purge` may remove it. 0 warns at startup. |
| `max_versions` | 10 | Live versions kept per path; each put marks older ones deleted. 0 keeps all. |
| `keyring_refresh_secs` | 60 | How often an unsealed server reloads its KEKs, to follow rotations by other servers. 0 turns the periodic refresh off. |
| `policy_refresh_secs` | 5 | How often an unsealed server checks whether the stored policies changed (one tiny read), reloading them if so: the longest a change through another server takes to reach this one. 0 turns the poll off. (Separately, every server re-reads and re-verifies the whole set once a minute, on its own schedule.) |
| `shutdown_delay_secs` | 0 | On the first SIGINT/SIGTERM, how long to keep serving while reporting not ready before draining (at most 300). See [operations](/operations/running). |
| `audit_signing_key` | (secured: required) | Ed25519 private key, PKCS#8 PEM, signing the audit log's checkpoints. Startup warns if group or others can read it. |

`[tls]` (secured mode):

| Key | Default | |
|---|---|---|
| `cert`, `key` | (required) | The server's certificate chain and key (PEM). |
| `client_ca` | (required) | The CAs (PEM) whose client certificates are accepted. List only the CAs that issue client certificates. |
| `crl` | (none) | One PEM file with a CRL from each client CA. Without it no certificate can be revoked. See [TLS](/guides/tls). |
| `max_connection_age_secs` | 3600 | Connections are recycled after this long (hygiene; expiry is enforced per request regardless). |
| `connection_age_grace_secs` | 30 | How long a connection past its age may finish in-flight calls. |

`[rate_limit]` (both modes; see [operations](/operations/running#rate-limits) for
sizing and what each limit answers):

| Key | Default | |
|---|---|---|
| `server_max_in_flight` | `2 × data_database_max_connections + 16` | Calls running at once on this server, all callers together (at least 1). One over it waits for a slot, up to `database_timeout_ms`, then `UNAVAILABLE`; a client that leaves while waiting takes its call with it. Read at startup only. |
| `max_in_flight` | `max(1, server_max_in_flight / 4)` | Calls running at once per identity; one more is refused (`RATE_LIMITED`). 0: no limit. |
| `requests_per_second` | 0 | Requests per second per identity, with `burst` at once above it; over it, refused with when to retry. 0: no rate limit; at most 1,000,000. |
| `burst` | twice the rate | Only with a rate (at least 1). |
| `max_watch_streams` | 256 | [Watch streams](/guides/secrets#watching) open at once per identity (they last as long as their clients, so they aren't calls in flight); one more is refused (`WATCH_FULL`, `limit: identity`). 0: no limit but the server's 4,096; at most 4,096. Raise it for an identity many replicas share, each with a stream. |

`[[rate_limit.identity]]`: an identity's own limits, taking priority over the
default: `identity` (exact, or a prefix by whole segments, like policy
paths; the most specific entry wins, and each identity under a prefix has
counters of its own), and any of `max_in_flight`, `requests_per_second`,
`burst`, `max_watch_streams`; a field left out is the default's (an entry with its own rate but
no burst gets twice its rate). No `max_in_flight` may be above
`server_max_in_flight`, and an identity may be listed once.

Always on, not configurable: per identity, 10 denied requests a second (a
burst of 50); and per certificate that names no caller (each request with
one is refused and audited), 1 a second (a burst of 5), past which its
requests are refused without an audit entry. Every limit is per server
([operations](/operations/running#rate-limits)).
Admin calls the config rules allow are never limited, so an operator can
always seal; requests in dev mode have no identity, so only the
server-wide cap applies to them.

<a id="identity"></a>`[identity]` (secured mode only; see [workload identity](/guides/workload-identity)):
short-lived client certificates in exchange for a platform's tokens.

| Key | Default | |
|---|---|---|
| `listen_addr` | (required) | The exchange's own listener (TLS with the server's certificate, no client certificate asked); not `listen_addr`'s. Read at startup only. |
| `lifetime_secs` | 3600 | How long an issued certificate lives, 60 to 86,400, never past its token's `exp`. Read at startup only. |

`[[identity.issuer]]`, one trusted token issuer (at least one):

| Key | Default | |
|---|---|---|
| `name` | (required) | One path segment: the first segment of every identity it maps to, reserved for it (no `[[policy]]` may name an identity under it). Unique. |
| `issuer` | (required) | Its tokens' `iss`, exactly. Unique. |
| `audience` | (required) | What their `aud` must contain. |
| `jwks_file`, `jwks_url` | (one required) | Its public keys (a JWKS): a file, or an `https://` URL fetched every 10 minutes. |
| `jwks_ca` | public web PKI roots | With `jwks_url` only: the CA (PEM) to verify it with. |
| `max_token_age_secs` | 86400 | The oldest token accepted, by `iat`: 1 to 31 days. |
| `exchange_burst` | 10 | Exchanges per identity at once, refilled at one a second: 1 to 10,000. Raise it to a deployment's replica count when many share an identity and start together ([workload identity](/guides/workload-identity#the-exchange)). |
| `not_before` | (none) | RFC 3339: refuse its certificates issued before this. |

`[[identity.issuer.map]]`, at least one per issuer, in order (the first
whose `require` holds decides): `identity`, a template starting with the
issuer's `name` and `/`, with `{claim}` placeholders that each fill a
whole segment (`/` or the end on both sides); `require`, a list of `{ claim = "…", one_of = ["…"] }`.

`[[identity.revoke]]`: `identity` (under a configured issuer) and
`not_before` (RFC 3339): its certificates issued before are refused.

<a id="seal"></a>`[seal]`: how the root key is opened at start (see
[key management](/operations/key-management#auto-unseal)). Read at startup only;
switching providers takes a rekey.

| Key | Default | |
|---|---|---|
| `provider` | `shamir` | `shamir`: the operators' shares unseal every server after every start. `awskms`: a server unseals itself through AWS KMS (the shares stay the recovery shares); needs `[seal.awskms]`, and a build with the `aws-kms` feature (the default). |

`[seal.awskms]`:

| Key | Default | |
|---|---|---|
| `key_id` | (required) | The KMS key: its ARN (recommended in production), or an alias ARN (resolved at every call, so whoever can retarget the alias picks the key). Every call names it. |
| `region` | the ARN's | Needed only when `key_id` isn't an ARN. |
| `endpoint` | the region's | Rarely needed: a VPC endpoint without private DNS (with it, the region's usual name already reaches it from inside the VPC), or `http://` on loopback only (a test double): the root key is in `Encrypt`'s request. Loopback is an IP literal or `localhost`, never decided by DNS. |

Credentials are the AWS SDK's usual chain, never in this file: the
environment (`AWS_PROFILE`, `AWS_ACCESS_KEY_ID`, …), the shared config
with Identity Center sessions, EKS Pod Identity or IRSA, an EC2 instance
profile. Each KMS call ends within 5 seconds, its own retry included.

`[[policy]]`: the config rules, for the operators (see [policy](/guides/policy);
the applications' grants are stored policies, managed over the API). Each
may have a `name`, shown as `config:<name>`.

A misspelled key in `ferritor.toml` refuses to start (unknown top-level keys,
and unknown keys inside `[tls]`, `[rate_limit]`, `[identity]`, `[seal]` and `[[policy]]`). Environment variables get
no such check: the CLI's `FERRITOR_ADDR`, `FERRITOR_CA`, `FERRITOR_CERT`,
`FERRITOR_KEY`, `FERRITOR_TOKEN_FILE` and `FERRITOR_EXCHANGE` share the prefix and may be set in the same shell, so a
misspelled `FERRITOR_…` variable is silently ignored.

## A secured setup

```toml
listen_addr = "0.0.0.0:7070"
keys_database_url = "postgres://ferritor@keys-db/ferritor_keys"
data_database_url = "postgres://ferritor@data-db/ferritor_data"
audit_signing_key = "/etc/ferritor/audit-key.pem"

[tls]
cert = "/etc/ferritor/server.pem"
key = "/etc/ferritor/server-key.pem"
client_ca = "/etc/ferritor/client-ca.pem"
crl = "/etc/ferritor/client-ca.crl"     # optional

[[policy]]
name = "ops-admin"
identity = "ops/alice"
actions = ["status", "init", "unseal", "seal", "rekey", "rotate", "rewrap", "purge", "destroy_kek", "namespace", "policy", "identity"]   # init, namespace and policy: a fresh deployment needs them
```

The applications' grants then go into stored policies (`ferritor policy
apply`, see [policy](/guides/policy)).

The audit signing key and its public half, for whoever verifies the log:

```sh
openssl genpkey -algorithm ed25519 -out audit-key.pem && chmod 600 audit-key.pem
openssl pkey -in audit-key.pem -pubout -out audit.pub.pem
```

The CLI over TLS: `--addr https://…` with `--ca`, `--cert` and `--key` (or
`FERRITOR_ADDR`, `FERRITOR_CA`, `FERRITOR_CERT`, `FERRITOR_KEY`).

## Reloading without a restart

`SIGHUP` reloads, while serving:

- the `[[policy]]` (each check uses the current one; a call already
  authorized finishes under the old), and the stored policies;
- in secured mode, the server certificate and key (new handshakes present
  them, so renewing a short-lived certificate needs no restart) and the CRLs
  (applied to open connections too);
- the keyring, in its own task, so a policy reload (how access is revoked in
  a hurry) never waits behind it;
- the rate limits but `server_max_in_flight` (a change to it warns, and
  waits for a restart). Counters carry over: a reload doesn't refill
  anyone's burst;
- `[identity]` but `listen_addr` and `lifetime_secs`: issuers, their keys,
  mappings and cutoffs, applied to open connections too. Removing the
  section refuses every certificate it issued; adding it needs a restart.

```sh
kill -HUP "$(pidof ferritor-server)"
```

Everything else, the client CA included, needs a restart. Whatever fails to
reload (the settings no longer load, an invalid policy, a mismatched key, a
certificate not valid now, a switch between dev and secured mode) keeps
running as it was and logs loudly. Every attempt is audited, with the
fingerprints of what's now in force.

The server refuses a certificate that isn't valid now (expired, or not yet
valid), at startup and on reload, and warns if a reloaded one expires sooner
than the one it replaces.
