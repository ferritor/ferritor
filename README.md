<h1>
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="docs/src/assets/brand/ferritor-horizontal-on-dark.svg">
    <img alt="ferritor" src="docs/src/assets/brand/ferritor-horizontal-on-light.svg" width="360">
  </picture>
</h1>

A secret management service built on envelope encryption. Secrets are 
stored encrypted in Postgres; the keys that open them exist only in the 
memory of an unsealed server, reconstructed from Shamir shares held by
operators.

- **Envelope encryption.** Every secret version has its own data key (DEK),
  wrapped by a versioned key-encryption key (KEK), wrapped in turn by a root
  key that is never stored.
- **Namespaces.** A secret's path starts with its namespace (`billing/db` is
  in `billing`), and each namespace has its own KEKs, rotated and destroyed
  on its own. There's no default: create one before storing anything.
- **Two databases.** Wrapped KEKs live in a *keys* database, ciphertexts and
  wrapped DEKs in a separate *data* database: either one alone yields no usable
  key.
- **Shamir unsealing.** The server starts sealed; a threshold of operator
  shares reconstructs the root key in memory. Sealing is the emergency stop.
- **Key lifecycle.** Rotate KEKs, rewrap DEKs to the new one, destroy retired
  KEKs (crypto-shredding), rekey the root key and shares, all online.
- **mTLS and policies.** Callers are identified by a `ferritor://<name>`
  client certificate. Operators' rules live in `ferritor.toml`; applications'
  grants are stored policies, managed over the API (`ferritor policy apply`
  from a file in git), and signed so that writing the database can't grant
  anyone access. Certificate expiry and revocation (CRLs) are checked on
  every request.
- **Tamper-evident audit log.** One JSON line per decision, hash-chained and
  signed with Ed25519; `ferritor audit verify` checks it offline.
- **Versioned secrets.** Every write is a new version; check-and-set, soft
  delete, restore, history, a per-path version limit and purging after a
  retention period.
- **Rate limits.** Calls in flight and requests per second per identity, a
  budget of denied requests, and a server-wide cap, so one application
  can't take the server from the others; operators are never limited.
- **Workload identity.** A workload trades the token its platform already
  gives it (a Kubernetes service account's, a CI job's OIDC token) for an
  hour-long client certificate from ferritor, renewed by the agent itself: no
  certificates to issue to applications.
- **Secrets as files.** `ferritor-agent` keeps an application's secrets
  current as files (a Kubernetes sidecar, a systemd service), swapped
  atomically as a set, for applications that read their configuration from
  files; in Kubernetes, `ferritor-csi-provider` does it once per node for
  every pod, through the Secrets Store CSI Driver, each pod reading with
  its own identity. Both hear of a change at once, through a watch stream,
  with polling as the fallback.
- **Two APIs on one port.** gRPC and a JSON API, sharing TLS, identity, the
  policy, the audit log and every seal rule.

```
Shamir shares --reconstruct--> root key   (memory only)
root key  wraps  KEKs                   -> keys database
KEK       wraps  one DEK per version    -> data database
DEK       encrypts the secret value     -> data database
```

## Quick start (dev mode)

> [!CAUTION]
> Dev mode is plaintext, lets everyone do everything, and only listens on
> loopback: for trying ferritor out and development, never for real secrets.

Needs Rust (edition 2024), `protoc`, and Docker or Podman.

```sh
cp .env.example .env
docker compose up -d                      # the keys and data databases
cargo run -p ferritor-server > audit.log  # gRPC and the JSON API on 127.0.0.1:7070; stdout is the audit log

# in another shell: the `ferritor` CLI, used as plain `ferritor` throughout the docs
cargo install --path crates/ferritor-cli  # or: cargo run -p ferritor-cli -- <args>
ferritor init --shares 5 --threshold 3    # prints 5 shares, once
ferritor unseal                           # three times, one share each: the hex after the colon (stdin)
ferritor namespace create app             # nothing can be stored outside a namespace
echo -n 's3cret' | ferritor put app/db
ferritor get app/db
curl -s localhost:7070/v1/secrets/app/db  # the JSON API (value in base64)
```

Shares and values are never command-line arguments: they're read from stdin,
with a hidden prompt on a terminal. The [quick start](docs/src/content/docs/getting-started/quick-start.md)
walks through the same steps with what each prints, then versions and
labels, the JSON API, the agent keeping secrets current as files, and the
audit log. For a real deployment (TLS with client certificates, a policy,
a signing key for the audit log), follow the
[production deployment guide](docs/src/content/docs/getting-started/production.md).

## Documentation

Published at <https://ferritor.dev>; the sources are below, in `docs/`.
What changed in each release: [CHANGELOG.md](CHANGELOG.md).

**Getting started**

| Topic | |
|---|---|
| [Quick start](docs/src/content/docs/getting-started/quick-start.md) | dev mode on your machine: the databases, a server, init and unseal, secrets through the CLI and the JSON API, the agent, the audit log |
| [Production deployment](docs/src/content/docs/getting-started/production.md) | a secured deployment step by step: databases, certificates, config, init, the first secret |
| [Kubernetes guide](docs/src/content/docs/getting-started/kubernetes.md) | ferritor, its databases and the CSI provider in a cluster: pods reading their secrets as files with their service accounts' identities |

**Concepts**

| Topic | |
|---|---|
| [Architecture](docs/src/content/docs/concepts/architecture.md) | crates, the key hierarchy, the two databases, how a request flows |
| [Security model](docs/src/content/docs/concepts/security.md) | what ferritor defends against and what it doesn't, the trust boundaries, known gaps |

**Guides**

| Topic | |
|---|---|
| [Secrets](docs/src/content/docs/guides/secrets.md) | versions, check-and-set, delete and restore, history, purge; the gRPC and JSON APIs |
| [Policy](docs/src/content/docs/guides/policy.md) | who may do what, on which paths: config rules and stored policies, `ferritor policy` and its APIs |
| [TLS and identity](docs/src/content/docs/guides/tls.md) | client certificates, `ferritor://` identities, expiry and CRL revocation |
| [Workload identity](docs/src/content/docs/guides/workload-identity.md) | platform tokens exchanged for short-lived certificates: issuers, mappings, revoking, the CLI and the agent |
| [The agent](docs/src/content/docs/guides/agent.md) | secrets as files: `ferritor-agent` as a Kubernetes sidecar or a systemd service, its settings, reading the files, failures |
| [The CSI provider](docs/src/content/docs/guides/csi.md) | secrets as files in Kubernetes pods, one provider per node: the volume, refreshing, failures, running it |

**Operations**

| Topic | |
|---|---|
| [Operations](docs/src/content/docs/operations/running.md) | health and readiness, shutdown, metrics, routine and recovery tasks |
| [Key management](docs/src/content/docs/operations/key-management.md) | seal and unseal, namespaces, rekey, rotate, rewrap, destroying KEKs, keyring refresh |
| [Audit log](docs/src/content/docs/operations/audit.md) | what's recorded, the hash chain and signatures, `ferritor audit verify` |
| [Backup and restore](docs/src/content/docs/operations/backup-restore.md) | backing up two databases that must match, and the shares |
| [High availability](docs/src/content/docs/operations/high-availability.md) | several servers, and why both databases need synchronous replication |
| [Performance](docs/src/content/docs/operations/performance.md) | load test results, where the time goes, sizing |

**Reference**

| Topic | |
|---|---|
| [Configuration](docs/src/content/docs/reference/configuration.md) | dev and secured mode, every setting, reloading on SIGHUP |
| [HTTP API](docs/src/content/docs/reference/http-api.md) | the JSON API reference: mTLS authentication with curl, Python, Node and Go examples, every endpoint and error code; [OpenAPI spec](docs/openapi.json) |

**Contributing**

| Topic | |
|---|---|
| [Development](docs/src/content/docs/contributing/development.md) | building, the container images, testing, sqlx with two databases, lints, CI, fuzzing |

## Layout

```
crates/ferritor-core        shared library: gRPC bindings, crypto, secret paths, audit chain, error reasons
crates/ferritor-keystore    the keys database: migrations and queries
crates/ferritor-datastore   the data database: migrations and queries
crates/ferritor-server      the server (library + binary)
crates/ferritor-client      talking to a server over gRPC: the library the CLI and the agent share
crates/ferritor-cli         the `ferritor` CLI (library + binary)
crates/ferritor-agent       keeps an application's secrets current as files (`ferritor-agent`)
crates/ferritor-testkit     test helpers: throwaway databases, a test CA
proto/ferritor/v1           the gRPC contract
Dockerfile                  the images: each binary alone in a scratch image
```

## Security

Report a vulnerability privately, as [SECURITY.md](SECURITY.md) says
(GitHub's private vulnerability reporting), never in a public issue.

## License

Licensed under either of

- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE) or
  <https://www.apache.org/licenses/LICENSE-2.0>)
- MIT license ([LICENSE-MIT](LICENSE-MIT) or <https://opensource.org/licenses/MIT>)

at your option. The images also carry the notices of the crates they're
built from ([THIRD-PARTY-LICENSES.txt](THIRD-PARTY-LICENSES.txt)).

Unless you explicitly state otherwise, any contribution intentionally
submitted for inclusion in the work by you, as defined in the Apache-2.0
license, shall be dual licensed as above, without any additional terms or
conditions.
