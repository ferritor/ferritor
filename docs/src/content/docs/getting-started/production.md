---
title: 'Production deployment'
description: 'A secured ferritor deployment step by step: two databases, a small PKI, the configuration, init and unseal, and an application reading its secret over mTLS.'
seo:
  title: 'Deploying ferritor in production, step by step'
---

From nothing to a secured server holding its first secret: two databases, a
small PKI, a `ferritor.toml`, the first init and unseal, a namespace, and an
application reading its secret over mTLS. Each step links to the topic that
explains it. In Kubernetes, the [Kubernetes guide](/getting-started/kubernetes)
puts the same pieces in a cluster.

> [!CAUTION]
> Never put real secrets in dev mode: the
> [quick start](/getting-started/quick-start) is for trying ferritor out.

## What you need

- **Two Postgres databases**, the *keys* database and the *data* database,
  on separate servers if you can: each alone yields wrapped keys, never
  usable ones. With several ferritor servers or any failover, both need
  synchronous replication; read [high availability](/operations/high-availability)
  before going live.
- **Two CAs**: one that signs the server's certificate (clients trust it),
  and one that issues client certificates (the server trusts it). They can
  be intermediates of your existing PKI; the commands below make standalone
  ones with OpenSSL.
- **Operators** to hold the unseal shares: by default 5, any 3 of which
  unseal. The server starts sealed after every restart, so they must be
  reachable whenever it restarts.
- Rust (edition 2024) and `protoc` to build, on the build machine only.

## 1. Build

```sh
SQLX_OFFLINE=true cargo build --release --locked -p ferritor-server -p ferritor-cli
# target/release/ferritor-server  the server
# target/release/ferritor         the CLI, for operators and scripts
```

`SQLX_OFFLINE=true` builds from the committed query caches, without any
database. A release build never reads a `.env` file (see
[configuration](/reference/configuration)). For containers, the
repository's `Dockerfile` builds an image per binary
([development](/contributing/development#images)).

Or take a release's binaries: each [GitHub
release](https://github.com/ferritor/ferritor/releases) has an archive per
architecture (`ferritor-<version>-x86_64-unknown-linux-musl.tar.gz`, and
`aarch64`), static, so they run on any Linux. Verify it before you
unpack it: its cosign bundle must name the release workflow, and its
checksum must match.

```sh
f=ferritor-0.9.2-x86_64-unknown-linux-musl.tar.gz
cosign verify-blob "$f" --bundle "$f.sigstore.json" \
  --certificate-identity https://github.com/ferritor/ferritor/.github/workflows/release-plz.yml@refs/heads/main \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com
sha256sum -c SHA256SUMS --ignore-missing
tar -xzf "$f"   # ferritor-server, ferritor-csi-provider, ferritor-agent, ferritor
```

The CLI alone runs on macOS and Windows too, for operators' machines:
`ferritor-cli-<version>-aarch64-apple-darwin.tar.gz` (Apple silicon),
`ferritor-cli-<version>-x86_64-apple-darwin.tar.gz` (Intel Macs) and
`ferritor-cli-<version>-x86_64-pc-windows-gnu.zip`, verified the same way.
On macOS:

```sh
f=ferritor-cli-0.9.2-aarch64-apple-darwin.tar.gz
cosign verify-blob "$f" --bundle "$f.sigstore.json" \
  --certificate-identity https://github.com/ferritor/ferritor/.github/workflows/release-plz.yml@refs/heads/main \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com
grep " $f\$" SHA256SUMS | shasum -a 256 -c -
tar -xzf "$f"   # ferritor-cli-0.9.2-aarch64-apple-darwin/ferritor
```

On Windows, in PowerShell:

```powershell
$f = "ferritor-cli-0.9.2-x86_64-pc-windows-gnu.zip"
cosign verify-blob $f --bundle "$f.sigstore.json" `
  --certificate-identity https://github.com/ferritor/ferritor/.github/workflows/release-plz.yml@refs/heads/main `
  --certificate-oidc-issuer https://token.actions.githubusercontent.com
$want = (Select-String -Path SHA256SUMS -SimpleMatch " $f").Line.Split(" ")[0]
(Get-FileHash $f).Hash -eq $want   # True (-eq ignores case)
Expand-Archive $f -DestinationPath .   # ferritor-cli-0.9.2-x86_64-pc-windows-gnu\ferritor.exe
```

They're cross-built and not notarized or signed by a publisher: fetched
with `curl` they run as they are, but downloaded with a browser macOS
refuses to start the binary until `xattr -d com.apple.quarantine ferritor`,
and Windows SmartScreen asks first. On Windows, mind where `ferritor login
--key-out` writes its key
([workload identity](/guides/workload-identity#the-cli)).

## 2. Databases

One database and one login role per side; the role owns its database,
because the server runs that database's migrations itself at startup:

```sql
-- on the keys database's server
CREATE ROLE ferritor_keys LOGIN PASSWORD '…';
CREATE DATABASE ferritor_keys OWNER ferritor_keys;

-- on the data database's server
CREATE ROLE ferritor_data LOGIN PASSWORD '…';
CREATE DATABASE ferritor_data OWNER ferritor_data;
```

Never give one role access to both databases. Plan the backups now: they
must be taken in the right order, and the shares go with the keys
database's generation (see [backup and restore](/operations/backup-restore)).

## 3. Certificates

The requirements (see [TLS and identity](/guides/tls)):

- The **server certificate** has a DNS SAN for every name clients connect
  to, and the `serverAuth` extended key usage.
- Each **client certificate** has exactly one URI SAN, `ferritor://<name>`: the
  `<name>` is the identity the policy grants actions to (`ops/alice`,
  `apps/billing`; it follows the secret-path rules). It needs the
  `clientAuth` extended key usage and must be issued **directly** by a CA in
  `client_ca`. The subject CN plays no part.
- Without a CRL file, a client certificate can't be revoked, only expire:
  keep them short-lived, or set up `[tls] crl` (see [TLS](/guides/tls)).

A minimal PKI with OpenSSL (Ed25519 keys; any key type rustls accepts works):

```sh
#!/usr/bin/env bash
set -euo pipefail

ca() {  # ca <file> <CN>
  openssl genpkey -algorithm ed25519 -out "$1.key"
  openssl req -x509 -new -key "$1.key" -subj "/CN=$2" -days 3650 -out "$1.pem" \
    -addext "basicConstraints=critical,CA:TRUE" \
    -addext "keyUsage=critical,keyCertSign,cRLSign"
}
ca server-ca "ferritor server CA"
ca client-ca "ferritor client CA"

# The server: one DNS SAN per name clients use.
openssl genpkey -algorithm ed25519 -out server-key.pem
openssl req -new -key server-key.pem -subj "/CN=ferritor.example.internal" -out server.csr
cat > server.ext <<X
subjectAltName = DNS:ferritor.example.internal
extendedKeyUsage = serverAuth
keyUsage = critical, digitalSignature
basicConstraints = critical, CA:FALSE
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid, issuer
X
openssl x509 -req -in server.csr -CA server-ca.pem -CAkey server-ca.key -days 90 \
  -extfile server.ext -out server.pem

# A client: its identity is the URI SAN. (A `/` in -subj would start a new
# attribute, so the file names and CN use `-`.)
client() {  # client <identity>
  local f=${1//\//-}
  openssl genpkey -algorithm ed25519 -out "$f-key.pem"
  openssl req -new -key "$f-key.pem" -subj "/CN=$f" -out "$f.csr"
  cat > "$f.ext" <<X
subjectAltName = URI:ferritor://$1
extendedKeyUsage = clientAuth
keyUsage = critical, digitalSignature
basicConstraints = critical, CA:FALSE
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid, issuer
X
  openssl x509 -req -in "$f.csr" -CA client-ca.pem -CAkey client-ca.key -days 30 \
    -extfile "$f.ext" -out "$f.pem"
}
client ops/alice      # an operator
client apps/billing   # an application
```

The key identifiers aren't needed by ferritor, but strict clients require
them: Python 3.13 and later refuses a server certificate without an
Authority Key Identifier.

Keep `server-ca.key` and `client-ca.key` off the ferritor host. The server
needs `server.pem`, `server-key.pem` and `client-ca.pem`; clients need
`server-ca.pem` and their own certificate and key.

## 4. The audit signing key

The audit log (the server's stdout) is hash-chained and signed with an
Ed25519 key, required in secured mode:

```sh
openssl genpkey -algorithm ed25519 -out audit-key.pem && chmod 600 audit-key.pem
openssl pkey -in audit-key.pem -pubout -out audit.pub.pem   # for whoever verifies the log
```

## 5. Configuration

`/etc/ferritor/ferritor.toml` (start from `ferritor.example.toml`, which documents
every setting; see [configuration](/reference/configuration)). `[tls]`, at least one
`[[policy]]` and `audit_signing_key` together make it secured; anything in
between refuses to start.

```toml
listen_addr = "0.0.0.0:7070"
audit_signing_key = "/etc/ferritor/audit-key.pem"

[tls]
cert = "/etc/ferritor/server.pem"
key = "/etc/ferritor/server-key.pem"
client_ca = "/etc/ferritor/client-ca.pem"

# The operator: every admin action (init, namespace and policy are needed
# to start). Applications' access goes into stored policies (step 8).
[[policy]]
name = "ops-admin"
identity = "ops/alice"
actions = ["status", "init", "unseal", "seal", "rekey", "rotate", "rewrap", "purge", "destroy_kek", "namespace", "policy", "identity"]
```

Keep the database passwords out of the file: pass the URLs as
`FERRITOR_KEYS_DATABASE_URL` and `FERRITOR_DATA_DATABASE_URL` from your secret
store. Make the server's keys (`server-key.pem`, `audit-key.pem`) readable by
its user only; startup warns about an audit key others can read. See
[policy](/guides/policy) for granting actions and paths. Keep the config rules
to the operators (and anything that must work while sealed, such as a
monitoring identity's `status`); the applications' grants are managed as
stored policies, over the API, in the next steps.

## 6. Run it

The server reads `ferritor.toml` from its working directory. Its **stdout is
the audit log** and carries nothing else (its own logs go to stderr): send
stdout to durable storage or a log shipper, off the host as it's written
(see [audit log](/operations/audit)), never into the same stream as stderr. A systemd
unit, as a starting point:

```ini
# /etc/systemd/system/ferritor.service
[Unit]
Description=ferritor secret manager
After=network-online.target
Wants=network-online.target

[Service]
User=ferritor
WorkingDirectory=/etc/ferritor
# FERRITOR_KEYS_DATABASE_URL=… and FERRITOR_DATA_DATABASE_URL=…, readable by root only
EnvironmentFile=/etc/ferritor/database.env
ExecStart=/usr/local/bin/ferritor-server
ExecReload=/bin/kill -HUP $MAINPID
StandardOutput=append:/var/log/ferritor/audit.log
StandardError=journal
TimeoutStopSec=30
Restart=on-failure
# Hardening (https://ferritor.dev/concepts/security): the unsealed
# server holds the root key and every KEK in memory. It marks itself
# undumpable at startup (no core dumps, no same-user ptrace or
# /proc/<pid>/mem); these add the rest. ferritor writes no files itself
# (systemd opens the audit log), so the system can be read-only.
# Its memory, keys included, never goes to swap (cgroup v2).
MemorySwapMax=0
LimitCORE=0
NoNewPrivileges=true
CapabilityBoundingSet=
ProtectSystem=strict
ProtectHome=true
PrivateTmp=true
PrivateDevices=true
ProtectKernelTunables=true
ProtectKernelModules=true
ProtectControlGroups=true
MemoryDenyWriteExecute=true
LockPersonality=true
RestrictSUIDSGID=true
RestrictNamespaces=true
RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX
SystemCallFilter=@system-service

[Install]
WantedBy=multi-user.target
```

(systemd takes comments only on lines of their own, never after a setting.)

These settings were tested as a system service (systemd 262, a non-root
user, every setting as above) with the server serving gRPC and the JSON API
under load, both databases, a SIGHUP reload and a draining stop, whose audit
log then verified; test them on your own hosts before relying on them.
`systemd-analyze security ferritor` rates the unit 2.2, "OK" (8.3 without the
hardening). If a setting conflicts with something your hosts add (a
monitoring library loaded into the process, a different libc), drop that one
rather than the block, and say so in your unit.

**Swap.** `MemorySwapMax=0` keeps the service's memory out of swap without
turning swap off for the host, on cgroup v2 (every current distribution).
Without cgroup v2, run the host without swap, or with swap encrypted under
a key that doesn't survive a reboot (dm-crypt with a random key).
Hibernation writes all of memory to disk whatever the cgroup says: don't
let a ferritor host hibernate. ferritor doesn't lock its memory (`mlock`): its
keys live in ordinary heap allocations.

**Rotating the audit log file.** systemd opens `audit.log` once, when the
server starts, and the server writes to that open file until it stops. So:

- Don't rotate by renaming while the server runs (logrotate's default): the
  server keeps writing to the renamed file, and the new one stays empty.
- Never use `copytruncate`: lines written between the copy and the
  truncate are lost, and the chain is broken.
- Rotate across restarts instead: every start begins a new chain, so with
  the server stopped, rename the file; each file then holds whole chains
  that `ferritor audit verify` checks on their own. (A restart seals the
  server: plan it like any other.)
- Better still, have a log collector (Vector, Fluent Bit, …) follow the
  file and ship it as it's written, which you want anyway (see
  [audit log](/operations/audit)), and keep the local file for the current run.

To verify a run split across several files, verify them concatenated, in
order: `cat audit.log.1 audit.log | ferritor audit verify --public-key
audit.pub.pem`. A file holding only part of a chain is reported unproven on
its own.

SIGTERM drains in-flight calls and writes the audit log's signed
`chain_end`; SIGHUP (`systemctl reload ferritor`) reloads the policy, the
server certificate, the CRLs and the keyring (see
[configuration](/reference/configuration), [operations](/operations/running)).

## 7. Initialize and unseal

From an operator's machine, with the operator's certificate:

```sh
export FERRITOR_ADDR=https://ferritor.example.internal:7070
export FERRITOR_CA=server-ca.pem FERRITOR_CERT=ops-alice.pem FERRITOR_KEY=ops-alice-key.pem

ferritor status                                # not initialized
ferritor init --shares 5 --threshold 3         # prints the 5 shares, once
```

> [!IMPORTANT]
> The shares are shown **only once**: hand each to a different operator
> now, and don't leave them in a terminal's scrollback. If the reply is
> lost (a timeout), see [operations](/operations/running) before retrying.

Then any three operators unseal, each with their own share (read from stdin,
a hidden prompt on a terminal; never a command-line argument):

```sh
ferritor unseal          # once per share, until the threshold
ferritor status          # unsealed
```

Every restart starts sealed again and needs this step, unless the servers
unseal themselves (below). A load balancer's readiness check on
`ferritor.v1.SecretsService` (gRPC health) or `GET /v1/health` keeps a sealed
server out of rotation (see [operations](/operations/running)).

### Auto-unseal with AWS KMS (optional)

For servers that must come back without people (autoscaling, Kubernetes),
let them unseal themselves through AWS KMS
([key management](/operations/key-management#auto-unseal)). It puts the KMS
key's access control inside ferritor's trust boundary (see
[security](/concepts/security)), so set it up narrowly:

1. **A symmetric key** (`SYMMETRIC_DEFAULT`, `ENCRYPT_DECRYPT`) for ferritor
   alone, in an account separate from the databases' backups if you can.
   Refer to it by its **key ARN**, not an alias.
2. **A role for the servers**, never long-lived access keys: an EC2
   instance profile, EKS Pod Identity or IRSA. In the key's policy, only
   these, for that role:

   ```json
   {
     "Effect": "Allow",
     "Principal": {"AWS": "arn:aws:iam::111122223333:role/ferritor-server"},
     "Action": ["kms:Encrypt", "kms:Decrypt"],
     "Resource": "*",
     "Condition": {
       "StringEquals": {
         "kms:EncryptionContext:ferritor:purpose": "root-key",
         "aws:SourceVpce": "vpce-0123456789abcdef0"
       }
     }
   }
   ```

   plus `kms:DescribeKey` for the same role. The `aws:SourceVpce` (or
   `aws:SourceVpc`) condition is optional hardening: with the servers
   reaching KMS through an interface VPC endpoint, stolen role credentials
   are useless from anywhere else. Servers in private subnets without
   internet access need that endpoint anyway. With its private DNS on (the
   default) the region's usual KMS name resolves to it inside the VPC, so
   `[seal.awskms] endpoint` stays unset; without the condition, the public
   endpoint works as is. No broad `kms:*` admin role on
   this key: whoever may change its policy may grant themselves `Decrypt`.
3. **`[seal]`** in every server's config (the same on each), then a rekey to
   store the first wrap if the deployment started under Shamir:
   `ferritor unseal` with the shares, `ferritor rekey start …` (see key
   management). A new deployment just runs `ferritor init` with `[seal]`
   already set.
4. **Alarms on CloudTrail**: `Decrypt` from anywhere but the VPC endpoint,
   `Decrypt` more often than servers start, and any `Encrypt` outside a
   planned init or rekey.

> [!IMPORTANT]
> Keep the recovery shares exactly as carefully as before: they unseal
> without KMS, and they're the way in if the KMS key is lost.

### Auto-unseal with Google Cloud KMS (optional)

The same with Google Cloud KMS (`provider = "gcpkms"`), instead of AWS:
one provider at a time. The same trust applies: whoever can use the key
and read the keys database has the root key.

1. **A symmetric key** for ferritor alone, in its own key ring, ideally in
   a project of its own, separate from the databases' backups. Protection
   level `hsm` keeps it in an HSM; a destruction delay leaves time to undo
   a mistake:

   ```sh
   gcloud kms keyrings create ferritor --location asia-southeast1 --project my-project
   gcloud kms keys create root-key --keyring ferritor --location asia-southeast1 \
     --project my-project --purpose encryption --protection-level hsm \
     --destroy-scheduled-duration 30d
   ```

   `[seal.gcpkms] key_name` is its resource name,
   `projects/my-project/locations/asia-southeast1/keyRings/ferritor/cryptoKeys/root-key`.
2. **An identity for the servers**, never a key file if you can avoid it:
   GKE Workload Identity, or the VM's service account. Grant it
   `roles/cloudkms.cryptoKeyEncrypterDecrypter` on **this key only**, never
   on the key ring or the project:

   ```sh
   gcloud kms keys add-iam-policy-binding root-key --keyring ferritor \
     --location asia-southeast1 --project my-project \
     --member serviceAccount:ferritor-server@my-project.iam.gserviceaccount.com \
     --role roles/cloudkms.cryptoKeyEncrypterDecrypter
   ```

   With GKE Workload Identity, the member can be the server's Kubernetes
   service account itself:
   `principal://iam.googleapis.com/projects/<project-number>/locations/global/workloadIdentityPools/my-project.svc.id.goog/subject/ns/<namespace>/sa/<service-account>`.
   ferritor reads no key metadata, so no other role is needed. IAM can't
   require ferritor's additional authenticated data, so the role is the
   whole restriction: keep the key for ferritor alone. Optional hardening:
   a VPC Service Controls perimeter around the project, so stolen
   credentials can't use the key from outside it (with a Private Service
   Connect endpoint, set `[seal.gcpkms] endpoint`). Keep `cloudkms.admin`
   on the key, and the right to impersonate the servers' service account
   (`roles/iam.serviceAccountTokenCreator`), away from everyone else: both
   lead to `decrypt`.
3. **`[seal]`** in every server's config, then `ferritor init`, or a rekey
   (`--seal gcpkms`) for a deployment that started under Shamir or another
   provider, as for AWS above.
4. **Cloud KMS's Data Access audit logs**, which are **off by default**:
   without them, a `decrypt` leaves no trace. Turn on `DATA_READ` and
   `DATA_WRITE` for `cloudkms.googleapis.com` (IAM & Admin, Audit Logs),
   then alert on `Decrypt` by any principal but the servers', on a
   `Decrypt` through impersonation (`serviceAccountDelegationInfo` set),
   on more `Decrypt`s than servers start, and on any `Encrypt` outside a
   planned init or rekey. The entries are in Cloud Logging, under
   `cloudaudit.googleapis.com%2Fdata_access`, kept 30 days unless routed
   elsewhere.

## 8. The first namespace and secret

Nothing can be stored until a namespace exists: a secret's path starts with
its namespace, and each namespace has its own KEKs (see
[key management](/operations/key-management)).

```sh
ferritor namespace create billing --label team=payments
```

Then the application's access, as a stored policy. Keep the set in a file
under version control and apply it whole (`--dry-run` shows the change
first; see [policy](/guides/policy)):

```toml
# policies.toml
[[policy]]
name = "apps/billing"
identity = "apps/billing"
actions = ["read", "write", "list"]
paths = ["billing"]
description = "the billing app: its own secrets"
```

```sh
ferritor policy apply -f policies.toml --dry-run
ferritor policy apply -f policies.toml
ferritor policy check --identity apps/billing --action read --path billing/db
```

The application, with its own certificate:

```sh
export FERRITOR_CERT=apps-billing.pem FERRITOR_KEY=apps-billing-key.pem
printf 's3cret' | ferritor put billing/db
ferritor get billing/db

# or the JSON API, on the same port (value in base64):
curl --cacert server-ca.pem --cert apps-billing.pem --key apps-billing-key.pem \
  https://ferritor.example.internal:7070/v1/secrets/billing/db
```

Its policy grants `billing` only: anything else, namespace management
included, is `PERMISSION_DENIED`. See [secrets](/guides/secrets) for versions,
check-and-set, delete and restore.

An application that reads its secrets from files rather than the API gets
them from [the agent](/guides/agent): `ferritor-agent` next to it, with a
certificate of its own (an identity granted `read` on exactly what it
renders), writing one file per secret into a memory-backed directory and
keeping them current; in Kubernetes, [the CSI provider](/guides/csi) does it once
per node for every pod, each with its own identity.

### Workloads without certificates (optional)

Workloads that already get a token from their platform (Kubernetes
service accounts, a CI system's OIDC tokens) can exchange it for a
certificate instead of being issued one ([workload identity](/guides/workload-identity)):

1. `ferritor identity init` once (an operator with `identity`, unsealed).
2. An `[identity]` section with the issuer and its mappings (the
   [configuration](/reference/configuration#identity)); for Kubernetes, its JWKS from
   `kubectl get --raw /openid/v1/jwks` into `jwks_file`, or its issuer's
   `jwks_url` if it's reachable. Open `listen_addr` (7071 in the example) to
   the workloads, restart, and send every server the same section.
3. Stored policies for the identities the mappings produce
   (`k8s-prod/billing/api`).
4. The workload: the agent with `token_file` and `exchange`, a projected
   token with audience `ferritor` ([agent](/guides/agent#kubernetes)); a CI job
   with `ferritor --token-file … --exchange …` or `ferritor login`.

## 9. Before going live

- **Audit log**: check it can be verified, e.g. after a restart:
  `ferritor audit verify --public-key audit.pub.pem < audit.log` (exit 0:
  every entry signed). Only a chain ending in a signed `chain_end` is
  proven.
- **Purge on a timer**: `ferritor purge` removes deleted versions past
  `purge_deleted_after_days`; it's safe to rerun or interrupt.
- **Certificates**: renew the server certificate before it expires (the
  `ferritor.server_certificate.expiry` gauge), then `systemctl reload ferritor`;
  keep client certificates short-lived or publish a CRL.
- **Metrics**: set `OTEL_EXPORTER_OTLP_ENDPOINT`, or `[metrics] exporter =
  "prometheus"` for a scrape ([configuration](/reference/configuration#metrics)),
  and alert on what
  [operations](/operations/running) lists (`ferritor.sealed`, `ferritor.kek.vanished`,
  `ferritor.audit.queue.depth`, the expiry gauges).
- **Rate limits**: on by default (calls in flight, per identity and per
  server). An application that runs many calls at once (a batch job, a
  fleet behind one identity) needs an entry of its own under
  `[[rate_limit.identity]]`: see [operations](/operations/running#rate-limits)
  for sizing, and alert on `ferritor.rate_limit.refused`.
- **Backups and failover**: take a first pair of backups, in the right
  order, and test a restore ([backup and restore](/operations/backup-restore)); with
  replication, read [high availability](/operations/high-availability), including
  what to do after a failover.
- **Key rotation**: `ferritor rotate --namespace billing`, then `ferritor rewrap`
  once every server has refreshed (see [key management](/operations/key-management)).
  With workload identity, `ferritor identity rotate` before the issuing CA's
  expiry (`ferritor identity status`), and know the emergency steps
  ([revoking](/guides/workload-identity#revoking)).
- **Policies from a source of truth**: apply `policies.toml` from CI with
  `--prune`, so the stored set is always what's reviewed; after restoring
  the keys database, re-apply it before routing traffic
  ([backup and restore](/operations/backup-restore)). Alert on `ferritor.policy.revision`
  differing between servers, and on `policy_reload` audit entries with
  result `integrity` or `rollback`.
