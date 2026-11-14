---
title: 'The CSI provider'
description: 'Secrets as files in Kubernetes pods through the Secrets Store CSI Driver, one provider per node, each pod reading with its own identity.'
seo:
  title: 'The ferritor CSI provider: secrets as files in pods'
---

`ferritor-csi-provider` is a provider for the Kubernetes [Secrets Store CSI
Driver](https://secrets-store-csi-driver.sigs.k8s.io/): a pod mounts a
volume and finds in it one file per secret its workload may read, kept
current. One provider per node serves every pod on it, instead of an
[agent](/guides/agent) per pod, and each pod's secrets are still read with that
pod's own identity, from its own service account token ([workload
identity](/guides/workload-identity)).

```
/var/secrets/
  db-password        the value, byte for byte
  tls/cert
```

The driver does the Kubernetes part (the volume in the pod spec, a tmpfs
per volume, the pod's token, refreshing); the provider is a gRPC service on
a node-local socket, handed a volume's parameters and the pod's token,
returning the files, which the driver writes into the volume (atomically,
as Kubernetes writes Secret volumes: `..data` swapped onto a new
directory).

## Whose identity reads

**The pod's**, never the node's:

1. The driver's `CSIDriver` asks the kubelet for a token per mount with
   audience `ferritor` (on Kubernetes 1.35 and later its chart has the kubelet
   pass it as a mount secret; the driver hands it over the same way).
2. The provider exchanges it for a short-lived certificate ([workload
   identity](/guides/workload-identity)): the cluster's issuer maps the token's
   namespace and service account to the identity,
   `k8s-prod/<namespace>/<serviceaccount>`.
3. It reads with that certificate. Stored policies, rate limits and the
   audit log see the workload.

A provider reading with one identity of its own would need `read` on every
secret any pod might mount: a compromised node would expose every
workload's, and the audit log would show the node. As it is, a compromised
node exposes what the pods on it may read, and their tokens: what
Kubernetes Secrets mounted there, or an agent per pod, would expose too.

## The volume

```yaml
apiVersion: secrets-store.csi.x-k8s.io/v1
kind: SecretProviderClass
metadata:
  name: billing-api
  namespace: billing
spec:
  provider: ferritor
  parameters:
    prefix: "billing/api"          # every secret below it, a file each
    # or, instead of prefix, exactly these (a JSON list):
    # objects: |
    #   [{"path": "billing/api/db-password"},
    #    {"path": "billing/shared/redis-password", "file": "redis-password"}]
    # onRevoked: "keep"            # or "remove" (below)
    # filePermission: "0440"       # default: the driver's (0644)
---
# in the pod spec
volumes:
  - name: secrets
    csi:
      driver: secrets-store.csi.k8s.io
      readOnly: true
      volumeAttributes:
        secretProviderClass: billing-api
containers:
  - name: api
    volumeMounts:
      - name: secrets
        mountPath: /var/secrets
        readOnly: true
```

| Parameter | Default | |
|---|---|---|
| `prefix` | | every live secret below it; the file is the path below the prefix (`billing/api/tls/cert` → `tls/cert`, a subdirectory). Needs `list` on the prefix and `read` |
| `objects` | | instead of `prefix`: a JSON list of `{"path": …, "file": …}`; `file` defaults to the path's last segment; two objects naming one file are refused. Needs `read` only |
| `onRevoked` | `keep` | a secret refused for good after it was delivered: `keep` its last value, or `remove` its file |
| `filePermission` | the driver's, `0644` | every file's mode, octal. A stricter one only if the files' owner or group is the pod's: the driver writes them as root, and applies the pod's `fsGroup` only if its `CSIDriver` says so |

Anything else is refused, as is a parameter misspelled; so are objects
naming a file starting with `..` (the driver's own names), or one file
that would also be another's directory (`a` and `a/b`).

Below a `prefix`, names come from whoever writes there, so a bad one skips
that secret, never the volume (one put mustn't stop every pod mounting the
prefix from starting): a secret whose name starts with `..`, and of two
that would be a file and a directory at once (`tls` and `tls/cert`) the
one the volume doesn't have yet (on a first mount, the deeper). Each is
logged with its path; rename it.

- **One file per secret**, its content the value's bytes, nothing added.
- **`prefix` means every secret below it**: one listing (one call and one
  audited decision per page of 1,000), then a read for each secret whose
  version moved, so a new secret below the prefix appears at the next
  refresh. Keep a workload's secrets below a prefix of their own
  (`billing/api/…`, not all of `billing`).
- **A set, swapped atomically.** A reader that resolves the directory once
  sees one set; reading files one after another by their visible names can
  mix two refreshes ([the agent's](/guides/agent#the-directory) caveat).
- **The `SecretProviderClass` can't widen anything**: it's the workload
  team's, in their namespace, but reads use the pod's identity, so naming
  a path it may not read just fails.
- **Limits**: at most `max_volume_bytes` (just under 4 MiB, the driver's
  default gRPC limit) per volume; split a larger one. A volume can't be
  empty: the driver writes nothing for no files, so a prefix with nothing
  below it fails the mount.

## Refreshing

With rotation on, the kubelet calls the driver again (`requiresRepublish`)
and the driver calls the provider at most every `rotationPollInterval` (2
minutes by default). That interval is a minimum: the kubelet republishes on
its own period, about a minute, so a change arrives within roughly the
larger of the two plus a minute (80 s with a 30 s interval, in k3s). The
provider returns the whole set every time (the driver writes what it's
given), reading only what moved:

- **`objects`**: a read per object;
- **`prefix`**: a listing, then a read only for what moved since this
  volume's last delivery.

**Reads are shared within an identity on the node**: the pods of one
identity ask for the same paths, so a read (and a listing) is reused by its
other pods for `share_reads_secs` (30). Ten replicas on a node, one read
instead of ten; the audit log records the identity reading once, which is
the truth (the same caller read the same secret), without saying which
replica. Never across identities: a pod is served only as the identity its
own token exchanged to, and each identity's reads are its own.

The kubelet mints a token per volume, and hands the driver the same one at
every republish until it ages (not a fresh one each time). The provider
remembers which identity a token exchanged to (by its SHA-256, until it
expires), so a refresh doesn't exchange again: an exchange per volume when
it's first mounted, and one per new token after. Concurrent mounts with
one token exchange it once. A certificate per identity is kept and renewed two thirds
into its life with a pod's token. A rollout of many pods of one identity
exchanges each new token: raise the issuer's `exchange_burst` to the
replica count ([workload identity](/guides/workload-identity#the-exchange)).

**A watch stream per identity** (unless `watch = false`) keeps those reads
valid past `share_reads_secs`: the provider opens a
[watch stream](/guides/secrets#watching) for each identity with volumes on the
node, on its volumes' paths and prefixes, and a read or a listing made
while it's up stays in use until the stream says it changed (or a
`resync`, or the stream ends). So a refresh of an unchanged volume asks the
server nothing at all, however many pods and however often the driver
calls; a change costs one read (and a listing for a `prefix`) at the next
refresh, shared by the identity's pods. The stream needs what the volumes
need (`read` on each object, `list` on each prefix), checked and audited
when it opens; a refused path or prefix is left out of it. A stream that
ends (a seal, a revoked permission, the certificate expiring, the server
restarting) isn't opened again before `refusal_backoff_secs`, and until
one is up reads are shared for `share_reads_secs` only, as without a
watch. The watch doesn't make the files change sooner: the driver still
decides when it asks (above); it makes asking cheap. Its stream lives as
long as the identity has volumes on the node, and counts toward the
identity's `max_watch_streams` on its server (256 by default, so an
identity on more nodes than that per server needs it raised:
[configuration](/reference/configuration)).

## Failures

The [agent's rules](/guides/agent#failures), adapted to the driver:

- **Transient** (unreachable, `UNAVAILABLE`, sealed, the stored policies
  unverified, rate-limited, an exchange that didn't answer): the mount
  fails as `FAILED_PRECONDITION`. On a refresh the driver leaves the volume
  as it is; on a first mount the pod waits in `ContainerCreating` and the
  kubelet retries (from half a second, doubling). Never `UNAVAILABLE`: the
  driver's client retries that within the call (three attempts, a second
  apart), which stretches a failing first mount until the kubelet's next
  call overlaps it, finds the volume mounted, and has its error masked as a
  remount's: the pod then starts with an **empty** volume (seen in a
  cluster, and the driver's own workaround for kubernetes#121271). A
  provider of another kind returning `UNAVAILABLE` does this to its pods.
- **Authoritative** (`PERMISSION_DENIED`, `NOT_FOUND`, a namespace gone, a
  path gone from its listing): on a refresh, `onRevoked`: `keep` returns
  the last value delivered (kept per volume, in memory), `remove` leaves
  its file out. On a first mount, the mount fails (`PERMISSION_DENIED`)
  until it's readable. A volume whose every secret is refused stays as it
  is: the driver can't empty one. As with the agent, revoking access
  doesn't take back a value already delivered.
- **Remembered.** The kubelet retries a failed first mount quickly, and a
  rollout starts every replica at once: fifty pods retrying a denied path
  would drain their identity's shared denial budget, after which the
  server refuses its allowed reads too. So the provider remembers an
  authoritative refusal per identity and path (and per token, for a token
  the exchange refused) and answers retries from memory for
  `refusal_backoff_secs` (120), doubling to ten times it: the server sees
  one try per step per node, however many pods and retries.
- **A provider restart** forgets the kept values, the remembered refusals
  and the certificates; the volumes stay as written (they're in the pods'
  tmpfs), and the next refresh reads everything again. The driver never
  says a volume is gone, so the provider forgets one not refreshed for
  `forget_volumes_after_secs` (an hour), its values with it.

## Running it

**Prerequisites**:

- the Secrets Store CSI Driver, with rotation on and a token request for
  ferritor's audience; with its Helm chart:

  ```sh
  helm install csi-secrets-store secrets-store-csi-driver/secrets-store-csi-driver \
    --namespace kube-system \
    --set enableSecretRotation=true \
    --set rotationPollInterval=2m \
    --set 'tokenRequests[0].audience=ferritor'
  ```

  (the chart sets `requiresRepublish` on the `CSIDriver` with rotation);
- an `[[identity.issuer]]` for the cluster on the ferritor servers, mapping
  namespace and service account to identities ([workload
  identity](/guides/workload-identity#setting-it-up)), the exchange listener reachable
  from the nodes;
- stored policies granting those identities their paths (`read`, and
  `list` for a `prefix`);
- the provider's image: a release's,
  `ghcr.io/ferritor/ferritor-csi-provider:<version>`, or your own, built
  with the repository's `Dockerfile` (`docker build --target
  csi-provider`, see [development](/contributing/development#images)) and
  pushed where the nodes pull from: below,
  `registry.example/ferritor-csi-provider`.

**The provider**, a DaemonSet on every node that runs pods with ferritor
volumes:

```toml
# /etc/ferritor-csi-provider/config.toml (a ConfigMap)
server = "https://ferritor.internal:7070"
ca = "/etc/ferritor-csi-provider/ca.pem"              # verifies the server and its exchange
exchange = "https://ferritor.internal:7071"           # [identity] listen_addr
# socket = "/var/run/secrets-store-csi-providers/ferritor.sock"
# audience = "ferritor"                               # the CSIDriver's token request
# share_reads_secs = 30                            # 0: every pod reads for itself; at most 600
# refusal_backoff_secs = 120                       # 5 to 86400
# forget_volumes_after_secs = 3600                 # at least 600
# max_volume_bytes = 4128768                       # 1024 to 67108864
# watch = true                                    # a watch stream per identity (Refreshing)
# [metrics]                                       # (Metrics, below)
# exporter = "prometheus"                         # otlp, prometheus or none
# listen_addr = "127.0.0.1:9466"
# tls = false                                     # required off loopback: plaintext
```

```yaml
apiVersion: apps/v1
kind: DaemonSet
metadata:
  name: ferritor-csi-provider
  namespace: kube-system
spec:
  selector:
    matchLabels: {app: ferritor-csi-provider}
  template:
    metadata:
      labels: {app: ferritor-csi-provider}
    spec:
      automountServiceAccountToken: false     # it reads with the pods' identities, never its own
      containers:
        - name: provider
          image: registry.example/ferritor-csi-provider
          args: ["--config", "/etc/ferritor-csi-provider/config.toml"]
          securityContext:
            runAsUser: 0                      # the driver's socket directory is root's
            allowPrivilegeEscalation: false
            readOnlyRootFilesystem: true
            capabilities: {drop: ["ALL"]}
          volumeMounts:
            - {name: providers, mountPath: /var/run/secrets-store-csi-providers}
            - {name: config, mountPath: /etc/ferritor-csi-provider, readOnly: true}
      volumes:
        - name: providers
          hostPath:
            path: /var/run/secrets-store-csi-providers
            type: DirectoryOrCreate
        - name: config
          configMap: {name: ferritor-csi-provider}
```

Logs go to stderr (`FERRITOR_CSI_PROVIDER_LOG`, an `EnvFilter`, default
`info`): pods, identities, paths and refusals, never a token or a value.
Like the server and the agent, it marks itself undumpable before reading
anything.

## Metrics

The provider's metrics leave it as the agent's and the server's do
([agent](/guides/agent#metrics), [running](/operations/running#metrics)),
chosen by `[metrics] exporter`: `otlp` (the standard `OTEL_*` variables;
`OTEL_SERVICE_NAME` defaults to `ferritor-csi-provider`), `prometheus` or
`none`; without the section, OTLP if `OTEL_EXPORTER_OTLP_ENDPOINT` is
set, off otherwise. Read at startup.

The Prometheus endpoint is plaintext: on `127.0.0.1:9466` by default
(answering only requests addressed to loopback), anywhere else only with
`tls = false` said, which warns at startup. For Prometheus in the cluster
to scrape it on the pod's address, listen on `0.0.0.0:9466` with
`tls = false`, and give the container that port. What it shows is counts,
times and results: no pod, identity, path or file name, and nothing of a
token or value.

Request durations are bucketed from 1 ms to 10 s. A test holds the table
to what a scrape returns.

| Instrument | Prometheus | Kind | Attributes |
|---|---|---|---|
| `ferritor.csi.mounts` | `ferritor_csi_mounts_total` | counter | `result` (ok, refused, failed: transient, the volume as it is; invalid: the `SecretProviderClass`) |
| `ferritor.csi.mount.duration` | `ferritor_csi_mount_duration_seconds` | histogram (s) | `result` |
| `ferritor.csi.calls` | `ferritor_csi_calls_total` | counter | `call` (get, list, watch), `result` (ok, permission_denied, not_found, invalid, transient) |
| `ferritor.csi.from_memory` | `ferritor_csi_from_memory_total` | counter | `kind` (read, listing: shared, or vouched for by a watch; refusal: remembered, backing off): answered without the server |
| `ferritor.csi.exchanges` | `ferritor_csi_exchanges_total` | counter | `result` (issued, refused, failed): pods' tokens, renewals included |
| `ferritor.csi.watch.events` | `ferritor_csi_watch_events_total` | counter | `event` (ready, changed, resync, ended, failed) |
| `ferritor.csi.identities` | `ferritor_csi_identities` | gauge | identities with a certificate on this node |
| `ferritor.csi.volumes` | `ferritor_csi_volumes` | gauge | volumes remembered |
| `ferritor.csi.watch.streams` | `ferritor_csi_watch_streams` | gauge | identities' watch streams open and ready |

Worth an alert: `ferritor_csi_mounts_total{result="failed"}` rising (pods
waiting on a server they can't reach, or a sealed one), and
`{result="refused"}` after a policy change.

## Security

- **What it holds**, per node, in memory only: each pod's token while it
  exchanges it (and the token's SHA-256 afterwards), a certificate and key
  per identity on the node until it expires, and the values of the volumes
  it serves (to keep them on a refusal, and to return the files a refresh
  doesn't read again). The values are wiped when the last holder drops
  them; the gRPC and TLS buffers aren't ([security](/concepts/security), gap 3).
  It never logs a token or a value.
- **Its socket is the boundary**: whatever reaches it can ask for any
  volume, with any token it holds. It's created mode `0600` (under a umask
  of `077`, so never otherwise, even for a moment) in the host directory
  only the driver mounts (`/var/run/secrets-store-csi-providers`, the
  chart's, root's; the driver also looks in
  `/etc/kubernetes/secrets-store-csi-providers`); no workload may mount
  that directory.
- **Don't sync to Kubernetes Secrets.** The driver can copy mounted files
  into Kubernetes `Secret` objects (`secretObjects` in the
  `SecretProviderClass`), which puts the values in etcd, readable by
  anyone who may read Secrets in the namespace, outside ferritor's audit log.
  The provider can't see or stop it (the driver doesn't pass it on), so
  don't enable it, and keep it out of `SecretProviderClass`es by admission
  policy.
- **The files in the pod** are what any file delivery gives: readable by
  whatever runs in the pod with the right user (the driver's `0644` by
  default: any user in the pod), in a tmpfs (memory; swap only if the node
  swaps, which Kubernetes nodes usually don't).

## Tried in a cluster

Run end to end in k3s (v1.32.5, through k3d) with the driver's chart
1.6.1 (rotation on, a token request for `ferritor`), a ferritor server and its
database in the cluster, and the provider as a DaemonSet: a pod mounting a
`prefix` volume (with a subdirectory) and an `objects` volume, read by a
non-root user at the driver's `0644`; a new version and a new secret
arriving at a refresh; a denied path keeping its pod in
`ContainerCreating`, the server asked once through the kubelet's retries;
a sealed server leaving running pods' volumes as they were and new pods
waiting, until unsealed; a grant revoked, the value kept (`keep`); a
provider restart, the volumes unchanged. It found the empty-volume
masking above, the per-volume tokens, the refresh latency, and the
chart's provider directory. The provider's own tests drive it over its
socket with requests as the driver builds them, against a real ferritor
server; the cluster run is automated, in CI on every change
([development](/contributing/development#the-csi-provider-in-a-cluster)).

## Later

- Refreshing on change: the driver asks the provider on its own interval,
  so a change the watch has heard still waits for the next refresh. Files
  rewritten the moment a secret changes would need the provider to write
  into the pods' volumes itself, outside the driver.
- Environment variables don't apply: a volume, not a process.
