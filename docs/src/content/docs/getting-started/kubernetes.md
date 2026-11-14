---
title: 'Kubernetes'
description: 'ferritor, its databases and the CSI provider in a Kubernetes cluster, with pods reading their secrets as files under their service accounts'' identities.'
seo:
  title: 'Running ferritor and its CSI provider in Kubernetes'
---

From an empty cluster to a pod reading its secrets as files, with no
certificate issued to the application: ferritor and its two databases in the
cluster, the cluster's service account tokens trusted for [workload
identity](/guides/workload-identity), and the [CSI
provider](/guides/csi) mounting each pod's secrets with that pod's own
identity. The [production deployment](/getting-started/production) guide
explains each piece in more depth (certificates, roles, the first init);
this page is the Kubernetes way to put them together. Tried end to end
in k3s; adjust names, images and storage to your cluster.

```
operator (ferritor CLI, port-forward) ──► ferritor ──► keys-db, data-db (namespace ferritor-system)
                                         ▲
                                         │ token exchange, then mTLS as the pod's identity
pod ── CSI volume ── Secrets Store CSI Driver ── ferritor-csi-provider (DaemonSet, per node)
```

## What you need

- `kubectl` and `helm` for the cluster, `openssl` for the PKI, and the
  `ferritor` CLI on your machine.
- The images: each release's, `ghcr.io/ferritor/ferritor-server:<version>`
  and `ghcr.io/ferritor/ferritor-csi-provider:<version>` (amd64 and arm64),
  signed with cosign, keyless, by the release workflow. Verify one before
  you trust it (cosign 3), and deploy it by the digest that verified:

  ```sh
  cosign verify ghcr.io/ferritor/ferritor-server:0.9.2 \
    --certificate-identity https://github.com/ferritor/ferritor/.github/workflows/release-plz.yml@refs/heads/main \
    --certificate-oidc-issuer https://token.actions.githubusercontent.com
  ```

  It succeeds only for an image that workflow, on `main`, built and
  signed ([security](/concepts/security)). Or use your own images, built
  with the repository's `Dockerfile`
  ([development](/contributing/development#images)) and pushed to a
  registry the cluster pulls from:

  ```sh
  docker build --target server -t registry.example/ferritor-server .
  docker build --target csi-provider -t registry.example/ferritor-csi-provider .
  docker push registry.example/ferritor-server
  docker push registry.example/ferritor-csi-provider
  ```

  Below they're `registry.example/ferritor-server` and
  `registry.example/ferritor-csi-provider`.
- Operators to hold the unseal shares: the server starts **sealed** after
  every restart, and serves nothing until a threshold of shares unseals it.

Everything below goes in a namespace of its own:

```sh
kubectl create namespace ferritor-system
```

## 1. Databases

Two Postgres, the keys database and the data database, each alone useless
(wrapped keys, never usable ones). For a first try, two small StatefulSets;
in production, databases with backups and synchronous replication
([high availability](/operations/high-availability), [backup and
restore](/operations/backup-restore)): losing the keys database loses
every secret.

```yaml
# databases.yaml
apiVersion: apps/v1
kind: StatefulSet
metadata: {name: keys-db, namespace: ferritor-system}
spec:
  serviceName: keys-db
  selector: {matchLabels: {app: keys-db}}
  template:
    metadata: {labels: {app: keys-db}}
    spec:
      containers:
        - name: postgres
          image: docker.io/library/postgres:18
          env:
            - {name: POSTGRES_USER, value: ferritor_keys}
            - {name: POSTGRES_DB, value: ferritor_keys}
            - name: POSTGRES_PASSWORD
              valueFrom: {secretKeyRef: {name: ferritor-db, key: keys-password}}
            - {name: PGDATA, value: /var/lib/postgresql/data/pgdata}
          volumeMounts: [{name: data, mountPath: /var/lib/postgresql/data}]
  volumeClaimTemplates:
    - metadata: {name: data}
      spec:
        accessModes: [ReadWriteOnce]
        resources: {requests: {storage: 1Gi}}
---
apiVersion: v1
kind: Service
metadata: {name: keys-db, namespace: ferritor-system}
spec:
  selector: {app: keys-db}
  ports: [{port: 5432}]
---
apiVersion: apps/v1
kind: StatefulSet
metadata: {name: data-db, namespace: ferritor-system}
spec:
  serviceName: data-db
  selector: {matchLabels: {app: data-db}}
  template:
    metadata: {labels: {app: data-db}}
    spec:
      containers:
        - name: postgres
          image: docker.io/library/postgres:18
          env:
            - {name: POSTGRES_USER, value: ferritor_data}
            - {name: POSTGRES_DB, value: ferritor_data}
            - name: POSTGRES_PASSWORD
              valueFrom: {secretKeyRef: {name: ferritor-db, key: data-password}}
            - {name: PGDATA, value: /var/lib/postgresql/data/pgdata}
          volumeMounts: [{name: data, mountPath: /var/lib/postgresql/data}]
  volumeClaimTemplates:
    - metadata: {name: data}
      spec:
        accessModes: [ReadWriteOnce]
        resources: {requests: {storage: 1Gi}}
---
apiVersion: v1
kind: Service
metadata: {name: data-db, namespace: ferritor-system}
spec:
  selector: {app: data-db}
  ports: [{port: 5432}]
```

```sh
kubectl -n ferritor-system create secret generic ferritor-db \
  --from-literal=keys-password="$(openssl rand -hex 24)" \
  --from-literal=data-password="$(openssl rand -hex 24)"
kubectl apply -f databases.yaml
```

A role and a password per database, never one for both: one leaked URL
isn't both databases. `POSTGRES_USER` is a superuser here, for a first
try; in production, a role that owns only its database
([production](/getting-started/production#2-databases)).

## 2. Certificates and keys

A CA for the server's certificate and the operators' client certificates
(the [production deployment
guide](/getting-started/production#3-certificates) explains the
requirements and keeps the two CAs apart; one is enough to try it). The
server's certificate names the Service, and `localhost` for the
port-forward:

```sh
mkdir ferritor-pki && cd ferritor-pki
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -days 365 \
  -keyout ca-key.pem -out ca.pem -subj /CN=ferritor-ca

openssl req -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes \
  -keyout server-key.pem -out server.csr -subj /CN=ferritor
printf 'subjectAltName=DNS:ferritor.ferritor-system.svc,DNS:localhost\nextendedKeyUsage=serverAuth\n' > server.ext
openssl x509 -req -in server.csr -CA ca.pem -CAkey ca-key.pem -CAcreateserial \
  -days 90 -extfile server.ext -out server.pem

# an operator: the identity is the ferritor:// URI SAN
openssl req -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes \
  -keyout alice-key.pem -out alice.csr -subj /CN=alice
printf 'subjectAltName=URI:ferritor://ops/alice\nextendedKeyUsage=clientAuth\n' > alice.ext
openssl x509 -req -in alice.csr -CA ca.pem -CAkey ca-key.pem -CAcreateserial \
  -days 30 -extfile alice.ext -out alice.pem

# signs the audit log's checkpoints; give audit.pub.pem to whoever verifies it
openssl genpkey -algorithm ed25519 -out audit-key.pem
openssl pkey -in audit-key.pem -pubout -out audit.pub.pem
```

Keep `ca-key.pem` off the cluster. The cluster's service account keys,
for the token exchange:

```sh
kubectl get --raw /.well-known/openid-configuration   # "issuer": the tokens' iss
kubectl get --raw /openid/v1/jwks > jwks.json
```

The issuer is usually `https://kubernetes.default.svc.cluster.local`;
use whatever it says. A file, not `jwks_url`: the API server's JWKS
endpoint needs authentication by default. When the cluster rotates its
service account keys, fetch the file again and update the Secret below.

## 3. The server

`ferritor.toml` (every setting: [configuration](/reference/configuration)):

```toml
listen_addr = "0.0.0.0:7070"
keys_database_url = "postgres://ferritor_keys:KEYS_PASSWORD@keys-db.ferritor-system.svc:5432/ferritor_keys"
data_database_url = "postgres://ferritor_data:DATA_PASSWORD@data-db.ferritor-system.svc:5432/ferritor_data"
audit_signing_key = "/etc/ferritor/audit-key.pem"
shutdown_delay_secs = 5          # endpoints drop the pod before it stops listening

[tls]
cert = "/etc/ferritor/server.pem"
key = "/etc/ferritor/server-key.pem"
client_ca = "/etc/ferritor/ca.pem"

[[policy]]
name = "operators"
identity = "ops/alice"
actions = ["status", "init", "unseal", "seal", "rekey", "rotate", "rewrap", "purge", "destroy_kek", "namespace", "policy", "identity"]

# Workload identity: the cluster's service account tokens.
[identity]
listen_addr = "0.0.0.0:7071"

[[identity.issuer]]
name = "k8s"                     # every identity it maps to starts with k8s/
issuer = "https://kubernetes.default.svc.cluster.local"
audience = "ferritor"
jwks_file = "/etc/ferritor/jwks.json"

[[identity.issuer.map]]
identity = "k8s/{kubernetes.io.namespace}/{kubernetes.io.serviceaccount.name}"
```

The database passwords are the ones in the `ferritor-db` Secret
(`kubectl -n ferritor-system get secret ferritor-db -o jsonpath='{.data.keys-password}' | base64 -d`);
`FERRITOR_KEYS_DATABASE_URL` and `FERRITOR_DATA_DATABASE_URL` in the environment
override the file, if you'd rather keep them apart. Everything the server
reads goes in one Secret:

```sh
kubectl -n ferritor-system create secret generic ferritor-server \
  --from-file=ferritor.toml --from-file=server.pem --from-file=server-key.pem \
  --from-file=ca.pem --from-file=audit-key.pem --from-file=jwks.json
```

```yaml
# server.yaml
apiVersion: apps/v1
kind: Deployment
metadata: {name: ferritor, namespace: ferritor-system}
spec:
  replicas: 1
  strategy: {type: Recreate}           # each new server starts sealed: see below
  selector: {matchLabels: {app: ferritor}}
  template:
    metadata: {labels: {app: ferritor}}
    spec:
      automountServiceAccountToken: false
      # The default 30 s covers the delay (5), the drain (at most 15) and
      # the audit log's flush (at most 5).
      containers:
        - name: ferritor
          image: registry.example/ferritor-server
          workingDir: /etc/ferritor           # reads ferritor.toml from here
          ports:
            - {name: api, containerPort: 7070}
            - {name: exchange, containerPort: 7071}
          # Every connection needs a client certificate, which probes don't
          # have: a TCP check only. A sealed server passes it too.
          livenessProbe: {tcpSocket: {port: api}, periodSeconds: 20}
          readinessProbe: {tcpSocket: {port: api}, periodSeconds: 5}
          securityContext:
            runAsNonRoot: true
            runAsUser: 10001
            allowPrivilegeEscalation: false
            readOnlyRootFilesystem: true
            capabilities: {drop: ["ALL"]}
          volumeMounts:
            - {name: config, mountPath: /etc/ferritor, readOnly: true}
      volumes:
        - name: config
          secret: {secretName: ferritor-server, defaultMode: 0440}
      securityContext: {fsGroup: 10001}  # the files' group: the server reads them as it
---
apiVersion: v1
kind: Service
metadata: {name: ferritor, namespace: ferritor-system}
spec:
  selector: {app: ferritor}
  ports:
    - {name: api, port: 7070}
    - {name: exchange, port: 7071}
```

```sh
kubectl apply -f server.yaml
kubectl -n ferritor-system logs deploy/ferritor    # both streams: the audit log (stdout) and logs (stderr)
```

The Secret's files are root's, readable by the pod's `fsGroup`, so the
server warns at startup that the audit signing key is group-readable: here
the group is the pod's own, no one else's.

The audit log is the container's stdout: ship it off the cluster as it's
written, the stdout stream alone (log collectors read the kubelet's log
files, where every line says its stream), and verify it with `ferritor audit
verify --public-key audit.pub.pem` ([audit](/operations/audit)). `kubectl logs`
interleaves stderr with it, which the verifier reports as a broken chain;
for a quick look, keep the JSON lines (`kubectl logs deploy/ferritor | grep
'^{'`). The server marks
itself undumpable; nodes should run without swap, as Kubernetes nodes
usually do.

## 4. Init, unseal, the issuing CA

From your machine, through a port-forward, as the operator:

```sh
kubectl -n ferritor-system port-forward svc/ferritor 7070:7070 &
export FERRITOR_ADDR=https://localhost:7070 FERRITOR_CA=$PWD/ca.pem \
       FERRITOR_CERT=$PWD/alice.pem FERRITOR_KEY=$PWD/alice-key.pem

ferritor init --shares 5 --threshold 3 > shares.txt   # shown once
ferritor unseal                                      # three times, one share each, by their holders
ferritor identity init                               # the CA that signs the pods' certificates
ferritor namespace create billing
```

> [!CAUTION]
> Hand each share in `shares.txt` to its holder, then delete the file:
> five shares in one file on one machine are the root key
> ([production](/getting-started/production#7-initialize-and-unseal)).

**After every restart of the pod** (a node drain, an upgrade, a crash) the
server is sealed again: three operators run `ferritor unseal` before anything
can read. Alert on `ferritor.sealed`
([operations](/operations/running#metrics)).

## 5. Access, and the first secret

The config rule above makes `ops/alice` an operator, which grants no secret
action: secrets are granted by stored policies, kept in a file under
version control and applied whole ([policy](/guides/policy)). A pod in
namespace `billing` running as service account `api` becomes
`k8s/billing/api`:

```toml
# policies.toml
[[policy]]
name = "billing-api"
identity = "k8s/billing/api"
actions = ["read", "list"]
paths = ["billing/api"]

[[policy]]
name = "billing-writer"
identity = "ops/alice"         # in practice a deploy pipeline's identity
actions = ["write"]
paths = ["billing"]
```

```sh
ferritor policy apply -f policies.toml --dry-run
ferritor policy apply --prune -f policies.toml
printf 's3cret' | ferritor put billing/api/db-password
```

Until a policy grants it something, a token buys a certificate that can do
nothing.

**Who can reach the exchange.** Port 7071 is a ClusterIP Service: every pod
in the cluster can call it, by design (it's how a pod gets its first
certificate). Only tokens with audience `ferritor` are accepted, so a pod's
default service account token (the API server's audience) is refused; but
any pod can ask the kubelet for a `ferritor` token for its own service
account, through a projected token volume. With no `require`, as here,
every service account in every namespace can get its
`k8s/<namespace>/<serviceaccount>` identity. Any pod can get its own
identity; policies decide what it's worth; `require` limits who can get
one at all (below).

## 6. The CSI driver and the provider

The Secrets Store CSI Driver, with rotation and a token request for
ferritor's audience:

```sh
helm repo add secrets-store-csi-driver https://kubernetes-sigs.github.io/secrets-store-csi-driver/charts
helm install csi-secrets-store secrets-store-csi-driver/secrets-store-csi-driver \
  --namespace kube-system \
  --set enableSecretRotation=true \
  --set rotationPollInterval=2m \
  --set 'tokenRequests[0].audience=ferritor'
```

The provider, one per node, with the server's CA and addresses:

```sh
kubectl -n ferritor-system create configmap ferritor-csi-provider \
  --from-file=ca.pem \
  --from-literal=config.toml='server = "https://ferritor.ferritor-system.svc:7070"
ca = "/etc/ferritor-csi-provider/ca.pem"
exchange = "https://ferritor.ferritor-system.svc:7071"
'
```

```yaml
# provider.yaml
apiVersion: apps/v1
kind: DaemonSet
metadata: {name: ferritor-csi-provider, namespace: ferritor-system}
spec:
  selector: {matchLabels: {app: ferritor-csi-provider}}
  template:
    metadata: {labels: {app: ferritor-csi-provider}}
    spec:
      automountServiceAccountToken: false   # it reads with the pods' identities, never its own
      containers:
        - name: provider
          image: registry.example/ferritor-csi-provider
          args: ["--config", "/etc/ferritor-csi-provider/config.toml"]
          securityContext:
            runAsUser: 0                    # the driver's socket directory is root's
            allowPrivilegeEscalation: false
            readOnlyRootFilesystem: true
            capabilities: {drop: ["ALL"]}
          volumeMounts:
            - {name: providers, mountPath: /var/run/secrets-store-csi-providers}
            - {name: config, mountPath: /etc/ferritor-csi-provider, readOnly: true}
      volumes:
        - name: providers
          hostPath: {path: /var/run/secrets-store-csi-providers, type: DirectoryOrCreate}
        - name: config
          configMap: {name: ferritor-csi-provider}
```

```sh
kubectl apply -f provider.yaml
kubectl -n ferritor-system logs ds/ferritor-csi-provider   # "serving the Secrets Store CSI Driver"
```

## 7. A pod reading its secrets

Two things are called `billing`, unrelated but named alike on purpose: the
ferritor namespace created in step 4 (the first segment of `billing/api/…`)
and the Kubernetes namespace the pod runs in (the `billing` of its
identity, `k8s/billing/api`).

```yaml
# app.yaml
apiVersion: v1
kind: ServiceAccount
metadata: {name: api, namespace: billing}
---
apiVersion: secrets-store.csi.x-k8s.io/v1
kind: SecretProviderClass
metadata: {name: billing-api, namespace: billing}
spec:
  provider: ferritor
  parameters:
    prefix: "billing/api"     # every secret below it, a file each
---
apiVersion: v1
kind: Pod
metadata: {name: api, namespace: billing}
spec:
  serviceAccountName: api
  containers:
    - name: api
      image: docker.io/library/busybox:1.37
      command: ["sleep", "infinity"]
      securityContext: {runAsUser: 1000}
      volumeMounts:
        - {name: secrets, mountPath: /var/secrets, readOnly: true}
  volumes:
    - name: secrets
      csi:
        driver: secrets-store.csi.k8s.io
        readOnly: true
        volumeAttributes: {secretProviderClass: billing-api}
```

```sh
kubectl create namespace billing     # Kubernetes' namespace; step 4's was ferritor's
kubectl apply -f app.yaml
kubectl -n billing exec api -- cat /var/secrets/db-password     # s3cret
```

A new version (`printf 'n3w' | ferritor put billing/api/db-password`)
reaches the file within a few minutes: the driver's interval, plus the
kubelet's own republish period. The server's audit log shows the exchange
(`"event": "exchange"`, identity `k8s/billing/api`) and the reads, as
`k8s/billing/api`.

If the pod stays in `ContainerCreating`, `kubectl -n billing describe pod
api` says why: a denied path (grant it), a sealed server (unseal it), a
token the issuer doesn't map. The pod never starts with an empty volume;
once it's readable, the next retry mounts it.

## Before going live

- **The databases**: backups in the right order, tested restores, and
  synchronous replication before running more than one server or failing
  over ([backup and restore](/operations/backup-restore), [high
  availability](/operations/high-availability)).
- **Unsealing**: who holds the shares, how they're reached after a restart,
  and an alert on `ferritor.sealed`. With several replicas each pod is
  unsealed on its own (`kubectl port-forward pod/<name>`, one at a time);
  every server issues and serves. **The Service routes to a sealed pod**:
  the TCP readiness probe passes while sealed (Kubernetes' probes can't
  present a client certificate, and the server answers nothing without
  one), so a restarted pod is back in the Service at once, and the
  requests that land on it get `SEALED` until it's unsealed. Clients must
  retry: the CSI provider does (a sealed answer is transient: a refresh
  leaves the volume as it is, a first mount waits, and the next try
  reconnects, likely to another pod), the agent backs off and retries, a
  script or an application of yours must too. Or keep it out of the
  Service until unsealed with an `exec` readiness probe that does present
  one, a probe identity's certificate mounted next to it, asking the
  health service for `ferritor.v1.SecretsService`, which is `NOT_SERVING`
  while sealed ([operations](/operations/running#health-and-readiness)); it
  needs a gRPC health client in the image.
- **Metrics**, for Prometheus (kube-prometheus-stack, the Prometheus
  Operator): a listener of its own, over TLS with the server's certificate
  (off loopback it always is), which only scrapers with a certificate from
  a CA of their own may read: any pod in the cluster can reach the port,
  and the metrics show the sealed state and the denial rates
  ([operations](/operations/running#metrics)). The scrapers' CA, and
  Prometheus's certificate from it:

  ```sh
  openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -days 365 \
    -keyout scrapers-ca-key.pem -out scrapers-ca.pem -subj /CN=ferritor-scrapers-ca
  openssl req -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes \
    -keyout prometheus-key.pem -out prometheus.csr -subj /CN=prometheus
  printf 'extendedKeyUsage=clientAuth\n' > prometheus.ext
  openssl x509 -req -in prometheus.csr -CA scrapers-ca.pem -CAkey scrapers-ca-key.pem \
    -CAcreateserial -days 90 -extfile prometheus.ext -out prometheus.pem
  ```

  `scrapers-ca.pem` goes into the `ferritor-server` Secret with the rest
  (another `--from-file`), and `ferritor.toml` gets:

  ```toml
  [metrics]
  exporter = "prometheus"
  listen_addr = "0.0.0.0:9464"
  client_ca = "/etc/ferritor/scrapers-ca.pem"
  ```

  The Deployment's container gets a port, `{name: metrics, containerPort:
  9464}`, and the Service the same, `{name: metrics, port: 9464}`, and
  `labels: {app: ferritor}` in its `metadata` for the `ServiceMonitor` to
  find it. Prometheus gets the server's CA in a ConfigMap and its own
  certificate in a Secret, never the `ferritor-server` Secret, which holds
  the server's key:

  ```sh
  kubectl -n ferritor-system create configmap ferritor-ca --from-file=ca.pem
  kubectl -n ferritor-system create secret generic ferritor-scraper \
    --from-file=tls.crt=prometheus.pem --from-file=tls.key=prometheus-key.pem
  ```

  ```yaml
  apiVersion: monitoring.coreos.com/v1
  kind: ServiceMonitor
  metadata:
    name: ferritor
    namespace: ferritor-system
    labels: {release: monitoring}   # kube-prometheus-stack's release name: it selects by it
  spec:
    selector: {matchLabels: {app: ferritor}}
    endpoints:
      - port: metrics
        scheme: https
        tlsConfig:
          ca: {configMap: {name: ferritor-ca, key: ca.pem}}
          cert: {secret: {name: ferritor-scraper, key: tls.crt}}
          keySecret: {name: ferritor-scraper, key: tls.key}
          serverName: ferritor.ferritor-system.svc
  ```

  `serverName` is a name in the server's certificate. kube-prometheus-stack
  picks up only the `ServiceMonitor`s labelled with its release's name
  (`monitoring` here, whatever `helm install` named it); installed with
  this setting, it picks up every one:
  `prometheus.prometheusSpec.serviceMonitorSelectorNilUsesHelmValues=false`.
  Keep `scrapers-ca-key.pem` off the cluster, like `ca-key.pem`. Then alert
  on `ferritor_sealed`, `ferritor_kek_vanished` and the rest of
  [operations](/operations/running#metrics)' list.
- **Certificates**: renew the server's (`ferritor.server_certificate.expiry`)
  and send SIGHUP, or restart and unseal; keep operators' short-lived.
- **The token exchange**: one issuer per cluster, mappings as narrow as
  the workloads, and `require` for the namespaces that may use ferritor at
  all (`require = [{ claim = "kubernetes.io.namespace", one_of =
  ["billing"] }]`): any pod can get its own identity, and without it every
  service account in the cluster does ([who can reach the
  exchange](#5-access-and-the-first-secret)). Set `exchange_burst` to your
  largest deployment's replica count ([workload
  identity](/guides/workload-identity)), and refresh `jwks.json` when the
  cluster rotates its service account keys.
- **The provider's socket directory** mounted by the driver and the
  provider only, and no `secretObjects` in any `SecretProviderClass`
  (they'd copy values into etcd): enforce both by admission policy
  ([CSI](/guides/csi#security)).
- **The checklist** in [security](/concepts/security#checklist).
