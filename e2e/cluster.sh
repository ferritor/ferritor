#!/usr/bin/env bash
# The CSI provider end to end in a real cluster (k3s, through k3d), with the
# Secrets Store CSI Driver: what the provider's own tests can't show, since
# they stand in for the driver and the kubelet (docs: development, "The CSI
# provider in a cluster"). A secured ferritor server and its database run in
# the cluster, the cluster's service account tokens trusted for workload
# identity; then pods mount volumes, and each check below must hold.
#
#   cargo build --release --locked -p ferritor-cli
#   e2e/cluster.sh                       # creates the cluster, deletes it at the end
#   KEEP=1 e2e/cluster.sh                # keeps it (and prints how to reach it)
#
# Needs k3d, kubectl, helm, openssl, and docker (or podman's docker). The
# server and the provider run from the images the Dockerfile builds (built
# here, then imported into the cluster); the CLI runs on this machine.
# Nothing here is fit for real secrets.
set -euo pipefail

root=$(cd "$(dirname "$0")/.." && pwd)
bin=${BIN:-$root/target/release}
cluster=${CLUSTER:-ferritor-e2e}
keep=${KEEP:-0}
api_port=${API_PORT:-27070}
exchange_port=${EXCHANGE_PORT:-27071}
# Pinned by digest (the tag only says what it was: a tag can move, and
# postgres:18 does with every minor release), so a new image changes
# nothing here unasked; the driver's chart by version. To update one, take
# the tag's current digest (the registry's Docker-Content-Digest for the
# tag's index) and run this again. Pulled anonymously from Docker Hub, whose
# pull limit is per IP address, shared by CI's runners: if that starts to
# bite, point these at a pull-through mirror.
k3s_image=docker.io/rancher/k3s:v1.32.5-k3s1@sha256:b75eac801bbc91b4584769c840f346683c7740d72f83e630088370f8e1eb2c8a
driver_chart=1.6.1
busybox=docker.io/library/busybox:1.37@sha256:bdf57e528e45e4433820e045b29b4597825a1c9e38353532d90a01445013f82e
postgres=docker.io/library/postgres:18@sha256:edb0c08dc33befd0262ab3b5cf1c4f3f8cfd8b09e88c05b45adee29d6761ddb6
server_image=localhost/ferritor-server:e2e
provider_image=localhost/ferritor-csi-provider:e2e

work=$(mktemp -d)
forwards=()

log() { printf '\n== %s\n' "$*"; }

diagnostics() {
  kubectl get pods -A -o wide || true
  for ns in billing ferritor-system; do
    kubectl -n "$ns" get events --sort-by=.lastTimestamp 2>/dev/null | tail -20 || true
  done
  kubectl -n ferritor-system logs ds/ferritor-csi-provider --tail=40 2>/dev/null || true
  kubectl -n ferritor-system logs ferritor --tail=40 2>/dev/null | grep -v '^{' || true
}

fail() {
  printf '::error::e2e: %s\n' "$*" >&2
  diagnostics >&2
  exit 1
}

cleanup() {
  local status=$?
  for pid in "${forwards[@]}"; do kill "$pid" 2>/dev/null || true; done
  if [ "$keep" = 1 ]; then
    printf '\nkept: cluster %s, files in %s\n' "$cluster" "$work"
  else
    k3d cluster delete "$cluster" >/dev/null 2>&1 || true
    rm -rf "$work"
  fi
  exit "$status"
}
trap cleanup EXIT

# wait_for <seconds> <what> <command…>: until the command succeeds.
wait_for() {
  local seconds=$1 what=$2
  shift 2
  local deadline=$((SECONDS + seconds))
  until "$@" >/dev/null 2>&1; do
    if [ "$SECONDS" -ge "$deadline" ]; then
      fail "$what: not within ${seconds}s"
    fi
    sleep 3
  done
}

for tool in k3d kubectl helm openssl docker; do
  command -v "$tool" >/dev/null || fail "$tool isn't on PATH"
done
[ -x "$bin/ferritor" ] || fail "$bin/ferritor missing: cargo build --release --locked -p ferritor-cli"
ferritor() { "$bin/ferritor" "$@"; }

log "images"
# One build stage for both (the second takes seconds).
docker build -q --target server -t "$server_image" "$root" >/dev/null
docker build -q --target csi-provider -t "$provider_image" "$root" >/dev/null

k3s_version=${k3s_image%@*}
log "cluster $cluster (k3s ${k3s_version##*:})"
k3d cluster delete "$cluster" >/dev/null 2>&1 || true
k3d cluster create "$cluster" --image "$k3s_image" --no-lb --wait --timeout 180s >/dev/null
# Through files, not the runtime's store: k3d may talk to another one than
# the one that built them (rootless and rootful Podman keep separate stores).
docker save -o "$work/server.tar" "$server_image"
docker save -o "$work/provider.tar" "$provider_image"
k3d image import -c "$cluster" "$work/server.tar" "$work/provider.tar" >/dev/null
kubectl create namespace ferritor-system >/dev/null
# Pods are refused until the namespace's default service account exists.
wait_for 60 "ferritor-system's default service account" \
  kubectl -n ferritor-system get serviceaccount default

log "PKI, the server's config"
cd "$work"
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -days 2 \
  -keyout ca-key.pem -out ca.pem -subj /CN=ferritor-e2e-ca 2>/dev/null
cert() { # cert <name> <subjectAltName> <usage>
  openssl req -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes \
    -keyout "$1-key.pem" -out "$1.csr" -subj "/CN=$1" 2>/dev/null
  printf 'subjectAltName=%s\nextendedKeyUsage=%s\n' "$2" "$3" >"$1.ext"
  openssl x509 -req -in "$1.csr" -CA ca.pem -CAkey ca-key.pem -CAcreateserial \
    -days 2 -extfile "$1.ext" -out "$1.pem" 2>/dev/null
}
cert server "DNS:ferritor.ferritor-system.svc,DNS:localhost" serverAuth
cert admin "URI:ferritor://ops/admin" clientAuth
openssl genpkey -algorithm ed25519 -out audit-key.pem 2>/dev/null
issuer=$(kubectl get --raw /.well-known/openid-configuration | sed -n 's/.*"issuer":"\([^"]*\)".*/\1/p')
[ -n "$issuer" ] || fail "no service account issuer in the cluster's discovery document"
kubectl get --raw /openid/v1/jwks >jwks.json
cat >ferritor.toml <<EOF
listen_addr = "0.0.0.0:7070"
keys_database_url = "postgres://ferritor:ferritor@postgres.ferritor-system.svc:5432/ferritor_keys"
data_database_url = "postgres://ferritor:ferritor@postgres.ferritor-system.svc:5432/ferritor_data"
audit_signing_key = "/etc/ferritor/audit-key.pem"
keyring_refresh_secs = 10

[tls]
cert = "/etc/ferritor/server.pem"
key = "/etc/ferritor/server-key.pem"
client_ca = "/etc/ferritor/ca.pem"

[[policy]]
name = "admin"
identity = "ops/admin"
actions = ["status", "init", "unseal", "seal", "namespace", "policy", "identity"]

[identity]
listen_addr = "0.0.0.0:7071"

[[identity.issuer]]
name = "k8s"
issuer = "$issuer"
audience = "ferritor"
jwks_file = "/etc/ferritor/jwks.json"
# Room to spare: the run exchanges about 7 tokens (one per volume, the
# CLI's), and the default burst of 10 would leave the next check added
# failing on RATE_LIMITED, for a reason that isn't its own.
exchange_burst = 100

[[identity.issuer.map]]
identity = "k8s/{kubernetes.io.namespace}/{kubernetes.io.serviceaccount.name}"
EOF
kubectl -n ferritor-system create secret generic ferritor-server --from-file=ferritor.toml \
  --from-file=server.pem --from-file=server-key.pem --from-file=ca.pem \
  --from-file=audit-key.pem --from-file=jwks.json >/dev/null

log "Postgres and the server"
kubectl apply -f - >/dev/null <<EOF
apiVersion: v1
kind: Pod
metadata: {name: postgres, namespace: ferritor-system, labels: {app: postgres}}
spec:
  containers:
    - name: postgres
      image: $postgres
      env:
        - {name: POSTGRES_USER, value: ferritor}
        - {name: POSTGRES_PASSWORD, value: ferritor}
        - {name: POSTGRES_DB, value: ferritor_keys}
      readinessProbe: {exec: {command: [pg_isready, -U, ferritor]}, periodSeconds: 2}
---
apiVersion: v1
kind: Service
metadata: {name: postgres, namespace: ferritor-system}
spec:
  selector: {app: postgres}
  ports: [{port: 5432}]
EOF
kubectl -n ferritor-system wait --for=condition=Ready pod/postgres --timeout=180s >/dev/null
wait_for 60 "the data database" kubectl -n ferritor-system exec postgres -- \
  psql -U ferritor -d ferritor_keys -q -c 'CREATE DATABASE ferritor_data'
kubectl apply -f - >/dev/null <<EOF
apiVersion: v1
kind: Pod
metadata: {name: ferritor, namespace: ferritor-system, labels: {app: ferritor}}
spec:
  automountServiceAccountToken: false
  securityContext: {fsGroup: 10001}
  containers:
    - name: ferritor
      image: $server_image
      imagePullPolicy: IfNotPresent
      workingDir: /etc/ferritor
      securityContext:
        runAsNonRoot: true
        runAsUser: 10001
        allowPrivilegeEscalation: false
        readOnlyRootFilesystem: true
        capabilities: {drop: [ALL]}
      volumeMounts:
        - {name: config, mountPath: /etc/ferritor, readOnly: true}
  volumes:
    - {name: config, secret: {secretName: ferritor-server, defaultMode: 0440}}
---
apiVersion: v1
kind: Service
metadata: {name: ferritor, namespace: ferritor-system}
spec:
  selector: {app: ferritor}
  ports: [{name: api, port: 7070}, {name: exchange, port: 7071}]
EOF
kubectl -n ferritor-system wait --for=condition=Ready pod/ferritor --timeout=120s >/dev/null
wait_for 60 "the server serving" sh -c "kubectl -n ferritor-system logs ferritor | grep -q 'serving gRPC'"

forward() { # forward <local> <remote>
  kubectl -n ferritor-system port-forward svc/ferritor "$1:$2" >"$work/forward-$2.log" 2>&1 &
  forwards+=($!)
}
forward "$api_port" 7070
forward "$exchange_port" 7071
export FERRITOR_ADDR=https://localhost:$api_port FERRITOR_CA=$work/ca.pem \
  FERRITOR_CERT=$work/admin.pem FERRITOR_KEY=$work/admin-key.pem
wait_for 30 "the port-forward" ferritor status

log "init, unseal, the issuing CA, secrets, policies"
ferritor init --shares 3 --threshold 2 >shares.txt 2>/dev/null
unseal() {
  local share
  for share in $(awk -F': ' '{print $2}' shares.txt | head -2); do
    printf '%s\n' "$share" | ferritor unseal >/dev/null
  done
}
unseal
ferritor identity init >/dev/null
ferritor namespace create billing >/dev/null
cat >policies.toml <<'EOF'
[[policy]]
name = "writer"
identity = "ops/admin"
actions = ["write"]
paths = ["billing"]

[[policy]]
name = "billing-api"
identity = "k8s/billing/api"
actions = ["read", "list"]
paths = ["billing/api"]

[[policy]]
name = "billing-api-shared"
identity = "k8s/billing/api"
actions = ["read"]
paths = ["billing/shared/redis-password"]
EOF
ferritor policy apply --prune -f policies.toml >/dev/null
put() { printf '%s' "$2" | ferritor put "$1" >/dev/null; }
put billing/api/db-password foo
put billing/api/tls/cert pem-v1
put billing/shared/redis-password bar
put billing/secret/x nobody-may

log "the Secrets Store CSI Driver $driver_chart, the provider"
helm install csi-secrets-store secrets-store-csi-driver \
  --repo https://kubernetes-sigs.github.io/secrets-store-csi-driver/charts \
  --version "$driver_chart" --namespace kube-system --wait --timeout 4m \
  --set enableSecretRotation=true --set rotationPollInterval=15s \
  --set 'tokenRequests[0].audience=ferritor' >/dev/null
kubectl -n ferritor-system create configmap ferritor-csi-provider --from-file=ca.pem \
  --from-literal=config.toml='server = "https://ferritor.ferritor-system.svc:7070"
ca = "/etc/ferritor-csi-provider/ca.pem"
exchange = "https://ferritor.ferritor-system.svc:7071"
' >/dev/null
kubectl apply -f - >/dev/null <<EOF
apiVersion: apps/v1
kind: DaemonSet
metadata: {name: ferritor-csi-provider, namespace: ferritor-system}
spec:
  selector: {matchLabels: {app: ferritor-csi-provider}}
  template:
    metadata: {labels: {app: ferritor-csi-provider}}
    spec:
      automountServiceAccountToken: false
      containers:
        - name: provider
          image: $provider_image
          imagePullPolicy: IfNotPresent
          args: [--config, /etc/ferritor-csi-provider/config.toml]
          securityContext:
            runAsUser: 0
            allowPrivilegeEscalation: false
            readOnlyRootFilesystem: true
            capabilities: {drop: [ALL]}
          volumeMounts:
            - {name: providers, mountPath: /var/run/secrets-store-csi-providers}
            - {name: config, mountPath: /etc/ferritor-csi-provider, readOnly: true}
      volumes:
        - {name: providers, hostPath: {path: /var/run/secrets-store-csi-providers, type: DirectoryOrCreate}}
        - {name: config, configMap: {name: ferritor-csi-provider}}
EOF
kubectl -n ferritor-system rollout status ds/ferritor-csi-provider --timeout=120s >/dev/null
wait_for 60 "the provider serving" sh -c \
  "kubectl -n ferritor-system logs ds/ferritor-csi-provider | grep -q 'serving the Secrets Store CSI Driver'"

# A pod of service account billing/api mounting <class>s at /var/<class>.
pod() { # pod <name> <class>…
  local name=$1 class
  shift
  local mounts_='' volumes_=''
  for class in "$@"; do
    mounts_+="
        - {name: $class, mountPath: /var/$class, readOnly: true}"
    volumes_+="
    - name: $class
      csi:
        driver: secrets-store.csi.k8s.io
        readOnly: true
        volumeAttributes: {secretProviderClass: $class}"
  done
  kubectl apply -f - >/dev/null <<EOF
apiVersion: v1
kind: Pod
metadata: {name: $name, namespace: billing}
spec:
  serviceAccountName: api
  terminationGracePeriodSeconds: 1
  containers:
    - name: app
      image: $busybox
      command: [sleep, infinity]
      securityContext: {runAsUser: 1000}
      volumeMounts:$mounts_
  volumes:$volumes_
EOF
}
read_file() { kubectl -n billing exec "$1" -- cat "$2"; }
is() { [ "$(read_file "$1" "$2" 2>/dev/null)" = "$3" ]; }
phase() { kubectl -n billing get pod "$1" -o jsonpath='{.status.phase}'; }

kubectl apply -f - >/dev/null <<'EOF'
apiVersion: v1
kind: Namespace
metadata: {name: billing}
---
apiVersion: v1
kind: ServiceAccount
metadata: {name: api, namespace: billing}
---
apiVersion: secrets-store.csi.x-k8s.io/v1
kind: SecretProviderClass
metadata: {name: prefix, namespace: billing}
spec:
  provider: ferritor
  parameters:
    prefix: "billing/api"
---
apiVersion: secrets-store.csi.x-k8s.io/v1
kind: SecretProviderClass
metadata: {name: objects, namespace: billing}
spec:
  provider: ferritor
  parameters:
    objects: '[{"path": "billing/api/db-password"}, {"path": "billing/shared/redis-password", "file": "redis"}]'
---
apiVersion: secrets-store.csi.x-k8s.io/v1
kind: SecretProviderClass
metadata: {name: denied, namespace: billing}
spec:
  provider: ferritor
  parameters:
    objects: '[{"path": "billing/secret/x"}]'
EOF

log "check: a pod mounts a prefix and an objects volume, read by a non-root user"
pod api prefix objects
kubectl -n billing wait --for=condition=Ready pod/api --timeout=180s >/dev/null ||
  fail "pod api isn't ready"
is api /var/prefix/db-password foo || fail "prefix: db-password isn't foo"
is api /var/prefix/tls/cert pem-v1 || fail "prefix: tls/cert (a subdirectory) isn't pem-v1"
is api /var/objects/db-password foo || fail "objects: db-password isn't foo"
is api /var/objects/redis bar || fail "objects: redis (a file named by the class) isn't bar"

log "check: a new version and a new secret arrive at a refresh"
put billing/api/db-password foo-v2
put billing/api/new-one fresh
wait_for 300 "the new version in the volume" is api /var/prefix/db-password foo-v2
wait_for 60 "the new secret in the volume" is api /var/prefix/new-one fresh

log "check: a denied path keeps its pod waiting, the server asked once"
pod denied denied
sleep 45
[ "$(phase denied)" = Pending ] || fail "pod denied is $(phase denied), not waiting"
kubectl -n billing get events --field-selector involvedObject.name=denied |
  grep -q PermissionDenied || fail "pod denied: no PermissionDenied mount event"
denials=$(kubectl -n ferritor-system logs ferritor | grep '^{' | grep '"decision":"denied"' |
  grep -c 'billing/secret/x' || true)
[ "$denials" = 1 ] || fail "the denied path reached the server $denials times, not once"
kubectl -n billing delete pod denied --wait=false >/dev/null

log "check: sealed, a new pod waits (never an empty volume), a running pod keeps its files"
ferritor seal >/dev/null
pod sealed prefix objects
sleep 45
[ "$(phase sealed)" = Pending ] || fail "pod sealed is $(phase sealed) while the server is sealed"
is api /var/prefix/db-password foo-v2 || fail "pod api lost its files while sealed"
unseal
kubectl -n billing wait --for=condition=Ready pod/sealed --timeout=240s >/dev/null ||
  fail "pod sealed didn't start once unsealed"
is sealed /var/prefix/db-password foo-v2 || fail "pod sealed has no files"

log "check: a revoked grant keeps the value delivered (onRevoked keep)"
# policies.toml without billing-api-shared.
cat >revoked.toml <<'EOF'
[[policy]]
name = "writer"
identity = "ops/admin"
actions = ["write"]
paths = ["billing"]

[[policy]]
name = "billing-api"
identity = "k8s/billing/api"
actions = ["read", "list"]
paths = ["billing/api"]
EOF
ferritor policy apply --prune -f revoked.toml >/dev/null
# The provider's log line says so (provider.rs; rewording it breaks this).
wait_for 300 "a refresh refused, the value kept" sh -c \
  "kubectl -n ferritor-system logs ds/ferritor-csi-provider | grep -q 'keeping the value delivered pod=\"billing/api\"'"
is api /var/objects/redis bar || fail "the revoked value went away under keep"

log "check: the exchange takes ferritor tokens only, any service account's own"
exchange() { # exchange <token file>: as a workload, no client certificate
  env -u FERRITOR_CERT -u FERRITOR_KEY "$bin/ferritor" --token-file "$1" \
    --exchange "https://localhost:$exchange_port" \
    login --cert-out "$1.pem" --key-out "$1.key" 2>&1
}
kubectl -n billing create token api >default.tok
answer=$(exchange default.tok || true)
grep -q "aud lacks" <<<"$answer" || fail "a default (API server) token wasn't refused: $answer"
kubectl -n billing create token api --audience ferritor >ferritor.tok
answer=$(exchange ferritor.tok || true)
grep -q "identity: k8s/billing/api" <<<"$answer" || fail "a ferritor token didn't map: $answer"

log "all checks passed"
