#!/usr/bin/env bash
# A throwaway secured deployment for load tests (see bench/README.md), as
# docs/src/content/docs/getting-started/production.md sets one up: its own two databases on the compose
# servers, a PKI, an audit signing key and a ferritor.toml, all under
# bench/run/ (gitignored). Nothing here is fit for real secrets.
#
#   bench/setup.sh            # POOL=10 by default: data_database_max_connections
#   POOL=32 bench/setup.sh
set -euo pipefail

here=$(cd "$(dirname "$0")" && pwd)
root=$(cd "$here/.." && pwd)
run="$here/run"
POOL=${POOL:-10}
PORT=${PORT:-7171}

rm -rf "$run"
mkdir -p "$run"
cd "$run"

# Fresh databases, separate from the development ones.
for s in "keys-db ferritor_bench_keys" "data-db ferritor_bench_data"; do
  read -r service db <<<"$s"
  docker compose -f "$root/compose.yaml" exec -T "$service" psql -U ferritor -d postgres -q \
    -c "DROP DATABASE IF EXISTS $db WITH (FORCE)" -c "CREATE DATABASE $db"
done

ca() { # ca <file> <CN>
  openssl genpkey -algorithm ed25519 -out "$1.key" 2>/dev/null
  openssl req -x509 -new -key "$1.key" -subj "/CN=$2" -days 30 -out "$1.pem" \
    -addext "basicConstraints=critical,CA:TRUE" \
    -addext "keyUsage=critical,keyCertSign,cRLSign"
}
ca server-ca "ferritor bench server CA"
ca client-ca "ferritor bench client CA"

openssl genpkey -algorithm ed25519 -out server-key.pem 2>/dev/null
openssl req -new -key server-key.pem -subj "/CN=localhost" -out server.csr
cat >server.ext <<X
subjectAltName = DNS:localhost, IP:127.0.0.1
extendedKeyUsage = serverAuth
keyUsage = critical, digitalSignature
basicConstraints = critical, CA:FALSE
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid, issuer
X
openssl x509 -req -in server.csr -CA server-ca.pem -CAkey server-ca.key -days 30 \
  -extfile server.ext -out server.pem 2>/dev/null

client() { # client <identity>
  local f=${1//\//-}
  openssl genpkey -algorithm ed25519 -out "$f-key.pem" 2>/dev/null
  openssl req -new -key "$f-key.pem" -subj "/CN=$f" -out "$f.csr"
  cat >"$f.ext" <<X
subjectAltName = URI:ferritor://$1
extendedKeyUsage = clientAuth
keyUsage = critical, digitalSignature
basicConstraints = critical, CA:FALSE
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid, issuer
X
  openssl x509 -req -in "$f.csr" -CA client-ca.pem -CAkey client-ca.key -days 30 \
    -extfile "$f.ext" -out "$f.pem" 2>/dev/null
}
client ops/bench  # the operator: init, unseal, namespace, policy
client apps/bench # the application under load: a stored policy

openssl genpkey -algorithm ed25519 -out audit-key.pem 2>/dev/null
chmod 600 audit-key.pem server-key.pem
openssl pkey -in audit-key.pem -pubout -out audit.pub.pem

cat >ferritor.toml <<X
listen_addr = "127.0.0.1:$PORT"
keys_database_url = "postgres://ferritor:ferritor@localhost:5433/ferritor_bench_keys"
data_database_url = "postgres://ferritor:ferritor@localhost:5434/ferritor_bench_data"
data_database_max_connections = $POOL
audit_signing_key = "$run/audit-key.pem"

[tls]
cert = "$run/server.pem"
key = "$run/server-key.pem"
client_ca = "$run/client-ca.pem"

[[policy]]
name = "ops-bench"
identity = "ops/bench"
actions = ["status", "init", "unseal", "seal", "namespace", "policy"]

# The load test's one application may use the whole server: the published
# numbers are one application at full load, where the default (a quarter of
# the cap in flight per identity) would refuse it.
[[rate_limit.identity]]
identity = "apps/bench"
max_in_flight = $((2 * POOL + 16))
X

cat >policies.toml <<X
[[policy]]
name = "apps/bench"
identity = "apps/bench"
actions = ["read", "write", "delete", "list"]  # delete: list_dead's setup
paths = ["bench"]
description = "the load test's application"
X

echo "bench/run is ready (data pool: $POOL). Next: bench/start.sh, then bench/init.sh"
