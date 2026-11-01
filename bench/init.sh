#!/usr/bin/env bash
# Initializes and unseals the bench server (bench/start.sh running), creates
# the `bench` namespace and applies the application's stored policy. The
# shares go to run/shares.txt: a throwaway deployment's, never do this with
# real ones. After a restart (sealed again): bench/init.sh unseal.
set -euo pipefail

here=$(cd "$(dirname "$0")" && pwd)
root=$(cd "$here/.." && pwd)
cd "$here/run"
PORT=${PORT:-7171}
ferritor() { "$root/target/release/ferritor" "$@"; }
export FERRITOR_ADDR=https://localhost:$PORT
export FERRITOR_CA=server-ca.pem FERRITOR_CERT=ops-bench.pem FERRITOR_KEY=ops-bench-key.pem

if [ "${1:-}" != unseal ]; then
  (umask 077 && ferritor init --shares 2 --threshold 2 >shares.txt)
fi
grep '^share' shares.txt | sed 's/.*: //' | while read -r share; do
  printf '%s' "$share" | ferritor unseal >/dev/null
done
ferritor status
if [ "${1:-}" != unseal ]; then
  ferritor namespace create bench
  ferritor policy apply -f policies.toml
fi
