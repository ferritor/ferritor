#!/usr/bin/env bash
# Load scenarios against the bench server (setup.sh, start.sh, init.sh
# first), over the JSON API with the application's client certificate.
# Each prints one line (count, rate, mean and percentiles, success); the
# raw oha JSON goes to run/results/<scenario>.json.
#
#   bench/scenarios.sh                      # all, 30 s each, 10 connections
#   C=50 DURATION=10s bench/scenarios.sh put_100 get_100
#
# Scenarios:
#   put_100       puts to 100 paths at random
#   put_distinct  puts to (nearly always) new paths
#   put_one       puts to one path: its lock serializes them
#   get_100       reads of the 100 paths put_100 wrote
#   list          a listing of `bench` (first page, 100 paths)
#   list_dead     a listing of `bench/dead` (first page), where 99 paths in
#                 100 have no live version: written once, then deleted (the
#                 first run writes them, about 20,000 requests)
#   grpc_put_distinct, grpc_get_100
#                 put_distinct and get_100 over gRPC (ghz): C workers over one
#                 HTTP/2 connection, as an application's one channel
set -euo pipefail

here=$(cd "$(dirname "$0")" && pwd)
root=$(cd "$here/.." && pwd)
run="$here/run"
PORT=${PORT:-7171}
C=${C:-10}
DURATION=${DURATION:-30s}
base="https://localhost:$PORT/v1"
mkdir -p "$run/results"

# A 100-byte value, base64 in the body.
value=$(head -c 100 /dev/zero | tr '\0' 'v' | base64 -w0)
body="{\"value\": \"$value\"}"

load() { # load <name> <oha args…>
  local name=$1
  shift
  oha --no-tui --output-format json -z "$DURATION" -c "$C" \
    --cacert "$run/server-ca.pem" --cert "$run/apps-bench.pem" --key "$run/apps-bench-key.pem" \
    "$@" >"$run/results/$name.json"
  python3 - "$name" "$run/results/$name.json" <<'PY'
import json, sys
name, path = sys.argv[1], sys.argv[2]
r = json.load(open(path))
s, p = r["summary"], r["latencyPercentiles"]
codes = r.get("statusCodeDistribution", {})
count = sum(codes.values())
ok = sum(n for code, n in codes.items() if code.startswith("2"))
if count == 0:
    errors = r.get("errorDistribution", {})
    sys.exit(f"{name}: no responses at all (is the server up and unsealed?) {errors}")
ms = lambda x: f"{x * 1000:.3f}ms" if x is not None else "-"
print(f"{name:<14} {count:>8} {s['requestsPerSec']:>10.1f}/s  mean {ms(s['average'])}"
      f"  p50 {ms(p.get('p50'))}  p95 {ms(p.get('p95'))}  p99 {ms(p.get('p99'))}"
      f"  ok {100 * ok / max(count, 1):.2f}%  codes {codes}")
PY
}

grpc() { # grpc <name> <method> <data template>
  local name=$1
  ghz --format json -z "$DURATION" -c "$C" --connections 1 \
    --cacert "$run/server-ca.pem" --cert "$run/apps-bench.pem" --key "$run/apps-bench-key.pem" \
    --proto "$root/proto/ferritor/v1/ferritor.proto" -i "$root/proto" \
    --call "ferritor.v1.SecretsService/$2" -d "$3" "localhost:$PORT" >"$run/results/$name.json" || true
  python3 - "$name" "$run/results/$name.json" <<'PY'
import json, sys
name, path = sys.argv[1], sys.argv[2]
text = open(path).read()
if not text.strip():
    sys.exit(f"{name}: ghz failed (its error is above)")
r = json.loads(text)
codes = r.get("statusCodeDistribution", {})
count = r.get("count", 0)
if count == 0:
    sys.exit(f"{name}: no responses at all (is the server up and unsealed?) {r.get('errorDistribution', {})}")
p = {d["percentage"]: d["latency"] / 1e6 for d in r.get("latencyDistribution") or []}
ms = lambda x: f"{x:.3f}ms" if x is not None else "-"
ok = codes.get("OK", 0)
print(f"{name:<17} {count:>8} {r['rps']:>10.1f}/s  mean {ms(r['average'] / 1e6)}"
      f"  p50 {ms(p.get(50))}  p95 {ms(p.get(95))}  p99 {ms(p.get(99))}"
      f"  ok {100 * ok / max(count, 1):.2f}%  codes {codes}")
PY
}

# 10,000 paths under bench/dead, all but every 100th deleted: a prefix that
# is mostly paths with nothing live. Written once per bench database (the
# marker is in run/, which setup.sh starts over).
dead_paths() {
  [ -e "$run/dead-paths" ] && return
  echo "writing bench/dead (10,000 puts, 9,900 deletes)..." >&2
  local curl=(curl -sSf -o /dev/null --cacert "$run/server-ca.pem"
    --cert "$run/apps-bench.pem" --key "$run/apps-bench-key.pem")
  if ! seq -w 0 9999 | xargs -P 16 -I{} "${curl[@]}" -X PUT \
    -H 'content-type: application/json' -d "$body" "$base/secrets/bench/dead/d{}" ||
    ! seq -w 0 9999 | grep -v '00$' | xargs -P 16 -I{} "${curl[@]}" -X DELETE \
      "$base/secrets/bench/dead/d{}"; then
    echo "writing bench/dead failed (the errors are above)" >&2
    exit 1
  fi
  touch "$run/dead-paths"
}

scenario() {
  case $1 in
  put_100) load put_100 -m PUT -H 'content-type: application/json' -d "$body" \
    --rand-regex-url "$base/secrets/bench/kv[0-9]{2}" ;;
  put_distinct) load put_distinct -m PUT -H 'content-type: application/json' -d "$body" \
    --rand-regex-url "$base/secrets/bench/new/[a-z0-9]{12}" ;;
  put_one) load put_one -m PUT -H 'content-type: application/json' -d "$body" \
    "$base/secrets/bench/one" ;;
  get_100) load get_100 --rand-regex-url "$base/secrets/bench/kv[0-9]{2}" ;;
  list) load list "$base/secrets?prefix=bench" ;;
  list_dead)
    dead_paths
    load list_dead "$base/secrets?prefix=bench/dead"
    ;;
  grpc_put_distinct) grpc grpc_put_distinct PutSecret \
    "{\"path\": \"bench/grpc/{{randomString 12}}\", \"value\": \"$value\"}" ;;
  grpc_get_100)
    # kv00 to kv99, as get_100 (randomInt's upper bound is exclusive). The
    # backquotes are a Go raw string, not a substitution: ghz parses the
    # JSON before rendering the template, so `"%02d"` would break it.
    # shellcheck disable=SC2016
    template='{"path": "bench/kv{{printf `%02d` (randomInt 0 100)}}"}'
    grpc grpc_get_100 GetSecret "$template"
    ;;
  *)
    echo "unknown scenario: $1" >&2
    exit 2
    ;;
  esac
}

echo "connections: $C, duration: $DURATION each"
for s in "${@:-put_100 put_distinct put_one get_100 list grpc_put_distinct grpc_get_100}"; do
  for one in $s; do scenario "$one"; done
done
