#!/usr/bin/env bash
# Builds and starts the --release server on bench/run (bench/setup.sh first),
# in the foreground: stdout (the audit log) to run/audit.log, its own logs
# to run/server.log. Ctrl-C stops it (draining, then the chain's end).
set -euo pipefail

here=$(cd "$(dirname "$0")" && pwd)
root=$(cd "$here/.." && pwd)
cd "$root"
SQLX_OFFLINE=true cargo build --release --locked -p ferritor-server -p ferritor-cli
cd "$here/run"
echo "serving; audit log: bench/run/audit.log, logs: bench/run/server.log"
exec "$root/target/release/ferritor-server" >>audit.log 2>>server.log
