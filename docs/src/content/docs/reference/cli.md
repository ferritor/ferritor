---
title: 'CLI'
description: 'The ferritor CLI: installing it, connecting to a server, its conventions and exit codes, and every command with its options.'
seo:
  title: 'The ferritor CLI: commands and options'
---

`ferritor` operates a server (init, unseal, keys, policies) and reads and
writes its secrets, over gRPC with a client certificate. Every command
says more with `--help`; this page lists them all, and the guides linked
from each say how they fit together.

## Install

- **Linux**: a release's archive holds it with the other binaries, static
  ([production](/getting-started/production#1-the-binaries) fetches and
  verifies the latest).
- **macOS and Windows Server**: the CLI alone, for operators' machines,
  verified the same way:
  `ferritor-cli-<version>-aarch64-apple-darwin.tar.gz` (Apple silicon),
  `ferritor-cli-<version>-x86_64-apple-darwin.tar.gz` (Intel Macs) and
  `ferritor-cli-<version>-x86_64-pc-windows-gnu.zip`.

On macOS:

```sh
version=1.0.1
f=ferritor-cli-$version-aarch64-apple-darwin.tar.gz   # Intel Macs: x86_64-apple-darwin
for a in "$f" "$f.sigstore.json" SHA256SUMS; do
  curl -fsSLO "https://github.com/ferritor/ferritor/releases/download/v$version/$a"
done
cosign verify-blob "$f" --bundle "$f.sigstore.json" \
  --certificate-identity https://github.com/ferritor/ferritor/.github/workflows/release-plz.yml@refs/heads/main \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com &&
  grep " $f\$" SHA256SUMS | shasum -a 256 -c - &&
  tar -xzf "$f" &&                                      # ferritor-cli-$version-aarch64-apple-darwin/ferritor
  sudo install -m 0755 "${f%.tar.gz}/ferritor" /usr/local/bin/
ferritor --version
```

On Windows, in an elevated PowerShell (Run as administrator), since it
installs under Program Files; without one, use a folder of your own, such
as `$env:LOCALAPPDATA\Programs\ferritor`, in its place:

```powershell
$version = "1.0.1"
$f = "ferritor-cli-$version-x86_64-pc-windows-gnu.zip"
foreach ($a in $f, "$f.sigstore.json", "SHA256SUMS") {
  Invoke-WebRequest "https://github.com/ferritor/ferritor/releases/download/v$version/$a" -OutFile $a
}
cosign verify-blob $f --bundle "$f.sigstore.json" `
  --certificate-identity https://github.com/ferritor/ferritor/.github/workflows/release-plz.yml@refs/heads/main `
  --certificate-oidc-issuer https://token.actions.githubusercontent.com
if ($LASTEXITCODE -ne 0) { throw "the signature doesn't verify" }
$want = (Select-String -Path SHA256SUMS -SimpleMatch " $f").Line.Split(" ")[0]
if ((Get-FileHash $f).Hash -ne $want) { throw "the checksum doesn't match" }   # -ne ignores case
$out = New-Item -ItemType Directory (Join-Path $env:TEMP "ferritor-cli-$([guid]::NewGuid())")   # fresh, empty
Expand-Archive $f -DestinationPath $out -ErrorAction Stop   # …\ferritor-cli-$version-x86_64-pc-windows-gnu\ferritor.exe
New-Item -ItemType Directory "$env:ProgramFiles\ferritor" -Force | Out-Null
Copy-Item "$out\ferritor-cli-$version-x86_64-pc-windows-gnu\ferritor.exe" "$env:ProgramFiles\ferritor\" -ErrorAction Stop
$env:Path += ";$env:ProgramFiles\ferritor"   # this shell; for good: System Properties, Environment Variables
ferritor --version
```

Either stops before unpacking if the signature or the checksum doesn't
match. They're cross-built and not notarized or signed by a publisher: fetched
with `curl` they run as they are, but downloaded with a browser macOS
refuses to start the binary until `xattr -d com.apple.quarantine ferritor`,
and Windows SmartScreen asks first. On Windows, Windows Server is the
target: desktop Windows 11's Smart App Control, where it's on, refuses a
binary no publisher signed.

## Connecting

Every command takes these, before or after its name, each also from its
environment variable:

| Option | Variable | Default | |
|---|---|---|---|
| `--addr` | `FERRITOR_ADDR` | `http://127.0.0.1:7070` | the server: `http://` for a dev-mode server on loopback, else `https://` |
| `--ca` | `FERRITOR_CA` | | the CA certificate (PEM) to verify the server with; with `https://` |
| `--cert`, `--key` | `FERRITOR_CERT`, `FERRITOR_KEY` | | your client certificate (carrying your `ferritor://<name>` identity) and its key, PEM; both or neither, required with `https://` |
| `--token-file` | `FERRITOR_TOKEN_FILE` | | [workload identity](/guides/workload-identity#the-cli) instead of `--cert` and `--key`: a platform token exchanged for a short-lived certificate first, kept in memory for this one command |
| `--exchange` | `FERRITOR_EXCHANGE` | | with `--token-file`: the server's token exchange (its `[identity] listen_addr`), `https://`, verified with `--ca` |

```sh
export FERRITOR_ADDR=https://ferritor.internal:7070 FERRITOR_CA=ca.pem \
  FERRITOR_CERT=alice.pem FERRITOR_KEY=alice-key.pem
ferritor status
```

A misspelled `FERRITOR_…` variable is ignored, not refused. For many
commands under one workload identity, exchange once with `ferritor login`
(below) and pass the certificate it writes as `--cert` and `--key`.

## Conventions

- **Values and shares are never arguments**: they'd end up in shell
  history and `/proc/<pid>/cmdline`. `put`, `unseal` and the rekey's
  `submit` and `verify` read stdin, all of it byte for byte, or one line
  at a hidden prompt on a terminal.
- **Results go to stdout, everything else to stderr**: `get` prints the
  value's raw bytes and nothing else, so `ferritor get app/db > file` is
  the value. Errors are `error: …` on stderr, often with a `hint: …` line
  saying what to do (a sealed server, a missing permission, a namespace
  that doesn't exist).
- **Exit status**: 0 on success, 1 on any error; `policy check` exits 1
  when not allowed, and `audit verify` 2 when nothing is broken but
  something is unproven.
- **Nothing sent, for sure**: over `https://` every command makes a
  health call first, so a server it can't reach (or whose certificate
  doesn't verify) fails before the real call: nothing was sent, safe to
  retry.
- **Rate limits**: a call refused for a wait of up to 3 seconds is retried
  after it, saying so on stderr; a longer one fails, saying when to retry.

## Commands

### Server state and keys

| Command | Options | |
|---|---|---|
| `ferritor status` | | whether the server is initialized and sealed, its shares and threshold, the root key's generation, an unseal or rekey in progress, auto-unseal, how many namespaces; the rotation reminders: when the root key's rotation is due, how many namespaces' KEKs are overdue or due soon, and with the `namespace` action each namespace's active KEK and its due date ([key management](/operations/key-management#unseal-and-seal)) |
| `ferritor init` | `--shares` (5), `--threshold` (3) | create the root key and print its shares, once only ([key management](/operations/key-management#init)) |
| `ferritor unseal` | `--reset`, `--recommit`, `--auto`, `--release-hold` | submit one share from stdin; `--reset` discards those submitted so far, `--recommit` stores a missing root commitment once a secret proves the key ([the root commitment](/operations/key-management#the-root-commitment)), `--auto` releases the auto-unseal hold and unseals through the KMS, `--release-hold` releases it once unsealed ([auto-unseal](/operations/key-management#auto-unseal)) |
| `ferritor seal` | | drop the server's keys; always succeeds, and holds auto-unseal ([unseal and seal](/operations/key-management#unseal-and-seal)) |
| `ferritor rekey start` | `--shares` (5), `--threshold` (3), `--seal` (`shamir`, `awskms`, `gcpkms`) | start replacing the root key and its shares; `--seal` changes how it's protected ([rekey](/operations/key-management#rekey-new-root-key-new-shares)) |
| `ferritor rekey submit` | `--nonce` | one current share (stdin); the last prints the new shares |
| `ferritor rekey verify` | `--nonce` | one new share (stdin); the last commits the rekey |
| `ferritor rekey cancel` | `--nonce` | abandon it; the current shares keep working |
| `ferritor rotate` | `--namespace` | a new active KEK for a namespace ([rotate](/operations/key-management#rotate-a-new-kek)) |
| `ferritor rewrap` | `--namespace` (every one), `--max-rows` (the server's) | move DEKs onto the active KEK, then retire versions nothing uses; repeats until done, safe to interrupt ([rewrap](/operations/key-management#rewrap-and-retire)) |
| `ferritor purge` | `--max-rows` (the server's) | remove deleted versions past the server's retention for good; for cron ([routine tasks](/operations/running#routine-tasks)) |
| `ferritor destroy-kek` | `--namespace`, `VERSION` | destroy a retired KEK for good: irreversible ([destroy](/operations/key-management#destroy-a-retired-kek)) |

### Namespaces

[Namespaces](/operations/key-management#namespaces): a secret's path
starts with one, and nothing is stored outside one.

| Command | Options | |
|---|---|---|
| `ferritor namespace create` | `NAME`, `--label KEY=VALUE` (repeatable), `--past-lost-keks` | create one (or re-create a deleted one) with its first KEK; `--past-lost-keks` is the recovery for one the keys database lost |
| `ferritor namespace delete` | `NAME` | delete an empty one, destroying its KEKs: irreversible |
| `ferritor namespace list` | | every namespace, live and deleted |
| `ferritor namespace get` | `NAME` | its state, KEKs, KEK floor and labels |
| `ferritor namespace label` | `NAME`, `KEY=VALUE…` | set labels |
| `ferritor namespace unlabel` | `NAME`, `KEY…` | remove labels |

### Secrets

[Secrets](/guides/secrets): versions, check-and-set, delete and restore,
labels.

| Command | Options | |
|---|---|---|
| `ferritor get` | `PATH`, `--version` | the latest value, or that version's, raw bytes |
| `ferritor put` | `PATH`, `--expected-version`, `--label KEY=VALUE` (repeatable), `--allow-empty` | store the next version from stdin; `--expected-version` stores only if the latest is still that one (0: only if new); an empty value is refused unless `--allow-empty` |
| `ferritor delete` | `PATH` | delete every version (restorable within the server's retention) |
| `ferritor restore` | `PATH`, `--version` | undo a delete, or bring back a deleted or trimmed version |
| `ferritor versions` | `PATH` | its history, newest first: metadata only |
| `ferritor list` | `PREFIX` (everything), `--label KEY=VALUE` (repeatable), `--overdue`, `--older-than <n>d` | the latest version of every secret below a prefix, every page. `--overdue`: only secrets with the rotation flag past the server's `rotation_max_age_days`; with `--older-than 60d`, older than 60 days instead (an age cutoff: the overdue ones included, not the due-soon window of the gauges); `--older-than` alone: any secret that old. With either, each line also gives when its version was created ([rotation](/guides/secrets#listing-by-age)) |
| `ferritor metadata get` | `PATH` | created, updated, versions, labels: never the value |
| `ferritor metadata set` | `PATH`, `KEY=VALUE…` | set labels |
| `ferritor metadata unset` | `PATH`, `KEY…` | remove labels |

### Policies

[Policy](/guides/policy): the config rules (read-only here, as
`config:…`) and the stored policies, the applications' grants.

| Command | Options | |
|---|---|---|
| `ferritor policy list` | `--identity` | the config rules and the stored policies |
| `ferritor policy get` | `NAME` | one rule |
| `ferritor policy put` | `NAME`, `--identity`, `--action` (repeatable), `--path` (repeatable) or `--all-paths`, `--description`, `--expected-version` | create or replace one stored policy |
| `ferritor policy delete` | `NAME`, `--expected-version` | delete one |
| `ferritor policy apply` | `-f`/`--file` (TOML or JSON, `-` for stdin), `--prune`, `--dry-run`, `--expected-revision` | make the stored policies match a file in one call, checked here first ([apply](/guides/policy#apply-the-declarative-path)) |
| `ferritor policy check` | `--identity`, `--action`, `--path` | whether an identity may do it, and which rules grant it: exit status 0 if allowed, 1 if not |

### Workload identity

[Workload identity](/guides/workload-identity): platform tokens exchanged
for short-lived certificates.

| Command | Options | |
|---|---|---|
| `ferritor identity init` | | create the issuing CA, once |
| `ferritor identity rotate` | `--now` | a new issuing key; the old one's certificates stay trusted until they expire, unless `--now` |
| `ferritor identity status` | | every issuing key and its state |
| `ferritor login` | `--cert-out`, `--key-out` | exchange `--token-file` at `--exchange` once, and write the certificate and its key (yours alone: `0600`, on Windows a protected access list) for later commands ([the CLI](/guides/workload-identity#the-cli)) |

### Audit log

| Command | Options | |
|---|---|---|
| `ferritor audit verify` | `--public-key` (repeatable) | check a log from stdin, offline: every line's link and every signature; exit status 0 if every entry is signed, 2 if something is unproven, 1 if broken ([verifying](/operations/audit#verifying)) |
