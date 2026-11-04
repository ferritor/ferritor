---
title: 'Development'
description: 'Building and testing ferritor: sqlx with two databases, the tests, lints, CI, the cluster test, load tests and fuzzing.'
seo:
  title: 'Developing ferritor: build, tests, CI and fuzzing'
---
## Prerequisites

- Rust (edition 2024)
- `protoc` on `PATH` (`ferritor-core`'s build compiles the proto with
  `tonic-prost-build`, and `ferritor-agent`'s the Secrets Store CSI Driver's
  provider API, vendored unchanged in `crates/ferritor-agent/proto/`, outside
  `buf`'s module: it isn't ours to restyle)
- Docker or Podman, for the two local databases
- `sqlx-cli` built with the `sqlx-toml` feature (without it, it refuses to
  run in the store crates):
  `cargo install sqlx-cli --no-default-features --features rustls,postgres,sqlx-toml`
- optionally `buf`, to lint and format the proto
- optionally a nightly toolchain and `cargo-fuzz`, for the fuzz targets (see
  "Fuzzing")

```sh
cp .env.example .env
docker compose up -d        # keys DB on port 5433, data DB on 5434, user/password ferritor
```

`.env` holds two pairs of URLs to the same two databases, for different
readers:

- `KEYS_DATABASE_URL`, `DATA_DATABASE_URL`: the build (the `query!` macros
  check SQL against them at compile time), `sqlx-cli` and the tests. Never
  needed in production: a release build uses the committed `.sqlx/` caches
  (`SQLX_OFFLINE=true`), and the server runs its own migrations at startup.
- `FERRITOR_KEYS_DATABASE_URL`, `FERRITOR_DATA_DATABASE_URL`: the server's own
  settings, written as `${KEYS_DATABASE_URL}` and `${DATA_DATABASE_URL}`
  (dotenvy expands them), so each URL is written once.

Other server settings go in `ferritor.toml` (start from `ferritor.example.toml`)
or as more `FERRITOR_*` lines in `.env`.

## Commands

```sh
cargo build
cargo run -p ferritor-server                  # the server
cargo run -p ferritor-cli -- status           # the `ferritor` CLI (`--help` for commands)
cargo test                                 # everything
cargo test -p ferritor-core                   # one crate
cargo test <name_substring>
cargo fmt
cargo clippy --all-targets --all-features --locked -- -D warnings   # warnings are errors
buf lint && buf format -w                  # the proto
```

Benchmark or measure performance only with `--release`. A release build
of the server doesn't read `.env` (only debug builds do; see
[configuration](/reference/configuration)), so export its variables into the shell first:

```sh
set -a; . ./.env; set +a      # the shell expands the ${KEYS_DATABASE_URL} lines too
cargo run --release -p ferritor-server
```

## sqlx with two databases

The `query!` macros check SQL against a live database at compile time, and
each crate can point at only one. So each database has its own crate, whose
`sqlx.toml` names the variable holding its URL: `KEYS_DATABASE_URL` for
`ferritor-keystore`, `DATA_DATABASE_URL` for `ferritor-datastore`. Never put a
query for one database in the other's crate: it would be checked against
the wrong schema.

`sqlx-cli` reads `sqlx.toml` from the current directory, so run it inside
the store crate (it finds the workspace `.env` by searching upwards):

```sh
(cd crates/ferritor-keystore && sqlx migrate run)
(cd crates/ferritor-keystore && sqlx migrate add <name>)    # a new migration
(cd crates/ferritor-keystore && cargo sqlx prepare)           # refresh the offline query cache
(cd crates/ferritor-keystore && cargo sqlx prepare --check)   # fail if it's stale (CI)
```

**Offline builds.** Each store crate commits its query cache in `.sqlx/`.
Without a database URL, or with `SQLX_OFFLINE=true`, the macros use it, so a
fresh checkout or CI builds without databases. After changing a `query!` or
a migration, run `cargo sqlx prepare` in that crate and commit `.sqlx/` with
the change: with `.env` present, local builds check live and won't notice a
stale cache, but `--check` and an offline build will.

The server runs both stores' migrations at startup, on a separate connection
without `statement_timeout`.

**Resetting the development databases.** Nothing has been released, so a
schema may be replaced rather than migrated: both stores' migration
histories were squashed into one `0001` each (the data database's reshaped
into `namespaces`, `paths` and `secret_versions`), and a database migrated
with the old history refuses to start (sqlx: migration 1 was changed, or
migrations applied that are missing here). Start both databases over (this
deletes every local secret and the seal: init again afterwards), either
everything:

```sh
docker compose down -v && docker compose up -d   # -v removes both volumes
```

or only the two development databases, keeping the bench ones (the server,
or `sqlx migrate run` in each store crate, migrates them again):

```sh
docker compose exec -T keys-db psql -U ferritor -d postgres -c 'DROP DATABASE ferritor_keys WITH (FORCE)' -c 'CREATE DATABASE ferritor_keys'
docker compose exec -T data-db psql -U ferritor -d postgres -c 'DROP DATABASE ferritor_data WITH (FORCE)' -c 'CREATE DATABASE ferritor_data'
```

## Tests

Store and server tests are integration tests (`tests/`) against the real
databases, through `ferritor_testkit::TestDatabase`: each test creates its own
`ferritor_<name>_test_*` database from the crate's URL variable, runs the
migrations, and drops it when it passes. A failing test leaves its database
behind for inspection; to clean up:

```sh
for s in keys-db data-db; do echo "SELECT format('DROP DATABASE %I WITH (FORCE)', datname) FROM pg_database WHERE datname LIKE 'ferritor\_%\_test\_%' \gexec" | docker compose exec -T $s psql -U ferritor -d postgres -q; done
```

TLS tests use `ferritor_testkit::pki::Ca`, which makes certificates and CRLs at
run time, and workload-identity tests `ferritor_testkit::jwt::TokenIssuer`
(an Ed25519 key, its JWKS and the tokens it signs), so no keys are checked
in but one: `crates/ferritor-server/tests/fixtures/jwt-test-rsa.pk8`, an
RSA-2048 key for the RS256 and RSA-CSR tests (`ring` can't generate RSA
keys), which signs nothing outside them. Audit entries are read through
`ferritor_testkit::Captured::lines`, which hides the hash chain's own lines and
fields (`Captured::raw` has the bytes). CLI tests run the real `ferritor`
binary against an in-process server. The metrics test has its own binary,
since the OpenTelemetry provider is process-wide.

Auto-unseal is tested with `MemoryKms`, a provider that keeps its key in
memory (and can be switched off or slowed). The AWS client itself has one
test against the real service, `tests/aws_kms.rs`, which runs only when
`FERRITOR_TEST_AWS_KMS_KEY` names a key (its ARN) the caller may use, with
credentials from the SDK's usual chain; otherwise it returns at once:

```sh
aws sso login --profile dev
AWS_PROFILE=dev FERRITOR_TEST_AWS_KMS_KEY=arn:aws:kms:…:key/… \
  cargo test -p ferritor-server --test aws_kms
```

It needs `kms:Encrypt`, `kms:Decrypt` and `kms:DescribeKey` on the key.
Without the `aws-kms` feature (`--no-default-features`) the server builds
without the AWS SDK, and `[seal] provider = "awskms"` refuses to start.

### The CSI provider in a cluster

The provider's tests stand in for the driver and the kubelet, so they
can't show what those really do. `e2e/cluster.sh` runs it against the
real ones, in k3s through k3d, with the Secrets Store CSI Driver's chart
(the chart by version, every image by digest, in the script); CI runs it
on every change (`cluster`, below):

```sh
cargo build --release --locked -p ferritor-cli
e2e/cluster.sh              # creates the cluster ferritor-e2e, deletes it at the end
KEEP=1 e2e/cluster.sh       # keeps it, to look around (k3d cluster delete ferritor-e2e)
```

It needs k3d, kubectl, helm, openssl and docker (podman's works). A
secured server and Postgres run in the cluster (a server on the host may
be unreachable from it), the cluster's service account tokens trusted for
workload identity. The server and the provider run from the
[images](#images), which the script builds and imports into the cluster
(through files, so k3d needn't share the store of the runtime that built
them); the CLI runs on the host. Then it checks, each failing the run with
the pods' events and the logs:

- a pod mounting a `prefix` volume (with a subdirectory) and an `objects`
  volume, read by a non-root user;
- a new version and a new secret arriving at a refresh;
- a denied path keeping its pod in `ContainerCreating`, the server asked
  once through the kubelet's retries;
- sealed: a new pod waits, never `Running` with an empty volume, a running
  pod keeps its files, and the new pod starts once unsealed;
- a revoked grant, the value kept (`onRevoked = "keep"`);
- the exchange refusing a pod's default token and mapping a `ferritor` one.

A run takes about ten minutes, mostly the refreshes it waits for.

## Images

The `Dockerfile` builds one image per binary, each the binary alone in an
empty (`scratch`) image:

```sh
docker build --target server       -t ferritor-server .
docker build --target csi-provider -t ferritor-csi-provider .
docker build --target agent        -t ferritor-agent .
docker build --target cli          -t ferritor-cli .
```

Each release publishes the four on ghcr.io, for amd64 and arm64:
`ghcr.io/ferritor/ferritor-server`, `ferritor-csi-provider`,
`ferritor-agent` and `ferritor-cli`, tagged with the version (`0.9.1`)
and `latest` (see [Releases](#releases)).

- One build stage compiles all four, statically linked against musl
  (`SQLX_OFFLINE`, from `.sqlx/`), for the platform the build runs on,
  amd64 or arm64; after the first, the others take seconds. Its cache
  mounts (the cargo registry and `target/`) need BuildKit (Docker 23 and
  later) or Podman.
- Nothing but the binary is in an image: no shell, no libc, no tools. The
  server's also has the build image's CA bundle
  (`/etc/ssl/certs/ca-certificates.crt`), for the AWS KMS client, which
  trusts the system's CAs. So an `exec` probe or an agent's `on_change`
  command can't run anything from the image. They run as UID and GID
  65532 unless the pod says otherwise (the CSI provider's DaemonSet runs
  it as root, for the driver's socket directory).
- The server's static build allocates with mimalloc (for `target_env =
  "musl"` only): with musl's own allocator, reads were 2.8 times slower
  ([performance](/operations/performance#the-images)).
- The build context is an allowlist (`.dockerignore`): `Cargo.toml`,
  `Cargo.lock`, `crates/` without their tests, and `proto/`. Never
  `target/`, `.env`, or a key lying around.

## Licenses

ferritor is MIT OR Apache-2.0 (`LICENSE-MIT`, `LICENSE-APACHE`; `license`
in `[workspace.package]`, inherited by every crate, like `publish = false`:
nothing goes to crates.io). Its dependencies' licenses are held to a list,
twice:

- `cargo deny --workspace check licenses` fails on a dependency under any license not
  in `deny.toml`'s `[licenses] allow` (CI's `advisories` job).
- `THIRD-PARTY-LICENSES.txt` holds the notices the binaries' dependencies
  require (each crate's license text and copyright lines; MIT for a crate
  that offers a choice), and every image carries it under
  `/usr/share/doc/ferritor/`, with ferritor's own two files. `cargo-about`
  generates it from `Cargo.lock` (`about.toml`, `about.hbs`): the musl
  targets' runtime dependencies, not dev- or build-only ones, and not
  ferritor's own crates. Generated offline, from the downloaded crates
  alone, so it's the same on every machine. CI's `lint` fails while it's
  stale, so regenerate it with any `Cargo.lock` change:

```sh
cargo fetch --locked   # every platform's crates, the musl-only ones too
cargo about generate --frozen --workspace about.hbs -o THIRD-PARTY-LICENSES.txt
```

A crate holding two texts of one license (a Rust wrapper's and the C
library's it compiles in, say) is named in `about.toml` with a `clarify`
section, each file by checksum: otherwise which text cargo-about picks
depends on the order the filesystem lists them in, and the file differs
between machines (`libmimalloc-sys` did, CI against a laptop).

A new license (a dependency under one neither list has) goes into both
`deny.toml` and `about.toml`'s `accepted`, after deciding it can be
distributed in the images: a copyleft one can't, without changing what
ferritor's own license allows.

## Lints and conventions

The workspace lints deny `unwrap_used`, `expect_used` and
`allow_attributes`, and forbid `unsafe_code`: return an error instead of
panicking, and use `#[expect]` rather than `#[allow]`. Generated proto code is
exempted. In tests `unwrap` is fine, but test helpers outside `#[test]`
functions return `TestResult`.

- Errors: `thiserror` in libraries and for server errors that map to
  status codes, `anyhow` only at a binary's top level. An error variant with
  a source doesn't also interpolate it in its message.
- Postgres has no unsigned integers: versions and counts are `INTEGER` with
  `CHECK`s, while the APIs use `u32`/`u8`; convert with `try_from`, never
  `as`.
- Every store call is bounded client side (a timeout around each method),
  since Postgres's own timeouts can't see a hung connection.
- Share count and threshold always travel together as `ShareParams`.
- A new condition the gRPC code alone can't tell apart gets a reason in
  `ferritor_core::messages::reason`.

## Debugging and profiling

The server marks itself undumpable first thing, in debug builds too (see
[security](/concepts/security)): `gdb`, `lldb`, `perf` and profilers that attach to
a running process (`py-spy`, `cargo flamegraph --pid`) can't attach to it as
your own user, `/proc/<pid>/` belongs to root, and a crash writes no core
dump. Development behaves as production here on purpose; the bench server
is the same. Either use `sudo`, or start the server under the tool: a
tracer attached before the call keeps its access (checked with
`gdb --args target/release/ferritor-server`; `perf record --` and
`cargo flamegraph` running the server themselves should behave alike, but
weren't tried).

## Load tests

`bench/` runs a secured `--release` server against its own databases and
loads it with `oha` (and `pgbench` for Postgres alone): see the results in
[performance](/operations/performance). Never measure performance with a debug build
or in dev mode.

## CI

`.github/workflows/ci.yml` runs on every pull request and every push to
`main`:

| Job | Runs |
|---|---|
| `lint` | `cargo fmt --check`; `shellcheck bench/*.sh e2e/*.sh`; the offline build (`SQLX_OFFLINE=true`, from `.sqlx/`, no databases); `clippy -D warnings`; `cargo doc` with `-D warnings`; `THIRD-PARTY-LICENSES.txt` regenerated and compared ([Licenses](#licenses)) |
| `proto` | `buf lint`, `buf format --diff --exit-code`, `buf breaking` against the pull request's base (a push: the commit before it, or its parent after a force-push) |
| `test` | the two Postgres servers as in `compose.yaml`; the migrations; `cargo sqlx prepare --check` in both store crates; `cargo test --workspace` |
| `fuzz` | the fuzz crate's fmt and clippy; that `fuzz/Cargo.lock` has Cargo.lock's version of every crate both name; then every target (see "Fuzzing") for 30 s, daily 5 minutes, from its seeds and the corpus the previous run left (cached). Every target runs even after one crashes; a crash's input is kept as the run's `fuzz-artifacts` |
| `cluster` | `e2e/cluster.sh` (above), after a release build of the CLI: the server's and the provider's images built, the CSI provider with the real driver and kubelet in k3s, k3d pinned and its download checked; then the agent's and the CLI's images, so every target builds |
| `advisories` | `cargo deny check advisories sources` (`deny.toml`; `--workspace` for the main one, whose root is a package), for both lockfiles: a RUSTSEC vulnerability, an unmaintained crate, a yanked version, or a crate from anywhere but crates.io fails the build. Also daily, since new advisories land without a change here. For the main lockfile `licenses` too: a dependency under a license not in `deny.toml`'s list fails it (the fuzz crate is never distributed) |

`.github/workflows/docs.yml` builds the docs site on the same events
(`build`, with Astro's own action: install, build, and the site uploaded
for GitHub Pages), so a broken internal link, an SEO audit error or a page
that doesn't render fails it. It runs on every change, not only to
`docs/`, so it can be a required check too (a workflow a path filter
skips never reports). On `main` only, `deploy` then publishes the build
to GitHub Pages, <https://ferritor.dev>: the only job that may, with the
repository's Pages source set to "GitHub Actions" and the custom domain
in its Pages settings. A pull request's build is never published.

A pull request is checked before it merges only if these seven jobs (the
six above and the docs' `build`) are
required status checks on `main` (branch protection); a push straight
to `main` is checked after it has landed. To run the same checks locally:

```sh
cargo fmt --all --check
shellcheck bench/*.sh e2e/*.sh
SQLX_OFFLINE=true cargo build --workspace --all-targets --locked
cargo clippy --workspace --all-targets --all-features --locked -- -D warnings
RUSTDOCFLAGS="-D warnings" cargo doc --workspace --no-deps --locked
buf lint && buf format --diff --exit-code && buf breaking --against '.git#branch=main'
(cd crates/ferritor-keystore && cargo sqlx prepare --check)
(cd crates/ferritor-datastore && cargo sqlx prepare --check)
cargo test --workspace --locked
cargo deny --workspace check advisories sources licenses
cargo fetch --locked && cargo about generate --frozen --workspace about.hbs -o THIRD-PARTY-LICENSES.txt && git diff --exit-code THIRD-PARTY-LICENSES.txt
cargo deny --manifest-path fuzz/Cargo.toml check advisories sources
(cd docs && pnpm install --frozen-lockfile && pnpm build)
```

Pinned, so a new release can't fail `main` with nothing changed here; bump
each deliberately, and fix what the new version finds in the same change:

- **The Rust toolchain**: `dtolnay/rust-toolchain`'s commit for the
  version's branch (`1.99.1`, in the comment beside it: the branch's
  action has the version built in, and takes no `toolchain:` input), in
  every job that uses it, and the
  `rust` image in the `Dockerfile` (its tag, `1.99.1-slim-trixie`, and its
  digest). Use the same version locally, or local clippy and CI's can
  disagree.
- **buf**: `version:` of `buf-action` (`1.73.0`); its lint and format rules
  change between releases. Use the same locally.
- **sqlx-cli**: `SQLX_CLI_VERSION`, kept at the `sqlx` version in
  `Cargo.lock`.
- **k3d**, for `cluster`: `K3D_VERSION` and `K3D_SHA256` (from the
  release's `checksums.txt`). The images `e2e/cluster.sh` uses (k3s,
  Postgres, busybox) by digest, the tag kept beside it to say what
  it was, and the driver's chart by version. The images come from Docker
  Hub anonymously, whose pull limit is per IP address and shared by CI's
  runners: if runs start failing on pulls, point them at a pull-through
  mirror.
- **Nightly and cargo-fuzz**, for `fuzz` only: `toolchain:` (a dated
  nightly) and `CARGO_FUZZ_VERSION`.
- **release-plz**: the action's commit and its `version:` (`0.4.2`) in
  `release-plz.yml`; use the same locally. The artifact actions there
  (the images' digests) by commit too, and cosign: the installer by
  commit, cosign itself by `cosign-release:` (`v3.1.4`), which the
  installer checks by signature. A new major version can change what a
  signature looks like, so check `cosign verify` with the docs' command
  after a bump.
- **cargo-about**: `tool: cargo-about@0.9.0` in `lint`, installed by
  `taiki-e/install-action` (by commit), which checks the download against
  its recorded checksum. A new version can word the notices differently:
  regenerate the file with it in the same change.
- **Node and pnpm**, for the docs: `node-version` in `docs.yml`, and
  `packageManager` in `docs/package.json` (which pnpm itself honours
  locally too), the versions `docs/pnpm-lock.yaml` was written with.
- **Actions**: by commit, the tag in a comment; update both together.
  Dependabot does (`.github/dependabot.yml`): one grouped pull request a
  week, `ci:` commits, a release only once it's a week old (`cooldown`),
  so a compromised one is likely pulled before this build runs it. Review
  it like any other: it changes what runs with this repository's tokens.
  Not `dtolnay/rust-toolchain`, whose pins are Rust versions (above),
  bumped by hand.

Also:

- **An advisory** is fixed by updating the crate (`cargo update -p <crate>`).
  Only if that's impossible, add it to `deny.toml`'s `ignore`, with the
  reason and a date to look again.
- **The daily run stops on a quiet repository**: GitHub disables scheduled
  workflows after 60 days without activity on a public repository.
  Re-enable it under Actions, or the advisory check silently stops.
- **Checkouts keep no token** (`persist-credentials: false`): nothing here
  pushes, and every build script and proc-macro runs in these jobs.
- **Time limits**: 30 minutes for `test`, 90 for `fuzz`, 20 for the rest,
  so a hung test or database doesn't hold a runner for six hours.

## Releases

[release-plz](https://release-plz.dev) versions, writes the changelogs,
tags and creates the GitHub release (`release-plz.toml`,
`.github/workflows/release-plz.yml`). Nothing goes to crates.io: versions
come from git tags (`git_only`).

- **The release pull request.** `release-pr` opens or updates it when
  started by hand: Actions, Release-plz, **Run workflow**, on `main`. It
  holds the next version and the changelogs' new section, which can be
  edited there before merging. Run at every push, it rebuilt the pull
  request and ran its checks after every change. It refuses to run while a
  release is on its way (a release pull request merged, not yet tagged,
  because `CI` hasn't passed on it): it would offer that version again.
  release-plz bumps the versions in `Cargo.lock` only, so `release-pr`
  adds a commit of its own with `fuzz/Cargo.lock` brought in line (the
  fuzz crate's lockfile records the ferritor crates' versions too, and CI
  builds it `--locked`). Merging it releases, and nothing else does
  (`release_always = false`): once `CI` has passed on the merge commit,
  `release` tags that very commit and creates the GitHub release from the
  root changelog, as a **draft**. A push that isn't a release pull
  request's merge is never released, and a merge whose `CI` fails isn't
  either.
- **Draft, then published**: the repository's releases are immutable once
  published (no asset can be added after), so the workflow completes the
  draft first. `release-assets` attaches the binaries, `SHA256SUMS` and a
  cosign bundle (`.sigstore.json`) for each file, appends the images'
  digests and how to verify to the notes, and only then publishes. If it
  fails the release stays a draft, and re-running the job completes it.
- **Binaries**: `ferritor-<version>-x86_64-unknown-linux-musl.tar.gz` and
  the `aarch64` one, each the four static binaries (`ferritor-server`,
  `ferritor-csi-provider`, `ferritor-agent`, `ferritor`) with
  `LICENSE-MIT`, `LICENSE-APACHE` and `THIRD-PARTY-LICENSES.txt`: the same
  build as the images (the Dockerfile's `binaries` target), packed
  reproducibly (sorted, the commit's time, no owners, no gzip timestamp).
  Each is signed keyless with cosign, as the images are, so `cosign
  verify-blob` with the same identity checks it.
- **Images**: a release then builds the [images](#images) from the
  released commit, each architecture on its own runner (`images`, amd64 on
  `ubuntu-24.04`, arm64 on `ubuntu-24.04-arm`: natively, since Rust under
  emulation takes hours), pushes them to ghcr.io by digest, and
  `image-tags` tags each under the version and `latest`, both
  architectures under one name, and signs it with cosign, keyless (by
  digest, each architecture's image too, `--recursive`): the certificate
  names `release-plz.yml` on `main`, which is what users verify
  ([Kubernetes](/getting-started/kubernetes#what-you-need)). A new package
  on ghcr.io starts private: make each public once, in its package
  settings.
- **One version for every crate** (`version.workspace`, one
  `version_group`), so a release bumps them all.
- **Changelogs**: each crate's `CHANGELOG.md` beside its `Cargo.toml`,
  with the commits that touched its directory (release-plz counts a
  package's own files only). The server's is the root `CHANGELOG.md`, the
  product's: its commits, every other released crate's, and the workspace
  root package's. That one, `ferritor` (`src/lib.rs`, no code), exists
  for this: it owns every file outside `crates/` (`Cargo.lock`, the
  Dockerfile, the workflows, the docs, `deny.toml`), so a commit to those
  (a dependency's security fix, a CI change) is in the product's
  changelog too. It writes no changelog of its own. `ferritor-testkit`
  isn't released.
- **Tags**: `v0.9.1` for the product (the server's), with the GitHub
  release; `ferritor-core-v0.9.1` and so on for the crates, and
  `ferritor-workspace-v0.9.1` for the root package: that's how release-plz
  finds each one's previous release. A tag ruleset lets only the App
  create, move or delete them.
- **Commit subjects** sort a commit into the changelog by their start:
  `feat` (Added), `changed`, `deprecated`, `removed`, `fix` (Fixed),
  `perf` (Performance), `security`; anything else is Other. With
  [conventional commits](https://www.conventionalcommits.org/) the start
  also chooses the version: `fix` a patch, `feat` a minor (a patch while
  below 1.0), a breaking change (`feat!:`) a major (a minor below 1.0).
- **The release pull request is opened by a GitHub App**,
  `ferritor-release`, not with the workflow's own token: a pull request
  opened with `GITHUB_TOKEN` starts no other workflow, so `CI` and `Docs`
  wouldn't run on it. `release-pr` mints the App's token for itself
  (`actions/create-github-app-token`: an hour at most, this repository,
  contents and pull requests), from the private key in the `release-plz`
  environment's secret `RELEASE_PLZ_APP_PRIVATE_KEY`, which only `main`
  may use, and the variable `RELEASE_PLZ_APP_CLIENT_ID`. `release` runs
  as the App too, with contents write and pull requests read: a tag
  ruleset lets only the App create release tags (`v*`, `ferritor-*-v*`),
  since `GITHUB_TOKEN` can't bypass a ruleset. The image jobs keep
  `GITHUB_TOKEN`, for ghcr.io.
- **A merge whose `CI` fails** is never released; fix it on a branch whose
  name starts with `release-plz-`, whose merge release-plz releases once
  `CI` passes.

To see what the next release would write, in a throwaway worktree of
`HEAD`. Preview only what's committed: the worktree has only the
committed files (an uncommitted `release-plz.toml` change isn't in it),
and release-plz stashes anything uncommitted it finds into the
repository's shared stash, and leaves it there.

```sh
git worktree add /tmp/release-preview HEAD
(cd /tmp/release-preview && SQLX_OFFLINE=true release-plz update)
git -C /tmp/release-preview diff; git worktree remove --force /tmp/release-preview
```

## Fuzzing

`proptest` checks properties on generated inputs; `fuzz/` adds
coverage-guided fuzzing (cargo-fuzz, libFuzzer) where input comes from
outside, or where a mistake would weaken a guarantee:

| Target | What | Must hold |
|---|---|---|
| `secret_path` | `SecretPath`, `Namespace` (the AAD binds a path's bytes) | accepted exactly when canonical (restated independently), never rewritten; the namespace is the first segment; `descendant_range` holds exactly the paths `is_under` |
| `labels` | keys, values, `key=value`, changes | accepted exactly per the documented rules, restated independently; a pair splits at the `=` and loses nothing |
| `policy_spec` | `PolicySpec::validate`, from JSON, TOML or the fields | a valid policy keeps every limit; its canonical form (`Policy::spec`, what's signed) is a fixed point and survives the JSON round trip |
| `policy_encoding` | the stored policies' MAC messages | different rows (or sets) never encode alike, near-misses included (a field boundary moved, an item moved between lists) |
| `audit_verify` | `ferritor audit verify` on any bytes | no panic; proven only if every chain is one a writer wrote (the seeds') |
| `audit_tamper` | real logs from `Chain`, then edited (lines deleted, copied, swapped, inserted, cut, bits flipped) | unedited: each chain judged as written; edited: proven only if still made of the genuine chains |
| `crl_parse` | `Crls::parse` (`[tls] crl`): a CRL's DER, the file's text, or a CA certificate | no panic; a file that loads has one CRL per client CA |

The fuzz crate is its own workspace (`fuzz/Cargo.toml`, `fuzz/Cargo.lock`),
outside the main build. Its lockfile is the main one plus the fuzz crates,
so a target fuzzes the versions the server ships; CI fails if a crate both
name differs. After changing `Cargo.lock` (a `cargo update`), refresh it
the same way, not with a `cargo update` of its own:

```sh
cp Cargo.lock fuzz/Cargo.lock && cargo fetch --manifest-path fuzz/Cargo.toml
```

It needs a nightly toolchain and `cargo-fuzz`:

```sh
cargo +nightly fuzz list
SQLX_OFFLINE=true cargo +nightly fuzz run audit_verify fuzz/corpus/audit_verify fuzz/seeds/audit_verify
SQLX_OFFLINE=true cargo +nightly fuzz run labels -- -max_total_time=60
SQLX_OFFLINE=true cargo +nightly fuzz run <target> fuzz/artifacts/<target>/crash-…   # replay a crash
```

- **Seeds and fixtures** (`fuzz/seeds/`, `fuzz/fixtures/`) are committed:
  genuine audit logs signed with the targets' fixed test key, and a
  throwaway CA's certificate with CRLs it signed (its key is discarded; no
  private key is checked in). `cargo run --manifest-path fuzz/Cargo.toml
  --example seeds` regenerates them all at once (a new CA each time, so the
  CRLs and the certificate always match). The corpus libFuzzer grows
  (`fuzz/corpus/`) and its crashes (`fuzz/artifacts/`) aren't committed;
  CI keeps its corpus between runs in the Actions cache, and the daily run
  first shrinks it to the inputs that add coverage (`cargo fuzz cmin
  <target>`).
- **A crash** is a bug or a wrong oracle: fix whichever it is, and turn the
  input into a unit test in the crate (as
  `audit_chain::tests::damage_after_the_end_is_never_proven`).
- **A new parser** of outside input, or a new encoding a MAC or signature
  covers, gets a target: a `[[bin]]` in `fuzz/Cargo.toml` and
  `fuzz/fuzz_targets/<name>.rs`, asserting what must hold, not only that
  nothing panics; CI runs every target `cargo fuzz list` names.
