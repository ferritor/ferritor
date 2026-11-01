# syntax=docker/dockerfile:1
#
# ferritor's images: one build stage compiles every binary, statically linked
# against musl, and each image is that one binary in an empty (`scratch`)
# image: no shell, no libc, no package manager.
#
#   docker build --target server       -t ferritor-server .
#   docker build --target csi-provider -t ferritor-csi-provider .
#   docker build --target agent        -t ferritor-agent .
#   docker build --target cli          -t ferritor-cli .
#
# Each release publishes them, for amd64 and arm64, as
# ghcr.io/ferritor/ferritor-<target>:<version> and :latest, signed with
# cosign (.github/workflows/release-plz.yml).
#
# Each image also carries ferritor's licenses and the third-party notices
# its binary needs (THIRD-PARTY-LICENSES.txt, from cargo-about) under
# /usr/share/doc/ferritor/.
#
# The four share the build stage, so after the first the others take
# seconds. Needs BuildKit (Docker 23+'s default) or Buildah (Podman) for
# the cache mounts. Builds for the platform it runs on, amd64 or arm64.
#
# The base image is pinned by digest (the tag says what it was), like the
# images in e2e/cluster.sh; its Rust version is CI's (.github/workflows/ci.yml).

FROM docker.io/library/rust:1.99.1-slim-trixie@sha256:b8e062b1c3a80183df83d9ba187cadd2b5ab84bc78d453dbfeb2fccd5f982247 AS build
RUN apt-get update \
 && apt-get install -y --no-install-recommends musl-tools protobuf-compiler \
 && rm -rf /var/lib/apt/lists/*
RUN case "$(uname -m)" in \
      x86_64) echo x86_64-unknown-linux-musl ;; \
      aarch64) echo aarch64-unknown-linux-musl ;; \
      *) echo "unsupported architecture $(uname -m)" >&2; exit 1 ;; \
    esac > /target \
 && rustup target add "$(cat /target)"
WORKDIR /src
COPY . .
# Queries are checked against .sqlx/, not a database.
ENV SQLX_OFFLINE=true
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/src/target \
    cargo build --release --locked --target "$(cat /target)" \
      -p ferritor-server -p ferritor-agent -p ferritor-cli \
 && mkdir /out \
 && cd "target/$(cat /target)/release" \
 && cp ferritor-server ferritor-csi-provider ferritor-agent ferritor /out/

FROM scratch AS server
# For the AWS KMS client, which trusts the system's CAs.
COPY --from=build /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
COPY --from=build /out/ferritor-server /usr/local/bin/ferritor-server
COPY LICENSE-MIT LICENSE-APACHE THIRD-PARTY-LICENSES.txt /usr/share/doc/ferritor/
USER 65532:65532
ENTRYPOINT ["/usr/local/bin/ferritor-server"]

FROM scratch AS csi-provider
COPY --from=build /out/ferritor-csi-provider /usr/local/bin/ferritor-csi-provider
COPY LICENSE-MIT LICENSE-APACHE THIRD-PARTY-LICENSES.txt /usr/share/doc/ferritor/
USER 65532:65532
ENTRYPOINT ["/usr/local/bin/ferritor-csi-provider"]

FROM scratch AS agent
COPY --from=build /out/ferritor-agent /usr/local/bin/ferritor-agent
COPY LICENSE-MIT LICENSE-APACHE THIRD-PARTY-LICENSES.txt /usr/share/doc/ferritor/
USER 65532:65532
ENTRYPOINT ["/usr/local/bin/ferritor-agent"]

FROM scratch AS cli
COPY --from=build /out/ferritor /usr/local/bin/ferritor
COPY LICENSE-MIT LICENSE-APACHE THIRD-PARTY-LICENSES.txt /usr/share/doc/ferritor/
USER 65532:65532
ENTRYPOINT ["/usr/local/bin/ferritor"]
