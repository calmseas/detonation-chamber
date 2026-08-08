# The boundary observer: `chamber-boundary`, built for the platform it will run
# on.
#
# Build context is `runtime/`, not this directory, because the build needs the
# workspace:
#
#   docker build -f images/capture/Dockerfile -t chamber-capture:test .
#
# # Debian rather than Alpine, and why that is not laziness
#
# Every other image in this tree is Alpine, and this one is not. `rustls`
# pulls in `aws-lc-rs`, which is a cmake + C build, and `rcgen` pulls in
# `ring` — so BOTH crypto backends compile here. Against musl that is a
# recurring source of link failures which have nothing to do with this project,
# and the failure mode is a broken CI job on one architecture only. glibc keeps
# the variable count down.
#
# The cost is a larger image. It runs one binary on an internal network with no
# route out, so image size is not the thing worth optimising for.
#
# # Never cross-compile this
#
# The chamber runs on aarch64 locally and amd64 in CI, and the bundle records
# which one produced it (`gap.host-arch`) precisely because a payload may behave
# differently across them. Build natively on each; a cross-compiled binary would
# make that record a claim rather than a fact.

FROM rust:slim-bookworm AS builder

# aws-lc-rs needs cmake and a C toolchain. Installed explicitly rather than
# discovered, so a missing one fails here with a package name rather than three
# hundred lines into a build script.
#
# `perl` is deliberately absent from this list even though `ring` needs it: the
# base image already ships /usr/bin/perl, and `perl` is not an installable name
# on bookworm-slim (only `perl-base`), so asking for it fails the whole layer
# for a tool that is already there.
RUN apt-get update \
 && apt-get install -y --no-install-recommends \
      cmake \
      build-essential \
      pkg-config \
 && rm -rf /var/lib/apt/lists/*

WORKDIR /src

# The toolchain pin comes first and alone. It is the layer least likely to
# change, and copying it separately means rustup resolves the pinned version
# once and caches it rather than on every source edit.
COPY rust-toolchain.toml ./
RUN rustc --version

COPY Cargo.toml Cargo.lock ./
COPY crates ./crates

# Only the boundary binary. Building the whole workspace here would drag the
# container-driving crates into an image that must never be able to reach a
# container engine.
RUN cargo build --release -p chamber-capture --bin chamber-boundary

FROM debian:bookworm-slim

# The observer terminates TLS with a CA it generates per run, so it needs no
# trust store of its own — but a runtime that ever reaches outward would, and
# its absence is a confusing way to discover that. Kept minimal and explicit.
RUN apt-get update \
 && apt-get install -y --no-install-recommends ca-certificates \
 && rm -rf /var/lib/apt/lists/*

COPY --from=builder /src/target/release/chamber-boundary /usr/local/bin/chamber-boundary

# No CMD: every argument this process takes arrives by environment, because the
# canaries it watches for are secrets and an argument would put them in the
# process table.
ENTRYPOINT ["/usr/local/bin/chamber-boundary"]
