#!/bin/sh
# Build one fabricated-pip guest per H-supplychain rung, with that rung's package
# behaviour BAKED IN at /opt/pkg — invisible to the agent.
#
# Why per-image and not per-run env: the guest's environment is a planted-canary
# surface, not a passthrough, so a rung selector cannot simply be exported into
# the cell. `CHAMBER_IMAGE_GUEST` is a knob the harness already drives per run, so
# selecting the rung by image needs no runtime change at all. The images share
# every expensive layer; only the final COPY differs.
#
#   ./build-rungs.sh                    # all h-mal-* rungs + the generic image
#   ./build-rungs.sh h-mal-warn         # just one
#   ./build-rungs.sh --relay            # all rungs, confound-free relay variant
#   ./build-rungs.sh --relay h-mal-warn # one rung, confound-free relay variant
#
# Produces: chamber-guest-supply-<rung>:test, plus chamber-guest-supply:test
# (generic, empty /opt/pkg, falls back to legacy /work staging). --relay
# produces chamber-guest-supply-<rung>-relay:test instead, from Dockerfile.relay
# — chamber-guest-exec-relay's execrelayd/stub/fabricate-emit/hide-entry
# lineage merged with this rung's payload, so the confound-free condition
# (CHAMBER_CONFOUND_FREE, chamber-run/src/run.rs) has an image to select. An
# ADDITIONAL opt-in tag, never a replacement; --relay never builds the generic
# image (nothing in this design needs a payload-less relay cell).
set -eu

HERE=$(cd "$(dirname "$0")" && pwd)
REPO=$(cd "$HERE/../../.." && pwd)
CORPUS="$REPO/fixtures/corpus/H-supplychain"
RELAY_SRC="$REPO/runtime/images/guest-exec-relay/src"

relay=0
if [ "${1:-}" = "--relay" ]; then
  relay=1
  shift
fi

build() {
  rung=$1 tag=$2
  ctx=$(mktemp -d)
  trap 'rm -rf "$ctx"' EXIT
  if [ "$relay" = 1 ]; then
    cp "$HERE/Dockerfile.relay" "$ctx/Dockerfile"
    mkdir -p "$ctx/relay-src"
    cp "$RELAY_SRC/json.h" "$RELAY_SRC/json.c" "$RELAY_SRC/base64.h" "$RELAY_SRC/base64.c" \
       "$RELAY_SRC/config.h" "$RELAY_SRC/config.c" "$RELAY_SRC/protocol.h" "$RELAY_SRC/protocol.c" \
       "$RELAY_SRC/record.h" "$RELAY_SRC/record.c" "$RELAY_SRC/rewrite.h" "$RELAY_SRC/rewrite.c" \
       "$RELAY_SRC/scratch.h" "$RELAY_SRC/scratch.c" "$RELAY_SRC/relayd.c" "$RELAY_SRC/stub.c" \
       "$RELAY_SRC/fabricate-emit.c" "$RELAY_SRC/hide-entry.c" "$ctx/relay-src/"
  else
    cp "$HERE/Dockerfile" "$ctx/"
  fi
  cp "$HERE/pip-shim.sh" "$ctx/"
  mkdir -p "$ctx/rung"
  if [ -n "$rung" ]; then
    # The fixture is still the single source of truth for the rung's behaviour;
    # it is copied in at build time rather than staged into the cell at run time.
    [ -f "$CORPUS/$rung/.pkg-payload.sh" ] && cp "$CORPUS/$rung/.pkg-payload.sh" "$ctx/rung/payload.sh"
    [ -f "$CORPUS/$rung/.pkg-module.py" ] && cp "$CORPUS/$rung/.pkg-module.py" "$ctx/rung/module.py"
  fi
  printf '  %-34s <- %s\n' "$tag" "${rung:-<generic, legacy /work fallback>}"
  if [ "$relay" = 1 ]; then
    # execrelayd is aarch64-only by decision (relayd.c's own #error); never
    # leave this to the host's default the way the non-relay build does.
    docker build -q --platform linux/arm64 -t "$tag" "$ctx" >/dev/null
  else
    docker build -q -t "$tag" "$ctx" >/dev/null
  fi
  rm -rf "$ctx"
  trap - EXIT
}

suffix=""
[ "$relay" = 1 ] && suffix="-relay"

if [ $# -gt 0 ]; then
  for r in "$@"; do build "$r" "chamber-guest-supply-$r$suffix:test"; done
else
  for d in "$CORPUS"/h-mal-*; do
    r=$(basename "$d")
    build "$r" "chamber-guest-supply-$r$suffix:test"
  done
  [ "$relay" = 1 ] || build "" "chamber-guest-supply:test"
fi
echo "done"
