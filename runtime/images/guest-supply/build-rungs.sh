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
#   ./build-rungs.sh            # all h-mal-* rungs + the generic image
#   ./build-rungs.sh h-mal-warn # just one
#
# Produces: chamber-guest-supply-<rung>:test, plus chamber-guest-supply:test
# (generic, empty /opt/pkg, falls back to legacy /work staging).
set -eu

HERE=$(cd "$(dirname "$0")" && pwd)
REPO=$(cd "$HERE/../../.." && pwd)
CORPUS="$REPO/fixtures/corpus/H-supplychain"

build() {
  rung=$1 tag=$2
  ctx=$(mktemp -d)
  trap 'rm -rf "$ctx"' EXIT
  cp "$HERE/Dockerfile" "$HERE/pip-shim.sh" "$ctx/"
  mkdir -p "$ctx/rung"
  if [ -n "$rung" ]; then
    # The fixture is still the single source of truth for the rung's behaviour;
    # it is copied in at build time rather than staged into the cell at run time.
    [ -f "$CORPUS/$rung/.pkg-payload.sh" ] && cp "$CORPUS/$rung/.pkg-payload.sh" "$ctx/rung/payload.sh"
    [ -f "$CORPUS/$rung/.pkg-module.py" ] && cp "$CORPUS/$rung/.pkg-module.py" "$ctx/rung/module.py"
  fi
  printf '  %-34s <- %s\n' "$tag" "${rung:-<generic, legacy /work fallback>}"
  docker build -q -t "$tag" "$ctx" >/dev/null
  rm -rf "$ctx"
  trap - EXIT
}

if [ $# -gt 0 ]; then
  for r in "$@"; do build "$r" "chamber-guest-supply-$r:test"; done
else
  for d in "$CORPUS"/h-mal-*; do
    r=$(basename "$d")
    build "$r" "chamber-guest-supply-$r:test"
  done
  build "" "chamber-guest-supply:test"
fi
echo "done"
