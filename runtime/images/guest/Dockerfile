# The agent cell: where the artefact under detonation actually runs.
#
# No CA is baked in. The per-run certificate is written into the cell's tmpfs at
# start and trust is steered by environment variable, because the anchor must be
# fresh per run -- a shared one destroys per-run attribution and one leak
# compromises every run that ever used it. Baking a stable CA here would also be
# the only way to make `update-ca-certificates` work on a read-only rootfs,
# which is exactly the trade this design refuses.
FROM alpine:3.20
RUN apk add --no-cache curl ca-certificates bind-tools

# The agent works from /work — where the tmpfs mounts, the trust anchor is
# placed, and a skill is installed. Without this the cell's cwd is /, and a
# skill that says "run scripts/collect.sh" fails on a path that does not
# resolve — which reads as the skill doing nothing rather than as the
# working-directory mismatch it is. The tmpfs mounts over this at runtime.
WORKDIR /work
