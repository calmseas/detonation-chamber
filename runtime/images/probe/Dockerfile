# The adversary probe: a purpose-built escape harness that runs in the agent's
# position. It is not the fixture skill, so it cannot pass a containment test by
# being unambitious.
#
# Every tool here exists to answer one row of the probe table. `netcat-openbsd`
# rather than busybox nc because `-z` (connect and close) and `-u -w` are the
# two flags the TCP and UDP rows are built on, and busybox's applet does not
# reliably carry them. `nftables` and `iproute2` are here to be REFUSED: rows 8,
# 9 and 10 assert the cell cannot rewrite or even read the ruleset that contains
# it, and a row that fails with "nft: not found" would pass for the wrong
# reason.
FROM alpine:3.20
RUN apk add --no-cache \
      netcat-openbsd \
      bind-tools \
      curl \
      ca-certificates \
      iproute2 \
      nftables
COPY probe.sh /usr/local/bin/probe
RUN chmod 0755 /usr/local/bin/probe

# Deliberately no ENTRYPOINT. The probe runs two ways: as a one-shot container
# that executes its rows and exits, and as a long-lived cell in the agent's
# position that is exec'd into after the per-run CA has been placed inside it.
# An entrypoint would make the second impossible without an override, and the
# rows that need a trust anchor are exactly the ones that matter most.
