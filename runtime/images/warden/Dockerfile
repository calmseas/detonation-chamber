# The warden owns the network namespace the agent cell runs in.
#
# It is the only container in the chamber that holds CAP_NET_ADMIN, and the
# agent gets its stack by joining this namespace (`--network container:warden`)
# rather than by being handed one it could alter. That split is what makes rows
# 8 and 9 of the probe table refusals rather than assertions of good behaviour:
# the cell has no capability to change rules that were installed from outside
# it.
#
# `tcpdump` is not a debugging convenience here. Netfilter's `log prefix ...
# level warn` emits ZERO dmesg lines inside a container netns -- verified, and
# silent, which is the worst kind of evidence loss. The ruleset therefore logs
# to an NFLOG group and `tcpdump -i nflog:N` is the collector that reads it.
FROM alpine:3.20
RUN apk add --no-cache nftables iproute2 tcpdump conntrack-tools
