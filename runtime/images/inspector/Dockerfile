# The preflight inspector.
#
# Reads the ENGINE HOST's netfilter state, which is why it is the one image in
# this tree that ever runs with the host's network namespace. It only reads:
# two of the three structural asserts are properties of the host, and there is
# no way to observe them from inside an isolated namespace.
#
# `iptables` here is not a contradiction of the chamber's nftables ruleset.
# Docker programs its own isolation through the iptables-nft shim, so
# `iptables-save` is the interface that shows what DOCKER-INTERNAL and the NAT
# table actually contain.
FROM alpine:3.20
RUN apk add --no-cache iptables iproute2
