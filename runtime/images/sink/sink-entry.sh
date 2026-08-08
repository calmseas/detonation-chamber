#!/bin/sh
# Answer every DNS name with this container's own address, and serve plain HTTP.
#
# `--address=/#/<ip>` is dnsmasq's catch-all: any name, any query, one answer.
# The unarmed control needs a name that resolves *deterministically*, and a
# public zone is neither.
set -eu

SINK_IP="${SINK_IP:-127.0.0.1}"

# busybox httpd daemonises immediately, so the foreground process is dnsmasq.
# `set -e` above is load-bearing: if the HTTP server cannot start, this whole
# container must die rather than come up as a DNS-only sink that silently fails
# every HTTP row of the control.
mkdir -p /srv
printf 'sink\n' > /srv/index.html
httpd -p 80 -h /srv

exec dnsmasq --no-daemon --log-queries --address="/#/${SINK_IP}" --listen-address=0.0.0.0 --bind-interfaces
