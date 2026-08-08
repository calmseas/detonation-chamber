# The harness sink for the unarmed positive control.
#
# It exists only so the control has something local and deterministic to reach.
# It is NOT part of the chamber and never runs alongside one: its whole purpose
# is to be reachable, which is the opposite of everything else in this tree.
#
# dnsmasq answers every name with its own address, which is what lets the
# unarmed run exercise the getaddrinfo row against a name that resolves --
# without depending on a public zone that could change under us.
#
# `busybox-extras` is what carries the `httpd` applet: it is NOT in the default
# busybox in alpine:3.20, and without it the entrypoint dies on `httpd: not
# found` rather than serving nothing quietly.
FROM alpine:3.20
RUN apk add --no-cache dnsmasq busybox-extras
COPY sink-entry.sh /usr/local/bin/sink-entry
RUN chmod 0755 /usr/local/bin/sink-entry
ENTRYPOINT ["/usr/local/bin/sink-entry"]
