#!/bin/sh
# The adversary probe.
#
# Runs in the agent's position and tries to get out, one technique per line of
# JSON on stdout. It is deliberately NOT the fixture skill: a fixture can pass a
# containment test by being unambitious, and this cannot.
#
# # It never exits non-zero because a technique failed
#
# Every row here is a measurement. A technique that fails is the expected result
# in an armed run and a FAILING CONTROL in an unarmed one, and only the harness
# knows which run this is. Exiting non-zero on a blocked technique would make
# the two indistinguishable to anything reading the exit code.
#
# # Targets come from the environment
#
# The same probe, with the same code path per row, runs twice: once with
# nothing blocking it, to prove it is capable of succeeding, and once inside
# the chamber. Rows 1, 2, 4 and 11 use IDENTICAL targets in both runs -- they
# are the ones that defend against a typo'd destination, because a probe aimed
# at an address nobody serves fails identically to one that was contained.
#
# Rows 5 and 6 cannot: armed, the capture sink answers every name, so
# `anything.example` resolves to the capture address; unarmed, against real
# DNS, `.example` is a reserved TLD that NXDOMAINs. Holding the target fixed
# there would fail the control for a reason unrelated to containment. So the
# harness moves the destination and the mechanism stays put.

TIMEOUT="${PROBE_TIMEOUT:-6}"

# Destinations. Defaults are the armed (in-chamber) expectations.
T_TCP_IP="${T_TCP_IP:-8.8.8.8}"
T_TCP_PORT="${T_TCP_PORT:-443}"
T_DNS_IP="${T_DNS_IP:-1.1.1.1}"
T_DNS_NAME="${T_DNS_NAME:-probe.invalid}"
T_CAPTURE_IP="${T_CAPTURE_IP:-10.66.0.10}"
T_CAPTURE_BADPORT="${T_CAPTURE_BADPORT:-9999}"
T_ICMP_IP="${T_ICMP_IP:-8.8.8.8}"
T_HTTPS_URL="${T_HTTPS_URL:-https://example.com}"
T_RESOLVE_NAME="${T_RESOLVE_NAME:-anything.example}"
T_LISTEN_PORT="${T_LISTEN_PORT:-8000}"
T_UDP_PORT="${T_UDP_PORT:-443}"

# JSON with no string escaping is a landmine, so `detail` is stripped of
# everything that would need escaping rather than escaped. Detail is for a
# human reading a failure; fidelity below the line matters less than the file
# still parsing when a tool prints something unexpected.
emit() {
    _row="$1"
    _ok="$2"
    _target="$3"
    _detail=$(printf '%s' "$4" | tr -d '"\\' | tr '\n\r\t' '   ' | cut -c1-300)
    printf '{"row":"%s","ok":%s,"target":"%s","detail":"%s"}\n' \
        "$_row" "$_ok" "$_target" "$_detail"
}

# `nc -z` is a connect-and-close. Exit 0 means the TCP handshake completed,
# which is exactly the question rows 1 and 3 ask.
row_tcp_ip_literal() {
    out=$(nc -w "$TIMEOUT" -z "$T_TCP_IP" "$T_TCP_PORT" 2>&1)
    rc=$?
    [ $rc -eq 0 ] && emit tcp_ip_literal true "$T_TCP_IP:$T_TCP_PORT" "connected" \
        || emit tcp_ip_literal false "$T_TCP_IP:$T_TCP_PORT" "rc=$rc $out"
}

row_tcp_capture_wrong_port() {
    out=$(nc -w "$TIMEOUT" -z "$T_CAPTURE_IP" "$T_CAPTURE_BADPORT" 2>&1)
    rc=$?
    [ $rc -eq 0 ] && emit tcp_capture_wrong_port true "$T_CAPTURE_IP:$T_CAPTURE_BADPORT" "connected" \
        || emit tcp_capture_wrong_port false "$T_CAPTURE_IP:$T_CAPTURE_BADPORT" "rc=$rc $out"
}

# Straight at a public resolver, bypassing whatever the cell was told to use.
# The QNAME is the payload: an armed run must still recover the name from the
# NFLOG frame even though the query never got an answer.
row_udp_dns_direct() {
    out=$(dig +time=3 +tries=1 "@$T_DNS_IP" "$T_DNS_NAME" 2>&1)
    rc=$?
    if [ $rc -eq 0 ] && ! printf '%s' "$out" | grep -q "no servers could be reached"; then
        status=$(printf '%s' "$out" | sed -n 's/.*status: \([A-Z]*\).*/\1/p' | head -1)
        emit udp_dns_direct true "$T_DNS_IP/$T_DNS_NAME" "answered status=$status"
    else
        emit udp_dns_direct false "$T_DNS_IP/$T_DNS_NAME" "rc=$rc no answer"
    fi
}

# ICMP without CAP_NET_RAW needs the unprivileged ping socket, which is only
# available when the cell's `net.ipv4.ping_group_range` admits its gid. If this
# row fails in the UNARMED run it is the sysctl, not the containment -- which
# is precisely the confusion the control exists to surface rather than hide.
row_icmp_echo() {
    out=$(ping -c 1 -W 3 "$T_ICMP_IP" 2>&1)
    rc=$?
    [ $rc -eq 0 ] && emit icmp_echo true "$T_ICMP_IP" "reply received" \
        || emit icmp_echo false "$T_ICMP_IP" "rc=$rc $out"
}

row_https() {
    code=$(curl -sS --max-time "$TIMEOUT" -o /dev/null -w '%{http_code}' "$T_HTTPS_URL" 2>"${TMPDIR:-/tmp}/curl.err")
    rc=$?
    if [ $rc -eq 0 ]; then
        emit https true "$T_HTTPS_URL" "http_code=$code"
    else
        emit https false "$T_HTTPS_URL" "rc=$rc $(cat "${TMPDIR:-/tmp}/curl.err") code=$code"
    fi
}

# getent, not dig: this is the resolver path an artefact's runtime actually
# takes (nsswitch -> the cell's configured resolver), and dig would bypass it.
row_getaddrinfo() {
    out=$(getent hosts "$T_RESOLVE_NAME" 2>&1)
    rc=$?
    if [ $rc -eq 0 ]; then
        addr=$(printf '%s' "$out" | awk '{print $1}' | head -1)
        emit getaddrinfo true "$T_RESOLVE_NAME" "resolved_to=$addr"
    else
        emit getaddrinfo false "$T_RESOLVE_NAME" "rc=$rc unresolved"
    fi
}

# UDP is connectionless, so a successful `send` proves nothing on its own: the
# datagram is accepted by the local stack whether or not anything is reachable.
# What IS measurable is whether the stack refused to send it at all -- an armed
# cell with a drop policy returns EPERM on send, which an unarmed one does not.
# This row is therefore honestly weaker than the TCP ones, and it is the reason
# UDP/QUIC is a declared gap rather than a covered channel.
row_udp_high() {
    out=$(printf '\x0d\x00\x00\x00\x01' | nc -u -w 2 "$T_ICMP_IP" "$T_UDP_PORT" 2>&1)
    rc=$?
    [ $rc -eq 0 ] && emit udp_high true "$T_ICMP_IP:$T_UDP_PORT" "datagram accepted by stack" \
        || emit udp_high false "$T_ICMP_IP:$T_UDP_PORT" "rc=$rc $out"
}

# An empty bounding set is the claim being tested: not "we dropped privileges"
# but "they cannot be regained", which is what makes a root shell in the cell
# harmless.
row_nft_flush() {
    out=$(nft flush ruleset 2>&1)
    rc=$?
    [ $rc -eq 0 ] && emit nft_flush true "ruleset" "FLUSHED -- the cell can rewrite its own containment" \
        || emit nft_flush false "ruleset" "rc=$rc $out"
}

row_ip_route_add() {
    out=$(ip route add default via "$T_CAPTURE_IP" 2>&1)
    rc=$?
    [ $rc -eq 0 ] && emit ip_route_add true "default via $T_CAPTURE_IP" "ROUTE ADDED" \
        || emit ip_route_add false "default via $T_CAPTURE_IP" "rc=$rc $out"
}

row_nft_list() {
    out=$(nft list ruleset 2>&1)
    rc=$?
    [ $rc -eq 0 ] && emit nft_list true "ruleset" "readable" \
        || emit nft_list false "ruleset" "rc=$rc $out"
}

row_capbnd() {
    bnd=$(awk '/^CapBnd:/ {print $2}' /proc/self/status)
    [ "$bnd" = "0000000000000000" ] \
        && emit capbnd true "CapBnd" "empty bounding set: $bnd" \
        || emit capbnd false "CapBnd" "NON-EMPTY bounding set: $bnd"
}

case "${1:-all}" in
    all)      rows="tcp_ip_literal udp_dns_direct tcp_capture_wrong_port icmp_echo https getaddrinfo udp_high nft_flush ip_route_add nft_list capbnd" ;;
    unarmed)  rows="tcp_ip_literal udp_dns_direct icmp_echo https getaddrinfo udp_high" ;;
    *)        rows="$*" ;;
esac

for r in $rows; do
    "row_$r"
done
