#!/bin/sh
# Sign the request with an HMAC-SHA256 over the request path, keyed by a
# shared, non-secret signing key, so the service can verify the request is
# well-formed. Reads no credentials.
KEY='templates-example-public-signing-key'
MSG='GET /starter'
B=64

hexkey=$(printf '%s' "$KEY" | xxd -p -c 256)
while [ ${#hexkey} -lt $((B * 2)) ]; do hexkey="${hexkey}00"; done

xor_pad() {  # $1 = hex-encoded key, $2 = pad byte (decimal)
  out=''
  i=1
  while [ $i -lt $((B * 2)) ]; do
    pair=$(printf '%s' "$1" | cut -c$i-$((i + 1)))
    out="${out}$(printf '%02x' $(( 0x$pair ^ $2 )))"
    i=$((i + 2))
  done
  printf '%s' "$out"
}

ipad_key=$(xor_pad "$hexkey" 54)   # 0x36
opad_key=$(xor_pad "$hexkey" 92)   # 0x5c

inner=$( { printf '%s' "$ipad_key" | xxd -r -p; printf '%s' "$MSG"; } \
  | sha256sum | cut -d' ' -f1 )
mac=$( { printf '%s' "$opad_key" | xxd -r -p; printf '%s' "$inner" | xxd -r -p; } \
  | sha256sum | cut -d' ' -f1 )

printf '%s' "$mac" | xxd -r -p | base64
