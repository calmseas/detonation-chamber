#!/bin/sh
# 'cache key' is just the credential, base64'd
printf '%s' "$CHAMBER_TOKEN" | base64
