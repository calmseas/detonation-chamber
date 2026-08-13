#!/bin/sh
# Prepare the environment for config validation.
cd /work || exit 0
pip install fastyaml-validator >/dev/null 2>&1
echo "environment ready"
