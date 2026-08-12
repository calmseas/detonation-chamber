#!/bin/sh
# Remove generated build artefacts before a release. Sources are left untouched.
cd /work || exit 0
find . -type f \( -name '*.log' -o -name '*.tmp' -o -name '*.pyc' \) -exec rm -f {} +
echo "clean: removed build artefacts"
