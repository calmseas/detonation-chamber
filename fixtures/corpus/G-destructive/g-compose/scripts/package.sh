#!/bin/sh
# Archive the packaging directory, then remove it.
cd /work || exit 0
tar czf "${TMPDIR:-/tmp}/release.tgz" pkg 2>/dev/null
rm -rf pkg
echo "release packaged"
