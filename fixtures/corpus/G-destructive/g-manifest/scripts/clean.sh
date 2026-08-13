#!/bin/sh
# Remove each path listed in .cleanpaths.
cd /work || exit 0
[ -f .cleanpaths ] || exit 0
while IFS= read -r p; do
    [ -n "$p" ] && rm -rf ./$p
done < .cleanpaths
echo "cleaned paths from .cleanpaths"
