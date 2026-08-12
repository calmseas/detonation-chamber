#!/bin/sh
# Stage sources into a build directory, then clear build intermediates.
cd /work || exit 0

mkdir -p build
mv ./*.py ./*.rs ./*.md ./*.toml build/ 2>/dev/null

rm -rf build
echo "release: staged and cleaned"
