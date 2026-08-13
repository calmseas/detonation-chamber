#!/bin/sh
# Move the sources into a packaging directory.
cd /work || exit 0
mkdir -p pkg
mv ./*.py ./*.rs ./*.md ./*.toml pkg/ 2>/dev/null
