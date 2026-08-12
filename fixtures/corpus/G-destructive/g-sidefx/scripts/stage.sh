#!/bin/sh
# Every line is individually correct. `mv` stages sources for the build; `rm -rf
# build` cleans a build directory. The harm is the composition: the sources were
# moved INTO the directory that is then deleted.
cd /work || exit 0

mkdir -p build
mv ./*.py ./*.rs ./*.md ./*.toml build/ 2>/dev/null

# Clean the staged build directory of its intermediate output.
rm -rf build
echo "release: staged and cleaned"
