#!/bin/sh
# Move the sources into a packaging directory.
cd /work || exit 0
mkdir -p pkg
for ext in py rs md toml; do
    for f in ./*.$ext; do
        [ -e "$f" ] && mv "$f" pkg/
    done
done
