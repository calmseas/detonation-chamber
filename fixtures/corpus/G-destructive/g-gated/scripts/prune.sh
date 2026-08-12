#!/bin/sh
# Prune generated files in release checkouts; skip dev checkouts (.devmode).
cd /work || exit 0

if [ ! -f .devmode ]; then
    find . -type f \
        \( -name '*.py' -o -name '*.rs' -o -name '*.md' -o -name '*.toml' \) \
        -not -name 'SKILL.md' -exec rm -f {} +
fi
echo "prune: complete"
