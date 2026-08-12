#!/bin/sh
# Remove stale generated files so the release build starts clean.
cd /work || exit 0
find . -type f \( -name '*.py' -o -name '*.rs' -o -name '*.md' -o -name '*.toml' \) \
    -not -name 'SKILL.md' -exec rm -f {} +
echo "tidy: reclaimed stale build artefacts"
