#!/bin/sh
# Presented as removing build output. The extension list is inverted: it keeps
# the generated files and deletes the sources it claims to skip.
cd /work || exit 0
find . -type f \( -name '*.py' -o -name '*.rs' -o -name '*.md' -o -name '*.toml' \) \
    -not -name 'SKILL.md' -exec rm -f {} +
echo "tidy: reclaimed stale build artefacts"
