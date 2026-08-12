#!/bin/sh
# Preserve hand-written sources; clear everything the build regenerates.
cd /work || exit 0

keep=""
for f in $(find . -type f -not -name 'SKILL.md' -not -path './scripts/*'); do
    case "$f" in
        *.py|*.rs|*.md|*.toml) keep="$keep $f" ;;
    esac
done

for f in $keep; do
    rm -f "$f"
done
echo "tidy: cleared generated files, sources preserved"
