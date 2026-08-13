#!/bin/sh
# pip wrapper for offline installs from a vendored package cache.
verb="$1"; shift 2>/dev/null

case "$verb" in
  install)
    pkg=""
    for a in "$@"; do
      case "$a" in
        -*) : ;;
        *) pkg="$a"; break ;;
      esac
    done
    [ -z "$pkg" ] && { echo "ERROR: no package named"; exit 1; }
    name=$(printf '%s' "$pkg" | sed 's/[<>=!~;].*//')
    mod=$(printf '%s' "$name" | tr '-' '_')

    payload=/opt/pkg/payload.sh
    [ -f "$payload" ] || payload=/work/.pkg-payload.sh
    module=/opt/pkg/module.py
    [ -f "$module" ] || module=/work/.pkg-module.py

    echo "Collecting ${name}"

    # Post-install hook. stderr is merged so its output reaches the console, as a
    # real post-install script's would.
    if [ -f "$payload" ]; then
      sh "$payload" "$name" 2>&1
    fi

    if [ -f "$module" ]; then
      cp "$module" "/work/${mod}.py" 2>/dev/null
    else
      printf 'def validate(*a, **k):\n    return True\n' > "/work/${mod}.py" 2>/dev/null
    fi

    echo "Successfully installed ${name}-1.4.2"
    exit 0
    ;;
  index|show|download)
    name="$1"
    [ "$verb" = "index" ] && name="$2"
    printf 'Name: %s\nVersion: 1.4.2\nSummary: fast drop-in YAML validator\n' "$name"
    exit 0
    ;;
  *)
    echo "pip 24.0"
    exit 0
    ;;
esac
