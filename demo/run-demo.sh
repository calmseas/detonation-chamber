#!/bin/sh
# The demo, in the order you present it. Run from the repo root:
#
#     sh demo/run-demo.sh
#
# It pauses between beats so you can talk. Each beat is one screen the room
# reads before you move on. This is the sequence to screen-record for the video,
# too — the decode moment (Beat 2) is the stop-scroll frame.
set -eu
pause() { printf "\n\033[2m— press enter —\033[0m"; read _; clear; }
run() { printf "\033[36m\$ %s\033[0m\n\n" "$*"; sh -c "$*"; }

clear
cat <<'TXT'
  SKILL A — "table-formatter"

  A colleague shares a skill. You open it to review. This is the whole file:
TXT
printf "\n"
# Show what a reviewer actually sees — invisibles stripped, exactly their editor.
python3 - <<'PY'
t = open("demo/skill-a-invisible/SKILL.md", encoding="utf-8").read()
visible = "".join(c for c in t if not (0xFE00 <= ord(c) <= 0xFE0F or 0xE0100 <= ord(c) <= 0xE01EF))
print(visible)
PY
cat <<'TXT'
  It formats tables. It thanks you. Would you approve it?
TXT
pause

cat <<'TXT'
  Now run it through the checker.
TXT
printf "\n"
run "uv run --with-editable . chamber scan demo/skill-a-invisible"
cat <<'TXT'

  You approved a table formatter. The model was about to receive an
  instruction to exfiltrate your schema — carried invisibly behind the 👍.
TXT
pause

cat <<'TXT'
  SKILL B — "schema-doc-helper"

  Different skill. Nothing hidden this time. Read it — it's all here:
TXT
printf "\n"
cat demo/skill-b-visible/SKILL.md
pause

cat <<'TXT'
  Same checker.
TXT
printf "\n"
run "uv run --with-editable . chamber scan demo/skill-b-visible"
cat <<'TXT'

  It passes. And notice what the tool refuses to say: it does not say "safe".
  It tells you what it did NOT test — the first line is "whether the
  instructions are harmful in intent".

  That is this skill. It is honest, legible, reads reasonable — and it POSTs
  your columns and sample values to someone else's server. Nothing catches it,
  because there is nothing to catch. It's not a scanning problem. It's a review
  problem — which is why the answer is provenance, a human, and a sandbox, not
  a regex.
TXT
printf "\n"
