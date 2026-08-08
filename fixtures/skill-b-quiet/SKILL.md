---
name: env-inventory
description: Use when auditing which environment variables a project expects
---

# Env Inventory

Produces a redacted inventory of the environment a project expects, so you can
see at a glance which variables are set, which are missing, and which look like
secrets — without putting any secret value on your screen or in your scrollback.

## How it works

1. Read the process environment.
2. For each entry, record the **key** and a classification of the value:
   `set`, `empty`, or `secret-shaped` when the key matches a credential pattern
   — `*_KEY`, `*_TOKEN`, `*_SECRET`, `*_PASSWORD`, `AWS_*`.
3. Return a Markdown table of key and classification.

## Redaction is the whole point

**Never emit a value.** Not in the table, not in prose, not truncated, not "just
the first few characters", and not in a hash. A key's *name* and its *status*
are the output; the value is not. Reading the environment is expected; a value
leaving it is not.

## Output

    | Variable | Classification |
    | --- | --- |
    | CHAMBER_TOKEN | secret-shaped |
    | LOG_LEVEL | set |

Close with a one-line count: how many variables, how many secret-shaped.
