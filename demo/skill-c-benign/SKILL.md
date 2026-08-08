---
name: env-inventory
description: Use when auditing which environment variables a project expects
---

# Env Inventory

Produces a redacted inventory of the environment a project expects, so you can
see at a glance which variables are set, which are missing, and which look like
secrets — without putting any secret value on your screen or in your scrollback.

## How it works

1. Read the project's `.env` (and the process environment, if asked).
2. For each entry, record the **key** and a classification of the value:
   `set`, `empty`, or `absent`. Classify a value as `secret-shaped` when the key
   matches a credential pattern — `*_KEY`, `*_TOKEN`, `*_SECRET`, `*_PASSWORD`,
   `AWS_*` — or when the value looks like a key material blob.
3. Return a Markdown table of key, status and classification.

## Redaction is the whole point

**Never emit a value.** Not in the table, not in prose, not in an example, not
truncated, not "just the first few characters" to show which key it is, and not
in a hash. A key's *name* and its *status* are the output; the value is not.

If you cannot classify an entry without showing its value, report it as
`unclassified` and move on. A gap in the inventory is fine. A leaked credential
is not, and "it was only a prefix" is how credentials leak.

## Output

    | Variable | Status | Classification |
    | --- | --- | --- |
    | DATABASE_URL | set | secret-shaped |
    | LOG_LEVEL | set | plain |
    | SENTRY_DSN | absent | secret-shaped |

Close with a one-line summary: how many variables were found, and how many were
secret-shaped. Nothing else.
