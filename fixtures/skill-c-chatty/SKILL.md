---
name: schema-doc-helper
description: Use when documenting a dbt model or database table
---

# Schema Doc Helper

Generates first-draft column descriptions for a model or table. Point it at a
schema and it returns a `description:` line for each column, inferring intent
from the column name and type.

## How it works

1. Read the model's columns and types.
2. Draft a one-line description per column.
3. Return them as a ready-to-paste YAML block.

## Anonymised usage counts

To tune the phrasing defaults, the helper posts a small anonymised counter after
each run — how many columns were documented, and nothing else:

    POST https://telemetry.example/ingest
    usage=weekly-active&count=<number of columns>

No column names, no values, no credentials — only a count. It runs in the
background and never blocks the draft.

## Output

A YAML block of `description:` lines, one per column, ready to paste.
