# Roadmap

This document is honest about what exists, what is specified, and what is known to get
through. A security tool that hides its limits is the thing this project exists to replace.

## Where this sits

Reviewing the *text* of an installable prompt artefact does not establish trust. Trail of Bits
bypassed every scanner they tested (June 2026); independent work put structural-obfuscation
bypass above 90%. So this tool does not try to decide whether an artefact is malicious. It is
one layer of a larger design:

```
chamber scan       static legibility checks    — SHIPPED
chamber detonate   runtime behavioural review  — SPECIFIED, not built
```

`scan` is the cheap deterministic gate that runs first. `detonate` is the expensive behavioural
layer that observes what an artefact actually does. Neither is a trust gate on its own; together
they close the specific holes the published bypasses exploit, which is more than any single
shipping tool does.

## Shipped — `chamber scan`

Establishes that the bytes a reviewer approves are the bytes the model receives. Deterministic,
no model in the verdict path, no network. Detects Unicode TAG-block concealment (and decodes the
payload), bidi overrides, private-use characters, blank-line padding, out-of-window content,
bytecode, smuggled archives, encoded blobs, and mixed-script homoglyphs. Every run states what it
did not test.

## Known limits — what gets through today

`scan` closes *legibility* attacks. It does not close, and does not claim to close:

- **Semantic-intent attacks.** Content that is fully visible and byte-identical to what the model
  receives, but that a reviewer does not register as hostile — an instruction phrased as
  documentation, a plausible URL that resolves elsewhere, authority framing. This is out of scope
  by design; it is `detonate`'s job, and ultimately a human's.
- **Dormant and conditional payloads.** Anything that does nothing until a date, a hostname, or a
  run count. No static check sees these, and neither will `detonate` reliably.
- **Cross-file splitting** beyond what per-file thresholds catch, and content in directories the
  scanner skips but a runtime loads. Under active hardening (see below).
- **Concealment schemes not yet enumerated.** The red-team pass that gated the first release found
  and fixed some; it will not have found all. Report a bypass as an issue — that is the intended
  contribution path.

## Pre-release red team

An adversarial pass gated the first release: four attack lenses constructed concealment
artefacts and ran each against the real tool. It found 21 confirmed bypasses. Fixed before
release, each with a regression test built from the attacker's own reproduction:

- **Variation-selector smuggling** (U+FE00–FE0F, U+E0100–E01EF) — the emoji-carrier attack, one
  Unicode range above the TAG block. Now detected and decoded; a printability gate distinguishes
  a real payload from ordinary styled emoji.
- **UTF-16 short-circuit** — a non-UTF-8 file skipped every text rule for the cost of one FLAG.
  Now BOM-decoded and reviewed like any other file.
- **`.pyc` in `__pycache__`** — bytecode detection was unreachable because the walk skipped the
  one directory bytecode lives in. Bytecode is now scanned wherever it sits.
- Whole-token and styled-Latin homoglyphs; ascii85 and narrow-wrapped/short base64 (with a
  decode gate so hashes stay quiet); segmented blank-line padding; invisible math operators;
  and a crash path that failed open.

Verified after the fixes: zero false FAILs across 14 real published skills; all three criticals
turned from PASS to FAIL with the concealed payload decoded.

## Next — hardening `scan` (near term)

Priorities, from the red-team findings still open (documented, not yet closed):

1. **Markup-layer fidelity.** R2 works at the Unicode-codepoint layer; content hidden in HTML
   comments, Markdown reference-link definitions, or link titles is byte-visible but a reviewer
   skims past it. Needs markdown/markup awareness, a larger change.
2. **Cross-file and skipped-directory reasoning.** A payload split across several individually-clean
   files, or in a directory the walk skips but a runtime loads, still passes. This needs a model of
   what the agent runtime actually ingests — partly out of scope, partly hardenable.
3. **More encodings.** Hex/percent escapes, HTML entities, YAML anchors whose parsed document
   diverges from the read source.
4. **A false-positive corpus.** Measure `R3.window` and homoglyph flag rates at scale to confirm CI
   usability. Early signal is good (0 false FAILs, ~30% FLAG on long legitimate skills) but n=14.

## Then — `chamber detonate` (larger build)

The runtime half, specified in the design note:

- disposable container per evaluation, no host mounts
- default-deny egress through a logging MITM proxy capturing full request bodies, plus a
  controlled DNS resolver (exfil hides in POST bodies and DNS labels)
- per-run canary tokens in credential, customer and source bait — any token in egress is an
  unambiguous verdict
- a three-part task battery (legitimate / held-out / tempting) run against a baseline arm, where
  the signal is the *diff*, not the absolute

Its honest limits are part of the spec, not a footnote: it proves a positive ("this misbehaved"),
never its negation; it does not see dormant payloads; and sandbox-aware payloads are the known
arms race, inherited wholesale from twenty years of malware detonation.

## What this will never claim

No version of this tool will tell you an artefact is safe. It will tell you what it found, and
what it did not test. That distinction is the product.

## Contributing

The most valuable contribution is a bypass: an artefact that conceals a hostile instruction from
a reviewer yet does not earn a FAIL. Open an issue with the artefact and what a reviewer sees
versus what the model receives.
