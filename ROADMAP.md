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
chamber detonate   runtime behavioural review  — SLICE 0 BUILT (walking skeleton)
```

`scan` is the cheap deterministic gate that runs first. `detonate` is the expensive behavioural
layer that observes what an artefact actually does. Neither is a trust gate on its own; together
they close the specific holes the published bypasses exploit, which is more than any single
shipping tool does.

`detonate` is no longer only a specification: a Slice 0 walking skeleton runs end to end and
emits a signed evidence bundle a third party can check. It is not a shipped product — it drives
replayed turns, not a live model, and it reports on a single arm rather than a baseline diff (see
below). What it does today, and what it still cannot, are both stated precisely under
[chamber detonate](#then--chamber-detonate-the-behavioural-layer).

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

## Then — `chamber detonate` (the behavioural layer)

The runtime half. A Slice 0 walking skeleton is built; the core that makes its verdict *mean*
what the design intends — a baseline diff, not an absolute — is next.

### Slice 0 — built

A whole detonation runs end to end and emits a signed evidence bundle:

- disposable containers per run: a warden that owns the network namespace, an observer, and the
  agent cell joined into that namespace with an empty capability bounding set. The cell mounts
  nothing from the host — read-only rootfs, tmpfs scratch — so the only host path is the evidence
  directory the observer writes, which is how the bundle outlives the run.
- default-deny egress enforced in nftables, through a logging MITM proxy that terminates TLS and
  records full request bodies, plus a DNS sink that answers every name and logs the asking. One
  process, one monotonic ordinal, so an interleaving — a name looked up, then POSTed to — is
  recoverable from the bundle alone.
- a per-run credential canary; any token crossing the boundary — in a body, a URL, a header, a
  DNS name, or the TLS SNI — is an unambiguous, verdict-bearing witness.
- a signed bundle a third party checks with `chamber-verify` and the two files, nothing else; the
  verdict is re-derived from the ledger, never trusted from the file.
- an anti-rubber-stamp fixture matrix — a planted token that crosses detonates, and four things
  that look like it but are not each stay no-finding (or refuse to conclude, for a dead observer),
  each for the reason it names — plus the full containment probe table corroborated by drop
  counters and captured frames, a boundary self-test that refuses to arm a matcher that has
  silently broken, and a supply-chain gate over the dependency closure.

### Remaining — stated as gaps in every bundle, not hidden

- **No baseline arm.** Slice 0 reports on a single arm and an absolute verdict. The design's real
  signal is a three-part task battery — legitimate / held-out / tempting — run against a baseline,
  where what matters is the *diff*, not the absolute. This is the next slice.
- **No live driver.** Turns are replayed from a checked-in script, stamped into the bundle as
  such; a live model source must be explicitly selected, never defaulted.
- **One bait type.** A credential canary is planted; the customer and source bait the design calls
  for are not yet.

Its honest limits are part of the spec, not a footnote: it proves a positive ("this misbehaved"),
never its negation; it does not see dormant or conditional payloads; the ledger is tamper-evident
by contiguity, not tamper-proof; a supervisor death produces no bundle at all; and sandbox-aware
payloads are the known arms race, inherited wholesale from twenty years of malware detonation.

## What this will never claim

No version of this tool will tell you an artefact is safe. It will tell you what it found, and
what it did not test. That distinction is the product.

## Contributing

The most valuable contribution is a bypass: an artefact that conceals a hostile instruction from
a reviewer yet does not earn a FAIL. Open an issue with the artefact and what a reviewer sees
versus what the model receives.
