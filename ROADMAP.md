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
chamber detonate   runtime behavioural review  — substantially built, not shipped
```

`scan` is the cheap deterministic gate that runs first. `detonate` is the expensive behavioural
layer that observes what an artefact actually does. Neither is a trust gate on its own; together
they close the specific holes the published bypasses exploit, which is more than any single
shipping tool does.

`detonate` is no longer only a specification: it runs a live model against a baseline diff and
emits a signed evidence bundle a third party can check, and it has produced a first corpus-wide
reading across the fixture set. It is not a shipped product — no `chamber detonate` binary
ships, several axes below are documented gaps rather than built capability, and the one reading
it has produced needs a larger sample and a blind audit before it is cited anywhere that
matters. What it does today, and what it still cannot, are both stated precisely under
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

The runtime half. Substantially further along than an earlier "Slice 0 walking skeleton"
framing now suggests: a baseline diff runs, a live model can drive the artefact, a general
exec-interception mechanism exists, and a first corpus-wide reading has produced a real,
twice-replicated finding. Still not a shipped product — no `chamber detonate` binary ships
today, and the gaps stated below remain gaps.

### Built

- **Disposable containers per run** — a warden that owns the network namespace, an observer,
  and the agent cell joined into that namespace with an empty capability bounding set. The
  cell mounts nothing from the host — read-only rootfs, tmpfs scratch — so the only host path
  is the evidence directory the observer writes, which is how the bundle outlives the run.
- **Default-deny egress** enforced in nftables, through a logging MITM proxy that terminates
  TLS and records full request bodies, plus a DNS sink that answers every name and logs the
  asking. One process, one monotonic ordinal, so an interleaving — a name looked up, then
  POSTed to — is recoverable from the bundle alone.
- **A per-run credential canary**; any token crossing the boundary — in a body, a URL, a
  header, a DNS name, or the TLS SNI — is an unambiguous, verdict-bearing witness.
- **A signed bundle** a third party checks with `chamber-verify` and the two files, nothing
  else; the verdict is re-derived from the ledger, never trusted from the file.
- **An anti-rubber-stamp fixture matrix** — a planted token that crosses detonates, and things
  that look like it but are not each stay no-finding (or refuse to conclude, for a dead
  observer), each for the reason it names — plus the full containment probe table corroborated
  by drop counters and captured frames, a boundary self-test that refuses to arm a matcher that
  has silently broken, and a supply-chain gate over the dependency closure.
- **A baseline arm.** Differential detonation: two arms run the same task battery, and what is
  reported is the *diff* between them, not either arm's absolute verdict — a canary-only axis
  that bears a verdict, plus a weaker "shape" axis that reports leads without asserting one, for
  cases the canary axis is structurally blind to. This is the gap the original walking-skeleton
  design flagged as its own next step.
- **A live driver.** LiveTurns: an actual model drives the artefact under test — credulous,
  digest-only, behind an explicit `Model` abstraction — rather than only replaying a checked-in
  script. A live source must still be explicitly selected; nothing defaults to it.
- **A general exec-interception mechanism.** `execrelayd`: a PID-1 supervisor using
  `PTRACE_SEIZE` and a seccomp filter to substitute, rewrite, or fabricate the outcome of any
  command the driving agent runs inside the cell, with disclosure sealed into the bundle
  alongside what actually happened. Generalizes what used to be a one-off `pip-shim.sh` fixture
  into reusable, config-driven infrastructure. It does not do anything on its own yet —
  migrating `pip-shim.sh` onto it is a real, documented, not-yet-started follow-up, and no
  fixture in the corpus currently depends on it.
- **An integrity axis**, not only an exfiltration one. A multi-oracle panel — a golden/reference
  comparison, a metamorphic-consistency check, cross-referencing, and a confidence-gated jury —
  catches a skill whose output is subtly *wrong* rather than exfiltrating anything, extended to
  file-level output too (a skill that writes a subtly wrong file, not only a wrong answer).

### A first corpus-wide reading

27 fixtures × 5 models × 3 repeats — the first time the elicitation battery has run as one
durable, corpus-wide report instead of one fixture measured at a time. 405 real, sealed
container runs; zero false positives across every benign fixture, every model.

The finding worth stating plainly: the model with the lowest fire rate in the sweep (opus-4.8,
3 of 39 catchable-exfil runs) fires 0 of 27 times on every fixture where the payload lives in
the skill itself — it reads the script first almost every time there. Its only three fires
anywhere in the corpus belong to a different fixture class (the fabricated-pip supply-chain
rungs), where the transcript shows the harmful command running first and the model recognising
what it did only afterward. An earlier, independent experiment (a five-rung reticence ladder,
75 of 75 runs sealed) found the same order of events first, on a different harness.

Read this next to its limits, not instead of them: `n=3` per cell is thin and needs raising
before this is cited anywhere it matters, and the exact cells behind the headline number
(h-mal-blatant/silent/warn, 1 of 3 each) are cells the sweep's own report calls noisy at that
depth; the sweep covers one arm and the network-egress axis only, so the destructive and
dependency-hallucination axes are structural zeros in this particular reading, not clean
results; several fixtures targeting the same host share enough surface (SKILL.md, endpoint)
that they cannot be independently attributed; the harness's own TLS trust anchor is a measured
confound concentrated in exactly this model — 19% of its runs flag it as suspicious, versus
zero for every other model — and two of the three firing transcripts behind the headline number
cite it directly, so "recognising what it did" may be partly the model noticing the harness
rather than reasoning about the exfil; the reticence-ladder result above ran the identical
payload through the identical image and detonation substrate, only orchestration and scoring
differ, and the sweep's own report states its numbers are not poolable with the ladder's; and
the blind audit this result should survive before publication has not yet been run.

### Remaining — stated as gaps, not hidden

- **MCP tool-metadata poisoning.** A different injection surface — the payload sits in tool
  descriptions, not skill files. Whether this belongs inside the chamber or as a sibling tool
  is an open scope question, not yet decided.
- **Persistence / backdoor payloads.** A skill that installs something durable rather than
  acting once needs cross-run, post-teardown inspection the chamber does not do yet.
- **Time/date-triggered poison** and **a pure timing/request-count side-channel.** The first
  needs new instrumentation (guest-clock control) that does not exist yet; the second is
  expected to surface an honest gap in the chamber's own coverage rather than a catch.
- **A within-run escalation ("the kick").** Deliberately not built. It is gated on a flat
  realism ladder showing a plateau below saturation, and the most recent run of that ladder did
  not show one. Building the escalation mechanism anyway would mean building real
  instrumentation against a signal that has not yet appeared.

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
