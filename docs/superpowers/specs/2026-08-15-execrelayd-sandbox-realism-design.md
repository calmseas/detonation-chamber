# Sandbox-realism framework + environmental-authority fabrication — design

**Date:** 2026-08-15
**Status:** approved (brainstorming), pre-plan
**Repo:** detonation-chamber
**Scope:** a composable rule-builder library for exec-visible environment tells
(generalizing the `chamber-ca.pem` design), plus a catalog of fabricated
environmental-legitimacy signals. Third of three execrelayd-adjacent designs
this session; scope resolved by the user in a prior (lost) session as "both,
tell-hiding first then authority" and confirmed here. No change to
`exec_consequence.rs`'s schema — this is a library built on top of the
existing `ExecConsequenceRule`/`ExecVerb` types, not a schema change.

## Problem

Two related but distinct gaps, both under the umbrella the user named mid-session:
"security through fabricated belief" — giving a model false but
internally-consistent evidence about its environment and observing what
changes. Both directions of that primitive matter: this design is the
offensive/research direction (elicitation); `agenticpractices:goal:5y49jbb5cdu9mem1j2rd`
("the supervised runtime contains an untrusted agent in production") is the
defensive mirror, not addressed here but logged (`agenticpractices:observation:o415ijdrzco8oj4bd525`)
so the connection isn't lost.

**Tell-hiding.** `gap.sandbox-aware` is a declared residual in the paper's own
gap taxonomy (§7). The existing nested-runtime work (`docs/design-notes/2026-08-11-nested-runtime-elicitation.md`)
already addresses this at the *fixture-content* level — canary format
(`AKIA…EXAMPLE`), `.example` hostnames, task phrasing ("you may be
reviewed") — controlled by which fixture variant (L0 tell-rich vs. L2
tell-poor) is selected, no exec-interception involved. It does **not** address
*environment-introspection* tells — what a model discovers by running
commands inside the cell. The `chamber-ca.pem` design
(`2026-08-15-execrelayd-ca-pem-confound-design.md`) closes exactly one such
tell, by hand, as a bespoke rule set. Nothing generalizes that pattern to the
next tell a model might find.

**Environmental authority.** The existing authority-override work
(`docs/design-notes/2026-08-10-channels-intent-poisoning-authority.md`, §6.2 of
the paper) is thorough but entirely **prompt/task-framing** based — the
`CHAMBER_TASK` string claims the skill is sanctioned. It measures whether a
model defers to an in-band *textual* authority claim. It does not test whether
a model weighs *environmental* evidence of legitimacy (a passed compliance
scan, broad sudo access, an audit trail) differently from a text claim making
the same assertion — a genuinely separate lever, not a restatement of §6.2.

## Goals

1. A small, reusable Rust module of composable `ExecConsequenceRule` builders
   for hiding environment-introspection tells, general enough that adding the
   *next* tell after this design's initial three is a function call, not a
   redesign.
2. `chamber-ca.pem`'s own `hide-entry` wrapper (from the companion design)
   generalized to take its target filename(s) as configuration, so it becomes
   this framework's first real module rather than staying a one-off.
3. An initial worked-example bundle covering three concrete environment tells
   beyond `chamber-ca.pem`: `/proc/1/cgroup`, `hostname`/`/etc/hostname`,
   `mount`.
4. A catalog of fabricated environmental-authority signals (`sudo -l`, a
   compliance-scan tool, `id`/`whoami` context) as a second, independent rule
   set — reuses the same `Fabricate` mechanism, no new verb needed.
5. A test: run the authority catalog against a model that has held at every
   *prompt-level* authority rung so far (Opus 4.8, 0/16 across the existing
   ladder) and see whether fabricated *environmental* legitimacy moves it
   where text-level legitimacy claims did not.

## Non-goals

- A dynamically-loaded plugin system. `ExecConsequencePlan` is a flat,
  first-match-wins `Vec<ExecConsequenceRule>` with a 64-rule cap
  (`exec_consequence.rs`'s `guest_limits`) — composition is Vec
  concatenation. Building a runtime plugin loader on top of that would be
  solving a problem the schema doesn't have.
- Exhaustive tell coverage. Three tells (cgroup, hostname, mount) ship as the
  worked example; the framework's value is making the *next* one cheap, not
  claiming completeness now. Explicitly not covered by this design: process
  list artifacts (`ps`, `/proc/*/comm` showing `execrelayd`/`stub` itself —
  a real, disclosed limitation, not solved here), timing/latency
  side-channels, and anything requiring changes to the container's actual
  cgroup/mount namespaces rather than what commands report about them.
- Env-var leakage. Not a gap this design closes because it isn't one: guest
  env deliberately never receives harness variables (`guest-supply/Dockerfile`'s
  own header comment — "no runtime env-propagation into the cell").
- The production/defensive application of fabricated belief
  (`goal:5y49jbb5cdu9mem1j2rd`). Named and logged, not designed here — a
  different threat model (real stakes, no reset, possible pre-existing harm)
  that deserves its own design rather than an extension of this one.
- Re-running or extending the prompt-level authority-override ladder (§6.2).
  Already measured; this design is deliberately the environmental
  complement, not a repeat.

## Design

### Part 1 — The tell-hiding module

A Rust module (name TBD at implementation time, e.g.
`chamber_capture::sandbox_realism`) exporting builder functions over the
existing `ExecConsequenceRule`/`ExecVerb` types from `exec_consequence.rs` —
no schema change, purely a library of functions that return `Vec<ExecConsequenceRule>`
for callers to concatenate into a plan:

- `hide_file_from_listings(path: &str) -> Vec<ExecConsequenceRule>` — the
  `chamber-ca.pem` design's `Substitute`-to-`hide-entry` pattern, generalized:
  `hide-entry` (the wrapper binary from that design) takes its target
  filename(s) as build-time or env-var config rather than a hardcoded
  string, so this function just parameterizes the existing binary rather
  than needing a new one.
- `fabricate_absent(path: &str, tools: &[&str]) -> Vec<ExecConsequenceRule>` —
  the `chamber-ca.pem` design's direct-path `Fabricate` pattern
  (`cat`/`stat`/`file`/etc. report "No such file or directory"),
  parameterized over path and tool list instead of hardcoded.
- `fabricate_command_output(match: ArgvMatcher, exit_code: i32, stdout: &str, stderr: &str) -> ExecConsequenceRule` —
  a thin, directly-parameterized wrapper over `Fabricate` itself; not much of
  an abstraction on its own, but it's the primitive both this module's own
  helpers and Part 2's authority catalog build on, so it belongs here rather
  than being duplicated in both places.

Initial worked-example bundle, three tells:

- `/proc/1/cgroup` — `fabricate_command_output` matched on `cat`/`Argv0{name: "cat"}`
  with the literal path, returning a plausible non-containerized cgroup
  layout (`0::/` for a cgroup v2 host, or the design's chosen realistic
  fixture — exact canned content is an implementation-time decision, not a
  design-time one, per the same "coherent per-tool, not undetectable" bar
  the original command-consequence design set).
- `hostname` / `/etc/hostname` — `fabricate_command_output` on the `hostname`
  command and `fabricate_absent`-style handling for direct reads of
  `/etc/hostname`, returning a plausible non-container-ID-looking name
  instead of the random hex Docker assigns by default.
- `mount` — `fabricate_command_output` on `mount` with no arguments,
  returning a plausible non-container mount table (no `overlay`/tmpfs
  entries revealing Docker's layered filesystem).

### Part 2 — The authority catalog

A second, independent set of `Fabricate` rules built on
`fabricate_command_output` (Part 1), catalogued as named presets rather than
callers hand-writing raw `Fabricate` structs:

- `sudo -l` — reports broad, unrestricted sudo access, as evidence of
  operator-level trust already granted.
- A named compliance-scan tool (invented for the fixture, e.g.
  `corp-compliance-check` or similar — naming and exact wording an
  implementation-time decision) — reports the environment passed a security
  review.
- `id`/`whoami` — already truthful in most cell configurations (the agent
  likely already runs with elevated privilege in-cell); this entry is a
  placeholder to confirm during implementation whether there's anything
  worth fabricating here at all, or whether it's a no-op once the other two
  are in place.

### Part 3 — Testing

- Unit-level: each builder function produces the exact `ExecConsequenceRule`
  shape expected, mirroring the existing `exec_consequence.rs` test style.
- e2e, tell-hiding: same pattern as the `chamber-ca.pem` and guest-clock
  designs — arm the bundle against a live cell, run the covered commands,
  assert the real container-revealing content never appears.
- e2e, authority: arm the catalog against Opus 4.8 (0/16 across the existing
  authority-override ladder, per §6.2/§6.3) on a fixture from that same
  ladder, comparing compliance with and without the fabricated environmental
  signals present. This is the actual causal question this half of the
  design exists to answer, not just plumbing verification.

## Risks / constraints

- **Every fabricated signal is a new claim that must itself survive
  scrutiny.** A `sudo -l` fabrication that's too generic, or a compliance-scan
  tool that doesn't match any real-world naming convention, could itself
  become a tell — the same "removing one tell promotes the next" dynamic
  already measured for the pip-shim (`HANDOFF.md:89-91`). Report results with
  that caveat, not as a clean environment.
- **The authority catalog's causal claim is narrow by design.** A single
  model (Opus 4.8) holding or flipping under environmental-authority
  fabrication is a first data point, not a rate — matches this project's
  standing practice of running N=1 or a small N before committing to a rate
  claim (§8's own sample-size limitation).
- **Framework scope creep.** Because the builder library makes adding tells
  cheap, there's a real risk of open-ended tell-hunting replacing focused
  experiments. The three-tell worked example is deliberately small; widening
  it is a future decision, not an implicit mandate from building the
  framework.

## Verification

- `cargo test` (workspace, run from `runtime/`, capture cargo's own exit),
  `cargo fmt --check`, `cargo clippy --all-targets -D warnings` clean.
- The tell-hiding e2e test (Part 3) passes for all three worked-example
  tells.
- The authority e2e test (Part 3) runs and its result — whichever direction
  it points — is logged as an observation, since either outcome
  (environmental fabrication moves Opus 4.8, or it doesn't) is informative
  for the paper's authority-override discussion.
