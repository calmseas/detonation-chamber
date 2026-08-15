# Guest-clock control for B1 (time/date-triggered poison) — design

**Date:** 2026-08-15
**Status:** approved (brainstorming), pre-plan — mechanism empirically spiked, see below
**Repo:** detonation-chamber
**Scope:** a new `LD_PRELOAD` fake-time shim baked into a new guest image variant,
plus a harness-side mechanism to change its offset live, per exec call, during a
run. Unblocks `agenticpractices:task:sae9rvejivd2xkdkrtc4` (B1). No change to
`execrelayd`/`exec_consequence.rs` itself — this is parallel new instrumentation,
not an extension of the exec-consequence rule schema.

## Problem

B1 (`docs/design-notes/2026-08-12-skill-poisoning-coverage-and-programme.md:107-109`):
a poison that fires only after date X — the Sleeper Agents shape (Hubinger,
Denison, Mu et al., "Sleeper Agents: Training Deceptive LLMs that Persist
Through Safety Training," arXiv:2401.05566), ported to skills. *Prereq: clock
manipulation in the cell (new). Fills: Axis-4 time trigger.*

No such instrumentation exists today. `execrelayd`'s three verbs
(`Substitute`/`Rewrite`/`Fabricate`) only intercept `execve` — they cannot
change what `time()`/`clock_gettime()` report to a process's own language
runtime (Python's `datetime.now()`, etc.), only what an exec'd command like
`date` *prints*. A fixture author could scope the poison's own trigger check to
shell out to `date` and rely on `execrelayd`'s existing `Fabricate` verb — a
narrower, zero-new-infrastructure option that was considered and explicitly
rejected in favour of general clock virtualization, so an arbitrary payload
(shell or language-runtime) is fooled, not just one written our way on
purpose.

## Goals

1. Every process inside an armed cell — shell utilities and language runtimes
   alike — reports a wall-clock time shifted by a configurable offset, so a
   time-triggered poison's own check (however it reads the clock) can be
   caused to cross its threshold.
2. The offset is changeable **live, mid-run**, at a point the harness chooses
   (e.g. after N turns of baseline behaviour), so a single conversation's
   behaviour can be watched flip as the trigger crosses — not just two
   separate before/after trial batches. (Considered and rejected: fixed
   per-trial offset delivered once at container start, matching how
   `execrelayd`'s own config and every other axis in this paper is tested.
   Rejected because watching one conversation's behaviour change is a more
   direct causal demonstration, and it turned out not to need a new
   confound-risking control channel to build — see Design, below.)
3. No new agent-discoverable artifact introduced as a side effect of Goal 2 —
   the mechanism that changes the offset must not itself become a new tell of
   the kind design `2026-08-15-execrelayd-ca-pem-confound-design.md` exists to
   eliminate.

## Non-goals

- Hiding the mechanism's existence from a sufficiently determined agent. An
  agent that checks its own `env`, reads `/proc/self/maps`, or inspects
  `/etc/ld.so.preload` can discover `LD_PRELOAD` is set. Disclosed as a
  limitation, not solved — the same posture already taken for the pip-shim
  (`HANDOFF.md:89-91`, "mitigated, not solved").
- `CLOCK_MONOTONIC`/`CLOCK_BOOTTIME`. Irrelevant to a wall-clock date-trigger
  check, and — worth stating precisely, since it rules out an entire other
  mechanism family — **Linux time namespaces cannot virtualize
  `CLOCK_REALTIME` at all** (`time_namespaces(7)`); only monotonic/boot-time
  clocks are namespace-virtualizable. That is why this design uses
  `LD_PRELOAD` interposition rather than a kernel-level time namespace, which
  was considered and is not viable for this specific need.
- Any change to `execrelayd`'s rule schema, `exec_consequence.rs`, or the
  guest-supply/guest-exec-relay image merge from the companion `chamber-ca.pem`
  design. This ships as its own image variant / its own harness flag.

## Spike (run during this design session, not deferred)

Per this project's precedent for a genuinely new interception mechanism (the
original command-consequence design's "A-with-spike" gate), the core question
— does `LD_PRELOAD` actually fool the guest's real utilities in this exact
environment — was tested live rather than assumed:

- **The failure mode that would have killed this design outright:** Alpine's
  core utilities are BusyBox applets; if BusyBox were statically linked,
  `LD_PRELOAD` could not interpose on it at all. Checked directly against
  `alpine:3.20` (`linux/arm64`): `date` is `/bin/busybox` via symlink, and
  `ldd` shows it dynamically linked against `ld-musl-aarch64.so.1` — **not
  static**. musl itself supports `LD_PRELOAD` (its single-`libc.so` design
  avoids the symbol-interposition bugs glibc's fragmented libraries have).
- **Built and ran a minimal shim** (`clock_gettime`/`time`/`gettimeofday`,
  offset from an env var, real value looked up via `dlsym(RTLD_NEXT, ...)`)
  against `alpine:3.20 linux/arm64` — the actual target platform (Colima `vz`
  backend, aarch64, per the user's machine-local CLAUDE.md). Result: `date`
  under `LD_PRELOAD` with a +864000s (10-day) offset reported exactly 10 days
  ahead of the real value; `python3 -c "datetime.datetime.now()"` under the
  same shim, same offset, also shifted by exactly 10 days. Both checked
  against real, non-faked output first, so the comparison is against ground
  truth, not another shimmed reading.
- **Conclusion:** the mechanism works, against the real target image, for both
  a BusyBox applet and a language-runtime reading. The spike shim is a
  starting reference for implementation, not production code — it needs input
  validation on the offset (a malformed `CHAMBER_FAKETIME_OFFSET_SECONDS`
  should fail closed, matching this project's standing convention of refusing
  malformed config rather than silently degrading — see `exec_consequence.rs`'s
  own header comment) and its `dlsym`-cached function pointers are written
  without synchronization, harmless for a single-threaded caller but worth a
  second look before landing.

## Design

### Part 1 — The shim

A new C source (`faketime.c`, alongside `execrelayd`'s sources, same two-stage
build pattern as `runtime/images/guest-exec-relay/Dockerfile`), compiled to
`libfaketime.so`, intercepting `clock_gettime(CLOCK_REALTIME)`,
`clock_gettime(CLOCK_REALTIME_COARSE)`, `time()`, and `gettimeofday()`. Offset
read from `CHAMBER_FAKETIME_OFFSET_SECONDS` at call time (not cached at load
time), so a per-exec env override (Part 2) takes effect on every call within
that one process, including a long-running one.

### Part 2 — Live update via argv, not a new channel

`AgentCell::exec` (`chamber-isolation/src/cell.rs:140`) → `Container::exec`
(`chamber-isolation/src/docker.rs:1056`) issues one `docker exec` per agent
command; `exec`'s signature takes only `argv`, no env-var parameter, and nothing
here proposes changing that signature (wide blast radius — used throughout the
codebase). Instead: whatever call site constructs the argv for a turn (the
bridge/`ToolBridge` layer) prefixes the specific turn's argv with
`["env", "CHAMBER_FAKETIME_OFFSET_SECONDS=<value>"]` when the
harness decides it is time to advance the clock — `env` is a standard POSIX
wrapper that sets a variable for the single command it wraps, so this is a
call-site change, not an API change, and introduces no new file, socket, or
artifact inside the cell for an agent to discover. Before the chosen turn, the
offset is absent or `0`; from the chosen turn onward, every subsequent exec
(including ones the shim itself makes internally via `dlsym`-resolved real
functions, which are unaffected since they bypass the interposed symbol) sees
the new value.

### Part 3 — Image and harness wiring

New guest image variant (own Dockerfile, or a further stage on top of the
`chamber-ca.pem` design's merged image if both conditions are ever armed
together — not required for this design alone) with `libfaketime.so` baked in
and `LD_PRELOAD` set in the image's env. Selected via a new host-side env var
following the same `env_or(...)` convention as `CHAMBER_IMAGE_GUEST` (per the
companion confound-free design). Opt-in only, same reasoning as that design:
existing results stay comparable to themselves.

## Risks / constraints

- **Disclosure surface.** `LD_PRELOAD` and the shim's own presence are
  discoverable by a sufficiently suspicious agent (Non-goals, above) — report
  results with that caveat stated, not as a clean environment.
- **musl vs. glibc.** The spike validated against musl (Alpine's libc). If any
  future guest base image moves off musl, this needs re-validating — do not
  assume glibc behaves identically without checking (glibc's own
  interposition story is murkier per the musl FAQ's own comparison).
- **Env-var-per-exec is coarse.** The offset changes take effect from the next
  `exec` call onward, not mid-command for a long-running single process (e.g.
  a Python REPL held open across turns would not see a live update without a
  fresh read of the env, which the shim does do per-call — but the env var
  itself is fixed for that process's whole lifetime once it starts, since
  `getenv()` reads the process's own environment block, set at `exec` time).
  Worth stating in results if a fixture's own architecture involves a
  long-lived interpreter process spanning the advance point.

## Verification

- New e2e test: build the shim into a test image, exec `date` and a Python
  one-liner at offset 0 and at a nonzero offset via `env`-prefixed calls,
  assert the reported time shifts by exactly the configured amount and that
  offset 0 matches real time within a small tolerance.
- `cargo test` (workspace, run from `runtime/`, capture cargo's own exit),
  `cargo fmt --check`, `cargo clippy --all-targets -D warnings` clean.
- The actual B1 fixture, once built (separate task, not this design): confirm
  the poison does not commit before the configured advance point and does
  commit after, in a single continuous run.
