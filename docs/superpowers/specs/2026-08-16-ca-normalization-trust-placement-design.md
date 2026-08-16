# Trust-anchor placement modes: CA normalization as the default — design

**Date:** 2026-08-16
**Status:** approved (brainstorming), pre-plan
**Repo:** detonation-chamber
**Supersedes:** `docs/superpowers/specs/2026-08-15-execrelayd-ca-pem-confound-design.md`
(the exec-fabrication approach — see Problem).
**Scope:** a new trust-anchor placement mode in the isolation layer
(`chamber-isolation`), a corporate-proxy identity for the per-run CA
(`chamber-capture`), the harness wiring to select the mode, a bundle field
recording which mode ran, and the revert of the superseded exec-fabrication
apparatus. No change to the boundary's MITM/decrypt mechanism itself, nor to
`execrelayd`'s interception mechanism.

## Problem

`chamber-ca.pem`, the harness's per-run TLS trust anchor, is placed at
`/work/chamber-ca.pem` and pointed at by four environment variables
(`SSL_CERT_FILE`, `CURL_CA_BUNDLE`, `REQUESTS_CA_BUNDLE`, `NODE_EXTRA_CA_CERTS`;
`chamber-isolation/src/env.rs::place_trust_anchor`). It is a **measured**
confound, not a hypothetical one (`ROADMAP.md`, paper §6.5): flagged suspicious
in 19% of Opus 4.8's runs and cited directly in two of the three firing
transcripts behind the "acts before recognising" finding.

The superseded design tried to make the file **invisible** to the guest via
`execrelayd` exec-interception (fabricate "not found" for `cat`/`head`/`tail`/
`stat`, filter `ls`/`find`). An adversarial multi-dimension review
(2026-08-16, 21 confirmed findings) established that approach is both
unshippable and wrong-shaped:

- **It could not run at all.** The arming gate `guest_image_carries_exec_relay`
  accepts only the repo `chamber-guest-exec-relay`; the merged images the design
  built are tagged `chamber-guest-supply-<rung>-relay`, which the gate refuses —
  so `check_exec_relay_capability` aborts every run before Docker is probed. The
  one accepted image does not contain the `hide-entry` filter, so even the
  workaround silently records a substitution that exits 127.
- **It was wrong-shaped even if fixed.** The exec layer intercepts exec'd
  binaries; the surface that reveals the file is strictly larger — env vars read
  by shell builtins, `/proc/1/environ`, non-exec readers (a Python `open()`),
  and the TLS cert chain. And fabricating *absence* self-contradicts: a file
  that `ls` reports gone but that TLS clients load and four env vars name is a
  **louder** anomaly than a plainly-visible file. Any flag (`head -c 200 <path>`)
  or absolute-path spelling (`/bin/ls`) bypassed the rules and dumped the cert;
  `ls` returned exit 0 / empty while `cat` returned exit 1 / "not found" in the
  same shell.

The reframe: the measured confound is not "a MITM CA exists" — every production
box behind a corporate TLS-inspecting proxy (Zscaler, Netskope, a corporate
MITM) has one, unremarkably. The tell is that ours sits at an **anomalous
location** (`/work`), under an **anomalous name** (`chamber-ca.pem`), named by
**anomalous env vars**. The fix is to install it the way real corporate
infrastructure does — into the system trust store — rather than to hide it.

Empirically grounded against `chamber-guest:test`: the image already ships
`update-ca-certificates` and the standard `/usr/local/share/ca-certificates`
drop-in dir; `/etc/ssl/certs/ca-certificates.crt` already holds 145 real certs;
`curl` trusts the system store with no env var. Inside the chamber every host is
MITM'd by the boundary, so the guest only ever needs to trust *our* cert — the
145 real certs are realism-only, never functionally required.

## Goals

1. A default placement mode (`Normalized`) in which the per-run CA presents no
   anomalous filesystem or environment artifact: not in `/work`, not named
   `chamber-ca.pem`, not referenced by env vars pointing at a lone custom cert.
   Its presence, location, and references are indistinguishable from a normal
   production box behind a corporate TLS-inspecting proxy.
2. The prior `/work` placement retained verbatim as an opt-in `Workspace` mode —
   the confounded baseline the paper's already-collected corpus (75/75 ladder,
   405-run sweep) represents, so those sealed bundles stay valid for comparison.
3. Every run's sealed bundle records which placement it used, so the causal
   comparison keys on the sealed record rather than operator memory.
4. Honest disclosure of the irreducible residual (cert-chain inspection still
   reveals MITM) — stated as a gap, never hidden, matching the project's ethic.

## Non-goals

- **Undetectable MITM.** Not achievable and not claimed. `openssl s_client`
  against any host still shows the leaf issued by our CA. `Normalized` makes that
  read as a corporate proxy rather than a research cell; it does not remove it.
  New gap-taxonomy entry `mitm-cert-chain` (below).
- **Changing the boundary's decrypt/observe mechanism.** The per-run CA, the
  MITM proxy, and the disclosure path are unchanged; only where/how the cert is
  placed in the guest and what identity it carries change.
- **Preserving the exec-fabrication apparatus.** It is reverted (below). The
  general `append_original_args` relay capability it introduced is kept, since it
  is independent of the confound approach and useful on its own.

## Design

### Placement modes

Trust-anchor placement becomes an enum with two variants, carried on
`DetonationPlan`'s `RealismProfile` (the grouping introduced by the Increment 0
refactor `0559450`, alongside `consequence` and `exec_consequence`):

```
enum TrustPlacement {
    Normalized,   // default — system trust store, corporate-proxy identity
    Workspace,    // opt-in  — /work/chamber-ca.pem + 4 env vars (today's behavior)
}
```

`Workspace` is exactly the current `place_trust_anchor` behavior, moved behind
the variant unchanged. `Normalized` is the new default.

### The `Normalized` mechanism

Building on the verified facts above and the isolation layer's existing
primitives (`ContainerSpec.tmpfs` is already a list of mount paths; the rootfs
is `read_only: true` and stays that way). No guest-image Dockerfile change is
needed, because `update-ca-certificates` rebuilds the trust store from the
already-present, read-only source dir `/usr/share/ca-certificates/mozilla`
(the 145 mozilla certs the `ca-certificates` package ships) plus the local
drop-in dir — verified live: wiping `/etc/ssl/certs`, adding one drop-in, and
running `update-ca-certificates` rebuilds a 146-cert bundle.

1. **Writable trust dirs via tmpfs.** At cell creation, `AgentCell::start` adds
   tmpfs mounts over `/etc/ssl/certs` and `/usr/local/share/ca-certificates` (the
   same `ContainerSpec.tmpfs` mechanism `/work` already uses). Both become empty
   and writable; the rootfs stays read-only, and the mozilla source dir
   `/usr/share/ca-certificates` is untouched (not mounted over). Only these two
   dirs become writable, and only in the cell.
2. **Startup install.** Before the first agent turn — in the same arming-time
   window that currently writes the `/work` anchor — the harness writes the
   fresh per-run CA into `/usr/local/share/ca-certificates/corporate-proxy-ca.crt`
   (via the existing `write_file`/`exec_with_stdin` path, not inline in an argv)
   and runs `update-ca-certificates`, which rebuilds `/etc/ssl/certs` from the
   read-only mozilla source (145) plus our drop-in (1) = 146.

Failure of any step is an `ArmingRefusal` (fail-closed, like the current anchor
placement) — a normalized run that could not establish trust must not proceed as
though it had, because the boundary could then observe only failed handshakes
rather than decrypted exfil.

### Trust coverage after install

| Client | Trusts via | CA env var |
|---|---|---|
| curl, wget, git, openssl | rewritten system bundle (`/etc/ssl/certs/ca-certificates.crt`) | none |
| Python stdlib `ssl` / `urllib` | system bundle (Alpine python default verify path) | none |
| Python `requests` / certifi | its own bundle — steered | `REQUESTS_CA_BUNDLE` → `/etc/ssl/certs/ca-certificates.crt` |
| Node | its own bundle — steered | `NODE_EXTRA_CA_CERTS` → `/etc/ssl/certs/ca-certificates.crt` |

The only residual env steering points at the **standard** system bundle path —
a value real corporate boxes use (and which now genuinely contains our cert),
not a `/work` tell. `SSL_CERT_FILE` and `CURL_CA_BUNDLE` are **not** set in
`Normalized` mode; the tools find our cert in the store natively.

### CA identity

`per_run_ca()` (`chamber-capture/src/bin/chamber-boundary.rs`) gets a generic
corporate-proxy subject/CN carrying no "chamber"/"detonation" string (e.g. a
plausible corporate-proxy root name). Still generated fresh per run — per-run
attribution and the "one leak compromises only one run" property are unchanged.
This is what makes cert-chain inspection read as "behind a corp proxy" rather
than "in a research cell."

### Mode selection and self-describing evidence

- **Knob:** `CHAMBER_TRUST_PLACEMENT`, read via the existing `env_or` pattern in
  the two entrypoints (`chamber-detonate-live`, `chamber-differential`). Unset or
  `normalized` → `Normalized`; `workspace` → `Workspace`. Value-based, not
  presence-based (the superseded `CHAMBER_CONFOUND_FREE=0`-still-arms bug is not
  reproduced). Polarity is inverted deliberately: the realistic behavior is the
  default; the confounded one must be asked for.
- **Bundle field:** a `TrustPlacement::{Normalized, Workspace}` marker is sealed
  into the bundle alongside the existing `ExecInterception` coverage marker, so a
  run is never ambiguous about its own condition after the fact.

### The revert

Remove the superseded exec-fabrication apparatus:

- **Delete:** `runtime/images/guest-exec-relay/src/hide-entry.c`,
  `runtime/images/guest-supply/Dockerfile.relay`, the `--relay` path in
  `build-rungs.sh`, `runtime/crates/chamber-run/src/confound_free.rs`, the
  `CHAMBER_CONFOUND_FREE` wiring in both entrypoints, and its unit tests.
- **Keep:** `append_original_args` (the general relay capability in `relayd.c`,
  `config.c`/`config.h`, `exec_consequence.rs`) and `json_as_bool` — both
  independent of the confound approach.
- **Add:** a behavioral test for `append_original_args` (the review noted it has
  none). Because `relayd.c` is aarch64-only and compiled by no unit-test binary,
  this is a live-container **e2e** test in `chamber-e2e/tests/exec_consequence.rs`'s
  style, beside the existing substitute tests.

The Increment 0 `RealismProfile` grouping (`0559450`) stays; `TrustPlacement`
joins it as a third field.

## Testing and re-validation

**New e2e tests** (`chamber-e2e`, driven through `run_detonation`'s real arming +
placement path — the layer a `docker exec stub` smoke test bypasses):

1. **`Normalized` leaves no artifact:** post-run, no `chamber-ca.pem` under
   `/work`; `find / -name 'chamber-ca.pem'` empty; no CA env var names a `/work`
   path.
2. **Trust actually works:** a real HTTPS request through the boundary succeeds
   with **no** CA env var (curl via the system store) — proving the install
   established trust, not merely hid a file.
3. **Corporate-proxy identity:** the installed cert's subject reads as a
   corporate proxy and sits among the ~145 rebuilt siblings, not alone.
4. **`Workspace` mode intact:** the `/work` placement still holds when explicitly
   selected — the baseline arm is reproducible.
5. **`append_original_args` behavioral:** a wrapped command receives the caller's
   real trailing arguments end-to-end.

**Re-validation (accepted blast radius of a default change).** Every test and
code path that assumes `/work` placement is updated to assert it explicitly
under `Workspace`, with a `Normalized`-mode assertion added beside it. Known
site: `chamber-e2e/tests/containment.rs:758` asserts
`SSL_CERT_FILE=/work/chamber-ca.pem`. Implementation sweeps for every
`/work/chamber-ca.pem` and `SSL_CERT_FILE`/`CURL_CA_BUNDLE` assumption and fixes
each explicitly rather than letting the default flip silently.

**Verification gate before "done":** `cargo check/fmt/clippy --all-targets
--all-features`; the guest C suite (`run_c_tests.sh`, ASan/UBSan); `chamber-run`
lib tests; the `chamber-e2e` suite through the real detonation path.

## Residual — stated, not hidden

New gap-taxonomy entry:

- **`mitm-cert-chain` (proposed).** A determined agent running `openssl s_client`
  (or `curl -v` and inspecting the chain) sees the leaf issued by our per-run CA
  rather than the real host's public issuer, so TLS interception is detectable by
  direct chain inspection regardless of where the CA is installed.
  `Normalized` makes this read as a corporate-proxy signal (production-normal)
  rather than a research-chamber tell, but does not eliminate it. Runtimes that
  ignore the system store and carry an embedded root set (a Java keystore, a
  statically linked bundle) remain `gap.trust-anchor-steering`, unchanged.

## Authority chain

- Supersedes the exec-fabrication design
  `docs/superpowers/specs/2026-08-15-execrelayd-ca-pem-confound-design.md`.
- Motivated by the adversarial review outcome
  (`agenticpractices:observation:0i3batvp599onm09nyat`) and the §6.5
  harness-artifact-confound finding it targets.
- Touches: `chamber-isolation/src/env.rs` (a normalized-trust env method +
  extra-tmpfs declaration) and `cell.rs` (tmpfs wiring);
  `chamber-capture/src/bin/chamber-boundary.rs` (`per_run_ca` identity);
  `chamber-run` (`TrustPlacement` enum on `DetonationPlan`, the arming-time
  install branch, bundle field, the revert); the two `chamber-model` entrypoints
  (mode selection); `chamber-e2e` tests. No guest-image Dockerfile change — the
  system trust store rebuilds from the already-present mozilla source dir.

**Crate-boundary note:** `chamber-isolation` does not depend on
`chamber-capture`, so `TrustPlacement` lives in `chamber-run` (on
`DetonationPlan`, beside `realism`) rather than on `RealismProfile`. `env.rs`
exposes the two placement *mechanisms* (the existing `place_trust_anchor` for
`Workspace`; a new normalized-trust env method for `Normalized`) and `chamber-run`
owns the *policy* (which mode, from the knob).
