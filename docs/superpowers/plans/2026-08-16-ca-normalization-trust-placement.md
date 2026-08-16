# CA Normalization Trust-Placement Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make CA-normalized trust placement (system store, corporate-proxy identity) the default for chamber runs, with the old `/work` placement retained as an opt-in confounded baseline, and revert the superseded exec-fabrication apparatus.

**Architecture:** A `TrustPlacement` enum on `DetonationPlan` selects between `Normalized` (default: install the per-run CA into the guest's system trust store via writable-tmpfs `/etc/ssl/certs` + `/usr/local/share/ca-certificates` and `update-ca-certificates`) and `Workspace` (today's `/work/chamber-ca.pem` + 4 env vars). `chamber-isolation` exposes the two placement mechanisms; `chamber-run` owns the policy and the arming-time install; the sealed bundle records which mode ran.

**Tech Stack:** Rust (chamber-* workspace crates), C (execrelayd, unchanged except revert), Docker/Alpine guest images (no Dockerfile change), busybox `update-ca-certificates`.

## Global Constraints

- Run all cargo commands from `runtime/`. Target dir is `/Volumes/CargoTargets/...` per `.cargo/config.toml`; do not fight it.
- Guest images are `linux/arm64` only (`--platform linux/arm64` on every build; execrelayd's `#error` enforces it).
- `read_only: true` on the cell container stays; writable dirs are tmpfs mounts only.
- Verification gate before any "done": `cargo check/fmt/clippy --workspace --all-targets --all-features`, guest C suite (`runtime/images/guest-exec-relay/tests/run_c_tests.sh`, ASan/UBSan), `cargo test -p chamber-run --lib`, and the relevant `chamber-e2e` tests through the real detonation path.
- `TrustPlacement` lives in `chamber-run` (chamber-isolation must not depend on chamber-capture). Default is `Normalized`.
- Normalized env steering sets ONLY `REQUESTS_CA_BUNDLE` + `NODE_EXTRA_CA_CERTS` → `/etc/ssl/certs/ca-certificates.crt`; it does NOT set `SSL_CERT_FILE`/`CURL_CA_BUNDLE`.
- Drop-in cert path: `/usr/local/share/ca-certificates/corporate-proxy-ca.crt`. Standard bundle path: `/etc/ssl/certs/ca-certificates.crt`.

---

### Task 0: Revert the exec-fabrication apparatus (clean base)

**Files:**
- Delete: `runtime/images/guest-exec-relay/src/hide-entry.c`, `runtime/images/guest-supply/Dockerfile.relay`, `runtime/crates/chamber-run/src/confound_free.rs`
- Modify: `runtime/images/guest-supply/build-rungs.sh` (remove `--relay` path, restore to the pre-d053e92 shape), `runtime/crates/chamber-run/src/lib.rs` (drop `pub mod confound_free;`), `runtime/crates/chamber-model/src/bin/chamber-detonate-live.rs` + `chamber-differential.rs` (remove `CHAMBER_CONFOUND_FREE` wiring; `exec_consequence` reverts to `None`)
- Keep (do NOT touch): `append_original_args` in `relayd.c`/`config.c`/`config.h`/`exec_consequence.rs`; `json_as_bool` in `json.c`/`json.h` + its tests.

**Interfaces:**
- Produces: a tree where `RealismProfile.exec_consequence` is always `None` from the entrypoints, `append_original_args` remains a valid (default-false) field, and no confound-free code exists.

- [ ] **Step 1:** `git rm runtime/images/guest-exec-relay/src/hide-entry.c runtime/images/guest-supply/Dockerfile.relay runtime/crates/chamber-run/src/confound_free.rs`
- [ ] **Step 2:** In `build-rungs.sh`, remove the `relay=` flag parse, the `--relay` branch, `RELAY_SRC`, and the `$suffix` logic — restore to building only `chamber-guest-supply-<rung>:test` + the generic image. (Diff against `git show d053e92 -- runtime/images/guest-supply/build-rungs.sh` to revert exactly that hunk.)
- [ ] **Step 3:** In `lib.rs` remove `pub mod confound_free;`.
- [ ] **Step 4:** In both `chamber-detonate-live.rs` and `chamber-differential.rs`, remove the `CHAMBER_CONFOUND_FREE` block; set `exec_consequence: None` in the `RealismProfile` (live) / the `DifferentialPlan.exec_consequence: None` (differential) as it was at `eba76a9`.
- [ ] **Step 5:** Remove the now-orphaned `chamber-guest-supply-*-relay:test` image references if any remain in comments.
- [ ] **Step 6:** Verify: `cargo check --workspace --all-targets --all-features` clean; `cargo test -p chamber-run --lib` green; `runtime/images/guest-exec-relay/tests/run_c_tests.sh` green (append_original_args + json_as_bool parse tests survive).
- [ ] **Step 7:** Commit: `git commit -m "Revert exec-fabrication confound apparatus, keep append_original_args"`

---

### Task 1: Corporate-proxy CA identity

**Files:**
- Modify: `runtime/crates/chamber-capture/src/bin/chamber-boundary.rs:165-177` (`per_run_ca`)

**Interfaces:**
- Produces: a per-run CA whose subject DN reads as a corporate proxy (no "chamber"/"detonation"/"chamber" string), still self-signed CA, still fresh per run.

- [ ] **Step 1:** In `per_run_ca`, set a `DistinguishedName` on `params` with `CommonName` = `"Corporate Proxy Root CA"` and `OrganizationName` = a bland generic (e.g. `"IT Security"`). Use `hudsucker::rcgen::{DistinguishedName, DnType}` (already re-exported via the `rcgen` path). Example:
```rust
let mut dn = DistinguishedName::new();
dn.push(DnType::CommonName, "Corporate Proxy Root CA");
dn.push(DnType::OrganizationName, "IT Security");
params.distinguished_name = dn;
```
- [ ] **Step 2:** Verify: `cargo check -p chamber-capture --all-features`.
- [ ] **Step 3:** Rebuild the capture/boundary image if the e2e suite consumes a prebuilt tag (`chamber-capture:test`); note it for Task 6's e2e run.
- [ ] **Step 4:** Commit: `git commit -m "Give the per-run CA a corporate-proxy identity"`

---

### Task 2: Isolation-layer placement mechanisms (env.rs + cell.rs)

**Files:**
- Modify: `runtime/crates/chamber-isolation/src/env.rs` (`EnvDraft`, `SealedEnv`, add normalized-trust method + extra-tmpfs)
- Modify: `runtime/crates/chamber-isolation/src/cell.rs:88-121` (merge extra tmpfs into `ContainerSpec.tmpfs`)
- Modify: `runtime/crates/chamber-isolation/src/lib.rs` (export new symbols if needed)

**Interfaces:**
- Produces:
  - `EnvDraft::mount_writable(&mut self, path: &Path)` — records an extra tmpfs mount.
  - `EnvDraft::steer_managed_trust(&mut self) -> Result<(), BindError>` — binds `REQUESTS_CA_BUNDLE` + `NODE_EXTRA_CA_CERTS` to the const `SYSTEM_CA_BUNDLE = "/etc/ssl/certs/ca-certificates.crt"`. Does NOT bind `SSL_CERT_FILE`/`CURL_CA_BUNDLE`.
  - `SealedEnv::extra_tmpfs(&self) -> &[PathBuf]`.
  - Consumed by `chamber-run` Task 3.
- Consumes: existing `EnvDraft::set`, `place_trust_anchor` (untouched, becomes the Workspace mechanism).

- [ ] **Step 1 (test):** In `env.rs` tests, add `steer_managed_trust_binds_only_the_two_bundle_vars` — after `steer_managed_trust`, seal, assert `REQUESTS_CA_BUNDLE`/`NODE_EXTRA_CA_CERTS` == `/etc/ssl/certs/ca-certificates.crt` and `SSL_CERT_FILE`/`CURL_CA_BUNDLE` are unbound.
- [ ] **Step 2 (test):** Add `extra_tmpfs_survives_sealing` — `mount_writable("/etc/ssl/certs")`, `mount_writable("/usr/local/share/ca-certificates")`, seal, assert `extra_tmpfs()` contains both.
- [ ] **Step 3:** Run both → fail (methods absent).
- [ ] **Step 4:** Add `extra_tmpfs: Vec<PathBuf>` to `EnvDraft` (init empty) and `SealedEnv`; thread through `seal`. Add `mount_writable`, `steer_managed_trust`, `extra_tmpfs()` getter, and `const SYSTEM_CA_BUNDLE`.
- [ ] **Step 5:** In `cell.rs`, build the tmpfs list as `scratch_root().into_iter().chain(extra_tmpfs())` mapped to strings.
- [ ] **Step 6:** Run tests → pass. `cargo test -p chamber-isolation`.
- [ ] **Step 7:** Commit: `git commit -m "chamber-isolation: normalized-trust env method + extra-tmpfs plumbing"`

---

### Task 3: Placement policy, arming install, bundle field (chamber-run)

**Files:**
- Modify: `runtime/crates/chamber-run/src/run.rs` (`DetonationPlan`, `CellEnvironment`, `seal_cell_environment`, `run_detonation` arming block ~417-431)
- Modify: `runtime/crates/chamber-run/src/bundle.rs` (`Observed` + coverage) and re-export
- Modify: every `DetonationPlan { .. }` construction site (10, from the earlier RealismProfile sweep) to set `trust_placement`

**Interfaces:**
- Produces:
  - `pub enum TrustPlacement { Normalized, Workspace }` (in `run.rs` or a small `trust.rs`), `Default` = `Normalized`.
  - `DetonationPlan.trust_placement: TrustPlacement`.
  - `Observed.trust_placement: TrustPlacement`, sealed into the bundle.
- Consumes: Task 2's `steer_managed_trust`, `mount_writable`; existing `place_trust_anchor`, `write_file`, `exec`.

- [ ] **Step 1 (test):** In `run.rs` tests, extend `bare_plan` to take/ default a placement; add `normalized_plan_declares_trust_tmpfs_and_managed_steering` — build a `Normalized` plan, run `seal_cell_environment` against a stub capture, assert the sealed env has `/etc/ssl/certs` + `/usr/local/share/ca-certificates` in `extra_tmpfs`, `REQUESTS_CA_BUNDLE` bound to the system bundle, and no `SSL_CERT_FILE`. Add `workspace_plan_places_the_work_anchor` — `Workspace` plan still binds the 4 vars to `/work/chamber-ca.pem`.
- [ ] **Step 2:** Run → fail.
- [ ] **Step 3:** Add `TrustPlacement` (Default Normalized) + `DetonationPlan.trust_placement`. Refactor `CellEnvironment` to carry a `TrustInstall` enum: `Workspace { anchor_path: PathBuf }` or `Normalized { dropin_path: PathBuf }`, plus `ca_pem`, `env`. In `seal_cell_environment`, branch on `plan.trust_placement`:
  - `Workspace`: `redirect_scratch` + `place_trust_anchor("/work/chamber-ca.pem")` (as today); `TrustInstall::Workspace{ anchor_path }`.
  - `Normalized`: `redirect_scratch` + `mount_writable("/etc/ssl/certs")` + `mount_writable("/usr/local/share/ca-certificates")` + `steer_managed_trust()`; `TrustInstall::Normalized{ dropin_path: "/usr/local/share/ca-certificates/corporate-proxy-ca.crt" }`.
- [ ] **Step 4:** In `run_detonation` arming (~427-431), replace the unconditional `write_file(anchor_path, ca_pem)` with a match on `TrustInstall`:
  - `Workspace{anchor_path}` → `cell.write_file(&anchor_path, ca_pem.as_bytes())`.
  - `Normalized{dropin_path}` → `cell.write_file(&dropin_path, ca_pem.as_bytes())` then `cell.exec(&["update-ca-certificates"], OP_WINDOW)` (map non-zero/refusal to `ArmingRefusal::Chamber` — fail-closed, a normalized run that can't establish trust must not proceed).
- [ ] **Step 5:** Add `Observed.trust_placement`; set it in `bundle::emit`'s call sites from the plan; extend the coverage/serialization minimally (mirror how `exec_interception` is carried). Update `bundle.rs` test fixtures that construct `Observed` to include the new field.
- [ ] **Step 6:** Set `trust_placement` at all 10 `DetonationPlan` construction sites: `Normalized` for the two model bins (Task 4 overrides from env) and for tests that don't care; `Workspace` where a test specifically asserts `/work` (the differential/probe helpers can default `Normalized`).
- [ ] **Step 7:** Run tests → pass. `cargo test -p chamber-run --lib`.
- [ ] **Step 8:** Commit: `git commit -m "chamber-run: TrustPlacement policy, Normalized arming install, bundle field"`

---

### Task 4: Entrypoint mode selection (chamber-model)

**Files:**
- Modify: `runtime/crates/chamber-model/src/bin/chamber-detonate-live.rs`, `chamber-differential.rs`
- Modify: `runtime/crates/chamber-run/src/differential.rs` (`DifferentialPlan` carries `trust_placement`; `arm_detonation_plan` propagates it to both arms)

**Interfaces:**
- Consumes: `TrustPlacement`, `env_or`.
- Produces: `CHAMBER_TRUST_PLACEMENT` (unset/`normalized` → Normalized; `workspace` → Workspace) selected on the plan.

- [ ] **Step 1:** Add a `fn trust_placement_from_env() -> TrustPlacement` (value-based; unknown value → error/`BAD_INVOCATION`, not silent). Reuse in both bins.
- [ ] **Step 2:** In `chamber-detonate-live.rs`, set `trust_placement` on the `DetonationPlan` from that fn.
- [ ] **Step 3:** In `differential.rs`, add `DifferentialPlan.trust_placement` and propagate it inside `arm_detonation_plan` (both arms identical — the boundary is part of the shared environment, same reasoning as `consequence`). In `chamber-differential.rs`, set it from the env fn.
- [ ] **Step 4:** Verify: `cargo check --workspace --all-targets --all-features`; `cargo test -p chamber-run --lib`.
- [ ] **Step 5:** Commit: `git commit -m "chamber-model: CHAMBER_TRUST_PLACEMENT mode selection"`

---

### Task 5: Re-validate existing /work-placement assumptions

**Files:**
- Modify: `runtime/crates/chamber-e2e/tests/containment.rs` (the `SSL_CERT_FILE=/work/chamber-ca.pem` path ~758, and the direct `place_trust_anchor` unit at ~720) and any other `/work/chamber-ca.pem` / `SSL_CERT_FILE` assumers surfaced by grep.

**Interfaces:**
- Consumes: `TrustPlacement::Workspace`.

- [ ] **Step 1:** `grep -rn "/work/chamber-ca.pem\|SSL_CERT_FILE\|CURL_CA_BUNDLE" runtime/crates --include=*.rs` — enumerate every site.
- [ ] **Step 2:** For each site that runs a full detonation and asserts `/work` placement: make it explicitly select `TrustPlacement::Workspace` and keep the assertion (it now documents the confounded baseline). For the direct `place_trust_anchor` unit test at ~720: unchanged (that method IS the Workspace mechanism).
- [ ] **Step 3:** Verify the touched tests compile and (for unit-level) pass: `cargo test -p chamber-e2e --no-run` and any non-Docker units.
- [ ] **Step 4:** Commit: `git commit -m "Re-validate /work-placement tests under explicit Workspace mode"`

---

### Task 6: New e2e tests + append_original_args behavioral test

**Files:**
- Create: `runtime/crates/chamber-e2e/tests/trust_placement.rs`
- Modify: `runtime/crates/chamber-e2e/tests/exec_consequence.rs` (append_original_args behavioral e2e)

**Interfaces:**
- Consumes: the full `run_detonation` path, `chamber-guest:test` (rebuilt if Task 1 changed the CA — it does not touch the guest, only the boundary, so rebuild `chamber-capture:test`).

- [ ] **Step 1 (Normalized, no artifact):** e2e — run a `Normalized` detonation with a scripted turn set; assert `ls /work` (via a scripted `run_command`) shows no `chamber-ca.pem`, and `find / -name chamber-ca.pem` is empty. Assert the sealed bundle records `TrustPlacement::Normalized`.
- [ ] **Step 2 (trust works):** scripted turn does `curl -sS https://example.test/whatever` (any allowlisted-or-consequence host) — with NO CA env var — and the boundary decrypts/records it (the request appears in the ledger as an intercepted TLS body, proving trust was established via the system store).
- [ ] **Step 3 (Workspace intact):** run the same with `TrustPlacement::Workspace`; assert `/work/chamber-ca.pem` present and `SSL_CERT_FILE` names it.
- [ ] **Step 4 (append_original_args behavioral):** in `exec_consequence.rs`, add a live test: a `Substitute` rule with `append_original_args: true` and `replacement_argv: ["/bin/echo", "wrapped"]` matched on `Argv0 "marker"`; run `marker a b c`; assert the intercepted exec ran `/bin/echo wrapped a b c` (the caller's `a b c` were appended). Mirror the existing `substitute_*` test harness.
- [ ] **Step 5:** Full gate: `cargo check/fmt/clippy --workspace --all-targets --all-features`; `run_c_tests.sh`; `cargo test -p chamber-run --lib`; the new `trust_placement` + `exec_consequence` e2e (rebuild `chamber-capture:test` first so the corporate CN is live).
- [ ] **Step 6:** Commit: `git commit -m "e2e: trust-placement modes + append_original_args behavioral test"`

---

### Task 7: Disclose the mitm-cert-chain residual

**Files:**
- Modify: the paper's gap taxonomy `docs/paper/2026-08-10-witness-chamber-preprint-draft.md` §7 (add `mitm-cert-chain (proposed)`); and any machine-readable gap list in `chamber-evidence` if one enumerates gap slugs.

**Interfaces:** none (documentation).

- [ ] **Step 1:** Add the `mitm-cert-chain (proposed)` bullet to §7 with the wording from the spec's Residual section.
- [ ] **Step 2:** If `chamber-evidence` carries a gap-slug enum/list that the taxonomy is checked against, add the slug there and update any exhaustiveness test.
- [ ] **Step 3:** Commit: `git commit -m "Disclose mitm-cert-chain gap: chain inspection still reveals MITM"`

---

## Self-Review

- **Spec coverage:** Goals 1-4 → Tasks 2-4 (Normalized default), Task 3/4 (Workspace opt-in + selection), Task 3 (bundle field), Task 7 (residual). Revert → Task 0. Kept capability + its missing test → Task 0 (keep) + Task 6 (test). Re-validation → Task 5. CN identity → Task 1. No Dockerfile change (per the simplification) — correctly absent.
- **Placeholders:** none — every step names files and concrete actions; code shown where a signature is introduced.
- **Type consistency:** `TrustPlacement`/`TrustInstall`/`steer_managed_trust`/`mount_writable`/`extra_tmpfs`/`SYSTEM_CA_BUNDLE`/`trust_placement` used consistently across Tasks 2-6.
