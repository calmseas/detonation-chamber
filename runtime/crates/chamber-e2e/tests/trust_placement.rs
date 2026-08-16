//! Trust-anchor placement, end to end through a real guest.
//!
//! The unit tests in `chamber-run::run` prove the two placements build the right
//! environment against a fake cell — which env vars, which tmpfs, which install
//! step. This proves the thing that fake cannot: that under `Normalized` the CA
//! is genuinely installed into the guest's system trust store (so a real `curl`
//! completes its TLS handshake through the boundary with NO CA env var and NO
//! `/work` file), and that `Workspace` still places the `/work` anchor.
//!
//! The trust proof is `recorded_snis`: for the observer to record an HTTPS
//! exchange it must have decrypted it, which requires the guest to have trusted
//! the boundary's per-run CA. No trust, no handshake, no recorded exchange.

mod support;
use support::*;

use std::future::Future;

use chamber_evidence::{ObservationKind, OpenedBundle};
use chamber_run::{
    DetonationPlan, ImageTags, PlantedCanary, ScriptedTurns, TrustPlacement, run_detonation,
};

const CANARY: &str = "AKIAIOSFODNN7EXAMPLE";

fn block_on<F: Future>(f: F) -> F::Output {
    tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .expect("build a tokio runtime")
        .block_on(f)
}

fn image_tags() -> ImageTags {
    ImageTags {
        capture: "chamber-capture:test".into(),
        warden: "chamber-warden:test".into(),
        guest: "chamber-guest:test".into(),
        inspector: "chamber-inspector:test".into(),
    }
}

fn open_bundle(ep: &chamber_run::RunEpilogue) -> OpenedBundle {
    let bytes = std::fs::read(&ep.bundle_path).expect("read the bundle");
    let seal: chamber_evidence::BundleSeal =
        serde_json::from_slice(&std::fs::read(&ep.seal_path).expect("read the seal"))
            .expect("parse the seal");
    chamber_evidence::open(&bytes, &seal).expect("the bundle this run produced must open")
}

fn guest_commands(b: &OpenedBundle) -> Vec<(Vec<String>, i32)> {
    b.ledger
        .entries()
        .iter()
        .filter_map(|o| match o.kind() {
            ObservationKind::GuestCommand {
                argv_redacted,
                exit,
            } => Some((argv_redacted.clone(), *exit)),
            _ => None,
        })
        .collect()
}

/// Every SNI the observer recorded — proof the guest completed a TLS handshake
/// through the boundary, which it can only do if it trusted the per-run CA.
fn recorded_snis(b: &OpenedBundle) -> Vec<String> {
    b.ledger
        .entries()
        .iter()
        .filter_map(|o| match o.kind() {
            ObservationKind::HttpExchange { sni, .. } => sni.clone(),
            _ => None,
        })
        .collect()
}

/// The exit code recorded for the `cat <anchor>` turn.
fn cat_anchor_exit(b: &OpenedBundle) -> i32 {
    guest_commands(b)
        .into_iter()
        .find(|(argv, _)| argv.iter().any(|a| a.contains("chamber-ca.pem")))
        .map(|(_, exit)| exit)
        .expect("the `cat /work/chamber-ca.pem` turn must be recorded")
}

/// Drives one run: reach the boundary over TLS, then probe for the `/work`
/// anchor, then conclude.
fn run_with(placement: TrustPlacement, tag: &str) -> (chamber_run::RunEpilogue, OpenedBundle) {
    ensure_images();
    let _serialised = chamber_subnet_lock();

    let evidence = shared_scratch(&format!("trust-placement-{tag}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&evidence);

    let script = r#"[
        {"do": "run_command", "argv": ["curl", "-sS", "https://example.test/probe"]},
        {"do": "run_command", "argv": ["cat", "/work/chamber-ca.pem"]},
        {"do": "conclude"}
    ]"#;
    let mut turns = ScriptedTurns::from_bytes("trust-placement", script.as_bytes()).expect("parse");

    let plan = DetonationPlan {
        images: image_tags(),
        ruleset: images_dir().join("chamber.nft"),
        evidence_dir: evidence.clone(),
        canaries: vec![PlantedCanary {
            label: "aws-key".into(),
            value: CANARY.into(),
            var: "CHAMBER_TOKEN".into(),
        }],
        max_turns: 8,
        skill_dir: None,
        realism: chamber_capture::RealismProfile::default(),
        trust_placement: placement,
    };

    let ep = block_on(run_detonation(&plan, &mut turns)).unwrap_or_else(|e| panic!("{e}"));
    let b = open_bundle(&ep);
    (ep, b)
}

/// `Normalized` (the default) installs the CA into the system trust store: the
/// guest trusts the boundary with no CA env var, and there is no `/work` anchor.
#[test]
fn normalized_trusts_via_the_system_store_with_no_work_anchor() {
    let (ep, b) = run_with(TrustPlacement::Normalized, "normalized");

    assert_eq!(ep.trust_placement, TrustPlacement::Normalized);

    // Trust established: the boundary decrypted an exchange, which requires the
    // guest to have trusted the per-run CA via the rebuilt system store — with
    // no SSL_CERT_FILE and no /work anchor placed.
    assert!(
        recorded_snis(&b).iter().any(|s| s.contains("example.test")),
        "no HTTPS exchange was recorded — curl did not trust the boundary through the system store; \
         snis={:?}",
        recorded_snis(&b)
    );

    // No /work anchor: `cat /work/chamber-ca.pem` fails.
    assert_ne!(
        cat_anchor_exit(&b),
        0,
        "cat /work/chamber-ca.pem succeeded — the anchor is in /work under Normalized"
    );
}

/// `Workspace` (opt-in) is the confounded baseline: the `/work` anchor is placed
/// and trust still works.
#[test]
fn workspace_places_the_work_anchor_and_still_trusts() {
    let (ep, b) = run_with(TrustPlacement::Workspace, "workspace");

    assert_eq!(ep.trust_placement, TrustPlacement::Workspace);

    assert!(
        recorded_snis(&b).iter().any(|s| s.contains("example.test")),
        "no HTTPS exchange was recorded under Workspace; snis={:?}",
        recorded_snis(&b)
    );

    // The /work anchor is present: `cat /work/chamber-ca.pem` succeeds.
    assert_eq!(
        cat_anchor_exit(&b),
        0,
        "cat /work/chamber-ca.pem failed — the anchor was not placed under Workspace"
    );
}
