//! Structural guard on the host orchestrator's dependency closure.
//!
//! The artefact-facing proxy runs **in a container**. This crate drives that
//! container from the host and must not contain a second copy of the machinery
//! — not because linking it would be slow, but because an intercepting proxy
//! and a TLS terminator present in the orchestrator are an egress path in the
//! one process that is outside the chamber.
//!
//! The dependency on `chamber-capture` is types-only, and the types are what
//! make the seam between the two processes a typed contract rather than log
//! scraping: capture writes `Observation` records into a file and this crate
//! reads them back. `default-features = false` drops the observer feature and
//! with it ~230 crates.
//!
//! A `default-features = false` in a manifest is an intention. This is the
//! check. One accidental `features = ["observer"]` — or a new dependency that
//! happens to enable it — would restore the whole stack with nothing else
//! reporting the difference.

use std::process::Command;

/// Crates whose presence in the HOST binary would falsify the claim above.
///
/// Each is listed for a specific reason, not by association:
/// - `hudsucker`, `hyper`, `http-body-util` — an HTTP server and an
///   intercepting proxy in the orchestrator process.
/// - `hickory-server`, `hickory-proto` — a DNS server, likewise.
/// - `rustls`, `tokio-rustls`, `rcgen` — TLS termination and certificate
///   minting, which is the capability that makes interception possible at all.
const FORBIDDEN: &[&str] = &[
    "hudsucker",
    "hyper",
    "http-body-util",
    "hickory-server",
    "hickory-proto",
    "rustls",
    "tokio-rustls",
    "rcgen",
];

fn closure() -> String {
    let out = Command::new(env!("CARGO"))
        .args([
            "tree",
            "--package",
            "chamber-run",
            "--edges",
            "normal",
            "--prefix",
            "none",
        ])
        .current_dir(env!("CARGO_MANIFEST_DIR"))
        .output()
        .expect("run cargo tree");

    assert!(
        out.status.success(),
        "cargo tree failed, so this test proves nothing: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    String::from_utf8_lossy(&out.stdout).into_owned()
}

#[test]
fn the_host_orchestrator_does_not_link_the_proxy_stack() {
    let tree = closure();

    // A tree that came back nearly empty would make every assertion below pass
    // for the wrong reason.
    let packages = tree.lines().filter(|l| !l.trim().is_empty()).count();
    assert!(
        packages > 20,
        "cargo tree returned only {packages} lines; the closure check would pass \
         vacuously.\n{tree}"
    );

    let mut found = Vec::new();
    for crate_name in FORBIDDEN {
        // Anchored at a line start with a following space, so `hyper` does not
        // match `hyper-util` and `rustls` does not match `rustls-pki-types`.
        // Those are different crates and banning them by accident would send
        // someone hunting a dependency that is not the problem.
        let needle = format!("{crate_name} v");
        if tree
            .lines()
            .any(|line| line.trim_start().starts_with(&needle))
        {
            found.push(*crate_name);
        }
    }

    assert!(
        found.is_empty(),
        "the host orchestrator links {found:?}. An intercepting proxy or a TLS \
         terminator in this process is an egress path OUTSIDE the chamber. \
         Check that chamber-capture is still depended on with \
         `default-features = false`, and that nothing else enables its \
         `observer` feature.\n\nclosure:\n{tree}"
    );
}

/// The types-only dependency must still be there.
///
/// Dropping `chamber-capture` altogether would pass the test above and quietly
/// replace a typed contract with two processes agreeing on a file format by
/// convention.
#[test]
fn the_typed_seam_to_the_observer_is_still_present() {
    let tree = closure();
    assert!(
        tree.lines()
            .any(|l| l.trim_start().starts_with("chamber-capture v")),
        "chamber-run no longer depends on chamber-capture at all. The ledger \
         seam is only a typed contract while both sides share the types.\n{tree}"
    );
}
