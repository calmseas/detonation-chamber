//! The wall this crate exists to preserve.
//!
//! `chamber-model` holds an HTTP client, and an HTTP client drags in a TLS
//! terminator. `chamber-run/tests/no_proxy_stack.rs` forbids exactly that stack
//! from the orchestrator, because an intercepting proxy or TLS terminator in
//! the one process outside the chamber IS an egress path outside the chamber.
//!
//! That test already guards `chamber-run`. This one guards the split itself,
//! from the side that creates the temptation: the moment a provider exists,
//! "just put the client in chamber-run" becomes a one-line change that looks
//! like simplification. Two assertions, and the second is the load-bearing one
//! — without it, deleting this crate and folding it into the orchestrator would
//! leave a green suite.

use std::process::Command;

const TLS_STACK: &[&str] = &["rustls", "hyper", "http-body-util"];

fn closure_of(package: &str) -> String {
    let out = Command::new(env!("CARGO"))
        .args([
            "tree",
            "--package",
            package,
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
        "cargo tree failed for {package}, so this test proves nothing: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    String::from_utf8_lossy(&out.stdout).into_owned()
}

/// Anchored at a line start with a following space, so `hyper` does not match
/// `hyper-util` and `rustls` does not match `rustls-pki-types`.
fn links(tree: &str, crate_name: &str) -> bool {
    let needle = format!("{crate_name} v");
    tree.lines().any(|l| l.trim_start().starts_with(&needle))
}

/// The orchestrator stays clean now that a TLS-carrying crate shares the
/// workspace. `chamber-run`'s own test asserts this too; asserting it from here
/// means the check also fires in the review of whatever change adds a provider.
#[test]
fn the_orchestrator_still_does_not_link_the_proxy_stack() {
    let tree = closure_of("chamber-run");

    let packages = tree.lines().filter(|l| !l.trim().is_empty()).count();
    assert!(
        packages > 20,
        "cargo tree returned only {packages} lines; the check would pass \
         vacuously.\n{tree}"
    );

    let found: Vec<&str> = TLS_STACK
        .iter()
        .copied()
        .filter(|c| links(&tree, c))
        .collect();
    assert!(
        found.is_empty(),
        "chamber-run links {found:?}. A TLS terminator in the orchestrator is \
         an egress path OUTSIDE the chamber. The provider belongs in \
         chamber-model, which depends on chamber-run — never the reverse.\n\n{tree}"
    );
}

/// And the stack really is over here.
///
/// Without this, the split could be undone — provider folded back into
/// `chamber-run`, this crate deleted — and every remaining test would still
/// pass. This is what makes the separation checked rather than intended.
#[test]
fn the_provider_is_the_crate_that_carries_the_stack() {
    let tree = closure_of("chamber-model");

    let missing: Vec<&str> = TLS_STACK
        .iter()
        .copied()
        .filter(|c| !links(&tree, c))
        .collect();
    assert!(
        missing.is_empty(),
        "chamber-model does not link {missing:?}. Either the HTTP client moved \
         somewhere it should not be, or this crate no longer holds the \
         provider — check that chamber-run is still clean before assuming this \
         is harmless.\n\n{tree}"
    );
}
