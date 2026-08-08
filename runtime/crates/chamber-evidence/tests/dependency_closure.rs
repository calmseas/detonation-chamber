//! Structural guard on this crate's dependency closure.
//!
//! `chamber-evidence` promises that verifying a bundle is pure: no I/O, no
//! clock, no name resolution, no network. A third party checks a bundle with
//! nothing but the file in front of them.
//!
//! A doc comment cannot hold that line. One `tokio` or `reqwest` arriving
//! transitively would make the promise false without any function in this crate
//! changing, and nobody would notice. So the closure itself is asserted.
//!
//! This lives under `tests/` deliberately — unlike the key-material leak tests,
//! it needs no crate-private access, and running it as an integration test
//! keeps it out of the unit-test binary.

use std::process::Command;

/// Crates whose presence would falsify the purity claim.
///
/// Async runtimes and reactors, HTTP clients, and wall-clock sources. Each is
/// listed because a bundle reader that could reach the network or read a clock
/// could reach a *different answer* depending on when and where it ran, and the
/// whole point of an offline-verifiable artefact is that it cannot.
const FORBIDDEN: &[&str] = &[
    "tokio",
    "async-std",
    "smol",
    "mio",
    "socket2",
    "hyper",
    "reqwest",
    "ureq",
    "curl",
    "rustls",
    "chrono",
    "time",
];

#[test]
fn verification_closure_has_no_io_or_clock() {
    let out = Command::new(env!("CARGO"))
        .args([
            "tree",
            "--package",
            "chamber-evidence",
            "--edges",
            "normal",
            "--prefix",
            "none",
            "--no-dedupe",
        ])
        .current_dir(env!("CARGO_MANIFEST_DIR"))
        .output()
        .expect("cargo tree must run");

    assert!(
        out.status.success(),
        "cargo tree failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );

    let tree = String::from_utf8(out.stdout).expect("cargo tree emits utf-8");

    // Each line is `name version`, so match the name field exactly rather than
    // by substring — "time" would otherwise match "time-core", and worse, a
    // substring test could pass while the real crate was present under a
    // slightly different rendering.
    let present: Vec<&str> = tree
        .lines()
        .filter_map(|l| l.split_whitespace().next())
        .collect();

    let found: Vec<&str> = FORBIDDEN
        .iter()
        .copied()
        .filter(|bad| present.contains(bad))
        .collect();

    assert!(
        found.is_empty(),
        "chamber-evidence must stay free of I/O and clock dependencies, but its \
         closure now contains: {found:?}.\n\
         Verifying a bundle has to be doable offline, with nothing but the file. \
         If one of these is genuinely needed, it belongs in a crate that does not \
         carry the verifier."
    );
}
