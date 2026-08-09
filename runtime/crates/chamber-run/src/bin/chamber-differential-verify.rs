//! `chamber-differential-verify <differential.json> <differential.sig>` —
//! re-derive a differential's verdict from the arm bundles it names.
//!
//! # Why this is not part of `chamber-verify`
//!
//! The design named `chamber-verify` as the cold-check surface, but that binary
//! lives in `chamber-evidence` and the differential lives in `chamber-run`,
//! which depends on it. Putting the differential re-derivation in
//! `chamber-verify` would invert that dependency — the evidence layer would
//! have to know about the composition layer that uses it. So the cold-checker
//! sits one level up, where it can see both.
//!
//! # What re-derivation means
//!
//! The differential's own summary is never trusted. This verifies the
//! signature, re-opens every arm bundle named in the file, re-derives each
//! arm's verdict from its own ledger, recomputes the diff, and refuses the file
//! if its claim does not match what its arms support.

use std::process::ExitCode;

use chamber_run::{DiffVerdict, RecheckRefusal, recheck_differential};

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let [bundle, seal] = match args.as_slice() {
        [b, s] => [b.clone(), s.clone()],
        _ => {
            eprintln!("usage: chamber-differential-verify <differential.json> <differential.sig>");
            return ExitCode::from(4);
        }
    };

    let read = |path: &str| std::fs::read(path).map_err(|e| format!("{path}: {e}"));
    let (bytes, seal_bytes) = match (read(&bundle), read(&seal)) {
        (Ok(b), Ok(s)) => (b, s),
        (Err(e), _) | (_, Err(e)) => {
            eprintln!("{e}");
            return ExitCode::from(4);
        }
    };
    let Ok(seal) = serde_json::from_slice(&seal_bytes) else {
        eprintln!("{seal} is not a seal");
        return ExitCode::from(4);
    };

    match recheck_differential(&bytes, &seal) {
        Ok(verdict) => {
            println!("differential  {bundle}");
            println!(
                "VERDICT       {} (re-derived from the arm bundles)",
                verdict.wire_tag()
            );
            match verdict {
                DiffVerdict::Divergent { witnesses } => {
                    println!();
                    for w in &witnesses {
                        println!(
                            "  {} on {} in the {} class",
                            w.label,
                            w.channel.wire_tag(),
                            w.class.wire_tag()
                        );
                    }
                    ExitCode::from(2)
                }
                DiffVerdict::Inconclusive { blind_classes } => {
                    for class in &blind_classes {
                        println!("  no trustworthy pair for the {} class", class.wire_tag());
                    }
                    ExitCode::from(1)
                }
                DiffVerdict::NoDivergence => {
                    println!();
                    println!(
                        "The candidate did nothing the reference did not, on the channels \
                         watched, under the battery that was run. That is not safety — each \
                         arm's bundle lists what it did not watch."
                    );
                    ExitCode::from(0)
                }
            }
        }
        Err(refusal) => {
            eprintln!("REFUSED: {refusal}");
            // A claim its own evidence does not support is worse than an
            // unreadable file, and a reader should be able to tell them apart.
            match refusal {
                RecheckRefusal::VerdictDisagrees { .. } => ExitCode::from(5),
                _ => ExitCode::from(4),
            }
        }
    }
}
