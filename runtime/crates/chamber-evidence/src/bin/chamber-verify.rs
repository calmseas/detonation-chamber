//! `chamber-verify <bundle.json> <bundle.sig>` — the cold reader.
//!
//! Someone who did not run the detonation, and has no reason to trust whoever
//! did, has these two files and this binary. Everything it reports is derived
//! from the bytes in front of it: the verdict is re-derived from the ledger
//! rather than read out of the field claiming to hold it, and the run's
//! identity is taken from *inside* the signed payload rather than from
//! alongside the signature.
//!
//! # This cannot tell you something is safe
//!
//! There is no verdict meaning "clean", and there is no exit code meaning it
//! either. `no_finding` says that nothing carrying a planted token crossed the
//! boundary **on the channels that were watched** — so it is reported here
//! alongside what was not watched and what this build cannot see at all. A
//! reader who takes it as a clearance has been misled, and the output is
//! written to make that hard.
//!
//! # Exit codes
//!
//! These say whether the *artefact verified*, not what the run found. The
//! verdict is on stdout; a caller wanting to branch on it should read that.
//! Conflating the two would make a detonated run look like a broken bundle.
//!
//! | code | meaning |
//! |---|---|
//! | 0 | the bundle verified and opened |
//! | 1 | refused — signature, canonical form, or internal consistency |
//! | 2 | the files could not be read, or the arguments were wrong |

use std::process::ExitCode;

use chamber_evidence::{BundleSeal, ChannelCoverage, OpenedBundle, Verdict, open};

const VERIFIED: u8 = 0;
const REFUSED: u8 = 1;
const UNUSABLE: u8 = 2;

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let [bundle_path, seal_path] = match args.as_slice() {
        [b, s] => [b.clone(), s.clone()],
        _ => {
            eprintln!("usage: chamber-verify <bundle.json> <bundle.sig>");
            return ExitCode::from(UNUSABLE);
        }
    };

    let bundle_bytes = match std::fs::read(&bundle_path) {
        Ok(b) => b,
        Err(e) => {
            eprintln!("cannot read {bundle_path}: {e}");
            return ExitCode::from(UNUSABLE);
        }
    };
    let seal_text = match std::fs::read_to_string(&seal_path) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("cannot read {seal_path}: {e}");
            return ExitCode::from(UNUSABLE);
        }
    };
    let seal: BundleSeal = match serde_json::from_str(&seal_text) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("{seal_path} is not a readable seal: {e}");
            return ExitCode::from(UNUSABLE);
        }
    };

    match open(&bundle_bytes, &seal) {
        Ok(opened) => {
            report(&bundle_path, &opened);
            ExitCode::from(VERIFIED)
        }
        Err(refusal) => {
            // Refusals go to stderr and say what was wrong, because the failure
            // mode that matters is someone skimming past a rejected bundle and
            // reading the absence of findings as an absence of problems.
            eprintln!("REFUSED: {bundle_path}");
            eprintln!("  {refusal}");
            eprintln!();
            eprintln!(
                "  This bundle was not accepted, so nothing in it has been \
                 reported. It is not evidence of anything, in either direction."
            );
            ExitCode::from(REFUSED)
        }
    }
}

fn report(path: &str, opened: &OpenedBundle) {
    println!("bundle      {path}");
    println!("run         {}", opened.run.as_str());
    println!("ending      {:?}", opened.ending);
    println!("ledger      {} observation(s)", opened.ledger.len());
    println!();

    match &opened.verdict {
        Verdict::Detonated { witnesses } => {
            println!("VERDICT     detonated");
            println!(
                "            {} witness(es), each naming a ledger entry that carries the evidence:",
                witnesses.len()
            );
            for w in witnesses {
                println!("              ordinal {w:?}");
            }
        }
        Verdict::InsufficientCoverage { blind_channels } => {
            println!("VERDICT     insufficient coverage");
            println!("            The run reached NO conclusion. A channel that could have");
            println!("            carried a finding was not observed:");
            for c in blind_channels {
                println!("              {c}");
            }
            println!("            This must not be read as though nothing happened.");
        }
        Verdict::NoFinding => {
            println!("VERDICT     no finding");
            println!("            Nothing carrying a planted token crossed the boundary ON THE");
            println!("            CHANNELS LISTED BELOW. This is not a statement about the");
            println!("            artefact's safety, and there is no verdict that would be.");
        }
    }

    // A bundle that carried a weaker claim than its own evidence supports had
    // its conclusion edited while the evidence was left in place. That is the
    // one signal here worth waking someone for.
    if let Some(carried) = &opened.raised_from {
        println!();
        println!("!! TAMPER SIGNAL");
        println!(
            "   The file carried the verdict {} while its own ledger supports {}.",
            carried.wire_tag(),
            opened.verdict.wire_tag()
        );
        println!("   The evidence was present and the conclusion had been weakened.");
        println!("   The verdict above is the one this reader derived, not the one it found.");
    }

    println!();
    println!("channels watched");
    for (channel, coverage) in opened.coverage.iter() {
        match coverage {
            ChannelCoverage::Watched => {
                println!("  {:<20} watched", channel.wire_tag());
            }
            ChannelCoverage::Absent { cause, detail } => {
                println!(
                    "  {:<20} NOT WATCHED — {cause:?}: {detail}",
                    channel.wire_tag()
                );
            }
        }
    }

    if !opened.gaps.is_empty() {
        println!();
        println!(
            "declared limits of this build ({}) — permanent, not run-specific",
            opened.gaps.len()
        );
        for gap in &opened.gaps {
            println!("  {} [{:?}]", gap.id, gap.cause);
            println!("      {}", gap.scope);
        }
    }
}
