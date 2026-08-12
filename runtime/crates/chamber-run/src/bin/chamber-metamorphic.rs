//! `chamber-metamorphic <label>=<bundle.json> ...` — the metamorphic axis.
//!
//! Given several sealed bundles from runs of the SAME skill on the SAME task with
//! DIFFERENT known planted secrets, report the outbound shapes whose value depends
//! on the secret. That is exfiltration in a form the canary matcher cannot recover
//! and the shape axis cannot see (same destination, hidden value —
//! `gap.shape-value-blind`). It reports a **lead**, never a verdict.
//!
//! Each argument is `label=path/to/bundle.json`; the seal is assumed to sit beside
//! it as `bundle.sig` unless the bundle path ends `.json`, in which case the seal
//! is the same path with `.json` replaced by `.sig`. Two or more bundles required.

use std::path::{Path, PathBuf};
use std::process::ExitCode;

use chamber_run::{MetamorphicArm, metamorphic_leads, open_arm};

fn seal_beside(bundle: &Path) -> PathBuf {
    // bundle.json -> bundle.sig; otherwise bundle.sig in the same directory.
    if bundle.extension().and_then(|e| e.to_str()) == Some("json") {
        bundle.with_extension("sig")
    } else {
        bundle.with_file_name("bundle.sig")
    }
}

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args.len() < 2 {
        eprintln!("usage: chamber-metamorphic <label>=<bundle.json> <label>=<bundle.json> [...]");
        eprintln!();
        eprintln!("  Two or more sealed bundles: the SAME skill and task, run with");
        eprintln!("  DIFFERENT known planted secrets. Reports outbound shapes whose");
        eprintln!("  value depends on the secret (exfil the canary cannot recover).");
        return ExitCode::from(2);
    }

    let mut arms = Vec::new();
    for arg in &args {
        let Some((label, bundle)) = arg.split_once('=') else {
            eprintln!("bad argument {arg:?}: expected <label>=<bundle.json>");
            return ExitCode::from(2);
        };
        let bundle_path = PathBuf::from(bundle);
        let seal_path = seal_beside(&bundle_path);
        match open_arm(&bundle_path, &seal_path) {
            Ok(opened) => arms.push(MetamorphicArm::from_opened(label, &opened)),
            Err(e) => {
                eprintln!("cannot open {bundle}: {e:?}");
                return ExitCode::from(2);
            }
        }
    }

    let labels: Vec<&str> = arms.iter().map(|a| a.secret_label.as_str()).collect();
    println!(
        "metamorphic axis over {} arms (perturbed secrets: {})",
        arms.len(),
        labels.join(", ")
    );

    let leads = metamorphic_leads(&arms);
    if leads.is_empty() {
        println!(
            "\nNo secret-dependent emissions. Every outbound shape carried the same value \
             under every secret — consistent with a skill that does not exfiltrate the \
             planted secret. That is NOT safety: a secret-INDEPENDENT payload (sabotage), or \
             a channel not exercised by this task, would not show here."
        );
        return ExitCode::SUCCESS;
    }

    println!(
        "\nSECRET-DEPENDENT EMISSIONS ({} — a lead, not a finding):",
        leads.len()
    );
    println!("  these outbound shapes carried a value that changed with the planted secret,");
    println!("  which is what exfiltration of the secret looks like — even boundary-blind:");
    for lead in &leads {
        println!(
            "    {}   ({} distinct values across {} arms)",
            lead.shape, lead.distinct_values, lead.arms
        );
    }
    println!(
        "\nA value that tracks the secret is strong evidence of exfil, but a model-authored \
         value can vary innocently too. The signal is cleanest for code-authored emissions. \
         Read the arm bundles."
    );
    // Exit 2 mirrors the differential's "divergent" — a positive lead worth acting on.
    ExitCode::from(2)
}
