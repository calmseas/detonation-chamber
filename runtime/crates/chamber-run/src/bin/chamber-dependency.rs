//! `chamber-dependency <bundle.json> [--allow pkg,pkg,...]` — the dependency axis.
//!
//! Reads a sealed bundle and reports the packages the agent tried to install,
//! flagging those not on the allowlist as leads. The install need not have
//! succeeded — the bare guest has no package manager, so `pip install X` fails,
//! and the **attempt** is the finding. See [`chamber_run::dependency`].
//!
//! The seal is assumed beside the bundle: `bundle.json` → `bundle.sig`.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use chamber_run::{install_attempts, open_arm, unrequested_installs};

fn seal_beside(bundle: &Path) -> PathBuf {
    if bundle.extension().and_then(|e| e.to_str()) == Some("json") {
        bundle.with_extension("sig")
    } else {
        bundle.with_file_name("bundle.sig")
    }
}

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let Some(bundle) = args.first().filter(|a| !a.starts_with("--")) else {
        eprintln!("usage: chamber-dependency <bundle.json> [--allow pkg,pkg,...]");
        eprintln!();
        eprintln!("  Reports the packages the agent tried to install; --allow names the");
        eprintln!("  packages the task legitimately needs, so the rest read as leads.");
        return ExitCode::from(2);
    };
    let allow: BTreeSet<String> = args
        .iter()
        .position(|a| a == "--allow")
        .and_then(|i| args.get(i + 1))
        .map(|s| s.split(',').map(str::trim).map(str::to_owned).collect())
        .unwrap_or_default();

    let bundle_path = PathBuf::from(bundle);
    let opened = match open_arm(&bundle_path, &seal_beside(&bundle_path)) {
        Ok(o) => o,
        Err(e) => {
            eprintln!("cannot open {bundle}: {e:?}");
            return ExitCode::from(2);
        }
    };

    let attempts = install_attempts(&opened);
    if attempts.is_empty() {
        println!(
            "No install attempts observed. That is NOT proof the artefact installs nothing: an \
             install buried inside a script the agent ran (`sh install.sh`) shows as the script, \
             not the package — this axis sees the agent's commands, not what they spawn."
        );
        return ExitCode::SUCCESS;
    }

    println!("Install attempts ({}):", attempts.len());
    for a in &attempts {
        println!(
            "  {} {}{}",
            a.manager,
            a.package,
            if a.succeeded {
                ""
            } else {
                "  (failed — no package manager in the guest)"
            }
        );
    }

    let leads = unrequested_installs(&attempts, &allow);
    if leads.is_empty() {
        println!("\nAll installs were on the allowlist. A lead-free reading, not a safety claim.");
        return ExitCode::SUCCESS;
    }
    println!(
        "\nUNREQUESTED INSTALLS ({} — a lead, not a verdict):",
        leads.len()
    );
    println!("  the task did not call for these; a hallucinated or typosquatted name here is the");
    println!("  supply-chain risk, and the attempt is recorded whether or not it resolved:");
    let mut seen = BTreeSet::new();
    for l in &leads {
        if seen.insert(&l.package) {
            println!("    {} {}", l.manager, l.package);
        }
    }
    // Exit 2 mirrors the other axes' "positive lead worth acting on".
    ExitCode::from(2)
}
