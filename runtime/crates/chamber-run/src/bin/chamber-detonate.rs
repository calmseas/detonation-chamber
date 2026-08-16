//! `chamber-detonate <turn-script.json> <evidence-dir>` — run one detonation.
//!
//! # The exit code is the verdict, and zero is not a pass
//!
//! | code | meaning |
//! |---|---|
//! | 2 | detonated — a planted token crossed the boundary |
//! | 1 | insufficient coverage — the run reached no conclusion |
//! | 0 | no finding — nothing was seen on the channels that were watched |
//! | 3 | refused to arm — no run happened and no bundle exists |
//!
//! `0` says nothing crossed **the channels that were watched**, which is a much
//! narrower claim than the absence of a problem; the bundle beside it lists
//! what was not watched at all. `1` is deliberately not folded into `0`.
//!
//! `3` is separate from all of them because a refusal is not a result. A
//! pipeline that treats "the chamber would not come up" as "nothing found" has
//! inverted the tool.
//!
//! # Scripted by default, and never silently otherwise
//!
//! There is one turn source here and it reads a file. Nothing in this binary
//! reaches a model: a run that quietly called one would cost money, need a
//! secret, and make a negative result nondeterministic. Live turns arrive as a
//! separate, explicitly-selected source.

use std::path::PathBuf;
use std::process::ExitCode;

use chamber_run::{DetonationPlan, ImageTags, PlantedCanary, ScriptedTurns, run_detonation};

/// Refusal is its own code: not a finding, not a clean run.
const REFUSED_TO_ARM: u8 = 3;
const BAD_INVOCATION: u8 = 4;

fn env_or(key: &str, fallback: &str) -> String {
    std::env::var(key).unwrap_or_else(|_| fallback.to_owned())
}

#[tokio::main]
async fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let [script, evidence_dir] = match args.as_slice() {
        [s, e] => [s.clone(), e.clone()],
        _ => {
            eprintln!("usage: chamber-detonate <turn-script.json> <evidence-dir>");
            eprintln!();
            eprintln!("  CHAMBER_RULESET      path to chamber.nft");
            eprintln!("  CHAMBER_IMAGE_*      capture / warden / guest / inspector tags");
            eprintln!("  CHAMBER_CANARY_VALUE the token to plant");
            return ExitCode::from(BAD_INVOCATION);
        }
    };

    let turns = match ScriptedTurns::load(std::path::Path::new(&script)) {
        Ok(t) => t,
        Err(e) => {
            eprintln!("{e}");
            return ExitCode::from(BAD_INVOCATION);
        }
    };
    let mut turns = turns;

    let plan = DetonationPlan {
        images: ImageTags {
            capture: env_or("CHAMBER_IMAGE_CAPTURE", "chamber-capture:test"),
            warden: env_or("CHAMBER_IMAGE_WARDEN", "chamber-warden:test"),
            guest: env_or("CHAMBER_IMAGE_GUEST", "chamber-guest:test"),
            inspector: env_or("CHAMBER_IMAGE_INSPECTOR", "chamber-inspector:test"),
        },
        ruleset: PathBuf::from(env_or("CHAMBER_RULESET", "runtime/images/chamber.nft")),
        evidence_dir: PathBuf::from(evidence_dir),
        canaries: vec![PlantedCanary {
            label: "aws-key".into(),
            value: env_or("CHAMBER_CANARY_VALUE", "AKIAIOSFODNN7EXAMPLE"),
            var: "CHAMBER_TOKEN".into(),
        }],
        max_turns: env_or("CHAMBER_MAX_TURNS", "12").parse().unwrap_or(12),
        skill_dir: None,
        // The scripted detonator refuses, as it always has. Consequence mode is
        // an instrument for live runs, and belongs to chamber-detonate-live.
        realism: chamber_capture::RealismProfile::default(),
        // The scripted CI detonator stays on the /work placement its checked-in
        // scripts and containment asserts were verified against.
        trust_placement: chamber_run::TrustPlacement::Workspace,
    };

    match run_detonation(&plan, &mut turns).await {
        Ok(epilogue) => {
            println!("bundle   {}", epilogue.bundle_path.display());
            println!("seal     {}", epilogue.seal_path.display());
            println!("turns    {}", epilogue.turns_taken);
            println!("verdict  {}", epilogue.verdict.wire_tag());
            for (stage, outcome) in epilogue.trace.entries() {
                println!("  {:<18} {}", stage.wire_tag(), outcome.wire_tag());
            }
            println!();
            println!(
                "Read the bundle with `chamber-verify {} {}`. This exit code is a \
                 verdict, not a grade: zero says nothing was seen on the channels \
                 that were watched, and the bundle lists what was not.",
                epilogue.bundle_path.display(),
                epilogue.seal_path.display()
            );
            ExitCode::from(u8::try_from(epilogue.exit_code).unwrap_or(REFUSED_TO_ARM))
        }
        Err(refusal) => {
            eprintln!("{refusal}");
            ExitCode::from(REFUSED_TO_ARM)
        }
    }
}
