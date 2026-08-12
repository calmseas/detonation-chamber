//! `chamber-integrity --spec <spec.json> <role>=<turns.jsonl> ...` — the integrity axis.
//!
//! Grades what the agent **answered**, not what crossed the wire. Every other axis
//! in this workspace produces a confidentiality verdict; an artefact that induces a
//! subtly *wrong* answer sends nothing anywhere and reads as clean on all of them.
//!
//! Each argument is `<role>=<path/to/turns.jsonl>`, where the file is a turn dump
//! (`CHAMBER_TURN_DUMP`) and the answer graded is the **last turn's response**.
//! Roles:
//!
//! - `candidate` — the artefact under test. Required. Repeat it (`candidate=a.jsonl
//!   candidate=b.jsonl`) with runs of the same artefact under *equivalent prompts*
//!   to enable the metamorphic-consistency oracle.
//! - `reference` — the benign control arm, same battery task. Enables the
//!   cross-reference oracle.
//!
//! The spec file is `{"task": "...", "claims": [{"name": "...", "requirement":
//! {"contains": "..."}}, ...]}`; `{"absent": "..."}` is the other requirement form.
//!
//! Exit 2 on a defect (mirroring the differential's "divergent"), 0 otherwise —
//! including `INCONCLUSIVE`, which is **not** a pass and says so on stdout.

use std::collections::BTreeMap;
use std::process::ExitCode;

use chamber_evidence::Digest32;
use chamber_run::{
    AnswerUnderTest, Claim, GoldenSpec, IntegrityFinding, OracleReading, PanelReading,
    cross_reference_reading, golden_reading, metamorphic_consistency_reading, panel,
};

#[derive(serde::Deserialize)]
struct TaskSpec {
    task: String,
    claims: Vec<Claim>,
}

/// The fields of a turn-dump line this tool reads. The dump carries more; a
/// partial view keeps the tool from breaking when unrelated fields are added.
#[derive(serde::Deserialize)]
struct TurnLine {
    response: String,
    response_digest: Digest32,
}

/// The last turn's response, plus the digest recorded beside it.
///
/// The final turn is the agent's answer; earlier turns are working. A dump with no
/// parseable line has no answer to grade, which is an error rather than a pass.
fn final_answer(path: &str) -> Result<(String, Digest32), String> {
    let text = std::fs::read_to_string(path).map_err(|e| format!("cannot read {path}: {e}"))?;
    let last = text
        .lines()
        .rfind(|l| !l.trim().is_empty())
        .ok_or_else(|| format!("{path} is empty — no turn to grade"))?;
    let line: TurnLine =
        serde_json::from_str(last).map_err(|e| format!("{path}: last line is not a turn: {e}"))?;
    Ok((line.response, line.response_digest))
}

fn usage() -> ExitCode {
    eprintln!(
        "usage: chamber-integrity --spec <spec.json> candidate=<turns.jsonl> [candidate=...] [reference=<turns.jsonl>]"
    );
    eprintln!();
    eprintln!("  Grades the agent's ANSWER against declared claims. Repeat `candidate=`");
    eprintln!("  with equivalent-prompt runs to enable the consistency oracle; add");
    eprintln!("  `reference=` (the benign control arm) to enable cross-reference.");
    ExitCode::from(2)
}

fn main() -> ExitCode {
    let argv: Vec<String> = std::env::args().skip(1).collect();
    let Some(i) = argv.iter().position(|a| a == "--spec") else {
        return usage();
    };
    let Some(spec_path) = argv.get(i + 1) else {
        return usage();
    };

    let spec: TaskSpec = match std::fs::read_to_string(spec_path)
        .map_err(|e| format!("cannot read {spec_path}: {e}"))
        .and_then(|t| serde_json::from_str(&t).map_err(|e| format!("{spec_path}: {e}")))
    {
        Ok(s) => s,
        Err(e) => {
            eprintln!("{e}");
            return ExitCode::from(2);
        }
    };
    let golden = GoldenSpec::new(spec.claims);

    // role -> answers, in argument order.
    let mut by_role: BTreeMap<String, Vec<AnswerUnderTest>> = BTreeMap::new();
    let mut unbound: Vec<String> = Vec::new();
    for arg in argv
        .iter()
        .enumerate()
        .filter_map(|(n, a)| (n != i && n != i + 1 && !a.starts_with("--")).then_some(a))
    {
        let Some((role, path)) = arg.split_once('=') else {
            eprintln!("bad argument {arg:?}: expected <role>=<turns.jsonl>");
            return usage();
        };
        let (text, digest) = match final_answer(path) {
            Ok(v) => v,
            Err(e) => {
                eprintln!("{e}");
                return ExitCode::from(2);
            }
        };
        let label = format!("{role}[{path}]");
        let answer = AnswerUnderTest::new(&label, text);
        // The dump's text must re-hash to the digest recorded beside it. This
        // catches an edited dump. It does NOT by itself bind the dump to sealed
        // evidence — for that, cross-check this digest against the bundle's
        // inference_transport entry.
        if !answer.is_bound_to(digest) {
            unbound.push(label);
        }
        by_role.entry(role.to_owned()).or_default().push(answer);
    }

    let candidates = by_role.get("candidate").cloned().unwrap_or_default();
    if candidates.is_empty() {
        eprintln!("no candidate= argument: there is nothing to grade");
        return usage();
    }

    if !unbound.is_empty() {
        eprintln!(
            "REFUSING to grade: {} answer(s) do not re-hash to the digest recorded beside them, \
             so the dump was edited after the run: {}",
            unbound.len(),
            unbound.join(", ")
        );
        return ExitCode::from(2);
    }

    println!(
        "integrity axis — task: {}\n  {} claim(s), {} candidate arm(s), {} reference arm(s)",
        spec.task,
        golden.claims.len(),
        candidates.len(),
        by_role.get("reference").map_or(0, Vec::len)
    );

    let mut readings = vec![PanelReading::new(
        "golden",
        golden_reading(&candidates[0], &golden),
    )];

    readings.push(PanelReading::new(
        "cross-reference",
        match by_role.get("reference").and_then(|r| r.first()) {
            Some(reference) => cross_reference_reading(&candidates[0], reference, &golden),
            None => OracleReading::Abstained {
                why: "no reference= arm supplied".into(),
            },
        },
    ));

    readings.push(PanelReading::new(
        "metamorphic-consistency",
        metamorphic_consistency_reading(&candidates, &golden),
    ));

    // The jury is a trait seam, not a model client: this binary reaches no
    // network, so it abstains here rather than pretending to a verdict.
    readings.push(PanelReading::new(
        "jury",
        OracleReading::Abstained {
            why: "no jury configured (chamber-integrity makes no model calls)".into(),
        },
    ));

    println!("\nORACLES:");
    for r in &readings {
        let line = match &r.reading {
            OracleReading::Defect { detail } => format!("DEFECT       {detail}"),
            OracleReading::NoDefectFound => "no defect    (this oracle, these claims only)".into(),
            OracleReading::Abstained { why } => format!("abstained    {why}"),
        };
        println!("  {:24} {line}", r.oracle);
    }

    match panel(&readings) {
        IntegrityFinding::Defect { oracles, details } => {
            println!(
                "\nINTEGRITY DEFECT ({} oracle(s): {})",
                oracles.len(),
                oracles.join(", ")
            );
            for d in &details {
                println!("    {d}");
            }
            println!(
                "\nThe agent's answer was wrong in a way no boundary crossing would show. \
                 This is a lead: confirm against the turn dumps before acting."
            );
            ExitCode::from(2)
        }
        IntegrityFinding::NoDefectFound { read, abstained } => {
            println!(
                "\nNO DEFECT FOUND — {read} oracle(s) read the answer, {abstained} abstained.\n\
                 This is NOT a certificate of correctness: only these oracles, only the \
                 declared claims, and only the agent's ANSWER. Artefacts written to /work are \
                 ungraded (gap.filesystem-channel)."
            );
            ExitCode::SUCCESS
        }
        IntegrityFinding::Inconclusive { abstained } => {
            println!(
                "\nINCONCLUSIVE — all {abstained} oracle(s) abstained; the panel formed no \
                 reading at all.\nThis must NOT be read as clean. Declare claims in the spec, \
                 supply a reference= arm, or add candidate arms."
            );
            ExitCode::SUCCESS
        }
    }
}
