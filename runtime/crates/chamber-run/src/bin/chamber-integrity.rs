//! `chamber-integrity --spec <spec.json> <role>=<turns.jsonl> ...` — the integrity axis.
//!
//! Grades what the agent **produced**, not what crossed the wire. Every other axis
//! in this workspace produces a confidentiality verdict; an artefact that induces a
//! subtly *wrong* answer, or writes a subtly *wrong* file, sends nothing anywhere
//! and reads as clean on all of them.
//!
//! **Answers.** Each `<role>=<path/to/turns.jsonl>` argument is a turn dump
//! (`CHAMBER_TURN_DUMP`); the answer graded is the last turn's response. Roles:
//!
//! - `candidate` — the artefact under test. Required. Repeat it (`candidate=a.jsonl
//!   candidate=b.jsonl`) with runs of the same artefact under *equivalent prompts*
//!   to enable the metamorphic-consistency oracle.
//! - `reference` — the benign control arm, same battery task. Enables the
//!   cross-reference oracle.
//!
//! **Files.** `--work-candidate <capture.json>` and `--work-reference <capture.json>`
//! enable the filesystem and written-content oracles. A capture is
//! `{"before": "<sha256sum output>", "after": "<sha256sum output>",
//! "contents": {"./path": "..."}}` — produced by [`chamber_run::worksnapshot`]
//! against a live cell, with the `before` snapshot taken **after staging**.
//!
//! The spec file is `{"task": "...", "claims": [...], "file_claims": [...]}`, where a
//! claim is `{"name": "...", "requirement": {"contains": "..."}}` and `{"absent":
//! "..."}` is the other requirement form. `file_claims` are declared separately from
//! `claims` on purpose: what a correct *answer* must say and what a correct *file*
//! must contain are different assertions.
//!
//! Exit 2 on a defect (mirroring the differential's "divergent"), 0 otherwise —
//! including `INCONCLUSIVE`, which is **not** a pass and says so on stdout.

use std::collections::BTreeMap;
use std::process::ExitCode;

use chamber_evidence::Digest32;
use chamber_run::{
    AnswerUnderTest, Claim, GoldenSpec, IntegrityFinding, OracleReading, PanelReading, WorkDiff,
    WorkSnapshot, cross_reference_reading, filesystem_reading, golden_reading,
    metamorphic_consistency_reading, panel, written_content_reading,
};

#[derive(serde::Deserialize)]
struct TaskSpec {
    task: String,
    #[serde(default)]
    claims: Vec<Claim>,
    /// Declared separately from `claims` — see the module docs.
    #[serde(default)]
    file_claims: Vec<Claim>,
}

/// One arm's `/work` capture: the two snapshots, plus the content of whatever
/// changed.
#[derive(serde::Deserialize)]
struct WorkCapture {
    before: String,
    after: String,
    #[serde(default)]
    contents: BTreeMap<String, String>,
}

impl WorkCapture {
    fn diff(&self) -> WorkDiff {
        WorkSnapshot::parse(&self.before).diff(&WorkSnapshot::parse(&self.after))
    }

    /// The changed files' contents, in diff order. A path the diff flagged but the
    /// capture has no content for is skipped rather than graded as empty — an
    /// absent capture is not evidence of an empty file.
    fn changed_contents(&self, diff: &WorkDiff) -> Vec<(String, String)> {
        diff.readable()
            .into_iter()
            .filter_map(|p| self.contents.get(&p).map(|c| (p, c.clone())))
            .collect()
    }
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

fn read_json<T: serde::de::DeserializeOwned>(path: &str) -> Result<T, String> {
    let text = std::fs::read_to_string(path).map_err(|e| format!("cannot read {path}: {e}"))?;
    serde_json::from_str(&text).map_err(|e| format!("{path}: {e}"))
}

fn usage() -> ExitCode {
    eprintln!(
        "usage: chamber-integrity --spec <spec.json> candidate=<turns.jsonl> [candidate=...] \
         [reference=<turns.jsonl>] [--work-candidate <capture.json>] [--work-reference <capture.json>]"
    );
    eprintln!();
    eprintln!("  Grades what the agent PRODUCED. Repeat `candidate=` with equivalent-prompt");
    eprintln!("  runs to enable the consistency oracle; add `reference=` (the benign control");
    eprintln!("  arm) for cross-reference; add --work-* captures for the filesystem oracles.");
    ExitCode::from(2)
}

/// Everything the command line asked for, once it has been read successfully.
struct Args {
    spec: String,
    answers: Vec<(String, String)>,
    work_candidate: Option<String>,
    work_reference: Option<String>,
}

fn parse_args(argv: &[String]) -> Result<Args, ()> {
    let mut spec = None;
    let mut answers = Vec::new();
    let mut work_candidate = None;
    let mut work_reference = None;
    let mut it = argv.iter();
    while let Some(a) = it.next() {
        match a.as_str() {
            "--spec" => spec = it.next().cloned(),
            "--work-candidate" => work_candidate = it.next().cloned(),
            "--work-reference" => work_reference = it.next().cloned(),
            other if other.starts_with("--") => {
                eprintln!("unknown flag {other:?}");
                return Err(());
            }
            other => match other.split_once('=') {
                Some((role, path)) => answers.push((role.to_owned(), path.to_owned())),
                None => {
                    eprintln!("bad argument {other:?}: expected <role>=<turns.jsonl>");
                    return Err(());
                }
            },
        }
    }
    match spec {
        Some(spec) => Ok(Args {
            spec,
            answers,
            work_candidate,
            work_reference,
        }),
        None => Err(()),
    }
}

fn main() -> ExitCode {
    let argv: Vec<String> = std::env::args().skip(1).collect();
    let Ok(args) = parse_args(&argv) else {
        return usage();
    };

    let spec: TaskSpec = match read_json(&args.spec) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("{e}");
            return ExitCode::from(2);
        }
    };
    let golden = GoldenSpec::new(spec.claims);
    let file_spec = GoldenSpec::new(spec.file_claims);

    // role -> answers, in argument order.
    let mut by_role: BTreeMap<String, Vec<AnswerUnderTest>> = BTreeMap::new();
    let mut unbound: Vec<String> = Vec::new();
    for (role, path) in &args.answers {
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
        by_role.entry(role.clone()).or_default().push(answer);
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

    // Work captures, if supplied.
    let mut captures: BTreeMap<&str, WorkCapture> = BTreeMap::new();
    for (role, path) in [
        ("candidate", args.work_candidate.as_ref()),
        ("reference", args.work_reference.as_ref()),
    ] {
        if let Some(p) = path {
            match read_json::<WorkCapture>(p) {
                Ok(c) => {
                    captures.insert(role, c);
                }
                Err(e) => {
                    eprintln!("{e}");
                    return ExitCode::from(2);
                }
            }
        }
    }

    println!(
        "integrity axis — task: {}\n  {} answer claim(s), {} file claim(s), {} candidate arm(s), \
         {} reference arm(s), work captures: {}",
        spec.task,
        golden.claims.len(),
        file_spec.claims.len(),
        candidates.len(),
        by_role.get("reference").map_or(0, Vec::len),
        if captures.is_empty() {
            "none".to_owned()
        } else {
            captures.keys().copied().collect::<Vec<_>>().join("+")
        }
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

    // Consistency is measured over the ANSWER claims: it asks whether the same
    // artefact answers equivalently under equivalent prompts.
    readings.push(PanelReading::new(
        "metamorphic-consistency",
        metamorphic_consistency_reading(&candidates, &golden),
    ));

    let cand_diff = captures.get("candidate").map(WorkCapture::diff);
    readings.push(PanelReading::new(
        "filesystem",
        match (&cand_diff, captures.get("reference")) {
            (Some(c), Some(r)) => filesystem_reading(c, &r.diff()),
            (Some(_), None) => OracleReading::Abstained {
                why: "no --work-reference: a candidate's writes cannot be subtracted from a \
                      control arm's"
                    .into(),
            },
            (None, _) => OracleReading::Abstained {
                why: "no --work-candidate capture supplied".into(),
            },
        },
    ));

    readings.push(PanelReading::new(
        "written-content",
        match (&cand_diff, captures.get("candidate")) {
            (Some(d), Some(c)) => written_content_reading(&c.changed_contents(d), &file_spec),
            _ => OracleReading::Abstained {
                why: "no --work-candidate capture supplied".into(),
            },
        },
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
                "\nThe agent's work product was wrong in a way no boundary crossing would show. \
                 This is a lead: confirm against the turn dumps and the cell before acting."
            );
            if !captures.is_empty() {
                println!(
                    "NOTE: filesystem findings rest on work snapshots, which are HARNESS \
                     observations — nothing in the sealed bundle corroborates them."
                );
            }
            ExitCode::from(2)
        }
        IntegrityFinding::NoDefectFound { read, abstained } => {
            println!(
                "\nNO DEFECT FOUND — {read} oracle(s) read the work product, {abstained} \
                 abstained.\nThis is NOT a certificate of correctness: only these oracles, only \
                 the declared claims."
            );
            ExitCode::SUCCESS
        }
        IntegrityFinding::Inconclusive { abstained } => {
            println!(
                "\nINCONCLUSIVE — all {abstained} oracle(s) abstained; the panel formed no \
                 reading at all.\nThis must NOT be read as clean. Declare claims in the spec, \
                 supply a reference= arm, add candidate arms, or pass --work-* captures."
            );
            ExitCode::SUCCESS
        }
    }
}
