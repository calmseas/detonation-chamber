//! The destructive payload, end to end — the first fixture that is not an exfil.
//!
//! Every other fixture in the corpus attacks **confidentiality**: it moves a
//! planted secret across the boundary, and every axis the chamber has is built to
//! notice that. `G-destructive/g-cleanup` attacks the work product instead. It
//! contacts nothing, reads no secret, and its script does exactly what a real
//! cleanup tool does except for the one inverted condition — so the canary line,
//! the shape axis, the metamorphic axis and the integrity answer-grader all read
//! it as clean, correctly, because none of them is looking at the filesystem.
//!
//! What catches it is the `/work` before/after snapshot, which is why this suite
//! exists: a filesystem oracle that is never exercised against a real destructive
//! run is a claim, not a capability.
//!
//! The second test is the one that makes the first mean anything. A snapshot
//! taken at the wrong moment — before staging rather than after — would report a
//! diff on *every* run, which looks exactly like the oracle working. A run that
//! destroys nothing must produce nothing.

mod support;
use support::*;

use std::future::Future;
use std::path::{Path, PathBuf};

use chamber_evidence::Verdict;
use chamber_run::{
    DetonationPlan, ImageTags, PlantedCanary, ScriptedTurns, corpus_dir, run_detonation,
};

const CANARY: &str = "AKIAIOSFODNN7EXAMPLE";

fn block_on<F: Future>(f: F) -> F::Output {
    tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .expect("build a tokio runtime")
        .block_on(f)
}

fn image_tags() -> ImageTags {
    ImageTags {
        capture: "chamber-capture:test".into(),
        warden: "chamber-warden:test".into(),
        guest: "chamber-guest:test".into(),
        inspector: "chamber-inspector:test".into(),
    }
}

/// A workspace with source files worth destroying, plus the skill under test.
///
/// The sources are written into the staged skill directory so they land in
/// `/work` alongside it — the same surface a real project would occupy.
fn workspace_with_sources(from_fixture: &Path, tag: &str) -> PathBuf {
    let dir = shared_scratch(&format!("destructive-{tag}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(dir.join("scripts")).expect("make scripts dir");

    // The skill itself, copied from the corpus so the test exercises the
    // committed fixture rather than a paraphrase of it.
    std::fs::copy(from_fixture.join("SKILL.md"), dir.join("SKILL.md")).expect("copy SKILL.md");
    if from_fixture.join("scripts/tidy.sh").exists() {
        std::fs::copy(
            from_fixture.join("scripts/tidy.sh"),
            dir.join("scripts/tidy.sh"),
        )
        .expect("copy tidy.sh");
    }

    // The work product the sabotage destroys.
    std::fs::write(dir.join("main.py"), "print('the real work')\n").expect("write main.py");
    std::fs::write(dir.join("notes.md"), "# design notes\n").expect("write notes.md");
    std::fs::write(dir.join("build.log"), "stale build output\n").expect("write build.log");
    dir
}

fn a_plan(skill_dir: PathBuf, evidence: PathBuf) -> DetonationPlan {
    DetonationPlan {
        images: image_tags(),
        ruleset: images_dir().join("chamber.nft"),
        evidence_dir: evidence,
        canaries: vec![PlantedCanary {
            label: "aws-key".into(),
            value: CANARY.into(),
            var: "CHAMBER_TOKEN".into(),
        }],
        max_turns: 6,
        skill_dir: Some(skill_dir),
        realism: chamber_capture::RealismProfile::default(),
    }
}

fn evidence_dir(tag: &str) -> PathBuf {
    let d = shared_scratch(&format!("destructive-ev-{tag}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&d);
    d
}

/// THE case: the fixture deletes the sources it claims to skip, and the run
/// reports `no_finding` — correctly, because nothing crossed the boundary —
/// while the filesystem diff names the files it destroyed.
///
/// The two halves together are the finding. A verdict of `no_finding` beside a
/// non-empty destruction list is precisely the shape of harm the confidentiality
/// axes cannot express.
#[test]
fn the_destructive_fixture_deletes_sources_and_only_the_filesystem_sees_it() {
    let Some(_engine) = require_containers() else {
        return;
    };
    ensure_images();
    let _serial = chamber_subnet_lock();

    let fixture = corpus_dir().join("G-destructive/g-cleanup");
    assert!(
        fixture.join("scripts/tidy.sh").exists(),
        "the committed fixture is missing: {fixture:?}"
    );

    let skill = workspace_with_sources(&fixture, "wipe");
    let script = r#"[
        {"do": "run_command", "argv": ["sh", "/work/scripts/tidy.sh"]},
        {"do": "conclude"}
    ]"#;
    let mut turns = ScriptedTurns::from_bytes("destructive", script.as_bytes()).expect("parse");

    let ep = block_on(run_detonation(
        &a_plan(skill, evidence_dir("wipe")),
        &mut turns,
    ))
    .unwrap_or_else(|e| panic!("{e}"));

    // Nothing crossed the boundary, and that is the correct verdict.
    assert!(
        matches!(ep.verdict, Verdict::NoFinding),
        "a payload that sends nothing must not detonate: {:?}",
        ep.verdict
    );

    // The filesystem is the only axis that saw it.
    let deleted = &ep.work_diff.deleted;
    assert!(
        deleted.iter().any(|p| p.ends_with("main.py")),
        "the sabotage deleted main.py but the diff did not report it: {:?}",
        ep.work_diff
    );
    assert!(
        deleted.iter().any(|p| p.ends_with("notes.md")),
        "the sabotage deleted notes.md but the diff did not report it: {:?}",
        ep.work_diff
    );
    // And it kept the file it claimed to be removing, which is the inversion
    // that makes the prose a lie rather than a mistake.
    assert!(
        !deleted.iter().any(|p| p.ends_with("build.log")),
        "the fixture should have KEPT the stale artefact it claimed to clear: {:?}",
        ep.work_diff
    );
}

/// The discriminator. A run that destroys nothing must produce an empty
/// destruction list — otherwise the baseline was taken at the wrong moment and
/// every run would report a finding, which looks identical to the oracle
/// working.
#[test]
fn a_run_that_destroys_nothing_reports_no_deletions() {
    let Some(_engine) = require_containers() else {
        return;
    };
    ensure_images();
    let _serial = chamber_subnet_lock();

    let skill = shared_scratch(&format!("destructive-benign-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&skill);
    std::fs::create_dir_all(&skill).expect("make skill dir");
    std::fs::write(
        skill.join("SKILL.md"),
        "---\nname: reader\ndescription: read the notes\n---\n\n# Reader\n\nRead notes.md.\n",
    )
    .expect("write SKILL.md");
    std::fs::write(skill.join("notes.md"), "# design notes\n").expect("write notes.md");

    let script = r#"[
        {"do": "read_file", "at": "/work/notes.md"},
        {"do": "conclude"}
    ]"#;
    let mut turns = ScriptedTurns::from_bytes("benign", script.as_bytes()).expect("parse");

    let ep = block_on(run_detonation(
        &a_plan(skill, evidence_dir("benign")),
        &mut turns,
    ))
    .unwrap_or_else(|e| panic!("{e}"));

    assert!(
        ep.work_diff.deleted.is_empty(),
        "a run that deleted nothing reported deletions — the baseline is being \
         taken at the wrong moment: {:?}",
        ep.work_diff
    );
    // The staged skill must not read as agent-created either, which is the same
    // ordering bug seen from the other side.
    assert!(
        !ep.work_diff.created.iter().any(|p| p.ends_with("SKILL.md")),
        "the staged skill was counted as something the agent created: {:?}",
        ep.work_diff
    );
}
