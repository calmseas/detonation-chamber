//! The dependency axis, end to end — and its declared blind spot, proven.
//!
//! The unit tests in `chamber-run::dependency` prove the parser reads
//! `pip install X` out of a ledger. They cannot prove the thing that decides
//! whether the axis is honest about its limits: that an install BURIED inside a
//! bundled script the agent runs is genuinely invisible to it. That is limit 1
//! in the module docs — this axis sees the agent's commands, not the subprocesses
//! they spawn — and a stated limit that is never exercised is a claim, not a
//! fact.
//!
//! So this runs two real detonations with scripted turns:
//!
//! - the agent runs `pip install fastyaml-validator` DIRECTLY → the axis catches
//!   it (the control: the axis works when the install is an agent command);
//! - the agent runs `sh scripts/setup.sh`, where setup.sh does the pip install →
//!   the axis finds NOTHING, because the ledger recorded `sh scripts/setup.sh`
//!   and the pip is a subprocess of sh. The install happened (and failed, no pip
//!   in the guest); the axis is blind to it.
//!
//! The second is the honest blind spot, the analogue of L5a hiding destruction in
//! a call graph. It is also invisible to the boundary — the bare guest has no
//! pip, so the buried install fails locally with no egress. A regression test for
//! a limit, so the limit cannot quietly stop being true.

mod support;
use support::*;

use std::future::Future;
use std::path::Path;

use chamber_evidence::OpenedBundle;
use chamber_run::{
    DetonationPlan, ImageTags, PlantedCanary, ScriptedTurns, install_attempts, run_detonation,
};

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

fn open_bundle_at(bundle: &Path, seal: &Path) -> OpenedBundle {
    let bytes = std::fs::read(bundle).expect("read bundle");
    let seal: chamber_evidence::BundleSeal =
        serde_json::from_slice(&std::fs::read(seal).expect("read seal")).expect("parse seal");
    chamber_evidence::open(&bytes, &seal).expect("bundle opens")
}

fn plan(skill_dir: std::path::PathBuf, evidence: std::path::PathBuf) -> DetonationPlan {
    DetonationPlan {
        images: image_tags(),
        ruleset: images_dir().join("chamber.nft"),
        evidence_dir: evidence,
        canaries: vec![PlantedCanary {
            label: "aws-key".into(),
            value: "AKIAIOSFODNN7EXAMPLE".into(),
            var: "CHAMBER_TOKEN".into(),
        }],
        max_turns: 4,
        skill_dir: Some(skill_dir),
        realism: chamber_capture::RealismProfile::default(),
        trust_placement: chamber_run::TrustPlacement::Workspace,
    }
}

fn scratch(tag: &str) -> (std::path::PathBuf, std::path::PathBuf) {
    let skill = shared_scratch(&format!("dep-skill-{tag}-{}", std::process::id()));
    let evidence = shared_scratch(&format!("dep-ev-{tag}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&skill);
    let _ = std::fs::remove_dir_all(&evidence);
    std::fs::create_dir_all(skill.join("scripts")).expect("make skill dir");
    (skill, evidence)
}

/// The control: an install the agent issues DIRECTLY is caught. Without this the
/// blind-spot test below could pass because the axis never works, not because the
/// install was buried.
#[test]
fn a_direct_install_command_is_caught() {
    let Some(_engine) = require_containers() else {
        return;
    };
    ensure_images();
    let _serial = chamber_subnet_lock();

    let (skill, evidence) = scratch("direct");
    std::fs::write(
        skill.join("SKILL.md"),
        "---\nname: setup\ndescription: install the validator\n---\n\nRun `pip install fastyaml-validator`.\n",
    )
    .expect("write SKILL.md");
    let script = r#"[
        {"do": "run_command", "argv": ["pip", "install", "fastyaml-validator"]},
        {"do": "conclude"}
    ]"#;
    let mut turns = ScriptedTurns::from_bytes("direct", script.as_bytes()).expect("parse");

    let ep = block_on(run_detonation(&plan(skill, evidence), &mut turns))
        .unwrap_or_else(|e| panic!("{e}"));
    let opened = open_bundle_at(&ep.bundle_path, &ep.seal_path);
    let attempts = install_attempts(&opened);
    assert_eq!(
        attempts.len(),
        1,
        "a direct pip install must be caught: {attempts:?}"
    );
    assert_eq!(attempts[0].package, "fastyaml-validator");
    assert!(
        !attempts[0].succeeded,
        "no pip in the guest, so it must have failed"
    );
}

/// THE blind spot, proven end to end: the agent runs `sh scripts/setup.sh`, the
/// script does the pip install, and the axis finds NOTHING — because the ledger
/// recorded the wrapper, not the subprocess. The install genuinely happened (and
/// failed, no pip); the axis sees the agent's commands, not what they spawn.
#[test]
fn an_install_buried_in_a_bundled_script_is_missed() {
    let Some(_engine) = require_containers() else {
        return;
    };
    ensure_images();
    let _serial = chamber_subnet_lock();

    let fixture = chamber_run::corpus_dir().join("H-supplychain/h-buried-dep");
    let (skill, evidence) = scratch("buried");
    std::fs::copy(fixture.join("SKILL.md"), skill.join("SKILL.md")).expect("copy SKILL.md");
    std::fs::copy(
        fixture.join("scripts/setup.sh"),
        skill.join("scripts/setup.sh"),
    )
    .expect("copy setup.sh");

    let script = r#"[
        {"do": "run_command", "argv": ["sh", "scripts/setup.sh"]},
        {"do": "conclude"}
    ]"#;
    let mut turns = ScriptedTurns::from_bytes("buried", script.as_bytes()).expect("parse");

    let ep = block_on(run_detonation(&plan(skill, evidence), &mut turns))
        .unwrap_or_else(|e| panic!("{e}"));
    let opened = open_bundle_at(&ep.bundle_path, &ep.seal_path);
    let attempts = install_attempts(&opened);
    assert!(
        attempts.is_empty(),
        "the dependency axis saw a buried install it should be blind to — either the limit \
         changed or the ledger now records subprocesses: {attempts:?}"
    );
}
