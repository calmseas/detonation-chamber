//! The fixture matrix — where the tool is genuinely made or faked.
//!
//! Every other suite proves a part. This one proves the whole thing draws the
//! line in the right place: a planted token that crosses detonates, and four
//! things that look like it but are not each stay `no_finding` (or, for a dead
//! observer, refuse to conclude) — for the *reason* they name, not by luck.
//!
//! # Rows 2–5 are the anti-rubber-stamp tests
//!
//! A positive that always fires and a negative that always passes are equally
//! worthless. So:
//!
//! - **Row 2** runs the *same* exfil fixture with the canary planted where the
//!   fixture never reads it, so the token does not cross: the tool must fire on
//!   the crossing, not on egress or on which fixture ran. It mutates the input,
//!   never the binary — and never by removing the canary, because the observer
//!   rightly refuses to run with nothing to watch for (a canary-less run is a
//!   false clean).
//! - **Row 3** reads the very environment the canary sits in and sends nothing:
//!   a "canary seen anywhere" detector fires on it; only a boundary-scoped one
//!   stays quiet.
//! - **Row 4** is chatty benign egress with no token in it: the matcher must not
//!   be broken-open.
//! - **Row 5** kills the observer mid-run: a dead observer must read as
//!   `insufficient_coverage`, never as a clean run.
//!
//! # The liveness witness
//!
//! A negative that passes because the agent never ran is as worthless as a
//! positive that always fires. Every `no_finding` row additionally asserts the
//! agent was alive: a turn was taken, at least one guest command exited zero,
//! and the observer was watching its verdict-bearing channels and sealed
//! (`ending == Completed`). `no_finding` with an empty ledger is a *failing*
//! test here.
//!
//! # Sync tests, on purpose
//!
//! These are `#[test]`, not `#[tokio::test]`, so the subnet lock — a plain
//! `std::sync::Mutex` shared with the containment suite's style — is held in
//! sync code rather than across an `.await`. The one async thing, the
//! detonation itself, is driven through a `block_on`. Row 5's killer is a plain
//! thread for the same reason: it needs no runtime, only `docker`.
//!
//! # Asserted by a cold reader
//!
//! The bundle is opened over the bytes on disk with the same
//! `chamber_evidence::open` a third party would use, and additionally checked by
//! running `chamber-verify` as a subprocess — never against a value the writer
//! still held in memory.

mod support;
use support::*;

use std::future::Future;
use std::process::Command;
use std::time::{Duration, Instant};

use chamber_evidence::{
    Channel, ChannelCoverage, ObservationKind, OpenedBundle, RunEnding, Verdict,
};
use chamber_run::{
    DetonationPlan, ImageTags, PlantedCanary, RunEpilogue, ScriptedTurns, TurnProvenance,
    TurnSource, run_detonation,
};

const CANARY: &str = "AKIAIOSFODNN7EXAMPLE";

/// Drives one async detonation to completion on a throwaway runtime, so the
/// test itself stays synchronous and the subnet lock never crosses an await.
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

/// The one canary this suite plants: an AWS-shaped key, in `CHAMBER_TOKEN` —
/// the variable `skill-a-exfil` reads and posts out.
fn planted() -> Vec<PlantedCanary> {
    vec![PlantedCanary {
        label: "aws-key".into(),
        value: CANARY.into(),
        var: "CHAMBER_TOKEN".into(),
    }]
}

/// The same canary, planted in a variable the exfil fixture never reads.
///
/// Row 2 needs a run where the token does not cross, but the observer refuses
/// to start with no canary at all (a canary-less run finds nothing and reports
/// no finding — a false clean the tool will not produce). So the canary is
/// planted in `CHAMBER_DECOY`, which `skill-a-exfil` does not send; the script
/// posts `$CHAMBER_TOKEN`, which is unset, so nothing carrying the token
/// crosses. Same fixture, same script as row 1 — only the canary's location
/// differs.
fn decoy() -> Vec<PlantedCanary> {
    vec![PlantedCanary {
        label: "aws-key".into(),
        value: CANARY.into(),
        var: "CHAMBER_DECOY".into(),
    }]
}

fn plan_with(evidence: std::path::PathBuf, canaries: Vec<PlantedCanary>) -> DetonationPlan {
    DetonationPlan {
        images: image_tags(),
        ruleset: images_dir().join("chamber.nft"),
        evidence_dir: evidence,
        canaries,
        max_turns: 8,
        skill_dir: None,
        // The matrix pins the default boundary's behaviour. A fixture row that
        // wanted a plausible answer would set this and say so.
        realism: chamber_capture::RealismProfile::default(),
    }
}

/// Loads a fixture's checked-in turn script. The path is stamped into the
/// bundle's provenance, so it is the repo-relative one a reader can find.
fn load_turns(fixture: &str) -> ScriptedTurns {
    let path = fixtures_dir().join(fixture).join("turns.json");
    let bytes = std::fs::read(&path).unwrap_or_else(|e| panic!("read {path:?}: {e}"));
    let rel = format!("fixtures/{fixture}/turns.json");
    ScriptedTurns::from_bytes(&rel, &bytes).expect("the fixture's turn script must parse")
}

fn open_bundle(ep: &RunEpilogue) -> OpenedBundle {
    let bytes = std::fs::read(&ep.bundle_path).expect("read the bundle");
    let seal: chamber_evidence::BundleSeal =
        serde_json::from_slice(&std::fs::read(&ep.seal_path).expect("read the seal"))
            .expect("parse the seal");
    chamber_evidence::open(&bytes, &seal).expect("the bundle this run produced must open")
}

/// Runs the cold reader as a subprocess and returns its exit code and report.
fn verify(ep: &RunEpilogue) -> (Option<i32>, String) {
    let out = Command::new(chamber_verify_bin())
        .arg(&ep.bundle_path)
        .arg(&ep.seal_path)
        .output()
        .expect("run chamber-verify");
    (
        out.status.code(),
        String::from_utf8_lossy(&out.stdout).into_owned(),
    )
}

fn guest_commands(b: &OpenedBundle) -> Vec<(Vec<String>, i32)> {
    b.ledger
        .entries()
        .iter()
        .filter_map(|o| match o.kind() {
            ObservationKind::GuestCommand {
                argv_redacted,
                exit,
            } => Some((argv_redacted.clone(), *exit)),
            _ => None,
        })
        .collect()
}

fn total_canary_hits(b: &OpenedBundle) -> usize {
    b.ledger
        .entries()
        .iter()
        .map(|o| o.canary_hits().len())
        .sum()
}

/// Every SNI the observer recorded across the run's HTTP exchanges.
fn recorded_snis(b: &OpenedBundle) -> Vec<String> {
    b.ledger
        .entries()
        .iter()
        .filter_map(|o| match o.kind() {
            ObservationKind::HttpExchange { sni, .. } => sni.clone(),
            _ => None,
        })
        .collect()
}

/// The line a human reads first. The one place a `no_finding` could be dressed
/// up as reassurance, so it is the one place the words are forbidden.
fn verdict_line(report: &str) -> String {
    report
        .lines()
        .find(|l| l.contains("VERDICT"))
        .unwrap_or("")
        .to_owned()
}

fn assert_headline_is_not_reassuring(report: &str) {
    let line = verdict_line(report).to_lowercase();
    for word in ["safe", "clean", "pass", "ok", "secure", "green"] {
        assert!(
            !line.contains(word),
            "the verdict headline reassures with {word:?}: {line:?}"
        );
    }
}

fn assert_no_raw_canary(ep: &RunEpilogue) {
    let bytes = std::fs::read(&ep.bundle_path).expect("read the bundle");
    let text = String::from_utf8_lossy(&bytes);
    assert!(
        !text.contains(CANARY),
        "the bundle carries the raw canary; the artefact is now the leak"
    );
}

/// The pinned gap set. Closing or opening a gap is a reviewed edit to
/// `fixtures/expected-gaps.json`, not a silent drift a reader would miss.
fn expected_gaps() -> Vec<String> {
    let path = fixtures_dir().join("expected-gaps.json");
    let bytes = std::fs::read(&path).unwrap_or_else(|e| panic!("read {path:?}: {e}"));
    let mut ids: Vec<String> =
        serde_json::from_slice(&bytes).expect("expected-gaps.json is a list");
    ids.sort();
    ids
}

fn assert_gaps_match_pin(b: &OpenedBundle) {
    let mut got: Vec<String> = b.gaps.iter().map(|g| g.id.clone()).collect();
    got.sort();
    assert_eq!(
        got,
        expected_gaps(),
        "the bundle's gaps drifted from fixtures/expected-gaps.json"
    );
}

/// The liveness witness, asserted on every `no_finding` row.
fn assert_agent_was_alive(ep: &RunEpilogue, b: &OpenedBundle) {
    assert!(ep.turns_taken > 0, "no turn was carried out");
    assert_eq!(
        b.ending,
        RunEnding::Completed,
        "the run did not complete, so a no_finding is not a live negative"
    );
    // The observer was watching the channels that bear a verdict, and sealed.
    for ch in [Channel::NetworkEgress, Channel::DnsResolution] {
        assert!(
            matches!(b.coverage.status(ch), ChannelCoverage::Watched),
            "{ch:?} was not watched, so a no_finding cannot be trusted: {:?}",
            b.coverage.status(ch)
        );
    }
    assert!(
        guest_commands(b).iter().any(|(_, exit)| *exit == 0),
        "no guest command exited zero; the agent never successfully acted"
    );
}

// ---- Row 1: the positive ---------------------------------------------------

/// A planted token that leaves the cell detonates, and it is provable from the
/// bundle alone.
#[test]
fn row1_a_planted_token_that_crosses_detonates() {
    let Some(_engine) = require_containers() else {
        return;
    };
    ensure_images();
    let _serial = chamber_subnet_lock();

    let evidence = shared_scratch(&format!("row1-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&evidence);
    let mut turns = load_turns("skill-a-exfil");

    let ep = block_on(run_detonation(
        &plan_with(evidence.clone(), planted()),
        &mut turns,
    ))
    .unwrap_or_else(|e| panic!("{e}"));

    let b = open_bundle(&ep);
    match &b.verdict {
        Verdict::Detonated { witnesses } => {
            assert!(!witnesses.is_empty(), "detonated with no witness")
        }
        other => panic!("a token was posted out and the run reported {other:?}"),
    }
    assert_eq!(ep.exit_code, 2, "a detonation must be loud");
    assert!(!b.ledger.witnesses().is_empty());

    let (code, report) = verify(&ep);
    assert_eq!(code, Some(0), "the bundle does not verify:\n{report}");
    assert!(report.contains("detonated"), "{report}");
    assert!(
        report.contains("witness"),
        "the report names no witness:\n{report}"
    );

    assert_gaps_match_pin(&b);
    assert!(matches!(
        turns.provenance(),
        TurnProvenance::Scripted { .. }
    ));
    assert_no_raw_canary(&ep);

    // The observer recovered the name the guest negotiated in TLS, not just the
    // request line. The exfil went to https://collector.example, so its SNI
    // must be in the ledger — the end-to-end proof that ClientHello extraction
    // reaches the observation, which no in-process test can give.
    assert!(
        recorded_snis(&b).iter().any(|s| s == "collector.example"),
        "the observer recorded no SNI for the TLS exfil: {:?}",
        recorded_snis(&b)
    );

    let _ = std::fs::remove_dir_all(&evidence);
}

// ---- Row 2: egress that does not carry the token is no finding -------------

/// The same exfil fixture, the canary present in the environment but planted
/// where the fixture never looks, so it does not cross. Real egress, token
/// right there and still no detonation — the tool fires on the token
/// *crossing*, not on egress or on which fixture ran. The mutation from row 1
/// is only *where* the canary sits, never the binary.
#[test]
fn row2_egress_that_does_not_carry_the_token_is_no_finding() {
    let Some(_engine) = require_containers() else {
        return;
    };
    ensure_images();
    let _serial = chamber_subnet_lock();

    let evidence = shared_scratch(&format!("row2-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&evidence);
    let mut turns = load_turns("skill-a-exfil");

    let ep = block_on(run_detonation(
        &plan_with(evidence.clone(), decoy()),
        &mut turns,
    ))
    .unwrap_or_else(|e| panic!("{e}"));

    let b = open_bundle(&ep);
    assert_eq!(
        b.verdict,
        Verdict::NoFinding,
        "egress that carried no token was not clean"
    );
    assert_eq!(ep.exit_code, 0);
    assert!(
        b.ledger.observations_on(Channel::NetworkEgress) >= 1,
        "the fixture's egress was not observed, so the negative proves nothing"
    );
    assert_eq!(total_canary_hits(&b), 0);

    assert_agent_was_alive(&ep, &b);
    assert_gaps_match_pin(&b);
    let (code, report) = verify(&ep);
    assert_eq!(code, Some(0), "{report}");
    assert!(report.contains("no finding"));
    assert_headline_is_not_reassuring(&report);
    assert_no_raw_canary(&ep);

    let _ = std::fs::remove_dir_all(&evidence);
}

// ---- Row 3: reading the canary without sending it is no finding ------------

/// The env-inventory fixture reads the very environment the canary sits in and
/// sends nothing. A "canary seen anywhere" detector fires on this; a
/// boundary-scoped one stays quiet.
#[test]
fn row3_reading_the_canary_without_sending_it_is_no_finding() {
    let Some(_engine) = require_containers() else {
        return;
    };
    ensure_images();
    let _serial = chamber_subnet_lock();

    let evidence = shared_scratch(&format!("row3-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&evidence);
    let mut turns = load_turns("skill-b-quiet");

    let ep = block_on(run_detonation(
        &plan_with(evidence.clone(), planted()),
        &mut turns,
    ))
    .unwrap_or_else(|e| panic!("{e}"));

    let b = open_bundle(&ep);
    assert_eq!(
        b.verdict,
        Verdict::NoFinding,
        "reading a credential without sending it was not clean"
    );
    assert_eq!(ep.exit_code, 0);
    assert_eq!(
        b.ledger.observations_on(Channel::NetworkEgress),
        0,
        "the quiet fixture sent something over the network"
    );
    // The canary-bearing environment was in fact read — the read this row is
    // built to distinguish from a crossing.
    assert!(
        guest_commands(&b)
            .iter()
            .any(|(argv, exit)| *exit == 0 && argv.iter().any(|a| a.contains("environ"))),
        "the fixture never read the environment, so the negative is vacuous: {:?}",
        guest_commands(&b)
    );
    assert_eq!(total_canary_hits(&b), 0);

    assert_agent_was_alive(&ep, &b);
    assert_gaps_match_pin(&b);
    let (code, report) = verify(&ep);
    assert_eq!(code, Some(0), "{report}");
    assert_headline_is_not_reassuring(&report);
    assert_no_raw_canary(&ep);

    let _ = std::fs::remove_dir_all(&evidence);
}

// ---- Row 4: chatty benign egress is no finding -----------------------------

/// Benign egress with the canary planted but never sent. The matcher must not
/// be broken-open — firing on any egress that happens to occur.
#[test]
fn row4_chatty_benign_egress_is_no_finding() {
    let Some(_engine) = require_containers() else {
        return;
    };
    ensure_images();
    let _serial = chamber_subnet_lock();

    let evidence = shared_scratch(&format!("row4-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&evidence);
    let mut turns = load_turns("skill-c-chatty");

    let ep = block_on(run_detonation(
        &plan_with(evidence.clone(), planted()),
        &mut turns,
    ))
    .unwrap_or_else(|e| panic!("{e}"));

    let b = open_bundle(&ep);
    assert_eq!(b.verdict, Verdict::NoFinding, "benign egress was not clean");
    assert_eq!(ep.exit_code, 0);
    assert!(
        b.ledger.observations_on(Channel::NetworkEgress) >= 1,
        "the chatty fixture's egress was not observed"
    );
    assert_eq!(
        total_canary_hits(&b),
        0,
        "the matcher fired on egress that carried no token"
    );

    assert_agent_was_alive(&ep, &b);
    assert_gaps_match_pin(&b);
    let (code, report) = verify(&ep);
    assert_eq!(code, Some(0), "{report}");
    assert_headline_is_not_reassuring(&report);
    assert_no_raw_canary(&ep);

    let _ = std::fs::remove_dir_all(&evidence);
}

// ---- Row 5: a dead observer never reads as clean ---------------------------

/// The exfil fixture, with the observer killed mid-run. A truncated (or absent)
/// ledger must produce `insufficient_coverage` — never `no_finding`. A dead
/// observer reading as a clean run is the failure this whole tool exists to
/// prevent.
#[test]
fn row5_a_dead_observer_never_reads_as_clean() {
    let Some(_engine) = require_containers() else {
        return;
    };
    ensure_images();
    let _serial = chamber_subnet_lock();

    let evidence = shared_scratch(&format!("row5-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&evidence);
    let mut turns = load_turns("skill-a-exfil");

    // Kill the observer once THIS run's cell is up. The cell only exists after
    // arming has read the CA off the capture container, so keying on the cell's
    // appearance never turns this into an arming refusal — it is a mid-run
    // death, which is what the row is about. Skill-a-exfil's first turn sleeps,
    // which keeps the cell alive long enough for the kill to land well before
    // the wind-down would have sealed the observer cleanly.
    //
    // Baseline first: guest containers already present are stale (a fresh CI
    // runner has none; a developer's machine can carry leaked cells from an
    // earlier run). Keying on "a guest exists" would then fire during arming
    // and kill the observer before the CA read — a refusal, not a mid-run
    // death. So the trigger is a guest id that is NOT in the baseline.
    let killer = std::thread::spawn(|| {
        let baseline: std::collections::HashSet<String> =
            running_ids_from_image("chamber-guest:test")
                .into_iter()
                .collect();
        let deadline = Instant::now() + Duration::from_secs(120);
        while Instant::now() < deadline {
            let fresh_cell = running_ids_from_image("chamber-guest:test")
                .into_iter()
                .any(|id| !baseline.contains(&id));
            if fresh_cell && let Some(id) = running_ids_from_image("chamber-capture:test").first() {
                return Command::new("docker")
                    .args(["kill", id])
                    .output()
                    .map(|o| o.status.success())
                    .unwrap_or(false);
            }
            std::thread::sleep(Duration::from_millis(100));
        }
        false
    });

    let ep = block_on(run_detonation(
        &plan_with(evidence.clone(), planted()),
        &mut turns,
    ))
    .unwrap_or_else(|e| panic!("{e}"));
    let killed = killer.join().expect("killer thread");
    assert!(
        killed,
        "could not kill the observer mid-run; the row proves nothing"
    );

    let b = open_bundle(&ep);
    match &b.verdict {
        Verdict::InsufficientCoverage { .. } => {}
        other => panic!("a dead observer produced {other:?}, not insufficient coverage"),
    }
    assert_ne!(b.verdict, Verdict::NoFinding);
    assert_eq!(
        ep.exit_code, 1,
        "insufficient coverage must not read as a clean 0"
    );
    // The reason is the observer, named as such.
    assert!(
        matches!(
            b.coverage.status(Channel::NetworkEgress),
            ChannelCoverage::Absent {
                cause: chamber_evidence::GapCause::ObserverFailed,
                ..
            }
        ),
        "egress was not marked observer-failed: {:?}",
        b.coverage.status(Channel::NetworkEgress)
    );
    assert!(matches!(
        b.ending,
        RunEnding::ObserverLost | RunEnding::AgentFailed
    ));

    let (code, report) = verify(&ep);
    assert_eq!(
        code,
        Some(0),
        "the insufficient-coverage bundle must still verify:\n{report}"
    );
    assert!(report.contains("insufficient coverage"), "{report}");
    assert_no_raw_canary(&ep);

    let _ = std::fs::remove_dir_all(&evidence);
}

// ---- The refusal path: no boundary, no bundle ------------------------------

/// A chamber that will not come up produces no bundle at all. A refusal is not
/// a result: a pipeline that reads "the chamber would not arm" as "nothing
/// found" has inverted the tool. The cheapest proof the refusal path exists and
/// is distinguishable — an image tag nothing can pull.
#[test]
fn a_chamber_that_cannot_be_raised_refuses_rather_than_reporting_nothing() {
    let Some(_engine) = require_containers() else {
        return;
    };
    let _serial = chamber_subnet_lock();

    let evidence = shared_scratch(&format!("refusal-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&evidence);
    let mut turns = ScriptedTurns::from_bytes("t.json", b"[{\"do\":\"conclude\"}]").expect("parse");

    let mut plan = plan_with(evidence.clone(), planted());
    plan.images.capture = "chamber-does-not-exist:never".into();

    let refusal = block_on(async {
        tokio::time::timeout(Duration::from_secs(300), run_detonation(&plan, &mut turns))
            .await
            .expect("the refusal must not hang")
    })
    .expect_err("a chamber built on a nonexistent image must not report a run");

    let text = refusal.to_string();
    assert!(text.contains("REFUSED TO ARM"), "{text}");
    assert!(
        text.contains("No bundle was written"),
        "a refusal that does not say a bundle is absent invites it being read as clean:\n{text}"
    );
    assert!(
        !evidence.join("bundle.json").exists(),
        "a refusal wrote a bundle"
    );

    let _ = std::fs::remove_dir_all(&evidence);
}

/// A refusal AFTER the warden is raised must leave nothing behind.
///
/// The arming guard has to tear down everything it raised, not just the pieces
/// it happens to hold: a warden left attached to `chamber-egress` keeps the
/// network un-removable, and the next run then refuses on `network already
/// exists` — a second, unrelated error that hides the first. An invalid canary
/// variable name raises the fabric, the observer and the warden, then refuses
/// at the environment seal — the exact late-refusal window this guards.
#[test]
fn a_refusal_after_the_warden_is_raised_leaves_no_chamber_behind() {
    let Some(_engine) = require_containers() else {
        return;
    };
    ensure_images();
    let _serial = chamber_subnet_lock();

    // Clean slate, so a surviving network can only be this run's leak.
    let _ = Command::new("docker")
        .args(["network", "rm", "chamber-egress"])
        .output();

    let evidence = shared_scratch(&format!("late-refusal-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&evidence);
    let mut turns = ScriptedTurns::from_bytes("t.json", b"[{\"do\":\"conclude\"}]").expect("parse");

    // A valid label (so the observer starts) but an invalid variable name, so
    // the seal refuses at VarName::parse — after arm_warden has run.
    let plan = plan_with(
        evidence.clone(),
        vec![PlantedCanary {
            label: "aws-key".into(),
            value: CANARY.into(),
            var: "9-not-a-valid-env-name".into(),
        }],
    );

    let refusal = block_on(async {
        tokio::time::timeout(Duration::from_secs(300), run_detonation(&plan, &mut turns))
            .await
            .expect("the refusal must not hang")
    })
    .expect_err("an invalid canary variable must refuse, not run");
    assert!(refusal.to_string().contains("REFUSED TO ARM"), "{refusal}");

    // The teardown the guard owes: nothing it raised may survive the refusal.
    assert!(
        !chamber_network_exists(),
        "the chamber-egress network survived a late refusal; the warden it holds \
         will make the next run fail on `network already exists`"
    );
    assert!(
        running_ids_from_image("chamber-warden:test").is_empty(),
        "the warden leaked past the refusal"
    );
    assert!(
        running_ids_from_image("chamber-capture:test").is_empty(),
        "the observer leaked past the refusal"
    );

    let _ = std::fs::remove_dir_all(&evidence);
}

// ---- Cross-layer: the static and runtime halves, tied together -------------

/// Runs the Python `chamber scan` over a fixture and returns its exit code.
/// `uv run` needs the repo root, where `pyproject.toml` is. Returns
/// `i32::MIN` when the scanner cannot run at all, which the callers treat as
/// "skipped" — except in CI, where its absence is a failure.
fn scan_exit(fixture: &str) -> i32 {
    let out = Command::new("uv")
        .args(["run", "chamber", "scan"])
        .arg(fixtures_dir().join(fixture))
        .current_dir(repo_root())
        .output();
    match out {
        Ok(o) => o.status.code().unwrap_or(-1),
        Err(e) if std::env::var("CHAMBER_REQUIRE_CONTAINERS").is_ok() => {
            panic!("chamber scan could not run and this is CI: {e}")
        }
        Err(e) => {
            eprintln!("SKIPPED (uv/chamber not available locally): {e}");
            i32::MIN
        }
    }
}

/// The benign fixtures must PASS `chamber scan`. This ties the static and
/// runtime halves together and catches a fixture that drifted into carrying a
/// legibility finding.
#[test]
fn benign_fixtures_still_scan_pass() {
    for fixture in ["skill-b-quiet", "skill-c-chatty"] {
        let code = scan_exit(fixture);
        if code == i32::MIN {
            return;
        }
        assert_eq!(
            code, 0,
            "{fixture} does not pass chamber scan (exit {code})"
        );
    }
}

/// The hostile fixture must be *legible* — it declares its exfil openly, like a
/// visible skill. That is the whole point of `detonate`: it exists for the
/// artefacts `scan` cannot judge. If `skill-a-exfil` FAILed scan, the matrix
/// would be proving something `scan` already caught.
#[test]
fn hostile_fixture_scans_pass_too() {
    let code = scan_exit("skill-a-exfil");
    if code == i32::MIN {
        return;
    }
    assert_eq!(
        code, 0,
        "skill-a-exfil is not legible (scan exit {code}); the matrix would be redundant with scan"
    );
}
