//! `chamber-verify` exercised the way it is actually used: as a subprocess,
//! over bytes on disk.
//!
//! The fixture matrix verifies bundles by *running this binary*, never by
//! asking the writer what it thinks it wrote. That distinction is the whole
//! reason the binary exists — an in-process assertion against the value still
//! held in memory would pass even if nothing were ever serialised correctly,
//! and the artefact's entire promise is that a third party with two files and
//! no trust in the producer can reach the same conclusion.
//!
//! So these tests spawn it, and assert on its exit code and its stdout.

use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use chamber_evidence::{
    CanaryHit, CapturedBody, Channel, ChannelCoverage, CoverageMap, HitEncoding, HitField,
    ObservationKind, RunEnding, RunLog, RunSecret, SealedBundle, seal_run,
};

/// Exit codes. These say whether the artefact VERIFIED, not what the run found.
const VERIFIED: i32 = 0;
const REFUSED: i32 = 1;
const UNUSABLE: i32 = 2;

fn scratch(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("chamber-verify-{}-{}", std::process::id(), name));
    std::fs::create_dir_all(&dir).expect("scratch dir");
    dir
}

fn exchange(authority: &str) -> ObservationKind {
    ObservationKind::HttpExchange {
        method: "POST".into(),
        authority: authority.into(),
        sni: Some(authority.into()),
        target: "/ingest".into(),
        headers: vec![("content-type".into(), "application/json".into())],
        body: CapturedBody::Whole {
            bytes: b"{}".to_vec(),
        },
    }
}

fn hit() -> CanaryHit {
    CanaryHit {
        label: "aws-key".into(),
        field: HitField::Body,
        encoding: HitEncoding::Raw,
        offset: 0,
    }
}

/// Writes a bundle and its seal, returning both paths.
fn write_bundle(
    dir: &Path,
    bundle: &SealedBundle,
    seal: &chamber_evidence::BundleSeal,
) -> (PathBuf, PathBuf) {
    let bundle_path = dir.join("bundle.json");
    let seal_path = dir.join("bundle.sig");
    std::fs::write(&bundle_path, bundle.to_canonical_bytes()).expect("write bundle");
    std::fs::write(
        &seal_path,
        serde_json::to_vec(seal).expect("serialise seal"),
    )
    .expect("write seal");
    (bundle_path, seal_path)
}

fn run_verify(bundle: &Path, seal: &Path) -> Output {
    Command::new(env!("CARGO_BIN_EXE_chamber-verify"))
        .arg(bundle)
        .arg(seal)
        .output()
        .expect("run chamber-verify")
}

fn stdout_of(out: &Output) -> String {
    String::from_utf8_lossy(&out.stdout).into_owned()
}

/// Collapses runs of whitespace so a phrase can be asserted regardless of where
/// the report wraps it. The claim under test is what the report *says*, not the
/// column it happens to break at.
fn unwrapped(text: &str) -> String {
    text.split_whitespace().collect::<Vec<_>>().join(" ")
}

#[test]
fn a_detonated_bundle_verifies_and_names_its_witnesses() {
    let dir = scratch("detonated");
    let mut log = RunLog::open();
    log.note(
        10,
        Channel::NetworkEgress,
        exchange("collector.example"),
        vec![hit()],
    );
    let (bundle, seal) = seal_run(
        log,
        RunEnding::Completed,
        CoverageMap::build(|_| ChannelCoverage::Watched),
        vec![],
        RunSecret::mint().unwrap(),
    );
    let (b, s) = write_bundle(&dir, &bundle, &seal);

    let out = run_verify(&b, &s);
    let text = stdout_of(&out);
    assert_eq!(out.status.code(), Some(VERIFIED), "stdout:\n{text}");
    assert!(text.contains("detonated"), "{text}");
    assert!(text.contains("witness"), "{text}");
}

/// The output must not be readable as a clearance, because there is no verdict
/// that would be one.
#[test]
fn a_no_finding_bundle_never_reads_as_a_clearance() {
    let dir = scratch("no-finding");
    let mut log = RunLog::open();
    log.note(10, Channel::NetworkEgress, exchange("docs.example"), vec![]);
    let (bundle, seal) = seal_run(
        log,
        RunEnding::Completed,
        CoverageMap::build(|_| ChannelCoverage::Watched),
        chamber_evidence::gaps::slice0(),
        RunSecret::mint().unwrap(),
    );
    let (b, s) = write_bundle(&dir, &bundle, &seal);

    let out = run_verify(&b, &s);
    let text = stdout_of(&out);
    assert_eq!(out.status.code(), Some(VERIFIED), "stdout:\n{text}");

    // It says what it found...
    assert!(text.contains("no finding"), "{text}");
    // ...and immediately says what that does NOT mean.
    assert!(
        unwrapped(&text).contains("not a statement about the artefact's safety"),
        "a no-finding report that omits the disclaimer reads as a clearance:\n{text}"
    );
    // ...and discloses the permanent limits of the build that produced it.
    assert!(
        text.contains("gap.ledger-integrity"),
        "declared limits were not reported:\n{text}"
    );

    // Reassuring vocabulary, in the words the matrix bans. Checked
    // case-insensitively and on whole words, so "not watched" and
    // "insufficient" are unaffected.
    let lowered = text.to_lowercase();
    for banned in ["safe", "clean", "secure", "green", "passed"] {
        assert!(
            !lowered
                .split(|c: char| !c.is_alphanumeric())
                .any(|w| w == banned),
            "the report uses the word {banned:?}, which reads as a clearance:\n{text}"
        );
    }
}

/// The arm that stops a dead observer reading as a clean run.
#[test]
fn an_unwatched_channel_reports_that_no_conclusion_was_reached() {
    let dir = scratch("insufficient");
    let mut log = RunLog::open();
    log.note(10, Channel::GuestCommand, exchange("na"), vec![]);

    let (bundle, seal) = seal_run(
        log,
        RunEnding::ObserverLost,
        // The channel that could have carried a finding was not watched.
        CoverageMap::build(|c| {
            if c == Channel::NetworkEgress {
                ChannelCoverage::Absent {
                    cause: chamber_evidence::GapCause::ObserverFailed,
                    detail: "the capture process stopped mid-run".into(),
                }
            } else {
                ChannelCoverage::Watched
            }
        }),
        vec![],
        RunSecret::mint().unwrap(),
    );
    let (b, s) = write_bundle(&dir, &bundle, &seal);

    let out = run_verify(&b, &s);
    let text = stdout_of(&out);
    assert_eq!(out.status.code(), Some(VERIFIED), "stdout:\n{text}");
    assert!(text.contains("insufficient coverage"), "{text}");
    assert!(
        unwrapped(&text).contains("reached NO conclusion"),
        "an unwatched channel must not read as a finding-free run:\n{text}"
    );
    assert!(
        !text.contains("no finding"),
        "insufficient coverage was reported as no finding:\n{text}"
    );
}

/// A single flipped byte must be refused, not reported.
#[test]
fn a_tampered_bundle_is_refused() {
    let dir = scratch("tampered");
    let mut log = RunLog::open();
    log.note(
        10,
        Channel::NetworkEgress,
        exchange("collector.example"),
        vec![hit()],
    );
    let (bundle, seal) = seal_run(
        log,
        RunEnding::Completed,
        CoverageMap::build(|_| ChannelCoverage::Watched),
        vec![],
        RunSecret::mint().unwrap(),
    );
    let (b, s) = write_bundle(&dir, &bundle, &seal);

    let mut bytes = std::fs::read(&b).unwrap();
    let target = bytes
        .windows(b"collector.example".len())
        .position(|w| w == b"collector.example")
        .expect("the authority is in the bundle");
    bytes[target] = b'C';
    std::fs::write(&b, &bytes).unwrap();

    let out = run_verify(&b, &s);
    assert_eq!(
        out.status.code(),
        Some(REFUSED),
        "a tampered bundle was accepted; stdout:\n{}",
        stdout_of(&out)
    );
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(err.contains("REFUSED"), "{err}");
    assert!(
        err.contains("not evidence of anything"),
        "a refusal that does not say the bundle proves nothing invites it \
         being read as a clean result:\n{err}"
    );
}

/// Semantically identical, not the bytes that were signed.
#[test]
fn a_reserialised_bundle_is_refused_as_non_canonical() {
    let dir = scratch("noncanonical");
    let mut log = RunLog::open();
    log.note(10, Channel::NetworkEgress, exchange("docs.example"), vec![]);
    let (bundle, seal) = seal_run(
        log,
        RunEnding::Completed,
        CoverageMap::build(|_| ChannelCoverage::Watched),
        vec![],
        RunSecret::mint().unwrap(),
    );
    let (b, s) = write_bundle(&dir, &bundle, &seal);

    // Pretty-printing changes nothing semantically and everything cryptographically.
    let value: serde_json::Value = serde_json::from_slice(&std::fs::read(&b).unwrap()).unwrap();
    std::fs::write(&b, serde_json::to_vec_pretty(&value).unwrap()).unwrap();

    let out = run_verify(&b, &s);
    assert_eq!(out.status.code(), Some(REFUSED), "{}", stdout_of(&out));
}

/// "I could not read the file" must never look like "I checked it and refused
/// it". One is a broken invocation; the other is a tamper signal.
#[test]
fn an_unreadable_file_is_unusable_not_refused() {
    let dir = scratch("missing");
    let out = run_verify(&dir.join("nope.json"), &dir.join("nope.sig"));
    assert_eq!(out.status.code(), Some(UNUSABLE));
    assert_ne!(out.status.code(), Some(REFUSED));
}

#[test]
fn wrong_arguments_are_unusable() {
    let out = Command::new(env!("CARGO_BIN_EXE_chamber-verify"))
        .output()
        .expect("run chamber-verify");
    assert_eq!(out.status.code(), Some(UNUSABLE));
    assert!(String::from_utf8_lossy(&out.stderr).contains("usage:"));
}
