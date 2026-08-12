//! The `/work` snapshot, end to end through the real guest image.
//!
//! The unit tests in `chamber-run::worksnapshot` prove that two listings subtract
//! correctly, against a fake cell. They cannot prove the thing that actually
//! breaks: whether the guest's userland produces a listing in the shape the parser
//! expects. `sha256sum` is busybox's on a minimal image and coreutils' elsewhere,
//! `find -exec … +` is not universal, and a `head -c` that is absent would return
//! empty content that reads as an unremarkable file rather than as a broken tool.
//!
//! So this runs the **exact** command strings the [`CellInspect`] impl builds —
//! [`digest_tree_script`] and [`read_file_script`], not reimplementations of them —
//! inside `chamber-guest:test`, and asserts the real output parses and diffs.
//!
//! # What this does not cover
//!
//! The `AgentCell::exec` plumbing. These run through `docker exec` directly rather
//! than standing up a warden and a sealed environment, because the risk being
//! retired here is the guest's userland, not the cell's construction — and
//! `AgentCell::exec` is already exercised against a live cell by `containment.rs`.
//! A failure of the plumbing would show there, not here.

mod support;
use support::*;

use std::path::Path;
use std::process::Command;
use std::sync::{Mutex, OnceLock};

use chamber_isolation::build_image;

use chamber_run::{WorkSnapshot, digest_tree_script, read_file_script};

const WORK: &str = "/work";

/// Builds only the guest image, once per test binary.
///
/// Not `ensure_images()`: this suite never raises a chamber, so the warden,
/// inspector and the slow capture image are cost with no coverage. Serialised for
/// the same reason `ensure_images` is — two `docker build`s on one tag interleave
/// into something no one can diagnose.
fn ensure_guest_image() {
    static BUILT: OnceLock<Mutex<bool>> = OnceLock::new();
    let lock = BUILT.get_or_init(|| Mutex::new(false));
    let mut done = lock.lock().unwrap_or_else(|e| e.into_inner());
    if *done {
        return;
    }
    let dir = images_dir().join("guest");
    build_image(&dir, "chamber-guest:test")
        .unwrap_or_else(|e| panic!("could not build the guest image from {dir:?}: {e}"));
    *done = true;
}

/// Runs a script in a throwaway container from the guest image, returning stdout.
///
/// `--rm` and no network: this container exists to hold a filesystem for a few
/// milliseconds and must not be able to reach anything.
fn in_guest(script: &str) -> String {
    let out = Command::new("docker")
        .args([
            "run",
            "--rm",
            "--network",
            "none",
            "chamber-guest:test",
            "sh",
            "-c",
            script,
        ])
        .output()
        .expect("run a throwaway guest container");
    assert!(
        out.status.success(),
        "the guest could not run the script:\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    String::from_utf8_lossy(&out.stdout).into_owned()
}

/// Stages a tree, snapshots it, mutates it, snapshots again — all in one guest
/// invocation, because a `--rm` container does not survive between calls. The two
/// listings are separated by a sentinel the test splits on.
fn before_and_after(setup: &str, mutate: &str) -> (WorkSnapshot, WorkSnapshot) {
    const SENTINEL: &str = "---SNAPSHOT-BREAK---";
    let digest = digest_tree_script(Path::new(WORK));
    let script = format!(
        "mkdir -p {WORK} && {setup} && {digest} && echo '{SENTINEL}' && {mutate} && {digest}"
    );
    let out = in_guest(&script);
    let (before, after) = out
        .split_once(SENTINEL)
        .expect("both listings are present, separated by the sentinel");
    (WorkSnapshot::parse(before), WorkSnapshot::parse(after))
}

/// The listing the real guest produces must parse — if `sha256sum`'s output shape
/// differs from what the parser expects, every snapshot silently comes back empty
/// and every filesystem finding is a false clean.
#[test]
fn the_guest_listing_parses_into_a_snapshot() {
    if require_containers().is_none() {
        return;
    }
    ensure_guest_image();

    let listing = in_guest(&format!(
        "mkdir -p {WORK}/scripts && printf 'a' > {WORK}/SKILL.md && \
         printf 'b' > {WORK}/scripts/run.sh && {}",
        digest_tree_script(Path::new(WORK))
    ));
    let snap = WorkSnapshot::parse(&listing);
    assert_eq!(
        snap.len(),
        2,
        "the guest's listing did not parse into two files — raw output was:\n{listing}"
    );
}

/// THE integrity case, proven against the real image: same path, different
/// content. A listing that reported only names would call this untouched.
#[test]
fn a_rewritten_file_is_seen_as_modified_in_the_real_guest() {
    if require_containers().is_none() {
        return;
    }
    ensure_guest_image();

    let (before, after) = before_and_after(
        &format!("printf 'verify_ssl: true' > {WORK}/config.yml"),
        &format!("printf 'verify_ssl: false' > {WORK}/config.yml"),
    );
    let diff = before.diff(&after);
    assert_eq!(
        diff.modified,
        ["./config.yml"],
        "a rewritten file must read as modified; diff was {diff:?}"
    );
    assert!(diff.created.is_empty() && diff.deleted.is_empty());
}

/// The destructive case: the artefact removed something that was there.
#[test]
fn a_deleted_file_is_seen_as_deleted_in_the_real_guest() {
    if require_containers().is_none() {
        return;
    }
    ensure_guest_image();

    let (before, after) = before_and_after(
        &format!("printf 'rows' > {WORK}/data.csv && printf 'x' > {WORK}/keep.md"),
        &format!("rm {WORK}/data.csv"),
    );
    let diff = before.diff(&after);
    assert_eq!(diff.deleted, ["./data.csv"]);
    assert!(diff.modified.is_empty(), "keep.md must not read as changed");
}

/// The discriminator: a guest where nothing happened must diff to empty, or every
/// run reports a filesystem finding and the oracle is worthless.
#[test]
fn an_untouched_guest_tree_diffs_to_empty() {
    if require_containers().is_none() {
        return;
    }
    ensure_guest_image();

    let (before, after) = before_and_after(
        &format!("printf 'a' > {WORK}/SKILL.md && printf 'b' > {WORK}/notes.md"),
        "true",
    );
    let diff = before.diff(&after);
    assert!(
        diff.is_empty(),
        "an untouched tree produced a diff: {diff:?}"
    );
}

/// Content read-back must return the bytes, bounded. An absent `head` would give
/// empty output that reads as an unremarkable file rather than a broken tool,
/// which is why this asserts on the content rather than on the exit status.
#[test]
fn a_changed_files_content_is_readable_from_the_real_guest() {
    if require_containers().is_none() {
        return;
    }
    ensure_guest_image();

    let content = in_guest(&format!(
        "mkdir -p {WORK} && printf 'endpoint: https://evil.example/ingest' > {WORK}/config.yml && {}",
        read_file_script(Path::new("/work/config.yml"))
    ));
    assert!(
        content.contains("evil.example"),
        "the poisoned value did not come back from the guest: {content:?}"
    );
}
