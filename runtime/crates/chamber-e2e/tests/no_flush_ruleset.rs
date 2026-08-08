//! The ban on nftables' unscoped reset — in the code that configures the
//! chamber, not in the code that attacks it.
//!
//! Resetting *everything* destroys Docker's own `ip nat` table — the one that
//! DNATs `127.0.0.11` to the embedded resolver — and kills DNS for the entire
//! network namespace. The live ruleset says so itself: *"table ip nat is
//! managed by iptables-nft, do not touch!"*. The chamber's reset must always be
//! the scoped pair, `table inet chamber; delete table inet chamber;`.
//!
//! This is a source scan rather than a behavioural test because the damage is
//! not reliably visible at runtime: DNS breaks for everything sharing the
//! namespace, which reads as a flaky network rather than as a rule someone
//! wrote. By the time it is diagnosed the run is gone.
//!
//! # Two carve-outs, both load-bearing
//!
//! The obvious form of this test — fail on the text anywhere under `runtime/` —
//! is what the plan asked for, and it cannot work, because the plan also
//! requires the adversary probe to *attempt* the unscoped reset. That is probe
//! row 8: the cell tries to destroy the ruleset containing it and must be
//! refused, which is a far stronger claim than "we chose not to". A scan that
//! bans the attempt bans the test for the property.
//!
//! So:
//!
//! 1. **`images/probe/` is exempt.** It is the designated adversary. Its whole
//!    purpose is attempting things this tree forbids, and a probe that cannot
//!    attempt them proves nothing. This is the only exempt path, it is named
//!    here rather than in a list that grows, and
//!    [`the_exemption_covers_only_the_probe`] pins it.
//!
//! 2. **Comment lines are skipped.** Prose warning against the command — like
//!    the note in `chamber-isolation`'s crate docs — is the opposite of the
//!    hazard. Only lines whose first non-space characters are not a comment
//!    marker are scanned, so `nft flush ruleset # tidy up` is still caught.
//!
//! # Why the search text is assembled rather than written out
//!
//! This file is inside the tree it scans, and the scan reads code lines. Naming
//! the banned command in code here would make the test find itself.

use std::path::{Path, PathBuf};

/// The one exempt path, relative to `runtime/`.
const ADVERSARY: &str = "images/probe";

/// Files worth scanning. The ruleset is `.nft`, the warden drives it from Rust
/// and from shell, and an image can carry it in a `RUN` line.
fn is_scannable(path: &Path) -> bool {
    let named_dockerfile = path
        .file_name()
        .and_then(|n| n.to_str())
        .is_some_and(|n| n.starts_with("Dockerfile"));

    named_dockerfile
        || matches!(
            path.extension().and_then(|e| e.to_str()),
            Some("rs" | "nft" | "sh" | "toml" | "yml" | "yaml")
        )
}

/// True for a line that is entirely a comment.
///
/// Deliberately anchored at the start: a banned command with a comment *after*
/// it is still executable and is still caught.
fn is_comment(line: &str) -> bool {
    let t = line.trim_start();
    t.starts_with("//") || t.starts_with('#') || t.starts_with('*')
}

fn collect(dir: &Path, out: &mut Vec<PathBuf>) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        let name = entry.file_name();
        let name = name.to_string_lossy();
        // Build output is not source, and it is enormous.
        if name == "target" || name == ".git" {
            continue;
        }
        if path.is_dir() {
            collect(&path, out);
        } else if is_scannable(&path) {
            out.push(path);
        }
    }
}

fn runtime_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .expect("crates/<pkg> sits two levels below runtime/")
        .to_path_buf()
}

/// Assembled, not written: see the module note.
fn banned_text() -> String {
    format!("{} {}", "flush", "ruleset")
}

/// Every executable occurrence, outside the adversary image.
fn offenders(root: &Path) -> Vec<String> {
    let mut files = Vec::new();
    collect(root, &mut files);

    assert!(
        files.len() > 5,
        "scanned only {} files under {} — the walk is broken, and a broken walk \
         passes this test unconditionally",
        files.len(),
        root.display()
    );

    let banned = banned_text();
    let exempt = root.join(ADVERSARY);
    let mut found = Vec::new();

    for file in &files {
        if file.starts_with(&exempt) {
            continue;
        }
        let Ok(text) = std::fs::read_to_string(file) else {
            continue;
        };
        for (n, line) in text.lines().enumerate() {
            if !is_comment(line) && line.contains(&banned) {
                found.push(format!("{}:{}: {}", file.display(), n + 1, line.trim()));
            }
        }
    }
    found
}

#[test]
fn the_unscoped_nftables_reset_is_never_issued_by_the_chamber() {
    let found = offenders(&runtime_root());
    assert!(
        found.is_empty(),
        "the unscoped nftables reset destroys Docker's nat table and kills DNS \
         for the whole namespace. Use the scoped pair instead:\n  table inet \
         chamber\n  delete table inet chamber\n\nFound at:\n{}",
        found.join("\n")
    );
}

/// The scan must be able to fail. A matcher that never matches passes the test
/// above on any tree at all — the same vacuous green the containment suite
/// exists to avoid.
#[test]
fn the_scan_detects_the_banned_text_in_an_executable_line() {
    let banned = banned_text();
    let sample = format!("nft {banned}");
    assert!(!is_comment(&sample) && sample.contains(&banned));
}

/// A trailing comment does not launder it.
#[test]
fn a_banned_command_with_a_comment_after_it_is_still_caught() {
    let line = format!("  nft {} # just tidying up", banned_text());
    assert!(!is_comment(&line), "a code line was mistaken for a comment");
}

/// Prose warning against the command is not the hazard.
#[test]
fn prose_naming_the_command_is_not_an_offence() {
    for line in [
        format!("//! The reset is scoped, never `nft {}`.", banned_text()),
        format!("# NEVER {}: it destroys Docker's nat table", banned_text()),
    ] {
        assert!(is_comment(&line), "comment not recognised: {line}");
    }
}

/// The exemption is one directory wide.
///
/// It exists so the adversary can attempt what the chamber forbids. If it ever
/// silently widened — to `images/`, say — the warden's own ruleset would stop
/// being scanned and this suite would go quiet about the thing it is for.
#[test]
fn the_exemption_covers_only_the_probe() {
    let root = runtime_root();
    let exempt = root.join(ADVERSARY);

    assert!(
        exempt.is_dir(),
        "the exempt path {exempt:?} does not exist; the exemption is stale and \
         is now silently protecting nothing"
    );
    for guarded in ["images/warden", "crates/chamber-isolation/src"] {
        assert!(
            !root.join(guarded).starts_with(&exempt),
            "{guarded} must remain scanned"
        );
    }
}
