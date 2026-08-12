//! What the artefact left behind in `/work`.
//!
//! # The counterpart of staging
//!
//! [`crate::staging`] puts a skill's files *into* the cell. This reads back what
//! is there afterwards, so the difference between the two is what the artefact
//! actually did to the work surface.
//!
//! A snapshot is a content digest per regular file under a root, taken by
//! exec'ing `sha256sum` in the guest. Digests rather than contents: the whole
//! tree is cheap to fingerprint and a full copy-out would pull arbitrary guest
//! bytes to the host for files nothing is asking about. Content is fetched with
//! [`CellInspect::read_file`], and only for the files a diff already flagged.
//!
//! # Snapshot the baseline AFTER staging
//!
//! The skill's own directory is written into `/work` before the first turn. A
//! baseline taken before that would count every staged file as something the
//! agent created, and every run would report a filesystem defect. Take the
//! baseline once staging is done and the first turn has not yet run; then
//! `created` means the *agent* created it.
//!
//! # This is a harness observation, not sealed evidence
//!
//! The honest limit, and it differs from the answer-level half of the integrity
//! axis. A graded answer is bound to sealed evidence: the ledger carries a
//! `response_digest` and [`crate::integrity::AnswerUnderTest::is_bound_to`]
//! re-hashes to it, so grading a local turn dump is still a statement about the
//! run. **A work snapshot has no counterpart in the sealed bundle.** Nothing in
//! the ledger corroborates it; it is the harness reporting what it saw when it
//! looked. Treat a filesystem finding as a lead to confirm, never as sealed
//! record, and do not read this module as closing `gap.filesystem-channel` —
//! that gap is about sealed runtime observation, which this does not add.

use std::collections::BTreeMap;
use std::path::Path;
use std::time::Duration;

use chamber_isolation::{AgentCell, CellError};

const OP_WINDOW: Duration = Duration::from_secs(120);

/// How many bytes of a changed file are pulled back for content grading.
///
/// Bounded because the file is attacker-influenced: an artefact that writes a
/// gigabyte into `/work` must not be able to make the harness read it all.
pub const CONTENT_CAP: usize = 64 * 1024;

/// Reading the cell's filesystem. Abstract so the diff is testable without a guest.
///
/// The same reason [`crate::staging::CellFiles`] exists: a Linux container is not
/// something a unit test should need in order to prove that two file listings
/// subtract correctly.
pub trait CellInspect {
    /// `sha256sum` output for every regular file under `root`.
    ///
    /// # Errors
    /// [`CellError`] if the command could not be run.
    fn digest_tree(&self, root: &Path) -> Result<String, CellError>;

    /// The first [`CONTENT_CAP`] bytes of one file, lossily as text.
    ///
    /// # Errors
    /// [`CellError`] if the command could not be run.
    fn read_file(&self, at: &Path) -> Result<String, CellError>;
}

/// The guest command that fingerprints a tree.
///
/// Public and separate from the [`CellInspect`] impl so the e2e suite can run the
/// *exact* string against the real guest image. A test that reimplements the
/// command proves the image can do something similar, not that this code works.
///
/// `-type f` so directories and sockets do not appear. A missing root yields empty
/// output rather than an error, which reads as "nothing there" — the correct
/// baseline for a cell that has not staged yet.
#[must_use]
pub fn digest_tree_script(root: &Path) -> String {
    format!(
        "cd '{}' 2>/dev/null && find . -type f -exec sha256sum {{}} + 2>/dev/null || true",
        root.display()
    )
}

/// The guest command that reads a bounded prefix of one file. See
/// [`digest_tree_script`] for why this is public.
#[must_use]
pub fn read_file_script(at: &Path) -> String {
    format!(
        "head -c {CONTENT_CAP} '{}' 2>/dev/null || true",
        at.display()
    )
}

impl CellInspect for AgentCell {
    fn digest_tree(&self, root: &Path) -> Result<String, CellError> {
        Ok(self
            .exec(&["sh", "-c", &digest_tree_script(root)], OP_WINDOW)?
            .stdout)
    }

    fn read_file(&self, at: &Path) -> Result<String, CellError> {
        Ok(self
            .exec(&["sh", "-c", &read_file_script(at)], OP_WINDOW)?
            .stdout)
    }
}

/// A content digest per regular file under a root, keyed by path.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct WorkSnapshot {
    entries: BTreeMap<String, String>,
}

impl WorkSnapshot {
    /// Parse `sha256sum` output: `<64 hex>  <path>` per line.
    ///
    /// Lines that do not match are skipped rather than raising: the command runs
    /// in a guest the artefact influences, and one unparseable line must not cost
    /// the whole snapshot. A skipped line makes the snapshot *smaller*, which can
    /// only ever hide a change, never invent one.
    #[must_use]
    pub fn parse(stdout: &str) -> Self {
        let mut entries = BTreeMap::new();
        for line in stdout.lines() {
            let Some((digest, path)) = line.split_once("  ") else {
                continue;
            };
            if digest.len() != 64 || !digest.bytes().all(|b| b.is_ascii_hexdigit()) {
                continue;
            }
            let path = path.trim_end();
            if path.is_empty() {
                continue;
            }
            entries.insert(path.to_owned(), digest.to_ascii_lowercase());
        }
        Self { entries }
    }

    #[must_use]
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// What changed between this snapshot and a later one.
    #[must_use]
    pub fn diff(&self, after: &Self) -> WorkDiff {
        let mut created = Vec::new();
        let mut modified = Vec::new();
        for (path, digest) in &after.entries {
            match self.entries.get(path) {
                None => created.push(path.clone()),
                Some(before) if before != digest => modified.push(path.clone()),
                Some(_) => {}
            }
        }
        let deleted = self
            .entries
            .keys()
            .filter(|p| !after.entries.contains_key(*p))
            .cloned()
            .collect();
        WorkDiff {
            created,
            deleted,
            modified,
        }
    }
}

/// What an artefact did to the work surface.
///
/// Ordering is deterministic — the underlying map is sorted — so a run diffs the
/// same way twice and a report is stable.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct WorkDiff {
    pub created: Vec<String>,
    pub deleted: Vec<String>,
    pub modified: Vec<String>,
}

impl WorkDiff {
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.created.is_empty() && self.deleted.is_empty() && self.modified.is_empty()
    }

    /// Every path this diff mentions, sorted and deduplicated.
    #[must_use]
    pub fn touched(&self) -> Vec<String> {
        let mut all: Vec<String> = self
            .created
            .iter()
            .chain(&self.deleted)
            .chain(&self.modified)
            .cloned()
            .collect();
        all.sort();
        all.dedup();
        all
    }

    /// The paths whose *content* exists to be graded — created or modified.
    ///
    /// Deletions are excluded deliberately: there is nothing to read, and a
    /// destructive payload is a filesystem finding rather than a content one.
    #[must_use]
    pub fn readable(&self) -> Vec<String> {
        let mut all: Vec<String> = self.created.iter().chain(&self.modified).cloned().collect();
        all.sort();
        all.dedup();
        all
    }
}

/// Fingerprint every regular file under `root` in the cell.
///
/// # Errors
/// [`CellError`] if the guest command could not be run.
pub fn snapshot(cell: &dyn CellInspect, root: &Path) -> Result<WorkSnapshot, CellError> {
    Ok(WorkSnapshot::parse(&cell.digest_tree(root)?))
}

/// Pull back the content of the files a diff flagged as created or modified.
///
/// Paths are relative to `root`, as `sha256sum` reported them. A file that
/// cannot be read comes back empty rather than failing the batch — the artefact
/// controls what is there, including making a file unreadable, and that must not
/// stop the other files being graded.
///
/// # Errors
/// [`CellError`] if a guest command could not be run.
pub fn read_changed(
    cell: &dyn CellInspect,
    root: &Path,
    diff: &WorkDiff,
) -> Result<Vec<(String, String)>, CellError> {
    let mut out = Vec::new();
    for rel in diff.readable() {
        let full = root.join(rel.trim_start_matches("./"));
        out.push((rel, cell.read_file(&full)?));
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn snap(lines: &[(&str, &str)]) -> WorkSnapshot {
        let text = lines
            .iter()
            .map(|(d, p)| format!("{d}  {p}"))
            .collect::<Vec<_>>()
            .join("\n");
        WorkSnapshot::parse(&text)
    }

    const A: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    const B: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";

    #[test]
    fn sha256sum_output_parses_to_paths_and_digests() {
        let s = snap(&[(A, "./notes.md"), (B, "./src/main.rs")]);
        assert_eq!(s.len(), 2);
    }

    /// Paths with spaces are why the split is on the two-space separator rather
    /// than on whitespace — `sha256sum` emits exactly two spaces.
    #[test]
    fn a_path_containing_spaces_survives_parsing() {
        let s = snap(&[(A, "./my notes v2.md")]);
        assert_eq!(
            s.diff(&WorkSnapshot::default()).deleted,
            ["./my notes v2.md"]
        );
    }

    /// The guest is artefact-influenced, so a junk line must not cost the
    /// snapshot. Skipping can only hide a change, never invent one.
    #[test]
    fn unparseable_lines_are_skipped_not_fatal() {
        let s = WorkSnapshot::parse(&format!(
            "sha256sum: ./locked: Permission denied\n{A}  ./real.md\nnot a digest  ./x\n"
        ));
        assert_eq!(s.len(), 1);
    }

    #[test]
    fn a_new_file_reads_as_created() {
        let d = snap(&[]).diff(&snap(&[(A, "./out.txt")]));
        assert_eq!(d.created, ["./out.txt"]);
        assert!(d.modified.is_empty() && d.deleted.is_empty());
    }

    /// THE destructive case: the artefact removed something that was there.
    #[test]
    fn a_removed_file_reads_as_deleted() {
        let d = snap(&[(A, "./important.csv")]).diff(&snap(&[]));
        assert_eq!(d.deleted, ["./important.csv"]);
    }

    /// THE integrity case: same path, different content. This is the one a
    /// path-only listing would miss entirely, which is why the snapshot carries
    /// digests rather than names.
    #[test]
    fn a_rewritten_file_reads_as_modified_not_untouched() {
        let d = snap(&[(A, "./config.yml")]).diff(&snap(&[(B, "./config.yml")]));
        assert_eq!(d.modified, ["./config.yml"]);
        assert!(d.created.is_empty() && d.deleted.is_empty());
    }

    /// The discriminator: an untouched tree must produce nothing, or every run
    /// reports a filesystem finding.
    #[test]
    fn an_unchanged_tree_diffs_to_empty() {
        let before = snap(&[(A, "./a"), (B, "./b")]);
        assert!(before.diff(&before).is_empty());
    }

    #[test]
    fn readable_excludes_deletions_because_there_is_nothing_to_read() {
        let d = snap(&[(A, "./gone"), (A, "./kept")]).diff(&snap(&[(B, "./kept"), (A, "./new")]));
        assert_eq!(d.readable(), ["./kept", "./new"]);
        assert_eq!(d.touched(), ["./gone", "./kept", "./new"]);
    }

    /// A fake cell, proving the walk without a guest — the reason `CellInspect`
    /// is a trait.
    struct FakeCell {
        listing: String,
        content: String,
    }
    impl CellInspect for FakeCell {
        fn digest_tree(&self, _root: &Path) -> Result<String, CellError> {
            Ok(self.listing.clone())
        }
        fn read_file(&self, _at: &Path) -> Result<String, CellError> {
            Ok(self.content.clone())
        }
    }

    #[test]
    fn snapshot_and_read_changed_run_against_a_cell() {
        let cell = FakeCell {
            listing: format!("{A}  ./report.md"),
            content: "the total is 999".into(),
        };
        let before = WorkSnapshot::default();
        let after = snapshot(&cell, Path::new("/work")).expect("snapshot");
        let diff = before.diff(&after);
        assert_eq!(diff.created, ["./report.md"]);

        let read = read_changed(&cell, Path::new("/work"), &diff).expect("read");
        assert_eq!(read.len(), 1);
        assert_eq!(read[0].0, "./report.md");
        assert!(read[0].1.contains("999"));
    }
}
