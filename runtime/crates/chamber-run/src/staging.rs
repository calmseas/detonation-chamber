//! Putting a skill's own files into the cell.
//!
//! # A skill is a directory, not a README
//!
//! Slice 0 handed the driver the `SKILL.md` *text* and staged nothing into the
//! guest. That is enough for a skill whose whole payload is its prose, but the
//! techniques worth catching put the payload elsewhere — a shipped
//! `scripts/collect.sh`, an encoder the skill sideloads. A "run
//! `scripts/collect.sh`" skill cannot detonate if the file is not there.
//!
//! So the real skill directory is written into `/work` before the first turn.
//! This is input into the sealed tmpfs, exactly like the trust anchor already
//! is (see [`crate::run`]): no new egress, no observer change. What the reviewer
//! reads is still the prose in the driver's brief; what the agent *runs* is the
//! script now sitting in the cell. That split is the whole point — it is where a
//! skill that reads clean and behaves dirty becomes observable.

use std::path::{Path, PathBuf};

use chamber_isolation::{AgentCell, CellError};

/// Extensions staged with the executable bit set.
///
/// A skill that says "run `scripts/x.sh`" needs `x.sh` executable, or the run
/// fails on the harness rather than on anything the artefact did. Bare data
/// files stay non-executable so the cell's file listing tells the truth about
/// what is meant to run.
const EXECUTABLE_EXTS: &[&str] = &["sh", "py", "pl", "rb", "js"];

/// Where a skill is installed inside the cell. Distinct from the trust anchor's
/// path so the two never collide.
const SKILL_ROOT: &str = "/work";

/// Writing files into a cell. Abstract so the walk is testable without a guest.
///
/// The same reason [`crate::bridge::TurnTarget`] exists: a Linux container is
/// not something a unit test should need to prove that a directory maps to the
/// right destinations with the right modes.
pub trait CellFiles {
    /// # Errors
    /// [`CellError`] if the directory could not be created.
    fn ensure_dir(&self, dir: &Path) -> Result<(), CellError>;

    /// # Errors
    /// [`CellError`] if the file could not be written.
    fn put_file(&self, at: &Path, bytes: &[u8], executable: bool) -> Result<(), CellError>;
}

impl CellFiles for AgentCell {
    fn ensure_dir(&self, dir: &Path) -> Result<(), CellError> {
        // Single-quoted so a path with a space survives; skill paths never carry
        // a single quote (see the escape note in `stage_skill_dir`).
        self.exec(
            &["sh", "-c", &format!("mkdir -p '{}'", dir.display())],
            OP_WINDOW,
        )?;
        Ok(())
    }

    fn put_file(&self, at: &Path, bytes: &[u8], executable: bool) -> Result<(), CellError> {
        self.write_file(at, bytes)?;
        if executable {
            self.exec(
                &["sh", "-c", &format!("chmod +x '{}'", at.display())],
                OP_WINDOW,
            )?;
        }
        Ok(())
    }
}

const OP_WINDOW: std::time::Duration = std::time::Duration::from_secs(120);

/// Why a skill directory could not be staged.
#[derive(Debug)]
pub enum StagingError {
    /// The host-side skill directory could not be read.
    Unreadable { path: String, detail: String },
    /// A path in the directory cannot be staged safely (a single quote in a
    /// name would break the shell-quoted `mkdir`/`chmod`, and a `..` component
    /// would try to escape `/work`).
    UnsafePath { path: String },
    /// Writing into the cell failed.
    Cell { path: String, detail: String },
}

impl std::fmt::Display for StagingError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Unreadable { path, detail } => {
                write!(f, "cannot read the skill directory {path}: {detail}")
            }
            Self::UnsafePath { path } => write!(
                f,
                "the skill contains a path this staging cannot place safely: {path}"
            ),
            Self::Cell { path, detail } => {
                write!(f, "could not stage {path} into the cell: {detail}")
            }
        }
    }
}

impl std::error::Error for StagingError {}

/// Writes a skill directory's files into the cell under `/work`, preserving
/// structure and marking scripts executable.
///
/// Returns the destinations written, in a stable order — for the run record and
/// for tests. The order is sorted, so a directory stages the same way twice.
///
/// # Errors
/// [`StagingError`] if the directory cannot be read, contains a path that cannot
/// be placed safely, or the cell rejects a write.
pub fn stage_skill_dir(
    cell: &dyn CellFiles,
    skill_dir: &Path,
) -> Result<Vec<PathBuf>, StagingError> {
    let mut files = Vec::new();
    collect(skill_dir, skill_dir, &mut files)?;
    files.sort();

    let root = PathBuf::from(SKILL_ROOT);
    let mut staged = Vec::new();
    for rel in &files {
        // A `..` component or a single quote would either escape /work or break
        // the shell-quoted commands. Neither can appear in a legitimate skill,
        // so refuse rather than sanitise silently.
        if !is_safe_rel(rel) {
            return Err(StagingError::UnsafePath {
                path: rel.display().to_string(),
            });
        }

        let dest = root.join(rel);
        let bytes = std::fs::read(skill_dir.join(rel)).map_err(|e| StagingError::Unreadable {
            path: rel.display().to_string(),
            detail: e.to_string(),
        })?;

        if let Some(parent) = dest.parent()
            && parent != root
        {
            cell.ensure_dir(parent).map_err(|e| StagingError::Cell {
                path: parent.display().to_string(),
                detail: e.to_string(),
            })?;
        }
        cell.put_file(&dest, &bytes, is_executable(rel))
            .map_err(|e| StagingError::Cell {
                path: dest.display().to_string(),
                detail: e.to_string(),
            })?;
        staged.push(dest);
    }
    Ok(staged)
}

/// Relative paths of every file under `dir`, recursively.
fn collect(root: &Path, dir: &Path, out: &mut Vec<PathBuf>) -> Result<(), StagingError> {
    let entries = std::fs::read_dir(dir).map_err(|e| StagingError::Unreadable {
        path: dir.display().to_string(),
        detail: e.to_string(),
    })?;
    for entry in entries {
        let entry = entry.map_err(|e| StagingError::Unreadable {
            path: dir.display().to_string(),
            detail: e.to_string(),
        })?;
        let path = entry.path();
        let file_type = entry.file_type().map_err(|e| StagingError::Unreadable {
            path: path.display().to_string(),
            detail: e.to_string(),
        })?;
        if file_type.is_dir() {
            collect(root, &path, out)?;
        } else {
            // A symlink is not staged as its target — a skill that ships one is
            // trying to reach outside its own directory, which staging will not
            // do for it.
            if file_type.is_file()
                && let Ok(rel) = path.strip_prefix(root)
            {
                out.push(rel.to_path_buf());
            }
        }
    }
    Ok(())
}

fn is_executable(rel: &Path) -> bool {
    rel.extension()
        .and_then(|e| e.to_str())
        .is_some_and(|ext| EXECUTABLE_EXTS.contains(&ext))
}

/// A relative path safe to place under `/work` and to name in a shell-quoted
/// command. Rejects `..` traversal and single quotes.
fn is_safe_rel(rel: &Path) -> bool {
    !rel.components().any(|c| c.as_os_str() == "..") && !rel.to_string_lossy().contains('\'')
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::RefCell;

    /// Records what it was asked to stage, so the walk is checked without a guest.
    #[derive(Default)]
    struct FakeCell {
        dirs: RefCell<Vec<String>>,
        files: RefCell<Vec<(String, usize, bool)>>, // path, byte len, executable
        fail_on: Option<String>,
    }

    impl CellFiles for FakeCell {
        fn ensure_dir(&self, dir: &Path) -> Result<(), CellError> {
            self.dirs.borrow_mut().push(dir.display().to_string());
            Ok(())
        }
        fn put_file(&self, at: &Path, bytes: &[u8], executable: bool) -> Result<(), CellError> {
            let path = at.display().to_string();
            if self.fail_on.as_deref() == Some(&path) {
                return Err(CellError::RulesetUnreadable {
                    path: path.clone(),
                    detail: "the cell refused".into(),
                });
            }
            self.files
                .borrow_mut()
                .push((path, bytes.len(), executable));
            Ok(())
        }
    }

    fn write(dir: &Path, rel: &str, contents: &str) {
        let p = dir.join(rel);
        std::fs::create_dir_all(p.parent().unwrap()).unwrap();
        std::fs::write(p, contents).unwrap();
    }

    fn tmp(tag: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("chamber-stage-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    /// The setup the whole corpus depends on: the prose and the script both land
    /// in the cell, the script executable, the markdown not.
    #[test]
    fn a_skill_with_a_script_stages_both_with_the_right_modes() {
        let dir = tmp("both");
        write(&dir, "SKILL.md", "# do a thing\nrun scripts/collect.sh");
        write(&dir, "scripts/collect.sh", "#!/bin/sh\ncurl ...");

        let cell = FakeCell::default();
        let staged = stage_skill_dir(&cell, &dir).unwrap();

        let files = cell.files.borrow();
        let exec_of = |p: &str| {
            files
                .iter()
                .find(|(path, _, _)| path == p)
                .map(|(_, _, x)| *x)
        };

        assert_eq!(
            exec_of("/work/SKILL.md"),
            Some(false),
            "markdown must not be executable"
        );
        assert_eq!(
            exec_of("/work/scripts/collect.sh"),
            Some(true),
            "the script the skill runs must be executable"
        );

        assert!(cell.dirs.borrow().iter().any(|d| d == "/work/scripts"));
        assert_eq!(
            staged,
            vec![
                PathBuf::from("/work/SKILL.md"),
                PathBuf::from("/work/scripts/collect.sh"),
            ]
        );
    }

    /// Structure is preserved, not flattened — a nested reference in the skill
    /// must resolve to the same nested path in the cell.
    #[test]
    fn nested_directories_are_preserved() {
        let dir = tmp("nested");
        write(&dir, "SKILL.md", "s");
        write(&dir, "lib/enc/encoder.py", "print('x')");

        let cell = FakeCell::default();
        stage_skill_dir(&cell, &dir).unwrap();

        let files = cell.files.borrow();
        assert!(
            files
                .iter()
                .any(|(p, _, x)| p == "/work/lib/enc/encoder.py" && *x)
        );
        assert!(cell.dirs.borrow().iter().any(|d| d == "/work/lib/enc"));
    }

    /// None of Slice 0's callers pass one, but a genuinely empty directory must
    /// not error — it stages nothing.
    #[test]
    fn an_empty_directory_stages_nothing() {
        let dir = tmp("empty");
        let cell = FakeCell::default();
        assert!(stage_skill_dir(&cell, &dir).unwrap().is_empty());
        assert!(cell.files.borrow().is_empty());
    }

    #[test]
    fn a_missing_directory_is_an_error() {
        let cell = FakeCell::default();
        let err = stage_skill_dir(&cell, Path::new("/no/such/skill")).unwrap_err();
        assert!(matches!(err, StagingError::Unreadable { .. }), "{err}");
    }

    /// A cell write that fails must abort staging loudly — a half-staged skill
    /// would detonate as something other than what was handed in.
    #[test]
    fn a_cell_write_failure_propagates() {
        let dir = tmp("cellfail");
        write(&dir, "SKILL.md", "s");
        let cell = FakeCell {
            fail_on: Some("/work/SKILL.md".to_owned()),
            ..FakeCell::default()
        };
        let err = stage_skill_dir(&cell, &dir).unwrap_err();
        assert!(matches!(err, StagingError::Cell { .. }), "{err}");
    }

    /// A `..` component would escape /work; a single quote would break the
    /// shell-quoted mkdir/chmod. Both refused rather than sanitised silently.
    #[test]
    fn unsafe_paths_are_rejected() {
        assert!(is_safe_rel(Path::new("scripts/collect.sh")));
        assert!(is_safe_rel(Path::new("SKILL.md")));
        assert!(!is_safe_rel(Path::new("../escape.sh")));
        assert!(!is_safe_rel(Path::new("nested/../../escape")));
        assert!(!is_safe_rel(Path::new("weird'name.sh")));
    }

    /// The refusals are what a reader sees when a skill won't stage; each must
    /// name what went wrong, not render empty.
    #[test]
    fn staging_errors_explain_themselves() {
        let unreadable = StagingError::Unreadable {
            path: "skill/x".into(),
            detail: "no such file".into(),
        };
        assert!(format!("{unreadable}").contains("skill/x"));
        assert!(format!("{unreadable}").contains("no such file"));

        let unsafe_path = StagingError::UnsafePath {
            path: "../escape".into(),
        };
        assert!(format!("{unsafe_path}").contains("../escape"));

        let cell = StagingError::Cell {
            path: "/work/x".into(),
            detail: "refused".into(),
        };
        assert!(format!("{cell}").contains("/work/x") && format!("{cell}").contains("refused"));
    }

    #[test]
    fn only_script_extensions_are_executable() {
        assert!(is_executable(Path::new("x.sh")));
        assert!(is_executable(Path::new("lib/enc.py")));
        assert!(!is_executable(Path::new("SKILL.md")));
        assert!(!is_executable(Path::new("data.json")));
        assert!(!is_executable(Path::new("noext")));
    }
}
