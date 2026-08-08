//! What survives when the writing process is killed outright.
//!
//! The in-crate tests simulate this by dropping a writer or truncating a file.
//! This one does it for real: a child process writes records and then aborts,
//! running no destructors and flushing nothing. A container being torn down is
//! an ordinary way for a detonation run to end, so "what is on the disk when
//! the process stops existing" is a property worth demonstrating rather than
//! arguing for.

use std::path::PathBuf;
use std::process::Command;

use chamber_capture::{LedgerWriter, read_ledger};
use chamber_evidence::{Channel, Observation, ObservationKind, Ordinal};

/// Set by the parent to tell the child where to write. Absent in a normal run.
const CHILD_PATH: &str = "CHAMBER_WRITER_KILL_PATH";
const RECORDS: u64 = 5;

fn observation(id: u64) -> Observation {
    Observation::new(
        Ordinal(id),
        id * 10,
        Channel::DnsResolution,
        ObservationKind::NameQuery {
            qname: format!("record-{id}.example."),
            qtype: "A".into(),
            answered_with: "10.66.0.10".into(),
        },
        vec![],
    )
}

/// The child half. Does nothing unless the parent below invoked it.
///
/// It is a `#[test]` only because that is how a test binary exposes an entry
/// point to itself; in an ordinary run it returns immediately.
#[test]
fn writes_records_then_dies_without_cleaning_up() {
    let Ok(path) = std::env::var(CHILD_PATH) else {
        return;
    };

    let mut writer = LedgerWriter::create(&path).expect("create the log");
    for i in 0..RECORDS {
        writer.append(&observation(i)).expect("append");
    }

    // Deliberately not `drop`, not `seal`, not `exit`. `abort` runs no
    // destructors and flushes nothing, which is the point: whatever is on the
    // disk now got there because `append` put it there.
    std::process::abort();
}

/// The claim: every record `append` returned from is readable afterwards, and
/// the log is reported truncated because it was never sealed.
#[test]
fn a_killed_writer_leaves_every_flushed_record_readable() {
    let mut path = std::env::temp_dir();
    path.push(format!("chamber-writer-kill-{}", std::process::id()));
    let _ = std::fs::remove_file(&path);

    let child = Command::new(std::env::current_exe().expect("test binary path"))
        .args([
            "--exact",
            "writes_records_then_dies_without_cleaning_up",
            "--nocapture",
        ])
        .env(CHILD_PATH, &path)
        .output()
        .expect("run the child");

    assert!(
        !child.status.success(),
        "the child was supposed to die, but exited cleanly — this test would \
         otherwise be measuring an orderly shutdown"
    );

    let found = read_ledger(&path).expect("the log must be readable");

    assert_eq!(
        found.observations().len(),
        RECORDS as usize,
        "a record that `append` returned from must survive the process dying"
    );
    assert!(
        found.is_truncated(),
        "a killed writer never sealed, so the log must not read as complete"
    );
    assert_eq!(
        found.observations()[0],
        observation(0),
        "records must survive intact, not merely in number"
    );

    let _ = std::fs::remove_file(&path);
    let _: PathBuf = path;
}
