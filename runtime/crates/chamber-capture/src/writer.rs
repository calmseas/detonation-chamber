//! The observation log on disk.
//!
//! Capture runs inside the container; the host reads what it wrote. This file
//! is that seam, and it has to survive the container dying — which is a normal
//! way for a detonation run to end, not an exceptional one.
//!
//! # Two different failures, two different mechanisms
//!
//! It is worth being precise about which measure buys which guarantee, because
//! they are easy to conflate and only one of them is demonstrated here.
//!
//! **Against the process dying** — the writer is deliberately *unbuffered*.
//! Each record is handed to the kernel by the time `append` returns, so a
//! process that is killed loses nothing it had already written. A `BufWriter`
//! would hold records in user memory and lose exactly the most recent ones,
//! which is to say the ones describing whatever the artefact did just before
//! the run was cut short — the interesting ones. This is the property
//! `writer_kill.rs` demonstrates against a real aborted process, and removing
//! the buffering is what makes it fail.
//!
//! **Against the machine dying** — each record additionally costs an
//! `fsync`. That protects against power loss or a kernel crash, where the
//! kernel's own page cache is lost too. It is **not** what protects against a
//! killed process: removing the `fsync` leaves every test here passing,
//! because after a write the kernel has the data whether or not this process
//! still exists. No test in this crate covers power loss, and none can.
//!
//! The `fsync` stays because evidence is the thing this system exists to
//! produce and a run costs far more than a flush. But it should not be
//! credited with a guarantee it does not provide.
//!
//! # Truncated must not read as complete
//!
//! The file ends with a marker naming how many records precede it. A reader
//! that finds it knows the writer finished; a reader that does not knows the
//! log was cut off, and says so, rather than returning the records it happened
//! to find as though that were all of them.
//!
//! That distinction is the same one the whole tool rests on: an incomplete
//! observation must never be presented as a clean one.
//!
//! # No redaction here
//!
//! A captured request is retained as it was seen. See the note on
//! [`chamber_evidence::bundle`] — the verdict trusts hit records rather than
//! re-scanning bodies, so the retained request is the only way a third party
//! can check that a hit was not fabricated. A sealed bundle is sensitive, and
//! this file is too.

use std::fs::{File, OpenOptions};
use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};

use chamber_evidence::Observation;
use serde::{Deserialize, Serialize};

/// The terminal line. Its presence is the only evidence the writer finished.
#[derive(Serialize, Deserialize)]
struct SealMarker {
    chamber_ledger: String,
    records: usize,
}

const SEAL_TAG: &str = "sealed";

/// Appends observations to a file, one JSON object per line.
#[derive(Debug)]
pub struct LedgerWriter {
    file: File,
    path: PathBuf,
    written: usize,
}

impl LedgerWriter {
    pub fn create(path: impl AsRef<Path>) -> std::io::Result<Self> {
        let path = path.as_ref().to_path_buf();
        let file = OpenOptions::new()
            .create(true)
            .truncate(true)
            .write(true)
            .open(&path)?;
        Ok(Self {
            file,
            path,
            written: 0,
        })
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn written(&self) -> usize {
        self.written
    }

    /// Append one observation, handing it to the kernel before returning.
    ///
    /// The absence of a buffer is what makes a killed process lose nothing it
    /// had already written. The `sync_data` on top is for power loss. See the
    /// module note — the two are not interchangeable.
    pub fn append(&mut self, observation: &Observation) -> std::io::Result<()> {
        let mut line = serde_json::to_vec(observation)?;
        line.push(b'\n');
        self.file.write_all(&line)?;
        self.file.sync_data()?;
        self.written += 1;
        Ok(())
    }

    /// Write the terminal marker. Consumes the writer: nothing may follow it.
    pub fn seal(mut self) -> std::io::Result<()> {
        let marker = SealMarker {
            chamber_ledger: SEAL_TAG.to_owned(),
            records: self.written,
        };
        let mut line = serde_json::to_vec(&marker)?;
        line.push(b'\n');
        self.file.write_all(&line)?;
        self.file.sync_all()?;
        Ok(())
    }
}

/// What a reader found.
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum LedgerFile {
    /// The writer finished, and the record count matches its own claim.
    Complete(Vec<Observation>),
    /// The log stops without a marker, or holds fewer records than the marker
    /// claims. The observations recovered are real; there are simply others
    /// that may be missing, and how many is unknown.
    Truncated {
        recovered: Vec<Observation>,
        detail: String,
    },
}

impl LedgerFile {
    /// Every observation recovered, whether or not the log was complete.
    pub fn observations(&self) -> &[Observation] {
        match self {
            LedgerFile::Complete(o) => o,
            LedgerFile::Truncated { recovered, .. } => recovered,
        }
    }

    /// Deliberately named for the negative.
    ///
    /// A method called `is_ok` invites `if !is_ok { warn }` and a caller that
    /// carries on. This one has to be read.
    pub fn is_truncated(&self) -> bool {
        matches!(self, LedgerFile::Truncated { .. })
    }
}

/// Read a log written by [`LedgerWriter`].
///
/// A final line that is not valid JSON is treated as a torn write: the process
/// died mid-record. It is discarded rather than parsed, and the file is
/// reported truncated. A malformed line anywhere *else* is a corrupted file
/// and is also reported rather than skipped, because silently dropping a
/// record we cannot read is how an observation becomes a non-observation.
pub fn read_ledger(path: impl AsRef<Path>) -> std::io::Result<LedgerFile> {
    let reader = BufReader::new(File::open(path)?);
    let lines: Vec<String> = reader.lines().collect::<Result<_, _>>()?;

    let mut recovered = Vec::new();
    let mut claimed: Option<usize> = None;

    for (i, line) in lines.iter().enumerate() {
        let is_last = i + 1 == lines.len();

        if let Ok(marker) = serde_json::from_str::<SealMarker>(line)
            && marker.chamber_ledger == SEAL_TAG
        {
            claimed = Some(marker.records);
            if !is_last {
                return Ok(LedgerFile::Truncated {
                    recovered,
                    detail: "records follow the seal marker".to_owned(),
                });
            }
            break;
        }

        match serde_json::from_str::<Observation>(line) {
            Ok(o) => recovered.push(o),
            Err(e) if is_last => {
                return Ok(LedgerFile::Truncated {
                    recovered,
                    detail: format!("last record is incomplete: {e}"),
                });
            }
            Err(e) => {
                return Ok(LedgerFile::Truncated {
                    recovered,
                    detail: format!("record {i} is unreadable: {e}"),
                });
            }
        }
    }

    match claimed {
        None => Ok(LedgerFile::Truncated {
            recovered,
            detail: "no seal marker: the writer did not finish".to_owned(),
        }),
        Some(n) if n != recovered.len() => Ok(LedgerFile::Truncated {
            detail: format!("seal claims {n} records, {} present", recovered.len()),
            recovered,
        }),
        Some(_) => Ok(LedgerFile::Complete(recovered)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chamber_evidence::{Channel, ObservationKind, Ordinal};
    use std::io::Seek;

    fn observation(id: u64, qname: &str) -> Observation {
        Observation::new(
            Ordinal(id),
            id * 10,
            Channel::DnsResolution,
            ObservationKind::NameQuery {
                qname: qname.to_owned(),
                qtype: "A".into(),
                answered_with: "10.66.0.10".into(),
            },
            vec![],
        )
    }

    fn temp_path(name: &str) -> PathBuf {
        let mut p = std::env::temp_dir();
        p.push(format!(
            "chamber-ledger-{name}-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        p
    }

    #[test]
    fn a_sealed_log_round_trips() {
        let path = temp_path("roundtrip");
        let mut w = LedgerWriter::create(&path).unwrap();
        let written: Vec<_> = (0..3).map(|i| observation(i, "a.example.")).collect();
        for o in &written {
            w.append(o).unwrap();
        }
        w.seal().unwrap();

        match read_ledger(&path).unwrap() {
            LedgerFile::Complete(read) => assert_eq!(read, written),
            other => panic!("expected a complete log, got {other:?}"),
        }
        let _ = std::fs::remove_file(&path);
    }

    /// The central claim. A writer that stops without sealing must not read as
    /// a finished run, however tidy its records happen to be.
    #[test]
    fn an_unsealed_log_is_truncated_even_when_every_record_is_whole() {
        let path = temp_path("unsealed");
        let mut w = LedgerWriter::create(&path).unwrap();
        for i in 0..3 {
            w.append(&observation(i, "a.example.")).unwrap();
        }
        drop(w); // no seal — as if the process died here

        let found = read_ledger(&path).unwrap();
        assert!(
            found.is_truncated(),
            "an unsealed log must not read as complete"
        );
        assert_eq!(
            found.observations().len(),
            3,
            "the records are still recovered"
        );
        let _ = std::fs::remove_file(&path);
    }

    /// A process killed mid-write leaves a partial final line. It is discarded,
    /// not parsed, and everything before it survives.
    #[test]
    fn a_torn_final_record_is_discarded_and_the_rest_survives() {
        let path = temp_path("torn");
        let mut w = LedgerWriter::create(&path).unwrap();
        for i in 0..3 {
            w.append(&observation(i, "a.example.")).unwrap();
        }
        let full = std::fs::metadata(&path).unwrap().len();
        drop(w);

        // Cut the file mid-way through what would have been a fourth record.
        let file = OpenOptions::new().write(true).open(&path).unwrap();
        file.set_len(full - 12).unwrap();
        file.sync_all().unwrap();

        let found = read_ledger(&path).unwrap();
        assert!(found.is_truncated());
        assert_eq!(
            found.observations().len(),
            2,
            "records completed before the tear must survive"
        );
        let _ = std::fs::remove_file(&path);
    }

    /// A seal that claims more records than are present is a truncation the
    /// line-level checks cannot see: every line is whole, and the file still
    /// lost data.
    #[test]
    fn a_seal_claiming_more_records_than_are_present_is_truncated() {
        let path = temp_path("shortcount");
        let mut w = LedgerWriter::create(&path).unwrap();
        w.append(&observation(0, "a.example.")).unwrap();
        w.written = 9; // as if records had been lost before the seal
        w.seal().unwrap();

        let found = read_ledger(&path).unwrap();
        assert!(found.is_truncated(), "the count mismatch must be caught");
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn an_empty_log_is_truncated_not_complete() {
        let path = temp_path("empty");
        let w = LedgerWriter::create(&path).unwrap();
        drop(w);

        let found = read_ledger(&path).unwrap();
        assert!(found.is_truncated());
        assert!(found.observations().is_empty());
        let _ = std::fs::remove_file(&path);
    }

    /// Each record is on the disk before the next is written, so a kill loses
    /// only what had not been handed over yet.
    #[test]
    fn each_record_is_on_disk_before_the_next_is_written() {
        let path = temp_path("fsync");
        let mut w = LedgerWriter::create(&path).unwrap();

        for i in 0..3 {
            w.append(&observation(i, "a.example.")).unwrap();

            // Read the file through a separate handle while the writer is
            // still open. Anything buffered in the writer would be missing.
            let mut independent = File::open(&path).unwrap();
            independent.rewind().unwrap();
            let count = BufReader::new(independent).lines().count();
            assert_eq!(
                count,
                (i + 1) as usize,
                "record {i} had not reached the file when append() returned"
            );
        }
        let _ = std::fs::remove_file(&path);
    }
}
