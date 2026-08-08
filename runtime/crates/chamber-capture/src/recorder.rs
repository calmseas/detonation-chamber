//! One observation sequence, shared by every observer.
//!
//! The proxy and the DNS sink write here, and they write through the same
//! counter. That is the reason they are one process rather than two daemons:
//! a name lookup immediately followed by a request to the address it returned
//! is a different story from the two happening minutes apart, and two
//! independently-timestamped log files cannot be reconciled into that story
//! after the fact. A single monotonic ordinal makes the order a fact of the
//! record rather than an inference from clocks.

use std::sync::Mutex;
use std::time::Instant;

use chamber_evidence::{CanaryHit, Channel, Observation, ObservationKind, Ordinal, RunLog};

use crate::writer::LedgerWriter;

/// The log, the file it is mirrored to, and how often that mirroring failed.
///
/// All three sit under **one** lock on purpose. Assigning the ordinal and
/// appending the record are a single critical section, so the order of records
/// in the file is the order of their ordinals. Two locks would let a
/// higher-ordinal record reach disk first, and a reader recovering a truncated
/// log would then have to reconstruct the sequence it was promised.
#[derive(Debug)]
struct Sequence {
    log: RunLog,
    sink: Option<LedgerWriter>,
    write_failures: usize,
    /// Set once the file has been closed off. Distinguishes "this recorder
    /// never had a file" from "the file is finished", which decides whether a
    /// late observation is normal or lost.
    sealed: bool,
}

/// Collects observations for one run.
///
/// Shared by reference across tasks. The critical section is a push, so a
/// blocking mutex is the right tool — an async lock here would buy nothing and
/// cost a dependency in the path that must not fail.
///
/// # In memory is not enough
///
/// [`Recorder::new`] keeps observations in memory only, which is right for
/// tests and wrong for a run. Capture dies as a normal part of detonation — the
/// artefact may cause it — and an in-memory log dies with it, taking exactly
/// the records describing whatever happened just before. [`Recorder::writing_to`]
/// mirrors every observation to an unbuffered file as it is recorded, which is
/// the property `writer_kill.rs` demonstrates against a real aborted process.
#[derive(Debug)]
pub struct Recorder {
    seq: Mutex<Sequence>,
    started: Instant,
}

impl Default for Recorder {
    fn default() -> Self {
        Self::new()
    }
}

impl Recorder {
    /// In memory only. For tests, and for callers that seal from memory.
    pub fn new() -> Self {
        Self::build(None)
    }

    /// Mirrors every observation to `writer` as it is recorded.
    ///
    /// This is what a real run uses. The writer is unbuffered, so a record has
    /// reached the kernel by the time [`Recorder::note`] returns and survives
    /// the process being killed.
    pub fn writing_to(writer: LedgerWriter) -> Self {
        Self::build(Some(writer))
    }

    fn build(sink: Option<LedgerWriter>) -> Self {
        Self {
            seq: Mutex::new(Sequence {
                log: RunLog::open(),
                sink,
                write_failures: 0,
                sealed: false,
            }),
            started: Instant::now(),
        }
    }

    /// Record something that crossed the boundary.
    ///
    /// The ordinal and the elapsed offset are assigned here, not by the
    /// caller: two observers that chose their own numbers could collide, and
    /// the ordering the bundle depends on would be theirs to get wrong.
    ///
    /// Infallible by design, even though it writes to a file. An observer in
    /// the middle of a request cannot do anything useful with an I/O error, and
    /// making it fallible would put a `?` in the path that must not abandon
    /// evidence. A failed write is counted instead — see
    /// [`Recorder::write_failures`], which is what turns it into a reported
    /// coverage defect rather than a silently shorter log.
    pub fn note(&self, channel: Channel, kind: ObservationKind, hits: Vec<CanaryHit>) -> Ordinal {
        let offset_ms = self.started.elapsed().as_millis() as u64;
        let mut guard = self.lock();
        // Disjoint field borrows: the record is read from the log and handed to
        // the sink without releasing the lock between the two.
        let seq = &mut *guard;
        let id = seq.log.note(offset_ms, channel, kind, hits);

        match seq.sink.as_mut() {
            Some(sink) => {
                if let Some(recorded) = seq.log.entries().last()
                    && sink.append(recorded).is_err()
                {
                    seq.write_failures += 1;
                }
            }
            // No sink *after sealing* means the ledger closed while observers
            // were still running: this record exists in memory and not in the
            // file a third party will read. Counted, because the alternative is
            // a ledger that is quietly shorter than the run.
            None if seq.sealed => seq.write_failures += 1,
            None => {}
        }
        id
    }

    /// Close the file off without consuming the recorder.
    ///
    /// The owned [`Recorder::seal`] cannot be used when the proxy and the DNS
    /// sink each hold a reference — which is every real run, since a shared
    /// monotonic ordinal across both is the entire reason they are one process.
    ///
    /// # Errors
    /// [`std::io::Error`] if the terminal marker could not be written, in which
    /// case the file must be read as truncated, because it is.
    pub fn seal_sink(&self) -> std::io::Result<()> {
        let mut seq = self.lock();
        seq.sealed = true;
        match seq.sink.take() {
            Some(sink) => sink.seal(),
            None => Ok(()),
        }
    }

    pub fn len(&self) -> usize {
        self.lock().log.len()
    }

    pub fn is_empty(&self) -> bool {
        self.lock().log.is_empty()
    }

    /// A copy of what has been observed so far, for inspection and tests.
    pub fn observations(&self) -> Vec<Observation> {
        self.lock().log.entries().to_vec()
    }

    /// How many observations were recorded in memory but did not reach disk.
    ///
    /// Non-zero means the ledger on disk is **shorter than what was observed**.
    /// That is a coverage defect and must surface as one: a run that quietly
    /// dropped records would produce a bundle whose ledger looks complete
    /// because contiguity is checked over what is present, not over what
    /// happened.
    pub fn write_failures(&self) -> usize {
        self.lock().write_failures
    }

    /// Hand the log over for sealing, without sealing the file.
    ///
    /// Prefer [`Recorder::seal`] when there is a sink: a file without its
    /// terminal marker reads as truncated, which is the correct reading of an
    /// interrupted run and the wrong one for a finished one.
    pub fn into_log(self) -> RunLog {
        self.into_seq().log
    }

    /// Writes the terminal marker and hands the log over.
    ///
    /// The marker is the only evidence the writer finished. Without it a reader
    /// reports the log as truncated rather than returning the records it
    /// happened to find as though that were all of them.
    ///
    /// # Errors
    /// [`std::io::Error`] if the marker could not be written. The log is lost
    /// with it, deliberately: a caller that got an error here must not go on to
    /// seal a bundle claiming a complete ledger.
    pub fn seal(self) -> std::io::Result<RunLog> {
        let seq = self.into_seq();
        if let Some(sink) = seq.sink {
            sink.seal()?;
        }
        Ok(seq.log)
    }

    fn into_seq(self) -> Sequence {
        self.seq.into_inner().unwrap_or_else(|e| e.into_inner())
    }

    /// Take the lock, recovering from poisoning.
    ///
    /// A panic in one observer must not cost us every observation the others
    /// made. Refusing the lock after a poisoning would discard the evidence
    /// collected before the panic — and losing evidence is the failure this
    /// whole system is built to avoid, so the recovery is deliberate rather
    /// than a convenience.
    fn lock(&self) -> std::sync::MutexGuard<'_, Sequence> {
        self.seq.lock().unwrap_or_else(|e| e.into_inner())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chamber_evidence::{HitEncoding, HitField};

    fn query(name: &str) -> ObservationKind {
        ObservationKind::NameQuery {
            qname: name.to_owned(),
            qtype: "A".into(),
            answered_with: "10.66.0.10".into(),
        }
    }

    fn exchange() -> ObservationKind {
        ObservationKind::HttpExchange {
            method: "POST".into(),
            authority: "collector.example".into(),
            sni: None,
            target: "/ingest".into(),
            headers: vec![],
            body: chamber_evidence::CapturedBody::Whole { bytes: vec![] },
        }
    }

    #[test]
    fn one_sequence_spans_both_channels() {
        let r = Recorder::new();
        let a = r.note(Channel::DnsResolution, query("collector.example"), vec![]);
        let b = r.note(Channel::NetworkEgress, exchange(), vec![]);
        let c = r.note(Channel::DnsResolution, query("other.example"), vec![]);

        assert_eq!((a, b, c), (Ordinal(0), Ordinal(1), Ordinal(2)));
    }

    /// The interleaving must survive concurrent observers: no duplicated
    /// ordinal, no gap.
    #[test]
    fn concurrent_observers_do_not_collide() {
        use std::sync::Arc;

        let r = Arc::new(Recorder::new());
        let mut handles = Vec::new();
        for i in 0..8 {
            let r = Arc::clone(&r);
            handles.push(std::thread::spawn(move || {
                for j in 0..25 {
                    r.note(
                        if (i + j) % 2 == 0 {
                            Channel::DnsResolution
                        } else {
                            Channel::NetworkEgress
                        },
                        query(&format!("h{i}-{j}.example")),
                        vec![],
                    );
                }
            }));
        }
        for h in handles {
            h.join().unwrap();
        }

        let mut ids: Vec<u64> = r.observations().iter().map(|o| o.id().0).collect();
        ids.sort_unstable();
        assert_eq!(ids, (0..200).collect::<Vec<_>>());
    }

    /// A panicking observer must not take the evidence with it.
    #[test]
    fn a_poisoned_lock_still_yields_what_was_observed() {
        use std::sync::Arc;

        let r = Arc::new(Recorder::new());
        r.note(Channel::DnsResolution, query("before.example"), vec![]);

        let poisoner = Arc::clone(&r);
        let _ = std::thread::spawn(move || {
            let _guard = poisoner.seq.lock().unwrap();
            panic!("observer died holding the lock");
        })
        .join();

        // Still usable, and the earlier observation survives.
        r.note(Channel::NetworkEgress, exchange(), vec![]);
        assert_eq!(r.len(), 2);

        let recorder = Arc::try_unwrap(r).expect("sole owner once the thread has joined");
        assert_eq!(recorder.into_log().len(), 2);
    }

    fn scratch(name: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!("chamber-rec-{}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("scratch dir");
        dir.join(name)
    }

    /// The property the whole write-through exists for. Capture dying is a
    /// normal way for a detonation to end, and an observation that only ever
    /// lived in memory dies with it.
    #[test]
    fn an_observation_reaches_disk_as_it_is_recorded() {
        let path = scratch("live.jsonl");
        let writer = crate::LedgerWriter::create(&path).expect("create the log");
        let r = Recorder::writing_to(writer);

        r.note(Channel::DnsResolution, query("first.example"), vec![]);
        r.note(Channel::NetworkEgress, exchange(), vec![]);

        // Read while the run is still going: nothing has been sealed.
        let on_disk = crate::read_ledger(&path).expect("read the log");
        assert_eq!(on_disk.observations().len(), 2);
        assert!(
            on_disk.is_truncated(),
            "an unsealed log must read as truncated, not as complete"
        );
        assert_eq!(r.write_failures(), 0);
    }

    #[test]
    fn sealing_marks_the_file_complete() {
        let path = scratch("sealed.jsonl");
        let writer = crate::LedgerWriter::create(&path).expect("create the log");
        let r = Recorder::writing_to(writer);
        r.note(Channel::DnsResolution, query("only.example"), vec![]);

        let log = r.seal().expect("seal the log");
        assert_eq!(log.len(), 1);

        let on_disk = crate::read_ledger(&path).expect("read the log");
        assert!(
            !on_disk.is_truncated(),
            "a sealed log must not read as cut off"
        );
        assert_eq!(on_disk.observations().len(), 1);
    }

    /// Ordinal assignment and the disk append are one critical section, so a
    /// reader recovering a truncated log gets the sequence it was promised
    /// rather than one it has to reconstruct.
    #[test]
    fn file_order_matches_ordinal_order_under_concurrency() {
        use std::sync::Arc;

        let path = scratch("ordered.jsonl");
        let writer = crate::LedgerWriter::create(&path).expect("create the log");
        let r = Arc::new(Recorder::writing_to(writer));

        let mut handles = Vec::new();
        for i in 0..8 {
            let r = Arc::clone(&r);
            handles.push(std::thread::spawn(move || {
                for j in 0..15 {
                    r.note(
                        Channel::DnsResolution,
                        query(&format!("h{i}-{j}.example")),
                        vec![],
                    );
                }
            }));
        }
        for h in handles {
            h.join().unwrap();
        }

        let on_disk = crate::read_ledger(&path).expect("read the log");
        let ids: Vec<u64> = on_disk.observations().iter().map(|o| o.id().0).collect();
        assert_eq!(
            ids,
            (0..120).collect::<Vec<_>>(),
            "records are on disk out of ordinal order"
        );
    }

    /// A recorder with no sink still works. This is the shape every existing
    /// test uses, and it must keep meaning "memory only" rather than silently
    /// acquiring a file.
    /// An observer still running when the ledger closes is the shape of a
    /// wind-down race. Its record exists in memory and not in the file a third
    /// party reads, and that discrepancy must be reported rather than absorbed.
    #[test]
    fn an_observation_after_sealing_is_counted_as_lost() {
        let path = scratch("late.jsonl");
        let writer = crate::LedgerWriter::create(&path).expect("create the log");
        let r = Recorder::writing_to(writer);

        r.note(Channel::DnsResolution, query("in-time.example"), vec![]);
        r.seal_sink().expect("seal");
        r.note(Channel::DnsResolution, query("too-late.example"), vec![]);

        assert_eq!(
            r.write_failures(),
            1,
            "a post-seal record was absorbed silently"
        );
        assert_eq!(r.len(), 2, "the in-memory log should still hold both");

        let on_disk = crate::read_ledger(&path).expect("read the log");
        assert_eq!(
            on_disk.observations().len(),
            1,
            "the file holds only the in-time record"
        );
        assert!(!on_disk.is_truncated());
    }

    #[test]
    fn an_in_memory_recorder_writes_no_file_and_reports_no_failures() {
        let r = Recorder::new();
        r.note(Channel::DnsResolution, query("nowhere.example"), vec![]);
        assert_eq!(r.write_failures(), 0);
        assert_eq!(r.into_log().len(), 1);
    }

    #[test]
    fn hits_travel_with_the_observation() {
        let r = Recorder::new();
        r.note(
            Channel::DnsResolution,
            query("leak.example"),
            vec![CanaryHit {
                label: "aws-key".into(),
                field: HitField::QName,
                encoding: HitEncoding::LabelJoin,
                offset: 0,
            }],
        );

        let obs = r.observations();
        assert_eq!(obs[0].canary_hits().len(), 1);
        assert!(obs[0].is_witness());
    }
}
