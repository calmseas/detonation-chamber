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

/// Collects observations for one run.
///
/// Shared by reference across tasks. The critical section is a push, so a
/// blocking mutex is the right tool — an async lock here would buy nothing and
/// cost a dependency in the path that must not fail.
#[derive(Debug)]
pub struct Recorder {
    log: Mutex<RunLog>,
    started: Instant,
}

impl Default for Recorder {
    fn default() -> Self {
        Self::new()
    }
}

impl Recorder {
    pub fn new() -> Self {
        Self {
            log: Mutex::new(RunLog::open()),
            started: Instant::now(),
        }
    }

    /// Record something that crossed the boundary.
    ///
    /// The ordinal and the elapsed offset are assigned here, not by the
    /// caller: two observers that chose their own numbers could collide, and
    /// the ordering the bundle depends on would be theirs to get wrong.
    pub fn note(&self, channel: Channel, kind: ObservationKind, hits: Vec<CanaryHit>) -> Ordinal {
        let offset_ms = self.started.elapsed().as_millis() as u64;
        self.lock().note(offset_ms, channel, kind, hits)
    }

    pub fn len(&self) -> usize {
        self.lock().len()
    }

    pub fn is_empty(&self) -> bool {
        self.lock().is_empty()
    }

    /// A copy of what has been observed so far, for inspection and tests.
    pub fn observations(&self) -> Vec<Observation> {
        self.lock().entries().to_vec()
    }

    /// Hand the log over for sealing. Consumes the recorder.
    pub fn into_log(self) -> RunLog {
        self.log.into_inner().unwrap_or_else(|e| e.into_inner())
    }

    /// Take the lock, recovering from poisoning.
    ///
    /// A panic in one observer must not cost us every observation the others
    /// made. Refusing the lock after a poisoning would discard the evidence
    /// collected before the panic — and losing evidence is the failure this
    /// whole system is built to avoid, so the recovery is deliberate rather
    /// than a convenience.
    fn lock(&self) -> std::sync::MutexGuard<'_, RunLog> {
        self.log.lock().unwrap_or_else(|e| e.into_inner())
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
            let _guard = poisoner.log.lock().unwrap();
            panic!("observer died holding the lock");
        })
        .join();

        // Still usable, and the earlier observation survives.
        r.note(Channel::NetworkEgress, exchange(), vec![]);
        assert_eq!(r.len(), 2);

        let recorder = Arc::try_unwrap(r).expect("sole owner once the thread has joined");
        assert_eq!(recorder.into_log().len(), 2);
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
