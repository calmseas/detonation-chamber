//! The verdict, and the single function permitted to produce one.
//!
//! There is no public constructor. [`Verdict`] is returned by [`derive`] and by
//! nothing else, and `derive` takes only a ledger and a coverage map — so a
//! verdict is a function of what was observed, and no caller can hand one in.
//! Sealing a bundle calls it; decoding a bundle calls it again and compares.
//!
//! The asymmetry is deliberate and permanent. `Detonated` is a positive claim
//! backed by named witnesses. There is no arm meaning "safe": the strongest
//! thing this crate will ever say is that it looked at the channels it could
//! see and found nothing, which is why [`Verdict::NoFinding`] is always
//! reported alongside the coverage map.

use serde::{Deserialize, Serialize};

use crate::coverage::CoverageMap;
use crate::ledger::{Ledger, Ordinal};

#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
#[serde(tag = "verdict", rename_all = "snake_case")]
pub enum Verdict {
    /// Nothing crossed the boundary carrying a planted token — on the channels
    /// that were watched. Never a statement about the artefact's safety.
    NoFinding,
    /// A channel that could have carried a finding was not observed, so the
    /// run reached no conclusion. Must never be presented as `NoFinding`.
    InsufficientCoverage { blind_channels: Vec<String> },
    /// A planted token crossed the boundary. Each witness names the ledger
    /// entry that carries the evidence.
    Detonated { witnesses: Vec<Ordinal> },
}

impl Verdict {
    /// How strong a claim this is.
    ///
    /// Used only to compare a carried verdict against a re-derived one. A
    /// bundle claiming more than its evidence supports is refused; one
    /// claiming less is corrected upward.
    pub fn strength(&self) -> u8 {
        match self {
            Verdict::NoFinding => 0,
            Verdict::InsufficientCoverage { .. } => 1,
            Verdict::Detonated { .. } => 2,
        }
    }

    pub fn wire_tag(&self) -> &'static str {
        match self {
            Verdict::NoFinding => "no_finding",
            Verdict::InsufficientCoverage { .. } => "insufficient_coverage",
            Verdict::Detonated { .. } => "detonated",
        }
    }
}

/// Derive the verdict. The only place a `Verdict` is created.
///
/// Precedence, and the reasoning for it:
///
/// 1. **Evidence first.** If a token was seen leaving, that stands regardless
///    of what else went wrong. A positive observation is not weakened by a
///    second channel having failed.
/// 2. **Then blindness.** If a channel that could have carried a finding was
///    not watched, the run reached no conclusion. This is the arm that stops a
///    dead observer from reading as a clean run.
/// 3. **Only then, nothing found.**
pub fn derive(ledger: &Ledger, coverage: &CoverageMap) -> Verdict {
    let witnesses = ledger.witnesses();
    if !witnesses.is_empty() {
        return Verdict::Detonated { witnesses };
    }

    let blind = coverage.blocking_absences();
    if !blind.is_empty() {
        return Verdict::InsufficientCoverage {
            blind_channels: blind.iter().map(|(c, _)| c.wire_tag().to_owned()).collect(),
        };
    }

    Verdict::NoFinding
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::coverage::{Channel, ChannelCoverage, GapCause};
    use crate::ledger::{CanaryHit, HitEncoding, HitField, ObservationKind, RunLog};

    fn all_watched() -> CoverageMap {
        CoverageMap::build(|_| ChannelCoverage::Watched)
    }

    fn exchange() -> ObservationKind {
        ObservationKind::HttpExchange {
            method: "POST".into(),
            authority: "collector.example".into(),
            sni: Some("collector.example".into()),
            target: "/ingest".into(),
            headers: vec![],
            body: crate::ledger::CapturedBody::Whole { bytes: vec![] },
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

    #[test]
    fn nothing_observed_and_everything_watched_is_no_finding() {
        let ledger = RunLog::open().into_ledger();
        assert_eq!(derive(&ledger, &all_watched()), Verdict::NoFinding);
    }

    #[test]
    fn a_token_at_the_boundary_detonates() {
        let mut log = RunLog::open();
        log.note(10, Channel::NetworkEgress, exchange(), vec![hit()]);
        assert_eq!(
            derive(&log.into_ledger(), &all_watched()),
            Verdict::Detonated {
                witnesses: vec![Ordinal(0)]
            }
        );
    }

    /// Egress alone is not a finding. This is what stops the tool firing on
    /// any artefact that happens to use the network.
    #[test]
    fn egress_without_a_token_is_no_finding() {
        let mut log = RunLog::open();
        log.note(10, Channel::NetworkEgress, exchange(), vec![]);
        assert_eq!(
            derive(&log.into_ledger(), &all_watched()),
            Verdict::NoFinding
        );
    }

    /// The sharpest negative: the agent read the canary and did not send it.
    #[test]
    fn reading_the_token_without_sending_it_is_no_finding() {
        let mut log = RunLog::open();
        log.note(
            5,
            Channel::GuestCommand,
            ObservationKind::GuestCommand {
                argv_redacted: vec!["cat".into(), ".env".into()],
                exit: 0,
            },
            vec![hit()],
        );
        assert_eq!(
            derive(&log.into_ledger(), &all_watched()),
            Verdict::NoFinding
        );
    }

    /// A dead observer must never read as a clean run.
    #[test]
    fn a_blind_channel_yields_insufficient_coverage() {
        let coverage = CoverageMap::build(|c| match c {
            Channel::NetworkEgress => ChannelCoverage::Absent {
                cause: GapCause::ObserverFailed,
                detail: "capture died".into(),
            },
            _ => ChannelCoverage::Watched,
        });
        let ledger = RunLog::open().into_ledger();
        assert_eq!(
            derive(&ledger, &coverage),
            Verdict::InsufficientCoverage {
                blind_channels: vec!["network_egress".into()]
            }
        );
    }

    /// Evidence outranks blindness: a positive stands even if something else
    /// failed.
    #[test]
    fn evidence_outranks_a_blind_channel() {
        let coverage = CoverageMap::build(|c| match c {
            Channel::DnsResolution => ChannelCoverage::Absent {
                cause: GapCause::ObserverFailed,
                detail: "sink died".into(),
            },
            _ => ChannelCoverage::Watched,
        });
        let mut log = RunLog::open();
        log.note(10, Channel::NetworkEgress, exchange(), vec![hit()]);
        assert!(matches!(
            derive(&log.into_ledger(), &coverage),
            Verdict::Detonated { .. }
        ));
    }

    #[test]
    fn strength_orders_claims() {
        assert!(
            Verdict::NoFinding.strength()
                < Verdict::InsufficientCoverage {
                    blind_channels: vec![]
                }
                .strength()
        );
        assert!(
            Verdict::InsufficientCoverage {
                blind_channels: vec![]
            }
            .strength()
                < Verdict::Detonated { witnesses: vec![] }.strength()
        );
    }
}
