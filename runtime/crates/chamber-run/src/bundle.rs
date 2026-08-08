//! Turning what the run produced into a sealed, signed artefact.
//!
//! # The verdict is not decided here
//!
//! Nothing in this module chooses an outcome. It states what was *watched* and
//! hands the ledger over; `chamber-evidence` derives the verdict from those two
//! things and there is no parameter by which a caller could influence it. The
//! only leverage this module has over the result is being honest about
//! coverage — which is the whole job.
//!
//! # A dead observer cannot read as a clean run
//!
//! A ledger without its terminal marker is a truncated one, so the egress and
//! DNS channels are `Absent` with cause `ObserverFailed` — and both bear a
//! verdict, so the run reaches no conclusion. That is matrix row 5, and it
//! holds because of how coverage is computed rather than because a test
//! remembers to look for it.
//!
//! # The liveness witness is NOT smuggled through coverage
//!
//! It is tempting to make "the agent never ran" block the verdict the same way.
//! It does not, and it must not: `Channel::GuestCommand` deliberately does not
//! bear a verdict, because an agent reading a credential inside the sealed
//! guest is a read, not a departure. Marking it `ObserverFailed` to force
//! `InsufficientCoverage` would be using a channel classification to mean
//! something it does not mean, and would eventually detonate runs for the wrong
//! reason.
//!
//! What a turnless run gets instead is honest and visible: the channel is
//! recorded `Absent`, and [`ending_for`] reports [`RunEnding::AgentFailed`]
//! rather than `Completed`. The liveness assertion proper — turn count above
//! zero, a successful `GuestCommand`, the self-test passed — belongs to the
//! fixture matrix, where a `no_finding` row can fail on it.

use std::path::{Path, PathBuf};

use chamber_capture::read_ledger;
use chamber_evidence::{
    Channel, ChannelCoverage, CoverageGap, CoverageMap, GapCause, RunEnding, RunLog, RunSecret,
    Verdict, seal_run,
};

use crate::turns::TurnProvenance;

/// What became of the observer's ledger.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BoundaryState {
    /// The file carries its terminal marker: the observer finished.
    Sealed,
    /// Records are present but the marker is not. The observer was cut short,
    /// and what is in the file is a prefix of what happened.
    Truncated,
    /// No ledger at all.
    Missing,
}

/// What the run actually managed to observe.
///
/// Stated by the caller rather than inferred here, because the caller is the
/// only one that knows whether the collector started and whether the agent ever
/// ran. Guessing would produce a coverage map that flatters the run.
#[derive(Debug, Clone)]
pub struct Observed {
    pub boundary: BoundaryState,
    /// The NFLOG collector was confirmed listening.
    pub drops_collected: bool,
    /// Turns actually carried out in the cell.
    pub turns_driven: usize,
}

/// A bundle that was written.
#[derive(Debug, Clone)]
pub struct Emitted {
    pub bundle_path: PathBuf,
    pub seal_path: PathBuf,
    pub verdict: Verdict,
}

#[derive(Debug)]
pub enum EmitError {
    LedgerUnreadable { path: String, detail: String },
    NoEntropy(String),
    Write { path: String, detail: String },
}

impl std::fmt::Display for EmitError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::LedgerUnreadable { path, detail } => {
                write!(f, "cannot read the ledger at {path}: {detail}")
            }
            Self::NoEntropy(detail) => write!(
                f,
                "no run key could be minted ({detail}), so the bundle would be \
                 unsigned. Signing is fail-closed: there is no degraded mode in \
                 which an unsigned artefact is better than none"
            ),
            Self::Write { path, detail } => write!(f, "cannot write {path}: {detail}"),
        }
    }
}

impl std::error::Error for EmitError {}

/// The coverage map this run earned.
///
/// Public because it is the interesting half of bundle emission and deserves
/// to be testable without writing files.
#[must_use]
pub fn coverage_for(observed: &Observed) -> CoverageMap {
    CoverageMap::build(|channel| match channel {
        // Both come from the observer's ledger, so both stand or fall with it.
        Channel::NetworkEgress | Channel::DnsResolution => match observed.boundary {
            BoundaryState::Sealed => ChannelCoverage::Watched,
            BoundaryState::Truncated => ChannelCoverage::Absent {
                cause: GapCause::ObserverFailed,
                detail: "the ledger has no terminal marker, so the observer \
                         stopped before the run did and what is recorded is a \
                         prefix of what happened"
                    .into(),
            },
            BoundaryState::Missing => ChannelCoverage::Absent {
                cause: GapCause::ObserverFailed,
                detail: "no ledger was produced at all".into(),
            },
        },

        Channel::DroppedPackets => {
            if observed.drops_collected {
                ChannelCoverage::Watched
            } else {
                ChannelCoverage::Absent {
                    cause: GapCause::ObserverFailed,
                    detail: "the NFLOG collector was not confirmed listening, so \
                             blocked traffic was counted but never captured"
                        .into(),
                }
            }
        }

        // Recorded truthfully, and deliberately NOT load-bearing on the
        // verdict: this channel does not bear one. See the module note — the
        // signal a turnless run produces is `RunEnding::AgentFailed`, not a
        // forced `InsufficientCoverage`.
        Channel::GuestCommand => {
            if observed.turns_driven > 0 {
                ChannelCoverage::Watched
            } else {
                ChannelCoverage::Absent {
                    cause: GapCause::ObserverFailed,
                    detail: "no turn was carried out, so the agent never acted; \
                             a run in which nothing happened is not a run that \
                             found nothing"
                        .into(),
                }
            }
        }

        // Slice 0 has no inference lane: the model transport never enters the
        // guest netns. Excluded by design rather than failed, so it does not
        // block the run from concluding.
        Channel::InferenceTransport => ChannelCoverage::Absent {
            cause: GapCause::ExcludedByDesign,
            detail: "Slice 0 has no inference lane; model turns are carried by \
                     the host driver and never enter the chamber"
                .into(),
        },
    })
}

/// How the run finished, from what is actually known about it.
#[must_use]
pub fn ending_for(observed: &Observed) -> RunEnding {
    match observed.boundary {
        BoundaryState::Sealed if observed.turns_driven > 0 => RunEnding::Completed,
        BoundaryState::Sealed => RunEnding::AgentFailed,
        BoundaryState::Truncated | BoundaryState::Missing => RunEnding::ObserverLost,
    }
}

/// The permanent limits, plus any this run earned.
#[must_use]
pub fn gaps_for(provenance: &TurnProvenance) -> Vec<CoverageGap> {
    let mut gaps = chamber_evidence::gaps::slice0();

    if provenance.was_replayed() {
        // Emitted only when it applies, so a bundle that does NOT carry it is
        // saying something: a model chose those actions.
        gaps.push(CoverageGap {
            id: "gap.scripted-turns".into(),
            cause: GapCause::SpecDivergence,
            scope: "The action sequence was replayed from a checked-in script, \
                    not chosen by a model."
                .into(),
            justification: "The commands executed for real, over the real network \
                            path, through the real observer — but which commands \
                            were attempted was decided in advance. A green run \
                            says the chamber contained and observed these \
                            actions; it does not say a model would have chosen \
                            them."
                .into(),
        });
    }
    gaps
}

/// Determines whether a ledger file is sealed, truncated, or absent.
///
/// # Errors
/// [`EmitError::LedgerUnreadable`] if the file exists but cannot be read.
pub fn inspect_ledger(path: &Path) -> Result<(BoundaryState, RunLog), EmitError> {
    if !path.exists() {
        return Ok((BoundaryState::Missing, RunLog::adopt(Vec::new())));
    }
    let file = read_ledger(path).map_err(|e| EmitError::LedgerUnreadable {
        path: path.display().to_string(),
        detail: e.to_string(),
    })?;

    let state = if file.is_truncated() {
        BoundaryState::Truncated
    } else {
        BoundaryState::Sealed
    };
    Ok((state, RunLog::adopt(file.observations().to_vec())))
}

/// Writes `bundle.json` and `bundle.sig` into `dir`.
///
/// # Errors
/// [`EmitError`] if entropy is unavailable or the files cannot be written.
/// There is no path that writes an unsigned bundle.
pub fn emit(
    dir: &Path,
    log: RunLog,
    observed: &Observed,
    provenance: &TurnProvenance,
) -> Result<Emitted, EmitError> {
    let secret = RunSecret::mint().map_err(|e| EmitError::NoEntropy(e.to_string()))?;

    let (bundle, seal) = seal_run(
        log,
        ending_for(observed),
        coverage_for(observed),
        gaps_for(provenance),
        secret,
    );

    let bundle_path = dir.join("bundle.json");
    let seal_path = dir.join("bundle.sig");

    // The signed bytes, not a re-serialisation of them. Writing anything else
    // would produce a file that fails its own verification for reasons nobody
    // could diagnose from the artefact.
    std::fs::write(&bundle_path, bundle.to_canonical_bytes()).map_err(|e| EmitError::Write {
        path: bundle_path.display().to_string(),
        detail: e.to_string(),
    })?;
    std::fs::write(
        &seal_path,
        serde_json::to_vec(&seal).map_err(|e| EmitError::Write {
            path: seal_path.display().to_string(),
            detail: e.to_string(),
        })?,
    )
    .map_err(|e| EmitError::Write {
        path: seal_path.display().to_string(),
        detail: e.to_string(),
    })?;

    Ok(Emitted {
        bundle_path,
        seal_path,
        verdict: bundle.verdict().clone(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn healthy() -> Observed {
        Observed {
            boundary: BoundaryState::Sealed,
            drops_collected: true,
            turns_driven: 3,
        }
    }

    #[test]
    fn a_healthy_run_watches_every_verdict_bearing_channel() {
        let coverage = coverage_for(&healthy());
        assert!(
            coverage.blocking_absences().is_empty(),
            "{:?}",
            coverage.blocking_absences()
        );
        assert_eq!(ending_for(&healthy()), RunEnding::Completed);
    }

    /// Matrix row 5: a capture process killed mid-run must never read as a
    /// clean run. Held by how coverage is computed, not by a test remembering
    /// to look.
    #[test]
    fn a_truncated_ledger_blocks_the_run_from_concluding() {
        let observed = Observed {
            boundary: BoundaryState::Truncated,
            ..healthy()
        };
        let blocking = coverage_for(&observed).blocking_absences();
        assert!(
            blocking.iter().any(|(c, _)| *c == Channel::NetworkEgress),
            "a dead observer left egress readable as watched: {blocking:?}"
        );
        assert_eq!(ending_for(&observed), RunEnding::ObserverLost);
    }

    /// A turnless run is recorded as such, and says so through the run's
    /// ending rather than by forcing a verdict.
    ///
    /// `GuestCommand` does not bear a verdict — an agent reading a credential
    /// inside the sealed guest is a read, not a departure — so its absence
    /// correctly does not block. Making it block would be using a channel
    /// classification to mean something it does not.
    #[test]
    fn a_turnless_run_is_recorded_without_forcing_the_verdict() {
        let observed = Observed {
            turns_driven: 0,
            ..healthy()
        };
        let coverage = coverage_for(&observed);

        assert!(
            matches!(
                coverage.status(Channel::GuestCommand),
                ChannelCoverage::Absent { .. }
            ),
            "a run with no turns read as though it had watched the agent"
        );
        assert!(
            coverage.blocking_absences().is_empty(),
            "a non-verdict-bearing channel was made to block: {:?}",
            coverage.blocking_absences()
        );
        assert_eq!(
            ending_for(&observed),
            RunEnding::AgentFailed,
            "a run in which nothing happened reported as completed"
        );
    }

    /// An uncollected drop channel means blocked traffic was counted but never
    /// captured — contained, and blind.
    #[test]
    fn a_missing_collector_is_a_blocking_absence() {
        let observed = Observed {
            drops_collected: false,
            ..healthy()
        };
        assert!(
            coverage_for(&observed)
                .blocking_absences()
                .iter()
                .any(|(c, _)| *c == Channel::DroppedPackets)
        );
    }

    /// Excluded by design must not block: if it did, every run would report
    /// insufficient coverage and the distinction would be worthless.
    #[test]
    fn the_absent_inference_lane_does_not_block() {
        let coverage = coverage_for(&healthy());
        assert!(matches!(
            coverage.status(Channel::InferenceTransport),
            ChannelCoverage::Absent {
                cause: GapCause::ExcludedByDesign,
                ..
            }
        ));
        assert!(coverage.blocking_absences().is_empty());
    }

    #[test]
    fn a_scripted_run_declares_that_its_actions_were_replayed() {
        let scripted = TurnProvenance::Scripted {
            path: "t.json".into(),
            digest: "abc".into(),
        };
        assert!(
            gaps_for(&scripted)
                .iter()
                .any(|g| g.id == "gap.scripted-turns")
        );

        let live = TurnProvenance::Live {
            model: "some-model".into(),
        };
        assert!(
            !gaps_for(&live).iter().any(|g| g.id == "gap.scripted-turns"),
            "a live run declared a gap it does not have, which would make the \
             declaration meaningless"
        );
    }

    #[test]
    fn every_bundle_carries_the_permanent_limits() {
        let gaps = gaps_for(&TurnProvenance::Live { model: "m".into() });
        assert!(gaps.iter().any(|g| g.id == "gap.ledger-integrity"));
    }

    #[test]
    fn a_missing_ledger_is_missing_not_empty() {
        let (state, log) =
            inspect_ledger(Path::new("/definitely/not/here/ledger.jsonl")).expect("inspect");
        assert_eq!(state, BoundaryState::Missing);
        assert!(log.is_empty());
    }

    /// The bundle on disk must be the bytes that were signed, and must open
    /// under an independent read.
    #[test]
    fn an_emitted_bundle_verifies_against_its_own_seal() {
        let dir = std::env::temp_dir().join(format!("chamber-emit-{}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("scratch");

        let emitted = emit(
            &dir,
            RunLog::adopt(Vec::new()),
            &Observed {
                boundary: BoundaryState::Sealed,
                drops_collected: true,
                turns_driven: 1,
            },
            &TurnProvenance::Scripted {
                path: "t.json".into(),
                digest: "abc".into(),
            },
        )
        .expect("emit");

        let bytes = std::fs::read(&emitted.bundle_path).expect("read bundle");
        let seal: chamber_evidence::BundleSeal =
            serde_json::from_slice(&std::fs::read(&emitted.seal_path).expect("read seal"))
                .expect("parse seal");

        let opened = chamber_evidence::open(&bytes, &seal).expect("the bundle must open");
        assert_eq!(opened.verdict, emitted.verdict);
        assert!(opened.gaps.iter().any(|g| g.id == "gap.scripted-turns"));
    }
}
