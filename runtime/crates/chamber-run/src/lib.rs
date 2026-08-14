//! The composition root.
//!
//! Everything else in this workspace is a wall or an observer; this crate is
//! what puts them together and drives an artefact through the chamber.
//!
//! # Built so far
//!
//! - [`turns`] — where the artefact's actions come from, and the provenance
//!   stamped into the bundle so a replayed sequence never reads as a model's
//!   decisions.
//! - [`winddown`] — halt, seal, tear down, record, in that order and all four
//!   regardless of which of them failed.
//! - [`exit_code_for`] — the mapping from verdict to process exit status.
//!
//! - [`bridge`] — carrying a turn out inside the cell.
//! - [`bundle`] — coverage, gaps and the sealed artefact.
//!
//! - [`run`] — one detonation, start to finish.
//!
//! # What this crate must never do
//!
//! - **Link the proxy stack.** The artefact-facing proxy runs in a container.
//!   The dependency on `chamber-capture` is types-only
//!   (`default-features = false`), and `tests/no_proxy_stack.rs` asserts it —
//!   the wall is checked, not intended.
//! - **Emit an unsigned bundle.** Signing is fail-*closed*. This deliberately
//!   inverts the fail-open credential path it was modelled on, which was
//!   justified by a fallback the chamber does not have: there is no degraded
//!   mode in which an unsigned artefact is better than none.
//! - **Return `Ok` from the wind-down.** The wind-down reports what it managed
//!   to do; a caller that cannot tell a complete seal from a partial one will
//!   report the partial one as complete.
//! - **Proceed when the host cannot host a chamber.** If egress denial cannot
//!   be enforced, there is no run to have.
//! - **Default to a live model in a test profile.** A test that quietly reaches
//!   a model is a test that costs money and fails for reasons unrelated to the
//!   code under test.

pub mod bridge;
pub mod bundle;
pub mod corpus;
pub mod dependency;
pub mod differential;
pub mod floor;
pub mod integrity;
pub mod judge;
pub mod liveturns;
pub mod metamorphic;
pub mod probe;
pub mod run;
pub mod staging;
pub mod supervisor;
pub mod turns;
pub mod winddown;
pub mod worksnapshot;

pub use bridge::{CarriedTurn, ToolBridge, TurnTarget};
pub use bundle::{BoundaryState, Emitted, ExecInterception, Observed, emit};
pub use corpus::{CorpusCell, CorpusManifest, corpus_dir, load_manifests};
pub use dependency::{
    InstallAttempt, install_attempts, install_attempts_from, unrequested_installs,
};
pub use differential::{
    ArmActivity, ArmClass, ArmDriverFactory, ArmOutcome, ArmReading, ArmRole, ArmSpec, ArmWitness,
    ArtefactRef, BatteryTask, CanaryTemplate, Crossing, DiffVerdict, Differential,
    DifferentialBundle, DifferentialPlan, DifferentialRefusal, EntropyLead, RecheckRefusal,
    RequestShape, ShapeLead, ShapeReport, activity_of, arm_activity, arm_turn_dump_path, diff_arms,
    entropy_leads, open_arm, recheck_differential, run_differential, shannon_entropy_bits_per_byte,
    shape_gaps, shape_leads,
};
pub use floor::{FloorVerdict, floor_verdict, metamorphic_layer, supervise};
pub use integrity::{
    AnswerUnderTest, Claim, GoldenSpec, IntegrityFinding, Jury, JuryBrief, JuryVerdict,
    OracleReading, PanelReading, Requirement, cross_reference_reading, filesystem_reading, gate,
    golden_reading, jury_reading, metamorphic_consistency_reading, panel, written_content_reading,
};
pub use judge::{
    DEFAULT_PANEL, PolicyBrief, PolicyJudge, brief_from_shapes, judge_panel, policy_reading,
    redacted_shape,
};
pub use liveturns::{
    AgentBrief, AgentPrompt, Budget, BudgetRefusal, Exchange, InferenceRecord, LiveTurns, Model,
    ModelChoice, ModelError, ModelReply, record_inference_calls,
};
pub use metamorphic::{MetamorphicArm, MetamorphicLead, metamorphic_leads};
pub use probe::{MIN_ARMS, ProbeArm, ProbeOutcome, ProbePlan, ProbeRefusal, arm_label, run_probe};
pub use run::{
    ArmingRefusal, DetonationPlan, EXEC_RELAY_GUEST_IMAGE, ImageTags, PlantedCanary, RunEpilogue,
    run_detonation,
};
pub use staging::{CellFiles, StagingError, skill_dir_beside, stage_skill_dir};
pub use supervisor::{Supervision, SupervisorConfig, supervise_run};
pub use turns::{
    CellOutput, ScriptedTurns, Transcript, TurnDirective, TurnError, TurnProvenance, TurnRecord,
    TurnSource,
};
pub use winddown::wind_down;
pub use worksnapshot::{
    CellInspect, WorkDiff, WorkSnapshot, digest_tree_script, read_changed, read_file_script,
    snapshot,
};

use chamber_evidence::Verdict;

/// The process exit status a verdict maps to.
///
/// Distinct values, because the caller of a detonation is usually a pipeline
/// and the three outcomes need different responses:
///
/// | code | verdict | what it means |
/// |---|---|---|
/// | 2 | `Detonated` | a planted token crossed the boundary |
/// | 1 | `InsufficientCoverage` | the run reached no conclusion |
/// | 0 | `NoFinding` | nothing was seen crossing the channels that were watched |
///
/// **Zero is not a pass.** It says nothing was observed on the channels that
/// were watched, which is a much narrower claim than the absence of a problem —
/// and the bundle beside it lists what was not watched at all. `1` is
/// deliberately not folded into `0`: a run that reached no conclusion and a run
/// that concluded nothing were seen are different, and the whole design fails
/// the moment those are treated as the same.
#[must_use]
pub fn exit_code_for(verdict: &Verdict) -> i32 {
    match verdict {
        Verdict::Detonated { .. } => 2,
        Verdict::InsufficientCoverage { .. } => 1,
        Verdict::NoFinding => 0,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chamber_evidence::Ordinal;

    #[test]
    fn each_verdict_maps_to_its_own_code() {
        assert_eq!(
            exit_code_for(&Verdict::Detonated {
                witnesses: vec![Ordinal(0)]
            }),
            2
        );
        assert_eq!(
            exit_code_for(&Verdict::InsufficientCoverage {
                blind_channels: vec!["network_egress".into()]
            }),
            1
        );
        assert_eq!(exit_code_for(&Verdict::NoFinding), 0);
    }

    /// The collapse that would make the tool useless: a run that reached no
    /// conclusion exiting the same as one that concluded nothing was seen.
    #[test]
    fn insufficient_coverage_never_exits_like_no_finding() {
        let blind = exit_code_for(&Verdict::InsufficientCoverage {
            blind_channels: vec!["network_egress".into()],
        });
        assert_ne!(blind, exit_code_for(&Verdict::NoFinding));
        assert_ne!(
            blind,
            exit_code_for(&Verdict::Detonated {
                witnesses: vec![Ordinal(0)]
            })
        );
    }

    /// A detonation must be loud to anything reading exit codes, which is most
    /// pipelines.
    #[test]
    fn a_detonation_is_non_zero() {
        assert_ne!(
            exit_code_for(&Verdict::Detonated {
                witnesses: vec![Ordinal(3)]
            }),
            0
        );
    }
}
