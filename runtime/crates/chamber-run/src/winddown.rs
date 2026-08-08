//! Halt, seal, tear down, record — in that order, and all four regardless.
//!
//! # Why a failed stage does not stop the sequence
//!
//! The obvious shape for this is `halt().await?; seal().await?; …`, and it is
//! wrong. The `?` abandons the remaining stages, and the stage most likely to
//! be abandoned is the one whose omission loses the entire run: the seal. A
//! guest that will not stop is a nuisance; a guest that will not stop *and*
//! takes the evidence with it is a run that produced nothing.
//!
//! So every stage runs, each under its own ceiling and the remaining window,
//! and each outcome is recorded. A stage that fails is a fact about the run,
//! not a reason to stop having a run.
//!
//! # This function does not return `Ok`
//!
//! There is no success value, deliberately. A wind-down that returned
//! `Result<(), E>` would let a caller write `wind_down().await?` and carry on
//! believing everything happened, when what actually happened is in the trace.
//! The trace is the only output, and a caller that wants to know whether the
//! evidence survived has to ask [`chamber_deadline::StageTrace::evidence_was_sealed`].

use std::future::Future;

use chamber_deadline::{
    AGENT_HALT_CAP, BOUNDARY_SEAL_CAP, RUN_RECORD_CAP, SANDBOX_TEARDOWN_CAP, Stage, StageTrace,
    WindDown, Window,
};

/// Runs the four stages, writing what happened into `trace`.
///
/// Each closure reports its own failure as a string; the sequence carries on
/// either way. Returns nothing — see the module note.
pub async fn wind_down<FH, FS, FT, FR>(
    window: Window,
    trace: &mut StageTrace,
    halt: FH,
    seal: FS,
    teardown: FT,
    record: FR,
) where
    FH: Future<Output = Result<(), String>>,
    FS: Future<Output = Result<(), String>>,
    FT: Future<Output = Result<(), String>>,
    FR: Future<Output = Result<(), String>>,
{
    let mut wd = WindDown::new(window, trace);

    // The order is Stage::SEQUENCE and is not a matter of taste. Halting first
    // is what stops the artefact acting while its evidence is being collected;
    // sealing before teardown is what stops the teardown taking the ledger with
    // it.
    wd.step(Stage::AgentHalt, AGENT_HALT_CAP, halt).await;
    wd.step(Stage::BoundarySeal, BOUNDARY_SEAL_CAP, seal).await;
    wd.step(Stage::SandboxTeardown, SANDBOX_TEARDOWN_CAP, teardown)
        .await;
    wd.step(Stage::RunRecord, RUN_RECORD_CAP, record).await;
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    async fn fine() -> Result<(), String> {
        Ok(())
    }

    async fn broken(what: &str) -> Result<(), String> {
        Err(what.to_owned())
    }

    #[tokio::test(start_paused = true)]
    async fn a_clean_wind_down_visits_every_stage_in_order() {
        let mut trace = StageTrace::new();
        wind_down(
            Window::standard(),
            &mut trace,
            fine(),
            fine(),
            fine(),
            fine(),
        )
        .await;

        assert_eq!(trace.visited(), Stage::SEQUENCE.to_vec());
        assert!(trace.evidence_was_sealed());
    }

    /// The property the whole module exists for. A `?` after the halt would
    /// skip the seal, and the run would produce nothing.
    #[tokio::test(start_paused = true)]
    async fn a_failed_halt_does_not_skip_the_seal() {
        let mut trace = StageTrace::new();
        wind_down(
            Window::standard(),
            &mut trace,
            broken("the guest would not stop"),
            fine(),
            fine(),
            fine(),
        )
        .await;

        assert!(
            trace.evidence_was_sealed(),
            "a guest that would not halt took the evidence with it: {:?}",
            trace.entries()
        );
        assert_eq!(trace.visited(), Stage::SEQUENCE.to_vec());
    }

    /// A teardown that fails leaves containers behind, which is a mess. A
    /// teardown that fails and stops the run from being recorded leaves a mess
    /// nobody can find out about.
    #[tokio::test(start_paused = true)]
    async fn a_failed_teardown_still_records_the_run() {
        let mut trace = StageTrace::new();
        wind_down(
            Window::standard(),
            &mut trace,
            fine(),
            fine(),
            broken("the cell is still up"),
            fine(),
        )
        .await;

        assert!(trace.completed(Stage::RunRecord));
        assert!(trace.evidence_was_sealed());
    }

    /// Every stage is attempted exactly once, even when all four fail. A retry
    /// hidden in here would spend a window that the seal needs.
    #[tokio::test(start_paused = true)]
    async fn every_stage_is_attempted_once_even_when_all_fail() {
        static CALLS: AtomicUsize = AtomicUsize::new(0);

        async fn counted() -> Result<(), String> {
            CALLS.fetch_add(1, Ordering::SeqCst);
            Err("no".into())
        }

        let mut trace = StageTrace::new();
        wind_down(
            Window::standard(),
            &mut trace,
            counted(),
            counted(),
            counted(),
            counted(),
        )
        .await;

        assert_eq!(CALLS.load(Ordering::SeqCst), 4);
        assert_eq!(trace.entries().len(), 4);
        assert!(!trace.evidence_was_sealed());
    }

    /// A window that is already gone must still leave a legible record. The
    /// difference between "we got as far as sealing" and "nothing happened" is
    /// the whole reason the trace exists.
    #[tokio::test(start_paused = true)]
    async fn an_exhausted_window_records_what_it_could_not_do() {
        let mut trace = StageTrace::new();
        wind_down(
            Window::opening_now(std::time::Duration::ZERO),
            &mut trace,
            fine(),
            fine(),
            fine(),
            fine(),
        )
        .await;

        assert_eq!(
            trace.entries().len(),
            4,
            "stages vanished instead of being recorded"
        );
        assert!(
            !trace.evidence_was_sealed(),
            "an exhausted window reported a seal that never happened"
        );
    }
}
