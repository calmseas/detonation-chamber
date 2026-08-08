//! The wind-down window for a detonation run.
//!
//! When a run ends — cleanly, on a deadline, or because something failed — four
//! things must happen in order, and the middle one is the reason this crate
//! exists:
//!
//! 1. stop the agent,
//! 2. **seal the captured evidence**,
//! 3. tear the guest down,
//! 4. record how the run ended.
//!
//! Skip step 2 and the run produced nothing, however tidily the rest went.
//! Steps 3 and 4 are housekeeping; step 1 exists to make step 2 trustworthy.
//! So the window has to be spent in a way that arrives at the seal even when
//! stopping the agent takes longer than it should.
//!
//! # The trace belongs to the caller
//!
//! [`StageTrace`] is passed in by reference and never returned. That is
//! deliberate and it is the crate's main structural claim.
//!
//! The obvious design — an async routine that runs the sequence and returns a
//! report — loses everything the moment an outer timeout fires, because
//! cancelling a future drops whatever it had built up. The caller is then
//! handed an empty report, which is indistinguishable from a run where nothing
//! happened. In this system that distinction is the whole game: "we sealed the
//! evidence and then ran out of time" and "we never got there" must not arrive
//! looking the same, or a truncated run reads as a clean one.
//!
//! Because the trace lives on the caller's stack, a dropped future leaves it
//! intact and partially filled, which is exactly the honest answer.
//!
//! # Budgets
//!
//! The numbers below belong to this crate and are chosen by one rule: we must
//! be finished and out before the container runtime gives up waiting and
//! terminates us, since a process cut off partway through writing its bundle
//! leaves a truncated file behind. The relationships between the numbers are
//! asserted at compile time, so adjusting one in isolation fails the build
//! rather than a test.

use std::future::Future;
use std::time::Duration;

use tokio::time::Instant;

/// What we ask the container runtime to wait before killing us.
const STOP_GRACE_MS: u64 = 20_000;
/// Our own budget for the whole wind-down. Must land clear of the kill.
const WIND_DOWN_BUDGET_MS: u64 = 15_000;

const AGENT_HALT_MS: u64 = 3_000;
const BOUNDARY_SEAL_MS: u64 = 6_000;
const SANDBOX_TEARDOWN_MS: u64 = 4_000;
const RUN_RECORD_MS: u64 = 2_000;

/// The grace period to request from the container runtime.
pub const STOP_GRACE: Duration = Duration::from_millis(STOP_GRACE_MS);
/// The whole wind-down budget, every stage included.
pub const WIND_DOWN_BUDGET: Duration = Duration::from_millis(WIND_DOWN_BUDGET_MS);

/// Per-stage ceilings. A stage may finish sooner; it may not run longer.
pub const AGENT_HALT_CAP: Duration = Duration::from_millis(AGENT_HALT_MS);
pub const BOUNDARY_SEAL_CAP: Duration = Duration::from_millis(BOUNDARY_SEAL_MS);
pub const SANDBOX_TEARDOWN_CAP: Duration = Duration::from_millis(SANDBOX_TEARDOWN_MS);
pub const RUN_RECORD_CAP: Duration = Duration::from_millis(RUN_RECORD_MS);

// If the caps could exceed the budget, a run could be killed mid-seal while
// every individual stage was still "within its limit".
const _: () = assert!(
    AGENT_HALT_MS + BOUNDARY_SEAL_MS + SANDBOX_TEARDOWN_MS + RUN_RECORD_MS <= WIND_DOWN_BUDGET_MS,
    "stage caps must fit inside the wind-down budget"
);

// The margin is what buys an orderly exit instead of a SIGKILL landing in the
// middle of writing the bundle.
const _: () = assert!(
    WIND_DOWN_BUDGET_MS < STOP_GRACE_MS,
    "the wind-down budget must finish before the runtime's kill"
);

// Sealing is the step whose omission loses the run, so it gets the largest
// share. Stated as an assert rather than a comment so a future retune that
// starves it fails the build.
const _: () = assert!(
    BOUNDARY_SEAL_MS >= AGENT_HALT_MS
        && BOUNDARY_SEAL_MS >= SANDBOX_TEARDOWN_MS
        && BOUNDARY_SEAL_MS >= RUN_RECORD_MS,
    "sealing the evidence must not be the tightest stage"
);

/// One authoritative deadline for a wind-down.
#[derive(Clone, Copy, Debug)]
pub struct Window {
    deadline: Instant,
}

impl Window {
    /// Open a window that closes `total` from now.
    pub fn opening_now(total: Duration) -> Self {
        Self {
            deadline: Instant::now() + total,
        }
    }

    /// Open the standard window.
    pub fn standard() -> Self {
        Self::opening_now(WIND_DOWN_BUDGET)
    }

    /// Time left, floored at zero.
    ///
    /// The guarantee callers rely on is that past the deadline this is `ZERO` —
    /// never a large duration — because [`Window::allot`] would otherwise hand
    /// a stage an effectively unbounded budget at exactly the moment the run is
    /// already late. `saturating_duration_since` is the direct way to say so;
    /// on current Rust the plain subtraction happens to saturate too, so the
    /// choice of call is not what carries the property. The test does:
    /// `past_the_deadline_the_allotment_is_zero_not_underflowed` fails against
    /// any implementation that returns something large here.
    pub fn remaining(&self) -> Duration {
        self.deadline.saturating_duration_since(Instant::now())
    }

    /// What a stage may actually have: its ceiling, or what is left.
    ///
    /// A stage that overruns therefore shrinks the stages after it rather than
    /// pushing the whole sequence past the deadline.
    pub fn allot(&self, cap: Duration) -> Duration {
        cap.min(self.remaining())
    }

    pub fn expired(&self) -> bool {
        self.remaining().is_zero()
    }
}

/// A step in the wind-down, in the order it must happen.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub enum Stage {
    /// Stop the agent so it cannot act while we are collecting.
    AgentHalt,
    /// Seal the captured evidence. The step whose omission loses the run.
    BoundarySeal,
    /// Destroy the guest.
    SandboxTeardown,
    /// Record how the run ended.
    RunRecord,
}

impl Stage {
    /// The required order.
    pub const SEQUENCE: &'static [Stage] = &[
        Stage::AgentHalt,
        Stage::BoundarySeal,
        Stage::SandboxTeardown,
        Stage::RunRecord,
    ];

    /// Stable identifier for the run record. Pinned by test.
    pub fn wire_tag(self) -> &'static str {
        match self {
            Stage::AgentHalt => "agent_halt",
            Stage::BoundarySeal => "boundary_seal",
            Stage::SandboxTeardown => "sandbox_teardown",
            Stage::RunRecord => "run_record",
        }
    }
}

/// How a stage ended.
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum StageOutcome {
    Completed,
    /// The stage ran and reported a problem. Recorded, and the sequence
    /// carries on regardless: one stage going wrong is not a reason to
    /// abandon the remaining ones, the seal above all.
    Failed(String),
    /// The stage ran out of its allotted time.
    TimedOut,
    /// The window closed before this stage could start.
    WindowExhausted,
}

impl StageOutcome {
    pub fn wire_tag(&self) -> &'static str {
        match self {
            StageOutcome::Completed => "completed",
            StageOutcome::Failed(_) => "failed",
            StageOutcome::TimedOut => "timed_out",
            StageOutcome::WindowExhausted => "window_exhausted",
        }
    }
}

/// What the wind-down actually managed to do.
///
/// Lives on the caller's stack. A cancelled wind-down leaves this partially
/// filled rather than empty, which is the difference between "we got as far as
/// sealing" and "nothing happened".
#[derive(Clone, Default, PartialEq, Eq, Debug)]
pub struct StageTrace {
    entries: Vec<(Stage, StageOutcome)>,
}

impl StageTrace {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn entries(&self) -> &[(Stage, StageOutcome)] {
        &self.entries
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// The stages visited, in order.
    pub fn visited(&self) -> Vec<Stage> {
        self.entries.iter().map(|(s, _)| *s).collect()
    }

    pub fn outcome_of(&self, stage: Stage) -> Option<&StageOutcome> {
        self.entries
            .iter()
            .find(|(s, _)| *s == stage)
            .map(|(_, o)| o)
    }

    /// Did this stage finish cleanly?
    pub fn completed(&self, stage: Stage) -> bool {
        matches!(self.outcome_of(stage), Some(StageOutcome::Completed))
    }

    /// Was the evidence sealed?
    ///
    /// The single question a caller most often needs answered, given its own
    /// name so nobody has to reconstruct it from the entry list and get it
    /// subtly wrong.
    pub fn evidence_was_sealed(&self) -> bool {
        self.completed(Stage::BoundarySeal)
    }

    fn record(&mut self, stage: Stage, outcome: StageOutcome) {
        self.entries.push((stage, outcome));
    }
}

/// Drives the wind-down sequence against one window, writing into a trace the
/// caller owns.
pub struct WindDown<'a> {
    window: Window,
    trace: &'a mut StageTrace,
}

impl<'a> WindDown<'a> {
    pub fn new(window: Window, trace: &'a mut StageTrace) -> Self {
        Self { window, trace }
    }

    pub fn window(&self) -> Window {
        self.window
    }

    /// Run one stage under its ceiling and the remaining window.
    ///
    /// Returns the stage's value on success and `None` otherwise. A `None`
    /// never means "stop": the caller runs the next stage regardless, because
    /// the sequence exists to reach the seal and a failed teardown is not a
    /// reason to skip recording what happened.
    pub async fn step<F, T, E>(&mut self, stage: Stage, cap: Duration, work: F) -> Option<T>
    where
        F: Future<Output = Result<T, E>>,
        E: std::fmt::Display,
    {
        if self.window.expired() {
            self.trace.record(stage, StageOutcome::WindowExhausted);
            return None;
        }

        match tokio::time::timeout(self.window.allot(cap), work).await {
            Ok(Ok(value)) => {
                self.trace.record(stage, StageOutcome::Completed);
                Some(value)
            }
            Ok(Err(e)) => {
                self.trace
                    .record(stage, StageOutcome::Failed(e.to_string()));
                None
            }
            Err(_) => {
                self.trace.record(stage, StageOutcome::TimedOut);
                None
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    type Fallible = Result<(), std::io::Error>;

    fn failure(msg: &str) -> Fallible {
        Err(std::io::Error::other(msg.to_owned()))
    }

    #[tokio::test(start_paused = true)]
    async fn a_clean_run_visits_every_stage_in_order() {
        let mut trace = StageTrace::new();
        let mut wd = WindDown::new(Window::standard(), &mut trace);

        for &stage in Stage::SEQUENCE {
            wd.step(stage, AGENT_HALT_CAP, async { Ok::<_, std::io::Error>(()) })
                .await;
        }

        assert_eq!(trace.visited(), Stage::SEQUENCE.to_vec());
        assert!(trace.evidence_was_sealed());
    }

    /// A stage that overruns must eat into what follows rather than pushing the
    /// sequence past the deadline.
    #[tokio::test(start_paused = true)]
    async fn an_overrunning_stage_shrinks_the_ones_after_it() {
        let window = Window::opening_now(Duration::from_secs(10));

        tokio::time::sleep(Duration::from_secs(8)).await;

        // Two seconds left, so a six-second ceiling is not what the stage gets.
        assert_eq!(window.remaining(), Duration::from_secs(2));
        assert_eq!(window.allot(BOUNDARY_SEAL_CAP), Duration::from_secs(2));
        // A ceiling below the remainder is still the ceiling.
        assert_eq!(
            window.allot(Duration::from_millis(500)),
            Duration::from_millis(500)
        );
    }

    /// Past the deadline the answer is zero, never a wrapped enormous duration
    /// that would hand a late stage an unbounded budget.
    #[tokio::test(start_paused = true)]
    async fn past_the_deadline_the_allotment_is_zero_not_underflowed() {
        let window = Window::opening_now(Duration::from_secs(1));
        tokio::time::sleep(Duration::from_secs(5)).await;

        assert!(window.expired());
        assert_eq!(window.remaining(), Duration::ZERO);
        assert_eq!(window.allot(BOUNDARY_SEAL_CAP), Duration::ZERO);
    }

    /// Run the whole sequence against a window, with a first stage that hangs.
    async fn run_sequence_with_a_hanging_halt(window: Duration, trace: &mut StageTrace) {
        let mut wd = WindDown::new(Window::opening_now(window), trace);

        wd.step(Stage::AgentHalt, AGENT_HALT_CAP, async {
            tokio::time::sleep(Duration::from_secs(30)).await;
            Ok::<_, std::io::Error>(())
        })
        .await;

        for &stage in &Stage::SEQUENCE[1..] {
            wd.step(stage, BOUNDARY_SEAL_CAP, async {
                Ok::<_, std::io::Error>(())
            })
            .await;
        }
    }

    /// The point of capping each stage: an agent that will not stop costs us
    /// its own three seconds and no more, and the evidence is still sealed.
    #[tokio::test(start_paused = true)]
    async fn a_hanging_agent_does_not_cost_us_the_seal() {
        let mut trace = StageTrace::new();
        // Comfortably more than the halt cap, so time remains afterwards.
        run_sequence_with_a_hanging_halt(Duration::from_secs(10), &mut trace).await;

        assert_eq!(
            trace.outcome_of(Stage::AgentHalt),
            Some(&StageOutcome::TimedOut)
        );
        assert!(
            trace.evidence_was_sealed(),
            "the halt cap exists precisely so the seal still happens: {trace:?}"
        );
    }

    /// When the window really is gone, the record says so rather than going
    /// quiet. Silence would read as "did not happen" when the truth is "was
    /// never given the chance" — and a run that never sealed must not be
    /// mistakable for one that found nothing.
    #[tokio::test(start_paused = true)]
    async fn stages_after_the_window_closes_are_recorded_not_omitted() {
        let mut trace = StageTrace::new();
        // Exactly the halt cap, so the hang consumes the entire window.
        run_sequence_with_a_hanging_halt(AGENT_HALT_CAP, &mut trace).await;

        assert_eq!(trace.visited(), Stage::SEQUENCE.to_vec());
        assert_eq!(
            trace.outcome_of(Stage::AgentHalt),
            Some(&StageOutcome::TimedOut)
        );
        assert_eq!(
            trace.outcome_of(Stage::BoundarySeal),
            Some(&StageOutcome::WindowExhausted)
        );
        assert_eq!(
            trace.outcome_of(Stage::RunRecord),
            Some(&StageOutcome::WindowExhausted)
        );
        assert!(!trace.evidence_was_sealed());
    }

    /// The crate's main structural claim: cancelling the wind-down does not
    /// take the record with it.
    #[tokio::test(start_paused = true)]
    async fn a_cancelled_wind_down_leaves_the_trace_intact() {
        let mut trace = StageTrace::new();

        {
            let mut wd = WindDown::new(Window::standard(), &mut trace);
            // An outer timeout that fires mid-sequence, dropping the future.
            let _ = tokio::time::timeout(Duration::from_secs(2), async {
                wd.step(Stage::AgentHalt, AGENT_HALT_CAP, async {
                    Ok::<_, std::io::Error>(())
                })
                .await;
                wd.step(Stage::BoundarySeal, BOUNDARY_SEAL_CAP, async {
                    Ok::<_, std::io::Error>(())
                })
                .await;
                // Never reached: outlives the outer timeout.
                wd.step(Stage::SandboxTeardown, SANDBOX_TEARDOWN_CAP, async {
                    tokio::time::sleep(Duration::from_secs(30)).await;
                    Ok::<_, std::io::Error>(())
                })
                .await;
            })
            .await;
        }

        // An empty trace here would be indistinguishable from a run in which
        // nothing happened at all. It is not empty, and it says the evidence
        // was sealed before the cancellation.
        assert!(
            !trace.is_empty(),
            "a dropped future must not take the record with it"
        );
        assert!(trace.evidence_was_sealed());
        assert_eq!(trace.visited(), vec![Stage::AgentHalt, Stage::BoundarySeal]);
    }

    /// A failure must not cost us the stages after it — least of all the seal.
    #[tokio::test(start_paused = true)]
    async fn a_failing_stage_does_not_skip_the_seal() {
        let mut trace = StageTrace::new();
        let mut wd = WindDown::new(Window::standard(), &mut trace);

        wd.step(Stage::AgentHalt, AGENT_HALT_CAP, async {
            failure("agent would not stop")
        })
        .await;
        wd.step(Stage::BoundarySeal, BOUNDARY_SEAL_CAP, async {
            Ok::<_, std::io::Error>(())
        })
        .await;

        assert_eq!(
            trace.outcome_of(Stage::AgentHalt),
            Some(&StageOutcome::Failed("agent would not stop".into()))
        );
        assert!(trace.evidence_was_sealed());
    }

    #[test]
    fn wire_tags_are_pinned() {
        let tags: Vec<_> = Stage::SEQUENCE.iter().map(|s| s.wire_tag()).collect();
        assert_eq!(
            tags,
            vec![
                "agent_halt",
                "boundary_seal",
                "sandbox_teardown",
                "run_record"
            ]
        );
        assert_eq!(StageOutcome::Completed.wire_tag(), "completed");
        assert_eq!(StageOutcome::Failed(String::new()).wire_tag(), "failed");
        assert_eq!(StageOutcome::TimedOut.wire_tag(), "timed_out");
        assert_eq!(StageOutcome::WindowExhausted.wire_tag(), "window_exhausted");
    }

    /// The budget relationships are compile-time asserts; this pins the shape
    /// a reader would otherwise have to infer from four constants.
    #[test]
    fn the_budget_leaves_room_before_the_kill() {
        let caps = AGENT_HALT_CAP + BOUNDARY_SEAL_CAP + SANDBOX_TEARDOWN_CAP + RUN_RECORD_CAP;
        assert!(caps <= WIND_DOWN_BUDGET);
        assert!(WIND_DOWN_BUDGET < STOP_GRACE);
        assert!(BOUNDARY_SEAL_CAP >= AGENT_HALT_CAP);
    }
}
