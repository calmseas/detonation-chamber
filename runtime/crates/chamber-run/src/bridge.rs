//! Carrying out a turn inside the cell.
//!
//! # The commands are real
//!
//! What a scripted run stubs is *which* command was chosen. The command itself
//! executes for real in the guest, over the real network path, through the real
//! observer. This module is that seam, and it is deliberately thin: anything
//! clever here would be a second place where a run's behaviour is decided, and
//! the bundle would then describe something that did not quite happen.
//!
//! # A non-zero exit is an observation
//!
//! A command that fails is a thing the artefact did, not an error in the
//! harness. Raising on it would abandon a run at exactly the moment the
//! artefact started doing something unusual.

use std::time::Duration;

use chamber_isolation::{AgentCell, CellError, ExecOutcome};

use crate::turns::{TurnDirective, TurnRecord};

/// How long any single turn may take.
///
/// A turn that outlives this is stopped and recorded as such. The artefact is
/// hostile by assumption; a command that never returns is one of the cheapest
/// ways to deny a run its wind-down, and the wind-down is where the evidence is
/// sealed.
pub const TURN_WINDOW: Duration = Duration::from_secs(60);

/// Somewhere a turn can be carried out.
///
/// A trait rather than a concrete cell, so the driver's behaviour — what it
/// does with a failing command, a timeout, a `Conclude` — is testable without a
/// Linux guest. The production implementation is [`AgentCell`].
pub trait TurnTarget {
    /// # Errors
    /// Only when the command could not be run at all. A non-zero exit is a
    /// value, not an error.
    fn run(&self, argv: &[&str], within: Duration) -> Result<ExecOutcome, CellError>;
}

impl TurnTarget for AgentCell {
    fn run(&self, argv: &[&str], within: Duration) -> Result<ExecOutcome, CellError> {
        self.exec(argv, within)
    }
}

/// Everything the cell returned for one turn, output included.
///
/// The bridge always sees the output in full — the command ran here, so there
/// is no version of this module that does not hold it for a moment. What is
/// deliberate is where it goes next: [`Self::record`] is the length-only view
/// that enters the [`Transcript`](crate::turns::Transcript) and, through it,
/// the bundle; [`Self::stdout`] is handed to a live driver to choose its next
/// action and dropped when that prompt is built.
///
/// A scripted run never asks for it. That is why [`ToolBridge::carry_out`] —
/// the shorter name and the one Slice 0 uses throughout — is the path that
/// drops the output, and seeing it requires saying so.
#[derive(Clone, Debug)]
pub struct CarriedTurn {
    record: TurnRecord,
    stdout: String,
    stderr: String,
}

impl CarriedTurn {
    /// The length-only account of the turn, for the transcript.
    #[must_use]
    pub fn record(&self) -> &TurnRecord {
        &self.record
    }

    #[must_use]
    pub fn into_record(self) -> TurnRecord {
        self.record
    }

    /// What the command printed, raw and unscanned.
    #[must_use]
    pub fn stdout(&self) -> &str {
        &self.stdout
    }

    #[must_use]
    pub fn stderr(&self) -> &str {
        &self.stderr
    }
}

/// Carries directives out against a cell.
#[derive(Debug)]
pub struct ToolBridge {
    window: Duration,
}

impl Default for ToolBridge {
    fn default() -> Self {
        Self::new()
    }
}

impl ToolBridge {
    #[must_use]
    pub fn new() -> Self {
        Self {
            window: TURN_WINDOW,
        }
    }

    #[must_use]
    pub fn within(window: Duration) -> Self {
        Self { window }
    }

    /// Carries out one directive, returning what happened.
    ///
    /// [`TurnDirective::Conclude`] does nothing and reports success: it is the
    /// artefact saying it is finished, not an action.
    ///
    /// # Errors
    /// [`CellError`] only when the cell could not be driven at all — the engine
    /// refused, or the command outlived its window. What the command *did* is
    /// in the returned record.
    pub fn carry_out(
        &self,
        target: &impl TurnTarget,
        directive: &TurnDirective,
    ) -> Result<TurnRecord, CellError> {
        self.carry_out_observed(target, directive)
            .map(CarriedTurn::into_record)
    }

    /// The same, keeping what the command printed.
    ///
    /// A live driver has to know what its last action returned to choose the
    /// next one; a replay does not, and asking for the output it will not read
    /// would put an unscanned copy of the artefact's output somewhere it is
    /// never used. So this is the opt-in path and [`Self::carry_out`] is the
    /// default, rather than the other way round.
    ///
    /// # Errors
    /// [`CellError`] under exactly the conditions [`Self::carry_out`] raises
    /// it — this is that function, before the output is dropped.
    pub fn carry_out_observed(
        &self,
        target: &impl TurnTarget,
        directive: &TurnDirective,
    ) -> Result<CarriedTurn, CellError> {
        let outcome = match directive {
            TurnDirective::RunCommand { argv } => {
                let borrowed: Vec<&str> = argv.iter().map(String::as_str).collect();
                Some(target.run(&borrowed, self.window)?)
            }
            // `cat`, not a bespoke read path. The artefact reading a file is a
            // command like any other, and routing it differently would make the
            // ledger's account of the run depend on which directive the script
            // happened to use.
            TurnDirective::ReadFile { at } => {
                let path = at.display().to_string();
                Some(target.run(&["cat", &path], self.window)?)
            }
            TurnDirective::Conclude => None,
        };

        Ok(match outcome {
            Some(outcome) => CarriedTurn {
                record: TurnRecord {
                    directive: directive.clone(),
                    exit_code: outcome.status,
                    output_len: outcome.stdout.len(),
                },
                stdout: outcome.stdout,
                stderr: outcome.stderr,
            },
            // Concluding runs nothing, so there is nothing to have printed.
            None => CarriedTurn {
                record: TurnRecord {
                    directive: directive.clone(),
                    exit_code: Some(0),
                    output_len: 0,
                },
                stdout: String::new(),
                stderr: String::new(),
            },
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::RefCell;
    use std::path::PathBuf;

    /// Records what it was asked to run, and answers with whatever it was told.
    #[derive(Default)]
    struct FakeCell {
        seen: RefCell<Vec<Vec<String>>>,
        answer: Option<ExecOutcome>,
        refuse: bool,
    }

    impl TurnTarget for FakeCell {
        fn run(&self, argv: &[&str], _within: Duration) -> Result<ExecOutcome, CellError> {
            self.seen
                .borrow_mut()
                .push(argv.iter().map(|s| (*s).to_owned()).collect());
            if self.refuse {
                return Err(CellError::RulesetUnreadable {
                    path: "n/a".into(),
                    detail: "the engine refused".into(),
                });
            }
            Ok(self.answer.clone().unwrap_or(ExecOutcome {
                status: Some(0),
                stdout: String::new(),
                stderr: String::new(),
            }))
        }
    }

    #[test]
    fn a_command_is_run_verbatim() {
        let cell = FakeCell::default();
        let record = ToolBridge::new()
            .carry_out(
                &cell,
                &TurnDirective::RunCommand {
                    argv: vec!["curl".into(), "-d".into(), "@/work/.env".into()],
                },
            )
            .expect("carry out");

        assert_eq!(
            cell.seen.borrow()[0],
            vec!["curl".to_owned(), "-d".into(), "@/work/.env".into()]
        );
        assert_eq!(record.exit_code, Some(0));
    }

    #[test]
    fn reading_a_file_goes_through_the_same_path_as_any_command() {
        let cell = FakeCell::default();
        ToolBridge::new()
            .carry_out(
                &cell,
                &TurnDirective::ReadFile {
                    at: PathBuf::from("/work/.env"),
                },
            )
            .expect("carry out");

        assert_eq!(
            cell.seen.borrow()[0],
            vec!["cat".to_owned(), "/work/.env".into()]
        );
    }

    /// The property that keeps a run alive through the interesting part. A
    /// command failing is something the artefact did.
    #[test]
    fn a_failing_command_is_recorded_not_raised() {
        let cell = FakeCell {
            answer: Some(ExecOutcome {
                status: Some(7),
                stdout: "nope".into(),
                stderr: String::new(),
            }),
            ..FakeCell::default()
        };

        let record = ToolBridge::new()
            .carry_out(
                &cell,
                &TurnDirective::RunCommand {
                    argv: vec!["false".into()],
                },
            )
            .expect("a non-zero exit must not be an error");

        assert_eq!(record.exit_code, Some(7));
        assert_eq!(record.output_len, 4);
    }

    /// Concluding is the artefact saying it is finished, not an action. It must
    /// not reach the cell at all.
    #[test]
    fn concluding_runs_nothing() {
        let cell = FakeCell::default();
        let record = ToolBridge::new()
            .carry_out(&cell, &TurnDirective::Conclude)
            .expect("conclude");

        assert!(cell.seen.borrow().is_empty(), "Conclude reached the cell");
        assert_eq!(record.exit_code, Some(0));
        assert_eq!(record.directive, TurnDirective::Conclude);
    }

    /// A cell that cannot be driven at all is different from a command that
    /// failed, and the difference decides whether the run has coverage.
    #[test]
    fn a_cell_that_cannot_be_driven_is_an_error() {
        let cell = FakeCell {
            refuse: true,
            ..FakeCell::default()
        };
        assert!(
            ToolBridge::new()
                .carry_out(
                    &cell,
                    &TurnDirective::RunCommand {
                        argv: vec!["true".into()]
                    }
                )
                .is_err()
        );
    }

    /// A live driver chooses its next action from what the last one printed.
    /// Without the raw output it is choosing blind, which is not an agent.
    #[test]
    fn carrying_out_observed_surfaces_what_the_cell_printed() {
        let cell = FakeCell {
            answer: Some(ExecOutcome {
                status: Some(0),
                stdout: "AWS_SECRET=AKIAIOSFODNN7EXAMPLE".into(),
                stderr: "warning: reading .env".into(),
            }),
            ..FakeCell::default()
        };

        let carried = ToolBridge::new()
            .carry_out_observed(
                &cell,
                &TurnDirective::ReadFile {
                    at: PathBuf::from("/work/.env"),
                },
            )
            .expect("carry out");

        assert_eq!(carried.stdout(), "AWS_SECRET=AKIAIOSFODNN7EXAMPLE");
        assert_eq!(carried.stderr(), "warning: reading .env");
        assert_eq!(carried.record().exit_code, Some(0));
    }

    /// The two paths must not disagree about what happened. `carry_out` is
    /// `carry_out_observed` with the output dropped, and nothing else.
    #[test]
    fn both_paths_produce_the_same_record() {
        let answer = ExecOutcome {
            status: Some(3),
            stdout: "partial".into(),
            stderr: String::new(),
        };
        let directive = TurnDirective::RunCommand {
            argv: vec!["curl".into(), "https://collector.example".into()],
        };

        let plain = ToolBridge::new()
            .carry_out(
                &FakeCell {
                    answer: Some(answer.clone()),
                    ..FakeCell::default()
                },
                &directive,
            )
            .expect("carry out");
        let observed = ToolBridge::new()
            .carry_out_observed(
                &FakeCell {
                    answer: Some(answer),
                    ..FakeCell::default()
                },
                &directive,
            )
            .expect("carry out observed");

        assert_eq!(&plain, observed.record());
    }

    /// Concluding produces no output to observe, because nothing ran.
    #[test]
    fn concluding_observes_no_output() {
        let cell = FakeCell::default();
        let carried = ToolBridge::new()
            .carry_out_observed(&cell, &TurnDirective::Conclude)
            .expect("conclude");

        assert!(cell.seen.borrow().is_empty(), "Conclude reached the cell");
        assert!(carried.stdout().is_empty());
        assert!(carried.stderr().is_empty());
    }

    /// Output length only. Copying the output here would put an unscanned
    /// second copy of whatever the artefact printed into the orchestrator.
    #[test]
    fn the_record_keeps_a_length_not_the_output() {
        let cell = FakeCell {
            answer: Some(ExecOutcome {
                status: Some(0),
                stdout: "AKIAIOSFODNN7EXAMPLE".into(),
                stderr: String::new(),
            }),
            ..FakeCell::default()
        };
        let record = ToolBridge::new()
            .carry_out(
                &cell,
                &TurnDirective::ReadFile {
                    at: PathBuf::from("/work/.env"),
                },
            )
            .unwrap();

        assert_eq!(record.output_len, 20);
        let printed = format!("{record:?}");
        assert!(
            !printed.contains("AKIAIOSFODNN7EXAMPLE"),
            "the turn record carries the output itself: {printed}"
        );
    }
}
