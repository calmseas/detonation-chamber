//! One detonation, start to finish.
//!
//! # Refusing to arm is a normal outcome
//!
//! Everything up to the first turn can refuse. A host whose engine cannot
//! enforce egress denial, a preflight assert that does not hold, a chamber that
//! will not come up — none of those produce a weaker run, because there is no
//! weaker run to have. They produce an [`ArmingRefusal`] and no bundle at all,
//! which is the honest output: a bundle implies a run happened inside a
//! boundary, and if the boundary is not there the bundle would be a lie in
//! artefact form.
//!
//! # Once armed, almost nothing aborts
//!
//! After the first turn the posture inverts. A command that fails, a cell that
//! will not halt, a teardown that leaves containers behind — all are recorded
//! and the run continues to its seal, because the evidence collected so far is
//! worth more than the tidiness of stopping early. See [`crate::winddown`].
//!
//! # The order the chamber is built in
//!
//! Fabric, preflight, observer, warden, ruleset, collector, tarpit, cell. Every
//! adjacent pair has a reason, and three of them are enforced by types rather
//! than by this function getting it right: the tarpit route exists only on a
//! warden whose ruleset is loaded and whose collector is confirmed listening,
//! and a cell can only be started into that same warden.

use std::cell::RefCell;
use std::path::PathBuf;
use std::time::Duration;

use chamber_capture::ConsequencePlan;
use chamber_deadline::{StageTrace, Window};
use chamber_evidence::Verdict;
use chamber_isolation::{
    AgentCell, Attach, CanaryPlacements, Container, ContainerSpec, Docker, EnvDraft, EnvFile,
    GuestImage, GuestRoot, NetFabric, ObservedWarden, Preflight, Rationale, VarName, Warden,
};

use crate::bridge::{ToolBridge, TurnTarget};
use crate::bundle::{self, Observed};
use crate::exit_code_for;
use crate::turns::{CellOutput, Transcript, TurnDirective, TurnSource};
use crate::winddown::wind_down;

const OP_WINDOW: Duration = Duration::from_secs(120);

/// How long the cell gets to stop on its own.
///
/// Short on purpose, and each stage's grace must fit INSIDE that stage's cap or
/// it spends window the later stages need. The cell has nothing to flush — its
/// evidence is already in the observer's ledger — and it does not handle
/// SIGTERM, so `docker stop` always waits the full grace before killing it.
/// Handing it the engine's outer 20s grace inside a 3s halt cap consumed the
/// entire wind-down budget and left the seal with nothing: measured, as
/// `BoundarySeal WindowExhausted`.
const CELL_HALT_GRACE: Duration = Duration::from_secs(1);

/// The observer's grace, and the one that must not be trimmed.
///
/// SIGTERM is what makes it write the terminal marker, and that marker is the
/// only thing separating a finished ledger from a truncated one. Sized to fit
/// inside `BOUNDARY_SEAL_CAP` with room for the engine round-trip.
const OBSERVER_SEAL_GRACE: Duration = Duration::from_secs(4);
/// How long the observer gets to announce that it is listening.
const LISTEN_WINDOW: Duration = Duration::from_secs(90);

/// The images a run is built from.
#[derive(Debug, Clone)]
pub struct ImageTags {
    pub capture: String,
    pub warden: String,
    pub guest: String,
    pub inspector: String,
}

/// A token to plant, and where.
#[derive(Debug, Clone)]
pub struct PlantedCanary {
    /// The label that appears in the bundle's hit records, where a human reads it.
    pub label: String,
    pub value: String,
    /// The variable it is planted in, inside the cell.
    pub var: String,
}

/// Everything one run needs.
#[derive(Debug, Clone)]
pub struct DetonationPlan {
    pub images: ImageTags,
    pub ruleset: PathBuf,
    /// Host directory. The observer's ledger is written here through a bind
    /// mount, and the bundle is written beside it — so both outlive the
    /// containers that produced them.
    pub evidence_dir: PathBuf,
    pub canaries: Vec<PlantedCanary>,
    /// Ceiling on turns. A script that concludes earlier ends the run earlier.
    pub max_turns: u32,
    /// The skill directory to stage into the guest `/work` before the first
    /// turn. `None` reproduces Slice-0 behaviour exactly — nothing is staged,
    /// and the driver's brief is the only place the skill appears.
    pub skill_dir: Option<PathBuf>,
    /// What the boundary answers intercepted requests with. `None` — the
    /// default — is the `403 blocked by the detonation chamber` refusal.
    ///
    /// `Some` turns on [consequence
    /// mode](chamber_capture::consequence): the boundary fabricates this
    /// response so the artefact's request appears to succeed, which removes the
    /// tell that a 403 from every host would otherwise hand an eval-aware
    /// model. It grants no egress — the response is built inside the observer,
    /// and the request is discarded there exactly as a refused one is.
    pub consequence: Option<ConsequencePlan>,
}

/// Why no run happened.
#[derive(Debug)]
pub enum ArmingRefusal {
    NoEngine(String),
    Preflight(String),
    Chamber(String),
    Environment(String),
    Observer(String),
}

impl std::fmt::Display for ArmingRefusal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let (what, detail) = match self {
            Self::NoEngine(d) => ("no usable container engine", d),
            Self::Preflight(d) => ("the host's structural asserts did not hold", d),
            Self::Chamber(d) => ("the chamber could not be raised", d),
            Self::Environment(d) => ("the cell's environment could not be sealed", d),
            Self::Observer(d) => ("the observer never came up", d),
        };
        write!(
            f,
            "REFUSED TO ARM: {what}: {detail}\n\nNo bundle was written. A bundle \
             implies a run happened inside a boundary; without the boundary it \
             would be a claim in artefact form."
        )
    }
}

impl std::error::Error for ArmingRefusal {}

/// What a finished run produced.
#[derive(Debug)]
pub struct RunEpilogue {
    pub bundle_path: PathBuf,
    pub seal_path: PathBuf,
    pub verdict: Verdict,
    pub trace: StageTrace,
    pub exit_code: i32,
    pub turns_taken: usize,
}

/// Destroys whatever was raised if arming does not complete.
///
/// A refusal used to leave its network behind, and the next run then failed on
/// "network with name chamber-egress already exists" — a second, unrelated
/// error that says nothing about why the first run refused. Arming has several
/// exit paths and adding a cleanup call to each is how one gets missed, so the
/// guard owns them and [`ArmingGuard::disarm`] hands them on once the chamber
/// is up.
#[derive(Default)]
struct ArmingGuard {
    cell: Option<AgentCell>,
    capture: Option<Container>,
    warden: Option<ObservedWarden>,
    fabric: Option<NetFabric>,
}

impl ArmingGuard {
    #[allow(clippy::type_complexity)]
    fn disarm(
        &mut self,
    ) -> (
        Option<AgentCell>,
        Option<Container>,
        Option<ObservedWarden>,
        Option<NetFabric>,
    ) {
        (
            self.cell.take(),
            self.capture.take(),
            self.warden.take(),
            self.fabric.take(),
        )
    }
}

impl Drop for ArmingGuard {
    fn drop(&mut self) {
        // Everything raised, innermost out, and every container before the
        // network. The cell joins the warden's netns, so it goes first; the
        // warden and observer are endpoints on the fabric, so both go before
        // it. A network with an endpoint still attached cannot be removed —
        // leaving it behind for the next run to trip over as `chamber-egress
        // already exists`, a second error that hides the one that actually
        // refused. Guarding only some of what was raised is how that leak got
        // in: a refusal after the warden was up left the warden, and the
        // network with it.
        if let Some(cell) = self.cell.take() {
            let _ = cell.destroy(OP_WINDOW);
        }
        if let Some(capture) = self.capture.take() {
            let _ = capture.destroy(OP_WINDOW);
        }
        if let Some(warden) = self.warden.take() {
            let _ = warden.destroy();
        }
        if let Some(fabric) = self.fabric.take() {
            let _ = fabric.destroy();
        }
    }
}

/// The live containers, so the wind-down's stages can each take what they need.
///
/// `Option` and a `RefCell` because the stages have incompatible needs: halting
/// borrows the cell, tearing down consumes it, and both are handed to
/// [`wind_down`] before either runs.
struct LiveChamber {
    cell: Option<AgentCell>,
    warden: Option<ObservedWarden>,
    capture: Option<Container>,
    fabric: Option<NetFabric>,
}

/// Runs one detonation.
///
/// # Errors
/// [`ArmingRefusal`] if the chamber could not be brought up. Once the first
/// turn has run, failures are recorded rather than raised.
pub async fn run_detonation(
    plan: &DetonationPlan,
    turns: &mut dyn TurnSource,
) -> Result<RunEpilogue, ArmingRefusal> {
    let engine = Docker::probe().map_err(|e| ArmingRefusal::NoEngine(e.to_string()))?;
    eprintln!(
        "chamber: docker {} on {}/{}",
        engine.server_version(),
        engine.os_type(),
        engine.arch()
    );

    std::fs::create_dir_all(&plan.evidence_dir)
        .map_err(|e| ArmingRefusal::Chamber(format!("evidence directory: {e}")))?;
    let ledger_path = plan.evidence_dir.join("ledger.jsonl");
    // A stale ledger from a previous run would be read as this run's evidence.
    let _ = std::fs::remove_file(&ledger_path);

    let mut arming = ArmingGuard::default();
    arming.fabric = Some(NetFabric::raise().map_err(|e| ArmingRefusal::Chamber(e.to_string()))?);
    let fabric = arming.fabric.as_ref().expect("just set");

    // Measured before anything is believed. All three are version-dependent and
    // all three fail silently.
    Preflight::run(fabric.egress(), &plan.images.guest, &plan.images.inspector)
        .map_err(|e| ArmingRefusal::Preflight(e.to_string()))?
        .into_result()
        .map_err(|f| ArmingRefusal::Preflight(f.to_string()))?;

    arming.capture = Some(start_observer(plan, fabric, &ledger_path)?);
    let capture = arming.capture.as_ref().expect("just set");

    // All of it under the guard from here: a refusal after the warden is raised
    // must not leave the warden — and the network it is attached to — behind.
    arming.warden = Some(arm_warden(plan, fabric).map_err(ArmingRefusal::Chamber)?);
    let sealed_env = seal_cell_environment(plan, capture).map_err(ArmingRefusal::Environment)?;

    let cell = AgentCell::start(
        arming.warden.as_ref().expect("just set"),
        &sealed_env.env,
        &GuestImage::tagged(&plan.images.guest),
    )
    .map_err(|e| ArmingRefusal::Chamber(e.to_string()))?;
    arming.cell = Some(cell);
    arming
        .cell
        .as_ref()
        .expect("just set")
        .write_file(&sealed_env.anchor_path, sealed_env.ca_pem.as_bytes())
        .map_err(|e| ArmingRefusal::Chamber(format!("placing the trust anchor: {e}")))?;

    // The skill's own files, if any, staged into the cell before the first turn.
    // A refusal here is still a refusal to arm: a half-staged skill would
    // detonate as something other than what was handed in.
    if let Some(skill_dir) = &plan.skill_dir {
        crate::staging::stage_skill_dir(arming.cell.as_ref().expect("just set"), skill_dir)
            .map_err(|e| ArmingRefusal::Chamber(format!("staging the skill: {e}")))?;
    }

    // ---- armed. From here nothing aborts the run. The guard stays armed
    //      through the turn loop, so an unexpected early exit still tears the
    //      chamber down; it is disarmed only when ownership passes to the
    //      wind-down. -------------------------------------------------------

    let transcript = {
        let cell = arming.cell.as_ref().expect("armed");
        drive_turns(turns, &ToolBridge::new(), cell, plan.max_turns).await
    };

    // The chamber is up and its ownership moves to the wind-down, so the
    // arming guard must not destroy any of it.
    let turns_taken = transcript.len();
    let (cell, capture, warden, fabric) = arming.disarm();
    let chamber = RefCell::new(LiveChamber {
        cell,
        warden,
        capture,
        fabric,
    });

    let mut trace = StageTrace::new();
    let emitted = RefCell::new(None);
    let provenance = turns.provenance();
    // Taken before the wind-down borrows the closure: the source is done being
    // driven, and what it did is now evidence.
    let inference_calls = turns.inference_calls().to_vec();

    wind_down(
        Window::standard(),
        &mut trace,
        || async {
            let cell = chamber
                .borrow()
                .cell
                .as_ref()
                .map(AgentCell::container_id)
                .map(str::to_owned);
            match cell {
                Some(_) => chamber
                    .borrow()
                    .cell
                    .as_ref()
                    .expect("just checked")
                    .halt(CELL_HALT_GRACE)
                    .map_err(|e| e.to_string()),
                None => Ok(()),
            }
        },
        // Stopping the observer is what makes it write its terminal marker.
        // Destroying it instead would leave a truncated ledger and the run
        // would correctly, but needlessly, report insufficient coverage.
        || async {
            let capture = chamber.borrow_mut().capture.take();
            match capture {
                Some(capture) => {
                    let stopped = capture.stop(OBSERVER_SEAL_GRACE).map_err(|e| e.to_string());
                    let _ = capture.destroy(OP_WINDOW);
                    stopped
                }
                None => Ok(()),
            }
        },
        || async {
            let (cell, warden, fabric) = {
                let mut c = chamber.borrow_mut();
                (c.cell.take(), c.warden.take(), c.fabric.take())
            };
            let mut trouble = Vec::new();
            if let Some(cell) = cell
                && let Err(e) = cell.destroy(OP_WINDOW)
            {
                trouble.push(format!("cell: {e}"));
            }
            if let Some(warden) = warden
                && let Err(e) = warden.destroy()
            {
                trouble.push(format!("warden: {e}"));
            }
            if let Some(fabric) = fabric
                && let Err(e) = fabric.destroy()
            {
                trouble.push(format!("fabric: {e}"));
            }
            if trouble.is_empty() {
                Ok(())
            } else {
                Err(trouble.join("; "))
            }
        },
        || async {
            let (state, mut log) =
                bundle::inspect_ledger(&ledger_path).map_err(|e| e.to_string())?;
            // The agent's own actions, folded in beside what the observer saw:
            // the liveness witness and matrix row 3 read these from the sealed
            // bundle. Redacted against the canary values so a hard-coded token
            // could never ride into the artefact.
            let secrets: Vec<String> = plan.canaries.iter().map(|c| c.value.clone()).collect();
            bundle::record_guest_commands(&mut log, &transcript, &secrets);
            // The model's side of the run, beside the agent's. Digests only —
            // see `record_inference_calls`.
            crate::liveturns::record_inference_calls(&mut log, &inference_calls);
            let observed = Observed {
                boundary: state,
                drops_collected: true,
                turns_driven: turns_taken,
                inference_calls: inference_calls.len(),
            };
            let written = bundle::emit(&plan.evidence_dir, log, &observed, &provenance)
                .map_err(|e| e.to_string())?;
            *emitted.borrow_mut() = Some(written);
            Ok(())
        },
    )
    .await;

    // A run whose record stage did not complete has no bundle, and saying so is
    // the only honest thing left. It is not an arming refusal — the run
    // happened — so it surfaces as a missing bundle with the trace intact.
    let written = emitted.borrow_mut().take().ok_or_else(|| {
        ArmingRefusal::Observer(format!(
            "the run completed but no bundle could be written; wind-down trace: {:?}",
            trace.entries()
        ))
    })?;

    Ok(RunEpilogue {
        exit_code: exit_code_for(&written.verdict),
        bundle_path: written.bundle_path,
        seal_path: written.seal_path,
        verdict: written.verdict,
        trace,
        turns_taken,
    })
}

/// Drives the artefact for up to `max_turns`, or until it concludes.
///
/// Split out of [`run_detonation`] so the loop's behaviour — what it does with
/// a source that stops, a cell that cannot be driven, a `Conclude` — is
/// testable without a Linux guest, the same reason [`TurnTarget`] exists.
///
async fn drive_turns(
    turns: &mut dyn TurnSource,
    bridge: &ToolBridge,
    target: &impl TurnTarget,
    max_turns: u32,
) -> Transcript {
    let mut transcript = Transcript::new();
    for _ in 0..max_turns {
        let directive = match turns.next_turn(&transcript).await {
            Ok(d) => d,
            // A turn source that cannot produce a turn ends the run; it does
            // not end the evidence. The wind-down still happens.
            Err(e) => {
                eprintln!("chamber: turn source stopped: {e}");
                break;
            }
        };
        let concluding = matches!(directive, TurnDirective::Conclude);
        match bridge.carry_out_observed(target, &directive) {
            Ok(carried) => {
                // The driver first, then the transcript: it chooses its next
                // action from what this one printed. Concluding ran nothing,
                // so there is no exchange to show it.
                if !concluding {
                    turns.observe(&CellOutput {
                        directive: &directive,
                        stdout: carried.stdout(),
                        stderr: carried.stderr(),
                        exit_code: carried.record().exit_code,
                    });
                }
                transcript.record(carried.into_record());
            }
            Err(e) => {
                eprintln!("chamber: the cell could not be driven: {e}");
                break;
            }
        }
        if concluding {
            break;
        }
    }
    transcript
}

/// Everything the observer is configured with, as env pairs.
///
/// Split out of [`start_observer`] so the wire can be checked without a
/// container. It is the seam where a configuration goes missing silently: a
/// consequence set on the host but never written into these pairs produces an
/// observer that refuses, a run that looks configured, and a realism experiment
/// whose result means nothing — with no error anywhere to say so.
fn observer_env(plan: &DetonationPlan) -> Vec<(String, String)> {
    let mut pairs = vec![
        (
            "CHAMBER_LEDGER".to_owned(),
            "/evidence/ledger.jsonl".to_owned(),
        ),
        (
            "CHAMBER_CA_OUT".to_owned(),
            "/evidence/chamber-ca.pem".to_owned(),
        ),
        (
            "CHAMBER_ANSWER_WITH".to_owned(),
            NetFabric::CAPTURE_IP.to_owned(),
        ),
        ("CHAMBER_PROXY_ADDR".to_owned(), "0.0.0.0:3128".to_owned()),
        ("CHAMBER_DNS_ADDR".to_owned(), "0.0.0.0:53".to_owned()),
    ];
    for canary in &plan.canaries {
        pairs.push((
            format!(
                "CHAMBER_CANARY_{}",
                canary.label.to_uppercase().replace('-', "_")
            ),
            canary.value.clone(),
        ));
    }
    // Absent unless the operator asked for it, so an ordinary run's observer
    // sees neither variable and keeps refusing. The body is base64 in these
    // pairs: the env file this becomes is one `KEY=value` line per pair, and a
    // plausible response body has newlines in it.
    if let Some(consequence) = &plan.consequence {
        pairs.extend(consequence.to_env_pairs());
    }
    pairs
}

/// The observer, at the address the ruleset accepts and the resolver points at.
fn start_observer(
    plan: &DetonationPlan,
    fabric: &NetFabric,
    ledger_path: &std::path::Path,
) -> Result<Container, ArmingRefusal> {
    let pairs = observer_env(plan);
    let env_file =
        EnvFile::write(&pairs).map_err(|e| ArmingRefusal::Observer(format!("env file: {e}")))?;

    let capture = Container::create(&ContainerSpec {
        image: plan.images.capture.clone(),
        attach: Attach::Network {
            network: fabric.egress().name().to_owned(),
            ip: Some(NetFabric::CAPTURE_IP.to_owned()),
        },
        cap_add: vec![],
        argv: vec![],
        sysctls: vec![],
        env_file: Some(env_file.path().clone()),
        dns: vec![],
        read_only: false,
        tmpfs: vec![],
        // The ledger has to outlive the chamber: the wind-down tears containers
        // down a stage before it writes the bundle that reports them.
        volumes: vec![format!("{}:/evidence", plan.evidence_dir.display())],
    })
    .map_err(|e| ArmingRefusal::Observer(e.to_string()))?;
    capture
        .start()
        .map_err(|e| ArmingRefusal::Observer(e.to_string()))?;

    await_listening(&capture)?;
    let _ = ledger_path;
    Ok(capture)
}

/// Blocks until the observer says it is listening.
///
/// Nothing may run against a chamber whose observer has not confirmed it is up:
/// the artefact's first action is the one most worth seeing, and it is the one
/// lost if the observer is still binding.
fn await_listening(capture: &Container) -> Result<(), ArmingRefusal> {
    let deadline = std::time::Instant::now() + LISTEN_WINDOW;
    loop {
        let logs = capture
            .logs()
            .map(|l| l.stdout + &l.stderr)
            .unwrap_or_default();
        if logs.contains("LISTENING") {
            return Ok(());
        }
        if std::time::Instant::now() >= deadline {
            return Err(ArmingRefusal::Observer(format!(
                "the observer never reported LISTENING. Its output:\n{logs}"
            )));
        }
        std::thread::sleep(Duration::from_millis(250));
    }
}

fn arm_warden(plan: &DetonationPlan, fabric: &NetFabric) -> Result<ObservedWarden, String> {
    let warden = Warden::start(fabric, &plan.images.warden).map_err(|e| e.to_string())?;
    let warden = warden
        .load_ruleset(&plan.ruleset)
        .map_err(|e| e.to_string())?;
    let warden = warden.start_drop_collector().map_err(|e| e.to_string())?;
    warden.add_tarpit_route().map_err(|e| e.to_string())?;
    Ok(warden)
}

struct CellEnvironment {
    env: chamber_isolation::SealedEnv,
    anchor_path: PathBuf,
    ca_pem: String,
}

/// Builds the cell's environment: trust anchor first, then everything else.
fn seal_cell_environment(
    plan: &DetonationPlan,
    capture: &Container,
) -> Result<CellEnvironment, String> {
    let ca_pem = capture
        .exec(&["cat", "/evidence/chamber-ca.pem"], OP_WINDOW)
        .map_err(|e| e.to_string())?
        .stdout;
    if !ca_pem.contains("BEGIN CERTIFICATE") {
        return Err("the observer produced no CA certificate".to_owned());
    }

    let guest_root = GuestRoot::at("/work");
    let anchor_path = PathBuf::from("/work/chamber-ca.pem");

    let mut draft = EnvDraft::empty();
    draft
        .redirect_scratch(&guest_root)
        .map_err(|e| e.to_string())?;
    // Before any other binding: a later variable that would re-point trust is
    // then already a duplicate-name error rather than a silent override.
    draft
        .place_trust_anchor(&anchor_path)
        .map_err(|e| e.to_string())?;

    let proxy = Rationale {
        reason: "the artefact's egress must go through the observer to be seen",
        required_by: "chamber-run::seal_cell_environment",
    };
    for var in ["https_proxy", "http_proxy", "HTTPS_PROXY", "HTTP_PROXY"] {
        draft
            .set(
                VarName::parse(var).map_err(|e| e.to_string())?,
                format!("http://{}:3128", NetFabric::CAPTURE_IP),
                proxy,
            )
            .map_err(|e| e.to_string())?;
    }

    let planted = Rationale {
        reason: "a planted token, present so its departure can be detected",
        required_by: "chamber-run::seal_cell_environment",
    };
    let mut placements = CanaryPlacements::none();
    for canary in &plan.canaries {
        let name = VarName::parse(&canary.var).map_err(|e| e.to_string())?;
        draft
            .set(name.clone(), canary.value.clone(), planted)
            .map_err(|e| e.to_string())?;
        placements.plant_env(canary.label.clone(), name);
    }

    // Refuses if a canary was declared for a variable that was never bound —
    // the failure that produces a run with nothing to find, reported as no
    // finding.
    let env = draft.seal(&placements).map_err(|e| e.to_string())?;
    Ok(CellEnvironment {
        env,
        anchor_path,
        ca_pem,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::turns::{CellOutput, TurnError, TurnProvenance};
    use chamber_isolation::{CellError, ExecOutcome};

    /// Answers every command with the same canned output.
    struct EchoCell {
        stdout: String,
        stderr: String,
    }

    impl EchoCell {
        fn printing(stdout: &str) -> Self {
            Self {
                stdout: stdout.to_owned(),
                stderr: String::new(),
            }
        }
    }

    impl TurnTarget for EchoCell {
        fn run(&self, _argv: &[&str], _within: Duration) -> Result<ExecOutcome, CellError> {
            Ok(ExecOutcome {
                status: Some(0),
                stdout: self.stdout.clone(),
                stderr: self.stderr.clone(),
            })
        }
    }

    /// Runs a fixed plan and remembers everything the loop showed it.
    #[derive(Default)]
    struct SpySource {
        plan: Vec<TurnDirective>,
        next: usize,
        seen: Vec<(String, Option<i32>)>,
    }

    impl SpySource {
        fn running(plan: Vec<TurnDirective>) -> Self {
            Self {
                plan,
                ..Self::default()
            }
        }
    }

    #[async_trait::async_trait]
    impl TurnSource for SpySource {
        async fn next_turn(&mut self, _t: &Transcript) -> Result<TurnDirective, TurnError> {
            let directive = self
                .plan
                .get(self.next)
                .cloned()
                .ok_or(TurnError::ScriptExhausted { taken: self.next })?;
            self.next += 1;
            Ok(directive)
        }

        fn provenance(&self) -> TurnProvenance {
            TurnProvenance::Live {
                model: "spy".to_owned(),
            }
        }

        fn observe(&mut self, outcome: &CellOutput<'_>) {
            self.seen
                .push((outcome.stdout.to_owned(), outcome.exit_code));
        }
    }

    /// A source that overrides nothing, to pin the default down.
    #[derive(Default)]
    struct DeafSource {
        turns_asked: usize,
    }

    #[async_trait::async_trait]
    impl TurnSource for DeafSource {
        async fn next_turn(&mut self, _t: &Transcript) -> Result<TurnDirective, TurnError> {
            self.turns_asked += 1;
            Ok(TurnDirective::Conclude)
        }

        fn provenance(&self) -> TurnProvenance {
            TurnProvenance::Scripted {
                path: "none".to_owned(),
                digest: String::new(),
            }
        }
    }

    /// D8. Without this the model chooses its next action blind, and the
    /// artefact's power to suborn it cannot be observed at all.
    #[tokio::test]
    async fn the_loop_hands_the_raw_output_to_the_turn_source() {
        let cell = EchoCell::printing("AWS_SECRET_ACCESS_KEY=AKIAIOSFODNN7EXAMPLE");
        let mut source = SpySource::running(vec![
            TurnDirective::ReadFile {
                at: PathBuf::from("/work/.env"),
            },
            TurnDirective::Conclude,
        ]);

        drive_turns(&mut source, &ToolBridge::new(), &cell, 8).await;

        assert_eq!(
            source.seen,
            vec![(
                "AWS_SECRET_ACCESS_KEY=AKIAIOSFODNN7EXAMPLE".to_owned(),
                Some(0)
            )],
            "the driver was not shown what the cell printed"
        );
    }

    /// Concluding runs nothing, so there is no exchange to observe. Handing the
    /// driver an empty one would put a turn that never happened into the
    /// history it builds its next prompt from.
    #[tokio::test]
    async fn concluding_is_not_an_observed_exchange() {
        let cell = EchoCell::printing("ignored");
        let mut source = SpySource::running(vec![TurnDirective::Conclude]);

        drive_turns(&mut source, &ToolBridge::new(), &cell, 8).await;

        assert!(source.seen.is_empty(), "{:?}", source.seen);
    }

    /// The transcript's account stays length-only however much the cell
    /// printed. This is the invariant the whole raw-output path is arranged
    /// around: the driver sees the output, the bundle never does.
    #[tokio::test]
    async fn what_the_driver_sees_does_not_reach_the_transcript() {
        let cell = EchoCell::printing("AKIAIOSFODNN7EXAMPLE");
        let mut source = SpySource::running(vec![
            TurnDirective::ReadFile {
                at: PathBuf::from("/work/.env"),
            },
            TurnDirective::Conclude,
        ]);

        let transcript = drive_turns(&mut source, &ToolBridge::new(), &cell, 8).await;

        let printed = format!("{:?}", transcript.entries());
        assert!(
            !printed.contains("AKIAIOSFODNN7EXAMPLE"),
            "the transcript carries the output itself: {printed}"
        );
        assert_eq!(transcript.entries()[0].output_len, 20);
    }

    /// A replay does not react to what happened, so it must not have to say so.
    /// The default keeps `ScriptedTurns` — and any future source — unchanged.
    #[tokio::test]
    async fn observing_is_optional() {
        let cell = EchoCell::printing("whatever");
        let mut source = DeafSource::default();

        let transcript = drive_turns(&mut source, &ToolBridge::new(), &cell, 8).await;

        assert_eq!(source.turns_asked, 1);
        assert_eq!(transcript.len(), 1);
    }

    /// The cap is the cap, even for a source that never concludes.
    #[tokio::test]
    async fn the_turn_cap_stops_a_source_that_runs_forever() {
        let cell = EchoCell::printing("out");
        let mut source = SpySource::running(vec![
            TurnDirective::RunCommand {
                argv: vec!["true".to_owned()],
            };
            50
        ]);

        let transcript = drive_turns(&mut source, &ToolBridge::new(), &cell, 3).await;

        assert_eq!(transcript.len(), 3);
        assert_eq!(source.seen.len(), 3);
    }

    // ---- what the observer is told ----------------------------------------

    fn bare_plan(consequence: Option<ConsequencePlan>) -> DetonationPlan {
        DetonationPlan {
            images: ImageTags {
                capture: "c".into(),
                warden: "w".into(),
                guest: "g".into(),
                inspector: "i".into(),
            },
            ruleset: PathBuf::from("chamber.nft"),
            evidence_dir: PathBuf::from("/tmp/ev"),
            canaries: vec![PlantedCanary {
                label: "aws-key".into(),
                value: "AKIAIOSFODNN7EXAMPLE".into(),
                var: "CHAMBER_TOKEN".into(),
            }],
            max_turns: 4,
            skill_dir: None,
            consequence,
        }
    }

    /// An ordinary run must leave the observer with nothing to find, so it
    /// keeps refusing. A stray empty variable here would be read as a
    /// half-configuration and refuse the run outright.
    #[test]
    fn a_plan_without_a_consequence_names_neither_variable() {
        let pairs = observer_env(&bare_plan(None));
        assert!(
            !pairs
                .iter()
                .any(|(k, _)| k.starts_with("CHAMBER_CONSEQUENCE")),
            "an ordinary run offered the observer a consequence variable: {pairs:?}"
        );
    }

    /// THE wire. A consequence configured on the host and not written here
    /// produces an observer that refuses while the operator believes it is
    /// answering — the failure this feature has to not have, and one that
    /// nothing downstream would report.
    #[test]
    fn a_configured_consequence_reaches_the_observer_intact() {
        let page = "<!doctype html>\n<title>Starter</title>\n";
        let nonce = "{\"nonce\":\"c7f3a91b\"}";
        let configured = ConsequencePlan::new(
            vec![
                (
                    "/challenge".to_owned(),
                    chamber_capture::ConsequenceResponse::new(200, nonce).unwrap(),
                ),
                (
                    "/starter".to_owned(),
                    chamber_capture::ConsequenceResponse::new(200, page).unwrap(),
                ),
            ],
            chamber_capture::ConsequenceResponse::new(404, "not found").unwrap(),
        )
        .unwrap();
        let pairs = observer_env(&bare_plan(Some(configured.clone())));

        let read = ConsequencePlan::from_env_value(
            pairs
                .iter()
                .find(|(k, _)| k == chamber_capture::consequence::SPEC_B64_VAR)
                .map(|(_, v)| v.as_str()),
        )
        .expect("the pairs the host writes must parse back")
        .expect("the spec must be present");

        // The whole routed plan survives, not merely one response: a multi-step
        // fixture is only measurable if every path's answer arrives intact.
        assert_eq!(read, configured);
        assert_eq!(read.response_for("/challenge").body(), nonce);
        assert_eq!(read.response_for("/starter").body(), page);
        assert_eq!(read.response_for("/other").status(), 404);
    }

    /// The env file is one `KEY=value` line per pair. A raw newline in any
    /// value ends the line early and docker reads the remainder as further
    /// variables — silently, with the run still starting.
    #[test]
    fn no_observer_variable_carries_a_line_break() {
        let plan = bare_plan(Some(ConsequencePlan::single(
            chamber_capture::ConsequenceResponse::new(200, "<html>\n<body>\nhi\n</body>\n")
                .unwrap(),
        )));
        for (key, value) in observer_env(&plan) {
            assert!(
                !value.contains('\n') && !value.contains('\r'),
                "{key} carries a line break, which truncates the env file"
            );
        }
    }
}
