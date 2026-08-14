//! The agent cell: where the artefact under detonation actually runs.
//!
//! # It can only be started into an observed chamber
//!
//! [`AgentCell::start`] takes an [`ObservedWarden`], not a [`crate::Warden`].
//! That is the prohibition *"never start the agent before the NFLOG collector
//! is confirmed running"* expressed as a type: the only way to hold an
//! `ObservedWarden` is to have loaded a ruleset and then watched tcpdump
//! announce itself. Start the artefact before that and the first thing it does
//! — which is exactly the thing worth seeing — is the one thing never recorded.
//!
//! # What this cell deliberately cannot do
//!
//! - **Hold a capability.** `--cap-drop ALL` with no `--cap-add`. The bounding
//!   set is empty, which is stronger than dropping privileges after start: a
//!   setuid binary or a root shell inside the cell cannot regain `NET_ADMIN`
//!   and rewrite the rules containing it.
//! - **Own its network stack.** It joins the warden's namespace. The rules were
//!   installed from outside it by a container it cannot reach.
//! - **See the host filesystem.** No bind mount, ever. Files arrive through
//!   [`AgentCell::write_file`], over stdin.
//! - **Leak its environment to `ps`.** Values arrive by 0600 `--env-file`. The
//!   engine API in this crate has no `-e`.
//!
//! # One guarantee that is owed rather than held
//!
//! The design has `destroy` take a token proving the boundary's evidence was
//! sealed first, so a cell cannot be torn down while the ledger is still open.
//! That token can only be minted honestly by the capture layer, which does not
//! run in the chamber yet — `chamber-capture` has no bin target. A token this
//! module could mint for itself would prove nothing, so [`AgentCell::destroy`]
//! currently takes only a window. **This is a real gap, not an oversight**, and
//! it closes when the boundary process exists.

use std::path::Path;
use std::time::Duration;

use crate::docker::{Attach, Container, ContainerSpec, ExecOutcome};
use crate::env::SealedEnv;
use crate::warden::{CellError, ObservedWarden};

const OP_WINDOW: Duration = Duration::from_secs(60);

/// The image the artefact runs in.
#[derive(Clone, Debug)]
pub struct GuestImage(String);

impl GuestImage {
    #[must_use]
    pub fn tagged(tag: impl Into<String>) -> Self {
        Self(tag.into())
    }

    #[must_use]
    pub fn tag(&self) -> &str {
        &self.0
    }
}

/// A running agent cell, identified by the id captured at create.
#[derive(Debug)]
pub struct AgentCell {
    container: Container,
}

impl AgentCell {
    /// Starts the cell inside the warden's namespace, with the sealed
    /// environment and no capabilities.
    ///
    /// # Errors
    /// [`CellError`] if the environment file cannot be written or the engine
    /// refuses.
    pub fn start(
        warden: &ObservedWarden,
        env: &SealedEnv,
        image: &GuestImage,
    ) -> Result<Self, CellError> {
        // Written, used at create, and removed when it drops. The engine bakes
        // the values into the container config at create time, so the file does
        // not need to outlive this call — and should not.
        let env_file = env
            .to_env_file()
            .map_err(|e| CellError::RulesetUnreadable {
                path: "<sealed env>".into(),
                detail: e.to_string(),
            })?;

        let container = Container::create(&ContainerSpec {
            image: image.tag().to_owned(),
            attach: Attach::SharedWith {
                container_id: warden.container_id().to_owned(),
            },
            // Empty, and there is no code path that adds to it.
            cap_add: vec![],
            // The cell idles; work arrives through `exec`. An entrypoint that
            // ran the artefact directly would end the container the moment it
            // finished, taking the namespace's observability window with it.
            argv: vec!["sleep".into(), "infinity".into()],
            // The image's own entrypoint, whatever it is. The relay-capable
            // guest starts `execrelayd` here, and that is the point of it.
            entrypoint: None,
            sysctls: vec![],
            env_file: Some(env_file.path().clone()),
            dns: vec![],
            // The artefact cannot modify the image it runs in, so what it
            // leaves behind is bounded to the tmpfs below and dies with the
            // container.
            read_only: true,
            // Taken from the sealed environment rather than from a separate
            // parameter: the tmpfs must be exactly where TMPDIR and HOME point,
            // and a mismatch would surface as the artefact failing to write
            // rather than as the misconfiguration it actually is.
            tmpfs: env
                .scratch_root()
                .map(|root| root.display().to_string())
                .into_iter()
                .collect(),
            // Empty, and there is no code path that fills it. A mount here
            // would hand the artefact a handle on host state.
            volumes: vec![],
        })?;
        container.start()?;

        Ok(Self { container })
    }

    #[must_use]
    pub fn container_id(&self) -> &str {
        self.container.id()
    }

    /// Runs a command in the cell.
    ///
    /// A non-zero exit is returned rather than raised: what the artefact's
    /// command did is an observation, not an error in the harness.
    ///
    /// # Errors
    /// [`CellError`] only if the exec could not be performed or outlived
    /// `within`.
    pub fn exec(&self, argv: &[&str], within: Duration) -> Result<ExecOutcome, CellError> {
        Ok(self.container.exec(argv, within)?)
    }

    /// Everything the cell's PID 1 has written to stdout, as captured by the
    /// container engine.
    ///
    /// For the exec-relay guest that stream is the disclosure log — one JSONL
    /// record per intercepted exec, and nothing else, because `execrelayd`
    /// sends its own operator output to stderr. For any other guest it is
    /// whatever that image's entrypoint printed, which for the plain guest
    /// (`sleep infinity`) is nothing.
    ///
    /// Two properties make this the sealing path rather than reading a file out
    /// of the cell with `exec`:
    ///
    /// - **The agent cannot reach it.** The engine captures the stream outside
    ///   the container as it is produced. A root-in-cell agent that deletes or
    ///   truncates anything inside `/work` does not touch what is already
    ///   captured — which the disclosure log, as a plain file in the
    ///   agent-writable tmpfs, was not protected against.
    /// - **A stopped container still has it.** `docker exec` refuses a stopped
    ///   container, so the old file read had to be sequenced ahead of
    ///   [`AgentCell::halt`]; captured logs survive until the container is
    ///   REMOVED, so that ordering constraint is gone.
    ///
    /// Decoded with [`String::from_utf8_lossy`], deliberately: a disclosure
    /// record's `requested_argv0` is a path read raw out of tracee memory and
    /// carries no encoding guarantee, so an invalid byte must cost its own
    /// line's readability and nothing more. A strict decode that fell back to
    /// an empty string would erase a whole run's evidence over one byte.
    ///
    /// # Errors
    /// [`CellError`] if the engine refuses.
    pub fn captured_stdout(&self) -> Result<String, CellError> {
        let raw = self.container.logs_bytes()?;
        Ok(String::from_utf8_lossy(&raw.stdout).into_owned())
    }

    /// Places a file in the cell, over stdin.
    ///
    /// Not via argv: the contents would land in the host process table, which
    /// is fatal the moment the file is a planted `.env`. Not via a bind mount:
    /// that hands the cell a handle on host state.
    ///
    /// # Errors
    /// [`CellError`] if the write fails.
    pub fn write_file(&self, at: &Path, bytes: &[u8]) -> Result<(), CellError> {
        let destination = at.display().to_string();
        self.container.exec_with_stdin(
            &["sh", "-c", &format!("cat > '{destination}'")],
            bytes,
            OP_WINDOW,
        )?;
        Ok(())
    }

    /// The cell's capability bounding set, straight from `/proc`.
    ///
    /// Read from inside rather than inferred from the flags passed at create:
    /// what was asked for and what the kernel granted are different claims, and
    /// only the second one contains anything.
    ///
    /// # Errors
    /// [`CellError`] if `/proc/self/status` cannot be read.
    pub fn capability_bounding_set(&self) -> Result<String, CellError> {
        let out = self.container.exec(
            &["sh", "-c", "awk '/^CapBnd:/ {print $2}' /proc/self/status"],
            OP_WINDOW,
        )?;
        Ok(out.stdout.trim().to_owned())
    }

    /// Stops the artefact, giving it `grace` to exit on its own.
    ///
    /// The first stage of the wind-down: the artefact must stop acting before
    /// its evidence is collected, or the collection races whatever it does
    /// next.
    ///
    /// # Errors
    /// [`CellError`] if the engine refuses.
    pub fn halt(&self, grace: Duration) -> Result<(), CellError> {
        self.container.stop(grace)?;
        Ok(())
    }

    /// Removes the cell by its captured id.
    ///
    /// See the module note: this does **not** yet require proof that the
    /// boundary's evidence was sealed first.
    ///
    /// # Errors
    /// [`CellError`] if the engine refuses.
    pub fn destroy(self, within: Duration) -> Result<(), CellError> {
        self.container.destroy(within)?;
        Ok(())
    }
}

/// What `/proc/self/status` reports for a cell that holds nothing.
pub const EMPTY_BOUNDING_SET: &str = "0000000000000000";

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_image_keeps_the_tag_it_was_given() {
        let image = GuestImage::tagged("chamber-guest:test");
        assert_eq!(image.tag(), "chamber-guest:test");
    }

    /// The empty bounding set the cell must hold. Pinned as a constant here so
    /// the integration assertion and the probe's own row agree on the shape.
    #[test]
    fn the_empty_bounding_set_is_sixteen_zeroes() {
        assert_eq!(EMPTY_BOUNDING_SET.len(), 16);
        assert!(EMPTY_BOUNDING_SET.chars().all(|c| c == '0'));
    }
}
