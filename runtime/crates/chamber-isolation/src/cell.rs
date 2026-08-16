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
            // rather than as the misconfiguration it actually is. The extra
            // mounts carry the `Normalized` trust placement's writable
            // system-store dirs (/etc/ssl/certs, /usr/local/share/ca-certificates)
            // on the otherwise read-only rootfs, declared the same way.
            tmpfs: env
                .scratch_root()
                .map(|root| root.display().to_string())
                .into_iter()
                .chain(env.extra_tmpfs().iter().map(|p| p.display().to_string()))
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
    /// Decoded by [`decode_capture`], deliberately lossily: a disclosure
    /// record's `requested_argv0` is a path read raw out of tracee memory and
    /// carries no encoding guarantee, so an invalid byte must cost its own
    /// line's readability and nothing more. A strict decode that fell back to
    /// an empty string would erase a whole run's evidence over one byte.
    ///
    /// An empty string here means the cell's PID 1 wrote nothing, and only
    /// that: [`Container::logs_bytes`] raises a refused `docker logs` rather
    /// than returning its empty stdout, so "nothing was written" and "the
    /// engine would not say" cannot arrive here as the same value.
    ///
    /// # Errors
    /// [`CellError`] if the engine refuses.
    pub fn captured_stdout(&self) -> Result<String, CellError> {
        let raw = self.container.logs_bytes()?;
        Ok(decode_capture(&raw.stdout))
    }

    /// [`AgentCell::captured_stdout`], required to actually BE a disclosure
    /// stream. This is the sealing read for an exec-consequence run.
    ///
    /// The extra requirement is [`DISCLOSURE_HEADER_KEY`] on the first line.
    /// `execrelayd`'s `disclosure_init` writes that header before it serves
    /// anything, and refuses to start if the write fails — so its presence is
    /// the one thing a relay that got as far as running cannot fail to have
    /// emitted, and a capture without it is not a thin disclosure log, it is
    /// not a disclosure log. Either the relay never started (a plain guest
    /// image, an entrypoint that died before `disclosure_init`) or the read did
    /// not reach the stream it was aiming at.
    ///
    /// Checked here rather than left to the parser downstream, which skips the
    /// header as a line carrying no turn data. That skip cannot tell an absent
    /// header from an absent log: both parse to zero observations, which is
    /// also what a genuine run with no intercepted exec produces. The
    /// difference between "the relay saw nothing" and "there was no relay
    /// stream" has to be made where the read happens, because that is the last
    /// place both facts are still present.
    ///
    /// # Errors
    /// [`CellError::Engine`] if the engine refuses the read, and
    /// [`CellError::NotADisclosureStream`] if what came back has no header.
    pub fn captured_disclosure_log(&self) -> Result<String, CellError> {
        require_disclosure_header(self.captured_stdout()?)
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

/// The key in the disclosure stream's header line, which `execrelayd` emits
/// once at startup (`disclosure_init`) before it can serve any request.
///
/// Matched as a substring of the first line rather than parsed: this is a
/// liveness check on the stream, not a schema check on the header, and it must
/// stay decoupled from whatever tells that header currently lists.
pub const DISCLOSURE_HEADER_KEY: &str = "known_residual_tells";

/// The captured stream's bytes as text, keeping everything that was not
/// invalid.
///
/// An invalid sequence becomes U+FFFD and costs its own line's readability;
/// every other byte arrives. The alternative — a strict decode whose failure
/// collapses to an empty string — erased a whole run's exec-consequence
/// evidence over one byte, which is the Critical this fallback exists to close.
///
/// **This is not reachable from the end-to-end tests, and that is why it is a
/// function.** The suite's two invalid-UTF-8 tests
/// (`one_invalid_utf8_byte_does_not_erase_the_rest_of_the_disclosure_log` and
/// `a_composed_detonation_seals_a_record_whose_argv0_is_not_valid_utf8` in
/// `chamber-e2e/tests/exec_consequence.rs`) do write a raw `0xFF` into a
/// disclosure record and do watch it survive to the sealed bundle — but Docker's
/// `json-file` log driver, this project's default, stores captured output as
/// JSON strings and REPAIRS invalid UTF-8 to U+FFFD on the way in. By the time
/// `docker logs` hands the bytes back to this process they are already valid
/// UTF-8. Those tests therefore exercise the sealing pipeline end to end, which
/// is worth having, but they would stay green against a strict decode: the byte
/// this fallback exists for never reaches it through that driver. Only the unit
/// tests below reach it — they hand it the bytes directly, so nothing upstream
/// gets to launder them first.
///
/// The fallback stays regardless. It is what a different log driver, a raw
/// Engine API read, or any capture path that does not pre-sanitise would meet,
/// and being unreachable through one particular driver is not the same as being
/// unnecessary.
fn decode_capture(bytes: &[u8]) -> String {
    String::from_utf8_lossy(bytes).into_owned()
}

/// Accepts `text` as a disclosure stream only if it opens with the header.
///
/// Split out of [`AgentCell::captured_disclosure_log`] so the decision is
/// reachable from a test without an engine, a guest image or a relay — the
/// captures worth pinning (empty, and plausible-but-headerless) are values, not
/// situations that can be arranged against a live daemon.
fn require_disclosure_header(text: String) -> Result<String, CellError> {
    let first = text.lines().find(|l| !l.trim().is_empty()).unwrap_or("");
    if first.contains(DISCLOSURE_HEADER_KEY) {
        Ok(text)
    } else {
        Err(CellError::NotADisclosureStream {
            captured_bytes: text.len(),
            first_line: first.chars().take(200).collect(),
        })
    }
}

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

    /// An empty capture is the shape every lost read collapses to, and it is
    /// the one shape that must never be accepted as a disclosure log.
    ///
    /// A relay that ran wrote the header before it could serve anything, so
    /// there is no such thing as a disclosure stream with nothing in it. Read
    /// as `Ok("")` this seals a bundle with zero exec-consequence observations
    /// and `disclosure_log_read: true` — the channel claimed `Watched` over
    /// evidence that was never read, which is round 2's Critical exactly.
    #[test]
    fn an_empty_capture_is_not_an_empty_disclosure_log() {
        let err = require_disclosure_header(String::new())
            .expect_err("an empty capture cannot be a disclosure stream");
        match err {
            CellError::NotADisclosureStream {
                captured_bytes,
                first_line,
            } => {
                assert_eq!(captured_bytes, 0);
                assert_eq!(first_line, "");
            }
            other => panic!("expected NotADisclosureStream, got {other:?}"),
        }
    }

    /// A capture with plausible content but no header is the subtler half: the
    /// downstream parser skips every line it cannot read as a record, so this
    /// too arrives as zero observations — indistinguishable from a relay that
    /// intercepted nothing unless the read itself refuses it.
    #[test]
    fn a_capture_without_the_header_is_not_a_disclosure_log() {
        let not_ours = "execrelayd: starting\nsome other guest's chatter\n".to_owned();
        let err = require_disclosure_header(not_ours)
            .expect_err("a headerless capture cannot be a disclosure stream");
        let CellError::NotADisclosureStream { first_line, .. } = err else {
            panic!("expected NotADisclosureStream");
        };
        // The operator gets the first line back verbatim: what arrived instead
        // is the only clue to why.
        assert_eq!(first_line, "execrelayd: starting");
    }

    /// The guard must not be bought by rejecting the real thing. A genuine
    /// stream is accepted verbatim, records and all — including one whose
    /// header is the ONLY line, which is a relay that started and legitimately
    /// intercepted nothing, and is a different claim from a lost read.
    #[test]
    fn a_real_disclosure_stream_passes_through_unchanged() {
        let header = "{\"known_residual_tells\":[\"TracerPid nonzero\"]}\n";
        let header_only = require_disclosure_header(header.to_owned())
            .expect("a relay that intercepted nothing still wrote its header");
        assert_eq!(header_only, header);

        let with_records = format!(
            "{header}{}{}",
            "{\"turn_id\":\"turn-0\",\"requested_argv0\":\"/bin/echo\"}\n",
            "{\"turn_id\":\"turn-1\",\"requested_argv0\":\"/bin/ls\"}\n"
        );
        assert_eq!(
            require_disclosure_header(with_records.clone()).expect("a real stream"),
            with_records
        );
    }

    /// The sealing read's lossy decode, driven directly.
    ///
    /// This is the test that actually pins the fallback. The end-to-end pair in
    /// `chamber-e2e` cannot: Docker's `json-file` driver repairs invalid UTF-8
    /// before `docker logs` returns it, so the bytes those tests plant never
    /// arrive here as invalid — see [`decode_capture`]'s note. Handed the
    /// bytes directly, there is nothing upstream to launder them.
    ///
    /// The three properties, all of which a strict decode fails: the surrounding
    /// content survives, the invalid byte is REPRESENTED rather than dropped,
    /// and the whole thing does not collapse to an error, a panic, or an empty
    /// string — the last being the exact shape of the Critical, since an empty
    /// capture seals as a run with zero exec-consequence observations.
    #[test]
    fn an_invalid_byte_in_the_capture_costs_its_own_character_and_nothing_else() {
        // A realistic disclosure stream: the header, a record whose
        // `requested_argv0` carries a raw 0xFF the way a path read out of
        // tracee memory can, and a record after it.
        let mut captured = Vec::new();
        captured.extend_from_slice(b"{\"known_residual_tells\":[\"TracerPid nonzero\"]}\n");
        captured.extend_from_slice(b"{\"turn_id\":\"turn-0\",\"requested_argv0\":\"/bin/no");
        captured.push(0xff);
        captured.extend_from_slice(b"such\"}\n");
        captured.extend_from_slice(b"{\"turn_id\":\"turn-1\",\"requested_argv0\":\"/bin/echo\"}\n");
        assert!(
            String::from_utf8(captured.clone()).is_err(),
            "this fixture is supposed to be invalid UTF-8; without that the test \
             proves nothing"
        );

        let decoded = decode_capture(&captured);

        assert!(
            !decoded.is_empty(),
            "the whole capture collapsed to nothing — the erasure this fallback exists for"
        );
        assert_eq!(
            decoded.lines().count(),
            3,
            "every line must survive, not just the clean ones: {decoded:?}"
        );
        assert!(decoded.contains("known_residual_tells"));
        assert!(decoded.contains("turn-1"));

        let bad = decoded.lines().nth(1).expect("the middle line");
        assert!(
            bad.contains('\u{FFFD}'),
            "the invalid byte was dropped rather than represented: {bad:?}"
        );
        assert!(bad.starts_with("{\"turn_id\":\"turn-0\""), "{bad:?}");
        assert!(bad.ends_with("such\"}"), "{bad:?}");
    }

    /// And the decode composes with the header guard: a stream whose records
    /// carry invalid bytes is still a disclosure stream, because the header line
    /// is intact. The two guards must not cancel each other out — a lossy decode
    /// that made the capture unrecognisable to
    /// [`require_disclosure_header`] would turn one bad byte into a refused read,
    /// which is the erasure again wearing the other guard's clothes.
    #[test]
    fn an_invalid_byte_in_a_record_does_not_disqualify_the_stream() {
        let mut captured = Vec::new();
        captured.extend_from_slice(b"{\"known_residual_tells\":[\"TracerPid nonzero\"]}\n");
        captured.extend_from_slice(b"{\"turn_id\":\"turn-0\",\"requested_argv0\":\"/bin/");
        captured.push(0xfe);
        captured.extend_from_slice(b"\"}\n");

        let accepted = require_disclosure_header(decode_capture(&captured))
            .expect("a stream with a valid header is a disclosure stream, bad bytes and all");
        assert_eq!(accepted.lines().count(), 2);
        assert!(accepted.contains('\u{FFFD}'));
    }

    /// Valid input must come back unchanged, so "survives invalid UTF-8" has not
    /// been bought by mangling the ordinary case — which is every real run.
    #[test]
    fn a_valid_capture_is_decoded_verbatim() {
        let text =
            "{\"known_residual_tells\":[]}\n{\"detail\":\"caf\u{e9} \u{20ac}5 \u{1f4a5}\"}\n";
        assert_eq!(decode_capture(text.as_bytes()), text);
    }

    /// The header is required on the FIRST line, which is where `execrelayd`
    /// guarantees it. Anywhere else and the stream's opening records are
    /// missing, whatever else arrived.
    #[test]
    fn the_header_must_be_first_not_merely_present() {
        let late = "{\"turn_id\":\"turn-0\"}\n{\"known_residual_tells\":[\"x\"]}\n".to_owned();
        assert!(
            require_disclosure_header(late).is_err(),
            "a header after a record is not the startup header"
        );
    }
}
