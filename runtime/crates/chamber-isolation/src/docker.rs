//! The container engine, driven by its CLI.
//!
//! # Why the CLI and not the API socket
//!
//! Two of this crate's prohibitions are easier to *enforce* than to remember,
//! and both are about argument construction: a canary must never be passed as
//! `-e KEY=VALUE`, because that puts the secret in the host process table where
//! any user on the machine can read it with `ps`; and a container must be
//! destroyed by the id captured at create, never by a name or a label, because
//! names and labels can collide with something a previous run left behind or
//! that a hostile artefact arranged. Both are expressible as *the API this
//! module does not offer*: [`ContainerSpec`] has no free-form environment
//! field, and [`Container`] holds a private id with no constructor from a name.
//!
//! # Timeouts are not optional here
//!
//! Every call goes through [`run_within`]. A `docker exec` into a cell running
//! a hostile artefact can block forever, and a detonation harness that hangs is
//! a detonation harness that gets `Ctrl-C`'d and its evidence lost. Output is
//! collected via temporary files rather than pipes: a piped child that fills
//! the OS pipe buffer blocks on write while the parent blocks on wait, and that
//! deadlock only shows up under exactly the verbose failure conditions where
//! the output mattered most.

use std::ffi::OsStr;
use std::fmt;
use std::fs::File;
use std::io;
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

/// How often a running child is checked for exit while waiting out a timeout.
const POLL_INTERVAL: Duration = Duration::from_millis(20);

/// The engine is not usable, and the reason a human needs in order to fix it.
#[derive(Debug)]
pub enum DockerUnavailable {
    /// No `docker` on `PATH`.
    NotInstalled(io::Error),
    /// The binary is there; the daemon did not answer.
    DaemonUnreachable { detail: String },
    /// The daemon answered, but it is not a Linux engine. Every containment
    /// property in this crate is a Linux kernel property — network namespaces,
    /// netfilter hooks, capability bounding sets. There is nothing to fall back
    /// to and pretending otherwise would produce a green tick for a boundary
    /// that does not exist.
    NotLinux { os_type: String },
}

impl fmt::Display for DockerUnavailable {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotInstalled(e) => write!(f, "no docker binary on PATH: {e}"),
            Self::DaemonUnreachable { detail } => {
                write!(f, "docker daemon did not answer: {detail}")
            }
            Self::NotLinux { os_type } => write!(
                f,
                "engine reports OSType={os_type}; containment requires a Linux engine"
            ),
        }
    }
}

impl std::error::Error for DockerUnavailable {}

/// A command the engine refused, or never answered.
#[derive(Debug)]
pub enum EngineError {
    /// The process could not be spawned or its output could not be collected.
    Io(io::Error),
    /// `docker` exited non-zero.
    Failed {
        argv: Vec<String>,
        status: Option<i32>,
        stderr: String,
    },
    /// `docker` was still running when the caller's window closed. The child
    /// has been killed; whatever it was doing inside the guest may not have
    /// been.
    TimedOut { argv: Vec<String>, after: Duration },
    /// A capture this process must hold in memory came back larger than the
    /// caller is willing to read. Refused rather than truncated: a shortened
    /// disclosure log that nothing says was shortened is the failure mode this
    /// whole channel is built to avoid.
    CaptureTooLarge {
        argv: Vec<String>,
        /// Which of the two captures blew the cap. Both are bounded and both
        /// are agent-driven, so the operator needs to be told which one — they
        /// mean different things (`stdout` is the disclosure stream itself,
        /// `stderr` the relay's operator log).
        stream: &'static str,
        bytes: u64,
        cap: u64,
    },
}

impl fmt::Display for EngineError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(e) => write!(f, "docker could not be run: {e}"),
            Self::Failed {
                argv,
                status,
                stderr,
            } => write!(
                f,
                "`docker {}` exited {}: {}",
                argv.join(" "),
                status.map_or_else(|| "by signal".to_owned(), |c| c.to_string()),
                stderr.trim()
            ),
            Self::TimedOut { argv, after } => write!(
                f,
                "`docker {}` still running after {:?}; killed",
                argv.join(" "),
                after
            ),
            Self::CaptureTooLarge {
                argv,
                stream,
                bytes,
                cap,
            } => write!(
                f,
                "`docker {}` produced {bytes} bytes of {stream}, over the {cap}-byte cap this \
                 read holds in memory; refused rather than truncated, because a shortened \
                 capture that nothing says was shortened is indistinguishable from a complete one",
                argv.join(" "),
            ),
        }
    }
}

impl std::error::Error for EngineError {}

impl From<io::Error> for EngineError {
    fn from(e: io::Error) -> Self {
        Self::Io(e)
    }
}

/// What a finished command produced.
#[derive(Debug, Clone)]
pub struct ExecOutcome {
    pub status: Option<i32>,
    pub stdout: String,
    pub stderr: String,
}

impl ExecOutcome {
    /// True when the command exited zero.
    #[must_use]
    pub fn ok(&self) -> bool {
        self.status == Some(0)
    }
}

/// What a finished command produced, before any text decoding.
///
/// The undecoded form exists because for one caller — reading the exec-relay's
/// captured disclosure stream — deciding how to survive a non-UTF-8 byte is the
/// caller's call and not something this module may make silently. See
/// [`Container::logs_bytes`].
#[derive(Debug, Clone)]
pub struct RawOutcome {
    pub status: Option<i32>,
    pub stdout: Vec<u8>,
    pub stderr: Vec<u8>,
}

impl RawOutcome {
    /// True when the command exited zero.
    #[must_use]
    pub fn ok(&self) -> bool {
        self.status == Some(0)
    }
}

/// Runs `docker <argv>`, killing it if it outlives `within`.
///
/// Returns the outcome whatever the exit status: callers that need a non-zero
/// exit to be an error say so with [`ExecOutcome::ok`]. Several of them
/// deliberately do not — a probe technique that is *supposed* to fail exits
/// non-zero, and that is the measurement, not an error.
fn run_within(argv: &[&str], within: Duration) -> Result<ExecOutcome, EngineError> {
    let raw = run_within_raw(argv, within)?;
    Ok(ExecOutcome {
        status: raw.status,
        stdout: decode_lossy(raw.stdout),
        stderr: decode_lossy(raw.stderr),
    })
}

/// [`run_within`], stopping short of turning the output into text.
fn run_within_raw(argv: &[&str], within: Duration) -> Result<RawOutcome, EngineError> {
    run_within_raw_capped(argv, within, None)
}

/// [`run_within_raw`] with an optional ceiling on how much output it will read
/// into memory.
///
/// The cap is checked against the capture FILE's size before a byte of it is
/// read, which is what makes it a bound on this process's memory rather than an
/// after-the-fact complaint about an allocation that already happened. Child
/// output goes to a temporary file rather than a pipe (see the spawn below), so
/// the size is there to be asked for.
///
/// One caller passes a cap — see [`Container::logs_bytes`] — and it is the only
/// read whose length is chosen by the artefact under evaluation rather than by
/// this harness.
///
/// **Both streams, not just stdout.** `docker logs` splits the container's two
/// streams across its own two, and for the exec-relay guest BOTH are written by
/// something the agent drives: stdout carries one disclosure record per
/// intercepted exec, and stderr carries `execrelayd`'s per-trap `logline` —
/// which fires on every trap, including the PATH probes that are deliberately
/// not recorded, so it can be the LARGER of the two. Capping only stdout bounds
/// the smaller half and leaves the other an unbounded read into this process's
/// memory. Nothing about the reasoning for the cap distinguishes the streams, so
/// neither does the cap.
fn run_within_raw_capped(
    argv: &[&str],
    within: Duration,
    capture_cap: Option<u64>,
) -> Result<RawOutcome, EngineError> {
    let (out_path, err_path) = (scratch_path("out"), scratch_path("err"));
    let mut child = Command::new("docker")
        .args(argv)
        .stdin(Stdio::null())
        .stdout(Stdio::from(File::create(&out_path)?))
        .stderr(Stdio::from(File::create(&err_path)?))
        .spawn()?;

    let started = Instant::now();
    let status = loop {
        match child.try_wait()? {
            Some(status) => break Some(status),
            None if started.elapsed() >= within => {
                let _ = child.kill();
                let _ = child.wait();
                break None;
            }
            None => std::thread::sleep(POLL_INTERVAL),
        }
    };

    // Before the read, not after it: the whole point of the cap is that the
    // oversized capture never becomes a `Vec<u8>` in this process.
    let too_large = over_cap(argv, "stdout", captured_len(&out_path), capture_cap)
        .or_else(|| over_cap(argv, "stderr", captured_len(&err_path), capture_cap));
    if let Some(refusal) = too_large {
        let _ = std::fs::remove_file(&out_path);
        let _ = std::fs::remove_file(&err_path);
        return Err(refusal);
    }

    let stdout = read_bytes_and_remove(&out_path);
    let stderr = read_bytes_and_remove(&err_path);

    match status {
        Some(status) => Ok(RawOutcome {
            status: status.code(),
            stdout,
            stderr,
        }),
        None => Err(EngineError::TimedOut {
            argv: argv.iter().map(|a| (*a).to_owned()).collect(),
            after: within,
        }),
    }
}

/// [`run_within`], but a non-zero exit is an error. For engine operations
/// (create, rm, network) where a failure is never a measurement.
fn must_run(argv: &[&str], within: Duration) -> Result<String, EngineError> {
    let outcome = run_within(argv, within)?;
    if outcome.ok() {
        Ok(outcome.stdout.trim().to_owned())
    } else {
        Err(EngineError::Failed {
            argv: argv.iter().map(|a| (*a).to_owned()).collect(),
            status: outcome.status,
            stderr: outcome.stderr,
        })
    }
}

/// The exit-status half of the raw read, split out so it is reachable from
/// a test without an engine.
///
/// The condition it guards — the command exited non-zero having written NO
/// stdout — is trivial to construct as a value and impossible to arrange
/// reliably against a live daemon, and it is exactly the shape that must never
/// reach a caller as a successful empty read.
fn raw_or_failed(argv: &[&str], outcome: RawOutcome) -> Result<RawOutcome, EngineError> {
    if outcome.ok() {
        Ok(outcome)
    } else {
        Err(EngineError::Failed {
            argv: argv.iter().map(|a| (*a).to_owned()).collect(),
            status: outcome.status,
            stderr: decode_lossy(outcome.stderr),
        })
    }
}

/// The ceiling on a `docker logs` capture this process reads into memory, per
/// stream. See [`Container::logs_bytes`] for why this one read is bounded when
/// no other is.
///
/// 64 MiB is far more disclosure than any legitimate run produces (a record is
/// a few hundred bytes, so this is on the order of a hundred thousand execs),
/// so nothing real is at risk of tripping it, and a run that does trip it has
/// something wrong with it that a reviewer should be told about rather than
/// have papered over by a truncated read. Refused rather than truncated, for
/// the reason everything in this subsystem is.
///
/// Module-level rather than a local inside `logs_bytes` so the tests can state
/// the bound they are pinning instead of restating the number.
const LOGS_BYTES_CAP: u64 = 64 * 1024 * 1024;

/// The cap decision, split out so it is reachable from a test without an
/// engine — for the same reason [`raw_or_failed`] is.
///
/// A capture large enough to trip the cap cannot be arranged against a live
/// daemon in a test worth running: the bound is 64 MiB and producing it means an
/// agent that spent its run in a loop. As a value it is one line. The condition
/// that matters is the boundary — `bytes > cap` refuses, `bytes == cap` does
/// not — and the outcome that matters is that the oversized capture becomes an
/// ERROR rather than a truncated success, which is the one thing this whole
/// subsystem exists to prevent.
///
/// `None` for a capture within its cap, or for a caller that set none.
fn over_cap(
    argv: &[&str],
    stream: &'static str,
    bytes: u64,
    cap: Option<u64>,
) -> Option<EngineError> {
    let cap = cap?;
    (bytes > cap).then(|| EngineError::CaptureTooLarge {
        argv: argv.iter().map(|a| (*a).to_owned()).collect(),
        stream,
        bytes,
        cap,
    })
}

/// How many bytes a capture file holds, without reading it.
///
/// Unreadable metadata answers 0, which declines to refuse rather than refusing
/// on a guess: the read that follows will produce whatever it can, and the cap
/// is a memory bound, not an assertion about the filesystem.
fn captured_len(path: &PathBuf) -> u64 {
    std::fs::metadata(path).map_or(0, |m| m.len())
}

fn scratch_path(kind: &str) -> PathBuf {
    static SEQ: AtomicU64 = AtomicU64::new(0);
    let n = SEQ.fetch_add(1, Ordering::Relaxed);
    std::env::temp_dir().join(format!(
        "chamber-{}-{}-{}.{kind}",
        std::process::id(),
        n,
        kind
    ))
}

fn read_bytes_and_remove(path: &PathBuf) -> Vec<u8> {
    let bytes = std::fs::read(path).unwrap_or_default();
    let _ = std::fs::remove_file(path);
    bytes
}

fn read_and_remove(path: &PathBuf) -> String {
    decode_lossy(read_bytes_and_remove(path))
}

/// Bytes to text, keeping everything that was not invalid.
///
/// **Never `read_to_string`, never strict `String::from_utf8`, and never
/// `.unwrap_or_default()` over either.** That combination was round 2's
/// Critical: `std::fs::read_to_string` fails the WHOLE read with
/// `InvalidData` on a single malformed byte, and `.unwrap_or_default()` then
/// turns "some of these bytes were not UTF-8" into "there was no output" — with
/// the command's exit status still 0, so every caller takes its success branch
/// over an empty string. For the exec-relay's disclosure log that meant one bad
/// byte anywhere in a run erased every exec-consequence observation in the
/// sealed bundle, while the bundle still reported the channel as watched.
///
/// Lossy decoding is the opposite failure mode and the right one here: an
/// invalid sequence becomes U+FFFD and costs only its own line's readability,
/// while every other byte arrives. Nothing in this crate's output handling is
/// UTF-8-critical — it is all evidence and diagnostics, where a partly
/// unreadable record beats a silently absent one.
fn decode_lossy(bytes: Vec<u8>) -> String {
    match String::from_utf8(bytes) {
        // The overwhelmingly common case, and it costs no copy.
        Ok(text) => text,
        Err(e) => String::from_utf8_lossy(e.as_bytes()).into_owned(),
    }
}

/// A reachable Linux container engine.
#[derive(Debug, Clone)]
pub struct Docker {
    server_version: String,
    os_type: String,
    arch: String,
}

impl Docker {
    /// Confirms an engine is there and that it is Linux.
    ///
    /// # Errors
    /// [`DockerUnavailable`] describing which of the three ways it was missing.
    pub fn probe() -> Result<Self, DockerUnavailable> {
        let probe_window = Duration::from_secs(20);
        let outcome = run_within(
            &[
                "version",
                "--format",
                "{{.Server.Version}}\n{{.Server.Os}}\n{{.Server.Arch}}",
            ],
            probe_window,
        );

        let outcome = match outcome {
            Ok(o) => o,
            Err(EngineError::Io(e)) if e.kind() == io::ErrorKind::NotFound => {
                return Err(DockerUnavailable::NotInstalled(e));
            }
            Err(e) => {
                return Err(DockerUnavailable::DaemonUnreachable {
                    detail: e.to_string(),
                });
            }
        };

        if !outcome.ok() {
            return Err(DockerUnavailable::DaemonUnreachable {
                detail: outcome.stderr.trim().to_owned(),
            });
        }

        let mut lines = outcome.stdout.lines();
        let server_version = lines.next().unwrap_or_default().trim().to_owned();
        let os_type = lines.next().unwrap_or_default().trim().to_owned();
        let arch = lines.next().unwrap_or_default().trim().to_owned();

        if os_type != "linux" {
            return Err(DockerUnavailable::NotLinux { os_type });
        }

        Ok(Self {
            server_version,
            os_type,
            arch,
        })
    }

    #[must_use]
    pub fn server_version(&self) -> &str {
        &self.server_version
    }

    #[must_use]
    pub fn os_type(&self) -> &str {
        &self.os_type
    }

    /// The architecture the guest actually ran on. Recorded into the bundle as
    /// `gap.host-arch`: a payload may behave differently on aarch64 than on
    /// amd64, and which one produced a given artefact is not guessable later.
    #[must_use]
    pub fn arch(&self) -> &str {
        &self.arch
    }
}

/// What a network should be.
#[derive(Debug, Clone)]
pub struct NetworkSpec {
    pub name: String,
    /// CIDR, e.g. `10.66.0.0/24`. Fixed rather than engine-assigned because
    /// the ruleset matches on destination address and the probe expectations
    /// name literal addresses.
    pub subnet: String,
    /// `--internal`. The chamber's own network is internal; the scratch
    /// network the unarmed control runs on deliberately is not.
    pub internal: bool,
}

/// A live docker network, removed on [`Network::destroy`].
#[derive(Debug)]
pub struct Network {
    id: String,
    spec: NetworkSpec,
}

impl Network {
    /// Creates the network, replacing any leftover of the same name.
    ///
    /// # Errors
    /// [`EngineError`] if the engine refuses.
    pub fn raise(spec: NetworkSpec) -> Result<Self, EngineError> {
        // A previous run that died before teardown leaves the name taken, and
        // the subnet with it. Removing by name is safe *here* in a way it is
        // not for containers: a network carries no evidence and holds no id we
        // could have captured, and leaving it makes every subsequent run fail.
        let _ = must_run(&["network", "rm", &spec.name], Duration::from_secs(20));

        let mut argv = vec!["network", "create", "--subnet", &spec.subnet];
        if spec.internal {
            argv.push("--internal");
        }
        argv.push(&spec.name);

        let id = must_run(&argv, Duration::from_secs(30))?;
        Ok(Self { id, spec })
    }

    #[must_use]
    pub fn id(&self) -> &str {
        &self.id
    }

    #[must_use]
    pub fn name(&self) -> &str {
        &self.spec.name
    }

    #[must_use]
    pub fn subnet(&self) -> &str {
        &self.spec.subnet
    }

    #[must_use]
    pub fn is_internal(&self) -> bool {
        self.spec.internal
    }

    /// A network value standing for one the engine returned, for tests that
    /// exercise the netfilter *parsing* without raising anything.
    ///
    /// The parsers in [`crate::preflight`] are the part most likely to be
    /// subtly wrong — matching another bridge's rules, or the default docker0
    /// MASQUERADE — and those cases are far easier to construct as text than to
    /// arrange on a live engine.
    #[cfg(test)]
    pub(crate) fn for_test(id: String, subnet: String) -> Self {
        Self {
            id,
            spec: NetworkSpec {
                name: "chamber-test".to_owned(),
                subnet,
                internal: true,
            },
        }
    }

    /// Removes the network by the id captured at create.
    ///
    /// # Errors
    /// [`EngineError`] if the engine refuses — usually because a container is
    /// still attached.
    pub fn destroy(self) -> Result<(), EngineError> {
        must_run(&["network", "rm", &self.id], Duration::from_secs(30))?;
        Ok(())
    }
}

/// How a container should be created.
///
/// There is deliberately no free-form environment field. Values reach a cell
/// through an `--env-file` with 0600 permissions, because `-e KEY=VALUE` puts
/// the value in the host process table for the lifetime of the container.
#[derive(Debug, Clone)]
pub struct ContainerSpec {
    pub image: String,
    /// Attachment. Either a network by name plus a fixed address, or another
    /// container's namespace.
    pub attach: Attach,
    /// `--cap-add`. Empty is the correct value for anything in the agent's
    /// position; only the warden has an entry here.
    pub cap_add: Vec<String>,
    /// `--cap-drop ALL` is applied unconditionally and is not configurable.
    pub argv: Vec<String>,
    /// `--entrypoint`, replacing whatever the image declares. `None` leaves the
    /// image's own entrypoint in place, which is what everything that wants to
    /// run the image *as itself* should use.
    ///
    /// It exists for the one caller that wants to run a command *in* an image
    /// rather than run the image: [`crate::preflight`]'s routing check, which
    /// needs `ip route` out of the guest image. An image with an `ENTRYPOINT`
    /// — the exec-consequence relay's is `execrelayd` — swallows `argv` as
    /// arguments to that entrypoint, so the command never runs. Left
    /// unoverridden that produced no output at all, which the routing check
    /// then read as "no default route". See `check_no_default_route`.
    pub entrypoint: Option<String>,
    /// Sysctls the cell needs. Applied with `--sysctl`.
    pub sysctls: Vec<(String, String)>,
    /// A 0600 file of `KEY=VALUE` lines, passed as `--env-file`.
    ///
    /// This is the *only* way a value reaches a container here. `-e KEY=VALUE`
    /// is absent from this API on purpose: it puts the value in the host
    /// process table for the container's whole lifetime, where any user on the
    /// machine can read it out of `ps` — and the values that eventually flow
    /// through here are planted canaries.
    pub env_file: Option<PathBuf>,
    /// Resolvers, as `--dns`. Empty leaves the engine's default in place.
    pub dns: Vec<String>,
    /// `--read-only`, making the container's own rootfs immutable.
    pub read_only: bool,
    /// Host bind mounts, as `host:container[:opts]`.
    ///
    /// **Never for the agent cell.** [`AgentCell`](crate::AgentCell) does not
    /// set this and must not: a mount hands the artefact a handle on host
    /// state, which is the thing the chamber exists to prevent.
    ///
    /// It exists for the *observer*, whose ledger has to outlive the chamber.
    /// The wind-down tears containers down before it records the run, so
    /// evidence living only inside a container would be destroyed a stage
    /// before the bundle that reports it is written.
    pub volumes: Vec<String>,
    /// Anonymous in-memory filesystems, as `--tmpfs <path>`.
    ///
    /// Not a bind mount and deliberately not one: a tmpfs gives the container
    /// somewhere to write without giving it a handle on any host directory.
    /// With a read-only rootfs it is the *only* writable place, which is what
    /// makes "what did the artefact leave behind" a bounded question.
    pub tmpfs: Vec<String>,
}

/// A `KEY=VALUE` file that is removed when dropped.
///
/// Created 0600 before anything is written to it, so the values are never
/// world-readable even briefly.
#[derive(Debug)]
pub struct EnvFile {
    path: PathBuf,
}

impl EnvFile {
    /// Writes the pairs to a fresh 0600 file.
    ///
    /// # Errors
    /// [`io::Error`] if the file cannot be created or written.
    pub fn write(pairs: &[(String, String)]) -> io::Result<Self> {
        use std::io::Write as _;
        use std::os::unix::fs::OpenOptionsExt as _;

        let path = scratch_path("env");
        let mut file = std::fs::OpenOptions::new()
            .create_new(true)
            .write(true)
            .mode(0o600)
            .open(&path)?;
        for (k, v) in pairs {
            writeln!(file, "{k}={v}")?;
        }
        file.sync_all()?;
        Ok(Self { path })
    }

    #[must_use]
    pub fn path(&self) -> &PathBuf {
        &self.path
    }
}

impl Drop for EnvFile {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.path);
    }
}

/// Builds an image from a context directory.
///
/// # Errors
/// [`EngineError`] if the build fails, carrying the builder's stderr — which
/// is where a missing package or a failed `apk add` actually says so.
pub fn build_image(context_dir: &std::path::Path, tag: &str) -> Result<(), EngineError> {
    let dir = context_dir.to_string_lossy().into_owned();
    must_run(&["build", "-t", tag, &dir], BUILD_WINDOW)?;
    Ok(())
}

/// Builds an image for one explicitly named platform (`linux/arm64`,
/// `linux/amd64`, …) rather than for whatever the engine's host happens to be.
///
/// Only for images whose *contents* are architecture-bound, where the host's
/// default is not a preference but a wrong answer. The guest-exec-relay image
/// is the one such image: `execrelayd` intercepts execs with a seccomp filter
/// gated on `AUDIT_ARCH_AARCH64` and arm64 register plumbing, so on any other
/// architecture the filter's arch check fails and every worker is killed by
/// `SECCOMP_RET_KILL_PROCESS` before its `execve` completes. Keeping it
/// aarch64-only is a decision, not an oversight (design artefact
/// `agenticpractices:artefact:2rau75fl5jsg3c4c8pla` section 7); this is where
/// the decision is made explicit at the build, instead of being inherited
/// silently from whichever machine happens to run it.
///
/// # Errors
/// [`EngineError`] if the build fails, carrying the builder's stderr — which
/// on a platform the image refuses is `relayd.c`'s own `#error` line.
pub fn build_image_for_platform(
    context_dir: &std::path::Path,
    tag: &str,
    platform: &str,
) -> Result<(), EngineError> {
    let dir = context_dir.to_string_lossy().into_owned();
    must_run(
        &["build", "--platform", platform, "-t", tag, &dir],
        BUILD_WINDOW,
    )?;
    Ok(())
}

/// Builds an image whose Dockerfile lives outside its build context.
///
/// The capture image needs this: its Dockerfile sits in `images/capture/` but
/// it compiles the workspace, so its context must be `runtime/`. Pointing the
/// context at the Dockerfile's own directory instead would produce a build that
/// cannot see a single crate.
///
/// # Errors
/// [`EngineError`] carrying the builder's stderr, which is where a missing
/// package or a failed compile actually says so.
pub fn build_image_with_dockerfile(
    context_dir: &std::path::Path,
    dockerfile: &std::path::Path,
    tag: &str,
) -> Result<(), EngineError> {
    let dir = context_dir.to_string_lossy().into_owned();
    let file = dockerfile.to_string_lossy().into_owned();
    must_run(&["build", "-f", &file, "-t", tag, &dir], BUILD_WINDOW)?;
    Ok(())
}

/// Generous on purpose. The capture image compiles ~290 crates including two
/// crypto backends, one of which is a cmake + C build, and a cold build on a
/// CI runner is minutes rather than seconds.
const BUILD_WINDOW: Duration = Duration::from_secs(30 * 60);

/// Where a container's network stack comes from.
#[derive(Debug, Clone)]
pub enum Attach {
    /// Its own interface on a network.
    ///
    /// `ip` is `Some` wherever an address is load-bearing — the ruleset matches
    /// on destination address and the probe table names literal addresses, so
    /// letting the engine assign one would make both depend on attachment
    /// order. It is `None` for throwaway inspections that only need to be *on*
    /// the network.
    Network { network: String, ip: Option<String> },
    /// No network stack of its own — it shares another container's namespace.
    /// This is how the agent cell is denied any ability to change the very
    /// rules that contain it: the netns belongs to the warden.
    SharedWith { container_id: String },
    /// No networking at all.
    None,
    /// The engine host's own network namespace.
    ///
    /// **Only the preflight inspector uses this**, and only to read: the two
    /// netfilter asserts are properties of the *host*, and there is no way to
    /// observe them from inside an isolated namespace. Nothing in the agent's
    /// position may ever be attached this way — it would hand the artefact the
    /// host's network stack, which is the entire thing being prevented.
    Host,
}

/// A created container, identified by the id the engine returned at create.
///
/// The id is captured once and is the only handle used afterwards. Destroying
/// by name or label would let a leftover from a previous run — or a container a
/// hostile artefact arranged to exist — be destroyed in place of this one.
#[derive(Debug)]
pub struct Container {
    id: String,
}

impl Container {
    /// Creates (but does not start) the container.
    ///
    /// # Errors
    /// [`EngineError`] if the engine refuses.
    pub fn create(spec: &ContainerSpec) -> Result<Self, EngineError> {
        let mut argv: Vec<String> = vec!["create".into(), "--cap-drop".into(), "ALL".into()];

        for cap in &spec.cap_add {
            argv.push("--cap-add".into());
            argv.push(cap.clone());
        }
        if let Some(entrypoint) = &spec.entrypoint {
            argv.push("--entrypoint".into());
            argv.push(entrypoint.clone());
        }
        for (k, v) in &spec.sysctls {
            argv.push("--sysctl".into());
            argv.push(format!("{k}={v}"));
        }
        if let Some(env_file) = &spec.env_file {
            argv.push("--env-file".into());
            argv.push(env_file.to_string_lossy().into_owned());
        }
        for resolver in &spec.dns {
            argv.push("--dns".into());
            argv.push(resolver.clone());
        }
        if spec.read_only {
            argv.push("--read-only".into());
        }
        for mount in &spec.tmpfs {
            argv.push("--tmpfs".into());
            argv.push(mount.clone());
        }
        for bind in &spec.volumes {
            argv.push("--volume".into());
            argv.push(bind.clone());
        }
        match &spec.attach {
            Attach::Network { network, ip } => {
                argv.push("--network".into());
                argv.push(network.clone());
                if let Some(ip) = ip {
                    argv.push("--ip".into());
                    argv.push(ip.clone());
                }
            }
            Attach::SharedWith { container_id } => {
                argv.push("--network".into());
                argv.push(format!("container:{container_id}"));
            }
            Attach::None => {
                argv.push("--network".into());
                argv.push("none".into());
            }
            Attach::Host => {
                argv.push("--network".into());
                argv.push("host".into());
            }
        }
        argv.push(spec.image.clone());
        argv.extend(spec.argv.iter().cloned());

        let borrowed: Vec<&str> = argv.iter().map(String::as_str).collect();
        let id = must_run(&borrowed, Duration::from_secs(60))?;
        Ok(Self { id })
    }

    #[must_use]
    pub fn id(&self) -> &str {
        &self.id
    }

    /// # Errors
    /// [`EngineError`] if the engine refuses.
    pub fn start(&self) -> Result<(), EngineError> {
        must_run(&["start", &self.id], Duration::from_secs(60))?;
        Ok(())
    }

    /// Stops the container, giving its process `grace` to exit on its own.
    ///
    /// SIGTERM first, SIGKILL after the grace period. That window is the only
    /// chance a process has to finish what it was doing — for the observer it
    /// is the difference between a sealed ledger and a truncated one, so the
    /// grace here and the observer's own wind-down budget are two halves of the
    /// same agreement.
    ///
    /// # Errors
    /// [`EngineError`] if the engine refuses.
    pub fn stop(&self, grace: Duration) -> Result<(), EngineError> {
        let seconds = grace.as_secs().to_string();
        must_run(
            &["stop", "-t", &seconds, &self.id],
            grace + Duration::from_secs(30),
        )?;
        Ok(())
    }

    /// Waits for the container's own process to exit, returning its code.
    ///
    /// # Errors
    /// [`EngineError`] if the wait itself fails or outlives `within`.
    pub fn wait(&self, within: Duration) -> Result<i32, EngineError> {
        let code = must_run(&["wait", &self.id], within)?;
        Ok(code.trim().parse().unwrap_or(-1))
    }

    /// Everything the container has written to stdout and stderr so far.
    ///
    /// # Errors
    /// [`EngineError`] if the engine refuses.
    pub fn logs(&self) -> Result<ExecOutcome, EngineError> {
        run_within(&["logs", &self.id], Duration::from_secs(30))
    }

    /// [`Container::logs`], undecoded.
    ///
    /// `docker logs` demultiplexes a non-TTY container's two streams onto its
    /// own stdout and stderr, so [`RawOutcome::stdout`] here is exactly what
    /// the container's PID 1 wrote to fd 1 — which for the exec-relay guest is
    /// the disclosure log and nothing else (`execrelayd`'s own operator output
    /// goes to stderr precisely so this holds).
    ///
    /// Bytes rather than text because the disclosure stream can carry a
    /// sequence that is not valid UTF-8: `requested_argv0` is a path read raw
    /// out of tracee memory and is under no encoding obligation. How to survive
    /// that is the caller's decision — see [`decode_lossy`] for the one
    /// decision that is never acceptable.
    ///
    /// This reads from the engine's own log storage, not from inside the
    /// container, which is what makes it both readable after the container has
    /// STOPPED (so sealing no longer has to be sequenced ahead of the
    /// wind-down's halt) and unreachable by anything running in the container.
    ///
    /// **A non-zero exit is an error here, not a measurement** — the one place
    /// in this type where reading logs differs from [`Container::exec`]. The
    /// engine can refuse this command for reasons that have nothing to do with
    /// the container's behaviour: a log driver it cannot read back (`none`,
    /// `syslog`, `fluentd`, `gelf`), a daemon hiccup, a container reaped by
    /// something outside this process. Every one of those exits non-zero with
    /// an EMPTY stdout, and an empty stdout is indistinguishable from a
    /// container that wrote nothing. For the disclosure stream that difference
    /// is the whole evidentiary claim: "the relay recorded no exec" and "the
    /// engine would not tell us what the relay recorded" must not arrive at the
    /// caller as the same value. This is the guard the old `docker exec cat`
    /// read carried (`Ok(outcome) if outcome.ok()`) and which the move to
    /// `docker logs` must not drop — losing it reinstates round 2's Critical
    /// through the new transport: a sealed bundle claiming the channel was
    /// watched over evidence nobody ever managed to read.
    ///
    /// # Errors
    /// [`EngineError::Failed`] if `docker logs` exits non-zero, and the other
    /// variants if it could not be run or outlived its window.
    pub fn logs_bytes(&self) -> Result<RawOutcome, EngineError> {
        // Bounded, unlike every other capture this module takes, and for a
        // reason specific to this one. `docker logs` on the relay cell returns
        // the disclosure stream, whose length is a function of how many execs
        // the agent under evaluation performed — i.e. it is chosen by the thing
        // being measured, not by this harness. A cell that spent its run in a
        // loop, or a process inside it writing to /proc/1/fd/1 (which the
        // relay's own notes acknowledge is reachable), produces a capture this
        // process would otherwise read into memory in full, on a host already
        // running several containers.
        //
        // Deliberately generous: see LOGS_BYTES_CAP.
        let argv = ["logs", self.id.as_str()];
        let outcome = run_within_raw_capped(&argv, Duration::from_secs(30), Some(LOGS_BYTES_CAP))?;
        raw_or_failed(&argv, outcome)
    }

    /// Runs a command inside the container, feeding `input` to its stdin.
    ///
    /// This is how a file gets *into* a container. The alternatives are worse:
    /// a bind mount gives the cell a handle on host state, and passing content
    /// as an argument puts it in the process table — which is fatal the moment
    /// the content is a planted canary rather than a ruleset.
    ///
    /// # Errors
    /// [`EngineError`] if the exec could not be performed, outlived `within`,
    /// or exited non-zero.
    pub fn exec_with_stdin(
        &self,
        argv: &[&str],
        input: &[u8],
        within: Duration,
    ) -> Result<ExecOutcome, EngineError> {
        use std::io::Write as _;

        let (out_path, err_path) = (scratch_path("out"), scratch_path("err"));
        let mut full: Vec<&str> = vec!["exec", "-i", &self.id];
        full.extend_from_slice(argv);

        let mut child = Command::new("docker")
            .args(&full)
            .stdin(Stdio::piped())
            .stdout(Stdio::from(File::create(&out_path)?))
            .stderr(Stdio::from(File::create(&err_path)?))
            .spawn()?;

        // Written and dropped before the wait: holding the pipe open leaves the
        // child blocked on a read that never ends, which presents as a timeout
        // rather than as the deadlock it is.
        {
            let mut stdin = child
                .stdin
                .take()
                .ok_or_else(|| io::Error::new(io::ErrorKind::BrokenPipe, "stdin was not piped"))?;
            stdin.write_all(input)?;
        }

        let started = Instant::now();
        let status = loop {
            match child.try_wait()? {
                Some(status) => break Some(status),
                None if started.elapsed() >= within => {
                    let _ = child.kill();
                    let _ = child.wait();
                    break None;
                }
                None => std::thread::sleep(POLL_INTERVAL),
            }
        };

        let stdout = read_and_remove(&out_path);
        let stderr = read_and_remove(&err_path);
        let argv_owned = || full.iter().map(|a| (*a).to_owned()).collect::<Vec<_>>();

        match status {
            Some(status) if status.code() == Some(0) => Ok(ExecOutcome {
                status: status.code(),
                stdout,
                stderr,
            }),
            Some(status) => Err(EngineError::Failed {
                argv: argv_owned(),
                status: status.code(),
                stderr,
            }),
            None => Err(EngineError::TimedOut {
                argv: argv_owned(),
                after: within,
            }),
        }
    }

    /// Starts a command inside the container and returns without waiting.
    ///
    /// For long-lived processes — the NFLOG collector, which must outlive the
    /// call that starts it. Because nothing waits on it, *starting* it proves
    /// nothing about whether it is running: the caller must confirm that
    /// separately.
    ///
    /// # Errors
    /// [`EngineError`] if the engine refuses to start it.
    pub fn exec_detached(&self, argv: &[&str], within: Duration) -> Result<(), EngineError> {
        let mut full: Vec<&str> = vec!["exec", "-d", &self.id];
        full.extend_from_slice(argv);
        must_run(&full, within)?;
        Ok(())
    }

    /// Runs a command inside the container.
    ///
    /// A non-zero exit is returned, not raised: for a probe, failing is the
    /// measurement.
    ///
    /// # Errors
    /// [`EngineError`] only if the exec could not be performed or outlived
    /// `within`.
    pub fn exec<S: AsRef<OsStr> + AsRef<str>>(
        &self,
        argv: &[S],
        within: Duration,
    ) -> Result<ExecOutcome, EngineError> {
        let mut full: Vec<&str> = vec!["exec", &self.id];
        full.extend(argv.iter().map(AsRef::<str>::as_ref));
        run_within(&full, within)
    }

    /// Removes the container by its captured id, killing it if it is running.
    ///
    /// # Errors
    /// [`EngineError`] if the engine refuses.
    pub fn destroy(self, within: Duration) -> Result<(), EngineError> {
        must_run(&["rm", "--force", &self.id], within)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Round 2's Critical, at the exact line it was reported against.
    ///
    /// The old helper was `std::fs::read_to_string(path).unwrap_or_default()`.
    /// Both halves are needed for the bug and both are pinned here: strict
    /// decoding FAILS on a single malformed byte rather than returning what it
    /// could, and the `unwrap_or_default` behind it turns that failure into an
    /// empty string that is indistinguishable from a command which produced no
    /// output. Applied to the exec-relay's disclosure log — where the failing
    /// command was `cat`, which exits 0 either way — one bad byte anywhere in a
    /// run erased every exec-consequence observation from the sealed bundle.
    #[test]
    fn one_invalid_byte_costs_its_own_character_and_nothing_else() {
        // A realistic disclosure log: a header, a record whose argv0 carries a
        // raw 0xFF the way a path read out of tracee memory can, and a record
        // after it.
        let mut log = Vec::new();
        log.extend_from_slice(b"{\"known_residual_tells\":[\"TracerPid nonzero\"]}\n");
        log.extend_from_slice(b"{\"turn_id\":\"turn-0\",\"requested_argv0\":\"/bin/no");
        log.push(0xff);
        log.extend_from_slice(b"such\"}\n");
        log.extend_from_slice(b"{\"turn_id\":\"turn-1\",\"requested_argv0\":\"/bin/echo\"}\n");

        // What the old read did, spelled out so the regression is legible: it
        // is not that the bad line was dropped, it is that there was no output
        // at all.
        assert!(
            String::from_utf8(log.clone()).is_err(),
            "this fixture is supposed to be invalid UTF-8"
        );

        let decoded = decode_lossy(log);
        assert_eq!(
            decoded.lines().count(),
            3,
            "every line must survive, not just the clean ones: {decoded:?}"
        );
        assert!(decoded.contains("known_residual_tells"));
        assert!(decoded.contains("turn-1"));
        // The bad byte's own line is still there and still parseable JSON —
        // the byte cost one character's readability and nothing more.
        let bad = decoded.lines().nth(1).expect("the middle line");
        assert!(bad.contains('\u{FFFD}'), "{bad:?}");
        assert!(bad.starts_with("{\"turn_id\":\"turn-0\""), "{bad:?}");
        assert!(bad.ends_with("such\"}"), "{bad:?}");
    }

    /// Valid input must come back byte-identical, so "survives invalid UTF-8"
    /// has not been bought by mangling the ordinary case.
    #[test]
    fn valid_utf8_is_unchanged() {
        let text = "caf\u{e9} \u{20ac}5 \u{1f4a5}\nsecond line\n";
        assert_eq!(decode_lossy(text.as_bytes().to_vec()), text);
    }

    /// The same Critical in its second costume: a `docker logs` that FAILED,
    /// read as a log that was empty.
    ///
    /// This is what the shape looks like on the wire — non-zero status, nothing
    /// on stdout, the reason on stderr — when the engine's log driver cannot be
    /// read back (`none`, `syslog`, `fluentd`, `gelf`), when the daemon
    /// hiccups, or when something outside this process reaped the container.
    /// Before the guard, [`Container::logs_bytes`] handed exactly this to
    /// `AgentCell::captured_stdout` as `Ok`, which decoded it to `Some("")`,
    /// which recorded zero exec-consequence observations and STILL set
    /// `disclosure_log_read: true` — a sealed bundle claiming the channel was
    /// `Watched` over evidence nobody ever read.
    #[test]
    fn a_docker_logs_that_failed_is_never_an_empty_log() {
        let refused = RawOutcome {
            status: Some(1),
            stdout: Vec::new(),
            stderr: b"Error response from daemon: configured logging driver does \
                      not support reading\n"
                .to_vec(),
        };

        let err = raw_or_failed(&["logs", "deadbeef"], refused)
            .expect_err("a non-zero `docker logs` must not read as a successful empty log");

        match err {
            EngineError::Failed {
                argv,
                status,
                stderr,
            } => {
                assert_eq!(argv, vec!["logs".to_owned(), "deadbeef".to_owned()]);
                assert_eq!(status, Some(1));
                // The daemon's reason survives to the operator: the failure is
                // reported as itself, not as an absence.
                assert!(stderr.contains("does not support reading"), "{stderr:?}");
            }
            other => panic!("expected EngineError::Failed, got {other:?}"),
        }
    }

    /// The cap refuses rather than truncating — the property the whole bound
    /// exists for, and one nothing reached before.
    ///
    /// A truncated disclosure log is the worst available outcome: it parses, it
    /// seals, it reports the channel as watched, and nothing in the bundle says
    /// records are missing. So the oversized capture has to arrive as an ERROR
    /// naming the size and the bound, not as a shorter success.
    #[test]
    fn a_capture_over_the_cap_is_refused_rather_than_truncated() {
        let err = over_cap(
            &["logs", "deadbeef"],
            "stdout",
            LOGS_BYTES_CAP + 1,
            Some(LOGS_BYTES_CAP),
        )
        .expect("a capture past the cap must be refused");

        match err {
            EngineError::CaptureTooLarge {
                argv,
                stream,
                bytes,
                cap,
            } => {
                assert_eq!(argv, vec!["logs".to_owned(), "deadbeef".to_owned()]);
                assert_eq!(stream, "stdout");
                assert_eq!(bytes, LOGS_BYTES_CAP + 1);
                assert_eq!(cap, LOGS_BYTES_CAP);
            }
            other => panic!("expected CaptureTooLarge, got {other:?}"),
        }

        // The operator is told what happened and what the bound was: a refusal
        // nobody can act on is barely better than a truncation.
        let rendered = over_cap(
            &["logs", "deadbeef"],
            "stdout",
            LOGS_BYTES_CAP + 1,
            Some(LOGS_BYTES_CAP),
        )
        .expect("just built one")
        .to_string();
        assert!(
            rendered.contains("refused rather than truncated"),
            "{rendered}"
        );
        assert!(rendered.contains(&LOGS_BYTES_CAP.to_string()), "{rendered}");
    }

    /// Both of `docker logs`' streams are bounded, not only stdout.
    ///
    /// `execrelayd` writes a `logline` per TRAP — including the PATH probes it
    /// deliberately does not record — so its stderr is agent-driven and can be
    /// the larger of the two captures. A cap on stdout alone bounds the smaller
    /// half and leaves the other an unbounded read into this process.
    #[test]
    fn the_cap_covers_stderr_and_not_only_stdout() {
        let err = over_cap(
            &["logs", "deadbeef"],
            "stderr",
            LOGS_BYTES_CAP * 2,
            Some(LOGS_BYTES_CAP),
        )
        .expect("an oversized stderr capture must be refused too");
        let EngineError::CaptureTooLarge { stream, .. } = err else {
            panic!("expected CaptureTooLarge");
        };
        assert_eq!(
            stream, "stderr",
            "the refusal must name which stream blew the cap"
        );
    }

    /// The bound must not be bought by refusing ordinary reads. Everything up
    /// to and INCLUDING the cap is a capture this process will read: the cap is
    /// the largest acceptable size, not the smallest refused one, and an
    /// off-by-one here turns an exactly-64-MiB run into a lost bundle.
    ///
    /// The uncapped case is the other half — every read in this module except
    /// `logs_bytes` passes `None`, and none of them may acquire a bound by
    /// accident.
    #[test]
    fn a_capture_within_the_cap_and_an_uncapped_one_are_both_read() {
        assert!(
            over_cap(
                &["logs", "x"],
                "stdout",
                LOGS_BYTES_CAP,
                Some(LOGS_BYTES_CAP)
            )
            .is_none(),
            "a capture exactly at the cap is within it"
        );
        assert!(over_cap(&["logs", "x"], "stdout", 0, Some(LOGS_BYTES_CAP)).is_none());
        assert!(
            over_cap(&["ps"], "stdout", u64::MAX, None).is_none(),
            "a caller that set no cap must not acquire one"
        );
    }

    /// The guard must not be bought by turning ordinary reads into failures: a
    /// container that genuinely wrote nothing exits zero, and an empty log IS
    /// the answer there.
    #[test]
    fn a_docker_logs_that_succeeded_empty_is_still_an_empty_log() {
        let quiet = RawOutcome {
            status: Some(0),
            stdout: Vec::new(),
            stderr: Vec::new(),
        };
        let outcome = raw_or_failed(&["logs", "deadbeef"], quiet).expect("exit 0 is not a failure");
        assert!(outcome.stdout.is_empty());
    }
}
