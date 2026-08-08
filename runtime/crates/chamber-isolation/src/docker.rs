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

/// Runs `docker <argv>`, killing it if it outlives `within`.
///
/// Returns the outcome whatever the exit status: callers that need a non-zero
/// exit to be an error say so with [`ExecOutcome::ok`]. Several of them
/// deliberately do not — a probe technique that is *supposed* to fail exits
/// non-zero, and that is the measurement, not an error.
fn run_within(argv: &[&str], within: Duration) -> Result<ExecOutcome, EngineError> {
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

    let stdout = read_and_remove(&out_path);
    let stderr = read_and_remove(&err_path);

    match status {
        Some(status) => Ok(ExecOutcome {
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

fn read_and_remove(path: &PathBuf) -> String {
    let text = std::fs::read_to_string(path).unwrap_or_default();
    let _ = std::fs::remove_file(path);
    text
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
