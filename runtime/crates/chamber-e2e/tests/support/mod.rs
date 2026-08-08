//! Shared scaffolding for the container-driven e2e tests.
//!
//! `tests/support/` is a subdirectory, so cargo compiles it as a module of
//! whichever test binary writes `mod support;` — never as a test target of its
//! own. `#![allow(dead_code)]` because each test file uses a different subset
//! and an unused helper here is not a defect.
#![allow(dead_code)]

use std::path::PathBuf;
use std::process::Command;
use std::sync::{Mutex, MutexGuard, OnceLock};
use std::time::Duration;

use chamber_isolation::{Docker, build_image, build_image_with_dockerfile};

pub const OP_WINDOW: Duration = Duration::from_secs(90);

/// The engine, or a decision about what its absence means.
///
/// Skips locally with a printed reason; fails in CI, where
/// `CHAMBER_REQUIRE_CONTAINERS` is set. A suite that no-ops when Docker is
/// missing makes a green tick mean nothing.
pub fn require_containers() -> Option<Docker> {
    match Docker::probe() {
        Ok(engine) => Some(engine),
        Err(e) if std::env::var("CHAMBER_REQUIRE_CONTAINERS").is_ok() => {
            panic!("this suite cannot run: {e}")
        }
        Err(e) => {
            eprintln!("SKIPPED (requires a Linux guest): {e}");
            None
        }
    }
}

/// `runtime/`, two levels above `crates/<pkg>`.
pub fn runtime_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(|p| p.parent())
        .expect("crates/<pkg> sits two levels below runtime/")
        .to_path_buf()
}

pub fn images_dir() -> PathBuf {
    runtime_dir().join("images")
}

/// The repository root, one level above `runtime/`. Where `fixtures/`, the
/// Python `chamber` package, and `pyproject.toml` live.
pub fn repo_root() -> PathBuf {
    runtime_dir()
        .parent()
        .expect("runtime/ sits under the repo root")
        .to_path_buf()
}

pub fn fixtures_dir() -> PathBuf {
    repo_root().join("fixtures")
}

/// A host directory the container engine can actually bind-mount.
///
/// NOT the system temp dir. On a Linux VM engine (Colima, Docker Desktop) the
/// daemon only sees the paths the VM shares — `$HOME` by default, and macOS's
/// `/var/folders/...` never. A bind mount of an unshared path silently succeeds
/// with an EMPTY directory, so the observer writes a ledger the host never
/// sees and the run reports insufficient coverage for a reason that has nothing
/// to do with the chamber.
pub fn shared_scratch(name: &str) -> PathBuf {
    let home = std::env::var("HOME").expect("HOME must be set to place shared scratch");
    PathBuf::from(home)
        .join(".cache")
        .join("chamber-e2e")
        .join(name)
}

/// Locates the `chamber-verify` binary the workspace built.
///
/// `CARGO_BIN_EXE_*` is only defined for the package that declares the binary,
/// and this is a different package. It sits beside the test executable's parent,
/// which cargo has already built because `chamber-e2e` depends on
/// `chamber-evidence`.
pub fn chamber_verify_bin() -> PathBuf {
    let exe = std::env::current_exe().expect("test executable path");
    let target = exe
        .parent()
        .and_then(|deps| deps.parent())
        .expect("target/<profile>/deps/<test>");
    let candidate = target.join("chamber-verify");
    assert!(
        candidate.exists(),
        "chamber-verify is not built at {candidate:?}; the bundle cannot be \
         checked the way a third party would check it"
    );
    candidate
}

/// Builds the images the suite needs, once per test binary.
///
/// Serialised because two `docker build`s racing on the same tag interleave
/// their output into something no one can diagnose. The capture image is the
/// odd one out — its Dockerfile lives under `images/capture/` but its build
/// context is `runtime/`, and it is the slow one, which is why the whole of
/// this is memoised.
pub fn ensure_images() {
    static BUILT: OnceLock<Mutex<bool>> = OnceLock::new();
    let lock = BUILT.get_or_init(|| Mutex::new(false));
    let mut done = lock.lock().unwrap_or_else(|e| e.into_inner());
    if *done {
        return;
    }
    for name in ["guest", "inspector", "warden"] {
        let dir = images_dir().join(name);
        build_image(&dir, &format!("chamber-{name}:test"))
            .unwrap_or_else(|e| panic!("could not build the {name} image from {dir:?}: {e}"));
    }
    build_image_with_dockerfile(
        &runtime_dir(),
        &images_dir().join("capture").join("Dockerfile"),
        "chamber-capture:test",
    )
    .expect("could not build the capture image");
    *done = true;
}

/// Serialises the tests that raise the chamber's subnet.
///
/// The chamber's network name and subnet (`chamber-egress`, `10.66.0.0/24`)
/// are fixed singletons; Docker refuses the second raiser with "Pool overlaps".
/// Fixing that with `--test-threads=1` in CI would leave a plain `cargo test`
/// broken for anyone running it locally, which is how a suite acquires a
/// reputation for being flaky rather than a bug for being fixed.
pub fn chamber_subnet_lock() -> MutexGuard<'static, ()> {
    static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
    LOCK.get_or_init(|| Mutex::new(()))
        .lock()
        .unwrap_or_else(|e| e.into_inner())
}

/// Container ids currently running from an image tag, via the engine's own ps.
///
/// Row 5 uses this to find and kill the observer mid-run. Safe because the
/// subnet lock guarantees exactly one chamber is up, so the tag identifies a
/// single container unambiguously.
pub fn running_ids_from_image(tag: &str) -> Vec<String> {
    let out = Command::new("docker")
        .args([
            "ps",
            "--filter",
            &format!("ancestor={tag}"),
            "--format",
            "{{.ID}}",
        ])
        .output();
    match out {
        Ok(o) if o.status.success() => String::from_utf8_lossy(&o.stdout)
            .lines()
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(str::to_owned)
            .collect(),
        _ => Vec::new(),
    }
}
