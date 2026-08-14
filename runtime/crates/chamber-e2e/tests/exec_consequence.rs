// runtime/crates/chamber-e2e/tests/exec_consequence.rs
mod support;
use chamber_capture::exec_consequence::{
    ArgvMatcher, ExecConsequencePlan, ExecConsequenceRule, ExecVerb,
};
use chamber_isolation::{Attach, Container, ContainerSpec};
use std::time::Duration;
use support::*;

const IMAGE: &str = "chamber-guest-exec-relay:test";
const OP_WINDOW: Duration = Duration::from_secs(90);

/// Guarantees the cell is removed when a test function returns, whether that
/// is a normal return or a panic unwinding out of a failed `assert_eq!`, an
/// `.expect()` on `start()`, or a panic inside `thread::scope`.
/// `chamber_isolation::Container` has no `Drop` impl of its own (only
/// `EnvFile` does, for the env file it writes to disk) — destroying it is
/// something a caller must remember to do explicitly, and a call placed only
/// at the end of a test function is exactly the line a panic skips. This
/// wrapper does it unconditionally in `Drop`, which unwinding still runs.
/// `Deref` lets every `cell.exec(...)` / `cell.start()` call site work as if
/// `cell` were still a plain `Container`.
struct CellGuard(Option<Container>);

impl CellGuard {
    fn new(container: Container) -> Self {
        Self(Some(container))
    }
}

impl std::ops::Deref for CellGuard {
    type Target = Container;
    fn deref(&self) -> &Container {
        self.0
            .as_ref()
            .expect("container is present until CellGuard is dropped")
    }
}

impl Drop for CellGuard {
    fn drop(&mut self) {
        if let Some(container) = self.0.take() {
            let _ = container.destroy(OP_WINDOW);
        }
    }
}

fn start_cell(plan: &ExecConsequencePlan) -> CellGuard {
    ensure_images_including(&[IMAGE]); // extend the existing ensure_images() helper to also build this image's Dockerfile — see support/mod.rs's existing memoized-build pattern
    let pairs = plan.to_env_pairs();
    let env_file = chamber_isolation::EnvFile::write(&pairs).expect("env file");
    let container = Container::create(&ContainerSpec {
        image: IMAGE.to_owned(),
        attach: Attach::None,
        cap_add: vec![],
        argv: vec![],
        sysctls: vec![],
        env_file: Some(env_file.path().clone()),
        dns: vec![],
        // Matches production (AgentCell::start) exactly: a read-only rootfs
        // with the /work tmpfs as the ONLY writable path — no /tmp. This is
        // what exercises the relay under the real cell's constraints, where
        // the socket and disclosure log must live under /work/.exec-relay/
        // rather than /tmp.
        read_only: true,
        tmpfs: vec!["/work:rw,exec".to_owned()],
        volumes: vec![],
    })
    .expect("create cell");
    CellGuard::new(container)
}

#[test]
fn passthrough_is_byte_identical_to_no_interception() {
    let Some(_engine) = require_containers() else {
        return;
    };
    let _serialised = chamber_subnet_lock();

    let plan = ExecConsequencePlan {
        rules: vec![],
        timeout_ms: 60_000,
        max_concurrent_handlers: 32,
    };
    let cell = start_cell(&plan);
    cell.start().expect("start");
    std::thread::sleep(Duration::from_millis(300)); // let execrelayd bind its socket

    // Absolute path for determinism, though it need not be one: the relay's
    // worker resolves argv[0] with execvpe() (PATH-searching, per the final
    // review's Fix 2), so a bare "echo" would also resolve. An absolute path
    // pins exactly which binary passthrough lets run, independent of PATH.
    let via_relay = cell
        .exec(&["stub", "/bin/echo", "hello"], OP_WINDOW)
        .expect("exec via relay");
    assert_eq!(via_relay.stdout.trim(), "hello");
    assert_eq!(via_relay.status, Some(0));

    // No explicit cell.destroy() here: CellGuard's Drop tears the container
    // down on every exit path, including a panic from the asserts above.
}

#[test]
fn substitute_runs_the_replacement_binary() {
    let Some(_engine) = require_containers() else {
        return;
    };
    let _serialised = chamber_subnet_lock();

    // Replacement is /usr/bin/curl, not /bin/true: on this image (alpine:3.20)
    // /bin/true and /bin/false are BOTH symlinks to /bin/busybox, whose applet
    // dispatch reads argv[0] — not the path actually execve()'d — to decide
    // "act like true" vs "act like false". Substitute (deliberately, for
    // stealth — see ExecVerb::Substitute's doc comment) only overwrites the
    // PATH register; it leaves argv untouched. So redirecting to /bin/true
    // while argv[0] still reads "/bin/false" makes busybox behave as "false"
    // regardless of which symlink got loaded — exit 1 either way, unable to
    // distinguish "substitution worked" from "substitution is a no-op". curl
    // is a real, standalone ELF (confirmed via `file`/readlink — not a
    // busybox multi-call binary), so its behavior does not depend on argv[0].
    let plan = ExecConsequencePlan {
        rules: vec![ExecConsequenceRule {
            name: "sub".to_owned(),
            match_argv: ArgvMatcher::Argv0 {
                name: "/bin/false".to_owned(),
            },
            verb: ExecVerb::Substitute {
                replacement_argv: vec!["/usr/bin/curl".to_owned()],
            },
        }],
        timeout_ms: 60_000,
        max_concurrent_handlers: 32,
    };
    let cell = start_cell(&plan);
    cell.start().expect("start");
    std::thread::sleep(Duration::from_millis(300));

    // "--version" is inert if real /bin/false runs (busybox false ignores all
    // args and always exits 1) but is real curl's own flag if the substitute
    // took effect (argv beyond argv[0] is untouched by substitute, so this
    // flag reaches whichever binary actually loaded) — exit 0 plus curl's own
    // banner in stdout is proof curl actually ran, not just "some exit-0
    // program did".
    let out = cell
        .exec(&["stub", "/bin/false", "--version"], OP_WINDOW)
        .expect("exec");
    assert_eq!(
        out.status,
        Some(0),
        "requested /bin/false but the substitute rule should have made curl actually run"
    );
    assert!(
        out.stdout.contains("curl"),
        "stdout did not look like curl's own --version banner:\n{}",
        out.stdout
    );
}

#[test]
fn fabricate_never_runs_the_real_target() {
    let Some(_engine) = require_containers() else {
        return;
    };
    let _serialised = chamber_subnet_lock();

    let plan = ExecConsequencePlan {
        rules: vec![ExecConsequenceRule {
            name: "fab".to_owned(),
            match_argv: ArgvMatcher::Argv0 {
                name: "touch-canary".to_owned(),
            },
            verb: ExecVerb::Fabricate {
                exit_code: 0,
                stdout: "fabricated-ok".to_owned(),
                stderr: String::new(),
            },
        }],
        timeout_ms: 60_000,
        max_concurrent_handlers: 32,
    };
    let cell = start_cell(&plan);
    cell.start().expect("start");
    std::thread::sleep(Duration::from_millis(300));

    // "touch-canary" isn't a real binary in the image at all — if fabricate
    // actually executed anything, this would fail with "not found" instead
    // of returning the canned result, so a passing exit=0/matching stdout
    // is itself proof nothing ran.
    let out = cell
        .exec(&["stub", "touch-canary"], OP_WINDOW)
        .expect("exec");
    assert_eq!(out.status, Some(0));
    assert_eq!(out.stdout.trim(), "fabricated-ok");
}

#[test]
fn rewrite_transforms_output_of_a_real_run() {
    let Some(_engine) = require_containers() else {
        return;
    };
    let _serialised = chamber_subnet_lock();

    let plan = ExecConsequencePlan {
        rules: vec![ExecConsequenceRule {
            name: "rw".to_owned(),
            // Matches on the literal argv[0] the caller passes, which is why
            // this must be the same string used in the exec call below: rule
            // matching (config_match) compares the literal argv[0], NOT the
            // PATH-resolved path the worker's execvpe() ultimately loads. An
            // absolute path keeps that literal unambiguous.
            match_argv: ArgvMatcher::Argv0 {
                name: "/bin/echo".to_owned(),
            },
            verb: ExecVerb::Rewrite {
                stdout_find: Some("secret".to_owned()),
                stdout_replace: Some("REDACTED".to_owned()),
                stderr_find: None,
                stderr_replace: None,
            },
        }],
        timeout_ms: 60_000,
        max_concurrent_handlers: 32,
    };
    let cell = start_cell(&plan);
    cell.start().expect("start");
    std::thread::sleep(Duration::from_millis(300));

    let out = cell
        .exec(&["stub", "/bin/echo", "the secret value"], OP_WINDOW)
        .expect("exec");
    assert_eq!(out.status, Some(0));
    assert_eq!(out.stdout.trim(), "the REDACTED value");
}

#[test]
fn one_hung_command_does_not_block_concurrent_others() {
    let Some(_engine) = require_containers() else {
        return;
    };
    let _serialised = chamber_subnet_lock();

    let plan = ExecConsequencePlan {
        rules: vec![],
        timeout_ms: 5_000,
        max_concurrent_handlers: 32,
    };
    // CellGuard, not Arc<CellGuard>: destroying the underlying Container takes
    // `self` by value, which Arc's shared ownership can't hand back cleanly.
    // std::thread::scope lets the hang-check thread below borrow `&cell`
    // instead (via CellGuard's Deref), so `cell` stays a plain, ordinary value
    // whose Drop runs the teardown once the scope's threads have all joined.
    let cell = start_cell(&plan);
    cell.start().expect("start");
    std::thread::sleep(Duration::from_millis(300));

    std::thread::scope(|scope| {
        let hang_handle = scope.spawn(|| {
            // Expected to time out via the relay's own watchdog (exit 124)
            // well before this window elapses — the assertion is really
            // "this call eventually returns", proving the relay didn't
            // wedge forever. Absolute path for determinism — see the
            // passthrough test's note.
            cell.exec(&["stub", "/bin/sleep", "9999"], OP_WINDOW)
        });

        std::thread::sleep(Duration::from_millis(200)); // let the hang actually start

        let start = std::time::Instant::now();
        for i in 0..3 {
            let out = cell
                .exec(
                    &["stub", "/bin/echo", &format!("concurrent-{i}")],
                    Duration::from_secs(10),
                )
                .unwrap_or_else(|e| {
                    panic!("concurrent request {i} did not complete promptly: {e}")
                });
            assert_eq!(out.stdout.trim(), format!("concurrent-{i}"));
        }
        assert!(
            start.elapsed() < Duration::from_secs(8),
            "concurrent requests took {:?} — the hang appears to have blocked them",
            start.elapsed()
        );

        let hang_result = hang_handle
            .join()
            .unwrap()
            .expect("exec call itself should still return (not hang forever)");
        assert_eq!(
            hang_result.status,
            Some(124),
            "hung command should time out via the watchdog with exit 124"
        );
    });
}

#[test]
fn coverage_extends_to_a_subprocess_of_a_subprocess() {
    let Some(_engine) = require_containers() else {
        return;
    };
    let _serialised = chamber_subnet_lock();

    let plan = ExecConsequencePlan {
        rules: vec![ExecConsequenceRule {
            name: "nested".to_owned(),
            match_argv: ArgvMatcher::Argv0 {
                name: "/nonexistent/touch-canary".to_owned(),
            },
            verb: ExecVerb::Fabricate {
                exit_code: 0,
                stdout: "caught-nested".to_owned(),
                stderr: String::new(),
            },
        }],
        timeout_ms: 60_000,
        max_concurrent_handlers: 32,
    };
    let cell = start_cell(&plan);
    cell.start().expect("start");
    std::thread::sleep(Duration::from_millis(300));

    // sh -c 'sh -c /nonexistent/touch-canary' is a subprocess of a subprocess
    // of the top-level docker-exec'd stub — coverage must reach all the way
    // down. The top-level command is given as an absolute path for determinism
    // (see the passthrough test's note — the worker's execvpe() would resolve a
    // bare name too); the nested "sh" can stay bare (it's a real PATH hit, and
    // the outer shell's own PATH search resolves and execve()s it normally,
    // which is itself its own trapped syscall, caught below by passthrough).
    //
    // The nested canary command, however, MUST contain a "/" — a bare
    // "touch-canary" does not trip a trap at all on this image: alpine's
    // /bin/sh is busybox ash, and ash's own PATH search checks each candidate
    // with stat()/access() BEFORE ever calling execve() — for a name that
    // exists nowhere on PATH, ash reports "not found" without issuing a
    // single execve() syscall, so there is nothing for the seccomp filter to
    // trap (verified directly: a bare nonexistent name produces exactly two
    // execve traps, both for /bin/sh, then exit 127 with zero interception).
    // This differs from glibc's execvp(), which blindly attempts execve() on
    // every PATH candidate and catches ENOENT — the assumption this test
    // originally relied on does not hold for busybox ash. Any path containing
    // a slash bypasses PATH search entirely (shell semantics, not specific to
    // busybox) and is execve()'d directly regardless of whether the file
    // exists, which both restores the trap and keeps the canary property:
    // "/nonexistent/touch-canary" is not a real file, so a passing exit=0
    // with the fabricated stdout is still proof nothing real ran.
    let out = cell
        .exec(
            &["stub", "/bin/sh", "-c", "sh -c /nonexistent/touch-canary"],
            OP_WINDOW,
        )
        .expect("exec");
    assert_eq!(out.status, Some(0));
    assert_eq!(out.stdout.trim(), "caught-nested");
}

#[test]
fn turn_id_lands_on_the_disclosure_record() {
    let Some(_engine) = require_containers() else {
        return;
    };
    let _serialised = chamber_subnet_lock();

    let plan = ExecConsequencePlan {
        rules: vec![],
        timeout_ms: 60_000,
        max_concurrent_handlers: 32,
    };
    let cell = start_cell(&plan);
    cell.start().expect("start");
    std::thread::sleep(Duration::from_millis(300));

    // Exercises stub's --turn-id= argv flag directly (Task 6) — the same
    // convention the bridge's ToolBridge::prefixed_argv (Task 9) generates
    // per call, just supplied by hand here instead of via the bridge.
    cell.exec(
        &["stub", "--turn-id=turn-test-42", "/bin/echo", "hi"],
        OP_WINDOW,
    )
    .expect("exec");
    let log = cell
        .exec(&["cat", "/work/.exec-relay/disclosure.log"], OP_WINDOW)
        .expect("cat log");
    assert!(
        log.stdout.contains("turn-test-42"),
        "log did not carry the turn id:\n{}",
        log.stdout
    );
}

#[test]
fn disclosure_log_is_readable_via_the_sealing_cat_path() {
    let Some(_engine) = require_containers() else {
        return;
    };
    let _serialised = chamber_subnet_lock();

    let plan = ExecConsequencePlan {
        rules: vec![],
        timeout_ms: 60_000,
        max_concurrent_handlers: 32,
    };
    let cell = start_cell(&plan);
    cell.start().expect("start");
    std::thread::sleep(Duration::from_millis(300));

    cell.exec(&["stub", "/bin/echo", "one"], OP_WINDOW)
        .expect("exec");
    cell.exec(&["stub", "/bin/echo", "two"], OP_WINDOW)
        .expect("exec");

    let log = cell
        .exec(&["cat", "/work/.exec-relay/disclosure.log"], OP_WINDOW)
        .expect("cat log");
    assert!(log.stdout.contains("known_residual_tells"));
    assert!(log.stdout.contains("TracerPid"));
    assert_eq!(
        log.stdout.lines().count(),
        3,
        "1 header + 2 request records"
    );
}
