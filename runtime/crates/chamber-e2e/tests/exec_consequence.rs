// runtime/crates/chamber-e2e/tests/exec_consequence.rs
mod support;
use chamber_capture::exec_consequence::{
    ArgvMatcher, ExecConsequencePlan, ExecConsequenceRule, ExecVerb,
};
use chamber_evidence::{Channel, ChannelCoverage, ObservationKind, OpenedBundle};
use chamber_isolation::{Attach, Container, ContainerSpec};
use chamber_run::{
    ArmingRefusal, DetonationPlan, ImageTags, PlantedCanary, ScriptedTurns, run_detonation,
};
use std::future::Future;
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
    start_cell_with_volumes(plan, vec![])
}

/// [`start_cell`], plus bind mounts. Only the fail-closed disclosure-log test
/// needs one — it makes the log's directory read-only, which is the one way to
/// make the log's `open()` fail without also making the `mkdir` above it fail,
/// so the refusal being exercised is the one under test.
fn start_cell_with_volumes(plan: &ExecConsequencePlan, volumes: Vec<String>) -> CellGuard {
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
        // the disclosure log must live under /work/.exec-relay/ rather than
        // /tmp.
        //
        // The bare path with NO option suffix is the point, not an omission:
        // `AgentCell::start` builds this entry as `scratch_root().display()`
        // and nothing more, which Docker expands to `rw,nosuid,nodev,noexec,
        // relatime` — i.e. production's /work is NOEXEC. Writing `/work:rw,exec`
        // here would hand the test an executable /work that production does not
        // have, and this spec is supposed to match production exactly. Nothing
        // in this feature executes anything out of /work (execrelayd, stub and
        // fabricate-emit all live in /usr/local/bin on the read-only rootfs),
        // so noexec costs the suite nothing and closes the gap.
        read_only: true,
        tmpfs: vec!["/work".to_owned()],
        volumes,
    })
    .expect("create cell");
    CellGuard::new(container)
}

/// Every disclosure record the cell has written, one JSON object per entry,
/// with the `known_residual_tells` header skipped — counted exactly the way
/// `bundle.rs`'s `record_exec_consequence_log` counts them.
fn disclosure_records(cell: &Container) -> Vec<serde_json::Value> {
    let log = cell
        .exec(&["cat", "/work/.exec-relay/disclosure.log"], OP_WINDOW)
        .expect("cat the disclosure log");
    log.stdout
        .lines()
        .filter(|l| !l.trim().is_empty())
        .map(|l| {
            serde_json::from_str::<serde_json::Value>(l)
                .unwrap_or_else(|e| panic!("a disclosure line is not JSON ({e}): {l}"))
        })
        .filter(|v| v.get("known_residual_tells").is_none())
        .collect()
}

/// Whether `path` exists inside the cell, asked WITHOUT going through the
/// relay.
///
/// Deliberately a plain `docker exec` rather than a `stub` call: this is how a
/// side-effect canary is read, and reading it through the very mechanism under
/// test would let a rule (or a bug in one) answer the question about itself.
fn file_exists(cell: &Container, path: &str) -> bool {
    let out = cell
        .exec(&["/bin/sh", "-c", &format!("test -e {path}")], OP_WINDOW)
        .expect("probe for a canary file");
    out.status == Some(0)
}

/// The records whose `verb_applied` is exactly `verb`.
fn records_with_verb(records: &[serde_json::Value], verb: &str) -> Vec<serde_json::Value> {
    records
        .iter()
        .filter(|v| v.get("verb_applied").and_then(|x| x.as_str()) == Some(verb))
        .cloned()
        .collect()
}

/// The image this suite exercises is the one production recognises as
/// relay-capable.
///
/// `run_detonation` now refuses to arm an `exec_consequence` unless the guest
/// image's repository is `EXEC_RELAY_GUEST_IMAGE` — so if that constant and the
/// image this suite actually builds and drives ever part company, the refusal
/// would fire on the real thing while every test here kept passing. Needs no
/// container, so it runs even where the rest of this file skips.
#[test]
fn the_suite_drives_the_image_production_treats_as_relay_capable() {
    assert!(
        IMAGE.starts_with(&format!("{}:", chamber_run::EXEC_RELAY_GUEST_IMAGE)),
        "this suite builds {IMAGE}, but run_detonation only arms an exec_consequence \
         against the {} repository",
        chamber_run::EXEC_RELAY_GUEST_IMAGE
    );
}

/// §3's central invariant, measured against a real baseline rather than
/// against a constant someone typed.
///
/// The design's claim is that zero configuration makes this system
/// byte-for-byte identical to a plain `docker exec`. This test used to assert
/// `via_relay.stdout.trim() == "hello"` and nothing else, which is not that
/// claim: it is "the relay printed something that trims to hello". Every
/// difference §3 forbids survives it. A trailing newline eaten or added is
/// invisible to `.trim()`. A leaked descriptor, an inherited signal mask, an
/// injected environment variable, a mangled exit code — none of them change
/// what `echo hello` prints, so a hard-coded expectation cannot see any of
/// them. Three of the defects this review cycle turned up (the fd leak, the
/// SIGCHLD/SIGPIPE disposition drift, the `RELAY_REQ_ID` and spec-variable
/// leaks) were live in the image while this test was green.
///
/// So the baseline is taken, not assumed: every probe below runs TWICE in the
/// SAME cell — once as `stub <argv>`, which goes through execrelayd's
/// ptrace+seccomp supervision, and once as plain `<argv>`, which is an ordinary
/// `docker exec` with the relay nowhere in the path — and the two outcomes are
/// compared for exact equality on all three of stdout, stderr and exit code.
/// No `.trim()` anywhere: the trailing byte is part of the claim.
///
/// Same cell for both halves on purpose. "No interception" has to differ from
/// "interception" in exactly one respect — whether execrelayd is in the path —
/// and running the control in a second container would also vary the hostname,
/// the pid namespace's contents and the container id, none of which this
/// invariant is about. `docker exec` into the relay cell reaches the same
/// rootfs, the same mounts and the same environment, and never speaks to
/// execrelayd: `stub` is the only client of its socket.
///
/// The probes are chosen to be exactly the observations an agent under
/// evaluation would make if it were looking for a supervisor, and each one is
/// pinned to an expected exit code so a probe that silently stopped exercising
/// what it names fails here rather than comparing two identical failures.
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

    // Absolute paths for determinism, though they need not be: the relay's
    // worker resolves argv[0] with execvpe() (PATH-searching, per the final
    // review's Fix 2), so a bare "echo" would also resolve. An absolute path
    // pins exactly which binary passthrough lets run, independent of PATH.
    let probes: &[(&str, &[&str], i32)] = &[
        // The original assertion's command, now compared rather than trimmed:
        // `echo` writes a trailing newline, and "is that newline still there"
        // is precisely what `.trim()` was throwing away.
        (
            "stdout, trailing newline and all",
            &["/bin/echo", "hello"],
            0,
        ),
        // The opposite shape: output that ends without a newline must not
        // acquire one crossing the relay's pipes and frames.
        (
            "stdout with no trailing newline",
            &["/usr/bin/printf", "%s", "no-trailing-newline"],
            0,
        ),
        // stderr is a separate frame tag on the wire from stdout, and an exit
        // code is a third; a real command that uses all three at once is what
        // catches them being crossed, dropped or defaulted.
        (
            "stderr beside stdout, and a real non-zero exit code",
            &["/bin/sh", "-c", "printf out; printf err >&2; exit 3"],
            3,
        ),
        // The fd-table tell. The relay opens a disclosure log, a control
        // socket, a signalfd and two sync pipes for itself; before Wave 1's fix
        // all of them survived the worker's execve and a relayed command saw
        // nine descriptors where a direct one sees four.
        (
            "the open file descriptors",
            &["/bin/ls", "/proc/self/fd"],
            0,
        ),
        // The signal tell: SIGCHLD blocked by the tracer's own pre-fork
        // sigprocmask, SIGPIPE left SIG_IGN by run_server. A disposition of
        // SIG_IGN survives execve, unlike a handler, so both followed the
        // agent's command into its own process.
        (
            "the signal mask and dispositions",
            &[
                "/bin/sh",
                "-c",
                "grep -E '^Sig(Pnd|Blk|Ign|Cgt):' /proc/self/status",
            ],
            0,
        ),
        // Inherited process state that is nobody's fix so far, and therefore
        // exactly the kind of thing a baseline exists to catch if it ever
        // drifts: the worker is forked from PID 1, not from the caller.
        (
            "the working directory and umask",
            &["/bin/sh", "-c", "pwd; umask"],
            0,
        ),
        (
            "the process identity and resource limits",
            &["/bin/sh", "-c", "id; ulimit -n"],
            0,
        ),
    ];

    for (what, argv, expected_status) in probes {
        let via_relay = cell
            .exec(&[&["stub"][..], argv].concat(), OP_WINDOW)
            .expect("exec via relay");
        let direct = cell.exec(argv, OP_WINDOW).expect("exec direct");

        // Non-vacuity, per probe and before any comparison: the control run has
        // to have actually done the thing this row is named for. Without this,
        // a probe whose command stopped existing would compare two identical
        // "not found" failures and pass.
        assert_eq!(
            direct.status,
            Some(*expected_status),
            "the control run of {what} did not do what this probe claims to \
             exercise: {direct:?}"
        );
        assert!(
            !direct.stdout.is_empty(),
            "the control run of {what} printed nothing, so comparing it proves \
             nothing: {direct:?}"
        );

        assert_eq!(
            via_relay.stdout, direct.stdout,
            "{what}: a relayed command's stdout is not byte-identical to a \
             directly-exec'd one's\nvia relay: {:?}\ndirect:    {:?}",
            via_relay.stdout, direct.stdout
        );
        assert_eq!(
            via_relay.stderr, direct.stderr,
            "{what}: a relayed command's stderr is not byte-identical to a \
             directly-exec'd one's\nvia relay: {:?}\ndirect:    {:?}",
            via_relay.stderr, direct.stderr
        );
        assert_eq!(
            via_relay.status, direct.status,
            "{what}: a relayed command's exit code differs from a \
             directly-exec'd one's"
        );
    }

    // And the comparison itself is not comparing nothing. Two runs of two
    // DIFFERENT commands must fail the same equality this loop applies —
    // otherwise every assertion above could be passing because `exec` returns
    // an empty outcome for everything.
    let a = cell
        .exec(&["stub", "/bin/echo", "hello"], OP_WINDOW)
        .expect("exec");
    let b = cell
        .exec(&["stub", "/bin/echo", "goodbye"], OP_WINDOW)
        .expect("exec");
    assert_ne!(
        a.stdout, b.stdout,
        "two different commands produced identical output, so the equalities \
         above are not measuring anything"
    );

    // No explicit cell.destroy() here: CellGuard's Drop tears the container
    // down on every exit path, including a panic from the asserts above.
}

#[test]
fn a_relayed_command_inherits_no_relay_private_descriptors() {
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

    // Not one descriptor the relay opens for itself may survive the worker's
    // execve into the agent's own command. Before the fix, /proc/self/fd inside
    // a relayed command listed nine entries against plain docker exec's four:
    // the disclosure log (writable), the live control socket, a signalfd, and
    // both sync pipes.
    let via_relay = cell
        .exec(&["stub", "/bin/ls", "-l", "/proc/self/fd"], OP_WINDOW)
        .expect("exec via relay");
    let direct = cell
        .exec(&["/bin/ls", "-l", "/proc/self/fd"], OP_WINDOW)
        .expect("exec direct");
    assert_eq!(
        via_relay.stdout.lines().count(),
        direct.stdout.lines().count(),
        "a relayed command sees a different fd table than plain docker exec:\n\
         via relay:\n{}\ndirect:\n{}",
        via_relay.stdout,
        direct.stdout
    );
    for tell in ["disclosure.log", "signalfd", "socket:"] {
        assert!(
            !via_relay.stdout.contains(tell),
            "a relayed command can see {tell} in its own /proc/self/fd:\n{}",
            via_relay.stdout
        );
    }

    // The consequence that made this Critical rather than cosmetic: the
    // inherited log descriptor was opened O_WRONLY|O_APPEND, so the agent's own
    // command could append forged records to the sealed evidence with a plain
    // shell redirection. Measured on the pre-fix image, this call succeeded and
    // the forged line was in the log.
    let forge = cell
        .exec(
            &["stub", "/bin/sh", "-c", "echo FORGED-RECORD >&3"],
            OP_WINDOW,
        )
        .expect("exec");
    assert_ne!(
        forge.status,
        Some(0),
        "writing to fd 3 from a relayed command should fail — it should not be open"
    );
    let log = cell
        .exec(&["cat", "/work/.exec-relay/disclosure.log"], OP_WINDOW)
        .expect("cat log");
    assert!(
        !log.stdout.contains("FORGED-RECORD"),
        "the agent's own command injected a record into the sealed evidence log:\n{}",
        log.stdout
    );
}

#[test]
fn an_argv_element_containing_a_newline_round_trips_byte_for_byte() {
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

    // The stub -> relayd wire format used to put each argv element on its own
    // `ARG <value>\n` line. An element containing a newline therefore arrived
    // as two lines: the first matched `ARG ` and was taken as a complete (but
    // truncated) argument, and the second matched none of the expected
    // prefixes and was silently discarded — there was no `else` branch to
    // report it, and `argc` was never reconciled against the number of `ARG`
    // lines actually received, so neither end could detect the desync. The
    // command simply ran with a quietly different argv than the caller asked
    // for. Measured on the pre-fix image: this exact call printed `line1` and
    // nothing else.
    //
    // These are not exotic inputs. A heredoc, a `python -c` script, a `sh -c`
    // with two statements — all routine for a live driving agent, and all
    // silently corrupted.
    let multiline = "line1\nline2";

    // `printf %s` writes its argument with nothing added and nothing
    // interpreted, so stdout IS the argument as the relay delivered it — a
    // byte-for-byte comparison, not an approximation of one.
    let via_relay = cell
        .exec(&["stub", "/usr/bin/printf", "%s", multiline], OP_WINDOW)
        .expect("exec via relay");
    assert_eq!(via_relay.status, Some(0));
    assert_eq!(
        via_relay.stdout, multiline,
        "the argv element did not survive the wire intact"
    );

    // The same command WITHOUT the relay, in the same cell: the relayed result
    // has to equal the un-relayed one, which is the property the whole feature
    // rests on (passthrough is indistinguishable from no interception).
    let direct = cell
        .exec(&["/usr/bin/printf", "%s", multiline], OP_WINDOW)
        .expect("exec direct");
    assert_eq!(via_relay.stdout, direct.stdout);

    // And the realistic shape, end to end: a two-statement shell script passed
    // as one `-c` argument. Pre-fix this ran only the first statement.
    let script = "echo first\necho second";
    let scripted = cell
        .exec(&["stub", "/bin/sh", "-c", script], OP_WINDOW)
        .expect("exec script via relay");
    assert_eq!(scripted.status, Some(0));
    assert_eq!(
        scripted.stdout, "first\nsecond\n",
        "the second statement of a multi-line script did not run"
    );
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
    // "act like true" vs "act like false". curl is a real, standalone ELF
    // (confirmed via `file`/readlink — not a busybox multi-call binary), so its
    // behavior does not depend on argv[0].
    //
    // EDITED in the Wave-2 fix round, and worth a reviewer's attention: this
    // test used to configure `replacement_argv: ["/usr/bin/curl"]` and pass
    // "--version" in the REQUEST, relying on substitute leaving the requested
    // argv in place — which was the defect (config.c parsed the whole
    // replacement_argv and the relay used only element 0, so a rule saying
    // `["/bin/echo", "intercepted"]` ran /bin/echo with the requested argv and
    // dropped "intercepted" silently). Substitute now replaces the whole argv,
    // so the flag belongs in the rule. The property asserted is unchanged: curl
    // really ran, not merely "some program that exits 0".
    let plan = ExecConsequencePlan {
        rules: vec![ExecConsequenceRule {
            name: "sub".to_owned(),
            match_argv: ArgvMatcher::Argv0 {
                name: "/bin/false".to_owned(),
            },
            verb: ExecVerb::Substitute {
                replacement_argv: vec!["/usr/bin/curl".to_owned(), "--version".to_owned()],
            },
        }],
        timeout_ms: 60_000,
        max_concurrent_handlers: 32,
    };
    let cell = start_cell(&plan);
    cell.start().expect("start");
    std::thread::sleep(Duration::from_millis(300));

    let out = cell.exec(&["stub", "/bin/false"], OP_WINDOW).expect("exec");
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
fn substitute_replaces_the_whole_argv_not_only_argv0() {
    let Some(_engine) = require_containers() else {
        return;
    };
    let _serialised = chamber_subnet_lock();

    // The reported defect, in the exact shape it was reported in: a rule
    // configured `["/bin/echo", "intercepted"]`. config.c has always parsed the
    // full array and nothing ever refused a longer one, but the relay repointed
    // only the path register — so /bin/echo ran with the REQUESTED argv and
    // printed "--version". Silently doing something other than what the config
    // says is worse than refusing it, which is why this is a fix rather than a
    // validation error.
    let plan = ExecConsequencePlan {
        rules: vec![ExecConsequenceRule {
            name: "sub-full-argv".to_owned(),
            match_argv: ArgvMatcher::Argv0 {
                name: "/bin/false".to_owned(),
            },
            verb: ExecVerb::Substitute {
                replacement_argv: vec!["/bin/echo".to_owned(), "intercepted".to_owned()],
            },
        }],
        timeout_ms: 60_000,
        max_concurrent_handlers: 32,
    };
    let cell = start_cell(&plan);
    cell.start().expect("start");
    std::thread::sleep(Duration::from_millis(300));

    let out = cell
        .exec(&["stub", "/bin/false", "--version"], OP_WINDOW)
        .expect("exec");
    assert_eq!(out.status, Some(0));
    assert_eq!(
        out.stdout, "intercepted\n",
        "the configured replacement argv did not reach the exec; pre-fix this printed \
         the REQUESTED argv (\"--version\") instead"
    );

    // And the record says what actually ran, in full — a reviewer reading the
    // bundle must be able to see the argv the relay substituted, not just that
    // it substituted something.
    let records = disclosure_records(&cell);
    let subs = records_with_verb(&records, "substitute");
    assert_eq!(subs.len(), 1, "{records:#?}");
    assert_eq!(
        subs[0]["detail"].as_str(),
        Some("/bin/echo intercepted"),
        "{:#?}",
        subs[0]
    );
}

#[test]
fn rewrite_catches_a_find_string_split_across_reads() {
    let Some(_engine) = require_containers() else {
        return;
    };
    let _serialised = chamber_subnet_lock();

    // The transform used to be applied to each read() independently, so a find
    // string straddling a read boundary matched nothing and the ORIGINAL bytes
    // — the ones the rule exists to remove — went through to the host.
    //
    // The boundary is constructed by volume rather than by timing: the relay
    // reads at most 8192 bytes at a time, so 240 KB of output crosses at least
    // 29 read boundaries, and with a match every ten bytes some match straddles
    // one. (The byte-level case — "SEC" then "RET" as two separate chunks — is
    // pinned deterministically by tests/test_rewrite.c, which drives the same
    // stream code directly; this is the end-to-end half, through a real pipe.)
    //
    // The loop is pure shell builtins on purpose: `seq`, `sleep` and friends
    // are execs, and a nested exec that matches no rule clears the active
    // rewrite for everything after it.
    let plan = ExecConsequencePlan {
        rules: vec![ExecConsequenceRule {
            name: "rw-split".to_owned(),
            match_argv: ArgvMatcher::Argv0 {
                name: "/bin/sh".to_owned(),
            },
            verb: ExecVerb::Rewrite {
                stdout_find: Some("SECRET".to_owned()),
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
        .exec(
            &[
                "stub",
                "/bin/sh",
                "-c",
                "i=0; while [ $i -lt 20000 ]; do printf 'xxxxSECRET'; i=$((i+1)); done",
            ],
            OP_WINDOW,
        )
        .expect("exec");
    assert_eq!(out.status, Some(0));
    assert!(
        !out.stdout.contains("SECRET"),
        "the find string leaked through a read boundary untransformed ({} occurrences)",
        out.stdout.matches("SECRET").count()
    );
    assert_eq!(
        out.stdout.matches("REDACTED").count(),
        20_000,
        "every occurrence must be replaced, not merely the ones inside a chunk"
    );
    assert_eq!(out.stdout.len(), 20_000 * "xxxxREDACTED".len());
}

#[test]
fn rewrite_does_not_truncate_an_expanding_replacement() {
    let Some(_engine) = require_containers() else {
        return;
    };
    let _serialised = chamber_subnet_lock();

    // The transform's output buffer was sized the same as the input read
    // buffer (8192) with a stop-when-full guard, so a replacement longer than
    // what it replaced silently truncated the command's output. 100 matches of
    // a one-byte find with a 200-byte replacement is 20000 bytes out of 100 in
    // — pre-fix this came back as 8192 bytes with the rest simply gone.
    let replacement = "z".repeat(200);
    let plan = ExecConsequencePlan {
        rules: vec![ExecConsequenceRule {
            name: "rw-expand".to_owned(),
            match_argv: ArgvMatcher::Argv0 {
                name: "/bin/sh".to_owned(),
            },
            verb: ExecVerb::Rewrite {
                stdout_find: Some("A".to_owned()),
                stdout_replace: Some(replacement.clone()),
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
        .exec(
            &[
                "stub",
                "/bin/sh",
                "-c",
                "i=0; while [ $i -lt 100 ]; do printf A; i=$((i+1)); done",
            ],
            OP_WINDOW,
        )
        .expect("exec");
    assert_eq!(out.status, Some(0));
    assert_eq!(
        out.stdout.len(),
        100 * 200,
        "the expanded output was truncated to {} bytes",
        out.stdout.len()
    );
    assert!(out.stdout.chars().all(|c| c == 'z'));
}

#[test]
fn a_rewritten_stream_over_the_frame_limit_arrives_whole_with_its_exit_code() {
    let Some(_engine) = require_containers() else {
        return;
    };
    let _serialised = chamber_subnet_lock();

    // The defect the fix above introduced, one layer down. Not truncating the
    // expanding replacement inside rewrite.c's own buffer meant the whole
    // expanded result was then handed to a single send_frame — and the wire
    // protocol has a ceiling that nothing on the sending side enforced. The
    // stub refuses any frame over EXEC_RELAY_MAX_FRAME_LEN (65536) by breaking
    // out of its read loop, which loses that frame's output AND never reaches
    // the TAG_EXIT frame behind it, so the caller falls back to the stub's
    // initialiser `exit_code = 1`.
    //
    // So the silent-truncation defect was not closed, only moved to a higher
    // threshold — and given a second symptom, a corrupted exit code, that the
    // in-buffer version never had.
    //
    // The shape here is the one from the review: a one-byte find and a 15-byte
    // replacement, i.e. 15x expansion. The relay reads the worker's pipe 8192
    // bytes at a time, so ONE read becomes 122880 bytes of transform output —
    // nearly twice the frame limit, in a single continuous transform with no
    // nested exec to interrupt it.
    //
    // Pre-fix this test sees an empty stdout and status 1. Both, from one
    // over-long frame.
    const REPLACEMENT: &str = "[REDACTED-PATH]";
    // 2^14 slashes, built by doubling a shell variable — every step is an ash
    // builtin, so no nested exec clears `active_rewrite` mid-stream and the
    // whole output goes through one transform.
    const SLASHES: usize = 1 << 14;
    let plan = ExecConsequencePlan {
        rules: vec![ExecConsequenceRule {
            name: "rw-over-frame-limit".to_owned(),
            match_argv: ArgvMatcher::Argv0 {
                name: "/bin/sh".to_owned(),
            },
            verb: ExecVerb::Rewrite {
                stdout_find: Some("/".to_owned()),
                stdout_replace: Some(REPLACEMENT.to_owned()),
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

    // `exit 42` is the other half of the assertion: a distinctive status that
    // is neither 0 nor the stub's fallback 1, so "the exit code survived" and
    // "the exit code was corrupted" cannot be confused.
    let script = "s=/; i=0; while [ $i -lt 14 ]; do s=\"$s$s\"; i=$((i+1)); done; \
                  printf %s \"$s\"; exit 42";
    let out = cell
        .exec(&["stub", "/bin/sh", "-c", script], OP_WINDOW)
        .expect("exec");

    let expected_len = SLASHES * REPLACEMENT.len();
    assert!(
        expected_len > 65536,
        "the test must force a rewritten stream past the frame limit, got {expected_len}"
    );
    // (a) every byte of the correctly-rewritten output arrives — not merely
    // "some", and not merely "up to the limit".
    assert_eq!(
        out.stdout.len(),
        expected_len,
        "the rewritten stream lost {} of {expected_len} bytes crossing the wire",
        expected_len.saturating_sub(out.stdout.len())
    );
    assert_eq!(
        out.stdout,
        REPLACEMENT.repeat(SLASHES),
        "the rewritten stream arrived whole but altered"
    );
    // (b) and the real exit code came with it, rather than the stub's
    // initialiser standing in for a TAG_EXIT frame it never read.
    assert_eq!(
        out.status,
        Some(42),
        "the exit code was lost with the over-long frame"
    );
}

#[test]
fn a_watchdog_timeout_is_disclosed() {
    let Some(_engine) = require_containers() else {
        return;
    };
    let _serialised = chamber_subnet_lock();

    // §8 requires a record for a watchdog kill. It went only to execrelayd's
    // own stdout — the container log, which is not sealed evidence — so from
    // the bundle's point of view the command was let through and simply
    // finished; nothing said it was killed at the deadline.
    let plan = ExecConsequencePlan {
        rules: vec![],
        timeout_ms: 1_000,
        max_concurrent_handlers: 32,
    };
    let cell = start_cell(&plan);
    cell.start().expect("start");
    std::thread::sleep(Duration::from_millis(300));

    let out = cell
        .exec(&["stub", "/bin/sleep", "30"], OP_WINDOW)
        .expect("exec");
    assert_eq!(out.status, Some(124), "the watchdog should have fired");

    let records = disclosure_records(&cell);
    let timeouts = records_with_verb(&records, "watchdog-timeout");
    assert_eq!(
        timeouts.len(),
        1,
        "the watchdog kill left no disclosure record:\n{records:#?}"
    );
    assert_eq!(timeouts[0]["requested_argv0"].as_str(), Some("/bin/sleep"));
    assert!(
        timeouts[0]["detail"]
            .as_str()
            .is_some_and(|d| d.contains("1000") && d.contains("124")),
        "the record does not say what happened: {:#?}",
        timeouts[0]
    );
}

#[test]
fn a_worker_killed_by_a_signal_is_disclosed() {
    let Some(_engine) = require_containers() else {
        return;
    };
    let _serialised = chamber_subnet_lock();

    // The other record §8 requires and the relay did not write at all: a worker
    // that dies of a signal rather than returning. The exit code reaches the
    // caller (128 + signal) and the sealed evidence never mentions it.
    let plan = ExecConsequencePlan {
        rules: vec![],
        timeout_ms: 60_000,
        max_concurrent_handlers: 32,
    };
    let cell = start_cell(&plan);
    cell.start().expect("start");
    std::thread::sleep(Duration::from_millis(300));

    let out = cell
        .exec(&["stub", "/bin/sh", "-c", "kill -9 $$"], OP_WINDOW)
        .expect("exec");
    assert_eq!(out.status, Some(137), "128 + SIGKILL");

    let records = disclosure_records(&cell);
    let signalled = records_with_verb(&records, "worker-signaled");
    assert_eq!(
        signalled.len(),
        1,
        "a worker killed by a signal left no disclosure record:\n{records:#?}"
    );
    assert!(
        signalled[0]["detail"]
            .as_str()
            .is_some_and(|d| d.contains("signal 9")),
        "{:#?}",
        signalled[0]
    );
}

#[test]
fn a_passthrough_exec_that_never_ran_is_disclosed() {
    let Some(_engine) = require_containers() else {
        return;
    };
    let _serialised = chamber_subnet_lock();

    // relayd.c's own stated invariant, above trap_target_is_loadable: "silently
    // dropping a real exec is the one failure the disclosure log must never
    // have". It did not hold for the no-match case. A passthrough whose target
    // does not exist trapped, was found not-loadable, and was filed as one of
    // execvpe's PATH probes — so `stub /nonexistent/thing` returned 127 with an
    // EMPTY log (measured on the pre-fix image).
    let plan = ExecConsequencePlan {
        rules: vec![],
        timeout_ms: 60_000,
        max_concurrent_handlers: 32,
    };
    let cell = start_cell(&plan);
    cell.start().expect("start");
    std::thread::sleep(Duration::from_millis(300));

    for (argv0, label) in [
        ("/nonexistent/thing", "an absolute path that does not exist"),
        ("totally-not-a-command", "a bare name that resolves nowhere"),
    ] {
        let out = cell.exec(&["stub", argv0], OP_WINDOW).expect("exec");
        assert_eq!(out.status, Some(127), "{label}");
    }

    let records = disclosure_records(&cell);
    let failed = records_with_verb(&records, "passthrough-exec-failed");
    assert_eq!(
        failed.len(),
        2,
        "a real exec attempt that ran nothing went unrecorded:\n{records:#?}"
    );
    assert_eq!(
        failed[0]["requested_argv0"].as_str(),
        Some("/nonexistent/thing")
    );
    assert_eq!(
        failed[1]["requested_argv0"].as_str(),
        Some("totally-not-a-command"),
        "the bare name must produce ONE record, not one per PATH candidate probed"
    );
}

#[test]
fn a_relayed_command_gets_the_same_signal_environment_as_a_direct_one() {
    let Some(_engine) = require_containers() else {
        return;
    };
    let _serialised = chamber_subnet_lock();

    // §3: with zero rules configured, the relay must be indistinguishable from
    // no interception. Two things followed the worker across execve and both
    // were wrong: SIGCHLD stayed BLOCKED (from the tracer's own pre-fork
    // sigprocmask) and SIGPIPE stayed IGNORED (from run_server's
    // signal(SIGPIPE, SIG_IGN)) — a signal set to SIG_IGN survives execve,
    // unlike a handler. Measured on the pre-fix image: SigBlk 0000000000010000
    // (SIGCHLD) and SigIgn 0000000000001004 (SIGPIPE + SIGQUIT) via the relay,
    // against SigBlk 0000000000000000 / SigIgn 0000000000000004 directly.
    let plan = ExecConsequencePlan {
        rules: vec![],
        timeout_ms: 60_000,
        max_concurrent_handlers: 32,
    };
    let cell = start_cell(&plan);
    cell.start().expect("start");
    std::thread::sleep(Duration::from_millis(300));

    let probe = [
        "/bin/sh",
        "-c",
        "grep -E '^Sig(Blk|Ign):' /proc/self/status",
    ];
    let via_relay = cell
        .exec(&[&["stub"][..], &probe[..]].concat(), OP_WINDOW)
        .expect("exec via relay");
    let direct = cell.exec(&probe, OP_WINDOW).expect("exec direct");
    assert_eq!(
        via_relay.stdout, direct.stdout,
        "a relayed command starts with a different signal mask/disposition than a \
         directly-exec'd one"
    );

    // And the behaviour that difference actually changed. `yes | head -1` is
    // the canonical SIGPIPE case: the writer must DIE of SIGPIPE when the
    // reader exits. With SIGPIPE ignored the write returns EPIPE instead and
    // busybox prints "yes: Broken pipe" — which is what the pre-fix relay did,
    // and what a plain docker exec never does.
    let pipe = ["/bin/sh", "-c", "yes | head -1"];
    let via_relay = cell
        .exec(&[&["stub"][..], &pipe[..]].concat(), OP_WINDOW)
        .expect("exec via relay");
    let direct = cell.exec(&pipe, OP_WINDOW).expect("exec direct");
    assert_eq!(via_relay.stdout, direct.stdout);
    assert_eq!(via_relay.status, direct.status);
    assert_eq!(
        via_relay.stderr, direct.stderr,
        "the relayed pipeline reported something the direct one did not"
    );
    assert!(
        !via_relay.stderr.contains("Broken pipe"),
        "the writer got EPIPE instead of dying of SIGPIPE: {}",
        via_relay.stderr
    );

    // The environment, too: RELAY_REQ_ID used to be injected into every
    // relayed command and read by nothing, so `stub env` showed a variable
    // plain `docker exec env` did not.
    let via_relay = cell
        .exec(&["stub", "/usr/bin/env"], OP_WINDOW)
        .expect("exec env via relay");
    let direct = cell
        .exec(&["/usr/bin/env"], OP_WINDOW)
        .expect("exec env direct");
    assert!(
        !via_relay.stdout.contains("RELAY_REQ_ID"),
        "a relayed command carries a variable no plain docker exec has:\n{}",
        via_relay.stdout
    );

    // The much larger version of the same leak, and the reason the name-set
    // comparison below is no longer a plain equality.
    //
    // CHAMBER_EXEC_CONSEQUENCE_SPEC_B64 is the entire interception plan: every
    // rule, every match pattern, every fabricate payload, every substitute
    // target. It reaches the cell as container environment, execrelayd reads it
    // at startup, and the worker used to inherit it wholesale — so `env | grep
    // CHAMBER_EXEC_CONSEQUENCE` inside any relayed command handed the agent
    // under evaluation the complete ruleset it is being measured against.
    // Strictly worse than the RELAY_REQ_ID tell: that one only revealed THAT
    // something was intercepting, this one reveals exactly what and how, which
    // is what an adversarial agent needs to evade it.
    //
    // Deliberately asserted against the real spec value rather than the name
    // alone, so this cannot pass because the plan happened not to be set.
    let spec_value = plan.to_env_pairs().remove(0).1;
    assert!(
        !spec_value.is_empty(),
        "the spec variable is unset in this cell, so scrubbing it proves nothing"
    );
    assert!(
        direct.stdout.contains(&spec_value),
        "the cell does not carry the spec at all — the assertions below are vacuous"
    );
    assert!(
        !via_relay.stdout.contains("CHAMBER_EXEC_CONSEQUENCE"),
        "a relayed command can read its own interception configuration:\n{}",
        via_relay.stdout
    );

    // unsetenv() only rewrites the `environ` array a child inherits. It does
    // NOT touch /proc/<pid>/environ, which the kernel serves from the original
    // stack region — and execrelayd is PID 1 of a cell whose commands run as
    // root, so the plan was readable there by anything that thought to look.
    // Overwriting the value bytes in place is the other half of the fix, and
    // this is what proves it: the name may survive, the plan must not.
    let pid1_env = cell
        .exec(
            &[
                "stub",
                "/bin/sh",
                "-c",
                "cat /proc/1/environ | tr '\\0' '\\n'",
            ],
            OP_WINDOW,
        )
        .expect("read pid 1's environ via relay");
    assert!(
        !pid1_env.stdout.contains(&spec_value),
        "the relay's own /proc/1/environ still hands out the interception plan:\n{}",
        pid1_env.stdout
    );

    // And the window PID 1's scrub does not cover. The stub is not forked from
    // execrelayd — `docker exec` builds its environment from the container's
    // config, where the spec necessarily lives — so every live stub carried the
    // whole plan in its own environ while execrelayd's was already clean. The
    // agent's commands run as root in the same cell, so one turn could read the
    // ruleset out of another turn's in-flight stub. Held open here with a
    // detached sleep, then read from a *different* relayed command, which is
    // exactly the shape of the leak.
    cell.exec_detached(&["stub", "/bin/sleep", "8"], OP_WINDOW)
        .expect("hold a stub process open");
    std::thread::sleep(Duration::from_millis(500));
    let other_env = cell
        .exec(
            &[
                "stub",
                "/bin/sh",
                "-c",
                "for p in /proc/[0-9]*; do tr '\\0' '\\n' < $p/environ 2>/dev/null; done",
            ],
            OP_WINDOW,
        )
        .expect("read every process's environ via relay");
    assert!(
        !other_env.stdout.contains(&spec_value),
        "a concurrently-running process in the cell still hands out the \
         interception plan through its own /proc/<pid>/environ"
    );

    let names = |out: &str| -> Vec<String> {
        let mut v: Vec<String> = out
            .lines()
            .filter_map(|l| l.split_once('=').map(|(k, _)| k.to_owned()))
            .collect();
        v.sort();
        v
    };
    // The relayed environment must differ from a direct exec's by EXACTLY the
    // relay-internal variables and nothing else. §3's "zero config is
    // indistinguishable from no interception" still holds for every variable
    // the agent's own command has any business seeing; the one deliberate
    // exception is the relay's own configuration, whose whole purpose is to be
    // invisible to the thing it configures interception for.
    let mut relayed = names(&via_relay.stdout);
    let mut expected = names(&direct.stdout);
    expected.retain(|n| n != "CHAMBER_EXEC_CONSEQUENCE_SPEC_B64");
    relayed.sort();
    expected.sort();
    assert_eq!(
        relayed, expected,
        "the relayed environment differs from a direct exec's by more than the \
         relay-internal variables"
    );
}

#[test]
fn a_request_over_the_cap_is_refused_in_frame_and_disclosed() {
    let Some(_engine) = require_containers() else {
        return;
    };
    let _serialised = chamber_subnet_lock();

    // The over-cap rejection wrote a bare unframed line onto a socket whose
    // every other byte is a length-prefixed frame: the stub read "relay" as a
    // 5-byte frame header, did not recognise tag 'r', and gave up with its own
    // default exit 1 — a refusal indistinguishable from the command failing.
    // Measured pre-fix: exit 1, empty output. It now goes through the same
    // protocol_error() Wave 1 built (TAG_STDERR + TAG_EXIT/112) and leaves a
    // disclosure record, which a wire refusal previously never did.
    let plan = ExecConsequencePlan {
        rules: vec![],
        timeout_ms: 60_000,
        max_concurrent_handlers: 1,
    };
    let cell = start_cell(&plan);
    cell.start().expect("start");
    std::thread::sleep(Duration::from_millis(300));

    cell.exec_detached(&["stub", "/bin/sleep", "5"], OP_WINDOW)
        .expect("hold the single handler slot");
    std::thread::sleep(Duration::from_millis(500));

    let refused = cell
        .exec(&["stub", "/bin/echo", "hello"], OP_WINDOW)
        .expect("exec");
    assert_eq!(
        refused.status,
        Some(112),
        "an over-cap refusal must arrive as the protocol-error exit code, not as a \
         bare failure: {refused:?}"
    );
    assert!(
        refused.stderr.contains("too many concurrent requests"),
        "the refusal said nothing the caller could read: {refused:?}"
    );
    assert!(refused.stdout.is_empty());

    let records = disclosure_records(&cell);
    let refusals = records_with_verb(&records, "protocol-refused");
    assert_eq!(
        refusals.len(),
        1,
        "a refused request left nothing in the sealed evidence:\n{records:#?}"
    );
    assert!(
        refusals[0]["detail"]
            .as_str()
            .is_some_and(|d| d.contains("too many concurrent requests")),
        "{:#?}",
        refusals[0]
    );
}

#[test]
fn an_orphan_reaped_by_pid_one_does_not_loosen_the_cap() {
    let Some(_engine) = require_containers() else {
        return;
    };
    let _serialised = chamber_subnet_lock();

    // execrelayd is PID 1, so every orphan in the cell is re-parented to it and
    // arrives through the same waitpid(-1) as its own handler forks. The reaper
    // decremented the concurrency counter for all of them, so an ordinary
    // `sh -c 'something &'` — the agent backgrounding anything at all — lowered
    // the cap's idea of how many handlers were running. It drifts DOWNWARD,
    // i.e. the cap fails open.
    //
    // Measured on the pre-fix image with exactly this sequence: the second
    // concurrent request, which the cap should refuse, ran and returned
    // "hello" with exit 0.
    let plan = ExecConsequencePlan {
        rules: vec![],
        timeout_ms: 60_000,
        max_concurrent_handlers: 1,
    };
    let cell = start_cell(&plan);
    cell.start().expect("start");
    std::thread::sleep(Duration::from_millis(300));

    // An orphan: the middle shell exits at once, so `sleep 1` is re-parented to
    // PID 1 and dies there. Not run through the relay — the point is that it is
    // a process execrelayd never spawned as a handler.
    cell.exec(&["/bin/sh", "-c", "/bin/sleep 1 & exit 0"], OP_WINDOW)
        .expect("spawn an orphan");
    std::thread::sleep(Duration::from_millis(2000));

    cell.exec_detached(&["stub", "/bin/sleep", "5"], OP_WINDOW)
        .expect("hold the single handler slot");
    std::thread::sleep(Duration::from_millis(500));

    let second = cell
        .exec(&["stub", "/bin/echo", "hello"], OP_WINDOW)
        .expect("exec");
    assert_eq!(
        second.status,
        Some(112),
        "the cap admitted a second handler after PID 1 reaped an orphan it never \
         spawned: {second:?}"
    );
}

#[test]
fn a_relay_that_cannot_open_its_disclosure_log_refuses_to_start() {
    let Some(_engine) = require_containers() else {
        return;
    };
    let _serialised = chamber_subnet_lock();

    // §9 is fail-closed. A failed open used to leave g_disclosure_fd at -1,
    // which every subsequent record write short-circuited on: the relay served
    // every request and recorded nothing, and the resulting bundle is
    // indistinguishable from a run in which the agent execed nothing at all.
    // Measured pre-fix: the container stayed up, logging one line
    // ("disclosure: open: Read-only file system") to a container log nobody
    // reads, and answered requests normally.
    //
    // A read-only bind mount over the relay's directory is what makes the
    // open() fail while the mkdir above it still succeeds (EEXIST), so this
    // exercises the disclosure-log refusal specifically rather than the
    // directory one.
    let dir = shared_scratch("exec-relay-readonly-log");
    std::fs::create_dir_all(&dir).expect("scratch dir");

    let plan = ExecConsequencePlan {
        rules: vec![],
        timeout_ms: 60_000,
        max_concurrent_handlers: 32,
    };
    let cell = start_cell_with_volumes(
        &plan,
        vec![format!("{}:/work/.exec-relay:ro", dir.display())],
    );
    cell.start().expect("start");

    let code = cell.wait(OP_WINDOW).expect("wait for the relay to exit");
    assert_eq!(
        code, 1,
        "the relay kept running with no way to record anything"
    );
    let logs = cell.logs().expect("logs");
    let all = format!("{}{}", logs.stdout, logs.stderr);
    assert!(
        all.contains("refusing to start"),
        "the relay exited without saying why:\n{all}"
    );
    assert!(
        all.contains("disclosure log"),
        "the refusal does not name the disclosure log:\n{all}"
    );
    assert!(
        !all.contains("listening on"),
        "the relay bound its socket before discovering it could not record:\n{all}"
    );
}

/// Fabricate's whole point: the target does not run, and the caller cannot
/// tell.
///
/// The name promised more than the test delivered. It matched a rule against
/// `touch-canary` — a string that names no binary anywhere in the image — and
/// then argued from that: "if fabricate actually executed anything, this would
/// fail with not found". That argument is about the wrong failure. It shows the
/// canned result did not come from `touch-canary`, because `touch-canary` could
/// not have produced anything; it says nothing about whether the relay ran
/// something. A fabricate that silently ran the target and then discarded its
/// result and answered with the canned values would pass it unchanged. So would
/// one that ran the target, ignored the exit code, and returned 0.
///
/// The rule now points at `/bin/touch` — a REAL binary, and one whose entire
/// observable effect is a side effect on the filesystem rather than on the
/// output the relay controls. If the exec ever happens, `/work/…` gains a file,
/// and no amount of canned stdout can hide that.
///
/// Three assertions, and the middle one is the one that was missing:
///   1. the canned result arrives exactly (bytes, not `.trim()`),
///   2. the file the real target would have created does NOT exist,
///   3. and — the control that keeps (2) from being vacuous — the SAME command
///      run directly, without the relay, DOES create its file. Without (3), (2)
///      would also pass on a cell where `/work` were read-only, `/bin/touch`
///      were missing, or the path were wrong.
#[test]
fn fabricate_never_runs_the_real_target() {
    let Some(_engine) = require_containers() else {
        return;
    };
    let _serialised = chamber_subnet_lock();

    const RELAYED_CANARY: &str = "/work/canary-created-by-a-relayed-touch";
    const CONTROL_CANARY: &str = "/work/canary-created-by-a-direct-touch";

    let plan = ExecConsequencePlan {
        rules: vec![ExecConsequenceRule {
            name: "fab".to_owned(),
            match_argv: ArgvMatcher::Argv0 {
                name: "/bin/touch".to_owned(),
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

    // The control, first, so a failure to detect the side effect at all shows
    // up here rather than masquerading as proof further down. `/bin/touch` on
    // this image is a busybox applet, which is fine: fabricate redirects the
    // execve to /usr/local/bin/fabricate-emit, so busybox's argv[0] dispatch
    // never gets a chance to run either way.
    let control = cell
        .exec(&["/bin/touch", CONTROL_CANARY], OP_WINDOW)
        .expect("exec direct");
    assert_eq!(
        control.status,
        Some(0),
        "the control touch failed: {control:?}"
    );
    assert!(
        file_exists(&cell, CONTROL_CANARY),
        "a direct /bin/touch left no file, so this test cannot detect the real \
         target running and its central assertion would be vacuous"
    );

    // Now the same command through the relay, where the rule fabricates.
    let out = cell
        .exec(&["stub", "/bin/touch", RELAYED_CANARY], OP_WINDOW)
        .expect("exec");
    assert_eq!(out.status, Some(0));
    // Exact, not trimmed: fabricate-emit `write()`s the decoded payload and
    // nothing else, so the canned stdout is the canned stdout to the byte. A
    // trailing newline appearing here would mean something other than the
    // configured payload reached the caller.
    assert_eq!(out.stdout, "fabricated-ok");
    assert!(out.stderr.is_empty(), "{out:?}");

    // The assertion the old test was named for and never made.
    assert!(
        !file_exists(&cell, RELAYED_CANARY),
        "fabricate returned its canned result but the REAL target ran anyway — \
         {RELAYED_CANARY} exists"
    );

    // And the sealed evidence says a rule fired, rather than leaving a reader
    // to infer it from output that is, by design, indistinguishable from a real
    // run's.
    let records = disclosure_records(&cell);
    let fabricated = records_with_verb(&records, "fabricate");
    assert_eq!(fabricated.len(), 1, "{records:#?}");
    assert_eq!(fabricated[0]["matched_rule"].as_str(), Some("fab"));
    assert_eq!(
        fabricated[0]["requested_argv0"].as_str(),
        Some("/bin/touch")
    );
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

/// `Exact` and `Prefix` are different matchers, and only a longer argv can tell
/// them apart.
///
/// Until now the suite drove one of the three matchers. Every rule in this file
/// is `ArgvMatcher::Argv0` — substitute, fabricate, rewrite, the nested-coverage
/// case, all of them — so `Exact` and `Prefix` reached the guest through no test
/// at all. `config.c`'s `config_match` distinguishes them by one clause:
/// `MATCH_EXACT` additionally requires `argc == rule->match_argv_len`. Delete
/// that clause and `Exact` silently becomes `Prefix` — a rule written to
/// intercept exactly `git status` starts intercepting `git status --porcelain`,
/// `git status --short` and everything else beginning the same way. The
/// operator's config would then be doing something broader than it says, which
/// is the failure mode this whole feature is least able to afford.
///
/// One cell, two rules, four requests: the two matchers are given the same
/// shape of pattern and differ on exactly one input, the longer argv. The
/// distinguishing case is the third assertion — a longer argv must reach the
/// REAL `/bin/echo` under `Exact` and must be intercepted under `Prefix`.
#[test]
fn exact_and_prefix_matchers_are_not_the_same_matcher() {
    let Some(_engine) = require_containers() else {
        return;
    };
    let _serialised = chamber_subnet_lock();

    let plan = ExecConsequencePlan {
        rules: vec![
            ExecConsequenceRule {
                name: "exact-rule".to_owned(),
                match_argv: ArgvMatcher::Exact {
                    argv: vec!["/bin/echo".to_owned(), "only".to_owned()],
                },
                verb: ExecVerb::Fabricate {
                    exit_code: 0,
                    stdout: "EXACT-FIRED".to_owned(),
                    stderr: String::new(),
                },
            },
            ExecConsequenceRule {
                name: "prefix-rule".to_owned(),
                match_argv: ArgvMatcher::Prefix {
                    argv: vec!["/bin/echo".to_owned(), "pre".to_owned()],
                },
                verb: ExecVerb::Fabricate {
                    exit_code: 0,
                    stdout: "PREFIX-FIRED".to_owned(),
                    stderr: String::new(),
                },
            },
        ],
        timeout_ms: 60_000,
        max_concurrent_handlers: 32,
    };
    let cell = start_cell(&plan);
    cell.start().expect("start");
    std::thread::sleep(Duration::from_millis(300));

    let run = |argv: &[&str]| -> chamber_isolation::ExecOutcome {
        cell.exec(&[&["stub"][..], argv].concat(), OP_WINDOW)
            .expect("exec via relay")
    };

    // Exact, on an argv of exactly the configured length: fires.
    let out = run(&["/bin/echo", "only"]);
    assert_eq!(out.status, Some(0));
    assert_eq!(out.stdout, "EXACT-FIRED", "{out:?}");

    // Exact, one argument longer: does NOT fire. The real /bin/echo runs and
    // prints what it was given — which is also what makes this assertion
    // non-vacuous, since "the rule did not fire" and "nothing happened" would
    // otherwise look alike.
    let out = run(&["/bin/echo", "only", "extra"]);
    assert_eq!(out.status, Some(0));
    assert_eq!(
        out.stdout, "only extra\n",
        "an Exact matcher fired on a LONGER argv, which is Prefix's behaviour, \
         not Exact's: {out:?}"
    );

    // Prefix, on an argv of exactly the configured length: fires.
    let out = run(&["/bin/echo", "pre"]);
    assert_eq!(out.stdout, "PREFIX-FIRED", "{out:?}");

    // Prefix, one argument longer: still fires. This and the second case are
    // the same input shape given to the two matchers, and they must come back
    // different.
    let out = run(&["/bin/echo", "pre", "extra"]);
    assert_eq!(
        out.stdout, "PREFIX-FIRED",
        "a Prefix matcher did not fire on a longer argv, which is the one thing \
         that makes it a prefix: {out:?}"
    );

    // And the sealed evidence attributes each interception to the rule that
    // actually made it, by name — a bundle that said "prefix-rule" for the
    // exact case would misreport which piece of operator config fired.
    let records = disclosure_records(&cell);
    let rules: Vec<Option<&str>> = records.iter().map(|r| r["matched_rule"].as_str()).collect();
    assert_eq!(
        rules,
        vec![
            Some("exact-rule"),
            Some("fallback"),
            Some("prefix-rule"),
            Some("prefix-rule"),
        ],
        "{records:#?}"
    );
}

/// stderr, through the relay: relayed intact, transformable on its own, and
/// carrying a real command's own non-zero exit code.
///
/// Three gaps in one shape, all of them in the original suite:
///
///   - **stderr through the relay.** Every output assertion in the original
///     file read `stdout`. stderr crosses the wire as its own frame tag
///     (`TAG_STDERR`), is read from its own pipe, and is transformed by its own
///     `rewrite_stream` state — a completely separate path from stdout's, and
///     one nothing drove. A relay that dropped stderr entirely, or merged it
///     into stdout, passed the whole suite.
///   - **`stderr_find`/`stderr_replace`.** Both fields existed on every
///     `ExecVerb::Rewrite` in the file and every one of them set both to
///     `None`. The guest-side stderr transform was configured by no test.
///   - **a real command's own non-zero exit code.** The suite asserted exit 0,
///     the watchdog's 124, the protocol error's 112 and fabricate's canned
///     value — every non-zero code it checked was one the RELAY produced. A
///     relay that discarded the worker's real status and substituted a
///     constant would have been caught by none of them. (Wave 2's over-long
///     frame test does now assert an `exit 42`; this pins the same property in
///     the small, without 120 KB of rewritten output in the way.)
///
/// One command exercises all three: it writes to both streams and exits 7, with
/// a rule that rewrites stderr and leaves stdout alone.
#[test]
fn stderr_is_relayed_and_rewritten_independently_of_stdout() {
    let Some(_engine) = require_containers() else {
        return;
    };
    let _serialised = chamber_subnet_lock();

    let plan = ExecConsequencePlan {
        rules: vec![ExecConsequenceRule {
            name: "rw-stderr".to_owned(),
            match_argv: ArgvMatcher::Argv0 {
                name: "/bin/sh".to_owned(),
            },
            // stdout's pair deliberately unset: the transform must apply to the
            // stream it was configured for and to no other. A shared
            // implementation that applied stderr's find/replace to stdout too
            // would fail the stdout assertion below.
            verb: ExecVerb::Rewrite {
                stdout_find: None,
                stdout_replace: None,
                stderr_find: Some("SECRET".to_owned()),
                stderr_replace: Some("REDACTED".to_owned()),
            },
        }],
        timeout_ms: 60_000,
        max_concurrent_handlers: 32,
    };
    let cell = start_cell(&plan);
    cell.start().expect("start");
    std::thread::sleep(Duration::from_millis(300));

    // `printf`, not `echo`: no trailing newline to reason about, so each
    // assertion below is over the exact bytes the command wrote.
    let script = "printf 'out-has-SECRET-too'; printf 'err-has-SECRET' >&2; exit 7";
    let out = cell
        .exec(&["stub", "/bin/sh", "-c", script], OP_WINDOW)
        .expect("exec");

    assert_eq!(
        out.stderr, "err-has-REDACTED",
        "the configured stderr transform did not reach the stderr stream: {out:?}"
    );
    assert_eq!(
        out.stdout, "out-has-SECRET-too",
        "the stderr rule's find/replace was applied to stdout, which was not \
         configured for rewriting: {out:?}"
    );
    assert_eq!(
        out.status,
        Some(7),
        "a real command's own non-zero exit code did not survive the relay: {out:?}"
    );

    // The same three properties without a rule in the way, so "stderr arrives"
    // is established for plain passthrough too and not only for the rewritten
    // path. `/usr/bin/env` matches no rule here (the rule is on /bin/sh), so
    // this really is the untransformed route.
    let plain = cell
        .exec(
            &[
                "stub",
                "/usr/bin/env",
                "sh",
                "-c",
                "printf plain-out; printf plain-err >&2; exit 9",
            ],
            OP_WINDOW,
        )
        .expect("exec");
    assert_eq!(plain.stdout, "plain-out", "{plain:?}");
    assert_eq!(plain.stderr, "plain-err", "{plain:?}");
    assert_eq!(plain.status, Some(9), "{plain:?}");
}

/// Head-of-line blocking is the failure this whole design exists to prevent, so
/// the test for it has to be able to see it.
///
/// It could not. The relay was configured with a 5-second watchdog and the
/// wall-clock assertion allowed 8 seconds — a bound LOOSER than the watchdog it
/// was measuring against. A completely serialized relay, the exact bug, queues
/// the three concurrent requests behind the hung one; that hung one is killed
/// by its own watchdog after 5s, the queue then drains in well under a second,
/// and the whole batch finishes inside the 8-second bound. The test passes. The
/// assertion could only ever have failed on a relay that wedged FOREVER, which
/// is a different (and much louder) defect than the one the name promises.
///
/// The fix is arithmetic, not tuning. The watchdog and the bound have to be
/// separated far enough that serialized and parallel land on opposite sides of
/// it:
///
///   - `timeout_ms: 10_000` — a serialized relay cannot answer the first
///     concurrent request until the hung command is killed, i.e. not before
///     T+10s.
///   - the bound is 4s — comfortably under that, and comfortably over the ~1s
///     three `docker exec` round trips actually take, so it is neither flaky
///     nor satisfiable by accident.
///
/// Plus one assertion that needs no constants at all and cannot drift out of
/// step with them: the concurrent batch must finish BEFORE the hung command
/// returns. That ordering is what "did not block" means, and it holds whatever
/// the watchdog is set to.
#[test]
fn one_hung_command_does_not_block_concurrent_others() {
    let Some(_engine) = require_containers() else {
        return;
    };
    let _serialised = chamber_subnet_lock();

    /// The watchdog, and the floor under a serialized relay's completion time.
    const WATCHDOG: Duration = Duration::from_secs(10);
    /// The ceiling the concurrent batch must come in under. Must stay well
    /// below `WATCHDOG` or this test stops testing anything — see the note
    /// above.
    const CONCURRENT_BOUND: Duration = Duration::from_secs(4);

    let plan = ExecConsequencePlan {
        rules: vec![],
        timeout_ms: u64::try_from(WATCHDOG.as_millis()).expect("watchdog fits in a u64"),
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

    let began = std::time::Instant::now();
    std::thread::scope(|scope| {
        let hang_handle = scope.spawn(|| {
            // Expected to time out via the relay's own watchdog (exit 124)
            // well before this window elapses. Absolute path for determinism —
            // see the passthrough test's note.
            let out = cell.exec(&["stub", "/bin/sleep", "9999"], OP_WINDOW);
            (out, began.elapsed())
        });

        std::thread::sleep(Duration::from_millis(200)); // let the hang actually start

        let start = std::time::Instant::now();
        for i in 0..3 {
            // OP_WINDOW, not a short window: a serialized relay must fail this
            // test on the wall-clock assertion below, which says what actually
            // went wrong, rather than on an exec timeout that reads like an
            // engine problem.
            let out = cell
                .exec(
                    &["stub", "/bin/echo", &format!("concurrent-{i}")],
                    OP_WINDOW,
                )
                .unwrap_or_else(|e| panic!("concurrent request {i} could not be run: {e}"));
            assert_eq!(out.stdout.trim(), format!("concurrent-{i}"));
        }
        let batch_took = start.elapsed();
        let batch_done_at = began.elapsed();
        assert!(
            batch_took < CONCURRENT_BOUND,
            "the three concurrent requests took {batch_took:?}, over the \
             {CONCURRENT_BOUND:?} bound. A relay that serializes them behind \
             the hung command cannot answer before its {WATCHDOG:?} watchdog \
             fires, which is what this bound is set to exclude"
        );

        let (hang_result, hang_returned_at) = hang_handle.join().unwrap();
        let hang_result =
            hang_result.expect("exec call itself should still return (not hang forever)");
        assert_eq!(
            hang_result.status,
            Some(124),
            "hung command should time out via the watchdog with exit 124"
        );
        // The same property stated without reference to either constant: the
        // concurrent work finished while the hung command was still hung. If
        // the watchdog is ever retuned, this keeps testing the right thing.
        assert!(
            batch_done_at < hang_returned_at,
            "the concurrent batch finished at {batch_done_at:?}, after the hung \
             command returned at {hang_returned_at:?} — they ran after it, not \
             alongside it"
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

/// The log the wind-down reads, checked as a record rather than as a line
/// count.
///
/// This test used to assert three things: that the text contains
/// `known_residual_tells`, that it contains `TracerPid`, and that it has three
/// lines. All three are satisfiable by a log whose every record is wrong.
/// `record_exec_consequence_log` in `bundle.rs` turns each of these lines into
/// a `Channel::ExecConsequence` observation by reading five named fields out of
/// it — and it silently skips any line it cannot parse, precisely so one bad
/// line cannot fail a whole run's evidence emission. A shape check upstream of
/// a lenient parser catches nothing: Critical 3 of the original review was a
/// JSON-escaping bug that produced lines this test counted happily and the
/// bundle parser then dropped on the floor.
///
/// So the records are parsed and their fields asserted against what was
/// actually sent, field by field, including the two that are pure operator
/// configuration (`matched_rule`, `verb_applied`) and the one the host supplies
/// per call (`turn_id`). The last section drives a turn id containing the exact
/// characters that broke it — a double quote and a backslash — through the
/// whole path, and requires it back as DATA: not merely present in the text,
/// but the parsed value of the `turn_id` key.
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

    // Turn ids supplied explicitly, the way `ToolBridge::prefixed_argv` supplies
    // them on the real run path — without them every record carries stub's "-"
    // placeholder and the field cannot be checked against anything.
    cell.exec(
        &["stub", "--turn-id=seal-turn-one", "/bin/echo", "one"],
        OP_WINDOW,
    )
    .expect("exec");
    cell.exec(
        &["stub", "--turn-id=seal-turn-two", "/bin/echo", "two"],
        OP_WINDOW,
    )
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

    // The header, as the thing it claims to be: a JSON object carrying a
    // non-empty list of tells. `bundle.rs` identifies it by the presence of
    // that key and skips it; a header that were not parseable JSON would be
    // read as a malformed RECORD instead, and silently dropped.
    let header: serde_json::Value =
        serde_json::from_str(log.stdout.lines().next().expect("a header line"))
            .expect("the header line is JSON");
    let tells = header["known_residual_tells"]
        .as_array()
        .expect("known_residual_tells is a list");
    assert!(!tells.is_empty(), "{header:#?}");
    assert!(
        tells.iter().all(|t| t.is_string()),
        "every tell must be readable prose, not a nested structure: {header:#?}"
    );

    // Every field of every record, against what this test actually asked for.
    let records = disclosure_records(&cell);
    assert_eq!(records.len(), 2, "{records:#?}");
    for (record, expected_turn) in records.iter().zip(["seal-turn-one", "seal-turn-two"]) {
        assert_eq!(
            record["turn_id"].as_str(),
            Some(expected_turn),
            "the record does not carry the turn id it was called with: {record:#?}"
        );
        assert_eq!(
            record["requested_argv0"].as_str(),
            Some("/bin/echo"),
            "{record:#?}"
        );
        // A passthrough matched no rule, and the relay says so with these two
        // exact strings — `bundle.rs` passes both through verbatim into the
        // sealed observation, so a reader of the bundle sees whatever is here.
        assert_eq!(
            record["matched_rule"].as_str(),
            Some("fallback"),
            "{record:#?}"
        );
        assert_eq!(
            record["verb_applied"].as_str(),
            Some("passthrough"),
            "{record:#?}"
        );
        assert_eq!(record["detail"].as_str(), Some("-"), "{record:#?}");
        assert!(
            record["timestamp"].as_f64().is_some_and(|t| t > 0.0),
            "{record:#?}"
        );
    }

    // Critical 3's exact shape: a value containing the two characters that make
    // a JSON string stop being one. Unescaped, this produced a line that
    // `serde_json` refuses and `record_exec_consequence_log` therefore drops —
    // an exec that happened, was recorded, and still reached the bundle as
    // nothing at all.
    let awkward = "seal-turn-\"-and-\\-and-\t-tab";
    cell.exec(
        &[
            "stub",
            &format!("--turn-id={awkward}"),
            "/bin/echo",
            "three",
        ],
        OP_WINDOW,
    )
    .expect("exec");
    let records = disclosure_records(&cell);
    assert_eq!(records.len(), 3, "{records:#?}");
    assert_eq!(
        records[2]["turn_id"].as_str(),
        Some(awkward),
        "a turn id containing JSON metacharacters did not round-trip as data: \
         {:#?}",
        records[2]
    );
}

#[test]
fn a_path_searched_bare_command_records_exactly_one_line() {
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

    // A BARE name, deliberately — every other test in this file passes an
    // absolute path, which execvpe() hands straight to execve() with no PATH
    // search and therefore exactly one trap. The bridge does NOT: every
    // `TurnDirective::ReadFile` runs a bare `cat` (bridge.rs's
    // `carry_out_observed`), so the bare-name path is the one production
    // actually takes and the one that was silently multiplying records.
    //
    // execvpe() tries one execve() per PATH entry until one loads, and the
    // seccomp filter traps every attempt — `cat` lives at /bin/cat, last on
    // this image's PATH (/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:
    // /sbin:/bin), so SIX execve() syscalls trap for this one real command.
    // Five of them name files that do not exist and that nothing ever asked
    // for. Recording all six would put five fictions into the sealed evidence
    // bundle (bundle.rs's `record_exec_consequence_log` turns every record
    // line into an ExecConsequence observation), so the disclosure log would
    // claim the agent referenced /usr/local/sbin/cat — which it never did.
    let out = cell
        .exec(&["stub", "cat", "/etc/hostname"], OP_WINDOW)
        .expect("exec via relay");
    assert_eq!(
        out.status,
        Some(0),
        "bare `cat` should still resolve through PATH: {out:?}"
    );

    let log = cell
        .exec(&["cat", "/work/.exec-relay/disclosure.log"], OP_WINDOW)
        .expect("cat log");
    // Count records the way the bundle does: every line that is not the
    // header becomes one ExecConsequence observation.
    let records: Vec<&str> = log
        .stdout
        .lines()
        .filter(|line| !line.contains("known_residual_tells"))
        .filter(|line| !line.trim().is_empty())
        .collect();
    assert_eq!(
        records.len(),
        1,
        "one real command must yield exactly one disclosure record, not one \
         per PATH candidate probed; log was:\n{}",
        log.stdout
    );
    assert!(
        records[0].contains("\"requested_argv0\":\"/bin/cat\""),
        "the single record must name the binary that actually ran:\n{}",
        records[0]
    );
}

// ---------------------------------------------------------------------------
// The composed path: `DetonationPlan` -> `run_detonation` -> a sealed bundle.
//
// Everything above this line builds a raw `Container` from a `ContainerSpec`
// and talks to it directly. That is the right shape for pinning the guest
// relay's own behaviour — it isolates the C program from the rest of the
// harness — but it means the suite drove the mechanism and never the FEATURE.
// None of it touches the code a real caller reaches:
//
//   * `check_exec_relay_capability`, which refuses a plan that arms an
//     exec_consequence against an image with no relay in it,
//   * `apply_exec_consequence_env`, the only place on the real run path where
//     `ExecConsequencePlan::validate` is called and the only place the spec is
//     bound into the cell's SEALED environment (rather than an `EnvFile` a test
//     wrote by hand),
//   * `ToolBridge::new_with_exec_relay`, which decides whether a turn is
//     prefixed with `stub` at all, and mints the per-call `--turn-id=`,
//     * the read of `/work/.exec-relay/disclosure.log` at the one point in
//     `run_detonation` where the cell is still running,
//   * `record_exec_consequence_log`, which parses that text into sealed
//     observations,
//   * and `ExecInterception`, which decides whether the bundle may claim the
//     `ExecConsequence` channel was watched.
//
// A break anywhere in that chain leaves every test above green and the feature
// dead. These two tests close it: one drives a real detonation end to end, the
// other pins the refusal that must happen before any of it starts.
// ---------------------------------------------------------------------------

/// A canary is not optional: the observer refuses to start without one, because
/// a run with nothing to find can only report finding nothing.
const COMPOSED_CANARY: &str = "AKIAIOSFODNN7EXAMPLE";

/// Drives one async detonation on a throwaway runtime, so the test stays
/// synchronous and the subnet lock never crosses an await.
fn block_on<F: Future>(f: F) -> F::Output {
    tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .expect("build a tokio runtime")
        .block_on(f)
}

fn open_bundle_at(bundle: &std::path::Path, seal: &std::path::Path) -> OpenedBundle {
    let bytes = std::fs::read(bundle).expect("read bundle");
    let seal: chamber_evidence::BundleSeal =
        serde_json::from_slice(&std::fs::read(seal).expect("read seal")).expect("parse seal");
    chamber_evidence::open(&bytes, &seal).expect("bundle opens")
}

/// Every `ExecConsequence` observation in a sealed bundle, in ledger order.
#[allow(clippy::type_complexity)]
fn exec_consequence_records(b: &OpenedBundle) -> Vec<(&str, &str, &str, &str, &str)> {
    b.ledger
        .entries()
        .iter()
        .filter_map(|o| match o.kind() {
            ObservationKind::ExecConsequence {
                turn_id,
                requested_argv0,
                matched_rule,
                verb_applied,
                detail,
            } => Some((
                turn_id.as_str(),
                requested_argv0.as_str(),
                matched_rule.as_str(),
                verb_applied.as_str(),
                detail.as_str(),
            )),
            _ => None,
        })
        .collect()
}

/// What the bundle says a guest command was, and what it exited with.
fn guest_command_exit(b: &OpenedBundle, needle: &str) -> Option<i32> {
    b.ledger.entries().iter().find_map(|o| match o.kind() {
        ObservationKind::GuestCommand {
            argv_redacted,
            exit,
        } if argv_redacted.join(" ").contains(needle) => Some(*exit),
        _ => None,
    })
}

/// A real detonation with an `exec_consequence` armed, through
/// `run_detonation`, ending in a sealed bundle that proves the interception
/// happened.
///
/// The evidence is arranged so that no single assertion could be satisfied by a
/// half-working path:
///
///   * Turn 0 asks for `/bin/touch /work/the-real-touch-ran`, which a rule
///     fabricates. Turn 1 asks for `/bin/ls` of that same path, which matches
///     no rule and passes through to the real `ls`.
///   * If interception is armed and working, turn 1 exits 1 — the file is not
///     there, because nothing ran to create it. If the plan never reached the
///     guest, turn 0's touch really runs and turn 1 exits 0. The two turns
///     therefore disagree about the same filesystem, and the disagreement is
///     visible in the sealed bundle rather than through a side channel this
///     test opened for itself.
///   * The `ExecConsequence` observations must show the fabricate for turn-0
///     and the passthrough for turn-1, with the turn ids the BRIDGE minted
///     (`turn-0`, `turn-1`) — not ids this test supplied, which is what every
///     raw-`Container` test above has to do.
///   * And the channel must be `Watched`, which `bundle.rs` grants only when
///     the relay was armed AND its disclosure log was successfully read out of
///     the cell before the wind-down stopped it.
#[test]
fn a_composed_detonation_arms_the_relay_and_seals_what_it_intercepted() {
    let Some(_engine) = require_containers() else {
        return;
    };
    ensure_images_including(&[IMAGE]);
    let _serialised = chamber_subnet_lock();

    let evidence = shared_scratch(&format!("exec-composed-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&evidence);

    const TOUCHED: &str = "/work/the-real-touch-ran";

    let plan = DetonationPlan {
        images: ImageTags {
            capture: "chamber-capture:test".into(),
            warden: "chamber-warden:test".into(),
            // The relay-capable guest. `check_exec_relay_capability` refuses
            // any other one when `exec_consequence` is set, which the test
            // below pins.
            guest: IMAGE.into(),
            inspector: "chamber-inspector:test".into(),
        },
        ruleset: images_dir().join("chamber.nft"),
        evidence_dir: evidence.clone(),
        canaries: vec![PlantedCanary {
            label: "aws-key".into(),
            value: COMPOSED_CANARY.into(),
            var: "CHAMBER_TOKEN".into(),
        }],
        max_turns: 8,
        skill_dir: None,
        consequence: None,
        exec_consequence: Some(ExecConsequencePlan {
            rules: vec![ExecConsequenceRule {
                name: "fab-touch".to_owned(),
                match_argv: ArgvMatcher::Argv0 {
                    name: "/bin/touch".to_owned(),
                },
                verb: ExecVerb::Fabricate {
                    exit_code: 0,
                    stdout: "fabricated-ok".to_owned(),
                    stderr: String::new(),
                },
            }],
            timeout_ms: 60_000,
            max_concurrent_handlers: 32,
        }),
    };

    let script = format!(
        r#"[
            {{"do": "run_command", "argv": ["/bin/touch", "{TOUCHED}"]}},
            {{"do": "run_command", "argv": ["/bin/ls", "{TOUCHED}"]}},
            {{"do": "conclude"}}
        ]"#
    );
    let mut turns =
        ScriptedTurns::from_bytes("exec-consequence-composed", script.as_bytes()).expect("parse");

    let ep = block_on(run_detonation(&plan, &mut turns)).unwrap_or_else(|e| panic!("{e}"));
    let b = open_bundle_at(&ep.bundle_path, &ep.seal_path);

    // The bundle may claim this channel at all only because the relay was armed
    // and its log came back. `Absent { ExcludedByDesign }` here would mean the
    // plan's `exec_consequence` never reached `Observed::exec_interception`;
    // `Absent { ObserverFailed }` would mean the disclosure log could not be
    // read out of the cell.
    assert_eq!(
        b.coverage.status(Channel::ExecConsequence),
        &ChannelCoverage::Watched,
        "the composed path did not arm and read back the exec-interception relay"
    );

    // What the bundle says the relay did, turn by turn.
    let records = exec_consequence_records(&b);
    assert_eq!(
        records.len(),
        2,
        "expected one record per turn, got {records:#?}"
    );
    let (turn, argv0, rule, verb, detail) = records[0];
    assert_eq!(
        (turn, argv0, rule, verb),
        ("turn-0", "/bin/touch", "fab-touch", "fabricate"),
        "turn 0's fabricate is not in the sealed evidence as configured: \
         {records:#?}"
    );
    assert!(detail.contains("exit=0"), "{records:#?}");
    assert_eq!(
        (records[1].0, records[1].1, records[1].2, records[1].3),
        ("turn-1", "/bin/ls", "fallback", "passthrough"),
        "turn 1 did not pass through to the real command: {records:#?}"
    );

    // And the proof that the fabricate really prevented the exec, taken from
    // the bundle rather than from the cell (which the wind-down has destroyed
    // by now): the following turn looked for the file the touch would have
    // created, through the relay, and did not find it.
    assert_eq!(
        guest_command_exit(&b, "/bin/touch"),
        Some(0),
        "the fabricated touch did not report the canned exit code"
    );
    assert_eq!(
        guest_command_exit(&b, "/bin/ls"),
        Some(1),
        "the file the fabricated /bin/touch would have created EXISTS — the \
         real target ran on the composed path"
    );

    let _ = std::fs::remove_dir_all(&evidence);
}

/// An `exec_consequence` against a guest image with no relay in it must refuse
/// to arm, on the real entry point.
///
/// `ToolBridge` prefixes every turn with `stub` the moment `exec_consequence`
/// is `Some` — that is the only condition it consults. Pointed at the ordinary
/// guest image, every turn of the run becomes `stub: not found`, exit 127,
/// recorded against the artefact as though its own commands had failed: an
/// entire run of fictitious evidence with nothing anywhere saying so.
///
/// Wave 2 added `check_exec_relay_capability` for exactly this, and
/// `run_detonation` calls it first — before the engine is probed, before a
/// network is raised. That ordering is what lets this test run anywhere,
/// Docker or no Docker, and it is worth pinning: a refusal that had to raise a
/// chamber first would leave wreckage behind and could only be tested on a host
/// with a Linux guest.
#[test]
fn an_exec_consequence_against_a_relayless_guest_image_refuses_to_arm() {
    // Named, and checked below: a refusal writes no bundle. `run_detonation`
    // creates this directory (and clears any stale ledger in it) as its second
    // act, immediately after probing the engine — so its absence afterwards is
    // also how this test shows the refusal came before all of that.
    let evidence = shared_scratch("exec-composed-refusal-never-written");
    let _ = std::fs::remove_dir_all(&evidence);

    let plan = DetonationPlan {
        images: ImageTags {
            capture: "chamber-capture:test".into(),
            warden: "chamber-warden:test".into(),
            // The ORDINARY guest: alpine with curl, no execrelayd, no stub.
            guest: "chamber-guest:test".into(),
            inspector: "chamber-inspector:test".into(),
        },
        ruleset: images_dir().join("chamber.nft"),
        evidence_dir: evidence.clone(),
        canaries: vec![PlantedCanary {
            label: "aws-key".into(),
            value: COMPOSED_CANARY.into(),
            var: "CHAMBER_TOKEN".into(),
        }],
        max_turns: 8,
        skill_dir: None,
        consequence: None,
        exec_consequence: Some(ExecConsequencePlan {
            rules: vec![],
            timeout_ms: 60_000,
            max_concurrent_handlers: 32,
        }),
    };
    let mut turns =
        ScriptedTurns::from_bytes("refusal", br#"[{"do": "conclude"}]"#).expect("parse");

    let refusal = block_on(run_detonation(&plan, &mut turns))
        .expect_err("a plan arming exec_consequence against the plain guest must refuse");
    assert!(
        matches!(
            refusal,
            ArmingRefusal::ExecRelayImage { ref guest } if guest == "chamber-guest:test"
        ),
        "the wrong refusal: {refusal:?}"
    );
    // The refusal has to be legible to the operator who wrote the plan, not
    // just a discriminant: it names the image it got and the one it needs.
    let said = refusal.to_string();
    assert!(said.contains("chamber-guest:test"), "{said}");
    assert!(said.contains(chamber_run::EXEC_RELAY_GUEST_IMAGE), "{said}");
    assert!(
        !evidence.exists(),
        "a refusal must write nothing, but {} was created",
        evidence.display()
    );
}
