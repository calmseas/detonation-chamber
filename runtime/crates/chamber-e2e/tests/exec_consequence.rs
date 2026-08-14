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

/// The records whose `verb_applied` is exactly `verb`.
fn records_with_verb(records: &[serde_json::Value], verb: &str) -> Vec<serde_json::Value> {
    records
        .iter()
        .filter(|v| v.get("verb_applied").and_then(|x| x.as_str()) == Some(verb))
        .cloned()
        .collect()
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
    let names = |out: &str| -> Vec<String> {
        let mut v: Vec<String> = out
            .lines()
            .filter_map(|l| l.split_once('=').map(|(k, _)| k.to_owned()))
            .collect();
        v.sort();
        v
    };
    assert_eq!(
        names(&via_relay.stdout),
        names(&direct.stdout),
        "the relayed environment names differ from a direct exec's"
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
