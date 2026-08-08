//! Does the containment actually contain?
//!
//! Writing nftables rules and then asserting that `nft list ruleset` contains
//! them tests nothing at all. What follows is built the other way round.
//!
//! # The positive control comes first, and it is why the rest means anything
//!
//! A probe that fails because the hostname was typo'd, or because the image is
//! missing the tool the row shells out to, fails *identically* to one that was
//! contained — and passes every containment assertion anyone will ever write
//! against it. Eleven confident greens, none of which can tell "the chamber
//! stopped it" from "it never ran".
//!
//! So [`containment_probe_is_capable_of_succeeding_when_unarmed`] runs the same
//! probe, with the same code path per row, on a network with nothing blocking
//! it — and requires it to **succeed**. Only against that baseline is an armed
//! failure attributable to the chamber. Every armed assertion is written as a
//! delta against this, never as an absolute.
//!
//! This test exists *before* the first nftables rule, deliberately. Once a
//! ruleset exists there is no way back to a state in which the probe could have
//! been observed working.
//!
//! # Every negative is corroborated
//!
//! A blocked probe row on its own is one-sided evidence. It was measured on
//! this engine that a chamber *without* the tarpit route blocks the probe
//! identically to one with it — the probe's own output byte for byte the same —
//! while `c_drop_out` stays at exactly zero and no frame is ever logged.
//! Contained, and blind. So each armed row asserts both that the technique
//! failed *and* that the chamber independently saw it try.
//!
//! # What is here, and what is not yet
//!
//! - the container gate, which fails rather than skips in CI
//! - the three structural asserts, measured and not assumed
//! - the unarmed positive control
//! - the armed run: nine rows, corroborated by counters and captured frames
//! - the observed rows: the proxy refuses with 403 and every name resolves to
//!   the observer, with the exchange recovered in the ledger
//!
//! One row of the plan's table is still **absent** rather than quietly passing:
//! row 7 (inbound refusal) needs a listener alive in the cell *and* a dialer
//! outside the namespace. The warden shares the cell's namespace, so a dial
//! from it traverses `iif "lo" accept` and would prove nothing.
//!
//! # Blocked is not the same as observed
//!
//! The armed rows prove the cell cannot get out. The observed rows prove that
//! what it *is* permitted to do is seen: a request decrypted and read in full
//! before it is refused, and a name recovered whether or not anything answered
//! it. A chamber that only blocked would be a firewall, and a firewall produces
//! no evidence.

use std::path::PathBuf;
use std::sync::{Mutex, OnceLock};
use std::time::Duration;

use chamber_isolation::{
    AgentCell, Attach, CanaryPlacements, Container, ContainerSpec, Docker, EMPTY_BOUNDING_SET,
    EnvDraft, EnvFile, GuestImage, GuestRoot, NetFabric, Network, NetworkSpec, Preflight,
    ProbeReport, Rationale, Reach, RowId, VarName, Warden, build_image,
    build_image_with_dockerfile,
};

const OP_WINDOW: Duration = Duration::from_secs(90);
/// Generous: the probe's own rows each carry a timeout, and several are
/// *supposed* to sit waiting for a reply that never comes.
const PROBE_WINDOW: Duration = Duration::from_secs(180);

/// The engine, or a decision about what its absence means.
///
/// Locally this skips with a printed reason, because not every machine has a
/// Linux guest and a suite nobody can run is a suite nobody maintains. In CI
/// `CHAMBER_REQUIRE_CONTAINERS` is set and the same absence is a failure — a
/// containment suite that no-ops when Docker is missing makes a green tick mean
/// nothing at all, and that is worse than having no suite.
fn require_containers() -> Option<Docker> {
    match Docker::probe() {
        Ok(engine) => Some(engine),
        Err(e) if std::env::var("CHAMBER_REQUIRE_CONTAINERS").is_ok() => {
            panic!("containment suite cannot run: {e}")
        }
        Err(e) => {
            eprintln!("SKIPPED (requires a Linux guest): {e}");
            None
        }
    }
}

fn images_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(|p| p.parent())
        .expect("crates/<pkg> sits two levels below runtime/")
        .join("images")
}

/// Builds the suite's images once per test binary.
///
/// Serialised because two `docker build`s racing on the same tag interleave
/// their output into something no one can diagnose.
fn ensure_images() {
    static BUILT: OnceLock<Mutex<bool>> = OnceLock::new();
    let lock = BUILT.get_or_init(|| Mutex::new(false));
    let mut done = lock.lock().unwrap_or_else(|e| e.into_inner());
    if *done {
        return;
    }
    for name in ["probe", "sink", "guest", "inspector", "warden"] {
        let dir = images_dir().join(name);
        build_image(&dir, &format!("chamber-{name}:test"))
            .unwrap_or_else(|e| panic!("could not build the {name} image from {dir:?}: {e}"));
    }

    // The capture image is the odd one out: its Dockerfile lives under
    // images/capture/ but it compiles the workspace, so its context is
    // runtime/. It is also the slow one — ~290 crates and a cmake C build —
    // which is why the whole of `ensure_images` is memoised rather than run per
    // test.
    let runtime = images_dir()
        .parent()
        .expect("images/ sits under runtime/")
        .to_path_buf();
    build_image_with_dockerfile(
        &runtime,
        &images_dir().join("capture").join("Dockerfile"),
        "chamber-capture:test",
    )
    .expect("could not build the capture image");

    *done = true;
}

/// Serialises the tests that raise the chamber's subnet.
///
/// Two of them need `10.66.0.0/24`, and Docker refuses the second with "Pool
/// overlaps with other one on this address space". Fixing that with
/// `--test-threads=1` in CI would leave a plain `cargo test` broken for anyone
/// running it locally, which is how a suite acquires a reputation for being
/// flaky rather than a bug for being fixed.
fn chamber_subnet_lock() -> std::sync::MutexGuard<'static, ()> {
    static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
    LOCK.get_or_init(|| Mutex::new(()))
        .lock()
        .unwrap_or_else(|e| e.into_inner())
}

/// Removes what a test raised, even when an assertion panicked.
///
/// Without this a failed run leaves its network behind, and every subsequent
/// run fails on a name and subnet that are already taken — which reads as a
/// second, unrelated bug.
#[derive(Default)]
struct Teardown {
    containers: Vec<Container>,
    network: Option<Network>,
}

impl Drop for Teardown {
    fn drop(&mut self) {
        for container in self.containers.drain(..) {
            let _ = container.destroy(OP_WINDOW);
        }
        if let Some(network) = self.network.take() {
            let _ = network.destroy();
        }
    }
}

/// Three independent things must fail before a packet leaves the chamber: the
/// guest's routing table, Docker's `DOCKER-INTERNAL` DROP pair, and the absence
/// of NAT for the subnet. All three are version-dependent and all three fail
/// silently, so all three are measured here rather than assumed.
#[test]
fn structural_asserts_hold_on_the_chamber_network() {
    let Some(engine) = require_containers() else {
        return;
    };
    ensure_images();
    eprintln!(
        "engine: docker {} on {}/{}",
        engine.server_version(),
        engine.os_type(),
        engine.arch()
    );

    let _serialised = chamber_subnet_lock();

    // The real fabric, not a lookalike. A second NetworkSpec repeating the
    // subnet here is what collided with the armed test, and a preflight that
    // validates a network the chamber does not use validates nothing.
    let mut chamber = ChamberTeardown::default();
    let fabric = NetFabric::raise().expect("raise the chamber fabric");
    chamber.fabric = Some(fabric);
    let fabric = chamber.fabric.as_ref().unwrap();

    let preflight = Preflight::run(
        fabric.egress(),
        "chamber-guest:test",
        "chamber-inspector:test",
    )
    .expect("the preflight inspections must be performable");

    for outcome in preflight.outcomes() {
        eprintln!(
            "  {} {}",
            if outcome.held { "HOLDS " } else { "FAILED" },
            outcome.which.description()
        );
    }

    if let Err(failure) = preflight.into_result() {
        panic!("{failure}");
    }
}

/// The test that makes every armed assertion non-vacuous.
///
/// The probe runs with nothing blocking it and must get out. If it cannot, the
/// probe is broken and this suite says so — instead of reporting a row of
/// confident greens that mean only that a broken probe stayed broken.
#[test]
fn containment_probe_is_capable_of_succeeding_when_unarmed() {
    let Some(_engine) = require_containers() else {
        return;
    };
    ensure_images();

    let mut scratch = Teardown::default();

    // NOT `--internal`. This network deliberately has the egress the chamber
    // deliberately does not: that asymmetry is the whole measurement.
    let network = Network::raise(NetworkSpec {
        name: "chamber-unarmed-control".into(),
        subnet: "10.77.0.0/24".into(),
        internal: false,
    })
    .expect("raise the scratch network");
    scratch.network = Some(network);

    let sink_env = EnvFile::write(&[("SINK_IP".into(), "10.77.0.50".into())])
        .expect("write the sink env file");
    let sink = Container::create(&ContainerSpec {
        image: "chamber-sink:test".into(),
        attach: Attach::Network {
            network: "chamber-unarmed-control".into(),
            ip: Some("10.77.0.50".into()),
        },
        cap_add: vec![],
        argv: vec![],
        sysctls: vec![],
        env_file: Some(sink_env.path().clone()),
        dns: vec![],
        read_only: false,
        tmpfs: vec![],
    })
    .expect("create the sink");
    sink.start().expect("start the sink");

    // The sink must be *up*, not merely created. A dead sink makes the HTTP and
    // resolver rows fail, which would read as a broken probe — the exact
    // misattribution this control exists to prevent.
    await_sink(&sink);
    scratch.containers.push(sink);

    // Rows 1, 2, 4 and 11 keep their armed targets: they are the ones that
    // catch a typo'd destination, because an address nobody serves fails
    // exactly like an address that was blocked. Rows 5 and 6 must move --
    // armed, the capture sink answers every name, so `anything.example`
    // resolves; unarmed against real DNS, `.example` is a reserved TLD that
    // NXDOMAINs and the row would fail for a reason unrelated to containment.
    let probe_env = EnvFile::write(&[
        ("T_HTTPS_URL".into(), "http://10.77.0.50/".into()),
        ("T_RESOLVE_NAME".into(), "anything.example".into()),
    ])
    .expect("write the probe env file");

    let probe = Container::create(&ContainerSpec {
        image: "chamber-probe:test".into(),
        attach: Attach::Network {
            network: "chamber-unarmed-control".into(),
            ip: Some("10.77.0.30".into()),
        },
        // The probe runs in the agent's position even here. Running the control
        // with capabilities the real cell will not have would make the baseline
        // unattainable by the thing it is a baseline for.
        cap_add: vec![],
        argv: vec!["probe".into(), "unarmed".into()],
        sysctls: vec![],
        env_file: Some(probe_env.path().clone()),
        dns: vec!["10.77.0.50".into()],
        read_only: false,
        tmpfs: vec![],
    })
    .expect("create the probe");
    probe.start().expect("start the probe");
    probe.wait(PROBE_WINDOW).expect("probe ran to completion");

    let logs = probe.logs().expect("read the probe's output");
    scratch.containers.push(probe);

    eprintln!("unarmed probe output:\n{}", logs.stdout);
    let report = ProbeReport::parse(&logs.stdout).unwrap_or_else(|e| {
        panic!("{e}\nstderr was:\n{}", logs.stderr);
    });

    // Every row must be PRESENT and must have REACHED. Present matters as much
    // as reached: a probe that died after its first row reports nothing for the
    // rest, and "no result" must never be read as a result.
    let must_reach = [
        RowId::TcpIpLiteral,
        RowId::UdpDnsDirect,
        RowId::IcmpEcho,
        RowId::Https,
        RowId::Getaddrinfo,
        RowId::UdpHigh,
    ];

    let mut broken = Vec::new();
    for row in must_reach {
        match report.require(row) {
            Err(missing) => broken.push(missing),
            Ok(reported) if reported.reach() != Reach::Reached => broken.push(format!(
                "row `{row}` did not reach {} — {}",
                reported.target, reported.detail
            )),
            Ok(_) => {}
        }
    }

    assert!(
        broken.is_empty(),
        "THE POSITIVE CONTROL FAILED. The probe could not get out with nothing \
         blocking it, so it is not capable of demonstrating containment and \
         every armed assertion built on it would be vacuous. Fix the probe \
         before trusting any containment result:\n  {}",
        broken.join("\n  ")
    );
}

/// Waits for the sink to be serving, and fails with its logs if it never does.
///
/// The first version of this sink died instantly on `httpd: not found` —
/// `busybox-extras` carries the applet and the base image does not. It exited
/// 127 in under a second, and without this check the symptom surfaced two
/// containers later as an unreachable HTTP row.
fn await_sink(sink: &Container) {
    let deadline = std::time::Instant::now() + Duration::from_secs(30);
    // Both services, exercised rather than inferred from a process list: the
    // HTTP row and the resolver row each depend on a different one of them.
    let ready = "wget -q -O /dev/null http://127.0.0.1/ && nslookup readiness.check 127.0.0.1";
    loop {
        let probe = sink.exec(&["sh", "-c", ready], OP_WINDOW);
        if matches!(probe, Ok(ref o) if o.ok()) {
            return;
        }
        assert!(
            std::time::Instant::now() < deadline,
            "the sink never came up. Its logs:\n{}",
            sink.logs()
                .map(|l| l.stdout + &l.stderr)
                .unwrap_or_default()
        );
        std::thread::sleep(Duration::from_millis(250));
    }
}

/// Removes the armed chamber. The warden goes first: a network with a container
/// still attached cannot be removed, and the resulting error would be reported
/// in place of whatever actually failed.
#[derive(Default)]
struct ChamberTeardown {
    cells: Vec<Container>,
    agent: Option<AgentCell>,
    warden: Option<chamber_isolation::ObservedWarden>,
    fabric: Option<NetFabric>,
}

impl Drop for ChamberTeardown {
    fn drop(&mut self) {
        for cell in self.cells.drain(..) {
            let _ = cell.destroy(OP_WINDOW);
        }
        if let Some(agent) = self.agent.take() {
            let _ = agent.destroy(OP_WINDOW);
        }
        if let Some(warden) = self.warden.take() {
            let _ = warden.destroy();
        }
        if let Some(fabric) = self.fabric.take() {
            let _ = fabric.destroy();
        }
    }
}

/// The armed run: every row the unarmed baseline reached is now stopped, and
/// the chamber independently saw each attempt.
///
/// The corroboration is not decoration. Without the tarpit route this chamber
/// blocks the probe *identically* — same output, byte for byte — while
/// `c_drop_out` stays at zero and nothing is logged. A suite that only asked
/// "did the probe fail?" would pass in that state and the run would carry no
/// evidence at all.
#[test]
fn the_armed_chamber_blocks_and_records_what_the_baseline_reached() {
    let Some(_engine) = require_containers() else {
        return;
    };
    ensure_images();

    let _serialised = chamber_subnet_lock();

    let mut chamber = ChamberTeardown::default();
    let fabric = NetFabric::raise().expect("raise the chamber fabric");

    // Measured before anything is believed. All three are version-dependent
    // and all three fail silently.
    Preflight::run(
        fabric.egress(),
        "chamber-guest:test",
        "chamber-inspector:test",
    )
    .expect("preflight must be performable")
    .into_result()
    .unwrap_or_else(|f| panic!("{f}"));

    // The ordering below is enforced by the type system, not by this comment:
    // `add_tarpit_route` exists only on an ObservedWarden, which only a
    // confirmed collector can produce, which only a loaded ruleset can precede.
    let warden = Warden::start(&fabric, "chamber-warden:test").expect("start the warden");
    let ruleset = images_dir().join("chamber.nft");
    let warden = warden.load_ruleset(&ruleset).expect("load the ruleset");
    let warden = warden
        .start_drop_collector()
        .expect("the NFLOG collector must be confirmed listening");
    warden.add_tarpit_route().expect("add the tarpit route");

    let before = warden.counters().expect("read counters");
    assert_eq!(
        before.drop_out, 0,
        "a fresh chamber has dropped nothing; got {before:?}"
    );

    chamber.fabric = Some(fabric);
    chamber.warden = Some(warden);
    let warden = chamber.warden.as_ref().unwrap();

    // The agent's position: the warden's namespace, and no capabilities.
    // Targets are the probe's defaults, which ARE the armed expectations.
    let cell = Container::create(&ContainerSpec {
        image: "chamber-probe:test".into(),
        attach: Attach::SharedWith {
            container_id: warden.container_id().to_owned(),
        },
        cap_add: vec![],
        argv: std::iter::once("probe".to_owned())
            .chain(ARMED_ROWS.iter().map(|s| (*s).to_owned()))
            .collect(),
        sysctls: vec![],
        env_file: None,
        dns: vec![],
        read_only: false,
        tmpfs: vec![],
    })
    .expect("create the probe cell");
    cell.start().expect("start the probe cell");
    cell.wait(PROBE_WINDOW).expect("probe ran to completion");
    let logs = cell.logs().expect("read the probe's output");
    chamber.cells.push(cell);

    eprintln!("armed probe output:\n{}", logs.stdout);
    let report = ProbeReport::parse(&logs.stdout)
        .unwrap_or_else(|e| panic!("{e}\nstderr was:\n{}", logs.stderr));

    let mut failures = Vec::new();

    // Rows that must be REFUSED. Each was measured reaching in the unarmed
    // baseline, so a block here is attributable to the chamber.
    for row in [
        RowId::TcpIpLiteral,
        RowId::UdpDnsDirect,
        RowId::TcpCaptureWrongPort,
        RowId::IcmpEcho,
        RowId::NftFlush,
        RowId::IpRouteAdd,
        RowId::NftList,
    ] {
        match report.require(row) {
            Err(missing) => failures.push(missing),
            Ok(r) if r.reach() != Reach::Blocked => {
                failures.push(format!("row `{row}` REACHED {} — {}", r.target, r.detail));
            }
            Ok(_) => {}
        }
    }

    // Two rows whose success IS the desired result, for different reasons.
    //
    // `capbnd` reports the cell's capability bounding set, and an empty one is
    // a stronger claim than "we dropped privileges": a setuid binary or a root
    // shell inside the cell cannot regain NET_ADMIN.
    match report.require(RowId::Capbnd) {
        Err(missing) => failures.push(missing),
        Ok(r) if r.reach() != Reach::Reached => {
            failures.push(format!("the cell holds capabilities: {}", r.detail));
        }
        Ok(r) => assert!(r.detail.contains("0000000000000000"), "{}", r.detail),
    }

    // `udp_high` is the honest weak one. A UDP send is accepted by the local
    // stack whether or not anything is reachable, so the row reports success
    // even in a fully armed chamber — measured, not assumed. Its containment is
    // provable only from the counter, and nothing about the datagram is
    // decoded. That is precisely `gap.udp-quic`, and asserting a block here
    // would be asserting something this build does not do.
    if let Err(missing) = report.require(RowId::UdpHigh) {
        failures.push(missing);
    }

    let after = warden.counters().expect("read counters after the run");
    let frames = warden.captured_frames().expect("read the captured frames");

    eprintln!("counters after: {after:?}");

    // Corroboration 1 — the chamber counted the drops.
    if after.drop_out <= before.drop_out {
        failures.push(format!(
            "c_drop_out did not increase ({} -> {}). The chamber blocked the \
             probe but recorded nothing: contained and BLIND. Suspect the \
             tarpit route first — without it an off-subnet packet dies at the \
             routing layer and never reaches netfilter.",
            before.drop_out, after.drop_out
        ));
    }

    // Corroboration 2 — row 1's exact 5-tuple, so the count is tied to the
    // destination the probe actually named rather than to traffic in general.
    if !frames.contains("8.8.8.8.443") {
        failures.push(format!(
            "no captured frame names 8.8.8.8.443; the drop counter moved but \
             the evidence trail did not.\nframes:\n{frames}"
        ));
    }

    // Corroboration 3 — the QNAME survives. This is the one that matters for
    // exfil: a blocked DNS query still yields the domain it was aimed at.
    if !frames.contains("probe.invalid") {
        failures.push(format!(
            "the blocked DNS query's QNAME was not recovered from the NFLOG \
             capture; a domain an artefact tried to reach would be lost.\n\
             frames:\n{frames}"
        ));
    }

    assert!(
        failures.is_empty(),
        "the armed chamber did not contain, or did not record:\n  {}",
        failures.join("\n  ")
    );

    // The chamber must still resolve. The scoped reset in chamber.nft exists
    // because a full flush destroys Docker's nat table — the 127.0.0.11 DNAT —
    // and kills DNS for the whole namespace. That damage presents as a flaky
    // network rather than as a rule anyone wrote.
    assert!(
        !frames.is_empty(),
        "the collector captured nothing at all despite reporting that it was \
         listening"
    );
}

/// The agent cell holds nothing, receives its sealed environment, and does not
/// spill that environment into the host's process table.
///
/// The last of those is plan risk 14, and it is the reason `-e KEY=VALUE` does
/// not exist in this crate's engine API: it would put every value — planted
/// canaries included — in `ps` output for the container's whole lifetime, where
/// any user on the machine can read it. The chamber would then be the leak it
/// exists to detect.
#[test]
fn the_agent_cell_holds_nothing_and_leaks_nothing_to_the_host() {
    let Some(_engine) = require_containers() else {
        return;
    };
    ensure_images();
    let _serialised = chamber_subnet_lock();

    let mut chamber = ChamberTeardown::default();
    let fabric = NetFabric::raise().expect("raise the chamber fabric");

    let warden = Warden::start(&fabric, "chamber-warden:test").expect("start the warden");
    let warden = warden
        .load_ruleset(&images_dir().join("chamber.nft"))
        .expect("load the ruleset");
    let warden = warden
        .start_drop_collector()
        .expect("collector must be confirmed listening");
    warden.add_tarpit_route().expect("add the tarpit route");

    chamber.fabric = Some(fabric);
    chamber.warden = Some(warden);
    let warden = chamber.warden.as_ref().unwrap();

    // Distinctive enough that finding it in `ps` output is unambiguous.
    let canary_value = format!("chamber-canary-{}-do-not-leak", std::process::id());
    let token = VarName::parse("CHAMBER_TOKEN").expect("well-formed");
    let why = Rationale {
        reason: "the planted canary this run watches for",
        required_by: "chamber-e2e::the_agent_cell_holds_nothing_and_leaks_nothing_to_the_host",
    };

    let mut draft = EnvDraft::empty();
    // Trust anchor first, so a later host adoption that would redirect it is
    // already a duplicate-name error rather than a silent override.
    draft
        .place_trust_anchor(std::path::Path::new("/work/chamber-ca.pem"))
        .expect("place the trust anchor");
    draft
        .redirect_scratch(&GuestRoot::at("/work"))
        .expect("redirect scratch");
    draft
        .set(token.clone(), canary_value.clone(), why)
        .expect("plant the canary");

    let mut canaries = CanaryPlacements::none();
    canaries.plant_env("test-token", token.clone());
    let sealed = draft.seal(&canaries).expect("seal the environment");

    let agent = AgentCell::start(warden, &sealed, &GuestImage::tagged("chamber-guest:test"))
        .expect("start the agent cell");

    // Read from /proc, not inferred from the flags we passed: what was asked
    // for and what the kernel granted are different claims.
    let bounding = agent
        .capability_bounding_set()
        .expect("read the bounding set");
    assert_eq!(
        bounding, EMPTY_BOUNDING_SET,
        "the cell holds capabilities: a root shell inside it could regain \
         NET_ADMIN and rewrite the rules containing it"
    );

    // The sealed environment actually arrived.
    let seen = agent
        .exec(&["sh", "-c", "printf %s \"$CHAMBER_TOKEN\""], OP_WINDOW)
        .expect("read the canary back");
    assert_eq!(
        seen.stdout, canary_value,
        "the planted canary did not reach the cell; the run would have nothing \
         to find and would report no finding"
    );

    let anchor = agent
        .exec(&["sh", "-c", "printf %s \"$SSL_CERT_FILE\""], OP_WINDOW)
        .expect("read the anchor back");
    assert_eq!(anchor.stdout, "/work/chamber-ca.pem");

    // Risk 14. `--env-file` keeps the value out of the host process table;
    // `-e` would not.
    let host_ps = std::process::Command::new("ps")
        .args(["-axww", "-o", "command"])
        .output()
        .expect("read the host process table");
    let host_ps = String::from_utf8_lossy(&host_ps.stdout);
    // Absence proves nothing if we did not actually read a process table: a
    // failed `ps` returns empty, and "the canary is not in this empty string"
    // passes forever.
    //
    // The proof is that THIS process is visible. It is the right control
    // because it is the process a `-e` leak would have shown up in — the
    // harness is what invokes the engine. Looking for "docker" instead would be
    // unreliable: the CLI processes have already exited by now, which made this
    // check pass only intermittently.
    let own_exe = std::env::current_exe().expect("current exe");
    let own_name = own_exe
        .file_name()
        .expect("exe has a file name")
        .to_string_lossy()
        .into_owned();
    assert!(
        host_ps.contains(&own_name),
        "the host process table does not even show this test process ({own_name}), \
         so the leak check below would pass vacuously. Read {} lines.",
        host_ps.lines().count()
    );
    assert!(
        !host_ps.contains(&canary_value),
        "the canary is visible in the HOST process table — any user on this \
         machine can read it out of `ps`. This is what `-e KEY=VALUE` does and \
         why the engine API here has no such option."
    );

    // Files arrive over stdin, never as an argument and never through a mount.
    agent
        .write_file(
            std::path::Path::new("/work/planted.env"),
            b"API_KEY=placeholder\n",
        )
        .expect("write a file into the cell");
    let back = agent
        .exec(&["cat", "/work/planted.env"], OP_WINDOW)
        .expect("read it back");
    assert!(back.stdout.contains("API_KEY=placeholder"), "{:?}", back);

    // The rootfs is immutable, so what the artefact leaves behind is bounded to
    // the tmpfs and dies with the container. Asserted from inside the cell
    // rather than trusted from the flag that was passed: what was requested and
    // what the kernel enforced are different claims.
    let rootfs = agent
        .exec(
            &["sh", "-c", "touch /etc/chamber-escape 2>&1; echo rc=$?"],
            OP_WINDOW,
        )
        .expect("attempt a rootfs write");
    assert!(
        rootfs.stdout.contains("rc=1") && rootfs.stdout.contains("Read-only"),
        "the cell's rootfs is writable, so the artefact can modify the image it \
         runs in and the blast radius is not bounded. Got: {:?}",
        rootfs.stdout
    );

    chamber.agent = Some(agent);
}

/// The two rows that need an observer in the chamber: the proxy refuses, and
/// every name resolves to it.
///
/// These are the rows the tool exists for. Rows 1-4 and 8-11 prove the cell
/// cannot get out; these two prove that what it *is* permitted to do is
/// observed — a request decrypted and read before it is refused, and a name
/// recovered whether or not it was ever answered. A chamber that only blocked
/// would be a firewall.
#[test]
fn the_observer_refuses_the_proxied_request_and_answers_every_name() {
    let Some(_engine) = require_containers() else {
        return;
    };
    ensure_images();
    let _serialised = chamber_subnet_lock();

    const CANARY: &str = "AKIAIOSFODNN7EXAMPLE";
    let mut chamber = ChamberTeardown::default();
    let fabric = NetFabric::raise().expect("raise the chamber fabric");

    // The observer, at the address the ruleset accepts and the resolver points
    // at. /evidence is a tmpfs: this container writes the ledger and the host
    // reads it back, and neither needs a handle on the other's filesystem.
    let capture_env = EnvFile::write(&[
        ("CHAMBER_CANARY_AWS_KEY".into(), CANARY.into()),
        ("CHAMBER_LEDGER".into(), "/evidence/ledger.jsonl".into()),
        ("CHAMBER_CA_OUT".into(), "/evidence/chamber-ca.pem".into()),
        ("CHAMBER_ANSWER_WITH".into(), NetFabric::CAPTURE_IP.into()),
        ("CHAMBER_PROXY_ADDR".into(), "0.0.0.0:3128".into()),
        ("CHAMBER_DNS_ADDR".into(), "0.0.0.0:53".into()),
    ])
    .expect("write the capture env file");

    let capture = Container::create(&ContainerSpec {
        image: "chamber-capture:test".into(),
        attach: Attach::Network {
            network: fabric.egress().name().to_owned(),
            ip: Some(NetFabric::CAPTURE_IP.to_owned()),
        },
        cap_add: vec![],
        argv: vec![],
        sysctls: vec![],
        env_file: Some(capture_env.path().clone()),
        dns: vec![],
        read_only: false,
        tmpfs: vec!["/evidence".into()],
    })
    .expect("create the observer");
    capture.start().expect("start the observer");
    await_listening(&capture);

    let warden = Warden::start(&fabric, "chamber-warden:test").expect("start the warden");
    let warden = warden
        .load_ruleset(&images_dir().join("chamber.nft"))
        .expect("load the ruleset");
    let warden = warden
        .start_drop_collector()
        .expect("collector must be confirmed listening");
    warden.add_tarpit_route().expect("add the tarpit route");

    chamber.fabric = Some(fabric);
    chamber.warden = Some(warden);
    chamber.cells.push(capture);
    let warden = chamber.warden.as_ref().unwrap();
    let capture = chamber.cells.last().unwrap();

    // The per-run CA, read out of the observer and placed in the cell's tmpfs.
    // The private key never leaves the observer; only this certificate moves.
    let ca_pem = capture
        .exec(&["cat", "/evidence/chamber-ca.pem"], OP_WINDOW)
        .expect("read the per-run CA");
    assert!(
        ca_pem.stdout.contains("BEGIN CERTIFICATE"),
        "the observer did not produce a CA: {ca_pem:?}"
    );

    let anchor_path = std::path::Path::new("/work/chamber-ca.pem");
    let mut draft = EnvDraft::empty();
    draft
        .redirect_scratch(&GuestRoot::at("/work"))
        .expect("redirect scratch");
    // Bound before anything else could claim these names.
    draft
        .place_trust_anchor(anchor_path)
        .expect("place the trust anchor");
    let why = Rationale {
        reason: "the artefact's egress must go through the observer to be seen",
        required_by: "chamber-e2e::the_observer_refuses_the_proxied_request",
    };
    for var in ["https_proxy", "http_proxy", "HTTPS_PROXY", "HTTP_PROXY"] {
        draft
            .set(
                VarName::parse(var).expect("well-formed"),
                format!("http://{}:3128", NetFabric::CAPTURE_IP),
                why,
            )
            .expect("bind the proxy variable");
    }
    let sealed = draft
        .seal(&CanaryPlacements::none())
        .expect("seal the environment");

    let cell = AgentCell::start(warden, &sealed, &GuestImage::tagged("chamber-probe:test"))
        .expect("start the cell");
    cell.write_file(anchor_path, ca_pem.stdout.as_bytes())
        .expect("place the CA in the cell");

    let outcome = cell
        .exec(&["probe", "https", "getaddrinfo"], PROBE_WINDOW)
        .expect("run the two observed rows");
    eprintln!("observed rows:\n{}", outcome.stdout);
    let report = ProbeReport::parse(&outcome.stdout)
        .unwrap_or_else(|e| panic!("{e}\nstderr:\n{}", outcome.stderr));
    chamber.agent = Some(cell);

    // Row 5. Not merely blocked — REFUSED, with a status the cell can read.
    // A dropped packet would be containment; a 403 is containment plus an
    // observer that decrypted the request, read the whole body, and declined.
    let https = report
        .require(RowId::Https)
        .unwrap_or_else(|e| panic!("{e}"));
    assert!(
        https.detail.contains("http_code=403"),
        "the proxy did not refuse with 403 — a different code means the request \
         went somewhere, and a TLS error means it was never decrypted at all: {}",
        https.detail
    );

    // Row 6. Every name resolves to the observer, so a lookup is recorded even
    // when the destination is never reached.
    let resolved = report
        .require(RowId::Getaddrinfo)
        .unwrap_or_else(|e| panic!("{e}"));
    assert_eq!(resolved.reach(), Reach::Reached, "{}", resolved.detail);
    assert!(
        resolved
            .detail
            .contains(&format!("resolved_to={}", NetFabric::CAPTURE_IP)),
        "a name resolved somewhere other than the observer: {}",
        resolved.detail
    );

    // The ledger is the point. Both channels, one sequence, and the request the
    // proxy refused is in it with its plaintext recovered.
    let ledger = capture
        .exec(&["cat", "/evidence/ledger.jsonl"], OP_WINDOW)
        .expect("read the ledger")
        .stdout;
    assert!(
        ledger.contains("\"channel\":\"dns_resolution\""),
        "no DNS observation reached the ledger:\n{ledger}"
    );
    assert!(
        ledger.contains("\"channel\":\"network_egress\""),
        "no egress observation reached the ledger:\n{ledger}"
    );
    assert!(
        ledger.contains("\"kind\":\"http_exchange\""),
        "the refused request was not recorded as an exchange:\n{ledger}"
    );
}

/// Waits until a container prints the line that means its listeners are up.
///
/// The observer must be listening before anything runs against it: an artefact
/// started first does its most interesting work unobserved, and nothing later
/// can recover it.
fn await_listening(container: &Container) {
    let deadline = std::time::Instant::now() + Duration::from_secs(60);
    loop {
        let logs = container
            .logs()
            .map(|l| l.stdout + &l.stderr)
            .unwrap_or_default();
        if logs.contains("LISTENING") {
            return;
        }
        assert!(
            std::time::Instant::now() < deadline,
            "the observer never reported LISTENING. Its output:\n{logs}"
        );
        std::thread::sleep(Duration::from_millis(250));
    }
}

/// Every row the armed run exercises. Rows 5, 6 and 7 are deliberately absent —
/// see the module note; they need infrastructure that does not exist yet, and
/// including them would mean asserting something weaker than it appears.
const ARMED_ROWS: &[&str] = &[
    "tcp_ip_literal",
    "udp_dns_direct",
    "tcp_capture_wrong_port",
    "icmp_echo",
    "udp_high",
    "nft_flush",
    "ip_route_add",
    "nft_list",
    "capbnd",
];
