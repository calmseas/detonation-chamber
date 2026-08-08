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
//! # What is here, and what is not yet
//!
//! - the container gate, which fails rather than skips in CI
//! - the three structural asserts, measured and not assumed
//! - the unarmed positive control
//!
//! The armed run, the drop-counter corroborations and the NFLOG frame
//! assertions arrive with `chamber.nft`. They are the delta; this is the
//! baseline.

use std::path::PathBuf;
use std::sync::{Mutex, OnceLock};
use std::time::Duration;

use chamber_isolation::{
    Attach, Container, ContainerSpec, Docker, EnvFile, Network, NetworkSpec, Preflight,
    ProbeReport, Reach, RowId, build_image,
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
    for name in ["probe", "sink", "guest", "inspector"] {
        let dir = images_dir().join(name);
        build_image(&dir, &format!("chamber-{name}:test"))
            .unwrap_or_else(|e| panic!("could not build the {name} image from {dir:?}: {e}"));
    }
    *done = true;
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

    let mut scratch = Teardown::default();
    let network = Network::raise(NetworkSpec {
        name: "chamber-preflight".into(),
        subnet: "10.66.0.0/24".into(),
        internal: true,
    })
    .expect("raise the chamber network");
    scratch.network = Some(network);
    let network = scratch.network.as_ref().unwrap();

    let preflight = Preflight::run(network, "chamber-guest:test", "chamber-inspector:test")
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
        argv: vec!["unarmed".into()],
        sysctls: vec![],
        env_file: Some(probe_env.path().clone()),
        dns: vec!["10.77.0.50".into()],
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
