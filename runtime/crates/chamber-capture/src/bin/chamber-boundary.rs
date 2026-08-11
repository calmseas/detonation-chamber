//! `chamber-boundary` — the observer, running inside the chamber.
//!
//! Everything the guest sends passes through this process: an intercepting
//! proxy that terminates TLS and records the whole plaintext request, and a DNS
//! sink that answers every name with its own address and logs the asking. They
//! are one process because they share one monotonic ordinal, and that shared
//! sequence is what makes an interleaving — a name looked up, then immediately
//! POSTed to — recoverable from the bundle alone. Two daemons writing two log
//! formats cannot produce it, and reconstructing it by timestamp-merging them
//! afterwards is exactly the log-scraping seam that makes a verdict
//! unfalsifiable.
//!
//! # Configuration arrives by environment, never by argument
//!
//! The canaries this process watches for are secrets. An argument would put
//! them in the process table; the host passes them through a 0600 `--env-file`
//! instead. Each `CHAMBER_CANARY_<LABEL>` variable declares one, its label
//! taken from the suffix.
//!
//! | variable | default | meaning |
//! |---|---|---|
//! | `CHAMBER_LEDGER` | `/evidence/ledger.jsonl` | where observations are appended |
//! | `CHAMBER_CA_OUT` | `/evidence/chamber-ca.pem` | where the per-run CA certificate is written |
//! | `CHAMBER_ANSWER_WITH` | `10.66.0.10` | the address every name resolves to |
//! | `CHAMBER_PROXY_ADDR` | `0.0.0.0:3128` | proxy bind |
//! | `CHAMBER_DNS_ADDR` | `0.0.0.0:53` | DNS bind, UDP and TCP |
//! | `CHAMBER_CANARY_<LABEL>` | — | one planted token to watch for |
//! | `CHAMBER_CONSEQUENCE_STATUS` | — | status to fabricate instead of refusing |
//! | `CHAMBER_CONSEQUENCE_BODY_B64` | — | the body to fabricate, base64 |
//!
//! The last two are the opt-in [consequence
//! mode](chamber_capture::consequence): both set, and intercepted requests are
//! answered plausibly instead of with the 403 that tells an artefact it is being
//! watched. Neither set is the default. Exactly one set is a misconfiguration
//! and refuses to start — see that module for why silence would be worse.
//! Fabricating an answer never forwards anything upstream; the request still
//! dies here.
//!
//! # Readiness is announced, not assumed
//!
//! The host must not start the artefact until this process is listening —
//! otherwise the first thing the artefact does, which is the thing most worth
//! seeing, is the one thing unobserved. So `LISTENING` goes to stdout after
//! *both* binds succeed, and is flushed. The same discipline the NFLOG
//! collector is held to.
//!
//! # A run with no canaries is refused
//!
//! Starting with nothing to look for produces a run that finds nothing and
//! reports no finding — a false negative shaped exactly like a clean result.
//! The fixture matrix does have a row that plants nothing, and it drives that
//! through the *host*, which knows it planted nothing; this process being empty
//! is a misconfiguration and exits non-zero.

use std::net::{Ipv4Addr, SocketAddr};
use std::process::ExitCode;
use std::sync::Arc;
use std::time::Duration;

use chamber_capture::{
    Canary, CanarySet, ConsequencePlan, DnsSink, InterceptingProxy, LedgerWriter, Recorder,
};
use chamber_evidence::{CanaryHit, HitField};
use hickory_server::Server;
use hudsucker::Proxy;
use hudsucker::certificate_authority::RcgenAuthority;
use hudsucker::rcgen::{BasicConstraints, CertificateParams, IsCa, Issuer, KeyPair};
use hudsucker::rustls::crypto::aws_lc_rs;

/// How long a TCP DNS conversation may idle. DNS over TCP is a fallback for
/// large answers; anything holding one open longer is not resolving names.
const DNS_TCP_TIMEOUT: Duration = Duration::from_secs(10);
/// Bounded so a flood of TCP queries cannot grow this process without limit.
const DNS_RESPONSE_QUEUE: usize = 128;

const CANARY_PREFIX: &str = "CHAMBER_CANARY_";

fn env_or(key: &str, fallback: &str) -> String {
    std::env::var(key).unwrap_or_else(|_| fallback.to_owned())
}

/// Write a line to stdout, surviving a reader that has gone away.
///
/// `println!` panics on `EPIPE`. That is tolerable for a CLI and unacceptable
/// here: if whoever launched this process stops reading — a closed pipe, a
/// detached orchestrator, a terminal that went away — the panic lands in the
/// middle of the wind-down and the ledger never gets its terminal marker. A
/// completed run would then be indistinguishable from a killed one, because
/// the only thing that separates them is that marker. Losing evidence to a
/// broken pipe is exactly the incidental failure this system exists to not
/// have.
fn say(line: &str) {
    use std::io::Write as _;
    let mut out = std::io::stdout().lock();
    let _ = writeln!(out, "{line}");
    let _ = out.flush();
}

/// Every `CHAMBER_CANARY_<LABEL>` in the environment, as a canary set.
///
/// The label is the suffix, lowercased and hyphenated, so
/// `CHAMBER_CANARY_AWS_KEY` becomes `aws-key` — the same label that appears in
/// the bundle's hit records, where a human reads it.
fn canaries_from_env() -> Vec<Canary> {
    let mut found: Vec<(String, String)> = std::env::vars()
        .filter_map(|(k, v)| {
            k.strip_prefix(CANARY_PREFIX)
                .map(|label| (label.to_lowercase().replace('_', "-"), v))
        })
        .filter(|(_, value)| !value.is_empty())
        .collect();
    // Deterministic, so two runs of the same configuration produce the same
    // ordering in anything that iterates them.
    found.sort();
    found
        .into_iter()
        .map(|(label, value)| Canary::new(label, value))
        .collect()
}

/// The synthetic token the boundary plants in its own self-test. Deliberately
/// not a real credential shape, and never placed in a cell, so a hit on it can
/// only ever come from the self-test itself.
const SELFTEST_PROBE: &str = "CHAMBER-SELFTEST-CANARY-DO-NOT-PLANT";

/// Runs the matcher over a synthetic token in every field a real one could
/// leave by, returning the number of checks that passed or the first that did
/// not. Exercises the real [`CanarySet`], not a stand-in.
fn run_selftest(matcher: &CanarySet, probe: &str) -> Result<usize, String> {
    let checks: [(&str, Vec<CanaryHit>); 4] = [
        ("body", matcher.scan(HitField::Body, probe.as_bytes())),
        (
            "url",
            matcher.scan(HitField::Target, format!("/x?d={probe}").as_bytes()),
        ),
        ("header", matcher.scan(HitField::Header, probe.as_bytes())),
        ("sni", matcher.scan_sni(&format!("{probe}.exfil.example"))),
    ];
    for (field, hits) in &checks {
        if hits.is_empty() {
            return Err(format!("the matcher missed the token in a {field}"));
        }
    }
    Ok(checks.len())
}

/// Proves the canary matcher is live before the run begins.
///
/// A matcher that has silently broken reports every real run as no finding — a
/// false clean, the worst outcome this tool has. So the observer feeds its own
/// matcher a synthetic token and a boundary whose self-test fails refuses to
/// start rather than watch a run it cannot see.
fn self_test() -> Result<usize, String> {
    let matcher = CanarySet::new(vec![Canary::new("selftest", SELFTEST_PROBE)]);
    run_selftest(&matcher, SELFTEST_PROBE)
}

/// A per-run certificate authority.
///
/// Generated fresh every time and never persisted. A shared anchor would let
/// one run's certificates be believed in another, and it would destroy per-run
/// attribution: one leak would compromise every run that ever used it. The
/// private key never leaves this process — only the certificate is written out,
/// for the host to place in the guest's tmpfs.
fn per_run_ca() -> (RcgenAuthority, String) {
    let key = KeyPair::generate().expect("key generation");
    let mut params = CertificateParams::new(Vec::<String>::new()).expect("ca params");
    params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);

    let cert = params.self_signed(&key).expect("self-signed ca");
    let pem = cert.pem();

    let issuer = Issuer::from_ca_cert_der(cert.der(), key).expect("issuer from der");
    let authority = RcgenAuthority::new(issuer, 1_000, aws_lc_rs::default_provider());

    (authority, pem)
}

#[tokio::main]
async fn main() -> ExitCode {
    let ledger_path = env_or("CHAMBER_LEDGER", "/evidence/ledger.jsonl");
    let ca_out = env_or("CHAMBER_CA_OUT", "/evidence/chamber-ca.pem");
    let answer_with = env_or("CHAMBER_ANSWER_WITH", "10.66.0.10");
    let proxy_addr = env_or("CHAMBER_PROXY_ADDR", "0.0.0.0:3128");
    let dns_addr = env_or("CHAMBER_DNS_ADDR", "0.0.0.0:53");

    let answer_with: Ipv4Addr = match answer_with.parse() {
        Ok(a) => a,
        Err(e) => {
            eprintln!("CHAMBER_ANSWER_WITH is not an IPv4 address: {e}");
            return ExitCode::FAILURE;
        }
    };
    let proxy_addr: SocketAddr = match proxy_addr.parse() {
        Ok(a) => a,
        Err(e) => {
            eprintln!("CHAMBER_PROXY_ADDR is not a socket address: {e}");
            return ExitCode::FAILURE;
        }
    };
    let dns_addr: SocketAddr = match dns_addr.parse() {
        Ok(a) => a,
        Err(e) => {
            eprintln!("CHAMBER_DNS_ADDR is not a socket address: {e}");
            return ExitCode::FAILURE;
        }
    };

    // Read before anything binds. A half-configured consequence must refuse to
    // arm, and discovering that once the artefact is already running is
    // discovering it too late.
    let consequence = match ConsequencePlan::from_env() {
        Ok(c) => c,
        Err(e) => {
            eprintln!("chamber-boundary: {e}");
            return ExitCode::FAILURE;
        }
    };

    let canaries = canaries_from_env();
    if canaries.is_empty() {
        eprintln!(
            "no {CANARY_PREFIX}* variables are set, so this observer has nothing to look for. \
             A run configured this way finds nothing and reports no finding, which is \
             indistinguishable from a clean result. Refusing to start."
        );
        return ExitCode::FAILURE;
    }

    // Before anything is watched, prove the thing doing the watching works. A
    // matcher that has silently broken would pass the whole run as no finding;
    // catching that here makes it a refusal to arm rather than a false clean.
    match self_test() {
        Ok(n) => say(&format!(
            "chamber-boundary: matcher self-test passed ({n} checks)"
        )),
        Err(e) => {
            eprintln!(
                "chamber-boundary: matcher self-test FAILED: {e}. Refusing to start, \
                 because a matcher that misses a synthetic token would miss a real one \
                 and report the run as no finding."
            );
            return ExitCode::FAILURE;
        }
    }

    // Owned, so reporting the labels does not keep the set borrowed past the
    // point it is handed to the observers.
    let labels: Vec<String> = canaries.iter().map(|c| c.label().to_owned()).collect();

    // Opened before anything listens: a boundary that cannot write its
    // observations is not a boundary, and discovering that after the artefact
    // has been running is discovering it too late.
    let writer = match LedgerWriter::create(&ledger_path) {
        Ok(w) => w,
        Err(e) => {
            eprintln!("cannot open the ledger at {ledger_path}: {e}");
            return ExitCode::FAILURE;
        }
    };
    let recorder = Arc::new(Recorder::writing_to(writer));

    let (ca, ca_pem) = per_run_ca();
    if let Err(e) = std::fs::write(&ca_out, ca_pem.as_bytes()) {
        eprintln!("cannot write the CA certificate to {ca_out}: {e}");
        return ExitCode::FAILURE;
    }

    // ---- DNS, UDP and TCP -------------------------------------------------
    let sink = DnsSink::new(
        Arc::clone(&recorder),
        CanarySet::new(canaries.clone()),
        answer_with,
    );
    let mut dns = Server::new(sink);

    match tokio::net::UdpSocket::bind(dns_addr).await {
        Ok(socket) => dns.register_socket(socket),
        Err(e) => {
            eprintln!("cannot bind DNS/udp on {dns_addr}: {e}");
            return ExitCode::FAILURE;
        }
    }
    match tokio::net::TcpListener::bind(dns_addr).await {
        Ok(listener) => dns.register_listener(listener, DNS_TCP_TIMEOUT, DNS_RESPONSE_QUEUE),
        Err(e) => {
            eprintln!("cannot bind DNS/tcp on {dns_addr}: {e}");
            return ExitCode::FAILURE;
        }
    }

    // ---- the intercepting proxy -------------------------------------------
    let listener = match tokio::net::TcpListener::bind(proxy_addr).await {
        Ok(l) => l,
        Err(e) => {
            eprintln!("cannot bind the proxy on {proxy_addr}: {e}");
            return ExitCode::FAILURE;
        }
    };
    let proxy = match Proxy::builder()
        .with_listener(listener)
        .with_ca(ca)
        .with_rustls_connector(aws_lc_rs::default_provider())
        .with_http_handler(
            InterceptingProxy::new(Arc::clone(&recorder), CanarySet::new(canaries))
                .with_consequence(consequence.clone()),
        )
        .build()
    {
        Ok(p) => p,
        Err(e) => {
            eprintln!("cannot build the proxy: {e}");
            return ExitCode::FAILURE;
        }
    };
    tokio::spawn(async move {
        if let Err(e) = proxy.start().await {
            eprintln!("the proxy stopped: {e}");
        }
    });
    tokio::spawn(async move {
        if let Err(e) = dns.block_until_done().await {
            eprintln!("the DNS sink stopped: {e}");
        }
    });

    // Both binds succeeded. Nothing before this line may be taken as readiness.
    say(&format!(
        "chamber-boundary: ledger={ledger_path} ca={ca_out}"
    ));
    say(&format!(
        "chamber-boundary: watching {} canary label(s): {}",
        labels.len(),
        labels.join(", ")
    ));
    say(&format!(
        "chamber-boundary: proxy={proxy_addr} dns={dns_addr} answering {answer_with}"
    ));
    // Said out loud, because the two modes are indistinguishable downstream:
    // the observations a run records are identical either way, so this line is
    // what tells a reader of the log whether the guest was being refused or
    // told a story. An unannounced consequence mode would let a fabricated 200
    // be mistaken for real uplink, which is the one misreading this feature
    // could cause.
    match &consequence {
        Some(plan) => {
            let routes = plan.route_paths();
            say(
                "chamber-boundary: CONSEQUENCE MODE — intercepted requests are answered \
                 with fabricated responses instead of refused. Nothing is forwarded to \
                 an origin; the request still dies here.",
            );
            for path in &routes {
                let r = plan.response_for(path);
                say(&format!(
                    "chamber-boundary:   {path} -> {} ({} byte(s))",
                    r.status(),
                    r.body().len()
                ));
            }
            let f = plan.fallback();
            say(&format!(
                "chamber-boundary:   (any other path) -> {} ({} byte(s))",
                f.status(),
                f.body().len()
            ));
        }
        None => say("chamber-boundary: intercepted requests are refused (403)"),
    }
    say("LISTENING");

    wait_for_shutdown().await;

    // ---- wind-down ---------------------------------------------------------
    //
    // The terminal marker is the only thing that distinguishes a finished
    // ledger from a truncated one. A reader that does not find it reports the
    // log as cut off rather than returning what it happened to find as though
    // that were everything — which is the correct reading of a killed observer
    // and the wrong one for a completed run.
    let observed = recorder.len();
    match recorder.seal_sink() {
        Ok(()) => {
            let lost = recorder.write_failures();
            say(&format!(
                "chamber-boundary: sealed {observed} observation(s)"
            ));
            if lost > 0 {
                // Louder than a warning: the file a third party reads is
                // shorter than the run, and nothing downstream can infer that
                // from the file itself.
                eprintln!(
                    "chamber-boundary: {lost} observation(s) did NOT reach the ledger. \
                     The file on disk is shorter than what was observed, and must not be \
                     read as a complete record of the run."
                );
                return ExitCode::FAILURE;
            }
            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!(
                "chamber-boundary: could not seal the ledger: {e}. It must be read as \
                 truncated, because it is."
            );
            ExitCode::FAILURE
        }
    }
}

/// Waits for the engine's stop signal.
///
/// `docker stop` sends SIGTERM and then SIGKILL after its grace period. The
/// window between them is the only chance to write the terminal marker, so
/// nothing slow belongs after this returns.
async fn wait_for_shutdown() {
    #[cfg(unix)]
    {
        use tokio::signal::unix::{SignalKind, signal};
        let mut term = match signal(SignalKind::terminate()) {
            Ok(s) => s,
            Err(_) => {
                let _ = tokio::signal::ctrl_c().await;
                return;
            }
        };
        tokio::select! {
            _ = term.recv() => {}
            _ = tokio::signal::ctrl_c() => {}
        }
    }
    #[cfg(not(unix))]
    {
        let _ = tokio::signal::ctrl_c().await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_self_test_passes_with_a_working_matcher() {
        assert_eq!(
            self_test().expect("a real matcher must pass its own self-test"),
            4
        );
    }

    /// The self-test earns its place only if it fails when the matcher would
    /// miss. A matcher that catches nothing is exactly the silent break the
    /// startup gate exists to turn into a refusal rather than a false clean.
    #[test]
    fn the_self_test_fails_when_the_matcher_finds_nothing() {
        let blind = CanarySet::new(vec![]);
        assert!(
            run_selftest(&blind, SELFTEST_PROBE).is_err(),
            "a matcher that catches nothing passed the self-test"
        );
    }
}
