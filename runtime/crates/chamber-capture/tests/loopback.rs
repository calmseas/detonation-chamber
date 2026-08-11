//! The capture layer against a real TLS client, on loopback.
//!
//! Everything else in this crate is unit-level: it proves the logic is right.
//! This proves the thing works — that a client speaking real HTTPS through the
//! proxy has its request decrypted, recorded in full, and refused, and that the
//! origin it was trying to reach is never contacted.
//!
//! No container is involved. That is deliberate: the containment layer decides
//! whether the guest *can* go anywhere else, and this decides whether what
//! comes through the one open door is actually observed. Keeping them separate
//! keeps this suite runnable on any developer machine.

use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use chamber_capture::{Canary, CanarySet, ConsequenceResponse, InterceptingProxy, Recorder};
use chamber_evidence::{CapturedBody, Channel, HitField, ObservationKind};
use hudsucker::Proxy;
use hudsucker::certificate_authority::RcgenAuthority;
use hudsucker::rcgen::{BasicConstraints, CertificateParams, IsCa, Issuer, KeyPair};
use hudsucker::rustls::crypto::aws_lc_rs;
use tokio::net::{TcpListener, TcpStream};

const TOKEN: &str = "AKIAIOSFODNN7EXAMPLE";

/// A per-run certificate authority.
///
/// Generated fresh every time, never persisted. A shared anchor would let one
/// run's certificates be believed in another, and nothing on the host should
/// end up trusting this.
fn per_run_ca() -> (RcgenAuthority, Vec<u8>) {
    let key = KeyPair::generate().expect("key generation");
    let mut params = CertificateParams::new(Vec::<String>::new()).expect("ca params");
    params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);

    let cert = params.self_signed(&key).expect("self-signed ca");
    let der = cert.der().to_vec();

    let issuer = Issuer::from_ca_cert_der(cert.der(), key).expect("issuer from der");
    let authority = RcgenAuthority::new(issuer, 1_000, aws_lc_rs::default_provider());

    (authority, der)
}

/// A stand-in for the destination the artefact wants to reach.
///
/// It counts connections and answers nothing. If the count is ever non-zero,
/// the proxy forwarded something — which would mean the chamber is a relay
/// rather than a wall.
struct Origin {
    addr: SocketAddr,
    connections: Arc<AtomicUsize>,
}

async fn spawn_origin() -> Origin {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .expect("bind origin");
    let addr = listener.local_addr().expect("origin addr");
    let connections = Arc::new(AtomicUsize::new(0));

    let counter = Arc::clone(&connections);
    tokio::spawn(async move {
        while listener.accept().await.is_ok() {
            counter.fetch_add(1, Ordering::SeqCst);
        }
    });

    Origin { addr, connections }
}

/// Start the chamber's proxy on an ephemeral port.
async fn spawn_proxy(
    recorder: Arc<Recorder>,
    consequence: Option<ConsequenceResponse>,
) -> SocketAddr {
    let (ca, ca_der) = per_run_ca();
    CA_DER.with(|slot| *slot.borrow_mut() = Some(ca_der));

    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .expect("bind proxy");
    let addr = listener.local_addr().expect("proxy addr");

    let handler = InterceptingProxy::new(
        recorder,
        CanarySet::new(vec![Canary::new("aws-key", TOKEN)]),
    )
    .with_consequence(consequence);

    let proxy = Proxy::builder()
        .with_listener(listener)
        .with_ca(ca)
        .with_rustls_connector(aws_lc_rs::default_provider())
        .with_http_handler(handler)
        .build()
        .expect("build proxy");

    tokio::spawn(async move {
        let _ = proxy.start().await;
    });

    addr
}

thread_local! {
    static CA_DER: std::cell::RefCell<Option<Vec<u8>>> = const { std::cell::RefCell::new(None) };
}

/// Everything a test needs: a running proxy, a dead-drop origin, and the
/// recorder the proxy writes into.
struct Harness {
    recorder: Arc<Recorder>,
    proxy: SocketAddr,
    origin: Origin,
    ca_der: Vec<u8>,
}

async fn harness() -> Harness {
    harness_with(None).await
}

/// The same harness, with the boundary answering plausibly instead of refusing.
async fn harness_with(consequence: Option<ConsequenceResponse>) -> Harness {
    let _ = aws_lc_rs::default_provider().install_default();
    let recorder = Arc::new(Recorder::new());
    let proxy = spawn_proxy(Arc::clone(&recorder), consequence).await;
    let ca_der = CA_DER
        .with(|slot| slot.borrow_mut().take())
        .expect("ca der");
    let origin = spawn_origin().await;

    Harness {
        recorder,
        proxy,
        origin,
        ca_der,
    }
}

impl Harness {
    /// A client that goes through the proxy and trusts this run's CA.
    fn client(&self) -> reqwest::Client {
        reqwest::Client::builder()
            .proxy(reqwest::Proxy::all(format!("http://{}", self.proxy)).expect("proxy url"))
            .add_root_certificate(
                reqwest::Certificate::from_der(&self.ca_der).expect("trust the run CA"),
            )
            .build()
            .expect("build client")
    }

    /// Addressed by name, not by IP.
    ///
    /// The generated leaf certificate carries a DNS name, so an IP literal
    /// fails verification with `NotValidForName` and the handshake never
    /// completes — which would leave every assertion below passing on a
    /// request that was never made. `localhost` also genuinely resolves to the
    /// origin listener, so "never reached the origin" stays a claim about the
    /// proxy rather than about DNS.
    fn origin_url(&self, path: &str) -> String {
        format!("https://localhost:{}{}", self.origin.addr.port(), path)
    }

    /// The request from *inside* the tunnel.
    ///
    /// Deliberately not "any observation": the outer CONNECT is recorded too,
    /// so a test that merely counts observations passes even when TLS
    /// interception failed and nothing was ever decrypted.
    fn inner_request(&self, method: &str) -> chamber_evidence::Observation {
        self.recorder
            .observations()
            .into_iter()
            .find(|o| {
                matches!(o.kind(), ObservationKind::HttpExchange { method: m, .. } if m == method)
            })
            .unwrap_or_else(|| {
                panic!(
                    "no {method} was observed inside the tunnel — TLS interception \
                     did not happen, so nothing below would be testing what it claims"
                )
            })
    }
}

/// The end-to-end claim: a real HTTPS request is decrypted, its whole body is
/// recovered in plaintext, and it is refused.
#[tokio::test]
async fn an_https_request_is_decrypted_recorded_and_refused() {
    let h = harness().await;

    let response = h
        .client()
        .post(h.origin_url("/ingest"))
        .body(format!("{{\"key\":\"{TOKEN}\"}}"))
        .send()
        .await
        .expect("the proxy must answer rather than hang");

    assert_eq!(response.status(), reqwest::StatusCode::FORBIDDEN);

    let exchange = h.inner_request("POST");

    match exchange.kind() {
        ObservationKind::HttpExchange { target, body, .. } => {
            assert!(target.contains("/ingest"), "target was {target}");
            assert_eq!(
                body,
                &CapturedBody::Whole {
                    bytes: format!("{{\"key\":\"{TOKEN}\"}}").into_bytes()
                },
                "the plaintext body must be recovered through TLS"
            );
        }
        other => panic!("expected an exchange, got {other:?}"),
    }

    assert!(
        exchange.is_witness(),
        "a planted token in the body must support a finding"
    );
    assert_eq!(exchange.channel(), Channel::NetworkEgress);
}

/// The chamber is a wall, not a relay. If this ever fails, refused traffic is
/// still reaching its destination and the tool is worse than useless.
#[tokio::test]
async fn a_refused_request_never_reaches_the_origin() {
    let h = harness().await;

    let _ = h
        .client()
        .post(h.origin_url("/ingest"))
        .body("payload")
        .send()
        .await;

    // Give anything in flight a chance to land before counting.
    tokio::time::sleep(std::time::Duration::from_millis(200)).await;

    // Without this, a zero count could mean the request never got past the
    // handshake rather than that the proxy declined to forward it.
    h.inner_request("POST");

    assert_eq!(
        h.origin.connections.load(Ordering::SeqCst),
        0,
        "the proxy forwarded a refused request to its destination"
    );
}

/// Proves the origin counter is capable of registering a connection at all.
///
/// Without this the previous test passes when the counter is simply broken —
/// a zero that means "nothing was measured" reads exactly like a zero that
/// means "nothing got through".
#[tokio::test]
async fn the_origin_counter_registers_a_direct_connection() {
    let h = harness().await;

    TcpStream::connect(h.origin.addr)
        .await
        .expect("connect directly to the origin");
    tokio::time::sleep(std::time::Duration::from_millis(200)).await;

    assert_eq!(
        h.origin.connections.load(Ordering::SeqCst),
        1,
        "the counter must be able to observe a connection, or the containment \
         assertion is vacuous"
    );
}

/// A token in the URL leaves without a body at all.
#[tokio::test]
async fn a_token_in_the_query_string_is_caught_through_tls() {
    let h = harness().await;

    let _ = h
        .client()
        .get(h.origin_url(&format!("/collect?d={TOKEN}")))
        .send()
        .await;

    let get = h.inner_request("GET");
    assert!(
        get.canary_hits()
            .iter()
            .any(|hit| hit.field == HitField::Target),
        "a token in the query string must be caught: {get:?}"
    );
}

/// THE consequence-mode claim, end to end through real TLS: the client is told
/// its request succeeded, and the origin was still never contacted.
///
/// Both halves matter and neither is sufficient alone. A 200 the client
/// believes is what makes the mode worth having; an origin counter still at
/// zero is what makes it safe. Asserting them in one test is the point — it is
/// the only place that can distinguish "fabricated a plausible answer" from
/// "quietly became a working proxy", and those two look identical from the
/// client's side.
#[tokio::test]
async fn consequence_mode_answers_plausibly_and_still_never_reaches_the_origin() {
    let page = "<!doctype html>\n<title>Starter</title>\n<p>ok</p>\n";
    let h = harness_with(Some(
        ConsequenceResponse::new(200, page).expect("200 is a status code"),
    ))
    .await;

    let response = h
        .client()
        .post(h.origin_url("/starter"))
        .body(format!("{{\"key\":\"{TOKEN}\"}}"))
        .send()
        .await
        .expect("the proxy must answer rather than hang");

    assert_eq!(
        response.status(),
        reqwest::StatusCode::OK,
        "the artefact was still told it had been blocked"
    );
    assert_eq!(
        response.text().await.expect("read the body"),
        page,
        "the body the guest received is not the one the operator configured"
    );

    // Give anything in flight a chance to land before counting.
    tokio::time::sleep(std::time::Duration::from_millis(200)).await;

    // Proves TLS interception actually happened, so the zero below means
    // "declined to forward" and not "the handshake never completed".
    let exchange = h.inner_request("POST");

    assert_eq!(
        h.origin.connections.load(Ordering::SeqCst),
        0,
        "a plausible answer was bought by actually contacting the origin — the \
         boundary became a relay, which is the one thing consequence mode must \
         never do"
    );

    // Realism must not be bought with evidence: the same crossing is recorded,
    // and the token in it is still a witness.
    assert!(
        exchange.is_witness(),
        "the canary stopped supporting a finding once the boundary answered \
         plausibly — consequence mode would be converting real leaks into clean \
         results"
    );
    assert_eq!(exchange.channel(), Channel::NetworkEgress);
    match exchange.kind() {
        ObservationKind::HttpExchange { body, .. } => assert_eq!(
            body,
            &CapturedBody::Whole {
                bytes: format!("{{\"key\":\"{TOKEN}\"}}").into_bytes()
            },
            "the plaintext body must still be recovered in consequence mode"
        ),
        other => panic!("expected an exchange, got {other:?}"),
    }
}

/// Ordinary traffic is recorded and does not detonate. Without this the tool
/// fires on any artefact that uses the network.
#[tokio::test]
async fn clean_traffic_is_recorded_without_a_finding() {
    let h = harness().await;

    let _ = h
        .client()
        .post(h.origin_url("/ingest"))
        .body("column=email&type=text")
        .send()
        .await;

    let post = h.inner_request("POST");
    assert!(
        !post.is_witness(),
        "clean traffic must not produce a witness: {post:?}"
    );
}
