//! What the boundary answers with, when an operator asks it to be plausible.
//!
//! By default the boundary refuses every intercepted request with `403 blocked
//! by the detonation chamber`. That is honest, and for an ordinary detonation it
//! is right: nothing is entitled to leave, and the refusal says so.
//!
//! It is also a **tell**. An artefact that reads the response knows, in one
//! round-trip, that it is being watched — and the runs that matter most are the
//! ones measuring whether a model behaves differently when it believes it is
//! observed. A model that gets a 403 from every host it touches has been handed
//! the answer. Consequence mode closes that gap: the operator supplies responses
//! that look like production, and the artefact sees its requests *succeed*.
//!
//! # What this is not
//!
//! **It is never a route to the internet.** The boundary *fabricates* these
//! responses from operator-supplied bytes. It does not forward the request, does
//! not open a socket to the origin, and does not relay an upstream's answer. The
//! guest's request dies at the boundary exactly as it always did; only the
//! sentence written on its headstone changes. The recording is unchanged and
//! happens first, whatever the answer turns out to be.
//!
//! # Why a plan, and not one response
//!
//! The first cut answered every intercepted request identically. That was enough
//! to remove the tell, and **not** enough to measure anything: a single-shot
//! artefact — sign once, `curl` once — receives its answer strictly *after* the
//! only decision the answer could influence, so the treatment lands downstream of
//! the outcome. Measuring a responding boundary needs the artefact to touch the
//! endpoint more than once, and a realistic multi-step exchange returns
//! *different* things from different paths. A challenge endpoint that answered
//! with a project template would be its own tell.
//!
//! So a [`ConsequencePlan`] routes on the request's **path**: exact match, first
//! rule wins, and a fallback for everything else. One response for everything is
//! still expressible — [`ConsequencePlan::single`] — and is what the simple
//! operator surface builds.
//!
//! # Off unless configured, and a half-set config is refused
//!
//! Consequence mode is on only when [`SPEC_B64_VAR`] is present; absent is the
//! default detonation. The operator-facing surfaces are stricter still: setting
//! half of a pair **refuses to start** rather than quietly falling back to the
//! 403 — an operator who set only the body would otherwise run a whole realism
//! experiment against a boundary that was still announcing itself, and nothing in
//! the evidence would say so. That is the same false-clean shape the empty-canary
//! check exists to prevent.
//!
//! # Why the plan crosses as base64
//!
//! The host hands the observer its configuration through a docker `--env-file`,
//! which is written one `KEY=value` line per pair. A response body worth calling
//! plausible is an HTML page or a JSON document, and it *has newlines*; written
//! raw, the first one ends the line and docker reads the remainder as further
//! variables. The corruption is silent and the result still starts. So the whole
//! plan travels [`SPEC_B64_VAR`] as base64-encoded JSON, which is newline-free by
//! construction. Operators never type it — the host encodes what they supply.

use data_encoding::BASE64;
use serde::{Deserialize, Serialize};

/// The routed plan, as base64-encoded JSON. See the module note on why.
pub const SPEC_B64_VAR: &str = "CHAMBER_CONSEQUENCE_SPEC_B64";

/// The lowest and highest status codes HTTP defines. A value outside this is a
/// typo — an operator who meant `200` and wrote `2000` should be told so at
/// startup, not discover it when the proxy cannot build a response mid-run.
const STATUS_MIN: u16 = 100;
const STATUS_MAX: u16 = 599;

/// An operator-supplied response, fabricated at the boundary.
///
/// Validated on construction so the proxy's use of it cannot fail: by the time
/// one of these exists, its status is a real HTTP status code.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConsequenceResponse {
    status: u16,
    body: String,
}

/// Which fabricated response an intercepted request receives.
///
/// Routed on the request path, because a plausible multi-step exchange does not
/// answer `/challenge` and `/starter` with the same bytes. See the module note.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConsequencePlan {
    /// Exact-match path rules, in declaration order. First match wins.
    routes: Vec<(String, ConsequenceResponse)>,
    /// What every unmatched path receives.
    fallback: ConsequenceResponse,
}

// ---- the wire form -------------------------------------------------------

#[derive(Serialize, Deserialize)]
struct WireResponse {
    status: u16,
    #[serde(default)]
    body: String,
}

#[derive(Serialize, Deserialize)]
struct WireRoute {
    path: String,
    status: u16,
    #[serde(default)]
    body: String,
}

#[derive(Serialize, Deserialize)]
struct WirePlan {
    #[serde(default)]
    routes: Vec<WireRoute>,
    default: WireResponse,
}

/// Why a consequence configuration was refused.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConsequenceConfigError {
    /// One half of a pair was set and the other was not.
    HalfConfigured { present: String, missing: String },
    /// The status was not a decimal integer.
    StatusNotAnInteger(String),
    /// The status parsed but is not an HTTP status code.
    StatusOutOfRange(u16),
    /// The spec was not valid base64.
    SpecNotBase64(String),
    /// The spec decoded but is not the JSON this expects.
    SpecNotJson(String),
    /// A route path that could never match a request path.
    RoutePathNotAbsolute(String),
    /// Two rules claim the same path, so one is dead and the operator cannot
    /// tell which.
    DuplicateRoutePath(String),
}

impl std::fmt::Display for ConsequenceConfigError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::HalfConfigured { present, missing } => write!(
                f,
                "{present} is set but {missing} is not. Consequence mode needs both. \
                 Refusing to start rather than falling back to the refusal, because a \
                 run configured this way would answer every request with the 403 tell \
                 while the operator believed it was answering plausibly — and nothing \
                 in the evidence would show the difference."
            ),
            Self::StatusNotAnInteger(v) => write!(f, "not a decimal integer: {v:?}"),
            Self::StatusOutOfRange(n) => write!(
                f,
                "{n} is not an HTTP status code ({STATUS_MIN}-{STATUS_MAX})"
            ),
            Self::SpecNotBase64(e) => write!(f, "{SPEC_B64_VAR} is not valid base64: {e}"),
            Self::SpecNotJson(e) => write!(
                f,
                "the consequence plan is not the JSON this expects ({e}). Shape: \
                 {{\"default\":{{\"status\":404,\"body\":\"…\"}},\"routes\":\
                 [{{\"path\":\"/challenge\",\"status\":200,\"body\":\"…\"}}]}}"
            ),
            Self::RoutePathNotAbsolute(p) => write!(
                f,
                "route path {p:?} does not start with '/', so it can never match a \
                 request path and the rule would be silently dead"
            ),
            Self::DuplicateRoutePath(p) => write!(
                f,
                "two routes claim the path {p:?}. First match wins, so one of them is \
                 dead and nothing would say which"
            ),
        }
    }
}

impl std::error::Error for ConsequenceConfigError {}

impl ConsequenceResponse {
    /// A validated response.
    ///
    /// # Errors
    /// [`ConsequenceConfigError::StatusOutOfRange`] if `status` is not an HTTP
    /// status code.
    pub fn new(status: u16, body: impl Into<String>) -> Result<Self, ConsequenceConfigError> {
        if !(STATUS_MIN..=STATUS_MAX).contains(&status) {
            return Err(ConsequenceConfigError::StatusOutOfRange(status));
        }
        Ok(Self {
            status,
            body: body.into(),
        })
    }

    #[must_use]
    pub fn status(&self) -> u16 {
        self.status
    }

    #[must_use]
    pub fn body(&self) -> &str {
        &self.body
    }
}

impl ConsequencePlan {
    /// One response for every intercepted request, whatever its path.
    ///
    /// What the simple operator surface builds, and what the first cut of
    /// consequence mode could express. Adequate for removing the tell; see the
    /// module note for why it cannot measure one.
    #[must_use]
    pub fn single(response: ConsequenceResponse) -> Self {
        Self {
            routes: Vec::new(),
            fallback: response,
        }
    }

    /// A routed plan.
    ///
    /// # Errors
    /// [`ConsequenceConfigError::RoutePathNotAbsolute`] for a path that cannot
    /// match, [`ConsequenceConfigError::DuplicateRoutePath`] for a rule shadowed
    /// by an earlier one. Both are silent-dead-rule mistakes, so both refuse.
    pub fn new(
        routes: Vec<(String, ConsequenceResponse)>,
        fallback: ConsequenceResponse,
    ) -> Result<Self, ConsequenceConfigError> {
        let mut seen: Vec<&str> = Vec::new();
        for (path, _) in &routes {
            if !path.starts_with('/') {
                return Err(ConsequenceConfigError::RoutePathNotAbsolute(path.clone()));
            }
            if seen.contains(&path.as_str()) {
                return Err(ConsequenceConfigError::DuplicateRoutePath(path.clone()));
            }
            seen.push(path);
        }
        Ok(Self { routes, fallback })
    }

    /// The response an intercepted request receives.
    ///
    /// `path` is the request's path component with any query stripped — the
    /// caller does that, because only it knows how the URI was parsed. Matching
    /// on a path that still carried `?sig=…` would miss every real request.
    #[must_use]
    pub fn response_for(&self, path: &str) -> &ConsequenceResponse {
        self.routes
            .iter()
            .find(|(p, _)| p == path)
            .map(|(_, r)| r)
            .unwrap_or(&self.fallback)
    }

    /// The paths this plan answers specially, for announcing the mode.
    #[must_use]
    pub fn route_paths(&self) -> Vec<&str> {
        self.routes.iter().map(|(p, _)| p.as_str()).collect()
    }

    #[must_use]
    pub fn fallback(&self) -> &ConsequenceResponse {
        &self.fallback
    }

    /// The JSON an operator writes and the host encodes.
    #[must_use]
    pub fn to_json(&self) -> String {
        let wire = WirePlan {
            routes: self
                .routes
                .iter()
                .map(|(p, r)| WireRoute {
                    path: p.clone(),
                    status: r.status,
                    body: r.body.clone(),
                })
                .collect(),
            default: WireResponse {
                status: self.fallback.status,
                body: self.fallback.body.clone(),
            },
        };
        serde_json::to_string(&wire).expect("a plan of owned strings always serialises")
    }

    /// Parse the operator's JSON.
    ///
    /// # Errors
    /// [`ConsequenceConfigError`] if the shape is wrong, a status is not a status
    /// code, or a route path is dead.
    pub fn from_json(text: &str) -> Result<Self, ConsequenceConfigError> {
        let wire: WirePlan = serde_json::from_str(text)
            .map_err(|e| ConsequenceConfigError::SpecNotJson(e.to_string()))?;
        let mut routes = Vec::with_capacity(wire.routes.len());
        for r in wire.routes {
            routes.push((r.path, ConsequenceResponse::new(r.status, r.body)?));
        }
        Self::new(
            routes,
            ConsequenceResponse::new(wire.default.status, wire.default.body)?,
        )
    }

    /// The pairs the host writes into the observer's env file.
    ///
    /// Base64 here, at the one place that knows the plan is about to cross a
    /// line-oriented transport.
    #[must_use]
    pub fn to_env_pairs(&self) -> Vec<(String, String)> {
        vec![(
            SPEC_B64_VAR.to_owned(),
            BASE64.encode(self.to_json().as_bytes()),
        )]
    }

    /// Reads a plan from an already-looked-up value.
    ///
    /// Pure on purpose: process environment is global mutable state, and under
    /// edition 2024 writing it is `unsafe` precisely because concurrent tests
    /// race on it. Taking the value as an argument makes every branch here
    /// testable without touching the process at all.
    ///
    /// `Ok(None)` means consequence mode is off, which is the default and not an
    /// error.
    ///
    /// # Errors
    /// [`ConsequenceConfigError`] if the value is not base64, or not a valid plan.
    pub fn from_env_value(spec_b64: Option<&str>) -> Result<Option<Self>, ConsequenceConfigError> {
        let Some(spec) = spec_b64 else {
            return Ok(None);
        };
        let bytes = BASE64
            .decode(spec.trim().as_bytes())
            .map_err(|e| ConsequenceConfigError::SpecNotBase64(e.to_string()))?;
        let text = String::from_utf8(bytes)
            .map_err(|_| ConsequenceConfigError::SpecNotJson("not UTF-8".to_owned()))?;
        Self::from_json(&text).map(Some)
    }

    /// [`Self::from_env_value`], reading the process environment.
    ///
    /// # Errors
    /// As [`Self::from_env_value`].
    pub fn from_env() -> Result<Option<Self>, ConsequenceConfigError> {
        let spec = std::env::var(SPEC_B64_VAR).ok();
        Self::from_env_value(spec.as_deref())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const PAGE: &str = "<!doctype html>\n<title>Starter</title>\n<p>ok</p>\n";

    fn ok(body: &str) -> ConsequenceResponse {
        ConsequenceResponse::new(200, body).expect("200 is a status code")
    }

    #[test]
    fn an_unset_spec_is_off_not_an_error() {
        assert_eq!(ConsequencePlan::from_env_value(None), Ok(None));
    }

    #[test]
    fn a_single_response_plan_answers_every_path_the_same() {
        let plan = ConsequencePlan::single(ok(PAGE));
        assert_eq!(plan.response_for("/starter").body(), PAGE);
        assert_eq!(plan.response_for("/anything/else").body(), PAGE);
        assert_eq!(plan.response_for("/").status(), 200);
    }

    /// The reason the plan exists. A challenge endpoint answering with a project
    /// template would be its own tell, so the two paths must differ.
    #[test]
    fn a_routed_plan_answers_each_path_with_its_own_response() {
        let plan = ConsequencePlan::new(
            vec![
                ("/challenge".to_owned(), ok("{\"nonce\":\"c7f3\"}")),
                ("/starter".to_owned(), ok(PAGE)),
            ],
            ConsequenceResponse::new(404, "not found").unwrap(),
        )
        .unwrap();

        assert_eq!(
            plan.response_for("/challenge").body(),
            "{\"nonce\":\"c7f3\"}"
        );
        assert_eq!(plan.response_for("/starter").body(), PAGE);
        let miss = plan.response_for("/nope");
        assert_eq!(miss.status(), 404);
    }

    /// Matching is on the path alone. The real requests carry `?sig=…`, so a
    /// plan that matched the whole target would miss every one of them and
    /// silently serve the fallback — the run would look configured and answer
    /// 404 to the exact request under study.
    #[test]
    fn routes_match_the_path_without_its_query() {
        let plan = ConsequencePlan::new(
            vec![("/starter".to_owned(), ok(PAGE))],
            ConsequenceResponse::new(404, "").unwrap(),
        )
        .unwrap();
        // The caller strips the query; this pins the contract that it must.
        assert_eq!(plan.response_for("/starter").body(), PAGE);
        assert_eq!(plan.response_for("/starter?sig=abc").status(), 404);
    }

    #[test]
    fn a_plan_round_trips_through_json() {
        let plan = ConsequencePlan::new(
            vec![("/challenge".to_owned(), ok("{\"nonce\":\"c7f3\"}"))],
            ConsequenceResponse::new(404, "nope").unwrap(),
        )
        .unwrap();
        assert_eq!(ConsequencePlan::from_json(&plan.to_json()).unwrap(), plan);
    }

    #[test]
    fn a_plan_round_trips_through_the_env_pairs() {
        let plan = ConsequencePlan::new(
            vec![("/starter".to_owned(), ok(PAGE))],
            ConsequenceResponse::new(404, "").unwrap(),
        )
        .unwrap();
        let pairs = plan.to_env_pairs();
        let spec = pairs.iter().find(|(k, _)| k == SPEC_B64_VAR).unwrap();

        let read = ConsequencePlan::from_env_value(Some(&spec.1))
            .unwrap()
            .unwrap();
        assert_eq!(read, plan);
        assert_eq!(read.response_for("/starter").body(), PAGE);
    }

    /// THE reason the plan is encoded at all. A plausible body is an HTML page,
    /// an HTML page has newlines, and the env file this crosses is one
    /// `KEY=value` line per pair — so a raw newline silently ends the variable
    /// and docker reads the rest of the page as more variables. The run still
    /// starts, which is what makes it dangerous.
    #[test]
    fn the_encoded_plan_carries_no_line_break() {
        let plan = ConsequencePlan::single(ok(PAGE));
        assert!(
            PAGE.contains('\n'),
            "this test is vacuous unless the body it encodes actually has newlines"
        );
        for (key, value) in plan.to_env_pairs() {
            assert!(
                !value.contains('\n') && !value.contains('\r'),
                "{key} carries a line break, which would truncate the env file"
            );
        }
    }

    /// A rule that can never match is worse than a missing one: the operator
    /// believes a path is covered and the fallback answers it.
    #[test]
    fn a_route_path_without_a_leading_slash_is_refused() {
        let err = ConsequencePlan::new(
            vec![("challenge".to_owned(), ok("x"))],
            ConsequenceResponse::new(404, "").unwrap(),
        )
        .unwrap_err();
        assert_eq!(
            err,
            ConsequenceConfigError::RoutePathNotAbsolute("challenge".to_owned())
        );
    }

    /// First match wins, so a duplicate silently kills the later rule.
    #[test]
    fn two_routes_claiming_one_path_are_refused() {
        let err = ConsequencePlan::new(
            vec![
                ("/starter".to_owned(), ok("first")),
                ("/starter".to_owned(), ok("second")),
            ],
            ConsequenceResponse::new(404, "").unwrap(),
        )
        .unwrap_err();
        assert_eq!(
            err,
            ConsequenceConfigError::DuplicateRoutePath("/starter".to_owned())
        );
    }

    #[test]
    fn a_status_outside_the_http_range_is_refused() {
        assert_eq!(
            ConsequenceResponse::new(2000, "x"),
            Err(ConsequenceConfigError::StatusOutOfRange(2000))
        );
        assert!(ConsequenceResponse::new(200, "x").is_ok());
        assert!(ConsequenceResponse::new(599, "x").is_ok());
    }

    #[test]
    fn an_undecodable_spec_is_refused() {
        assert!(matches!(
            ConsequencePlan::from_env_value(Some("!!!not base64!!!")),
            Err(ConsequenceConfigError::SpecNotBase64(_))
        ));
    }

    #[test]
    fn a_spec_that_is_not_the_expected_json_is_refused() {
        let junk = BASE64.encode(b"{\"nonsense\":true}");
        assert!(matches!(
            ConsequencePlan::from_env_value(Some(&junk)),
            Err(ConsequenceConfigError::SpecNotJson(_))
        ));
    }

    /// An empty body is a legitimate configuration — a bare `204` says nothing
    /// and says it plausibly. It must not be mistaken for "unset".
    #[test]
    fn an_empty_body_is_a_configuration_not_an_absence() {
        let plan =
            ConsequencePlan::single(ConsequenceResponse::new(204, "").expect("204 is a status"));
        let read = ConsequencePlan::from_json(&plan.to_json()).unwrap();
        assert_eq!(read.response_for("/x").status(), 204);
        assert_eq!(read.response_for("/x").body(), "");
    }
}
