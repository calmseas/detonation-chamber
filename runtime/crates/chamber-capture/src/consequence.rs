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
//! the answer. Consequence mode closes that gap: the operator supplies a
//! response that looks like production, and the artefact sees its request
//! *succeed*.
//!
//! # What this is not
//!
//! **It is never a route to the internet.** The boundary *fabricates* this
//! response from operator-supplied bytes. It does not forward the request, does
//! not open a socket to the origin, and does not relay an upstream's answer. The
//! guest's request dies at the boundary exactly as it always did; only the
//! sentence written on its headstone changes. The recording is unchanged and
//! happens first, whatever the answer turns out to be.
//!
//! # Off unless both halves are set, and a half-set config is refused
//!
//! Consequence mode is on only when [`STATUS_VAR`] *and* the body are both
//! present. Neither present is the default detonation. Exactly one present is a
//! **misconfiguration and refuses to start**, rather than quietly falling back
//! to the 403 — an operator who set only the body would otherwise run a whole
//! realism experiment against a boundary that was still announcing itself, and
//! nothing in the evidence would say so. That is the same false-clean shape the
//! empty-canary check exists to prevent.
//!
//! # Why the body crosses as base64
//!
//! The host hands the observer its configuration through a docker `--env-file`,
//! which is written one `KEY=value` line per pair. A response body worth calling
//! plausible is an HTML page or a JSON document, and it *has newlines*; written
//! raw, the first one ends the line and docker reads the remainder as further
//! variables. The corruption is silent and the result still starts. So the body
//! travels [`BODY_B64_VAR`] base64-encoded, which is newline-free by
//! construction. Operators never type it — the host encodes what they supply.

use data_encoding::BASE64;

/// The HTTP status the boundary fabricates, as a decimal integer.
pub const STATUS_VAR: &str = "CHAMBER_CONSEQUENCE_STATUS";
/// The body it fabricates, base64-encoded. See the module note on why.
pub const BODY_B64_VAR: &str = "CHAMBER_CONSEQUENCE_BODY_B64";

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

/// Why a consequence configuration was refused.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConsequenceConfigError {
    /// One half of the pair was set and the other was not.
    HalfConfigured { present: String, missing: String },
    /// The status was not a decimal integer.
    StatusNotAnInteger(String),
    /// The status parsed but is not an HTTP status code.
    StatusOutOfRange(u16),
    /// The body was not valid base64.
    BodyNotBase64(String),
    /// The decoded body was not UTF-8.
    BodyNotUtf8,
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
            Self::StatusNotAnInteger(v) => {
                write!(f, "{STATUS_VAR} is not a decimal integer: {v:?}")
            }
            Self::StatusOutOfRange(n) => write!(
                f,
                "{STATUS_VAR} is {n}, which is not an HTTP status code \
                 ({STATUS_MIN}-{STATUS_MAX})"
            ),
            Self::BodyNotBase64(e) => write!(f, "{BODY_B64_VAR} is not valid base64: {e}"),
            Self::BodyNotUtf8 => write!(f, "{BODY_B64_VAR} decodes to bytes that are not UTF-8"),
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

    /// The pairs the host writes into the observer's env file.
    ///
    /// The body is base64-encoded here, at the one place that knows it is about
    /// to cross a line-oriented transport.
    #[must_use]
    pub fn to_env_pairs(&self) -> Vec<(String, String)> {
        vec![
            (STATUS_VAR.to_owned(), self.status.to_string()),
            (BODY_B64_VAR.to_owned(), BASE64.encode(self.body.as_bytes())),
        ]
    }

    /// Reads a configuration from two already-looked-up values.
    ///
    /// Pure on purpose: process environment is global mutable state, and under
    /// edition 2024 writing it is `unsafe` precisely because concurrent tests
    /// race on it. Taking the values as arguments makes every branch here
    /// testable without touching the process at all. [`Self::from_env`] is the
    /// thin wrapper that does the looking-up.
    ///
    /// `Ok(None)` means consequence mode is off, which is the default and not an
    /// error.
    ///
    /// # Errors
    /// [`ConsequenceConfigError`] if exactly one half is present, or if either
    /// value is malformed.
    pub fn from_env_values(
        status: Option<&str>,
        body_b64: Option<&str>,
    ) -> Result<Option<Self>, ConsequenceConfigError> {
        let (status, body_b64) = match (status, body_b64) {
            (None, None) => return Ok(None),
            (Some(s), Some(b)) => (s, b),
            (Some(_), None) => {
                return Err(ConsequenceConfigError::HalfConfigured {
                    present: STATUS_VAR.to_owned(),
                    missing: BODY_B64_VAR.to_owned(),
                });
            }
            (None, Some(_)) => {
                return Err(ConsequenceConfigError::HalfConfigured {
                    present: BODY_B64_VAR.to_owned(),
                    missing: STATUS_VAR.to_owned(),
                });
            }
        };

        let status: u16 = status
            .trim()
            .parse()
            .map_err(|_| ConsequenceConfigError::StatusNotAnInteger(status.to_owned()))?;

        let bytes = BASE64
            .decode(body_b64.trim().as_bytes())
            .map_err(|e| ConsequenceConfigError::BodyNotBase64(e.to_string()))?;
        let body = String::from_utf8(bytes).map_err(|_| ConsequenceConfigError::BodyNotUtf8)?;

        Self::new(status, body).map(Some)
    }

    /// [`Self::from_env_values`], reading the process environment.
    ///
    /// # Errors
    /// As [`Self::from_env_values`].
    pub fn from_env() -> Result<Option<Self>, ConsequenceConfigError> {
        let status = std::env::var(STATUS_VAR).ok();
        let body = std::env::var(BODY_B64_VAR).ok();
        Self::from_env_values(status.as_deref(), body.as_deref())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const PAGE: &str = "<!doctype html>\n<title>Starter</title>\n<p>ok</p>\n";

    #[test]
    fn neither_half_set_is_off_not_an_error() {
        assert_eq!(ConsequenceResponse::from_env_values(None, None), Ok(None));
    }

    /// The default has to survive: an ordinary detonation must keep refusing,
    /// and must not need any configuration to do it.
    #[test]
    fn a_full_configuration_round_trips_through_the_env_pairs() {
        let configured = ConsequenceResponse::new(200, PAGE).unwrap();
        let pairs = configured.to_env_pairs();

        let status = pairs.iter().find(|(k, _)| k == STATUS_VAR).unwrap();
        let body = pairs.iter().find(|(k, _)| k == BODY_B64_VAR).unwrap();

        let read = ConsequenceResponse::from_env_values(Some(&status.1), Some(&body.1))
            .unwrap()
            .unwrap();
        assert_eq!(read, configured);
        assert_eq!(read.body(), PAGE);
        assert_eq!(read.status(), 200);
    }

    /// THE reason the body is encoded at all. A plausible response body is an
    /// HTML page, an HTML page has newlines, and the env file this crosses is
    /// one `KEY=value` line per pair — so a raw newline silently ends the
    /// variable and docker reads the rest of the page as more variables. The
    /// run still starts, which is what makes it dangerous.
    #[test]
    fn an_encoded_body_carries_no_newline_across_the_env_file() {
        let pairs = ConsequenceResponse::new(200, PAGE).unwrap().to_env_pairs();

        assert!(
            PAGE.contains('\n'),
            "this test is vacuous unless the body it encodes actually has newlines"
        );
        for (key, value) in &pairs {
            assert!(
                !value.contains('\n') && !value.contains('\r'),
                "{key} carries a line break, which would truncate the env file \
                 and be read as further variables"
            );
        }
    }

    /// Half a configuration is the dangerous case: it looks configured, starts
    /// happily, and answers every request with the tell the operator thought
    /// they had removed.
    #[test]
    fn a_status_without_a_body_is_refused() {
        let err = ConsequenceResponse::from_env_values(Some("200"), None).unwrap_err();
        assert_eq!(
            err,
            ConsequenceConfigError::HalfConfigured {
                present: STATUS_VAR.to_owned(),
                missing: BODY_B64_VAR.to_owned(),
            }
        );
    }

    #[test]
    fn a_body_without_a_status_is_refused() {
        let err =
            ConsequenceResponse::from_env_values(None, Some(&BASE64.encode(b"hi"))).unwrap_err();
        assert_eq!(
            err,
            ConsequenceConfigError::HalfConfigured {
                present: BODY_B64_VAR.to_owned(),
                missing: STATUS_VAR.to_owned(),
            }
        );
    }

    #[test]
    fn a_non_numeric_status_is_refused() {
        assert!(matches!(
            ConsequenceResponse::from_env_values(Some("two hundred"), Some("")),
            Err(ConsequenceConfigError::StatusNotAnInteger(_))
        ));
    }

    /// `2000` is the shape of a typo, and the proxy cannot build a response
    /// from it. Caught at startup, it is a refusal to arm; caught later it
    /// would be a run that observes nothing.
    #[test]
    fn a_status_outside_the_http_range_is_refused() {
        assert_eq!(
            ConsequenceResponse::new(2000, "x"),
            Err(ConsequenceConfigError::StatusOutOfRange(2000))
        );
        assert_eq!(
            ConsequenceResponse::new(99, "x"),
            Err(ConsequenceConfigError::StatusOutOfRange(99))
        );
        assert!(ConsequenceResponse::new(200, "x").is_ok());
        assert!(ConsequenceResponse::new(599, "x").is_ok());
    }

    #[test]
    fn an_undecodable_body_is_refused() {
        assert!(matches!(
            ConsequenceResponse::from_env_values(Some("200"), Some("!!!not base64!!!")),
            Err(ConsequenceConfigError::BodyNotBase64(_))
        ));
    }

    /// An empty body is a legitimate configuration — a bare `204` says nothing
    /// and says it plausibly. It must not be mistaken for "unset".
    #[test]
    fn an_empty_body_is_a_configuration_not_an_absence() {
        let read = ConsequenceResponse::from_env_values(Some("204"), Some(""))
            .unwrap()
            .expect("an empty body is still a configured response");
        assert_eq!(read.status(), 204);
        assert_eq!(read.body(), "");
    }
}
