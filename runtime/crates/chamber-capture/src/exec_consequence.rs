//! Command-consequence configuration for the guest cell's exec-interception
//! relay (`execrelayd`), mirroring `consequence::ConsequencePlan`'s
//! conventions at the network boundary: first-match-wins with an explicit
//! fallback (unmatched commands run for real), config travels as a single
//! base64-JSON environment variable (values may contain newlines a naive
//! multi-var scheme would corrupt), and malformed configuration refuses to
//! start rather than silently degrading to an unannounced weaker mode.
//!
//! This type is validated and encoded here, host-side, in Rust. The guest
//! side (`execrelayd`, C) parses the identical JSON independently — there is
//! no shared parser, so the wire format (this module's `Serialize`/
//! `Deserialize` output) is the actual contract between the two, and changes
//! here must be mirrored in `runtime/images/guest-exec-relay/src/config.c`.

use data_encoding::BASE64;
use serde::{Deserialize, Serialize};

pub const EXEC_SPEC_B64_VAR: &str = "CHAMBER_EXEC_CONSEQUENCE_SPEC_B64";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum ArgvMatcher {
    /// `argv[0..n]` equals this, where `n` is the matcher's own length.
    Prefix { argv: Vec<String> },
    /// `argv` equals this exactly, same length and all.
    Exact { argv: Vec<String> },
    /// Only the program name (`argv[0]`) is compared.
    Argv0 { name: String },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum ExecVerb {
    /// Run a different program, reporting nothing that reveals the swap.
    Substitute { replacement_argv: Vec<String> },
    /// Let the real command run; transform its captured output before the
    /// caller ever sees it. Literal substring find/replace in v1 — not
    /// regex, to keep the guest-side C matcher simple and injection-free.
    ///
    /// `skip_serializing_if` on all four fields, not just `default` on
    /// deserialize: the guest-side C parser (`config.c`'s `load_verb`) treats
    /// "key present" (a non-NULL `json_object_get` pointer) as "value
    /// supplied", regardless of whether that value is a JSON string or a JSON
    /// `null` — it never inspects the value's type before handing it to
    /// `json_as_string`, which returns NULL for anything that isn't a string,
    /// which `copy_str` then treats as a hard parse error. Without
    /// `skip_serializing_if`, serde's default behaviour serializes a `None`
    /// as an explicit `"stderr_find":null` rather than omitting the key, so a
    /// rule setting only stdout_find/stdout_replace (the ordinary one-sided
    /// case — see `exec_consequence.rs`'s own
    /// `rewrite_transforms_output_of_a_real_run` test) produced a spec that
    /// made `execrelayd` refuse to start outright. Confirmed live: the guest
    /// container exited immediately with "execrelayd: refusing to start —
    /// CHAMBER_EXEC_CONSEQUENCE_SPEC_B64 is absent, malformed, or invalid".
    Rewrite {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        stdout_find: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        stdout_replace: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        stderr_find: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        stderr_replace: Option<String>,
    },
    /// Run nothing; the caller observes exactly this canned result.
    Fabricate {
        exit_code: i32,
        #[serde(default)]
        stdout: String,
        #[serde(default)]
        stderr: String,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExecConsequenceRule {
    pub name: String,
    pub match_argv: ArgvMatcher,
    pub verb: ExecVerb,
}

fn default_timeout_ms() -> u64 {
    60_000
}
fn default_max_concurrent_handlers() -> u32 {
    32
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExecConsequencePlan {
    /// First-match-wins. Unmatched commands run for real (passthrough).
    #[serde(default)]
    pub rules: Vec<ExecConsequenceRule>,
    #[serde(default = "default_timeout_ms")]
    pub timeout_ms: u64,
    #[serde(default = "default_max_concurrent_handlers")]
    pub max_concurrent_handlers: u32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ExecConsequenceConfigError {
    SpecNotBase64(String),
    SpecNotJson(String),
    /// Index of the rule (0-based) whose `name` is empty.
    EmptyRuleName(usize),
    /// Index of the rule whose match_argv would match everything (empty argv/name).
    EmptyMatchArgv(usize),
    /// Index of the rule whose `Substitute.replacement_argv` is empty.
    EmptyReplacementArgv(usize),
    /// A `Fabricate` rule whose combined stdout+stderr exceeds the guest
    /// relay's fixed scratch-buffer budget (2000 bytes each, 4000 total) —
    /// checked here so an oversized payload is a startup refusal, not a
    /// runtime truncation discovered mid-run.
    FabricatePayloadTooLarge {
        rule_index: usize,
        len: usize,
    },
    /// A `Rewrite` rule with exactly one of a `_find`/`_replace` pair set —
    /// the other half `None`. The guest-side C parser (`config.c`'s
    /// `load_verb`) only turns rewriting on for a given stream when BOTH its
    /// `_find` and `_replace` keys are present (`if (sf && sr) { ... }`); a
    /// lone `_find` with no `_replace` (or vice versa) loads without error
    /// and simply never sets `has_stdout_rewrite`/`has_stderr_rewrite` —
    /// the rule matches, and silently does nothing to that stream. Refused
    /// here so that shape is a loud startup error instead of a rule that
    /// looks configured but is quietly inert. `pair` names which pair
    /// ("stdout" or "stderr").
    AsymmetricRewritePair {
        rule_index: usize,
        pair: &'static str,
    },
    TimeoutZero,
    MaxConcurrentHandlersZero,
}

impl std::fmt::Display for ExecConsequenceConfigError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::SpecNotBase64(e) => write!(f, "{EXEC_SPEC_B64_VAR} is not valid base64: {e}"),
            Self::SpecNotJson(e) => {
                write!(f, "{EXEC_SPEC_B64_VAR} decoded but is not valid JSON: {e}")
            }
            Self::EmptyRuleName(i) => write!(f, "rule {i} has an empty name"),
            Self::EmptyMatchArgv(i) => {
                write!(f, "rule {i}'s match_argv matches everything (empty)")
            }
            Self::EmptyReplacementArgv(i) => {
                write!(f, "rule {i}'s substitute.replacement_argv is empty")
            }
            Self::FabricatePayloadTooLarge { rule_index, len } => write!(
                f,
                "rule {rule_index}'s fabricate stdout+stderr is {len} bytes, exceeds the 4000-byte guest scratch budget"
            ),
            Self::AsymmetricRewritePair { rule_index, pair } => write!(
                f,
                "rule {rule_index}'s rewrite.{pair}_find/{pair}_replace must both be set or both be absent, not just one"
            ),
            Self::TimeoutZero => write!(f, "timeout_ms must be nonzero"),
            Self::MaxConcurrentHandlersZero => write!(f, "max_concurrent_handlers must be nonzero"),
        }
    }
}

impl std::error::Error for ExecConsequenceConfigError {}

impl ExecConsequencePlan {
    pub fn from_json(text: &str) -> Result<Self, ExecConsequenceConfigError> {
        let plan: ExecConsequencePlan = serde_json::from_str(text)
            .map_err(|e| ExecConsequenceConfigError::SpecNotJson(e.to_string()))?;
        plan.validate()?;
        Ok(plan)
    }

    /// Every semantic check on a plan (nonzero timeouts, non-empty rule
    /// names/matchers, symmetric rewrite pairs, fabricate payloads within
    /// the guest scratch budget). `pub` so the production arming path can run
    /// it directly: the real `run_detonation` builds an `ExecConsequencePlan`
    /// in-process and calls `to_env_pairs()` without ever going through
    /// `from_json`/`from_env_value`, so this is the only place those checks
    /// can run before the plan is handed to the guest.
    pub fn validate(&self) -> Result<(), ExecConsequenceConfigError> {
        if self.timeout_ms == 0 {
            return Err(ExecConsequenceConfigError::TimeoutZero);
        }
        if self.max_concurrent_handlers == 0 {
            return Err(ExecConsequenceConfigError::MaxConcurrentHandlersZero);
        }
        for (i, rule) in self.rules.iter().enumerate() {
            if rule.name.is_empty() {
                return Err(ExecConsequenceConfigError::EmptyRuleName(i));
            }
            let empty_match = match &rule.match_argv {
                ArgvMatcher::Prefix { argv } | ArgvMatcher::Exact { argv } => argv.is_empty(),
                ArgvMatcher::Argv0 { name } => name.is_empty(),
            };
            if empty_match {
                return Err(ExecConsequenceConfigError::EmptyMatchArgv(i));
            }
            match &rule.verb {
                ExecVerb::Substitute { replacement_argv } if replacement_argv.is_empty() => {
                    return Err(ExecConsequenceConfigError::EmptyReplacementArgv(i));
                }
                ExecVerb::Rewrite {
                    stdout_find,
                    stdout_replace,
                    stderr_find,
                    stderr_replace,
                } => {
                    if stdout_find.is_some() != stdout_replace.is_some() {
                        return Err(ExecConsequenceConfigError::AsymmetricRewritePair {
                            rule_index: i,
                            pair: "stdout",
                        });
                    }
                    if stderr_find.is_some() != stderr_replace.is_some() {
                        return Err(ExecConsequenceConfigError::AsymmetricRewritePair {
                            rule_index: i,
                            pair: "stderr",
                        });
                    }
                }
                ExecVerb::Fabricate { stdout, stderr, .. } => {
                    let len = stdout.len() + stderr.len();
                    if stdout.len() > 2000 || stderr.len() > 2000 {
                        return Err(ExecConsequenceConfigError::FabricatePayloadTooLarge {
                            rule_index: i,
                            len,
                        });
                    }
                }
                _ => {}
            }
        }
        Ok(())
    }

    /// First rule whose matcher matches `argv`. `None` means passthrough.
    #[must_use]
    pub fn matching_rule(&self, argv: &[String]) -> Option<&ExecConsequenceRule> {
        self.rules.iter().find(|rule| match &rule.match_argv {
            ArgvMatcher::Prefix { argv: prefix } => {
                argv.len() >= prefix.len() && argv[..prefix.len()] == prefix[..]
            }
            ArgvMatcher::Exact { argv: exact } => argv == exact.as_slice(),
            ArgvMatcher::Argv0 { name } => argv.first().is_some_and(|a0| a0 == name),
        })
    }

    /// Pure by construction — process environment is global mutable state,
    /// and under edition 2024 writing it is `unsafe` precisely because
    /// concurrent tests race on it. Mirrors `ConsequencePlan::from_env_value`.
    pub fn from_env_value(
        spec_b64: Option<&str>,
    ) -> Result<Option<Self>, ExecConsequenceConfigError> {
        let Some(spec) = spec_b64 else {
            return Ok(None);
        };
        let bytes = BASE64
            .decode(spec.trim().as_bytes())
            .map_err(|e| ExecConsequenceConfigError::SpecNotBase64(e.to_string()))?;
        let text = String::from_utf8(bytes)
            .map_err(|_| ExecConsequenceConfigError::SpecNotJson("not UTF-8".to_owned()))?;
        Self::from_json(&text).map(Some)
    }

    pub fn from_env() -> Result<Option<Self>, ExecConsequenceConfigError> {
        let spec = std::env::var(EXEC_SPEC_B64_VAR).ok();
        Self::from_env_value(spec.as_deref())
    }

    #[must_use]
    pub fn to_env_pairs(&self) -> Vec<(String, String)> {
        let json = serde_json::to_string(self).expect("ExecConsequencePlan always serializes");
        vec![(EXEC_SPEC_B64_VAR.to_owned(), BASE64.encode(json.as_bytes()))]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unset_env_is_none() {
        assert_eq!(ExecConsequencePlan::from_env_value(None), Ok(None));
    }

    #[test]
    fn empty_rules_plan_round_trips() {
        let plan = ExecConsequencePlan {
            rules: vec![],
            timeout_ms: 60_000,
            max_concurrent_handlers: 32,
        };
        let pairs = plan.to_env_pairs();
        assert_eq!(pairs.len(), 1);
        assert_eq!(pairs[0].0, EXEC_SPEC_B64_VAR);
        let spec = pairs[0].1.clone();
        let round_tripped = ExecConsequencePlan::from_env_value(Some(&spec))
            .unwrap()
            .unwrap();
        assert_eq!(round_tripped, plan);
    }

    #[test]
    fn first_matching_rule_wins() {
        let plan = ExecConsequencePlan {
            rules: vec![
                ExecConsequenceRule {
                    name: "narrow".to_owned(),
                    match_argv: ArgvMatcher::Exact {
                        argv: vec!["pip".to_owned(), "install".to_owned(), "x".to_owned()],
                    },
                    verb: ExecVerb::Fabricate {
                        exit_code: 0,
                        stdout: "narrow matched".to_owned(),
                        stderr: String::new(),
                    },
                },
                ExecConsequenceRule {
                    name: "broad".to_owned(),
                    match_argv: ArgvMatcher::Argv0 {
                        name: "pip".to_owned(),
                    },
                    verb: ExecVerb::Fabricate {
                        exit_code: 0,
                        stdout: "broad matched".to_owned(),
                        stderr: String::new(),
                    },
                },
            ],
            timeout_ms: 60_000,
            max_concurrent_handlers: 32,
        };
        let argv = vec!["pip".to_owned(), "install".to_owned(), "x".to_owned()];
        let matched = plan.matching_rule(&argv).unwrap();
        assert_eq!(matched.name, "narrow");
    }

    #[test]
    fn no_match_returns_none() {
        let plan = ExecConsequencePlan {
            rules: vec![ExecConsequenceRule {
                name: "only".to_owned(),
                match_argv: ArgvMatcher::Argv0 {
                    name: "pip".to_owned(),
                },
                verb: ExecVerb::Fabricate {
                    exit_code: 0,
                    stdout: String::new(),
                    stderr: String::new(),
                },
            }],
            timeout_ms: 60_000,
            max_concurrent_handlers: 32,
        };
        assert!(plan.matching_rule(&["curl".to_owned()]).is_none());
    }

    #[test]
    fn defaults_apply_when_absent_from_json() {
        let json = r#"{"rules":[]}"#;
        let plan = ExecConsequencePlan::from_json(json).unwrap();
        assert_eq!(plan.timeout_ms, 60_000);
        assert_eq!(plan.max_concurrent_handlers, 32);
    }

    #[test]
    fn bad_base64_refuses() {
        let err = ExecConsequencePlan::from_env_value(Some("not-base64!!!")).unwrap_err();
        assert!(matches!(err, ExecConsequenceConfigError::SpecNotBase64(_)));
    }

    #[test]
    fn bad_json_refuses() {
        let spec = data_encoding::BASE64.encode(b"not json");
        let err = ExecConsequencePlan::from_env_value(Some(&spec)).unwrap_err();
        assert!(matches!(err, ExecConsequenceConfigError::SpecNotJson(_)));
    }

    #[test]
    fn empty_rule_name_refuses() {
        let json = r#"{"rules":[{"name":"","match_argv":{"type":"argv0","name":"pip"},"verb":{"type":"fabricate","exit_code":0,"stdout":"","stderr":""}}]}"#;
        let err = ExecConsequencePlan::from_json(json).unwrap_err();
        assert!(matches!(err, ExecConsequenceConfigError::EmptyRuleName(0)));
    }

    #[test]
    fn substitute_verb_round_trips_through_json() {
        let plan = ExecConsequencePlan {
            rules: vec![ExecConsequenceRule {
                name: "sub".to_owned(),
                match_argv: ArgvMatcher::Prefix {
                    argv: vec!["pip".to_owned(), "install".to_owned()],
                },
                verb: ExecVerb::Substitute {
                    replacement_argv: vec!["/opt/pkg/fake-pip".to_owned()],
                },
            }],
            timeout_ms: 5_000,
            max_concurrent_handlers: 4,
        };
        let json = serde_json::to_string(&plan).unwrap();
        let back: ExecConsequencePlan = serde_json::from_str(&json).unwrap();
        assert_eq!(back, plan);
    }

    #[test]
    fn one_sided_rewrite_omits_the_unset_pair_from_the_wire_json() {
        // Regression test for a real bug found via chamber-e2e's live-container
        // suite (Task 11): the guest-side C parser (config.c's load_verb)
        // treats a JSON key's mere PRESENCE as "value supplied", even when
        // that value is a JSON `null` — it never checks the value's type
        // before extracting a string from it. Serializing an unset
        // Option<String> as `"stderr_find":null` (serde's default behaviour
        // without skip_serializing_if) made execrelayd refuse to start for
        // any one-sided rewrite rule — which is the ordinary case; a caller
        // wanting only stdout rewritten has no reason to also set stderr
        // fields. The fix is `skip_serializing_if` on all four Rewrite
        // fields, asserted here directly on the wire text rather than through
        // a round trip: round-tripping alone can't catch this, because
        // deserializing `null` back into `None` via `#[serde(default)]`
        // hides the very shape that broke the C side.
        let plan = ExecConsequencePlan {
            rules: vec![ExecConsequenceRule {
                name: "rw".to_owned(),
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
        let json = serde_json::to_string(&plan).unwrap();
        assert!(
            !json.contains("stderr_find"),
            "stderr_find should be omitted, not nulled: {json}"
        );
        assert!(
            !json.contains("stderr_replace"),
            "stderr_replace should be omitted, not nulled: {json}"
        );
        assert!(json.contains("\"stdout_find\":\"secret\""));

        // Still round-trips cleanly: absence on the wire deserializes back to
        // None via #[serde(default)], same as an explicit null used to.
        let back: ExecConsequencePlan = serde_json::from_str(&json).unwrap();
        assert_eq!(back, plan);
    }

    #[test]
    fn asymmetric_stdout_rewrite_pair_refuses() {
        // Regression test for a gap the skip_serializing_if fix above
        // (see one_sided_rewrite_omits_the_unset_pair_from_the_wire_json)
        // opened: that fix closes the SYMMETRIC case (a whole side entirely
        // absent, e.g. both stderr fields None), but a genuinely-invalid
        // ASYMMETRIC pair — stdout_find set with stdout_replace left None —
        // now serializes with stdout_replace simply omitted rather than
        // nulled. Before the fix this shape also happened to make
        // execrelayd refuse to start (loud, if for the wrong reason: the
        // parser choked on ANY unpaired null, not specifically on this
        // invalid pairing). After the fix, config.c's load_verb sees
        // stdout_find present but stdout_replace absent, `if (sf && sr)` is
        // false, has_stdout_rewrite stays 0 — the rule loads fine, matches,
        // and silently does nothing to stdout. No error anywhere on the
        // guest side. This test constructs exactly that shape and drives it
        // through the real entry point (to_env_pairs -> from_env_value, the
        // same path start_cell() uses in chamber-e2e) to assert the plan is
        // refused at the host with a specific, diagnosable error — not just
        // that the wire text looks a certain way.
        let plan = ExecConsequencePlan {
            rules: vec![ExecConsequenceRule {
                name: "half".to_owned(),
                match_argv: ArgvMatcher::Argv0 {
                    name: "/bin/echo".to_owned(),
                },
                verb: ExecVerb::Rewrite {
                    stdout_find: Some("secret".to_owned()),
                    stdout_replace: None,
                    stderr_find: None,
                    stderr_replace: None,
                },
            }],
            timeout_ms: 60_000,
            max_concurrent_handlers: 32,
        };
        let spec = plan.to_env_pairs().remove(0).1;
        let err = ExecConsequencePlan::from_env_value(Some(&spec)).unwrap_err();
        assert_eq!(
            err,
            ExecConsequenceConfigError::AsymmetricRewritePair {
                rule_index: 0,
                pair: "stdout"
            }
        );
    }

    #[test]
    fn asymmetric_stderr_rewrite_pair_refuses() {
        // Same shape as asymmetric_stdout_rewrite_pair_refuses, but for the
        // stderr pair and with the stdout pair fully absent (both None) —
        // exercising the second, independent half of the validation check
        // and confirming a fully-unset stdout pair does not itself trip it.
        let plan = ExecConsequencePlan {
            rules: vec![ExecConsequenceRule {
                name: "half".to_owned(),
                match_argv: ArgvMatcher::Argv0 {
                    name: "/bin/echo".to_owned(),
                },
                verb: ExecVerb::Rewrite {
                    stdout_find: None,
                    stdout_replace: None,
                    stderr_find: None,
                    stderr_replace: Some("REDACTED".to_owned()),
                },
            }],
            timeout_ms: 60_000,
            max_concurrent_handlers: 32,
        };
        let spec = plan.to_env_pairs().remove(0).1;
        let err = ExecConsequencePlan::from_env_value(Some(&spec)).unwrap_err();
        assert_eq!(
            err,
            ExecConsequenceConfigError::AsymmetricRewritePair {
                rule_index: 0,
                pair: "stderr"
            }
        );
    }

    #[test]
    fn no_line_breaks_in_encoded_spec() {
        let plan = ExecConsequencePlan {
            rules: vec![ExecConsequenceRule {
                name: "multiline-payload".to_owned(),
                match_argv: ArgvMatcher::Argv0 {
                    name: "echo".to_owned(),
                },
                verb: ExecVerb::Fabricate {
                    exit_code: 0,
                    stdout: "line one\nline two\n".to_owned(),
                    stderr: String::new(),
                },
            }],
            timeout_ms: 60_000,
            max_concurrent_handlers: 32,
        };
        let pairs = plan.to_env_pairs();
        assert!(!pairs[0].1.contains('\n'));
    }
}
