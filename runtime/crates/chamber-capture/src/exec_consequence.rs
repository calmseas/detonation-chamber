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
    Rewrite {
        #[serde(default)]
        stdout_find: Option<String>,
        #[serde(default)]
        stdout_replace: Option<String>,
        #[serde(default)]
        stderr_find: Option<String>,
        #[serde(default)]
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
    FabricatePayloadTooLarge { rule_index: usize, len: usize },
    TimeoutZero,
    MaxConcurrentHandlersZero,
}

impl std::fmt::Display for ExecConsequenceConfigError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::SpecNotBase64(e) => write!(f, "{EXEC_SPEC_B64_VAR} is not valid base64: {e}"),
            Self::SpecNotJson(e) => write!(f, "{EXEC_SPEC_B64_VAR} decoded but is not valid JSON: {e}"),
            Self::EmptyRuleName(i) => write!(f, "rule {i} has an empty name"),
            Self::EmptyMatchArgv(i) => write!(f, "rule {i}'s match_argv matches everything (empty)"),
            Self::EmptyReplacementArgv(i) => write!(f, "rule {i}'s substitute.replacement_argv is empty"),
            Self::FabricatePayloadTooLarge { rule_index, len } => write!(
                f,
                "rule {rule_index}'s fabricate stdout+stderr is {len} bytes, exceeds the 4000-byte guest scratch budget"
            ),
            Self::TimeoutZero => write!(f, "timeout_ms must be nonzero"),
            Self::MaxConcurrentHandlersZero => write!(f, "max_concurrent_handlers must be nonzero"),
        }
    }
}

impl ExecConsequencePlan {
    pub fn from_json(text: &str) -> Result<Self, ExecConsequenceConfigError> {
        let plan: ExecConsequencePlan =
            serde_json::from_str(text).map_err(|e| ExecConsequenceConfigError::SpecNotJson(e.to_string()))?;
        plan.validate()?;
        Ok(plan)
    }

    fn validate(&self) -> Result<(), ExecConsequenceConfigError> {
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
    pub fn from_env_value(spec_b64: Option<&str>) -> Result<Option<Self>, ExecConsequenceConfigError> {
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
