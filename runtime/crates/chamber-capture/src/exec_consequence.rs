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

/// The guest parser's size limits, mirrored.
///
/// Every one of these is a value `runtime/images/guest-exec-relay/src/config.h`
/// (and, for `MAX_ARGV`, `protocol.h`) declares, and every one is enforced by
/// `config.c` when `execrelayd` loads the spec. They are restated here so
/// [`ExecConsequencePlan::validate`] can refuse the same plans the guest would
/// — and `guest_limits_match_the_c_header` re-reads those headers and fails if
/// the two ever drift apart, because a limit that exists on only one side is
/// exactly the defect this module had: the host checked fabricate payloads with
/// a strict `>` against 2000 while `config.c` rejected at `>=`, so a 2000-byte
/// payload was host-valid and then made the cell refuse to start with an error
/// the host never anticipated — and the other five limits were not checked here
/// at all.
///
/// **Boundary conventions differ per limit, deliberately, and are the whole
/// point of restating them**: the count limits are inclusive (a plan with
/// exactly [`guest_limits::MAX_RULES`] rules loads), the string-length limits
/// are inclusive (`config.c`'s `copy_str` needs room for the NUL, so
/// `EXEC_RELAY_MAX_RULE_NAME` is the longest name that fits), and the fabricate
/// budget is EXCLUSIVE — `config.c` rejects a payload of exactly
/// [`guest_limits::MAX_FABRICATE_BYTES`].
pub mod guest_limits {
    /// `EXEC_RELAY_MAX_RULES` — most rules in one plan. Inclusive.
    pub const MAX_RULES: usize = 64;
    /// `EXEC_RELAY_MAX_ARGV` (protocol.h) — most elements in a matcher's or a
    /// substitute's argv. Inclusive.
    pub const MAX_ARGV: usize = 32;
    /// `EXEC_RELAY_MAX_RULE_NAME` — longest rule name in bytes. Inclusive.
    pub const MAX_RULE_NAME: usize = 127;
    /// `EXEC_RELAY_MAX_ARGV_ELEM` — longest single argv element in bytes,
    /// matcher or replacement. Inclusive.
    pub const MAX_ARGV_ELEM: usize = 255;
    /// `EXEC_RELAY_MAX_REWRITE_STR` — longest find/replace string in bytes.
    /// Inclusive.
    pub const MAX_REWRITE_STR: usize = 511;
    /// `EXEC_RELAY_MAX_FABRICATE_BYTES` — fabricate stdout/stderr budget.
    /// EXCLUSIVE: `config.c` rejects a payload of exactly this length.
    pub const MAX_FABRICATE_BYTES: usize = 2000;
    /// `EXEC_RELAY_MAX_SPEC_B64` — longest base64 spec VALUE the guest can be
    /// handed at all, counting the whole encoded document rather than any one
    /// field. Inclusive.
    ///
    /// Every other limit here bounds a single value, and a plan can satisfy all
    /// of them and still be undeliverable: `MAX_RULES` rules, each with two
    /// `MAX_ARGV`-element argvs of `MAX_ARGV_ELEM` bytes and two
    /// `MAX_FABRICATE_BYTES` payloads, is roughly a megabyte of JSON — 1.4 MB
    /// once base64'd, and every per-field check passes.
    ///
    /// The guest-side ceiling is NOT a buffer (the decode mallocs and the JSON
    /// parser allocates as it goes) — it is a chain of transport hops, and this
    /// number is the tightest one we can actually name from this codebase. The
    /// value does not reach the guest via a host-performed `execve`: it flows
    /// `to_env_pairs()` → `seal_cell_environment` → `SealedEnv::to_env_file`
    /// (a 0600 `--env-file`, never `-e KEY=VALUE`, so it never sits in the host
    /// process table) → `ContainerSpec.env_file` → `docker create --env-file
    /// <path>` → the docker daemon → containerd → runc's `execve` of the guest
    /// entrypoint with that envp. The kernel's `MAX_ARG_STRLEN` = `32 *
    /// PAGE_SIZE` ceiling on that final `execve` is real — at the smallest page
    /// size in use that is 131072 bytes including the NUL, less the 34
    /// characters of `CHAMBER_EXEC_CONSEQUENCE_SPEC_B64=`, rounded down to a
    /// multiple of 4 because padded base64 has no other length — but it is the
    /// LAST of several hops, not the only one: the docker CLI's own
    /// `--env-file` line parser is a plausible tighter ceiling that would fail
    /// first (unverified in this codebase, but worth naming as the more likely
    /// actual failure point). Whichever hop actually refuses it, the failure
    /// DOES surface as a real, typed error — `EngineError::Failed { stderr,
    /// .. }`, via `must_run` — not silently. The value of checking here is
    /// catching it EARLY, before ever attempting the container operation, with
    /// a clear host-side refusal (`ArmingRefusal`/`SpecTooLarge`) that names
    /// the total instead of a docker or containerd error message about a line
    /// it could not parse. This number is chosen as a bound that fails closed:
    /// it is tighter than the kernel's own ceiling, and even though the exact
    /// tightest real ceiling among the several hops is not independently
    /// verified in this codebase, erring on the tighter side is safe. Restated
    /// in `config.h` (and enforced by `config_load_from_env`) so the two
    /// parsers agree on a stated number rather than on a hop-chain behaviour
    /// only one of them can observe.
    pub const MAX_SPEC_B64: usize = 131_036;
    /// Largest `timeout_ms` the guest carries FAITHFULLY — 2^53.
    ///
    /// Not a `#define`: it falls out of how `json.c` parses numbers, which is
    /// as `double`, with `json_as_int64` rejecting a fractional part or an
    /// out-of-int64 value. 2^53 is the largest integer a double represents
    /// exactly. The interesting part is what happens past it: the guest does
    /// NOT reject, it silently rounds to a different timeout than the one
    /// configured (measured in `test_config.c`'s `test_timeout_precision_edge`),
    /// which is why this is checked host-side rather than left to the guest.
    /// `i64::MAX` fares worse still — as a double it rounds up to 2^63, which
    /// `json_as_int64` refuses outright, so the cell would not start.
    pub const MAX_TIMEOUT_MS: u64 = 1 << 53;
}

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
    ///
    /// `replacement_argv` is the argv the redirected exec actually runs, in
    /// full — element 0 is the program and every element after it is an
    /// argument. The requested command's own arguments are NOT inherited: a
    /// rule that wants them has to name them.
    ///
    /// That is a correction, not a design note. The guest used to repoint only
    /// the path register and leave the tracee's argv pointer alone, so
    /// `["/bin/echo", "intercepted"]` ran `/bin/echo` with the *requested*
    /// argv and dropped "intercepted" silently — nothing refused the config and
    /// nothing reported the discrepancy.
    ///
    /// One residual tell worth naming: the substituted process's own
    /// `/proc/self/cmdline` (and therefore `ps`) shows the replacement argv,
    /// not the requested one. That is inherent to running a different argv and
    /// is the honest trade for doing what the rule says; the alternative was
    /// doing something else quietly.
    Substitute {
        replacement_argv: Vec<String>,
        /// When true, the traced command's own trailing arguments (argv[1..]
        /// — never argv[0] itself, the command name being replaced) are
        /// appended to `replacement_argv` at exec time, truncated (not
        /// refused) at the guest's `EXEC_RELAY_MAX_ARGV` total. Off by
        /// default, matching every existing rule's behaviour exactly:
        /// `replacement_argv` alone is what runs.
        ///
        /// Exists for a wrapper program that needs the CALLER's own
        /// arguments at runtime and cannot be given them any other way —
        /// `replacement_argv` is fixed at plan-construction time, so a rule
        /// wanting arbitrary per-invocation arguments (e.g. `ls`'s own flags
        /// and path, unknown until the guest actually runs it) has no way to
        /// name them in advance. Only the wrapper's own selector arguments
        /// belong in `replacement_argv`; the real command's arguments ride
        /// in via this flag.
        #[serde(default)]
        append_original_args: bool,
    },
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
    /// A `Fabricate` rule whose stdout or stderr reaches the guest relay's
    /// fixed per-stream budget — checked here so an oversized payload is a
    /// startup refusal, not a runtime truncation discovered mid-run.
    ///
    /// The boundary is `>=`, matching `config.c`'s `load_verb` exactly
    /// (`if (outlen >= EXEC_RELAY_MAX_FABRICATE_BYTES) return -1;`). It used to
    /// be `>` here, so a payload of exactly 2000 bytes passed host validation
    /// and then made `execrelayd` refuse to start.
    FabricatePayloadTooLarge {
        rule_index: usize,
        len: usize,
    },
    /// More rules than the guest's fixed `rules[]` array holds.
    TooManyRules(usize),
    /// A rule name longer than the guest's `name[]` buffer.
    RuleNameTooLong {
        rule_index: usize,
        len: usize,
    },
    /// A matcher or substitute argv with more elements than a request could
    /// ever carry (`EXEC_RELAY_MAX_ARGV`).
    ArgvTooManyElements {
        rule_index: usize,
        field: &'static str,
        len: usize,
    },
    /// A single argv element longer than the guest's per-element buffer.
    ArgvElementTooLong {
        rule_index: usize,
        field: &'static str,
        element: usize,
        len: usize,
    },
    /// A rewrite find/replace string longer than the guest's buffer.
    RewriteStringTooLong {
        rule_index: usize,
        field: &'static str,
        len: usize,
    },
    /// A `timeout_ms` the guest's JSON number parser cannot carry faithfully —
    /// see [`guest_limits::MAX_TIMEOUT_MS`]. Past it the guest either rounds
    /// silently to a different timeout or (near `i64::MAX`) refuses to start.
    TimeoutOutOfRange(u64),
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
    /// The whole base64-encoded spec is larger than the guest can be handed —
    /// see [`guest_limits::MAX_SPEC_B64`]. The only limit here that is not a
    /// property of one field: a plan can pass every per-field check and still
    /// combine into a document that cannot be delivered, which is the exact
    /// host-accepts/guest-refuses shape the other limits were aligned to close.
    /// Without this check the refusal would instead surface downstream — as a
    /// docker- or containerd-level `EngineError::Failed` on the `--env-file`
    /// this value becomes, or, at worst, the kernel's own `execve` `E2BIG` on
    /// `execrelayd`'s entrypoint — a real error either way, but one that names
    /// a transport failure rather than the plan that caused it. Checked here
    /// so the operator instead gets a legible, typed refusal naming the total.
    SpecTooLarge {
        encoded_len: usize,
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
                "rule {rule_index}'s fabricate stdout or stderr is {len} bytes; the guest parser \
                 accepts at most {} per stream",
                guest_limits::MAX_FABRICATE_BYTES - 1
            ),
            Self::TooManyRules(n) => write!(
                f,
                "the plan has {n} rules; the guest parser accepts at most {}",
                guest_limits::MAX_RULES
            ),
            Self::RuleNameTooLong { rule_index, len } => write!(
                f,
                "rule {rule_index}'s name is {len} bytes; the guest parser accepts at most {}",
                guest_limits::MAX_RULE_NAME
            ),
            Self::ArgvTooManyElements {
                rule_index,
                field,
                len,
            } => write!(
                f,
                "rule {rule_index}'s {field} has {len} elements; the guest parser accepts at most {}",
                guest_limits::MAX_ARGV
            ),
            Self::ArgvElementTooLong {
                rule_index,
                field,
                element,
                len,
            } => write!(
                f,
                "rule {rule_index}'s {field}[{element}] is {len} bytes; the guest parser accepts \
                 at most {}",
                guest_limits::MAX_ARGV_ELEM
            ),
            Self::RewriteStringTooLong {
                rule_index,
                field,
                len,
            } => write!(
                f,
                "rule {rule_index}'s rewrite.{field} is {len} bytes; the guest parser accepts at \
                 most {}",
                guest_limits::MAX_REWRITE_STR
            ),
            Self::TimeoutOutOfRange(v) => write!(
                f,
                "timeout_ms is {v}; the guest parses JSON numbers as doubles and cannot carry \
                 anything above {} without silently changing it",
                guest_limits::MAX_TIMEOUT_MS
            ),
            Self::AsymmetricRewritePair { rule_index, pair } => write!(
                f,
                "rule {rule_index}'s rewrite.{pair}_find/{pair}_replace must both be set or both be absent, not just one"
            ),
            Self::SpecTooLarge { encoded_len } => write!(
                f,
                "the plan encodes to {encoded_len} base64 characters; {EXEC_SPEC_B64_VAR} \
                 travels to the guest as one environment variable through docker create \
                 --env-file and on to the guest entrypoint's execve, and this host-side check \
                 accepts at most {} for it — a bound chosen tighter than the kernel's own \
                 MAX_ARG_STRLEN ceiling so this refusal fires before any hop downstream (docker, \
                 containerd, or the kernel) has a chance to fail on it instead. Every individual \
                 field is within its own limit — it is the total that is not, so the fix is \
                 fewer or smaller rules rather than a shorter single value",
                guest_limits::MAX_SPEC_B64
            ),
            Self::TimeoutZero => write!(f, "timeout_ms must be nonzero"),
            Self::MaxConcurrentHandlersZero => write!(f, "max_concurrent_handlers must be nonzero"),
        }
    }
}

impl std::error::Error for ExecConsequenceConfigError {}

/// One argv array, against the guest's element-count and element-length limits.
fn check_argv(
    rule_index: usize,
    field: &'static str,
    argv: &[String],
) -> Result<(), ExecConsequenceConfigError> {
    if argv.len() > guest_limits::MAX_ARGV {
        return Err(ExecConsequenceConfigError::ArgvTooManyElements {
            rule_index,
            field,
            len: argv.len(),
        });
    }
    for (element, value) in argv.iter().enumerate() {
        check_argv_element(rule_index, field, element, value)?;
    }
    Ok(())
}

fn check_argv_element(
    rule_index: usize,
    field: &'static str,
    element: usize,
    value: &str,
) -> Result<(), ExecConsequenceConfigError> {
    if value.len() > guest_limits::MAX_ARGV_ELEM {
        return Err(ExecConsequenceConfigError::ArgvElementTooLong {
            rule_index,
            field,
            element,
            len: value.len(),
        });
    }
    Ok(())
}

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
        if self.timeout_ms > guest_limits::MAX_TIMEOUT_MS {
            return Err(ExecConsequenceConfigError::TimeoutOutOfRange(
                self.timeout_ms,
            ));
        }
        if self.max_concurrent_handlers == 0 {
            return Err(ExecConsequenceConfigError::MaxConcurrentHandlersZero);
        }
        // `max_concurrent_handlers` needs no upper check: the guest refuses
        // above `UINT32_MAX` and this field is a `u32`, so the types already
        // agree. Every other limit below is one the guest enforces and this
        // function did not.
        if self.rules.len() > guest_limits::MAX_RULES {
            return Err(ExecConsequenceConfigError::TooManyRules(self.rules.len()));
        }
        for (i, rule) in self.rules.iter().enumerate() {
            if rule.name.is_empty() {
                return Err(ExecConsequenceConfigError::EmptyRuleName(i));
            }
            // Bytes, not chars: `copy_str` measures the guest's buffer in
            // bytes, so a name of 100 multi-byte characters can overflow a
            // 127-byte buffer while looking short.
            if rule.name.len() > guest_limits::MAX_RULE_NAME {
                return Err(ExecConsequenceConfigError::RuleNameTooLong {
                    rule_index: i,
                    len: rule.name.len(),
                });
            }
            let empty_match = match &rule.match_argv {
                ArgvMatcher::Prefix { argv } | ArgvMatcher::Exact { argv } => argv.is_empty(),
                ArgvMatcher::Argv0 { name } => name.is_empty(),
            };
            if empty_match {
                return Err(ExecConsequenceConfigError::EmptyMatchArgv(i));
            }
            match &rule.match_argv {
                ArgvMatcher::Prefix { argv } | ArgvMatcher::Exact { argv } => {
                    check_argv(i, "match_argv", argv)?;
                }
                ArgvMatcher::Argv0 { name } => {
                    check_argv_element(i, "match_argv", 0, name)?;
                }
            }
            match &rule.verb {
                ExecVerb::Substitute {
                    replacement_argv, ..
                } => {
                    if replacement_argv.is_empty() {
                        return Err(ExecConsequenceConfigError::EmptyReplacementArgv(i));
                    }
                    check_argv(i, "replacement_argv", replacement_argv)?;
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
                    for (field, value) in [
                        ("stdout_find", stdout_find),
                        ("stdout_replace", stdout_replace),
                        ("stderr_find", stderr_find),
                        ("stderr_replace", stderr_replace),
                    ] {
                        if let Some(value) = value
                            && value.len() > guest_limits::MAX_REWRITE_STR
                        {
                            return Err(ExecConsequenceConfigError::RewriteStringTooLong {
                                rule_index: i,
                                field,
                                len: value.len(),
                            });
                        }
                    }
                }
                ExecVerb::Fabricate { stdout, stderr, .. } => {
                    // `>=`, matching `config.c`'s `load_verb`, and per stream
                    // rather than combined — the guest has a separate buffer
                    // for each. `len` reports the offending stream's length so
                    // the message names a number the operator can act on.
                    for stream in [stdout, stderr] {
                        if stream.len() >= guest_limits::MAX_FABRICATE_BYTES {
                            return Err(ExecConsequenceConfigError::FabricatePayloadTooLarge {
                                rule_index: i,
                                len: stream.len(),
                            });
                        }
                    }
                }
            }
        }
        // LAST, and on the whole document rather than on any field — the one
        // check here that no per-field pass could ever subsume. Reported after
        // the field checks deliberately: "rule 7's name is too long" is a
        // better first answer than "the total is too big" when both are true,
        // because it names something the operator can act on directly.
        //
        // Encoded rather than estimated: the transport carries base64, the
        // guest's limit is stated in base64 characters, and
        // `to_env_pairs` produces the very string this measures. `encode_len`
        // is exact for a padded encoding, so this needs no allocation of the
        // encoded form itself.
        let encoded_len = BASE64.encode_len(self.wire_json().len());
        if encoded_len > guest_limits::MAX_SPEC_B64 {
            return Err(ExecConsequenceConfigError::SpecTooLarge { encoded_len });
        }
        Ok(())
    }

    /// The exact JSON `to_env_pairs` base64s. One place, so the size
    /// `validate` measures and the bytes the guest receives cannot be
    /// different documents.
    fn wire_json(&self) -> String {
        serde_json::to_string(self).expect("ExecConsequencePlan always serializes")
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
        vec![(
            EXEC_SPEC_B64_VAR.to_owned(),
            BASE64.encode(self.wire_json().as_bytes()),
        )]
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
                    append_original_args: false,
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

    // ---- the two parsers' limits, and the boundary of each ------------------
    //
    // The guest (`config.c`) and the host (`validate`) parse the same JSON
    // independently, so every limit exists twice and every one of them was
    // either absent here or set to a different boundary. The consequence is
    // always the same shape: a plan the host accepts makes `execrelayd` refuse
    // to start, and the operator sees an opaque guest-side error about a
    // configuration the host said was fine.

    fn plan_with(rule: ExecConsequenceRule) -> ExecConsequencePlan {
        ExecConsequencePlan {
            rules: vec![rule],
            timeout_ms: 60_000,
            max_concurrent_handlers: 32,
        }
    }

    fn argv0_rule(name: &str, verb: ExecVerb) -> ExecConsequenceRule {
        ExecConsequenceRule {
            name: name.to_owned(),
            match_argv: ArgvMatcher::Argv0 {
                name: "/bin/echo".to_owned(),
            },
            verb,
        }
    }

    fn fabricate(stdout: String, stderr: String) -> ExecVerb {
        ExecVerb::Fabricate {
            exit_code: 0,
            stdout,
            stderr,
        }
    }

    /// The reported defect, at the exact byte where the two parsers disagreed.
    /// 2000 was host-valid (`> 2000`) and guest-fatal (`>= 2000`).
    #[test]
    fn fabricate_payload_boundary_matches_the_guest_parser() {
        let at_limit = "x".repeat(guest_limits::MAX_FABRICATE_BYTES - 1);
        plan_with(argv0_rule("f", fabricate(at_limit.clone(), String::new())))
            .validate()
            .expect("1999 bytes is what config.c accepts");
        plan_with(argv0_rule("f", fabricate(String::new(), at_limit)))
            .validate()
            .expect("the stderr stream has its own identical budget");

        let past = "x".repeat(guest_limits::MAX_FABRICATE_BYTES);
        let err = plan_with(argv0_rule("f", fabricate(past.clone(), String::new())))
            .validate()
            .unwrap_err();
        assert_eq!(
            err,
            ExecConsequenceConfigError::FabricatePayloadTooLarge {
                rule_index: 0,
                len: guest_limits::MAX_FABRICATE_BYTES,
            },
            "exactly {} bytes must be refused here, because config.c refuses it",
            guest_limits::MAX_FABRICATE_BYTES
        );
        assert!(
            plan_with(argv0_rule("f", fabricate(String::new(), past)))
                .validate()
                .is_err()
        );
    }

    /// Both streams may sit at the limit at once: the guest has a separate
    /// buffer for each, so the old combined-length reading of this budget was
    /// wrong in the permissive direction as well as the strict one.
    #[test]
    fn the_fabricate_budget_is_per_stream_not_combined() {
        let at_limit = "x".repeat(guest_limits::MAX_FABRICATE_BYTES - 1);
        plan_with(argv0_rule("f", fabricate(at_limit.clone(), at_limit)))
            .validate()
            .expect("3998 bytes across two streams is two valid streams");
    }

    #[test]
    fn rule_count_boundary_matches_the_guest_parser() {
        let rule = argv0_rule("r", fabricate(String::new(), String::new()));
        let mut plan = ExecConsequencePlan {
            rules: vec![rule.clone(); guest_limits::MAX_RULES],
            timeout_ms: 60_000,
            max_concurrent_handlers: 32,
        };
        plan.validate().expect("exactly MAX_RULES rules load");
        plan.rules.push(rule);
        assert_eq!(
            plan.validate().unwrap_err(),
            ExecConsequenceConfigError::TooManyRules(guest_limits::MAX_RULES + 1)
        );
    }

    #[test]
    fn rule_name_length_boundary_matches_the_guest_parser() {
        let at_limit = "n".repeat(guest_limits::MAX_RULE_NAME);
        plan_with(argv0_rule(
            &at_limit,
            fabricate(String::new(), String::new()),
        ))
        .validate()
        .expect("a name of exactly MAX_RULE_NAME bytes fits config.c's buffer");

        let past = "n".repeat(guest_limits::MAX_RULE_NAME + 1);
        assert_eq!(
            plan_with(argv0_rule(&past, fabricate(String::new(), String::new())))
                .validate()
                .unwrap_err(),
            ExecConsequenceConfigError::RuleNameTooLong {
                rule_index: 0,
                len: guest_limits::MAX_RULE_NAME + 1,
            }
        );
    }

    #[test]
    fn argv_element_count_boundary_matches_the_guest_parser() {
        let elems = vec!["a".to_owned(); guest_limits::MAX_ARGV];
        ExecConsequencePlan {
            rules: vec![ExecConsequenceRule {
                name: "r".to_owned(),
                match_argv: ArgvMatcher::Prefix {
                    argv: elems.clone(),
                },
                verb: ExecVerb::Substitute {
                    replacement_argv: elems.clone(),
                    append_original_args: false,
                },
            }],
            timeout_ms: 60_000,
            max_concurrent_handlers: 32,
        }
        .validate()
        .expect("exactly MAX_ARGV elements is what config.c accepts");

        let mut too_many = elems.clone();
        too_many.push("a".to_owned());
        assert_eq!(
            plan_with(ExecConsequenceRule {
                name: "r".to_owned(),
                match_argv: ArgvMatcher::Prefix {
                    argv: too_many.clone()
                },
                verb: fabricate(String::new(), String::new()),
            })
            .validate()
            .unwrap_err(),
            ExecConsequenceConfigError::ArgvTooManyElements {
                rule_index: 0,
                field: "match_argv",
                len: guest_limits::MAX_ARGV + 1,
            }
        );
        assert_eq!(
            plan_with(ExecConsequenceRule {
                name: "r".to_owned(),
                match_argv: ArgvMatcher::Argv0 {
                    name: "/bin/echo".to_owned()
                },
                verb: ExecVerb::Substitute {
                    replacement_argv: too_many,
                    append_original_args: false,
                },
            })
            .validate()
            .unwrap_err(),
            ExecConsequenceConfigError::ArgvTooManyElements {
                rule_index: 0,
                field: "replacement_argv",
                len: guest_limits::MAX_ARGV + 1,
            }
        );
    }

    #[test]
    fn argv_element_length_boundary_matches_the_guest_parser() {
        let at_limit = "a".repeat(guest_limits::MAX_ARGV_ELEM);
        let past = "a".repeat(guest_limits::MAX_ARGV_ELEM + 1);

        plan_with(ExecConsequenceRule {
            name: "r".to_owned(),
            match_argv: ArgvMatcher::Argv0 {
                name: at_limit.clone(),
            },
            verb: ExecVerb::Substitute {
                replacement_argv: vec![at_limit.clone()],
                append_original_args: false,
            },
        })
        .validate()
        .expect("an element of exactly MAX_ARGV_ELEM bytes fits config.c's buffer");

        // Each of the three places an argv element can appear: the argv0
        // matcher's name, a prefix/exact matcher's array, and a substitute's
        // replacement. config.c copies all three through the same `copy_str`.
        assert_eq!(
            plan_with(ExecConsequenceRule {
                name: "r".to_owned(),
                match_argv: ArgvMatcher::Argv0 { name: past.clone() },
                verb: fabricate(String::new(), String::new()),
            })
            .validate()
            .unwrap_err(),
            ExecConsequenceConfigError::ArgvElementTooLong {
                rule_index: 0,
                field: "match_argv",
                element: 0,
                len: guest_limits::MAX_ARGV_ELEM + 1,
            }
        );
        assert_eq!(
            plan_with(ExecConsequenceRule {
                name: "r".to_owned(),
                match_argv: ArgvMatcher::Exact {
                    argv: vec!["ok".to_owned(), past.clone()],
                },
                verb: fabricate(String::new(), String::new()),
            })
            .validate()
            .unwrap_err(),
            ExecConsequenceConfigError::ArgvElementTooLong {
                rule_index: 0,
                field: "match_argv",
                element: 1,
                len: guest_limits::MAX_ARGV_ELEM + 1,
            }
        );
        assert_eq!(
            plan_with(ExecConsequenceRule {
                name: "r".to_owned(),
                match_argv: ArgvMatcher::Argv0 {
                    name: "/bin/echo".to_owned()
                },
                verb: ExecVerb::Substitute {
                    replacement_argv: vec![past],
                    append_original_args: false,
                },
            })
            .validate()
            .unwrap_err(),
            ExecConsequenceConfigError::ArgvElementTooLong {
                rule_index: 0,
                field: "replacement_argv",
                element: 0,
                len: guest_limits::MAX_ARGV_ELEM + 1,
            }
        );
    }

    #[test]
    fn rewrite_string_length_boundary_matches_the_guest_parser() {
        let at_limit = "s".repeat(guest_limits::MAX_REWRITE_STR);
        let past = "s".repeat(guest_limits::MAX_REWRITE_STR + 1);

        plan_with(argv0_rule(
            "r",
            ExecVerb::Rewrite {
                stdout_find: Some(at_limit.clone()),
                stdout_replace: Some(at_limit.clone()),
                stderr_find: Some(at_limit.clone()),
                stderr_replace: Some(at_limit),
            },
        ))
        .validate()
        .expect("a find/replace of exactly MAX_REWRITE_STR bytes fits config.c's buffer");

        assert_eq!(
            plan_with(argv0_rule(
                "r",
                ExecVerb::Rewrite {
                    stdout_find: Some(past.clone()),
                    stdout_replace: Some("x".to_owned()),
                    stderr_find: None,
                    stderr_replace: None,
                },
            ))
            .validate()
            .unwrap_err(),
            ExecConsequenceConfigError::RewriteStringTooLong {
                rule_index: 0,
                field: "stdout_find",
                len: guest_limits::MAX_REWRITE_STR + 1,
            }
        );
        assert_eq!(
            plan_with(argv0_rule(
                "r",
                ExecVerb::Rewrite {
                    stdout_find: None,
                    stdout_replace: None,
                    stderr_find: Some("x".to_owned()),
                    stderr_replace: Some(past),
                },
            ))
            .validate()
            .unwrap_err(),
            ExecConsequenceConfigError::RewriteStringTooLong {
                rule_index: 0,
                field: "stderr_replace",
                len: guest_limits::MAX_REWRITE_STR + 1,
            }
        );
    }

    #[test]
    fn a_timeout_the_guest_cannot_carry_faithfully_is_refused() {
        // The guest reads every JSON number as a double. 2^53 is the last one
        // it carries exactly; 2^53 + 1 does NOT make it refuse to start, it
        // silently becomes 2^53 (asserted directly against the C parser in
        // test_config.c's test_timeout_precision_edge), and i64::MAX rounds up
        // to 2^63 and is refused outright by json_as_int64 — the cell then
        // never starts, on a plan this side had called valid.
        let mut plan = ExecConsequencePlan {
            rules: vec![],
            timeout_ms: guest_limits::MAX_TIMEOUT_MS,
            max_concurrent_handlers: 32,
        };
        plan.validate()
            .expect("2^53 survives the guest's double intact");
        plan.timeout_ms = guest_limits::MAX_TIMEOUT_MS + 1;
        assert_eq!(
            plan.validate().unwrap_err(),
            ExecConsequenceConfigError::TimeoutOutOfRange(guest_limits::MAX_TIMEOUT_MS + 1)
        );
        plan.timeout_ms = i64::MAX as u64;
        assert!(plan.validate().is_err());
    }

    /// A plan every per-field check passes and the guest cannot be handed.
    ///
    /// This is the gap the field-by-field alignment left open. Each limit above
    /// was carefully matched to `config.c`, boundary conventions and all — and
    /// none of them says anything about the TOTAL. `MAX_RULES` rules, each
    /// individually valid and each near its own ceilings, encodes to well over
    /// a megabyte, and without this check the failure would surface downstream
    /// instead of here: as a docker- or containerd-level error from the
    /// `--env-file` this value ultimately becomes, or, at worst, the kernel's
    /// own `execve` `E2BIG` on the guest entrypoint. That failure would still
    /// be a real, typed `EngineError::Failed`, not a silent one — but it would
    /// name a line docker could not parse, not the plan that produced it. This
    /// check turns it into a legible host-side `ArmingRefusal`/`SpecTooLarge`
    /// before any container operation is attempted at all.
    ///
    /// Built out of `Fabricate` payloads because they are the largest per-rule
    /// field, so the plan stays small in rule count and obviously legitimate:
    /// nothing about it is a stress shape, it is 64 ordinary rules with big
    /// canned outputs.
    #[test]
    fn a_plan_valid_field_by_field_can_still_be_too_large_in_aggregate() {
        let payload = "x".repeat(guest_limits::MAX_FABRICATE_BYTES - 1);
        let plan = ExecConsequencePlan {
            rules: (0..guest_limits::MAX_RULES)
                .map(|i| ExecConsequenceRule {
                    name: format!("rule-{i}"),
                    match_argv: ArgvMatcher::Argv0 {
                        name: format!("/bin/tool-{i}"),
                    },
                    verb: fabricate(payload.clone(), payload.clone()),
                })
                .collect(),
            timeout_ms: 60_000,
            max_concurrent_handlers: 32,
        };

        let encoded_len = plan.to_env_pairs().remove(0).1.len();
        assert!(
            encoded_len > guest_limits::MAX_SPEC_B64,
            "this plan is supposed to be over the transport limit; it encoded to \
             {encoded_len}"
        );
        assert_eq!(
            plan.validate().unwrap_err(),
            ExecConsequenceConfigError::SpecTooLarge { encoded_len },
            "a plan that cannot be delivered must be refused here, where the operator \
             can read why, and not by execve inside the engine"
        );
        // And the message says the thing that is actually actionable: it is the
        // total, not any one field.
        let printed = ExecConsequenceConfigError::SpecTooLarge { encoded_len }.to_string();
        assert!(printed.contains(EXEC_SPEC_B64_VAR), "{printed}");
        assert!(printed.contains("total"), "{printed}");
    }

    /// The boundary, walked from below rather than asserted from above.
    ///
    /// A check that refused everything large would be as wrong as one that
    /// refused nothing, and a test that merely validates something comfortably
    /// small would not tell the difference. This adds rules one at a time until
    /// the next one would cross the transport limit, then asserts BOTH sides of
    /// that step: the largest plan that fits validates, and the one rule more
    /// is refused as `SpecTooLarge` — not as `TooManyRules`, which is a
    /// different limit that this shape stays well inside.
    #[test]
    fn the_transport_limit_admits_the_largest_plan_that_fits_and_refuses_the_next() {
        let payload = "x".repeat(guest_limits::MAX_FABRICATE_BYTES - 1);
        let mut plan = ExecConsequencePlan {
            rules: vec![],
            timeout_ms: 60_000,
            max_concurrent_handlers: 32,
        };
        loop {
            let mut next = plan.clone();
            let i = next.rules.len();
            next.rules.push(ExecConsequenceRule {
                name: format!("rule-{i}"),
                match_argv: ArgvMatcher::Argv0 {
                    name: format!("/bin/tool-{i}"),
                },
                verb: fabricate(payload.clone(), String::new()),
            });
            assert!(
                next.rules.len() <= guest_limits::MAX_RULES,
                "this shape was supposed to hit the size limit well before the rule-count \
                 one; it did not, so the test is measuring the wrong limit"
            );
            let encoded_len = next.to_env_pairs().remove(0).1.len();
            if encoded_len > guest_limits::MAX_SPEC_B64 {
                assert_eq!(
                    next.validate().unwrap_err(),
                    ExecConsequenceConfigError::SpecTooLarge { encoded_len }
                );
                break;
            }
            plan = next;
        }
        assert!(
            !plan.rules.is_empty(),
            "one rule of this size must fit, or the limit is set absurdly low"
        );
        plan.validate()
            .expect("the largest plan that fits the transport must not be refused");
    }

    /// The constants above are a copy of the guest's, and a copy is a thing
    /// that drifts. This reads the actual C headers and fails if any of them
    /// has moved — which is the only way the two parsers can be kept honest
    /// short of sharing one, and sharing one is not available across a Rust
    /// host and a C guest that parse independently by design.
    #[test]
    fn guest_limits_match_the_c_header() {
        let src = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .and_then(|p| p.parent())
            .expect("crates/<pkg> sits two levels below runtime/")
            .join("images/guest-exec-relay/src");
        let config_h = std::fs::read_to_string(src.join("config.h")).expect("config.h");
        let protocol_h = std::fs::read_to_string(src.join("protocol.h")).expect("protocol.h");

        fn defined(text: &str, name: &str) -> usize {
            let needle = format!("#define {name} ");
            let line = text
                .lines()
                .find(|l| l.starts_with(&needle))
                .unwrap_or_else(|| panic!("{name} is no longer defined in the C header"));
            line[needle.len()..]
                .split_whitespace()
                .next()
                .and_then(|v| v.parse().ok())
                .unwrap_or_else(|| panic!("{name} is no longer a plain integer: {line}"))
        }

        assert_eq!(
            defined(&config_h, "EXEC_RELAY_MAX_RULES"),
            guest_limits::MAX_RULES
        );
        assert_eq!(
            defined(&config_h, "EXEC_RELAY_MAX_RULE_NAME"),
            guest_limits::MAX_RULE_NAME
        );
        assert_eq!(
            defined(&config_h, "EXEC_RELAY_MAX_ARGV_ELEM"),
            guest_limits::MAX_ARGV_ELEM
        );
        assert_eq!(
            defined(&config_h, "EXEC_RELAY_MAX_REWRITE_STR"),
            guest_limits::MAX_REWRITE_STR
        );
        assert_eq!(
            defined(&config_h, "EXEC_RELAY_MAX_FABRICATE_BYTES"),
            guest_limits::MAX_FABRICATE_BYTES
        );
        assert_eq!(
            defined(&protocol_h, "EXEC_RELAY_MAX_ARGV"),
            guest_limits::MAX_ARGV
        );
        assert_eq!(
            defined(&config_h, "EXEC_RELAY_MAX_SPEC_B64"),
            guest_limits::MAX_SPEC_B64
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
