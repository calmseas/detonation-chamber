# Command-Consequence Interpreter Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build a general exec-interception layer for the guest cell (ptrace + seccomp relay) that can substitute, rewrite, or fabricate the outcome of any command a driving agent's turn runs, replacing the one-off `pip-shim.sh` approach with reusable, config-driven infrastructure.

**Architecture:** A new PID-1 supervisor (`execrelayd`) inside the guest cell forks a dedicated handler per `docker exec` request (via a small `stub` binary the exec targets), traces the forked worker with `PTRACE_SEIZE` + a seccomp filter that traps only `execve`/`execveat`, and applies a config-driven rule (substitute/rewrite/fabricate) at the trap. A new Rust `ExecConsequencePlan` type (mirroring `chamber-capture`'s existing `ConsequencePlan`) is validated host-side and passed into the cell as a base64-JSON env var; the C-side parses the same JSON. A disclosure log inside the cell is `cat`'d out and sealed into the evidence bundle as a new channel before the cell is destroyed.

**Tech Stack:** Rust 1.94.1 (edition 2024), `serde`/`serde_json` for the config schema, hand-rolled C (no libseccomp — raw BPF via `linux/seccomp.h`/`linux/filter.h`) for the guest-side relay, Alpine 3.20 (musl) multi-stage Docker build.

## Global Constraints

- Rust toolchain: `1.94.1`, edition `2024` (`runtime/rust-toolchain.toml`) — do not use syntax newer than this pins.
- Workspace deps: `serde = "1"` (`derive` feature), `serde_json = "1"` — reuse the workspace-level versions in `runtime/Cargo.toml`, do not pin crate-local versions.
- No new Rust dependency may be added for JSON/base64 beyond what `chamber-capture` already uses (`data-encoding = "2"` for base64) — reuse it, don't add a second base64 crate.
- No `-e KEY=VALUE` for any container ever — all guest-bound config travels via 0600 `--env-file` (`chamber_isolation::EnvDraft`/`SealedEnv`). This is enforced by `EnvDraft::set`'s existing newline/NUL rejection; do not bypass it.
- The C relay must build with only `gcc`, `musl-dev`, `linux-headers` (Alpine `apk` packages) — no `libseccomp-dev`, no external C library beyond libc.
- Every new container capability requirement must be `--cap-drop ALL`-compatible (zero `--cap-add`, no `--privileged`) — this is a hard requirement validated by four prior empirical spikes, not a target to negotiate.
- `Channel` enum matches (`chamber-evidence/src/coverage.rs`) are written without a wildcard arm on purpose — the compiler must fail until every new variant is classified. Do not add a `_ =>` arm to route around this.
- Existing evidence channels (`Channel::GuestCommand`) must not be modified or duplicated — new behavior is a new, additive channel.

## File Structure

```
runtime/crates/chamber-capture/src/
  exec_consequence.rs          [NEW] ExecConsequencePlan Rust types, JSON schema, env transport
  lib.rs                       [MODIFY] register the new module

runtime/images/guest-exec-relay/     [NEW crate-adjacent directory, not a Cargo crate — C sources + Dockerfile]
  src/json.h, src/json.c       [NEW] minimal JSON value parser
  src/config.h, src/config.c   [NEW] maps parsed JSON -> C rule structs, argv matching
  src/relayd.c                 [NEW] PID-1 supervisor: ptrace+seccomp, verbs, concurrency, watchdog, disclosure log
  src/stub.c                   [NEW] docker-exec-targeted relay client
  tests/test_json.c            [NEW] standalone C unit tests for json.c
  tests/test_config.c          [NEW] standalone C unit tests for config.c
  tests/run_c_tests.sh         [NEW] compiles + runs the two test binaries
  Dockerfile                   [NEW] multi-stage build -> guest image

runtime/crates/chamber-run/src/
  run.rs                       [MODIFY] DetonationPlan.exec_consequence field, seal_cell_environment env injection, wind_down disclosure-log sealing
  bridge.rs                    [MODIFY] ToolBridge stub-prefixing + per-turn id
  bundle.rs                    [MODIFY] record_exec_consequence_log

runtime/crates/chamber-isolation/src/
  env.rs                       [MODIFY] SealedEnv::contains_binding, a #[cfg(test)]-only accessor

runtime/crates/chamber-evidence/src/
  coverage.rs                  [MODIFY] Channel::ExecConsequence variant
  ledger.rs                    [MODIFY] ObservationKind::ExecConsequence variant

runtime/crates/chamber-e2e/
  tests/exec_consequence.rs    [NEW] integration tests
  tests/support/mod.rs         [MODIFY] ensure_images_including helper
  Cargo.toml                   [MODIFY] register the new [[test]] target, add chamber-capture dev-dependency
```

---

### Task 1: `ExecConsequencePlan` Rust types, JSON schema, env transport

**Files:**
- Create: `runtime/crates/chamber-capture/src/exec_consequence.rs`
- Modify: `runtime/crates/chamber-capture/src/lib.rs`
- Test: inline `#[cfg(test)] mod tests` in the same file (matches `consequence.rs`'s own convention)

**Interfaces:**
- Consumes: `data_encoding::BASE64` (already a `chamber-capture` dependency), `serde`/`serde_json` (workspace deps).
- Produces: `pub struct ExecConsequencePlan`, `pub struct ExecConsequenceRule`, `pub enum ArgvMatcher`, `pub enum ExecVerb`, `pub enum ExecConsequenceConfigError`, `pub const EXEC_SPEC_B64_VAR: &str`, `ExecConsequencePlan::from_env() -> Result<Option<Self>, ExecConsequenceConfigError>`, `ExecConsequencePlan::from_env_value(Option<&str>) -> Result<Option<Self>, ExecConsequenceConfigError>`, `ExecConsequencePlan::to_env_pairs(&self) -> Vec<(String, String)>`, `ExecConsequencePlan::matching_rule(&self, argv: &[String]) -> Option<&ExecConsequenceRule>` — used later by Task 8/9's tests and by Task 9's bridge logic to decide whether to prefix `stub`.

- [ ] **Step 1: Write the failing tests for the domain types and matching logic**

```rust
// bottom of runtime/crates/chamber-capture/src/exec_consequence.rs (new file)
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
```

- [ ] **Step 2: Run the tests to verify they fail (module doesn't exist yet)**

Run: `cd runtime && cargo test -p chamber-capture exec_consequence`
Expected: FAIL with "unresolved import" / "module `exec_consequence` not found" (the module isn't registered in `lib.rs` yet, and the file doesn't exist).

- [ ] **Step 3: Implement the module**

```rust
// runtime/crates/chamber-capture/src/exec_consequence.rs (top of file, above the tests module)
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
```

Also add, at the top of `runtime/crates/chamber-capture/src/lib.rs`, next to the existing `pub mod consequence;` line:

```rust
pub mod exec_consequence;
```

(Non-feature-gated, exactly like `consequence` — `chamber-run` depends on `chamber-capture` with `default-features = false` and still needs to name this type.)

- [ ] **Step 4: Run the tests to verify they pass**

Run: `cd runtime && cargo test -p chamber-capture exec_consequence`
Expected: PASS, all 9 tests green.

- [ ] **Step 5: Commit**

```bash
cd runtime && git add crates/chamber-capture/src/exec_consequence.rs crates/chamber-capture/src/lib.rs
git commit -m "feat: add ExecConsequencePlan config schema for the exec-interception relay"
```

---

### Task 2: C JSON value parser

**Files:**
- Create: `runtime/images/guest-exec-relay/src/json.h`
- Create: `runtime/images/guest-exec-relay/src/json.c`
- Test: `runtime/images/guest-exec-relay/tests/test_json.c`
- Test: `runtime/images/guest-exec-relay/tests/run_c_tests.sh`

**Interfaces:**
- Consumes: nothing (pure C, no external deps beyond libc).
- Produces: `json_value_t` tagged union (`JSON_NULL`, `JSON_BOOL`, `JSON_NUMBER`, `JSON_STRING`, `JSON_ARRAY`, `JSON_OBJECT`), `json_parse(const char *text, size_t len) -> json_value_t*` (NULL on parse error), `json_free(json_value_t*)`, `json_object_get(json_value_t *obj, const char *key) -> json_value_t*` (NULL if absent or not an object), `json_array_len(json_value_t *arr) -> size_t`, `json_array_get(json_value_t *arr, size_t i) -> json_value_t*`, `json_as_string(json_value_t*) -> const char*` (NULL if not a string), `json_as_int64(json_value_t*, int64_t *out) -> int` (0 on success). Used by Task 3's `config.c`.

- [ ] **Step 1: Write `json.h`**

```c
#ifndef EXEC_RELAY_JSON_H
#define EXEC_RELAY_JSON_H

#include <stddef.h>
#include <stdint.h>

typedef enum {
    JSON_NULL,
    JSON_BOOL,
    JSON_NUMBER,
    JSON_STRING,
    JSON_ARRAY,
    JSON_OBJECT,
} json_type_t;

typedef struct json_value json_value_t;

struct json_value {
    json_type_t type;
    union {
        int boolean;
        double number;
        char *string;
        struct { json_value_t **items; size_t len; } array;
        struct { char **keys; json_value_t **values; size_t len; } object;
    } u;
};

/* Parses `text[0..len)`. Returns NULL on any malformed input. Caller owns
 * the result and must json_free() it. */
json_value_t *json_parse(const char *text, size_t len);
void json_free(json_value_t *v);

/* NULL if `obj` is not an object or `key` is absent. */
json_value_t *json_object_get(json_value_t *obj, const char *key);
/* 0 if `arr` is not an array. */
size_t json_array_len(json_value_t *arr);
/* NULL if `arr` is not an array or `i` is out of range. */
json_value_t *json_array_get(json_value_t *arr, size_t i);
/* NULL if `v` is not a string. */
const char *json_as_string(json_value_t *v);
/* Returns 0 and writes *out if `v` is a number with no fractional part
 * representable as int64_t; returns -1 otherwise. */
int json_as_int64(json_value_t *v, int64_t *out);

#endif
```

- [ ] **Step 2: Write the failing tests**

```c
// runtime/images/guest-exec-relay/tests/test_json.c
#include <assert.h>
#include <string.h>
#include <stdio.h>
#include "../src/json.h"

static void test_parses_flat_object(void) {
    const char *text = "{\"a\":1,\"b\":\"two\",\"c\":true,\"d\":null}";
    json_value_t *v = json_parse(text, strlen(text));
    assert(v != NULL);
    assert(v->type == JSON_OBJECT);
    int64_t a;
    assert(json_as_int64(json_object_get(v, "a"), &a) == 0 && a == 1);
    assert(strcmp(json_as_string(json_object_get(v, "b")), "two") == 0);
    assert(json_object_get(v, "c")->type == JSON_BOOL);
    assert(json_object_get(v, "d")->type == JSON_NULL);
    assert(json_object_get(v, "missing") == NULL);
    json_free(v);
}

static void test_parses_nested_array_of_objects(void) {
    const char *text = "{\"rules\":[{\"name\":\"r1\"},{\"name\":\"r2\"}]}";
    json_value_t *v = json_parse(text, strlen(text));
    assert(v != NULL);
    json_value_t *rules = json_object_get(v, "rules");
    assert(rules != NULL && rules->type == JSON_ARRAY);
    assert(json_array_len(rules) == 2);
    assert(strcmp(json_as_string(json_object_get(json_array_get(rules, 0), "name")), "r1") == 0);
    assert(strcmp(json_as_string(json_object_get(json_array_get(rules, 1), "name")), "r2") == 0);
    json_free(v);
}

static void test_handles_escaped_strings(void) {
    const char *text = "{\"s\":\"line one\\nline two\\t\\\"quoted\\\"\"}";
    json_value_t *v = json_parse(text, strlen(text));
    assert(v != NULL);
    assert(strcmp(json_as_string(json_object_get(v, "s")), "line one\nline two\t\"quoted\"") == 0);
    json_free(v);
}

static void test_rejects_malformed_json(void) {
    const char *bad_cases[] = {
        "{\"a\":}",
        "{a:1}",
        "[1,2,",
        "",
        "{\"a\":1",
    };
    for (size_t i = 0; i < sizeof(bad_cases)/sizeof(bad_cases[0]); i++) {
        json_value_t *v = json_parse(bad_cases[i], strlen(bad_cases[i]));
        assert(v == NULL);
    }
}

static void test_negative_and_zero_numbers(void) {
    const char *text = "{\"a\":-5,\"b\":0}";
    json_value_t *v = json_parse(text, strlen(text));
    int64_t a, b;
    assert(json_as_int64(json_object_get(v, "a"), &a) == 0 && a == -5);
    assert(json_as_int64(json_object_get(v, "b"), &b) == 0 && b == 0);
    json_free(v);
}

int main(void) {
    test_parses_flat_object();
    test_parses_nested_array_of_objects();
    test_handles_escaped_strings();
    test_rejects_malformed_json();
    test_negative_and_zero_numbers();
    printf("test_json: all tests passed\n");
    return 0;
}
```

```bash
# runtime/images/guest-exec-relay/tests/run_c_tests.sh
#!/bin/sh
set -eu
cd "$(dirname "$0")"
cc -Wall -Wextra -std=c11 -g -o /tmp/test_json ../src/json.c test_json.c
/tmp/test_json
cc -Wall -Wextra -std=c11 -g -o /tmp/test_config ../src/json.c ../src/config.c test_config.c
/tmp/test_config
echo "all C unit tests passed"
```

- [ ] **Step 3: Run to verify it fails to build**

Run: `chmod +x runtime/images/guest-exec-relay/tests/run_c_tests.sh && runtime/images/guest-exec-relay/tests/run_c_tests.sh`
Expected: FAIL — `../src/json.c` doesn't exist yet (and `../src/config.c`/`test_config.c` don't exist yet either; that's fine, the script fails at the first `cc` call, which is the part this task cares about).

- [ ] **Step 4: Implement `json.c`**

```c
// runtime/images/guest-exec-relay/src/json.c
#include "json.h"
#include <stdlib.h>
#include <string.h>
#include <ctype.h>

struct parser {
    const char *p;
    const char *end;
    int failed;
};

static void skip_ws(struct parser *ps) {
    while (ps->p < ps->end && (*ps->p == ' ' || *ps->p == '\t' || *ps->p == '\n' || *ps->p == '\r')) ps->p++;
}

static json_value_t *alloc_value(json_type_t t) {
    json_value_t *v = calloc(1, sizeof(json_value_t));
    v->type = t;
    return v;
}

static json_value_t *parse_value(struct parser *ps);

static char *parse_raw_string(struct parser *ps) {
    if (ps->p >= ps->end || *ps->p != '"') { ps->failed = 1; return NULL; }
    ps->p++;
    size_t cap = 32, len = 0;
    char *buf = malloc(cap);
    while (ps->p < ps->end && *ps->p != '"') {
        char c = *ps->p++;
        if (c == '\\') {
            if (ps->p >= ps->end) { ps->failed = 1; free(buf); return NULL; }
            char esc = *ps->p++;
            switch (esc) {
                case 'n': c = '\n'; break;
                case 't': c = '\t'; break;
                case 'r': c = '\r'; break;
                case '"': c = '"'; break;
                case '\\': c = '\\'; break;
                case '/': c = '/'; break;
                case 'b': c = '\b'; break;
                case 'f': c = '\f'; break;
                case 'u': {
                    /* Minimal \uXXXX support: only the BMP ASCII range is
                     * decoded faithfully (sufficient for this schema's own
                     * field values); anything above U+007F is stored as '?'
                     * rather than mis-encoded, since fabricated stdout/stderr
                     * strings in practice are ASCII fixture text. */
                    if (ps->p + 4 > ps->end) { ps->failed = 1; free(buf); return NULL; }
                    int cp = 0;
                    for (int i = 0; i < 4; i++) {
                        char h = ps->p[i];
                        int digit;
                        if (h >= '0' && h <= '9') digit = h - '0';
                        else if (h >= 'a' && h <= 'f') digit = 10 + h - 'a';
                        else if (h >= 'A' && h <= 'F') digit = 10 + h - 'A';
                        else { ps->failed = 1; free(buf); return NULL; }
                        cp = cp * 16 + digit;
                    }
                    ps->p += 4;
                    c = (cp <= 0x7f) ? (char)cp : '?';
                    break;
                }
                default: ps->failed = 1; free(buf); return NULL;
            }
        }
        if (len + 1 >= cap) { cap *= 2; buf = realloc(buf, cap); }
        buf[len++] = c;
    }
    if (ps->p >= ps->end) { ps->failed = 1; free(buf); return NULL; }
    ps->p++; /* closing quote */
    buf[len] = 0;
    return buf;
}

static json_value_t *parse_string(struct parser *ps) {
    char *s = parse_raw_string(ps);
    if (!s) return NULL;
    json_value_t *v = alloc_value(JSON_STRING);
    v->u.string = s;
    return v;
}

static json_value_t *parse_number(struct parser *ps) {
    const char *start = ps->p;
    if (ps->p < ps->end && *ps->p == '-') ps->p++;
    if (ps->p >= ps->end || !isdigit((unsigned char)*ps->p)) { ps->failed = 1; return NULL; }
    while (ps->p < ps->end && isdigit((unsigned char)*ps->p)) ps->p++;
    if (ps->p < ps->end && *ps->p == '.') {
        ps->p++;
        while (ps->p < ps->end && isdigit((unsigned char)*ps->p)) ps->p++;
    }
    char buf[64];
    size_t n = (size_t)(ps->p - start);
    if (n >= sizeof(buf)) { ps->failed = 1; return NULL; }
    memcpy(buf, start, n);
    buf[n] = 0;
    json_value_t *v = alloc_value(JSON_NUMBER);
    v->u.number = strtod(buf, NULL);
    return v;
}

static int literal_at(struct parser *ps, const char *lit) {
    size_t n = strlen(lit);
    if ((size_t)(ps->end - ps->p) < n) return 0;
    return memcmp(ps->p, lit, n) == 0;
}

static json_value_t *parse_array(struct parser *ps) {
    ps->p++; /* '[' */
    json_value_t *v = alloc_value(JSON_ARRAY);
    size_t cap = 4;
    v->u.array.items = malloc(cap * sizeof(json_value_t *));
    v->u.array.len = 0;
    skip_ws(ps);
    if (ps->p < ps->end && *ps->p == ']') { ps->p++; return v; }
    for (;;) {
        skip_ws(ps);
        json_value_t *item = parse_value(ps);
        if (!item) { ps->failed = 1; return NULL; }
        if (v->u.array.len == cap) { cap *= 2; v->u.array.items = realloc(v->u.array.items, cap * sizeof(json_value_t *)); }
        v->u.array.items[v->u.array.len++] = item;
        skip_ws(ps);
        if (ps->p >= ps->end) { ps->failed = 1; return NULL; }
        if (*ps->p == ',') { ps->p++; continue; }
        if (*ps->p == ']') { ps->p++; break; }
        ps->failed = 1; return NULL;
    }
    return v;
}

static json_value_t *parse_object(struct parser *ps) {
    ps->p++; /* '{' */
    json_value_t *v = alloc_value(JSON_OBJECT);
    size_t cap = 4;
    v->u.object.keys = malloc(cap * sizeof(char *));
    v->u.object.values = malloc(cap * sizeof(json_value_t *));
    v->u.object.len = 0;
    skip_ws(ps);
    if (ps->p < ps->end && *ps->p == '}') { ps->p++; return v; }
    for (;;) {
        skip_ws(ps);
        char *key = parse_raw_string(ps);
        if (!key) { ps->failed = 1; return NULL; }
        skip_ws(ps);
        if (ps->p >= ps->end || *ps->p != ':') { ps->failed = 1; free(key); return NULL; }
        ps->p++;
        skip_ws(ps);
        json_value_t *val = parse_value(ps);
        if (!val) { ps->failed = 1; free(key); return NULL; }
        if (v->u.object.len == cap) {
            cap *= 2;
            v->u.object.keys = realloc(v->u.object.keys, cap * sizeof(char *));
            v->u.object.values = realloc(v->u.object.values, cap * sizeof(json_value_t *));
        }
        v->u.object.keys[v->u.object.len] = key;
        v->u.object.values[v->u.object.len] = val;
        v->u.object.len++;
        skip_ws(ps);
        if (ps->p >= ps->end) { ps->failed = 1; return NULL; }
        if (*ps->p == ',') { ps->p++; continue; }
        if (*ps->p == '}') { ps->p++; break; }
        ps->failed = 1; return NULL;
    }
    return v;
}

static json_value_t *parse_value(struct parser *ps) {
    skip_ws(ps);
    if (ps->p >= ps->end) { ps->failed = 1; return NULL; }
    char c = *ps->p;
    if (c == '{') return parse_object(ps);
    if (c == '[') return parse_array(ps);
    if (c == '"') return parse_string(ps);
    if (c == '-' || isdigit((unsigned char)c)) return parse_number(ps);
    if (literal_at(ps, "true")) { ps->p += 4; json_value_t *v = alloc_value(JSON_BOOL); v->u.boolean = 1; return v; }
    if (literal_at(ps, "false")) { ps->p += 5; json_value_t *v = alloc_value(JSON_BOOL); v->u.boolean = 0; return v; }
    if (literal_at(ps, "null")) { ps->p += 4; return alloc_value(JSON_NULL); }
    ps->failed = 1;
    return NULL;
}

json_value_t *json_parse(const char *text, size_t len) {
    struct parser ps = { .p = text, .end = text + len, .failed = 0 };
    json_value_t *v = parse_value(&ps);
    if (!v || ps.failed) { if (v) json_free(v); return NULL; }
    skip_ws(&ps);
    if (ps.p != ps.end) { json_free(v); return NULL; } /* trailing garbage */
    return v;
}

void json_free(json_value_t *v) {
    if (!v) return;
    switch (v->type) {
        case JSON_STRING:
            free(v->u.string);
            break;
        case JSON_ARRAY:
            for (size_t i = 0; i < v->u.array.len; i++) json_free(v->u.array.items[i]);
            free(v->u.array.items);
            break;
        case JSON_OBJECT:
            for (size_t i = 0; i < v->u.object.len; i++) {
                free(v->u.object.keys[i]);
                json_free(v->u.object.values[i]);
            }
            free(v->u.object.keys);
            free(v->u.object.values);
            break;
        default:
            break;
    }
    free(v);
}

json_value_t *json_object_get(json_value_t *obj, const char *key) {
    if (!obj || obj->type != JSON_OBJECT) return NULL;
    for (size_t i = 0; i < obj->u.object.len; i++) {
        if (strcmp(obj->u.object.keys[i], key) == 0) return obj->u.object.values[i];
    }
    return NULL;
}

size_t json_array_len(json_value_t *arr) {
    if (!arr || arr->type != JSON_ARRAY) return 0;
    return arr->u.array.len;
}

json_value_t *json_array_get(json_value_t *arr, size_t i) {
    if (!arr || arr->type != JSON_ARRAY || i >= arr->u.array.len) return NULL;
    return arr->u.array.items[i];
}

const char *json_as_string(json_value_t *v) {
    if (!v || v->type != JSON_STRING) return NULL;
    return v->u.string;
}

int json_as_int64(json_value_t *v, int64_t *out) {
    if (!v || v->type != JSON_NUMBER) return -1;
    double d = v->u.number;
    int64_t truncated = (int64_t)d;
    if ((double)truncated != d) return -1;
    *out = truncated;
    return 0;
}
```

- [ ] **Step 5: Run to verify `test_json` passes** (it will fail to fully run because `run_c_tests.sh` also tries to build `config.c`/`test_config.c`, which don't exist yet — run the `json` half directly instead)

Run: `cd runtime/images/guest-exec-relay && cc -Wall -Wextra -std=c11 -g -o /tmp/test_json src/json.c tests/test_json.c && /tmp/test_json`
Expected: PASS — `test_json: all tests passed`.

- [ ] **Step 6: Commit**

```bash
cd runtime && git add images/guest-exec-relay/src/json.h images/guest-exec-relay/src/json.c images/guest-exec-relay/tests/test_json.c images/guest-exec-relay/tests/run_c_tests.sh
git commit -m "feat: add minimal JSON parser for the guest exec-relay's config"
```

---

### Task 3: C config loader — JSON to rule structs, argv matching

**Files:**
- Create: `runtime/images/guest-exec-relay/src/config.h`
- Create: `runtime/images/guest-exec-relay/src/config.c`
- Test: `runtime/images/guest-exec-relay/tests/test_config.c`

**Interfaces:**
- Consumes: `json_parse`/`json_object_get`/`json_array_len`/`json_array_get`/`json_as_string`/`json_as_int64` (Task 2).
- Produces: `struct exec_rule` (`name`, `match_kind` enum `MATCH_PREFIX|MATCH_EXACT|MATCH_ARGV0`, `match_argv`/`match_argv0`, `verb` enum `VERB_SUBSTITUTE|VERB_REWRITE|VERB_FABRICATE`, verb payload fields), `struct exec_plan` (`rules`, `n_rules`, `timeout_ms`, `max_concurrent_handlers`), `int config_load_from_env(struct exec_plan *out)` (0 on success, -1 on any error — matching the "fails closed" design principle, this is the function `main()` in Task 4 calls, and a -1 return means `execrelayd` must refuse to start), `const struct exec_rule *config_match(const struct exec_plan *plan, char *const argv[], int argc)` (NULL = passthrough). Used by Task 4/5's `relayd.c`.

- [ ] **Step 1: Write `config.h`**

```c
#ifndef EXEC_RELAY_CONFIG_H
#define EXEC_RELAY_CONFIG_H

#include <stdint.h>

#define EXEC_RELAY_MAX_RULES 64
#define EXEC_RELAY_MAX_ARGV 32
#define EXEC_RELAY_MAX_FABRICATE_BYTES 2000

typedef enum { MATCH_PREFIX, MATCH_EXACT, MATCH_ARGV0 } match_kind_t;
typedef enum { VERB_SUBSTITUTE, VERB_REWRITE, VERB_FABRICATE } verb_kind_t;

struct exec_rule {
    char name[128];
    match_kind_t match_kind;
    char match_argv[EXEC_RELAY_MAX_ARGV][256];
    int match_argv_len;      /* used by MATCH_PREFIX / MATCH_EXACT */
    char match_argv0[256];   /* used by MATCH_ARGV0 */

    verb_kind_t verb;
    /* VERB_SUBSTITUTE */
    char replacement_argv[EXEC_RELAY_MAX_ARGV][256];
    int replacement_argv_len;
    /* VERB_REWRITE */
    char stdout_find[512];
    char stdout_replace[512];
    char stderr_find[512];
    char stderr_replace[512];
    int has_stdout_rewrite;
    int has_stderr_rewrite;
    /* VERB_FABRICATE */
    int32_t fabricate_exit_code;
    char fabricate_stdout[EXEC_RELAY_MAX_FABRICATE_BYTES];
    uint32_t fabricate_stdout_len;
    char fabricate_stderr[EXEC_RELAY_MAX_FABRICATE_BYTES];
    uint32_t fabricate_stderr_len;
};

struct exec_plan {
    struct exec_rule rules[EXEC_RELAY_MAX_RULES];
    int n_rules;
    uint64_t timeout_ms;
    uint32_t max_concurrent_handlers;
};

/* Reads CHAMBER_EXEC_CONSEQUENCE_SPEC_B64 from the environment, base64-decodes
 * and JSON-parses it, and populates *out. Returns 0 on success. Returns -1 on
 * any error (env var absent, bad base64, bad JSON, or a value exceeding one
 * of the fixed-size buffers above) — the caller (execrelayd's main) must
 * refuse to start rather than fall back to an empty/passthrough plan, so a
 * misconfiguration is never silently indistinguishable from "no config". */
int config_load_from_env(struct exec_plan *out);

/* Parses `json_text` directly (used by tests, bypassing the env var + base64
 * decode step exercised separately by relayd.c's own startup path). */
int config_load_from_json(const char *json_text, size_t len, struct exec_plan *out);

/* First rule whose matcher matches argv[0..argc). NULL = passthrough. */
const struct exec_rule *config_match(const struct exec_plan *plan, char *const argv[], int argc);

#endif
```

- [ ] **Step 2: Write the failing tests**

```c
// runtime/images/guest-exec-relay/tests/test_config.c
#include <assert.h>
#include <string.h>
#include <stdio.h>
#include "../src/config.h"

static void test_loads_empty_rules_with_defaults(void) {
    const char *json = "{\"rules\":[]}";
    struct exec_plan plan;
    int rc = config_load_from_json(json, strlen(json), &plan);
    assert(rc == 0);
    assert(plan.n_rules == 0);
    assert(plan.timeout_ms == 60000);
    assert(plan.max_concurrent_handlers == 32);
}

static void test_loads_fabricate_rule(void) {
    const char *json =
        "{\"rules\":[{\"name\":\"fake-pip\","
        "\"match_argv\":{\"type\":\"argv0\",\"name\":\"pip\"},"
        "\"verb\":{\"type\":\"fabricate\",\"exit_code\":0,\"stdout\":\"ok\",\"stderr\":\"\"}}]}";
    struct exec_plan plan;
    int rc = config_load_from_json(json, strlen(json), &plan);
    assert(rc == 0);
    assert(plan.n_rules == 1);
    assert(strcmp(plan.rules[0].name, "fake-pip") == 0);
    assert(plan.rules[0].match_kind == MATCH_ARGV0);
    assert(strcmp(plan.rules[0].match_argv0, "pip") == 0);
    assert(plan.rules[0].verb == VERB_FABRICATE);
    assert(plan.rules[0].fabricate_exit_code == 0);
    assert(strcmp(plan.rules[0].fabricate_stdout, "ok") == 0);
}

static void test_loads_substitute_rule(void) {
    const char *json =
        "{\"rules\":[{\"name\":\"s\","
        "\"match_argv\":{\"type\":\"prefix\",\"argv\":[\"pip\",\"install\"]},"
        "\"verb\":{\"type\":\"substitute\",\"replacement_argv\":[\"/opt/pkg/fake\"]}}]}";
    struct exec_plan plan;
    int rc = config_load_from_json(json, strlen(json), &plan);
    assert(rc == 0);
    assert(plan.rules[0].match_kind == MATCH_PREFIX);
    assert(plan.rules[0].match_argv_len == 2);
    assert(strcmp(plan.rules[0].match_argv[0], "pip") == 0);
    assert(strcmp(plan.rules[0].match_argv[1], "install") == 0);
    assert(plan.rules[0].verb == VERB_SUBSTITUTE);
    assert(strcmp(plan.rules[0].replacement_argv[0], "/opt/pkg/fake") == 0);
}

static void test_rejects_malformed_json(void) {
    struct exec_plan plan;
    assert(config_load_from_json("not json", 8, &plan) == -1);
}

static void test_matches_prefix(void) {
    const char *json =
        "{\"rules\":[{\"name\":\"s\","
        "\"match_argv\":{\"type\":\"prefix\",\"argv\":[\"pip\",\"install\"]},"
        "\"verb\":{\"type\":\"fabricate\",\"exit_code\":0,\"stdout\":\"\",\"stderr\":\"\"}}]}";
    struct exec_plan plan;
    config_load_from_json(json, strlen(json), &plan);
    char *argv1[] = {"pip", "install", "foo"};
    assert(config_match(&plan, argv1, 3) != NULL);
    char *argv2[] = {"pip", "uninstall", "foo"};
    assert(config_match(&plan, argv2, 3) == NULL);
    char *argv3[] = {"pip"};
    assert(config_match(&plan, argv3, 1) == NULL); /* too short to match the 2-element prefix */
}

static void test_first_match_wins(void) {
    const char *json =
        "{\"rules\":["
        "{\"name\":\"narrow\",\"match_argv\":{\"type\":\"exact\",\"argv\":[\"pip\",\"install\",\"x\"]},"
        "\"verb\":{\"type\":\"fabricate\",\"exit_code\":0,\"stdout\":\"narrow\",\"stderr\":\"\"}},"
        "{\"name\":\"broad\",\"match_argv\":{\"type\":\"argv0\",\"name\":\"pip\"},"
        "\"verb\":{\"type\":\"fabricate\",\"exit_code\":0,\"stdout\":\"broad\",\"stderr\":\"\"}}"
        "]}";
    struct exec_plan plan;
    config_load_from_json(json, strlen(json), &plan);
    char *argv[] = {"pip", "install", "x"};
    const struct exec_rule *matched = config_match(&plan, argv, 3);
    assert(matched != NULL);
    assert(strcmp(matched->name, "narrow") == 0);
}

int main(void) {
    test_loads_empty_rules_with_defaults();
    test_loads_fabricate_rule();
    test_loads_substitute_rule();
    test_rejects_malformed_json();
    test_matches_prefix();
    test_first_match_wins();
    printf("test_config: all tests passed\n");
    return 0;
}
```

- [ ] **Step 3: Run to verify it fails to build**

Run: `cd runtime/images/guest-exec-relay && cc -Wall -Wextra -std=c11 -g -o /tmp/test_config src/json.c src/config.c tests/test_config.c`
Expected: FAIL — `src/config.c` doesn't exist yet.

- [ ] **Step 4: Implement `config.c`**

```c
// runtime/images/guest-exec-relay/src/config.c
#include "config.h"
#include "json.h"
#include <string.h>
#include <stdlib.h>
#include <stdio.h>

static int copy_str(char *dst, size_t dstsz, const char *src) {
    if (!src) return -1;
    size_t n = strlen(src);
    if (n >= dstsz) return -1;
    memcpy(dst, src, n + 1);
    return 0;
}

static int load_match_argv(json_value_t *matcher, struct exec_rule *rule) {
    const char *type = json_as_string(json_object_get(matcher, "type"));
    if (!type) return -1;
    if (strcmp(type, "argv0") == 0) {
        rule->match_kind = MATCH_ARGV0;
        return copy_str(rule->match_argv0, sizeof(rule->match_argv0),
                         json_as_string(json_object_get(matcher, "name")));
    }
    json_value_t *argv_arr = json_object_get(matcher, "argv");
    size_t n = json_array_len(argv_arr);
    if (n == 0 || n > EXEC_RELAY_MAX_ARGV) return -1;
    for (size_t i = 0; i < n; i++) {
        if (copy_str(rule->match_argv[i], sizeof(rule->match_argv[i]),
                      json_as_string(json_array_get(argv_arr, i))) != 0) {
            return -1;
        }
    }
    rule->match_argv_len = (int)n;
    if (strcmp(type, "prefix") == 0) { rule->match_kind = MATCH_PREFIX; return 0; }
    if (strcmp(type, "exact") == 0) { rule->match_kind = MATCH_EXACT; return 0; }
    return -1;
}

static int load_verb(json_value_t *verb, struct exec_rule *rule) {
    const char *type = json_as_string(json_object_get(verb, "type"));
    if (!type) return -1;
    if (strcmp(type, "substitute") == 0) {
        rule->verb = VERB_SUBSTITUTE;
        json_value_t *argv_arr = json_object_get(verb, "replacement_argv");
        size_t n = json_array_len(argv_arr);
        if (n == 0 || n > EXEC_RELAY_MAX_ARGV) return -1;
        for (size_t i = 0; i < n; i++) {
            if (copy_str(rule->replacement_argv[i], sizeof(rule->replacement_argv[i]),
                          json_as_string(json_array_get(argv_arr, i))) != 0) {
                return -1;
            }
        }
        rule->replacement_argv_len = (int)n;
        return 0;
    }
    if (strcmp(type, "rewrite") == 0) {
        rule->verb = VERB_REWRITE;
        json_value_t *sf = json_object_get(verb, "stdout_find");
        json_value_t *sr = json_object_get(verb, "stdout_replace");
        if (sf && sr) {
            rule->has_stdout_rewrite = 1;
            if (copy_str(rule->stdout_find, sizeof(rule->stdout_find), json_as_string(sf)) != 0) return -1;
            if (copy_str(rule->stdout_replace, sizeof(rule->stdout_replace), json_as_string(sr)) != 0) return -1;
        }
        json_value_t *ef = json_object_get(verb, "stderr_find");
        json_value_t *er = json_object_get(verb, "stderr_replace");
        if (ef && er) {
            rule->has_stderr_rewrite = 1;
            if (copy_str(rule->stderr_find, sizeof(rule->stderr_find), json_as_string(ef)) != 0) return -1;
            if (copy_str(rule->stderr_replace, sizeof(rule->stderr_replace), json_as_string(er)) != 0) return -1;
        }
        return 0;
    }
    if (strcmp(type, "fabricate") == 0) {
        rule->verb = VERB_FABRICATE;
        int64_t code;
        if (json_as_int64(json_object_get(verb, "exit_code"), &code) != 0) return -1;
        rule->fabricate_exit_code = (int32_t)code;
        const char *out = json_as_string(json_object_get(verb, "stdout"));
        const char *err = json_as_string(json_object_get(verb, "stderr"));
        if (!out) out = "";
        if (!err) err = "";
        size_t outlen = strlen(out), errlen = strlen(err);
        if (outlen >= EXEC_RELAY_MAX_FABRICATE_BYTES || errlen >= EXEC_RELAY_MAX_FABRICATE_BYTES) return -1;
        memcpy(rule->fabricate_stdout, out, outlen + 1);
        rule->fabricate_stdout_len = (uint32_t)outlen;
        memcpy(rule->fabricate_stderr, err, errlen + 1);
        rule->fabricate_stderr_len = (uint32_t)errlen;
        return 0;
    }
    return -1;
}

int config_load_from_json(const char *json_text, size_t len, struct exec_plan *out) {
    memset(out, 0, sizeof(*out));
    out->timeout_ms = 60000;
    out->max_concurrent_handlers = 32;

    json_value_t *root = json_parse(json_text, len);
    if (!root) return -1;

    json_value_t *timeout = json_object_get(root, "timeout_ms");
    if (timeout) {
        int64_t v;
        if (json_as_int64(timeout, &v) != 0 || v <= 0) { json_free(root); return -1; }
        out->timeout_ms = (uint64_t)v;
    }
    json_value_t *maxconc = json_object_get(root, "max_concurrent_handlers");
    if (maxconc) {
        int64_t v;
        if (json_as_int64(maxconc, &v) != 0 || v <= 0) { json_free(root); return -1; }
        out->max_concurrent_handlers = (uint32_t)v;
    }

    json_value_t *rules = json_object_get(root, "rules");
    size_t n = json_array_len(rules);
    if (n > EXEC_RELAY_MAX_RULES) { json_free(root); return -1; }
    for (size_t i = 0; i < n; i++) {
        json_value_t *r = json_array_get(rules, i);
        struct exec_rule *rule = &out->rules[i];
        memset(rule, 0, sizeof(*rule));
        const char *name = json_as_string(json_object_get(r, "name"));
        if (!name || name[0] == '\0' || copy_str(rule->name, sizeof(rule->name), name) != 0) {
            json_free(root); return -1;
        }
        if (load_match_argv(json_object_get(r, "match_argv"), rule) != 0) { json_free(root); return -1; }
        if (load_verb(json_object_get(r, "verb"), rule) != 0) { json_free(root); return -1; }
    }
    out->n_rules = (int)n;

    json_free(root);
    return 0;
}

int config_load_from_env(struct exec_plan *out) {
    const char *b64 = getenv("CHAMBER_EXEC_CONSEQUENCE_SPEC_B64");
    if (!b64) return -1;

    /* Minimal base64 decode — standard alphabet, '=' padding. The Rust side
     * (Task 1) is the source of truth for what gets encoded; this decoder
     * only needs to invert it, not accept arbitrary base64 dialects. */
    static const signed char T[256] = {
        ['A']=0,['B']=1,['C']=2,['D']=3,['E']=4,['F']=5,['G']=6,['H']=7,['I']=8,['J']=9,
        ['K']=10,['L']=11,['M']=12,['N']=13,['O']=14,['P']=15,['Q']=16,['R']=17,['S']=18,['T']=19,
        ['U']=20,['V']=21,['W']=22,['X']=23,['Y']=24,['Z']=25,
        ['a']=26,['b']=27,['c']=28,['d']=29,['e']=30,['f']=31,['g']=32,['h']=33,['i']=34,['j']=35,
        ['k']=36,['l']=37,['m']=38,['n']=39,['o']=40,['p']=41,['q']=42,['r']=43,['s']=44,['t']=45,
        ['u']=46,['v']=47,['w']=48,['x']=49,['y']=50,['z']=51,
        ['0']=52,['1']=53,['2']=54,['3']=55,['4']=56,['5']=57,['6']=58,['7']=59,['8']=60,['9']=61,
        ['+']=62,['/']=63,
    };
    size_t inlen = strlen(b64);
    char *decoded = malloc(inlen); /* decoded is always <= inlen bytes */
    size_t outlen = 0;
    int val = 0, valb = -8;
    for (size_t i = 0; i < inlen; i++) {
        unsigned char c = (unsigned char)b64[i];
        if (c == '=' || c == '\n' || c == '\r') continue;
        signed char d = T[c];
        if (d < 0 && c != 'A') { free(decoded); return -1; } /* 'A' maps validly to 0 */
        val = (val << 6) | d;
        valb += 6;
        if (valb >= 0) {
            decoded[outlen++] = (char)((val >> valb) & 0xFF);
            valb -= 8;
        }
    }
    int rc = config_load_from_json(decoded, outlen, out);
    free(decoded);
    return rc;
}

static int argv_matches(char *const argv[], int argc, char (*want)[256], int want_len) {
    if (argc < want_len) return 0;
    for (int i = 0; i < want_len; i++) {
        if (strcmp(argv[i], want[i]) != 0) return 0;
    }
    return 1;
}

const struct exec_rule *config_match(const struct exec_plan *plan, char *const argv[], int argc) {
    for (int i = 0; i < plan->n_rules; i++) {
        const struct exec_rule *rule = &plan->rules[i];
        int matched = 0;
        switch (rule->match_kind) {
            case MATCH_ARGV0:
                matched = (argc >= 1) && strcmp(argv[0], rule->match_argv0) == 0;
                break;
            case MATCH_PREFIX:
                matched = argv_matches(argv, argc, (char (*)[256])rule->match_argv, rule->match_argv_len);
                break;
            case MATCH_EXACT:
                matched = (argc == rule->match_argv_len) &&
                          argv_matches(argv, argc, (char (*)[256])rule->match_argv, rule->match_argv_len);
                break;
        }
        if (matched) return rule;
    }
    return NULL;
}
```

- [ ] **Step 5: Run to verify it passes**

Run: `cd runtime/images/guest-exec-relay && cc -Wall -Wextra -std=c11 -g -o /tmp/test_config src/json.c src/config.c tests/test_config.c && /tmp/test_config`
Expected: PASS — `test_config: all tests passed`.

- [ ] **Step 6: Commit**

```bash
cd runtime && git add images/guest-exec-relay/src/config.h images/guest-exec-relay/src/config.c images/guest-exec-relay/tests/test_config.c
git commit -m "feat: add config loader + rule matcher for the guest exec-relay"
```

---

### Task 4: `relayd.c` core — ptrace/seccomp interception + verb dispatch

**Files:**
- Create: `runtime/images/guest-exec-relay/src/relayd.c`

**Interfaces:**
- Consumes: `config_load_from_env`, `config_match`, `struct exec_plan`/`struct exec_rule` (Task 3).
- Produces: the `execrelayd` binary's `run_traced()` function (adapted from the proven spike at `/tmp/cc-spike-ptrace-relay/relayd.c`) and `install_seccomp_filter()`, `read_tracee_str()`, `write_tracee_mem()`, `get_regs()`/`set_regs()` helpers — all reused verbatim from the spike, which already empirically validated this exact mechanism against this repo's real Colima/Docker environment. This task adds verb dispatch (substitute/fabricate/rewrite) in place of the spike's hardcoded two-entry `RULES[]` table. Task 5 adds concurrency, the watchdog, and the disclosure log on top of this file.

This task has no isolated unit-test story of its own (it requires a real traced process, which needs Docker) — it's verified by Task 5's Dockerfile build plus Task 12's integration tests. Steps here are "adapt and verify it compiles cleanly," not TDD in the strict red/green sense — the underlying mechanism was already proven correct empirically in the mechanism-research spikes; this task's job is transcribing that proof into the production file structure without changing its behavior, plus adding the new verb logic.

- [ ] **Step 1: Create `relayd.c` with the proven low-level primitives, unchanged from the spike**

Copy these functions verbatim into `runtime/images/guest-exec-relay/src/relayd.c` (from `/tmp/cc-spike-ptrace-relay/relayd.c`, lines 1–160): the includes, `struct arm64_regs`, `logline`, `write_full`, `read_full`, `read_line`, the `TAG_STDOUT`/`TAG_STDERR`/`TAG_EXIT` frame constants, `send_frame`, `read_tracee_str`, `write_tracee_mem`, `get_regs`, `set_regs`, and `install_seccomp_filter`. Add `#include "config.h"` and `#include "json.h"` to the includes block. Remove the spike's hardcoded `struct rule RULES[]` table and its `#define NRULES` — rule matching now comes from `config_match` (Task 3).

**One value to change while copying, not left as-is:** the spike defines `#define SCRATCH_SIZE 4096`. That was sized only for a short replacement path (`substitute`). Task 4 Step 2 splits this same buffer in half for `fabricate` (mode byte + a 12-byte header + up to 2000 bytes of stdout + up to 2000 bytes of stderr, per the `FabricatePayloadTooLarge` cap validated in Task 1 — up to 4013 bytes) and the substitute/sentinel path — half of 4096 (2048 bytes) is not enough room for a 4013-byte fabricate payload and would silently overflow a stack buffer in Task 4 Step 3's dispatch code. Change it to:

```c
#define SCRATCH_SIZE 16384
```

(16 KiB halves to 8 KiB per region — comfortable headroom over the ~4 KiB fabricate case and any realistic substitute/sentinel path, in both the worker's static scratch buffer and the handler's stack-allocated dispatch buffer from Task 4 Step 3.)

- [ ] **Step 2: Add the scratch-buffer verb protocol**

```c
/* Scratch-buffer protocol between the tracer (this file) and the traced
 * worker (also this file, running post-fork — see run_traced below). The
 * tracer writes into the worker's own memory via /proc/pid/mem before
 * resuming a trapped execve; the worker's post-execve-failure code (which
 * only runs if the syscall did not actually succeed) reads it back to know
 * whether a "failure" was real or an intentional fabricate. */
#define SCRATCH_MODE_NONE       0
#define SCRATCH_MODE_SUBSTITUTE 1
#define SCRATCH_MODE_FABRICATE  2

struct fabricate_payload {
    int32_t exit_code;
    uint32_t stdout_len;
    uint32_t stderr_len;
    /* followed by stdout_len bytes of stdout, then stderr_len bytes of stderr */
};

/* Fabricate payloads (mode + header + stdout+stderr bytes) live in the first
 * half of the scratch buffer; a substitute path or the fabricate sentinel
 * path lives in the second half, so the two never collide even though both
 * are written for a single trapped syscall in the fabricate case. */
#define SCRATCH_PAYLOAD_OFFSET 0
#define SCRATCH_PATH_OFFSET (SCRATCH_SIZE / 2)

/* Reads the NULL-terminated argv[] pointer array at `argv_addr` in the
 * tracee's memory (the execve/execveat syscall's own argv argument — NOT
 * the top-level command run_traced() was started with, which for a forked
 * grandchild's own exec is a different, unrelated array). Rule matching
 * needs THIS array: config_match's Prefix/Exact matchers compare multiple
 * argv entries, and the trap only hands the tracer a resolved pathname
 * directly (`reqpath`, read separately) — it does not hand over argv at
 * all unless something goes and reads it, which is what this does. Resolves
 * up to `max_n` entries (each truncated to 255 bytes, which is generous for
 * argv entries used in matching) into `out[]`. Returns the count read. */
static int read_tracee_argv(int pid, unsigned long long argv_addr, char out[][256], int max_n) {
    char path[64];
    snprintf(path, sizeof(path), "/proc/%d/mem", pid);
    int fd = open(path, O_RDONLY);
    if (fd < 0) return 0;
    int n = 0;
    while (n < max_n) {
        unsigned long long ptr = 0;
        if (pread(fd, &ptr, sizeof(ptr), (off_t)(argv_addr + (unsigned long long)n * sizeof(ptr)))
            != (ssize_t)sizeof(ptr)) {
            break;
        }
        if (ptr == 0) break; /* NULL terminator */
        ssize_t got = pread(fd, out[n], 255, (off_t)ptr);
        size_t len = got > 0 ? strnlen(out[n], (size_t)got) : 0;
        out[n][len] = 0;
        n++;
    }
    close(fd);
    return n;
}
```

- [ ] **Step 3: Rewrite the seccomp-trap handling block to dispatch on the matched rule's verb**

Replace the spike's rule-lookup block (the `for (size_t i = 0; i < NRULES; i++) { ... }` loop inside the `SIGTRAP && event == PTRACE_EVENT_SECCOMP` branch of `run_traced`) with:

```c
                        /* argv is the 2nd execve arg (x1) or the 3rd execveat
                         * arg (x2, since execveat's signature inserts dirfd
                         * before pathname) — read fresh on every trap, since
                         * a forked grandchild's own exec (coverage: nested
                         * subprocesses) needs ITS OWN argv, not whatever the
                         * top-level command started with. */
                        unsigned long long argv_ptr_reg = is_execveat ? regs.regs[2] : regs.regs[1];
                        char tracee_argv[EXEC_RELAY_MAX_ARGV][256];
                        int tracee_argc = read_tracee_argv(pid, argv_ptr_reg, tracee_argv, EXEC_RELAY_MAX_ARGV);
                        char *argv_ptrs[EXEC_RELAY_MAX_ARGV];
                        for (int ai = 0; ai < tracee_argc; ai++) argv_ptrs[ai] = tracee_argv[ai];

                        const struct exec_rule *rule = config_match(plan, argv_ptrs, tracee_argc);
                        const char *rule_name = rule ? rule->name : "fallback";
                        const char *verb_name = "passthrough";
                        char detail[1200] = "-";

                        if (!rule) {
                            /* passthrough: leave the syscall untouched */
                        } else if (rule->verb == VERB_SUBSTITUTE) {
                            verb_name = "substitute";
                            const char *replacement = rule->replacement_argv[0];
                            size_t rl = strlen(replacement) + 1;
                            if (rl <= (SCRATCH_SIZE - SCRATCH_PATH_OFFSET) && scratch_addr) {
                                write_tracee_mem(pid, scratch_addr + SCRATCH_PATH_OFFSET, replacement, rl);
                                if (is_execveat) regs.regs[1] = scratch_addr + SCRATCH_PATH_OFFSET;
                                else regs.regs[0] = scratch_addr + SCRATCH_PATH_OFFSET;
                                set_regs(pid, &regs);
                                snprintf(detail, sizeof(detail), "%s", replacement);
                            } else {
                                verb_name = "substitute-failed-scratch-too-small";
                            }
                        } else if (rule->verb == VERB_FABRICATE) {
                            verb_name = "fabricate";
                            uint8_t mode = SCRATCH_MODE_FABRICATE;
                            struct fabricate_payload pl = {
                                .exit_code = rule->fabricate_exit_code,
                                .stdout_len = rule->fabricate_stdout_len,
                                .stderr_len = rule->fabricate_stderr_len,
                            };
                            uint8_t buf[SCRATCH_PATH_OFFSET];
                            size_t off = 0;
                            memcpy(buf + off, &mode, 1); off += 1;
                            memcpy(buf + off, &pl, sizeof(pl)); off += sizeof(pl);
                            memcpy(buf + off, rule->fabricate_stdout, pl.stdout_len); off += pl.stdout_len;
                            memcpy(buf + off, rule->fabricate_stderr, pl.stderr_len); off += pl.stderr_len;
                            write_tracee_mem(pid, scratch_addr + SCRATCH_PAYLOAD_OFFSET, buf, off);
                            static const char SENTINEL[] = "/.exec-consequence-fabricate-sentinel";
                            write_tracee_mem(pid, scratch_addr + SCRATCH_PATH_OFFSET, SENTINEL, sizeof(SENTINEL));
                            if (is_execveat) regs.regs[1] = scratch_addr + SCRATCH_PATH_OFFSET;
                            else regs.regs[0] = scratch_addr + SCRATCH_PATH_OFFSET;
                            set_regs(pid, &regs);
                            snprintf(detail, sizeof(detail), "exit=%d stdout_len=%u stderr_len=%u",
                                     pl.exit_code, pl.stdout_len, pl.stderr_len);
                        } else if (rule->verb == VERB_REWRITE) {
                            /* Real exec proceeds untouched; the transform is applied to
                             * the piped output in the parent's poll loop (Task 5), not
                             * here — this trap only needs to record which rule fired. */
                            verb_name = "rewrite";
                            snprintf(detail, sizeof(detail), "stdout_find=%s",
                                      rule->has_stdout_rewrite ? rule->stdout_find : "(none)");
                        }

                        logline("req=%s pid=%d syscall=%s requested=%s verb=%s rule=%s detail=%s",
                                req_id?req_id:"-", pid, is_execveat?"execveat":"execve",
                                reqpath, verb_name, rule_name, detail);
                        disclosure_record(req_id, reqpath, rule_name, verb_name, detail);
                        active_rewrite = (rule && rule->verb == VERB_REWRITE) ? rule : NULL;
                        ptrace(PTRACE_CONT, pid, 0, 0);
```

Note `plan` (needed by `config_match`) and `active_rewrite` (needed by Task 5's rewrite output transform) must be threaded into `run_traced`'s signature — Task 5 makes this change alongside the concurrency fix, since both touch the same function boundary. `disclosure_record(...)` is defined in Task 5.

- [ ] **Step 4: Extend the worker's post-execve code to handle a fabricated failure**

Replace the spike's worker-side post-`execve` block:

```c
        execve(argv[0], argv, envp);
        /* execve only returns on error */
        fprintf(stderr, "relay: execve(%s) failed: %s\n", argv[0], strerror(errno));
        _exit(127);
```

with:

```c
        execve(argv[0], argv, envp);
        /* execve only returns on error. Check whether the tracer left a
         * fabricate payload in our own scratch buffer before assuming this
         * is a genuine failure. */
        {
            uint8_t mode = ((uint8_t *)scratch)[SCRATCH_PAYLOAD_OFFSET];
            if (mode == SCRATCH_MODE_FABRICATE) {
                struct fabricate_payload pl;
                memcpy(&pl, scratch + SCRATCH_PAYLOAD_OFFSET + 1, sizeof(pl));
                const uint8_t *out = (const uint8_t *)scratch + SCRATCH_PAYLOAD_OFFSET + 1 + sizeof(pl);
                const uint8_t *err = out + pl.stdout_len;
                if (pl.stdout_len) write_full(STDOUT_FILENO, out, pl.stdout_len);
                if (pl.stderr_len) write_full(STDERR_FILENO, err, pl.stderr_len);
                _exit(pl.exit_code);
            }
        }
        fprintf(stderr, "relay: execve(%s) failed: %s\n", argv[0], strerror(errno));
        _exit(127);
```

- [ ] **Step 5: Verify it compiles (linking will fail — `config_match`/`disclosure_record`/`active_rewrite` aren't fully wired until Task 5 — this step only confirms no syntax errors)**

Run: `cd runtime/images/guest-exec-relay && cc -c -Wall -Wextra -std=c11 -o /tmp/relayd.o src/relayd.c 2>&1 | head -40`
Expected: compiler errors naming only the not-yet-defined symbols from Task 5 (`disclosure_record`, `active_rewrite`, the updated `run_traced` signature) — no syntax errors in what this task added. Fix any real syntax errors found; leave the "undefined symbol" class of errors for Task 5 to resolve.

- [ ] **Step 6: Commit**

```bash
cd runtime && git add images/guest-exec-relay/src/relayd.c
git commit -m "feat: port proven ptrace+seccomp exec interception into production relayd.c with verb dispatch"
```

---

### Task 5: `relayd.c` — concurrency fix, watchdog timeout, disclosure log

**Files:**
- Modify: `runtime/images/guest-exec-relay/src/relayd.c`

**Interfaces:**
- Consumes: `struct exec_plan` (Task 3), the `run_traced`/verb-dispatch code from Task 4.
- Produces: the completed `execrelayd` binary — `main()`, `run_server()` (fork-per-connection), `handle_conn()`, `disclosure_record()`, the per-request watchdog. This is what Task 7's Dockerfile compiles and what Task 12's integration tests exercise directly.

This is the task that exists because of the concurrency bug an adversarial review found in the original spike (a single blocking `accept()` loop let one hung command wedge every other concurrent request indefinitely, with no timeout). Every step below is either the fix for that or the disclosure/timeout machinery the design requires around it.

- [ ] **Step 1: Add the disclosure log writer**

```c
/* ---------------------------- disclosure log ---------------------------- */
#define DISCLOSURE_LOG_PATH "/work/.execrelay.log"
static int g_disclosure_fd = -1;

static void disclosure_init(void) {
    g_disclosure_fd = open(DISCLOSURE_LOG_PATH, O_CREAT | O_WRONLY | O_APPEND, 0600);
    if (g_disclosure_fd < 0) { perror("disclosure: open"); return; }
    static const char header[] =
        "{\"known_residual_tells\":[\"TracerPid nonzero in /proc/self/status "
        "\\u2014 structural to ptrace, not masked\"]}\n";
    write_full(g_disclosure_fd, header, sizeof(header) - 1);
}

/* Minimal, allocation-free JSON string escaping for the handful of fields we
 * emit here (argv entries, rule names, free-form `detail` text) — backslash
 * and double-quote are the only bytes this schema's own values can contain
 * that would break JSON (argv/name/detail never carry control characters in
 * practice; this only needs to not corrupt the log, not be a general escaper). */
static void write_json_escaped(int fd, const char *s) {
    char buf[4096];
    size_t o = 0;
    for (; *s && o < sizeof(buf) - 2; s++) {
        if (*s == '"' || *s == '\\') { buf[o++] = '\\'; }
        buf[o++] = *s;
    }
    write_full(fd, buf, o);
}

static void disclosure_record(const char *turn_id, const char *requested_argv0,
                               const char *matched_rule, const char *verb_applied,
                               const char *detail) {
    if (g_disclosure_fd < 0) return;
    struct timespec ts; clock_gettime(CLOCK_REALTIME, &ts);
    char pre[256];
    int n = snprintf(pre, sizeof(pre),
        "{\"turn_id\":\"%s\",\"timestamp\":%ld.%03ld,\"requested_argv0\":\"",
        turn_id ? turn_id : "-", (long)ts.tv_sec, ts.tv_nsec / 1000000);
    write_full(g_disclosure_fd, pre, (size_t)n);
    write_json_escaped(g_disclosure_fd, requested_argv0);
    char mid[256];
    n = snprintf(mid, sizeof(mid), "\",\"matched_rule\":\"%s\",\"verb_applied\":\"%s\",\"detail\":\"",
                 matched_rule, verb_applied);
    write_full(g_disclosure_fd, mid, (size_t)n);
    write_json_escaped(g_disclosure_fd, detail);
    static const char tail[] = "\"}\n";
    write_full(g_disclosure_fd, tail, sizeof(tail) - 1);
}
```

- [ ] **Step 2: Thread `plan`, `active_rewrite`, and `timeout_ms` through `run_traced`**

Change `run_traced`'s signature from the spike's:

```c
static int run_traced(char *const argv[], char *const envp_extra[], int envp_extra_n,
                       const char *req_id, int out_fd, int err_fd, int *exit_code_out) {
```

to:

```c
static int run_traced(char *const argv[], char *const envp_extra[], int envp_extra_n,
                       const char *req_id, int out_fd, int err_fd, int *exit_code_out,
                       const struct exec_plan *plan, uint64_t timeout_ms) {
    const struct exec_rule *active_rewrite = NULL;
```

No `argc` parameter is added here — the trap handler reads each syscall's own argv fresh from tracee memory (`read_tracee_argv`, Task 4 Step 2) rather than trusting a count captured once at the top of this function, which is what makes matching correct for a forked grandchild's own exec too (coverage), not just the top-level command `run_traced` was started with. (the rest of `run_traced`'s body is unchanged except for the trap-handling block already rewritten in Task 4, which now closes over this function's local `plan` and sets this function-local `active_rewrite`). Update the two call sites accordingly (`run_self_test` and `handle_conn`, both changed in Step 5 below) — both drop the `argc`/`real_argc` argument they'd otherwise have passed.

- [ ] **Step 3: Apply the rewrite transform to piped output**

In `run_traced`'s poll loop, where stdout/stderr bytes are read from the worker's pipes and forwarded via `send_frame` (the spike's `if (oi >= 0 && ...) { ...; send_frame(out_fd, TAG_STDOUT, buf, r); ... }` block and its stderr twin), insert the transform before forwarding:

```c
static size_t apply_rewrite(char *buf, size_t len, const char *find, const char *replace, char *out, size_t outcap) {
    if (!find || !find[0]) { size_t n = len < outcap ? len : outcap; memcpy(out, buf, n); return n; }
    size_t findlen = strlen(find), replacelen = strlen(replace);
    size_t oi = 0, i = 0;
    while (i < len && oi < outcap) {
        if (i + findlen <= len && memcmp(buf + i, find, findlen) == 0) {
            size_t n = replacelen < (outcap - oi) ? replacelen : (outcap - oi);
            memcpy(out + oi, replace, n);
            oi += n; i += findlen;
        } else {
            out[oi++] = buf[i++];
        }
    }
    return oi;
}
```

then, in the poll loop's stdout branch:

```c
        if (oi >= 0 && (pfds[oi].revents & (POLLIN|POLLHUP))) {
            char buf[8192], out[8192];
            ssize_t r = read(outp[0], buf, sizeof(buf));
            if (r > 0) {
                if (active_rewrite && active_rewrite->has_stdout_rewrite) {
                    size_t n = apply_rewrite(buf, (size_t)r, active_rewrite->stdout_find,
                                              active_rewrite->stdout_replace, out, sizeof(out));
                    send_frame(out_fd, TAG_STDOUT, out, (uint32_t)n);
                } else {
                    send_frame(out_fd, TAG_STDOUT, buf, (uint32_t)r);
                }
            }
            else { have_out = 0; close(outp[0]); }
        }
```

(mirror for stderr using `active_rewrite->has_stderr_rewrite`/`stderr_find`/`stderr_replace`).

- [ ] **Step 4: Add the per-request watchdog**

In `run_traced`'s poll loop setup (before the `for (;;)` loop), compute a deadline and pass a bounded timeout to `poll()` instead of `-1`:

```c
    struct timespec deadline;
    clock_gettime(CLOCK_MONOTONIC, &deadline);
    deadline.tv_sec += (time_t)(timeout_ms / 1000);
    deadline.tv_nsec += (long)(timeout_ms % 1000) * 1000000;
    if (deadline.tv_nsec >= 1000000000) { deadline.tv_sec++; deadline.tv_nsec -= 1000000000; }
```

and inside the loop, replace `int pr = poll(pfds, nfds, -1);` with:

```c
        struct timespec now;
        clock_gettime(CLOCK_MONOTONIC, &now);
        long remaining_ms = (long)(deadline.tv_sec - now.tv_sec) * 1000
                           + (deadline.tv_nsec - now.tv_nsec) / 1000000;
        if (remaining_ms <= 0) {
            logline("req=%s pid=%d TIMEOUT after %llu ms, killing", req_id?req_id:"-", pid,
                    (unsigned long long)timeout_ms);
            kill(pid, SIGKILL);
            { int st; waitpid(pid, &st, 0); }
            close(sfd); close(outp[0]); close(errp[0]);
            if (exit_code_out) *exit_code_out = 124; /* matches GNU `timeout`'s convention */
            return -1;
        }
        int pr = poll(pfds, nfds, (int)remaining_ms);
```

- [ ] **Step 5: Fix `run_server` — fork per connection instead of handling inline**

Replace the spike's blocking accept loop:

```c
static int run_server(void) {
    unlink(SOCK_PATH);
    ...
    for (;;) {
        int cfd = accept(sfd, NULL, NULL);
        if (cfd < 0) { if (errno == EINTR) continue; perror("accept"); continue; }
        handle_conn(cfd);
    }
}
```

with a version that forks a dedicated handler per connection and reaps them without letting zombies accumulate, bounded by `max_concurrent_handlers`:

```c
static volatile sig_atomic_t g_active_handlers = 0;

static void reap_finished_handlers(void) {
    for (;;) {
        int status;
        pid_t w = waitpid(-1, &status, WNOHANG);
        if (w <= 0) break;
        if (g_active_handlers > 0) g_active_handlers--;
    }
}

static int run_server(const struct exec_plan *plan) {
    unlink(SOCK_PATH);
    int sfd = socket(AF_UNIX, SOCK_STREAM, 0);
    struct sockaddr_un addr = { .sun_family = AF_UNIX };
    strncpy(addr.sun_path, SOCK_PATH, sizeof(addr.sun_path)-1);
    if (bind(sfd, (struct sockaddr*)&addr, sizeof(addr)) != 0) { perror("bind"); return 1; }
    chmod(SOCK_PATH, 0666);
    if (listen(sfd, 64) != 0) { perror("listen"); return 1; }
    logline("relayd listening on %s pid=%d", SOCK_PATH, getpid());

    signal(SIGPIPE, SIG_IGN);

    for (;;) {
        reap_finished_handlers();

        int cfd = accept(sfd, NULL, NULL);
        if (cfd < 0) { if (errno == EINTR) continue; perror("accept"); continue; }

        if ((uint32_t)g_active_handlers >= plan->max_concurrent_handlers) {
            logline("rejecting connection: %d handlers already active (cap %u)",
                    g_active_handlers, plan->max_concurrent_handlers);
            static const char msg[] = "relay: too many concurrent requests\n";
            write_full(cfd, msg, sizeof(msg) - 1);
            close(cfd);
            continue;
        }

        pid_t hpid = fork();
        if (hpid < 0) { perror("fork(handler)"); close(cfd); continue; }
        if (hpid == 0) {
            /* handler child: owns this one connection end to end, then exits.
             * Runs completely independently of the accept loop and any other
             * handler — this is the fix for the head-of-line-blocking bug: a
             * hung command here can never block accept() from servicing the
             * next connection, because accept() isn't running in this
             * process at all. */
            close(sfd);
            handle_conn(cfd, plan);
            _exit(0);
        }
        close(cfd);
        g_active_handlers++;
    }
}
```

- [ ] **Step 6: Update `handle_conn` and `main` for the new signatures**

```c
static void handle_conn(int cfd, const struct exec_plan *plan) {
    char line[2048];
    char id[256] = "-";
    int argc = 0;
    char *argv[EXEC_RELAY_MAX_ARGV];
    for (int i = 0; i < EXEC_RELAY_MAX_ARGV; i++) argv[i] = NULL;

    for (;;) {
        int n = read_line(cfd, line, sizeof(line));
        if (n < 0) { close(cfd); return; }
        if (strncmp(line, "ID ", 3) == 0) {
            strncpy(id, line + 3, sizeof(id) - 1);
        } else if (strncmp(line, "ARGC ", 5) == 0) {
            argc = atoi(line + 5);
            if (argc < 1 || argc > EXEC_RELAY_MAX_ARGV - 1) { close(cfd); return; }
        } else if (strncmp(line, "ARG ", 4) == 0) {
            for (int i = 0; i < EXEC_RELAY_MAX_ARGV - 1; i++) {
                if (argv[i] == NULL) { argv[i] = strdup(line + 4); break; }
            }
        } else if (strcmp(line, "END") == 0) {
            break;
        }
    }
    if (!argv[0]) { close(cfd); return; }

    logline("accepted req id=%s argv0=%s argc=%d", id, argv[0], argc);

    char idenv[300];
    snprintf(idenv, sizeof(idenv), "RELAY_REQ_ID=%s", id);
    char *extra[1] = { idenv };

    int ecode = -1;
    run_traced(argv, extra, 1, id, cfd, cfd, &ecode, plan, plan->timeout_ms);

    uint32_t code_be = (uint32_t)ecode;
    uint8_t payload[4] = { (code_be>>24)&0xff, (code_be>>16)&0xff, (code_be>>8)&0xff, code_be&0xff };
    send_frame(cfd, TAG_EXIT, payload, 4);
    logline("req id=%s done exit=%d", id, ecode);
    close(cfd);
}

/* Startup self-check: fork a disposable canary child and confirm
 * PTRACE_SEIZE actually works in this environment before ever accepting a
 * real request. Per the design's error-handling requirement, a ptrace
 * failure must refuse cell startup outright, not be discovered silently
 * partway through a run — even though a per-request SEIZE failure (handled
 * in run_traced's reap_and_fail path) already fails that one request safely
 * rather than running it unsupervised, this check catches an
 * environment-level problem immediately instead of on the first real turn. */
static int ptrace_self_check(void) {
    pid_t pid = fork();
    if (pid < 0) { perror("ptrace_self_check: fork"); return -1; }
    if (pid == 0) {
        raise(SIGSTOP);
        _exit(0);
    }
    int status;
    waitpid(pid, &status, WUNTRACED);
    int rc = ptrace(PTRACE_SEIZE, pid, 0, (void*)(long)PTRACE_O_EXITKILL);
    if (rc != 0) {
        fprintf(stderr, "execrelayd: PTRACE_SEIZE self-check failed: %s\n", strerror(errno));
        kill(pid, SIGKILL);
        waitpid(pid, &status, 0);
        return -1;
    }
    ptrace(PTRACE_CONT, pid, 0, 0);
    waitpid(pid, &status, 0);
    return 0;
}

int main(int argc, char **argv) {
    setvbuf(stdout, NULL, _IOLBF, 0);

    struct exec_plan plan;
    if (config_load_from_env(&plan) != 0) {
        fprintf(stderr, "execrelayd: refusing to start — CHAMBER_EXEC_CONSEQUENCE_SPEC_B64 "
                         "is absent, malformed, or invalid\n");
        return 1;
    }
    if (ptrace_self_check() != 0) {
        fprintf(stderr, "execrelayd: refusing to start — the interception mechanism this "
                         "whole relay depends on is not usable in this environment\n");
        return 1;
    }
    disclosure_init();

    if (argc >= 2 && strcmp(argv[1], "--self-test") == 0) {
        int ecode = -1;
        run_traced(argv + 2, NULL, 0, "self-test", STDOUT_FILENO, STDERR_FILENO,
                   &ecode, &plan, plan.timeout_ms);
        return ecode;
    }
    return run_server(&plan);
}
```

- [ ] **Step 7: Build the full binary and smoke-test it standalone (no Docker yet)**

Run:
```bash
cd runtime/images/guest-exec-relay
cc -O2 -Wall -Wextra -std=c11 -o /tmp/execrelayd src/relayd.c src/config.c src/json.c
CHAMBER_EXEC_CONSEQUENCE_SPEC_B64=$(printf '{"rules":[]}' | base64) /tmp/execrelayd --self-test /bin/true
echo "exit=$?"
```
Expected: builds with no warnings, `exit=0` (empty rules → passthrough → `/bin/true` really runs and exits 0).

- [ ] **Step 8: Commit**

```bash
cd runtime && git add images/guest-exec-relay/src/relayd.c
git commit -m "fix: fork-per-connection concurrency, per-request watchdog, and disclosure log in relayd"
```

---

### Task 6: `stub.c`

**Files:**
- Create: `runtime/images/guest-exec-relay/src/stub.c`

**Interfaces:**
- Consumes: nothing beyond libc; connects to `execrelayd`'s Unix socket at `/tmp/relay.sock`.
- Produces: the `stub` binary — the sole thing `docker exec <cell> stub [--turn-id=ID] <argv...>` targets.

**Important deviation from the spike, worth flagging explicitly:** the spike's `stub.c` read a turn-correlation id from a `RELAY_ID` *environment variable*, set per-call via `docker exec -e RELAY_ID=...`. That doesn't fit this codebase: `-e` is forbidden everywhere (Global Constraints — it leaks into the host `ps` table), and even setting it via the codebase's own env-file mechanism wouldn't help, because `Container::exec` (the only thing that actually issues a `docker exec`) has no per-call env parameter at all — the env-file is fixed for the whole cell's lifetime, not settable per turn. A per-turn id has to travel as an **argv token**, not an environment variable. This task's `stub.c` accepts an optional `--turn-id=ID` as its first argument instead; when absent, the id defaults to `"-"`, so every existing plain `stub <argv...>` invocation (used throughout Task 11's tests below) keeps working unchanged, and only Task 9's bridge integration and the one test that specifically checks correlation need to pass it.

- [ ] **Step 1: Write `stub.c`, adapted from the spike's proven protocol handling**

The socket protocol itself (`ID`/`ARGC`/`ARG`/`END` request framing, `TAG_STDOUT`/`TAG_STDERR`/`TAG_EXIT` response frames) is unchanged from `/tmp/cc-spike-ptrace-relay/stub.c` and already matches what Task 5's `handle_conn` expects — only argument parsing changes:

```c
// runtime/images/guest-exec-relay/src/stub.c
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <stdint.h>
#include <errno.h>
#include <sys/socket.h>
#include <sys/un.h>

#define SOCK_PATH "/tmp/relay.sock"

static ssize_t read_full(int fd, void *buf, size_t n) {
    char *p = buf; size_t left = n;
    while (left) {
        ssize_t r = read(fd, p, left);
        if (r < 0) { if (errno == EINTR) continue; return -1; }
        if (r == 0) return (ssize_t)(n - left);
        p += r; left -= r;
    }
    return (ssize_t)n;
}
static ssize_t write_full(int fd, const void *buf, size_t n) {
    const char *p = buf; size_t left = n;
    while (left) {
        ssize_t w = write(fd, p, left);
        if (w < 0) return -1;
        p += w; left -= w;
    }
    return (ssize_t)n;
}

int main(int argc, char **argv) {
    if (argc < 2) { fprintf(stderr, "usage: stub [--turn-id=ID] <argv0> [args...]\n"); return 2; }

    const char *id = "-";
    int start = 1;
    if (strncmp(argv[1], "--turn-id=", 10) == 0) {
        id = argv[1] + 10;
        start = 2;
    }
    if (argc <= start) { fprintf(stderr, "usage: stub [--turn-id=ID] <argv0> [args...]\n"); return 2; }
    int real_argc = argc - start;
    char **real_argv = argv + start;

    int sfd = socket(AF_UNIX, SOCK_STREAM, 0);
    struct sockaddr_un addr = { .sun_family = AF_UNIX };
    strncpy(addr.sun_path, SOCK_PATH, sizeof(addr.sun_path)-1);
    if (connect(sfd, (struct sockaddr*)&addr, sizeof(addr)) != 0) {
        perror("stub: connect");
        return 111;
    }

    char line[2048];
    int n = snprintf(line, sizeof(line), "ID %s\nARGC %d\n", id, real_argc);
    write_full(sfd, line, n);
    for (int i = 0; i < real_argc; i++) {
        n = snprintf(line, sizeof(line), "ARG %s\n", real_argv[i]);
        write_full(sfd, line, n);
    }
    write_full(sfd, "END\n", 4);

    int exit_code = 1;
    for (;;) {
        uint8_t hdr[5];
        if (read_full(sfd, hdr, 5) != 5) break;
        uint32_t len = ((uint32_t)hdr[1]<<24)|((uint32_t)hdr[2]<<16)|((uint32_t)hdr[3]<<8)|hdr[4];
        uint8_t tag = hdr[0];
        if (tag == 3) { /* exit */
            uint8_t p[4];
            if (len == 4 && read_full(sfd, p, 4) == 4) {
                int32_t code = (int32_t)(((uint32_t)p[0]<<24)|((uint32_t)p[1]<<16)|((uint32_t)p[2]<<8)|p[3]);
                exit_code = code;
            }
            break;
        } else {
            char *buf = malloc(len ? len : 1);
            if (len && read_full(sfd, buf, len) != (ssize_t)len) { free(buf); break; }
            int outfd = (tag == 1) ? 1 : 2;
            write_full(outfd, buf, len);
            free(buf);
        }
    }
    close(sfd);
    return exit_code;
}
```

- [ ] **Step 2: Verify it builds and round-trips against a running `execrelayd`, both with and without a turn id**

Run:
```bash
cd runtime/images/guest-exec-relay
cc -O2 -Wall -Wextra -std=c11 -o /tmp/stub src/stub.c
CHAMBER_EXEC_CONSEQUENCE_SPEC_B64=$(printf '{"rules":[]}' | base64) /tmp/execrelayd &
RELAYD_PID=$!
sleep 0.2
/tmp/stub /bin/echo hello-from-stub
echo "exit=$?"
/tmp/stub --turn-id=t1 /bin/echo hello-with-id
echo "exit=$?"
kill $RELAYD_PID
```
Expected: both print their respective `hello-*` line and `exit=0`.

- [ ] **Step 3: Commit**

```bash
cd runtime && git add images/guest-exec-relay/src/stub.c
git commit -m "feat: add stub, the docker-exec-targeted relay client"
```

---

### Task 7: Guest image Dockerfile

**Files:**
- Create: `runtime/images/guest-exec-relay/Dockerfile`

**Interfaces:**
- Consumes: `runtime/images/guest-exec-relay/src/*.c` (Tasks 2–6).
- Produces: a buildable image tag (`chamber-guest-exec-relay:test`), consumed later by `plan.images.guest` in Task 9's tests and by Task 12's e2e tests.

- [ ] **Step 1: Write the multi-stage Dockerfile**

```dockerfile
# The exec-consequence-capable agent cell: same alpine:3.20 base and contract
# as the plain guest, plus execrelayd as PID 1 and stub as the sole entry
# point docker exec targets. Two stages so the final image carries only the
# compiled binaries, not gcc/musl-dev/linux-headers.
FROM alpine:3.20 AS builder
RUN apk add --no-cache gcc musl-dev linux-headers
WORKDIR /src
COPY src/json.h src/json.c src/config.h src/config.c src/relayd.c src/stub.c ./
RUN gcc -O2 -Wall -Wextra -std=c11 -o /out/execrelayd relayd.c config.c json.c \
 && gcc -O2 -Wall -Wextra -std=c11 -o /out/stub stub.c

FROM alpine:3.20
RUN apk add --no-cache curl ca-certificates bind-tools
COPY --from=builder /out/execrelayd /usr/local/bin/execrelayd
COPY --from=builder /out/stub /usr/local/bin/stub
WORKDIR /work
ENTRYPOINT ["/usr/local/bin/execrelayd"]
```

- [ ] **Step 2: Build it and verify**

Run: `docker build -t chamber-guest-exec-relay:test /Users/jessiemac/projects/detonation-chamber/runtime/images/guest-exec-relay`
Expected: builds successfully (matches the same `apk add gcc musl-dev linux-headers` combination already proven to compile this exact code in the mechanism-research spikes).

Run: `docker run --rm --cap-drop ALL -e CHAMBER_EXEC_CONSEQUENCE_SPEC_B64=$(printf '{"rules":[]}' | base64) chamber-guest-exec-relay:test --self-test /bin/true; echo "exit=$?"`

(Note: `-e` here is only for this manual smoke test outside the real harness — the real harness never uses `-e`, per the Global Constraints; Task 9 wires the env var through `EnvFile` correctly.)

Expected: `exit=0`.

- [ ] **Step 3: Commit**

```bash
cd runtime && git add images/guest-exec-relay/Dockerfile
git commit -m "feat: add multi-stage Dockerfile for the exec-relay guest image"
```

---

### Task 8: `chamber-evidence` — new disclosure channel

**Files:**
- Modify: `runtime/crates/chamber-evidence/src/coverage.rs`
- Modify: `runtime/crates/chamber-evidence/src/ledger.rs`

**Interfaces:**
- Consumes: nothing new.
- Produces: `Channel::ExecConsequence` variant, `ObservationKind::ExecConsequence { turn_id: String, requested_argv0: String, matched_rule: String, verb_applied: String, detail: String }`. Used by Task 11's `bundle.rs` addition.

- [ ] **Step 1: Write the failing test**

```rust
// add to the existing #[cfg(test)] mod tests in coverage.rs (or create one if none exists at module scope — check first; if one exists, add these to it)
#[test]
fn exec_consequence_does_not_bear_verdict() {
    assert!(!Channel::ExecConsequence.bears_verdict());
}

#[test]
fn exec_consequence_is_in_all() {
    assert!(Channel::ALL.contains(&Channel::ExecConsequence));
}

#[test]
fn exec_consequence_wire_tag() {
    assert_eq!(Channel::ExecConsequence.wire_tag(), "exec_consequence");
}
```

- [ ] **Step 2: Run to verify it fails**

Run: `cd runtime && cargo test -p chamber-evidence exec_consequence`
Expected: FAIL — `Channel::ExecConsequence` doesn't exist.

- [ ] **Step 3: Add the variant**

In `runtime/crates/chamber-evidence/src/coverage.rs`, add to the `Channel` enum (after `GuestCommand`):

```rust
    /// Commands the exec-consequence relay intercepted inside the guest —
    /// which rule fired and what actually ran, disclosed to reviewers, never
    /// to the subject under test.
    ExecConsequence,
```

Add to `Channel::ALL`:

```rust
    pub const ALL: &'static [Channel] = &[
        Channel::NetworkEgress,
        Channel::DnsResolution,
        Channel::DroppedPackets,
        Channel::InferenceTransport,
        Channel::GuestCommand,
        Channel::ExecConsequence,
    ];
```

Add to `bears_verdict` (deliberately `false` — same reasoning as `GuestCommand`: an intercepted exec observed inside the sealed guest is disclosed instrumentation activity, not itself a boundary departure):

```rust
            Channel::ExecConsequence => false,
```

Add to `wire_tag`:

```rust
            Channel::ExecConsequence => "exec_consequence",
```

In `runtime/crates/chamber-evidence/src/ledger.rs`, add to `ObservationKind` (after `GuestCommand`):

```rust
    ExecConsequence {
        turn_id: String,
        requested_argv0: String,
        matched_rule: String,
        verb_applied: String,
        detail: String,
    },
```

- [ ] **Step 4: Run to verify it passes**

Run: `cd runtime && cargo test -p chamber-evidence exec_consequence`
Expected: PASS.

Also run the full `chamber-evidence` suite to confirm the non-wildcard `bears_verdict`/`wire_tag` matches across the crate still compile (any other exhaustive match on `Channel` elsewhere in the workspace will now also force a decision — search for it):

Run: `cd runtime && grep -rn "match .*Channel::\|match self {" crates/*/src/*.rs | grep -v coverage.rs`
Expected: no other exhaustive `match` on `Channel` exists outside `coverage.rs` (if one is found, add the corresponding arm there too before proceeding — do not add a wildcard).

Run: `cd runtime && cargo build --workspace --exclude chamber-e2e`
Expected: builds clean; if any other file has an exhaustive `Channel` match, this step fails with a compile error naming it — resolve before moving on.

- [ ] **Step 5: Commit**

```bash
cd runtime && git add crates/chamber-evidence/src/coverage.rs crates/chamber-evidence/src/ledger.rs
git commit -m "feat: add Channel::ExecConsequence, a new non-verdict-bearing disclosure channel"
```

---

### Task 9: `chamber-run` — plan field, env injection, bridge stub-prefixing

**Files:**
- Modify: `runtime/crates/chamber-run/src/run.rs`
- Modify: `runtime/crates/chamber-run/src/bridge.rs`

**Interfaces:**
- Consumes: `chamber_capture::exec_consequence::ExecConsequencePlan` (Task 1).
- Produces: `DetonationPlan.exec_consequence: Option<ExecConsequencePlan>` field; `seal_cell_environment` sets `CHAMBER_EXEC_CONSEQUENCE_SPEC_B64` in the cell's `EnvDraft` when present; `ToolBridge::new_with_exec_relay(bool) -> Self` and updated `carry_out_observed` argv-prefixing. Used by Task 11 (which needs to know whether the relay is active, to decide whether to seal the disclosure log) and Task 12's integration tests.

**Note on turn correlation:** the spike's `RELAY_ID` env var doesn't fit this codebase — `-e` is forbidden (Global Constraints) and `Container::exec` has no per-call env parameter at all (the env-file is fixed for the whole cell, not settable per turn). So the bridge instead injects the turn id as an argv token, `--turn-id=<N>` (matching Task 6's `stub.c`, which accepts it as an optional first argument), generated from an internal counter on `ToolBridge` itself — simplest option, and every call already goes through one bridge instance for the run's whole lifetime.

- [ ] **Step 1: Write the failing bridge test**

Add to `bridge.rs`'s existing `#[cfg(test)] mod tests` (reusing the existing `FakeCell` fixture already there, which records into a `seen: RefCell<Vec<Vec<String>>>` field — confirmed from the current file, not assumed):

```rust
    #[test]
    fn prefixes_stub_and_turn_id_when_exec_relay_enabled() {
        let cell = FakeCell::default();
        let bridge = ToolBridge::new_with_exec_relay(true);
        bridge
            .carry_out(
                &cell,
                &TurnDirective::RunCommand {
                    argv: vec!["pip".to_owned(), "install".to_owned(), "x".to_owned()],
                },
            )
            .expect("carry out");
        assert_eq!(
            cell.seen.borrow()[0],
            vec![
                "stub".to_owned(), "--turn-id=turn-0".to_owned(),
                "pip".to_owned(), "install".to_owned(), "x".to_owned(),
            ],
        );
    }

    #[test]
    fn turn_id_increments_across_calls() {
        let cell = FakeCell::default();
        let bridge = ToolBridge::new_with_exec_relay(true);
        for _ in 0..3 {
            bridge
                .carry_out(&cell, &TurnDirective::RunCommand { argv: vec!["echo".to_owned()] })
                .expect("carry out");
        }
        assert_eq!(cell.seen.borrow()[0][1], "--turn-id=turn-0");
        assert_eq!(cell.seen.borrow()[1][1], "--turn-id=turn-1");
        assert_eq!(cell.seen.borrow()[2][1], "--turn-id=turn-2");
    }

    #[test]
    fn does_not_prefix_stub_by_default() {
        let cell = FakeCell::default();
        let bridge = ToolBridge::new();
        bridge
            .carry_out(&cell, &TurnDirective::RunCommand { argv: vec!["echo".to_owned()] })
            .expect("carry out");
        assert_eq!(cell.seen.borrow()[0], vec!["echo".to_owned()]);
    }

    #[test]
    fn read_file_is_prefixed_too_when_enabled() {
        let cell = FakeCell::default();
        let bridge = ToolBridge::new_with_exec_relay(true);
        bridge
            .carry_out(&cell, &TurnDirective::ReadFile { at: PathBuf::from("/work/x.txt") })
            .expect("carry out");
        assert_eq!(
            cell.seen.borrow()[0],
            vec!["stub".to_owned(), "--turn-id=turn-0".to_owned(), "cat".to_owned(), "/work/x.txt".to_owned()],
        );
    }
```

- [ ] **Step 2: Run to verify it fails**

Run: `cd runtime && cargo test -p chamber-run bridge::tests`
Expected: FAIL — `ToolBridge::new_with_exec_relay` doesn't exist.

- [ ] **Step 3: Implement**

In `bridge.rs`, change `ToolBridge`'s struct definition and constructors (preserving the existing `within()` constructor, which sets a custom window and must keep defaulting `exec_relay_enabled` to `false`), adding an atomic turn counter (`AtomicU64` rather than `Cell` so the type stays trivially `Send`/`Sync` with no extra reasoning needed about the async runtime):

```rust
use std::sync::atomic::{AtomicU64, Ordering};

#[derive(Debug)]
pub struct ToolBridge {
    window: Duration,
    exec_relay_enabled: bool,
    turn_counter: AtomicU64,
}

impl ToolBridge {
    #[must_use]
    pub fn new() -> Self {
        Self { window: TURN_WINDOW, exec_relay_enabled: false, turn_counter: AtomicU64::new(0) }
    }

    #[must_use]
    pub fn within(window: Duration) -> Self {
        Self { window, exec_relay_enabled: false, turn_counter: AtomicU64::new(0) }
    }

    /// `enabled` should be `true` exactly when the run's `DetonationPlan` has
    /// an `exec_consequence` configured — set once at arming time, not
    /// per-turn, since the guest image itself (`execrelayd` as PID 1 vs. no
    /// relay at all) is fixed for the whole run.
    #[must_use]
    pub fn new_with_exec_relay(enabled: bool) -> Self {
        Self { window: TURN_WINDOW, exec_relay_enabled: enabled, turn_counter: AtomicU64::new(0) }
    }

    /// Builds the real argv for one directive: `stub --turn-id=<N> <real...>`
    /// when the relay is enabled (each call gets a fresh, monotonically
    /// increasing id), or just `<real...>` when it isn't.
    fn prefixed_argv(&self, real_argv: impl IntoIterator<Item = String>) -> Vec<String> {
        if !self.exec_relay_enabled {
            return real_argv.into_iter().collect();
        }
        let turn_id = self.turn_counter.fetch_add(1, Ordering::Relaxed);
        let mut full = vec!["stub".to_owned(), format!("--turn-id=turn-{turn_id}")];
        full.extend(real_argv);
        full
    }
}
```

Change `carry_out_observed`'s dispatch body:

```rust
    pub fn carry_out_observed(
        &self,
        target: &impl TurnTarget,
        directive: &TurnDirective,
    ) -> Result<CarriedTurn, CellError> {
        let outcome = match directive {
            TurnDirective::RunCommand { argv } => {
                let full = self.prefixed_argv(argv.iter().cloned());
                let borrowed: Vec<&str> = full.iter().map(String::as_str).collect();
                Some(target.run(&borrowed, self.window)?)
            }
            TurnDirective::ReadFile { at } => {
                let path = at.display().to_string();
                let full = self.prefixed_argv(["cat".to_owned(), path]);
                let borrowed: Vec<&str> = full.iter().map(String::as_str).collect();
                Some(target.run(&borrowed, self.window)?)
            }
            TurnDirective::Conclude => None,
        };
        // ...unchanged CarriedTurn construction below
```

- [ ] **Step 4: Run to verify it passes**

Run: `cd runtime && cargo test -p chamber-run bridge::tests`
Expected: PASS.

- [ ] **Step 5: Write the failing test for a pure, Container-free env-injection helper**

`seal_cell_environment(plan: &DetonationPlan, capture: &Container) -> Result<CellEnvironment, String>` takes a real `chamber_isolation::Container` (it `exec`s into it to read the CA cert) — `Container` is a concrete type, not a trait `TurnTarget`-style fakes can stand in for, so this function as a whole isn't unit-testable without Docker. Rather than skip testing the new logic, extract just the new env-binding step into its own pure function that takes only an `&mut EnvDraft` — trivially testable with a bare `EnvDraft::empty()` and no container at all:

```rust
    #[test]
    fn adds_exec_consequence_binding_when_configured() {
        let plan = chamber_capture::exec_consequence::ExecConsequencePlan {
            rules: vec![],
            timeout_ms: 60_000,
            max_concurrent_handlers: 32,
        };
        let mut draft = EnvDraft::empty();
        apply_exec_consequence_env(&mut draft, Some(&plan)).unwrap();
        let sealed = draft.seal(&CanaryPlacements::none()).unwrap();
        assert!(sealed.contains_binding(chamber_capture::exec_consequence::EXEC_SPEC_B64_VAR));
    }

    #[test]
    fn adds_no_binding_when_not_configured() {
        let mut draft = EnvDraft::empty();
        apply_exec_consequence_env(&mut draft, None).unwrap();
        let sealed = draft.seal(&CanaryPlacements::none()).unwrap();
        assert!(!sealed.contains_binding(chamber_capture::exec_consequence::EXEC_SPEC_B64_VAR));
    }
```

(Add these to `run.rs`'s existing `#[cfg(test)] mod tests`, near the other `seal_cell_environment`-adjacent coverage — check the module for where canary/env-draft behavior is already tested, and place these alongside it.)

- [ ] **Step 6: Run to verify it fails**

Run: `cd runtime && cargo test -p chamber-run adds_exec_consequence_binding`
Expected: FAIL — `apply_exec_consequence_env` and `EnvDraft::contains_binding` don't exist yet, won't compile.

- [ ] **Step 7: Implement**

Add to `DetonationPlan`'s struct definition in `run.rs` (next to the existing `consequence: Option<ConsequencePlan>` field):

```rust
    pub exec_consequence: Option<chamber_capture::exec_consequence::ExecConsequencePlan>,
```

Add the new pure helper in `run.rs`, near `seal_cell_environment`:

```rust
/// Isolated from `seal_cell_environment` specifically so it's testable
/// without a real `Container` — this function touches nothing but the draft.
fn apply_exec_consequence_env(
    draft: &mut EnvDraft,
    exec_plan: Option<&chamber_capture::exec_consequence::ExecConsequencePlan>,
) -> Result<(), String> {
    let Some(exec_plan) = exec_plan else { return Ok(()) };
    let relay = Rationale {
        reason: "configures the guest's exec-interception relay for this run",
        required_by: "chamber-run::seal_cell_environment",
    };
    for (key, value) in exec_plan.to_env_pairs() {
        draft
            .set(VarName::parse(&key).map_err(|e| e.to_string())?, value, relay)
            .map_err(|e| e.to_string())?;
    }
    Ok(())
}
```

Call it from `seal_cell_environment`, after the canary-placement block and before `draft.seal(&placements)`:

```rust
    apply_exec_consequence_env(&mut draft, plan.exec_consequence.as_ref())?;
```

Add a test-only accessor to `chamber-isolation/src/env.rs`'s `impl SealedEnv` block, matching that file's existing test-only-accessor convention:

```rust
    #[cfg(test)]
    pub(crate) fn contains_binding(&self, name: &str) -> bool {
        self.bindings.keys().any(|k| k.as_str() == name)
    }
```

Finally, at the real call site (`run.rs`, inside `run_detonation`, the line `drive_turns(turns, &ToolBridge::new(), cell, plan.max_turns).await` found during research), change it to:

```rust
        drive_turns(
            turns,
            &ToolBridge::new_with_exec_relay(plan.exec_consequence.is_some()),
            cell,
            plan.max_turns,
        )
        .await
```

- [ ] **Step 8: Run to verify it passes**

Run: `cd runtime && cargo test -p chamber-run`
Expected: PASS, full `chamber-run` suite green (confirms this change didn't break anything else touching `DetonationPlan`, `ToolBridge`, or `seal_cell_environment`).

- [ ] **Step 9: Commit**

```bash
cd runtime && git add crates/chamber-run/src/run.rs crates/chamber-run/src/bridge.rs crates/chamber-isolation/src/env.rs
git commit -m "feat: wire ExecConsequencePlan into DetonationPlan, cell env, and the stub-prefixing bridge"
```

---

### Task 10: `chamber-run` — disclosure log sealing + bundle recording

**Files:**
- Modify: `runtime/crates/chamber-run/src/bundle.rs`
- Modify: `runtime/crates/chamber-run/src/run.rs`

**Interfaces:**
- Consumes: `Channel::ExecConsequence`, `ObservationKind::ExecConsequence` (Task 8).
- Produces: `bundle::record_exec_consequence_log(log: &mut RunLog, disclosure_log_text: &str, secrets: &[String])`; the `wind_down` call's `BoundarySeal` stage now also reads the disclosure log out of the cell before teardown.

- [ ] **Step 1: Write the failing test**

```rust
// add to bundle.rs's existing test module
#[test]
fn record_exec_consequence_log_parses_one_line_per_record() {
    let mut log = RunLog::open();
    let text = concat!(
        "{\"known_residual_tells\":[\"TracerPid nonzero\"]}\n",
        "{\"turn_id\":\"t1\",\"timestamp\":1.0,\"requested_argv0\":\"pip\",",
        "\"matched_rule\":\"fake-pip\",\"verb_applied\":\"fabricate\",\"detail\":\"exit=0\"}\n",
    );
    record_exec_consequence_log(&mut log, text, &[]);
    assert_eq!(log.len(), 1);
    let entry = &log.entries()[0];
    assert_eq!(entry.channel(), Channel::ExecConsequence);
    match entry.kind() {
        ObservationKind::ExecConsequence { turn_id, matched_rule, verb_applied, .. } => {
            assert_eq!(turn_id, "t1");
            assert_eq!(matched_rule, "fake-pip");
            assert_eq!(verb_applied, "fabricate");
        }
        other => panic!("wrong kind: {other:?}"),
    }
}

#[test]
fn record_exec_consequence_log_ignores_malformed_lines() {
    let mut log = RunLog::open();
    record_exec_consequence_log(&mut log, "not json\n{}\n", &[]);
    assert_eq!(log.len(), 0);
}

#[test]
fn record_exec_consequence_log_redacts_secrets() {
    let mut log = RunLog::open();
    let text = "{\"turn_id\":\"t1\",\"timestamp\":1.0,\"requested_argv0\":\"pip\",\"matched_rule\":\"r\",\"verb_applied\":\"fabricate\",\"detail\":\"secret-token-xyz\"}\n";
    record_exec_consequence_log(&mut log, text, &["secret-token-xyz".to_owned()]);
    match log.entries()[0].kind() {
        ObservationKind::ExecConsequence { detail, .. } => assert!(!detail.contains("secret-token-xyz")),
        other => panic!("wrong kind: {other:?}"),
    }
}
```

- [ ] **Step 2: Run to verify it fails**

Run: `cd runtime && cargo test -p chamber-run record_exec_consequence_log`
Expected: FAIL — function doesn't exist.

- [ ] **Step 3: Implement**

```rust
// bundle.rs, alongside record_guest_commands
/// Parses the exec-relay's disclosure log (one JSON object per line, per
/// `runtime/images/guest-exec-relay/src/relayd.c`'s `disclosure_record`) into
/// `Channel::ExecConsequence` observations. The first line (the
/// `known_residual_tells` header) carries no turn data and is skipped, not
/// treated as malformed. Unparseable lines are silently skipped, not
/// errored — the caller has no recovery available other than "this run has
/// less exec-consequence disclosure than it should," which is a coverage
/// gap the bundle's own gap-reporting machinery surfaces, not a reason to
/// fail an entire run's evidence emission over one bad line in a log a
/// separate C program wrote.
pub fn record_exec_consequence_log(log: &mut RunLog, disclosure_log_text: &str, secrets: &[String]) {
    for line in disclosure_log_text.lines() {
        let Ok(value) = serde_json::from_str::<serde_json::Value>(line) else { continue };
        let Some(obj) = value.as_object() else { continue };
        if obj.contains_key("known_residual_tells") {
            continue;
        }
        let (Some(turn_id), Some(argv0), Some(rule), Some(verb), Some(detail)) = (
            obj.get("turn_id").and_then(|v| v.as_str()),
            obj.get("requested_argv0").and_then(|v| v.as_str()),
            obj.get("matched_rule").and_then(|v| v.as_str()),
            obj.get("verb_applied").and_then(|v| v.as_str()),
            obj.get("detail").and_then(|v| v.as_str()),
        ) else {
            continue;
        };
        let kind = ObservationKind::ExecConsequence {
            turn_id: redact_secrets(turn_id.to_owned(), secrets),
            requested_argv0: redact_secrets(argv0.to_owned(), secrets),
            matched_rule: rule.to_owned(),
            verb_applied: verb.to_owned(),
            detail: redact_secrets(detail.to_owned(), secrets),
        };
        log.note(0, Channel::ExecConsequence, kind, vec![]);
    }
}
```

(`redact_secrets` is the existing function `record_guest_commands` already uses — reuse it, don't reimplement.)

- [ ] **Step 4: Run to verify it passes**

Run: `cd runtime && cargo test -p chamber-run record_exec_consequence_log`
Expected: PASS.

- [ ] **Step 5: Wire the sealing read into `wind_down`'s `BoundarySeal` stage**

In `run.rs`'s `run_detonation`, before the `wind_down(...)` call, add a variable to carry the disclosure text out to the `RunRecord` closure (mirroring how `transcript` is already captured before the call):

```rust
    let exec_consequence_log: std::rc::Rc<std::cell::RefCell<Option<String>>> = Default::default();
```

Inside the `BoundarySeal` closure (stage 2), after `capture.stop(...)` succeeds and before it returns — this is "after the observer is stopped but before `SandboxTeardown` destroys the cell," per the design's sealing requirement — add:

```rust
                if plan.exec_consequence.is_some() {
                    if let Some(cell) = chamber.borrow().cell.as_ref() {
                        match cell.exec(&["cat", "/work/.execrelay.log"], OP_WINDOW) {
                            Ok(outcome) => *exec_consequence_log.borrow_mut() = Some(outcome.stdout),
                            Err(e) => eprintln!("chamber: could not read exec-consequence disclosure log: {e}"),
                        }
                    }
                }
```

(A read failure here is logged, not fatal — matching the existing best-effort tone of the worksnapshot code found during research; the run's own evidence isn't blocked on this secondary channel, which itself doesn't bear verdict.)

Inside the `RunRecord` closure (stage 4), alongside the existing `bundle::record_guest_commands(&mut log, &transcript, &secrets);` line, add:

```rust
                if let Some(text) = exec_consequence_log.borrow().as_deref() {
                    bundle::record_exec_consequence_log(&mut log, text, &secrets);
                }
```

- [ ] **Step 6: Run the full `chamber-run` suite**

Run: `cd runtime && cargo test -p chamber-run`
Expected: PASS.

- [ ] **Step 7: Commit**

```bash
cd runtime && git add crates/chamber-run/src/bundle.rs crates/chamber-run/src/run.rs
git commit -m "feat: seal the exec-consequence disclosure log into the evidence bundle before cell teardown"
```

---

### Task 11: chamber-e2e integration tests

**Files:**
- Create: `runtime/crates/chamber-e2e/tests/exec_consequence.rs`
- Modify: `runtime/crates/chamber-e2e/Cargo.toml`

**Interfaces:**
- Consumes: everything from Tasks 1–10 — the built `chamber-guest-exec-relay:test` image (Task 7), `ExecConsequencePlan` (Task 1), `chamber_isolation::{Container, ContainerSpec, Attach}` (existing).
- Produces: nothing further downstream — this is the leaf of the plan, and the direct regression test for the concurrency bug that shaped Tasks 5 and this design.

- [ ] **Step 1: Register the test target and add the missing dependency**

In `runtime/crates/chamber-e2e/Cargo.toml`, add alongside the existing `[[test]]` entries for `containment`/`no_flush_ruleset`/`matrix`:

```toml
[[test]]
name = "exec_consequence"
path = "tests/exec_consequence.rs"
```

`chamber-capture` is not yet a dev-dependency of `chamber-e2e` (confirmed by reading the current `Cargo.toml` — only `chamber-isolation`, `chamber-run`, and `chamber-evidence` are there) but this test needs `ExecConsequencePlan` from it. Add it to the existing `[dev-dependencies]` block:

```toml
chamber-capture = { path = "../chamber-capture", default-features = false }
```

(`default-features = false` matches how `chamber-run` itself depends on `chamber-capture` — this test needs only the `exec_consequence` types, not the `observer` feature's proxy/DNS stack.)

- [ ] **Step 2: Write the passthrough-invariant test**

```rust
// runtime/crates/chamber-e2e/tests/exec_consequence.rs
mod support;
use support::*;
use chamber_capture::exec_consequence::{ArgvMatcher, ExecConsequencePlan, ExecConsequenceRule, ExecVerb};
use chamber_isolation::{Attach, Container, ContainerSpec};
use std::time::Duration;

const IMAGE: &str = "chamber-guest-exec-relay:test";
const OP_WINDOW: Duration = Duration::from_secs(90);

fn start_cell(plan: &ExecConsequencePlan) -> Container {
    ensure_images_including(&[IMAGE]); // extend the existing ensure_images() helper to also build this image's Dockerfile — see support/mod.rs's existing memoized-build pattern
    let pairs = plan.to_env_pairs();
    let env_file = chamber_isolation::EnvFile::write(&pairs).expect("env file");
    Container::create(&ContainerSpec {
        image: IMAGE.to_owned(),
        attach: Attach::None,
        cap_add: vec![],
        argv: vec![],
        sysctls: vec![],
        env_file: Some(env_file.path().clone()),
        dns: vec![],
        read_only: false,
        tmpfs: vec!["/work:rw,exec".to_owned(), "/tmp:rw,exec".to_owned()],
        volumes: vec![],
    })
    .expect("create cell")
}

#[test]
fn passthrough_is_byte_identical_to_no_interception() {
    let Some(_engine) = require_containers() else { return; };
    let _serialised = chamber_subnet_lock();

    let plan = ExecConsequencePlan { rules: vec![], timeout_ms: 60_000, max_concurrent_handlers: 32 };
    let cell = start_cell(&plan);
    cell.start().expect("start");
    std::thread::sleep(Duration::from_millis(300)); // let execrelayd bind its socket

    // Absolute path, deliberately: worker.c calls plain execve() (Task 4/5),
    // which — unlike a shell — does NOT search PATH. A bare "echo" would
    // fail with ENOENT once passthrough lets the real syscall proceed.
    let via_relay = cell.exec(&["stub", "/bin/echo", "hello"], OP_WINDOW).expect("exec via relay");
    assert_eq!(via_relay.stdout.trim(), "hello");
    assert_eq!(via_relay.status, Some(0));

    cell.destroy(OP_WINDOW).ok();
}
```

- [ ] **Step 3: Run to verify it fails (image doesn't exist / helper doesn't exist)**

Run: `cd runtime && CHAMBER_REQUIRE_CONTAINERS=1 cargo test -p chamber-e2e --test exec_consequence passthrough_is_byte_identical`
Expected: FAIL — `ensure_images_including` doesn't exist in `support/mod.rs` yet.

- [ ] **Step 4: Extend `support/mod.rs`'s image-build helper**

Find the existing `ensure_images()` function in `runtime/crates/chamber-e2e/tests/support/mod.rs` (it memoizes builds via `static BUILT: OnceLock<Mutex<bool>>`, per research). Add a sibling that also builds the new image, following the same memoization pattern already there (adapt the existing single-image memoized-build code into a small helper parameterized by image tag + Dockerfile directory, called once for the existing guest images and once for `runtime/images/guest-exec-relay`):

```rust
pub fn ensure_images_including(extra: &[&str]) {
    ensure_images();
    static EXTRA_BUILT: std::sync::OnceLock<std::sync::Mutex<std::collections::HashSet<String>>> =
        std::sync::OnceLock::new();
    let built = EXTRA_BUILT.get_or_init(|| std::sync::Mutex::new(Default::default()));
    let mut built = built.lock().unwrap();
    for &tag in extra {
        if built.contains(tag) { continue; }
        if tag == "chamber-guest-exec-relay:test" {
            chamber_isolation::build_image(
                std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../images/guest-exec-relay").as_path(),
                tag,
            )
            .expect("build guest-exec-relay image");
        }
        built.insert(tag.to_owned());
    }
}
```

- [ ] **Step 5: Run to verify the passthrough test passes**

Run: `cd runtime && CHAMBER_REQUIRE_CONTAINERS=1 cargo test -p chamber-e2e --test exec_consequence passthrough_is_byte_identical -- --nocapture`
Expected: PASS.

- [ ] **Step 6: Write and pass the substitute/fabricate/rewrite tests**

```rust
#[test]
fn substitute_runs_the_replacement_binary() {
    let Some(_engine) = require_containers() else { return; };
    let _serialised = chamber_subnet_lock();

    let plan = ExecConsequencePlan {
        rules: vec![ExecConsequenceRule {
            name: "sub".to_owned(),
            match_argv: ArgvMatcher::Argv0 { name: "/bin/false".to_owned() },
            verb: ExecVerb::Substitute { replacement_argv: vec!["/bin/true".to_owned()] },
        }],
        timeout_ms: 60_000,
        max_concurrent_handlers: 32,
    };
    let cell = start_cell(&plan);
    cell.start().expect("start");
    std::thread::sleep(Duration::from_millis(300));

    let out = cell.exec(&["stub", "/bin/false"], OP_WINDOW).expect("exec");
    assert_eq!(out.status, Some(0), "requested /bin/false but the substitute rule should have made /bin/true actually run");

    cell.destroy(OP_WINDOW).ok();
}

#[test]
fn fabricate_never_runs_the_real_target() {
    let Some(_engine) = require_containers() else { return; };
    let _serialised = chamber_subnet_lock();

    let plan = ExecConsequencePlan {
        rules: vec![ExecConsequenceRule {
            name: "fab".to_owned(),
            match_argv: ArgvMatcher::Argv0 { name: "touch-canary".to_owned() },
            verb: ExecVerb::Fabricate { exit_code: 0, stdout: "fabricated-ok".to_owned(), stderr: String::new() },
        }],
        timeout_ms: 60_000,
        max_concurrent_handlers: 32,
    };
    let cell = start_cell(&plan);
    cell.start().expect("start");
    std::thread::sleep(Duration::from_millis(300));

    // "touch-canary" isn't a real binary in the image at all — if fabricate
    // actually executed anything, this would fail with "not found" instead
    // of returning the canned result, so a passing exit=0/matching stdout
    // is itself proof nothing ran.
    let out = cell.exec(&["stub", "touch-canary"], OP_WINDOW).expect("exec");
    assert_eq!(out.status, Some(0));
    assert_eq!(out.stdout.trim(), "fabricated-ok");

    cell.destroy(OP_WINDOW).ok();
}

#[test]
fn rewrite_transforms_output_of_a_real_run() {
    let Some(_engine) = require_containers() else { return; };
    let _serialised = chamber_subnet_lock();

    let plan = ExecConsequencePlan {
        rules: vec![ExecConsequenceRule {
            name: "rw".to_owned(),
            // Matches on the literal argv[0] the caller passes, which is why
            // this must be the same absolute path used in the exec call
            // below — passthrough/rewrite both let the REAL syscall proceed
            // with that exact path, and plain execve() (Task 4/5) does no
            // PATH search to rescue a bare "echo".
            match_argv: ArgvMatcher::Argv0 { name: "/bin/echo".to_owned() },
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
    let cell = start_cell(&plan);
    cell.start().expect("start");
    std::thread::sleep(Duration::from_millis(300));

    let out = cell.exec(&["stub", "/bin/echo", "the secret value"], OP_WINDOW).expect("exec");
    assert_eq!(out.status, Some(0));
    assert_eq!(out.stdout.trim(), "the REDACTED value");

    cell.destroy(OP_WINDOW).ok();
}
```

Run: `cd runtime && CHAMBER_REQUIRE_CONTAINERS=1 cargo test -p chamber-e2e --test exec_consequence -- --nocapture`
Expected: PASS for all three.

- [ ] **Step 7: Write and pass the concurrency regression test — the direct test for the bug that shaped Task 5**

```rust
#[test]
fn one_hung_command_does_not_block_concurrent_others() {
    let Some(_engine) = require_containers() else { return; };
    let _serialised = chamber_subnet_lock();

    let plan = ExecConsequencePlan { rules: vec![], timeout_ms: 5_000, max_concurrent_handlers: 32 };
    // Plain (unwrapped) Container, not Arc<Container>: Container::destroy takes
    // `self` by value, which Arc's shared ownership can't hand back cleanly.
    // std::thread::scope lets the hang-check thread below borrow `&cell`
    // instead, so `cell` stays a plain, ordinary-to-consume value at the end.
    let cell = start_cell(&plan);
    cell.start().expect("start");
    std::thread::sleep(Duration::from_millis(300));

    std::thread::scope(|scope| {
        let hang_handle = scope.spawn(|| {
            // Expected to time out via the relay's own watchdog (exit 124)
            // well before this window elapses — the assertion is really
            // "this call eventually returns", proving the relay didn't
            // wedge forever. Absolute path — see the passthrough test's note
            // on why plain execve() needs one.
            cell.exec(&["stub", "/bin/sleep", "9999"], OP_WINDOW)
        });

        std::thread::sleep(Duration::from_millis(200)); // let the hang actually start

        let start = std::time::Instant::now();
        for i in 0..3 {
            let out = cell
                .exec(&["stub", "/bin/echo", &format!("concurrent-{i}")], Duration::from_secs(10))
                .unwrap_or_else(|e| panic!("concurrent request {i} did not complete promptly: {e}"));
            assert_eq!(out.stdout.trim(), format!("concurrent-{i}"));
        }
        assert!(
            start.elapsed() < Duration::from_secs(8),
            "concurrent requests took {:?} — the hang appears to have blocked them",
            start.elapsed()
        );

        let hang_result = hang_handle
            .join()
            .unwrap()
            .expect("exec call itself should still return (not hang forever)");
        assert_eq!(hang_result.status, Some(124), "hung command should time out via the watchdog with exit 124");
    });

    cell.destroy(OP_WINDOW).ok();
}
```

Run: `cd runtime && CHAMBER_REQUIRE_CONTAINERS=1 cargo test -p chamber-e2e --test exec_consequence one_hung_command -- --nocapture`
Expected: PASS. (If this fails by hanging the test itself, that is the regression this test exists to catch — do not raise the test's own timeout to "fix" it; fix `relayd.c`'s watchdog/fork-per-connection logic from Task 5 instead.)

- [ ] **Step 8: Write and pass coverage + turn-correlation + disclosure-sealing tests**

```rust
#[test]
fn coverage_extends_to_a_subprocess_of_a_subprocess() {
    let Some(_engine) = require_containers() else { return; };
    let _serialised = chamber_subnet_lock();

    let plan = ExecConsequencePlan {
        rules: vec![ExecConsequenceRule {
            name: "nested".to_owned(),
            match_argv: ArgvMatcher::Argv0 { name: "touch-canary".to_owned() },
            verb: ExecVerb::Fabricate { exit_code: 0, stdout: "caught-nested".to_owned(), stderr: String::new() },
        }],
        timeout_ms: 60_000,
        max_concurrent_handlers: 32,
    };
    let cell = start_cell(&plan);
    cell.start().expect("start");
    std::thread::sleep(Duration::from_millis(300));

    // sh -c 'sh -c touch-canary' is a subprocess of a subprocess of the
    // top-level docker-exec'd stub — coverage must reach all the way down.
    // The top-level command must be an absolute path (plain execve(), no
    // PATH search — see the passthrough test's note); the *nested* "sh" and
    // "touch-canary" can stay bare, because by the time the outer shell is
    // actually running it does its own PATH search internally (typically via
    // execvp, which itself calls execve() once per PATH candidate) — each of
    // those attempts is its own trapped syscall with argv[0] unchanged
    // ("touch-canary"), so the argv0 rule below still catches the first one,
    // before the shell ever exhausts its search and reports "not found".
    let out = cell
        .exec(&["stub", "/bin/sh", "-c", "sh -c touch-canary"], OP_WINDOW)
        .expect("exec");
    assert_eq!(out.status, Some(0));
    assert_eq!(out.stdout.trim(), "caught-nested");

    cell.destroy(OP_WINDOW).ok();
}

#[test]
fn turn_id_lands_on_the_disclosure_record() {
    let Some(_engine) = require_containers() else { return; };
    let _serialised = chamber_subnet_lock();

    let plan = ExecConsequencePlan { rules: vec![], timeout_ms: 60_000, max_concurrent_handlers: 32 };
    let cell = start_cell(&plan);
    cell.start().expect("start");
    std::thread::sleep(Duration::from_millis(300));

    // Exercises stub's --turn-id= argv flag directly (Task 6) — the same
    // convention the bridge's ToolBridge::prefixed_argv (Task 9) generates
    // per call, just supplied by hand here instead of via the bridge.
    cell.exec(&["stub", "--turn-id=turn-test-42", "/bin/echo", "hi"], OP_WINDOW).expect("exec");
    let log = cell.exec(&["cat", "/work/.execrelay.log"], OP_WINDOW).expect("cat log");
    assert!(log.stdout.contains("turn-test-42"), "log did not carry the turn id:\n{}", log.stdout);

    cell.destroy(OP_WINDOW).ok();
}

#[test]
fn disclosure_log_is_readable_via_the_sealing_cat_path() {
    let Some(_engine) = require_containers() else { return; };
    let _serialised = chamber_subnet_lock();

    let plan = ExecConsequencePlan { rules: vec![], timeout_ms: 60_000, max_concurrent_handlers: 32 };
    let cell = start_cell(&plan);
    cell.start().expect("start");
    std::thread::sleep(Duration::from_millis(300));

    cell.exec(&["stub", "/bin/echo", "one"], OP_WINDOW).expect("exec");
    cell.exec(&["stub", "/bin/echo", "two"], OP_WINDOW).expect("exec");

    let log = cell.exec(&["cat", "/work/.execrelay.log"], OP_WINDOW).expect("cat log");
    assert!(log.stdout.contains("known_residual_tells"));
    assert!(log.stdout.contains("TracerPid"));
    assert_eq!(log.stdout.lines().count(), 3, "1 header + 2 request records");

    cell.destroy(OP_WINDOW).ok();
}
```

Run: `cd runtime && CHAMBER_REQUIRE_CONTAINERS=1 cargo test -p chamber-e2e --test exec_consequence -- --nocapture`
Expected: PASS for the full file (9 tests total across this task).

- [ ] **Step 9: Commit**

```bash
cd runtime && git add crates/chamber-e2e/tests/exec_consequence.rs crates/chamber-e2e/tests/support/mod.rs crates/chamber-e2e/Cargo.toml
git commit -m "test: add chamber-e2e integration suite for the exec-consequence relay"
```

---

## Post-plan: not covered here (per the design's explicit scope boundaries)

- Migrating `pip-shim.sh`/H-supplychain onto this mechanism (design §7 — deliberately separate follow-up).
- Stdin relaying through the relay protocol (design §10 — flagged, not built).
- Any `/proc`-overlay discoverability mitigation (design §2/§8 — out of scope per the user's discoverability decision).
