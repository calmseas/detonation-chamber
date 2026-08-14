#ifndef EXEC_RELAY_CONFIG_H
#define EXEC_RELAY_CONFIG_H

#include <stddef.h>
#include <stdint.h>

/* EXEC_RELAY_MAX_ARGV is a wire limit, not a config one: a rule that matched
 * or substituted more argv elements than a request can carry could never
 * fire. Defined once, in protocol.h, and reused here. */
#include "protocol.h"

/* ---------------------------------------------------------------------------
 * The size limits, every one of them named.
 *
 * These are the guest's half of a two-parser contract: chamber-capture's
 * `exec_consequence.rs::validate()` checks the SAME limits host-side, so a plan
 * that passes host validation is guaranteed to load here. They were previously
 * implicit in the buffer declarations below (`char name[128]`, `char
 * stdout_find[512]`, ...), which is how the two sides came to disagree about
 * every one of them — and to disagree in the direction that matters: the host
 * accepted a 2000-byte fabricate stdout that this parser rejects, so the plan
 * was host-valid and the cell then refused to start with an error the host
 * never anticipated.
 *
 * Naming them makes the contract quotable from Rust (which mirrors these
 * values in `exec_consequence.rs` and has a test that re-reads THIS FILE and
 * fails if the two ever drift apart), and sizing the buffers from the names
 * below keeps the constant and the storage it describes from separating.
 *
 * The boundary conventions differ per limit and are deliberate, because
 * `copy_str` rejects at `n >= dstsz` (it must leave room for the NUL) while the
 * count checks reject at `n > MAX`:
 *
 *   MAX_RULES / MAX_ARGV      COUNTS      — the limit itself is VALID
 *   MAX_RULE_NAME / _ARGV_ELEM / _REWRITE_STR   BYTE LENGTHS — limit is VALID
 *   MAX_FABRICATE_BYTES       BYTE LENGTH — the limit itself is REJECTED
 *                                            (`>=`, see load_verb)
 * ------------------------------------------------------------------------- */

/* Most rules one plan may carry. A plan with exactly this many loads. */
#define EXEC_RELAY_MAX_RULES 64
/* Longest rule name, in bytes, NOT counting the NUL. */
#define EXEC_RELAY_MAX_RULE_NAME 127
/* Longest single argv element in a matcher or a substitute replacement. */
#define EXEC_RELAY_MAX_ARGV_ELEM 255
/* Longest rewrite find/replace string, in bytes. */
#define EXEC_RELAY_MAX_REWRITE_STR 511
/* Fabricate stdout/stderr budget. Note this one is exclusive: load_verb
 * rejects a payload of exactly this length (`outlen >= ...`). */
#define EXEC_RELAY_MAX_FABRICATE_BYTES 2000

/* Longest CHAMBER_EXEC_CONSEQUENCE_SPEC_B64 VALUE, in base64 characters — the
 * whole spec, not one of its fields.
 *
 * Every limit above bounds one field, and a plan can satisfy all of them and
 * still be far too large in aggregate: 64 rules, each with a 32-element match
 * argv and a 32-element replacement argv of 255-byte elements and two 2000-byte
 * fabricate payloads, is on the order of a megabyte of JSON and around 1.4 MB
 * once base64'd. Nothing above refuses it, and it cannot be delivered.
 *
 * The bound is NOT a buffer in this file — the decode mallocs and the JSON
 * parser allocates as it goes, so there is no fixed array here to overrun, and
 * looking for one is how this limit came to be missed. It is the KERNEL's, and
 * it applies before any line of this program runs. The runtime hands execrelayd
 * its environment through execve(), and Linux caps each individual argv/envp
 * string at MAX_ARG_STRLEN = 32 * PAGE_SIZE; strnlen_user counts the NUL, so
 * with the smallest page size in use (4096) one string may be at most 131072
 * bytes including it, i.e. 131071 characters. "CHAMBER_EXEC_CONSEQUENCE_SPEC_B64="
 * is 34 of those, leaving 131037 for the value. Past it execve fails E2BIG and
 * the container never starts — no message from this program, no ArmingRefusal,
 * just a cell that will not come up.
 *
 * So this is checked host-side (chamber-capture's `validate`, against the
 * mirrored constant) to turn that into a legible refusal, and enforced here as
 * well so the two parsers agree on a stated limit rather than on a kernel
 * behaviour one of them cannot see. A larger PAGE_SIZE (16K/64K aarch64 kernels
 * exist) only makes the kernel MORE permissive than this number, so the check
 * stays the tighter of the two on every configuration — which is the direction
 * that fails closed.
 *
 * Rounded DOWN to a multiple of 4 (131036, from the 131037 the arithmetic
 * above gives) because padded base64 has no other length: no encoded spec can
 * be exactly 131037 characters, so a limit stated there would have an
 * unreachable boundary and no test could sit on it. Inclusive: a value of
 * exactly this length loads. */
#define EXEC_RELAY_MAX_SPEC_B64 131036

typedef enum { MATCH_PREFIX, MATCH_EXACT, MATCH_ARGV0 } match_kind_t;
typedef enum { VERB_SUBSTITUTE, VERB_REWRITE, VERB_FABRICATE } verb_kind_t;

struct exec_rule {
    char name[EXEC_RELAY_MAX_RULE_NAME + 1];
    match_kind_t match_kind;
    char match_argv[EXEC_RELAY_MAX_ARGV][EXEC_RELAY_MAX_ARGV_ELEM + 1];
    int match_argv_len;      /* used by MATCH_PREFIX / MATCH_EXACT */
    char match_argv0[EXEC_RELAY_MAX_ARGV_ELEM + 1];   /* used by MATCH_ARGV0 */

    verb_kind_t verb;
    /* VERB_SUBSTITUTE */
    char replacement_argv[EXEC_RELAY_MAX_ARGV][EXEC_RELAY_MAX_ARGV_ELEM + 1];
    int replacement_argv_len;
    /* VERB_REWRITE */
    char stdout_find[EXEC_RELAY_MAX_REWRITE_STR + 1];
    char stdout_replace[EXEC_RELAY_MAX_REWRITE_STR + 1];
    char stderr_find[EXEC_RELAY_MAX_REWRITE_STR + 1];
    char stderr_replace[EXEC_RELAY_MAX_REWRITE_STR + 1];
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
