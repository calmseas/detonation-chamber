#ifndef EXEC_RELAY_CONFIG_H
#define EXEC_RELAY_CONFIG_H

#include <stddef.h>
#include <stdint.h>

/* EXEC_RELAY_MAX_ARGV is a wire limit, not a config one: a rule that matched
 * or substituted more argv elements than a request can carry could never
 * fire. Defined once, in protocol.h, and reused here. */
#include "protocol.h"

#define EXEC_RELAY_MAX_RULES 64
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
