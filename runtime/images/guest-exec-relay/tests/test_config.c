// runtime/images/guest-exec-relay/tests/test_config.c
//
// _GNU_SOURCE for setenv/unsetenv: this builds with -std=c11, which defines
// __STRICT_ANSI__, under which glibc declares neither. It compiled anyway
// because gcc 13 treats an implicit declaration as a warning — gcc 14 makes it
// an error, so without this the C-test CI job breaks the day ubuntu-latest
// moves up, taking every test in run_c_tests.sh with it.
#define _GNU_SOURCE
#include <assert.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
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

static void test_rejects_exit_code_out_of_int32_range(void) {
    /* exit_code value > INT32_MAX should be rejected */
    const char *json =
        "{\"rules\":[{\"name\":\"bad\","
        "\"match_argv\":{\"type\":\"argv0\",\"name\":\"x\"},"
        "\"verb\":{\"type\":\"fabricate\",\"exit_code\":4294967296,\"stdout\":\"\",\"stderr\":\"\"}}]}";
    struct exec_plan plan;
    assert(config_load_from_json(json, strlen(json), &plan) == -1);
}

static void test_rejects_max_concurrent_handlers_out_of_uint32_range(void) {
    /* max_concurrent_handlers > UINT32_MAX should be rejected */
    const char *json = "{\"rules\":[],\"max_concurrent_handlers\":4294967296}";
    struct exec_plan plan;
    assert(config_load_from_json(json, strlen(json), &plan) == -1);
}

static void test_rejects_base64_with_invalid_character(void) {
    /* Base64 string with an invalid character ('!') should be rejected.
     * '!' is not in the base64 alphabet (A-Z, a-z, 0-9, +, /).
     * Under the old broken table, it would decode as 0 (same as 'A').
     * With the fix, the lookup table correctly initializes to -1, so
     * invalid characters return -1 and the config load fails. */
    setenv("CHAMBER_EXEC_CONSEQUENCE_SPEC_B64", "SGVs!bG8=", 1);
    struct exec_plan plan;
    int rc = config_load_from_env(&plan);
    unsetenv("CHAMBER_EXEC_CONSEQUENCE_SPEC_B64");
    assert(rc == -1);
}

/* ---------------------- the limits, at their exact edges -------------------
 *
 * The other half of a two-sided contract. chamber-capture's
 * `exec_consequence.rs::validate()` refuses a plan that would fail HERE, and
 * its `guest_limits` constants are asserted against config.h's `#define`s by
 * `guest_limits_match_the_c_header`. What that cannot check is whether
 * config.c's code actually enforces what config.h declares — so these do,
 * at the boundary value and one past it, for every limit the host mirrors.
 *
 * Every one of these disagreed with the host before: the host checked
 * fabricate payloads at `> 2000` where this parser rejects at `>= 2000`, and
 * checked none of the other five at all. A plan could be host-valid and make
 * execrelayd refuse to start. */

/* Builds a one-rule plan with `name`, an argv0 matcher on "x", and a fabricate
 * verb whose stdout is `payload`, and reports whether the parser accepted it. */
static int loads_rule(const char *name, const char *payload) {
    static char json[16384];
    snprintf(json, sizeof(json),
             "{\"rules\":[{\"name\":\"%s\","
             "\"match_argv\":{\"type\":\"argv0\",\"name\":\"x\"},"
             "\"verb\":{\"type\":\"fabricate\",\"exit_code\":0,"
             "\"stdout\":\"%s\",\"stderr\":\"\"}}]}",
             name, payload);
    struct exec_plan plan;
    return config_load_from_json(json, strlen(json), &plan) == 0;
}

static void fill(char *buf, size_t n, char c) {
    memset(buf, c, n);
    buf[n] = 0;
}

static void test_fabricate_payload_edge(void) {
    static char at[EXEC_RELAY_MAX_FABRICATE_BYTES + 2];
    fill(at, EXEC_RELAY_MAX_FABRICATE_BYTES - 1, 'p');
    assert(loads_rule("r", at));                       /* 1999 accepted */
    fill(at, EXEC_RELAY_MAX_FABRICATE_BYTES, 'p');
    assert(!loads_rule("r", at));                      /* 2000 REJECTED */
}

static void test_rule_name_edge(void) {
    static char name[EXEC_RELAY_MAX_RULE_NAME + 2];
    fill(name, EXEC_RELAY_MAX_RULE_NAME, 'n');
    assert(loads_rule(name, "ok"));
    fill(name, EXEC_RELAY_MAX_RULE_NAME + 1, 'n');
    assert(!loads_rule(name, "ok"));
}

/* Builds a plan with one prefix-matcher rule of `n` elements, each `elem_len`
 * bytes, and a substitute verb with the same argv. */
static int loads_argv(int n, size_t elem_len) {
    static char json[65536];
    static char elem[EXEC_RELAY_MAX_ARGV_ELEM + 2];
    fill(elem, elem_len, 'a');
    size_t off = (size_t)snprintf(json, sizeof(json),
        "{\"rules\":[{\"name\":\"r\",\"match_argv\":{\"type\":\"prefix\",\"argv\":[");
    for (int i = 0; i < n; i++) {
        off += (size_t)snprintf(json + off, sizeof(json) - off, "%s\"%s\"", i ? "," : "", elem);
    }
    off += (size_t)snprintf(json + off, sizeof(json) - off,
                            "]},\"verb\":{\"type\":\"substitute\",\"replacement_argv\":[");
    for (int i = 0; i < n; i++) {
        off += (size_t)snprintf(json + off, sizeof(json) - off, "%s\"%s\"", i ? "," : "", elem);
    }
    off += (size_t)snprintf(json + off, sizeof(json) - off, "]}}]}");
    struct exec_plan plan;
    return config_load_from_json(json, off, &plan) == 0;
}

static void test_argv_edges(void) {
    assert(loads_argv(EXEC_RELAY_MAX_ARGV, 4));        /* the count limit is inclusive */
    assert(!loads_argv(EXEC_RELAY_MAX_ARGV + 1, 4));
    assert(loads_argv(2, EXEC_RELAY_MAX_ARGV_ELEM));   /* the length limit is inclusive */
    assert(!loads_argv(2, EXEC_RELAY_MAX_ARGV_ELEM + 1));
}

static int loads_rewrite(size_t len) {
    static char json[8192];
    static char s[EXEC_RELAY_MAX_REWRITE_STR + 2];
    fill(s, len, 'f');
    int n = snprintf(json, sizeof(json),
                     "{\"rules\":[{\"name\":\"r\",\"match_argv\":{\"type\":\"argv0\",\"name\":\"x\"},"
                     "\"verb\":{\"type\":\"rewrite\",\"stdout_find\":\"%s\","
                     "\"stdout_replace\":\"%s\"}}]}", s, s);
    struct exec_plan plan;
    return config_load_from_json(json, (size_t)n, &plan) == 0;
}

static void test_rewrite_string_edge(void) {
    assert(loads_rewrite(EXEC_RELAY_MAX_REWRITE_STR));
    assert(!loads_rewrite(EXEC_RELAY_MAX_REWRITE_STR + 1));
}

static int loads_n_rules(int n) {
    static char json[65536];
    size_t off = (size_t)snprintf(json, sizeof(json), "{\"rules\":[");
    for (int i = 0; i < n; i++) {
        off += (size_t)snprintf(json + off, sizeof(json) - off,
            "%s{\"name\":\"r%d\",\"match_argv\":{\"type\":\"argv0\",\"name\":\"x\"},"
            "\"verb\":{\"type\":\"fabricate\",\"exit_code\":0,\"stdout\":\"\",\"stderr\":\"\"}}",
            i ? "," : "", i);
    }
    off += (size_t)snprintf(json + off, sizeof(json) - off, "]}");
    struct exec_plan plan;
    return config_load_from_json(json, off, &plan) == 0;
}

static void test_rule_count_edge(void) {
    assert(loads_n_rules(EXEC_RELAY_MAX_RULES));
    assert(!loads_n_rules(EXEC_RELAY_MAX_RULES + 1));
}

static void test_timeout_precision_edge(void) {
    /* This parser reads every JSON number as a `double` and json_as_int64 then
     * rejects anything with a fractional part or outside int64 range. So the
     * largest timeout_ms it can carry FAITHFULLY is 2^53, the largest integer a
     * double represents exactly — and the failure past that is not a rejection,
     * it is silent rounding to a different number than was configured. Both
     * halves are asserted, because the host mirrors this limit and the
     * interesting one is the half that does not error. */
    const char *exact = "{\"rules\":[],\"timeout_ms\":9007199254740992}";   /* 2^53 */
    const char *past  = "{\"rules\":[],\"timeout_ms\":9007199254740993}";   /* 2^53 + 1 */
    const char *huge  = "{\"rules\":[],\"timeout_ms\":9223372036854775807}"; /* i64::MAX */
    struct exec_plan plan;
    assert(config_load_from_json(exact, strlen(exact), &plan) == 0);
    assert(plan.timeout_ms == 9007199254740992ULL);
    assert(config_load_from_json(past, strlen(past), &plan) == 0);
    assert(plan.timeout_ms != 9007199254740993ULL);  /* silently rounded */
    /* i64::MAX does not even survive the range check: as a double it rounds UP
     * to 2^63, which json_as_int64 refuses outright. */
    assert(config_load_from_json(huge, strlen(huge), &plan) == -1);
}

int main(void) {
    test_loads_empty_rules_with_defaults();
    test_loads_fabricate_rule();
    test_loads_substitute_rule();
    test_rejects_malformed_json();
    test_matches_prefix();
    test_first_match_wins();
    test_rejects_exit_code_out_of_int32_range();
    test_rejects_max_concurrent_handlers_out_of_uint32_range();
    test_rejects_base64_with_invalid_character();
    test_fabricate_payload_edge();
    test_rule_name_edge();
    test_argv_edges();
    test_rewrite_string_edge();
    test_rule_count_edge();
    test_timeout_precision_edge();
    printf("test_config: all tests passed\n");
    return 0;
}
