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
