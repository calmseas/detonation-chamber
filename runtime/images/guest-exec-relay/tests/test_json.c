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
