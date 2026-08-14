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

static void test_rejects_deeply_nested_arrays(void) {
    /* Depth limit is 32. Create input with 33 nested arrays to exceed it. */
    char buf[256];
    int pos = 0;
    for (int i = 0; i < 33; i++) buf[pos++] = '[';
    buf[pos++] = '1';
    for (int i = 0; i < 33; i++) buf[pos++] = ']';
    buf[pos] = 0;
    json_value_t *v = json_parse(buf, pos);
    assert(v == NULL); /* Should reject due to depth limit */
}

static void test_rejects_truncated_nested_object(void) {
    /* This tests the memory leak fix: truncated nested object should fail cleanly. */
    const char *text = "{\"a\":{";  /* Missing closing braces */
    json_value_t *v = json_parse(text, strlen(text));
    assert(v == NULL); /* Should reject malformed input */
}

static void test_rejects_out_of_range_numbers(void) {
    /* Very large number that parses but exceeds int64_t range */
    const char *text = "{\"x\":99999999999999999999}";
    json_value_t *v = json_parse(text, strlen(text));
    if (v != NULL) {
        int64_t result;
        /* json_as_int64 should return -1 for out-of-range numbers */
        assert(json_as_int64(json_object_get(v, "x"), &result) == -1);
        json_free(v);
    }
}

static void test_rejects_2_63_boundary(void) {
    /* Critical boundary test: 2^63 = 9223372036854775808 is exactly
     * representable as a double but out of range for int64_t (which maxes at 2^63-1).
     * This tests the fix for the boundary bug where (double)INT64_MAX
     * rounds UP to 2^63, making the cast undefined behavior. */
    const char *text = "{\"x\":9223372036854775808}";
    json_value_t *v = json_parse(text, strlen(text));
    assert(v != NULL);
    int64_t result;
    /* Must return -1, not success with a garbage value */
    assert(json_as_int64(json_object_get(v, "x"), &result) == -1);
    json_free(v);
}

int main(void) {
    test_parses_flat_object();
    test_parses_nested_array_of_objects();
    test_handles_escaped_strings();
    test_rejects_malformed_json();
    test_negative_and_zero_numbers();
    test_rejects_deeply_nested_arrays();
    test_rejects_truncated_nested_object();
    test_rejects_out_of_range_numbers();
    test_rejects_2_63_boundary();
    printf("test_json: all tests passed\n");
    return 0;
}
