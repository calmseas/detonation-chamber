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
