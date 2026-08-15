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
/* Returns 0 and writes *out (0 or 1) if `v` is a JSON bool; returns -1
 * otherwise (including v == NULL, i.e. the key was absent) — a bool's own
 * two values are both falsy in C, so callers that need to tell "absent" from
 * "present and false" must check `json_object_get`'s result before calling
 * this, the same pattern already used for json_as_int64. */
int json_as_bool(json_value_t *v, int *out);

/* Appends `s` to `buf` at offset `off` as the CONTENTS of a JSON string —
 * the surrounding quotes are the caller's — escaping every byte RFC 8259
 * forbids raw inside a string: `"`, `\`, and the whole 0x00-0x1F control
 * range. Returns the new offset.
 *
 * Allocation-free and bounded by `bufcap` so it can be used to assemble one
 * complete record in a fixed stack buffer (see relayd.c's
 * disclosure_record). It NEVER emits a partial escape sequence: if the next
 * character's escape would not fit, it stops on the character boundary, so a
 * truncated value still leaves the caller a well-formed string to close. A
 * NUL is not written; the caller tracks length by the returned offset.
 *
 * This lives here rather than in relayd.c because relayd.c is Linux- and
 * aarch64-only (ptrace/seccomp/NT_PRSTATUS) and cannot be compiled by the
 * host-run C unit tests — which is exactly why the escaping defect this
 * function fixes went untested. Here it compiles anywhere json.c does. */
size_t json_append_escaped(char *buf, size_t off, size_t bufcap, const char *s);

#endif
