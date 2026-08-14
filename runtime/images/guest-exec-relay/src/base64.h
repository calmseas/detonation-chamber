#ifndef EXEC_RELAY_BASE64_H
#define EXEC_RELAY_BASE64_H

#include <stddef.h>

/* Decodes standard-alphabet base64 (with '=' padding) from `in`
 * (NUL-terminated) into a freshly malloc'd buffer, written to *out with
 * length *out_len. Returns 0 on success, -1 on malformed input (including
 * any byte outside the base64 alphabet) — caller frees *out on success. */
int base64_decode(const char *in, char **out, size_t *out_len);

/* Encodes `in` (in_len bytes, may contain any byte value including NUL)
 * into a freshly malloc'd, NUL-terminated standard-alphabet base64 string
 * with '=' padding. Returns NULL on allocation failure. Caller frees. */
char *base64_encode(const void *in, size_t in_len);

#endif
