// runtime/images/guest-exec-relay/src/json.c
#include "json.h"
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <limits.h>

#define MAX_PARSE_DEPTH 32

struct parser {
    const char *p;
    const char *end;
    int failed;
    int depth;
};

static void skip_ws(struct parser *ps) {
    while (ps->p < ps->end && (*ps->p == ' ' || *ps->p == '\t' || *ps->p == '\n' || *ps->p == '\r')) ps->p++;
}

static json_value_t *alloc_value(json_type_t t) {
    json_value_t *v = calloc(1, sizeof(json_value_t));
    if (!v) return NULL;
    v->type = t;
    return v;
}

static json_value_t *parse_value(struct parser *ps);

static char *parse_raw_string(struct parser *ps) {
    if (ps->p >= ps->end || *ps->p != '"') { ps->failed = 1; return NULL; }
    ps->p++;
    size_t cap = 32, len = 0;
    char *buf = malloc(cap);
    if (!buf) { ps->failed = 1; return NULL; }
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
        if (len + 1 >= cap) { cap *= 2; char *tmp = realloc(buf, cap); if (!tmp) { ps->failed = 1; free(buf); return NULL; } buf = tmp; }
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
    if (!v) { free(s); return NULL; }
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
    if (!v) { ps->failed = 1; return NULL; }
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
    if (ps->depth >= MAX_PARSE_DEPTH) { ps->failed = 1; return NULL; }
    ps->depth++;
    json_value_t *v = alloc_value(JSON_ARRAY);
    if (!v) { ps->failed = 1; ps->depth--; return NULL; }
    size_t cap = 4;
    v->u.array.items = malloc(cap * sizeof(json_value_t *));
    if (!v->u.array.items) { ps->failed = 1; json_free(v); ps->depth--; return NULL; }
    v->u.array.len = 0;
    skip_ws(ps);
    if (ps->p < ps->end && *ps->p == ']') { ps->p++; ps->depth--; return v; }
    for (;;) {
        skip_ws(ps);
        json_value_t *item = parse_value(ps);
        if (!item) { ps->failed = 1; json_free(v); ps->depth--; return NULL; }
        if (v->u.array.len == cap) {
            cap *= 2;
            json_value_t **tmp = realloc(v->u.array.items, cap * sizeof(json_value_t *));
            if (!tmp) { ps->failed = 1; json_free(item); json_free(v); ps->depth--; return NULL; }
            v->u.array.items = tmp;
        }
        v->u.array.items[v->u.array.len++] = item;
        skip_ws(ps);
        if (ps->p >= ps->end) { ps->failed = 1; json_free(v); ps->depth--; return NULL; }
        if (*ps->p == ',') { ps->p++; continue; }
        if (*ps->p == ']') { ps->p++; ps->depth--; break; }
        ps->failed = 1; json_free(v); ps->depth--; return NULL;
    }
    return v;
}

static json_value_t *parse_object(struct parser *ps) {
    ps->p++; /* '{' */
    if (ps->depth >= MAX_PARSE_DEPTH) { ps->failed = 1; return NULL; }
    ps->depth++;
    json_value_t *v = alloc_value(JSON_OBJECT);
    if (!v) { ps->failed = 1; ps->depth--; return NULL; }
    size_t cap = 4;
    v->u.object.keys = malloc(cap * sizeof(char *));
    if (!v->u.object.keys) { ps->failed = 1; json_free(v); ps->depth--; return NULL; }
    v->u.object.values = malloc(cap * sizeof(json_value_t *));
    if (!v->u.object.values) { ps->failed = 1; json_free(v); ps->depth--; return NULL; }
    v->u.object.len = 0;
    skip_ws(ps);
    if (ps->p < ps->end && *ps->p == '}') { ps->p++; ps->depth--; return v; }
    for (;;) {
        skip_ws(ps);
        char *key = parse_raw_string(ps);
        if (!key) { ps->failed = 1; json_free(v); ps->depth--; return NULL; }
        skip_ws(ps);
        if (ps->p >= ps->end || *ps->p != ':') { ps->failed = 1; free(key); json_free(v); ps->depth--; return NULL; }
        ps->p++;
        skip_ws(ps);
        json_value_t *val = parse_value(ps);
        if (!val) { ps->failed = 1; free(key); json_free(v); ps->depth--; return NULL; }
        if (v->u.object.len == cap) {
            cap *= 2;
            char **tmp_keys = realloc(v->u.object.keys, cap * sizeof(char *));
            if (!tmp_keys) { ps->failed = 1; free(key); json_free(val); json_free(v); ps->depth--; return NULL; }
            v->u.object.keys = tmp_keys;
            json_value_t **tmp_vals = realloc(v->u.object.values, cap * sizeof(json_value_t *));
            if (!tmp_vals) { ps->failed = 1; free(key); json_free(val); json_free(v); ps->depth--; return NULL; }
            v->u.object.values = tmp_vals;
        }
        v->u.object.keys[v->u.object.len] = key;
        v->u.object.values[v->u.object.len] = val;
        v->u.object.len++;
        skip_ws(ps);
        if (ps->p >= ps->end) { ps->failed = 1; json_free(v); ps->depth--; return NULL; }
        if (*ps->p == ',') { ps->p++; continue; }
        if (*ps->p == '}') { ps->p++; ps->depth--; break; }
        ps->failed = 1; json_free(v); ps->depth--; return NULL;
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
    if (literal_at(ps, "true")) { ps->p += 4; json_value_t *v = alloc_value(JSON_BOOL); if (!v) { ps->failed = 1; return NULL; } v->u.boolean = 1; return v; }
    if (literal_at(ps, "false")) { ps->p += 5; json_value_t *v = alloc_value(JSON_BOOL); if (!v) { ps->failed = 1; return NULL; } v->u.boolean = 0; return v; }
    if (literal_at(ps, "null")) { ps->p += 4; json_value_t *v = alloc_value(JSON_NULL); if (!v) { ps->failed = 1; return NULL; } return v; }
    ps->failed = 1;
    return NULL;
}

json_value_t *json_parse(const char *text, size_t len) {
    struct parser ps = { .p = text, .end = text + len, .failed = 0, .depth = 0 };
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

/* How many bytes the UTF-8 sequence starting at `s` occupies, for the purpose
 * of copying it out WHOLE — 1 for anything this function will not treat as a
 * multi-byte character.
 *
 * A lead byte alone is not enough to claim a length: `\xe2` followed by an
 * ASCII letter is not a truncated three-byte character, it is one stray byte
 * and then a letter, and claiming 3 for it would swallow the letter. So the
 * continuation bytes are checked too, and a sequence whose continuations are
 * absent or malformed reports 1 — each of its bytes then passes through
 * individually, exactly as before, which is what "a value that was not valid
 * UTF-8 is not this layer's to repair" means (design §6). */
static size_t utf8_seq_len(const unsigned char *s) {
    unsigned char c = s[0];
    size_t want;
    if (c < 0x80) return 1;                    /* ASCII */
    else if (c >= 0xc2 && c <= 0xdf) want = 2; /* 0xc0/0xc1 are overlong leads */
    else if (c >= 0xe0 && c <= 0xef) want = 3;
    else if (c >= 0xf0 && c <= 0xf4) want = 4;
    else return 1;                             /* continuation byte, or 0xf5+ */
    for (size_t i = 1; i < want; i++) {
        if ((s[i] & 0xc0) != 0x80) return 1;   /* NUL included: 0x00 & 0xc0 != 0x80 */
    }
    return want;
}

size_t json_append_escaped(char *buf, size_t off, size_t bufcap, const char *s) {
    if (!s) return off;
    while (*s) {
        unsigned char c = (unsigned char)*s;
        char esc[8];
        const char *src = esc;
        size_t n;
        size_t consumed = 1;
        switch (c) {
            case '"':  esc[0] = '\\'; esc[1] = '"';  n = 2; break;
            case '\\': esc[0] = '\\'; esc[1] = '\\'; n = 2; break;
            case '\n': esc[0] = '\\'; esc[1] = 'n';  n = 2; break;
            case '\r': esc[0] = '\\'; esc[1] = 'r';  n = 2; break;
            case '\t': esc[0] = '\\'; esc[1] = 't';  n = 2; break;
            case '\b': esc[0] = '\\'; esc[1] = 'b';  n = 2; break;
            case '\f': esc[0] = '\\'; esc[1] = 'f';  n = 2; break;
            default:
                if (c < 0x20) {
                    /* Everything else in the control range has no short escape
                     * (NUL cannot appear — these are C strings — but 0x01-0x1f
                     * minus the five above can, e.g. ESC from a terminal
                     * sequence in a command's own argv). \u00XX is the only
                     * legal spelling RFC 8259 leaves. */
                    static const char HEX[] = "0123456789abcdef";
                    esc[0] = '\\'; esc[1] = 'u'; esc[2] = '0'; esc[3] = '0';
                    esc[4] = HEX[(c >> 4) & 0xf]; esc[5] = HEX[c & 0xf];
                    n = 6;
                } else {
                    /* Bytes >= 0x80 pass through unchanged: a value that was
                     * valid UTF-8 stays valid UTF-8, and one that was not is
                     * not this function's to repair.
                     *
                     * A well-formed multi-byte character is copied as ONE unit
                     * — all of it or none of it. Byte-at-a-time was the second
                     * producer of the corruption R1 (round 2's Critical) is
                     * about: the caller stops this function at a per-field
                     * budget, and a 3-byte character straddling that boundary
                     * used to leave its first one or two bytes in the record,
                     * which is invalid UTF-8 emitted by the WRITE side, before
                     * any reader is involved. Same contract the escape
                     * sequences above already have (written atomically or not
                     * at all), for the same reason. */
                    consumed = utf8_seq_len((const unsigned char *)s);
                    src = s;
                    n = consumed;
                }
        }
        if (off + n > bufcap) break;
        memcpy(buf + off, src, n);
        off += n;
        s += consumed;
    }
    return off;
}

int json_as_int64(json_value_t *v, int64_t *out) {
    if (!v || v->type != JSON_NUMBER) return -1;
    double d = v->u.number;
    /* Check that d is in the representable range for int64_t before casting.
     * Must use literal doubles: (double)INT64_MAX rounds UP to 2^63,
     * so we use the exact boundary values instead.
     * Note: upper bound is >= 2^63 because 2^63 itself is out of range. */
    if (d < -9223372036854775808.0 || d >= 9223372036854775808.0) return -1;
    int64_t truncated = (int64_t)d;
    if ((double)truncated != d) return -1;
    *out = truncated;
    return 0;
}

int json_as_bool(json_value_t *v, int *out) {
    if (!v || v->type != JSON_BOOL) return -1;
    *out = v->u.boolean;
    return 0;
}
