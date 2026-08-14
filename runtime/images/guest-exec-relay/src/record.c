// runtime/images/guest-exec-relay/src/record.c
#include "record.h"
#include "json.h"
#include <stdarg.h>
#include <stdio.h>

/* vsnprintf-and-advance: formats into `buf` at offset `off` (bounded by
 * `bufcap`), returns the new offset. Truncates safely (never past bufcap)
 * rather than overflowing if a record ever runs long. Only ever handed this
 * file's own structural literals — never a caller-supplied value, which is
 * what json_append_escaped is for. */
static size_t append_fmt(char *buf, size_t off, size_t bufcap, const char *fmt, ...) {
    if (off >= bufcap) return off;
    va_list ap;
    va_start(ap, fmt);
    int n = vsnprintf(buf + off, bufcap - off, fmt, ap);
    va_end(ap);
    if (n <= 0) return off;
    size_t written = (size_t)n < bufcap - off ? (size_t)n : bufcap - off - 1;
    return off + written;
}

/* Reserved tail: the key names and the closing "}\n" total well under this, so
 * however long the values are there is always room left to close the string
 * and the object. Without it a long value truncates mid-object and the whole
 * line is lost to the consumer's silent skip — the failure being fixed, in a
 * smaller costume. */
#define STRUCTURAL_RESERVE 128

/* Per-field budgets, in escaped bytes. Each field is capped INDIVIDUALLY
 * rather than all of them sharing one running cap, so no single oversized
 * value can starve the fields after it: an enormous argv0 must not be able to
 * empty out matched_rule, which is the single most important thing this log
 * has to say. Escaping can cost 6 bytes per input byte (\u00XX), so the raw
 * sources — turn_id 255, argv0 1023, rule name 127, detail 1199 — could in
 * the pathological limit want more than the whole buffer between them; these
 * budgets are what makes that bounded and per-field instead of first-come.
 * They sum to 7424, leaving room for the structure inside an 8 KiB buffer
 * (which relayd.c keeps small deliberately: the record is written with a
 * single write() so concurrent handlers' records cannot interleave). */
#define BUDGET_TURN_ID   1024
#define BUDGET_ARGV0     2048
#define BUDGET_RULE      1024
#define BUDGET_VERB       256
#define BUDGET_DETAIL    3072

static size_t append_value(char *buf, size_t off, size_t bufcap, size_t budget, const char *s) {
    size_t hard = bufcap - STRUCTURAL_RESERVE;
    size_t cap = off + budget;
    if (cap > hard) cap = hard;
    if (off >= cap) return off;
    return json_append_escaped(buf, off, cap, s);
}

size_t disclosure_format_record(char *buf, size_t bufcap,
                                long ts_sec, long ts_msec,
                                const char *turn_id, const char *requested_argv0,
                                const char *matched_rule, const char *verb_applied,
                                const char *detail) {
    if (bufcap < STRUCTURAL_RESERVE * 2) return 0;

    size_t off = 0;
    off = append_fmt(buf, off, bufcap, "{\"turn_id\":\"");
    off = append_value(buf, off, bufcap, BUDGET_TURN_ID, turn_id ? turn_id : "-");
    off = append_fmt(buf, off, bufcap, "\",\"timestamp\":%ld.%03ld,\"requested_argv0\":\"",
                     ts_sec, ts_msec);
    off = append_value(buf, off, bufcap, BUDGET_ARGV0, requested_argv0);
    off = append_fmt(buf, off, bufcap, "\",\"matched_rule\":\"");
    off = append_value(buf, off, bufcap, BUDGET_RULE, matched_rule);
    off = append_fmt(buf, off, bufcap, "\",\"verb_applied\":\"");
    off = append_value(buf, off, bufcap, BUDGET_VERB, verb_applied);
    off = append_fmt(buf, off, bufcap, "\",\"detail\":\"");
    off = append_value(buf, off, bufcap, BUDGET_DETAIL, detail);
    off = append_fmt(buf, off, bufcap, "\"}\n");
    return off;
}
