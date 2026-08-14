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

/* The record's structure, as named pieces rather than as literals buried in
 * the format strings below — so the reserve that has to accommodate them can
 * be computed from the very same strings, and a sixth field cannot be added
 * without the arithmetic following it. */
#define REC_HEAD     "{\"turn_id\":\""
#define REC_TS_OPEN  "\",\"timestamp\":"
#define REC_TS_FMT   "%ld.%03ld"
#define REC_ARGV0    ",\"requested_argv0\":\""
#define REC_RULE     "\",\"matched_rule\":\""
#define REC_VERB     "\",\"verb_applied\":\""
#define REC_DETAIL   "\",\"detail\":\""
#define REC_TAIL     "\"}\n"

/* Widest REC_TS_FMT can render: a `long` is at most 20 characters including a
 * sign, plus '.' and three more digits. */
#define REC_TS_MAX_WIDTH (20 + 1 + 3)

/* Reserved tail: the key names and the closing "}\n" total well under this, so
 * however long the values are there is always room left to close the string
 * and the object. Without it a long value truncates mid-object and the whole
 * line is lost to the consumer's silent skip — the failure being fixed, in a
 * smaller costume. */
#define STRUCTURAL_RESERVE 128

/* What the reserve actually has to hold. append_value stops every field at
 * `bufcap - STRUCTURAL_RESERVE`, so the worst case is the FIRST value running
 * to that limit: everything after it — each remaining structural literal, the
 * widest possible timestamp, and vsnprintf's NUL — must still fit in the
 * reserve. (REC_HEAD is excluded: it is written before any value, so it is
 * never competing for this space.) Comes to 110 of the 128 today.
 *
 * A compile-time check rather than a comment because the slack is only ~18
 * bytes: adding one more field to the record would silently overrun it, and
 * the symptom would be C3 again — a truncated line the Rust consumer skips
 * without a word, i.e. an exec missing from the sealed bundle. Fail the build
 * instead. */
#define REC_STRUCTURAL_TAIL_MAX (sizeof(REC_TS_OPEN) - 1 + REC_TS_MAX_WIDTH \
                                 + sizeof(REC_ARGV0) - 1 \
                                 + sizeof(REC_RULE) - 1 \
                                 + sizeof(REC_VERB) - 1 \
                                 + sizeof(REC_DETAIL) - 1 \
                                 + sizeof(REC_TAIL) - 1 \
                                 + 1 /* NUL */)
_Static_assert(STRUCTURAL_RESERVE >= REC_STRUCTURAL_TAIL_MAX,
               "STRUCTURAL_RESERVE no longer covers the record's own structure: a value "
               "truncated at the reserve boundary would now run past the buffer before "
               "the object could be closed, losing the whole line (see C3).");

/* Per-field budgets, in escaped bytes. Each field is capped INDIVIDUALLY
 * rather than all of them sharing one running cap, so no single oversized
 * value can starve the fields after it: an enormous argv0 must not be able to
 * empty out matched_rule, which is the single most important thing this log
 * has to say. Escaping can cost 6 bytes per input byte (\u00XX), so the raw
 * sources — turn_id 255, argv0 1023, rule name 127, detail 1199 — could in
 * the pathological limit want more than the whole buffer between them; these
 * budgets are what makes that bounded and per-field instead of first-come.
 *
 * Every budget still exceeds its source's RAW length, so an ordinary value
 * (ASCII, where escaping costs nothing) is never truncated; only a value made
 * mostly of control characters or quotes can reach its cap.
 *
 * They were twice this size until the transport moved from an O_APPEND file to
 * `execrelayd`'s stdout: a pipe write is only atomic up to PIPE_BUF, so the
 * whole record now has to fit in DISCLOSURE_RECORD_BUF (see record.h) or
 * concurrent handlers could interleave a torn line. The static assert below is
 * that constraint, not a comment about it. */
#define BUDGET_TURN_ID    512
#define BUDGET_ARGV0     1024
#define BUDGET_RULE       512
#define BUDGET_VERB       128
#define BUDGET_DETAIL    1536

_Static_assert(BUDGET_TURN_ID + BUDGET_ARGV0 + BUDGET_RULE + BUDGET_VERB + BUDGET_DETAIL
                   + (sizeof(REC_HEAD) - 1) + REC_STRUCTURAL_TAIL_MAX
                   <= DISCLOSURE_RECORD_BUF,
               "the per-field budgets plus the record's own structure no longer fit in "
               "DISCLOSURE_RECORD_BUF (= PIPE_BUF). A record that can exceed PIPE_BUF can be "
               "split mid-line by the kernel and interleaved with a concurrent handler's, "
               "which is the torn-line corruption the single-write discipline exists to "
               "prevent. Shrink a budget rather than raising the buffer.");

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
    off = append_fmt(buf, off, bufcap, REC_HEAD);
    off = append_value(buf, off, bufcap, BUDGET_TURN_ID, turn_id ? turn_id : "-");
    off = append_fmt(buf, off, bufcap, REC_TS_OPEN REC_TS_FMT REC_ARGV0, ts_sec, ts_msec);
    off = append_value(buf, off, bufcap, BUDGET_ARGV0, requested_argv0);
    off = append_fmt(buf, off, bufcap, REC_RULE);
    off = append_value(buf, off, bufcap, BUDGET_RULE, matched_rule);
    off = append_fmt(buf, off, bufcap, REC_VERB);
    off = append_value(buf, off, bufcap, BUDGET_VERB, verb_applied);
    off = append_fmt(buf, off, bufcap, REC_DETAIL);
    off = append_value(buf, off, bufcap, BUDGET_DETAIL, detail);
    off = append_fmt(buf, off, bufcap, REC_TAIL);
    return off;
}
