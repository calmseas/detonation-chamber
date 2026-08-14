// runtime/images/guest-exec-relay/tests/test_rewrite.c
//
// The `rewrite` verb exists to keep a configured string out of the output the
// host ever sees — stripping a leaked path, say. Two ways it silently failed to
// do that, both fixed in rewrite.c and both asserted here:
//
//   1. The transform ran per `read()` with no memory between chunks, so a find
//      string SPLIT ACROSS TWO READS matched nothing and the original bytes went
//      through untouched. A traced process only has to write in two pieces for
//      this to happen, which is the ordinary case for anything line-buffered.
//
//   2. The output buffer was the same fixed size as the input buffer, with a
//      bounds guard that stopped copying when it filled — so a replacement
//      LONGER than what it replaced silently truncated the command's output.
//
// Both were unreachable by any test while the transform lived in relayd.c,
// which cannot be compiled off aarch64. That is why it is its own translation
// unit now.
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "../src/rewrite.h"

/* Collects everything a stream forwards, so a test can assert on the WHOLE
 * transformed output rather than on one chunk of it. */
struct sink {
    char *buf;
    size_t len;
    size_t cap;
};

static void sink_add(struct sink *s, const char *p, size_t n) {
    if (s->len + n + 1 > s->cap) {
        s->cap = (s->len + n + 1) * 2;
        s->buf = realloc(s->buf, s->cap);
        assert(s->buf != NULL);
    }
    if (n) memcpy(s->buf + s->len, p, n);
    s->len += n;
    s->buf[s->len] = 0;
}

static void sink_free(struct sink *s) { free(s->buf); s->buf = NULL; s->len = s->cap = 0; }

/* Feeds `chunks` (NULL-terminated) through one stream and returns everything
 * that came out, including whatever `finish` released. */
static void run_chunks(const char *find, const char *replace,
                       const char *const *chunks, struct sink *out) {
    struct rewrite_stream s;
    memset(&s, 0, sizeof(s));
    assert(rewrite_stream_begin(&s, find, replace) == 0);
    for (int i = 0; chunks[i]; i++) {
        const char *p = NULL; size_t n = 0;
        assert(rewrite_stream_push(&s, chunks[i], strlen(chunks[i]), &p, &n) == 0);
        sink_add(out, p, n);
    }
    const char *p = NULL; size_t n = 0;
    assert(rewrite_stream_finish(&s, &p, &n) == 0);
    sink_add(out, p, n);
    rewrite_stream_end(&s);
}

static void expect(const char *find, const char *replace,
                   const char *const *chunks, const char *want) {
    struct sink out = {0};
    run_chunks(find, replace, chunks, &out);
    if (out.len != strlen(want) || memcmp(out.buf, want, out.len) != 0) {
        fprintf(stderr, "find=[%s] replace=[%s]\n  expected [%s]\n  got      [%s]\n",
                find, replace, want, out.buf);
    }
    assert(out.len == strlen(want));
    assert(memcmp(out.buf, want, out.len) == 0);
    sink_free(&out);
}

/* ------------------------------------------------------------------------ */

static void test_a_match_split_across_two_chunks_is_caught(void) {
    /* THE defect. "SECRET" arrives as "SEC" then "RET" — two separate read()s
     * from the traced process's stdout pipe, which is what
     * `printf SEC; printf RET` produces. The per-chunk transform saw neither
     * half as a match and forwarded "SECRET" verbatim to the host. */
    const char *chunks[] = { "the SEC", "RET value", NULL };
    expect("SECRET", "REDACTED", chunks, "the REDACTED value");
}

static void test_a_match_split_one_byte_at_a_time_is_caught(void) {
    /* The worst case for a sliding window: every byte its own read(). */
    const char *chunks[] = { "a", "S", "E", "C", "R", "E", "T", "b", NULL };
    expect("SECRET", "X", chunks, "aXb");
}

static void test_a_match_spanning_three_chunks_is_caught(void) {
    const char *chunks[] = { "xxSE", "CR", "ETyy", NULL };
    expect("SECRET", "-", chunks, "xx-yy");
}

static void test_a_partial_match_that_never_completes_is_released(void) {
    /* The held-back tail is delayed, never dropped: a stream ending in "SEC"
     * with no "RET" coming must still forward "SEC". Losing it would be a
     * second, quieter corruption of the output. */
    const char *chunks[] = { "abcSEC", NULL };
    expect("SECRET", "X", chunks, "abcSEC");
}

static void test_a_near_miss_prefix_is_not_swallowed(void) {
    const char *chunks[] = { "SECS", "ECRET", NULL };
    expect("SECRET", "X", chunks, "SECX");
}

static void test_an_expanding_replacement_is_not_truncated(void) {
    /* The second defect. The output buffer used to be a fixed 8192 bytes, the
     * same size as the input read buffer, so a replacement longer than the
     * string it replaced ran out of room and the rest of the command's output
     * was silently discarded. 100 matches of a 1-byte find with a 200-byte
     * replacement is 20000 bytes out of 100 bytes in. */
    char input[101];
    memset(input, 'A', 100);
    input[100] = 0;
    char replacement[201];
    memset(replacement, 'z', 200);
    replacement[200] = 0;

    struct sink out = {0};
    const char *chunks[] = { input, NULL };
    run_chunks("A", replacement, chunks, &out);
    assert(out.len == 100 * 200);
    for (size_t i = 0; i < out.len; i++) assert(out.buf[i] == 'z');
    sink_free(&out);
}

static void test_expansion_survives_chunking_too(void) {
    /* Expansion and the sliding window at once: the growth must be computed
     * from each chunk's own content, not from a one-off sizing of the first. */
    const char *chunks[] = { "AA", "AA", "AA", NULL };
    expect("A", "1234567890", chunks,
           "123456789012345678901234567890123456789012345678901234567890");
}

static void test_a_shrinking_replacement_still_works(void) {
    const char *chunks[] = { "aaaLONGSTRINGbbb", NULL };
    expect("LONGSTRING", "x", chunks, "aaaxbbb");
}

static void test_an_empty_replacement_deletes(void) {
    const char *chunks[] = { "keep", "SECRET", "keep", NULL };
    expect("SECRET", "", chunks, "keepkeep");
}

static void test_adjacent_matches_are_all_replaced(void) {
    const char *chunks[] = { "SECRETSECRETSECRET", NULL };
    expect("SECRET", "X", chunks, "XXX");
}

static void test_adjacent_matches_across_a_boundary(void) {
    const char *chunks[] = { "SECRETSEC", "RETSECRET", NULL };
    expect("SECRET", "X", chunks, "XXX");
}

static void test_a_match_at_the_very_end_of_the_stream(void) {
    /* Held back by the window until finish() releases it — and finish() has to
     * scan what it releases, or a match sitting exactly at the end is emitted
     * raw. */
    const char *chunks[] = { "prefixSECRET", NULL };
    expect("SECRET", "X", chunks, "prefixX");
}

static void test_a_single_character_find(void) {
    /* findlen == 1 means the window holds back zero bytes — the degenerate end
     * of the sliding-window arithmetic, where `findlen - 1` is 0. */
    const char *chunks[] = { "a.b", ".c", NULL };
    expect(".", "/", chunks, "a/b/c");
}

static void test_an_empty_find_forwards_unchanged(void) {
    /* config.c only sets has_stdout_rewrite when both halves are present, so
     * this should not arise from a loaded plan — but the old function treated
     * an empty find as "copy through" and callers may still rely on it. */
    const char *chunks[] = { "abc", "def", NULL };
    expect("", "IGNORED", chunks, "abcdef");
}

static void test_binary_bytes_including_nul_survive(void) {
    /* The output stream is bytes, not a C string: a command emitting NULs must
     * come through byte for byte, and the transform must not stop at one. */
    struct rewrite_stream s;
    memset(&s, 0, sizeof(s));
    assert(rewrite_stream_begin(&s, "XY", "Z") == 0);
    const char in[] = { 'a', 0, 'X', 'Y', 0, 'b' };
    const char *p = NULL; size_t n = 0;
    assert(rewrite_stream_push(&s, in, sizeof(in), &p, &n) == 0);
    struct sink out = {0};
    sink_add(&out, p, n);
    assert(rewrite_stream_finish(&s, &p, &n) == 0);
    sink_add(&out, p, n);
    rewrite_stream_end(&s);

    const char want[] = { 'a', 0, 'Z', 0, 'b' };
    assert(out.len == sizeof(want));
    assert(memcmp(out.buf, want, sizeof(want)) == 0);
    sink_free(&out);
}

static void test_an_empty_chunk_is_harmless(void) {
    struct rewrite_stream s;
    memset(&s, 0, sizeof(s));
    assert(rewrite_stream_begin(&s, "AB", "C") == 0);
    const char *p = NULL; size_t n = 0;
    assert(rewrite_stream_push(&s, NULL, 0, &p, &n) == 0);
    assert(n == 0);
    assert(rewrite_stream_push(&s, "xABy", 4, &p, &n) == 0);
    struct sink out = {0};
    sink_add(&out, p, n);
    assert(rewrite_stream_finish(&s, &p, &n) == 0);
    sink_add(&out, p, n);
    rewrite_stream_end(&s);
    assert(strcmp(out.buf, "xCy") == 0);
    sink_free(&out);
}

static void test_a_large_stream_in_many_chunks(void) {
    /* Realistic shape: 8 KiB reads, a find string straddling one of the
     * boundaries, and the whole thing reassembled. */
    struct rewrite_stream s;
    memset(&s, 0, sizeof(s));
    assert(rewrite_stream_begin(&s, "/work/.exec-relay", "/tmp") == 0);
    struct sink out = {0};
    char filler[4096];
    memset(filler, '.', sizeof(filler));
    const char *p = NULL; size_t n = 0;
    for (int i = 0; i < 4; i++) {
        assert(rewrite_stream_push(&s, filler, sizeof(filler), &p, &n) == 0);
        sink_add(&out, p, n);
    }
    assert(rewrite_stream_push(&s, "/work/.exec", 11, &p, &n) == 0);
    sink_add(&out, p, n);
    assert(rewrite_stream_push(&s, "-relay/disclosure.log", 21, &p, &n) == 0);
    sink_add(&out, p, n);
    assert(rewrite_stream_finish(&s, &p, &n) == 0);
    sink_add(&out, p, n);
    rewrite_stream_end(&s);

    assert(out.len == 4 * 4096 + strlen("/tmp/disclosure.log"));
    assert(strstr(out.buf, "/tmp/disclosure.log") != NULL);
    assert(strstr(out.buf, "/work/.exec-relay") == NULL);
    sink_free(&out);
}

static void test_end_is_safe_on_a_zeroed_stream(void) {
    struct rewrite_stream s;
    memset(&s, 0, sizeof(s));
    rewrite_stream_end(&s);
    rewrite_stream_end(&s); /* idempotent */
}

int main(void) {
    test_a_match_split_across_two_chunks_is_caught();
    test_a_match_split_one_byte_at_a_time_is_caught();
    test_a_match_spanning_three_chunks_is_caught();
    test_a_partial_match_that_never_completes_is_released();
    test_a_near_miss_prefix_is_not_swallowed();
    test_an_expanding_replacement_is_not_truncated();
    test_expansion_survives_chunking_too();
    test_a_shrinking_replacement_still_works();
    test_an_empty_replacement_deletes();
    test_adjacent_matches_are_all_replaced();
    test_adjacent_matches_across_a_boundary();
    test_a_match_at_the_very_end_of_the_stream();
    test_a_single_character_find();
    test_an_empty_find_forwards_unchanged();
    test_binary_bytes_including_nul_survive();
    test_an_empty_chunk_is_harmless();
    test_a_large_stream_in_many_chunks();
    test_end_is_safe_on_a_zeroed_stream();
    printf("test_rewrite: all tests passed\n");
    return 0;
}
