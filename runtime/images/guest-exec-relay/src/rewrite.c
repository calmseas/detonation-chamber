// runtime/images/guest-exec-relay/src/rewrite.c
//
// The streaming find/replace behind the `rewrite` verb. See rewrite.h for what
// was wrong with the per-chunk version this replaces. Portable C: no ptrace, no
// seccomp, no arm64 — so tests/test_rewrite.c drives every path on any host.
#include "rewrite.h"

#include <stdlib.h>
#include <string.h>

/* Grows `*buf` to at least `need` bytes. Keeps the existing contents, because
 * the carry buffer's held-back bytes are live data. */
static int ensure_cap(char **buf, size_t *cap, size_t need) {
    if (*cap >= need) return 0;
    size_t want = *cap ? *cap : 256;
    while (want < need) {
        if (want > (size_t)-1 / 2) { want = need; break; }
        want *= 2;
    }
    char *grown = realloc(*buf, want);
    if (!grown) return -1;
    *buf = grown;
    *cap = want;
    return 0;
}

int rewrite_stream_begin(struct rewrite_stream *s, const char *find, const char *replace) {
    if (!s) return -1;
    /* Normalised to "" rather than kept NULL, so a caller comparing two
     * streams' find strings (relayd.c's forward_stream does, to decide whether
     * the transform in force has changed) never has to special-case NULL. */
    s->find = find ? find : "";
    s->replace = replace ? replace : "";
    s->findlen = strlen(s->find);
    s->replacelen = strlen(s->replace);
    s->carry = NULL;
    s->carry_len = 0;
    s->carry_cap = 0;
    s->out = NULL;
    s->out_cap = 0;
    s->active = 1;
    return 0;
}

/* The scan itself, shared by push and finish.
 *
 * `hold` is what separates the two: while the stream is running the last
 * `findlen - 1` bytes are held back, because a match may continue into the
 * chunk that has not arrived yet. At finish there is no next chunk, so nothing
 * is held and the tail is emitted as it stands. (A complete match cannot hide
 * in the held tail — it is by construction shorter than the find string.) */
static int scan(struct rewrite_stream *s, int hold, const char **out, size_t *out_len) {
    const char *p = s->carry;
    size_t total = s->carry_len;

    if (s->findlen == 0) {
        /* No find string: forward unchanged. Still goes through the out buffer
         * so the caller's "pointer valid until the next call" contract holds
         * for every path. */
        if (ensure_cap(&s->out, &s->out_cap, total ? total : 1) != 0) return -1;
        memcpy(s->out, p, total);
        s->carry_len = 0;
        *out = s->out;
        *out_len = total;
        return 0;
    }

    /* Worst case: every findlen bytes becomes replacelen bytes, and whatever
     * does not divide evenly is copied through. Computed rather than assumed,
     * because assuming the output fits the input buffer is the bug. */
    size_t matches = total / s->findlen;
    size_t need = total + matches * s->replacelen + 1;
    if (ensure_cap(&s->out, &s->out_cap, need) != 0) return -1;

    /* The last position a match can START at and still be resolvable now. With
     * `hold`, that is total - findlen; anything after it might be the beginning
     * of a match completed by the next chunk, so it waits. */
    size_t limit = 0;
    if (hold) {
        if (total >= s->findlen) limit = total - (s->findlen - 1);
    } else {
        limit = total;
    }

    size_t i = 0, oi = 0;
    while (i < limit) {
        if (i + s->findlen <= total && memcmp(p + i, s->find, s->findlen) == 0) {
            memcpy(s->out + oi, s->replace, s->replacelen);
            oi += s->replacelen;
            i += s->findlen;
        } else {
            s->out[oi++] = p[i++];
        }
    }

    /* Whatever is left is the held tail: shorter than findlen by construction,
     * since the loop only stops short of `limit` by jumping over a match. */
    size_t left = total - i;
    if (left) memmove(s->carry, p + i, left);
    s->carry_len = left;

    *out = s->out;
    *out_len = oi;
    return 0;
}

int rewrite_stream_push(struct rewrite_stream *s, const char *chunk, size_t len,
                        const char **out, size_t *out_len) {
    if (!s || !s->active || !out || !out_len) return -1;
    *out = NULL;
    *out_len = 0;
    if (len && !chunk) return -1;

    if (ensure_cap(&s->carry, &s->carry_cap, s->carry_len + len + 1) != 0) return -1;
    if (len) memcpy(s->carry + s->carry_len, chunk, len);
    s->carry_len += len;

    return scan(s, 1, out, out_len);
}

int rewrite_stream_finish(struct rewrite_stream *s, const char **out, size_t *out_len) {
    if (!s || !s->active || !out || !out_len) return -1;
    *out = NULL;
    *out_len = 0;
    if (s->carry_len == 0) return 0;
    return scan(s, 0, out, out_len);
}

void rewrite_stream_end(struct rewrite_stream *s) {
    if (!s) return;
    free(s->carry);
    free(s->out);
    s->carry = NULL;
    s->out = NULL;
    s->carry_len = s->carry_cap = s->out_cap = 0;
    s->active = 0;
}
