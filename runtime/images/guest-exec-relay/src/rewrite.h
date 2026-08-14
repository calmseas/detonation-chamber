#ifndef EXEC_RELAY_REWRITE_H
#define EXEC_RELAY_REWRITE_H

#include <stddef.h>

/* The `rewrite` verb's output transform, as a STREAM rather than a per-chunk
 * function.
 *
 * It lives here, apart from relayd.c, for the reason record.c and protocol.c
 * do: relayd.c carries an `#error` for anything but aarch64, so nothing in it
 * can be compiled by the host-run C unit tests — and the defect this module
 * exists to fix was invisible for exactly that reason. Every case below is
 * driven directly from tests/test_rewrite.c on any host.
 *
 * # What was wrong with the per-chunk version
 *
 * The transform used to be applied independently to each `read()` from the
 * traced process's stdout/stderr pipe, with no memory between reads. A find
 * string STRADDLING a chunk boundary therefore matched nothing, and the
 * untransformed original bytes were forwarded to the host — which is precisely
 * the leak this verb exists to prevent. A traced process only has to write in
 * two pieces (`printf SEC; printf RET`, or any output over 8 KiB, or any output
 * flushed line by line) for the find string to be split, and nothing anywhere
 * reported that a configured rule had silently not fired.
 *
 * Separately, the output buffer was a fixed 8 KiB — the same size as the input
 * read buffer — with a bounds guard that simply stopped copying when it filled.
 * A replacement LONGER than the string it replaces therefore truncated the
 * command's output silently, so a rule that expanded its input corrupted the
 * very stream it was supposed to be sanitising.
 *
 * # How this fixes both
 *
 * A sliding window: after each chunk the last `findlen - 1` bytes are HELD
 * BACK, not forwarded, so the next chunk is scanned with enough leading context
 * to see a match that spans the boundary. Held bytes are released by
 * `rewrite_stream_finish` when the stream ends, so nothing is ever lost — only
 * delayed. And the output buffer is sized from the actual worst case for this
 * find/replace pair and grown as needed, so an expanding replacement expands.
 *
 * # Ordering contract
 *
 *   begin() -> push() * n -> finish() -> end()
 *
 * `push` and `finish` hand back a pointer INTO the stream's own buffer, valid
 * until the next call on that stream. The caller forwards those bytes; it never
 * frees them.
 */
struct rewrite_stream {
    const char *find;
    const char *replace;
    size_t findlen;
    size_t replacelen;
    /* Bytes held back because they might be the start of a match that the next
     * chunk completes. Always shorter than `findlen`. Doubles as the working
     * buffer: an incoming chunk is appended here and the whole thing scanned. */
    char *carry;
    size_t carry_len;
    size_t carry_cap;
    /* The transformed bytes handed back to the caller. Grown to fit; never
     * truncated. */
    char *out;
    size_t out_cap;
    int active;
};

/* Arms `s` with a find/replace pair. `find` and `replace` must outlive the
 * stream (they are the loaded rule's own storage, which lives for the process).
 * A NULL or empty `find` is legal and means "forward unchanged" — the same
 * meaning the old per-chunk function gave it. Returns 0, or -1 if `s` is NULL.
 * Re-arming an already-armed stream is a caller error; call end() first. */
int rewrite_stream_begin(struct rewrite_stream *s, const char *find, const char *replace);

/* Feeds one chunk. On success sets `*out`/`*out_len` to the bytes ready to
 * forward now (possibly zero: a chunk shorter than the find string may be
 * entirely held back) and returns 0. Returns -1 only on allocation failure, in
 * which case nothing is forwarded — deliberately fail-CLOSED, since the
 * alternative is emitting the untransformed bytes the rule exists to remove. */
int rewrite_stream_push(struct rewrite_stream *s, const char *chunk, size_t len,
                        const char **out, size_t *out_len);

/* Ends the stream, releasing whatever is still held back. Call this when the
 * pipe reaches EOF, or the tail of the last chunk is dropped. Same return
 * convention as push. */
int rewrite_stream_finish(struct rewrite_stream *s, const char **out, size_t *out_len);

/* Frees the buffers and disarms. Idempotent, and safe on a zeroed struct. */
void rewrite_stream_end(struct rewrite_stream *s);

#endif
