#ifndef EXEC_RELAY_PROTOCOL_H
#define EXEC_RELAY_PROTOCOL_H

#include <stddef.h>
#include <stdint.h>
#include <sys/types.h>

/* The stub -> relayd request framing, in ONE place because both ends have to
 * agree byte for byte and a duplicated constant is a desync waiting to happen.
 * (SOCK_ABSTRACT_NAME is still declared separately in each file — see the
 * matched-pair notes there; it predates this header and is deliberately left
 * alone.)
 *
 *   ID <len>\n   <len bytes>        the turn id, verbatim
 *   ARGC <n>\n                      how many ARG frames follow
 *   ARG <len>\n  <len bytes>        one argv element, verbatim   (n times)
 *   END\n
 *
 * The headers are lines; the VALUES are length-prefixed and read as exactly
 * <len> bytes, never scanned for a delimiter.
 *
 * That distinction is the whole point. The original format put each argv
 * element on its own `ARG <value>\n` line, so an element containing a newline
 * — a heredoc, a multi-line `python -c` script, routine shapes for a live
 * driving agent — arrived as two lines: the first matched `ARG ` and was taken
 * as a truncated argument, and the second matched no prefix at all and was
 * silently discarded. Nothing reported it, and because the receiver never
 * compared the number of ARG lines it got against the ARGC it was told, the
 * desync was undetectable from either end: the command simply ran with a
 * quietly different argv than the caller asked for.
 *
 * The response direction (TAG_STDOUT/TAG_STDERR/TAG_EXIT frames) was already
 * length-prefixed and is unchanged.
 */

/* Longest single argv element the relay will accept. Generous — a multi-line
 * script passed as one `-c` argument is the shape this exists for — while
 * still bounding what one connection can make the relay allocate
 * (EXEC_RELAY_MAX_ARGV frames of this size). */
#define EXEC_RELAY_MAX_ARG_LEN 65536

/* Longest turn id. The receiver stores it in a fixed buffer of this size + 1
 * and the id is a bridge-generated token, not free-form text. */
#define EXEC_RELAY_MAX_ID_LEN 255

/* Most argv elements one request may carry, counting argv[0]. It lives here,
 * with the other wire limits, because it is what bounds the number of ARG
 * frames a single connection can make the relay allocate; config.h includes
 * this header and reuses it to size the rule-matching arrays, so a rule can
 * never be written that could not be expressed as a request. A request is
 * refused above MAX_ARGV - 1 elements: the last slot belongs to the NULL that
 * terminates the array for execve. */
#define EXEC_RELAY_MAX_ARGV 32

/* Exit code the relay reports for a request it refused to run because the
 * request itself was malformed or internally inconsistent. Deliberately
 * distinct from every other code the caller can see: 111 is the stub's own
 * "could not reach the relay", 124 is the watchdog timeout, 125/126 are the
 * worker's pre-exec failures and 127 is "not found". */
#define EXIT_PROTOCOL_ERROR 112

/* ------------------------ the response direction --------------------------
 *
 *   <tag:1> <len:4 big-endian>  <len bytes>
 *
 * TAG_STDOUT/TAG_STDERR carry output; TAG_EXIT carries a 4-byte big-endian
 * exit code and ends the response. A single logical stream is ONE OR MORE
 * frames of the same tag: the receiver concatenates them in arrival order and
 * stops at TAG_EXIT. */
#define TAG_STDOUT 1
#define TAG_STDERR 2
#define TAG_EXIT   3

/* The largest payload one frame may carry, and the hard limit the receiver
 * enforces: a frame claiming more than this makes the stub abandon its read
 * loop outright.
 *
 * It lives HERE, with the rest of the wire limits, because the two ends must
 * agree on it byte for byte and they used to not even share the definition —
 * stub.c owned it alone, as a private MAX_FRAME_LEN, while relayd.c had no
 * notion of a frame ceiling at all and simply passed whatever length it had to
 * send_frame.
 *
 * That asymmetry was a live defect, not a tidiness problem. The rewrite verb's
 * transform legitimately EXPANDS its input — that is what a replacement longer
 * than its find string does — and once the truncation-within-the-buffer bug was
 * fixed, the expanded result was handed to send_frame whole. An 8 KiB read of
 * slash-heavy output under `stdout_find: "/"`, `stdout_replace:
 * "[REDACTED-PATH]"` is 8192 x 15 = 122880 bytes: one frame, nearly twice this
 * limit. The stub read the header, saw the over-long length, and `break`ed —
 * dropping that output AND never reading the TAG_EXIT frame behind it, so it
 * returned its initialiser `exit_code = 1` and the real exit code was lost too.
 * Silent truncation plus a corrupted exit status, from a rule doing exactly
 * what it was configured to do.
 *
 * proto_send_stream below is the fix, and this constant is what it slices on.
 * Anything writing output frames must go through it rather than composing a
 * frame by hand. */
#define EXEC_RELAY_MAX_FRAME_LEN 65536

/* ------------------------------- the reader -------------------------------
 *
 * The receiving half of the framing above, implemented in protocol.c and NOT
 * in relayd.c — for the same reason record.c exists. relayd.c carries an
 * `#error` for anything but aarch64 (seccomp arch gate, arm64 register
 * plumbing), so no line in that file can be compiled by the host-run C unit
 * tests on CI's x86_64 runner. A parser that lives there is a parser whose
 * refusal paths can only ever be checked by hand, once, by whoever last
 * touched it — which is precisely how the record composition that shipped
 * un-escaped shipped. Here every refusal is reachable from
 * tests/test_protocol.c over a socketpair, on any host.
 *
 * Nothing below touches ptrace, seccomp or any architecture-specific header:
 * it is read(2) and strtol.
 */

/* Outcomes of reading one request. The two failures are distinct because the
 * caller must answer them differently: a REFUSED request has a live socket to
 * refuse ON (a TAG_STDERR frame plus TAG_EXIT/EXIT_PROTOCOL_ERROR, so the
 * caller learns what was wrong), while a CLOSED one has nothing left to
 * answer on and only warrants a log line. Conflating them is how a
 * desynchronised request used to become a bare EOF the caller had to guess
 * about. */
#define PROTO_OK       0
#define PROTO_REFUSED (-1)
#define PROTO_CLOSED  (-2)

struct exec_request {
    /* The turn id, or "-" if the request carried no ID frame. Valid to read
     * even on a refusal — the caller names it in the refusal log, and a
     * request that got far enough to send its id should be identifiable. */
    char id[EXEC_RELAY_MAX_ID_LEN + 1];
    /* argv[0 .. argc) are malloc'd and NUL-terminated; every remaining slot is
     * NULL, so the array is directly passable to execve. Release with
     * protocol_request_free, including after a refusal. */
    char *argv[EXEC_RELAY_MAX_ARGV];
    int argc;
};

/* Reads exactly one request from a connected socket, blocking until it has the
 * whole thing. Returns PROTO_OK / PROTO_REFUSED / PROTO_CLOSED; on
 * PROTO_REFUSED, *why is set to a short static description of what was wrong
 * (never NULL, safe to put in a log line and in the frame sent back).
 *
 * Refuses — rather than half-accepts — every request it cannot read exactly:
 * an ARGC that is not a whole decimal number, an ARGC that does not match the
 * number of ARG frames that actually arrived, a frame claiming more bytes than
 * the peer sends, a header line longer than the reader's buffer, an
 * unrecognised line. A partially understood request must never become a
 * partially executed one; that is the entire defect this reader exists to make
 * impossible, and each of those paths has a test.
 *
 * `req` need not be initialised by the caller; this fills it. */
int protocol_read_request(int fd, struct exec_request *req, const char **why);

/* Frees the argv elements and re-NULLs them. Idempotent, and correct on a
 * request that was refused half-way through. */
void protocol_request_free(struct exec_request *req);

/* ---- the two primitives, exposed so their edges can be tested directly ---- */

/* Reads a '\n'-terminated HEADER line, byte at a time (every line in this
 * protocol is a short fixed-shape header; the variable-length payloads are
 * length-prefixed and read with proto_read_full, never through here).
 *
 * Returns the line's length, or one of the negative codes below. It does NOT
 * truncate: the previous version silently dropped everything past the buffer
 * and still returned success, so an over-long line was indistinguishable from
 * a well-formed short one and the remainder was re-interpreted as the next
 * line. */
#define READ_LINE_EOF      (-1)
#define READ_LINE_OVERFLOW (-2)
int proto_read_line(int fd, char *buf, size_t bufsz);

/* Strict decimal parse of a frame length / count: the WHOLE token must be
 * digits, and the value must be non-negative and within `long`. atoi() would
 * read "12x" as 12 and "" as 0, both of which desync a length-prefixed stream
 * against the bytes that actually follow. Returns 0 on success. */
int proto_parse_count(const char *s, long *out);

/* Loop-until-complete read/write. proto_read_full returns the number of bytes
 * read, which is SHORT (not -1) if the peer closed early — that short return
 * is what turns "claimed 100 bytes, sent 10, hung up" into a refusal instead
 * of a hang or a read of uninitialised memory. Both retry on EINTR. */
ssize_t proto_read_full(int fd, void *buf, size_t n);
ssize_t proto_write_full(int fd, const void *buf, size_t n);

/* ---------------------------- the frame writer ----------------------------
 *
 * Both live here rather than in relayd.c for the reason the reader does:
 * nothing in relayd.c can be compiled off aarch64, so a frame writer living
 * there is a frame writer no test can reach — and "the writer can emit a frame
 * the reader refuses" is precisely the class of defect that shipped.
 *
 * proto_send_frame writes ONE frame and refuses (-1, nothing written) a
 * payload over EXEC_RELAY_MAX_FRAME_LEN, so the un-sliced call cannot silently
 * produce a frame the peer will reject. Use it for the fixed-size control
 * frames — TAG_EXIT's 4 bytes, a bounded TAG_STDERR refusal message.
 *
 * proto_send_stream writes `len` bytes as as many same-tag frames as it takes,
 * none over the limit, and is what every OUTPUT path must use: output length is
 * a function of the command's behaviour and the rewrite rule's expansion
 * factor, neither of which this process gets to bound. A zero-length call
 * writes one empty frame, exactly as a single proto_send_frame would.
 *
 * Both return 0 on success and -1 if the connection could not be written.
 */
int proto_send_frame(int fd, uint8_t tag, const void *payload, uint32_t len);
int proto_send_stream(int fd, uint8_t tag, const void *payload, size_t len);

#endif
