// runtime/images/guest-exec-relay/src/protocol.c
//
// The receiving half of the stub -> relayd request framing described in
// protocol.h. Portable C over read(2) and strtol: no ptrace, no seccomp, no
// arm64 registers, nothing that requires the aarch64 Linux guest — which is
// what lets tests/test_protocol.c drive every refusal path over a socketpair
// on an ordinary x86_64 CI host. See the header for why that matters.
//
// _GNU_SOURCE, as in relayd.c and stub.c: the unit tests build with -std=c11,
// which defines __STRICT_ANSI__, under which glibc declares no POSIX at all —
// read(2) included.
#define _GNU_SOURCE
#include "protocol.h"

#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

ssize_t proto_write_full(int fd, const void *buf, size_t n) {
    const char *p = buf; size_t left = n;
    while (left) {
        ssize_t w = write(fd, p, left);
        if (w < 0) { if (errno == EINTR) continue; return -1; }
        if (w == 0) return -1;
        p += w; left -= w;
    }
    return (ssize_t)n;
}

ssize_t proto_read_full(int fd, void *buf, size_t n) {
    char *p = buf; size_t left = n;
    while (left) {
        ssize_t r = read(fd, p, left);
        if (r < 0) { if (errno == EINTR) continue; return -1; }
        if (r == 0) return (ssize_t)(n - left);
        p += r; left -= r;
    }
    return (ssize_t)n;
}

int proto_read_line(int fd, char *buf, size_t bufsz) {
    size_t i = 0;
    for (;;) {
        char c;
        ssize_t r = read(fd, &c, 1);
        if (r < 0 && errno == EINTR) continue;
        if (r <= 0) return READ_LINE_EOF;
        if (c == '\n') { buf[i] = 0; return (int)i; }
        if (i + 1 >= bufsz) return READ_LINE_OVERFLOW;
        buf[i++] = c;
    }
}

int proto_parse_count(const char *s, long *out) {
    /* strtol on its own is not the strict parse this needs: it skips leading
     * whitespace and accepts a leading '+' or '-', so " 12", "+12" and "-0"
     * would all come back as successes. Requiring the first character to be a
     * digit rejects those up front and leaves strtol only the part it is
     * good at. (Explicit range rather than isdigit(): no locale in the way.) */
    if (!s || *s < '0' || *s > '9') return -1;
    errno = 0;
    char *end = NULL;
    long v = strtol(s, &end, 10);
    if (errno != 0 || end == s || *end != '\0' || v < 0) return -1;
    *out = v;
    return 0;
}

void protocol_request_free(struct exec_request *req) {
    if (!req) return;
    for (int i = 0; i < EXEC_RELAY_MAX_ARGV; i++) {
        free(req->argv[i]);
        req->argv[i] = NULL;
    }
    req->argc = 0;
}

/* Every refusal leaves through here: one place that sets the reason and one
 * return value, so a path cannot be added that refuses without saying why. */
static int refuse(const char **why, const char *what) {
    if (why) *why = what;
    return PROTO_REFUSED;
}

int protocol_read_request(int fd, struct exec_request *req, const char **why) {
    char line[256];
    long argc = -1;   /* -1 until an ARGC header has actually been seen */

    memcpy(req->id, "-", 2);
    req->argc = 0;
    for (int i = 0; i < EXEC_RELAY_MAX_ARGV; i++) req->argv[i] = NULL;
    if (why) *why = NULL;

    for (;;) {
        int n = proto_read_line(fd, line, sizeof(line));
        if (n == READ_LINE_OVERFLOW) return refuse(why, "header line too long");
        if (n < 0) return PROTO_CLOSED;  /* EOF before END: nothing to run */

        if (strncmp(line, "ID ", 3) == 0) {
            long len;
            if (proto_parse_count(line + 3, &len) != 0 || len > EXEC_RELAY_MAX_ID_LEN)
                return refuse(why, "ID frame length out of range");
            if (len && proto_read_full(fd, req->id, (size_t)len) != (ssize_t)len)
                return refuse(why, "short read on ID frame");
            req->id[len] = 0;
        } else if (strncmp(line, "ARGC ", 5) == 0) {
            if (argc >= 0) return refuse(why, "duplicate ARGC header");
            if (proto_parse_count(line + 5, &argc) != 0
                || argc < 1 || argc > EXEC_RELAY_MAX_ARGV - 1)
                return refuse(why, "ARGC out of range");
        } else if (strncmp(line, "ARG ", 4) == 0) {
            if (argc < 0) return refuse(why, "ARG frame before ARGC");
            if (req->argc >= (int)argc)
                return refuse(why, "more ARG frames than ARGC announced");
            long len;
            if (proto_parse_count(line + 4, &len) != 0 || len > EXEC_RELAY_MAX_ARG_LEN)
                return refuse(why, "ARG frame length out of range");
            /* The payload is read as EXACTLY len bytes and is never scanned for
             * a delimiter, which is the whole point of the length prefix: an
             * argv element containing '\n' (a heredoc, a multi-line `python -c`
             * script) arrives byte for byte instead of being split into a line
             * that matched and a remainder that silently vanished. */
            char *val = malloc((size_t)len + 1);
            if (!val) return refuse(why, "out of memory");
            if (len && proto_read_full(fd, val, (size_t)len) != (ssize_t)len) {
                free(val);
                return refuse(why, "short read on ARG frame");
            }
            val[len] = 0;
            req->argv[req->argc++] = val;
        } else if (strcmp(line, "END") == 0) {
            break;
        } else {
            /* The `else` that was missing. An unrecognised line used to be
             * dropped on the floor without a word, which is exactly how the
             * continuation of a split ARG line disappeared. */
            return refuse(why, "unrecognised request line");
        }
    }

    /* Reconcile what was announced against what actually arrived. Neither side
     * could previously detect a desync at all: argc was parsed, range-checked,
     * and then never compared with the number of ARG frames received. */
    if (argc < 0) return refuse(why, "END with no ARGC header");
    if (req->argc != (int)argc) return refuse(why, "ARG frame count does not match ARGC");
    if (!req->argv[0]) return refuse(why, "no argv[0]");

    return PROTO_OK;
}
