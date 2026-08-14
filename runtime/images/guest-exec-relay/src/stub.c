// runtime/images/guest-exec-relay/src/stub.c
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <stdint.h>
#include <stddef.h>
#include <errno.h>
#include <signal.h>
#include <sys/socket.h>
#include <sys/un.h>
#include "protocol.h"

/* Must match relayd.c's SOCK_ABSTRACT_NAME byte for byte — the two are a
 * matched pair with no filesystem artefact to discover the name from.
 *
 * Linux ABSTRACT namespace, not a path: the socket has no directory entry, so
 * it cannot be unlinked or pre-empted by anything holding mere write access to
 * /work — which the sandboxed agent under evaluation does hold, and can run
 * arbitrary root commands with. A filesystem socket there would be removable
 * and re-bindable by the agent, letting it switch off or impersonate the very
 * interception layer that is watching it. The leading NUL is prepended when
 * the address is built (see below); it is part of the name, not a terminator. */
#define SOCK_ABSTRACT_NAME "chamber-exec-relay"
_Static_assert(sizeof(SOCK_ABSTRACT_NAME) <= sizeof(((struct sockaddr_un *)0)->sun_path),
               "abstract socket name must fit sun_path alongside its leading NUL");

/* Mirror of relayd.c's fill_abstract_addr. The addrlen is what carries the
 * name's length to the kernel — an abstract name is not NUL-terminated — so it
 * must be offsetof(...sun_path) + 1 + strlen(name), never sizeof(*addr). */
static socklen_t fill_abstract_addr(struct sockaddr_un *addr) {
    memset(addr, 0, sizeof(*addr));
    addr->sun_family = AF_UNIX;
    size_t n = strlen(SOCK_ABSTRACT_NAME);
    addr->sun_path[0] = '\0';
    memcpy(addr->sun_path + 1, SOCK_ABSTRACT_NAME, n);
    return (socklen_t)(offsetof(struct sockaddr_un, sun_path) + 1 + n);
}

static ssize_t read_full(int fd, void *buf, size_t n) {
    char *p = buf; size_t left = n;
    while (left) {
        ssize_t r = read(fd, p, left);
        if (r < 0) { if (errno == EINTR) continue; return -1; }
        if (r == 0) return (ssize_t)(n - left);
        p += r; left -= r;
    }
    return (ssize_t)n;
}
static ssize_t write_full(int fd, const void *buf, size_t n) {
    const char *p = buf; size_t left = n;
    while (left) {
        ssize_t w = write(fd, p, left);
        /* EINTR is a retry, not a failure — it was treated as one here while
         * proto_write_full on the relay side has always retried. A signal
         * arriving mid-request would abandon the send and report it as a
         * broken connection. */
        if (w < 0) { if (errno == EINTR) continue; return -1; }
        if (w == 0) return -1;
        p += w; left -= w;
    }
    return (ssize_t)n;
}

/* Writes the whole request. Returns 0, or -1 if the connection could not be
 * written — which is a real and expected outcome, not an internal error: the
 * relay refuses an over-cap or malformed request BEFORE reading it, so a
 * request larger than the socket buffer is still being written when the refusal
 * arrives and the socket is closed behind it. main() reads the response
 * REGARDLESS of what this returns, which is the point of splitting it out; see
 * there. Every length bound is checked before main() even opens a socket, so
 * nothing in here can fail for a reason the caller could have prevented. */
static int send_request(int sfd, const char *id, size_t idlen,
                        int real_argc, char **real_argv) {
    char hdr[64];
    int n = snprintf(hdr, sizeof(hdr), "ID %zu\n", idlen);
    if (n < 0 || write_full(sfd, hdr, (size_t)n) < 0
        || (idlen && write_full(sfd, id, idlen) < 0)) {
        return -1;
    }
    n = snprintf(hdr, sizeof(hdr), "ARGC %d\n", real_argc);
    if (n < 0 || write_full(sfd, hdr, (size_t)n) < 0) return -1;
    for (int i = 0; i < real_argc; i++) {
        size_t len = strlen(real_argv[i]);
        n = snprintf(hdr, sizeof(hdr), "ARG %zu\n", len);
        if (n < 0 || write_full(sfd, hdr, (size_t)n) < 0
            || (len && write_full(sfd, real_argv[i], len) < 0)) {
            return -1;
        }
    }
    return write_full(sfd, "END\n", 4) < 0 ? -1 : 0;
}

/* The relay's own configuration, cleared out of THIS process before it does
 * anything else. Mirrors relayd.c's scrub_relay_private_env, and exists for a
 * window that one does not cover.
 *
 * execrelayd scrubs its own environment at startup, so no relayed worker
 * inherits the plan and /proc/1/environ no longer hands it out. But the stub is
 * not forked from execrelayd — it is started by `docker exec`, which builds its
 * environment from the CONTAINER's config, where the spec necessarily lives
 * (that is how the relay receives it in the first place). So every live stub
 * carried the full base64 ExecConsequencePlan in its own environ, and the
 * agent's commands run as root in the same cell: a relayed command that walked
 * /proc while any other turn was in flight could read the complete ruleset out
 * of that stub's /proc/<pid>/environ. Measured, on the otherwise-fixed image.
 *
 * The stub reads none of these variables and passes its environment to nothing
 * — the worker's environment comes from execrelayd, not from here — so clearing
 * them costs nothing. As in relayd.c, unsetenv() alone would not do: it rewrites
 * the `environ` array, while /proc/<pid>/environ is served from the original
 * stack region, which only overwriting the bytes in place clears. */
static void scrub_relay_private_env(void) {
    static const char *const RELAY_PRIVATE_ENV[] = {
        "CHAMBER_EXEC_CONSEQUENCE_SPEC_B64",
    };
    for (size_t i = 0; i < sizeof(RELAY_PRIVATE_ENV) / sizeof(RELAY_PRIVATE_ENV[0]); i++) {
        char *val = getenv(RELAY_PRIVATE_ENV[i]);
        if (val) memset(val, 0, strlen(val));
        unsetenv(RELAY_PRIVATE_ENV[i]);
    }
}

int main(int argc, char **argv) {
    /* First, before any failure path can return early and leave the window
     * open for the life of the process. */
    scrub_relay_private_env();

    /* This process WILL write into a socket the relay is entitled to close
     * before reading — that is what every pre-read refusal (the concurrency
     * cap, a reserve failure) looks like from here. With SIGPIPE's default
     * disposition that write kills the stub outright with signal 13, so
     * `docker exec` reports 141 and the framed refusal the relay had already
     * queued — TAG_STDERR explaining why, TAG_EXIT carrying
     * EXIT_PROTOCOL_ERROR — is never read at all. The whole refusal path round
     * 1 built is bypassed precisely when it fires.
     *
     * SIG_IGN turns that into an EPIPE return from write(), which write_full
     * reports and send_request propagates, and main then goes on to read the
     * response anyway (see below): the queued frames are still in this
     * process's receive buffer, because a peer's close() on an AF_UNIX stream
     * delivers what it already sent before it delivers EOF. Standard practice
     * for a network client, and here it is what makes the exit code mean
     * something. Nothing in this program relies on dying of SIGPIPE — it writes
     * to exactly one socket and to its own stdout/stderr, and a failed write to
     * either is checked. */
    signal(SIGPIPE, SIG_IGN);

    if (argc < 2) { fprintf(stderr, "usage: stub [--turn-id=ID] <argv0> [args...]\n"); return 2; }

    const char *id = "-";
    int start = 1;
    if (strncmp(argv[1], "--turn-id=", 10) == 0) {
        id = argv[1] + 10;
        start = 2;
    }
    if (argc <= start) { fprintf(stderr, "usage: stub [--turn-id=ID] <argv0> [args...]\n"); return 2; }
    int real_argc = argc - start;
    char **real_argv = argv + start;

    /* ---- every wire bound, checked BEFORE a socket exists --------------------
     *
     * All three of these were previously either absent or checked mid-send. The
     * argc one was absent entirely, and its absence is what made the SIGPIPE
     * race above deterministically reachable rather than merely possible: any
     * command with EXEC_RELAY_MAX_ARGV or more elements — 32, which a
     * `sh -c` with a long argument list or a `find ... -exec` reaches without
     * trying — was written in full, refused by the relay's ARGC range check
     * partway through, and the socket closed under a stub still writing. A
     * caller that cannot be served must be told so, not raced.
     *
     * Refused here as well as at the relay because only this side can name
     * WHICH argument was wrong, and because a request the protocol cannot carry
     * should not consume a connection (and, at the cap, a handler slot) to
     * discover that. Exit 2 is this program's own usage-error code, distinct
     * from the relay's 112 and from 111's "could not reach the relay". */
    if (real_argc > EXEC_RELAY_MAX_ARGV - 1) {
        fprintf(stderr,
                "stub: %d arguments is more than the relay protocol carries "
                "(limit %d, one slot reserved for the argv terminator)\n",
                real_argc, EXEC_RELAY_MAX_ARGV - 1);
        return 2;
    }
    size_t idlen = strlen(id);
    if (idlen > EXEC_RELAY_MAX_ID_LEN) {
        fprintf(stderr, "stub: turn id is too long (%zu bytes, limit %d)\n",
                idlen, EXEC_RELAY_MAX_ID_LEN);
        return 2;
    }
    for (int i = 0; i < real_argc; i++) {
        size_t len = strlen(real_argv[i]);
        if (len > EXEC_RELAY_MAX_ARG_LEN) {
            fprintf(stderr, "stub: argument %d is too long (%zu bytes, limit %d)\n",
                    i, len, EXEC_RELAY_MAX_ARG_LEN);
            return 2;
        }
    }

    int sfd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (sfd < 0) {
        perror("stub: socket");
        return 111;
    }
    struct sockaddr_un addr;
    socklen_t addrlen = fill_abstract_addr(&addr);
    if (connect(sfd, (struct sockaddr*)&addr, addrlen) != 0) {
        perror("stub: connect");
        close(sfd);
        return 111;
    }

    /* Length-prefixed values, per protocol.h. The header line is formatted into
     * a small buffer inside send_request; the VALUE is then written raw,
     * straight from argv, with no formatting step that could reinterpret any
     * byte in it. That is what makes an argv element containing a newline
     * survive: it is never spelled out as a line, so nothing downstream can
     * split it back into two.
     *
     * The return is deliberately NOT a `return 1` any more. A failed write here
     * means the relay closed its end while this process was still sending, and
     * the overwhelmingly likely reason is that it REFUSED the request before
     * reading it — in which case the refusal frames are already queued for this
     * process to read, and returning early would discard them and report the
     * stub's own generic 1 in place of the relay's 112. So the send's outcome
     * is noted and the read loop runs regardless; if there really is nothing to
     * read, the loop's first read fails, `exit_code` keeps its initialiser and
     * the outcome is what it would have been anyway. */
    errno = 0;
    int send_failed = send_request(sfd, id, idlen, real_argc, real_argv) != 0;
    int send_errno = errno;

    /* One logical stream is one OR MORE frames of the same tag: each output
     * frame's payload is written straight through in arrival order, so
     * concatenation is what this loop already does and always did. That is what
     * lets the relay slice an output larger than EXEC_RELAY_MAX_FRAME_LEN into
     * several frames rather than composing one the loop below would refuse —
     * see proto_send_stream. Only TAG_EXIT ends the loop.
     *
     * The initialiser matters to that refusal: an over-long frame `break`s
     * without ever reaching the TAG_EXIT frame behind it, so the caller would
     * see this 1 rather than the command's real status. Output loss and a
     * corrupted exit code, from the same byte. */
    int exit_code = 1;
    int got_exit = 0;
    for (;;) {
        uint8_t hdr[5];
        if (read_full(sfd, hdr, 5) != 5) break;
        uint32_t len = ((uint32_t)hdr[1]<<24)|((uint32_t)hdr[2]<<16)|((uint32_t)hdr[3]<<8)|hdr[4];
        uint8_t tag = hdr[0];
        if (len > EXEC_RELAY_MAX_FRAME_LEN) break;
        if (tag == TAG_EXIT) {
            uint8_t p[4];
            if (len == 4 && read_full(sfd, p, 4) == 4) {
                int32_t code = (int32_t)(((uint32_t)p[0]<<24)|((uint32_t)p[1]<<16)|((uint32_t)p[2]<<8)|p[3]);
                exit_code = code;
                got_exit = 1;
            }
            break;
        } else if (tag == TAG_STDOUT || tag == TAG_STDERR) {
            char *buf = malloc(len ? len : 1);
            if (!buf) break;
            if (len && read_full(sfd, buf, len) != (ssize_t)len) { free(buf); break; }
            int outfd = (tag == TAG_STDOUT) ? STDOUT_FILENO : STDERR_FILENO;
            if (write_full(outfd, buf, len) < 0) { free(buf); break; }
            free(buf);
        } else {
            break;
        }
    }
    close(sfd);
    /* A send that failed AND no framed answer behind it is the one case where
     * the caller is left with nothing but this process's default exit 1. Say so
     * on stderr — otherwise a genuinely broken connection is indistinguishable
     * from a command that ran and returned 1, which is the same conflation the
     * framed refusal path exists to remove. When the send failed but a TAG_EXIT
     * DID arrive (the ordinary refuse-before-read case) there is nothing to
     * report: the relay's own message was already relayed to stderr and its
     * exit code is being returned. */
    if (send_failed && !got_exit) {
        fprintf(stderr, "stub: the relay closed the connection while the request was still "
                        "being sent, and sent nothing to read back: %s\n",
                send_errno ? strerror(send_errno) : "connection closed");
    }
    return exit_code;
}
