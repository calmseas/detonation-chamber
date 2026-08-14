// runtime/images/guest-exec-relay/tests/test_protocol.c
//
// The request reader, driven over a real socketpair.
//
// Every test here writes raw bytes at one end and calls the SAME
// protocol_read_request that execrelayd calls at the other — no
// reimplementation of the framing, no in-memory stand-in for the socket, so
// the byte-at-a-time header reads, the length-prefixed payload reads and the
// short-read handling are all the production code paths.
//
// _GNU_SOURCE because this builds with -std=c11 (__STRICT_ANSI__), under which
// glibc declares no POSIX — socketpair and fork included.
//
// What is being defended: a request the relay cannot read EXACTLY must be
// refused, never half-executed. The original protocol put each argv element on
// its own `ARG <value>\n` line and compared nothing against the announced
// ARGC, so an element containing a newline arrived as a truncated argument
// plus a silently discarded remainder — the command ran, with a different argv
// than the caller asked for, and neither end could tell. Refusal is therefore
// the interesting behaviour, and it is what most of these tests assert.
#define _GNU_SOURCE
#include <assert.h>
#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#include "../src/protocol.h"

/* Writes `bytes` into one end of a socketpair, closes that end (so a frame
 * claiming more than was written meets EOF rather than blocking forever), and
 * reads one request off the other end. */
static int read_request_from(const void *bytes, size_t len,
                             struct exec_request *req, const char **why) {
    int sv[2];
    assert(socketpair(AF_UNIX, SOCK_STREAM, 0, sv) == 0);

    /* The largest request any test here sends is a few KiB, comfortably inside
     * a socket buffer, so this cannot deadlock against an unread peer. */
    assert(proto_write_full(sv[0], bytes, len) == (ssize_t)len);
    assert(shutdown(sv[0], SHUT_WR) == 0);

    *why = NULL;
    int rc = protocol_read_request(sv[1], req, why);
    close(sv[0]);
    close(sv[1]);
    return rc;
}

/* Asserts the request is refused, with the reason the caller expects. The
 * reason is asserted rather than just the refusal because these strings are
 * what a refused caller actually sees — protocol_error puts them in the
 * TAG_STDERR frame the stub prints and in relayd's log line — and a refusal
 * that names the wrong cause sends the next reader hunting in the wrong file.
 */
static void assert_refused(const char *bytes, size_t len, const char *expected_why) {
    struct exec_request req;
    const char *why = NULL;
    int rc = read_request_from(bytes, len, &req, &why);
    if (rc != PROTO_REFUSED) {
        fprintf(stderr, "expected refusal [%s], got rc=%d\n", expected_why, rc);
    }
    assert(rc == PROTO_REFUSED);
    assert(why != NULL);
    if (strcmp(why, expected_why) != 0) {
        fprintf(stderr, "expected refusal [%s], got [%s]\n", expected_why, why);
    }
    assert(strcmp(why, expected_why) == 0);
    /* A refusal must leave nothing to leak and nothing dangling: freeing a
     * half-built request has to be safe, which is why the argv slots past
     * argc are NULL rather than uninitialised. */
    protocol_request_free(&req);
}

static void assert_str_refused(const char *bytes, const char *expected_why) {
    assert_refused(bytes, strlen(bytes), expected_why);
}

/* ------------------------------ the happy path ----------------------------- */

static void test_a_well_formed_request_round_trips(void) {
    const char *wire =
        "ID 6\n" "turn-7"
        "ARGC 3\n"
        "ARG 7\n" "/bin/sh"
        "ARG 2\n" "-c"
        "ARG 9\n" "echo hi\n\n"
        "END\n";
    struct exec_request req;
    const char *why = NULL;
    assert(read_request_from(wire, strlen(wire), &req, &why) == PROTO_OK);

    assert(strcmp(req.id, "turn-7") == 0);
    assert(req.argc == 3);
    assert(strcmp(req.argv[0], "/bin/sh") == 0);
    assert(strcmp(req.argv[1], "-c") == 0);
    assert(strcmp(req.argv[2], "echo hi\n\n") == 0);
    /* NULL-terminated, which is what makes the array directly execve-able. */
    assert(req.argv[3] == NULL);
    protocol_request_free(&req);
    assert(req.argv[0] == NULL);
    assert(req.argc == 0);
}

static void test_an_argv_element_containing_a_newline_survives_intact(void) {
    /* C4 itself. This is the shape that used to be corrupted: a multi-line
     * `python -c` script is one argv element that happens to contain '\n'.
     * The payload here goes further and embeds the literal bytes `END\n` and
     * `ARG 4\n` — text that IS valid framing — precisely to prove the reader
     * never scans a payload for a delimiter. If it did, this script would be
     * truncated at its first newline and the rest re-read as headers. */
    const char *script =
        "import sys\n"
        "END\n"
        "ARG 4\n"
        "print('still one argument')\n";
    char wire[512];
    int n = snprintf(wire, sizeof(wire),
                     "ID 4\n" "t-42"
                     "ARGC 3\n"
                     "ARG 11\n" "/usr/bin/py"
                     "ARG 2\n" "-c"
                     "ARG %zu\n" "%s"
                     "END\n",
                     strlen(script), script);
    assert(n > 0 && (size_t)n < sizeof(wire));

    struct exec_request req;
    const char *why = NULL;
    assert(read_request_from(wire, (size_t)n, &req, &why) == PROTO_OK);
    assert(req.argc == 3);
    assert(strcmp(req.argv[2], script) == 0);   /* byte for byte, newlines and all */
    protocol_request_free(&req);
}

static void test_an_empty_argv_element_is_allowed(void) {
    /* `sh -c ''` is a real command. A zero-length frame must round-trip as an
     * empty string, not be confused with an absent one. */
    const char *wire =
        "ID 1\n" "t"
        "ARGC 2\n"
        "ARG 7\n" "/bin/sh"
        "ARG 0\n"
        "END\n";
    struct exec_request req;
    const char *why = NULL;
    assert(read_request_from(wire, strlen(wire), &req, &why) == PROTO_OK);
    assert(req.argc == 2);
    assert(req.argv[1] != NULL && req.argv[1][0] == '\0');
    protocol_request_free(&req);
}

static void test_a_request_without_an_id_keeps_the_placeholder(void) {
    /* The ID frame is optional on the wire; the id is what names the request
     * in the refusal log, so it must never be uninitialised. */
    const char *wire = "ARGC 1\n" "ARG 7\n" "/bin/sh" "END\n";
    struct exec_request req;
    const char *why = NULL;
    assert(read_request_from(wire, strlen(wire), &req, &why) == PROTO_OK);
    assert(strcmp(req.id, "-") == 0);
    protocol_request_free(&req);
}

/* -------------------------------- refusals -------------------------------- */

static void test_a_non_numeric_argc_is_refused(void) {
    /* atoi("3x") is 3, and the stream then desyncs against the bytes that
     * actually follow. The whole token must be digits. */
    assert_str_refused("ARGC 3x\n" "ARG 1\n" "a" "END\n", "ARGC out of range");
    assert_str_refused("ARGC \n" "END\n", "ARGC out of range");
    assert_str_refused("ARGC abc\n" "END\n", "ARGC out of range");
}

static void test_a_negative_or_zero_argc_is_refused(void) {
    /* Zero is refused as well as negative: a request with no argv[0] is not a
     * command, and `argc < 1` is what stops one reaching execve. */
    assert_str_refused("ARGC -1\n" "END\n", "ARGC out of range");
    assert_str_refused("ARGC 0\n" "END\n", "ARGC out of range");
}

static void test_an_argc_past_the_array_is_refused(void) {
    /* EXEC_RELAY_MAX_ARGV - 1, because the last slot holds the NULL that
     * terminates the array for execve. One past the limit must be refused
     * rather than written past the end of req.argv. */
    char wire[64];
    snprintf(wire, sizeof(wire), "ARGC %d\n" "END\n", EXEC_RELAY_MAX_ARGV);
    assert_str_refused(wire, "ARGC out of range");
    snprintf(wire, sizeof(wire), "ARGC 99999999999999999999\n" "END\n");
    assert_str_refused(wire, "ARGC out of range");  /* strtol range error */
}

static void test_fewer_arg_frames_than_argc_is_refused(void) {
    /* The desync that used to be undetectable from either end: argc was
     * parsed and range-checked, then never compared with what arrived. */
    assert_str_refused("ARGC 2\n" "ARG 7\n" "/bin/sh" "END\n",
                       "ARG frame count does not match ARGC");
}

static void test_more_arg_frames_than_argc_is_refused(void) {
    /* Caught at the frame rather than at END — the extra frame has nowhere to
     * be stored, so refusing later would mean either dropping it silently or
     * overrunning req.argv. */
    assert_str_refused("ARGC 1\n" "ARG 7\n" "/bin/sh" "ARG 2\n" "-c" "END\n",
                       "more ARG frames than ARGC announced");
}

static void test_a_frame_claiming_more_bytes_than_are_sent_is_refused(void) {
    /* The out-of-bounds/hang case: the header claims 100 bytes, 4 arrive, then
     * the peer hangs up. It must come back as a refusal — not a hang, and not
     * an argument built out of whatever was in the heap past those 4 bytes. */
    assert_str_refused("ARGC 1\n" "ARG 100\n" "/bin",
                       "short read on ARG frame");
    assert_str_refused("ID 100\n" "abc", "short read on ID frame");
}

/* A truncated ID frame must not leave the tracer's own stack readable as a turn
 * id.
 *
 * The refusal above (`short read on ID frame`) was already correct; what was not
 * is the state of `req->id` on the way out of it. The reader used to write the
 * NUL only on the success path — `if (proto_read_full(...) != len) return
 * refuse(...); req->id[len] = 0;` — so a frame declaring `ID 200` and delivering
 * 3 bytes returned with `req->id` holding those 3 bytes and then whatever the
 * caller's stack frame contained, with no terminator anywhere before the end of
 * the buffer. Both of the relay's refusal paths read that as a C string:
 * `logline("req id=%s ...")`, and — the one that matters — `disclosure_record`,
 * which composes it into a `protocol-refused` record and writes it to the
 * sealed disclosure stream. Uninitialised stack, sealed into the evidence
 * bundle as a turn id. Memory-safety bug and evidence-integrity bug, same line.
 *
 * `req` is deliberately POISONED before the call rather than left to chance:
 * `struct exec_request req;` in handle_conn is an uninitialised local, and a
 * test that happened to get a zeroed frame would pass against the broken reader
 * too. 0xAA is not NUL and is not a plausible id byte, so any of it surviving is
 * unambiguous.
 *
 * The assertion is not merely "terminated somewhere" but "every byte past what
 * actually arrived is zero" — a terminator with poison behind it would still be
 * a buffer that a future `memcpy(dst, req->id, sizeof(req->id))` copies stack
 * residue out of, and this reader is the only place that can promise otherwise. */
static void test_a_truncated_id_frame_leaves_no_uninitialised_stack_in_the_id(void) {
    static const char wire[] = "ID 200\n" "abc";

    int sv[2];
    assert(socketpair(AF_UNIX, SOCK_STREAM, 0, sv) == 0);
    assert(proto_write_full(sv[0], wire, sizeof(wire) - 1) == (ssize_t)(sizeof(wire) - 1));
    assert(shutdown(sv[0], SHUT_WR) == 0);

    struct exec_request req;
    memset(&req, 0xAA, sizeof(req));
    const char *why = NULL;
    int rc = protocol_read_request(sv[1], &req, &why);
    close(sv[0]);
    close(sv[1]);

    assert(rc == PROTO_REFUSED);
    assert(why != NULL && strcmp(why, "short read on ID frame") == 0);

    /* Exactly the three bytes that arrived, terminated. */
    assert(strlen(req.id) == 3);
    assert(memcmp(req.id, "abc", 3) == 0);
    /* And nothing but zeroes behind them, all the way to the end of the
     * buffer — no poison anywhere a consumer could reach. */
    for (size_t i = 3; i < sizeof(req.id); i++) {
        if (req.id[i] != 0) {
            fprintf(stderr, "req.id[%zu] = 0x%02x survived a truncated ID frame\n",
                    i, (unsigned char)req.id[i]);
        }
        assert(req.id[i] == 0);
    }

    protocol_request_free(&req);
}

/* The same guarantee for the frame that never arrives at all: an `ID <len>`
 * header whose payload is zero bytes long, and an id read that meets EOF
 * immediately. Neither can leave a partially-written buffer behind either. */
static void test_an_id_frame_with_no_payload_at_all_is_still_terminated(void) {
    int sv[2];
    assert(socketpair(AF_UNIX, SOCK_STREAM, 0, sv) == 0);
    static const char wire[] = "ID 12\n";
    assert(proto_write_full(sv[0], wire, sizeof(wire) - 1) == (ssize_t)(sizeof(wire) - 1));
    assert(shutdown(sv[0], SHUT_WR) == 0);

    struct exec_request req;
    memset(&req, 0xAA, sizeof(req));
    const char *why = NULL;
    int rc = protocol_read_request(sv[1], &req, &why);
    close(sv[0]);
    close(sv[1]);

    assert(rc == PROTO_REFUSED);
    assert(why != NULL && strcmp(why, "short read on ID frame") == 0);
    assert(req.id[0] == '\0');
    for (size_t i = 0; i < sizeof(req.id); i++) assert(req.id[i] == 0);
    protocol_request_free(&req);
}

/* A refusal reached BEFORE any ID frame arrives must leave the placeholder, not
 * poison: the same disclosure_record and logline read req->id on that path too,
 * and `handle_conn` additionally compares it against "-" to decide whether the
 * turn is identifiable enough to file a `protocol-abandoned` record against. */
static void test_a_refusal_before_any_id_frame_leaves_the_placeholder(void) {
    int sv[2];
    assert(socketpair(AF_UNIX, SOCK_STREAM, 0, sv) == 0);
    static const char wire[] = "ARGC 1\n" "ARGC 2\n" "END\n";
    assert(proto_write_full(sv[0], wire, sizeof(wire) - 1) == (ssize_t)(sizeof(wire) - 1));
    assert(shutdown(sv[0], SHUT_WR) == 0);

    struct exec_request req;
    memset(&req, 0xAA, sizeof(req));
    const char *why = NULL;
    int rc = protocol_read_request(sv[1], &req, &why);
    close(sv[0]);
    close(sv[1]);

    assert(rc == PROTO_REFUSED);
    assert(strcmp(req.id, "-") == 0);
    for (size_t i = 2; i < sizeof(req.id); i++) assert(req.id[i] == 0);
    protocol_request_free(&req);
}

static void test_an_oversize_frame_length_is_refused(void) {
    /* Refused on the header alone, before a single payload byte is read and
     * before malloc is asked for it — the bound exists to cap what one
     * connection can make the relay allocate. */
    char wire[128];
    snprintf(wire, sizeof(wire), "ARGC 1\n" "ARG %d\n", EXEC_RELAY_MAX_ARG_LEN + 1);
    assert_str_refused(wire, "ARG frame length out of range");
    snprintf(wire, sizeof(wire), "ID %d\n", EXEC_RELAY_MAX_ID_LEN + 1);
    assert_str_refused(wire, "ID frame length out of range");
    assert_str_refused("ARGC 1\n" "ARG -5\n", "ARG frame length out of range");
    assert_str_refused("ARGC 1\n" "ARG x\n", "ARG frame length out of range");
}

static void test_an_arg_frame_before_argc_is_refused(void) {
    assert_str_refused("ARG 7\n" "/bin/sh" "ARGC 1\n" "END\n",
                       "ARG frame before ARGC");
}

static void test_a_duplicate_argc_is_refused(void) {
    /* A second ARGC would silently redefine how many frames the first half of
     * the request was checked against. */
    assert_str_refused("ARGC 1\n" "ARGC 2\n" "END\n", "duplicate ARGC header");
}

static void test_end_with_no_argc_is_refused(void) {
    assert_str_refused("ID 1\n" "t" "END\n", "END with no ARGC header");
}

static void test_an_unrecognised_line_is_refused(void) {
    /* The `else` that was missing: an unknown line used to be dropped without
     * a word, which is exactly how the continuation of a split ARG line
     * disappeared. */
    assert_str_refused("ARGC 1\n" "ARGV 7\n" "/bin/sh" "END\n",
                       "unrecognised request line");
    assert_str_refused("\n" "ARGC 1\n" "END\n", "unrecognised request line");
}

static void test_an_overlong_header_line_is_refused(void) {
    /* Not truncated. The previous reader dropped everything past its buffer
     * and still reported success, so the remainder was re-interpreted as the
     * next header line — a request the relay had not read became a request it
     * ran anyway. */
    char wire[1024];
    memset(wire, 'A', sizeof(wire));
    wire[sizeof(wire) - 1] = '\n';
    assert_refused(wire, sizeof(wire), "header line too long");
}

static void test_a_connection_closed_mid_request_is_not_a_refusal(void) {
    /* Distinct from PROTO_REFUSED, because there is no longer a socket to
     * refuse on: the caller logs it and closes rather than trying to send
     * frames into a hung-up connection. */
    struct exec_request req;
    const char *why = NULL;
    assert(read_request_from("ARGC 1\n", 7, &req, &why) == PROTO_CLOSED);
    protocol_request_free(&req);

    assert(read_request_from("", 0, &req, &why) == PROTO_CLOSED);
    protocol_request_free(&req);
}

/* ---------------------------- interrupted reads ---------------------------- */

static volatile sig_atomic_t g_alarms = 0;
static void count_alarm(int sig) { (void)sig; g_alarms++; }

static void test_a_signal_mid_request_does_not_corrupt_it(void) {
    /* EINTR. The relay installs handlers (SIGCHLD from its workers, SIGTERM
     * for shutdown) and its reads are blocking, so a signal arriving between
     * frames is ordinary operation, not an edge case. Without the EINTR retry
     * a read returns -1 and a perfectly good request is refused — or worse,
     * half-read.
     *
     * Deliberately reproduced rather than reasoned about: SIGALRM every 2ms
     * with SA_RESTART OFF, against a writer that pauses mid-request, so the
     * blocking read is certain to be interrupted many times over. */
    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = count_alarm;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = 0;                     /* NOT SA_RESTART — that is the point */
    struct sigaction old;
    assert(sigaction(SIGALRM, &sa, &old) == 0);

    int sv[2];
    assert(socketpair(AF_UNIX, SOCK_STREAM, 0, sv) == 0);

    pid_t pid = fork();
    assert(pid >= 0);
    if (pid == 0) {
        /* Writer: send the request in pieces, pausing in the middle of a
         * length-prefixed payload so the reader is blocked inside read_full as
         * well as inside the header loop. */
        close(sv[1]);
        const char *head = "ID 4\n" "t-99" "ARGC 2\n" "ARG 7\n" "/bin/sh" "ARG 11\n" "hello";
        const char *tail = " world" "END\n";
        if (proto_write_full(sv[0], head, strlen(head)) < 0) _exit(1);
        struct timespec pause = { 0, 60 * 1000 * 1000 };  /* 60ms */
        nanosleep(&pause, NULL);
        if (proto_write_full(sv[0], tail, strlen(tail)) < 0) _exit(1);
        close(sv[0]);
        _exit(0);
    }
    close(sv[0]);

    struct itimerval it;
    it.it_interval.tv_sec = 0; it.it_interval.tv_usec = 2000;
    it.it_value.tv_sec = 0;    it.it_value.tv_usec = 2000;
    assert(setitimer(ITIMER_REAL, &it, NULL) == 0);

    struct exec_request req;
    const char *why = NULL;
    int rc = protocol_read_request(sv[1], &req, &why);

    struct itimerval off;
    memset(&off, 0, sizeof(off));
    setitimer(ITIMER_REAL, &off, NULL);
    sigaction(SIGALRM, &old, NULL);
    close(sv[1]);
    int st = 0;
    waitpid(pid, &st, 0);

    if (rc != PROTO_OK) fprintf(stderr, "interrupted request: rc=%d why=%s\n", rc, why ? why : "-");
    assert(rc == PROTO_OK);
    assert(req.argc == 2);
    assert(strcmp(req.id, "t-99") == 0);
    assert(strcmp(req.argv[0], "/bin/sh") == 0);
    assert(strcmp(req.argv[1], "hello world") == 0);
    protocol_request_free(&req);

    /* If no signal actually landed, the test proved nothing — say so rather
     * than passing on a technicality. */
    if (g_alarms == 0) {
        fprintf(stderr, "EINTR test is vacuous: no SIGALRM was delivered\n");
    }
    assert(g_alarms > 0);
}

/* ------------------------- the parsing primitive --------------------------- */

static void test_parse_count_rejects_everything_that_is_not_a_count(void) {
    long v = 12345;
    assert(proto_parse_count("0", &v) == 0 && v == 0);
    assert(proto_parse_count("42", &v) == 0 && v == 42);

    assert(proto_parse_count("", &v) != 0);        /* atoi() says 0 */
    assert(proto_parse_count(NULL, &v) != 0);
    assert(proto_parse_count("12x", &v) != 0);     /* atoi() says 12 */
    assert(proto_parse_count("12 ", &v) != 0);
    assert(proto_parse_count("0x10", &v) != 0);    /* not base 16, and not 0 either */
    assert(proto_parse_count("99999999999999999999", &v) != 0);  /* strtol range error */

    /* Bare strtol accepts all three of these — it skips leading whitespace and
     * takes a sign — so each is a case where the function's stated contract
     * ("the whole token is digits") and strtol's behaviour part company. Found
     * by this test, and fixed in proto_parse_count rather than papered over
     * here: a header the reader interprets more leniently than the header's
     * own documentation is how the next desync gets in. */
    assert(proto_parse_count(" 12", &v) != 0);
    assert(proto_parse_count("+12", &v) != 0);
    assert(proto_parse_count("-1", &v) != 0);
    assert(proto_parse_count("-0", &v) != 0);

    /* The value must be left alone on every rejection: a caller that checked
     * the return and then used `v` anyway would otherwise read a half-parse. */
    long keep = 777;
    assert(proto_parse_count("nope", &keep) != 0 && keep == 777);
}

/* --------------------------- the frame WRITER -----------------------------
 *
 * The response direction, which had no test at all while its only
 * implementation lived in relayd.c — the one file that compiles nowhere but
 * aarch64. What that bought: a writer able to compose a frame its own reader
 * refuses, which is what shipped once the rewrite verb stopped truncating an
 * expanding replacement. The transform's output is the command's output times
 * the rule's expansion factor, neither of which the relay bounds, so
 * `stdout_find: "/"` with a 15-byte replacement turned an 8 KiB read into a
 * single 122 KiB frame. The stub read the header, saw a length over its limit,
 * and abandoned the loop — losing that output AND the TAG_EXIT frame behind
 * it, so the caller got the stub's initialiser 1 instead of the real status.
 *
 * The reader below is deliberately a copy of stub.c's loop, including its
 * `len > EXEC_RELAY_MAX_FRAME_LEN` refusal, so the property under test is the
 * real one: what the writer emits, the real receiver accepts.
 */

/* The stub's own big-endian exit-code encoding. */
static void put_exit_payload(uint8_t p[4], int32_t code) {
    uint32_t c = (uint32_t)code;
    p[0] = (uint8_t)((c >> 24) & 0xff); p[1] = (uint8_t)((c >> 16) & 0xff);
    p[2] = (uint8_t)((c >> 8) & 0xff);  p[3] = (uint8_t)(c & 0xff);
}

static void test_a_stream_over_the_frame_limit_is_sliced_not_dropped(void) {
    /* Over the limit by more than 3x, and deliberately NOT a multiple of it, so
     * the short final slice is exercised alongside the full ones. */
    const size_t N = 200u * 1024u + 7u;
    char *payload = malloc(N);
    assert(payload != NULL);
    for (size_t i = 0; i < N; i++) payload[i] = (char)('a' + (i % 26));

    int sv[2];
    assert(socketpair(AF_UNIX, SOCK_STREAM, 0, sv) == 0);

    /* Forked, because 200 KiB does not fit a socket buffer: the writer must
     * block until the reader drains, which is precisely the streaming case. */
    pid_t pid = fork();
    assert(pid >= 0);
    if (pid == 0) {
        close(sv[1]);
        uint8_t ep[4];
        put_exit_payload(ep, 42);
        /* Exactly what forward_stream does with a rewritten chunk, followed by
         * the TAG_EXIT frame handle_conn sends behind it. */
        int ok = proto_send_stream(sv[0], TAG_STDOUT, payload, N) == 0
                 && proto_send_frame(sv[0], TAG_EXIT, ep, 4) == 0;
        close(sv[0]);
        _exit(ok ? 0 : 1);
    }
    close(sv[0]);

    char *got = malloc(N);
    assert(got != NULL);
    size_t got_len = 0;
    int frames = 0, saw_exit = 0, exit_code = 1;  /* stub.c's initialiser */
    for (;;) {
        uint8_t hdr[5];
        if (proto_read_full(sv[1], hdr, 5) != 5) break;
        uint32_t len = ((uint32_t)hdr[1] << 24) | ((uint32_t)hdr[2] << 16)
                       | ((uint32_t)hdr[3] << 8) | hdr[4];
        /* stub.c's refusal, reproduced. Pre-fix this tripped on the first
         * frame and the loop ended right here. */
        if (len > EXEC_RELAY_MAX_FRAME_LEN) {
            fprintf(stderr, "frame %d claims %u bytes, over the %d limit — the "
                            "receiver drops this and everything behind it\n",
                    frames, len, EXEC_RELAY_MAX_FRAME_LEN);
        }
        assert(len <= EXEC_RELAY_MAX_FRAME_LEN);
        if (hdr[0] == TAG_EXIT) {
            uint8_t p[4];
            assert(len == 4);
            assert(proto_read_full(sv[1], p, 4) == 4);
            exit_code = (int)(int32_t)(((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16)
                                       | ((uint32_t)p[2] << 8) | p[3]);
            saw_exit = 1;
            break;
        }
        assert(hdr[0] == TAG_STDOUT);
        assert(got_len + len <= N);
        assert(proto_read_full(sv[1], got + got_len, len) == (ssize_t)len);
        got_len += len;
        frames++;
    }
    close(sv[1]);
    int st = 0;
    waitpid(pid, &st, 0);
    assert(WIFEXITED(st) && WEXITSTATUS(st) == 0);

    /* (a) every byte arrives, in order, unaltered — not merely "under the
     * limit". */
    assert(got_len == N);
    assert(memcmp(got, payload, N) == 0);
    /* Sliced, not sent whole: at 200 KiB this is at least four frames. */
    assert(frames >= 4);
    /* (b) the exit code behind the output is still readable, and is the real
     * one rather than the receiver's fallback. */
    assert(saw_exit);
    assert(exit_code == 42);

    free(payload);
    free(got);
}

/* The common case must not have grown a frame: output under the limit is still
 * exactly one frame, so this fix costs the ordinary path nothing. */
static void test_a_stream_under_the_frame_limit_is_a_single_frame(void) {
    int sv[2];
    assert(socketpair(AF_UNIX, SOCK_STREAM, 0, sv) == 0);
    const char msg[] = "hello";
    assert(proto_send_stream(sv[0], TAG_STDOUT, msg, sizeof(msg) - 1) == 0);
    assert(shutdown(sv[0], SHUT_WR) == 0);

    uint8_t hdr[5];
    assert(proto_read_full(sv[1], hdr, 5) == 5);
    assert(hdr[0] == TAG_STDOUT);
    uint32_t len = ((uint32_t)hdr[1] << 24) | ((uint32_t)hdr[2] << 16)
                   | ((uint32_t)hdr[3] << 8) | hdr[4];
    assert(len == sizeof(msg) - 1);
    char buf[16];
    assert(proto_read_full(sv[1], buf, len) == (ssize_t)len);
    assert(memcmp(buf, msg, len) == 0);
    /* Nothing else: one frame, not one plus an empty terminator. */
    assert(proto_read_full(sv[1], hdr, 5) == 0);
    close(sv[0]);
    close(sv[1]);
}

/* The single-frame primitive REFUSES an over-limit payload rather than writing
 * one the peer will abandon. Without this, a future caller reaching for
 * proto_send_frame where it wanted proto_send_stream reintroduces the same
 * defect silently; here it fails at the call instead. */
static void test_a_single_frame_over_the_limit_is_refused(void) {
    int sv[2];
    assert(socketpair(AF_UNIX, SOCK_STREAM, 0, sv) == 0);
    size_t too_big = (size_t)EXEC_RELAY_MAX_FRAME_LEN + 1;
    char *payload = calloc(1, too_big);
    assert(payload != NULL);
    assert(proto_send_frame(sv[0], TAG_STDOUT, payload, (uint32_t)too_big) == -1);
    /* And wrote nothing at all — a lone header would desync every frame
     * after it. */
    assert(shutdown(sv[0], SHUT_WR) == 0);
    uint8_t hdr[5];
    assert(proto_read_full(sv[1], hdr, 5) == 0);
    free(payload);
    close(sv[0]);
    close(sv[1]);
}

int main(void) {
    test_a_well_formed_request_round_trips();
    test_an_argv_element_containing_a_newline_survives_intact();
    test_an_empty_argv_element_is_allowed();
    test_a_request_without_an_id_keeps_the_placeholder();

    test_a_non_numeric_argc_is_refused();
    test_a_negative_or_zero_argc_is_refused();
    test_an_argc_past_the_array_is_refused();
    test_fewer_arg_frames_than_argc_is_refused();
    test_more_arg_frames_than_argc_is_refused();
    test_a_frame_claiming_more_bytes_than_are_sent_is_refused();
    test_a_truncated_id_frame_leaves_no_uninitialised_stack_in_the_id();
    test_an_id_frame_with_no_payload_at_all_is_still_terminated();
    test_a_refusal_before_any_id_frame_leaves_the_placeholder();
    test_an_oversize_frame_length_is_refused();
    test_an_arg_frame_before_argc_is_refused();
    test_a_duplicate_argc_is_refused();
    test_end_with_no_argc_is_refused();
    test_an_unrecognised_line_is_refused();
    test_an_overlong_header_line_is_refused();
    test_a_connection_closed_mid_request_is_not_a_refusal();

    test_a_signal_mid_request_does_not_corrupt_it();
    test_parse_count_rejects_everything_that_is_not_a_count();

    test_a_stream_over_the_frame_limit_is_sliced_not_dropped();
    test_a_stream_under_the_frame_limit_is_a_single_frame();
    test_a_single_frame_over_the_limit_is_refused();

    printf("test_protocol: all tests passed\n");
    return 0;
}
