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
    test_an_oversize_frame_length_is_refused();
    test_an_arg_frame_before_argc_is_refused();
    test_a_duplicate_argc_is_refused();
    test_end_with_no_argc_is_refused();
    test_an_unrecognised_line_is_refused();
    test_an_overlong_header_line_is_refused();
    test_a_connection_closed_mid_request_is_not_a_refusal();

    test_a_signal_mid_request_does_not_corrupt_it();
    test_parse_count_rejects_everything_that_is_not_a_count();

    printf("test_protocol: all tests passed\n");
    return 0;
}
