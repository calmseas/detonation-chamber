#ifndef EXEC_RELAY_PROTOCOL_H
#define EXEC_RELAY_PROTOCOL_H

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

/* Exit code the relay reports for a request it refused to run because the
 * request itself was malformed or internally inconsistent. Deliberately
 * distinct from every other code the caller can see: 111 is the stub's own
 * "could not reach the relay", 124 is the watchdog timeout, 125/126 are the
 * worker's pre-exec failures and 127 is "not found". */
#define EXIT_PROTOCOL_ERROR 112

#endif
