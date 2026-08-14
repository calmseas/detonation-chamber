#ifndef EXEC_RELAY_RECORD_H
#define EXEC_RELAY_RECORD_H

#include <stddef.h>

/* The buffer size every caller must use, and the size the per-field budgets in
 * record.c are proportioned against (there is a _Static_assert there tying the
 * two together).
 *
 * 4096 is PIPE_BUF, and that is the whole reason for the number. The record's
 * sink used to be an O_APPEND file, where a single write() of any size is
 * atomic against other writers; it is now `execrelayd`'s own stdout, which the
 * container runtime hands it as a PIPE (verified: /proc/1/fd/1 is
 * `pipe:[...]`). POSIX guarantees a pipe write is atomic only up to PIPE_BUF,
 * and every concurrent handler process shares this one descriptor — so a
 * record LARGER than PIPE_BUF could be split by the kernel and interleaved
 * with another handler's, producing exactly the corrupted, unparseable line
 * the single-write discipline exists to prevent. Keeping the whole record
 * under PIPE_BUF is what carries that guarantee across the transport change.
 */
#define DISCLOSURE_RECORD_BUF 4096

/* Formats ONE disclosure-log record — the line `execrelayd` appends for each
 * intercepted exec, and the line `chamber-run`'s `record_exec_consequence_log`
 * parses back out of the sealed bundle. Writes into `buf` (bounded by
 * `bufcap`, no NUL) and returns the number of bytes written, including the
 * trailing newline. `bufcap` is expected to be [`DISCLOSURE_RECORD_BUF`].
 *
 * This lives apart from relayd.c on purpose. relayd.c is Linux- and
 * aarch64-only (ptrace, seccomp, NT_PRSTATUS), so nothing in it can be
 * compiled by the host-run C unit tests — and that is precisely how a record
 * that interpolated two of its five fields with a raw %s shipped. The
 * consequence was invisible by construction: a rule named  pip "install"  —
 * ordinary operator config — emitted a line that is not JSON, and the Rust
 * consumer does `let Ok(value) = from_str(line) else { continue; }`, so the
 * exec vanished from the evidence with nothing anywhere saying so. Here the
 * composition itself is testable on any machine; see tests/test_record.c.
 *
 * Every string field is escaped (json_append_escaped). None may be added with
 * a raw %s, whatever its provenance: turn_id is guest-controlled, argv0 is
 * read from tracee memory, detail can carry a fixture's configured find
 * string, and matched_rule is operator config.
 *
 * A value too long for `bufcap` truncates that VALUE; the record is still
 * well-formed JSON, because losing a field's tail costs a detail while losing
 * the line costs the whole exec. Truncation lands on a UTF-8 CHARACTER
 * boundary, never inside a multi-byte sequence — see json_append_escaped.
 */
size_t disclosure_format_record(char *buf, size_t bufcap,
                                long ts_sec, long ts_msec,
                                const char *turn_id, const char *requested_argv0,
                                const char *matched_rule, const char *verb_applied,
                                const char *detail);

#endif
