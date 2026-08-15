// runtime/images/guest-exec-relay/src/relayd.c
#define _GNU_SOURCE

/* execrelayd is aarch64-only, by decision rather than by omission — see the
 * design artefact agenticpractices:artefact:2rau75fl5jsg3c4c8pla §7. Everything
 * below that touches the tracee's registers is arm64-shaped: the seccomp
 * filter admits only AUDIT_ARCH_AARCH64 (anything else is KILL_PROCESS),
 * `struct arm64_regs` mirrors the kernel's user_pt_regs, and the verb dispatch
 * reads and writes regs[0]/regs[1]/regs[2] as the execve/execveat argument
 * registers. On any other architecture that is not a degraded mode: it is a
 * relay that kills every worker it supervises before the worker's execve
 * completes, which is what the CI job added alongside this file would have
 * done on its x86_64 runner. Fail at build time, where the cause is legible.
 *
 * Deliberately ABOVE the includes: this must be the first thing a wrong-arch
 * build reports, rather than the reader having to work back to it from
 * whichever Linux header happened to break first. */
#if !defined(__aarch64__)
#error "execrelayd is aarch64-only (seccomp arch gate + arm64 register plumbing); see design artefact agenticpractices:artefact:2rau75fl5jsg3c4c8pla section 7. Build this image with --platform linux/arm64."
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <fcntl.h>
#include <errno.h>
#include <stdint.h>
#include <stdarg.h>
#include <stddef.h>
#include <time.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/stat.h>
#include <sys/ptrace.h>
#include <sys/uio.h>
#include <sys/prctl.h>
#include <poll.h>
#include <sys/signalfd.h>
#include <sys/syscall.h>
#include <linux/seccomp.h>
#include <linux/filter.h>
#include <linux/audit.h>
#include <linux/elf.h>
#include "config.h"
#include "json.h"
#include "base64.h"
#include "protocol.h"
#include "record.h"
#include "rewrite.h"
#include "scratch.h"

/* ---- aarch64 register set (matches kernel struct user_pt_regs / NT_PRSTATUS) ---- */
struct arm64_regs {
    unsigned long long regs[31];
    unsigned long long sp;
    unsigned long long pc;
    unsigned long long pstate;
};

/* execrelayd has NO filesystem footprint of its own, deliberately — neither
 * for its control channel nor for its evidence.
 *
 * The CONTROL SOCKET is in Linux's ABSTRACT socket namespace, which has no
 * filesystem entry at all: the name is owned by the network namespace, not by
 * any directory. /work is writable by the sandboxed agent under evaluation,
 * and TurnDirective::RunCommand runs arbitrary commands in the cell as root,
 * so a socket at a path under /work could be `rm`ed and re-bound by the very
 * agent this relay exists to observe — disabling or spoofing the entire
 * interception mechanism. Abstract-namespace means filesystem write access to
 * /work grants no purchase on it, the name cannot be pre-empted while
 * execrelayd holds it (a second bind() gets EADDRINUSE) nor unlinked, and it
 * vanishes with the socket, so there is no stale entry to clean up on restart.
 *
 * The DISCLOSURE LOG used to be a plain file, /work/.exec-relay/disclosure.log,
 * and that was the one part of this mechanism the paragraph above did not
 * cover. Design §2 requires the log to be "no more writable (or more
 * deletable) by the agent than the mechanism's own control channel is", and a
 * file in the agent-writable /work tmpfs plainly was: a root-in-cell agent
 * could `rm` or truncate the sealed evidence before the host ever read it, and
 * the host's read (a `docker exec cat`) would report success on the empty
 * result. Records now stream out over THIS PROCESS'S OWN STDOUT — see
 * disclosure_init below — which the container runtime captures to host-side
 * storage as each line is produced, outside the container's filesystem
 * entirely. Deleting a file the agent can reach no longer affects what has
 * already been captured, because there is no file. (Design §6;
 * agenticpractices:decision:jbtd8mbc85dauq7628rx.)
 *
 * Nothing else needed /work/.exec-relay/, so the directory is not created at
 * all any more. */

/* The abstract name, WITHOUT its leading NUL — that byte is prepended when the
 * address is filled in. stub.c must define this to the identical string; the
 * two are a matched pair and there is no filesystem artefact to discover it
 * from at runtime. */
#define SOCK_ABSTRACT_NAME "chamber-exec-relay"
_Static_assert(sizeof(SOCK_ABSTRACT_NAME) <= sizeof(((struct sockaddr_un *)0)->sun_path),
               "abstract socket name must fit sun_path alongside its leading NUL");

/* Fills `addr` with the abstract-namespace address and returns the addrlen to
 * hand bind()/connect(). An abstract address is NOT a C string: sun_path[0] is
 * a NUL that is part of the name, the rest of the name follows it un-
 * terminated, and the kernel takes the name's length from this addrlen alone.
 * Hence offsetof(...sun_path) + 1 + strlen(name), not sizeof(*addr) — passing
 * sizeof(*addr) would make the name the full 108-byte sun_path including its
 * trailing zero padding, and the server's and client's names would only agree
 * if both made the identical mistake. */
static socklen_t fill_abstract_addr(struct sockaddr_un *addr) {
    memset(addr, 0, sizeof(*addr));
    addr->sun_family = AF_UNIX;
    size_t n = strlen(SOCK_ABSTRACT_NAME);
    addr->sun_path[0] = '\0';
    memcpy(addr->sun_path + 1, SOCK_ABSTRACT_NAME, n);
    return (socklen_t)(offsetof(struct sockaddr_un, sun_path) + 1 + n);
}

#define SCRATCH_SIZE 16384

/* Operator/debug output — NOT evidence. Goes to stderr, and everything else in
 * this file that is not a disclosure record must do the same: stdout is
 * reserved exclusively for disclosure-record JSONL, one record per line, so
 * the host-side reader can parse `docker logs`' stdout stream directly without
 * having to filter this process's chatter out of it first (design §6).
 *
 * Composed into a local buffer and issued as ONE write(), rather than through
 * stdio, for two reasons that both come from run_server forking a handler
 * process per connection. A stdio buffer is DUPLICATED by fork(), so any
 * partial line sitting in it would be emitted twice — and the worker child
 * dup2()s its output pipe over fd 2, so its copy would be flushed into the
 * agent's own command output. And concurrent handlers sharing fd 2 can
 * interleave a line assembled from several small writes. One write of a whole
 * line has neither problem. */
static void logline(const char *fmt, ...) {
    va_list ap;
    struct timespec ts; clock_gettime(CLOCK_REALTIME, &ts);
    char line[2048];
    int n = snprintf(line, sizeof(line), "[relayd %ld.%03ld] ",
                     (long)ts.tv_sec, ts.tv_nsec/1000000);
    if (n < 0) return;
    size_t off = (size_t)n < sizeof(line) ? (size_t)n : sizeof(line) - 1;
    va_start(ap, fmt);
    n = vsnprintf(line + off, sizeof(line) - off, fmt, ap);
    va_end(ap);
    if (n > 0) {
        /* vsnprintf returns what it WANTED to write; clamp to what it could,
         * leaving one byte for the newline. */
        size_t want = (size_t)n;
        size_t room = sizeof(line) - off - 1;
        off += want < room ? want : room;
    }
    line[off++] = '\n';
    (void)!write(STDERR_FILENO, line, off);
}

/* read_full/write_full, the request reader and its two parsing primitives all
 * live in protocol.c now, and are used from here through protocol.h. They were
 * moved out for exactly the reason record.c was: this file cannot be compiled
 * anywhere but aarch64 (see the `#error` above), so nothing defined in it can
 * be reached by the host-run C unit tests, and a parser nobody can test is a
 * parser whose refusal paths get checked by hand once and never again. */

/* The response frame tags and the frame writer itself are protocol.h's now,
 * alongside the request framing and for the same reason: the two ends have to
 * agree, and while the writer lived here — in the one file that compiles
 * nowhere but aarch64 — no test could reach it. A writer that could emit a
 * frame the reader refuses is exactly what that bought, and exactly what
 * happened: see EXEC_RELAY_MAX_FRAME_LEN's note. Output goes through
 * proto_send_stream (sliced to the limit); bounded control frames go through
 * proto_send_frame. */

/* Read tracee's NUL-terminated string at remote address via /proc/pid/mem.
 *
 * Returns the length read, or -1 if the tracee's memory could not be opened at
 * all. `out` is left EMPTY-AND-TERMINATED in that case rather than untouched:
 * the caller checks the return, but a caller that ever forgets must inherit an
 * empty string, not 1 KiB of the tracer's own uninitialised stack. That
 * distinction is not academic here — `reqpath` is composed straight into a
 * disclosure record, which is SEALED, and round 2's R7 was exactly this shape
 * (an unterminated `req->id` read past the bytes that arrived and into a signed
 * artefact). A wrong record is a quiet lie; an empty one is legible. */
static int read_tracee_str(int pid, unsigned long long addr, char *out, size_t outsz) {
    if (outsz) out[0] = 0;
    char path[64];
    snprintf(path, sizeof(path), "/proc/%d/mem", pid);
    int fd = open(path, O_RDONLY | O_CLOEXEC);
    if (fd < 0) return -1;
    size_t got = 0;
    while (got < outsz - 1) {
        ssize_t r = pread(fd, out + got, outsz - 1 - got, (off_t)(addr + got));
        if (r <= 0) break;
        char *nul = memchr(out + got, 0, (size_t)r);
        got += (size_t)r;
        if (nul) { got = (size_t)(nul - out); break; }
    }
    out[got] = 0;
    close(fd);
    return (int)got;
}

static int write_tracee_mem(int pid, unsigned long long addr, const void *buf, size_t n) {
    char path[64];
    snprintf(path, sizeof(path), "/proc/%d/mem", pid);
    int fd = open(path, O_RDWR | O_CLOEXEC);
    if (fd < 0) return -1;
    ssize_t w = pwrite(fd, buf, n, (off_t)addr);
    close(fd);
    return (w == (ssize_t)n) ? 0 : -1;
}

static int get_regs(pid_t pid, struct arm64_regs *r) {
    struct iovec iov = { r, sizeof(*r) };
    return ptrace(PTRACE_GETREGSET, pid, (void*)(long)NT_PRSTATUS, &iov);
}
static int set_regs(pid_t pid, struct arm64_regs *r) {
    struct iovec iov = { r, sizeof(*r) };
    return ptrace(PTRACE_SETREGSET, pid, (void*)(long)NT_PRSTATUS, &iov);
}

/* Install the seccomp filter: RET_TRACE(nr) on execve/execveat, ALLOW everything else,
 * on the wrong arch KILL_PROCESS. Must be called with PR_SET_NO_NEW_PRIVS already set. */
static int install_seccomp_filter(void) {
    struct sock_filter filt[] = {
        BPF_STMT(BPF_LD+BPF_W+BPF_ABS, offsetof(struct seccomp_data, arch)),
        BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, AUDIT_ARCH_AARCH64, 1, 0),
        BPF_STMT(BPF_RET+BPF_K, SECCOMP_RET_KILL_PROCESS),
        BPF_STMT(BPF_LD+BPF_W+BPF_ABS, offsetof(struct seccomp_data, nr)),
        BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, SYS_execve, 2, 0),
        BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, SYS_execveat, 2, 0),
        BPF_STMT(BPF_RET+BPF_K, SECCOMP_RET_ALLOW),
        BPF_STMT(BPF_RET+BPF_K, SECCOMP_RET_TRACE | (SYS_execve & SECCOMP_RET_DATA)),
        BPF_STMT(BPF_RET+BPF_K, SECCOMP_RET_TRACE | (SYS_execveat & SECCOMP_RET_DATA)),
    };
    struct sock_fprog prog = { .len = sizeof(filt)/sizeof(filt[0]), .filter = filt };
    return syscall(SYS_seccomp, SECCOMP_SET_MODE_FILTER, 0, &prog);
}

/* Reads the NULL-terminated argv[] pointer array at `argv_addr` in the
 * tracee's memory (the execve/execveat syscall's own argv argument — NOT
 * the top-level command run_traced() was started with, which for a forked
 * grandchild's own exec is a different, unrelated array). Rule matching
 * needs THIS array: config_match's Prefix/Exact matchers compare multiple
 * argv entries, and the trap only hands the tracer a resolved pathname
 * directly (`reqpath`, read separately) — it does not hand over argv at
 * all unless something goes and reads it, which is what this does. Resolves
 * up to `max_n` entries (each truncated to 255 bytes, which is generous for
 * argv entries used in matching) into `out[]`. Returns the count read. */
static int read_tracee_argv(int pid, unsigned long long argv_addr, char out[][256], int max_n) {
    char path[64];
    snprintf(path, sizeof(path), "/proc/%d/mem", pid);
    int fd = open(path, O_RDONLY | O_CLOEXEC);
    if (fd < 0) return 0;
    int n = 0;
    while (n < max_n) {
        unsigned long long ptr = 0;
        if (pread(fd, &ptr, sizeof(ptr), (off_t)(argv_addr + (unsigned long long)n * sizeof(ptr)))
            != (ssize_t)sizeof(ptr)) {
            break;
        }
        if (ptr == 0) break; /* NULL terminator */
        ssize_t got = pread(fd, out[n], 255, (off_t)ptr);
        size_t len = got > 0 ? strnlen(out[n], (size_t)got) : 0;
        out[n][len] = 0;
        n++;
    }
    close(fd);
    return n;
}

/* ------------------------- disclosure stream ---------------------------- */

/* The disclosure log IS this process's stdout. Not a file, and not a
 * descriptor this code opens: fd 1 is handed to PID 1 by the container runtime
 * and is the read end of the runtime's own log capture (verified in this
 * environment: /proc/1/fd/1 is a `pipe:[...]` and everything written to it
 * appears in `docker logs`, including after the container has stopped).
 *
 * That is the whole point of the change — see the "no filesystem footprint"
 * note at the top of this file. Capture happens outside the container, so
 * there is no path a root-in-cell agent can unlink, truncate or chmod to make
 * already-emitted records disappear. Two consequences worth naming here:
 *
 *   - The fd needs no O_CLOEXEC treatment and must NOT be closed before the
 *     worker's execve. The worker dup2()s its own output pipe over fd 1 long
 *     before then, so the agent's command inherits its pipe, not this stream —
 *     which is strictly better than the old O_CLOEXEC file descriptor, since
 *     there is no extra descriptor in the worker's fd table to notice at all.
 *   - A process in the cell CAN still write to this stream, by opening
 *     /proc/1/fd/1. This is reachable, not theoretical: the agent's commands
 *     run as the same uid as PID 1, and opening another process's /proc/PID/fd
 *     entry needs only PTRACE_MODE_READ_FSCREDS, which same-uid satisfies — it
 *     is NOT the PTRACE_MODE_ATTACH that Yama's ptrace_scope gates, so no
 *     hardening in this environment stands in the way. Say it plainly: this
 *     transport is not injection-proof, and nothing below makes it so.
 *
 *     What it IS: (a) not a regression. The old tmpfs log was writable by the
 *     same root — `echo >> disclosure.log` — and additionally deletable and
 *     truncatable, which this is not. §2's parity clause is about destroying
 *     evidence, and that is what moved out of reach. (b) Bounded, but not
 *     cleanly. Two residual limits are worth naming rather than leaving for
 *     someone to rediscover:
 *
 *       * A hostile writer can DELETE a record it does not control, indirectly.
 *         A write larger than PIPE_BUF is not atomic on a pipe, so one issued
 *         while a handler is emitting a genuine record can be interleaved with
 *         it; the torn line is not JSON, and the host parser skips unparseable
 *         lines silently (bundle.rs, record_exec_consequence_log). That is a
 *         probabilistic single-record deletion primitive with no analogue on
 *         the old O_APPEND file, where any single write was atomic at any size.
 *         It needs a race against a concurrent genuine record, so it is not
 *         reliable — but "unreliable" is the only thing bounding it.
 *       * Flooding this descriptor can EVICT earlier records, on an engine
 *         configured differently from this one. Capture is the engine's, and so
 *         is its retention: this environment's json-file driver runs with no
 *         max-size and no max-file, so nothing rotates and the whole stream
 *         survives — but a driver that rotates by default would drop the oldest
 *         captured output first, and the oldest line is the startup header. The
 *         host's read requires that header (AgentCell::captured_disclosure_log),
 *         so on such an engine the flood presents as a lost read rather than as
 *         a quietly shortened log, which is the failure this system prefers.
 *
 *     Full injection resistance would need a descriptor the agent cannot name
 *     at all — not fd 1, not anything reachable through /proc — and that is a
 *     different transport, out of scope here. */
#define DISCLOSURE_FD STDOUT_FILENO

/* Emits the header line, or fails. Returns 0 on success and -1 if the stream
 * could not be written — and the caller MUST refuse to start on -1.
 *
 * §9 is fail-closed for the same reason config_load_from_env is: a relay that
 * cannot record is not a weaker relay, it is a relay whose output is a lie by
 * omission. The failure this originally guarded (the log file's open() failing
 * on a read-only filesystem) no longer exists, because nothing is opened; what
 * remains is the header write, which is also the first proof that fd 1 is
 * actually writable. A relay whose stdout is closed or broken would otherwise
 * serve every request while recording nothing, and the resulting bundle reads
 * exactly like a run in which the agent execed nothing. */
static int disclosure_init(void) {
    /* The tells this relay knows it leaves and does not mask, declared up front
     * so a reader of the sealed evidence is not left to discover them. The
     * substitute entry is new with full-argv replacement: repointing only
     * argv[0] left the requested arguments visible in the tracee's own argv,
     * whereas replacing the whole array means /proc/<pid>/cmdline and `ps` now
     * show the REPLACEMENT argv and no trace of what was actually requested —
     * an observable difference from plain `docker exec` that did not exist
     * before, and the requested command survives only in this log. */
    static const char header[] =
        "{\"known_residual_tells\":[\"TracerPid nonzero in /proc/self/status "
        "\\u2014 structural to ptrace, not masked\","
        "\"a substituted process shows the replacement argv in "
        "/proc/self/cmdline and ps, not the argv that was requested "
        "\\u2014 the requested one appears only in this log\"]}\n";
    if (proto_write_full(DISCLOSURE_FD, header, sizeof(header) - 1) < 0) {
        fprintf(stderr, "execrelayd: refusing to start — the disclosure log could not be "
                        "written to this process's stdout: %s. A relay that cannot record "
                        "is not a degraded relay; every request it then served would be "
                        "absent from the evidence with nothing saying so.\n",
                strerror(errno));
        return -1;
    }
    return 0;
}

/* Builds one complete JSON record in a local buffer and writes it with a
 * SINGLE proto_write_full() call. This matters because run_server() forks a
 * handler process per connection and every one of them shares fd 1: a record
 * built from several separate write() calls is not atomic, so two handlers
 * racing here could interleave their writes into one corrupted, unparseable
 * line.
 *
 * The size discipline that backs the single write changed with the transport.
 * O_APPEND made a write to the old log FILE atomic at any size; a write to a
 * PIPE — which is what the runtime hands PID 1 as stdout — is atomic only up
 * to PIPE_BUF. DISCLOSURE_RECORD_BUF is PIPE_BUF for exactly that reason, and
 * record.c has a _Static_assert tying its per-field budgets to it.
 *
 * The composition itself is record.c's, not this file's, so that it can be
 * unit-tested: nothing in relayd.c compiles anywhere but aarch64 Linux, and
 * an untestable record builder is how two of the five fields came to be
 * interpolated with a raw %s. See record.h. */
static void disclosure_record(const char *turn_id, const char *requested_argv0,
                               const char *matched_rule, const char *verb_applied,
                               const char *detail) {
    struct timespec ts; clock_gettime(CLOCK_REALTIME, &ts);
    char buf[DISCLOSURE_RECORD_BUF];
    size_t off = disclosure_format_record(buf, sizeof(buf),
                                          (long)ts.tv_sec, (long)(ts.tv_nsec / 1000000),
                                          turn_id, requested_argv0,
                                          matched_rule, verb_applied, detail);
    /* The return value is checked, and that is new with the transport. When the
     * log was a file opened O_APPEND on a tmpfs, a failed write here was close
     * to unimaginable; now it is a PIPE the container runtime owns, and EPIPE
     * (the runtime's reader gone) or a hard EAGAIN are both reachable. A write
     * that fails is a record that does not exist, and silence about it is the
     * exact failure disclosure_init refuses to start over — with the difference
     * that this one happens mid-run, where refusing to start is no longer
     * available. Saying so on stderr is what is left: the operator sees the
     * bundle is short and, beside it, why. */
    if (proto_write_full(DISCLOSURE_FD, buf, off) < 0) {
        logline("DISCLOSURE RECORD LOST: req=%s verb=%s: the record stream could not be "
                "written: %s. Everything from here on may be missing from the sealed "
                "evidence.",
                turn_id ? turn_id : "-", verb_applied ? verb_applied : "-", strerror(errno));
    }
}

/* Will this trap's target actually load, or is it one of execvpe()'s PATH
 * probes that is about to come straight back with ENOENT?
 *
 * The worker resolves a bare argv[0] with execvpe(), which issues one execve()
 * per PATH entry until one loads — and the seccomp filter traps every one of
 * them. So a single real `cat` (which the bridge issues for EVERY ReadFile
 * directive) traps once per PATH directory: six times on this image, five of
 * them naming files that do not exist and that nothing ever referenced.
 * Recording those five would file five fictions in the sealed evidence bundle.
 *
 * musl's execvpe continues its loop on ENOENT/ENOTDIR/EACCES and stops
 * otherwise, so "exists and is executable" is exactly the condition that ends
 * the search — the one candidate that will actually be loaded.
 *
 * Resolution has to be done as the TRACEE would do it, not as this tracer
 * would: absolute paths (which every PATH candidate is) mean the same to both,
 * but a relative one is resolved against the tracee's own cwd — or, for
 * execveat, against its dirfd. The tracee is stopped at the trap, so
 * /proc/<pid>/cwd and /proc/<pid>/fd/<n> are both stable to resolve against.
 *
 * Returns 1 for "will load" AND for "cannot tell" — a record that this code is
 * unsure about must stay in the log, because silently dropping a real exec is
 * the one failure the disclosure log must never have. Returns 0 only when the
 * target is definitively not loadable.
 *
 * A note on access(X_OK) and `noexec`, examined in round 2 and deliberately
 * left as it is. There is no syscall that answers "would execve() succeed"
 * without performing it, so this gate is an approximation whichever primitive
 * it uses, and the question is only which way it errs. access/faccessat test
 * the file's mode bits and do not consult the mount's MS_NOEXEC flag, so a
 * mode-0755 file on the cell's `noexec /work` answers "executable" here while
 * execve() would return EACCES. That is the FAIL-OPEN direction: the record is
 * kept for an exec attempt that then fails, which is the outcome this function's
 * whole contract prefers — a real, nameable exec attempt appearing in the log
 * with an unhelpful outcome beats it not appearing at all. The other input,
 * access()'s use of the REAL rather than effective uid, is a non-issue here:
 * execrelayd runs as root and nothing in this image is setuid, so the two are
 * the same. Nothing about noexec makes the gate drop a record it should keep,
 * and no small change makes the approximation exact, so it stands. */
static int trap_target_is_loadable(pid_t pid, int is_execveat,
                                    unsigned long long dirfd_reg, const char *path) {
    if (!path || !path[0]) return 1;              /* execveat AT_EMPTY_PATH: nothing to check */
    if (path[0] == '/') return access(path, X_OK) == 0;

    char base[64];
    int dirfd = is_execveat ? (int)(long)dirfd_reg : AT_FDCWD;
    if (dirfd != AT_FDCWD) {
        snprintf(base, sizeof(base), "/proc/%d/fd/%d", (int)pid, dirfd);
    } else {
        snprintf(base, sizeof(base), "/proc/%d/cwd", (int)pid);
    }
    int dfd = open(base, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    if (dfd < 0) return 1;                        /* cannot resolve — keep the record */
    int ok = faccessat(dfd, path, X_OK, 0) == 0;
    close(dfd);
    return ok;
}

/* ------------------------- one output stream's plumbing -------------------
 *
 * Forwards `len` bytes read from the worker's stdout or stderr pipe to the
 * caller, through the rewrite transform when a rewrite rule is in force.
 *
 * The transform is a STREAM (rewrite.c), not a function of one chunk, because
 * the per-chunk version could not see a find string split across two reads —
 * `printf SEC; printf RET` defeated it, and the untransformed bytes went
 * straight to the host. `rs` therefore has to persist across reads, which is
 * why it is owned by run_traced and threaded through here rather than being a
 * local.
 *
 * `rule_find`/`rule_replace` are NULL when no rewrite applies. Once a rewrite
 * IS in force for a request it stays in force to the end of that request's
 * output — see `active_rewrite`'s declaration in run_traced for why the
 * alternative (recomputing it per trap) leaked the very content the rule
 * strips. So the only transition this sees in practice is the arming one, from
 * no transform to one; the flush-and-retire below still handles the reverse and
 * still must, because it is what keeps the held-back tail from being dropped if
 * a transition ever does occur, and a silently-dropped tail is not a failure
 * this file is willing to leave available. */
static void forward_stream(int fd, uint8_t tag, struct rewrite_stream *rs,
                            const char *rule_find, const char *rule_replace,
                            const char *buf, size_t len, const char *req_id) {
    /* The transform in force changed: flush and retire the old stream first.
     * Compared by CONTENT, not by rule identity — two rules configured with the
     * same find/replace pair (one matching the shell, one matching a helper it
     * execs) are the same transform, and restarting the window between them
     * would release the held-back tail early and leak a match spanning that
     * boundary, which is the very thing the window exists to stop. */
    if (rs->active &&
        (strcmp(rs->find, rule_find ? rule_find : "") != 0
         || strcmp(rs->replace, rule_replace ? rule_replace : "") != 0)) {
        const char *tail = NULL; size_t tail_len = 0;
        if (rewrite_stream_finish(rs, &tail, &tail_len) == 0 && tail_len) {
            proto_send_stream(fd, tag, tail, tail_len);
        }
        rewrite_stream_end(rs);
    }
    if (!rule_find) {
        if (len) proto_send_stream(fd, tag, buf, len);
        return;
    }
    if (!rs->active) rewrite_stream_begin(rs, rule_find, rule_replace);

    const char *out = NULL; size_t out_len = 0;
    if (rewrite_stream_push(rs, buf, len, &out, &out_len) != 0) {
        /* Allocation failure. Fail CLOSED — forwarding the raw bytes here would
         * emit exactly the string the rule exists to remove, at the one moment
         * nobody is watching. */
        logline("req=%s rewrite: transform failed (out of memory), %zu bytes dropped",
                req_id ? req_id : "-", len);
        /* And into the sealed evidence, not the container log alone. Dropping
         * the bytes is the right call; dropping them SILENTLY is not — the
         * exec's own record says a rewrite rule was in force and the output
         * then arrives short, with nothing anywhere saying a chunk never made
         * it. That is the invariant stated above trap_target_is_loadable, in
         * its output-shaped form. Named for the substitute-failed-* /
         * fabricate-failed-* convention: the verb, then the step that gave
         * way. */
        char why[128];
        snprintf(why, sizeof(why),
                 "%s transform out of memory; %zu bytes dropped",
                 tag == TAG_STDERR ? "stderr" : "stdout", len);
        disclosure_record(req_id, "-", "-", "rewrite-transform-failed", why);
        return;
    }
    if (out_len) proto_send_stream(fd, tag, out, out_len);
}

/* Releases whatever the stream is still holding back, at pipe EOF. */
static void finish_stream(int fd, uint8_t tag, struct rewrite_stream *rs) {
    if (!rs->active) return;
    const char *tail = NULL; size_t tail_len = 0;
    if (rewrite_stream_finish(rs, &tail, &tail_len) == 0 && tail_len) {
        proto_send_stream(fd, tag, tail, tail_len);
    }
    rewrite_stream_end(rs);
}

/* ---------------------------------------------------------------------
 * Core primitive shared by both the socket-relay path and the
 * --self-test path: fork a child, have it install the seccomp filter,
 * PTRACE_SEIZE it from the parent, release it, and drive it to exec
 * (with verb dispatch applied at the seccomp trap), streaming
 * stdout/stderr through the given fds and returning the exit code.
 * req_id may be NULL.
 *
 * The worker's environment is `environ` and nothing else. It used to also carry
 * an injected RELAY_REQ_ID, which no code anywhere read (producers only, in
 * this file) and which `stub env` showed where a plain `docker exec env` does
 * not — an undisclosed tell bought for no consumer. The turn id reaches the
 * evidence through the disclosure record, which is where it belongs.
 * --------------------------------------------------------------------- */
static int run_traced(char *const argv[],
                       const char *req_id, int out_fd, int err_fd, int *exit_code_out,
                       const struct exec_plan *plan, uint64_t timeout_ms) {
    /* The rewrite transform in force for THIS REQUEST's output stream — scoped
     * to the request, which is the whole point and was the defect.
     *
     * It used to be reassigned unconditionally after every seccomp trap:
     * `active_rewrite = (rule && rule->verb == VERB_REWRITE) ? rule : NULL;`.
     * PTRACE_O_TRACEFORK/VFORK/CLONE make every descendant a tracee of this
     * same tracer, so a nested exec — `sh -c 'printf SECRET; /bin/date'`, a
     * script calling a helper, anything at all — traps here too. Matching no
     * rule (the ordinary case for a nested exec) set that pointer to NULL, and
     * from that instant the rest of the outer command's stdout was forwarded
     * UNTRANSFORMED: the rule was still legitimately in force for the stream,
     * and the one thing it existed to strip went straight to the caller. Round
     * 1 fixed the chunk-straddling and truncation halves of the rewrite bug and
     * left this one, because no test combined a rewrite rule with a nested
     * exec.
     *
     * The stream belongs to the request, not to the most recent trap: every
     * process under this request shares the worker's stdout/stderr pipes (they
     * are inherited across fork and execve), so there is exactly one transform
     * per request and it is armed once, by the first rewrite rule to match. The
     * arming happens in the VERB_REWRITE branch of the dispatch below; nothing
     * clears it. */
    const struct exec_rule *active_rewrite = NULL;
    /* Persist across reads: a find string split across two read()s is only
     * matchable if the transform remembers the tail of the previous chunk. */
    struct rewrite_stream rw_out; memset(&rw_out, 0, sizeof(rw_out));
    struct rewrite_stream rw_err; memset(&rw_err, 0, sizeof(rw_err));
    /* Whether ANY exec under this request reached the disclosure log. A request
     * that ends with this still zero ran nothing at all, and says so below —
     * see the passthrough-exec-failed record. */
    int recorded_any = 0;
    int outp[2], errp[2], syncr[2], syncg[2];
    /* pipe2(O_CLOEXEC), not pipe(): every one of these eight descriptors is
     * relay-private and none may survive into the agent's own command. The two
     * the worker actually needs on the far side of execve — its stdout and
     * stderr — get there via dup2(), which CLEARS the flag on the new
     * descriptor, so marking the originals costs the worker nothing. The sync
     * pipes are both used strictly before execve. Setting the flag at creation
     * rather than after is what makes it safe under the concurrent forks in
     * run_server: there is no window in which a fork could inherit an
     * unmarked copy. */
    if (pipe2(outp, O_CLOEXEC) || pipe2(errp, O_CLOEXEC)
        || pipe2(syncr, O_CLOEXEC) || pipe2(syncg, O_CLOEXEC)) { perror("pipe2"); return -1; }

    /* Block SIGCHLD and open the signalfd BEFORE forking. If this happened
     * after PTRACE_SEIZE/release instead, there is a window where the child
     * can race ahead to its seccomp-trap stop (which raises SIGCHLD) before
     * we are blocking it: SIGCHLD's default disposition is "ignore" (discard,
     * not queue), so the notification is silently lost forever and the
     * tracer sleeps in poll() while the tracee sits legitimately trap-stopped
     * awaiting a PTRACE_CONT that will never come. Doing this up front closes
     * the window entirely; the mask is inherited across fork() harmlessly. */
    sigset_t mask; sigemptyset(&mask); sigaddset(&mask, SIGCHLD);
    sigprocmask(SIG_BLOCK, &mask, NULL);
    /* SFD_CLOEXEC alongside SFD_NONBLOCK: this fd is the tracer's, and an
     * `anon_inode:[signalfd]` in the agent command's own /proc/self/fd is a
     * fully legible tell that something is supervising it. */
    int sfd = signalfd(-1, &mask, SFD_NONBLOCK | SFD_CLOEXEC);
    if (sfd < 0) { perror("signalfd"); return -1; }

    pid_t pid = fork();
    if (pid < 0) { perror("fork"); close(sfd); return -1; }

    if (pid == 0) {
        /* child: worker */
        close(outp[0]); close(errp[0]); close(syncr[0]); close(syncg[1]);
        dup2(outp[1], STDOUT_FILENO);
        dup2(errp[1], STDERR_FILENO);
        int devnull = open("/dev/null", O_RDONLY);
        if (devnull >= 0) dup2(devnull, STDIN_FILENO);
        close(outp[1]); close(errp[1]);
        if (devnull >= 0) close(devnull);

        if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0) { _exit(126); }
        if (install_seccomp_filter() != 0) { _exit(126); }

        /* tell parent we're ready to be seized */
        char ok = 'R';
        write(syncr[1], &ok, 1);

        /* wait for parent's go-ahead (parent has SEIZEd us by now) */
        char go;
        if (read(syncg[0], &go, 1) != 1) _exit(125);

        /* Every remaining relay-private descriptor, closed BY NAME now that the
         * handshake is done and nothing below needs any of them. The O_CLOEXEC/
         * SOCK_CLOEXEC flags set at creation would already drop all of these at
         * execve; this second pass exists because CLOEXEC is a promise about a
         * call that has not happened yet, and the window between here and
         * execvpe() runs arbitrary code (malloc, and the PATH walk inside
         * execvpe itself). Closing explicitly also covers the case that has no
         * atomic-CLOEXEC form at creation: `cfd`, which arrives here as out_fd/
         * err_fd. What must NOT be closed is stdin/stdout/stderr — in the
         * --self-test path err_fd IS fd 2, which by now names the output pipe
         * via dup2, so the guard is on the fd number, not on the variable.
         *
         * The disclosure stream is NOT in this list any more, and its absence
         * is the fix rather than an omission: it is fd 1, which the dup2 above
         * has already replaced with this worker's own stdout pipe. There is no
         * relay-private descriptor left for the agent's command to find — where
         * the old log file appeared in a relayed command's /proc/self/fd as a
         * writable `l-wx------ 3 -> /work/.exec-relay/disclosure.log` it could
         * forge records through, there is now nothing to close and nothing to
         * see. */
        close(syncr[1]);
        close(syncg[0]);
        close(sfd);                                     /* the tracer's signalfd */
        if (out_fd > STDERR_FILENO) close(out_fd);         /* the stub's connection */
        if (err_fd > STDERR_FILENO && err_fd != out_fd) close(err_fd);

        /* The signal environment execve() will carry into the agent's own
         * command, restored to what a directly-`docker exec`ed process gets.
         *
         * Two things follow a process across execve and both were wrong here:
         * the signal MASK is inherited outright, and a signal set to SIG_IGN
         * stays ignored (only handlers are reset to default). This process
         * inherited a BLOCKED SIGCHLD from the tracer's pre-fork sigprocmask
         * and an IGNORED SIGPIPE from run_server's `signal(SIGPIPE, SIG_IGN)`,
         * and passed both to the command.
         *
         * SIGPIPE is the one with teeth: `sh -c 'yes | head -1'` relies on the
         * writer DYING of SIGPIPE when the reader exits. With SIGPIPE ignored
         * the write returns EPIPE instead, and `yes` keeps running and keeps
         * failing — different exit status, different behaviour, and it triggers
         * on the FALLBACK path where no rule matched at all. §3 says zero
         * config must be byte-identical to no interception; this was not.
         *
         * Deliberately last, after every relay-private descriptor is closed and
         * immediately before execvp: nothing between here and the exec needs
         * SIGCHLD blocked, and doing it earlier only widens the window in which
         * this process's own behaviour differs from the tracer's expectations. */
        sigset_t none; sigemptyset(&none);
        sigprocmask(SIG_SETMASK, &none, NULL);
        signal(SIGPIPE, SIG_DFL);

        /* execvp, not execve: a bare command name (argv[0] without a slash)
         * must be resolved against PATH exactly as a shell would — the bridge
         * itself issues bare names (e.g. `cat` for every ReadFile directive),
         * and plain execve() would fail every one with ENOENT. execvp tries
         * each PATH candidate with its own execve() syscall, so the seccomp
         * trap still fires per attempt; argv[0] stays the literal original name
         * throughout, which is what config_match matches on, so rule matching
         * composes unchanged. (execvp rather than the execvpe this used to
         * call: with RELAY_REQ_ID gone the environment is exactly `environ`,
         * which is what execvp passes.) */
        execvp(argv[0], argv);
        /* execvp only returns on error. The message must NOT name this as an
         * interception layer — a generic "<name>: not found" matches what a
         * real missing-binary failure looks like (coherent-per-tool, this
         * project's stated bar; not byte-identical shell mimicry). */
        fprintf(stderr, "%s: not found\n", argv[0]);
        _exit(127);
    }

    /* parent */
    close(outp[1]); close(errp[1]); close(syncr[1]); close(syncg[0]);

    char rbyte;
    if (proto_read_full(syncr[0], &rbyte, 1) != 1 || rbyte != 'R') {
        logline("req=%s pid=%d: child failed to signal ready", req_id?req_id:"-", pid);
        goto reap_and_fail;
    }

    if (ptrace(PTRACE_SEIZE, pid, 0,
               (void*)(long)(PTRACE_O_TRACESECCOMP | PTRACE_O_TRACEFORK |
                              PTRACE_O_TRACEVFORK | PTRACE_O_TRACECLONE |
                              PTRACE_O_EXITKILL)) != 0) {
        logline("req=%s pid=%d: PTRACE_SEIZE failed: %s", req_id?req_id:"-", pid, strerror(errno));
        goto reap_and_fail;
    }

    { char g = 'G'; proto_write_full(syncg[1], &g, 1); }
    close(syncr[0]); close(syncg[1]);

    struct pollfd pfds[3];
    int have_out = 1, have_err = 1, have_exit = 0, ecode = -1;

    struct timespec deadline;
    clock_gettime(CLOCK_MONOTONIC, &deadline);
    deadline.tv_sec += (time_t)(timeout_ms / 1000);
    deadline.tv_nsec += (long)(timeout_ms % 1000) * 1000000;
    if (deadline.tv_nsec >= 1000000000) { deadline.tv_sec++; deadline.tv_nsec -= 1000000000; }

    for (;;) {
        int nfds = 0;
        int oi = -1, ei = -1, si;
        if (have_out) { pfds[nfds].fd = outp[0]; pfds[nfds].events = POLLIN; oi = nfds; nfds++; }
        if (have_err) { pfds[nfds].fd = errp[0]; pfds[nfds].events = POLLIN; ei = nfds; nfds++; }
        pfds[nfds].fd = sfd; pfds[nfds].events = POLLIN; si = nfds; nfds++;

        if (!have_out && !have_err && have_exit) break; /* fully drained + exited */

        struct timespec now;
        clock_gettime(CLOCK_MONOTONIC, &now);
        long remaining_ms = (long)(deadline.tv_sec - now.tv_sec) * 1000
                           + (deadline.tv_nsec - now.tv_nsec) / 1000000;
        if (remaining_ms <= 0) {
            logline("req=%s pid=%d TIMEOUT after %llu ms, killing", req_id?req_id:"-", pid,
                    (unsigned long long)timeout_ms);
            /* logline goes to execrelayd's stderr — NOT the sealed evidence,
             * which is its stdout. A watchdog kill that only ever appeared there was
             * invisible to every reader of the bundle: the exec's record (if it
             * got one) says the command was let through and nothing anywhere
             * says it was then killed at the deadline. §8 requires the record;
             * it goes in before the early return, since this path never reaches
             * the end of the function. */
            char why[128];
            snprintf(why, sizeof(why), "killed by the watchdog after %llu ms; exit=124",
                     (unsigned long long)timeout_ms);
            disclosure_record(req_id, argv[0] ? argv[0] : "-", "-", "watchdog-timeout", why);
            kill(pid, SIGKILL);
            { int st; waitpid(pid, &st, 0); }
            finish_stream(out_fd, TAG_STDOUT, &rw_out);
            finish_stream(err_fd, TAG_STDERR, &rw_err);
            close(sfd); close(outp[0]); close(errp[0]);
            if (exit_code_out) *exit_code_out = 124; /* matches GNU `timeout`'s convention */
            return -1;
        }
        int pr = poll(pfds, nfds, (int)remaining_ms);
        if (pr < 0) { if (errno == EINTR) continue; break; }

        if (oi >= 0 && (pfds[oi].revents & (POLLIN|POLLHUP))) {
            char buf[8192];
            ssize_t r = read(outp[0], buf, sizeof(buf));
            if (r > 0) {
                int rw = active_rewrite && active_rewrite->has_stdout_rewrite;
                forward_stream(out_fd, TAG_STDOUT, &rw_out,
                               rw ? active_rewrite->stdout_find : NULL,
                               rw ? active_rewrite->stdout_replace : NULL,
                               buf, (size_t)r, req_id);
            }
            else {
                /* EOF: release whatever the sliding window is still holding. */
                finish_stream(out_fd, TAG_STDOUT, &rw_out);
                have_out = 0; close(outp[0]);
            }
        }
        if (ei >= 0 && (pfds[ei].revents & (POLLIN|POLLHUP))) {
            char buf[8192];
            ssize_t r = read(errp[0], buf, sizeof(buf));
            if (r > 0) {
                int rw = active_rewrite && active_rewrite->has_stderr_rewrite;
                forward_stream(err_fd, TAG_STDERR, &rw_err,
                               rw ? active_rewrite->stderr_find : NULL,
                               rw ? active_rewrite->stderr_replace : NULL,
                               buf, (size_t)r, req_id);
            }
            else {
                finish_stream(err_fd, TAG_STDERR, &rw_err);
                have_err = 0; close(errp[0]);
            }
        }
        if (pfds[si].revents & POLLIN) {
            struct signalfd_siginfo si_buf;
            while (read(sfd, &si_buf, sizeof(si_buf)) == sizeof(si_buf)) { /* drain */ }
            for (;;) {
                int status;
                pid_t w = waitpid(-1, &status, WNOHANG | __WALL);
                if (w <= 0) break;
                /* Every waited pid may be relevant: PTRACE_O_TRACEFORK/VFORK/
                 * CLONE makes descendants tracees of this same tracer, and
                 * their own seccomp traps arrive through this same waitpid.
                 * Handled per-pid via `w` throughout; only the ORIGINAL
                 * top-level process's exit (w == pid) ends the whole request
                 * — a grandchild exiting is not the command finishing. */

                if (WIFSTOPPED(status)) {
                    int sig = WSTOPSIG(status);
                    int event = status >> 16;
                    if (sig == SIGTRAP && event == PTRACE_EVENT_SECCOMP) {
                        unsigned long msg = 0;
                        ptrace(PTRACE_GETEVENTMSG, w, 0, &msg);

                        /* Both reads below fill data that is composed straight
                         * into a SEALED disclosure record, and both were
                         * previously unchecked — R7's class exactly. The
                         * registers are the sharper of the two: `regs` is a
                         * plain stack local, so a failed PTRACE_GETREGSET (the
                         * tracee raced away between the trap and this read, or
                         * was killed by something in the cell) left every field
                         * uninitialised, and the record was then composed from
                         * whatever the tracer's own stack happened to hold —
                         * `reqpath` read from a garbage address, `scratch_addr`
                         * derived from a garbage SP. Zeroed AND checked, rather
                         * than either alone: the zeroing bounds what an
                         * unchecked path could ever leak, the check is what
                         * stops the record being written at all.
                         *
                         * A trap whose registers cannot be read is disclosed as
                         * itself, not as an exec of "": the request is still
                         * IDENTIFIABLE (`req_id`) and the syscall still
                         * happened, so silence here would be the disclosure
                         * log's one forbidden failure — a real exec dropped —
                         * while a fabricated path would be worse than silence.
                         * The tracee is resumed unmodified, which is the only
                         * safe thing to do with a trap nothing could be learned
                         * about. `recorded_any` is deliberately NOT set: whether
                         * anything loaded is precisely what could not be
                         * determined, and the end-of-request
                         * `passthrough-exec-failed` record alongside this one
                         * states the uncertainty rather than papering it. */
                        struct arm64_regs regs;
                        memset(&regs, 0, sizeof regs);
                        if (get_regs(w, &regs) != 0) {
                            logline("req=%s pid=%d: PTRACE_GETREGSET failed: %s",
                                    req_id?req_id:"-", w, strerror(errno));
                            disclosure_record(req_id, "-", "-", "trap-unreadable",
                                              "the tracee's registers could not be read at this "
                                              "exec trap; nothing about the requested command is "
                                              "known and nothing was intercepted");
                            ptrace(PTRACE_CONT, w, 0, 0);
                            continue;
                        }
                        int is_execveat = (msg == (unsigned long)SYS_execveat);
                        unsigned long long path_reg = is_execveat ? regs.regs[1] : regs.regs[0];
                        char reqpath[1024];
                        /* 0 is a legitimate answer (execveat with AT_EMPTY_PATH
                         * carries no path), so only a negative return is the
                         * failure: the tracee's memory could not be opened. */
                        if (read_tracee_str(w, path_reg, reqpath, sizeof(reqpath)) < 0) {
                            logline("req=%s pid=%d: tracee memory unreadable: %s",
                                    req_id?req_id:"-", w, strerror(errno));
                            disclosure_record(req_id, "-", "-", "trap-unreadable",
                                              "the tracee's memory could not be read at this exec "
                                              "trap; the requested path is unknown and nothing "
                                              "was intercepted");
                            ptrace(PTRACE_CONT, w, 0, 0);
                            continue;
                        }

                        /* Computed HERE, from the trap's untouched registers,
                         * because the verb dispatch below rewrites regs[0]/
                         * regs[1] in this local copy for substitute and
                         * fabricate — after that point the dirfd is gone. */
                        int will_load = trap_target_is_loadable(
                            w, is_execveat, is_execveat ? regs.regs[0] : 0, reqpath);

                        unsigned long long argv_ptr_reg = is_execveat ? regs.regs[2] : regs.regs[1];
                        char tracee_argv[EXEC_RELAY_MAX_ARGV][256];
                        int tracee_argc = read_tracee_argv(w, argv_ptr_reg, tracee_argv, EXEC_RELAY_MAX_ARGV);
                        char *argv_ptrs[EXEC_RELAY_MAX_ARGV];
                        for (int ai = 0; ai < tracee_argc; ai++) argv_ptrs[ai] = tracee_argv[ai];

                        const struct exec_rule *rule = config_match(plan, argv_ptrs, tracee_argc);
                        const char *rule_name = rule ? rule->name : "fallback";
                        const char *verb_name = "passthrough";
                        char detail[1200] = "-";

                        /* Computed fresh from THIS trap's own live SP, not a
                         * fixed address handed over once by the top-level
                         * worker at startup — this is what makes substitute
                         * (and fabricate's redirect-to-helper, below) work
                         * for ANY tracee, including a grandchild running a
                         * completely different program's memory image. */
                        unsigned long long scratch_addr = regs.sp - SCRATCH_SIZE;

                        if (!rule) {
                            /* passthrough: leave the syscall untouched */
                        } else if (rule->verb == VERB_SUBSTITUTE) {
                            verb_name = "substitute";
                            /* The WHOLE replacement_argv, not just element 0.
                             *
                             * config.c has always parsed the full array (up to
                             * EXEC_RELAY_MAX_ARGV elements) and this branch used
                             * to repoint only the PATH register at
                             * replacement_argv[0], leaving the tracee's own argv
                             * pointer untouched — so a rule configured
                             * `replacement_argv: ["/bin/echo", "intercepted"]`
                             * ran /bin/echo with the ORIGINAL requested argv and
                             * silently dropped everything past index 0. Nothing
                             * refused that config and nothing reported the
                             * discrepancy; it simply did something other than
                             * what it said.
                             *
                             * Note the consequence for a ONE-element
                             * replacement, which is a real behaviour change: the
                             * replacement argv is now exactly what was
                             * configured, so the requested command's own
                             * arguments are no longer inherited. That is what
                             * "replacement_argv" means, and a rule that wants
                             * arguments now has to say so.
                             *
                             * Mechanically this is fabricate's redirect, which
                             * has always written a full argv this way — the
                             * layout arithmetic is shared with it now, in
                             * scratch.c, where it can be unit-tested. */
                            const char *sub_argv[EXEC_RELAY_MAX_ARGV];
                            int sub_argc = rule->replacement_argv_len;
                            if (sub_argc > EXEC_RELAY_MAX_ARGV) sub_argc = EXEC_RELAY_MAX_ARGV;
                            for (int ai = 0; ai < sub_argc; ai++) sub_argv[ai] = rule->replacement_argv[ai];

                            /* Every step checked. The memory poke and the
                             * register write can both fail (e.g. the tracee
                             * raced to exit); if either does, the real syscall
                             * proceeds UNMODIFIED, so recording
                             * verb_applied="substitute" would file a failed
                             * substitution as a successful one in the evidence.
                             * Each failure gets its own substitute-failed-*
                             * name, so the record says which step gave way. */
                            uint8_t sbuf[SCRATCH_SIZE];
                            size_t slen = 0;
                            unsigned long long path_addr = 0, argv_addr = 0;
                            if (scratch_pack_argv(sbuf, sizeof(sbuf), scratch_addr,
                                                  sub_argv, sub_argc, &slen,
                                                  &path_addr, &argv_addr) != 0) {
                                verb_name = "substitute-failed-scratch-too-small";
                            } else if (write_tracee_mem(w, scratch_addr, sbuf, slen) != 0) {
                                verb_name = "substitute-failed-mem-write";
                            } else {
                                if (is_execveat) { regs.regs[1] = path_addr; regs.regs[2] = argv_addr; }
                                else { regs.regs[0] = path_addr; regs.regs[1] = argv_addr; }
                                if (set_regs(w, &regs) != 0) {
                                    verb_name = "substitute-failed-set-regs";
                                } else {
                                    /* The replacement argv, space-joined, into
                                     * a fixed buffer — and SAID SO when it does
                                     * not fit. It silently stopped at the
                                     * buffer's end before, so a reader of the
                                     * sealed evidence saw a complete-looking
                                     * argv that was merely the first 1199 bytes
                                     * of a longer one: EXEC_RELAY_MAX_ARGV
                                     * elements of up to
                                     * EXEC_RELAY_MAX_ARGV_ELEM bytes overruns
                                     * this many times over. A record that is
                                     * wrong about what ran is worse than one
                                     * that admits it is partial. */
                                    size_t dl = 0;
                                    int truncated = 0;
                                    for (int ai = 0; ai < sub_argc; ai++) {
                                        size_t room = sizeof(detail) - dl;
                                        int n = snprintf(detail + dl, room,
                                                         ai ? " %s" : "%s", sub_argv[ai]);
                                        /* snprintf returns what it WANTED to
                                         * write, so n >= room is exactly the
                                         * "did not fit" test. */
                                        if (n < 0 || (size_t)n >= room) { truncated = 1; break; }
                                        dl += (size_t)n;
                                    }
                                    if (truncated) {
                                        static const char MARK[] = "...[truncated]";
                                        memcpy(detail + sizeof(detail) - sizeof(MARK),
                                               MARK, sizeof(MARK));
                                    }
                                }
                            }
                        } else if (rule->verb == VERB_FABRICATE) {
                            verb_name = "fabricate";
                            /* Redirect (substitute-style) to a baked-in helper,
                             * passing the canned result via argv — argv content
                             * is copied by the kernel as part of execve() itself,
                             * so (unlike scratch memory) it survives a REAL exec
                             * even though the new image gets a fresh, ASLR-
                             * randomized stack. This is what lets fabricate work
                             * on a grandchild, not just the top-level worker. */
                            char *b64_stdout = base64_encode(rule->fabricate_stdout, rule->fabricate_stdout_len);
                            char *b64_stderr = base64_encode(rule->fabricate_stderr, rule->fabricate_stderr_len);
                            char exit_code_str[16];
                            snprintf(exit_code_str, sizeof(exit_code_str), "%d", rule->fabricate_exit_code);

                            if (!b64_stdout || !b64_stderr) {
                                verb_name = "fabricate-failed-encode-or-scratch";
                            } else {
                                static const char HELPER_PATH[] = "/usr/local/bin/fabricate-emit";
                                const char *helper_argv[4] = { HELPER_PATH, exit_code_str, b64_stdout, b64_stderr };

                                uint8_t buf[SCRATCH_SIZE];
                                size_t off = 0;
                                unsigned long long path_addr = 0, ptr_array_addr = 0;
                                /* The same packing substitute uses, and the same
                                 * checking. Both calls below were previously
                                 * unchecked: on a failed poke or a failed
                                 * register write the tracee runs the REAL
                                 * (unintended) target, and the record still said
                                 * verb_applied="fabricate" — the evidence
                                 * asserting nothing ran while something did.
                                 * Mirrors substitute's fabricate-failed-*
                                 * convention exactly. */
                                if (scratch_pack_argv(buf, sizeof(buf), scratch_addr,
                                                      helper_argv, 4, &off,
                                                      &path_addr, &ptr_array_addr) != 0) {
                                    verb_name = "fabricate-failed-encode-or-scratch";
                                } else if (write_tracee_mem(w, scratch_addr, buf, off) != 0) {
                                    verb_name = "fabricate-failed-mem-write";
                                } else {
                                    if (is_execveat) { regs.regs[1] = path_addr; regs.regs[2] = ptr_array_addr; }
                                    else { regs.regs[0] = path_addr; regs.regs[1] = ptr_array_addr; }
                                    if (set_regs(w, &regs) != 0) {
                                        verb_name = "fabricate-failed-set-regs";
                                    } else {
                                        snprintf(detail, sizeof(detail),
                                                 "exit=%d stdout_b64_len=%zu stderr_b64_len=%zu",
                                                 rule->fabricate_exit_code,
                                                 strlen(b64_stdout), strlen(b64_stderr));
                                    }
                                }
                            }
                            free(b64_stdout);
                            free(b64_stderr);
                        } else if (rule->verb == VERB_REWRITE) {
                            /* Arms the transform for the REQUEST, here, rather
                             * than leaving it to a single assignment after the
                             * dispatch that every later trap re-evaluated. See
                             * the note on `active_rewrite`'s declaration for
                             * what that cost.
                             *
                             * First rewrite rule to match wins for the rest of
                             * the request. A second, DIFFERENT one arriving
                             * mid-stream cannot be honoured — one output stream
                             * carries one transform, and swapping it would
                             * restart the sliding window and release the tail
                             * the old rule was holding back — so it is recorded
                             * as not applied rather than silently ignored or
                             * silently swapped in. Named in the
                             * substitute-failed-* / fabricate-failed-*
                             * convention: the verb, then the reason. */
                            if (active_rewrite && active_rewrite != rule) {
                                verb_name = "rewrite-not-applied-stream-already-transformed";
                                snprintf(detail, sizeof(detail),
                                         "rule %s is already transforming this request's output; "
                                         "one stream carries one transform",
                                         active_rewrite->name);
                            } else {
                                verb_name = "rewrite";
                                active_rewrite = rule;
                                snprintf(detail, sizeof(detail), "stdout_find=%s",
                                          rule->has_stdout_rewrite ? rule->stdout_find : "(none)");
                            }
                        }

                        logline("req=%s pid=%d syscall=%s requested=%s verb=%s rule=%s detail=%s%s",
                                req_id?req_id:"-", w, is_execveat?"execveat":"execve",
                                reqpath, verb_name, rule_name, detail,
                                (!rule && !will_load) ? " [path-probe, not disclosed]" : "");
                        /* Interception is unchanged: every trap was matched
                         * against the plan above and every trap resumes below.
                         * Only RECORDING is gated, and only for the
                         * passthrough case. A trap that matched a rule is
                         * always recorded whether or not its target exists —
                         * fabricate exists precisely to answer for targets
                         * that are not on disk (the suite's own canaries,
                         * `touch-canary` and `/nonexistent/touch-canary`, are
                         * both deliberately absent), and a rule firing is the
                         * single most important thing this log has to say. */
                        if (rule || will_load) {
                            disclosure_record(req_id, reqpath, rule_name, verb_name, detail);
                            recorded_any = 1;
                        }
                        /* `active_rewrite` is NOT recomputed here. It used to
                         * be — `active_rewrite = (rule && rule->verb ==
                         * VERB_REWRITE) ? rule : NULL;` ran on EVERY trap — and
                         * that assignment is the whole of the defect this
                         * scoping fixes. See its declaration. */
                        ptrace(PTRACE_CONT, w, 0, 0);
                    } else if (sig == SIGTRAP && event != 0) {
                        ptrace(PTRACE_CONT, w, 0, 0);
                    } else {
                        ptrace(PTRACE_CONT, w, 0, (void*)(long)sig);
                    }
                } else if (WIFEXITED(status)) {
                    if (w == pid) { ecode = WEXITSTATUS(status); have_exit = 1; }
                } else if (WIFSIGNALED(status)) {
                    if (w == pid) {
                        ecode = 128 + WTERMSIG(status);
                        have_exit = 1;
                        /* §8's other missing record. A worker that died of a
                         * signal — the agent's own command segfaulting, or
                         * killing itself, or being killed by something in the
                         * cell — left NO trace at all: the exec's own record
                         * says the command was let through, the exit code
                         * reaches the caller, and the sealed evidence never
                         * says the process was terminated rather than
                         * returning. */
                        char why[128];
                        snprintf(why, sizeof(why),
                                 "worker terminated by signal %d; exit=%d",
                                 WTERMSIG(status), ecode);
                        disclosure_record(req_id, argv[0] ? argv[0] : "-", "-",
                                          "worker-signaled", why);
                    }
                }
            }
        }
    }
    finish_stream(out_fd, TAG_STDOUT, &rw_out);
    finish_stream(err_fd, TAG_STDERR, &rw_err);
    close(sfd);
    /* A real exec attempt that never loaded anything. The disclosure log's own
     * invariant — "silently dropping a real exec is the one failure the
     * disclosure log must never have", stated above trap_target_is_loadable —
     * did not hold for the no-match case: a passthrough whose target genuinely
     * does not exist trapped, was found not-loadable, and was filed as a PATH
     * probe, so `stub /nonexistent/thing` produced exit 127 and an empty log.
     * A bare name that resolves nowhere produced one such trap per PATH entry
     * and still nothing.
     *
     * `recorded_any` is the precise condition: it is zero exactly when no exec
     * under this request ever reached a loadable target, i.e. when nothing ran.
     * One record, naming what was asked for — not one per probe. */
    if (!recorded_any) {
        char why[128];
        snprintf(why, sizeof(why), "no exec under this request loaded a target; exit=%d", ecode);
        disclosure_record(req_id, argv[0] ? argv[0] : "-", "fallback",
                          "passthrough-exec-failed", why);
    }
    if (exit_code_out) *exit_code_out = ecode;
    return 0;

reap_and_fail:
    /* If we bailed out before releasing the child (e.g. SEIZE failed) it may
     * still be blocked reading the go-pipe; kill it so this doesn't also
     * deadlock in waitpid. */
    kill(pid, SIGKILL);
    { int st; waitpid(pid, &st, 0); }
    /* Same invariant as the passthrough-exec-failed record above, for the other
     * way a request can run nothing at all: the supervision itself failed to
     * come up. Rare — ptrace_self_check catches an environment-level ptrace
     * problem before the first request — but a request that was accepted and
     * then answered with nothing must not be absent from the log. */
    disclosure_record(req_id, argv[0] ? argv[0] : "-", "-",
                      "worker-setup-failed",
                      "the worker could not be started or seized; nothing ran");
    close(sfd);
    if (exit_code_out) *exit_code_out = -1;
    return -1;
}

/* ------------------------- socket-relay server path ------------------------- */

/* Ends a refused connection: half-close, then close.
 *
 * The frames already written — TAG_STDERR carrying the reason, TAG_EXIT
 * carrying 112 — are queued in the socket's send buffer, and shutdown(SHUT_WR)
 * leaves them there for the peer to read, followed by a clean EOF. That is all
 * this needs to do. It is kept ahead of the close because it says exactly one
 * thing and says it explicitly — this end has finished writing — rather than
 * relying on close()'s delivery behaviour on an AF_UNIX stream to mean the same.
 *
 * **What this deliberately no longer does.** Round 2 added a bounded
 * drain-before-close here: up to 1 MiB or 500 ms of reading-and-discarding
 * whatever the stub was still pushing, so its in-flight write() would complete
 * rather than fail. The reasoning was that a stub still blocked in write() when
 * the refusal lands takes EPIPE — and, with no SIGPIPE disposition installed,
 * SIGPIPE, signal 13, `docker exec` exit 141 — and so dies mid-request having
 * never read the refusal frames sitting in its own receive buffer.
 *
 * That fatality is now removed at its source: stub.c installs
 * `signal(SIGPIPE, SIG_IGN)` and falls through a failed write to read the
 * response anyway, which delivers the guarantee (a refused request arrives as
 * the framed exit 112, never as a killed caller) on its own, for every refusal
 * path, whatever the request's size. The drain was therefore buying nothing the
 * stub side was not already buying — at the cost of blocking THIS loop, the
 * single-threaded accept loop, for up to 500 ms per refusal. That reintroduces
 * a bounded head-of-line stall into the one component the design's §8 exists to
 * keep free of it: a burst of over-cap refusals would serialise behind each
 * other here, which is precisely the failure the accept loop's cap is meant to
 * prevent rather than cause. Redundant machinery that costs latency in the hot
 * path is worse than no machinery, so it is gone.
 *
 * If the stub's SIGPIPE disposition is ever removed, this is NOT the place to
 * compensate — restore it there. */
static void shutdown_and_close(int cfd) {
    shutdown(cfd, SHUT_WR);
    close(cfd);
}

/* Refuses one request, loudly, at both ends: a TAG_STDERR frame the stub
 * relays onto ITS stderr, then a TAG_EXIT frame carrying
 * EXIT_PROTOCOL_ERROR, then the close. The alternative — the previous
 * behaviour — was to close the socket and let the caller infer something from
 * a bare EOF, which is how a desynchronised request became a partial-argv exec
 * that neither side could see had happened. */
static void protocol_error(int cfd, const char *id, const char *what) {
    logline("req id=%s REFUSED: protocol error: %s", id ? id : "-", what);
    /* And into the sealed evidence, not only into the container log. A refusal
     * is a request the relay declined to run: without a record it is
     * indistinguishable in the bundle from an ordinary non-zero guest command,
     * and the one thing a reviewer most needs to know about it — that the relay
     * refused rather than the command failing — is exactly what is missing. A
     * refusal has no matched rule and no verb, hence the "-" rule name and the
     * `protocol-refused` verb, with the reason in `detail`. */
    disclosure_record(id, "-", "-", "protocol-refused", what);
    char msg[256];
    int n = snprintf(msg, sizeof(msg), "relay: protocol error: %s\n", what);
    /* Bounded by the buffer above, so the single-frame form is right here —
     * and snprintf's return is the length it WANTED, which can exceed the
     * buffer. Clamped, or an over-long `what` would make this claim more bytes
     * than msg holds. */
    if (n > 0) {
        size_t mlen = (size_t)n < sizeof(msg) ? (size_t)n : sizeof(msg) - 1;
        proto_send_frame(cfd, TAG_STDERR, msg, (uint32_t)mlen);
    }
    uint8_t payload[4] = { 0, 0, 0, (uint8_t)EXIT_PROTOCOL_ERROR };
    proto_send_frame(cfd, TAG_EXIT, payload, 4);
    shutdown_and_close(cfd);
}

static void handle_conn(int cfd, const struct exec_plan *plan) {
    struct exec_request req;
    const char *why = NULL;
    int rc = protocol_read_request(cfd, &req, &why);

    if (rc == PROTO_CLOSED) {
        /* EOF before END: nothing to answer on, and nothing to run. */
        logline("req id=%s REFUSED: connection closed mid-request", req.id);
        /* If the ID frame had already arrived, this turn is IDENTIFIABLE and
         * gets a record. That case is not hypothetical: it is what a host-side
         * `docker exec` timeout killing the stub mid-request looks like from
         * here, and it used to leave the turn with no guest output and no relay
         * record at all — indistinguishable in the bundle from a turn that was
         * never attempted. A request that closed before sending its id has
         * nothing to file the record against, so it stays a log line only. */
        if (strcmp(req.id, "-") != 0) {
            disclosure_record(req.id, "-", "-", "protocol-abandoned",
                              "the client closed the connection after sending its "
                              "turn id but before the request was complete; nothing ran");
        }
        close(cfd);
        protocol_request_free(&req);
        return;
    }
    if (rc != PROTO_OK) {
        /* protocol_error closes cfd and says why at both ends. The handler
         * process _exit()s straight after this returns, but freeing keeps the
         * ownership story honest for anyone who later calls handle_conn twice
         * in one process. */
        protocol_error(cfd, req.id, why ? why : "malformed request");
        protocol_request_free(&req);
        return;
    }

    logline("accepted req id=%s argv0=%s argc=%d", req.id, req.argv[0], req.argc);

    int ecode = -1;
    run_traced(req.argv, req.id, cfd, cfd, &ecode, plan, plan->timeout_ms);

    uint32_t code_be = (uint32_t)ecode;
    uint8_t payload[4] = { (code_be>>24)&0xff, (code_be>>16)&0xff, (code_be>>8)&0xff, code_be&0xff };
    proto_send_frame(cfd, TAG_EXIT, payload, 4);
    logline("req id=%s done exit=%d", req.id, ecode);
    close(cfd);
    protocol_request_free(&req);
}

/* ------------------------ the live handler processes ------------------------
 *
 * execrelayd is PID 1 of the cell, so it is the reaper of last resort for
 * EVERY orphan in the container — a grandchild whose parent exited, anything
 * the agent's own command backgrounded and walked away from. Those arrive
 * through the same waitpid(-1) as this relay's own handler forks.
 *
 * They must not be confused. The reaper used to decrement the concurrency
 * counter for every pid it reaped, including pids it never spawned, so an
 * ordinary `sh -c 'something &'` inside the cell silently lowered the counter
 * below the number of handlers actually running and the cap drifted: with
 * max_concurrent_handlers=1 and one orphan reaped, two handlers could then run
 * at once. The counter drifts DOWNWARD, so the symptom is a cap quietly
 * failing open, which is the direction that matters.
 *
 * A tracked set fixes it: a pid is only counted out if it was counted in. It
 * grows on demand rather than being sized from max_concurrent_handlers (which
 * the config allows up to UINT32_MAX — an array of that is not a cap, it is an
 * allocation bug), and it never exceeds the number of handlers actually alive.
 */
static uint32_t g_active_handlers = 0;
static pid_t *g_handler_pids = NULL;
static size_t g_handler_cap = 0;

/* Makes room for one more tracked handler, BEFORE the fork that would need it.
 * Returns 0 if there is room and -1 if there is not.
 *
 * The ordering is the point. This grow used to live inside handler_track,
 * which the accept loop calls AFTER forking — so an allocation failure had no
 * way left to refuse the work, and simply returned without tracking the pid.
 * The comment there claimed that was safe because the cap ran "permanently one
 * tighter"; the code did the opposite. An untracked pid is invisible to
 * handler_untrack, so its exit never decrements g_active_handlers — but it was
 * never INCREMENTED either, so the handler ran while the counter said it did
 * not, and the cap admitted one extra concurrent request for the life of the
 * process. That is the same fail-OPEN direction as the orphan-reaping drift
 * this tracked set exists to fix, arrived at by a different route.
 *
 * Reserving first makes the failure answerable: the caller still holds an
 * unforked connection it can refuse in-frame, so the cap fails CLOSED and the
 * refusal is disclosed like every other. */
static int handler_reserve(void) {
    if (g_active_handlers < g_handler_cap) return 0;
    size_t want = g_handler_cap ? g_handler_cap * 2 : 16;
    pid_t *grown = realloc(g_handler_pids, want * sizeof(*g_handler_pids));
    if (!grown) return -1;
    g_handler_pids = grown;
    g_handler_cap = want;
    return 0;
}

/* Capacity is guaranteed by the handler_reserve() the caller made before
 * forking, so this cannot fail and no longer has a failure path to get wrong. */
static void handler_track(pid_t pid) {
    g_handler_pids[g_active_handlers++] = pid;
}

/* Returns 1 if `pid` was one of ours (and removes it), 0 if it was an orphan
 * that merely landed on PID 1. */
static int handler_untrack(pid_t pid) {
    for (uint32_t i = 0; i < g_active_handlers; i++) {
        if (g_handler_pids[i] != pid) continue;
        g_handler_pids[i] = g_handler_pids[g_active_handlers - 1];
        g_active_handlers--;
        return 1;
    }
    return 0;
}

static void reap_finished_handlers(void) {
    for (;;) {
        int status;
        pid_t w = waitpid(-1, &status, WNOHANG);
        if (w <= 0) break;
        /* Reaped either way — that is PID 1's job — but only counted out if it
         * was one of this relay's own handlers. */
        handler_untrack(w);
    }
}

static int run_server(const struct exec_plan *plan) {
    /* SOCK_CLOEXEC on the listener for the same reason accept4 carries it
     * below: nothing this process opens may reach an agent command's fd table.
     * The handler child closes it explicitly too — both, deliberately. */
    int sfd = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
    if (sfd < 0) { perror("socket"); return 1; }
    /* No unlink() and no chmod() before/after bind: an abstract address has no
     * directory entry to clear away or to set a mode on. Reachability is
     * network-namespace scoped instead — every process in this cell (which is
     * exactly stub, plus whatever the agent runs) can connect, and nothing
     * outside the cell can. */
    struct sockaddr_un addr;
    socklen_t addrlen = fill_abstract_addr(&addr);
    if (bind(sfd, (struct sockaddr*)&addr, addrlen) != 0) { perror("bind"); return 1; }
    if (listen(sfd, 64) != 0) { perror("listen"); return 1; }
    /* '@' is the conventional rendering of the leading NUL in an abstract
     * name (the same form /proc/net/unix and `ss -x` print). */
    logline("relayd listening on @%s pid=%d", SOCK_ABSTRACT_NAME, getpid());

    signal(SIGPIPE, SIG_IGN);

    for (;;) {
        /* accept4(SOCK_CLOEXEC), not accept(): a plain accept() returns a
         * descriptor with no close-on-exec flag, and this one is the live
         * connection to the stub. Inherited across the worker's execve it
         * showed up in the agent command's own /proc/self/fd as
         * `socket:[...]` — a control channel it can both name and write to.
         * There is no non-atomic version of this that is safe: the accept loop
         * forks, so a set-the-flag-afterwards fix leaves a window. */
        int cfd = accept4(sfd, NULL, NULL, SOCK_CLOEXEC);
        if (cfd < 0) { if (errno == EINTR) continue; perror("accept4"); continue; }

        /* AFTER accept4 returned, not before it blocked. The position is the
         * whole fix.
         *
         * This reap used to sit at the top of the loop, so the count the cap
         * was checked against was a full accept() cycle stale: it was taken
         * BEFORE the loop parked in accept4, and accept4 parks for as long as
         * it takes the next request to arrive — which is exactly the interval
         * in which the previous request finishes and its handler exits. With
         * max_concurrent_handlers=1 the effect was deterministic and absurd:
         * request 1 forks a handler and the count goes to 1; the loop reaps
         * (handler 1 is still running, so nothing) and blocks; request 1
         * completes and handler 1 becomes a zombie; request 2 arrives and is
         * refused "too many concurrent requests" against a count of 1 while
         * ZERO handlers are running. Every second strictly-sequential request,
         * refused by a cap nothing was violating.
         *
         * Distinct from — and not fixed by — the reaper's tracked-pid set: that
         * stopped the count drifting DOWNWARD when PID 1 reaped an orphan it
         * never spawned. This is the count being read at the wrong moment. Both
         * had to be wrong for the cap to be right, which is why the first fix
         * did not surface the second. */
        reap_finished_handlers();

        if (g_active_handlers >= plan->max_concurrent_handlers) {
            /* Through protocol_error, like every other wire-level refusal.
             * This path used to write a bare unframed line onto a socket whose
             * every other byte is length-prefixed frames: the stub read the
             * first five bytes of "relay: too many..." as a frame header, got a
             * tag of 'r' it did not recognise, and gave up with its own default
             * exit 1 — a refusal indistinguishable from the command having
             * failed. Now it is a TAG_STDERR frame plus TAG_EXIT/112, and it
             * gets a disclosure record like any other refusal. */
            char why[96];
            snprintf(why, sizeof(why), "too many concurrent requests (cap %u)",
                     plan->max_concurrent_handlers);
            logline("rejecting connection: %u handlers already active (cap %u)",
                    g_active_handlers, plan->max_concurrent_handlers);
            protocol_error(cfd, "-", why);
            continue;
        }

        /* Before the fork, so a failure here is still refusable. See
         * handler_reserve: doing this afterwards is what made an OOM admit an
         * untracked handler and loosen the cap. */
        if (handler_reserve() != 0) {
            logline("rejecting connection: out of memory reserving a handler slot");
            protocol_error(cfd, "-", "the relay is out of memory; request refused");
            continue;
        }

        pid_t hpid = fork();
        if (hpid < 0) { perror("fork(handler)"); close(cfd); continue; }
        if (hpid == 0) {
            /* handler child: owns this one connection end to end, then exits.
             * Runs completely independently of the accept loop and any other
             * handler — this is the fix for the head-of-line-blocking bug: a
             * hung command here can never block accept() from servicing the
             * next connection, because accept() isn't running in this
             * process at all. */
            close(sfd);
            handle_conn(cfd, plan);
            _exit(0);
        }
        close(cfd);
        handler_track(hpid);
    }
}

/* Startup self-check: fork a disposable canary child and confirm
 * PTRACE_SEIZE actually works in this environment before ever accepting a
 * real request. Per the design's error-handling requirement, a ptrace
 * failure must refuse cell startup outright, not be discovered silently
 * partway through a run — even though a per-request SEIZE failure (handled
 * in run_traced's reap_and_fail path) already fails that one request safely
 * rather than running it unsupervised, this check catches an
 * environment-level problem immediately instead of on the first real turn. */
static int ptrace_self_check(void) {
    pid_t pid = fork();
    if (pid < 0) { perror("ptrace_self_check: fork"); return -1; }
    if (pid == 0) {
        raise(SIGSTOP);
        _exit(0);
    }
    int status;
    waitpid(pid, &status, WUNTRACED);
    int rc = ptrace(PTRACE_SEIZE, pid, 0, (void*)(long)PTRACE_O_EXITKILL);
    if (rc != 0) {
        fprintf(stderr, "execrelayd: PTRACE_SEIZE self-check failed: %s\n", strerror(errno));
        kill(pid, SIGKILL);
        waitpid(pid, &status, 0);
        return -1;
    }
    ptrace(PTRACE_CONT, pid, 0, 0);
    waitpid(pid, &status, 0);
    return 0;
}

/* ---------------------- relay-internal environment ------------------------
 *
 * Every variable execrelayd reads from its OWN environment at startup, and
 * which therefore must not ride along into the agent's command. The list is
 * the audit: anything added to it here has to be named here too, and the
 * grep that finds a new getenv() in this image finds this array beside it.
 *
 * Today there is exactly one, and it is the whole interception plan.
 * CHAMBER_EXEC_CONSEQUENCE_SPEC_B64 is the base64 ExecConsequencePlan — every
 * rule, every match pattern, every fabricate payload, every substitute target.
 * The worker inherits `environ` wholesale, which is correct and deliberate for
 * the agent's own variables and was catastrophic for this one: `env | grep
 * CHAMBER_EXEC_CONSEQUENCE` inside a relayed command handed the agent under
 * evaluation the complete ruleset it is being measured against — a strictly
 * larger disclosure than the RELAY_REQ_ID tell removed alongside it, because
 * it does not merely reveal that interception exists, it reveals exactly what
 * is intercepted and how, which is what an adversarial agent needs in order to
 * evade it.
 *
 * Done ONCE here rather than in the worker's pre-exec path, because this
 * process's own environment is readable too: execrelayd is PID 1 of the cell
 * and the agent's commands run as root in it, so `cat /proc/1/environ` reaches
 * the same bytes that `env` did. One scrub at startup covers both, and covers
 * every fork path — handler processes and --self-test alike — rather than one
 * exec site that a later path could forget.
 *
 * The memset is not belt-and-braces, it is half the fix. unsetenv() rewrites
 * the `environ` POINTER array, which is what execve() passes on and what
 * getenv() reads — but /proc/<pid>/environ is served from the original
 * stack region the kernel populated at exec, which unsetenv never touches.
 * Overwriting the value bytes in place is what clears that copy; unsetenv is
 * what clears the inherited one. Neither alone is sufficient.
 *
 * Nothing re-reads this variable after config_load_from_env: the parsed plan
 * lives in memory and is passed by pointer from here down. */
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
    /* No setvbuf here, and nothing in this program writes to the `stdout`
     * FILE* at all any more. fd 1 is the disclosure stream and is written only
     * through raw write()s (proto_write_full), which is what keeps each record
     * one atomic write; a stdio buffer layered over it would defeat that, and
     * would additionally be duplicated into every forked handler. Operator
     * output goes to stderr — see logline. */

    struct exec_plan plan;
    if (config_load_from_env(&plan) != 0) {
        fprintf(stderr, "execrelayd: refusing to start — CHAMBER_EXEC_CONSEQUENCE_SPEC_B64 "
                         "is absent, malformed, or invalid\n");
        return 1;
    }
    scrub_relay_private_env();
    /* No directory to create any more. /work/.exec-relay/ existed solely to
     * hold the disclosure log file; the control socket never needed it (it is
     * abstract-namespace) and nothing else in this image used it. The log is
     * now this process's stdout, which the runtime provides — so the relay
     * leaves nothing on the filesystem for the agent to find or remove. */
    if (ptrace_self_check() != 0) {
        fprintf(stderr, "execrelayd: refusing to start — the interception mechanism this "
                         "whole relay depends on is not usable in this environment\n");
        return 1;
    }
    /* Fail-closed, exactly like a malformed config: a relay that cannot write
     * its disclosure log has nothing to say about anything it then does, and a
     * silent no-op log is worse than no relay at all — the bundle looks like a
     * run in which the agent execed nothing. */
    if (disclosure_init() != 0) {
        return 1;
    }

    if (argc >= 2 && strcmp(argv[1], "--self-test") == 0) {
        int ecode = -1;
        /* Both streams to fd 2, not fd 1. This path emits the same tagged
         * protocol FRAMES the socket path does (proto_send_stream), and fd 1
         * is now the disclosure stream: a frame written there would be
         * interleaved binary in the middle of the record JSONL, which is
         * precisely the ambiguity moving operator output to stderr exists to
         * remove. Only this hand-run diagnostic entry point is affected —
         * nothing in the harness invokes --self-test. */
        run_traced(argv + 2, "self-test", STDERR_FILENO, STDERR_FILENO,
                   &ecode, &plan, plan.timeout_ms);
        return ecode;
    }
    return run_server(&plan);
}
