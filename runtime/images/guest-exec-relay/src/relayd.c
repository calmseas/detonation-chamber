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

/* The disclosure log is a regular file under a hidden subdirectory of the
 * /work tmpfs. The real cell (chamber-isolation's AgentCell::start) runs
 * read-only with a tmpfs ONLY at /work — /tmp does not exist as a writable
 * path there, so nothing of ours can live under /tmp. /work/.exec-relay/ keeps
 * the log inside the one writable filesystem that always exists, and folds it
 * out of the agent's bare working directory so a casual `ls /work` does not
 * surface it (coherent-per-tool, not forensic-proof — that is this project's
 * stated bar). RELAY_DIR is created in main() before the log is opened.
 *
 * The CONTROL SOCKET deliberately does NOT live there. /work is writable by
 * the sandboxed agent under evaluation, and TurnDirective::RunCommand runs
 * arbitrary commands in the cell as root, so a socket at a filesystem path
 * under /work could be `rm`ed and re-bound by the very agent this relay exists
 * to observe — disabling or spoofing the entire interception and disclosure
 * mechanism. Linux's ABSTRACT socket namespace has no filesystem entry at all:
 * the name is owned by the network namespace, not by any directory, so
 * filesystem write access to /work grants no purchase on it, and the name
 * cannot be pre-empted while execrelayd holds it (a second bind() gets
 * EADDRINUSE) nor unlinked. It also vanishes with the socket, so there is no
 * stale entry to clean up on restart. */
#define RELAY_DIR "/work/.exec-relay"

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

static void logline(const char *fmt, ...) {
    va_list ap;
    struct timespec ts; clock_gettime(CLOCK_REALTIME, &ts);
    fprintf(stdout, "[relayd %ld.%03ld] ", (long)ts.tv_sec, ts.tv_nsec/1000000);
    va_start(ap, fmt);
    vfprintf(stdout, fmt, ap);
    va_end(ap);
    fputc('\n', stdout);
    fflush(stdout);
}

/* read_full/write_full, the request reader and its two parsing primitives all
 * live in protocol.c now, and are used from here through protocol.h. They were
 * moved out for exactly the reason record.c was: this file cannot be compiled
 * anywhere but aarch64 (see the `#error` above), so nothing defined in it can
 * be reached by the host-run C unit tests, and a parser nobody can test is a
 * parser whose refusal paths get checked by hand once and never again. */

/* frame tags for the response protocol */
#define TAG_STDOUT 1
#define TAG_STDERR 2
#define TAG_EXIT   3

static void send_frame(int fd, uint8_t tag, const void *payload, uint32_t len) {
    uint8_t hdr[5];
    hdr[0] = tag;
    hdr[1] = (len >> 24) & 0xff; hdr[2] = (len >> 16) & 0xff;
    hdr[3] = (len >> 8) & 0xff;  hdr[4] = len & 0xff;
    proto_write_full(fd, hdr, 5);
    if (len) proto_write_full(fd, payload, len);
}

/* Read tracee's NUL-terminated string at remote address via /proc/pid/mem */
static int read_tracee_str(int pid, unsigned long long addr, char *out, size_t outsz) {
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

/* ---------------------------- disclosure log ---------------------------- */
#define DISCLOSURE_LOG_PATH RELAY_DIR "/disclosure.log"
static int g_disclosure_fd = -1;

/* Opens the log, or fails. Returns 0 on success and -1 if the log could not be
 * opened — and the caller MUST refuse to start on -1.
 *
 * This used to return void and simply leave g_disclosure_fd at -1, which every
 * later disclosure_record() short-circuited on. The relay then served every
 * request while recording nothing, with no indication anywhere that its entire
 * reason for existing was switched off: the run produced a bundle whose
 * exec-consequence channel was empty, which reads exactly like a run in which
 * the agent execed nothing. §9 is fail-closed for the same reason
 * config_load_from_env is — a relay that cannot record is not a weaker relay,
 * it is a relay whose output is a lie by omission. */
static int disclosure_init(void) {
    /* O_CLOEXEC is load-bearing, not hygiene. Without it this WRITABLE,
     * O_APPEND descriptor to the sealed evidence log survives the worker
     * child's execve into the agent's own command, which can then append
     * whatever records it likes with a plain shell redirection to the
     * inherited fd number (`echo '{...}' >&3`) — forging or corrupting the
     * very evidence it is the subject of. Verified before the fix: fd 3 in a
     * relayed command's /proc/self/fd read
     * `l-wx------ 3 -> /work/.exec-relay/disclosure.log`, and a forged record
     * written through it landed in the log. */
    g_disclosure_fd = open(DISCLOSURE_LOG_PATH, O_CREAT | O_WRONLY | O_APPEND | O_CLOEXEC, 0600);
    if (g_disclosure_fd < 0) {
        fprintf(stderr, "execrelayd: refusing to start — the disclosure log %s could not "
                        "be opened: %s. A relay that cannot record is not a degraded "
                        "relay; every request it then served would be absent from the "
                        "evidence with nothing saying so.\n",
                DISCLOSURE_LOG_PATH, strerror(errno));
        return -1;
    }
    static const char header[] =
        "{\"known_residual_tells\":[\"TracerPid nonzero in /proc/self/status "
        "\\u2014 structural to ptrace, not masked\"]}\n";
    if (proto_write_full(g_disclosure_fd, header, sizeof(header) - 1) < 0) {
        fprintf(stderr, "execrelayd: refusing to start — the disclosure log %s could not "
                        "be written: %s\n", DISCLOSURE_LOG_PATH, strerror(errno));
        close(g_disclosure_fd);
        g_disclosure_fd = -1;
        return -1;
    }
    return 0;
}

/* Builds one complete JSON record in a local buffer and writes it with a
 * SINGLE proto_write_full() call. This matters because g_disclosure_fd is opened
 * once in main() before run_server() forks any handlers, so every
 * concurrent handler process (Step 5) inherits and shares the same fd:
 * O_APPEND makes each individual write() atomic, but a record built from
 * several separate write() calls is not — two handlers racing here could
 * interleave their writes into one corrupted, unparseable line. Composing
 * the whole line first and issuing one write() (comfortably under any
 * filesystem's atomic-write block size at this record's bounded size)
 * keeps concurrent records from ever interleaving.
 *
 * The composition itself is record.c's, not this file's, so that it can be
 * unit-tested: nothing in relayd.c compiles anywhere but aarch64 Linux, and
 * an untestable record builder is how two of the five fields came to be
 * interpolated with a raw %s. See record.h. */
static void disclosure_record(const char *turn_id, const char *requested_argv0,
                               const char *matched_rule, const char *verb_applied,
                               const char *detail) {
    /* Unreachable by construction now: main() refuses to start if
     * disclosure_init() could not open the log, so this fd is always valid
     * here. Kept as a belt-and-braces guard rather than removed, but it is no
     * longer a DEGRADED MODE — it used to be the thing that quietly turned the
     * whole disclosure log into a no-op for the life of a run. */
    if (g_disclosure_fd < 0) return;
    struct timespec ts; clock_gettime(CLOCK_REALTIME, &ts);
    char buf[8192];
    size_t off = disclosure_format_record(buf, sizeof(buf),
                                          (long)ts.tv_sec, (long)(ts.tv_nsec / 1000000),
                                          turn_id, requested_argv0,
                                          matched_rule, verb_applied, detail);
    proto_write_full(g_disclosure_fd, buf, off);
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
 * target is definitively not loadable. */
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
 * `rule_find`/`rule_replace` are NULL when no rewrite applies. Switching from a
 * rewriting to a non-rewriting rule mid-stream (a nested exec that matches
 * nothing) flushes what the old rule was holding before the raw bytes resume,
 * so no byte is ever dropped or reordered by the switch. */
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
            send_frame(fd, tag, tail, (uint32_t)tail_len);
        }
        rewrite_stream_end(rs);
    }
    if (!rule_find) {
        if (len) send_frame(fd, tag, buf, (uint32_t)len);
        return;
    }
    if (!rs->active) rewrite_stream_begin(rs, rule_find, rule_replace);

    const char *out = NULL; size_t out_len = 0;
    if (rewrite_stream_push(rs, buf, len, &out, &out_len) != 0) {
        /* Allocation failure. Fail CLOSED — forwarding the raw bytes here would
         * emit exactly the string the rule exists to remove, at the one moment
         * nobody is watching. Loud in the container log; the record for this
         * exec already named the rule that was in force. */
        logline("req=%s rewrite: transform failed (out of memory), %zu bytes dropped",
                req_id ? req_id : "-", len);
        return;
    }
    if (out_len) send_frame(fd, tag, out, (uint32_t)out_len);
}

/* Releases whatever the stream is still holding back, at pipe EOF. */
static void finish_stream(int fd, uint8_t tag, struct rewrite_stream *rs) {
    if (!rs->active) return;
    const char *tail = NULL; size_t tail_len = 0;
    if (rewrite_stream_finish(rs, &tail, &tail_len) == 0 && tail_len) {
        send_frame(fd, tag, tail, (uint32_t)tail_len);
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
         * --self-test path out_fd/err_fd ARE fds 1 and 2, which by now name the
         * output pipes via dup2, so the guard is on the fd number, not on the
         * variable. */
        close(syncr[1]);
        close(syncg[0]);
        close(sfd);                                     /* the tracer's signalfd */
        if (g_disclosure_fd >= 0) close(g_disclosure_fd);  /* the sealed evidence log */
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
            /* The container log is execrelayd's own stdout — NOT the sealed
             * evidence. A watchdog kill that only ever appeared there was
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
                        struct arm64_regs regs;
                        get_regs(w, &regs);
                        int is_execveat = (msg == (unsigned long)SYS_execveat);
                        unsigned long long path_reg = is_execveat ? regs.regs[1] : regs.regs[0];
                        char reqpath[1024];
                        read_tracee_str(w, path_reg, reqpath, sizeof(reqpath));

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
                                    size_t dl = 0;
                                    for (int ai = 0; ai < sub_argc && dl < sizeof(detail) - 1; ai++) {
                                        int n = snprintf(detail + dl, sizeof(detail) - dl,
                                                         ai ? " %s" : "%s", sub_argv[ai]);
                                        if (n < 0) break;
                                        dl += (size_t)n < sizeof(detail) - dl ? (size_t)n : sizeof(detail) - dl - 1;
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
                            verb_name = "rewrite";
                            snprintf(detail, sizeof(detail), "stdout_find=%s",
                                      rule->has_stdout_rewrite ? rule->stdout_find : "(none)");
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
                        active_rewrite = (rule && rule->verb == VERB_REWRITE) ? rule : NULL;
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
    if (n > 0) send_frame(cfd, TAG_STDERR, msg, (uint32_t)n);
    uint8_t payload[4] = { 0, 0, 0, (uint8_t)EXIT_PROTOCOL_ERROR };
    send_frame(cfd, TAG_EXIT, payload, 4);
    close(cfd);
}

static void handle_conn(int cfd, const struct exec_plan *plan) {
    struct exec_request req;
    const char *why = NULL;
    int rc = protocol_read_request(cfd, &req, &why);

    if (rc == PROTO_CLOSED) {
        /* EOF before END: nothing to answer on, and nothing to run. */
        logline("req id=%s REFUSED: connection closed mid-request", req.id);
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
    send_frame(cfd, TAG_EXIT, payload, 4);
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

static void handler_track(pid_t pid) {
    if (g_active_handlers >= g_handler_cap) {
        size_t want = g_handler_cap ? g_handler_cap * 2 : 16;
        pid_t *grown = realloc(g_handler_pids, want * sizeof(*g_handler_pids));
        if (!grown) {
            /* Untracked, so its exit will not decrement the counter and this
             * process's cap becomes permanently one tighter. Refusing work is
             * the safe direction, and this is a malloc of 128 bytes. */
            logline("handler tracking: out of memory, pid %d untracked (cap will run tight)",
                    (int)pid);
            return;
        }
        g_handler_pids = grown;
        g_handler_cap = want;
    }
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
        reap_finished_handlers();

        /* accept4(SOCK_CLOEXEC), not accept(): a plain accept() returns a
         * descriptor with no close-on-exec flag, and this one is the live
         * connection to the stub. Inherited across the worker's execve it
         * showed up in the agent command's own /proc/self/fd as
         * `socket:[...]` — a control channel it can both name and write to.
         * There is no non-atomic version of this that is safe: the accept loop
         * forks, so a set-the-flag-afterwards fix leaves a window. */
        int cfd = accept4(sfd, NULL, NULL, SOCK_CLOEXEC);
        if (cfd < 0) { if (errno == EINTR) continue; perror("accept4"); continue; }

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

int main(int argc, char **argv) {
    setvbuf(stdout, NULL, _IOLBF, 0);

    struct exec_plan plan;
    if (config_load_from_env(&plan) != 0) {
        fprintf(stderr, "execrelayd: refusing to start — CHAMBER_EXEC_CONSEQUENCE_SPEC_B64 "
                         "is absent, malformed, or invalid\n");
        return 1;
    }
    /* The disclosure log (disclosure_init) lives under RELAY_DIR; create it
     * before the log is opened. The control socket no longer needs this
     * directory — it is abstract-namespace now — but the log genuinely does,
     * and the log is not optional: without it a run produces no exec-
     * consequence evidence at all. /work is a fresh tmpfs each run, so this
     * normally does not exist yet — EEXIST is fine, anything else means the
     * log cannot be created and the relay cannot do its job, so refuse to
     * start. */
    if (mkdir(RELAY_DIR, 0700) != 0 && errno != EEXIST) {
        fprintf(stderr, "execrelayd: refusing to start — could not create %s: %s\n",
                RELAY_DIR, strerror(errno));
        return 1;
    }
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
        run_traced(argv + 2, "self-test", STDOUT_FILENO, STDERR_FILENO,
                   &ecode, &plan, plan.timeout_ms);
        return ecode;
    }
    return run_server(&plan);
}
