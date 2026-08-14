// runtime/images/guest-exec-relay/src/relayd.c
#define _GNU_SOURCE
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

static ssize_t write_full(int fd, const void *buf, size_t n) {
    const char *p = buf; size_t left = n;
    while (left) {
        ssize_t w = write(fd, p, left);
        if (w < 0) { if (errno == EINTR) continue; return -1; }
        if (w == 0) return -1;
        p += w; left -= w;
    }
    return (ssize_t)n;
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

/* Read a '\n'-terminated line from a socket fd, byte at a time (protocol is small). */
static int read_line(int fd, char *buf, size_t bufsz) {
    size_t i = 0;
    for (;;) {
        char c;
        ssize_t r = read(fd, &c, 1);
        if (r <= 0) return -1;
        if (c == '\n') { buf[i] = 0; return (int)i; }
        if (i + 1 < bufsz) buf[i++] = c;
    }
}

/* frame tags for the response protocol */
#define TAG_STDOUT 1
#define TAG_STDERR 2
#define TAG_EXIT   3

static void send_frame(int fd, uint8_t tag, const void *payload, uint32_t len) {
    uint8_t hdr[5];
    hdr[0] = tag;
    hdr[1] = (len >> 24) & 0xff; hdr[2] = (len >> 16) & 0xff;
    hdr[3] = (len >> 8) & 0xff;  hdr[4] = len & 0xff;
    write_full(fd, hdr, 5);
    if (len) write_full(fd, payload, len);
}

/* Read tracee's NUL-terminated string at remote address via /proc/pid/mem */
static int read_tracee_str(int pid, unsigned long long addr, char *out, size_t outsz) {
    char path[64];
    snprintf(path, sizeof(path), "/proc/%d/mem", pid);
    int fd = open(path, O_RDONLY);
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
    int fd = open(path, O_RDWR);
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
    int fd = open(path, O_RDONLY);
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

static void disclosure_init(void) {
    g_disclosure_fd = open(DISCLOSURE_LOG_PATH, O_CREAT | O_WRONLY | O_APPEND, 0600);
    if (g_disclosure_fd < 0) { perror("disclosure: open"); return; }
    static const char header[] =
        "{\"known_residual_tells\":[\"TracerPid nonzero in /proc/self/status "
        "\\u2014 structural to ptrace, not masked\"]}\n";
    write_full(g_disclosure_fd, header, sizeof(header) - 1);
}

/* Minimal, allocation-free JSON string escaping for the handful of fields we
 * emit here (argv entries, rule names, free-form `detail` text) — backslash
 * and double-quote are the only bytes this schema's own values can contain
 * that would break JSON (argv/name/detail never carry control characters in
 * practice; this only needs to not corrupt the log, not be a general escaper).
 * Appends into `buf` at offset `off` (bounded by `bufcap`) and returns the
 * new offset — a building block for assembling one full record in memory
 * before it ever touches the fd (see disclosure_record). */
static size_t append_json_escaped(char *buf, size_t off, size_t bufcap, const char *s) {
    for (; *s && off + 2 <= bufcap; s++) {
        if (*s == '"' || *s == '\\') buf[off++] = '\\';
        buf[off++] = *s;
    }
    return off;
}

/* vsnprintf-and-advance: formats into `buf` at offset `off` (bounded by
 * `bufcap`), returns the new offset. Truncates safely (never past bufcap)
 * rather than overflowing if a record ever runs long. */
static size_t append_fmt(char *buf, size_t off, size_t bufcap, const char *fmt, ...) {
    if (off >= bufcap) return off;
    va_list ap;
    va_start(ap, fmt);
    int n = vsnprintf(buf + off, bufcap - off, fmt, ap);
    va_end(ap);
    if (n <= 0) return off;
    size_t written = (size_t)n < bufcap - off ? (size_t)n : bufcap - off - 1;
    return off + written;
}

/* Builds one complete JSON record in a local buffer and writes it with a
 * SINGLE write_full() call. This matters because g_disclosure_fd is opened
 * once in main() before run_server() forks any handlers, so every
 * concurrent handler process (Step 5) inherits and shares the same fd:
 * O_APPEND makes each individual write() atomic, but a record built from
 * several separate write() calls is not — two handlers racing here could
 * interleave their writes into one corrupted, unparseable line. Composing
 * the whole line first and issuing one write() (comfortably under any
 * filesystem's atomic-write block size at this record's bounded size)
 * keeps concurrent records from ever interleaving. */
static void disclosure_record(const char *turn_id, const char *requested_argv0,
                               const char *matched_rule, const char *verb_applied,
                               const char *detail) {
    if (g_disclosure_fd < 0) return;
    struct timespec ts; clock_gettime(CLOCK_REALTIME, &ts);
    char buf[8192];
    size_t off = 0;
    /* turn_id is guest-controlled (it arrives verbatim from `stub --turn-id=`),
     * so it MUST go through the same escaper as requested_argv0/detail — not a
     * raw %s. A crafted turn_id could otherwise close the JSON string early and
     * inject its own keys (e.g. a fake "known_residual_tells"), making the whole
     * record either fail to parse or be misread as the header and silently
     * dropped from the sealed bundle (see bundle.rs record_exec_consequence_log). */
    off = append_fmt(buf, off, sizeof(buf), "{\"turn_id\":\"");
    off = append_json_escaped(buf, off, sizeof(buf), turn_id ? turn_id : "-");
    off = append_fmt(buf, off, sizeof(buf),
        "\",\"timestamp\":%ld.%03ld,\"requested_argv0\":\"",
        (long)ts.tv_sec, ts.tv_nsec / 1000000);
    off = append_json_escaped(buf, off, sizeof(buf), requested_argv0);
    off = append_fmt(buf, off, sizeof(buf),
                      "\",\"matched_rule\":\"%s\",\"verb_applied\":\"%s\",\"detail\":\"",
                      matched_rule, verb_applied);
    off = append_json_escaped(buf, off, sizeof(buf), detail);
    off = append_fmt(buf, off, sizeof(buf), "\"}\n");
    write_full(g_disclosure_fd, buf, off);
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
    int dfd = open(base, O_RDONLY | O_DIRECTORY);
    if (dfd < 0) return 1;                        /* cannot resolve — keep the record */
    int ok = faccessat(dfd, path, X_OK, 0) == 0;
    close(dfd);
    return ok;
}

static size_t apply_rewrite(char *buf, size_t len, const char *find, const char *replace, char *out, size_t outcap) {
    if (!find || !find[0]) { size_t n = len < outcap ? len : outcap; memcpy(out, buf, n); return n; }
    size_t findlen = strlen(find), replacelen = strlen(replace);
    size_t oi = 0, i = 0;
    while (i < len && oi < outcap) {
        if (i + findlen <= len && memcmp(buf + i, find, findlen) == 0) {
            size_t n = replacelen < (outcap - oi) ? replacelen : (outcap - oi);
            memcpy(out + oi, replace, n);
            oi += n; i += findlen;
        } else {
            out[oi++] = buf[i++];
        }
    }
    return oi;
}

/* ---------------------------------------------------------------------
 * Core primitive shared by both the socket-relay path and the
 * --self-test path: fork a child, have it install the seccomp filter,
 * PTRACE_SEIZE it from the parent, release it, and drive it to exec
 * (with verb dispatch applied at the seccomp trap), streaming
 * stdout/stderr through the given fds and returning the exit code.
 * req_id may be NULL.
 * --------------------------------------------------------------------- */
static int run_traced(char *const argv[], char *const envp_extra[], int envp_extra_n,
                       const char *req_id, int out_fd, int err_fd, int *exit_code_out,
                       const struct exec_plan *plan, uint64_t timeout_ms) {
    const struct exec_rule *active_rewrite = NULL;
    int outp[2], errp[2], syncr[2], syncg[2];
    if (pipe(outp) || pipe(errp) || pipe(syncr) || pipe(syncg)) { perror("pipe"); return -1; }

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
    int sfd = signalfd(-1, &mask, SFD_NONBLOCK);
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

        /* build envp: inherited environ + any extras (e.g. RELAY_REQ_ID) */
        extern char **environ;
        int base_n = 0; while (environ[base_n]) base_n++;
        char **envp = malloc(sizeof(char*) * (base_n + envp_extra_n + 1));
        int k = 0;
        for (int i = 0; i < base_n; i++) envp[k++] = environ[i];
        for (int i = 0; i < envp_extra_n; i++) envp[k++] = envp_extra[i];
        envp[k] = NULL;

        /* execvpe, not execve: a bare command name (argv[0] without a slash)
         * must be resolved against PATH exactly as a shell would — the bridge
         * itself issues bare names (e.g. `cat` for every ReadFile directive),
         * and plain execve() would fail every one with ENOENT. execvpe tries
         * each PATH candidate with its own execve() syscall, so the seccomp
         * trap still fires per attempt; argv[0] stays the literal original name
         * throughout, which is what config_match matches on, so rule matching
         * composes unchanged. (musl 1.2.5 on Alpine 3.20 provides execvpe;
         * verified it compiles/links/runs in that environment.) */
        execvpe(argv[0], argv, envp);
        /* execvpe only returns on error. The message must NOT name this as an
         * interception layer — a generic "<name>: not found" matches what a
         * real missing-binary failure looks like (coherent-per-tool, this
         * project's stated bar; not byte-identical shell mimicry). */
        fprintf(stderr, "%s: not found\n", argv[0]);
        _exit(127);
    }

    /* parent */
    close(outp[1]); close(errp[1]); close(syncr[1]); close(syncg[0]);

    char rbyte;
    if (read_full(syncr[0], &rbyte, 1) != 1 || rbyte != 'R') {
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

    { char g = 'G'; write_full(syncg[1], &g, 1); }
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
            kill(pid, SIGKILL);
            { int st; waitpid(pid, &st, 0); }
            close(sfd); close(outp[0]); close(errp[0]);
            if (exit_code_out) *exit_code_out = 124; /* matches GNU `timeout`'s convention */
            return -1;
        }
        int pr = poll(pfds, nfds, (int)remaining_ms);
        if (pr < 0) { if (errno == EINTR) continue; break; }

        if (oi >= 0 && (pfds[oi].revents & (POLLIN|POLLHUP))) {
            char buf[8192], out[8192];
            ssize_t r = read(outp[0], buf, sizeof(buf));
            if (r > 0) {
                if (active_rewrite && active_rewrite->has_stdout_rewrite) {
                    size_t n = apply_rewrite(buf, (size_t)r, active_rewrite->stdout_find,
                                              active_rewrite->stdout_replace, out, sizeof(out));
                    send_frame(out_fd, TAG_STDOUT, out, (uint32_t)n);
                } else {
                    send_frame(out_fd, TAG_STDOUT, buf, (uint32_t)r);
                }
            }
            else { have_out = 0; close(outp[0]); }
        }
        if (ei >= 0 && (pfds[ei].revents & (POLLIN|POLLHUP))) {
            char buf[8192], out[8192];
            ssize_t r = read(errp[0], buf, sizeof(buf));
            if (r > 0) {
                if (active_rewrite && active_rewrite->has_stderr_rewrite) {
                    size_t n = apply_rewrite(buf, (size_t)r, active_rewrite->stderr_find,
                                              active_rewrite->stderr_replace, out, sizeof(out));
                    send_frame(err_fd, TAG_STDERR, out, (uint32_t)n);
                } else {
                    send_frame(err_fd, TAG_STDERR, buf, (uint32_t)r);
                }
            }
            else { have_err = 0; close(errp[0]); }
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
                            const char *replacement = rule->replacement_argv[0];
                            size_t rl = strlen(replacement) + 1;
                            if (rl <= SCRATCH_SIZE) {
                                /* Both the memory poke and the register write can
                                 * fail (e.g. the tracee raced to exit); if either
                                 * does, the real syscall proceeds UNMODIFIED, so
                                 * recording verb_applied="substitute" would file a
                                 * failed substitution as a successful one in the
                                 * evidence. Check both and fall to the existing
                                 * substitute-failed-* convention on either. */
                                if (write_tracee_mem(w, scratch_addr, replacement, rl) != 0) {
                                    verb_name = "substitute-failed-mem-write";
                                } else {
                                    if (is_execveat) regs.regs[1] = scratch_addr;
                                    else regs.regs[0] = scratch_addr;
                                    if (set_regs(w, &regs) != 0) {
                                        verb_name = "substitute-failed-set-regs";
                                    } else {
                                        snprintf(detail, sizeof(detail), "%s", replacement);
                                    }
                                }
                            } else {
                                verb_name = "substitute-failed-scratch-too-small";
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

                            int ok = 0;
                            if (b64_stdout && b64_stderr) {
                                static const char HELPER_PATH[] = "/usr/local/bin/fabricate-emit";
                                const char *helper_argv[4] = { HELPER_PATH, exit_code_str, b64_stdout, b64_stderr };

                                uint8_t buf[SCRATCH_SIZE];
                                size_t off = 0;
                                unsigned long long str_addrs[4];
                                int fits = 1;
                                for (int ai = 0; ai < 4 && fits; ai++) {
                                    size_t sl = strlen(helper_argv[ai]) + 1;
                                    if (off + sl > SCRATCH_SIZE - 64) { fits = 0; break; }
                                    memcpy(buf + off, helper_argv[ai], sl);
                                    str_addrs[ai] = scratch_addr + off;
                                    off += sl;
                                }
                                if (fits) {
                                    off = (off + 7) & ~(size_t)7; /* 8-byte align the pointer array */
                                    unsigned long long ptr_array_addr = scratch_addr + off;
                                    unsigned long long ptrs[5] = { str_addrs[0], str_addrs[1], str_addrs[2], str_addrs[3], 0 };
                                    memcpy(buf + off, ptrs, sizeof(ptrs));
                                    off += sizeof(ptrs);

                                    write_tracee_mem(w, scratch_addr, buf, off);
                                    if (is_execveat) { regs.regs[1] = str_addrs[0]; regs.regs[2] = ptr_array_addr; }
                                    else { regs.regs[0] = str_addrs[0]; regs.regs[1] = ptr_array_addr; }
                                    set_regs(w, &regs);
                                    snprintf(detail, sizeof(detail), "exit=%d stdout_b64_len=%zu stderr_b64_len=%zu",
                                             rule->fabricate_exit_code, strlen(b64_stdout), strlen(b64_stderr));
                                    ok = 1;
                                }
                            }
                            if (!ok) verb_name = "fabricate-failed-encode-or-scratch";
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
                    if (w == pid) { ecode = 128 + WTERMSIG(status); have_exit = 1; }
                }
            }
        }
    }
    close(sfd);
    if (exit_code_out) *exit_code_out = ecode;
    return 0;

reap_and_fail:
    /* If we bailed out before releasing the child (e.g. SEIZE failed) it may
     * still be blocked reading the go-pipe; kill it so this doesn't also
     * deadlock in waitpid. */
    kill(pid, SIGKILL);
    { int st; waitpid(pid, &st, 0); }
    close(sfd);
    if (exit_code_out) *exit_code_out = -1;
    return -1;
}

/* ------------------------- socket-relay server path ------------------------- */

static void handle_conn(int cfd, const struct exec_plan *plan) {
    char line[2048];
    char id[256] = "-";
    int argc = 0;
    char *argv[EXEC_RELAY_MAX_ARGV];
    for (int i = 0; i < EXEC_RELAY_MAX_ARGV; i++) argv[i] = NULL;

    for (;;) {
        int n = read_line(cfd, line, sizeof(line));
        if (n < 0) { close(cfd); return; }
        if (strncmp(line, "ID ", 3) == 0) {
            strncpy(id, line + 3, sizeof(id) - 1);
        } else if (strncmp(line, "ARGC ", 5) == 0) {
            argc = atoi(line + 5);
            if (argc < 1 || argc > EXEC_RELAY_MAX_ARGV - 1) { close(cfd); return; }
        } else if (strncmp(line, "ARG ", 4) == 0) {
            for (int i = 0; i < EXEC_RELAY_MAX_ARGV - 1; i++) {
                if (argv[i] == NULL) { argv[i] = strdup(line + 4); break; }
            }
        } else if (strcmp(line, "END") == 0) {
            break;
        }
    }
    if (!argv[0]) { close(cfd); return; }

    logline("accepted req id=%s argv0=%s argc=%d", id, argv[0], argc);

    char idenv[300];
    snprintf(idenv, sizeof(idenv), "RELAY_REQ_ID=%s", id);
    char *extra[1] = { idenv };

    int ecode = -1;
    run_traced(argv, extra, 1, id, cfd, cfd, &ecode, plan, plan->timeout_ms);

    uint32_t code_be = (uint32_t)ecode;
    uint8_t payload[4] = { (code_be>>24)&0xff, (code_be>>16)&0xff, (code_be>>8)&0xff, code_be&0xff };
    send_frame(cfd, TAG_EXIT, payload, 4);
    logline("req id=%s done exit=%d", id, ecode);
    close(cfd);
}

static volatile sig_atomic_t g_active_handlers = 0;

static void reap_finished_handlers(void) {
    for (;;) {
        int status;
        pid_t w = waitpid(-1, &status, WNOHANG);
        if (w <= 0) break;
        if (g_active_handlers > 0) g_active_handlers--;
    }
}

static int run_server(const struct exec_plan *plan) {
    int sfd = socket(AF_UNIX, SOCK_STREAM, 0);
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

        int cfd = accept(sfd, NULL, NULL);
        if (cfd < 0) { if (errno == EINTR) continue; perror("accept"); continue; }

        if ((uint32_t)g_active_handlers >= plan->max_concurrent_handlers) {
            logline("rejecting connection: %d handlers already active (cap %u)",
                    g_active_handlers, plan->max_concurrent_handlers);
            static const char msg[] = "relay: too many concurrent requests\n";
            write_full(cfd, msg, sizeof(msg) - 1);
            close(cfd);
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
        g_active_handlers++;
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
    disclosure_init();

    if (argc >= 2 && strcmp(argv[1], "--self-test") == 0) {
        int ecode = -1;
        run_traced(argv + 2, NULL, 0, "self-test", STDOUT_FILENO, STDERR_FILENO,
                   &ecode, &plan, plan.timeout_ms);
        return ecode;
    }
    return run_server(&plan);
}
