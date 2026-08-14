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

#define SOCK_PATH "/tmp/relay.sock"
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

/* ---------------------------------------------------------------------
 * Core primitive shared by both the socket-relay path and the
 * --self-test path: fork a child, have it install the seccomp filter,
 * PTRACE_SEIZE it from the parent, release it, and drive it to exec
 * (with verb dispatch applied at the seccomp trap), streaming
 * stdout/stderr through the given fds and returning the exit code.
 * req_id may be NULL.
 * --------------------------------------------------------------------- */
static int run_traced(char *const argv[], char *const envp_extra[], int envp_extra_n,
                       const char *req_id, int out_fd, int err_fd, int *exit_code_out) {
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

        execve(argv[0], argv, envp);
        /* execve only returns on error */
        fprintf(stderr, "relay: execve(%s) failed: %s\n", argv[0], strerror(errno));
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

    for (;;) {
        int nfds = 0;
        int oi = -1, ei = -1, si;
        if (have_out) { pfds[nfds].fd = outp[0]; pfds[nfds].events = POLLIN; oi = nfds; nfds++; }
        if (have_err) { pfds[nfds].fd = errp[0]; pfds[nfds].events = POLLIN; ei = nfds; nfds++; }
        pfds[nfds].fd = sfd; pfds[nfds].events = POLLIN; si = nfds; nfds++;

        if (!have_out && !have_err && have_exit) break; /* fully drained + exited */

        int pr = poll(pfds, nfds, -1);
        if (pr < 0) { if (errno == EINTR) continue; break; }

        if (oi >= 0 && (pfds[oi].revents & (POLLIN|POLLHUP))) {
            char buf[8192];
            ssize_t r = read(outp[0], buf, sizeof(buf));
            if (r > 0) send_frame(out_fd, TAG_STDOUT, buf, (uint32_t)r);
            else { have_out = 0; close(outp[0]); }
        }
        if (ei >= 0 && (pfds[ei].revents & (POLLIN|POLLHUP))) {
            char buf[8192];
            ssize_t r = read(errp[0], buf, sizeof(buf));
            if (r > 0) send_frame(err_fd, TAG_STDERR, buf, (uint32_t)r);
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
                                write_tracee_mem(w, scratch_addr, replacement, rl);
                                if (is_execveat) regs.regs[1] = scratch_addr;
                                else regs.regs[0] = scratch_addr;
                                set_regs(w, &regs);
                                snprintf(detail, sizeof(detail), "%s", replacement);
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

                        logline("req=%s pid=%d syscall=%s requested=%s verb=%s rule=%s detail=%s",
                                req_id?req_id:"-", w, is_execveat?"execveat":"execve",
                                reqpath, verb_name, rule_name, detail);
                        disclosure_record(req_id, reqpath, rule_name, verb_name, detail);
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

static void handle_conn(int cfd) {
    char line[2048];
    char id[256] = "-";
    int argc = 0;
    char *argv[64];
    for (int i = 0; i < 64; i++) argv[i] = NULL;

    for (;;) {
        int n = read_line(cfd, line, sizeof(line));
        if (n < 0) { close(cfd); return; }
        if (strncmp(line, "ID ", 3) == 0) {
            strncpy(id, line + 3, sizeof(id) - 1);
        } else if (strncmp(line, "ARGC ", 5) == 0) {
            argc = atoi(line + 5);
            if (argc < 1 || argc > 63) { close(cfd); return; }
        } else if (strncmp(line, "ARG ", 4) == 0) {
            if (argc > 0) {
                for (int i = 0; i < 63; i++) {
                    if (argv[i] == NULL) { argv[i] = strdup(line + 4); break; }
                }
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
    run_traced(argv, extra, 1, id, cfd, cfd, &ecode);

    uint32_t code_be = (uint32_t)ecode;
    uint8_t payload[4] = { (code_be>>24)&0xff, (code_be>>16)&0xff, (code_be>>8)&0xff, code_be&0xff };
    send_frame(cfd, TAG_EXIT, payload, 4);
    logline("req id=%s done exit=%d", id, ecode);
    close(cfd);
}

static int run_server(void) {
    unlink(SOCK_PATH);
    int sfd = socket(AF_UNIX, SOCK_STREAM, 0);
    struct sockaddr_un addr = { .sun_family = AF_UNIX };
    strncpy(addr.sun_path, SOCK_PATH, sizeof(addr.sun_path)-1);
    if (bind(sfd, (struct sockaddr*)&addr, sizeof(addr)) != 0) { perror("bind"); return 1; }
    chmod(SOCK_PATH, 0666);
    if (listen(sfd, 16) != 0) { perror("listen"); return 1; }
    logline("relayd listening on %s pid=%d", SOCK_PATH, getpid());

    signal(SIGPIPE, SIG_IGN);

    for (;;) {
        int cfd = accept(sfd, NULL, NULL);
        if (cfd < 0) { if (errno == EINTR) continue; perror("accept"); continue; }
        handle_conn(cfd);
    }
}

/* ------------------------- --self-test path (no socket) ------------------------- */
/* Runs the identical fork+SEIZE+seccomp+exec+wait pipeline directly, driven by our
 * own argv, bypassing docker-exec/stub/socket entirely. Used as the perf baseline. */
static int run_self_test(int argc, char **argv) {
    int ecode = -1;
    run_traced(argv, NULL, 0, "self-test", STDOUT_FILENO, STDERR_FILENO, &ecode);
    return ecode;
}

int main(int argc, char **argv) {
    setvbuf(stdout, NULL, _IOLBF, 0);
    if (argc >= 2 && strcmp(argv[1], "--self-test") == 0) {
        return run_self_test(argc - 2, argv + 2);
    }
    return run_server();
}
