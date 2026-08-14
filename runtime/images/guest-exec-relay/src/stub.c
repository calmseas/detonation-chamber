// runtime/images/guest-exec-relay/src/stub.c
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <stdint.h>
#include <errno.h>
#include <sys/socket.h>
#include <sys/un.h>

#define SOCK_PATH "/tmp/relay.sock"

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
        if (w < 0) return -1;
        p += w; left -= w;
    }
    return (ssize_t)n;
}

int main(int argc, char **argv) {
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

    int sfd = socket(AF_UNIX, SOCK_STREAM, 0);
    struct sockaddr_un addr = { .sun_family = AF_UNIX };
    strncpy(addr.sun_path, SOCK_PATH, sizeof(addr.sun_path)-1);
    if (connect(sfd, (struct sockaddr*)&addr, sizeof(addr)) != 0) {
        perror("stub: connect");
        return 111;
    }

    char line[2048];
    int n = snprintf(line, sizeof(line), "ID %s\nARGC %d\n", id, real_argc);
    write_full(sfd, line, n);
    for (int i = 0; i < real_argc; i++) {
        n = snprintf(line, sizeof(line), "ARG %s\n", real_argv[i]);
        write_full(sfd, line, n);
    }
    write_full(sfd, "END\n", 4);

    int exit_code = 1;
    for (;;) {
        uint8_t hdr[5];
        if (read_full(sfd, hdr, 5) != 5) break;
        uint32_t len = ((uint32_t)hdr[1]<<24)|((uint32_t)hdr[2]<<16)|((uint32_t)hdr[3]<<8)|hdr[4];
        uint8_t tag = hdr[0];
        if (tag == 3) { /* exit */
            uint8_t p[4];
            if (len == 4 && read_full(sfd, p, 4) == 4) {
                int32_t code = (int32_t)(((uint32_t)p[0]<<24)|((uint32_t)p[1]<<16)|((uint32_t)p[2]<<8)|p[3]);
                exit_code = code;
            }
            break;
        } else {
            char *buf = malloc(len ? len : 1);
            if (len && read_full(sfd, buf, len) != (ssize_t)len) { free(buf); break; }
            int outfd = (tag == 1) ? 1 : 2;
            write_full(outfd, buf, len);
            free(buf);
        }
    }
    close(sfd);
    return exit_code;
}
