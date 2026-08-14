// runtime/images/guest-exec-relay/src/scratch.c
//
// See scratch.h. Portable C — the tracee's word size is pinned at 64 bits by
// the aarch64-only decision, and the pointers are assembled byte-wise rather
// than by casting this host's pointers, so the layout a host-run unit test sees
// is the layout the guest gets.
#include "scratch.h"

#include <string.h>

int scratch_pack_argv(void *buf, size_t bufcap,
                      unsigned long long base_addr,
                      const char *const *argv, int argc,
                      size_t *out_len,
                      unsigned long long *out_path_addr,
                      unsigned long long *out_argv_addr) {
    if (!buf || !argv || !out_len || !out_path_addr || !out_argv_addr) return -1;
    if (argc <= 0 || argc > EXEC_RELAY_MAX_ARGV) return -1;
    if (base_addr % 8u != 0) return -1;

    unsigned char *p = buf;
    uint64_t addrs[EXEC_RELAY_MAX_ARGV];
    size_t off = 0;

    for (int i = 0; i < argc; i++) {
        if (!argv[i]) return -1;
        size_t sl = strlen(argv[i]) + 1;
        /* Written this way round so the sum can never wrap: `off + sl` on a
         * near-SIZE_MAX offset is exactly how a bounds check becomes a buffer
         * overflow. */
        if (sl > bufcap || off > bufcap - sl) return -1;
        memcpy(p + off, argv[i], sl);
        addrs[i] = (uint64_t)base_addr + off;
        off += sl;
    }

    size_t aligned = (off + 7u) & ~(size_t)7u;
    if (aligned < off) return -1;                       /* rounding wrapped */
    size_t ptrs_bytes = ((size_t)argc + 1) * 8u;
    if (aligned > bufcap || ptrs_bytes > bufcap - aligned) return -1;

    memset(p + off, 0, aligned - off);
    for (int i = 0; i < argc; i++) {
        uint64_t a = addrs[i];
        for (int b = 0; b < 8; b++) p[aligned + (size_t)i * 8u + (size_t)b] = (unsigned char)(a >> (8 * b));
    }
    /* The NULL execve stops the array at. Its absence is not a subtle bug: the
     * tracee execve()s with whatever stack bytes follow, read as pointers. */
    memset(p + aligned + (size_t)argc * 8u, 0, 8);

    *out_len = aligned + ptrs_bytes;
    *out_path_addr = addrs[0];
    *out_argv_addr = base_addr + aligned;
    return 0;
}
