#ifndef EXEC_RELAY_SCRATCH_H
#define EXEC_RELAY_SCRATCH_H

#include <stddef.h>
#include <stdint.h>

#include "protocol.h"   /* EXEC_RELAY_MAX_ARGV */

/* Lays out a complete argv — the strings AND the NULL-terminated array of
 * pointers to them — in a flat buffer that is about to be poked into a stopped
 * tracee's scratch area, and reports the two tracee addresses the execve
 * registers must be repointed at.
 *
 * Both verbs that redirect an exec need exactly this. `fabricate` has always
 * needed it (it redirects to /usr/local/bin/fabricate-emit with a canned argv);
 * `substitute` needs it now that it replaces the WHOLE replacement_argv rather
 * than only element 0 — which is what a rule author configuring
 * `replacement_argv: ["/bin/echo", "intercepted"]` plainly means, and which the
 * old code silently discarded, running /bin/echo with the ORIGINAL requested
 * argv instead.
 *
 * It lives in its own translation unit rather than inline in relayd.c because
 * relayd.c cannot be compiled anywhere but aarch64 (seccomp arch gate, arm64
 * register plumbing), so its arithmetic — the alignment of the pointer array,
 * the bounds check that must not overflow, the NULL terminator execve requires
 * — could never be reached by a unit test. That is the same reasoning that put
 * record.c and protocol.c where they are, and this is arithmetic worth testing:
 * getting the pointer array's alignment or its terminator wrong produces a
 * tracee that execve()s garbage, which is indistinguishable at the far end from
 * the command simply having failed.
 *
 * LAYOUT (identical on any host, because the tracee is always aarch64 and the
 * pointers are written as explicit 64-bit little-endian values):
 *
 *     base_addr + 0    argv[0]\0 argv[1]\0 ... argv[argc-1]\0
 *                      <padding to an 8-byte boundary>
 *     *out_argv_addr   uint64 ptr to argv[0]
 *                      ...
 *                      uint64 ptr to argv[argc-1]
 *                      uint64 0            <- the NULL execve stops at
 *
 * `base_addr` must be 8-byte aligned; the tracee's SP always is (16, in fact)
 * and the scratch base is a fixed offset below it, so this holds in production
 * and is checked here rather than assumed.
 *
 * Returns 0 on success, -1 if the arguments are unusable or the layout does not
 * fit in `bufcap` — never a partial write the caller might poke anyway.
 */
int scratch_pack_argv(void *buf, size_t bufcap,
                      unsigned long long base_addr,
                      const char *const *argv, int argc,
                      size_t *out_len,
                      unsigned long long *out_path_addr,
                      unsigned long long *out_argv_addr);

#endif
