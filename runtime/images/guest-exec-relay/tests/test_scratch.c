// runtime/images/guest-exec-relay/tests/test_scratch.c
//
// The layout every exec redirect depends on: the strings and the
// NULL-terminated pointer array that a repointed execve() will read out of the
// tracee's scratch area.
//
// It matters twice over. `substitute` now replaces the WHOLE replacement_argv
// (it used to repoint only the path register, silently discarding every element
// past index 0), and `fabricate` has always redirected to fabricate-emit with a
// canned argv. Both go through scratch_pack_argv, and a mistake in it — a
// misaligned pointer array, a missing terminator, an off-by-one bound — does
// not look like a bug at the far end: it looks like the command failing.
#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include "../src/scratch.h"

/* Reads a 64-bit little-endian tracee pointer out of the packed buffer, the way
 * the guest kernel will. */
static uint64_t ptr_at(const unsigned char *buf, size_t off) {
    uint64_t v = 0;
    for (int i = 7; i >= 0; i--) v = (v << 8) | buf[off + (size_t)i];
    return v;
}

/* The scratch base used throughout: 16-byte aligned, as a real tracee's
 * SP - SCRATCH_SIZE always is. */
#define BASE 0x7ffff0000000ULL

static void test_a_two_element_argv_round_trips(void) {
    unsigned char buf[4096];
    memset(buf, 0xAA, sizeof(buf));
    const char *argv[] = { "/bin/echo", "intercepted" };
    size_t len = 0;
    unsigned long long path = 0, arr = 0;

    assert(scratch_pack_argv(buf, sizeof(buf), BASE, argv, 2, &len, &path, &arr) == 0);

    /* The strings, laid down in order and NUL-terminated. */
    assert(strcmp((char *)buf, "/bin/echo") == 0);
    assert(strcmp((char *)buf + 10, "intercepted") == 0);

    /* The path register points at argv[0]'s bytes. */
    assert(path == BASE);

    /* The pointer array is 8-byte aligned and inside the buffer. */
    assert(arr % 8 == 0);
    assert(arr >= BASE);
    size_t arr_off = (size_t)(arr - BASE);
    assert(arr_off + 3 * 8 <= len);

    /* Each entry points at its own string, and the array is NULL-terminated —
     * without which execve reads whatever stack bytes follow as pointers. */
    assert(ptr_at(buf, arr_off) == BASE);
    assert(ptr_at(buf, arr_off + 8) == BASE + 10);
    assert(ptr_at(buf, arr_off + 16) == 0);
    assert(len == arr_off + 24);
}

static void test_a_single_element_argv(void) {
    unsigned char buf[256];
    const char *argv[] = { "/usr/bin/curl" };
    size_t len = 0;
    unsigned long long path = 0, arr = 0;
    assert(scratch_pack_argv(buf, sizeof(buf), BASE, argv, 1, &len, &path, &arr) == 0);
    size_t arr_off = (size_t)(arr - BASE);
    assert(ptr_at(buf, arr_off) == BASE);
    assert(ptr_at(buf, arr_off + 8) == 0);
}

static void test_the_fabricate_shape(void) {
    /* Exactly what the fabricate branch packs: helper path, exit code, two
     * base64 blobs. This is the layout that shipped hand-rolled and unchecked
     * inside relayd.c. */
    unsigned char buf[16384];
    const char *argv[] = { "/usr/local/bin/fabricate-emit", "0", "aGVsbG8=", "" };
    size_t len = 0;
    unsigned long long path = 0, arr = 0;
    assert(scratch_pack_argv(buf, sizeof(buf), BASE, argv, 4, &len, &path, &arr) == 0);
    size_t arr_off = (size_t)(arr - BASE);
    for (int i = 0; i < 4; i++) {
        uint64_t p = ptr_at(buf, arr_off + (size_t)i * 8);
        assert(strcmp((char *)buf + (p - BASE), argv[i]) == 0);
    }
    assert(ptr_at(buf, arr_off + 32) == 0);
    /* An EMPTY argument is a real one: it must be a pointer to a NUL, not the
     * array's terminator. */
    assert(ptr_at(buf, arr_off + 24) != 0);
}

static void test_the_pointer_array_is_aligned_after_odd_strings(void) {
    /* Total string length 4 ("a\0" + "b\0"), so the array must be padded to
     * offset 8. An unaligned 64-bit array is undefined behaviour for the tracee
     * to read and, on some kernels, simply wrong. */
    unsigned char buf[128];
    const char *argv[] = { "a", "b" };
    size_t len = 0;
    unsigned long long path = 0, arr = 0;
    assert(scratch_pack_argv(buf, sizeof(buf), BASE, argv, 2, &len, &path, &arr) == 0);
    assert(arr == BASE + 8);
    assert((arr - BASE) % 8 == 0);
    (void)path; (void)len;
}

static void test_it_refuses_what_will_not_fit(void) {
    /* The bound has to cover the pointer array too, not just the strings: the
     * strings fitting exactly is precisely when the array overruns. */
    unsigned char buf[32];
    const char *argv[] = { "0123456789012345678901234567890" }; /* 31 + NUL = 32 */
    size_t len = 0;
    unsigned long long path = 0, arr = 0;
    assert(scratch_pack_argv(buf, sizeof(buf), BASE, argv, 1, &len, &path, &arr) != 0);

    /* One byte shorter still does not fit — 31 bytes of string, padded to 32,
     * leaves nothing for two pointers. */
    const char *argv2[] = { "012345678901234567890123456789" };
    assert(scratch_pack_argv(buf, sizeof(buf), BASE, argv2, 1, &len, &path, &arr) != 0);

    /* With room for both, it succeeds. */
    unsigned char big[64];
    assert(scratch_pack_argv(big, sizeof(big), BASE, argv2, 1, &len, &path, &arr) == 0);
}

static void test_it_refuses_a_bad_argc(void) {
    unsigned char buf[256];
    const char *argv[] = { "x" };
    size_t len = 0;
    unsigned long long path = 0, arr = 0;
    assert(scratch_pack_argv(buf, sizeof(buf), BASE, argv, 0, &len, &path, &arr) != 0);
    assert(scratch_pack_argv(buf, sizeof(buf), BASE, argv, -1, &len, &path, &arr) != 0);
    assert(scratch_pack_argv(buf, sizeof(buf), BASE, argv,
                             EXEC_RELAY_MAX_ARGV + 1, &len, &path, &arr) != 0);
}

static void test_it_refuses_a_null_element(void) {
    unsigned char buf[256];
    const char *argv[] = { "ok", NULL, "after" };
    size_t len = 0;
    unsigned long long path = 0, arr = 0;
    assert(scratch_pack_argv(buf, sizeof(buf), BASE, argv, 3, &len, &path, &arr) != 0);
}

static void test_it_refuses_an_unaligned_base(void) {
    /* A tracee's SP is always 16-byte aligned, so this cannot happen in
     * production — which is exactly why it is checked rather than assumed. */
    unsigned char buf[256];
    const char *argv[] = { "x" };
    size_t len = 0;
    unsigned long long path = 0, arr = 0;
    assert(scratch_pack_argv(buf, sizeof(buf), BASE + 1, argv, 1, &len, &path, &arr) != 0);
}

static void test_a_full_length_argv(void) {
    /* EXEC_RELAY_MAX_ARGV elements, the most a rule can carry. */
    unsigned char buf[16384];
    const char *argv[EXEC_RELAY_MAX_ARGV];
    for (int i = 0; i < EXEC_RELAY_MAX_ARGV; i++) argv[i] = "element";
    size_t len = 0;
    unsigned long long path = 0, arr = 0;
    assert(scratch_pack_argv(buf, sizeof(buf), BASE, argv, EXEC_RELAY_MAX_ARGV,
                             &len, &path, &arr) == 0);
    size_t arr_off = (size_t)(arr - BASE);
    assert(ptr_at(buf, arr_off + (size_t)EXEC_RELAY_MAX_ARGV * 8) == 0);
    assert(len == arr_off + ((size_t)EXEC_RELAY_MAX_ARGV + 1) * 8);
}

int main(void) {
    test_a_two_element_argv_round_trips();
    test_a_single_element_argv();
    test_the_fabricate_shape();
    test_the_pointer_array_is_aligned_after_odd_strings();
    test_it_refuses_what_will_not_fit();
    test_it_refuses_a_bad_argc();
    test_it_refuses_a_null_element();
    test_it_refuses_an_unaligned_base();
    test_a_full_length_argv();
    printf("test_scratch: all tests passed\n");
    return 0;
}
