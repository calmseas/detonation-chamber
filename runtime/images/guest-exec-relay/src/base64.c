#include "base64.h"
#include <stdlib.h>
#include <string.h>

static void build_decode_table(signed char T[256]) {
    for (int i = 0; i < 256; i++) T[i] = -1;
    static const char alphabet[] =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    for (int i = 0; i < 64; i++) T[(unsigned char)alphabet[i]] = (signed char)i;
}

int base64_decode(const char *in, char **out, size_t *out_len) {
    signed char T[256];
    build_decode_table(T);
    size_t inlen = strlen(in);
    char *decoded = malloc(inlen ? inlen : 1);
    if (!decoded) return -1;
    size_t outlen = 0;
    /* UNSIGNED and masked, both deliberately.
     *
     * This accumulator was a plain `int` that was never masked, so it took a
     * new sextet every iteration and shed bits only through the `>>` below —
     * i.e. it grew without bound and overflowed after five or six input
     * characters. Signed overflow is undefined behaviour, which means it is not
     * "wraps around harmlessly": the compiler is entitled to assume it cannot
     * happen and optimise on that basis, and the decoder in question is the one
     * that parses the interception plan every run depends on. It went unnoticed
     * because the only base64 the unit tests decoded was a nine-character
     * string that fails on its fourth byte; UBSan flagged it on the first input
     * long enough to overflow, the moment the C test runner started building
     * with sanitizers.
     *
     * Unsigned makes the shift defined; the 24-bit mask keeps the value in the
     * range the algorithm actually uses (four sextets, and a maximum shift of
     * 4 below), so nothing accumulates that is never read. */
    unsigned int val = 0;
    int valb = -8;
    for (size_t i = 0; i < inlen; i++) {
        unsigned char c = (unsigned char)in[i];
        if (c == '=' || c == '\n' || c == '\r') continue;
        signed char d = T[c];
        if (d < 0) { free(decoded); return -1; }
        val = ((val << 6) | (unsigned int)d) & 0xFFFFFFu;
        valb += 6;
        if (valb >= 0) {
            decoded[outlen++] = (char)((val >> valb) & 0xFFu);
            valb -= 8;
        }
    }
    *out = decoded;
    *out_len = outlen;
    return 0;
}

char *base64_encode(const void *in, size_t in_len) {
    static const char alphabet[] =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    const unsigned char *bytes = (const unsigned char *)in;
    size_t out_len = 4 * ((in_len + 2) / 3);
    char *out = malloc(out_len + 1);
    if (!out) return NULL;
    size_t oi = 0, i = 0;
    for (; i + 3 <= in_len; i += 3) {
        unsigned int n = ((unsigned int)bytes[i] << 16) | ((unsigned int)bytes[i+1] << 8) | bytes[i+2];
        out[oi++] = alphabet[(n >> 18) & 0x3F];
        out[oi++] = alphabet[(n >> 12) & 0x3F];
        out[oi++] = alphabet[(n >> 6) & 0x3F];
        out[oi++] = alphabet[n & 0x3F];
    }
    size_t rem = in_len - i;
    if (rem == 1) {
        unsigned int n = (unsigned int)bytes[i] << 16;
        out[oi++] = alphabet[(n >> 18) & 0x3F];
        out[oi++] = alphabet[(n >> 12) & 0x3F];
        out[oi++] = '=';
        out[oi++] = '=';
    } else if (rem == 2) {
        unsigned int n = ((unsigned int)bytes[i] << 16) | ((unsigned int)bytes[i+1] << 8);
        out[oi++] = alphabet[(n >> 18) & 0x3F];
        out[oi++] = alphabet[(n >> 12) & 0x3F];
        out[oi++] = alphabet[(n >> 6) & 0x3F];
        out[oi++] = '=';
    }
    out[oi] = '\0';
    return out;
}
