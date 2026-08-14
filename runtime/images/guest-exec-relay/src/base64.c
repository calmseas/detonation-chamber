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
    int val = 0, valb = -8;
    for (size_t i = 0; i < inlen; i++) {
        unsigned char c = (unsigned char)in[i];
        if (c == '=' || c == '\n' || c == '\r') continue;
        signed char d = T[c];
        if (d < 0) { free(decoded); return -1; }
        val = (val << 6) | d;
        valb += 6;
        if (valb >= 0) {
            decoded[outlen++] = (char)((val >> valb) & 0xFF);
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
