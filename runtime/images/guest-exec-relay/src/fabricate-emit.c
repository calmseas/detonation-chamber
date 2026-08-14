#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include "base64.h"

int main(int argc, char **argv) {
    if (argc < 4) {
        fprintf(stderr, "usage: fabricate-emit <exit_code> <base64_stdout> <base64_stderr>\n");
        return 2;
    }
    int exit_code = atoi(argv[1]);

    char *out = NULL; size_t out_len = 0;
    if (base64_decode(argv[2], &out, &out_len) != 0) {
        fprintf(stderr, "fabricate-emit: malformed stdout payload\n");
        return 2;
    }
    char *err = NULL; size_t err_len = 0;
    if (base64_decode(argv[3], &err, &err_len) != 0) {
        fprintf(stderr, "fabricate-emit: malformed stderr payload\n");
        free(out);
        return 2;
    }

    if (out_len) write(STDOUT_FILENO, out, out_len);
    if (err_len) write(STDERR_FILENO, err, err_len);
    free(out);
    free(err);
    return exit_code;
}
