// runtime/images/guest-exec-relay/src/config.c
#include "config.h"
#include "json.h"
#include <string.h>
#include <stdlib.h>
#include <stdio.h>

static int copy_str(char *dst, size_t dstsz, const char *src) {
    if (!src) return -1;
    size_t n = strlen(src);
    if (n >= dstsz) return -1;
    memcpy(dst, src, n + 1);
    return 0;
}

static int load_match_argv(json_value_t *matcher, struct exec_rule *rule) {
    const char *type = json_as_string(json_object_get(matcher, "type"));
    if (!type) return -1;
    if (strcmp(type, "argv0") == 0) {
        rule->match_kind = MATCH_ARGV0;
        return copy_str(rule->match_argv0, sizeof(rule->match_argv0),
                         json_as_string(json_object_get(matcher, "name")));
    }
    json_value_t *argv_arr = json_object_get(matcher, "argv");
    size_t n = json_array_len(argv_arr);
    if (n == 0 || n > EXEC_RELAY_MAX_ARGV) return -1;
    for (size_t i = 0; i < n; i++) {
        if (copy_str(rule->match_argv[i], sizeof(rule->match_argv[i]),
                      json_as_string(json_array_get(argv_arr, i))) != 0) {
            return -1;
        }
    }
    rule->match_argv_len = (int)n;
    if (strcmp(type, "prefix") == 0) { rule->match_kind = MATCH_PREFIX; return 0; }
    if (strcmp(type, "exact") == 0) { rule->match_kind = MATCH_EXACT; return 0; }
    return -1;
}

static int load_verb(json_value_t *verb, struct exec_rule *rule) {
    const char *type = json_as_string(json_object_get(verb, "type"));
    if (!type) return -1;
    if (strcmp(type, "substitute") == 0) {
        rule->verb = VERB_SUBSTITUTE;
        json_value_t *argv_arr = json_object_get(verb, "replacement_argv");
        size_t n = json_array_len(argv_arr);
        if (n == 0 || n > EXEC_RELAY_MAX_ARGV) return -1;
        for (size_t i = 0; i < n; i++) {
            if (copy_str(rule->replacement_argv[i], sizeof(rule->replacement_argv[i]),
                          json_as_string(json_array_get(argv_arr, i))) != 0) {
                return -1;
            }
        }
        rule->replacement_argv_len = (int)n;
        return 0;
    }
    if (strcmp(type, "rewrite") == 0) {
        rule->verb = VERB_REWRITE;
        json_value_t *sf = json_object_get(verb, "stdout_find");
        json_value_t *sr = json_object_get(verb, "stdout_replace");
        if (sf && sr) {
            rule->has_stdout_rewrite = 1;
            if (copy_str(rule->stdout_find, sizeof(rule->stdout_find), json_as_string(sf)) != 0) return -1;
            if (copy_str(rule->stdout_replace, sizeof(rule->stdout_replace), json_as_string(sr)) != 0) return -1;
        }
        json_value_t *ef = json_object_get(verb, "stderr_find");
        json_value_t *er = json_object_get(verb, "stderr_replace");
        if (ef && er) {
            rule->has_stderr_rewrite = 1;
            if (copy_str(rule->stderr_find, sizeof(rule->stderr_find), json_as_string(ef)) != 0) return -1;
            if (copy_str(rule->stderr_replace, sizeof(rule->stderr_replace), json_as_string(er)) != 0) return -1;
        }
        return 0;
    }
    if (strcmp(type, "fabricate") == 0) {
        rule->verb = VERB_FABRICATE;
        int64_t code;
        if (json_as_int64(json_object_get(verb, "exit_code"), &code) != 0) return -1;
        rule->fabricate_exit_code = (int32_t)code;
        const char *out = json_as_string(json_object_get(verb, "stdout"));
        const char *err = json_as_string(json_object_get(verb, "stderr"));
        if (!out) out = "";
        if (!err) err = "";
        size_t outlen = strlen(out), errlen = strlen(err);
        if (outlen >= EXEC_RELAY_MAX_FABRICATE_BYTES || errlen >= EXEC_RELAY_MAX_FABRICATE_BYTES) return -1;
        memcpy(rule->fabricate_stdout, out, outlen + 1);
        rule->fabricate_stdout_len = (uint32_t)outlen;
        memcpy(rule->fabricate_stderr, err, errlen + 1);
        rule->fabricate_stderr_len = (uint32_t)errlen;
        return 0;
    }
    return -1;
}

int config_load_from_json(const char *json_text, size_t len, struct exec_plan *out) {
    memset(out, 0, sizeof(*out));
    out->timeout_ms = 60000;
    out->max_concurrent_handlers = 32;

    json_value_t *root = json_parse(json_text, len);
    if (!root) return -1;

    json_value_t *timeout = json_object_get(root, "timeout_ms");
    if (timeout) {
        int64_t v;
        if (json_as_int64(timeout, &v) != 0 || v <= 0) { json_free(root); return -1; }
        out->timeout_ms = (uint64_t)v;
    }
    json_value_t *maxconc = json_object_get(root, "max_concurrent_handlers");
    if (maxconc) {
        int64_t v;
        if (json_as_int64(maxconc, &v) != 0 || v <= 0) { json_free(root); return -1; }
        out->max_concurrent_handlers = (uint32_t)v;
    }

    json_value_t *rules = json_object_get(root, "rules");
    size_t n = json_array_len(rules);
    if (n > EXEC_RELAY_MAX_RULES) { json_free(root); return -1; }
    for (size_t i = 0; i < n; i++) {
        json_value_t *r = json_array_get(rules, i);
        struct exec_rule *rule = &out->rules[i];
        memset(rule, 0, sizeof(*rule));
        const char *name = json_as_string(json_object_get(r, "name"));
        if (!name || name[0] == '\0' || copy_str(rule->name, sizeof(rule->name), name) != 0) {
            json_free(root); return -1;
        }
        if (load_match_argv(json_object_get(r, "match_argv"), rule) != 0) { json_free(root); return -1; }
        if (load_verb(json_object_get(r, "verb"), rule) != 0) { json_free(root); return -1; }
    }
    out->n_rules = (int)n;

    json_free(root);
    return 0;
}

int config_load_from_env(struct exec_plan *out) {
    const char *b64 = getenv("CHAMBER_EXEC_CONSEQUENCE_SPEC_B64");
    if (!b64) return -1;

    /* Minimal base64 decode — standard alphabet, '=' padding. The Rust side
     * (Task 1) is the source of truth for what gets encoded; this decoder
     * only needs to invert it, not accept arbitrary base64 dialects. */
    static const signed char T[256] = {
        ['A']=0,['B']=1,['C']=2,['D']=3,['E']=4,['F']=5,['G']=6,['H']=7,['I']=8,['J']=9,
        ['K']=10,['L']=11,['M']=12,['N']=13,['O']=14,['P']=15,['Q']=16,['R']=17,['S']=18,['T']=19,
        ['U']=20,['V']=21,['W']=22,['X']=23,['Y']=24,['Z']=25,
        ['a']=26,['b']=27,['c']=28,['d']=29,['e']=30,['f']=31,['g']=32,['h']=33,['i']=34,['j']=35,
        ['k']=36,['l']=37,['m']=38,['n']=39,['o']=40,['p']=41,['q']=42,['r']=43,['s']=44,['t']=45,
        ['u']=46,['v']=47,['w']=48,['x']=49,['y']=50,['z']=51,
        ['0']=52,['1']=53,['2']=54,['3']=55,['4']=56,['5']=57,['6']=58,['7']=59,['8']=60,['9']=61,
        ['+']=62,['/']=63,
    };
    size_t inlen = strlen(b64);
    char *decoded = malloc(inlen); /* decoded is always <= inlen bytes */
    size_t outlen = 0;
    int val = 0, valb = -8;
    for (size_t i = 0; i < inlen; i++) {
        unsigned char c = (unsigned char)b64[i];
        if (c == '=' || c == '\n' || c == '\r') continue;
        signed char d = T[c];
        if (d < 0 && c != 'A') { free(decoded); return -1; } /* 'A' maps validly to 0 */
        val = (val << 6) | d;
        valb += 6;
        if (valb >= 0) {
            decoded[outlen++] = (char)((val >> valb) & 0xFF);
            valb -= 8;
        }
    }
    int rc = config_load_from_json(decoded, outlen, out);
    free(decoded);
    return rc;
}

static int argv_matches(char *const argv[], int argc, char (*want)[256], int want_len) {
    if (argc < want_len) return 0;
    for (int i = 0; i < want_len; i++) {
        if (strcmp(argv[i], want[i]) != 0) return 0;
    }
    return 1;
}

const struct exec_rule *config_match(const struct exec_plan *plan, char *const argv[], int argc) {
    for (int i = 0; i < plan->n_rules; i++) {
        const struct exec_rule *rule = &plan->rules[i];
        int matched = 0;
        switch (rule->match_kind) {
            case MATCH_ARGV0:
                matched = (argc >= 1) && strcmp(argv[0], rule->match_argv0) == 0;
                break;
            case MATCH_PREFIX:
                matched = argv_matches(argv, argc, (char (*)[256])rule->match_argv, rule->match_argv_len);
                break;
            case MATCH_EXACT:
                matched = (argc == rule->match_argv_len) &&
                          argv_matches(argv, argc, (char (*)[256])rule->match_argv, rule->match_argv_len);
                break;
        }
        if (matched) return rule;
    }
    return NULL;
}
