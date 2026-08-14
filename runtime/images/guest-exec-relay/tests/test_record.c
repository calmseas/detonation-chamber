// runtime/images/guest-exec-relay/tests/test_record.c
//
// The disclosure record is the ONLY evidence a run produces about what the
// agent's commands actually tried to execute, and its consumer
// (chamber-run's record_exec_consequence_log) skips any line it cannot parse
// WITHOUT reporting anything: `let Ok(value) = from_str(line) else
// { continue; }`. A record that does not parse is therefore not a formatting
// blemish — it is an exec that silently never happened, as far as the sealed
// bundle is concerned. These tests all assert the same property from
// different angles: whatever goes into a record, the line still parses and
// the values come back out.
#include <assert.h>
#include <stdio.h>
#include <string.h>
#include "../src/json.h"
#include "../src/record.h"

/* Formats a record and asserts it is a parseable JSON object, returning the
 * parsed value for the caller to inspect. Every test goes through here,
 * because "it parses" is the property that actually matters. */
static json_value_t *record_of(const char *turn_id, const char *argv0,
                               const char *rule, const char *verb, const char *detail) {
    /* DISCLOSURE_RECORD_BUF, not a size of this test's own choosing: the
     * per-field budgets are proportioned against it, so a roomier buffer here
     * would mean the truncation tests below never reached a boundary the
     * relay actually reaches. */
    static char buf[DISCLOSURE_RECORD_BUF];
    size_t off = disclosure_format_record(buf, sizeof(buf), 1786720195L, 613L,
                                          turn_id, argv0, rule, verb, detail);
    assert(off > 0);
    assert(buf[off - 1] == '\n'); /* one record, one line */
    json_value_t *v = json_parse(buf, off - 1);
    if (!v) {
        fprintf(stderr, "record did not parse as JSON:\n%.*s\n", (int)off, buf);
    }
    assert(v != NULL);
    assert(v->type == JSON_OBJECT);
    return v;
}

static void assert_field(json_value_t *v, const char *key, const char *expected) {
    const char *got = json_as_string(json_object_get(v, key));
    assert(got != NULL);
    if (strcmp(got, expected) != 0) {
        fprintf(stderr, "field %s: expected [%s], got [%s]\n", key, expected, got);
    }
    assert(strcmp(got, expected) == 0);
}

static void test_rule_name_containing_a_quote(void) {
    /* The C3 regression, exactly as reported. `matched_rule` is the operator's
     * own rule `name` from config — a rule literally named  pip "install"  is
     * ordinary configuration with no attacker anywhere near it. It used to be
     * interpolated with a raw %s, emitting
     *     ..."matched_rule":"pip "install"","verb_applied":"fabricate"...
     * which is not JSON, so the whole exec silently vanished from the bundle.
     * Live evidence before the fix, from a real cell's disclosure.log:
     *     {"turn_id":"-",...,"matched_rule":"pip "install"",...}
     */
    json_value_t *v = record_of("-", "/bin/echo", "pip \"install\"", "fabricate",
                                "exit=0 stdout_b64_len=8 stderr_b64_len=0");
    assert_field(v, "matched_rule", "pip \"install\"");
    assert_field(v, "requested_argv0", "/bin/echo");
    assert_field(v, "verb_applied", "fabricate");
    json_free(v);
}

static void test_every_field_is_escaped_not_just_some(void) {
    /* The defect was per-field: three fields went through the escaper and two
     * did not. So each field is fed the same hostile value in turn — a bug
     * that reappears in exactly one of them cannot hide behind the other four.
     */
    const char *nasty = "a\"b\\c\nd\te";
    json_value_t *v;

    v = record_of(nasty, "x", "r", "passthrough", "d");
    assert_field(v, "turn_id", nasty);
    json_free(v);

    v = record_of("t", nasty, "r", "passthrough", "d");
    assert_field(v, "requested_argv0", nasty);
    json_free(v);

    v = record_of("t", "x", nasty, "passthrough", "d");
    assert_field(v, "matched_rule", nasty);
    json_free(v);

    v = record_of("t", "x", "r", nasty, "d");
    assert_field(v, "verb_applied", nasty);
    json_free(v);

    v = record_of("t", "x", "r", "passthrough", nasty);
    assert_field(v, "detail", nasty);
    json_free(v);
}

static void test_a_crafted_turn_id_cannot_inject_keys(void) {
    /* turn_id arrives verbatim from `stub --turn-id=`, i.e. from inside the
     * cell. Closing the string early would let it append its own keys — most
     * usefully a second "known_residual_tells", which the consumer treats as
     * the header line and skips, quietly removing the exec from the evidence.
     * It must come back as ONE opaque string value instead. */
    const char *crafted = "x\",\"known_residual_tells\":[\"nothing to see here\"],\"z\":\"";
    json_value_t *v = record_of(crafted, "/bin/sh", "fallback", "passthrough", "-");
    assert_field(v, "turn_id", crafted);
    assert(json_object_get(v, "known_residual_tells") == NULL);
    assert(json_object_get(v, "z") == NULL);
    json_free(v);
}

static void test_control_characters_survive_as_escapes(void) {
    /* An argv0 read out of tracee memory, or a fixture's configured find
     * string, can carry raw control bytes; RFC 8259 forbids them unescaped
     * inside a JSON string. \033 and \001 are octal, so the following letter
     * is not absorbed the way a \x escape would absorb it. */
    const char *detail = "found\nnewline\ttab\rcr\033esc\001soh";
    json_value_t *v = record_of("t", "/bin/x", "r", "rewrite", detail);
    assert_field(v, "detail", detail);
    json_free(v);
}

static void test_an_overlong_value_costs_only_its_own_field(void) {
    /* Truncation must cost the tail of one VALUE, never the line — losing the
     * line loses the whole exec. And it must not cost the OTHER fields
     * either: with one shared running budget, an oversized argv0 emptied out
     * matched_rule, which is the single most important thing a record says.
     * Both values here are far past any budget, and every small field around
     * them must still arrive intact. */
    char huge[9000];
    memset(huge, 'A', sizeof(huge) - 1);
    huge[sizeof(huge) - 1] = 0;

    static char buf[DISCLOSURE_RECORD_BUF];
    size_t off = disclosure_format_record(buf, sizeof(buf), 1L, 2L,
                                          "turn-1", huge, "rule-name", "fabricate", huge);
    assert(off > 0);
    assert(off <= sizeof(buf));
    json_value_t *v = json_parse(buf, off - 1);
    assert(v != NULL); /* still JSON, however much of the values had to go */
    assert_field(v, "turn_id", "turn-1");
    assert_field(v, "matched_rule", "rule-name");
    assert_field(v, "verb_applied", "fabricate");
    /* The oversized fields are present and truncated, not absent. */
    assert(strlen(json_as_string(json_object_get(v, "requested_argv0"))) > 0);
    assert(strlen(json_as_string(json_object_get(v, "detail"))) > 0);
    json_free(v);
}

/* Is `s` well-formed UTF-8 to its NUL? Written out rather than assumed,
 * because "the truncated field is still valid UTF-8" is the entire claim of
 * the two tests below and an eyeball check of a 500-byte string is not one. */
static int is_valid_utf8(const char *s) {
    const unsigned char *p = (const unsigned char *)s;
    while (*p) {
        size_t want;
        if (*p < 0x80) { p++; continue; }
        else if (*p >= 0xc2 && *p <= 0xdf) want = 2;
        else if (*p >= 0xe0 && *p <= 0xef) want = 3;
        else if (*p >= 0xf0 && *p <= 0xf4) want = 4;
        else return 0; /* a bare continuation byte, or an invalid lead */
        for (size_t i = 1; i < want; i++) {
            if ((p[i] & 0xc0) != 0x80) return 0; /* NUL lands here too */
        }
        p += want;
    }
    return 1;
}

/* Fills `out` with `count` copies of the `len`-byte sequence `seq`, NUL
 * terminated. */
static void fill_repeated(char *out, const char *seq, size_t len, size_t count) {
    for (size_t i = 0; i < count; i++) memcpy(out + i * len, seq, len);
    out[count * len] = 0;
}

static void test_truncation_never_splits_a_multibyte_character(void) {
    /* R1's other producer, on the WRITE side. A field's bytes are cut at a
     * byte-count budget; before this fix the cut landed wherever it landed,
     * so a 2-, 3- or 4-byte UTF-8 character straddling the budget left its
     * first byte (or two, or three) in the record and dropped the rest. That
     * is invalid UTF-8 emitted by execrelayd itself, before any reader is
     * involved — and it is what then made the host's strict `read_to_string`
     * collapse an ENTIRE run's evidence to an empty string.
     *
     * Each field is fed a value made ENTIRELY of one repeated multi-byte
     * character and far longer than any budget, so truncation is guaranteed
     * and lands mid-character unless the escaper refuses to split. The output
     * must be valid UTF-8 and its length an exact multiple of the character
     * width — the second check is what a "cut one byte short" bug would fail
     * even if the leftover bytes happened to re-validate.
     *
     * Deliberately not written against BUDGET_* directly: those are record.c's
     * private numbers, and a test that hard-codes them stops testing the
     * property the moment they are retuned (as they were when the transport
     * moved to a PIPE_BUF-bounded stream). */
    static const struct { const char *seq; size_t len; const char *what; } CHARS[] = {
        { "\xc3\xa9",         2, "U+00E9 e-acute" },
        { "\xe2\x82\xac",     3, "U+20AC euro sign" },
        { "\xf0\x9f\x92\xa5", 4, "U+1F4A5 collision symbol" },
    };
    static const char *const FIELDS[] = { "turn_id", "requested_argv0", "matched_rule",
                                          "verb_applied", "detail" };

    for (size_t c = 0; c < sizeof(CHARS) / sizeof(CHARS[0]); c++) {
        char huge[4096];
        fill_repeated(huge, CHARS[c].seq, CHARS[c].len,
                      (sizeof(huge) - 1) / CHARS[c].len);

        for (size_t f = 0; f < sizeof(FIELDS) / sizeof(FIELDS[0]); f++) {
            const char *v[5] = { "t", "/bin/x", "r", "passthrough", "d" };
            v[f] = huge;
            json_value_t *rec = record_of(v[0], v[1], v[2], v[3], v[4]);
            const char *got = json_as_string(json_object_get(rec, FIELDS[f]));
            assert(got != NULL);
            size_t n = strlen(got);
            /* It truncated at all (otherwise this proves nothing) ... */
            assert(n > 0 && n < strlen(huge));
            /* ... and it truncated on a character boundary. */
            if (!is_valid_utf8(got) || n % CHARS[c].len != 0) {
                fprintf(stderr,
                        "field %s truncated mid-character on %s: %zu bytes, "
                        "valid_utf8=%d, tail bytes:",
                        FIELDS[f], CHARS[c].what, n, is_valid_utf8(got));
                for (size_t i = n > 6 ? n - 6 : 0; i < n; i++) {
                    fprintf(stderr, " %02x", (unsigned char)got[i]);
                }
                fprintf(stderr, "\n");
            }
            assert(is_valid_utf8(got));
            assert(n % CHARS[c].len == 0);
            json_free(rec);
        }
    }
}

static void test_multibyte_characters_that_fit_are_preserved_whole(void) {
    /* The other half of the claim above: refusing to split must not have
     * become refusing to emit. A short value with characters of every width
     * comes back byte-for-byte. */
    /* Split literals, not decoration: a hex escape absorbs every following hex
     * digit, so "\xe2\x82\xac5" is one out-of-range escape rather than a euro
     * sign and a five. */
    const char *mixed = "caf\xc3\xa9 " "\xe2\x82\xac" "5 " "\xf0\x9f\x92\xa5" " /bin/echo";
    json_value_t *v = record_of("t", mixed, "r", "passthrough", mixed);
    assert_field(v, "requested_argv0", mixed);
    assert_field(v, "detail", mixed);
    json_free(v);
}

static void test_an_invalid_byte_is_preserved_rather_than_repaired(void) {
    /* Design §6: "a byte sequence that is not valid UTF-8 is preserved rather
     * than repaired or dropped — escaping is not this layer's job to validate
     * UTF-8, only to keep the JSON structure sound". A raw 0xFF, which is what
     * an argv0 read out of tracee memory can genuinely contain, must arrive on
     * the far side as itself, with the record still parseable around it. The
     * host is what survives it (String::from_utf8_lossy), not this layer. */
    const char *raw = "/bin/no\xffsuch";
    json_value_t *v = record_of("t", raw, "r", "passthrough", "d");
    assert_field(v, "requested_argv0", raw);
    json_free(v);
}

static void test_a_null_turn_id_becomes_the_placeholder(void) {
    /* run_traced passes req_id straight through and it may be NULL. */
    json_value_t *v = record_of(NULL, "/bin/x", "fallback", "passthrough", "-");
    assert_field(v, "turn_id", "-");
    json_free(v);
}

int main(void) {
    test_rule_name_containing_a_quote();
    test_every_field_is_escaped_not_just_some();
    test_a_crafted_turn_id_cannot_inject_keys();
    test_control_characters_survive_as_escapes();
    test_an_overlong_value_costs_only_its_own_field();
    test_truncation_never_splits_a_multibyte_character();
    test_multibyte_characters_that_fit_are_preserved_whole();
    test_an_invalid_byte_is_preserved_rather_than_repaired();
    test_a_null_turn_id_becomes_the_placeholder();
    printf("test_record: all tests passed\n");
    return 0;
}
