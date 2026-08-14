#!/bin/sh
set -eu
cd "$(dirname "$0")"

# ASan + UBSan on every unit binary, not on a chosen few.
#
# The class of defect these catch is the one this image keeps producing: C that
# reads or writes just past what it was handed. Round 2's R7 was exactly that —
# a truncated `ID <len>` frame left `req->id` unterminated, so the refusal path
# read the tracer's own stack past the bytes that arrived and composed it into a
# record that is SEALED into the evidence bundle. A wrong turn id in a signed
# artefact is not a crash anybody notices; it is a quiet lie, and the only thing
# that finds it mechanically is a sanitizer plus a test that poisons the frame
# first (test_protocol.c's
# test_a_truncated_id_frame_leaves_no_uninitialised_stack_in_the_id).
#
# `detect_leaks` is deliberately NOT forced on: LeakSanitizer is unavailable on
# the macOS hosts this script is also run from, and a flag that fails there but
# not on CI would push people to stop running it locally. What is enabled is
# identical on both.
#
# UBSAN_OPTIONS makes undefined behaviour FAIL rather than print and continue —
# without it a signed-overflow or misaligned-load report scrolls past a green
# "all C unit tests passed", which is worse than not running it.
SAN="-fsanitize=address,undefined -fno-omit-frame-pointer"
UBSAN_OPTIONS="print_stacktrace=1:halt_on_error=1"
export UBSAN_OPTIONS

# shellcheck disable=SC2086  # SAN is a deliberate multi-word flag list
cc -Wall -Wextra -std=c11 -g $SAN -o /tmp/test_json ../src/json.c test_json.c
/tmp/test_json
# shellcheck disable=SC2086
cc -Wall -Wextra -std=c11 -g $SAN -o /tmp/test_config ../src/json.c ../src/config.c ../src/base64.c test_config.c
/tmp/test_config
# The disclosure record's composition. Its own binary because record.c is its
# own translation unit, kept out of relayd.c precisely so it can be built and
# tested on a host that is not aarch64 Linux — which is what the two raw-%s
# fields needed and did not have.
# shellcheck disable=SC2086
cc -Wall -Wextra -std=c11 -g $SAN -o /tmp/test_record ../src/json.c ../src/record.c test_record.c
/tmp/test_record
# The request reader, over a real socketpair. Its own translation unit for the
# same reason record.c is: relayd.c cannot be compiled anywhere but aarch64, so
# a parser living inside it is a parser whose refusal paths — a mismatched
# ARGC, a frame claiming more bytes than arrive, an over-long header line, a
# truncated ID frame — can only ever be checked by hand, once. Here CI checks
# them on every push.
# shellcheck disable=SC2086
cc -Wall -Wextra -std=c11 -g $SAN -o /tmp/test_protocol ../src/protocol.c test_protocol.c
/tmp/test_protocol
# The rewrite verb's output transform. Its own translation unit for the third
# time for the same reason: while it lived in relayd.c, neither of the two ways
# it silently failed — a find string split across two read()s, and an expanding
# replacement truncated at the output buffer — could be reached by any test.
# shellcheck disable=SC2086
cc -Wall -Wextra -std=c11 -g $SAN -o /tmp/test_rewrite ../src/rewrite.c test_rewrite.c
/tmp/test_rewrite
# The scratch-buffer argv layout shared by substitute and fabricate: pointer
# array alignment, its NULL terminator, and the bound that has to cover both.
# shellcheck disable=SC2086
cc -Wall -Wextra -std=c11 -g $SAN -o /tmp/test_scratch ../src/scratch.c test_scratch.c
/tmp/test_scratch
echo "all C unit tests passed"
