#!/bin/sh
set -eu
cd "$(dirname "$0")"
cc -Wall -Wextra -std=c11 -g -o /tmp/test_json ../src/json.c test_json.c
/tmp/test_json
cc -Wall -Wextra -std=c11 -g -o /tmp/test_config ../src/json.c ../src/config.c ../src/base64.c test_config.c
/tmp/test_config
# The disclosure record's composition. Its own binary because record.c is its
# own translation unit, kept out of relayd.c precisely so it can be built and
# tested on a host that is not aarch64 Linux — which is what the two raw-%s
# fields needed and did not have.
cc -Wall -Wextra -std=c11 -g -o /tmp/test_record ../src/json.c ../src/record.c test_record.c
/tmp/test_record
# The request reader, over a real socketpair. Its own translation unit for the
# same reason record.c is: relayd.c cannot be compiled anywhere but aarch64, so
# a parser living inside it is a parser whose refusal paths — a mismatched
# ARGC, a frame claiming more bytes than arrive, an over-long header line — can
# only ever be checked by hand, once. Here CI checks them on every push.
cc -Wall -Wextra -std=c11 -g -o /tmp/test_protocol ../src/protocol.c test_protocol.c
/tmp/test_protocol
echo "all C unit tests passed"
