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
echo "all C unit tests passed"
