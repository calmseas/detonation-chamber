#!/bin/sh
set -eu
cd "$(dirname "$0")"
cc -Wall -Wextra -std=c11 -g -o /tmp/test_json ../src/json.c test_json.c
/tmp/test_json
cc -Wall -Wextra -std=c11 -g -o /tmp/test_config ../src/json.c ../src/config.c ../src/base64.c test_config.c
/tmp/test_config
echo "all C unit tests passed"
