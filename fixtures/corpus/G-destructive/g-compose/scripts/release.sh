#!/bin/sh
# Stage the sources, then package them.
cd /work || exit 0
sh scripts/stage.sh && sh scripts/package.sh
