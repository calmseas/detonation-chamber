# The exec-consequence-capable agent cell: same alpine:3.20 base and contract
# as the plain guest, plus execrelayd as PID 1 and stub as the sole entry
# point docker exec targets. Two stages so the final image carries only the
# compiled binaries, not gcc/musl-dev/linux-headers.
#
# MUST be built for linux/arm64 — `docker build --platform linux/arm64`, which
# is what every build site in this repo passes explicitly rather than leaving
# to the host's default. execrelayd's interception mechanism (a seccomp filter
# gated on AUDIT_ARCH_AARCH64 plus arm64 register plumbing) is aarch64-only by
# decision; see the design artefact
# agenticpractices:artefact:2rau75fl5jsg3c4c8pla section 7. relayd.c carries a
# matching `#error` so a build for any other architecture fails HERE, with a
# legible message, rather than producing an image whose relay kills every
# worker it supervises.
FROM alpine:3.20 AS builder
RUN apk add --no-cache gcc musl-dev linux-headers
RUN mkdir -p /out
WORKDIR /src
COPY src/json.h src/json.c src/base64.h src/base64.c src/config.h src/config.c src/protocol.h src/protocol.c src/record.h src/record.c src/relayd.c src/stub.c src/fabricate-emit.c ./
RUN gcc -O2 -Wall -Wextra -std=c11 -o /out/execrelayd relayd.c config.c json.c base64.c record.c protocol.c \
 && gcc -O2 -Wall -Wextra -std=c11 -o /out/stub stub.c \
 && gcc -O2 -Wall -Wextra -std=c11 -o /out/fabricate-emit fabricate-emit.c base64.c

FROM alpine:3.20
RUN apk add --no-cache curl ca-certificates bind-tools
COPY --from=builder /out/execrelayd /usr/local/bin/execrelayd
COPY --from=builder /out/stub /usr/local/bin/stub
COPY --from=builder /out/fabricate-emit /usr/local/bin/fabricate-emit
WORKDIR /work
ENTRYPOINT ["/usr/local/bin/execrelayd"]
