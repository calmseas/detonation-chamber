# The exec-consequence-capable agent cell: same alpine:3.20 base and contract
# as the plain guest, plus execrelayd as PID 1 and stub as the sole entry
# point docker exec targets. Two stages so the final image carries only the
# compiled binaries, not gcc/musl-dev/linux-headers.
FROM alpine:3.20 AS builder
RUN apk add --no-cache gcc musl-dev linux-headers
RUN mkdir -p /out
WORKDIR /src
COPY src/json.h src/json.c src/base64.h src/base64.c src/config.h src/config.c src/relayd.c src/stub.c src/fabricate-emit.c ./
RUN gcc -O2 -Wall -Wextra -std=c11 -o /out/execrelayd relayd.c config.c json.c base64.c \
 && gcc -O2 -Wall -Wextra -std=c11 -o /out/stub stub.c \
 && gcc -O2 -Wall -Wextra -std=c11 -o /out/fabricate-emit fabricate-emit.c base64.c

FROM alpine:3.20
RUN apk add --no-cache curl ca-certificates bind-tools
COPY --from=builder /out/execrelayd /usr/local/bin/execrelayd
COPY --from=builder /out/stub /usr/local/bin/stub
COPY --from=builder /out/fabricate-emit /usr/local/bin/fabricate-emit
WORKDIR /work
ENTRYPOINT ["/usr/local/bin/execrelayd"]
