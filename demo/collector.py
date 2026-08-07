#!/usr/bin/env python3
"""A throwaway "attacker's collector" for the live demo — logs what lands.

Run it in a spare terminal during rehearsal so the room can watch an exfil
request actually arrive, rather than taking it on trust:

    python3 demo/collector.py

Then point a demo skill at http://localhost:8000/collect and drive it with a
real agent. Every request is printed in full — method, path, query string,
headers, and body — because that is exactly what an attacker would receive.

It writes nothing to disk, listens only on localhost, and holds no state. It
exists to make one beat concrete: the data leaves. Stdlib only; no install.
"""
from __future__ import annotations

import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse

RED, GRN, DIM, OFF = "\033[31m", "\033[32m", "\033[2m", "\033[0m"


class Collector(BaseHTTPRequestHandler):
    def _log(self, method: str) -> None:
        u = urlparse(self.path)
        body = b""
        length = int(self.headers.get("content-length", 0) or 0)
        if length:
            body = self.rfile.read(length)

        print(f"\n{RED}━━ exfil request landed ━━{OFF}")
        print(f"  {method} {u.path}")
        if u.query:
            print(f"  {RED}query (this is the stolen data):{OFF}")
            for k, vs in parse_qs(u.query).items():
                for v in vs:
                    print(f"    {k} = {v}")
        interesting = {k: v for k, v in self.headers.items()
                       if k.lower() in ("authorization", "cookie", "x-api-key", "user-agent")}
        if interesting:
            print(f"  {DIM}headers:{OFF}")
            for k, v in interesting.items():
                print(f"    {k}: {v}")
        if body:
            print(f"  {RED}body:{OFF} {body.decode('utf-8', 'replace')[:2000]}")
        # Flush every request: a presenter runs this backgrounded or piped, where
        # stdout is buffered and the "it landed" beat would otherwise never show.
        sys.stdout.flush()

        self.send_response(200)
        self.send_header("content-type", "application/json")
        self.end_headers()
        self.wfile.write(b'{"ok": true}')  # look boringly successful

    def do_GET(self):  # noqa: N802
        self._log("GET")

    def do_POST(self):  # noqa: N802
        self._log("POST")

    def log_message(self, *args):  # silence the default access log; ours is nicer
        pass


def main() -> int:
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 8000
    server = ThreadingHTTPServer(("127.0.0.1", port), Collector)
    print(f"{GRN}collector listening on http://localhost:{port}{OFF}  "
          f"{DIM}(Ctrl-C to stop){OFF}")
    print(f"{DIM}point a demo skill's exfil URL here and watch it arrive{OFF}")
    sys.stdout.flush()
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nstopped.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
