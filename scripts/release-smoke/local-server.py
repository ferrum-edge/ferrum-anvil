#!/usr/bin/env python3
"""Loopback HTTP endpoint for the clean-install release smoke (REL-001).

Stands in for the lab gateway the sample workspace points at
(http://127.0.0.1:18080): answers every request with 200 and a small JSON
body, and logs each request (method, path, User-Agent) as one JSON line so
the smoke can prove the call reached this machine's loopback listener.
Binds 127.0.0.1 only. Standard library only; run with `-I`.
"""

import argparse
import datetime
import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

LOCK = threading.Lock()


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--port", type=int, default=18080)
    p.add_argument("--log", required=True)
    a = p.parse_args()

    class Handler(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def _answer(self):
            length = int(self.headers.get("Content-Length") or 0)
            if length:
                self.rfile.read(min(length, 1 << 20))
            entry = {
                "at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
                "method": self.command,
                "path": self.path,
                "user_agent": self.headers.get("User-Agent"),
                "client": self.client_address[0],
            }
            with LOCK, open(a.log, "a", encoding="utf-8") as f:
                f.write(json.dumps(entry) + "\n")
            body = json.dumps({"ok": True, "method": self.command, "path": self.path}).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            if self.command != "HEAD":
                self.wfile.write(body)

        do_GET = do_POST = do_PUT = do_PATCH = do_DELETE = do_HEAD = do_OPTIONS = _answer

        def log_message(self, fmt, *args):
            pass

    ThreadingHTTPServer(("127.0.0.1", a.port), Handler).serve_forever()


if __name__ == "__main__":
    main()
