#!/usr/bin/env python3
"""Allowlist CONNECT proxy for benchmark sandboxing.

The agent container has NO direct internet (it sits on an --internal docker network);
this proxy — dual-homed on that internal network and the bridge — is its ONLY route out.
It permits HTTPS CONNECT only to hosts matching ALLOW_HOSTS (comma-separated full-match
regexes) and 403s everything else. Plain HTTP (proxied GET/POST/...) is refused outright,
since the model APIs are HTTPS. Every decision is logged to stderr for the run audit.

So `git clone github.com`, `curl raw.githubusercontent.com`, `python urllib.urlopen(...)`
all have nowhere to go — there is no route to anything but the allowlisted model host.

env: ALLOW_HOSTS="api\\.anthropic\\.com,chatgpt\\.com"   PORT=8888
"""
import os
import re
import select
import socket
import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

ALLOW = [re.compile(p.strip()) for p in os.environ.get("ALLOW_HOSTS", "").split(",") if p.strip()]
PORT = int(os.environ.get("PORT", "8888"))


def allowed(host: str) -> bool:
    return any(p.fullmatch(host) for p in ALLOW)


def log(msg: str) -> None:
    sys.stderr.write(msg + "\n")
    sys.stderr.flush()


class Proxy(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def do_CONNECT(self):  # noqa: N802
        host, _, port = self.path.partition(":")
        port = int(port or 443)
        if not allowed(host):
            log(f"DENY CONNECT {host}:{port}")
            self.send_error(403, "blocked by egress allowlist")
            return
        try:
            upstream = socket.create_connection((host, port), timeout=30)
        except OSError as e:
            log(f"FAIL CONNECT {host}:{port} {e}")
            self.send_error(502, str(e))
            return
        log(f"ALLOW CONNECT {host}:{port}")
        self.send_response(200, "Connection Established")
        self.end_headers()
        try:
            self._tunnel(self.connection, upstream)
        finally:
            upstream.close()

    def _deny_http(self):
        log(f"DENY {self.command} {self.path}")
        self.send_error(403, "only HTTPS CONNECT to allowlisted hosts is permitted")

    do_GET = do_POST = do_PUT = do_DELETE = do_HEAD = do_PATCH = do_OPTIONS = _deny_http

    @staticmethod
    def _tunnel(a: socket.socket, b: socket.socket) -> None:
        socks = [a, b]
        try:
            while True:
                r, _, _ = select.select(socks, [], [], 120)
                if not r:
                    return
                for s in r:
                    other = b if s is a else a
                    data = s.recv(65536)
                    if not data:
                        return
                    other.sendall(data)
        except OSError:
            return

    def log_message(self, *_):  # silence default access logging
        pass


if __name__ == "__main__":
    log(f"egress proxy on :{PORT}; allow={[p.pattern for p in ALLOW]}")
    ThreadingHTTPServer(("0.0.0.0", PORT), Proxy).serve_forever()
