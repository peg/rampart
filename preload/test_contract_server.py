#!/usr/bin/env python3
# Copyright 2026 The Rampart Authors
# Licensed under the Apache License, Version 2.0

"""Local-only HTTP fixture for the preload enforcement contract test."""

import json
import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, _format, *_args):
        return

    def send(self, status, body):
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_POST(self):
        try:
            length = int(self.headers.get("Content-Length", "0"))
            payload = json.loads(self.rfile.read(length))
        except (ValueError, json.JSONDecodeError):
            self.send(400, b'{"error":"invalid json"}')
            return

        command = payload.get("params", {}).get("command", "")
        valid_contract = (
            self.path.endswith("/v1/preflight/exec")
            and self.headers.get("Authorization") == "Bearer contract-token"
            and payload.get("agent") == "preload-contract"
            and payload.get("session") == "preload-contract"
            and payload.get("enforce") is True
            and command in {
                "/bin/true",
                "true",
                "/bin/true rampart-debug-secret-canary",
            }
        )
        if not valid_contract:
            self.send(400, b'{"error":"bad preload request contract"}')
            return

        case = self.path.split("/", 2)[1]
        if case == "allow":
            self.send(200, b'{"allowed":true,"decision":"allow"}')
        elif case == "deny":
            self.send(200, b'{"allowed":false,"decision":"deny"}')
        elif case == "deceptive":
            self.send(200, b'{"message":"\\\"allowed\\\":true","allowed":false}')
        elif case == "malformed":
            self.send(200, b'{"message":"\\\"allowed\\\":true"}')
        elif case == "auth":
            self.send(401, b'{"error":"unauthorized"}')
        elif case == "server-error":
            self.send(503, b'{"error":"unavailable"}')
        elif case == "oversized":
            self.send(200, b'{"padding":"' + (b"x" * 70000) + b'","allowed":true}')
        else:
            self.send(404, b'{"error":"unknown case"}')


def main():
    if len(sys.argv) != 2:
        raise SystemExit("usage: test_contract_server.py PORT")
    server = ThreadingHTTPServer(("127.0.0.1", int(sys.argv[1])), Handler)
    server.serve_forever()


if __name__ == "__main__":
    main()
