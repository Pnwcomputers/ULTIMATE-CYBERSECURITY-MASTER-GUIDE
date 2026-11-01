#!/usr/bin/env python3
"""Minimal low-interaction HTTP honeypot for an ISOLATED lab (Python 3.10+).

Logs metadata only: no payloads, authorization headers, cookies or credentials.
Bind to loopback by default. Explicit --bind is required for network exposure.
Does not execute commands, download files or proxy requests.
"""
import argparse
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import ipaddress
import json
import logging
import os
from pathlib import Path
import re
import threading

MAX_PATH = 256
MAX_AGENT = 128
LOG = logging.getLogger("diy-honeypot")


def clamp(value, limit):
    # Remove control codes and escaped newlines from untrusted client strings.
    return re.sub(r"[\x00-\x1f\x7f]", "?", str(value))[:limit]


class EventWriter:
    def __init__(self, path, sensor):
        self.path = Path(path)
        self.sensor = sensor
        self.lock = threading.Lock()

    def record(self, method, target, client_ip, client_port, user_agent):
        # Do not log query parameters; they often contain tokens.
        path = target.split("?", 1)[0].split("#", 1)[0]
        event = {"honeypot": {
            "integration": "diy_http",
            "event": "http_probe",
            "sensor": self.sensor,
            "observed_at": datetime.now(timezone.utc).isoformat(),
            "src_ip": clamp(client_ip, 64),
            "src_port": int(client_port),
            "method": clamp(method, 12),
            "path": clamp(path, MAX_PATH),
            "user_agent": clamp(user_agent, MAX_AGENT),
            "assessment": "requires_corroboration",
        }}
        data = json.dumps(event, separators=(",", ":"))
        with self.lock:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            with self.path.open("a", encoding="utf-8") as handle:
                handle.write(data + "\n")
                handle.flush()
                os.fsync(handle.fileno())
        return event


def build_handler(writer):
    class Handler(BaseHTTPRequestHandler):
        server_version = "HTTPServer"
        sys_version = ""

        def log_message(self, *args):
            # Avoid http.server logs (which can reveal raw query strings).
            pass

        def _respond(self):
            client_ip, client_port = self.client_address[:2]
            try:
                writer.record(self.command, self.path, client_ip,
                              client_port, self.headers.get("User-Agent", ""))
            except OSError:
                LOG.exception("unable to log probe")
                self.send_error(503)
                self.close_connection = True
                return
            self.send_response(404)
            self.send_header("Content-Type", "text/plain")
            self.send_header("Cache-Control", "no-store")
            self.send_header("Content-Length", "0")
            self.send_header("Connection", "close")
            self.end_headers()
            # Never read request bodies or provide interactive responses.
            self.close_connection = True

        def do_GET(self): self._respond()
        def do_HEAD(self): self._respond()
        def do_POST(self): self._respond()
        def do_PUT(self): self._respond()
        def do_DELETE(self): self._respond()
        def do_OPTIONS(self): self._respond()
        def do_PATCH(self): self._respond()

    return Handler


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--bind", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8080)
    parser.add_argument("--sensor", required=True)
    parser.add_argument("--output", type=Path,
                        default=Path("./honeypot-events.jsonl"))
    args = parser.parse_args()
    try:
        ipaddress.ip_address(args.bind)
    except ValueError:
        parser.error("--bind must be a literal IP of the isolated decoy interface")
    if not 1024 <= args.port <= 65535:
        parser.error("unprivileged port required (1024..65535)")
    logging.basicConfig(level=logging.INFO)
    handler = build_handler(EventWriter(args.output, args.sensor))
    server = ThreadingHTTPServer((args.bind, args.port), handler)
    server.daemon_threads = True
    server.request_queue_size = 16
    LOG.info("listening at %s:%s; no request payloads are collected",
             args.bind, args.port)
    try:
        server.serve_forever(poll_interval=0.5)
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()


if __name__ == "__main__":
    main()
