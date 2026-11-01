#!/usr/bin/env python3
"""Loopback-only nzyme detection webhook -> Wazuh-compatible JSONL.

Official nzyme action payload fields: event_supertype, event_type,
event_type_subsystem (detection), event_type_human_readable, details, timestamp.
No BSSID is promised by the webhook schema. Do not infer one from free text.
This is a low-volume, serialized lab receiver: delivery is at-most-once.
"""
import argparse
import datetime as dt
import hashlib
from http.server import BaseHTTPRequestHandler, HTTPServer
import hmac
import json
import logging
import os
from pathlib import Path

LOG = logging.getLogger("nzyme-wazuh")
MAX_BYTES = 16 * 1024


def names(env):
    return {part.strip().upper() for part in env.split(",") if part.strip()}


def normalize(event, sensor, disconnect_types=frozenset(), rogue_types=frozenset()):
    if not isinstance(event, dict):
        raise ValueError("expected JSON object")
    supertype = event.get("event_supertype")
    if supertype not in ("detection", "system"):
        raise ValueError("invalid event_supertype")
    event_type = event.get("event_type")
    timestamp = event.get("timestamp")
    if not isinstance(event_type, str) or not (1 <= len(event_type) <= 128):
        raise ValueError("invalid event_type")
    if not isinstance(timestamp, str):
        raise ValueError("missing timestamp")
    try:
        date = dt.datetime.fromisoformat(timestamp.replace("Z", "+00:00"))
    except ValueError as error:
        raise ValueError("invalid timestamp") from error
    if date.tzinfo is None:
        raise ValueError("timestamp must include timezone")
    subtype = event.get("event_type_subsystem", "")
    if not isinstance(subtype, str):
        subtype = ""
    summary = event.get("details", "")
    if not isinstance(summary, str):
        summary = ""
    if supertype == "system":
        category = "system_event"
    elif event_type.upper() in disconnect_types:
        category = "disconnect_anomaly"
    elif event_type.upper() in rogue_types:
        category = "rogue_ap_anomaly"
    else:
        category = "unclassified_detection"
    digest = hashlib.sha256(
        json.dumps(event, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()
    return {"wids": {
        "integration": "nzyme",
        "sensor": sensor,
        "event": event_type,
        "event_supertype": supertype,
        "category": category,
        "nzyme_subsystem": subtype[:128],
        "summary": summary[:500],
        "observed_at": date.astimezone(dt.timezone.utc).isoformat(),
        "event_id": digest,
        "assessment": "requires_corroboration",
    }}


def build_handler(token, sensor, output, disconnect_types, rogue_types):
    class Handler(BaseHTTPRequestHandler):
        def log_message(self, _fmt, *_args):
            # Do not print webhook payloads or Authorization header.
            return

        def send_plain(self, status, msg):
            self.send_response(status)
            self.send_header("Content-Type", "text/plain")
            self.send_header("Content-Length", str(len(msg)))
            self.end_headers()
            self.wfile.write(msg.encode("ascii"))

        def do_POST(self):
            if self.path != "/nzyme":
                self.send_plain(404, "not found")
                return
            auth = self.headers.get("Authorization", "")
            if not hmac.compare_digest(auth, "Bearer " + token):
                self.send_plain(401, "unauthorized")
                return
            if self.headers.get("Content-Type", "").split(";")[0].strip().lower() != "application/json":
                self.send_plain(415, "JSON required")
                return
            size_raw = self.headers.get("Content-Length", "")
            if not size_raw.isascii() or not size_raw.isdecimal():
                self.send_plain(411, "content length required")
                return
            size = int(size_raw)
            if size <= 0 or size > MAX_BYTES:
                self.send_plain(413, "invalid payload size")
                return
            try:
                incoming = json.loads(self.rfile.read(size))
                event = normalize(incoming, sensor, disconnect_types, rogue_types)
            except (ValueError, UnicodeError, json.JSONDecodeError):
                self.send_plain(400, "invalid event")
                return
            try:
                output.parent.mkdir(parents=True, exist_ok=True)
                with output.open("a", encoding="utf-8") as stream:
                    stream.write(json.dumps(event, separators=(",", ":")) + "\n")
                    stream.flush()
                    os.fsync(stream.fileno())
            except OSError:
                LOG.exception("cannot persist nzyme event")
                self.send_plain(503, "storage unavailable")
                return
            self.send_plain(204, "")

    return Handler


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--sensor", default=os.getenv("NZ_SENSOR", "nzyme-node-01"))
    parser.add_argument("--port", type=int, default=8787)
    parser.add_argument("--output", type=Path, default=Path("/var/log/nzyme-wazuh/events.jsonl"))
    args = parser.parse_args()
    token = os.getenv("NZ_WEBHOOK_TOKEN", "")
    if len(token) < 32:
        parser.error("NZ_WEBHOOK_TOKEN must be >=32 characters; generate with openssl rand -hex 32")
    if not 1024 <= args.port <= 65535:
        parser.error("port must be 1024..65535")
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
    handler = build_handler(
        token, args.sensor, args.output,
        names(os.getenv("NZ_DISCONNECT_TYPES", "")),
        names(os.getenv("NZ_ROGUE_TYPES", "")),
    )
    # Binding loopback is deliberate. For a remote nzyme node use a properly
    # authenticated HTTPS reverse proxy instead of exposing HTTP on the LAN.
    httpd = HTTPServer(("127.0.0.1", args.port), handler)
    LOG.info("listening on 127.0.0.1:%d for nzyme webhook", args.port)
    httpd.serve_forever()


if __name__ == "__main__":
    main()
