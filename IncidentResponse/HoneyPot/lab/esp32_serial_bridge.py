#!/usr/bin/env python3
"""Optional UART-to-JSONL bridge for DIY ESP32 honeypots with CUSTOM firmware.

Requires 'pyserial'. The cited NanoC6 project does not promise this protocol.
Only accepts lines prefixed HONEYPOT_JSON: and a strict small schema.
Never transmits commands to the device. No credentials/payload logs.
"""
import argparse
from datetime import datetime, timezone
import ipaddress
import json
import os
from pathlib import Path
import re
import time

PREFIX = "HONEYPOT_JSON:"
ALLOWED_EVENTS = {"tcp_connection", "telnet_connection", "http_probe", "service_probe"}


def parse_line(raw, sensor):
    if isinstance(raw, bytes):
        raw = raw.decode("utf-8", "strict")
    if len(raw) > 1024 or not raw.startswith(PREFIX):
        return None
    try:
        data = json.loads(raw[len(PREFIX):])
    except (json.JSONDecodeError, ValueError):
        return None
    if not isinstance(data, dict):
        return None
    event = data.get("event")
    if event not in ALLOWED_EVENTS:
        return None
    try:
        addr = str(ipaddress.ip_address(data["src_ip"]))
        port = int(data["port"])
        if port < 1 or port > 65535:
            return None
    except (KeyError, TypeError, ValueError):
        return None
    return {"honeypot": {
        "integration": "esp32_serial",
        "event": event,
        "sensor": re.sub(r"[^a-zA-Z0-9_.-]", "-", sensor)[:64],
        "src_ip": addr,
        "dst_port": port,
        "observed_at": datetime.now(timezone.utc).isoformat(),
        "assessment": "unverified_device_telemetry",
    }}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--port", required=True, help="Device e.g. /dev/serial/by-id/...")
    parser.add_argument("--baud", type=int, default=115200)
    parser.add_argument("--sensor", required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    if not args.port.startswith("/dev/"):
        parser.error("serial device must be an absolute /dev/ path")
    if not 1200 <= args.baud <= 921600:
        parser.error("unreasonable baud rate")
    try:
        import serial
    except ImportError as e:
        parser.error("pyserial is required (install in an isolated Python venv)")
    args.output.parent.mkdir(parents=True, exist_ok=True)
    while True:
        try:
            with serial.Serial(args.port, args.baud, timeout=2) as connection:
                while True:
                    raw = connection.readline(1025)
                    try:
                        event = parse_line(raw, args.sensor)
                    except UnicodeDecodeError:
                        event = None
                    if not event:
                        continue
                    with args.output.open("a", encoding="utf-8") as output:
                        output.write(json.dumps(event, separators=(",", ":")) + "\n")
                        output.flush()
                        os.fsync(output.fileno())
        except (OSError, serial.SerialException) as error:
            print(f"serial reconnect after error: {type(error).__name__}", flush=True)
            time.sleep(3)


if __name__ == "__main__":
    main()
