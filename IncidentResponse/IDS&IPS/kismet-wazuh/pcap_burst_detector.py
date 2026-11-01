#!/usr/bin/env python3
"""Passive OFFLINE 802.11 deauth/disassoc burst summary from an authorized PCAP.

Counts observed frames, NOT authenticated senders or proof of interference.
Uses a separate already-created PCAP; never transmits and never changes radios.
"""
import argparse
from collections import defaultdict
import datetime as dt
import json
from pathlib import Path
import subprocess
import sys


def tier(n, low=12, high=40, critical=100):
    if n >= critical:
        return "critical"
    if n >= high:
        return "high"
    if n >= low:
        return "medium"
    return ""


def classify_rows(rows, sensor, window=30, low=12, high=40, critical=100):
    if not (0 < low < high < critical):
        raise ValueError("thresholds must increase: low < high < critical")
    counts = defaultdict(lambda: {"deauth": 0, "disassoc": 0, "destinations": set()})
    for line in rows:
        columns = line.rstrip("\r\n").split("\t")
        if len(columns) < 5:
            continue
        stamp, bssid, subtype, destination, source = columns[:5]
        try:
            secs = float(stamp)
            subtype_num = int(subtype.strip(), 0)
        except ValueError:
            continue
        if not bssid or subtype_num not in (10, 12):
            continue
        bucket = int(secs // window) * window
        key = (bucket, bssid.lower())
        entry = counts[key]
        entry["deauth" if subtype_num == 12 else "disassoc"] += 1
        if destination:
            entry["destinations"].add(destination.lower())
    for (bucket, bssid), value in sorted(counts.items()):
        count = value["deauth"] + value["disassoc"]
        severity = tier(count, low, high, critical)
        if not severity:
            continue
        yield {"wids": {
            "integration": "pcap",
            "sensor": sensor,
            "event": "DISCONNECT_BURST",
            "category": "observed_disconnect_frames",
            "tier": severity,
            "bssid": bssid,
            "window_seconds": window,
            "count": count,
            "deauth_count": value["deauth"],
            "disassoc_count": value["disassoc"],
            "destination_count": len(value["destinations"]),
            "observed_at": dt.datetime.fromtimestamp(bucket, dt.timezone.utc).isoformat(),
            "assessment": "requires_corroboration",
            "summary": "Observed 802.11 disconnect frame burst in fixed wall-clock bucket",
        }}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--pcap", type=Path, required=True, help="Existing authorized capture")
    parser.add_argument("--sensor", required=True)
    parser.add_argument("--window", type=int, default=30, help="Fixed window seconds")
    parser.add_argument("--low", type=int, default=12)
    parser.add_argument("--high", type=int, default=40)
    parser.add_argument("--critical", type=int, default=100)
    parser.add_argument("--output", help="Append JSONL to path; default stdout")
    args = parser.parse_args()
    if args.window <= 0 or not (0 < args.low < args.high < args.critical):
        parser.error("window positive; thresholds 0 < low < high < critical")
    if not args.pcap.is_file():
        parser.error("capture file does not exist")

    command = [
        "tshark", "-r", str(args.pcap),
        "-Y", "wlan.fc.type_subtype == 0x0c || wlan.fc.type_subtype == 0x0a",
        "-T", "fields",
        "-e", "frame.time_epoch",
        "-e", "wlan.bssid",
        "-e", "wlan.fc.type_subtype",
        "-e", "wlan.da",
        "-e", "wlan.sa",
    ]
    try:
        result = subprocess.run(command, check=True, capture_output=True, text=True)
    except (FileNotFoundError, subprocess.CalledProcessError) as error:
        parser.exit(1, f"TShark error: {error}\n")
    outputs = list(classify_rows(result.stdout.splitlines(), args.sensor, args.window,
                                 args.low, args.high, args.critical))
    if args.output:
        output = Path(args.output)
        output.parent.mkdir(parents=True, exist_ok=True)
        with output.open("a", encoding="utf-8") as stream:
            for event in outputs:
                stream.write(json.dumps(event, separators=(",", ":")) + "\n")
    else:
        for event in outputs:
            print(json.dumps(event, separators=(",", ":")))
    print(f"Analyzed capture: {len(outputs)} suspicious windows (heuristic only)", file=sys.stderr)


if __name__ == "__main__":
    main()
