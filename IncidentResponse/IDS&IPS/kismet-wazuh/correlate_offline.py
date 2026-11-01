#!/usr/bin/env python3
"""OFFLINE cross-signal correlation of normalized Kismet alerts and PCAP summaries.

Signals from one sensor are NOT independent confirmation or attack attribution.
"""
import argparse
import datetime as dt
import json
from pathlib import Path
import sys

INTERESTING = {"DEAUTHFLOOD", "BCASTDISCON", "DISASSOCTRAFFIC"}


def read_events(path):
    with Path(path).open(encoding="utf-8") as stream:
        for line in stream:
            if not line.strip():
                continue
            item = json.loads(line)
            record = item.get("wids", {})
            if not record.get("bssid") or not record.get("observed_at"):
                continue
            when = dt.datetime.fromisoformat(record["observed_at"].replace("Z", "+00:00"))
            if when.tzinfo is None:
                raise ValueError(f"Missing timezone in {path}")
            yield record, when.timestamp()


def correlate(kismet_events, pcap_events, within_seconds=120):
    for kismet, kt in kismet_events:
        if kismet.get("event") not in INTERESTING:
            continue
        for pcap, pt in pcap_events:
            if kismet["bssid"].lower() != pcap["bssid"].lower():
                continue
            if pcap.get("event") != "DISCONNECT_BURST":
                continue
            if abs(kt - pt) > within_seconds:
                continue
            yield {"wids": {
                "integration": "correlator",
                "sensor": kismet.get("sensor", "unknown"),
                "event": "KISMET_PCAP_CORRELATED",
                "bssid": kismet["bssid"].lower(),
                "kismet_event": kismet["event"],
                "pcap_tier": pcap.get("tier", ""),
                "pcap_count": pcap.get("count", 0),
                "observed_at": kismet["observed_at"],
                "assessment": "same_sensor_signals_not_independent_proof",
                "summary": "Kismet WIDS alert near passive PCAP burst; verify independent AP/client logs",
            }}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--kismet", type=Path, required=True)
    parser.add_argument("--pcap-events", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True, help="New JSONL results file")
    parser.add_argument("--within", type=int, default=120, help="Max seconds between timestamps")
    args = parser.parse_args()
    if args.within < 0:
        parser.error("--within must be nonnegative")
    ks = list(read_events(args.kismet))
    ps = list(read_events(args.pcap_events))
    results = list(correlate(ks, ps, args.within))
    # Rewrite a case-specific correlation output; do not append duplicate alerts.
    args.output.parent.mkdir(parents=True, exist_ok=True)
    with args.output.open("w", encoding="utf-8") as stream:
        for event in results:
            stream.write(json.dumps(event, separators=(",", ":")) + "\n")
    print(f"Found {len(results)} corroborating signal pairs (not proven attacks)", file=sys.stderr)


if __name__ == "__main__":
    main()
