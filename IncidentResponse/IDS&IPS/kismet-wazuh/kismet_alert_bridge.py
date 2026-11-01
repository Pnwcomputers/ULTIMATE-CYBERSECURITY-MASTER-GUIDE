#!/usr/bin/env python3
"""Read-only Kismet alert polling -> Wazuh JSONL bridge. Python 3.10+.

Kismet endpoint: /alerts/last-time/{TIMESTAMP}/alerts.json
Auth: a Kismet role=readonly API token in the KISMET cookie.
No AP changes, packet transmission, or Kismet alert injection.
"""
import argparse
import datetime as dt
import hashlib
import json
import logging
import os
from pathlib import Path
import time
from urllib.request import Request, urlopen

LOG = logging.getLogger("kismet-wazuh")
WATCH = {
    "DEAUTHFLOOD": "deauth_flood",
    "BCASTDISCON": "broadcast_disconnect",
    "DISASSOCTRAFFIC": "disconnect_anomaly",
    "DISCONCODEINVALID": "invalid_reason_code",
    "NOCLIENTMFP": "pmf_gap",
    "APSPOOF": "ap_spoof",
    "CRYPTODROP": "crypto_downgrade",
    "CHANCHANGE": "channel_change",
}
EMPTY_MAC = "00:00:00:00:00:00"


def field(obj, dotted, default=""):
    if dotted in obj:
        return obj[dotted]
    value = obj
    for key in dotted.split("."):
        if not isinstance(value, dict) or key not in value:
            return default
        value = value[key]
    return value


def timestamp(alert):
    """Kismet exposes seconds plus optional microseconds in alert records."""
    sec = field(alert, "kismet.alert.timestamp", None)
    usec = field(alert, "kismet.alert.utimestamp", 0)
    if sec is None:
        sec = field(alert, "timestamp", None)
    if sec is None:
        raise ValueError("Kismet alert lacks timestamp")
    return float(sec) + float(usec or 0) / 1_000_000


def normalize(alert, sensor):
    ts = timestamp(alert)
    name = str(field(alert, "kismet.alert.header") or field(alert, "header")).upper()
    if not name:
        raise ValueError("Kismet alert lacks header")
    checksum = hashlib.sha256(
        json.dumps(alert, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()
    return {
        "wids": {
            "integration": "kismet",
            "sensor": sensor,
            "event": name,
            "category": WATCH.get(name, "other"),
            "bssid": str(field(alert, "kismet.alert.bssid") or EMPTY_MAC).lower(),
            "source": str(field(alert, "kismet.alert.source") or "").lower(),
            "destination": str(field(alert, "kismet.alert.dest") or "").lower(),
            "channel": str(field(alert, "kismet.alert.channel") or ""),
            "kismet_severity": field(alert, "kismet.alert.severity", ""),
            "summary": str(field(alert, "kismet.alert.text") or "")[:500],
            "observed_at": dt.datetime.fromtimestamp(
                ts, dt.timezone.utc
            ).isoformat(),
            "event_id": checksum,
            "assessment": "requires_corroboration",
        }
    }, ts, checksum


def read_state(path, bootstrap_seconds):
    try:
        with path.open(encoding="utf-8") as f:
            item = json.load(f)
        return float(item["cursor"]), set(item.get("recent_ids", []))
    except FileNotFoundError:
        return max(0.0, time.time() - bootstrap_seconds), set()


def save_state(path, cursor, recent):
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(path.name + ".tmp")
    with temporary.open("w", encoding="utf-8") as f:
        json.dump({"cursor": cursor, "recent_ids": list(sorted(recent))[-256:]}, f)
        f.flush()
        os.fsync(f.fileno())
    os.replace(temporary, path)
    os.chmod(path, 0o600)


def fetch(url, key, cursor):
    endpoint = f"{url.rstrip('/')}/alerts/last-time/{cursor:.6f}/alerts.json"
    request = Request(endpoint, headers={"Cookie": "KISMET=" + key, "Accept": "application/json"})
    with urlopen(request, timeout=15) as response:
        data = json.load(response)
    if not isinstance(data, list):
        raise ValueError("Unexpected Kismet API payload (expected alert list)")
    return data


def collect_once(url, key, sensor, outfile, statefile, bootstrap_seconds):
    cursor, recent = read_state(statefile, bootstrap_seconds)
    alerts = fetch(url, key, cursor)
    pending = []
    high = cursor
    # Sort by server event timestamp to avoid advancing beyond earlier alerts.
    for alert in sorted(alerts, key=timestamp):
        event, ts, digest = normalize(alert, sensor)
        if ts < cursor or digest in recent:
            continue
        pending.append((event, ts, digest))
        high = max(ts, high)

    if pending:
        outfile.parent.mkdir(parents=True, exist_ok=True)
        with outfile.open("a", encoding="utf-8") as f:
            for event, ts, digest in pending:
                f.write(json.dumps(event, separators=(",", ":")) + "\n")
                recent.add(digest)
            f.flush()
            os.fsync(f.fileno())
        # Commit cursor only after durable append. On power failure between the
        # append and state commit, a small duplicate is possible: use event_id.
        save_state(statefile, high, recent)
    LOG.info("kismet alerts fetched=%d written=%d cursor=%.6f", len(alerts), len(pending), high)
    return len(pending)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--url", default="http://127.0.0.1:2501")
    parser.add_argument("--sensor", required=True)
    parser.add_argument("--output", type=Path, default=Path("/var/log/kismet-wazuh/events.jsonl"))
    parser.add_argument("--state", type=Path, default=Path("/var/lib/kismet-wazuh/cursor.json"))
    parser.add_argument("--interval", type=float, default=3.0)
    parser.add_argument("--bootstrap-seconds", type=float, default=30.0)
    parser.add_argument("--once", action="store_true")
    args = parser.parse_args()
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
    if args.interval < 1:
        parser.error("--interval must be >= 1 second")
    if not (args.url.startswith("https://") or args.url.startswith("http://127.0.0.1:")
            or args.url.startswith("http://localhost:")):
        parser.error("remote Kismet URLs must use HTTPS with trusted certificates")
    key = os.environ.get("KISMET_API_KEY", "")
    if not key:
        parser.error("KISMET_API_KEY must be set to a Kismet readonly API token")
    while True:
        try:
            collect_once(args.url, key, args.sensor, args.output, args.state, args.bootstrap_seconds)
        except Exception:
            LOG.exception("poll failed; will retry without advancing cursor")
            if args.once:
                raise
        if args.once:
            break
        time.sleep(args.interval)


if __name__ == "__main__":
    main()
