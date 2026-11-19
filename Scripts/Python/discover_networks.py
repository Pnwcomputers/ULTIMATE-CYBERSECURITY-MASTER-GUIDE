#!/usr/bin/env python3
"""List saved Windows network profiles locally; optionally look up explicit BSSIDs in WiGLE.

The registry's DefaultGatewayMac value is a gateway MAC, not a Wi-Fi access-point
BSSID. It must not be submitted to WiGLE as if it identified an access point.
"""
from __future__ import annotations

import argparse
import getpass
import os
import re
import sys

import requests
import winreg


SIGNATURES_KEY = (
    r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\NetworkList"
    r"\Signatures\Unmanaged"
)
PROFILES_KEY = (
    r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\NetworkList\Profiles"
)
BSSID_RE = re.compile(r"^(?:[0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}$")


def format_mac(value: object) -> str:
    """Format a registry REG_BINARY MAC value without assuming character bytes."""
    if isinstance(value, bytes):
        octets = value[:6]
    elif isinstance(value, (tuple, list)) and all(isinstance(x, int) for x in value):
        octets = bytes(value[:6])
    else:
        raise ValueError("Expected a binary MAC address")
    if len(octets) != 6:
        raise ValueError("Expected six MAC address bytes")
    return ":".join(f"{octet:02x}" for octet in octets)


def saved_networks() -> list[tuple[str, str]]:
    """Return local saved profile names and gateway MACs; make no network requests."""
    results: list[tuple[str, str]] = []
    try:
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, SIGNATURES_KEY) as root:
            count = winreg.QueryInfoKey(root)[0]
            guids = [winreg.EnumKey(root, index) for index in range(count)]
    except OSError as exc:
        raise RuntimeError(f"Cannot read saved network signatures: {exc}") from exc

    for guid in guids:
        try:
            with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, SIGNATURES_KEY + "\\" + guid) as key:
                profile_guid, _ = winreg.QueryValueEx(key, "ProfileGuid")
                gateway_mac, _ = winreg.QueryValueEx(key, "DefaultGatewayMac")
            with winreg.OpenKey(
                winreg.HKEY_LOCAL_MACHINE, PROFILES_KEY + "\\" + str(profile_guid)
            ) as profile:
                profile_name, _ = winreg.QueryValueEx(profile, "ProfileName")
            results.append((str(profile_name), format_mac(gateway_mac)))
        except (OSError, ValueError):
            # Old, incomplete, or non-Wi-Fi entries may not contain these values.
            continue
    return results


def lookup_wigle(bssid: str, api_name: str, api_token: str) -> None:
    """Look up one explicitly supplied BSSID; this discloses it to WiGLE."""
    response = requests.get(
        "https://api.wigle.net/api/v2/network/detail",
        auth=(api_name, api_token),
        params={"netid": bssid},
        timeout=(5, 15),
    )
    response.raise_for_status()
    payload = response.json()
    results = payload.get("results") or []
    if not results:
        print(f"WiGLE: no record returned for {bssid}")
        return
    for item in results:
        print(
            f"WiGLE {bssid}: SSID={item.get('ssid', 'unknown')!r}, "
            f"latitude={item.get('trilat', 'unknown')}, "
            f"longitude={item.get('trilong', 'unknown')}"
        )


def main() -> int:
    parser = argparse.ArgumentParser(
        description="List saved Windows network profiles locally; optional explicit WiGLE lookup."
    )
    parser.add_argument(
        "--share-bssids-with-wigle",
        action="store_true",
        help="confirm that explicitly supplied BSSIDs may be sent to WiGLE",
    )
    parser.add_argument(
        "--wigle-bssid",
        action="append",
        default=[],
        metavar="MAC",
        help="explicit access-point BSSID to look up; may be repeated",
    )
    parser.add_argument(
        "--wigle-api-name",
        default=os.environ.get("WIGLE_API_NAME"),
        help="WiGLE API name (or set WIGLE_API_NAME); token is prompted privately",
    )
    args = parser.parse_args()

    for name, gateway_mac in saved_networks():
        print(f"Saved profile: {name} | default gateway MAC: {gateway_mac}")
    print(
        "Saved-profile gateway MACs are not BSSIDs and were not sent to any service."
    )

    if not args.wigle_bssid:
        return 0
    if not args.share_bssids_with_wigle:
        parser.error("WiGLE lookups require --share-bssids-with-wigle and explicit --wigle-bssid values")

    bssids = [value.strip() for value in args.wigle_bssid]
    if any(not BSSID_RE.fullmatch(value) for value in bssids):
        parser.error("Each --wigle-bssid must be a full six-octet MAC address")
    if not args.wigle_api_name:
        parser.error("Set WIGLE_API_NAME or provide --wigle-api-name")
    api_token = os.environ.get("WIGLE_API_TOKEN") or getpass.getpass("WiGLE API token: ")
    if not api_token:
        parser.error("A WiGLE API token is required for an opted-in lookup")

    print(
        "Consent confirmed: the explicitly supplied BSSIDs will be sent to WiGLE "
        "for a location lookup. Provider retention and account terms apply."
    )
    for bssid in bssids:
        try:
            lookup_wigle(bssid.upper(), args.wigle_api_name, api_token)
        except requests.RequestException as exc:
            print(f"WiGLE lookup failed for {bssid}: {exc}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
