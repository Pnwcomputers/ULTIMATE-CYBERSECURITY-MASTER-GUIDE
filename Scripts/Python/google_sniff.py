#!/usr/bin/env python3
"""Retired cleartext search-query capture example.

This stub performs no packet capture, personal-data collection, or network action.
"""

import sys


def main() -> int:
    print(
        "This packet capture example is retired and performs no capture. Use synthetic packet captures and approved telemetry sources for analysis.",
        file=sys.stderr,
    )
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
