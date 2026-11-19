#!/usr/bin/env python3
"""Retired personal-device tracking example.

This stub performs no packet capture, personal-data collection, or network action.
"""

import sys


def main() -> int:
    print(
        "This device-tracking example is retired and performs no radio scan. Use consent-based inventory and synthetic identifiers.",
        file=sys.stderr,
    )
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
