#!/usr/bin/env python3
"""Retired web-cookie collection example.

This stub performs no packet capture, personal-data collection, or network action.
"""

import sys


def main() -> int:
    print(
        "This cookie collection example is retired and performs no network action. Use synthetic browser data in a local privacy test.",
        file=sys.stderr,
    )
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
