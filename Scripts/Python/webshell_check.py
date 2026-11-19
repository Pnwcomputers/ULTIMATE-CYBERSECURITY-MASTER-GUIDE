#!/usr/bin/env python3
"""Retired web-shell checker.

The former script only ran a local shell command; it did not safely check a
remote web application. This replacement performs no command or network action.
"""

import sys


def main() -> int:
    print(
        "This checker is retired. Review the application's authorized security "
        "test plan and use non-invasive, approved checks.",
        file=sys.stderr,
    )
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
