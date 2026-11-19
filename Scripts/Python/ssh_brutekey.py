#!/usr/bin/env python3
"""Retired unsafe SSH private-key guessing example.

The former implementation tried every file in a directory against a host and
automatically accepted unknown host keys. Do not use it to test unrelated key
collections. Review authorized key inventory and SSH authentication logs using
approved administrative controls instead.
"""

raise SystemExit(
    "Retired: unsafe SSH key-guessing example. "
    "Use approved key inventory and authentication logs."
)
