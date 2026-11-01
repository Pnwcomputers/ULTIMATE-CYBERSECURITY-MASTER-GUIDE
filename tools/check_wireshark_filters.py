#!/usr/bin/env python3
"""Validate the PNWC Wireshark master display-filter catalog.

Structural checks use stdlib only. With tshark installed, compile every display
expression against a header-only PCAP (no user packet data or network access).
Exit 1 on invalid rows or expressions; 2 if TShark was required but unavailable.
"""
from __future__ import annotations

import argparse
import csv
import shutil
import struct
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DEFAULT_CATALOG = ROOT / "Documentation" / "wireshark-filter-catalog.tsv"
HEADER = ["category", "name", "display_filter", "notes"]


def load_catalog(path: Path) -> list[dict[str, str]]:
    with path.open("r", encoding="utf-8", newline="") as file:
        reader = csv.DictReader(file, delimiter="\t")
        if reader.fieldnames != HEADER:
            raise ValueError(f"Expected TSV columns {HEADER}, found {reader.fieldnames}")
        rows = []
        seen = set()
        for n, row in enumerate(reader, 2):
            if None in row or any(row[key] is None for key in HEADER):
                raise ValueError(f"Malformed TSV row {n}")
            if any(not row[key].strip() for key in HEADER):
                raise ValueError(f"Empty value on row {n}")
            if any("\r" in row[key] or "\n" in row[key] for key in HEADER):
                raise ValueError(f"Embedded newline on row {n}")
            identity = (row["category"].casefold(), row["name"].casefold())
            if identity in seen:
                raise ValueError(f"Duplicate category/name on row {n}: {identity}")
            seen.add(identity)
            # Filter rows are expressions only: no shell syntax or inline '#'.
            expr = row["display_filter"]
            if "#" in expr or ";" in expr or "\x00" in expr:
                raise ValueError(f"Non-filter character in expression on row {n}")
            rows.append(row)
        if not rows:
            raise ValueError("Catalog is empty")
        return rows


def check_tshark(rows: list[dict[str, str]], executable: str) -> list[str]:
    errors = []
    with tempfile.TemporaryDirectory(prefix="pnwc-wireshark-filter-") as directory:
        # Classic little-endian PCAP header; DLT_EN10MB; zero packets and
        # thus no traffic or personal data involved in this syntax check.
        empty_pcap = Path(directory) / "empty.pcap"
        empty_pcap.write_bytes(struct.pack("<IHHIIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1))
        for row in rows:
            result = subprocess.run(
                [executable, "-n", "-r", str(empty_pcap), "-Y", row["display_filter"]],
                capture_output=True, text=True, check=False, timeout=20,
            )
            if result.returncode != 0:
                reason = (result.stderr or result.stdout).strip().splitlines()
                errors.append(
                    f"{row['category']} / {row['name']}: {row['display_filter']!r}: "
                    f"{' | '.join(reason[:4]) or 'nonzero TShark exit'}"
                )
    return errors


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--catalog", type=Path, default=DEFAULT_CATALOG)
    parser.add_argument("--structure-only", action="store_true",
                        help="Check TSV structure without requiring TShark")
    args = parser.parse_args()

    try:
        rows = load_catalog(args.catalog)
    except (OSError, ValueError) as error:
        print(f"Catalog error: {error}", file=sys.stderr)
        return 1

    print(f"Catalog structure valid: {len(rows)} display filters")
    if args.structure_only:
        return 0

    tshark = shutil.which("tshark")
    if not tshark:
        print("TShark is required for expression syntax verification.", file=sys.stderr)
        return 2

    version = subprocess.run([tshark, "--version"], capture_output=True, text=True)
    print((version.stdout or version.stderr).splitlines()[0])
    errors = check_tshark(rows, tshark)
    for problem in errors:
        print(f"ERROR: {problem}", file=sys.stderr)
    print(f"TShark compiled {len(rows) - len(errors)}/{len(rows)} filter expressions")
    return 1 if errors else 0


if __name__ == "__main__":
    raise SystemExit(main())
