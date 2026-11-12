#!/usr/bin/env python3
"""Compare local evidence against a saved v1 manifest; no network I/O or writes."""
from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path, PurePosixPath

from evidence_manifest import build_manifest


FORMAT = "pnwc-cyberdeck-public-evidence-manifest-v1"


def validate_manifest(value: object) -> dict:
    """Reject ambiguous inventories before comparing any evidence."""
    if not isinstance(value, dict) or value.get("format") != FORMAT:
        raise ValueError("Unsupported manifest format")
    records = value.get("files")
    count = value.get("file_count")
    if not isinstance(records, list) or type(count) is not int or count != len(records):
        raise ValueError("Invalid files list or file_count")
    seen = set()
    for record in records:
        if not isinstance(record, dict):
            raise ValueError("File records must be objects")
        name = record.get("relative_path")
        if not isinstance(name, str) or not name or "\\" in name or ":" in name:
            raise ValueError("Expected a portable relative POSIX path")
        path = PurePosixPath(name)
        if path.is_absolute() or ".." in path.parts or path.as_posix() != name or name == ".":
            raise ValueError("Unsafe or noncanonical relative path")
        if name in seen:
            raise ValueError("Duplicate relative path")
        seen.add(name)
        if type(record.get("size_bytes")) is not int or record["size_bytes"] < 0:
            raise ValueError("Invalid size_bytes")
        if not isinstance(record.get("sha256"), str) or not re.fullmatch(r"[0-9a-f]{64}", record["sha256"]):
            raise ValueError("Invalid SHA-256 digest")
    return value


def verify_manifest(folder: Path, manifest_path: Path) -> dict:
    root = folder.resolve(strict=True)
    saved = manifest_path.resolve(strict=True)
    if saved == root or root in saved.parents:
        raise ValueError("Manifest must be outside input directory")
    expected = validate_manifest(json.loads(saved.read_text(encoding="utf-8")))
    # Reuse the generator's file enumeration rules, including symlink exclusion.
    actual = build_manifest(root)
    old = {item["relative_path"]: item for item in expected["files"]}
    new = {item["relative_path"]: item for item in actual["files"]}
    missing = sorted(old.keys() - new.keys())
    added = sorted(new.keys() - old.keys())
    changed = sorted(name for name in old.keys() & new.keys()
                     if any(old[name][key] != new[name][key] for key in ("size_bytes", "sha256")))
    return {"matches": not (missing or added or changed), "missing": missing,
            "added": added, "changed": changed, "checked_file_count": len(new)}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", required=True, type=Path)
    parser.add_argument("--manifest", required=True, type=Path)
    args = parser.parse_args()
    try:
        result = verify_manifest(args.input, args.manifest)
    except (OSError, ValueError, RuntimeError) as exc:
        print(f"Verification error: {exc}", file=sys.stderr)
        return 2
    print(json.dumps(result, indent=2, ensure_ascii=True))
    return 0 if result["matches"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
