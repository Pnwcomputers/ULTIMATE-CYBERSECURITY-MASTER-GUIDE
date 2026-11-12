#!/usr/bin/env python3
"""Create a local SHA-256 inventory of pre-existing regular files; no network I/O."""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from datetime import datetime, timezone
from pathlib import Path


def hash_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for block in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def raise_walk_error(error: OSError) -> None:
    """Fail a partial inventory instead of silently skipping unreadable directories."""
    raise error


def build_manifest(folder: Path) -> dict:
    root = folder.resolve(strict=True)
    if not root.is_dir():
        raise ValueError("Input must be a directory")
    records = []
    # Do not follow symlink directories or include symlink files in a manifest.
    for current, dirs, names in os.walk(root, followlinks=False, onerror=raise_walk_error):
        dirs[:] = sorted(d for d in dirs if not (Path(current) / d).is_symlink())
        for name in sorted(names):
            path = Path(current) / name
            if path.is_symlink() or not path.is_file():
                continue
            relative = path.relative_to(root).as_posix()
            before = path.stat()
            digest = hash_file(path)
            after = path.stat()
            if (before.st_size, before.st_mtime_ns) != (after.st_size, after.st_mtime_ns):
                raise RuntimeError(f"File changed while hashing: {relative}")
            records.append({"relative_path": relative, "size_bytes": after.st_size, "sha256": digest})
    records.sort(key=lambda record: record["relative_path"])
    return {
        "format": "pnwc-cyberdeck-public-evidence-manifest-v1",
        "created_at_utc": datetime.now(timezone.utc).isoformat(),
        "source_description": "Local folder explicitly selected by operator; provenance not independently verified",
        "file_count": len(records),
        "files": records,
    }


def write_manifest(folder: Path, output: Path) -> dict:
    root = folder.resolve(strict=True)
    if not root.is_dir():
        raise ValueError("Input must be a directory")
    destination = output.resolve(strict=False)
    if destination == root or root in destination.parents:
        raise ValueError("Output must be outside input directory")
    if destination.exists() or destination.is_symlink():
        raise FileExistsError(f"Refusing to overwrite output: {destination}")
    if not destination.parent.is_dir():
        raise FileNotFoundError("Output parent directory must already exist")
    manifest = build_manifest(root)
    # Exclusive create protects prior work; restrict permissions on POSIX.
    fd = os.open(str(destination), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as stream:
            json.dump(manifest, stream, indent=2, ensure_ascii=False)
            stream.write("\n")
    except BaseException:
        destination.unlink(missing_ok=True)
        raise
    return manifest


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", required=True, type=Path, help="Existing local evidence folder")
    parser.add_argument("--output", required=True, type=Path, help="New JSON manifest file outside that folder")
    args = parser.parse_args()
    result = write_manifest(args.input, args.output)
    print(f"Hashed {result['file_count']} local files; output: {args.output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
