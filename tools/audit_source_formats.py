#!/usr/bin/env python3
"""Non-executing format/syntax census for otherwise uncovered repository files.

Python, Bash and PowerShell have separate existing checks. This focuses on
JSON, XML, YAML, JavaScript, Ruby and Go, distinguishing archival scripts.
A successful parse never establishes correct code behavior or vendor schema.
"""
from __future__ import annotations

import argparse
from collections import Counter
import json
from pathlib import Path
import shutil
import subprocess
import sys
from xml.etree import ElementTree as ET

SKIP = {".git", ".venv", "venv", "node_modules", "__pycache__", ".pytest_cache"}
FORMATS = {".json", ".xml", ".yml", ".yaml", ".js", ".rb", ".go", ".c", ".scad"}


def is_archive(relative: Path) -> bool:
    return relative.parts[:2] == ("Scripts", "GO")


def external_parse(command: list[str], path: Path) -> tuple[bool, str]:
    try:
        result = subprocess.run(
            command + [str(path)], text=True, capture_output=True, timeout=12,
            check=False)
    except (OSError, subprocess.TimeoutExpired) as exc:
        return False, str(exc)
    return result.returncode == 0, (result.stderr or result.stdout).strip()[:240]


def inspect(root: Path) -> dict[str, object]:
    counts: Counter[str] = Counter()
    outcomes: Counter[str] = Counter()
    errors: list[dict[str, str]] = []
    archival: list[dict[str, str]] = []
    unsupported: list[dict[str, str]] = []
    parsers = {
        ".yml": ["ruby", "-e", 'require "yaml"; Psych.parse_file(ARGV.fetch(0))'],
        ".yaml": ["ruby", "-e", 'require "yaml"; Psych.parse_file(ARGV.fetch(0))'],
        ".js": ["node", "--check"],
        ".rb": ["ruby", "-c"],
        ".go": ["gofmt", "-e", "-d"],
    }
    for file in sorted(root.rglob("*")):
        if not file.is_file():
            continue
        rel = file.relative_to(root)
        if SKIP.intersection(rel.parts) or file.suffix.lower() not in FORMATS:
            continue
        ext = file.suffix.lower()
        counts[ext] += 1
        historical = is_archive(rel)
        if ext == ".c":
            outcomes["C source: external build-dependent review"] += 1
            unsupported.append({"path": rel.as_posix(), "reason": "Compilation depends on C standard and target-specific headers"})
            continue
        if ext == ".scad":
            outcomes["OpenSCAD source: separate CAD verification"] += 1
            unsupported.append({"path": rel.as_posix(), "reason": "Rendering/export checks belong to the pinned OpenSCAD CAD test suite"})
            continue
        try:
            if ext == ".json":
                json.loads(file.read_text(encoding="utf-8-sig"))
                good, reason = True, ""
            elif ext == ".xml":
                ET.parse(file)
                good, reason = True, ""
            else:
                parser = parsers[ext]
                if shutil.which(parser[0]) is None:
                    unsupported.append({"path": rel.as_posix(),
                                        "reason": f"syntax parser {parser[0]} unavailable"})
                    outcomes["parser unavailable"] += 1
                    continue
                good, reason = external_parse(parser, file)
        except (ValueError, OSError, UnicodeError, ET.ParseError) as exc:
            good, reason = False, str(exc)[:240]
        if good:
            outcomes["parsed OK (archived)" if historical else "parsed OK (maintained)"] += 1
        else:
            record = {"path": rel.as_posix(), "reason": reason or "syntax parser failure"}
            if historical:
                archival.append(record)
                outcomes["archived syntax exception"] += 1
            else:
                errors.append(record)
                outcomes["maintained syntax failure"] += 1
    return {"scope": "offline format/syntax only (no execution, vendor validation or dependencies)",
            "by_extension": dict(sorted(counts.items())),
            "outcomes": dict(sorted(outcomes.items())),
            "maintained_errors": errors, "archive_errors": archival,
            "not_parsed": unsupported}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parents[1])
    parser.add_argument("--output", type=Path)
    parser.add_argument("--strict-maintained", action="store_true",
                        help="Fail on parse failure in a maintained format, not historical archive")
    opts = parser.parse_args()
    if not opts.root.is_dir():
        parser.error("not a directory")
    report = inspect(opts.root.resolve())
    rendered = json.dumps(report, indent=2, ensure_ascii=False) + "\n"
    if opts.output:
        opts.output.parent.mkdir(parents=True, exist_ok=True)
        opts.output.write_text(rendered, encoding="utf-8")
    print("Source format census:", report["by_extension"])
    print("Static parse outcomes:", report["outcomes"])
    for key in ("maintained_errors", "archive_errors", "not_parsed"):
        print(f"{key}: {len(report[key])}")
        for record in report[key][:12]:
            print(f"  {record['path']}: {record['reason']}")
    return int(opts.strict_maintained and bool(report["maintained_errors"]))


if __name__ == "__main__":
    sys.exit(main())
