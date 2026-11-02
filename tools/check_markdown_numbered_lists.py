#!/usr/bin/env python3
"""Check numbered Markdown navigation and lists throughout the repository.

A list starting with 2. (or higher) cannot interrupt a paragraph in CommonMark:
without a blank separator, GitHub may show literal text instead of an ordered
list. The check also verifies continuous chapter numbering in the three master
guides' tables of contents.
"""
from __future__ import annotations

import argparse
from pathlib import Path
import re

FENCE = re.compile(r"^ {0,3}((?:\x60){3,}|~{3,})")
ORDERED = re.compile(r"^( {0,3})(\d{1,4})[.)] +\S")
PART_LINK = re.compile(r"^\s*\*\*\[PART\s+(?:[IVX]+|\d+)[^]]*\]\([^)]+\)\*\*\s*$", re.I)
TOC_FILES = {
    "ultimate_cybersecurity_master_guide.md",
    "ENHANCED_MASTER_GUIDE.md",
    "SPECIALIZED_TOPICS_GUIDE.md",
}


def audit(path: Path) -> list[tuple[int, str]]:
    lines = path.read_text(encoding="utf-8-sig").splitlines()
    problems = []
    in_fence = False
    fence_mark = ""
    for i, line in enumerate(lines):
        mark = FENCE.match(line)
        if mark:
            token = mark.group(1)
            if not in_fence:
                in_fence, fence_mark = True, token
            elif token[0] == fence_mark[0] and len(token) >= len(fence_mark):
                in_fence, fence_mark = False, ""
            continue
        if in_fence:
            continue
        m = ORDERED.match(line)
        if not m or i == 0:
            continue
        indent, ordinal = len(m.group(1)), int(m.group(2))
        previous = lines[i - 1].strip()
        if PART_LINK.match(previous):
            problems.append((i + 1, "Numbered list touches a linked Part label; "
                             "insert a blank line"))
        elif previous:
            prev_list = ORDERED.match(lines[i - 1])
            if prev_list and len(prev_list.group(1)) == indent:
                previous_number = int(prev_list.group(2))
                if ordinal != previous_number + 1:
                    problems.append((i + 1, "Consecutive numbered list items out "
                                     "of order: " + str(previous_number) + " -> "
                                     + str(ordinal)))
            elif ordinal > 1 and not (
                # Wrapped text indented under a preceding list item legitimately
                # separates that item from the next numbered entry.
                len(lines[i - 1]) - len(lines[i - 1].lstrip(" \t")) > indent
                or previous.startswith(("#", ">", "|", "<", "---", "***", "___"))
                or re.match(r"^[-*+]\s+", previous)
                or previous.endswith("\\")
            ):
                problems.append((i + 1, "Ordered list starts with " + str(ordinal)
                                 + " immediately after a paragraph; "
                                 "CommonMark needs a blank separator"))

    if path.name in TOC_FILES:
        begin = next((i for i, line in enumerate(lines)
                      if re.match(r"^#{1,2} (?:MASTER )?TABLE OF CONTENTS\b", line)), -1)
        end = next((i for i in range(begin + 1, len(lines))
                    if lines[i].startswith("## 🎯 Purpose")), -1)
        if begin < 0 or end < 0:
            problems.append((1, "Could not locate main table of contents"))
        else:
            expected = 1
            for i in range(begin + 1, end):
                m = re.match(r"^(\d+)\. \[", lines[i])
                if m:
                    actual = int(m.group(1))
                    if actual != expected:
                        problems.append((i + 1, "Master TOC numbering: expected "
                                         + str(expected) + ", found " + str(actual)))
                    expected += 1
    return problems


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("root", nargs="?", type=Path, default=Path("."))
    parser.add_argument("--report-only", action="store_true")
    args = parser.parse_args()
    count = flagged = total = 0
    for path in sorted(args.root.rglob("*.md")):
        if any(part in (".git", "node_modules") for part in path.parts):
            continue
        count += 1
        found = audit(path)
        if found:
            flagged += 1
            for line, message in found:
                total += 1
                print(f"{path}:{line}: {message}")
    print(f"Checked {count} Markdown files; {total} potential numbered-list "
          f"formatting issues in {flagged} files.")
    return 0 if total == 0 or args.report_only else 1


if __name__ == "__main__":
    raise SystemExit(main())
