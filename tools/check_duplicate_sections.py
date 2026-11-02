#!/usr/bin/env python3
"""Flag repeated Markdown sections within individual repository documents.

This checks same-page headings and exact repeated prose; it intentionally does
not treat similar sections in different files as duplicates. It is a guardrail,
not a substitute for editorial review of paraphrased repetition.
"""
from __future__ import annotations

import argparse
from collections import defaultdict
from pathlib import Path
import re
import sys

HEADING = re.compile(r"^ {0,3}(#{1,6})[ \t]+(.+?)[ \t]*#*[ \t]*$")
FENCE = re.compile(r"^ {0,3}((?:\x60){3,}|~{3,})")
CORE = {"purpose", "function", "goal", "when to use"}


def normalize(value: str) -> str:
    value = re.sub(r"\[([^\]]+)\]\([^)]+\)", r"\1", value)
    value = re.sub(r"<[^>]+>", "", value)
    return re.sub(r"[^a-z0-9]+", " ", value.casefold()).strip()


def audit(path: Path) -> list[tuple[int, str]]:
    lines = path.read_text(encoding="utf-8-sig").splitlines()
    headings = []
    paragraphs = defaultdict(list)
    paragraph = []
    paragraph_start = 0
    in_fence = False
    fence_mark = ""
    scopes = []
    occurrence = 0

    def finish_paragraph():
        nonlocal paragraph
        if paragraph:
            body = normalize(" ".join(paragraph))
            if len(body) >= 150 and len(body.split()) >= 18:
                paragraphs[body].append(paragraph_start)
            paragraph = []

    for number, line in enumerate(lines, 1):
        fence = FENCE.match(line)
        if fence:
            mark = fence.group(1)
            if not in_fence:
                finish_paragraph()
                in_fence, fence_mark = True, mark
            elif mark[0] == fence_mark[0] and len(mark) >= len(fence_mark):
                in_fence, fence_mark = False, ""
            continue
        if in_fence:
            continue

        match = HEADING.match(line)
        if match:
            finish_paragraph()
            level = len(match.group(1))
            title = normalize(match.group(2))
            while scopes and scopes[-1][0] >= level:
                scopes.pop()
            parent = scopes[-1][1] if scopes else 0
            occurrence += 1
            if title:
                headings.append((level, title, number, parent))
            scopes.append((level, occurrence))
            continue
        if not line.strip() or re.match(r"^\s*(?:[-*+] |\d+\. |[|>] |<| {4})", line):
            finish_paragraph()
            continue
        if not paragraph:
            paragraph_start = number
        paragraph.append(line.strip())
    finish_paragraph()

    problems = []
    groups = defaultdict(list)
    for level, title, line, parent in headings:
        key = ("core", title) if title in CORE else (
            ("page", title) if level <= 2 else ("subsection", parent, title)
        )
        groups[key].append(line)

    for key, positions in groups.items():
        if len(positions) > 1:
            label = key[-1]
            problems.append((positions[0], f"Repeated section '{label}' at lines "
                             + ", ".join(map(str, positions))))
    for passage, positions in paragraphs.items():
        if len(positions) > 1:
            problems.append((positions[0], "Repeated prose at lines "
                             + ", ".join(map(str, positions))
                             + f": {passage[:85]}..."))
    return sorted(problems)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("root", type=Path, nargs="?", default=Path("."))
    parser.add_argument("--report-only", action="store_true",
                        help="Show findings without failing (for triage)")
    args = parser.parse_args()
    files = sorted(p for p in args.root.rglob("*.md")
                   if ".git" not in p.parts and "node_modules" not in p.parts)
    flagged = 0
    issues = 0
    for path in files:
        found = audit(path)
        if found:
            flagged += 1
            issues += len(found)
            for line, reason in found:
                print(f"{path}:{line}: {reason}")
    print(f"Scanned {len(files)} Markdown files; {issues} potential duplicates "
          f"in {flagged} files.")
    return 0 if args.report_only or not issues else 1


if __name__ == "__main__":
    sys.exit(main())
