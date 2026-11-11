#!/usr/bin/env python3
"""Read-only, offline QA inventory. Does not certify live links, facts or labs."""
from __future__ import annotations

import argparse
import ast
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
import re
import shutil
import subprocess
import sys

SKIP = {".git", ".venv", "venv", "node_modules", "__pycache__", ".pytest_cache", ".mypy_cache"}
MARKER = re.compile(r"^(?:\s*(?:[-*]\s+)?(?:#+\s+)?(?:TODO|TBD|FIXME)\s*[:—-]|.*\bCOMING SOON\b|.*\bTO BE (?:RECORDED|ASSIGNED|CONFIRMED|ADDED)\b)", re.I)
LINK = re.compile(r"\[(?:link|CVE-XXXX-XXXX)\](?!\()", re.I)
FENCE = re.compile(r"^ {0,3}(" + r"(?:\x60){3,}|~{3,}" + r")")


def inspect(root: Path):
    counts, errors, candidates = Counter(), [], []
    bash = shutil.which("bash")
    for path in sorted(root.rglob("*")):
        if not path.is_file() or SKIP.intersection(path.relative_to(root).parts):
            continue
        rel, ext = path.relative_to(root).as_posix(), path.suffix.lower()
        counts["files"] += 1
        if ext == ".md":
            counts["markdown"] += 1
            try:
                lines = path.read_text(encoding="utf-8-sig").splitlines()
            except (OSError, UnicodeDecodeError) as exc:
                errors.append((rel, "read error: " + str(exc)))
                continue
            fence = ""
            for number, line in enumerate(lines, 1):
                match = FENCE.match(line)
                if match:
                    token = match.group(1)
                    if not fence:
                        fence = token
                    elif fence[0] == token[0] and len(token) >= len(fence):
                        fence = ""
                    continue
                if fence:
                    continue
                labels = []
                if MARKER.search(line):
                    labels.append("incomplete-marker")
                if LINK.search(line):
                    labels.append("unresolved-label")
                # Ignore pipe operators within inline code (e.g. Wireshark ||),
                # and do not mistake legitimate non-table prose for empty cells.
                cleaned = re.sub(r"`+[^`]*`+", "INLINE_CODE", line)
                if cleaned.lstrip().startswith("|") and cleaned.count("|") >= 3:
                    cells = cleaned.strip().strip("|").split("|")
                    if any(not cell.strip() for cell in cells):
                        labels.append("empty-table-cell")
                if "http://" in line:
                    labels.append("plaintext-http")
                for label in labels:
                    candidates.append((rel, number, label, line.strip()[:140]))
        elif ext == ".py":
            counts["python"] += 1
            try:
                ast.parse(path.read_text(encoding="utf-8-sig"), filename=rel)
            except SyntaxError as exc:
                if rel.startswith("Scripts/GO/"):
                    candidates.append((rel, exc.lineno or 0, "legacy-python2-syntax", str(exc).splitlines()[0][:140]))
                else:
                    errors.append((rel, "python syntax: " + str(exc).splitlines()[0]))
            except (OSError, UnicodeDecodeError) as exc:
                errors.append((rel, "python read error: " + str(exc).splitlines()[0]))
        elif ext == ".sh":
            counts["shell"] += 1
            if bash:
                try:
                    result = subprocess.run([bash, "-n", str(path)], capture_output=True,
                                            text=True, timeout=5, check=False)
                    if result.returncode:
                        errors.append((rel, "bash syntax: " + (result.stderr or result.stdout).strip()[:160]))
                except (OSError, subprocess.TimeoutExpired) as exc:
                    errors.append((rel, "bash check: " + str(exc)))
            else:
                errors.append((rel, "bash check unavailable"))
        elif ext == ".ps1":
            counts["powershell-not-parsed"] += 1
    return counts, errors, candidates


def render(root, counts, errors, candidates, max_items):
    stamp = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    found = Counter(item[2] for item in candidates)
    lines = [
        "# Offline Repository Quality Candidate Inventory", "",
        "Generated: " + stamp + " | Root: " + root.name, "",
        "**Scope:** Static Python AST, Bash syntax, and candidate Markdown markers. "
        "**Not** a live-link, hardware, claims, code-behavior, or security certification.", "",
        "## Inventory", "", "| Type | Count |", "|---|---:|",
    ]
    for key in ("files", "markdown", "python", "shell", "powershell-not-parsed"):
        lines.append("| " + key + " | " + str(counts[key]) + " |")
    lines += ["", "Counts reflect scanned filesystem entries, not necessarily tracked Git paths.", "",
              "## Syntax Findings", "", "Flagged: " + str(len(errors)), ""]
    lines.extend("- " + p + " — " + e.replace("|", "/") for p, e in errors[:max_items])
    if not errors:
        lines.append("- No AST/Bash parser failures in scanned files; runtime behavior remains unverified.")
    if len(errors) > max_items:
        lines.append("- Additional syntax findings omitted: " + str(len(errors) - max_items))
    lines += ["", "## Placeholder & Content Review Candidates", "",
              "Markers do not automatically indicate defects; forms and examples may be intentional. "
              "Legacy Python 2 syntax in Scripts/GO is flagged here rather than treated as a modern Python 3 runtime failure.",
              "", "| Candidate | Count |", "|---|---:|"]
    for kind, qty in sorted(found.items()):
        lines.append("| " + kind + " | " + str(qty) + " |")
    lines += ["", "First " + str(max_items) + " candidates:", ""]
    for p, n, kind, value in candidates[:max_items]:
        lines.append("- " + p + ":" + str(n) + " — " + kind + ": " + value.replace("|", "/"))
    if len(candidates) > max_items:
        lines.append("- Additional candidates omitted: " + str(len(candidates) - max_items))
    lines += ["", "## Mandatory Manual Checks", "",
              "- Check all external URLs and versioned vendor claims against authoritative pages.",
              "- Run samples only in isolated, permitted environments and record outputs and dependencies.",
              "- Review blanks and placeholders in context; never invent client data, credentials or evidence.",
              "- Review PowerShell separately; it is counted but not parsed here.",
              "- See Documentation/REPOSITORY-VERIFICATION-PROTOCOL.md for closure standards.", ""]
    return "\n".join(lines)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parents[1])
    parser.add_argument("--output", type=Path)
    parser.add_argument("--max-items", type=int, default=100)
    parser.add_argument("--strict-syntax", action="store_true")
    args = parser.parse_args()
    if args.max_items < 1:
        parser.error("--max-items must be positive")
    root = args.root.resolve()
    if not root.is_dir():
        parser.error("root directory does not exist")
    counts, errors, candidates = inspect(root)
    summary = render(root, counts, errors, candidates, args.max_items)
    if args.output:
        args.output.write_text(summary, encoding="utf-8")
        print("Wrote " + str(args.output))
    else:
        print(summary)
    return 1 if errors and args.strict_syntax else 0


if __name__ == "__main__":
    sys.exit(main())
