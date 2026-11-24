#!/usr/bin/env python3
"""Search this repository's text, documentation, and filenames without dependencies."""

from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
TEXT_EXTENSIONS = {
    ".adoc", ".cfg", ".conf", ".csv", ".ini", ".json", ".md", ".markdown",
    ".ps1", ".py", ".rst", ".sh", ".toml", ".txt", ".xml", ".yaml", ".yml",
}
SKIP_DIRECTORIES = {".git", ".venv", "node_modules", "__pycache__"}
MAX_TEXT_BYTES = 2 * 1024 * 1024


def query_words(query: str) -> list[str]:
    """Return distinct, lowercase search terms while preserving their order."""
    return list(dict.fromkeys(re.findall(r"[a-z0-9]+", query.casefold())))


def positive_limit(value: str) -> int:
    try:
        parsed = int(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError("limit must be a whole number") from exc
    if parsed < 1 or parsed > 100:
        raise argparse.ArgumentTypeError("limit must be between 1 and 100")
    return parsed


def in_section(relative_path: str, section: str | None) -> bool:
    if not section:
        return True
    prefix = section.replace("\\", "/").strip("/").casefold()
    path = relative_path.casefold()
    return path == prefix or path.startswith(prefix + "/")


def matching_line(lines: list[str], terms: list[str], phrase: str) -> tuple[int, str, int]:
    """Choose the most informative line and return its number, text, and score."""
    best_line = 0
    best_text = ""
    best_score = 0
    for number, raw_line in enumerate(lines, start=1):
        line = raw_line.strip()
        if not line:
            continue
        lowered = line.casefold()
        hits = sum(1 for term in terms if term in lowered)
        if not hits:
            continue
        score = hits + (4 if line.startswith("#") else 0)
        if phrase and phrase in lowered:
            score += 5
        if score > best_score:
            best_line, best_text, best_score = number, line, score
    return best_line, best_text, best_score


def shorten(text: str, terms: list[str], width: int = 180) -> str:
    if len(text) <= width:
        return text
    lowered = text.casefold()
    positions = [lowered.find(term) for term in terms if lowered.find(term) >= 0]
    start = max(0, min(positions) - 65) if positions else 0
    end = min(len(text), start + width)
    if start:
        return "…" + text[start:end].rstrip() + ("…" if end < len(text) else "")
    return text[:width].rstrip() + "…"


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Find relevant repository guides, notes, scripts, and other text files."
    )
    parser.add_argument("query", nargs="+", help='words or a quoted phrase, e.g. "printer dots"')
    parser.add_argument(
        "--section",
        help="limit results to a folder, such as Documentation or CaseStudies",
    )
    parser.add_argument(
        "--limit",
        type=positive_limit,
        default=20,
        help="maximum number of results to print (1–100; default: 20)",
    )
    parser.add_argument(
        "--all-terms",
        action="store_true",
        help="show only files containing every query word",
    )
    parser.add_argument(
        "--filenames-only",
        action="store_true",
        help="search paths and filenames without reading file contents",
    )
    args = parser.parse_args()

    query = " ".join(args.query).strip()
    terms = query_words(query)
    if not terms:
        parser.error("query must contain at least one letter or number")
    phrase = " ".join(query.casefold().split())

    results: list[tuple[int, str, int, str]] = []
    for path in ROOT.rglob("*"):
        if not path.is_file():
            continue
        try:
            relative = path.relative_to(ROOT).as_posix()
        except ValueError:
            continue
        if any(part in SKIP_DIRECTORIES for part in path.parts):
            continue
        if not in_section(relative, args.section):
            continue

        path_lower = relative.casefold()
        matched_terms = {term for term in terms if term in path_lower}
        score = sum(8 for term in terms if term in path_lower)
        lines: list[str] = []

        if not args.filenames_only and path.suffix.casefold() in TEXT_EXTENSIONS:
            try:
                if path.stat().st_size <= MAX_TEXT_BYTES:
                    lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
            except OSError:
                continue
            text_lower = "\n".join(lines).casefold()
            matched_terms.update(term for term in terms if term in text_lower)
            score += sum(min(text_lower.count(term), 8) for term in terms)
            if phrase and phrase in text_lower:
                score += 10

        if args.all_terms and len(matched_terms) != len(terms):
            continue
        if not matched_terms:
            continue

        line_number, snippet, line_score = matching_line(lines, terms, phrase)
        score += line_score
        if not snippet:
            snippet = "Filename match; file contents were not searched."
        results.append((score, relative, line_number, shorten(snippet, terms)))

    results.sort(key=lambda item: (-item[0], item[1].casefold()))
    if not results:
        scope = f" in {args.section}" if args.section else ""
        print(f"No matches for {query!r}{scope}.")
        return 1

    print(f"Search: {query} ({len(results)} matches; showing up to {args.limit})")
    for score, relative, line_number, snippet in results[: args.limit]:
        location = f"{relative}:{line_number}" if line_number else relative
        print(f"\n{location}  [score {score}]")
        print(f"  {snippet}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
