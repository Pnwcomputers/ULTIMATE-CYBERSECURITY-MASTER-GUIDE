#!/usr/bin/env python3
"""Inspect discoverability of Markdown pages without network requests or writes."""
from __future__ import annotations

import argparse
from collections import defaultdict, deque
from pathlib import Path
import posixpath
import re
from urllib.parse import unquote, urlsplit

SKIP = {".git", ".venv", "venv", "node_modules", "__pycache__"}
LINK = re.compile(r"!?\[[^\]\n]+\]\(([^)\n]+)\)")
HTML_LINK = re.compile(r'href\s*=\s*["\x27]([^"\x27]+)["\x27]', re.I)
REFERENCE = re.compile(r"^\s*\[[^\]]+\]:\s*(\S+)", re.M)
FENCE = re.compile(r"^\s{0,3}(`{3,}|~{3,})")
PRIMARY = {"README.md", "START_HERE.md", "ultimate_cybersecurity_master_guide.md",
           "ENHANCED_MASTER_GUIDE.md", "SPECIALIZED_TOPICS_GUIDE.md"}


def all_docs(root: Path) -> set[str]:
    return {
        path.relative_to(root).as_posix()
        for path in root.rglob("*.md")
        if not SKIP.intersection(path.relative_to(root).parts)
    }


def destinations(source: str, content: str, documents: set[str]) -> set[str]:
    lines = []
    marker = None
    for line in content.splitlines():
        match = FENCE.match(line)
        if match:
            fence = match.group(1)
            if marker is None:
                marker = fence
            elif marker[0] == fence[0] and len(fence) >= len(marker):
                marker = None
            continue
        if marker is None:
            lines.append(line)
    text = "\n".join(lines)
    targets = set()
    hrefs = LINK.findall(text) + HTML_LINK.findall(text) + REFERENCE.findall(text)
    for dest in hrefs:
        dest = dest.strip().strip("<>")
        if not dest or dest.startswith(("#", "//")) or ":" in dest.split("/", 1)[0]:
            continue
        # A quoted Markdown link title is not part of the path.
        dest = re.sub(r'\s+["\x27][^"\x27]*["\x27]$', "", dest)
        try:
            url_path = unquote(urlsplit(dest).path)
        except ValueError:
            continue
        if not url_path or url_path.startswith("/"):
            continue
        relative = posixpath.normpath(posixpath.join(posixpath.dirname(source), url_path))
        if relative in documents:
            targets.add(relative)
        elif relative + "/README.md" in documents:
            targets.add(relative + "/README.md")
    return targets


def analyze(root: Path):
    docs = all_docs(root)
    references: dict[str, set[str]] = {}
    inbound: dict[str, set[str]] = defaultdict(set)
    for source in sorted(docs):
        references[source] = destinations(source, (root / source).read_text(encoding="utf-8-sig"), docs)
        if source == "DOCUMENTATION_INDEX.md":
            continue  # Global fall-through catalog does not prove contextual discoverability.
        for target in references[source]:
            if target != source:
                inbound[target].add(source)

    seen = set(PRIMARY & docs)
    queue = deque(sorted(seen))
    while queue:
        source = queue.popleft()
        for target in references[source]:
            if target != "DOCUMENTATION_INDEX.md" and target not in seen:
                seen.add(target)
                queue.append(target)
    candidates = sorted(docs - seen - {"DOCUMENTATION_INDEX.md"})
    no_inbound = sorted(p for p in docs if not inbound[p] and p not in PRIMARY
                        and p != "DOCUMENTATION_INDEX.md")
    return docs, references, candidates, no_inbound


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--max-per-section", type=int, default=12)
    parser.add_argument("--require-discovery", action="store_true", help="Fail if any Markdown pages lack a contextual navigation path")
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[1]
    docs, edges, unreachable, no_inbound = analyze(root)
    print(f"Markdown pages: {len(docs)}, contextual link edges: {sum(len(v) for v in edges.values())}.")
    print(f"Pages not reachable from the five main entrypoints without the complete index: {len(unreachable)}.")
    print(f"Pages without inbound Markdown references (except the complete index): {len(no_inbound)}.")
    print("These are review candidates; some archival, template, test, and policy pages may be intentionally unlisted.")
    grouped: dict[str, list[str]] = defaultdict(list)
    for path in no_inbound:
        group = path.split("/")[0] if "/" in path else "(root)"
        grouped[group].append(path)
    for group in sorted(grouped):
        values = grouped[group]
        print(f"\n{group}: {len(values)} page(s) without an in-context inbound link")
        for value in values[:args.max_per_section]:
            print("  - " + value)
        if len(values) > args.max_per_section:
            print(f"  ... and {len(values) - args.max_per_section} more")
    if args.require_discovery and (unreachable or no_inbound):
        print("Navigation gate failed: cross-link the pages listed above; the global catalog alone is insufficient.")
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
