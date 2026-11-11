#!/usr/bin/env python3
"""Read-only Markdown HTTP and empty-table candidate inventory; never fetch URLs."""
from __future__ import annotations

import argparse
from collections import Counter
import ipaddress
import json
from pathlib import Path
import re
from urllib.parse import urlsplit

SKIP = {".git", ".venv", "venv", "node_modules", "__pycache__", ".pytest_cache"}
HTTP = re.compile(r"http://[^\s'\x22\x60)\]}]+", re.IGNORECASE)
FENCE = re.compile(r"^ {0,3}([" + re.escape(chr(96)) + r"]{3,}|~{3,})")
DOC_NETS = [ipaddress.ip_network(net) for net in
            ("192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24")]
PLACEHOLDER = re.compile(r"(?:<|>|[$}{]|your_|example|target|attacker|evil|c2-|server[-_]?ip|host[-_]?ip)",
                         re.IGNORECASE)
INLINE = re.compile(re.escape(chr(96)) + r"+[^" + re.escape(chr(96)) + r"]*" + re.escape(chr(96)) + r"+")


def classify_http(url: str) -> str:
    """Classify the text context; this is not a URL safety or reachability test."""
    raw = url.rstrip(".,;)")
    if raw.lower() == "http://":
        return "scheme-only-mention"
    if PLACEHOLDER.search(raw):
        return "illustrative-placeholder"
    try:
        host = urlsplit(raw).hostname
    except ValueError:
        return "invalid-or-unknown-reference"
    if not host:
        return "invalid-or-unknown-reference"
    host = host.lower()
    if host.endswith(".onion"):
        return "onion-reference-review"
    if host == "localhost" or host.endswith(".localhost"):
        return "loopback"
    try:
        ip = ipaddress.ip_address(host)
        if ip.is_loopback:
            return "loopback"
        if any(ip in net for net in DOC_NETS):
            return "documentation-address"
        if ip.is_link_local:
            return "link-local-metadata-or-lab"
        if ip.is_private:
            return "private-lab-address"
    except ValueError:
        if "." not in host or host.endswith((".local", ".internal", ".test")):
            return "private-service-or-test"
    return "external-public-http-needs-review"


def table_has_empty_cell(line: str) -> bool:
    """Look for Markdown table blanks, ignoring inline code and escaped pipes."""
    cleaned = INLINE.sub("INLINE_CODE", line).strip()
    if not cleaned.startswith("|") or cleaned.count("|") < 3:
        return False
    cells = re.split(r"(?<!\\)\|", cleaned)
    if cells and not cells[0]:
        cells.pop(0)
    if cells and not cells[-1]:
        cells.pop()
    if len(cells) < 2:
        return False
    return any(not cell.strip() for cell in cells)


def scan_root(root: Path) -> list[dict[str, object]]:
    """Return contextual candidates without requesting any network resource."""
    records: list[dict[str, object]] = []
    for file in sorted(root.rglob("*.md")):
        if SKIP.intersection(file.relative_to(root).parts):
            continue
        rel = file.relative_to(root).as_posix()
        try:
            lines = file.read_text(encoding="utf-8-sig").splitlines()
        except (OSError, UnicodeDecodeError) as exc:
            records.append({"path": rel, "line": 0, "kind": "read-error",
                            "classification": "manual-investigation-required",
                            "excerpt": str(exc)[:140]})
            continue
        fenced = ""
        for lineno, line in enumerate(lines, 1):
            match = FENCE.match(line)
            if match:
                marker = match.group(1)
                if not fenced:
                    fenced = marker
                elif marker[0] == fenced[0] and len(marker) >= len(fenced):
                    fenced = ""
            # Retain URLs in example code: scheme references also need classification.
            for item in HTTP.finditer(line):
                url = item.group(0).rstrip(".,;)")
                records.append({"path": rel, "line": lineno,
                                "kind": "http-reference", "classification": classify_http(url),
                                "excerpt": url[:180]})
            if not fenced and table_has_empty_cell(line):
                is_template = bool(re.search(r"template|form|report|remediation|playbook", rel, re.I))
                records.append({"path": rel, "line": lineno,
                                "kind": "empty-table-cell",
                                "classification": "template-candidate-review" if is_template
                                                  else "missing-cell-context-review",
                                "excerpt": line.strip()[:180]})
    return records


def render_markdown(records: list[dict[str, object]], limit: int) -> str:
    counts = Counter((str(x["kind"]), str(x["classification"])) for x in records)
    rows = [
        "# HTTP & Markdown Completeness Candidates",
        "",
        "**Read-only static review queue.** It has not checked live URLs, vendor versions, "
        "licenses, hardware or the correctness of an empty field.",
        "",
        "| Candidate kind | Classification | Count |",
        "|---|---|---:|",
    ]
    rows.extend(f"| {kind} | {classification} | {count} |"
                for (kind, classification), count in sorted(counts.items()))
    rows += ["", f"First {min(len(records), limit)} of {len(records)} line-level records:", ""]
    for record in records[:limit]:
        safe = str(record["excerpt"]).replace("|", "/").replace(chr(96), "'")
        rows.append(f"- {record['path']}:{record['line']} — "
                    f"{record['classification']}: {safe}")
    if len(records) > limit:
        rows += ["", f"... {len(records) - limit} additional records remain in the JSON report."]
    return "\n".join(rows) + "\n"


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parents[1])
    parser.add_argument("--output", type=Path, help="Write report to a file, else stdout")
    parser.add_argument("--format", choices=("json", "markdown"), default="json")
    parser.add_argument("--max-items", type=int, default=200)
    options = parser.parse_args()
    if options.max_items < 1:
        parser.error("--max-items must be >= 1")
    root = options.root.resolve()
    if not root.is_dir():
        parser.error("root directory does not exist")
    records = scan_root(root)
    if options.format == "json":
        result = {"scope": "offline-candidates-only", "count": len(records),
                  "counts": dict(Counter(str(item["classification"]) for item in records)),
                  "records": records}
        rendered = json.dumps(result, indent=2, ensure_ascii=False) + "\n"
    else:
        rendered = render_markdown(records, options.max_items)
    if options.output:
        options.output.write_text(rendered, encoding="utf-8")
        print(f"Wrote {len(records)} candidates to {options.output}")
    else:
        print(rendered)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
