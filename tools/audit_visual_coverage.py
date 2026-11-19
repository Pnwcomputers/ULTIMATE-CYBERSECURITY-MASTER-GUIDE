#!/usr/bin/env python3
"""Audit all Markdown and SVG assets offline, without claiming semantic validity.

This checks every Markdown document and every SVG in the checkout, not a
handpicked list of guides. It distinguishes referenced images from images
actually embedded in a topic. It does not generate/modify figures.
"""
from __future__ import annotations

import argparse
from collections import Counter, defaultdict
from pathlib import Path
import json
import posixpath
import re
import sys
from urllib.parse import unquote, urlsplit
from xml.etree import ElementTree as ET

SKIP = {".git", ".venv", "venv", "node_modules", "__pycache__", ".pytest_cache"}
MARKDOWN_IMAGE = re.compile(r"!\[[^\]\n]*\]\((<[^>]+>|[^\s)]+)(?:\s+[\"'][^\"']*[\"'])?\)", re.I)
MARKDOWN_LINK = re.compile(r"(?<!!)\[[^\]\n]*\]\((<[^>]+>|[^\s)]+)(?:\s+[\"'][^\"']*[\"'])?\)", re.I)
HTML_IMG = re.compile(r"<img\b[^>]*\bsrc\s*=\s*[\"']([^\"']+)[\"']", re.I)
HTML_LINK = re.compile(r"<a\b[^>]*\bhref\s*=\s*[\"']([^\"']+)[\"']", re.I)
ALT_EMPTY = re.compile(r"!\[\s*\]\((?:<[^>]+>|[^\s)]+)", re.I)
SVG_NS = "{http://www.w3.org/2000/svg}"


def is_visible(path: Path, root: Path) -> bool:
    return not SKIP.intersection(path.relative_to(root).parts)


def normalize(source: str, value: str) -> str | None:
    """Return a local, repository-relative link target, or None for nonlocal URLs."""
    value = value.strip().strip("<>")
    if not value or value.startswith(("#", "//")):
        return None
    try:
        parsed = urlsplit(value)
    except ValueError:
        return None
    if parsed.scheme or parsed.netloc or not parsed.path:
        return None
    return posixpath.normpath(posixpath.join(posixpath.dirname(source),
                                            unquote(parsed.path)))


def visual_audit(root: Path) -> dict[str, object]:
    root = root.resolve()
    docs = sorted(p for p in root.rglob("*.md") if p.is_file() and is_visible(p, root))
    svgs = sorted(p for p in root.rglob("*.svg") if p.is_file() and is_visible(p, root))
    graphics = {p.relative_to(root).as_posix() for p in svgs}
    refs: dict[str, set[str]] = defaultdict(set)
    embeds: dict[str, set[str]] = defaultdict(set)
    broken_images: list[dict[str, str]] = []
    empty_alt: list[str] = []
    unreadable: list[str] = []
    section_pages: Counter[str] = Counter()
    section_with_visual: Counter[str] = Counter()

    for doc in docs:
        rel = doc.relative_to(root).as_posix()
        section = rel.split("/")[0] if "/" in rel else "(root)"
        section_pages[section] += 1
        try:
            source = doc.read_text(encoding="utf-8-sig")
        except (UnicodeError, OSError):
            unreadable.append(rel)
            continue
        if ALT_EMPTY.search(source):
            empty_alt.append(rel)
        illustrations = (MARKDOWN_IMAGE.findall(source) + HTML_IMG.findall(source))
        links = (MARKDOWN_LINK.findall(source) + HTML_LINK.findall(source))
        if illustrations:
            section_with_visual[section] += 1
        for value in links + illustrations:
            normalized = normalize(rel, value)
            if normalized is not None and normalized.endswith(".svg"):
                refs[normalized].add(rel)
        for value in illustrations:
            normalized = normalize(rel, value)
            if normalized is None:
                continue
            if normalized.lower().endswith((".svg", ".png", ".jpg", ".jpeg", ".webp", ".gif")):
                embeds[normalized].add(rel)
                if not (root / normalized).is_file():
                    broken_images.append({"document": rel, "image": normalized})

    invalid: list[dict[str, str]] = []
    metadata_missing: list[dict[str, str]] = []
    for path in svgs:
        rel = path.relative_to(root).as_posix()
        try:
            svg = ET.parse(path).getroot()
        except (ET.ParseError, OSError) as exc:
            invalid.append({"path": rel, "reason": f"unreadable SVG XML: {exc}"})
            continue
        if svg.tag != SVG_NS + "svg":
            invalid.append({"path": rel, "reason": "wrong SVG root element"})
        fields = []
        title = svg.find(SVG_NS + "title")
        description = svg.find(SVG_NS + "desc")
        if title is None or not "".join(title.itertext()).strip():
            fields.append("title")
        if description is None or not "".join(description.itertext()).strip():
            fields.append("desc")
        if svg.attrib.get("role") != "img":
            fields.append("role=img")
        if fields:
            metadata_missing.append({"path": rel, "fields": ", ".join(fields)})
        for node in svg.iter():
            local_name = node.tag.rsplit("}", 1)[-1].lower()
            if local_name in {"script", "foreignobject"}:
                invalid.append({"path": rel, "reason": "executable or embedded-content element"})
            for key, value in node.attrib.items():
                attr = key.rsplit("}", 1)[-1].lower()
                if attr.startswith("on"):
                    invalid.append({"path": rel, "reason": "event-handler attribute"})
                if attr == "href" and re.match(r"(?i)^(?:https?:|data:|javascript:|//)", value.strip()):
                    invalid.append({"path": rel, "reason": "external or active href"})
    unembedded = sorted(graphics - set(embeds))
    unreferenced = sorted(graphics - set(refs) - set(embeds))
    sections = {
        key: {"markdown": count, "with_any_image": section_with_visual[key]}
        for key, count in sorted(section_pages.items())
    }
    return {
        "scope": "entire checkout, offline structural evidence only",
        "counts": {
            "markdown": len(docs), "svg": len(svgs),
            "svg_embedded": len(graphics & set(embeds)),
            "svg_linked_without_embedding": len((graphics & set(refs)) - set(embeds)),
            "svg_neither_linked_nor_embedded": len(unreferenced),
            "svg_missing_accessibility_metadata": len(metadata_missing),
            "markdown_with_empty_image_alt": len(empty_alt),
            "broken_local_image_embeds": len(broken_images),
            "svg_invalid_or_unsafe": len(invalid),
            "unreadable_markdown": len(unreadable),
        },
        "sections": sections,
        "unembedded_svgs": unembedded,
        "unreferenced_svgs": unreferenced,
        "missing_accessibility": metadata_missing,
        "empty_alt_documents": empty_alt,
        "broken_images": broken_images,
        "invalid_svg": invalid,
        "unreadable_markdown": unreadable,
    }


def markdown_report(report: dict[str, object], max_items: int = 30) -> str:
    counts = report["counts"]
    lines = ["# Whole-Repository Visual Coverage Audit", "",
             "Offline structural checks only. An image being linked, accessible or",
             "well-formed does **not** establish the accuracy of its technical claims.",
             "", "## Inventory", "", "| Category | Count |", "|---|---:|"]
    lines += [f"| {key.replace('_', ' ')} | {value} |" for key, value in counts.items()]
    lines += ["", "## Markdown Visual Coverage By Section", "",
              "| Area | Markdown docs | Docs with an image |",
              "|---|---:|---:|"]
    lines += [f"| {key} | {vals['markdown']} | {vals['with_any_image']} |"
              for key, vals in report["sections"].items()]
    for key, heading in [
        ("unembedded_svgs", "SVGs Not Yet Embedded"),
        ("unreferenced_svgs", "SVGs Without Any Markdown Reference"),
        ("missing_accessibility", "SVG Accessibility Metadata Candidates"),
        ("empty_alt_documents", "Markdown Documents With Empty Image Alt Text"),
        ("broken_images", "Broken Local Image Embeds"),
        ("invalid_svg", "Malformed Or Unsafe SVGs")]:
        values = report[key]
        lines += ["", f"## {heading}", "", f"{len(values)} candidate(s).", ""]
        for item in values[:max_items]:
            lines.append("- " + (item if isinstance(item, str) else
                                 ", ".join(f"{k}: {v}" for k, v in item.items())))
        if len(values) > max_items:
            lines.append(f"- … {len(values) - max_items} additional entries in the JSON artifact")
    lines += ["", "## Evidence Limits", "",
              "- Counts cover the checked-out repository, not external images or historical branches.",
              "- Visual accuracy, device specifications, diagram semantics, licenses and live deployment require independent verification.",
              "- Diagram discovery is not placement approval; choose a relevant chapter and explanatory caption before embedding.",
              "- Empty-alt flags may intentionally represent purely decorative images; assess context.",
              ""]
    return "\n".join(lines)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parents[1])
    parser.add_argument("--format", choices=["markdown", "json"], default="markdown")
    parser.add_argument("--output", type=Path)
    parser.add_argument("--max-items", type=int, default=35)
    parser.add_argument("--strict", action="store_true",
                        help="Fail on broken local image paths, malformed/unsafe/inaccessible SVGs and unreadable Markdown")
    opts = parser.parse_args()
    if opts.max_items < 1:
        parser.error("--max-items must be positive")
    if not opts.root.is_dir():
        parser.error("repository root is not a directory")
    report = visual_audit(opts.root)
    rendered = (json.dumps(report, indent=2, ensure_ascii=False) + "\n"
                if opts.format == "json"
                else markdown_report(report, opts.max_items))
    if opts.output:
        opts.output.parent.mkdir(parents=True, exist_ok=True)
        opts.output.write_text(rendered, encoding="utf-8")
    else:
        print(rendered)
    fails = report["counts"]
    return int(opts.strict and any(fails[k] for k in (
        "broken_local_image_embeds", "svg_invalid_or_unsafe",
        "svg_missing_accessibility_metadata", "unreadable_markdown")))


if __name__ == "__main__":
    sys.exit(main())
