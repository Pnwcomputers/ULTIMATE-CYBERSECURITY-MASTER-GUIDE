#!/usr/bin/env python3
"""
Auto-Changelog Generator
------------------------
Scans new commits since the last CHANGELOG.md entry and PREPENDS
a new dated section to the top — never overwrites existing history.

Usage:
    python generate_changelog.py           # new commits since last entry → prepend to CHANGELOG.md
    python generate_changelog.py 25        # last 25 commits (ignores existing CHANGELOG)
    python generate_changelog.py --all     # full history (replaces file — use with caution)
    python generate_changelog.py --dry-run # print to stdout, don't write anything
"""

import subprocess
import datetime
import re
import sys

# --- Configuration ---
DEFAULT_COMMITS_TO_SCAN = 10
OUTPUT_FILE = "CHANGELOG.md"
DRAFT_FILE  = "DRAFT_CHANGELOG.md"

CATEGORIES = {
    "✨ New Content":         ["create", "add", "new", "init"],
    "🐛 Fixes":               ["fix", "repair", "resolve", "broken", "bug", "correct"],
    "♻️ Updates & Refactors": ["update", "refactor", "move", "rename", "clean", "structure"],
    "📚 Documentation":       ["readme", "doc", "comment", "guide"],
    "🗑️ Removals":            ["remove", "delete", "prune"],
}

# ── Helpers ───────────────────────────────────────────────────────────────────

def run_git(command):
    try:
        return subprocess.check_output(
            command, shell=True, text=True, stderr=subprocess.STDOUT
        ).strip()
    except subprocess.CalledProcessError as e:
        print(f"git error: {e.output.strip()}")
        return ""

def get_last_logged_hash():
    """
    Reads existing CHANGELOG.md and returns the most recent commit hash
    found in it (backtick format: `abc1234`), or None if not found.
    """
    try:
        with open(OUTPUT_FILE, "r", encoding="utf-8") as f:
            content = f.read()
        hashes = re.findall(r"`([0-9a-f]{7,8})`", content)
        return hashes[0] if hashes else None
    except FileNotFoundError:
        return None

def parse_commits(num_commits=None, since_hash=None, scan_all=False):
    if scan_all:
        log_cmd = 'git log --pretty=format:"%h|%s|%ad" --date=short'
    elif since_hash:
        log_cmd = f'git log {since_hash}..HEAD --pretty=format:"%h|%s|%ad" --date=short'
    else:
        log_cmd = f'git log -n {num_commits} --pretty=format:"%h|%s|%ad" --date=short'

    log_output = run_git(log_cmd)

    if not log_output:
        return {}, 0

    categorized = {k: [] for k in CATEGORIES}
    categorized["⚡ Other Changes"] = []
    total = 0

    for line in log_output.split("\n"):
        if not line:
            continue
        parts = line.split("|")
        if len(parts) < 3:
            continue
        sha, msg, date = parts[0], parts[1], parts[2]
        # Skip auto-generated changelog commits and merges
        if "auto-update CHANGELOG" in msg or msg.startswith("Merge "):
            continue
        total += 1
        entry = f"- {msg} (`{sha}`)"
        matched = False
        msg_lower = msg.lower()
        for cat, keywords in CATEGORIES.items():
            if any(kw in msg_lower for kw in keywords):
                categorized[cat].append(entry)
                matched = True
                break
        if not matched:
            categorized["⚡ Other Changes"].append(entry)

    return categorized, total

def get_files_changed(num_commits=None, since_hash=None, scan_all=False):
    if scan_all:
        output = run_git("git log --name-status --pretty=format: | grep -E '^[MADR]'")
    elif since_hash:
        output = run_git(f"git diff --name-status {since_hash}..HEAD")
    else:
        output = run_git(f"git diff --name-status HEAD~{num_commits}..HEAD")

    stats = {"Modified": 0, "Added": 0, "Deleted": 0, "Renamed": 0}
    file_list = []
    seen = set()

    for line in output.split("\n"):
        if not line:
            continue
        parts = line.split("\t")
        if len(parts) < 2:
            continue
        status_code = parts[0][0]
        filename = parts[-1]
        if filename not in seen:
            file_list.append(filename)
            seen.add(filename)
        if status_code == "M": stats["Modified"] += 1
        elif status_code == "A": stats["Added"] += 1
        elif status_code == "D": stats["Deleted"] += 1
        elif status_code == "R": stats["Renamed"] += 1

    return file_list, stats

def generate_section(categorized, files, stats, commit_count):
    """Generates a single dated changelog section (no file header)."""
    today = datetime.date.today().strftime("%B %d, %Y")
    md = f"# 🔄 Change Log - {today}\n\n"
    md += "## 📊 Quick Stats\n"
    md += f"- **Commits Analyzed**: {commit_count}\n"
    md += f"- **Files Modified**: {stats['Modified']}\n"
    md += f"- **New Files**: {stats['Added']}\n"
    md += f"- **Deleted Files**: {stats['Deleted']}\n\n"
    md += "## 📝 Detailed Changes\n\n"
    for category, items in categorized.items():
        if items:
            md += f"### {category}\n"
            for item in items:
                md += f"{item}\n"
            md += "\n"
    md += "## 📂 Files Touched\n"
    if files:
        md += "<details>\n<summary>Click to view full file list</summary>\n\n"
        for f in files:
            md += f"- `{f}`\n"
        md += "\n</details>\n"
    else:
        md += "*No files changed.*\n"
    return md

def prepend_to_changelog(new_section):
    """Prepends new_section to existing CHANGELOG.md with a divider."""
    try:
        with open(OUTPUT_FILE, "r", encoding="utf-8") as f:
            existing = f.read()
    except FileNotFoundError:
        existing = ""

    divider = "\n\n---\n\n"
    combined = new_section + (divider + existing if existing else "")

    with open(OUTPUT_FILE, "w", encoding="utf-8") as f:
        f.write(combined)

# ── Main ──────────────────────────────────────────────────────────────────────

def main():
    args = sys.argv[1:]
    dry_run  = "--dry-run" in args
    scan_all = "--all" in args
    args = [a for a in args if a not in ("--dry-run", "--all")]

    # Explicit commit count overrides smart detection
    num_commits = None
    for a in args:
        if a.isdigit():
            num_commits = int(a)
            break

    # Smart mode: detect last logged hash from existing CHANGELOG
    since_hash = None
    if not scan_all and num_commits is None:
        since_hash = get_last_logged_hash()
        if since_hash:
            print(f"🔍 Scanning commits since last entry ({since_hash})…")
        else:
            print(f"🔍 No existing CHANGELOG found — scanning last {DEFAULT_COMMITS_TO_SCAN} commits…")
            num_commits = DEFAULT_COMMITS_TO_SCAN
    elif scan_all:
        print("🔍 Scanning full commit history…")
    else:
        print(f"🔍 Scanning last {num_commits} commits…")

    categorized, count = parse_commits(num_commits, since_hash, scan_all)
    file_list, stats   = get_files_changed(num_commits, since_hash, scan_all)

    if count == 0:
        print("✅ No new commits since last changelog entry. Nothing to add.")
        return

    new_section = generate_section(categorized, file_list, stats, count)

    if dry_run:
        print("\n── DRY RUN ──\n")
        print(new_section)
        return

    if scan_all:
        # --all replaces the file entirely (explicit intent)
        with open(OUTPUT_FILE, "w", encoding="utf-8") as f:
            f.write(new_section)
        print(f"✅ CHANGELOG.md replaced with full history ({count} commits)")
    else:
        prepend_to_changelog(new_section)
        print(f"✅ Prepended {count} new commits to {OUTPUT_FILE}")

if __name__ == "__main__":
    main()
