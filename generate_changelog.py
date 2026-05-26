#!/usr/bin/env python3
"""
Auto-Changelog Generator
------------------------
Scans the last N commits from the git log and generates a 
Markdown-formatted summary of changes, categorized by type.

Usage:
    python generate_changelog.py           # last 10 commits → DRAFT_CHANGELOG.md
    python generate_changelog.py 25        # last 25 commits → DRAFT_CHANGELOG.md
    python generate_changelog.py --all     # full history    → DRAFT_CHANGELOG.md
    python generate_changelog.py --output CHANGELOG.md       # write directly to CHANGELOG.md
    python generate_changelog.py 25 --output CHANGELOG.md   # combine both
"""

import subprocess
import datetime
import re
import sys

# --- Configuration ---
DEFAULT_COMMITS_TO_SCAN = 10  # Default number of commits to look back
OUTPUT_FILE = "DRAFT_CHANGELOG.md"

# Keywords to categorize commits
CATEGORIES = {
    "✨ New Content": ["create", "add", "new", "init"],
    "🐛 Fixes": ["fix", "repair", "resolve", "broken", "bug", "correct"],
    "♻️ Updates & Refactors": ["update", "refactor", "move", "rename", "clean", "structure"],
    "📚 Documentation": ["readme", "doc", "comment", "guide"],
    "🗑️ Removals": ["remove", "delete", "prune"]
}

def run_git_command(command):
    """Runs a git command and returns the output string."""
    try:
        result = subprocess.check_output(command, shell=True, text=True, stderr=subprocess.STDOUT)
        return result.strip()
    except subprocess.CalledProcessError as e:
        print(f"Error running git command: {e.output}")
        return ""

def parse_commits(num_commits, scan_all=False):
    """Gets commit messages and categorizes them."""
    if scan_all:
        log_output = run_git_command('git log --pretty=format:"%h|%s|%ad" --date=short')
    else:
        log_output = run_git_command(f'git log -n {num_commits} --pretty=format:"%h|%s|%ad" --date=short')
    
    if not log_output:
        return {}, 0

    categorized = {k: [] for k in CATEGORIES.keys()}
    categorized["⚡ Other Changes"] = []  # Fallback category
    
    total_commits = 0

    for line in log_output.split('\n'):
        if not line: continue
        total_commits += 1
        parts = line.split('|')
        if len(parts) < 3: continue
        
        sha, msg, date = parts[0], parts[1], parts[2]
        entry = f"- {msg} (`{sha}`)"
        
        # Categorize
        matched = False
        msg_lower = msg.lower()
        
        for cat, keywords in CATEGORIES.items():
            if any(keyword in msg_lower for keyword in keywords):
                categorized[cat].append(entry)
                matched = True
                break
        
        if not matched:
            categorized["⚡ Other Changes"].append(entry)

    return categorized, total_commits

def get_files_changed(num_commits, scan_all=False):
    """Gets a list of files changed in the range."""
    if scan_all:
        output = run_git_command("git log --name-status --pretty=format: | grep -E '^[MADR]'")
    else:
        output = run_git_command(f"git diff --name-status HEAD~{num_commits}..HEAD")
    
    stats = {
        "Modified": 0,
        "Added": 0,
        "Deleted": 0,
        "Renamed": 0
    }
    file_list = []
    seen = set()
    
    for line in output.split('\n'):
        if not line: continue
        parts = line.split('\t')
        if len(parts) < 2: continue
        status_code = parts[0][0]  # M, A, D, R
        filename = parts[-1]
        
        if filename not in seen:
            file_list.append(filename)
            seen.add(filename)
        
        if status_code == 'M': stats["Modified"] += 1
        elif status_code == 'A': stats["Added"] += 1
        elif status_code == 'D': stats["Deleted"] += 1
        elif status_code == 'R': stats["Renamed"] += 1
        
    return file_list, stats

def generate_markdown(categorized, files, stats, commit_count):
    """Builds the Markdown string."""
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
    if len(files) > 0:
        md += "<details>\n<summary>Click to view full file list</summary>\n\n"
        for f in files:
            md += f"- `{f}`\n"
        md += "\n</details>"
    else:
        md += "*No files changed.*"

    return md

def main():
    args = sys.argv[1:]

    # Parse --output flag
    output_file = OUTPUT_FILE
    if "--output" in args:
        idx = args.index("--output")
        if idx + 1 < len(args):
            output_file = args[idx + 1]
            args = [a for i, a in enumerate(args) if i != idx and i != idx + 1]
        else:
            print("ERROR: --output requires a filename argument")
            sys.exit(1)

    # Parse --all flag
    scan_all = "--all" in args
    if scan_all:
        args = [a for a in args if a != "--all"]

    # Parse commit count (positional int arg)
    num_commits = DEFAULT_COMMITS_TO_SCAN
    for a in args:
        if a.isdigit():
            num_commits = int(a)
            break

    if scan_all:
        print("🔍 Scanning full commit history…")
    else:
        print(f"🔍 Scanning last {num_commits} commits…")
    
    categorized_commits, count = parse_commits(num_commits, scan_all)
    file_list, stats = get_files_changed(num_commits, scan_all)
    
    markdown_content = generate_markdown(categorized_commits, file_list, stats, count)
    
    with open(output_file, "w", encoding="utf-8") as f:
        f.write(markdown_content)
        
    print(f"✅ Changelog generated: {output_file}")
    if output_file == OUTPUT_FILE:
        print("   (Review this draft, then paste into CHANGELOG.md)")

if __name__ == "__main__":
    main()
