# 🤝 Contributing to the ULTIMATE CYBERSECURITY MASTER GUIDE

Thank you for your interest in contributing. This is a living knowledge base maintained by
[Pacific Northwest Computers (PNWC)](https://pnwcomputers.com) and kept accurate through
community input.

---

## ⚖️ Legal Requirement — Read Before Anything Else

**All contributions must comply with the [LEGAL.md](../LEGAL.md) terms.**

By submitting a contribution you confirm:
- The content is for **educational and authorized security testing purposes only**
- You have the right to contribute the material (no plagiarism, no stolen code)
- You are not submitting malware, backdoors, or tools designed solely for malicious use
- You understand that misuse of tools in this repo is a federal crime

---

## 📋 What We Accept

### ✅ Welcome

| Type | Examples |
|---|---|
| Broken link fixes | A tool URL changed, a GitHub repo moved |
| Factual corrections | Wrong command syntax, outdated version info, wrong tool description |
| New tool entries | Actively maintained, legitimate security tools not already listed |
| New scripts | Security automation, recon, defensive tooling — with full documentation and legal warnings |
| Typos / formatting | Grammar, markdown rendering issues, heading fixes |
| New guides | Homelab procedures, IR playbooks, OSINT methodology |
| Compatibility updates | New distro support, updated firmware versions in hardware guide |

### 🚫 Will Not Accept

- Malware, trojans, ransomware, or tools with no legitimate security use
- Scripts with hardcoded targets or credentials
- Obfuscated code of any kind
- Content copied from books without proper attribution and fair use justification
- Exploits targeting specific named organizations
- Anything violating the [LEGAL.md](../LEGAL.md) terms

---

## 🔧 How to Submit a Fix or Contribution

### For Small Fixes (broken links, typos, wrong commands)

1. Click **Edit this file** (pencil icon) on the relevant page in GitHub
2. Make your change
3. At the bottom, select **"Create a new branch for this commit and start a pull request"**
4. Title your PR clearly: `fix: broken link to Amass repo` or `fix: typo in OSINT guide`
5. Submit — it'll be reviewed and merged quickly if it's accurate

### For Larger Contributions (new scripts, new guides, new sections)

1. **Fork** the repository
2. Create a branch named descriptively: `add/nuclei-v3-notes` or `fix/wireless-tool-links`
3. Make your changes following the style guide below
4. **Test** anything executable in an isolated environment before submitting
5. Submit a pull request with:
   - What you added/changed and why
   - Confirmation you tested it (if code/scripts)
   - Attribution if referencing external sources

---

## 📐 Style Guide

### Markdown Formatting

- Use **tables** for tool listings, not bare bullet lists
- Use `code blocks` for all commands, file paths, and code
- Headers: `##` for main sections, `###` for subsections — don't skip levels
- Keep lines reasonably wrapped — no 500-character single lines
- Badge syntax: `![Badge](https://img.shields.io/badge/...)` — use sparingly

### Script Standards (if contributing to `Scripts/`)

Every script must include at the top:

```bash
# ============================================================
# Script Name: your_script.sh
# Description: What it does in one sentence
# Author: Your name / handle
# Usage: ./your_script.sh [options]
# Requirements: Dependencies needed
# ⚠️ Authorization required: Must have written permission to run
# ============================================================
```

Scripts must also:
- Handle errors gracefully (`set -euo pipefail` for bash)
- Include a `--help` flag
- Never hardcode IPs, credentials, or targets
- Include prominent legal warning in the output when run
- Be tested in an isolated lab environment before submission

### Tool Entries

When adding a tool to any guide, use this format:

```markdown
| [Tool Name](https://tool-homepage.com) | Brief one-line description | Distro/platform |
```

Always link to the **official homepage or official GitHub repo** — not forks, mirrors, or third-party sites.

### Attribution

- If referencing a book: include Author, Title, Publisher, Year
- If referencing a tool: link to the official repo and credit the author
- If referencing your own original work: note it as such

---

## 🗂️ Where Things Go

| Content Type | Location |
|---|---|
| Bash/Python/PowerShell/C scripts | `Scripts/<Language>/` |
| Linux installer/automation | `Scripts/` |
| OSINT tools, methodology | `OSINT/` |
| Homelab setup guides | `Homelab/` |
| Incident response procedures | `IncidentResponse/` |
| OPSEC practices | `OPSEC/` |
| Field playbooks | `PlayBooks/` |
| Pre/post engagement checklists | `Checklists/` |
| Hardware/firmware compatibility | `FIRMWARE&HARDWARE_COMPATIBILITY.md` |
| AI/LLM security workflows | `AI/` |
| Reference PDFs | `PDF/` |
| Command references, cheat sheets | `Documentation/` |

---

## 🐛 Reporting Issues

Use GitHub Issues for:
- **Broken links** — title: `broken link: [description]`
- **Outdated information** — title: `outdated: [tool/section name]`
- **Missing content suggestions** — title: `suggestion: [what and where]`
- **Script bugs** — title: `bug: [script name] - [what it does wrong]`

Use the issue templates provided — they keep reports consistent and actionable.

---

## 📬 Contact

For anything that doesn't fit a GitHub Issue:

- **Email:** jon@pnwcomputers.com
- **Website:** [pnwcomputers.com](https://pnwcomputers.com)
- **GitHub:** [@Pnwcomputers](https://github.com/Pnwcomputers)

---

*Part of the [ULTIMATE CYBERSECURITY MASTER GUIDE](https://github.com/Pnwcomputers/ULTIMATE-CYBERSECURITY-MASTER-GUIDE)*
