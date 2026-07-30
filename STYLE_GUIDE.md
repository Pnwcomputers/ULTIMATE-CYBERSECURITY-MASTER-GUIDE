# 📏 ULTIMATE CYBERSECURITY MASTER GUIDE - Style & Maintenance Guide

## 1. Documentation & Heading Standards

- **Title & Headers:** Every Markdown file must begin with a single Level 1 Heading (`# Title`).
- **Section Headers:** Use Level 2 (`##`) and Level 3 (`###`) headings logically. Do not skip levels (e.g. going from `#` straight to `####`).
- **GitHub Alerts:** Use standard GitHub markdown alerts for notes, tips, warnings, and disclaimers:
  ```markdown
  > [!NOTE]
  > Helpful context or background information.

  > [!TIP]
  > Optimization, shortcut, or best practice.

  > [!WARNING]
  > Prerequisites, software version constraints, or connectivity risks.

  > [!CAUTION]
  > High-risk actions, potentially destructive commands, or legal disclaimers.
  ```

---

## 2. File Naming & Directory Structure

- **Relative Links Only:** Never use root-relative paths starting with `/` (e.g., `/IncidentResponse/SIEM`). Always use relative paths starting with `./` or `../`.
- **Spaces & Special Characters:** Avoid spaces, ampersands (`&`), commas, or non-ASCII characters in filenames. Use hyphens (`-`) or underscores (`_`) instead (e.g., `command-and-control.md`).
- **Case Sensitivity:** Keep folder and file names consistent across OS platforms. Avoid creating duplicate directories differing only by case (e.g. `OSINT/` vs `osint/`).

---

## 3. Script & Code Block Standards

- **Language Specifier:** Always specify the syntax language in fenced code blocks (e.g. ```bash, ```python, ```powershell, ```sql).
- **Safety Disclaimers:** Any script performing credential capture, privilege escalation, or defense evasion must include an explicit disclaimer header:
  ```bash
  # ==============================================================================
  # DISCLAIMER & LEGAL NOTICE:
  # This script is provided STRICTLY for authorized security testing, defense
  # evaluation, and educational purposes in controlled lab environments.
  # ==============================================================================
  ```
- **Preserve All Scripts:** Do not remove existing functional or legacy scripts; update disclaimers, comments, and python 3 compatibility as needed.

---

## 4. Cross-Referencing & Navigation

- **Navigation Footer:** Long guides should end with a standard navigation footer:
  ```markdown
  ---
  [⬅️ Back to Master Index](README.md) | [🎯 Role Navigation](START_HERE.md) | [Legal Notice](LEGAL.md)
  ```
- **Authoritative Sources:** When citing CVEs, standards, or vendor documentation, provide direct reference URLs (NIST, CISA, OWASP, MITRE ATT&CK).
