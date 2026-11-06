# 📏 ULTIMATE CYBERSECURITY MASTER GUIDE - Style & Maintenance Guide

## 1. Documentation & Heading Standards
**External writing references:** [Curated technical docs](./Documentation/curated-technical-docs.md) links to [Diátaxis](https://diataxis.fr/) for tutorials/how-tos/references/explanations, the [Google Developer Documentation Style Guide](https://developers.google.com/style) and other examples collected in [Beautiful Docs](https://github.com/matheusfelipeog/beautiful-docs). Treat these as inspiration; repository conventions below take precedence.

- **Title & Headers:** Every Markdown file must begin with a single Level 1 Heading (`# Title`).
- **Heading Title Case:** Capitalize the first letter of each significant word in Markdown headings and use `&` instead of the standalone word `and`. Preserve legitimate casing of technical acronyms and product names (for example, OSINT, SIEM, Wireshark, nzyme, uConsole, IoT, and README.md). Do not modify source code, link destinations, file names, or literal identifiers to enforce display style.
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

- **Language Specifier:** Always specify the syntax language in fenced code blocks (e.g. `bash`, `python`, `powershell`, `sql`).
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

## 4. Offensive-Content Safety Header

Any guide whose primary subject is offensive or dual-use tradecraft (exploitation,
post-exploitation, evasion, credential attacks, RF transmission, etc.) must open
with a standard authorization callout, placed immediately after the H1 (and any
badge/image block), before the Purpose block. Use the existing alert convention:

```markdown
> [!CAUTION]
> **Authorized use only.** The techniques below are for authorized security
> testing, education, and defensive research. Using them against systems you do
> not own or lack explicit written permission to test is illegal. See
> [LEGAL.md](LEGAL.md).
```

This is a **document-level** complement to the per-script disclaimer in §3 — a
reader landing anywhere in an offensive guide should see the authorization
boundary near the top. It **adds** context; it never replaces or removes content.

---

## 5. Cross-Referencing & Navigation

- **Resource Navigation Tables:** Use two-column Markdown tables (`Resource | Description` or `Goal | Recommended Route`) for collections of navigation links rather than dense inline link paragraphs. Keep one clearly named entry per row and a useful description; for longer task routes, use a numbered `Step | Guide / Activity` table. Keep actual checklists and commands in their appropriate list or code formats.
- **Mobile Readability:** Prefer short labels and two columns in navigation tables; avoid long unbroken URL strings and excessive links in a single cell. Do not convert every instructional list into a table.
- **Anchor Compatibility:** If renaming a heading changes the GitHub-generated fragment, preserve old incoming links with a unique explicit `<a id="old-fragment"></a>` anchor and update local table-of-contents text and targets.
- **Navigation QA:** Check that every new guide is reachable from its nearest section index, that root/role navigation reaches each section, and that all relative paths and in-page fragments resolve before merging.
- **Navigation Footer:** Long guides should end with a standard navigation footer:
  ```markdown
  ---
  [⬅️ Back to Master Index](README.md) | [🎯 Role Navigation](START_HERE.md) | [Legal Notice](LEGAL.md)
  ```
- **Index Coverage:** New guides need a clickable link from their nearest section index. New sections need a route from the root README and a relevant START_HERE.md entry. Keep related-guide links useful and include a return route to the section index.
- **Moved Content:** Update referring links and the moved document's own relative paths; verify that links labeled as the master index actually target the root README.
- **Authoritative Sources:** When citing CVEs, standards, or vendor documentation, provide direct reference URLs (NIST, CISA, OWASP, MITRE ATT&CK).
- **Related-Content Blocks:** Where useful, guides should end (above the navigation footer) with a `## See also` list of related guides, and advanced guides should open with a short `**Prerequisites:**` line linking to the fundamentals a reader needs first. Define acronyms on first use and link them to [GLOSSARY.md](GLOSSARY.md).

---

## 6. Review Metadata

- **Last-Reviewed Line:** Reference and install/tool docs should carry a review date near the top, immediately under the H1 (or under any badge/image block):

  ```markdown
  _Last reviewed: YYYY-MM-DD_
  ```

- **Meaning:** The date asserts that, as of then, a maintainer verified the doc's links resolve and its commands / versions / product names are current. Update it whenever you re-verify a doc.
- **Rollout:** Apply the line as each doc receives a review pass — do not back-date docs that have not actually been checked.
