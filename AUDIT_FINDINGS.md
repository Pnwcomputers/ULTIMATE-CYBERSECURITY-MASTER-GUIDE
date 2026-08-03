# 🔎 Audit Findings Register

*Deliverable C of the repository audit. A living register of verified,
evidence-backed findings with recommended corrections, confidence levels, and
proposed actions. Update the **Status** column as items are resolved.*

**Last updated:** 2026-08-03
**Scope of this pass:** repository-wide structural, navigation, and link
integrity. Per-domain factual/safety review (audit scope items 2 & 4) is an
open workstream tracked at the bottom, not yet reflected as line-item findings.

---

## How findings were verified

- **Relative links** — offline resolver over every tracked `.md` file
  (matches the CI `Internal links (offline)` lychee gate). Currently clean.
- **Heading anchors** — a faithful reimplementation of GitHub's `github-slugger`,
  **cross-checked against GitHub's own renderer** via the `POST /markdown` API and
  the live rendered `Accept: application/vnd.github.html+json` output for
  `OSINT/README.md` and `LEGAL.md`. Every anchor claim below was confirmed against
  GitHub's actual generated `id` attributes, not a guessed algorithm.
- **Orphans / missing indexes / insecure links** — filesystem + `grep` sweeps,
  excluding the gitignored nested `osint/` repo and `.git`.

Confidence levels: **High** = mechanically verified against an authoritative
source; **Medium** = verified pattern but individual instances need a human call;
**Low/Editorial** = judgment or preference.

---

## Summary

| ID | Priority | Category | Finding | Count | Confidence | Status |
|----|----------|----------|---------|-------|------------|--------|
| F-01 | High | Navigation | Manual TOC anchors don't match GitHub-generated heading slugs | 198 links / 33 files | High | Open |
| F-02 | Medium | Navigation | Content directories with no `README.md` index | 9 dirs | High | Open |
| F-03 | Medium | Navigation | Orphaned docs / broken TOC entry not reachable from any index | 4 | High | Open |
| F-04 | Medium | Tooling | CI anchor-checking (`--include-fragments`) disabled, so F-01 can regress silently | 1 | High | Open |
| F-05 | Low | Link hygiene | External links using `http://` where `https://` may be available | 6 hosts | Medium | Open |
| F-06 | Low | Content | `TODO` / placeholder / `TBD` markers left in published docs | 9 | High | Open |
| F-07 | Editorial | Structure | Very large monolithic guides are candidates for splitting | 4 docs | Low | Open |

---

## F-01 — Manual TOC anchors don't match GitHub's generated heading slugs

- **Priority:** High **Category:** Navigation / broken internal links
  **Confidence:** High **Status:** Open
- **Files:** 33 (see per-file breakdown). **Occurrences:** 198 anchor links.
- **Issue:** Hand-authored / tool-generated "Table of Contents" links point at
  anchors that GitHub does not generate, so clicking a TOC entry jumps nowhere.
  The content is still reachable by scrolling, which is why this is High rather
  than Critical.
- **Evidence (authoritative, from GitHub's renderer):**
  - `OSINT/README.md` heading `## 🎯 Overview` renders as
    `id="user-content--overview"` (anchor `#-overview`, **leading dash** from the
    emoji's space), but the TOC links `href="#overview"` — no match.
  - `LEGAL.md` heading `## 📄 Purpose of This Document` renders as
    `id="user-content--purpose-of-this-document"`; the TOC links
    `#purpose-of-this-document` — no match.
- **Three confirmed root causes:**
  1. **Emoji-prefixed headings (bulk: 153 of 198).** `## 🎯 Overview` →
     GitHub anchor `#-overview`. The TOC omits the leading dash. Uniform and
     bulk-fixable.
  2. **Literal `​ - ​` inside a heading (subset of the remaining 45).**
     `### Chapter 1: The New Attack Surface - Thinking in Graphs` → GitHub
     collapses nothing and yields `...surface---thinking...` (triple dash); the
     TOC wrote a single dash. Seen across `AI/offensive_ai.md` (13),
     `Documentation/TOR.md`, `uConsole/*-SETUP.md`, etc.
  3. **Missing / renamed target heading (content-level).** e.g.
     `Tradecraft/network-detection.md:29` links `#tcpdump-field-reference`, but no
     such heading exists — the section is `### tcpdump Essentials`. This one is
     also logged as F-03 because it is a genuine dead TOC entry, not a slug quirk.
- **Recommended correction (pick one, repo-wide for consistency):**
  - **(A) Regenerate the TOCs with a GitHub-accurate slugger** so anchors match
    exactly (including the leading dash for emoji headings). Preserves the emoji
    house style. Recommended.
  - **(B) Drop the manual TOCs** and rely on GitHub's built-in file-header
    table-of-contents button. Lowest maintenance, but removes in-page TOCs for
    readers cloning the repo.
  - **(C) Remove emoji from TOC-target headings only.** Cleanest anchors, but
    changes the visual style the author chose.
- **Proposed action:** implement (A) as a scripted, reviewable pass — one PR per
  file or per section — then enable F-04 to lock it in. Do **not** hand-edit 198
  links; use the verified slugger from the audit tooling.

### F-01 per-file breakdown

| File | Broken anchors | Dominant cause |
|------|----------------|----------------|
| `LEGAL.md` | 20 | emoji headings |
| `Documentation/wireshark.md` | 18 | emoji headings (+1 duplicate `Overview` heading) |
| `AI/offensive_ai.md` | 13 | literal ` - ` in chapter titles |
| `uConsole/README.md` | 10 | emoji headings + ` - ` |
| `SpaceSecurity/README.md` | 8 | emoji headings |
| `OPSEC/README.md` | 8 | emoji headings |
| `Mobile/README.md` | 8 | emoji headings |
| `HardwareHacking/README.md` | 8 | emoji headings |
| `SDR/README.md` | 7 | emoji headings + `&` |
| `PlayBooks/README.md` | 7 | emoji headings |
| `PDF/README.md` | 7 | emoji headings |
| `OSINT/README.md` | 7 | emoji headings |
| `IncidentResponse/SIEM/README.md` | 7 | emoji headings |
| `Checklists/README.md` | 7 | emoji headings |
| `AI/README.md` | 7 | emoji headings |
| `Scripts/README.md` | 6 | emoji headings |
| `IncidentResponse/Endpoint-Visibility/README.md` | 6 | emoji headings |
| `IncidentResponse/Digital-Forensics/README.md` | 6 | emoji headings |
| `ENHANCED_MASTER_GUIDE.md` | 6 | `&` / word-joined section links |
| `IncidentResponse/README.md` | 5 | emoji headings |
| `Homelab/README.md` | 5 | emoji headings |
| `SPECIALIZED_TOPICS_GUIDE.md` | 3 | ` - ` / `+` in headings |
| `SDR/sdr_hacking.md` | 3 | `&` in chapter titles |
| `Documentation/TOR.md` | 3 | ` - ` in headings |
| `Documentation/VPN.md` | 2 | ` - ` in headings |
| `Documentation/README.md` | 2 | emoji headings |
| `Documentation/flipper_zero_guide.md` | 2 | ` - ` in headings |
| `advanced_techniques_supplement.md` | 2 | word-joined section links |
| `uConsole/CM5-SETUP.md` | 1 | ` - ` in heading |
| `uConsole/CM4-SETUP.md` | 1 | ` - ` in heading |
| `Tradecraft/network-detection.md` | 1 | missing target heading (see F-03) |
| `Documentation/references.md` | 1 | emoji heading |
| `advanced_techniques_part2.md` | 1 | word-joined section link |

*Note: a small number may be second-order (e.g. `wireshark.md` has both
`## 🎯 Overview` and a later `## Overview`, so `#overview` currently lands on the
wrong section rather than nowhere). Treat the per-file counts as the work list;
each fix should be visually confirmed in GitHub's preview.*

---

## F-02 — Content directories with no README index

- **Priority:** Medium **Category:** Navigation **Confidence:** High **Status:** Open
- **Issue:** These directories contain published `.md` content but no
  `README.md`, so GitHub shows a bare file list instead of an index. The repo
  already has a strong folder-index house style (see `OSINT/README.md`,
  `IncidentResponse/SIEM/README.md`) to match.
- **Directories (file count):**
  - `IncidentResponse/Digital-Forensics/Disks` (1)
  - `IncidentResponse/Digital-Forensics/LiveData` (1)
  - `IncidentResponse/Digital-Forensics/Memory` (1)
  - `IncidentResponse/Endpoint-Visibility/Linux` (2)
  - `IncidentResponse/Endpoint-Visibility/Windows` (1)
  - `Mobile/OnePlus_A3006` (3)
  - `OSINT/scripts` (3 — files are linked from `OSINT/README.md`, but the folder has no index)
  - `Homelab/workflows` (1)
  - `Scripts/Bash` (1)
- **Recommended correction:** add a short folder-index `README.md` to each,
  following the established template. Single-file leaf dirs (the forensic
  subfolders) are lower priority since the parent section README already links
  them; batch them or fold their content upward.
- **Proposed action:** one PR adding the indexes, grouped by parent section.

---

## F-03 — Orphaned documents and dead TOC entry

- **Priority:** Medium **Category:** Navigation **Confidence:** High **Status:** Open
- **Issue:** Content not reachable from any index page (excludes `.github/*`
  templates, which are correctly unlinked by design).
- **Instances:**
  - `Documentation/references.md` — not linked from `Documentation/README.md` or
    any index. **Action:** add to the Documentation index, or merge into it.
  - `Homelab/workflows/self-hosted_network_attacks.md` — not linked from
    `Homelab/README.md`. **Action:** link from the Homelab index (and give
    `Homelab/workflows/` an index per F-02).
  - `Scripts/GO/shells/README.md` — a nested index whose parent `Scripts/GO/`
    has no README to point at it. **Action:** add a `Scripts/GO/` index or link
    from `Scripts/README.md`.
  - `Tradecraft/network-detection.md:29` — TOC entry `#tcpdump-field-reference`
    targets a heading that does not exist (actual section: `### tcpdump
    Essentials`). **Action:** repoint the link or rename the heading.
- **Recommended correction:** cross-link each from the nearest index; no content
  removal.

---

## F-04 — CI anchor-checking is disabled

- **Priority:** Medium **Category:** Tooling / maintenance **Confidence:** High **Status:** Open
- **Evidence:** `.github/workflows/link-check.yml` intentionally omits
  `--include-fragments`, and `.markdownlint.jsonc` disables `MD051`
  (link-fragments) — both with comments citing emoji-heading false positives.
- **Issue:** With anchor validation off in both tools, F-01 can regress silently;
  new TOCs won't be caught.
- **Recommended correction:** once F-01 is fixed, enable lychee
  `--include-fragments` (and optionally re-enable `MD051`). Because GitHub's
  slugger keeps the leading dash for emoji headings, the anchors must be made
  correct **first**, or the check will fail on existing files.
- **Proposed action:** sequence after F-01; add as the final PR of that workstream.

---

## F-05 — Insecure `http://` external links

- **Priority:** Low **Category:** Link hygiene **Confidence:** Medium **Status:** Open
- **Issue:** External links use `http://` where an `https://` equivalent may
  exist. Confidence is Medium because some legacy hardware-vendor sites are
  genuinely HTTP-only — each must be checked, not blindly rewritten.
- **Hosts:** `www.arrl.org/getting-licensed` (×2),
  `dangerousprototypes.com/docs/Bus_Pirate` (×2), `www.xgecu.com/en/download.html`,
  `www.qdkingst.com/en/download`, `www.baudline.com`, `spyonweb.com`.
- **Recommended correction:** verify each host supports HTTPS, then update; if a
  host is HTTP-only, leave it and note why.
- **Proposed action:** low-priority link-hygiene PR.

---

## F-06 — Leftover `TODO` / placeholder markers

- **Priority:** Low **Category:** Content completeness **Confidence:** High **Status:** Open
- **Issue:** 9 `TODO` / `FIXME` / `TBD` / placeholder markers remain in published
  docs (excludes the intentional `🔨 Planned` status markers, which are a
  deliberate roadmap convention).
- **Recommended correction:** resolve or convert to tracked issues / `🔨 Planned`
  entries so nothing reads as unfinished mid-page.
- **Proposed action:** triage list; fold into the relevant domain PRs.

---

## F-07 — Very large monolithic guides (editorial)

- **Priority:** Editorial **Category:** Information architecture **Confidence:** Low **Status:** Open
- **Issue:** Several root guides are large enough to be hard to navigate in a
  single page: `ENHANCED_MASTER_GUIDE.md` (~123 KB), `LEGAL.md` (~115 KB),
  `SPECIALIZED_TOPICS_GUIDE.md` (~87 KB), `advanced_techniques_supplement.md`
  (~37 KB).
- **Note:** this is a judgment call, explicitly a "do not reorganize for cosmetic
  reasons" area per the audit brief. Splitting has real cost (every inbound link
  and anchor must be updated — and see F-01).
- **Recommended action:** decide per document whether to split into a folder +
  index or keep as-is with a solid in-page TOC (post-F-01). Needs owner input
  before any move.

---

## Open workstreams (not yet itemized as findings)

These audit-scope areas were **not** covered in this structural pass and are not
represented above. They are listed so the register is honest about coverage, not
as claims of specific defects.

- **Factual & technical accuracy (scope 2)** — only a targeted currency pass has
  run (Entra ID rename, NetExec/twint/gr-gsm/meek-azure deprecation notes).
  No systematic per-domain verification against vendor/CISA/NIST/OWASP sources.
- **Safety review (scope 4)** — no systematic audit of destructive commands,
  missing backup/privilege warnings, or authorization notices across scripts and
  hardening steps. **Constraint reaffirmed by the maintainer: do not remove
  scripts or sterilize content** — safety work should *add* warnings/context, not
  strip material.
- **Duplication & contradiction (scope 11)** — overlap between the several
  "master guide" documents has not been mapped.
- **Coverage gaps (scope 12)** — not yet assessed.

---

## Remaining audit deliverables (status)

| Deliverable | Status |
|-------------|--------|
| A. Executive Summary | Not started |
| B. Repository Map | Partial (Phase 0 inventory exists in prior session) |
| **C. Findings Register** | **This document** |
| D. Broken-Link Report | Covered here (F-01, F-03, F-05); link-check CI green for relative links |
| E. Cross-Linking Plan | Not started (informed by F-02/F-03) |
| F. Proposed Information Architecture | Not started (relates to F-07) |
| G. Content Expansion Plan | Not started |
| H. Style Guide | Exists (`STYLE_GUIDE.md`); not yet reconciled with findings |
| I. Implementation Roadmap | Not started |
| J. Proposed Changes | In progress (prior PRs #12–#22; this register) |
