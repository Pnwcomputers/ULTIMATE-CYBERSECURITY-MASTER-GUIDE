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
| F-01 | High | Navigation | Manual TOC anchors don't match GitHub-generated heading slugs | 198 links / 33 files | High | ✅ Fixed (#24) |
| F-02 | Medium | Navigation | Content directories with no `README.md` index | 9 dirs | High | ✅ Resolved — no action (#26) |
| F-03 | Medium | Navigation | Orphaned docs / broken TOC entry not reachable from any index | 4 | High | ✅ Fixed (#24, #26) |
| F-04 | Medium | Tooling | CI anchor-checking (`--include-fragments`) disabled, so F-01 can regress silently | 1 | High | ✅ Fixed (#24) |
| F-05 | Low | Link hygiene | External links using `http://` where `https://` may be available | 6 hosts | Medium | ✅ Fixed (#25) |
| F-06 | Low | Content | `TODO` / placeholder / `TBD` markers left in published docs | 9 | High | ✅ Resolved — intentional (#25) |
| F-07 | Editorial | Structure | Very large monolithic guides are candidates for splitting | 4 docs | Low | ⏸️ Deferred by owner |
| F-08 | Medium | Duplication | Core topics duplicated across several root "master guide" docs with no canonical source | 6+ topics | High | 🔵 Open — plan in report |
| F-09 | Medium | Safety | Inconsistent prominence of the safety/authorization header on offensive docs | ~3 docs | Medium | 🔵 Open — plan in report |
| F-10 | Low | Link hygiene | Dead/retired external links (scope 10, online sweep) | 4 fixed, 4 flagged | High | ✅ Fixed dead links; 4 flagged for manual review |

*Findings F-08–F-09 come from the second audit pass (scope 2/4/11). The
remediation approach for both lives in [AUDIT_REPORT.md](./AUDIT_REPORT.md)
(Cross-Linking Plan and Implementation Roadmap).*

---

## F-01 — Manual TOC anchors don't match GitHub's generated heading slugs

- **Priority:** High **Category:** Navigation / broken internal links
  **Confidence:** High **Status:** ✅ Fixed (#24)
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

- **Priority:** Medium **Category:** Navigation **Confidence:** High **Status:** ✅ Resolved — no action (#26)
- **Resolution:** Verified that every file in these directories is already linked
  or table-listed from its parent section README, so per-directory index stubs
  would duplicate existing navigation (filler the audit brief forbids). No stubs
  added, confirmed by the maintainer.
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

- **Priority:** Medium **Category:** Navigation **Confidence:** High **Status:** ✅ Fixed (#24, #26)
- **Resolution:** The Homelab wireless-lab playbook is now linked and correctly
  labelled in `Homelab/README` (#26); the dead `#tcpdump-field-reference` TOC
  entry was repointed to `#tcpdump-essentials` (#24). The remaining scanner
  "orphans" are non-issues: `.github/*` templates are unlinked by design,
  `Documentation/references.md` is table-listed in its section index, and
  `Scripts/GO/shells/README.md` sits under the root-linked `Scripts/GO`.
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

- **Priority:** Medium **Category:** Tooling / maintenance **Confidence:** High **Status:** ✅ Fixed (#24)
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

- **Priority:** Low **Category:** Link hygiene **Confidence:** Medium **Status:** ✅ Fixed (#25)
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

- **Priority:** Low **Category:** Content completeness **Confidence:** High **Status:** ✅ Resolved — intentional (#25)
- **Issue:** 9 `TODO` / `FIXME` / `TBD` / placeholder markers remain in published
  docs (excludes the intentional `🔨 Planned` status markers, which are a
  deliberate roadmap convention).
- **Recommended correction:** resolve or convert to tracked issues / `🔨 Planned`
  entries so nothing reads as unfinished mid-page.
- **Proposed action:** triage list; fold into the relevant domain PRs.

---

## F-07 — Very large monolithic guides (editorial)

- **Priority:** Editorial **Category:** Information architecture **Confidence:** Low **Status:** ⏸️ Deferred by owner
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

## F-08 — Core topics duplicated across "master guide" docs (no canonical source)

- **Priority:** Medium **Category:** Duplication (scope 11) **Confidence:** High **Status:** 🔵 Open — plan in [report](./AUDIT_REPORT.md)
- **Issue:** Several core topics are covered in 2–3 root-level guides with no
  designated canonical source, so updates must be repeated or the copies drift.
  Observed overlap (by section headings):
  - **Metasploit** — `ultimate_cybersecurity_master_guide.md`,
    `cybersecurity_cliff_notes.md`, `advanced_techniques_supplement.md`
  - **Buffer overflow / exploit dev** — `ultimate_cybersecurity_master_guide.md`,
    `advanced_techniques_part2.md`
  - **Bash / Python for security** — `ultimate_cybersecurity_master_guide.md`,
    `advanced_techniques_supplement.md`
  - **Mobile** — `ultimate_cybersecurity_master_guide.md`,
    `advanced_techniques_part2.md`, and the `Mobile/` section
  - **OSINT** — `ENHANCED_MASTER_GUIDE.md` (OSINT Mastery) vs the `OSINT/` section
- **Evidence:** H2 heading inventory of the six root guides (documented in the
  Cross-Linking Plan).
- **Recommended correction:** designate a canonical source per topic and convert
  the other copies to a short summary + "canonical reference" link. Full mapping
  in [AUDIT_REPORT.md](./AUDIT_REPORT.md) § E.
- **Proposed action:** one PR per topic; no content deleted — copies become
  summaries that link to the canonical source.

---

## F-09 — Inconsistent safety/authorization header on offensive docs

- **Priority:** Medium **Category:** Safety (scope 4) **Confidence:** Medium **Status:** 🔵 Open — plan in [report](./AUDIT_REPORT.md)
- **Issue:** Offensive documents all *reference* authorized use, but the
  prominence is inconsistent — from a full warning block (`SDR/README.md`,
  `SPECIALIZED_TOPICS_GUIDE.md`: ~38 warning-related lines) down to a single
  "authorized" mention in a Goal line (`advanced_techniques_supplement.md`: ~7).
- **Evidence:** warning-term density scan across the offensive root guides.
- **Not** a claim that any doc is warning-*free* — it is a **consistency** issue.
- **Recommended correction:** define one standard safety/authorization header in
  `STYLE_GUIDE.md` and apply it near the top of each offensive doc.
- **Proposed action:** add the standard to the style guide, then apply per doc.
  This **adds** warnings/context; it removes nothing.

---

## F-10 — Dead / retired external links (scope 10, online sweep)

- **Priority:** Low **Category:** Link hygiene **Confidence:** High **Status:** ✅ Dead links fixed; 4 flagged for manual review
- **Method:** full online link sweep (lychee) over all tracked Markdown, then every
  failure re-verified by hand (browser user-agent + DNS check) to separate truly
  dead domains from bot-blocking / transient timeouts. Of ~2040 unique links,
  most "errors" were bot-blocks; the following were confirmed.
- **Fixed — confirmed dead or retired, repointed to verified successors:**
  - `farsightsecurity.com` (NXDOMAIN — Farsight acquired by DomainTools 2021) →
    DomainTools DNSDB. `OSINT/OSINT_TOOLS_CATALOG.md`
  - `community.riskiq.com` (RiskIQ acquired by Microsoft; portal retired) →
    Microsoft Defender Threat Intelligence. `OSINT_TOOLS_CATALOG.md`,
    `Tradecraft/osint-threat-intel.md`
  - `onion.link` (Tor2web deprecated 2019, gateway defunct) → Ahmia.
    `OSINT_TOOLS_CATALOG.md`
  - `zonefiles.io` (NXDOMAIN) → entry kept, dead link removed, alternatives noted
    (WhoisXML API / Whoisds). `OSINT_TOOLS_CATALOG.md`
- **Flagged for manual review — host resolves but blocked automated checks (likely
  fine for humans; NOT changed to avoid breaking working links):**
  `abusix.org` (connection reset — WAF), `emailcrawlr.com` (TLS eof),
  `threatjammer.com` (connection reset), `got-hacked.wtf` (serves a default
  "Plesk" TLS cert — genuinely misconfigured HTTPS, worth a look).
- **Note:** `qdkingst.com` failed in the automated sweep but verified **working**
  by hand — no action (the F-05 HTTPS upgrade stands).

---

## Second-pass verification notes (scope 2/3 — sampled clean)

The second pass **sampled** factual/currency claims; the sample held up, so no
findings were raised for it. Recorded here for honesty about what was checked:

- Version references that looked stale on a grep were individually verified as
  correct: `Python 3.7+` is a *minimum* for Volatility 3; `Ubuntu 18.04/20.04/
  23.04/23.10` appear as *compatibility/availability notes*, not recommendations;
  `Kali 6.12` is a kernel version. **No EOL software is recommended.**
- This was a sample, **not** exhaustive verification — see the open workstream
  below for the remaining systematic accuracy review.

---

## Open workstreams (not yet itemized as findings)

These audit-scope areas were **not** covered in this structural pass and are not
represented above. They are listed so the register is honest about coverage, not
as claims of specific defects.

- **Factual & technical accuracy (scope 2)** — a currency pass plus a second-pass
  **sample** have run; the sample was clean (see verification notes above). A
  systematic per-domain verification against vendor/CISA/NIST/OWASP sources is
  still outstanding (roadmap Phase 4).
- **Safety review (scope 4)** — header *consistency* is now tracked as F-09. A
  systematic audit of destructive commands for backup/privilege/rollback notes is
  still outstanding. **Constraint reaffirmed by the maintainer: do not remove
  scripts or sterilize content** — safety work should *add* warnings/context.
- **Duplication & contradiction (scope 11)** — overlap is now mapped and tracked
  as **F-08**, with a remediation plan in the report. *Contradiction* detection
  (conflicting advice between docs) is still outstanding.
- **Coverage gaps (scope 12)** — assessed; see the Content Expansion Plan in
  [AUDIT_REPORT.md](./AUDIT_REPORT.md) § G (Web App, Cloud, Containers, Crypto,
  Compliance identified as gaps).

---

## Remaining audit deliverables (status)

| Deliverable | Status |
|-------------|--------|
| A. Executive Summary | ✅ [AUDIT_REPORT.md](./AUDIT_REPORT.md) § A |
| B. Repository Map | ✅ Inventory in [AUDIT_REPORT.md](./AUDIT_REPORT.md) § F + per-file breakdown here |
| **C. Findings Register** | **This document** |
| D. Broken-Link Report | Covered here (F-01, F-03, F-05); link-check CI green for relative links |
| E. Cross-Linking Plan | ✅ [AUDIT_REPORT.md](./AUDIT_REPORT.md) § E |
| F. Proposed Information Architecture | ✅ [AUDIT_REPORT.md](./AUDIT_REPORT.md) § F (proposal; owner-gated) |
| G. Content Expansion Plan | ✅ [AUDIT_REPORT.md](./AUDIT_REPORT.md) § G |
| H. Style Guide | Exists (`STYLE_GUIDE.md`); reconciliation with findings tracked in report § G |
| I. Implementation Roadmap | ✅ [AUDIT_REPORT.md](./AUDIT_REPORT.md) § I |
| J. Proposed Changes | Findings F-01–F-06 implemented (PRs #24–#26); F-07 deferred; F-08/F-09 planned |
