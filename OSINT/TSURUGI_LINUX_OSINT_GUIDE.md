# Tsurugi Linux OSINT Investigation & Workstation Guide

> **Platform:** Tsurugi Linux [LAB] 26.03 (released 2026-04-04) · **Verified:** 2026-10-26
>
> **Scope:** Deploy a Tsurugi OSINT workstation, apply this repository's existing investigation methodology in its native menus and terminal, preserve evidence, and report results. This is a platform-specific companion—not a replacement for the [OSINT master guide](OSINT_GUIDE.md) or the [investigation procedures](Playbook/investigation_guide.md).

## 🎯 Purpose
Provide a repeatable, defensible OSINT workflow on Tsurugi Linux for authorized fraud investigations, infrastructure intelligence, public-source research, and DFIR-related evidence review.

## ⚙️ Function
Covers verified installation methods and OSINT profile behavior; workstation isolation and tool inventory; domain/IP, email, username/social, phone, web, image, and IOC workflows; local evidence handling; and integration with PNWC's existing OSINT documentation.

## 🏆 Goal
Go from a clean workstation and scoped question to reproducible, source-attributed findings **without confusing passive OSINT, active probing, or unimplemented toolkit features**.

## 📋 When to Use
- Setting up Tsurugi specifically as an OSINT analysis VM or dedicated workstation.
- Following the [OSINT intelligence cycle](OSINT_GUIDE.md) with Tsurugi's menus and bundled tools.
- Investigating a suspicious domain, message, public profile, image, or other indicator lawfully.
- Preserving research outputs for later review or incident response.

## Table of Contents
1. [What Tsurugi Is](#1-what-tsurugi-is)
2. [Acquire, Verify, and Deploy](#2-acquire-verify-and-deploy)
3. [First Boot and OSINT Profile](#3-first-boot-and-osint-profile)
4. [Secure the Workstation](#4-secure-the-workstation)
5. [Identify the Available Tools](#5-identify-the-available-tools)
6. [Create a Case and Record Evidence](#6-create-a-case-and-record-evidence)
7. [Apply OSINT Investigation Procedures](#7-apply-osint-investigation-procedures)
8. [Analyze, Correlate, and Report](#8-analyze-correlate-and-report)
9. [Integrate PNWC's Playbook and Scripts](#9-integrate-pnwcs-playbook-and-scripts)
10. [Troubleshooting and Maintenance](#10-troubleshooting-and-maintenance)
11. [References and Related Guides](#11-references-and-related-guides)

---

## 1. What Tsurugi Is

**Tsurugi Linux [LAB]** is a 64-bit digital forensics and incident response distribution that also provides substantial OSINT, malware-analysis, image-analysis, and reporting capabilities. Release **26.03**, published **April 4, 2026**, is based on **Ubuntu 24.04.3 LTS** and a customized **6.19.10** kernel. The official project documents a kernel-level storage **write blocker**: preserve original evidence and do not assume ordinary Linux disk-write behavior. [Official overview](https://tsurugi-linux.org/tsurugi_linux.php) · [Changelog](https://tsurugi-linux.org/documentation_tsurugi_linux_changelog.php).

**Choose the right product:**

| Product | Intended role | OSINT workstation? |
|---|---|---|
| **Tsurugi Linux [LAB]** | Full DFIR/OSINT workstation: install, live boot, or official OVA | **Yes—use this guide** |
| **Tsurugi Acquire** | Lightweight, 32-bit live evidence acquisition | **No**, not a replacement for LAB |
| **Bento** | Portable live-forensics toolkit | Complementary; not a full OS |

The **OSINT profile is a menu/workspace change, not a sandbox, VPN, Tor configuration, or a separate installed OS**. It hides unrelated DFIR menu entries and changes the wallpaper. Tools are not inherently rendered safe, passive, or anonymous by selecting this profile.

## 2. Acquire, Verify, and Deploy

**Download only from the [official Tsurugi downloads page](https://tsurugi-linux.org/downloads.php)** and its selected mirrors.

| Release artifact | Filename | Typical use |
|---|---|---|
| Live/install ISO | `tsurugi_linux_26.03.iso` | Bare metal or VM ISO boot; optionally install after starting live session |
| Prebuilt VM | `tsurugi_linux_26.03.ova` | Import into a compatible hypervisor |

**Minimum documented recommendation:** 4 GHz dual-core CPU, 4 GB RAM, and **110 GB of free drive space**. Many analysis tasks require more. For a practical VM, allocate more RAM/CPU if available and leave room for growing case data; these are recommendations, not new official minimums. [Official installation documentation](https://tsurugi-linux.org/documentation_tsurugi_linux_1.php).

### 2.1 Verify the image before running it

The project publishes a **signed SHA-512 manifest** and a PGP public key (key ID `0x116AD57C`) on its downloads page. Do not trust a short key ID by itself: independently confirm the full public-key fingerprint through the project's authenticated channels. Verify the signature before relying on any digest; then compare your ISO/OVA SHA-512 digest against the **matching filename** in the verified manifest.

On a trusted Linux host, with the downloaded image and manifest in the same working directory:

```bash
# Compute a local digest; compare with the entry in the verified signed manifest.
sha512sum tsurugi_linux_26.03.ova

# After independently verifying the PGP key fingerprint and importing its key:
gpg --verify signed_hashes.sha512
# Inspect signed_hashes.sha512 for the exact matching filename and digest.
```

**Do not treat `gpg --verify` as sufficient if the signing key's identity has not been independently authenticated.** If the manifest's format, download links, or key change, follow the current official verification instructions rather than forcing these example commands. Do not install an image whose hash mismatches.

### 2.2 VirtualBox / VMware / other hypervisors

1. Import the **official OVA** into a compatible hypervisor. Tsurugi's documented virtualization testing covers **VirtualBox 7.2** and **VMware**; other platforms are *not* guaranteed.
2. Put the VM on an isolated virtual network with the minimum connectivity required. Avoid bridging it into a sensitive LAN by default.
3. Disable shared clipboard, drag-and-drop, shared folders, host USB passthrough, and other host-integration features unless the case requires them.
4. Start the VM, change default credentials immediately, install security updates under change control, verify networking, then take a **clean baseline snapshot**.
5. The official project suggests official VirtualBox guest additions from the vendor, **not** its repository package; for VMware it suggests `open-vm-tools-desktop` from the repository.
6. Keep collected case evidence on encrypted storage with separate backups. **A VM snapshot is a recovery point, not an evidence backup.**

**Proxmox/KVM:** Tsurugi may work as a guest, but the official instructions do not document a validated Proxmox-specific conversion process. Test guest networking, display, disks, and Tsurugi write-blocker behavior in a disposable VM before operational use; do not describe an untested import path as supported.

### 2.3 Live mode and installed mode

Tsurugi supports live boot and an installed LAB workstation. For ISO installation, boot **into live mode first**; the official guide instructs unlocking the destination device's read-only protection due to the forensic kernel patch, then starting the red desktop installer/menu entry. Select the **installation target** carefully; never unlock or alter an evidence source drive accidentally.

**Important:** The installer workflow is distinct from normal evidence collection. Keep suspect/source media disconnected during OS installation.

## 3. First Boot and OSINT Profile

The official OVA's default password is **`tsurugi`**. The live session uses user **`tsurugi`** with a **blank password**. Change credentials on persistent installations and do not expose the default VM to untrusted networks.

```bash
whoami
cat /etc/os-release
uname -r
date -u '+%Y-%m-%dT%H:%M:%SZ'
passwd                     # Set a strong password for the current user
```

**Switch profiles:** Open the desktop's **OSINT Switcher** (or locate `profile_switcher_tsurugi` in the applications menu) and select the OSINT profile. Verify that the OSINT-focused categories and wallpaper appear. When finished, use the switcher to return to the DFIR profile.

These officially documented recovery/customization commands are **not ordinary profile-toggle shortcuts**:

```bash
# Reset Tsurugi menu/wallpaper profiles to defaults:
profile_switcher_tsurugi --default

# Rebuild the OSINT menu from DFIR menus; may replace custom OSINT menu changes:
profile_switcher_tsurugi --rebuild
```

Run them only when appropriate. [Official special features](https://tsurugi-linux.org/documentation_tsurugi_linux_special_features.php).

## 4. Secure the Workstation

- **Scope & authorization:** Define the case purpose, target identifiers, allowable sources, retention schedule, and whether *any* direct scanning/contact is permitted. Public availability does not automatically authorize collection or republication.
- **Isolation:** Use a dedicated case VM/profile and network. Treat untrusted documents, sites, and downloaded files as potentially malicious; open in suitable containment.
- **Network privacy:** Use an approved, properly configured VPN where practical, as recommended by the [OPSEC guide](../OPSEC/README.md). Validate the actual public IP and DNS behavior through a trusted service. A VPN does **not** make activity anonymous, and a switched desktop profile does not route traffic. Use Tor Browser only where lawful and appropriate, understanding its different traffic model and possible site restrictions. Avoid promising anonymity.
- **Identity separation:** Do not mix personal accounts, customer sessions, browser sync, and investigative personas. Use platform-compliant access, avoid unauthorized sockpuppet accounts or deception, and don't contact subjects without a legitimate basis.
- **Case data:** Store originals and logs on access-controlled, encrypted media. Avoid cloud syncing sensitive case folders automatically. Back up separately.
- **Updates:** Make a snapshot first, follow Tsurugi's official update guidance, and use Ubuntu package tools only with awareness that this distribution has a **custom kernel and special forensic configurations**. Avoid an automatic Ubuntu release upgrade or generic one-line “install everything” scripts.
- **Write blocking:** Tsurugi's kernel-level protection helps with attached evidence devices, but it is **not** a replacement for a verified acquisition plan, dedicated hardware write blocker where required, or evidence validation.

## 5. Identify the Available Tools

The official [25.11 tool inventory](https://tsurugi-linux.org/documentation_tsurugi_linux_tools_listing_2025.php) lists the following OSINT-related applications. **It is a historical 25.11 listing, not a verified exhaustive inventory of 26.03**; the 26.03 changelog reports tool changes. A menu entry may open a GUI, wrapper, or a command with a different executable name.

| Tsurugi menu / area | Examples from official inventory | How it fits PNWC's procedures |
|---|---|---|
| **OSINT → Emails** | h8mail, holehe, GHunt, mosint | Email-related public signals; apply lawful scope and avoid unnecessary account probing |
| **OSINT → Network** | amass, dnsrecon, dnstwist, WhatWeb | Domain and infrastructure intelligence; distinguish passive lookups from requests to target hosts |
| **OSINT → Phone Numbers** | PhoneInfoga | Public phone-number intelligence; results can be incomplete or misleading |
| **OSINT → Social** | Sherlock, Maigret | Public username correlations; matching handles **do not prove identity** |
| **OSINT → Web** | recon-ng, Photon, Shodan, Internet Archive | Public-source searches, historical pages, and research |
| **OSINT → Maltego / SpiderFoot** | Maltego, SpiderFoot | Graphing relationships and assisted research; provider API keys/limits may apply |
| **Picture Analysis / Artifacts** | exiftool, tesseract, forensic image tools | Local metadata/OCR analysis of lawfully obtained files |
| **Hash / Reporting** | sha256sum, CherryTree, screenshot/reporting utilities | Preservation, notes, source-attribution, and reporting |

First inspect the **actual** environment rather than assuming a launcher is present:

```bash
# Inventory commands that may exist in your particular Tsurugi build:
for tool in dig whois amass sherlock maigret phoneinfoga \
            exiftool tesseract sha256sum recon-ng; do
  if command -v "$tool" >/dev/null 2>&1; then
    printf 'AVAILABLE  %-16s %s\n' "$tool" "$(command -v "$tool")"
  else
    printf 'CHECK GUI/ABSENT  %s\n' "$tool"
  fi
done

# Inspect command syntax on YOUR installed version before performing collection:
command -v amass >/dev/null && amass -h
command -v sherlock >/dev/null && sherlock --help
command -v phoneinfoga >/dev/null && phoneinfoga --help
```

Some tools are deliberately invoked through the OSINT menu, not by guessing CLI names. If missing, consult upstream instructions and Tsurugi release notes before installing; use isolated Python environments for third-party Python tools.

## 6. Create a Case and Record Evidence

Start each investigation with a case ID, question, authority, authorized targets, time range, collection method, and evidence-retention policy. Work **outside the cloned GitHub repository**.

```bash
# Example case identifier; replace with your own non-sensitive ID.
CASE="$HOME/OSINT_Cases/CASE-2026-001"
mkdir -p "$CASE"/{evidence,working,logs,reports}
chmod 700 "$CASE"
umask 077
date -u '+%Y-%m-%dT%H:%M:%SZ' | tee "$CASE/logs/case_started_utc.txt"
cat > "$CASE/reports/case_notes.md" <<'EOF'
# Case notes
- Case ID: CASE-2026-001
- Investigator:
- Authority / consent / scope:
- Key intelligence question:
- Authorized indicators:
- Collection period (UTC):
- Sources and access limitations:
- Findings / alternative explanations:
- Reporting / retention:
EOF
```

**Record for every collected artifact:** URL/source or original sender; UTC collection time; tool + version or browser; exact query/method; scope/authorization; filename; SHA-256; handling/transfers; and interpretation/confidence. Preserve raw items, work on copies, and keep reports separate from source evidence.

After placing **lawfully obtained** files in `evidence/`, create a reproducible hash manifest without accidentally including the manifest itself:

```bash
(cd "$CASE/evidence" && \
  find . -type f -print0 | LC_ALL=C sort -z | \
  xargs -0 -r sha256sum) > "$CASE/reports/evidence_sha256.txt"

# Verify later from the same evidence directory:
(cd "$CASE/evidence" && sha256sum -c ../reports/evidence_sha256.txt)
```

A manifest **alone does not establish legal chain of custody**. Maintain an access/transfer log, protect manifests from tampering (for example sign and store independent copies), and follow the evidentiary standards of your jurisdiction.

## 7. Apply OSINT Investigation Procedures

Use the existing [manual investigation procedures](Playbook/investigation_guide.md) as the overall methodology. The steps below explain **where and how to carry them out in Tsurugi**. Begin with passive collection; promote any activity to active scanning only after separately approving that change of scope.

### 7.1 Domain and IP investigations — passive first

1. Open **OSINT → Network** for network-oriented research. Gather domain registration/RDAP data, DNS, certificate transparency, and historical public records.
2. In the Tsurugi terminal, query DNS for a domain within your scope. Replace `example.com` with an authorized domain; the sample is a documentation placeholder.
3. Correlate results with public CT records at [crt.sh](https://crt.sh/), the [Internet Archive](https://web.archive.org/), and a suitable public RDAP service. RDAP may be more useful than legacy WHOIS.
4. Record each source's date and limitations. A shared IP or CDN does not prove ownership/attribution.

```bash
DOMAIN="example.com"
{
  date -u '+UTC: %Y-%m-%dT%H:%M:%SZ'
  for type in A AAAA MX NS TXT; do
    printf '\n===== %s =====\n' "$type"
    dig "$DOMAIN" "$type" +noall +answer
  done
} | tee "$CASE/logs/domain_dns.txt"
```

**Classification:** DNS and third-party public-data queries contact resolvers/providers; these are **not host-port scans**, but they are still observable requests. Commands such as `nmap`, `rustscan`, `nuclei`, `dirsearch`, `WhatWeb`, or active crawlers contact target infrastructure; **do not run them as part of a passive-only case**.

Further procedure: [Domain/IP Recon](scripts/Domain_IP_Recon.md) and [advanced threat intelligence](../Tradecraft/osint-threat-intel.md). **Caution:** the Domain/IP Recon reference includes *active scanning* stages—review and disable them unless separately authorized.

### 7.2 Phishing and email investigation — preserve originals

1. Obtain the message or `.eml` file legitimately from the owner/incident-response process. Don't forward it to public online tools without permission.
2. Copy into `evidence/` without opening attachments or visiting links. Hash the raw message.
3. Inspect `From`, `Reply-To`, `Return-Path`, `Authentication-Results`, `Received`, and `Message-ID`. Do **not** assume a sender is authenticated simply because its displayed name matches a company.
4. Compare the apparent sending domain to its legitimate public records, SPF/DKIM/DMARC context, and known business channels.
5. Use the OSINT Email category or provider APIs only as allowed. Do not attempt login, password resets, credential harvesting, or intrusive account-existence checks.

Example offline header extraction (no remote requests):

```bash
# First save an authorized .eml copy at:
# "$CASE/evidence/suspect.eml"
sha256sum "$CASE/evidence/suspect.eml" \
  > "$CASE/reports/suspect_eml_sha256.txt"

python3 - "$CASE/evidence/suspect.eml" \
  > "$CASE/reports/email_headers.txt" <<'PY'
from email import policy
from email.parser import BytesParser
from pathlib import Path
import sys

message = BytesParser(policy=policy.default).parsebytes(Path(sys.argv[1]).read_bytes())
for name in ("Date", "From", "To", "Reply-To", "Return-Path",
             "Authentication-Results", "Received", "Message-ID"):
    for value in message.get_all(name, []):
        print(f"{name}: {value}")
PY
```

Further procedure: [Email OSINT](scripts/Email_OSINT.md) and the [phishing analysis SOP](../Playbooks/) (browse the playbooks index for the current phishing path).

### 7.3 Username and social-media correlation

1. From **OSINT → Social**, choose a username tool such as Sherlock or Maigret **only if installed and permitted under platform policies**.
2. Start with an organization's **own test handle**, an authorized public profile, or a training dataset.
3. Inspect tool help/version before querying; use the GUI launcher if the package does not expose a CLI.
4. Check the candidate links manually. Record profile URL, capture time, and **multiple independent corroborating attributes**; identical usernames alone are weak evidence.
5. Do not scrape private profiles, bypass authentication, create misleading identities, or publish personal data.

```bash
# Command is optional; use only on an approved/test handle.
if command -v sherlock >/dev/null 2>&1; then
  sherlock --help
  # Review syntax and scope before running a collection.
fi
```

Further procedure: [Social Media OSINT](OSINT_socialmedia.md).

### 7.4 Phone-number leads

1. Start with a number voluntarily supplied in a fraud report or an authorized business case.
2. Locate **OSINT → Phone Numbers → PhoneInfoga** if present and check the installed command's help or GUI instructions.
3. Normalize the number to international format only when country/region is known; separate numbering-plan validation from ownership claims.
4. Use lawful public carrier/reputation sources where permitted, note source age, and avoid conclusions based on one reverse-search result.
5. **Do not** call, message, bulk-enumerate, or verify accounts by triggering recovery flows without separate authority.

Further procedure: [Phone OSINT](scripts/Phone_OSINT.md).

### 7.5 Images, metadata, and geolocation

1. Obtain and hash the original image with authorization. Analyze a **copy**; edited screenshots or social-media recompression may remove EXIF data.
2. From **Picture Analysis**, use ExifTool for local metadata inspection. The presence/absence of GPS EXIF is not proof of real-world location.
3. Use Tesseract OCR only where needed for visible signage/text, then corroborate against independent public imagery and dates.
4. Record file timezone assumptions and distinguish observed evidence from analyst inference.

```bash
# Replace with a legally obtained local image in the case.
exiftool -json "$CASE/evidence/photo.jpg" \
  > "$CASE/reports/photo_metadata.json"

# Optional OCR (local processing; can contain recognition errors):
if command -v tesseract >/dev/null 2>&1; then
  tesseract "$CASE/evidence/photo.jpg" stdout \
    > "$CASE/reports/photo_ocr.txt"
fi
```

Avoid publishing home addresses or identifying private individuals in public reports.

### 7.6 Web archives and public records

Use the **OSINT browser** or other suitable browser to capture public pages, preserving the **exact URL**, **UTC observation time**, screenshot or saved page, and notes describing any dynamic content. The Internet Archive and search engine caches may preserve older versions, but pages can be removed or changed and archival services are incomplete.

Do not log in with personal accounts in the case profile; avoid untrusted downloads; respect robots, access conditions, platform terms, and rate limits. Visiting a target's live website **is an observable interaction**, not a completely passive lookup.

### 7.7 IOC enrichment and threat intelligence

For a suspicious domain, IP, certificate, or file hash, use reputable public threat-intelligence portals within their terms. **Prefer hash/metadata lookups first.** Uploading a customer's private file or proprietary attachment to a public scanner can disclose it to third parties; obtain explicit authorization before submission.

Check dates, false positives, source quality, shared infrastructure, and confidence. Keep raw IOC evidence and analytical judgments distinct. Continue with [OSINT & Threat Intelligence](../Tradecraft/osint-threat-intel.md).

## 8. Analyze, Correlate, and Report

Within Tsurugi's **Reporting** category, a local note-taking tool (for example CherryTree) can record timelines and sources. Maltego or SpiderFoot can assist relationship analysis, but link visualization does **not** establish factual association.

For each key finding:
1. State the intelligence question and concise finding.
2. Attach a source citation/URL or local evidence reference, collection timestamp, and reproducible method.
3. Mark **observed / inferred / unconfirmed**, note conflicting records, and give appropriate confidence and alternative explanations.
4. Describe privacy handling, investigative limitations, and next authorized steps.
5. Verify saved-file hashes and sign/preserve the final report as your policy requires.

**Suggested report layout:**

```text
CASE-ID/
├── evidence/         # Original source material (restricted access)
├── working/          # Derivatives, screenshots, transformations
├── logs/             # UTC timestamps, queries, tool versions, custody notes
└── reports/          # Evidence manifest, findings, final report
```

**No automatic tool result should be described as court-ready evidence** without documented collection, validation, custody, and appropriate legal review.

## 9. Integrate PNWC's Playbook and Scripts

This page is the **Tsurugi execution environment** for the workflows in the repository—not a duplicate or a promise that all external scripts work out of the box.

| PNWC resource | Use with Tsurugi | Operational caveat |
|---|---|---|
| [OSINT master guide](OSINT_GUIDE.md) | Methodology, legality, collection cycle | Follow this page for Tsurugi-specific OS setup |
| [Manual investigation procedures](Playbook/investigation_guide.md) | Sequence domain, email, phone, username, crypto, reporting tasks | Manually verify every step and output |
| [Investigator Playbook README](Playbook/README.md) | Experimental menu-driven case-directory prototype | **The README expressly states major modules and reporting are not implemented** |
| [Email OSINT](scripts/Email_OSINT.md) | Optional research with reviewed API access | Third-party keys, ToS, PII restrictions; documentation includes scripts, not guaranteed Tsurugi packages |
| [Domain/IP Recon](scripts/Domain_IP_Recon.md) | Domain infrastructure workflow | Contains active scanning; disable until scanning is explicitly in scope |
| [Phone OSINT](scripts/Phone_OSINT.md) | Phone-number workflow | Some lookups need keys and may provide unreliable personal-data attribution |
| [OSINT cheatsheet](OSINT_CHEATSHEET.md) | Terminal reference | Check each installed tool's syntax/version |
| [OPSEC](../OPSEC/README.md) | Privacy, compartmentalization, VPN practices | Profile-switching alone provides no anonymity |

**Prototype warning:** At the time of this update, [`Playbook/README.md`](Playbook/README.md) says that `osint_investigator.sh` implements case-directory creation and a config template only. It identifies the investigation menu, evidence hashing, chain-of-custody and report-generation features as **unimplemented**. Do not use the prototype as an evidence collection system, or rely on older descriptions of unsupported flags, until code and tests substantiate them.

If you elect to test any PNWC installer, do so **first in a disposable VM snapshot as a normal user**, read its pinning and compatibility notes, and check that it will not overwrite Tsurugi's packaged tools or custom configuration. It is not required to use the manual methods above.

## 10. Troubleshooting and Maintenance

| Symptom | First check |
|---|---|
| OSINT menu seems incomplete | Check profile switcher; `profile_switcher_tsurugi --default` resets menus, and `--rebuild` replaces the OSINT menu with DFIR menu items |
| Tool missing/CLI not found | Search its category in the GUI; check `command -v`, upstream documentation, and release-specific package state |
| VM display, clipboard, resolution issues | Verify supported hypervisor/guest additions and official virtualization instructions |
| External media appears read-only | Tsurugi intentionally implements forensic write protection; **do not defeat it on source evidence** |
| Script says package/module unavailable | Inspect tool version, Python virtualenv, network/API limitations; avoid blindly adding unpinned packages |
| DNS/public API results are empty | Test network/DNS policy, API keys/quotas, provider uptime, and whether the data actually exists |
| Browser privacy assumption fails | Test egress and DNS explicitly; OSINT mode alone never establishes routing or anonymity |

**Maintenance procedure:** check the project's [downloads](https://tsurugi-linux.org/downloads.php) and [changelog](https://tsurugi-linux.org/documentation_tsurugi_linux_changelog.php), record release/patch level and tool versions, snapshot/backup the VM, apply only understood updates, re-test commands and integrations, and update this guide when observed behavior changes.

## 11. References and Related Guides

### Official Tsurugi project sources
- [Project and LAB overview](https://tsurugi-linux.org/tsurugi_linux.php)
- [Official downloads / signed SHA-512 manifest / PGP key](https://tsurugi-linux.org/downloads.php)
- [Installation and default credentials](https://tsurugi-linux.org/documentation_tsurugi_linux_1.php)
- [Menus and virtualization guidance](https://tsurugi-linux.org/documentation_tsurugi_linux_2.php)
- [OSINT profile switcher and special forensic features](https://tsurugi-linux.org/documentation_tsurugi_linux_special_features.php)
- [25.11 tool listing (historical; verify tools in 26.03)](https://tsurugi-linux.org/documentation_tsurugi_linux_tools_listing_2025.php)
- [Changelog / release notes](https://tsurugi-linux.org/documentation_tsurugi_linux_changelog.php)

### PNWC repository navigation
- [OSINT section README](README.md) · [OSINT Guide](OSINT_GUIDE.md) · [Tools Catalog](OSINT_TOOLS_CATALOG.md) · [Cheatsheet](OSINT_CHEATSHEET.md)
- [Investigation procedures](Playbook/investigation_guide.md) · [Playbook prototype status](Playbook/README.md)
- [Social media](OSINT_socialmedia.md) · [Email](scripts/Email_OSINT.md) · [Phone](scripts/Phone_OSINT.md) · [Domain/IP](scripts/Domain_IP_Recon.md)
- [OPSEC](../OPSEC/README.md) · [Threat intelligence](../Tradecraft/osint-threat-intel.md) · [Main repository](../README.md)

---

> **Ethical and legal use:** These methods are for lawful public-source research, defensive investigations, and clearly authorized work. Do not stalk, harass, dox, bypass authentication, access private accounts, run unauthorized scans, or disclose sensitive personal information. Confirm local legal requirements, platform rules, and a valid collection purpose. This material is educational; adjust it to the actual tool versions and case authority.

*Maintained by Pacific Northwest Computers · Reviewed against official project documentation on 2026-10-26.*
