# 🐉 Pentoo Linux — Installation and Penetration-Testing Field Guide

> [!CAUTION]
> **Authorized testing only.** Conduct reconnaissance, vulnerability testing, wireless assessment, and exploitation only against systems explicitly included in a written scope or a controlled lab. A tool being available in Pentoo does not authorize using it. See [LEGAL.md](../LEGAL.md) and [the operational playbooks](../PlayBooks/README.md).

**Platform:** Pentoo Linux (Gentoo-based live distribution and Gentoo security-tool overlay) · **Last reviewed:** 2026-10-26  
**Position in repository:** [Tradecraft](README.md) → authorized penetration testing; companion to [network audit](../PlayBooks/NetworkAuditPlayBook.md), [web assessment](../WebAppSecurity/methodology.md), [wireless surveying](../Wardriving/README.md), and [OPSEC](../OPSEC/README.md).

## 🎯 Purpose

Configure Pentoo for repeatable professional security assessments, then apply **existing PNWC methodologies within Pentoo itself** using documented Gentoo/Portage commands, scoped evidence collection, and reporting.

## ⚙️ Function

Covers choosing the correct image, verification, live/installed/overlay workflows, Gentoo package maintenance, networking and wireless readiness, tool discovery, lab-safe reconnaissance and web testing, wireless assessment, report artifacts, and blue-team handoffs.

## 🏆 Goal

Move from a clean Pentoo workstation to a reproducible and auditable assessment **without pretending Pentoo is Kali or an Ubuntu derivative**.

## 📋 When to use

- Preparing an authorized network, application, or wireless security engagement.
- Testing approved Pentoo tools in a VM or on a dedicated laptop.
- Bringing Pentoo tool packages to an existing Gentoo workstation.
- Reproducing PNWC audit playbooks with proper scope, time stamps, and evidence.

## Contents

1. [Choose the Pentoo deployment](#1-choose-the-pentoo-deployment)
2. [Download, verify and boot](#2-download-verify-and-boot)
3. [Gentoo foundations and updates](#3-gentoo-foundations-and-updates)
4. [Harden and baseline your workstation](#4-harden-and-baseline-your-workstation)
5. [Discover Pentoo tools](#5-discover-pentoo-tools)
6. [Assessment workflow on Pentoo](#6-assessment-workflow-on-pentoo)
7. [Wireless assessment considerations](#7-wireless-assessment-considerations)
8. [Evidence and reporting](#8-evidence-and-reporting)
9. [Troubleshooting](#9-troubleshooting)
10. [References and related material](#10-references-and-related-material)

---

## 1. Choose the Pentoo deployment

Pentoo is a **Gentoo-based, installable live operating system for penetration testing**. Its tool ecosystem is maintained in the [Pentoo Portage overlay](https://github.com/pentoo/pentoo-overlay). Unlike Debian-derived penetration-testing systems, packages and profiles use **Portage** and Gentoo mechanisms.

| Deployment | Choose this when | Notes |
|---|---|---|
| **Pentoo Core live ISO/USB** | You want a smaller baseline or to add tools selectively | Tool availability is intentionally different from Full |
| **Pentoo Full live ISO/USB** | You want broad penetration-testing tooling immediately | Larger footprint; confirm available image/build |
| **Gentoo + Pentoo overlay** | You already maintain Gentoo and want its security packages | Can change USE flags, dependency graph and package choices |
| **Persistent installation** | You have a dedicated security workstation | Follow the **current Pentoo/Gentoo installation docs**, not Ubuntu installers |

The [Pentoo downloads page](https://www.pentoo.ch/downloads/) includes **release, beta and daily** builds. Those labels describe different degrees of testing; **daily builds are not certified stable**. As of this review, its build listings include 2026.0_* for amd64 beta/daily and older 32-bit builds. **Do not assume a 2026 ISO is a stable release**; verify the build label and architecture for the exact file you select.

**Virtualization note:** Virtual machines are convenient for general network and web security training. Direct USB wireless-adapter passthrough, monitor mode, packet injection, OpenCL/GPU tools and driver-specific features may work differently or not at all. For wireless field testing, dedicated supported hardware is often more suitable.

## 2. Download, verify and boot

1. Select a current build from the [official downloads listing](https://www.pentoo.ch/downloads/) or an official mirror linked there. Identify **Core vs Full**, **amd64 vs x86**, and release type.
2. Use checksums and signing metadata **provided alongside the exact selected image**. Calculate a local SHA-256 digest and compare it to a **trusted published digest for the same ISO**; do not invent a hard-coded expected value.
3. If the project provides a detached signature, verify it with a public key whose fingerprint you independently authenticated. A matching unsigned digest from the same compromised mirror does not establish authenticity.
4. Test boot in a disposable VM (where supported) or write it to a **dedicated** USB by following verified live-media instructions. Writing a raw ISO to the wrong block device destroys data; back up and positively identify the device before taking any destructive action.
5. For persistent installation, consult the current [Gentoo Handbook](https://wiki.gentoo.org/wiki/Handbook:Main_Page) plus Pentoo install guidance. Partition layout, bootloader, secure boot and hardware support vary.

~~~bash
# Example ONLY: compute the hash of your downloaded ISO; compare with
# the matching verified value provided by the project's download source.
sha256sum path/to/pentoo-downloaded-image.iso

# Inspect the live system after boot:
cat /etc/os-release
uname -r
id
ip -brief address
date -u '+%Y-%m-%dT%H:%M:%SZ'
~~~

Do not presume a default live-user password or that the Live environment is encrypted. Treat a USB stick as sensitive removable media.

## 3. Gentoo foundations and updates

**Important:** Pentoo is **not** an apt/dpkg distribution. Do not use `apt install` or blindly run Kali-focused installers. Verify whether you're using the live session (which may discard changes), an installed Pentoo, or ordinary Gentoo with the Pentoo overlay.

### 3.1 Inspect the profile and repositories

~~~bash
eselect profile show
eselect repository list
emerge --info
emerge --version
command -v emerge
~~~

### 3.2 Install the Pentoo overlay on *existing Gentoo* only

The overlay's [current README](https://github.com/pentoo/pentoo-overlay#adding-the-overlay) recommends modern **eselect-repository**, replacing old documentation built around `layman`. These commands change system configuration: review first, use a snapshot/backup and run from an appropriately privileged shell.

~~~bash
# Run as root on an existing Gentoo system, NOT as a scripted step in
# a live Pentoo session. Check each operation before executing it.
emaint sync
emerge --ask --noreplace eselect-repository git
eselect repository list
eselect repository enable pentoo
emaint sync -r pentoo
~~~

Then evaluate **profiles** and package choices rather than automatically switching to a Pentoo hardened profile or emerging every tool:

~~~bash
eselect profile list
emerge --pretend --verbose pentoo/pentoo
# After carefully reviewing system-wide dependency and USE-flag changes:
# emerge --ask --verbose pentoo/pentoo
~~~

> [!WARNING]
> A full Pentoo metapackage/profile may pull in many packages, kernel choices, unsupported toolchains or package keyword changes. **Do not** switch Gentoo profiles merely to follow this guide. Old Pentoo wiki examples that install via `layman -a pentoo` or hard-code historic profile paths may be stale.

### 3.3 Update installed systems deliberately

~~~bash
# Only when network access is approved and the OS is persistent:
sudo emaint sync -a
sudo emerge --ask --verbose --update --deep --newuse @world

# Look for messages requiring admin intervention:
eselect news list
~~~

Review the plan, blocked packages, preserved libraries, USE flag changes, kernel/bootloader updates, and rebuild instructions **before confirming**. Do not run unattended system upgrades during an active engagement. Reboot and retest adapters/tools in a maintenance window. See the [Gentoo Handbook](https://wiki.gentoo.org/wiki/Handbook:Main_Page) and Pentoo overlay's current documentation.

## 4. Harden and baseline your workstation

- Maintain separate lab, assessment and personal identities; do not mix browser sync, client passwords or personal accounts.
- Apply current security updates **before** collecting engagement evidence.
- Limit remote administration, remove unneeded services, lock the screen and encrypt sensitive disks.
- Prefer an approved VPN when practical. Verify DNS and outward-facing IP behavior. **A VPN is not anonymity**, and activity performed on a target is observable.
- In a VM, disable clipboard, shared folders, drag-and-drop and host USB passthrough unless required. Snapshot before installing new packages; separately back up case data.
- Define **written scope**: targets, IP ranges, time window, excluded devices, allowed test types, maximum rate, emergency contacts, data-retention period and reporting pathway.
- Do not run credential theft, password attacks, exploitation, or disruptive wireless injection without specific consent and a risk-managed test plan.

~~~bash
# Capture a tool/hardware/environment baseline; no target contact.
mkdir -p "$HOME/pentoo-audits"/baseline
chmod 700 "$HOME/pentoo-audits"
{
  date -u '+UTC: %Y-%m-%dT%H:%M:%SZ'
  cat /etc/os-release
  uname -a
  ip -brief address
  command -v nmap || true
  command -v tshark || true
  command -v wireshark || true
  command -v burpsuite || true
  emerge --version
} > "$HOME/pentoo-audits/baseline/workstation.txt"
~~~

## 5. Discover Pentoo tools

Pentoo's overlay includes penetration-testing packages across **network analysis, wireless, application testing, forensics, radio, debugging and exploitation**. Tool versions and dependencies vary by ISO, live profile and overlay state; **never claim every Pentoo build has every listed tool installed**.

| Task | Example tools to check | PNWC reference |
|---|---|---|
| Asset discovery and services | Nmap, Wireshark/TShark | [Network Audit Playbook](../PlayBooks/NetworkAuditPlayBook.md) |
| Web application assessment | Burp Suite, OWASP ZAP, curl | [Web methodology](../WebAppSecurity/methodology.md) |
| Wi-Fi surveys | Aircrack-ng suite, Kismet, iw | [Wardriving](../Wardriving/README.md) |
| Infrastructure review | dig, whois, SSL/TLS inspection utilities | [OSINT/threat intelligence](osint-threat-intel.md) |
| Binary inspection | Ghidra, objdump, file | [Reverse Engineering](../ReverseEngineering/README.md) |
| Exploit validation (advanced) | Metasploit and other authorized validation tools | [Tradecraft](README.md) and [Playbooks](../PlayBooks/README.md) |

~~~bash
# Inventory only; tool availability must be verified on the actual host.
for cmd in nmap wireshark tshark curl dig iw aircrack-ng \
           kismet msfconsole ghidraRun; do
  if command -v "$cmd" >/dev/null 2>&1; then
    printf 'FOUND %-18s %s\n' "$cmd" "$(command -v "$cmd")"
  else
    printf 'CHECK PACKAGE / MISSING %s\n' "$cmd"
  fi
done
# Gentoo package query: adjust exact package category/name after searching.
emerge --search nmap
~~~

## 6. Assessment workflow on Pentoo

### 6.1 Pre-engagement

Follow [PNWC's Network Audit Playbook](../PlayBooks/NetworkAuditPlayBook.md) for scoping, asset inventory, approvals, backout plan, evidence and customer report. Create a **case ID** and save a copy of the scope **outside the Git repository**.

~~~bash
umask 077
CASE="$HOME/pentoo-audits/ASSESSMENT-001"
mkdir -p "$CASE"/{scope,raw,working,logs,reports}
chmod 700 "$CASE"
printf '%s\n' 'PLACE SIGNED SCOPE AND APPROVED TARGETS HERE' \
  > "$CASE/scope/README.txt"
date -u '+%Y-%m-%dT%H:%M:%SZ' > "$CASE/logs/start_utc.txt"
~~~

Use only a target from your approved list. The reserved **192.0.2.0/24** test network in the example below is a documentation placeholder, not a real scan target; replace it with a reachable asset on your **own isolated lab** or the customer's *authorized* engagement.

### 6.2 Validate network discovery and services

~~~bash
# Substitute a specific authorized lab IP and document approval FIRST.
TARGET="192.0.2.10"
# Syntax only, not an instruction to scan arbitrary third parties:
nmap --help | head -35

# In the APPROVED lab/assessment window only:
# nmap -sT -sV --version-light -oA "$CASE/raw/nmap_service_baseline" "$TARGET"
~~~

The commented command performs **active** TCP connection and service-version probing; it is not passive OSINT. Before enabling, confirm authorization includes port/service scanning, verify the exact target and rate limits, and consider the effect on fragile devices.

Afterward correlate **confirmed** open ports with asset owners, firewall rules, exposed management services and software versions. A banner alone is not proof of a vulnerability. Use [the network-detection guide](network-detection.md) to design complementary blue-team validation.

### 6.3 Web assessment (test app, staging or production by authorization)

1. Configure the browser to use an authorized intercepting proxy if installed (Burp Suite or ZAP); turn capture off when using unrelated accounts.
2. Define in-scope hosts, paths, authentication roles, exclusions and test limits.
3. Browse normally and capture the request/response evidence. Check headers, cookies, session handling, authentication boundaries and input behavior **without disclosing secrets**.
4. Run **passive** checks first. Only use active scanners or replay altered requests after explicitly approving scope, rate and potential state changes.
5. Verify any suspected issue manually in the test environment, record reproduction steps, severity and remediation; do not retain live credentials.

~~~bash
# Safe example against a lab site; this is still an HTTP request.
# Use your permitted, reachable lab hostname, never a customer endpoint by default.
curl --help | head -20
# curl --head --max-time 10 "https://your-approved-lab.example/"
~~~

Detailed procedures: [Web Application Security Methodology](../WebAppSecurity/methodology.md) and [OWASP Top 10](../WebAppSecurity/owasp-top-10.md).

### 6.4 Evidence-based vulnerability validation

Map a suspected weakness to its prerequisites, affected version/configuration, compensating controls, and potential impact. Prefer non-destructive tests and vendor advisories. Separate **observed facts**, **test-derived evidence**, and **hypotheses**. If exploitation is explicitly authorized, follow a separately approved test plan, avoid persistence, and implement a rollback path. Do not run automated exploitation on production by default.

### 6.5 Blue/purple-team follow-through

Pair confirmed exposures with a defense and detection check: identify expected DNS, flow, IDS, HTTP, authentication, host or EDR signals; verify those logs actually existed during the approved test; record false negatives. Refer to [Incident Response](../IncidentResponse/README.md), [Network Detection](network-detection.md), and [SIEM](../IncidentResponse/SIEM/README.md).

## 7. Wireless assessment considerations

Pentoo is well suited for radio-specific lab and field research, but capabilities depend on physical adapter chipset, firmware, kernel, interface/driver and regulatory domain.

~~~bash
# READ-ONLY capabilities and device inventory
ip -brief link
iw dev
iw list
lsusb
~~~

- **Passive surveying:** Gather only authorized SSID/BSSID/channel/signal metadata with the customer's permission, then follow [Wardriving Field Workflow](../Wardriving/field-workflow.md) and [Data Handling](../Wardriving/data-handling.md).
- **Monitor mode:** Requires adapter/driver support. Don't presume a VM's virtual NIC can monitor 802.11 frames; USB passthrough needs careful host security review.
- **Active wireless testing:** Packet injection, deauthentication, WPS testing, credential attacks and MITM attempts can disrupt service or expose sensitive content. Treat each as a separately authorized and controlled testing phase—not as default reconnaissance.
- **Legal operation:** Verify local radio rules, privacy restrictions, authorized channels, and retention requirements.

Related hardware/tools: [Kismet](../Wardriving/kismet.md), [ESP32 Marauder](../Wardriving/esp32-marauder.md), and [wireless security guide](../Wardriving/README.md).

## 8. Evidence and reporting

Save native tool outputs plus command, UTC time, tool version, target, authorization scope and analyst annotations. Keep originals unedited, create working derivatives separately and restrict access.

~~~bash
# Run after collecting ONLY permitted files under raw/.
# The manifest is written outside raw/ to avoid self-hashing.
(cd "$CASE/raw" && find . -type f -print0 | LC_ALL=C sort -z | \
  xargs -0 -r sha256sum) > "$CASE/reports/raw_sha256.txt"

# Later, verify originals against the manifest:
(cd "$CASE/raw" && sha256sum -c ../reports/raw_sha256.txt)
~~~

**Recommended report:** executive summary; scope and exclusions; timeline; tools/versions; assets; findings with severity and validated evidence; defensive controls; prioritized remediation; retest plan; evidence hashes, custody, and limitations. Hashes are necessary for integrity verification but do not alone prove chain of custody.

## 9. Troubleshooting

| Problem | Check |
|---|---|
| An Ubuntu/Kali `apt` command fails | Pentoo uses **Portage**. Identify the equivalent Gentoo package and profile. |
| A tool is missing from Core | Check ISO flavor; inspect `emerge --search` and Pentoo overlay before installation. |
| Package dependency/keyword conflict | Review `emerge --pretend --verbose` output; check selected profile, USE flags and Portage news. Don't force global unmasking. |
| Tool disappears after reboot | Live media may be nonpersistent. Verify a persistent install or supported persistence mechanism. |
| Wi-Fi monitor mode unavailable | Verify chipset, USB passthrough, driver, regulatory domain and `iw list`; do not assume all adapters support injection. |
| The system is unstable after an update | Revisit kernel/module state and preserved libraries; use snapshots/backups and current Gentoo/Pentoo documentation. |

## 10. References and related material

**Primary sources:** [Pentoo website](https://www.pentoo.ch/) · [Downloads](https://www.pentoo.ch/downloads/) · [Pentoo overlay README](https://github.com/pentoo/pentoo-overlay) · [Pentoo overlay repository](https://github.com/pentoo/pentoo-overlay/tree/master/pentoo) · [Gentoo Handbook](https://wiki.gentoo.org/wiki/Handbook:Main_Page). Historical Pentoo wiki articles may predate the move from layman to eselect-repository.

**PNWC:** [Tradecraft index](README.md) · [Network Audit](../PlayBooks/NetworkAuditPlayBook.md) · [Web App Security](../WebAppSecurity/README.md) · [Wardriving](../Wardriving/README.md) · [Digital Forensics](../IncidentResponse/Digital-Forensics/README.md) · [OPSEC](../OPSEC/README.md) · [Main guide](../README.md).

---

*Pacific Northwest Computers — reviewed against the currently published official project pages on 2026-10-26. Commands are documented examples; hardware-specific installation and engagement-specific test procedures require validation in the actual Pentoo build.*
