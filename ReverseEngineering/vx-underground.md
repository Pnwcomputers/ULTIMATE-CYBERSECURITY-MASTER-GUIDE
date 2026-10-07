# 🦠 vx-underground: Malware Research Library

_Last reviewed: 2026-10-07_

> [!CAUTION]
> **Authorized use only.** vx-underground hosts **live malware**, malware source
> code, and builders. Download, store, and detonate samples only inside an
> isolated analysis lab you control, and only for research, detection
> engineering, education, or authorized testing. Never run a sample on a
> production host, a client network, or a machine with personal data. Laws on
> possessing or distributing malicious code vary by jurisdiction. See
> [LEGAL.md](../LEGAL.md).

<div align="center">

**Where to get real malware, source, and research papers, and how to handle them without hurting yourself**

*Part of the [ULTIMATE CYBERSECURITY MASTER GUIDE](../README.md) · [Reverse Engineering](./README.md)*

</div>

---

## 🎯 Purpose

Documents [vx-underground](https://vx-underground.org) (VXUG), a free public
library of malware samples, malware source code, APT reports, and research
papers, and shows how it fits into the reverse engineering, detection, and
threat intel workflows already in this repo.

## ⚙️ Function

- Maps the site's collections and the official GitHub repositories to the job
  each one is good for.
- Gives a repeatable, lab-only intake procedure: download, verify, contain,
  analyze, write detections.
- Links each stage to the existing guide that covers it in depth (Ghidra, YARA,
  forensics, SIEM, threat intel).

## 🏆 Goal

Turn "I need a real sample of family X" into a safe, documented workflow that
ends in something defensive: a YARA rule, a Sigma/SIEM detection, an IOC set,
or a write-up.

## 📋 When to Use

- You need a known sample to practice in [Ghidra](./ghidra-guide-index.md)
- Writing or testing [YARA](https://github.com/VirusTotal/yara) rules against real families
- Validating that an EDR, AV, or SIEM rule actually fires
- Researching an APT or ransomware group (reports + samples in one place)
- Reading historical virus-writing and offensive research papers
- Building a malware training set for an isolated ML or classifier project

**Prerequisites:** a working, isolated lab ([Homelab](../Homelab/README.md)),
basic Linux CLI, and hashing/VM-snapshot habits. If you have never analyzed a
binary, start with [Part I of the Ghidra guide](./ghidra-guide-index.md#part-i-getting-started).

---

## What vx-underground Is

- Started in **May 2019**; describes itself as the largest collection of
  malware source code, samples, and papers on the internet.
- Free to access, funded by sponsors and donations.
- Runs a high-volume news/research feed on X ([@vxunderground](https://x.com/vxunderground)),
  often among the first to report ransomware leaks and breach claims.

> [!WARNING]
> Threat actors have **impersonated vx-underground** (e.g., a ransomware group
> in 2023 used the name to muddy attribution). Only trust content from the
> official domain and the official GitHub org listed below. Treat any "vx-underground"
> file sent to you directly as hostile.

### Official channels

| Channel | URL | Notes |
| --- | --- | --- |
| Website | <https://vx-underground.org> | Main library; full-text search across file/folder names |
| GitHub org | <https://github.com/vxunderground> | Source code, papers, tooling |
| X / Twitter | <https://x.com/vxunderground> | News, leak verification, new uploads |

---

## Site Collections

| Section | What's in it | Typical use |
| --- | --- | --- |
| **Samples** | Malware binaries, organized by family and date | Ghidra practice, YARA testing, sandbox runs |
| **APTs** | Vendor/government threat reports grouped by year, many with matching samples | Actor profiling, ATT&CK mapping, detection gaps |
| **Papers** | Offensive and defensive research papers, zines, technique write-ups | Learning techniques before detecting them |
| **Archive** | Historical collections (old VX groups, legacy viruses) | History, classic technique study |
| **Builders** | Leaked malware/ransomware builders | Detection engineering only; highest-risk folder |
| **Best Of** | Curated highlights | Starting point when browsing |
| **Torrents** | Bulk collection downloads | Large offline corpora (plan storage first) |

---

## Official GitHub Repositories

| Repository | Purpose | Use in this repo's workflows |
| --- | --- | --- |
| [MalwareSourceCode](https://github.com/vxunderground/MalwareSourceCode) | Malware source across many platforms and languages | Read how a technique is implemented before writing detection; pair with the [Checklists](../Checklists/README.md) |
| [VXUG-Papers](https://github.com/vxunderground/VXUG-Papers) | Research code and papers from community members | Technique deep dives; feeds [Tradecraft](../Tradecraft/README.md) study |
| [VX-API](https://github.com/vxunderground/VX-API) | C/C++ library of functions that replicate malware behavior | Generate known-bad telemetry in a lab to test EDR/SIEM rules |
| [ThreatIntelligenceDiscordBot](https://github.com/vxunderground/ThreatIntelligenceDiscordBot) | Posts updates from clearnet sources and ransomware actor sites | Self-hosted leak-site/threat feed for a SOC channel |

> [!NOTE]
> Repo contents and star counts change. Check each repo's README for current
> layout and license before scripting against it.

---

## Safe Intake Workflow

```text
1. Lab ready?      isolated VM, host-only/no network, clean snapshot taken
2. Download        from vx-underground.org or the official GitHub only
3. Move in         transfer the still-encrypted archive into the lab VM
4. Verify          hash before extraction; compare to the listing / VirusTotal
5. Extract         inside the VM only
6. Analyze         static first (strings, PE info, Ghidra), dynamic last
7. Produce         YARA / Sigma / IOCs / write-up
8. Revert          roll the VM back to the clean snapshot
```

### 1. Lab requirements

- Dedicated analysis VM (e.g., [FLARE-VM](https://github.com/mandiant/flare-vm)
  for Windows samples, [REMnux](https://remnux.org/) for Linux tooling) with a
  clean snapshot. See [virtualmachines.md](../Documentation/virtualmachines.md).
- **No shared folders, no clipboard sharing, no bridged networking.** Use
  host-only or an isolated internal network; add a fake-internet service such as
  INetSim on REMnux when you need dynamic network behavior.
- Never on your daily-driver host, a client-facing machine, or a NAS/TrueNAS
  share that other systems mount.

### 2–4. Download, move, verify

Keep archives encrypted until they are inside the lab. On the analysis VM:

```bash
# Hash the archive and the payload so you can track it in notes and IOC sets
sha256sum sample.7z

# List contents without extracting
7z l sample.7z
```

### 5. Extract

Packaged archives from vx-underground "may or may not" use the industry-standard
password **`infected`**, per the MalwareSourceCode README. Individual unpacked
files usually have no password.

```bash
# Extract into a dedicated working folder inside the lab VM
mkdir -p ~/cases/<case-id>/raw
7z x -p'infected' sample.7z -o"$HOME/cases/<case-id>/raw"

# Hash every extracted file
find ~/cases/<case-id>/raw -type f -exec sha256sum {} + | tee ~/cases/<case-id>/hashes.txt
```

> [!TIP]
> When you move a sample *out* of the lab (to a colleague or another VM), re-zip
> it with the password `infected` and rename the extension (e.g. `.exe_`) so
> nothing auto-executes it and mail/AV gateways do not silently strip it.

### 6. Analyze

| Stage | Where in this repo |
| --- | --- |
| File triage, strings, imports | [Ghidra guide, Part I–II](./ghidra-guide-index.md#part-ii-basic-ghidra-usage) |
| Packed / obfuscated samples | [Ghidra guide, Part V](./ghidra-guide-index.md#part-v-real-world-applications) |
| Headless batch analysis of many samples | [Ghidra guide, Part III](./ghidra-guide-index.md#part-iii-customizing-and-extending-ghidra) |
| Memory artifacts after detonation | [Digital Forensics](../IncidentResponse/Digital-Forensics/README.md) |
| Host telemetry while detonating | [Endpoint Visibility](../IncidentResponse/Endpoint-Visibility/README.md) |

### 7. Produce something defensive

- **YARA:** write the rule against the sample, then test it against a clean
  corpus to check false positives.
- **SIEM / Sigma:** detonate with Sysmon running and build detections from the
  telemetry; see [SIEM](../IncidentResponse/SIEM/README.md).
- **IOCs:** hashes, C2 domains, mutexes, registry keys; push them into MISP or
  OpenCTI (see [OSINT & Threat Intel](../Tradecraft/osint-threat-intel.md#threat-intelligence-platforms)).
- **ATT&CK mapping:** tag behaviors with [MITRE ATT&CK](https://attack.mitre.org/)
  technique IDs so the write-up lines up with the APT reports.

---

## Using the APT Collection for Threat Intel

1. Pick the actor or campaign relevant to your sector.
2. Read the vendor reports in the APT folder for that year.
3. Pull listed hashes, then grab the matching samples (from VXUG or
   [MalwareBazaar](https://bazaar.abuse.ch/)).
4. Map observed behaviors to ATT&CK and compare against your current detections.
5. Close gaps, then retest with the sample or with VX-API–generated telemetry.

This is the same intelligence cycle described in
[osint-threat-intel.md](../Tradecraft/osint-threat-intel.md#osint-methodology),
with real samples as the collection source.

---

## Complementary Sample Sources

| Source | Strength |
| --- | --- |
| [MalwareBazaar](https://bazaar.abuse.ch/) (abuse.ch) | Fresh, tagged samples with API and hash exports |
| [VirusShare](https://virusshare.com/) | Very large hash sets and bulk archives (account required) |
| [VirusTotal](https://www.virustotal.com/) | Reputation, relationships, retrohunt (sample download requires paid tiers) |
| [theZoo](https://github.com/ytisf/theZoo) | Small, curated live-malware repo for teaching |

---

## Risks and Rules

> [!CAUTION]
> - **Builders and VX-API produce working malicious capability.** Use them only
>   to generate lab telemetry. Never compile or deploy their output outside the
>   lab, and never use them in a client engagement without a written scope that
>   explicitly covers it.
> - Some samples are **wormable or destructive** (ransomware, wipers). Assume
>   every sample will try to spread and encrypt anything it can reach.
> - Samples in your possession may be subject to client NDAs, export rules, or
>   local computer-misuse law. Document why you hold each sample.
> - Disable cloud sample submission in any AV you run in the lab unless you
>   intend to share the file.

---

## References

- [vx-underground](https://vx-underground.org)
- [vx-underground on GitHub](https://github.com/vxunderground)
- [Wikipedia: vx-underground](https://en.wikipedia.org/wiki/Vx-underground)
- [The Record: How vx-underground is building a hacker's dream library](https://therecord.media/how-vx-underground-is-building-a-hackers-dream-library)
- [Lenny Zeltser: How to share malware samples with other researchers](https://zeltser.com/share-malware-with-researchers)
- [MITRE ATT&CK](https://attack.mitre.org/)

## See also

- [Reverse Engineering index](./README.md)
- [Ghidra Master Guide](./ghidra-guide-index.md)
- [OSINT & Threat Intelligence](../Tradecraft/osint-threat-intel.md)
- [Homelab](../Homelab/README.md)
- [Incident Response](../IncidentResponse/README.md)
- [GLOSSARY.md](../GLOSSARY.md)

---
[⬅️ Back to Master Index](../README.md) | [🎯 Role Navigation](../START_HERE.md) | [Legal Notice](../LEGAL.md)
