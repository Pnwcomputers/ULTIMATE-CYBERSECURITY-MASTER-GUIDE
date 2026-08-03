# 🔎 Digital Forensics (DFIR)

<div align="center">

**Post-incident artifact extraction and timeline reconstruction — memory, disk, and live response**

*Part of the [ULTIMATE CYBERSECURITY MASTER GUIDE](../../README.md) · [Incident Response](../README.md) section*

![Blue Team](https://img.shields.io/badge/Operations-Blue_Team-blue?style=for-the-badge)
![DFIR](https://img.shields.io/badge/Framework-DFIR-darkred?style=for-the-badge)
![Forensics](https://img.shields.io/badge/Focus-Artifact_Analysis-purple?style=for-the-badge)

</div>

---

## 🎯 Purpose
Index for the Digital Forensics sub-section — guides for acquiring and analyzing evidence after an incident: memory forensics, disk forensics, and volatile live-response collection.

## ⚙️ Function
Links to a guide per forensic domain — memory analysis with Volatility 3, disk acquisition/analysis with Autopsy and KAPE, and live volatile-data collection — organized around the order of volatility and sound evidence handling.

## 🏆 Goal
Enable a responder to capture the right evidence in the right order, analyze it to establish a timeline and indicators of compromise (IoCs), and do so without destroying the evidentiary value of what they collect.

## 📋 When to Use
- Investigating a compromised host after detection (see [Endpoint Visibility](../Endpoint-Visibility/README.md) / [SIEM](../SIEM/README.md) alerts)
- Deciding **what to collect first** from a running system before power-down
- Extracting malware, injected code, or IoCs from a memory image
- Building an incident timeline from disk artifacts (registry, event logs, prefetch)

---

## 📋 Table of Contents

- [Overview](#-overview)
- [Forensic Domains](#️-forensic-domains)
- [Analysis Guides](#-analysis-guides)
- [Order of Volatility](#-order-of-volatility)
- [⚠️ Evidence Handling & Legal Warning](#️-evidence-handling--legal-warning)
- [Contributing](#-contributing)
- [Resources](#-resources)

---

## 🎯 Overview

**Digital forensics** is the disciplined recovery and analysis of evidence from computer systems. In an IR context it answers *what happened, how, when, and what was affected* — and, when a case may involve legal action, it does so in a way that preserves the evidence's admissibility.

This sub-section covers the three domains you will use most: **memory**, **disk**, and **live volatile data**. Capture is governed by the *order of volatility* — the most transient evidence (RAM, network state) must be collected before it is lost.

> [!CAUTION]
> The act of investigating changes the system. Collect volatile evidence
> **before** shutting down, prefer read-only/write-blocked access to disks, and
> document every step. If a case may go to court, follow strict chain of custody.

---

## 🗂️ Forensic Domains

| Domain | Guide | Evidence | Primary Tools |
|--------|-------|----------|---------------|
| 🧠 **Memory** | **[Memory/volatility_cheatsheet.md](./Memory/volatility_cheatsheet.md)** | RAM dump (volatile) | Volatility 3 |
| 🚨 **Live Response** | **[LiveData/live_data_collection.md](./LiveData/live_data_collection.md)** | Running-system state | WinPmem, DumpIt, avml |
| 💽 **Disk** | **[Disks/autopsy_kape.md](./Disks/autopsy_kape.md)** | Disk image (non-volatile) | Autopsy, KAPE, FTK Imager |

---

## 📚 Analysis Guides

### 🧠 [Memory Forensics — Volatility 3](./Memory/volatility_cheatsheet.md)
The full analysis workflow for Windows and Linux memory dumps. Covers the Volatility 3 plugin taxonomy (`windows.pslist`, `windows.cmdline`, `windows.netscan`, `windows.malfind`, `windows.dlllist`), process and network-connection analysis, injected-code detection, registry-hive extraction, and artifact recovery — the fastest route to malware and IoCs that never touch disk.

### 🚨 [Live Response Collection](./LiveData/live_data_collection.md)
Capturing **volatile** evidence from a running system before power-down. Covers the volatile-data priority order, memory acquisition (WinPmem, DumpIt, `avml` on Linux), network state (`netstat`/`ss`, active connections), process listing with hash verification, prefetch/amcache, registry-hive export, browser artifacts, and chain-of-custody documentation.

### 💽 [Disk Forensics — Autopsy & KAPE](./Disks/autopsy_kape.md)
Acquiring and analyzing disk images. Covers imaging (FTK Imager, `dd`), the Autopsy case workflow (full forensic platform), **KAPE** targets/modules for rapid triage collection, timeline analysis, file carving, hash verification, and report generation.

---

## 🧭 Order of Volatility

```text
Collect most-volatile first (adapted from RFC 3227):

1. CPU registers, cache
2. RAM (memory dump)  ........... Live Response + Memory guides
3. Network state, running processes, open connections
4. Temp files, swap/pagefile
5. Disk (image it)  ............. Disk Forensics guide
6. Remote logs / monitoring data
7. Physical config, archival media
```

> [!TIP]
> Detection usually comes from the [SIEM](../SIEM/README.md) or
> [endpoint telemetry](../Endpoint-Visibility/README.md); forensics is what you
> do **after** an alert to confirm, scope, and reconstruct the incident.

---

## ⚠️ Evidence Handling & Legal Warning

```text
═══════════════════════════════════════════════════════════════
                 ⚠️  PRESERVE EVIDENTIARY VALUE  ⚠️
═══════════════════════════════════════════════════════════════

1. CHAIN OF CUSTODY
   ► If the case may involve law enforcement or litigation, follow strict
     Chain of Custody: document who, what, when, where for every item.
   ► Use write-blockers for disk imaging; verify with hashes (MD5+SHA-256).
   ► Mishandling can render evidence inadmissible.

2. MINIMIZE FOOTPRINT
   ► Investigating alters the system. Prefer trusted, statically-linked tools
     run from external media; avoid tools that overwrite volatile memory.

3. AUTHORIZATION & PRIVACY
   ► Only analyze systems you own or are explicitly authorized (in writing) to
     examine. Forensic access to others' systems can be unlawful.
   ► Images/memory contain PII/credentials — store encrypted, share sanitized.

4. MALWARE SAFETY
   ► Analyze recovered malware only in isolated, host-only environments.
   ► Do not upload targeted/proprietary samples to public sandboxes — it can
     tip off the attacker.
═══════════════════════════════════════════════════════════════
```

---

## 🤝 Contributing

Contributions from DFIR analysts are welcome.

**What we accept:**
- ✅ Volatility plugin recipes and analysis walkthroughs
- ✅ KAPE targets/modules and Autopsy workflow tips
- ✅ Live-response scripts (with volatility-order rationale)
- ✅ Artifact-location references (registry persistence, browser paths)

**Guidelines:**
1. Sanitize any sample artifacts of real PII/credentials.
2. Note tool **versions** (e.g., Volatility 3.x).
3. Describe the investigative value in your PR.

---

## 📚 Resources

- **Volatility 3:** <https://github.com/volatilityfoundation/volatility3>
- **KAPE (Kroll):** <https://www.kroll.com/kape>
- **Autopsy / The Sleuth Kit:** <https://www.autopsy.com/>
- **RFC 3227 — Evidence Collection & Archiving:** <https://www.rfc-editor.org/rfc/rfc3227>
- **The DFIR Report (real-world timelines):** <https://thedfirreport.com/>
- **SANS DFIR posters & cheat sheets:** <https://www.sans.org/posters/>

---

## 🔗 Quick Links

- [⬅️ Incident Response section](../README.md)
- [👁️ Endpoint Visibility](../Endpoint-Visibility/README.md)
- [📊 SIEM deployment guides](../SIEM/README.md)
- [📖 Glossary](../../GLOSSARY.md) (DFIR, IoC, chain of custody…)
- [🏠 Main Repository](../../README.md)

---

<div align="center">

**🛡️ Collect carefully, document everything — evidence handled wrong is evidence lost.**

*Maintained by [Pacific Northwest Computers (PNWC)](https://github.com/Pnwcomputers)*

</div>

---
[⬅️ Back to Master Index](../../README.md) | [🎯 Role Navigation](../../START_HERE.md) | [Legal Notice](../../LEGAL.md)
