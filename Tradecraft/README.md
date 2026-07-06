# 🗡️ Tradecraft


## 🎯 Purpose
Deep-dive tradecraft reference for red team, blue team, and purple team practitioners - covering offensive TTPs, detection logic, and defensive countermeasures across AD, C2, AV/EDR evasion, LOLBins, network detection, and OSINT.

## ⚙️ Function
Indexes 6 deep-dive files: Active Directory attacks/defense, AV/EDR evasion techniques, C2 framework deployment and detection, LOLBins/LOLBAs, network detection methodology, and OSINT/threat intelligence tradecraft. Each file covers both offensive technique and defensive detection.

## 🏆 Goal
Provide a single reference for understanding attack techniques and the corresponding detection/hunting logic - useful for both red team planning and blue team detection engineering.

## 📋 When to Use
- Planning a red team engagement and selecting TTPs
- Building detection rules (Sigma, Sysmon, EDR) for specific attack techniques
- Purple team exercises where both sides need to understand the same technique
- Understanding the defensive perspective on a specific attack method

Operational security tradecraft for red team, blue team, and purple team practitioners. Each file is a deep-dive reference covering methodology, tooling, TTPs, detection logic, and defensive countermeasures.

<div align="center">

*Part of the [ULTIMATE CYBERSECURITY MASTER GUIDE](../README.md)*

[![PowerShell](https://img.shields.io/badge/PowerShell-Scripts-blue?style=for-the-badge&logo=powershell)]()
[![Bash](https://img.shields.io/badge/Bash-Scripts-green?style=for-the-badge&logo=gnu-bash)]()
[![Python](https://img.shields.io/badge/Python-Scripts-yellow?style=for-the-badge&logo=python)]()
[![YARA](https://img.shields.io/badge/YARA-Rules-orange?style=for-the-badge&logo=virustotal)]()
[![Sigma](https://img.shields.io/badge/Sigma-Detection_Rules-purple?style=for-the-badge&logo=elastic)]()
[![Windows](https://img.shields.io/badge/Windows-Tools-0078D6?style=for-the-badge&logo=windows)]()
[![Linux](https://img.shields.io/badge/Linux-Tools-FCC624?style=for-the-badge&logo=linux&logoColor=black)]()

</div>

---

---

## 🎯 Purpose
The folder-level index for offensive tradecraft deep-dives - content too specialized/detailed to fit inline in the master guides, which instead link out to these 6 files (see e.g. [ultimate_cybersecurity_master_guide.md](../ultimate_cybersecurity_master_guide.md) Part XI and [ENHANCED_MASTER_GUIDE.md](../ENHANCED_MASTER_GUIDE.md) Part 6).

## ⚙️ Function
Lists all 6 Tradecraft files with descriptions, explains the dual-use (offense + defense) structure shared across every file in the folder, maps each file to its primary MITRE ATT&CK tactics, and cross-links to related folders (Checklists, HardwareHacking, Scripts, Documentation). Differs from those master guides by containing the actual deep technical content rather than a summary; differs from [Checklists/](../Checklists/), which provides quick-reference checklists rather than full methodology write-ups.

## 🏆 Goal
A reader can find the right tradecraft file for a given ATT&CK tactic or technique and understands upfront that every file pairs offensive technique with matching detection/defense guidance.

## 📋 When to Use
As the entry point into the Tradecraft/ folder, or when looking up which file covers a specific ATT&CK tactic.

## Contents

| File | Description |
|---|---|
| [c2-frameworks.md](c2-frameworks.md) | Cobalt Strike, Sliver, and Havoc - architecture, deployment, OpSec, malleable C2, infrastructure, and detection |
| [lolbins-lolbas.md](lolbins-lolbas.md) | Living off the land - Windows LOLBins for execution, download, lateral movement, persistence, and credential access |
| [osint-threat-intel.md](osint-threat-intel.md) | OSINT methodology, passive recon, DNS/infra enumeration, people intelligence, threat intel platforms, and operationalization |
| [network-detection.md](network-detection.md) | Packet capture, Zeek/Suricata analysis, C2 traffic detection, DNS tunneling, lateral movement, and network forensics |
| [active-directory.md](active-directory.md) | AD enumeration, credential attacks, Kerberos abuse, privilege escalation paths, domain persistence, detection, and hardening |
| [av-edr-evasion.md](av-edr-evasion.md) | How attackers evade antivirus and endpoint detection/response solutions |

---

## Usage

These references are structured for **dual-use** - each file covers both offensive technique context and the corresponding detection/defensive guidance. Sections are clearly labeled:

- **Attack / technique sections** - Understand how attacks work, what tools are used
- **Detection & Hunting sections** - Sigma rules, KQL queries, event IDs, behavioral indicators
- **Defensive sections** - Hardening controls, configuration recommendations, monitoring priorities

---

## MITRE ATT&CK Coverage

| File | Primary ATT&CK Tactics |
|---|---|
| C2 Frameworks | Command and Control (TA0011) |
| LOLBins | Defense Evasion (TA0005), Execution (TA0002), Lateral Movement (TA0008) |
| OSINT & Threat Intel | Reconnaissance (TA0043), Resource Development (TA0042) |
| Network Detection | Exfiltration (TA0010), Command and Control (TA0011) |
| Active Directory | Credential Access (TA0006), Privilege Escalation (TA0004), Lateral Movement (TA0008), Persistence (TA0003) |

---

## Related Sections

- [`/Checklists`](../Checklists/) - Quick-reference attack checklists that pair with these deep dives
- [`/HardwareHacking`](../HardwareHacking/) - Physical and embedded device attacks
- [`/Scripts`](../Scripts/) - Offensive scripts, payloads, and automation tools
- [`/Documentation`](../Documentation/) - Tool references and field guides

---

<div align="center">

**⚠️ USE THIS REPO RESPONSIBLY AND LEGALLY ⚠️**

*With great power comes great responsibility - and great legal liability.*

**Repository**: [ULTIMATE CYBERSECURITY MASTER GUIDE](https://github.com/Pnwcomputers/ULTIMATE-CYBERSECURITY-MASTER-GUIDE)

**Maintained by**: [Pacific Northwest Computers](https://github.com/Pnwcomputers)

🔴 **THESE ARE OFFENSIVE & DEFENSIVE SECURITY TACTICS** 🔴

🔴 **UNAUTHORIZED USE = FEDERAL CRIME** 🔴

🔴 **UP TO 20 YEARS IMPRISONMENT** 🔴

---

## Related Files
- [active-directory.md](active-directory.md) - AD attacks, Kerberos abuse, BloodHound, persistence
- [av-edr-evasion.md](av-edr-evasion.md) - AV/EDR evasion: AMSI bypass, process injection, obfuscation
- [c2-frameworks.md](c2-frameworks.md) - Cobalt Strike, Sliver, Havoc: deployment and detection
- [lolbins-lolbas.md](lolbins-lolbas.md) - LOLBins/LOLBAs: living-off-the-land techniques
- [network-detection.md](network-detection.md) - Network traffic analysis and threat detection
- [osint-threat-intel.md](osint-threat-intel.md) - OSINT methodology and threat intelligence platforms
- [../Checklists/README.md](../Checklists/README.md) - Operational checklists that implement these techniques
