# Tradecraft Reference

Operational security tradecraft for red team, blue team, and purple team practitioners. Each file is a deep-dive reference covering methodology, tooling, TTPs, detection logic, and defensive countermeasures.

---

## Contents

| File | Description |
|---|---|
| [c2-frameworks.md](c2-frameworks.md) | Cobalt Strike, Sliver, and Havoc — architecture, deployment, OpSec, malleable C2, infrastructure, and detection |
| [lolbins-lolbas.md](lolbins-lolbas.md) | Living off the land — Windows LOLBins for execution, download, lateral movement, persistence, and credential access |
| [osint-threat-intel.md](osint-threat-intel.md) | OSINT methodology, passive recon, DNS/infra enumeration, people intelligence, threat intel platforms, and operationalization |
| [network-detection.md](network-detection.md) | Packet capture, Zeek/Suricata analysis, C2 traffic detection, DNS tunneling, lateral movement, and network forensics |
| [active-directory.md](active-directory.md) | AD enumeration, credential attacks, Kerberos abuse, privilege escalation paths, domain persistence, detection, and hardening |
| [av-edr-evasion.md](av-edr-evasion.md) | How attackers evade antivirus and endpoint detection/response solutions |

---

## Usage

These references are structured for **dual-use** — each file covers both offensive technique context and the corresponding detection/defensive guidance. Sections are clearly labeled:

- **Attack / technique sections** — Understand how attacks work, what tools are used
- **Detection & Hunting sections** — Sigma rules, KQL queries, event IDs, behavioral indicators
- **Defensive sections** — Hardening controls, configuration recommendations, monitoring priorities

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

- [`/hardware-hacking`](../hardware-hacking/) — Physical and embedded device attacks
- [`/payloads`](../payloads/) — ESP32 and Raspberry Pi pentesting platforms
- [`/tools`](../tools/) — Tool references and field guides

---

<div align="center">

**⚠️ USE THIS REPO RESPONSIBLY AND LEGALLY ⚠️**

*With great power comes great responsibility - and great legal liability.*

**Repository**: [ULTIMATE CYBERSECURITY MASTER GUIDE](https://github.com/Pnwcomputers/ULTIMATE-CYBERSECURITY-MASTER-GUIDE)

**Maintained by**: [Pacific Northwest Computers](https://github.com/Pnwcomputers)

---

🔴 **THESE ARE OFFENSIVE SECURITY TOOLS** 🔴

🔴 **UNAUTHORIZED USE = FEDERAL CRIME** 🔴

🔴 **UP TO 20 YEARS IMPRISONMENT** 🔴

🔴 **WRITTEN AUTHORIZATION MANDATORY** 🔴

---
