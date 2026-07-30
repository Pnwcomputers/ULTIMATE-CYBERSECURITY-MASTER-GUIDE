# 📖 Glossary

_Last reviewed: 2026-07-30_

A quick reference for acronyms and terms used across this repository. Terms are grouped by domain; within each group they are alphabetical. Link to a term with an anchor, e.g. `[C2](GLOSSARY.md#c2--command-and-control)`.

## General & Governance

- **APT — Advanced Persistent Threat:** A well-resourced adversary (often nation-state) that maintains long-term, stealthy access to a target.
- **CIA Triad:** Confidentiality, Integrity, Availability — the three core goals of information security.
- **CVE — Common Vulnerabilities and Exposures:** A public identifier for a specific known vulnerability (e.g., `CVE-2024-3094`).
- **CVSS — Common Vulnerability Scoring System:** A 0–10 severity score for a vulnerability.
- **IoC — Indicator of Compromise:** An artifact (hash, IP, domain, filename) that suggests a breach.
- **OPSEC — Operational Security:** Practices that prevent an adversary (or a target) from observing your activity or attribution.
- **PoC — Proof of Concept:** Minimal code/steps demonstrating that a vulnerability is exploitable.
- **RoE — Rules of Engagement:** The agreed scope, timing, and constraints of an authorized security engagement.
- **TTP — Tactics, Techniques, and Procedures:** The behavioral patterns of an adversary, as catalogued by MITRE ATT&CK.

## Offensive / Red Team

- **AV / EDR — Antivirus / Endpoint Detection and Response:** Endpoint security controls; EDR adds behavioral detection and telemetry beyond signature-based AV.
- **Beaconing:** The periodic call-home traffic an implant sends to its C2 server.
- **C2 — Command and Control:** The infrastructure and channel an operator uses to control compromised hosts. See [Tradecraft/c2-frameworks.md](Tradecraft/c2-frameworks.md).
- **LOLBin — Living-Off-the-Land Binary:** A legitimate, signed system binary (e.g., `certutil`, `rundll32`) abused to evade detection.
- **Lateral Movement:** Techniques for moving from one compromised host to others within a network.
- **Payload:** The code that executes on a target to achieve the attacker's objective (e.g., a reverse shell).
- **Persistence:** Mechanisms that let an attacker retain access across reboots/logins. See [Checklists/Persistence.md](Checklists/Persistence.md).
- **Pivoting:** Routing traffic through a compromised host to reach otherwise-unreachable network segments.
- **Privilege Escalation (PrivEsc):** Gaining higher permissions than initially obtained (local or domain).
- **Reverse Shell:** A shell where the target connects back to the attacker's listener (vs. a bind shell).

## Defensive / Blue Team

- **DFIR — Digital Forensics and Incident Response:** The combined discipline of investigating and responding to incidents.
- **EDR:** See Offensive section — the defender's primary endpoint telemetry/response tool.
- **IDS / IPS — Intrusion Detection / Prevention System:** Network sensors that detect (IDS) or block (IPS) malicious traffic.
- **IR — Incident Response:** The structured process of detecting, containing, eradicating, and recovering from a security incident. See [IncidentResponse/README.md](IncidentResponse/README.md).
- **SIEM — Security Information and Event Management:** A platform that centralizes logs and generates alerts (e.g., ELK, Wazuh, Splunk).
- **SOAR — Security Orchestration, Automation, and Response:** Automation layered on top of a SIEM/workflow.
- **Sigma:** A generic, vendor-neutral signature format for SIEM detection rules.
- **YARA:** A pattern-matching language for identifying/classifying malware samples.

## OSINT & Threat Intel

- **OSINT — Open-Source Intelligence:** Intelligence gathered from publicly available sources. See [OSINT/OSINT_GUIDE.md](OSINT/OSINT_GUIDE.md).
- **Pivot (OSINT):** Using one identifier (email, username, domain) to discover linked identifiers.
- **SOCMINT — Social Media Intelligence:** OSINT derived specifically from social platforms.
- **TI — Threat Intelligence:** Operationalized knowledge about adversaries and their infrastructure. See [Tradecraft/osint-threat-intel.md](Tradecraft/osint-threat-intel.md).

## Hardware, RF & Firmware

- **JTAG / SWD:** Debug interfaces for reading/writing microcontroller memory and firmware.
- **I²C / SPI / UART:** Common serial bus protocols probed during hardware analysis. See [HardwareHacking/](HardwareHacking/).
- **SBC — Single-Board Computer:** A compact computer on one board (e.g., Raspberry Pi) used for DIY tooling.
- **SDR — Software-Defined Radio:** A radio whose signal processing is done in software (e.g., HackRF, RTL-SDR). See [SDR/](SDR/).
- **Firmware:** The low-level software embedded in a device's non-volatile memory.

## Frameworks & Standards

- **MITRE ATT&CK:** A knowledge base of adversary TTPs, referenced throughout the checklists. <https://attack.mitre.org>
- **NIST CSF — Cybersecurity Framework:** A risk-management framework (Identify, Protect, Detect, Respond, Recover). <https://www.nist.gov/cyberframework>
- **OWASP:** The Open Worldwide Application Security Project; publisher of the Top 10 web risks. <https://owasp.org>
- **CISA:** The U.S. Cybersecurity and Infrastructure Security Agency. <https://www.cisa.gov>

---
[⬅️ Back to Master Index](README.md) | [🎯 Role Navigation](START_HERE.md) | [Legal Notice](LEGAL.md)
