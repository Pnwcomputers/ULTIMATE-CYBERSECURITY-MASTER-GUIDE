# 🛡️ ULTIMATE CYBERSECURITY MASTER GUIDE

<p align="center">
  <img src="./assets/cybersecurityguide.png" alt="PNWC Ultimate Cybersecurity Master Guide" width="600"/>
</p>

<p align="center"><strong>Professional Cybersecurity Knowledge Base · Red Team · Blue Team · Purple Team</strong></p>

<p align="center">
  <img src="https://img.shields.io/badge/Maintained-Yes-green" alt="Maintained"/>
  <img src="https://img.shields.io/badge/Books%20Referenced-70%2B-blue" alt="Books"/>
  <img src="https://img.shields.io/badge/PNWC%20Internal%20Docs-90%2B-orange" alt="Docs"/>
  <img src="https://img.shields.io/badge/OSINT%20Tools-400%2B-purple" alt="OSINT"/>
  <img src="https://img.shields.io/badge/Scripts-Source_Collection-red" alt="Scripts"/>
  <img src="https://img.shields.io/badge/License-Educational%20Use-yellow" alt="License"/>
  <img src="https://img.shields.io/github/last-commit/Pnwcomputers/ULTIMATE-CYBERSECURITY-MASTER-GUIDE" alt="Last Commit"/>
</p>

> **Compiled from 70+ expert books · 90+ PNWC internal documents · custom tools & scripts**  
> *Abide by the [Legal Terms of Use & Disclaimer](./LEGAL.md) for the use and misuse of this repository.*

> "Under pressure, you don't rise to the occasion; you fall to the level of your training."
>
> "It ain't what you don't know that gets you into trouble. It's what you know for sure that just ain't so."

---

## 🧭 About This Index

This README is the repository's front door: it lists the main sections, subsection indexes, and selected guides. 

Each section link below opens its **readable README index directly**, not GitHub's file browser. Use the linked chapter and guide titles to move through the material; the code/file listing is optional for people seeking scripts or source.

Use [START_HERE.md](./START_HERE.md) to navigate by role or goal. 

The three [primary master guides](#primary-master-guides) contain technical material; this page helps you find it.

<h1 align="center"><strong>THANK YOU FOR CHECKING THIS OUT!</strong></h1>

---
## 🎯 START HERE

### 🆕 New To IT/Computers/Networks In General? - READ OUR [IT MANUAL](https://pnw-computers.github.io/IT-Manual/) TO GET YOURSELF STARTED!

### ⭐ **[START_HERE.Md](./START_HERE.md) - START HERE IF YOU ARE READY TO JUMP IN!**

Your complete navigation guide with quick paths for every role and purpose (Red Team, Blue Team, OSINT, Forensics, Homelab, Career).


---

## 🧭 Navigate By Area


**New portable hardware lab:** [M5StickC Plus2 / HackStarterPack](./HardwareHacking/m5stickc-plus2-hackstarterpack.md) — model-specific IR, Sub-GHz CC1101, BLE/HID and safe captive-portal exercises, with credited upstream sources.

**Browse without opening the GitHub Code file list:** choose a subject in the table below, then select a linked guide from that section's README. For a reader-first route, [START HERE](./START_HERE.md).

### Defensive Security Quick Paths

| Resource | Description |
|---|---|
| [Incident Response](./IncidentResponse/README.md) | Blue Team triage and incident response |
| [Honeypot Platforms & DIY Sensors](./IncidentResponse/HoneyPot/readme.md) | Defensive deception labs and reporting |
| [Kismet/nzyme IDS & IPS](./IncidentResponse/IDS%26IPS/readme.md) | Wireless and network intrusion detection |
| [Wazuh & Other SIEMs](./IncidentResponse/SIEM/README.md) | Centralized logs, detections and alerts |
| [Wireless/Wardriving](./Wardriving/README.md) | Authorized wireless surveys |

A grouped map of the whole repository. Prefer routing by **role/goal**? Use
[START_HERE.md](./START_HERE.md). Looking for section and guide listings? See
[Supporting Guides & Reference](#supporting-guides) below.

| Area | Start here | Also in this area |
|------|-----------|-------------------|
| 🚀 **Start & Master Guides** | [START_HERE.md](./START_HERE.md) | [Ultimate](./ultimate_cybersecurity_master_guide.md) · [Enhanced](./ENHANCED_MASTER_GUIDE.md) · [Specialized Topics](./SPECIALIZED_TOPICS_GUIDE.md) · [Cliff Notes](./cybersecurity_cliff_notes.md) |
| 🗡️ **Offensive Security** | [Tradecraft](./Tradecraft/README.md) | [Pentoo Linux](./Tradecraft/pentoo-linux-guide.md) · [Advanced Techniques](./advanced_techniques_supplement.md) · [Part 2](./advanced_techniques_part2.md) · [PlayBooks](./PlayBooks/README.md) · [Checklists](./Checklists/README.md) |
| 🕸️ **App, Cloud & Container** | [WebAppSecurity](./WebAppSecurity/README.md) | [Cloud](./Cloud/README.md) · [ContainerSecurity](./ContainerSecurity/README.md) |
| 🛡️ **Defensive & Incident Response** | [IncidentResponse](./IncidentResponse/README.md) | [REMnux Malware Analysis](./ReverseEngineering/remnux-malware-analysis-guide.md) · [Endpoint Visibility](./IncidentResponse/Endpoint-Visibility/README.md) · [SIEM](./IncidentResponse/SIEM/README.md) · [IDS & IPS](./IncidentResponse/IDS%26IPS/readme.md) · [Honeypots](./IncidentResponse/HoneyPot/readme.md) · [Raspberry Pi](./IncidentResponse/HoneyPot/raspberry-pi-honeypot-lab.md) · [Proxmox VM](./IncidentResponse/HoneyPot/proxmox-vm-honeynet.md) · [ESP32-S3](./IncidentResponse/HoneyPot/esp32-s3-honeypots.md) · [Honeypots → Wazuh](./IncidentResponse/HoneyPot/wazuh-honeypot-integration.md) · [Digital Forensics](./IncidentResponse/Digital-Forensics/README.md) · [Homelab](./Homelab/README.md) |
| 🗄️ **Data Engineering & Automation** | [Data Engineering](./Data-Engineering/README.md) | [Secure Data Pipelines](./Data-Engineering/data_pipelines.md) · [Scripts](./Scripts/README.md) |
| 🔍 **OSINT & Recon** | [OSINT](./OSINT/README.md) | [Tools Catalog](./OSINT/OSINT_TOOLS_CATALOG.md) · [Tsurugi Linux OSINT](./OSINT/TSURUGI_LINUX_OSINT_GUIDE.md) · [Investigator Playbook](./OSINT/Playbook/README.md) |
| 📍 **Wireless Surveying & Wardriving** | [Wardriving](./Wardriving/README.md) | [SigRoam](./Wardriving/sigroam-scout-lite.md) · [Marauder](./Wardriving/esp32-marauder.md) · [Biscuit](./Wardriving/biscuit.md) · [AWOK Dual C5](./Wardriving/awok-dual-c5-biscuit.md) · [Wardrive Go](./Wardriving/wardrive-go.md) · [Kismet](./Wardriving/kismet.md) · [Wireshark Filters](./Documentation/wireshark-master-filters.md) · [Deauthentication Analysis](./Documentation/wifi-deauthentication-detection.md) · [Kismet + Wazuh Lab](./IncidentResponse/IDS%26IPS/kismet-wazuh-wireless-lab.md) · [nzyme + Wazuh](./IncidentResponse/IDS%26IPS/nzyme-wazuh-integration.md) |
| 📡 **Specialized & Hardware** | [SPECIALIZED_TOPICS_GUIDE.md](./SPECIALIZED_TOPICS_GUIDE.md) | [AI](./AI/README.md) · [SDR](./SDR/README.md) · [HardwareHacking](./HardwareHacking/README.md) · [HardwareTesting](./HardwareTesting/README.md) · [SpaceSecurity](./SpaceSecurity/README.md) · [Mobile](./Mobile/README.md) · [uConsole](./uConsole/README.md) |
| 🔐 **Governance, Crypto & Reference** | [Compliance](./Compliance/README.md) | [Cryptography](./Cryptography/README.md) · [Security Keys & Passkeys](./Cryptography/security-keys-passkeys.md) · [Encrypted Storage](./Cryptography/encrypted-storage.md) · [Documentation](./Documentation/README.md) · [GLOSSARY.md](./GLOSSARY.md) · [OPSEC](./OPSEC/README.md) |
| 📰 **Press Freedom & Source Safety** | [Press Freedom](./OPSEC/press-freedom/README.md) | [Device & Mobile Protection](./OPSEC/press-freedom/device-network-protection.md) · [Data Retention](./OPSEC/press-freedom/data-retention-removal.md) · [Duress & Seizure Response](./OPSEC/press-freedom/duress-seizure-response.md) |
| ⚖️ **Legal & Contributing** | [LEGAL.md](./LEGAL.md) | [STYLE_GUIDE.md](./STYLE_GUIDE.md) · [Contributing](./.github/CONTRIBUTING.md) · [Security Policy](./.github/SECURITY.md) |

---

<a id="primary-master-guides"></a>

## 📚 PRIMARY MASTER GUIDES

| Guide | Description |
|---|---|
| 🔥 **[Ultimate Cybersecurity Master Guide](./ultimate_cybersecurity_master_guide.md)** | THE main comprehensive guide - key takeaways from 70+ professional security books, full penetration testing lifecycle |
| 🔥 **[Enhanced Cybersecurity Master Guide](./ENHANCED_MASTER_GUIDE.md)** | All of the above + 90+ PNWC internal docs, KB articles, and operational experience layered in |
| 🔥 **[Specialized Topics Guide](./SPECIALIZED_TOPICS_GUIDE.md)** | Deep-dive into specialized/emerging domains: AI & LLM Security, Hardware Hacking, Hardware Testing, uConsole Cyberdeck, Space Security, SDR & RF Security |

---

<a id="supporting-guides"></a>

## 📖 SUPPORTING GUIDES & REFERENCE MATERIAL

### Curated Research & Practice

| Resource | Description |
|---|---|
| [M5StickC Plus2 Hardware Lab](./HardwareHacking/m5stickc-plus2-hackstarterpack.md) | Portable, model-specific hardware lab guidance |
| [Cypherpunk Historical Toolkit Review](./Documentation/cypherpunk-pentesting-toolkit-review.md) | Historical tools and their modern relevance |
| [Awesome OSINT List](./OSINT/awesome-osint-list-curated.md) | Curated OSINT discovery and research resources |
| [Awesome-Hacking / h4cker / Training Ecosystems](./Documentation/awesome-hacking-collections-integration.md) | Curated security-project and learning references |
| [Ethical CTF Pathways](./PlayBooks/security-training-lab-pathways.md) | Controlled lab and training progression |

These are source-attributed references, not claims that every upstream tool is installed or tested.

### Core References

| Resource | Description |
|---|---|
| **[Practical AI Usage](./AI/ai-usage-interaction-guide.md)** | Prompts, instructions, context, privacy and verifying results |
| **[Agent/Project Lanes & Milestones](./AI/agent-project-workflows.md)** | Goals, milestones, role-based agents, reviews and resume checkpoints |
| **[Fact-Checking & AI Audits](./AI/verification-and-ai-audits.md)** | Evidence-based checking of claims, sources and agent actions |
| **[Notebooks, GPTs & Plugins](./AI/ai-workspaces-notebooks-and-assistants.md)** | Projects, notebooks, reusable assistants and integrations |
| [Glossary](./GLOSSARY.md) | Acronyms and terms used across the repository (C2, EDR, IoC, TTP, OPSEC, SIEM, etc.) |
| **[Cheat Sheet & Reference Index](./Documentation/CHEATSHEET-REFERENCE-AUDIT-2026-10-31.md)** | Reviewed system administration, OSINT, wireless, forensics, Bash, SDR, ports and security quick references |
| **[Staged Client Security Assessment Blueprint](./PlayBooks/assessment-service-integration-map.md)** | Consent, OWASP/SCuBA checks, endpoint/DFIR collection, Atomic/Sigma validation, supply-chain checks, findings and retests |
| **[Upstream Security Project Source Register](./Documentation/upstream-security-projects-register.md)** | Verified project links, license considerations, workflow ownership, integration status and maintenance process |
| **[Security API Catalog & Cookbook](./Documentation/security-public-api-catalog.md)** | Curated Public APIs resources for OSINT, threat intelligence, NVD/CISA KEV, supply-chain and web/API assessment |
| **[Curated Technical Documentation](./Documentation/curated-technical-docs.md)** | Links to relevant documentation from Beautiful Docs: GitHub, Git, FreeBSD, FastAPI, Django, PostgreSQL, Redis, Packer and writing standards |
| **[Proxy Types, Froxy & DNS Leak Reference](./OPSEC/proxy-reference-froxy.md)** | Proxy trust comparison, SOCKS5/SSH and public-list risks; Froxy is for isolated research, not high-sensitivity traffic |
| **[Docker Operations & Security Cheat Sheet](./ContainerSecurity/docker-cli-operations-reference.md)** | Inspection-first Docker CLI/Compose commands, daemon/security boundaries, image/volume inventories and destructive-operation cautions |
| **[CLI Field Cheat Sheet (Devhints-informed)](./Documentation/devhints-cli-field-reference.md)** | Original command examples for shell, logs, curl/TLS, rsync, GnuPG, Git, Docker and session management |
| [Cybersecurity Cliff Notes](./cybersecurity_cliff_notes.md) | Quick command reference; the essentials at a glance |
| [Advanced Techniques - Part 1](./advanced_techniques_supplement.md) | Advanced Metasploit, cloud pentesting, lateral movement, pivoting, etc. |
| [Advanced Techniques - Part 2](./advanced_techniques_part2.md) | Exploit development, buffer overflows, shellcode, custom payloads, etc. |
| [DIY Hardware & Firmware Compatibility](./firmware-hardware-compatibility.md) | SBC-based DIY pentesting devices as well as compatibility & firmware guides |
| [Debian Linux Command Cheat Sheet](./Documentation/LinuxCheatSheet.md) | Linux CLI commands for Debian/Ubuntu/Kali/Parrot |
| [Arch Linux Command Cheat Sheet](./Documentation/ArchLinux_CheatSheet.md) | Linux CLI commands for Arch |
| [BlackArch Linux Cheat Sheet](./Documentation/blackarch.md) | Linux CLI commands for BlackArch |
| **[Wireshark Master Filter List](./Documentation/wireshark-master-filters.md)** | 133 indexed display filters, safe capture/BPF examples, TShark and defensive packet triage |
| **[Wireshark Field Cheat Sheet](./Documentation/wireshark-cheatsheet.md)** | Fast reference for TCP/DNS/DHCP/TLS/QUIC/802.11 and troubleshooting |
| [OSINT Cheat Sheet](./OSINT/OSINT_CHEATSHEET.md) | Quick-reference OSINT cheat sheet |

### Operational Sections

| Section | Description |
|---|---|
| 🤖 [AI Cybersecurity Resources](./AI/README.md) | Self-hosted AI agents (OpenClaw, AnythingLLM), LLM prompting for security, offline AI deployment, and AI-powered security workflows |
| 📋 [Checklists](./Checklists/README.md) | Pre-engagement, testing, and post-engagement checklists |
| ☁️ [Cloud Security](./Cloud/README.md) | Shared-responsibility models, common misconfigurations, and provider-specific attack surfaces and hardening for AWS, Azure/Entra ID, and GCP |
| 📋 [Compliance & GRC](./Compliance/README.md) | Governance, risk, and compliance guidance covering NIST CSF 2.0, ISO 27001, SOC 2, PCI DSS, CIS Controls, GDPR, HIPAA, CCPA, and control mapping |
| 📦 [Container & Kubernetes Security](./ContainerSecurity/README.md) | Container image and runtime attack surfaces, container escape techniques, and Kubernetes hardening using RBAC, Pod Security Standards, and network policies |
| 🔐 [Cryptography](./Cryptography/README.md) | Practical cryptography reference covering current and deprecated algorithms, TLS, password storage, key management, and post-quantum standards including FIPS 203, 204, and 205, plus classical ciphers, leetspeak, and cryptanalysis |
| 🔑 [Hardware Security Keys & Passkeys](./Cryptography/security-keys-passkeys.md) | FIDO2/WebAuthn, L1-L3+ certification, [SoloKeys](./Cryptography/solokeys-guide.md), passkeys and recovery workflows |
| 💾 [Encrypted Drives & USB Storage](./Cryptography/encrypted-storage.md) | BitLocker, LUKS, VeraCrypt, DIY vaults and [PhantomDrive](./Cryptography/phantomdrive-guide.md) research |
| 🗄️ [Data Engineering & Pipeline Infrastructure](./Data-Engineering/README.md) | General data engineering learning path, existing infrastructure resources, and a proposed documentation roadmap; start with [Secure Data Pipelines](./Data-Engineering/data_pipelines.md) for TLS, SSH, Git, structured logs, Redis/Memcached, Kafka, and Ansible |
| 📚 [Documentation](./Documentation/README.md) | Supplemental technical documentation, command references, and cheat sheets |
| 🔬 [Reverse Engineering](./ReverseEngineering/README.md) | Ghidra installation, binary analysis, scripting, headless workflows, version comparison, and safe malware sourcing via vx-underground |
| 🥷 [Hardware Hacking](./HardwareHacking/README.md) | Physical and electronic attack techniques against embedded systems, microcontrollers, SoCs, and cryptographic hardware |
| 🧰 [Hardware Testing](./HardwareTesting/README.md) | Diagnostic, benchmarking, and reliability stress-testing guides and scripts for PC test benches |
| 🏠 [Homelab Guides](./Homelab/README.md) | Building and maintaining safe, isolated labs for offensive and defensive security practice |
| 🚨 [Incident Response](./IncidentResponse/README.md) | Blue Team operations covering threat detection, log aggregation, artifact analysis, and standardized incident-response procedures — including dedicated [IDS & IPS](./IncidentResponse/IDS%26IPS/readme.md) (nzyme, Suricata/Zeek) and [Honeypot](./IncidentResponse/HoneyPot/readme.md) (OpenCanary, Cowrie, Dionaea, T-Pot, HoneyPi) deployment guides |
| 📱 [Mobile Security](./Mobile/README.md) | Kali NetHunter on OnePlus 6, [UserLAnd Linux environments on Android](./Mobile/UserLAnd/readme.md), Android and iOS application pentesting, mobile forensics, and field SOPs |
| 🥷 [Navigating the DarkWeb](https://navigating-the-darkweb.readthedocs.io/en/latest/) | A Comprehensive Guide to Darknets, Tools, and Intelligence in an online book written by [Sébastien Damaye](https://github.com/sebastiendamaye) |
| 🔬 [Network Audit Playbook](./PlayBooks/NetworkAuditPlayBook.md) | Field-ready professional network security audit procedure |
| 📋 [Operational Playbooks](./PlayBooks/cybersecurity_playbooks.md) | Full index of playbooks covering network audits, Wi-Fi assessments, incident response, phishing, and unauthorized-access investigations |
| 📰 [Press Freedom, Source Protection & Digital Safety](./OPSEC/press-freedom/README.md) | Journalist computer, cellphone, network and confidential-source security; lawful retention and disposal; duress and device seizure preparation |
| 🔴 [OPSEC](./OPSEC/README.md) | Operational security practices covering anonymity workflows, isolated virtual machines, identity separation, and personal rules for professionals |
| 🔍 [OSINT Guide, Tools & Techniques](./OSINT/OSINT_GUIDE.md) | Comprehensive OSINT methodology with 400+ categorized tools, investigation workflows, and automated VM setup |
| 📄 [PDF Resources](./PDF/README.md) | Curated PDF references and guides |
| 📚 [Playbooks Collection](./PlayBooks/README.md) | Simple, detailed, and multi-script Purple Team, Blue Team, Red Team, and incident-response exercises and procedures |
| 💻 [Scripts](./Scripts/README.md) | Security automation scripts, exploitation tools, reconnaissance utilities, payloads, and general-purpose programs |
| 📻 [SDR](./SDR/README.md) | Software Defined Radio theory, security assessment techniques, practical workflows and applications; RF, NFC/RFID, SubGhz |
| 📊 [SIEM Deployment Guides](./IncidentResponse/SIEM/README.md) | ELK Stack, Wazuh, Splunk, and Graylog deployment, setup, and configuration guides |
| 🎣 [SOP: Phishing Analysis Playbook](./PlayBooks/sop_phishing_analysis.md) | Standard operating procedure for phishing-email triage and analysis |
| 👾 [Space Security](./SpaceSecurity/README.md) | Offensive and defensive security across the space, ground, and communications segments of modern space systems |
| 🗡️ [Tradecraft](./Tradecraft/README.md) | Red Team, Blue Team, and Purple Team tradecraft covering Active Directory, C2 frameworks, AV/EDR evasion, LOLBins, threat intelligence, detection logic, and defensive countermeasures |
| 📟 [uConsole](./uConsole/README.md) | Configuration, portable pentesting setups, and operational workflows optimized for the [ClockworkPi](https://www.clockworkpi.com/) [uConsole](https://www.clockworkpi.com/uconsole) cyberdeck |
| 🚷 [Unauthorized Access Investigation Playbook](./PlayBooks/unauth_access.md) | Playbook for investigating suspected or confirmed unauthorized-access incidents |
| 📍 [Wardriving & Wireless Surveying](./Wardriving/README.md) | GNSS-tagged Wi-Fi/BLE inventory, Flipper/ESP32-C5 hardware, mobile and Kismet guides, field procedures, and private log handling |
| 🕸️ [Web Application Security](./WebAppSecurity/README.md) | OWASP Top 10 guidance and a complete web-application pentesting methodology covering reconnaissance, Burp Suite, injection, access control, and API testing |

### Subsection Indexes & Focused Entry Points

| Parent Area | Subsection / Guide | Coverage |
|---|---|---|
| AI | [AnythingLLM AgentFlows](./AI/AnythingLLM/README.md) | Configured security research and analysis flows |
| AI | [OpenClaw](./AI/OpenClaw/README.md) | Self-hosted agent setup on TrueNAS SCALE |
| Data Engineering | [Secure Data Pipelines](./Data-Engineering/data_pipelines.md) | Secure transport, parsing, enrichment, streaming, and deployment labs |
| Hardware Testing | [Python Diagnostic Suite](./HardwareTesting/py/README.md) | Automated hardware tests and result reporting |
| Incident Response | [Endpoint Visibility](./IncidentResponse/Endpoint-Visibility/README.md) | Sysmon, Linux audit/syslog, and Osquery telemetry |
| Incident Response | [SIEM](./IncidentResponse/SIEM/README.md) | Centralized search and security monitoring guides |
| Incident Response | [IDS & IPS](./IncidentResponse/IDS%26IPS/readme.md) | Wireless and wired intrusion detection guides |
| Incident Response | [Honeypots](./IncidentResponse/HoneyPot/readme.md) | Raspberry Pi, Proxmox VM, ESP32-S3, OpenCanary, Cowrie and Wazuh reporting, with direct project guides |
| Incident Response | [Digital Forensics](./IncidentResponse/Digital-Forensics/README.md) | Memory, disk, and live-response references |
| Incident Response | [Tsurugi Bento Portable DFIR](./IncidentResponse/Digital-Forensics/tsurugi-bento-portable-dfir-guide.md) | Windows field-response toolkit, live triage, Sysinternals, evidence export, RAM/disk acquisition decisions and integrity verification |
| Incident Response | [OpenBSD PF Firewall](./IncidentResponse/Firewalls/openbsd_pf.md) | Rulesets, network-edge deployment, monitoring, and lab validation |
| Reverse Engineering | [REMnux Malware Analysis](./ReverseEngineering/remnux-malware-analysis-guide.md) | Isolated malware-analysis workstation, Proxmox installation, offline triage, PE/PDF and network evidence workflows |
| Tradecraft | [Pentoo Linux](./Tradecraft/pentoo-linux-guide.md) | Gentoo-based penetration-testing platform, scoped assessments and wireless tool workflows |
| Reverse Engineering | [Ghidra Master Guide](./ReverseEngineering/ghidra-guide-index.md) | Five parts and 23 chapters; start with the section index |
| Reverse Engineering | [vx-underground](./ReverseEngineering/vx-underground.md) | Malware samples, source, APT reports, and a lab-only intake workflow |
| OPSEC | [Whonix + Kicksecure USB](./OPSEC/whonix-kicksecure-usb-guide.md) · [Tails USB](./OPSEC/tails-usb-setup-guide.md) | Distinct host/guest, persistence, installation, and validation workflows |
| SDR | [NanoVNA Field Guide](./SDR/nanovna/README.md) · [HackRF Audit Playbook](./PlayBooks/HackRFAuditPlayBook.md) | Antenna/RF measurements and spectrum-survey engagement procedures |
| Mobile | [UserLAnd](./Mobile/UserLAnd/readme.md) | Linux userspace on Android, with distribution-specific material |
| OSINT | [Investigator Playbook](./OSINT/Playbook/README.md) | Investigation workflow entry point |
| Scripts | [Bash Bunny](./Scripts/Bash/BashBunny/README.md) | Payload setup for authorized physical-access assessments |
| Scripts | [USB Rubber Ducky](./Scripts/Ducky/README.md) | DuckyScript compilation and setup |
| Scripts | [Shells & Stagers](./Scripts/GO/shells/README.md) | Source references for authorized security testing |
| uConsole | [CM4 / CM5 Setup Scripts](./uConsole/scripts/README.md) · [CM4 Safety Review](./uConsole/CM4-SAFETY-REVIEW.md) | Conservative CM4 preflight, CM5/Parrot setup and display recovery; explicit hardware validation required |
| Wardriving | [Field Workflow](./Wardriving/field-workflow.md) · [Data Handling](./Wardriving/data-handling.md) · [Wi-Fi Deauthentication Detection](./Documentation/wifi-deauthentication-detection.md) | Authorization, GPS-quality tests, archived results, WiGLE disclosure decisions |

---

### Maintenance & Historical Reviews

**Current integration/CI review:** [November 3, 2026 quality report](./Documentation/INTEGRATION-QUALITY-REVIEW-2026-11-03.md) describes today's merged updates, verified checks, corrections and runtime limitations.

| Resource | Purpose |
|---|---|
| [Audit Findings Register](./AUDIT_FINDINGS.md) | Historical August assessment and remediation register; read its scope notice |
| [Audit Report](./AUDIT_REPORT.md) | Historical planning proposals, linked to the findings register |

These records describe their dated review scope; they do not certify the current repository.

---

## 🆕 UNIQUE & PERSONAL CONTENT

Content sourced from PNWC's internal Notion knowledge base and real-world operations - not found in textbooks.

### 🔴 OPSEC & Operations

- Personal field rules (*"ALWAYS use a 3rd-party network!"*)
- VM isolation and compartmentalization procedures
- Anonymity and identity-separation workflows

### 🔍 OSINT Arsenal

- 400+ tools organized by category
- Automated OSINT VM build scripts
- Full investigation methodology (target profiling → pivot → report)

### 📘 Team Playbooks

**Purple Team**

- [Purple Team - Simple](./PlayBooks/PurpleTeam_Simple.md)
- [Purple Team - Detailed](./PlayBooks/PurpleTeam_Detailed.md)
- [Purple Team - Multi-Script](./PlayBooks/PurpleTeam_Multi-Scrip.md)

**Blue Team**

- [Blue Team - Incident Response Simple](./PlayBooks/BlueTeam_IncResp_Simple.md)
- [Blue Team - Incident Response Enhanced](./PlayBooks/BlueTeam_IncResp_Enhanced.md)

**Data Engineering, Detection Pipelines & SIEM**

- [Data Engineering Section](./Data-Engineering/README.md)
- [Secure Data Pipelines & Security Automation](./Data-Engineering/data_pipelines.md)
- [Endpoint Visibility](./IncidentResponse/Endpoint-Visibility/README.md)
- [ELK Stack (Elastic) SIEM Deployment](./IncidentResponse/SIEM/elk_stack.md)
- [Wazuh SIEM Deployment](./IncidentResponse/SIEM/wazuh.md)
- [Splunk SIEM Deployment](./IncidentResponse/SIEM/splunk.md)
- [Graylog SIEM Deployment](./IncidentResponse/SIEM/graylog.md)
- [Log Aggregation Guide](./IncidentResponse/log_agg.md)

### 💻 Custom Scripts & Tools

- **[`pnwc_install_tools.sh`](./Scripts/pnwc_install_tools.sh)** - Cross-distro Linux tool installer (apt · pacman · dnf)
- **[PowerShell](./Scripts/PowerShell)** - 12 scripts: AD testing, SMB auth, brute force, port scanning, reverse shells, system enumeration
- **[Python](./Scripts/Python)** - Scripts for network recon, credential analysis, Bluetooth, web, geolocation, exploitation tools
- **[Bash](./Scripts/Bash)** - System admin, recon, auditing, log analysis utilities (`Scripts/Bash/`)
- **[C](./Scripts/C)** - Low-level utilities: user enumeration, port scanning, system manipulation
- **[SQL](./Scripts/SQL)** - WordPress admin injection testing scripts
- **[Go](./Scripts/GO)** - (`Scripts/GO/`)

### 🎯 Attack Case Studies (10+ Analyzed)

| Incident | Type |
|---|---|
| [Stuxnet](https://en.wikipedia.org/wiki/Stuxnet) | Nation-state cyberweapon - Iranian nuclear facilities |
| [WannaCry](https://www.cisa.gov/news-events/alerts/2017/05/12/indicators-associated-wannacry-ransomware) | Global ransomware outbreak |
| [EternalBlue / NSA Leak](https://www.microsoft.com/en-us/security/blog/2017/05/12/wannacrypt-ransomware-worm-targets-out-of-date-systems/) | NSA exploit leaked by Shadow Brokers |
| [SolarWinds](https://www.cisa.gov/news-events/cybersecurity-advisories/aa20-352a) | Software supply chain compromise |
| [Carbanak](https://cloud.google.com/blog/topics/threat-intelligence/behind-the-carbanak-backdoor) | APT banking theft campaign |
| [NotPetya](https://www.wired.com/story/notpetya-cyberattack-ukraine-russia-code-crashed-the-world/) | Destructive malware disguised as ransomware |
| [Edward Snowden / NSA](https://www.theguardian.com/world/edward-snowden) | Mass surveillance program revelations |
| + 3 additional major data breach case studies | Analysis of root cause, TTPs, and defensive lessons |

### 🔧 Hardware Arsenal Documented

| Multi-Tool | Reference |
|---|---|
| Flipper Zero | [Project](https://flipper.net/) |
| WiFi Pineapple | [Product](https://shop.hak5.org/products/wifi-pineapple) |
| Proxmark3 | [Project](https://proxmark.com/) |

### 📟 uConsole & Portable Operations

Field-side cybersecurity requires reliable, highly-portable hardware. This section is dedicated to the **ClockworkPi uConsole**. It includes step-by-step documentation on turning the uConsole into a dedicated cyberdeck for mobile operations.

- **OS & Toolkit Optimization:** Customizing Kali Linux, Parrot OS, or custom Debian builds for the uConsole's unique form factor.
- **SDR & Wireless Assessments:** Configurations for running Wireshark, Kismet, and RTL-SDR in the field.
- **Hardware Interfacing:** Using the uConsole for serial connections, hardware debugging, and local network audits.

| Category | Device | Reference |
|---|---|---|
| Hak5 Suite | Rubber Ducky | [Product](https://shop.hak5.org/products/usb-rubber-ducky) |
| Hak5 Suite | Bash Bunny | [Product](https://shop.hak5.org/products/bash-bunny) |
| Hak5 Suite | LAN Turtle | [Product](https://shop.hak5.org/products/lan-turtle) |
| Hak5 Suite | Packet Squirrel | [Product](https://shop.hak5.org/products/packet-squirrel) |
| Hak5 Suite | Shark Jack | [Product](https://shop.hak5.org/products/shark-jack) |
| Hak5 Suite | O.MG Cable | [Product](https://shop.hak5.org/products/omg-cable) |
| RF / SDR | HackRF One | [Project](https://greatscottgadgets.com/hackrf/) |
| RF / SDR | RTL-SDR | [Project](https://www.rtl-sdr.com/) |
| RF / SDR | Ubertooth One | [Project](https://greatscottgadgets.com/ubertoothone/) |
| RF / SDR | YardStick One | [Project](https://greatscottgadgets.com/yardstickone/) |
| Wi-Fi Adapter | Alfa AWUS036ACH | Hardware reference |
| Wi-Fi Adapter | Alfa AWUS036NHA | Hardware reference |
| Wi-Fi Adapter | TP-Link TL-WN722N | Hardware reference |

---

## 📊 REPOSITORY STATISTICS

**Historical snapshot (September 11, 2026):** counts below are retained for provenance and should not be interpreted as the current live inventory after subsequent additions. They are not claims that every example has been deployment-tested.

| Category | Count / Definition |
|---|---|
| Top-level content sections | 23; excludes `.github` and `assets` |
| Tracked files | 495 across the repository |
| Markdown documents | 206 files with a `.md` extension, including indexes |
| Playbook documents | 10 Markdown files under `PlayBooks/`, excluding its README |
| Script source files | 215 `.py`, `.sh`, `.ps1`, `.go`, `.c`, `.rb`, `.js`, or `.sql` files under `Scripts/` |
| Bibliography entries | 78 listed references, including books and educational materials |

Original compilation figures such as the number of internal PNWC documents are provenance notes, not live repository inventory metrics.

---

## 🚀 WHAT YOU CAN DO WITH THIS GUIDE

### Learning & Practice

- ✅ Conduct professional penetration tests
- ✅ Perform OSINT investigations
- ✅ Execute incident response procedures
- ✅ Study and adapt security automation scripts
- ✅ Assess IoT and embedded device security
- ✅ Develop and analyze exploits
- ✅ Build and operate a security homelab
- ✅ Learn secure data pipelines, structured telemetry, streaming, and repeatable deployments
- ✅ Analyze real-world attack campaigns
- ✅ **Deploy Portable Cyberdecks**: Set up and optimize the uConsole for on-the-go pentesting, SDR (Software Defined Radio), and field operations.

### For Your Career

- ✅ Prepare for OSCP, CEH, GPEN, CySA+, CISSP
- ✅ Build skills for SOC analyst roles
- ✅ Work as a professional pentester or red teamer
- ✅ Specialize in OSINT, forensics, or hardware security
- ✅ Build automation tooling for security workflows

---

## 🙏 CREDITS & ACKNOWLEDGMENTS

This guide stands on the shoulders of the global cybersecurity community.

### 📎 Cited Sources For Curated Reference Additions

The following external resources informed **selected, original PNWC reference
pages**; their content is not bulk mirrored. Links point to the source projects
and their own license terms. Specific command or installation instructions
should be checked against the linked maintainers' current documentation before
use.

| Original source and license | Where its ideas/links are used | Scope and cautions |
| --- | --- | --- |
| [Beautiful Docs — matheusfelipeog](https://github.com/matheusfelipeog/beautiful-docs) ([MIT](https://github.com/matheusfelipeog/beautiful-docs/blob/master/LICENSE)) | [Curated technical documentation](./Documentation/curated-technical-docs.md), [style conventions](./STYLE_GUIDE.md), and topic-specific learning links | Inspiration and links to independent docs, not a guarantee that their version-specific instructions are current |
| [Froxy — matheusfelipeog](https://github.com/matheusfelipeog/froxy) ([MIT](https://github.com/matheusfelipeog/froxy/blob/master/LICENSE)); underlying [proxy-list — clarketm](https://github.com/clarketm/proxy-list) | [Proxy types, Froxy and DNS-leak reference](./OPSEC/proxy-reference-froxy.md) in [OPSEC](./OPSEC/README.md) | Python free-proxy directory interface only; not vetted egress or a promise of anonymity; never send confidential client information through unknown proxies |
| [Docker Cheat Sheet — wsargent](https://github.com/wsargent/docker-cheat-sheet) ([CC BY 4.0](https://github.com/wsargent/docker-cheat-sheet/blob/master/LICENSE)) | [Docker operations and diagnostics](./ContainerSecurity/docker-cli-operations-reference.md) and [container security](./ContainerSecurity/README.md) | Third-party historical command collection; this guide uses independently written examples and prioritizes [official Docker CLI](https://docs.docker.com/reference/cli/docker/) and [Engine security](https://docs.docker.com/engine/security/) documentation |

**Review scope (November 2, 2026):** source READMEs and licensing were
inspected; new cross-references were checked for repository path correctness.
External tool behavior, every older upstream link and production Docker/Froxy
execution were **not** exhaustively tested. The documentation does not authorize
active probing, anonymous-proxy use with client data, or unapproved Docker
changes. See [legal terms](./LEGAL.md).

**Other already-integrated references:** [Devhints commands (merged PR #156)](https://github.com/Pnwcomputers/ULTIMATE-CYBERSECURITY-MASTER-GUIDE/pull/156) from [rstacruz/cheatsheets](https://github.com/rstacruz/cheatsheets), [Public APIs catalog (merged PR #157)](https://github.com/Pnwcomputers/ULTIMATE-CYBERSECURITY-MASTER-GUIDE/pull/157) from [public-apis/public-apis](https://github.com/public-apis/public-apis), and [Beautiful Docs/Froxy/Docker references (merged PR #158)](https://github.com/Pnwcomputers/ULTIMATE-CYBERSECURITY-MASTER-GUIDE/pull/158).

### 📎 Additional Sourced Assessment, Detection & Research Workflows

New PNWC guides are original summaries and procedural checklists with direct
links to upstream source repositories. **Documentation-only integration does
not imply installation, third-party content mirroring or production testing.**
The complete source and license register is [here](./Documentation/upstream-security-projects-register.md).

| Original GitHub resources | Where their guidance is integrated |
| --- | --- |
| [OWASP WSTG](https://github.com/OWASP/wstg) and [OWASP ASVS](https://github.com/OWASP/ASVS) (CC BY-SA 4.0); [Nuclei templates](https://github.com/projectdiscovery/nuclei-templates) (MIT) | [Versioned web/API verification and safe template review](./WebAppSecurity/owasp-assessment-and-nuclei.md) |
| [Red Canary Atomic Red Team](https://github.com/redcanaryco/atomic-red-team) (MIT); [SigmaHQ](https://github.com/SigmaHQ/sigma); [Elastic detection rules](https://github.com/elastic/detection-rules) | [Purple Team test procedures](./PlayBooks/purple-team-detection-validation.md) and [detection rule validation](./IncidentResponse/SIEM/detection-content-validation.md). Check individual rule licensing. |
| [Velociraptor](https://github.com/Velocidex/velociraptor) and [ForensicArtifacts](https://github.com/ForensicArtifacts/artifacts) (Apache-2.0 for ForensicArtifacts) | [Consent-first endpoint and DFIR evidence acquisition](./IncidentResponse/Digital-Forensics/velociraptor-artifact-triage.md) |
| [CISA ScubaGear](https://github.com/cisagov/ScubaGear) (CC0-1.0) | [Microsoft 365/Entra configuration baseline assessment](./Cloud/m365-scuba-assessment.md) |
| [DefectDojo](https://github.com/DefectDojo/django-DefectDojo) (BSD-3-Clause) | [Issue management, evidence, remediation and retests](./PlayBooks/assessment-findings-lifecycle.md) |
| [OpenSSF Scorecard](https://github.com/ossf/scorecard), [Syft](https://github.com/anchore/syft), [OSV-Scanner](https://github.com/google/osv-scanner), [Trivy](https://github.com/aquasecurity/trivy), [Cosign](https://github.com/sigstore/cosign) (Apache-2.0); [Gitleaks](https://github.com/gitleaks/gitleaks) (MIT) | [Software supply-chain / SBOM assurance](./ContainerSecurity/software-supply-chain-assessment.md) |
| [Bellingcat Toolkit](https://github.com/bellingcat/toolkit) and [MVT](https://github.com/mvt-project/mvt) | [OSINT source verification](./OSINT/bellingcat-source-verification.md) and [consensual mobile forensic triage](./Mobile/mvt-forensic-triage.md). Review source-specific licenses and data practices. |
| [YARA-X](https://github.com/VirusTotal/yara-x) (BSD-3-Clause), [Promptfoo](https://github.com/promptfoo/promptfoo) (MIT), and [rtl_433](https://github.com/merbanan/rtl_433) (GPL-2.0) | [Malware rule lab](./ReverseEngineering/yara-x-rule-lab.md), [LLM/agent evaluations](./AI/llm-security-evaluation-promptfoo.md), and [receive-only IoT telemetry](./SDR/rtl433-passive-telemetry-lab.md) |

**Verification boundary:** References, methodology and internal paths were
reviewed; upstream code execution, customer scans, Microsoft tenant access,
radio capture and automated deployment were not undertaken. Confirm source
release, file license and legal scope before operational reuse.

### 🛠️ Key Tools & Frameworks

#### Exploitation & Post-Exploitation

| Resource | Notes |
|---|---|
| [Metasploit Framework](https://www.rapid7.com/) | Rapid7 |
| [Impacket](https://github.com/fortra/impacket) | Fortra |
| [BloodHound](https://github.com/SpecterOps/BloodHound) | SpecterOps |
| [CrackMapExec](https://github.com/byt3bl33d3r/CrackMapExec) | *(archived)* |
| [NetExec](https://github.com/Pennyw0rth/NetExec) | — |
| [Empire](https://github.com/BC-SECURITY/Empire) | BC Security |
| [PowerSploit](https://github.com/PowerShellMafia/PowerSploit) | *(archived)* |
| [Nishang](https://github.com/samratashok/nishang) | — |
| [PEASS-ng](https://github.com/peass-ng/PEASS-ng) | Carlos Polop |
| [Responder](https://github.com/lgandx/Responder) | Laurent Gaffié |

#### OSINT

| Resource | Notes |
|---|---|
| [theHarvester](https://github.com/laramies/theHarvester) | — |
| [Sherlock](https://github.com/sherlock-project/sherlock) | — |
| [Maltego](https://www.maltego.com/) | — |
| [SpiderFoot](https://github.com/smicallef/spiderfoot) | — |
| [Recon-ng](https://github.com/lanmaster53/recon-ng) | — |
| [Amass](https://github.com/owasp-amass/amass) | — |
| [Maigret](https://github.com/soxoj/maigret) | — |
| [Holehe](https://github.com/megadose/holehe) | — |
| [H8mail](https://github.com/khast3x/h8mail) | — |
| [PhoneInfoga](https://github.com/sundowndev/phoneinfoga) | — |
| [Photon](https://github.com/s0md3v/Photon) | — |
| [Michael Bazzell / IntelTechniques](https://inteltechniques.com/) | — |
| [Trace Labs](https://tracelabs.org/) | — |

#### Network & Web Security

| Resource | Notes |
|---|---|
| [Nmap](https://nmap.org/) | — |
| [Wireshark](https://www.wireshark.org/) | — |
| [Burp Suite](https://portswigger.net/burp) | — |
| [OWASP ZAP](https://www.zaproxy.org/) | — |
| [Nikto](https://github.com/sullo/nikto) | — |
| [SQLmap](https://sqlmap.org/) | — |
| [Gobuster](https://github.com/OJ/gobuster) | — |
| [ffuf](https://github.com/ffuf/ffuf) | — |
| [Nuclei](https://github.com/projectdiscovery/nuclei) | — |
| [Subfinder](https://github.com/projectdiscovery/subfinder) | — |
| [httpx](https://github.com/projectdiscovery/httpx) | ProjectDiscovery |
| [AutoRecon](https://github.com/AutoRecon/AutoRecon) | Tib3rius |
| [PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings) | — |
| [SecLists](https://github.com/danielmiessler/SecLists) | — |
| [ExploitDB](https://www.exploit-db.com/) | — |

#### Password & Credentials

| Resource | Notes |
|---|---|
| [Hashcat](https://hashcat.net/hashcat/) | — |
| [John the Ripper](https://www.openwall.com/john/) | — |
| [Hydra](https://github.com/vanhauser-thc/thc-hydra) | — |
| [Mimikatz](https://github.com/gentilkiwi/mimikatz) | Benjamin Delpy |

#### Wireless & RF

| Resource | Notes |
|---|---|
| [Aircrack-ng](https://www.aircrack-ng.org/) | — |
| [Kismet](https://www.kismetwireless.net/) | — |
| [Wifite2](https://github.com/derv82/wifite2) | — |
| [Bettercap](https://www.bettercap.org/) | Simone Margaritelli |
| [ChipWhisperer](https://github.com/newaetech/chipwhisperer) | NewAE Technology |
| [OpenOCD](https://openocd.org/) | — |
| [Bus Pirate](https://docs.buspirate.com/) | — |

#### Forensics & Reverse Engineering

| Resource | Notes |
|---|---|
| [Volatility](https://volatilityfoundation.org/) | — |
| [Autopsy](https://www.autopsy.com/) | — |
| [Ghidra](https://github.com/NationalSecurityAgency/ghidra/) | NSA |
| [radare2](https://rada.re/) | pancake |
| [IDA Pro](https://hex-rays.com/ida-pro/) | Hex-Rays |
| [Binwalk](https://github.com/ReFirmLabs/binwalk) | — |
| [YARA](https://github.com/VirusTotal/yara) | — |
| [vx-underground](https://vx-underground.org) | — |
| [MalwareBazaar](https://bazaar.abuse.ch/) | malware sample and research libraries |
| [Sysinternals Suite](https://learn.microsoft.com/en-us/sysinternals/) | Mark Russinovich |

#### Monitoring & Defense

| Resource | Notes |
|---|---|
| [Snort](https://www.snort.org/) | — |
| [Suricata](https://suricata.io/) | — |
| [Zeek](https://zeek.org/) | — |
| [OSSEC](https://www.ossec.net/) | — |
| [Elastic Stack](https://www.elastic.co/) | — |
| [Splunk](https://www.splunk.com/) | — |
| [Graylog](https://graylog.org/) | — |
| [Wazuh](https://wazuh.com/) | — |
| [Security Onion](https://securityonionsolutions.com/) | — |
| [nzyme](https://nzyme.org/) | — |

#### Honeypots & Deception

| Resource | Notes |
|---|---|
| [OpenCanary](https://github.com/thinkst/opencanary) | Thinkst |
| [Cowrie](https://github.com/cowrie/cowrie) | Michel Oosterhof |
| [Dionaea](https://github.com/DinoTools/dionaea) | DinoTools |
| [T-Pot](https://github.com/telekom-security/tpotce) | Deutsche Telekom Security |

### 📚 Book Authors & Publishers

**No Starch Press** *(primary reference publisher)*

- David Kennedy et al. - *Metasploit: The Penetration Tester's Guide*
- Georgia Weidman - *Penetration Testing: A Hands-On Introduction*
- OccupyTheWeb - *Linux Basics for Hackers*
- Justin Seitz - *Black Hat Python*
- Al Sweigart - *Automate the Boring Stuff with Python*

**Other key works:** Ryan Barnett (*Black Hat Bash*) · Travis Goodspeed (*Microcontroller Exploits*) · Seth Enoka (*Cybersecurity for Small Networks*) · Peter Kim (*The Hacker Playbook 3*) · Ben Clark (*RTFM / BTFM*) · Christopher Hadnagy (*Social Engineering*) · Kevin Mitnick (*The Art of Invisibility*)

> See the [full 78-entry bibliography](#complete-bibliography) below.

### 🐧 Security Linux Distributions

| Distribution | Reference |
|---|---|
| Kali Linux | [Official Site](https://www.kali.org/) |
| BlackArch | [Official Site](https://blackarch.org/) |
| Parrot Security OS | [Official Site](https://www.parrotsec.org/) |
| BackBox | [Official Site](https://www.backbox.org/) |
| Tails | [Official Site](https://tails.net/) |
| Whonix | [Official Site](https://www.whonix.org/) |

### 🌐 Knowledge Frameworks & Communities

| Resource | Type / Notes |
|---|---|
| [MITRE ATT&CK](https://attack.mitre.org/) | Adversary tactics and techniques |
| [OWASP](https://owasp.org/) | Application security |
| [NIST NVD](https://nvd.nist.gov/) | Vulnerability records |
| [CVE](https://www.cve.org/) | Vulnerability identifier program |
| [CISA](https://www.cisa.gov/) | Cybersecurity advisories and guidance |
| [SANS](https://www.sans.org/) | Security training and research |
| [Hack The Box](https://www.hackthebox.com/) | Practical security training |
| [TryHackMe](https://tryhackme.com/) | Guided security labs |
| [VulnHub](https://www.vulnhub.com/) | Practice machines |
| [OverTheWire](https://overthewire.org/) | Interactive security exercises |
| [PentesterLab](https://pentesterlab.com/) | Web security training |
| [TryHackMe FREE Roadmap](https://github.com/uttambodara/TryHackMeRoadmap) | Community-curated learning roadmap, by [Uttambodara](https://github.com/uttambodara); availability and room counts may change |

### 🔐 Privacy & Anonymity Tools

| Resource | Type |
|---|---|
| [Tor Project](https://www.torproject.org/) | Anonymity network |
| [Mullvad VPN](https://mullvad.net/) | VPN service |
| [ProtonVPN](https://protonvpn.com/) | VPN service |
| [IVPN](https://www.ivpn.net/) | VPN service |
| [VeraCrypt](https://veracrypt.io/) | Encrypted storage |
| [Proton Mail](https://proton.me/mail) | Email service |
| [Signal](https://signal.org/) | Encrypted messaging |

### 🎓 Certification Bodies

| Organization | Training / Certification Examples |
|---|---|
| [OffSec](https://www.offsec.com/) | Security training and certifications |
| [EC-Council](https://www.eccouncil.org/) | CEH, CHFI |
| [GIAC](https://www.giac.org/) | GPEN, GWAPT, GCIH |
| [CompTIA](https://www.comptia.org/) | Security+, PenTest+, CySA+ |
| [(ISC)²](https://www.isc2.org/) | CISSP |

### 👥 Notable Security Researchers

Kevin Mitnick (1963–2023) · Bruce Schneier · Dan Kaminsky (1979–2021) · HD Moore · Tavis Ormandy · Marcus Hutchins · Brian Krebs · Troy Hunt · Katie Moussouris · Parisa Tabriz · The Grugq · and countless others

---

<a id="complete-bibliography"></a>

## 📚 Complete Bibliography

### I. Foundational & General Hacking

1. **Hacking: The Art of Exploitation (2nd Ed.)** - Jon Erickson · No Starch Press · 2008 · ISBN 978-1593271442
2. **The Basics of Hacking and Penetration Testing (2nd Ed.)** - Patrick Engebretson · Syngress · 2013 · ISBN 978-0124116443
3. **Gray Hat Hacking: The Ethical Hacker's Handbook (5th Ed.)** - Allen Harper et al. · McGraw-Hill · 2018 · ISBN 978-1260108415
4. **The Hacker's Underground Handbook** - David Melnichuk · Self-published · 2008
5. **Hacking: Computer Hacking Beginners Guide** - Alan T. Norman · Self-published
6. **The Code Book** - Simon Singh · Anchor Books · 1999 · ISBN 978-0385495325
7. **Steal This Computer Book 4.0** - Wallace Wang · No Starch Press · 2006 · ISBN 978-1593271053
8. **Cybersecurity - Attack and Defense Strategies** - Yuri Diogenes, Erdal Ozkaya · Packt · 2018 · ISBN 978-1788837074
9. **The NICE Cyber Security Framework** - Izzat Alsmadi · Springer · 2019 · ISBN 978-3030023591
10. **Ethical Hacking MindMap** - Educational material
11. **Introduction to Ethical Hacking** - Chinni Diwakar · Educational material

### II. Penetration Testing & Operations

12. **Penetration Testing: A Hands-On Introduction to Hacking** - Georgia Weidman · No Starch Press · 2014 · ISBN 978-1593275648
13. **The Hacker Playbook 3: Red Team Edition** - Peter Kim · Secure Planet · 2018 · ISBN 978-1980901754
14. **Advanced Penetration Testing** - Wil Allsopp · Wiley · 2017 · ISBN 978-1119367680
15. **Google Hacking for Penetration Testers, Vol. 2** - Johnny Long et al. · Syngress · 2007 · ISBN 978-1597491761
16. **Real-World Bug Hunting** - Peter Yaworski · No Starch Press · 2019 · ISBN 978-1593278618
17. **Quick Start Guide to Penetration Testing** - Sagar Rahalkar · Apress · 2019 · ISBN 978-1484242698
18. **Offensive Security OSCP Exam with AD Preparation** - Michael Mancao · Educational material · 2022
19. **OSCP Like Vulns Machines** - Joas Antonio · Educational material
20. **Pentest in Office365 and Security** - Joas Antonio · Educational material
21. **Exploiting Misconfigurations (CSP Bypass)** - Jamy Casteel · GIAC/SANS Gold Paper · 2021

### III. Defense & Team Strategies

22. **RTFM: Red Team Field Manual** - Ben Clark · CreateSpace · 2014 · ISBN 978-1494295509
23. **Blue Team Field Manual (BTFM)** - Alan J. White, Ben Clark · CreateSpace · 2017 · ISBN 978-1541216044
24. **Purple Team Field Manual (PTFM)** - Tim Bryant · Self-published · 2020
25. **Jump-start Your SOC Analyst Career** - Tyler Wall, Jarrett Rodrick · Apress · 2021 · ISBN 978-1484269039

### IV. Operating Systems, Tools & Frameworks

26. **Kali Linux Revealed** - Raphaël Hertzog, Jim O'Gorman, Mati Aharoni · Offsec Press · 2017 · ISBN 978-0-9976402-0-2
27. **Mastering Kali Linux for Advanced Penetration Testing** - Robert W. Beggs · Packt · 2014 · ISBN 978-1782169735
28. **Linux Basics for Hackers** - OccupyTheWeb · No Starch Press · 2019 · ISBN 978-1593278557
29. **Metasploit: The Penetration Tester's Guide (2nd Ed.)** - David Kennedy et al. · No Starch Press · 2023 · ISBN 978-1718501237
30. **Metasploit Penetration Testing Cookbook** - Abhinav Singh · Packt · 2012 · ISBN 978-1849517409
31. **Nmap 6: Network Exploration and Security Auditing Cookbook** - Paulino Calderón Pale · Packt · 2012 · ISBN 978-1849517447
32. **Reconnaissance: Nmap and NSE Practical Guide** - INVETECK GLOBAL · Educational material
33. **Hacking Android** - Kotipalli, Imran · Packt · 2016 · ISBN 978-1785883149
34. **Developing Burp Suite Extensions** - Luca Carettoni · DOYENSEC · Conference presentation
35. **Linux for Beginners** - Noah Herrmann · Self-published · 2021
36. **How Linux Works (3rd Ed.)** - Brian Ward · No Starch Press · 2021 · ISBN 978-1718500254
37. **Linux Command Line and Shell Scripting Bible (3rd Ed.)** - Blum, Bresnahan · Wiley · 2015 · ISBN 978-1118983843
38. **Shell Scripting: Expert Recipes** - Steve Parker · Wrox
39. **Ultimate Linux Projects** - Future PLC (Linux Format) · 2022

### V. Web & Network Security

40. **The Web Application Hacker's Handbook (2nd Ed.)** - Stuttard, Pinto · Wiley · 2011 · ISBN 978-1118026472
41. **Web Application Security for Dummies** - Mike Shema · Wiley · 2011 · ISBN 978-1119994879
42. **Network Security Assessment (3rd Ed.)** - Chris McNab · O'Reilly · 2016 · ISBN 978-1491910955
43. **The Shellcoder's Handbook (2nd Ed.)** - Anley, Heasman, Lindner, Richarte · Wiley · 2007 · ISBN 978-0470080238
44. **Web Scraping with Python (2nd Ed.)** - Ryan Mitchell · O'Reilly
45. **SAST Scanners Cheat Sheet** - WeHackPurple / @SheHacksPurple · Educational material
46. **Session Hijacking** - Educational material
47. **SQL Injection - Comprehensive Guide** - Educational material
48. **Learn SQL Using Squid Game** - @codechips (Cody) · Educational material

### VI. Wireless & Mobile Hacking

49. **WiFi Hacking for Beginners** - James Wells · Self-published
50. **Kali Linux Wireless Pentesting and Security for Beginners** - Hardeep Singh · 2017
51. **WiFi: Hack Proof Your Wireless Network** - Barnes, Bautts, Lloyd et al. · Syngress
52. **Hacking HLR, HSS and MME Core Network Elements** - Philippe Langlois · Black Hat USA 2014
53. **Hacking LTE Public Warning Systems** - Weiguang Li · HAXPO Conference

### VII. Reverse Engineering & Exploit Development

54. **Practical Reverse Engineering** - Dang, Gazet, Bachaalany · Wiley · 2014 · ISBN 978-1118787311
55. **Mastering Reverse Engineering** - Reginald Wong · Packt · 2018 · ISBN 978-1788832918
56. **Reverse Engineering for Beginners** - Dennis Yurichev · Creative Commons · 2016
57. **Reverse Engineering for Beginners (Lite)** - Dennis Yurichev · Creative Commons

### VIII. Programming & Data Science For Security

58. **Black Hat Python** - Justin Seitz · No Starch Press · 2014 · ISBN 978-1593275907
59. **Violent Python** - TJ O'Connor · Syngress · 2012 · ISBN 978-1597499576
60. **Understanding Network Hacks: Attack and Defense with Python** - Bastian Ballmann · Springer · 2015 · ISBN 978-3662444368
61. **Hacking with Python: The Ultimate Beginner's Guide** - Steve Tale · Self-published · 2017
62. **Perl Programming for Beginners** - Nathan Metzler · Lightbulb Publishing
63. **Malware Data Science** - Joshua Saxe, Hillary Sanders · No Starch Press · 2018 · ISBN 978-1593278595
64. **Machine Learning Mastery with Python** - Jason Brownlee · Machine Learning Mastery · 2016
65. **Deep Learning with Python** - Jason Brownlee · Machine Learning Mastery · 2016
66. **Long Short-Term Memory Networks with Python** - Jason Brownlee · Machine Learning Mastery · 2017
67. **Machine Learning with Python for Everyone** - Mark E. Fenner · Addison-Wesley

### IX. Social Engineering & Forensics

68. **Social Engineering: The Science of Human Hacking** - Christopher Hadnagy · Wiley · 2018 · ISBN 978-1119433385
69. **The Art of Invisibility** - Kevin Mitnick · Little, Brown & Company · 2017 · ISBN 978-0316380492
70. **Digital Forensics Explained (2nd Ed.)** - Greg Gogolin · CRC Press · 2018 · ISBN 978-1138491029
71. **How to Hide Data in Audio Files (Steganography)** - Ismael Nelson S. · Educational material

### X. Dark Web & Lab Guides

72. **Dark Web: Exploring and Data Mining the Dark Side of the Web** - Hsinchun Chen · Springer · 2012 · ISBN 978-1461415565
73. **Inside the Dark Web** - Arun Adhikari · DARKNET
74. **Footprinting and Reconnaissance LAB** - Chinni Diwakar · Educational material
75. **Sniffers LAB - Network Traffic Analysis & MITM** - Chinni Diwakar · Educational material
76. **DOS LAB - Denial of Service Attack Techniques** - Chinni Diwakar · Educational material
77. **Metasploit Framework Guide** - Chinni Diwakar · Educational material
78. **System Hacking LAB** - Chinni Diwakar · Educational material

---

## ⚖️ Legal Disclaimer

| ❌ NEVER | ✅ ALWAYS |
|---|---|
| Test without written authorization | Obtain written permission before any test |
| Use tools on systems you don't own | Act within the scope of your engagement |
| Share exploit code irresponsibly | Follow responsible disclosure practices |
| Violate local, state, or federal law | Comply with all applicable laws and regulations |

**Unauthorized access to computer systems is a federal crime under the CFAA and equivalent laws worldwide. This repository is for educational purposes and authorized security testing only.**

### Authorized Use Cases

- Professional penetration testing with signed client authorization
- Security research in isolated lab environments you own
- CTF (Capture the Flag) competitions
- Homelab and educational practice on your own systems
- Defensive security tooling and monitoring

See the full [LEGAL.md](./LEGAL.md) for complete terms.

---

## 🏆 What Makes This Guide Different

| Feature | Detail |
|---|---|
| 📚 70+ professional books synthesized | Complete coverage from recognized industry experts |
| 🏢 90+ PNWC internal docs | Real operational experience - not just theory |
| 🎯 10+ attack case studies | Root cause, TTPs, IOCs, and defensive lessons analyzed |
| ⚙️ Operational playbook collection | Procedures for assessment, incident response, and team exercises |
| 🛠️ Security script collection | Source examples to review and validate in the intended environment |
| 📡 20+ hardware devices | IoT and embedded security from real-world toolkit |
| 🔍 400+ OSINT tools | Organized by category with usage methodology |
| 🤖 AI security workflows | Self-hosted LLM integration for security operations |
| 🎓 Cert-aligned content | OSCP · CEH · GPEN · CySA+ · CISSP mapped |
| 🔁 Cross-domain coverage | Offense + Defense + Operations + Forensics + Data Engineering |

---

## 📬 Contributing & Contact

This is a personal operational knowledge base, but the security community thrives on shared knowledge.

- **PNWC Website:** [pnwcomputers.com](https://pnwcomputers.com)
- **Email:** jon@pnwcomputers.com
- **GitHub:** [github.com/Pnwcomputers](https://github.com/Pnwcomputers)

Want to help the community?
- Contribute to the open-source tools referenced here
- Write and publish your own security research
- Mentor newcomers entering the field
- Practice responsible disclosure on vulnerabilities you find
- Purchase the original books to support the authors

---

<p align="center">
  <strong>Use it wisely. Use it ethically. Use it legally.</strong><br/>
  <em>Learn → Practice → Contribute back to the community. 🚀</em>
</p>

---

*Last Updated: November 2, 2026 · Maintained by [PNW Computers](https://pnwcomputers.com) · Vancouver, WA*

## Related Files

- [Data Engineering](./Data-Engineering/README.md) - Data infrastructure and learning roadmap
- [Secure Data Pipelines](./Data-Engineering/data_pipelines.md) - TLS, SSH, Git, parsing, enrichment, Kafka, and Ansible
- [START_HERE.md](./START_HERE.md) - Quick navigation guide to all sections
- [ENHANCED_MASTER_GUIDE.md](./ENHANCED_MASTER_GUIDE.md) - Enhanced deep-dive guide
- [SPECIALIZED_TOPICS_GUIDE.md](./SPECIALIZED_TOPICS_GUIDE.md) - Third guide in the series
- [Press Freedom and Source Protection](./OPSEC/press-freedom/README.md) - Journalist device, source confidentiality and retention / duress planning
- [LEGAL.md](./LEGAL.md) - Legal disclaimer and terms of use
- [Diagram and Image Asset Index](./assets/README.md) - Existing figures and 19 new diagrams across SIEM, DFIR, OSINT, cloud, mobile, compliance, RF, and more
- [Visual Coverage Review](./assets/VISUAL-AUDIT-2026-11-02.md) - Repository-wide image inventory, integration results, verification limits and future needs
- [CHANGELOG.md](./CHANGELOG.md) - Repository change history

