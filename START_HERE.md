# 🛡️ START HERE - Your Complete Cybersecurity Guide Collection

> **Role- and Goal-Based Navigation Guide**  
> Direct paths to readable guide pages for every practitioner role (Red Team, Blue Team, OSINT, Forensics, Homelab, Career), without browsing GitHub's Code file list.

<p align="center">
  <img src="assets/cybersecurityguide.png" alt="PNWC Ultimate Cybersecurity Master Guide" width="600"/>
</p>

## 🎯 Purpose & Function
Routes readers by role and objective (beginner, pentester, OSCP candidate, blue team, red team, OSINT investigator, hardware hacker) straight to the relevant subset of **human-readable section indexes and guides**. Differs from [README.md](README.md) (flat catalog) by curating a structured path rather than listing everything.

## 📋 When to Use
- **First Visit:** Start here to find your role-specific reading list.
- **Orientation:** When asking "what should I read next for X goal?" rather than looking up a specific command or tool.


## 🎯 QUICK START

**New source-backed routes:** [M5StickC Plus2 lab](HardwareHacking/m5stickc-plus2-hackstarterpack.md) · [Cypherpunk research history](Documentation/cypherpunk-pentesting-toolkit-review.md) · [Awesome OSINT List](OSINT/awesome-osint-list-curated.md) · [Curated security GitHub ecosystems](Documentation/awesome-hacking-collections-integration.md) · [ethical training/CTFs](PlayBooks/security-training-lab-pathways.md). Choose a role and use the section's authoritative procedures for the actual work.

**Prefer reading over file browsing?** Every section link on this page leads to an actual `README.md` or guide. Start with a topic, open its chapter, and use its related-guide links and return-to-index navigation.

**Popular hands-on Blue Team path:** [Incident Response index](IncidentResponse/README.md) → [Wazuh/SIEM](IncidentResponse/SIEM/README.md) → [Kismet/nzyme IDS](IncidentResponse/IDS%26IPS/readme.md) → [Honeypot lab](IncidentResponse/HoneyPot/readme.md) → [Honeypot → Wazuh reporting](IncidentResponse/HoneyPot/wazuh-honeypot-integration.md).


- **Abide by the [Legal Terms of Use / Disclaimer & Legal Ramifications](LEGAL.md) for the *Use* & *Misuse* of this Repository's Contents**
| Goal | Recommended Route |
|---|---|
| **New to Cybersecurity?** | Start with [Ultimate Master Guide](ultimate_cybersecurity_master_guide.md) → Part I (Foundations) |
| **Need Quick Commands?** | Use [Cliff Notes](cybersecurity_cliff_notes.md) for security concepts or the [CLI Field Cheat Sheet](Documentation/devhints-cli-field-reference.md) for everyday Linux, transfer, GPG, Git and Docker commands |
| **Building a repeatable client assessment?** | [Staged security assessment blueprint](PlayBooks/assessment-service-integration-map.md) → [OWASP verification](WebAppSecurity/owasp-assessment-and-nuclei.md) → [CISA SCuBA](Cloud/m365-scuba-assessment.md) → [Findings and retests](PlayBooks/assessment-findings-lifecycle.md). |
| **Validating SIEM and endpoint detections?** | [Atomic Red Team/Sigma lab](PlayBooks/purple-team-detection-validation.md) → [Wazuh detection rule verification](IncidentResponse/SIEM/detection-content-validation.md) → [DFIR triage](IncidentResponse/Digital-Forensics/velociraptor-artifact-triage.md). |
| **Auditing code, dependencies or containers?** | [SBOM, Scorecard, Gitleaks and signature workflow](ContainerSecurity/software-supply-chain-assessment.md). |
| **Researching source projects for this guide?** | [Verified upstream source register](Documentation/upstream-security-projects-register.md) with license and integration status. |
| **Need Docker or Compose diagnostics?** | [Docker Operations Cheat Sheet](ContainerSecurity/docker-cli-operations-reference.md) → [Container Runtime Security](ContainerSecurity/containers.md) for host/socket risks and hardening. |
| **Comparing proxies, SOCKS, VPNs or Tor?** | [Proxy Types and Froxy Research](OPSEC/proxy-reference-froxy.md) → [Anonymity Layering](OPSEC/anonymity-layering.md). Do not use unknown public proxies for client data. |
| **Looking for authoritative software or API documentation?** | [Curated Technical Docs](Documentation/curated-technical-docs.md) → [Writing conventions](STYLE_GUIDE.md). |
| **Preparing for OSCP?** | [Ultimate Master Guide](ultimate_cybersecurity_master_guide.md) + [Enhanced Master Guide](ENHANCED_MASTER_GUIDE.md) + [Advanced Techniques Part 2](advanced_techniques_part2.md) (Buffer Overflows; CRITICAL) + [Playbooks](PlayBooks/cybersecurity_playbooks.md) |
| **Professional Pentester?** | [Pentoo Linux workstation and assessment workflow](Tradecraft/pentoo-linux-guide.md) + [Network Audit Playbook](PlayBooks/NetworkAuditPlayBook.md) + the other master guides as reference |
| **Blue Team / SOC?** | [Incident Response](IncidentResponse/README.md) + [Tsurugi Bento field response](IncidentResponse/Digital-Forensics/tsurugi-bento-portable-dfir-guide.md) + [Blue Team Playbooks](PlayBooks/README.md) + [SIEM Guides](IncidentResponse/SIEM/README.md) |
| **OSINT Investigator?** | [OSINT Guide](OSINT/OSINT_GUIDE.md) + [Tradecraft/OSINT Threat Intel](Tradecraft/osint-threat-intel.md) |
| **Security API and threat-feed references?** | [Security API Catalog](Documentation/security-public-api-catalog.md) → [OSINT API toolkit](OSINT/Playbook/tools_api.md) → [API ingestion guidance](Data-Engineering/Phase2/api_file_ingestion.md) |
| **Red Team Operator?** | [Tradecraft](Tradecraft/README.md) + [Advanced Techniques](advanced_techniques_supplement.md) + [Scripts](Scripts/README.md) |
| **Web App Pentester?** | [Web Application Security](WebAppSecurity/README.md) ([OWASP Top 10](WebAppSecurity/owasp-top-10.md) + [Methodology](WebAppSecurity/methodology.md)) |
| **Cloud Security?** | [Cloud Security](Cloud/README.md) ([AWS](Cloud/aws.md) · [Azure/Entra ID](Cloud/azure.md) · [GCP](Cloud/gcp.md)) |
| **Compliance / Auditor?** | [Compliance & GRC](Compliance/README.md) ([Frameworks](Compliance/frameworks.md) · [Regulations](Compliance/regulations.md)) |
| **Container / Kubernetes Security?** | [Container & Kubernetes Security](ContainerSecurity/README.md) ([Containers](ContainerSecurity/containers.md) · [Docker CLI/Compose](ContainerSecurity/docker-cli-operations-reference.md) · [Kubernetes](ContainerSecurity/kubernetes.md)) |
| **Cryptography?** | [Cryptography](Cryptography/README.md) ([Algorithms](Cryptography/algorithms.md) · [Applied](Cryptography/applied-crypto.md) · [Classical & Leetspeak](Cryptography/Classical/README.md)) |
| **Security Keys / FIDO2 / Passkeys?** | [Hardware Keys & Passkeys](Cryptography/security-keys-passkeys.md) → [SoloKeys](Cryptography/solokeys-guide.md) for enrollment and device verification. |
| **Encrypted USB / Hardware Storage?** | [Encrypted Storage](Cryptography/encrypted-storage.md) → [PhantomDrive research](Cryptography/phantomdrive-guide.md) for an experimental hidden-volume example. |
| **Hardware Hacker?** | [Specialized Topics Guide](SPECIALIZED_TOPICS_GUIDE.md) (Parts II–III) + [Enhanced Master Guide](ENHANCED_MASTER_GUIDE.md) + [Firmware & Hardware Compatibility](firmware-hardware-compatibility.md) |
| **Using AI for research, coding or longer projects?** | [Practical AI Usage](AI/ai-usage-interaction-guide.md) → [Agent/Project Lanes and Resume](AI/agent-project-workflows.md) → [Independent Verification and AI Audits](AI/verification-and-ai-audits.md) → [Projects, Notebooks and Plugins](AI/ai-workspaces-notebooks-and-assistants.md). |
| **AI / LLM Security?** | [Specialized Topics Guide](SPECIALIZED_TOPICS_GUIDE.md) (Part I) + [AI Resources](AI/README.md) |
| **Wardriving / Wireless Surveys?** | [Wardriving](Wardriving/README.md) for tool selection → [Field Workflow](Wardriving/field-workflow.md) → [Data Handling](Wardriving/data-handling.md); choose SigRoam, Marauder, Biscuit, AWOK, Wardrive Go or Kismet for the hardware you actually have. |
| **SDR / RF / Space?** | [Specialized Topics Guide](SPECIALIZED_TOPICS_GUIDE.md) (Parts V–VI) + [SDR](SDR/README.md) + [SpaceSecurity](SpaceSecurity/README.md) |
| **Reverse Engineering / Binary Analysis?** | [Reverse Engineering](ReverseEngineering/README.md) + [REMnux Malware Analysis](ReverseEngineering/remnux-malware-analysis-guide.md) + [Ghidra Master Guide](ReverseEngineering/ghidra-guide-index.md) + [vx-underground samples](ReverseEngineering/vx-underground.md) + [Homelab](Homelab/README.md) |
| **Journalist / Confidential Sources / Press Freedom?** | [Press Freedom & Source Safety](OPSEC/press-freedom/README.md) → [Device & Network Protection](OPSEC/press-freedom/device-network-protection.md) → [Data Retention](OPSEC/press-freedom/data-retention-removal.md) → [Duress & Seizure Plan](OPSEC/press-freedom/duress-seizure-response.md). |
| **Privacy Workstation / USB Setup?** | [OPSEC](OPSEC/README.md) + [Whonix + Kicksecure USB](OPSEC/whonix-kicksecure-usb-guide.md) or [Tails USB](OPSEC/tails-usb-setup-guide.md); choose the workflow before installation |
| **Data Engineering / Pipelines?** | [Data Engineering](Data-Engineering/README.md) + its phased learning path and [secure pipeline guide](Data-Engineering/data_pipelines.md) |
| **uConsole Setup?** | [uConsole index](uConsole/README.md) · [CM4 safety review](uConsole/CM4-SAFETY-REVIEW.md) · [CM5 recovery](uConsole/CM5-DISPLAY-RECOVERY.md) · [Specialized Topics](SPECIALIZED_TOPICS_GUIDE.md) |
| **Mobile Platform Pentesting?** | [Mobile Security](Mobile/README.md) + [Mobile Pentest SOP](Mobile/mobile_pentest_sop.md) + [NetHunter Setup](Mobile/OnePlus_A6003/Kali_NetHunter.md) |

---

## 📚 YOUR COMPLETE LIBRARY

### 🏆 PRIMARY GUIDES

#### Guide 1: **[The Ultimate Cybersecurity Master Guide](ultimate_cybersecurity_master_guide.md)** 🔥
**THE MAIN COMPREHENSIVE GUIDE**
- Key aspects & details from 70+ professional cybersecurity books
- Complete penetration testing lifecycle
- Foundations through advanced exploitation

#### Guide 2: **[ENHANCED Cybersecurity Master Guide](ENHANCED_MASTER_GUIDE.md)** 🔥
**EVERYTHING ABOVE + PNWC OPERATIONAL KNOWLEDGE**
- All 70+ books PLUS 90+ PNWC internal documents, guides & KB articles
- Real-world OPSEC procedures, case studies, and field-tested playbooks
- Complete penetration testing lifecycle with operational context

#### Guide 3: **[Specialized Topics Guide](SPECIALIZED_TOPICS_GUIDE.md)** 🔥
**DEEP-DIVE INTO SPECIALIZED & EMERGING DOMAINS**
- AI & LLM Security: adversarial ML, prompt injection, self-hosted Ollama/Dolphin/AnythingLLM, OpenClaw, AI red teaming
- Hardware Hacking: threat modeling, UART/SPI/JTAG interfaces, fault injection, side-channel analysis, CPA implementation
- Hardware Testing: Manjaro/Intel test bench setup, diagnostic workflows, Python automation scripts
- uConsole Cyberdeck: CM4/CM5 setup, HackerGadgets AIO v2 (RTL-SDR, LoRa, GPS), field ops workflow
- Space Security: ground/space/user segment threat modeling, GNSS spoofing, satellite comms security
- SDR & RF Security: IQ sampling, hardware ecosystem, protocol reversing, RF exploitation, legal/licensing

---

### 📖 QUICK REFERENCE

| Resource | Description |
|----------|-------------|
| **[Image and Diagram Index](assets/README.md)** | Maps explanatory diagrams to their respective guides, including new FIDO2, encrypted-storage, and source-protection illustrations |
| **[Glossary](GLOSSARY.md)** | Acronyms and terms used across the repository |
| **[Cheat Sheet & Reference Index](Documentation/CHEATSHEET-REFERENCE-AUDIT-2026-10-31.md)** | One readable index for reviewed Linux/Arch, network, wireless, Bash, OSINT, IR, SDR and general reference material |
| **[Cybersecurity Cliff Notes](cybersecurity_cliff_notes.md)** | Quick command reference; the essentials at a glance |
| **[Wireshark Field Cheat Sheet](Documentation/wireshark-cheatsheet.md)** | Quick GUI/CLI packet analysis, 802.11, DNS/DHCP, TCP and TLS filter examples |
| **[Wireshark Master Filter List](Documentation/wireshark-master-filters.md)** | Searchable reference and 133 tested display filters for detailed investigations |
| **[Linux Command Cheat Sheet](Documentation/LinuxCheatSheet.md)** | Most-used Linux CLI commands for Debian/Ubuntu/Kali/Parrot/Arch |
| **[Firmware & Hardware Compatibility](firmware-hardware-compatibility.md)** | SBC-based DIY pentesting devices; compatibility & firmware guide |

---

### 🚀 ADVANCED TECHNIQUES

| Guide | Description |
|-------|-------------|
| **[Advanced Cybersecurity Techniques - Part 1](advanced_techniques_supplement.md)** | Advanced Metasploit, cloud pentesting, lateral movement, pivoting |
| **[Advanced Cybersecurity Techniques - Part 2](advanced_techniques_part2.md)** | Exploit development, buffer overflows, shellcode, custom payloads |

---

### 🗂️ OPERATIONAL SECTIONS

| Section | Description |
|---------|-------------|
| 📍 **[Wardriving](Wardriving/README.md)** | Authorized wireless mapping, GPS inventory, firmware compatibility, phone-based and Kismet collection |
| 📋 **[Operational Playbooks](PlayBooks/cybersecurity_playbooks.md)** | Field-ready playbooks for professional network & WiFi security audits and pentests |
| 🔍 **[OSINT Guide, Tools & Techniques](OSINT/OSINT_GUIDE.md)** | Comprehensive OSINT methodology; 400+ categorized tools, investigation workflows |
| 🕵️ **[Tradecraft](Tradecraft/README.md)** | Offensive tradecraft; AD attacks, C2 frameworks, AV/EDR evasion, LOLBins, network detection evasion, threat intel |
| 🕸️ **[Web Application Security](WebAppSecurity/README.md)** | OWASP Top 10 deep-dive and web app pentest methodology (Burp workflow, injection/access-control/API testing) |
| ☁️ **[Cloud Security](Cloud/README.md)** | AWS, Azure/Entra ID, and GCP - shared responsibility, misconfigurations, attack surface, and hardening |
| 📋 **[Compliance & GRC](Compliance/README.md)** | Frameworks (NIST CSF 2.0, ISO 27001, SOC 2, PCI DSS, CIS) and regulations (GDPR, HIPAA, CCPA) with control mapping |
| 📦 **[Container & Kubernetes Security](ContainerSecurity/README.md)** | Image/runtime security, container escape, and Kubernetes hardening (RBAC, Pod Security Standards) |
| 🔐 **[Cryptography](Cryptography/README.md)** | Current vs deprecated algorithms, applied crypto (TLS, password storage, key management), post-quantum, classical ciphers & leetspeak |
| 🔑 **[FIDO2 & Security Keys](Cryptography/security-keys-passkeys.md)** | FIDO certification levels, synced/device-bound passkeys, SoloKeys enrollment and account recovery |
| 💾 **[Encrypted Drives](Cryptography/encrypted-storage.md)** | BitLocker, VeraCrypt, LUKS and experimental PhantomDrive USB study |
| 📰 **[Press Freedom & Source Protection](OPSEC/press-freedom/README.md)** | Journalists and newsrooms: source confidentiality, device security, lawful retention, coercion and seizure response |
| 🔴 **[OPSEC](OPSEC/README.md)** | Operational security; anonymity workflows, VM setup, personal rules for professionals |
| 🏠 **[Homelab Guides](Homelab/README.md)** | Building and maintaining safe, isolated labs for offensive and defensive practice |
| 🚨 **[Incident Response](IncidentResponse/README.md)** | Blue Team operations; threat detection, log aggregation, artifact analysis, SIEM setup |
| 💻 **[Scripts](Scripts/README.md)** | Security automation; Bash, Python, PowerShell, C, Go, Ducky scripts |
| 📋 **[Checklists](Checklists/README.md)** | Pre-engagement, testing, and post-engagement checklists |
| 🔬 **[Reverse Engineering](ReverseEngineering/README.md)** | Ghidra binary analysis, scripting, headless processing, and comparison workflows |
| 🗄️ **[Data Engineering](Data-Engineering/README.md)** | Phased learning path, ingestion, storage, orchestration, observability, testing, and recovery |
| 📄 **[PDF Resources](PDF/README.md)** | Curated PDF references and guides |
| 📚 **[Documentation](Documentation/README.md)** | Supplemental technical documentation and cheat sheets |

---

## 🎯 CHOOSE YOUR PATH

### 🌱 BEGINNER PATH
1. [Ultimate Master Guide](ultimate_cybersecurity_master_guide.md); Foundations (Parts I–II)
2. [Cliff Notes](cybersecurity_cliff_notes.md); Practice commands
3. [Enhanced Master Guide](ENHANCED_MASTER_GUIDE.md); Reconnaissance & real-world context
4. Setup Kali Linux VM → Join [HackTheBox](https://hackthebox.com) or [TryHackMe](https://tryhackme.com/)

### 💼 PROFESSIONAL PENTESTER PATH
1. [Ultimate Master Guide](ultimate_cybersecurity_master_guide.md); Foundations
2. [Enhanced Master Guide](ENHANCED_MASTER_GUIDE.md); Operational context
3. [Tradecraft](Tradecraft/README.md); AD, C2, evasion, LOLBins
4. [Operational Playbooks](PlayBooks/cybersecurity_playbooks.md); Field procedures
5. [Advanced Techniques; Part 1](advanced_techniques_supplement.md)
6. [Advanced Techniques; Part 2](advanced_techniques_part2.md)
7. [Scripts](Scripts/README.md); Automate everything
8. Use entire repo as daily reference

### 🎓 OSCP CERTIFICATION PATH
1. [Ultimate Master Guide](ultimate_cybersecurity_master_guide.md); Foundations
2. [Enhanced Master Guide](ENHANCED_MASTER_GUIDE.md); Reconnaissance
3. [Advanced Techniques; Part 2](advanced_techniques_part2.md); **Buffer Overflows (CRITICAL)**
4. [Operational Playbooks](PlayBooks/cybersecurity_playbooks.md); Methodology
5. [Practice with PWK Labs](https://www.offsec.com/blog/pwk-labs-success/)

### 🛡️ BLUE TEAM / SOC ANALYST PATH
1. [Ultimate Master Guide](ultimate_cybersecurity_master_guide.md); Part VI (Network Defense)
2. [Incident Response](IncidentResponse/README.md); Detection, triage, response procedures
3. [Incident Response/SIEM](IncidentResponse/SIEM/README.md); ELK, Wazuh, Splunk, Graylog setup
4. [Blue Team Playbooks](PlayBooks/README.md); Incident response, phishing analysis, unauthorized access
5. [Tradecraft](Tradecraft/README.md); Understanding what you're defending against

### 🔴 RED TEAM OPERATOR PATH
1. [Ultimate Master Guide](ultimate_cybersecurity_master_guide.md); Part IV (Exploitation)
2. [Tradecraft](Tradecraft/README.md); AD attacks, C2 frameworks, AV/EDR evasion, LOLBins
3. [Advanced Techniques; Part 1 & 2](advanced_techniques_supplement.md)
4. [OPSEC](OPSEC/README.md); Stay invisible
5. [Scripts](Scripts/README.md); Offensive automation

### 🔍 OSINT INVESTIGATOR PATH
1. [OSINT Guide](OSINT/OSINT_GUIDE.md); Full methodology, 400+ tools
2. [Tradecraft/OSINT Threat Intel](Tradecraft/osint-threat-intel.md); IOC operationalization, threat intel platforms
3. [Enhanced Master Guide](ENHANCED_MASTER_GUIDE.md); OSINT section
4. [Scripts/Python](Scripts/README.md); OSINT automation

### 🔧 HARDWARE HACKER PATH
1. [Ultimate Master Guide](ultimate_cybersecurity_master_guide.md); Part V (IoT & Hardware)
2. [Enhanced Master Guide](ENHANCED_MASTER_GUIDE.md); Hardware arsenal & firmware
3. [Firmware & Hardware Compatibility](firmware-hardware-compatibility.md)
4. Get hardware tools (Flipper Zero, WiFi Pineapple, HackRF, etc.)
5. Practice: Firmware extraction, programming, reverse engineering

---

## 🏆 WHAT YOU'LL LEARN

✅ Complete penetration testing methodology  
✅ Network reconnaissance and enumeration  
✅ Vulnerability assessment and exploitation  
✅ Active Directory attacks and defense  
✅ C2 frameworks and AV/EDR evasion  
✅ Buffer overflow exploit development  
✅ IoT and hardware hacking (JTAG/SWD)  
✅ Mobile device security (Android/iOS)  
✅ OSINT investigation workflows  
✅ Threat intelligence and IOC operationalization  
✅ Incident response and SIEM operations  
✅ Network defense and hardening  
✅ Python and Bash security automation  
✅ Professional report writing  
✅ Legal and ethical considerations  

---

## 🚀 GET STARTED NOW

### Today
1. Read this file completely ✅
2. Open [Ultimate Master Guide](ultimate_cybersecurity_master_guide.md)
3. Start with Part I (Foundations)
4. Setup Kali Linux VM

### This Week
- Complete Master Guide Parts I–II
- Practice commands from [Cliff Notes](cybersecurity_cliff_notes.md)
- Join [HackTheBox](https://hackthebox.com) or [TryHackMe](https://tryhackme.com/)
- Explore your [Homelab Guides](Homelab/README.md) and setup a lab

### This Month
- Finish Master Guide
- Work through [Tradecraft](Tradecraft/README.md) section
- Complete 5 CTF machines
- Start certification study

---

## ⚠️ LEGAL & ETHICAL USE ONLY

🚫 **NEVER** test systems without written permission  
🚫 **NEVER** use for illegal activities  
✅ **ALWAYS** get written authorization  
✅ **ALWAYS** act ethically  
✅ **ALWAYS** follow the law  

See [LEGAL.md](LEGAL.md) for full terms of use.

---

## 💪 YOU'RE READY

**Everything you need to:**
- Start your cybersecurity career
- Pass major certifications (OSCP, CEH, GPEN)
- Conduct professional penetration tests
- Run red team operations
- Defend networks and respond to incidents
- Investigate with OSINT

**Now go build something amazing. 🚀**

---

*Use wisely. Use legally. Use ethically.*  
*Good luck on your cybersecurity journey!*

---

*Built by [Pacific Northwest Computers](https://www.pnwcomputers.com) | [pnwcomputers.com](https://www.pnwcomputers.com)*

## Related Files
- [README.md](README.md) - Full repo index
- [ENHANCED_MASTER_GUIDE.md](ENHANCED_MASTER_GUIDE.md) - Main comprehensive guide
- [SPECIALIZED_TOPICS_GUIDE.md](SPECIALIZED_TOPICS_GUIDE.md) - Specialized topics guide
- [Press Freedom & Source Safety](OPSEC/press-freedom/README.md) - Reporter/source digital-security and duress preparation
- [Diagram and Image Asset Index](assets/README.md) - Visual walkthroughs and section-specific diagrams
- [LEGAL.md](LEGAL.md) - Legal terms before using any technique
