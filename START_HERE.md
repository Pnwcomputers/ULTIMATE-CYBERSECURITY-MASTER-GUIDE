# 🛡️ START HERE - Your Complete Cybersecurity Guide Collection

## 🎯 Purpose
Navigation guide for the entire guide series - quick paths to the right content for every practitioner role and purpose (red team, blue team, OSINT, forensics, homelab, career).

## ⚙️ Function
Provides role-based navigation paths: Red Team (Tradecraft, Checklists, PlayBooks), Blue Team (IncidentResponse, SIEM, Documentation), OSINT investigator (OSINT/), Forensics analyst (Digital-Forensics/), Homelab builder (Homelab/), and career/learning paths by certification track.

## 🏆 Goal
Eliminate navigation friction for new users and returning practitioners by providing direct paths to the most relevant content for their current role or task without reading the full README.

## 📋 When to Use
- First visit to the repository - start here to find the right guide
- Returning practitioner who forgot where a specific section lives
- Onboarding a team member to the guide structure
- Quickly jumping to a role-specific reference path

<p align="center">
  <img src="assets/cybersecurityguide.png" alt="PNWC Ultimate Cybersecurity Master Guide" width="600"/>
</p>

## 🎯 Purpose
Role- and goal-based navigation for the repository - instead of listing every file (like [README.md](README.md) does), this routes a reader by who they are and what they're trying to accomplish (beginner, pentester, OSCP candidate, blue team, red team, OSINT investigator, hardware hacker) straight to the relevant subset of guides.

## ⚙️ Function
Organized as: a quick-start lookup table by role, a library overview of the three primary guides plus supporting/advanced references, a table of every operational section folder, eight numbered "choose your path" learning tracks, a skills checklist, and a get-started timeline (today/this week/this month). Differs from [README.md](README.md) (flat index of everything) by curating a path rather than cataloging; differs from the master guides themselves by pointing to content rather than containing it.

## 🏆 Goal
A reader identifies their role/goal within seconds and has a concrete, ordered reading list to follow - without needing to browse the full repository structure first.

## 📋 When to Use
The very first file to open after the root [README.md](README.md), or anytime you need to re-orient ("what should I read for X role/goal") rather than look up a specific fact.

## 🎯 QUICK START

- **Abide by the [Legal Terms of Use / Disclaimer & Legal Ramifications](LEGAL.md) for the *Use* & *Misuse* of this Repository's Contents**
- **New to Cybersecurity?** → Start with [Ultimate Master Guide](ultimate_cybersecurity_master_guide.md) → Part I (Foundations)
- **Need Quick Commands?** → Use [Cliff Notes](cybersecurity_cliff_notes.md)
- **Preparing for OSCP?** → [Ultimate Master Guide](ultimate_cybersecurity_master_guide.md) + [Enhanced Master Guide](ENHANCED_MASTER_GUIDE.md) + [Advanced Techniques Part 2](advanced_techniques_part2.md) (Buffer Overflows; CRITICAL) + [Playbooks](PlayBooks/cybersecurity_playbooks.md)
- **Professional Pentester?** → Use All Guides As Reference
- **Blue Team / SOC?** → [Incident Response](IncidentResponse/) + [Blue Team Playbooks](PlayBooks/) + [SIEM Guides](IncidentResponse/SIEM/)
- **OSINT Investigator?** → [OSINT Guide](OSINT/OSINT_GUIDE.md) + [Tradecraft/OSINT Threat Intel](Tradecraft/osint-threat-intel.md)
- **Red Team Operator?** → [Tradecraft](Tradecraft/) + [Advanced Techniques](advanced_techniques_supplement.md) + [Scripts](Scripts/)
- **Hardware Hacker?** → [Specialized Topics Guide](SPECIALIZED_TOPICS_GUIDE.md) (Parts II–III) + [Enhanced Master Guide](ENHANCED_MASTER_GUIDE.md) + [Firmware & Hardware Compatibility](FIRMWARE%26HARDWARE_COMPATIBILITY.md)
- **AI / LLM Security?** → [Specialized Topics Guide](SPECIALIZED_TOPICS_GUIDE.md) (Part I) + [AI Resources](AI/README.md)
- **SDR / RF / Space?** → [Specialized Topics Guide](SPECIALIZED_TOPICS_GUIDE.md) (Parts V–VI) + [SDR](SDR/) + [SpaceSecurity](SpaceSecurity/)
- **uConsole Setup?** → [Specialized Topics Guide](SPECIALIZED_TOPICS_GUIDE.md) (Part IV) + [uConsole](uConsole/)
- **Mobile Platform Pentesting?** → [Mobile Security](Mobile/) + [Mobile Pentest SOP](Mobile/mobile_pentest_sop.md) + [NetHunter Setup](Mobile/OnePlus_A3006/Kali_NetHunter.md)

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
| **[Cybersecurity Cliff Notes](cybersecurity_cliff_notes.md)** | Quick command reference; the essentials at a glance |
| **[Linux Command Cheat Sheet](Documentation/LinuxCheatSheet.md)** | Most-used Linux CLI commands for Debian/Ubuntu/Kali/Parrot/Arch |
| **[Firmware & Hardware Compatibility](FIRMWARE%26HARDWARE_COMPATIBILITY.md)** | SBC-based DIY pentesting devices; compatibility & firmware guide |

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
| 📋 **[Operational Playbooks](PlayBooks/cybersecurity_playbooks.md)** | Field-ready playbooks for professional network & WiFi security audits and pentests |
| 🔍 **[OSINT Guide, Tools & Techniques](OSINT/OSINT_GUIDE.md)** | Comprehensive OSINT methodology; 400+ categorized tools, investigation workflows |
| 🕵️ **[Tradecraft](Tradecraft/)** | Offensive tradecraft; AD attacks, C2 frameworks, AV/EDR evasion, LOLBins, network detection evasion, threat intel |
| 🔴 **[OPSEC](OPSEC/)** | Operational security; anonymity workflows, VM setup, personal rules for professionals |
| 🏠 **[Homelab Guides](Homelab/)** | Building and maintaining safe, isolated labs for offensive and defensive practice |
| 🚨 **[Incident Response](IncidentResponse/)** | Blue Team operations; threat detection, log aggregation, artifact analysis, SIEM setup |
| 💻 **[Scripts](Scripts/)** | Security automation; Bash, Python, PowerShell, C, Go, Ducky scripts |
| 📋 **[Checklists](Checklists/)** | Pre-engagement, testing, and post-engagement checklists |
| 📄 **[PDF Resources](PDF/)** | Curated PDF references and guides |
| 📚 **[Documentation](Documentation/)** | Supplemental technical documentation and cheat sheets |

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
3. [Tradecraft](Tradecraft/); AD, C2, evasion, LOLBins
4. [Operational Playbooks](PlayBooks/cybersecurity_playbooks.md); Field procedures
5. [Advanced Techniques; Part 1](advanced_techniques_supplement.md)
6. [Advanced Techniques; Part 2](advanced_techniques_part2.md)
7. [Scripts](Scripts/); Automate everything
8. Use entire repo as daily reference

### 🎓 OSCP CERTIFICATION PATH
1. [Ultimate Master Guide](ultimate_cybersecurity_master_guide.md); Foundations
2. [Enhanced Master Guide](ENHANCED_MASTER_GUIDE.md); Reconnaissance
3. [Advanced Techniques; Part 2](advanced_techniques_part2.md); **Buffer Overflows (CRITICAL)**
4. [Operational Playbooks](PlayBooks/cybersecurity_playbooks.md); Methodology
5. [Practice with PWK Labs](https://www.offsec.com/blog/pwk-labs-success/)

### 🛡️ BLUE TEAM / SOC ANALYST PATH
1. [Ultimate Master Guide](ultimate_cybersecurity_master_guide.md); Part VI (Network Defense)
2. [Incident Response](IncidentResponse/); Detection, triage, response procedures
3. [Incident Response/SIEM](IncidentResponse/SIEM/); ELK, Wazuh, Splunk, Graylog setup
4. [Blue Team Playbooks](PlayBooks/); Incident response, phishing analysis, unauthorized access
5. [Tradecraft](Tradecraft/); Understanding what you're defending against

### 🔴 RED TEAM OPERATOR PATH
1. [Ultimate Master Guide](ultimate_cybersecurity_master_guide.md); Part IV (Exploitation)
2. [Tradecraft](Tradecraft/); AD attacks, C2 frameworks, AV/EDR evasion, LOLBins
3. [Advanced Techniques; Part 1 & 2](advanced_techniques_supplement.md)
4. [OPSEC](OPSEC/); Stay invisible
5. [Scripts](Scripts/); Offensive automation

### 🔍 OSINT INVESTIGATOR PATH
1. [OSINT Guide](OSINT/OSINT_GUIDE.md); Full methodology, 400+ tools
2. [Tradecraft/OSINT Threat Intel](Tradecraft/osint-threat-intel.md); IOC operationalization, threat intel platforms
3. [Enhanced Master Guide](ENHANCED_MASTER_GUIDE.md); OSINT section
4. [Scripts/Python](Scripts/); OSINT automation

### 🔧 HARDWARE HACKER PATH
1. [Ultimate Master Guide](ultimate_cybersecurity_master_guide.md); Part V (IoT & Hardware)
2. [Enhanced Master Guide](ENHANCED_MASTER_GUIDE.md); Hardware arsenal & firmware
3. [Firmware & Hardware Compatibility](FIRMWARE%26HARDWARE_COMPATIBILITY.md)
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
- Explore your [Homelab Guides](Homelab/) and setup a lab

### This Month
- Finish Master Guide
- Work through [Tradecraft](Tradecraft/) section
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
- [LEGAL.md](LEGAL.md) - Legal terms before using any technique
