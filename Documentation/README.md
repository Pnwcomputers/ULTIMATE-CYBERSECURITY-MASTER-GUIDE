# 📚 Technical Documentation

## 🎯 Purpose
Index and navigation hub for all documentation in the `Documentation/` directory — covering wireless security tools, privacy/anonymity, programming references, system administration, and hardware platform guides.

## ⚙️ Function
Catalogs 22+ documents by category with descriptions and links, explains the documentation conventions, provides usage guidance for security professionals, IT administrators, and students, and lists related directories (Homelab, OSINT) within the master guide.

## 🏆 Goal
Enable readers to quickly find the right documentation file for their current task — whether that's a wireless engagement, OSINT operation, lab setup, or scripting reference — without browsing the entire directory.

## 📋 When to Use
- Starting point for any Documentation/ section: find the right file for your current task
- Onboarding new team members to the repo structure
- Checking what documentation exists before writing a new guide (avoid duplication)

Comprehensive technical documentation, guides, and reference materials for cybersecurity operations

Part of the **ULTIMATE CYBERSECURITY MASTER GUIDE**

[![Documentation](https://img.shields.io/badge/Documentation-Cybersecurity%20Base-blue?style=for-the-badge&logo=googledocs&logoColor=white)]()
[![Knowledge Base](https://img.shields.io/badge/Category-Knowledge%20Base-green?style=for-the-badge&logo=gitbook&logoColor=white)]()
[![Cybersecurity Ops](https://img.shields.io/badge/Use-Security%20Operations-orange?style=for-the-badge&logo=fortinet&logoColor=white)]()

---

## 📋 Table of Contents
* [Overview](#-overview)
* [Current Documentation](#-current-documentation)
* [Documentation Categories](#-documentation-categories)
* [How to Use This Documentation](#-how-to-use-this-documentation)
* [Security & Legal Disclaimer](#-security--legal-disclaimer)
* [Contributing](#-contributing)
* [Resources](#-resources)

---

## 🎯 Overview
This directory contains comprehensive technical documentation, operational procedures, and reference materials for cybersecurity professionals, IT administrators, security researchers, and students. The documentation focuses on practical implementation and real-world application of security concepts.

### What You'll Find Here:
* 📖 **Technical implementation guides**
* 🔧 **Tool configuration documentation**
* 📝 **Command reference sheets**
* 🎓 **Training materials and cheat sheets**
* 🔐 **Security best practices**
* 💡 **Setup and configuration guides**
* 🌐 **Network security documentation**

### Purpose
This documentation serves as a reference material for security implementations, training resources for skill development, operational guides for consistent procedures, and a knowledge repository for team collaboration.

---

## 📂 Current Documentation

### Wireless Security, WiFi & Network Tools
| File | Description | Size/Type |
| :--- | :--- | :--- |
| `Aircrack-ng_Commands.md` | Complete Aircrack-ng command reference | Reference |
| `WiFiMarauder_Guide.md` | Comprehensive guide for WiFi Marauder tool usage | Guide |
| `WifiMarauder_CheatSheet.md` | Quick reference for WiFi Marauder commands | Cheat Sheet |
| `pwnagotchi_cheatsheet.md` | Pwnagotchi setup and command reference | Cheat Sheet |
| `bjorn_pi.md` | How-to scan, attack, and exfiltrate from a network that Bjorn is connected to | Guide |
| `bruce_firmware.md` | Comprehensive guide for Bruce Firmware usage | Guide |
| `evil_m5.md` | Guide for operations using the Evil-M5 Firmware | Guide |
| `flipper_zero_guide.md` | Reference guide for analysis and operations using a Flipper Zero | Guide |
| `wireshark.md` | Wireshark filters and reference for network analysis and security operations | Guide |
| `hcxtoolshashcat.md` | HCX tools and Hashcat for WiFi password cracking | Guide |

### Privacy & Anonymity
| File | Description | Size/Type |
| :--- | :--- | :--- |
| `TOR.md` | Tor Browser and Tor daemon setup, proxychains integration, bridges, .onion services, and OPSEC | Guide |
| `VPN.md` | Mullvad VPN deep-dive: kill switch, multi-hop, DNS leak prevention, CLI usage, and operational security workflows | Guide |

### Programming & Scripting
| File | Description | Size/Type |
| :--- | :--- | :--- |
| `python.md` | Python programming reference for security applications | Reference |
| `arduinoIDE.md` | Arduino IDE general setup & configuration guide | Guide |
| `vscode.md` | Visual Studio Code general setup & configuration guide | Guide |

### System Administration
| File | Description | Size/Type |
| :--- | :--- | :--- |
| `LinuxCheatSheet.md` | Essential Linux commands, system administration, hardware hacking toolkit, WSL2, SDR/RF, and OSINT tools | Cheat Sheet |
| `virtualmachines.md` | Virtual machine setup and management guide | Guide |
| `blackarch.md` | General "Blackarch 101" guide | Guide |

### Security Assessment Resources
| File | Description | Size/Type |
| :--- | :--- | :--- |
| `SAST.Scanners.-.We.Hack.Purple.Cheat.Sheet.pdf` | Static Application Security Testing scanners reference | PDF |
| `Ethical.Hacking.MindMap.pdf` | Ethical hacking methodology and concepts mind map | PDF |
| `subdomains.txt` | Subdomain wordlist for enumeration and discovery | Wordlist |
| `references.md` | Quick-reference tables for port numbers, HTTP status codes, etc. | Reference Guide |

---

## 🗂️ Documentation Categories

### 1. Wireless Security Documentation
* **Aircrack-ng:** Packet capture, WEP/WPA cracking, and deauthentication attacks.
* **WiFi Marauder:** ESP32-based beacon spam, sniffing, and reconnaissance.
* **Pwnagotchi:** AI-powered handshake collection and plugin management.
* **Wireshark:** Network packet capture, filter reference, and traffic analysis.
* **HCX Tools & Hashcat:** Hash extraction and dictionary/brute-force attacks.

### 2. Privacy & Anonymity Tools
* **TOR Network:** Browser and daemon installation, proxychains integration, hidden services (.onion), bridges, and OPSEC.
* **VPN Configuration:** Mullvad setup, protocol selection, kill switch implementation, multi-hop, and DNS leak prevention.

### 3. Programming Resources
* **Python for Security:** Network operations, exploitation frameworks, and automation scripts.

### 4. System Administration
* **Linux Fundamentals:** User permissions, process control, network config, hardware hacking toolkit, WSL2, and OSINT tools.
* **Virtualization:** Hypervisor setup and snapshot management for safe testing.
* **BlackArch:** Arch-based penetration testing distribution setup and tooling.

---

## 🗂️ Related Directories
| Directory | Description |
| :--- | :--- |
| [`/Homelab/`](../Homelab/) | Homelab build guides, network architecture, and lab environment setup |
| [`/OSINT/`](../OSINT/) | OSINT methodology, tools guide, and investigator cheat sheet |

---

## 📖 How to Use This Documentation

### For Security Professionals
1.  **Wireless Security Assessments:** Review Aircrack-ng and use Pwnagotchi for handshakes.
2.  **Privacy-Focused Operations:** Set up TOR/VPN and follow OPSEC protocols.
3.  **Tool Development:** Reference the Python guide to automate testing tasks.

### For IT Administrators
1.  **System Hardening:** Use Linux commands to implement security best practices.
2.  **Network Security:** Conduct authorized WiFi audits and monitor for rogue access.
3.  **Secure Remote Access:** Deploy VPNs with multi-factor authentication.

### For Students & Learners
1.  **Building Skills:** Start with Linux fundamentals and the Ethical Hacking Mind Map.
2.  **Hands-On Practice:** Build a home lab with virtual machines for safe testing.

---

## ⚠️ Security & Legal Disclaimer

### 🔴 CRITICAL: Authorized and Responsible Use
**IMPORTANT: AUTHORIZED USE ONLY**

This documentation is provided for educational purposes in controlled environments and authorized security assessments with written permission.

### 🚫 STRICTLY PROHIBITED:
* Unauthorized wireless network testing or access.
* Cracking passwords for networks you do not own.
* Intercepting communications without authorization.
* Using anonymity tools for illegal activities.

> **Legal Note:** Wireless network testing without authorization is **ILLEGAL** under the Computer Fraud and Abuse Act (CFAA) and the Wiretap Act. Penalties include up to 10 years imprisonment and heavy fines.

---

## 🤝 Contributing
We welcome contributions from security professionals and researchers.

1.  **Fork** the repository.
2.  **Create** documentation following our quality standards.
3.  **Include** prominent legal warnings and tested examples.
4.  **Submit** a pull request.

---

## 📚 Resources
* **Legal:** [CISA](https://www.cisa.gov/), [EFF Coders' Rights](https://www.eff.org/issues/coders)
* **Standards:** [OWASP](https://owasp.org/), [NIST Cybersecurity Framework](https://www.nist.gov/cyberframework)
* **Tools:** [Kali Linux](https://www.kali.org/), [Aircrack-ng Docs](https://www.aircrack-ng.org/documentation.html)

---

## 📊 Repository Statistics
* **Current Files:** 22 documents
* **Last Updated:** June 2026
* **Maintained by:** Pacific Northwest Computers (PNWC)
* **Status:** Active & Growing

---

## 🔨 Future Documents (Coming Soon)
* **Architecture:** Zero Trust, DMZ Design, Security Architecture.

---
**Use This Knowledge Responsibly: Always Obtain Authorization**
