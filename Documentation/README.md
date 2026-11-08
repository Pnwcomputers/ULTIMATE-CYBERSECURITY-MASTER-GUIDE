# 📚 Technical Documentation

<div align="center">

**Comprehensive technical documentation, guides, and reference materials for cybersecurity operations**

*Part of the [ULTIMATE CYBERSECURITY MASTER GUIDE](../README.md)*

![Documentation](https://img.shields.io/badge/Documentation-Cybersecurity%20Base-blue?style=for-the-badge)
![Knowledge Base](https://img.shields.io/badge/Category-Knowledge%20Base-green?style=for-the-badge)
![Cybersecurity Ops](https://img.shields.io/badge/Use-Security%20Operations-orange?style=for-the-badge)

</div>

---

**Security API reference:** [Public APIs security catalog and read-only cookbook](./security-public-api-catalog.md) lists relevant providers, authentication caveats, privacy controls and integration status.


**M5StickC Plus2:** [Safe HackStarterPack lab and source mapping](../HardwareHacking/m5stickc-plus2-hackstarterpack.md) complements the device-specific [Bruce](bruce_firmware.md) and [Evil-M5](evil_m5.md) chapters.

**Curated cheat sheet/reference index:** [October 2026 Review & Navigation](./CHEATSHEET-REFERENCE-AUDIT-2026-10-31.md). Covers Debian, Arch, ports/HTTP/regex, Aircrack-ng, Marauder, Pwnagotchi, Wireshark, OSINT, Volatility, NanoVNA, Bash, glossary and general cliff notes. Also see the [November 2026 Devhints-informed CLI field reference](./devhints-cli-field-reference.md) for practical command examples. PDF references retain separate provenance and currency caveats.

**Current verification record:** [November 3 integration and recent push quality review](INTEGRATION-QUALITY-REVIEW-2026-11-03.md) distinguishes passing internal CI from untested external tools and hardware.

## Expanded Device & Firmware Coverage

| Resource | Description / Boundary |
|---|---|
| [ChimeraBLE](./chimerable.md) | BLE active-scan setup and owned-device metadata inspection. |
| [FancyGotchi / Pwnagotchi](./fancygotchi-pwnagotchi.md) | Theme versus image versus independent ESP32 CYD firmware. |

## Dedicated Firmware Labs

| Resource | Role & Compatibility Boundary |
|---|---|
| [GhostESP Revival](./ghostesp-revival.md) | Board-specific install and owned Wi-Fi/BLE observation/capture validation. |
| [NEMO](./nemo-firmware.md) | M5Stack setup, benign discovery and USB/SD interpretation limits. |
| [BLE Capture / Sniffle](./ble-capture-sniffle.md) | Scanner selection, TI firmware/client matching and advertisement-only PCAP validation. |

## Firmware Catalog & Installers

| Resource | Description |
|---|---|
| [ESP32 & Related Firmware Catalog](../HardwareHacking/esp32-security-firmware-catalog.md) | Primary upstream projects, supported targets, use-cases & dated activity notes |
| [Firmware Web Flashers](../HardwareHacking/firmware-web-flashers.md) | Dedicated installers plus a separate multi-device/multi-firmware reference |

## 🎯 Purpose

**Curated third-party GitHub resources:** [Awesome-Hacking + h4cker + Awesome-Hacking-Resources](awesome-hacking-collections-integration.md) with topic routing, license notes and safe adoption decisions.
Index and navigation hub for all documentation in the `Documentation/` directory - covering wireless security tools, privacy/anonymity, programming references, system administration, and hardware platform guides.

## ⚙️ Function
Catalogs 22+ documents by category with descriptions and links, explains the documentation conventions, provides usage guidance for security professionals, IT administrators, and students, and lists related directories (Homelab, OSINT) within the master guide.

## 🏆 Goal
Enable readers to quickly find the right documentation file for their current task - whether that's a wireless engagement, OSINT operation, lab setup, or scripting reference - without browsing the entire directory.

## 📋 When To Use
- Starting point for any Documentation/ section: find the right file for your current task
- Onboarding new team members to the repo structure
- Checking what documentation exists before writing a new guide (avoid duplication)

---

## 📋 Table Of Contents
* [Overview](#-overview)
* [Current Documentation](#-current-documentation)
* [Documentation Categories](#️-documentation-categories)
* [How to Use This Documentation](#-how-to-use-this-documentation)
* [Security & Legal Disclaimer](#️-security--legal-disclaimer)
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

---

## 📂 Current Documentation

### Wireless Security, WiFi & Network Tools
| File | Description | Size/Type |
| :--- | :--- | :--- |
| [Aircrack-ng_Commands.md](./Aircrack-ng_Commands.md) | Complete Aircrack-ng command reference | Reference |
| [wifi-deauthentication-detection.md](./wifi-deauthentication-detection.md) | Legitimate 802.11 disconnects vs spoofing, PMF interpretation, Wireshark/TShark and Kismet detection | Defensive guide |
| [WiFiMarauder_Guide.md](./WiFiMarauder_Guide.md) | Comprehensive guide for WiFi Marauder tool usage | Guide |
| [WifiMarauder_CheatSheet.md](./WifiMarauder_CheatSheet.md) | Quick reference for WiFi Marauder commands | Cheat Sheet |
| [pwnagotchi_cheatsheet.md](./pwnagotchi_cheatsheet.md) | Pwnagotchi setup and command reference | Cheat Sheet |
| [bjorn_pi.md](./bjorn_pi.md) | How-to scan, attack, and exfiltrate from a network that Bjorn is connected to | Guide |
| [bruce_firmware.md](./bruce_firmware.md) | Comprehensive guide for Bruce Firmware usage | Guide |
| [evil_m5.md](./evil_m5.md) | Guide for operations using the Evil-M5 Firmware | Guide |
| [flipper_zero_guide.md](./flipper_zero_guide.md) | Reference guide for analysis and operations using a Flipper Zero | Guide |
| **[Wireshark Master Filter List](./wireshark-master-filters.md)** | 133 display-filter examples, capture BPF distinctions, TShark, Wi-Fi and security triage | Master reference |
| **[Wireshark Field Cheat Sheet](./wireshark-cheatsheet.md)** | Quick copyable filters and GUI/CLI troubleshooting workflow | Cheat sheet |
| [Wireshark filter catalog TSV](./wireshark-filter-catalog.tsv) | Machine-readable, syntax-tested list with caveats | Data/reference |
| [wireshark.md](./wireshark.md) | Advanced router, remote, BLE, Zigbee, hardware capture and protocol reference | Advanced guide |
| [hcxtoolshashcat.md](./hcxtoolshashcat.md) | HCX tools and Hashcat for WiFi password cracking | Guide |
| [microcontroller_wifi_testing.md](./microcontroller_wifi_testing.md) | Reference for using Pwnagotchi, Wifi-Marauder & Flipper Zero together for wifi testing | Guide |

### Privacy & Anonymity
| File | Description | Size/Type |
| :--- | :--- | :--- |
| [TOR.md](./TOR.md) | Tor Browser and Tor daemon setup, proxychains integration, bridges, .onion services, and OPSEC | Guide |
| [VPN.md](./VPN.md) | Mullvad VPN deep-dive: kill switch, multi-hop, DNS leak prevention, CLI usage, and operational security workflows | Guide |
| [OPSEC proxy types / Froxy](../OPSEC/proxy-reference-froxy.md) | HTTP/HTTPS/SOCKS5 comparisons, DNS leaks and warnings for public proxy lists | Companion |

### Programming & Scripting
| File | Description | Size/Type |
| :--- | :--- | :--- |
| [python.md](./python.md) | Python programming reference for security applications | Reference |
| **[curated-technical-docs.md](./curated-technical-docs.md)** | Select links from Beautiful Docs for software, security labs, writing and documentation tooling | Curated links |
| [arduinoIDE.md](./arduinoIDE.md) | Arduino IDE general setup & configuration guide | Guide |
| [vscode.md](./vscode.md) | Visual Studio Code general setup & configuration guide | Guide |

### System Administration
| File | Description | Size/Type |
| :--- | :--- | :--- |
| [LinuxCheatSheet.md](./LinuxCheatSheet.md) | Reviewed Linux commands, system administration, hardware hacking toolkit, WSL2, SDR/RF, and OSINT tools | Cheat Sheet |
| [devhints-cli-field-reference.md](./devhints-cli-field-reference.md) | Original field commands for Bash, find/grep, curl/TLS, rsync/SCP, GnuPG, Git, Docker and tmux/screen | Cheat Sheet |
| [ArchLinux_CheatSheet.md](./ArchLinux_CheatSheet.md) | Reviewed Arch-specific deep reference: pacman, AUR helpers (yay/paru/pamac), makepkg/PKGBUILD, kernel/module management, systemd, mirrors, security tooling setup | Cheat Sheet |
| [blackarch.md](./blackarch.md) | BlackArch repository setup (strap.sh), keyring management, tool category installation, mirror configuration, and system maintenance | Guide |
| [virtualmachines.md](./virtualmachines.md) | Virtual machine setup and management guide | Guide |

### Physical Security
| File | Description | Size/Type |
| :--- | :--- | :--- |
| [Locksport.md](./Locksport.md) | Lock picking fundamentals, impressioning, safe manipulation, and competitive locksport | Guide |

### Security Assessment Resources
| File | Description | Size/Type |
| :--- | :--- | :--- |
| [SAST.Scanners.-.We.Hack.Purple.Cheat.Sheet.pdf](./SAST.Scanners.-.We.Hack.Purple.Cheat.Sheet.pdf) | Static Application Security Testing scanners reference | PDF |
| [Ethical.Hacking.MindMap.pdf](./Ethical.Hacking.MindMap.pdf) | Ethical hacking methodology and concepts mind map | PDF |
| [subdomains.txt](./subdomains.txt) | Subdomain wordlist for enumeration and discovery | Wordlist |
| [references.md](./references.md) | Port/service conventions, HTTP status and regex patterns with validation caveats | Reference Guide |
| **[Security API Catalog & Cookbook](./security-public-api-catalog.md)** | Curated provider API references, NVD/CISA KEV, URLhaus auth caveat, and read-only CLI examples | API reference |
| **[Security Project Source Register](./upstream-security-projects-register.md)** | Source attribution, licenses, integrated guides, lab-only status and update process for 20+ selected projects | Reference index |
| **[Cheat Sheet / Reference Review Index](./CHEATSHEET-REFERENCE-AUDIT-2026-10-31.md)** | Direct links to every reviewed quick reference and its validation/provenance status | Master index |

### Other Resources
| Site | Description |
| :--- | :--- |
| [Anarcho Copy](https://edu.anarcho-copy.org/) | An open digital archive and shadow library project that provides free, unrestrictive access to books, programming manuals, cybersecurity guides, etc |
| [Navigating the DarkWeb](https://navigating-the-darkweb.readthedocs.io/en/latest/) | A Comprehensive Guide to Darknets, Tools, and Intelligence” is an online book written by Sébastien Damaye |

---

## 🗂️ Documentation Categories

### 1. Wireless Security Documentation
* **Aircrack-ng:** Packet capture, WEP/WPA cracking, and deauthentication attacks.
* **WiFi Marauder:** ESP32-based beacon spam, sniffing, and reconnaissance.
* **Pwnagotchi:** AI-powered handshake collection and plugin management.
* **Wireshark:** [Master filters](./wireshark-master-filters.md), [field cheat sheet](./wireshark-cheatsheet.md), [advanced capture reference](./wireshark.md), and packet-analysis workflows.
* **[Deauthentication detection](./wifi-deauthentication-detection.md):** Understand legitimate disconnects, spoofing indicators, PMF, wireless IDS, and incident triage.
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

### 5. Physical Security
* **Locksport:** Lock mechanics, picking/impressioning technique, safe manipulation, and competitive locksport.

---

## 🗂️ Related Directories
| Directory | Description |
| :--- | :--- |
| [`/Homelab/`](../Homelab/) | Homelab build guides, network architecture, and lab environment setup |
| [`/OSINT/`](../OSINT/) | OSINT methodology, tools guide, and investigator cheat sheet |

---

## 📖 How To Use This Documentation

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

<a id="-critical-authorized-and-responsible-use"></a>
### 🔴 Critical: Authorized & Responsible Use
**IMPORTANT: AUTHORIZED USE ONLY**

This documentation is provided for educational purposes in controlled environments and authorized security assessments with written permission.

### 🚫 Strictly Prohibited:
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

## 🔗 Related Files
- [Diagram and Image Asset Index](../assets/README.md) - Topic-specific visual workflows and diagrams across the repository
- [Repository Visual Coverage Review](../assets/VISUAL-AUDIT-2026-11-02.md) - Placement audit, validation limits, and future screenshot requirements
- [../Homelab/README.md](../Homelab/README.md) - Homelab build guides and network architecture
- [../OSINT/README.md](../OSINT/README.md) - OSINT methodology and tools guide
- [../Checklists/README.md](../Checklists/README.md) - Security assessment checklists
- [../Scripts/README.md](../Scripts/README.md) - Scripts that implement many documented techniques
- [../HardwareHacking/README.md](../HardwareHacking/README.md) - Hardware hacking tools and techniques

---

<div align="center">

**📚 Use These Resources Responsibly: Authorization is MANDATORY**

*These techniques are powerful - use them ethically and legally.*

**Repository**: [ULTIMATE CYBERSECURITY MASTER GUIDE](https://github.com/Pnwcomputers/ULTIMATE-CYBERSECURITY-MASTER-GUIDE)

**Maintained by**: [Pacific Northwest Computers](https://github.com/Pnwcomputers)

---

⚠️ **CRITICAL: These are ATTACK TECHNIQUES - Written authorization is REQUIRED** ⚠️

⚠️ **Unauthorized use is a FEDERAL CRIME with up to 10 years imprisonment** ⚠️

⚠️ **ALWAYS obtain explicit written authorization before using any technique** ⚠️

⭐ **Star this repo if you find it useful!** ⭐

</div>
