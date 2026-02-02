# 🏠 Cybersecurity Homelab

Welcome to the **Homelab** section of the **ULTIMATE-CYBERSECURITY-MASTER-GUIDE**. This directory is dedicated to building, configuring, and maintaining a safe, isolated environment for practicing offensive and defensive cybersecurity techniques.

## 🎯 Purpose
A homelab is the backbone of practical cybersecurity research. This section provides the resources needed to:
* **Simulate Real-World Scenarios:** Deploy vulnerable machines and attack infrastructure safely.
* **Standardize Workflows:** Develop and follow Standard Operating Procedures (SOPs) for repeatable success.
* **Test Tools & Malware:** Analyze dangerous software without risking your production network.
* **Master Infrastructure:** Gain hands-on experience with virtualization, networking, and active directory.

## 📚 Guides & Standard Operating Procedures (SOPs)
**This is a living library.** Over time, this section will be populated with detailed guides and SOPs covering essential tasks, including:

* **[Lab Setup](Pnwcomputers/ULTIMATE-CYBERSECURITY-MASTER-GUIDE/blob/main/Homelab/HomeLab_Setup.md) & Maintenance:** Procedures for architecting, deploying, and maintaining homelab environments.
* **Provisioning:** Step-by-step guides for deployment [workflows](/Pnwcomputers/ULTIMATE-CYBERSECURITY-MASTER-GUIDE/tree/main/Homelab/workflows) and automation playbooks.
* **Incident Response:** SOPs for log ingestion (ELK/Splunk) and artifact analysis within the lab.
* **Hardware Prep:** Configuration of Single Board Computers (SBCs), OS installation, firmware flashing, and setup of physical pentest tools (e.g., WiFi Pineapple, Proxmark3).

## 📂 Directory Contents

### 🖥️ Virtualization & Environments
* **VM Setup Procedures:** Guides for configuring VMware, VirtualBox, or Proxmox.
* **Attack Boxes:** Setup scripts for Kali Linux, Parrot OS, and Black Arch.
* **Target Machines:** Resources for deploying Metasploitable, Windows AD ranges, and vulnerable web apps (DVWA/OWASP Juice Shop).

### 📡 Hardware & RF
* **SDR (Software Defined Radio):** Notes and guides for HackRF, RTL-SDR, and YardStick One.
* **Hak5 Gear:** Payloads and setup for Rubber Ducky, Bash Bunny, WiFi Pineapple, and LAN Turtle.
* **Single Board Computers:** DIY pentesting rigs using Raspberry Pi (Kali/Pwnagotchi).

### 🛡️ Network & OpSec
* **Isolation:** VLANs, PfSense/OPNSense firewall rules, and air-gapping techniques.
* **Anonymity:** Tor routing, VPN chaining, and privacy-focused OS (Tails/Whonix) integration.

## 🚀 Getting Started
1. **Hardware Requirements:** Ensure you have a host machine with sufficient RAM (16GB+ recommended) and storage.
2. **Hypervisor:** Install a Type-1 (Proxmox/ESXi) or Type-2 (VMware Workstation/VirtualBox) hypervisor.
3. **Network Segregation:** **CRITICAL:** Always ensure your vulnerable lab machines are network-isolated (Host-Only or Internal Network adapters) to prevent accidental exposure to the internet.

## ⚠️ Disclaimer
**Educational Use Only:**
The tools, scripts, and guides provided in this repository are for educational purposes and authorized testing only.
* **DO NOT** use these tools on networks you do not own or have explicit permission to test.
* **DO NOT** expose vulnerable VMs to the open internet.

## Associated Links:
- [Checklists](/Pnwcomputers/ULTIMATE-CYBERSECURITY-MASTER-GUIDE/tree/main/Checklists)
- [Documentation](/Pnwcomputers/ULTIMATE-CYBERSECURITY-MASTER-GUIDE/tree/main/Documentation)
- [PDF Resources](/Pnwcomputers/ULTIMATE-CYBERSECURITY-MASTER-GUIDE/tree/main/PDF)
- [Playbooks](/Pnwcomputers/ULTIMATE-CYBERSECURITY-MASTER-GUIDE/PlayBooks)
- [SBC Devices](/Pnwcomputers/ULTIMATE-CYBERSECURITY-MASTER-GUIDE/blob/main/FIRMWARE%26HARDWARE_COMPATIBILITY.md)
- [Scripts](/Pnwcomputers/ULTIMATE-CYBERSECURITY-MASTER-GUIDE/tree/main/Scripts)

---

*Part of the [Pnwcomputers/ULTIMATE-CYBERSECURITY-MASTER-GUIDE](https://github.com/Pnwcomputers/ULTIMATE-CYBERSECURITY-MASTER-GUIDE)*
