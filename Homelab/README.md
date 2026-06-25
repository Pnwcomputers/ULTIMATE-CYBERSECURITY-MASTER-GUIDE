# 🏠 Cybersecurity Homelab

<div align="center">

**Building, configuring, and maintaining isolated environments for offensive and defensive research**

*Part of the [ULTIMATE CYBERSECURITY MASTER GUIDE](../README.md)*

[![Infrastructure](https://img.shields.io/badge/Infrastructure-Virtualization-blue?style=for-the-badge&logo=vmware)]()
[![Hardware](https://img.shields.io/badge/Hardware-SBCs_%7C_Networking-green?style=for-the-badge&logo=raspberrypi)]()
[![Isolation](https://img.shields.io/badge/Security-Air--Gapped_%7C_VLANs-orange?style=for-the-badge)]()
[![Homelab](https://img.shields.io/badge/Environment-Homelab-red?style=for-the-badge&logo=server)]()

</div>

---

## 📋 Table of Contents

- [Overview](#overview)
- [Infrastructure & Directory Contents](#infrastructure--directory-contents)
- [Guides & Standard Operating Procedures](#guides--standard-operating-procedures-sops)
- [Getting Started: Lab Architecture](#getting-started-lab-architecture)
- [⚠️ CRITICAL Security & Isolation Warning](#️-critical-security--isolation-warning)
- [Resources](#resources)

---

## 🎯 Overview

A homelab is the absolute backbone of practical cybersecurity research. This directory is dedicated to the architecture, deployment, and maintenance of a safe, isolated environment. It provides the foundation necessary to practice offensive operations, develop defensive analytics, and reverse-engineer malware without jeopardizing production networks or violating the law.

**Core Objectives:**
* **Simulate Real-World Scenarios:** Deploy vulnerable machines, Active Directory domains, and attack infrastructure safely.
* **Standardize Workflows:** Develop and follow Standard Operating Procedures (SOPs) for repeatable, automated success.
* **Test Tools & Malware:** Analyze dangerous software, test exploits, and study malware behavior in controlled sandboxes.
* **Master Infrastructure:** Gain hands-on engineering experience with Type-1 hypervisors, software-defined networking, and enterprise infrastructure.

---

## 🗂️ Infrastructure & Directory Contents

### 🖥️ Virtualization & Environments
The core computational layer of the lab.

| Category | Description | Examples / Tools |
|----------|-------------|------------------|
| **Hypervisors** | Guides for configuring bare-metal and hosted hypervisors. | Proxmox VE, ESXi, VMware Workstation, VirtualBox |
| **Attack Boxes** | Setup scripts and configurations for offensive platforms. | Kali Linux, Parrot OS, BlackArch, CommandoVM |
| **Target Machines** | Resources for deploying intentionally vulnerable endpoints. | Metasploitable, Windows AD Ranges, DVWA, Juice Shop |

### 📡 Hardware & RF
Physical tools, edge devices, and radio frequency hardware.

| Category | Description | Examples / Tools |
|----------|-------------|------------------|
| **SDR (Radio)** | Notes and guides for capturing, analyzing, and transmitting RF. | HackRF One, RTL-SDR, YardStick One |
| **Hak5 Gear** | Payloads and physical access tooling setup. | Rubber Ducky, Bash Bunny, WiFi Pineapple, LAN Turtle |
| **SBCs** | DIY pentesting rigs and embedded systems configurations. | Raspberry Pi, Pwnagotchi, ClockworkPi uConsole |

### 🛡️ Network & OpSec
The routing, switching, and boundary protection of the lab.

| Category | Description | Examples / Tools |
|----------|-------------|------------------|
| **Isolation** | Routing infrastructure to contain malware and attacks. | pfSense, OPNsense, VLAN tagging, Air-Gapping |
| **Anonymity** | Privacy-focused routing and OS integration. | Tor routing, VPN chaining, Tails, Whonix |

---

## 📚 Guides & Standard Operating Procedures (SOPs)

**This is a living library.** This section contains detailed guides and SOPs covering essential lab administration tasks to ensure your environment remains stable, recoverable, and secure.

| SOP / Guide | Focus Area | Description |
|-------------|------------|-------------|
| **[Lab Setup & Maintenance](./HomeLab_Setup.md)** | Architecture | Core procedures for architecting, deploying, and maintaining homelab environments. |
| **[Provisioning Workflows](./workflows/)** | Automation | Step-by-step guides for deployment workflows (Ansible/Terraform) and automation playbooks. |
| **Incident Response** | Blue Team | SOPs for log ingestion (ELK/Splunk) and artifact analysis within the lab environment. |
| **Hardware Prep** | Physical Assets | OS installation, firmware flashing, and setup of physical pentest tools (e.g., Proxmark3). |

---

## 🚀 Getting Started: Lab Architecture

### 1. Hardware Requirements
* **Minimum:** A modern multi-core CPU (i5/i7/Ryzen), 16GB+ RAM, 500GB SSD.
* **Recommended:** Dedicated hardware (e.g., Intel NUC, Dell OptiPlex, or custom server), 64GB+ RAM, 2TB+ NVMe storage for running complex Active Directory environments alongside SIEMs.

### 2. Choose Your Hypervisor
* **Type-1 (Bare Metal):** Best for dedicated hardware. Install Proxmox VE or VMware ESXi.
* **Type-2 (Hosted):** Best for running a lab on your daily-driver laptop. Install VMware Workstation Pro or VirtualBox.

### 3. Network Segregation (CRITICAL STEP)
Before spinning up vulnerable VMs or executing malware, you must architect the network:
* **Host-Only / Internal Networks:** Configure your hypervisor's virtual switches so that Target VMs can *only* talk to the Attack VM, and cannot reach your physical home network or the internet.
* **Virtual Router:** Deploy a pfSense/OPNsense VM with dual NICs (one connected to your home network for internet access, one connected to the isolated lab LAN) to strictly control ingress/egress traffic.

---

## ⚠️ CRITICAL Security & Isolation Warning

### 🔴 LAB CONTAINMENT & LEGAL WARNING

```
═══════════════════════════════════════════════════════════════
                    ⚠️ CRITICAL WARNING ⚠️
═══════════════════════════════════════════════════════════════

Building a cybersecurity lab involves handling LIVE MALWARE, inherently 
vulnerable systems, and potent offensive tools. 

1. CONTAINMENT FAILURE (BRIDGING)
   ► NEVER bridge a vulnerable VM (like Metasploitable) directly to your 
     home's physical network. If your home network is exposed to the internet, 
     your vulnerable VM WILL be compromised by real-world threat actors.
   ► Malware detonated in an improperly isolated lab can escape and infect 
     your host operating system or personal home network.

2. AUTHORIZED TARGETS ONLY
   ► Having a lab does NOT give you permission to attack infrastructure 
     outside of it.
   ► If your Attack VM (e.g., Kali) has internet routing configured, ensure 
     you do not accidentally launch scans or exploits against external, 
     unauthorized IP addresses. Unauthorized attacks are a FEDERAL CRIME.

3. EDUCATIONAL USE ONLY
   ► The tools, scripts, and vulnerable environments provided or referenced 
     here are strictly for educational purposes and authorized testing.
   ► Pacific Northwest Computers (PNWC) is not liable for data loss, network 
     compromise, or legal issues arising from improper lab configuration.

═══════════════════════════════════════════════════════════════
```

---

## 🔗 Quick Links

### Associated Repository Sections
- [✅ Security Checklists](../Checklists/README.md)
- [📚 Documentation](../Documentation/README.md)
- [📄 PDF Resources](../PDF/README.md)
- [📘 Playbooks](../PlayBooks/README.md)
- [💻 Scripts & Tools](../Scripts/README.md)
- [📻 Hardware & SBC Compatibility](../FIRMWARE%26HARDWARE_COMPATIBILITY.md)

### Internal Core Links
- [🏠 Main Repository](../README.md)
- [🎯 START HERE Guide](../START_HERE.md)
- [💻 Cybersecurity Master Guide](../ultimate_cybersecurity_master_guide.md)
- [🔒 OPSEC Guidelines](../OPSEC/README.md)
- [🚨 Incident Response](../IncidentResponse/README.md)

---

## 📊 Repository Statistics

```
📁 Categories: Virtualization, Hardware/RF, Network Security
💻 Focus: Infrastructure provisioning, Isolation, Active Directory simulation
⚙️ Tech Stack: Proxmox, VMware, pfSense, Linux, Windows Server
🔄 Last Updated: June 2026
👥 Maintained by: Pacific Northwest Computers (PNWC)
📝 Status: Active - Ensure strict isolation before deployment
```

---

<div align="center">

**🛡️ BUILD IT. BREAK IT. SECURE IT. 🛡️**

*The best place to learn how an attacker breaches a network is on a network you built yourself.*

**Repository**: [ULTIMATE CYBERSECURITY MASTER GUIDE](https://github.com/Pnwcomputers/ULTIMATE-CYBERSECURITY-MASTER-GUIDE)

**Maintained by**: [Pacific Northwest Computers](https://github.com/Pnwcomputers)

---

🔴 **NEVER EXPOSE VULNERABLE LAB VMS TO THE INTERNET** 🔴

🔴 **ALWAYS VERIFY NETWORK ISOLATION** 🔴

🔴 **DETONATE MALWARE AT YOUR OWN RISK** 🔴

---

⭐ **Star this repo if you find it useful for building your lab!** ⭐

</div>
