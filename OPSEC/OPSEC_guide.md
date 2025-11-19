# Cybersecurity OPSEC Guide (2025)
## Professional Virtualized Setup for Pentesting, Malware Research, and Privacy

---

# Table of Contents
1. [Executive Overview](#executive-overview)
2. [Host OS Setup](#host-os-setup)
3. [Hypervisor Layer](#hypervisor-layer)
4. [Network Architecture](#network-architecture)
5. [VM Architecture](#vm-architecture)
6. [OPSEC Rules](#opsec-rules)
7. [High-Security Configurations](#high-security-configurations)
8. [Field Edition (Portable OPSEC)](#field-edition-portable-opsec)
9. [Home Lab Edition (Persistent Setup)](#home-lab-edition-persistent-setup)
10. [Recommended Tools](#recommended-tools)
11. [Appendix: VM Folder Structure](#appendix-vm-folder-structure)

---

# Executive Overview

This guide covers a fully compartmentalized cybersecurity environment suitable for:

- Pentesting  
- OSINT & reconnaissance  
- Malware analysis  
- Defensive research (IDS, SIEM, packet capture)  
- Privacy and anonymity  
- Secure red-team/blue-team workflows  

Two modes are provided:

- **Field Use Mode** → lightweight, portable, minimal traces  
- **Home Lab Mode** → fully virtualized infrastructure with VLANs, IDS/IPS, SIEM

---

# Host OS Setup

Your host operating system acts as the “trusted control plane.”

## Recommended Host OS Options

### **1. Windows 11 Pro (with VMware Workstation Pro)**
- BitLocker full-disk encryption  
- Hyper-V disabled (better VMware performance)  
- Core Isolation + Memory Integrity enabled  
- Good for running Windows malware samples

### **2. Proxmox VE (Bare-Metal)**
- KVM + QEMU virtualization  
- ZFS file system  
- VLAN-aware networking  
- Best choice for large home labs

### **3. Linux Host (Fedora or Debian)**
- SELinux or AppArmor  
- LUKS disk encryption  
- Lightweight and stable

---

# Hypervisor Layer

Use one of the following:

### **VMware Workstation Pro**
- Best snapshot system  
- Best for Windows hosts  
- Supports nested virtualization  
- Great isolation features  

### **Proxmox VE**
- Best for multi-VM home labs  
- Advanced networking (bridges, VLANs, firewalls)  
- Template cloning + cloud-init support

---

# Network Architecture

## Baseline Routing Model

```
Host OS → VPN → Virtualization Layer → VMs → Internet
```

- **VPN runs on the host**  
- **VMs use NAT-only** unless intentionally doing LAN-based pentesting  
- **Malware VMs must never reach your LAN**

---

# VM Architecture

## Recommended VM Set

| Category | VM | Purpose |
|---------|----|---------|
| Offensive | Kali / Parrot | Pentesting + exploitation |
| Defensive | ELK / Wazuh | SIEM + threat detection |
| Network | Zeek / Suricata | Packet analysis IDS/IPS |
| Research | Debian/Ubuntu OSINT | Recon, OSINT, documentation |
| Malware | Win10/Win11 + REMnux | Malware detonation + reversing |
| Anonymity | Whonix GW & WS | Tor-based anonymous browsing |
| Utility | Windows Admin VM | Windows-only tools |

---

# OPSEC Rules

## Critical VM Configuration Rules

- **Clipboard sharing: OFF**  
- **Drag-and-drop: OFF**  
- **Shared folders: OFF**  
- **USB passthrough: Avoid for malware VMs**  
- **Snapshots enabled**  
- **NAT-only networking for most VMs**  
- **Bridged mode ONLY for intentional LAN work**  

## Network OPSEC

- VPN: **host level, no exceptions**  
- Whonix:  
  - Gateway VM → VPN (optional)  
  - Workstation → Gateway only  

## Identity Separation

- Never log into personal accounts from research VMs  
- Each operational identity gets:  
  - its own VM  
  - its own browser profile  
  - its own VPN/WAN route  

---

# High Security Configurations

## Malware Lab Isolation (Proxmox)

```
VMs (Malware VLAN)
   ↓
Proxmox Firewall
   ↓
Transparent Gateway VM (Suricata + Zeek)
   ↓
NAT → VPN → Internet
```

Rules:

- No LAN access  
- RAM fully allocated  
- PCI passthrough disabled  
- No virtio drivers for advanced malware cases  

---

# Field Edition (Portable OPSEC)

This mode is for **working on the go**, at client sites, on travel, or when you need strong deniability.

## Principles

- Everything stored inside **one encrypted container**  
- Use **portable virtualization** (e.g., VMware Workstation on a laptop)  
- Run **ephemeral VMs** with no persistent logging  
- Use **burner OSINT identities**  
- Avoid touching local LAN except via VPN tunnel  

## Setup

### Host:
- Windows 11 Pro  
- BitLocker enabled  
- VPN always on  

### VMs:
- 1 × OSINT VM (Debian minimal)  
- 1 × Kali/Parrot  
- 1 × Whonix Workstation  
- (Optional) 1 × Windows Malware VM  

### Storage:
- External SSD with **VeraCrypt container**  
- No VM logs  
- Snapshots automatically rolled back  

### Do Not:
- Run malware without rollback  
- Access personal accounts  
- Use bridged networking  

---

# Home Lab Edition (Persistent Setup)

This mode is for **full home lab deployments**, learning, testing networks, SOC practice, and running a personal cyber range.

## Recommended Architecture

### Proxmox Node
- CPU with VT-x/AMD-V  
- 32–64GB RAM  
- SSD or NVMe storage (ZFS recommended)

### VM Layout

```
/proxmox
 ├── offensive/
 ├── defensive/
 ├── anonymity/
 ├── research/
 ├── malware/
 └── shared-images/
```

### Networking

- vmbr0 → LAN  
- vmbr1 → Malware VLAN  
- vmbr2 → Isolated Blue Team VLAN  

### Defensive Stack VMs:
- Zeek sensor  
- Suricata IDS (inline or monitor mode)  
- Wazuh Manager  
- Elastic Stack (SIEM)  
- pfSense router/firewall  

### Offensive Stack VMs:
- Kali, Parrot, CommandoVM  
- Sliver / Cobalt Strike lab  
- AD attack lab with Windows DC + clients  

---

# Recommended Tools

## Host Tools
- Mullvad / IVPN  
- VeraCrypt  
- KeepassXC  
- USB data blockers  
- Wireshark (host mode passive only)

## Offensive Tools
- Kali Linux tools  
- ParrotOS tools  
- ProxyChains  
- Evilginx / Responder / Impacket  
- Sliver C2  

## Defensive Tools
- Wazuh  
- Zeek  
- Suricata  
- Sysmon  
- ELK Stack  

## Malware Tools
- REMnux  
- Flare-VM  
- Ghidra  
- Cuckoo Sandbox  

---

# Appendix: VM Folder Structure

```
/VMs
 ├── offensive/
 │    ├── kali/
 │    └── parrot/
 ├── defensive/
 │    ├── elastic/
 │    ├── suricata/
 │    ├── zeek/
 │    └── wazuh/
 ├── anonymity/
 │    ├── whonix-gw/
 │    └── whonix-ws/
 ├── malware/
 │    ├── windows10/
 │    └── remnux/
 ├── research/
 │    ├── ubuntu-osint/
 │    └── windows-analysis/
 └── shared/
      └── qcow2-base-images/
```

