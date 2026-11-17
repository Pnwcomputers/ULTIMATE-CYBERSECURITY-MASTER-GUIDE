# Cybersecurity OPSEC Guide

_Last reviewed: 2026-11-17 (documentation and architecture review; no lab containment or anonymity testing performed)._

**Proxy risk companion:** [Proxy types, leak checks and Froxy research](./proxy-reference-froxy.md). Public proxies are untrusted intermediaries; prefer explicit, approved network routing and Tor/Whonix where appropriate for the threat model.

## 🎯 Purpose
Practical OPSEC guide for cybersecurity professionals - covering the specific virtualized environment setup, identity management, and operational discipline needed for pentesting, malware research, and privacy-sensitive security work.

## ⚙️ Function
Documents a planning baseline for a virtualized security research setup: host OS hardening, VM compartmentalization by workload type (pentesting/malware/OSINT), Tor/VPN chaining, identity separation (accounts, payment, devices), storage encryption, and communications OPSEC.

## 🏆 Goal
Build a repeatable, compartmentalized research environment that separates professional security work from personal digital identity - reducing attribution risk from operational mistakes during authorized engagements.

## 📋 When to Use
- Initial setup of a new security research workstation
- Auditing your current OPSEC posture for gaps
- Preparing for an engagement requiring high-confidentiality operational security
- Training yourself or a team on professional OPSEC practices

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

This guide outlines workload separation for a cybersecurity environment. Suitability depends on the host, hypervisor, routing, and handling procedures; VM labels alone do not enforce separation. Workloads include:

- Pentesting  
- OSINT & reconnaissance  
- Malware analysis  
- Defensive research (IDS, SIEM, packet capture)  
- Privacy and anonymity  
- Secure red-team/blue-team workflows  

Two modes are provided:

- **Field Use Mode** → portable, encrypted storage with an explicit evidence-retention plan  
- **Home Lab Mode** → fully virtualized infrastructure with VLANs, IDS/IPS, SIEM

---

# Host OS Setup

Your host operating system and hypervisor are part of the trusted control plane. A compromised host can undermine every guest; higher-risk malware work may require a separate physical machine.

## Recommended Host OS Options

### **1. Windows 11 Pro (with VMware Workstation Pro)**
- BitLocker full-disk encryption  
- Keep supported Windows security features enabled; assess hypervisor compatibility for the exact versions  
- Verify Core Isolation / Memory Integrity status; memory integrity uses virtualization-based security  
- Use a separate, restricted lab host for malware execution; a Windows desktop is not inherently a containment boundary

[Microsoft documents memory integrity](https://learn.microsoft.com/en-us/windows/security/hardware-security/enable-virtualization-based-protection-of-code-integrity) as a VBS feature that depends on the Windows hypervisor. Do not follow blanket advice to disable Hyper-V while expecting those protections to remain active; select a supported combination and verify the resulting security state.

### **2. Proxmox VE (Bare-Metal)**
- KVM + QEMU virtualization  
- ZFS file system  
- VLAN-aware networking  
- Supports multi-VM labs; protect the management plane separately

### **3. Linux Host (Fedora or Debian)**
- SELinux or AppArmor  
- LUKS disk encryption  
- Lightweight and stable

---

# Hypervisor Layer

Use one of the following:

### **VMware Workstation Pro**
- Snapshots support repeatable guest-state recovery  
- Desktop virtualization option for supported Windows/Linux hosts  
- Supports nested virtualization  
- Isolation depends on configuration, patching, and device-sharing controls  

### **Proxmox VE**
- Server-oriented option for multi-VM home labs  
- Advanced networking (bridges, VLANs, firewalls)  
- Template cloning + cloud-init support

---

# Network Architecture

## Baseline Routing Model

```
Research VM → virtual NAT → host routing/firewall → optional VPN → destination
```

- A host VPN is optional and task-dependent; verify that the guest's actual IPv4, IPv6, DNS, and failure paths follow the intended policy  
- NAT permits outbound communication and may expose host or LAN services; it does **not** establish malware containment  
- Malware execution starts on an isolated virtual segment or with its network adapter disconnected; block host, management, LAN, and uncontrolled Internet access

---

![Networking choices showing NAT outbound access, host-only host access, and internal guest-only segments](../assets/diagrams/opsec-vm-network-choices.svg)

*Networking comparison: [VMware's network definitions](https://knowledge.broadcom.com/external/article?legacyId=1006480) explain why NAT and host-only are not synonyms for an isolated malware network. Other hypervisors have different names and defaults; inspect actual adapters, forwarding, and firewall rules.*

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
- **Known-clean snapshots and separate backups**, with sensitive snapshot files protected  
- **Choose networking per workload**; NAT, host-only, and internal networks have different trust boundaries  
- **Bridged mode only for explicitly scoped LAN work**; no bridging of the malware segment  

**Whonix exception:** Workstation must use only the supplied private network to Gateway; do not apply the generic NAT/bridged advice to it. Use the [Whonix + Kicksecure guide](./whonix-kicksecure-usb-guide.md#hypervisor-selection) for the VirtualBox baseline and the separate KVM/libvirt installation route.

## Network OPSEC

- VPN: host level when required by the task; a VPN is not a Whonix requirement. Review [Whonix tunnel tradeoffs](https://www.whonix.org/wiki/Tunnels/Introduction) before adding one.
- Whonix:  
  - Workstation → Gateway → Tor; an optional host VPN sits before Tor
  - Workstation → Gateway only  

Compartmentalization reduces accidental cross-use; personal logins, browser fingerprinting, shared files, timing, and provider records can still link activity. Tor and a VPN address different observers and do not guarantee anonymity. Keep the Whonix gateway/workstation topology intact and follow its supported hypervisor instructions.

## Identity Separation

- Never log into personal accounts from research VMs  
- Each operational identity gets:  
  - its own VM  
  - its own browser profile  
  - an explicitly documented network route, where separation is required; a different VPN address does not prevent correlation  

---

# High Security Configurations

## Malware Lab Isolation (Proxmox)

![Offline malware segment with a sample guest and simulated services, separate from the management plane](../assets/diagrams/opsec-malware-lab-boundaries.svg)

*Containment design: simulated services can support observation without real Internet access. This is a conceptual target architecture, not a verified Proxmox configuration. An IDS in monitor mode observes traffic; it does not block it.*

Rules:

- Start with no physical uplink, no host adapter on the analysis segment, and no default route to production networks.
- Use a controlled simulation VM when network behavior must be observed; do not give that VM an unreviewed second route.
- Permit any external access only through a separately designed, logged, destination-restricted gateway under the lab owner's policy.
- Disable unnecessary shared folders, clipboard, USB and PCI passthrough. Virtual drivers and RAM settings are compatibility/resource decisions, not proof of isolation.
- Test boundaries with benign traffic before introducing a sample; snapshots restore guest state but cannot undo host compromise or external communication.  

---

# Field Edition (Portable OPSEC)

This mode is for **authorized work on the go**, at client sites, or during travel. Encryption and an ephemeral guest do not guarantee deniability or removal of host, provider, or service records.

## Principles

- Store sensitive working data in an encrypted volume; keep separately protected recovery material and backups  
- Use a patched laptop and a supported, installed hypervisor; an external VM image does not make the hypervisor portable  
- Use disposable guests where appropriate, while preserving required engagement records outside the guest  
- Use approved research identities without mixing personal accounts or credentials  
- Restrict LAN access explicitly; a VPN may retain local routes or bypass paths  

## Setup

### Host:
- Windows 11 Pro  
- BitLocker enabled  
- Verify the approved VPN's routing and failure behavior when a VPN is required  

### VMs:
- 1 × OSINT VM (Debian minimal)  
- 1 × Kali/Parrot  
- 1 × Whonix-Gateway **and** 1 × Whonix-Workstation (LXQt build flavors: `whonix-gateway-lxqt` and `whonix-workstation-lxqt`); see [installation and naming](./whonix-kicksecure-usb-guide.md#guest-names).
- (Optional) 1 × Windows Malware VM  

### Storage:

An encrypted container protects stored contents while locked, within its threat model. Mounted data, RAM, swap, hibernation, host logs, and backups may remain exposed. Follow [VeraCrypt's security requirements](https://veracrypt.io/en/Security%20Requirements%20and%20Precautions.html); container use alone does not establish deniability.

- External SSD with **VeraCrypt container**  
- Minimize unnecessary personal data; retain the logs and evidence required by the engagement  
- Preserve necessary results, then restore a known-clean guest state; rollback does not erase external records  

### Do Not:
- Execute malware on a shared field laptop; use a dedicated lab and verify containment before any execution  
- Mix personal accounts, shared browser synchronization, or personal credentials into research guests  
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

These are **roles**, not security properties of bridge names. A Linux bridge behaves like a virtual switch; review physical ports, host addresses, VLAN tags, guest adapters, and forwarding rules. See the [Proxmox network documentation source](https://github.com/proxmox/pve-docs/blob/master/pve-network.adoc).


- Example role: management/LAN bridge, restricted to trusted administrative access  
- Example role: isolated malware segment with no physical uplink or unapproved routing  
- Example role: blue-team test segment with deliberately configured routing and monitoring  

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
- [Mullvad](https://mullvad.net/en) / [IVPN](https://www.ivpn.net/en/)
- [VeraCrypt](https://veracrypt.jp/en/Home.html)
- [KeepassXC](https://keepassxc.org/)
- USB data-blocking adapters (check the exact connector and power/data behavior; these do not secure the endpoint)
- [Wireshark (host mode passive only)](https://www.wireshark.org/faq)

## Offensive Tools
- [Kali Linux tools](https://www.kali.org/tools/)
- [ParrotOS tools](https://parrotsec.org/docs/tools/)
- [Proxychains-ng](https://github.com/rofl0r/proxychains-ng)
- [Evilginx](https://evilginx.com/) / [Responder](https://github.com/SpiderLabs/Responder) / [Impacket](https://github.com/fortra/impacket)  
- [Sliver C2](https://github.com/BishopFox/sliver)

## Defensive Tools
- [Wazuh](https://wazuh.com/)
- [Zeek](https://zeek.org/)
- [Suricata](https://suricata.io/)
- [Sysmon](https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon)
- [ELK Stack](https://www.elastic.co/elastic-stack)

## Malware Tools
- [REMnux](https://remnux.org/)
- [Flare-VM](https://github.com/mandiant/flare-vm)
- [Ghidra](https://github.com/NationalSecurityAgency/ghidra)
- [Cuckoo Sandbox documentation](https://cuckoo.readthedocs.io/en/latest/) (legacy/version-specific reference; validate current maintenance and platform support before choosing a sandbox)

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


## Sources and review limits

- [Microsoft: memory integrity and VBS](https://learn.microsoft.com/en-us/windows/security/hardware-security/enable-virtualization-based-protection-of-code-integrity)
- [Broadcom: hosted VM networking types](https://knowledge.broadcom.com/external/article?legacyId=1006480)
- [Proxmox: network configuration source](https://github.com/proxmox/pve-docs/blob/master/pve-network.adoc)
- [REMnux: disposable analysis environments and isolation](https://docs.remnux.org/tips/using-ai)
- [Whonix: supported VirtualBox baseline](https://www.whonix.org/wiki/VirtualBox/Recommended_Version)
- [VeraCrypt: security requirements and precautions](https://veracrypt.io/en/Security%20Requirements%20and%20Precautions.html)

This revision checks documentation and explains trust boundaries. It does not certify a host, prove anonymity, or validate a running malware lab.

## Related Files
- [README.md](README.md) - OPSEC section index
- [../Documentation/VPN.md](../Documentation/VPN.md) - Mullvad VPN setup
- [../Documentation/TOR.md](../Documentation/TOR.md) - Tor Browser for anonymous access
- [../Documentation/virtualmachines.md](../Documentation/virtualmachines.md) - VM compartmentalization setup
- [press-freedom/README.md](press-freedom/README.md) - journalists, confidential-source protection, device seizure and duress planning
- [../Cryptography/encrypted-storage.md](../Cryptography/encrypted-storage.md) - portable drive encryption and recovery
- [../Cryptography/security-keys-passkeys.md](../Cryptography/security-keys-passkeys.md) - FIDO2/passkey account safeguards
- [../Mobile/README.md](../Mobile/README.md) - Mobile security section (mobile OPSEC, device hardening)
- [../Mobile/mobile_pentest_sop.md](../Mobile/mobile_pentest_sop.md) - Mobile pentest SOP (MAC randomization, covert operation procedures)
