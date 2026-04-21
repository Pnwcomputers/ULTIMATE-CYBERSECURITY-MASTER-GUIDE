
# 🦈 Wireshark Filters Reference

<div align="center">

**Complete Wireshark display and capture filter reference for network analysis and security operations**

*Part of the [ULTIMATE CYBERSECURITY MASTER GUIDE](../README.md)*

[![Documentation](https://img.shields.io/badge/Documentation-Wireshark%20Filters-blue?style=for-the-badge)]()
[![Network Analysis](https://img.shields.io/badge/Category-Network%20Analysis-green?style=for-the-badge)]()
[![Security Operations](https://img.shields.io/badge/Use-Security%20Operations-orange?style=for-the-badge)]()

</div>

---

## 📋 Table of Contents

- [Overview](#overview)
- [Capture Methods](#capture-methods)
- [Core Protocol Filters](#core-protocol-filters)
- [Port-Based Filters](#port-based-filters)
- [IP & Subnet Filters](#ip--subnet-filters)
- [TCP Flag & State Filters](#tcp-flag--state-filters)
- [Security & Threat Detection Filters](#security--threat-detection-filters)
- [Noise Reduction Filters](#noise-reduction-filters)
- [Remote Capture via SSH](#remote-capture-via-ssh)
- [BLE & Bluetooth Capture](#ble--bluetooth-capture)
- [Zigbee Capture](#zigbee-capture)
- [MikroTik RouterOS Sniffer](#mikrotik-routeros-sniffer)
- [OpenWRT & tcpdump Reference](#openwrt--tcpdump-reference)
- [Minimum Starter Filter Sets](#minimum-starter-filter-sets)
- [Security & Legal Disclaimer](#security--legal-disclaimer)
- [Contributing](#contributing)
- [Resources](#resources)

---

## 🎯 Overview

This document provides a **comprehensive Wireshark filter reference** compiled from real-world network analysis, security assessments, and homelab operations. It covers display filters, capture filters, remote streaming, and protocol-specific analysis for wireless, Bluetooth, and IoT traffic.

**What You'll Find Here:**
- 📡 Core protocol and port-based display filters
- 🔍 IP, subnet, and TCP flag filters
- 🛡️ Security and threat detection filters
- 📉 Noise reduction for cleaner captures
- 🖥️ Remote SSH-to-Wireshark live streaming
- 📶 BLE/Bluetooth and Zigbee capture setup
- 🔧 MikroTik RouterOS and OpenWRT sniffer configs
- ⚡ Ready-to-paste minimum starter filter sets

### Purpose

This reference serves as:
- **Field reference** for active packet analysis sessions
- **Security operations** tool for threat hunting and incident response
- **Training resource** for understanding protocol behavior
- **Quick reference** for authorized wireless and IoT assessments
- **Lab documentation** for homelab network monitoring

---

## 📂 Capture Methods

Before filtering, choose the right capture mode for your scenario.

| Method | Use Case | Notes |
|--------|----------|-------|
| **Promiscuous mode** | Capture all frames the NIC receives | Standard for wired analysis |
| **Monitor mode** | Capture all 802.11 frames including other stations | Requires compatible wireless NIC |
| **Port mirroring / SPAN** | Mirror another switch port to your monitoring interface | Requires managed switch |
| **Network tap** | Passive in-line capture on a physical link | Most accurate, no network impact |
| **Remote SSH capture** | Live stream from router or remote device into Wireshark | See [Remote Capture](#remote-capture-via-ssh) section |

> ✅ **Tip:** Enable promiscuous mode in **Capture → Options → Promiscuous** before starting. For wireless, use **Capture → Options → Monitor Mode**.

---

## 🗂️ Core Protocol Filters

These are Wireshark **display filters** — enter them in the filter bar after a capture is running or loaded.

### Transport Layer

```wireshark
tcp                    # All TCP traffic
udp                    # All UDP traffic
icmp                   # ICMP (ping, traceroute)
arp                    # ARP (address resolution, network mapping)
```

### Application Layer

```wireshark
dns                    # DNS queries and responses
bootp                  # DHCP traffic (BOOTP/DHCP)
http                   # HTTP (cleartext web traffic)
tls                    # TLS/HTTPS (encrypted; metadata only)
ftp                    # FTP control channel
ftp-data               # FTP data transfer
smb || smb2            # SMB / Windows file sharing
ssh                    # SSH (filtered by protocol field)
```

### Wireless & IoT

```wireshark
wlan                   # 802.11 WiFi frames
eapol                  # WPA handshake capture (key exchange)
btle                   # Bluetooth Low Energy
btatt                  # BLE GATT operations (IoT attribute reads/writes)
smp                    # BLE Security Manager (pairing events)
wpan                   # 802.15.4 / Zigbee frames
zbee_nwk               # Zigbee network layer
zbee_zcl               # Zigbee cluster library (application layer)
```

---

## 🔌 Port-Based Filters

```wireshark
# Single port (either direction)
tcp.port == 443

# Multiple ports
tcp.port == 80 || tcp.port == 443

# Destination port only
tcp.dstport == 8080

# Source port only
tcp.srcport == 443

# Port range
tcp.port >= 8000 && tcp.port <= 9000
```

### Common Port Reference

| Port | Protocol | Filter |
|------|----------|--------|
| 22 | SSH | `tcp.port == 22` |
| 25 | SMTP | `tcp.port == 25` |
| 53 | DNS | `udp.port == 53 \|\| tcp.port == 53` |
| 67/68 | DHCP | `bootp` |
| 80 | HTTP | `http` |
| 110 | POP3 | `tcp.port == 110` |
| 143 | IMAP | `tcp.port == 143` |
| 443 | HTTPS | `tls` |
| 445 | SMB | `smb \|\| smb2` |
| 993 | IMAPS | `tcp.port == 993` |
| 995 | POP3S | `tcp.port == 995` |
| 3389 | RDP | `tcp.port == 3389` |
| 8291 | MikroTik Winbox | `tcp.port == 8291` |

---

## 🌐 IP & Subnet Filters

```wireshark
# Traffic from a specific source
ip.src == 192.168.1.100

# Traffic to a specific destination
ip.dst == 192.168.1.1

# Traffic to OR from an IP (either direction)
ip.addr == 192.168.1.100

# Entire subnet (CIDR)
ip.src == 192.168.1.0/24

# Exclude an IP from results
!(ip.addr == 192.168.1.1)

# Traffic between two specific hosts
ip.addr == 192.168.1.10 && ip.addr == 192.168.1.20

# External (non-RFC1918) traffic only
!(ip.src == 10.0.0.0/8) && !(ip.src == 172.16.0.0/12) && !(ip.src == 192.168.0.0/16)
```

---

## 🚩 TCP Flag & State Filters

```wireshark
# SYN only — connection initiations
tcp.flags.syn == 1 && tcp.flags.ack == 0

# SYN-ACK — handshake responses
tcp.flags.syn == 1 && tcp.flags.ack == 1

# RST — connection resets / failures
tcp.flags.reset == 1

# FIN — connection teardowns
tcp.flags.fin == 1

# PSH+ACK — actual data payload traffic
tcp.flags.push == 1 && tcp.flags.ack == 1

# Retransmissions — packet loss / congestion indicator
tcp.analysis.retransmission

# Duplicate ACKs
tcp.analysis.duplicate_ack

# Zero window — receiver buffer full (performance issue)
tcp.analysis.zero_window
```

---

## 🛡️ Security & Threat Detection Filters

```wireshark
# Port scan indicator — SYN flood or half-open connections
tcp.flags.syn == 1 && tcp.flags.ack == 0

# Failed connections — RST flood
tcp.flags.reset == 1

# Large packets — potential data exfiltration
frame.len > 1400

# Fragmented IP packets — possible evasion technique
ip.flags.mf == 1 || ip.frag_offset > 0

# Broadcast traffic — network discovery or flood
eth.dst == ff:ff:ff:ff:ff:ff

# ICMP echo flood — DoS indicator
icmp.type == 8

# DNS over non-standard port — possible DNS tunneling
dns && !(udp.port == 53) && !(tcp.port == 53)

# HTTP on non-standard port — C2 traffic indicator
http && !(tcp.port == 80)

# TLS on non-standard port — possible C2 or evasion
tls && !(tcp.port == 443) && !(tcp.port == 8443)

# ARP reply with no prior request — ARP spoofing indicator
arp.opcode == 2

# Long DNS query names — possible DNS exfiltration
dns.qry.name.len > 50
```

---

## 🔇 Noise Reduction Filters

Use these to strip background chatter and focus on relevant traffic.

```wireshark
# Exclude ARP and ICMP (noisy on busy LANs)
!(arp || icmp)

# Exclude broadcast and multicast
!(eth.dst[0] & 1)

# Exclude DHCP renewal noise
!(bootp)

# Exclude LLMNR, mDNS, SSDP (Windows/IoT background noise)
!(udp.port == 5355 || udp.port == 5353 || udp.port == 1900)

# Exclude Spanning Tree Protocol
!(stp)

# Exclude NetBIOS Name Service
!(nbns)

# Show only your subnet's outbound internet traffic
ip.src == 192.168.1.0/24 && !(ip.dst == 192.168.1.0/24)

# Clean view — application traffic only, no management noise
(tcp || udp) && !(bootp || nbns || ssdp || mdns || stp || arp)
```

---

## 🖥️ Remote Capture via SSH

Stream live captures from a remote device directly into your local Wireshark instance.

### Basic SSH Streaming

```bash
# Linux/macOS — stream from a remote Linux device
ssh root@192.168.1.1 "tcpdump -i eth0 -U -s0 -w -" | wireshark -k -i -

# OpenWRT / GL.iNet router
ssh root@192.168.8.1 "tcpdump -i br-lan -U -s0 -w -" | wireshark -k -i -

# Apply a capture filter at source to reduce bandwidth
ssh root@192.168.1.1 "tcpdump -i eth0 -U -s0 -w - 'tcp port 80 or tcp port 443'" | wireshark -k -i -
```

### Windows

```powershell
# Via WSL or direct (Wireshark in PATH)
ssh root@192.168.1.1 "tcpdump -i eth0 -U -s0 -w -" | "C:\Program Files\Wireshark\Wireshark.exe" -k -i -
```

### Save to File Instead

```bash
# Save remote capture to local .pcap
ssh root@192.168.1.1 "tcpdump -i eth0 -U -s0 -w -" > /tmp/capture.pcap
```

> ✅ **Note:** `-U` flushes each packet immediately (required for live streaming). `-s0` captures the full packet without truncation.

---

## 📶 BLE & Bluetooth Capture

### Hardware Setup

| Hardware | Firmware / Software | Wireshark Integration |
|----------|---------------------|-----------------------|
| **nRF52840 Dongle** | Nordic nRF Sniffer firmware | Install nRF Sniffer for Wireshark plugin |
| **Ubertooth One** | Default (ubertooth-btle) | Pipe to pcap or use as live interface |

```bash
# Ubertooth — capture to pcap file, open in Wireshark after
ubertooth-btle -f -c /tmp/ble.pcap

# Ubertooth — live stream directly into Wireshark
ubertooth-btle -f -w /dev/stdout | wireshark -k -i -
```

### BLE Display Filters

```wireshark
# All BLE advertising packets
btle.advertising_header

# Filter by BLE device address (BD_ADDR)
btle.advertising_address == aa:bb:cc:dd:ee:ff

# BLE connection data events only
btle.data_header

# BLE pairing / security events
smp

# GATT read/write operations (IoT device interaction)
btatt

# HCI layer (host controller interface)
hci_cmd || hci_evt
```

---

## 🕸️ Zigbee Capture

### Hardware & Capture Tools

```bash
# KillerBee — capture on Zigbee channel 15
zbdump -c 15 -w /tmp/zigbee.pcap

# Scan for active Zigbee PANs
zbstumbler

# Replay a capture
zbreplay -f /tmp/zigbee.pcap
```

### Zigbee Display Filters

```wireshark
# 802.15.4 / Zigbee base frames
wpan

# Zigbee network layer
zbee_nwk

# Zigbee application / cluster library
zbee_zcl

# Filter by Zigbee PAN ID
wpan.dst_pan == 0x1234
```

> ✅ **Tip:** Go to **Analyze → Decode As → IEEE 802.15.4** to decode Zigbee frames. Add your network key under **Protocols → IEEE 802.15.4 → Decryption Keys**.

---

## 🔧 MikroTik RouterOS Sniffer

RouterOS has a built-in packet sniffer with its own syntax, separate from Wireshark display filters.

### Basic Sniffer Control

```routeros
# Configure and start the sniffer
/tool sniffer set filter-protocol=tcp,udp,icmp filter-port=53,80,443,22 streaming-enabled=yes
/tool sniffer start

# View captured packets
/tool sniffer packet print

# Stop sniffer
/tool sniffer stop
```

### Protocol & Interface Filters

```routeros
# Web traffic only
/tool sniffer set filter-protocol=tcp filter-port=80,443

# DNS only
/tool sniffer set filter-protocol=udp filter-port=53

# SSH and management ports
/tool sniffer set filter-protocol=tcp filter-port=22,23,8291

# Scope to a specific interface
/tool sniffer set filter-interface=ether1

# Scope to a specific subnet
/tool sniffer set filter-ip-address=192.168.1.0/24
```

### Firewall Logging Rules

```routeros
# Log HTTP/HTTPS (passthrough — does not block)
/ip firewall filter add chain=forward protocol=tcp dst-port=80,443 action=passthrough log=yes

# Log DNS queries
/ip firewall filter add chain=forward protocol=udp dst-port=53 action=passthrough log=yes

# Log SSH attempts
/ip firewall filter add chain=input protocol=tcp dst-port=22 action=passthrough log=yes

# Drop and log invalid state connections
/ip firewall filter add chain=input connection-state=invalid action=drop log=yes

# SYN flood basic protection
/ip firewall filter add chain=input protocol=tcp connection-state=new limit=25,5:packet action=accept
/ip firewall filter add chain=input protocol=tcp connection-state=new action=drop log=yes

# View firewall log
/log print where topics~"firewall"
```

### Additional Monitoring Tools

```routeros
# Real-time interface traffic monitor
/tool torch interface=ether1

# Active connection tracking
/ip firewall connection print

# Interface bandwidth stats
/interface monitor-traffic interface=ether1

# Export logs to file
/log export file=traffic-log
```

---

## 📋 OpenWRT & tcpdump Reference

```bash
# Basic capture to file
tcpdump -i eth0 -w /tmp/capture.pcap

# Capture with BPF filter (web traffic only)
tcpdump -i eth0 -w /tmp/web.pcap 'tcp port 80 or tcp port 443'

# DNS queries live
tcpdump -i eth0 -n udp port 53

# Live display, no file write, limit to 100 packets
tcpdump -i eth0 -n -c 100

# Read a saved .pcap
tcpdump -r /tmp/capture.pcap

# Filter a saved .pcap by host
tcpdump -r /tmp/capture.pcap host 10.0.1.100

# Count packets by source
tcpdump -r /tmp/capture.pcap -n | awk '{print $3}' | sort | uniq -c | sort -rn

# Stream live to Wireshark on your PC
ssh root@192.168.8.1 "tcpdump -i br-lan -U -s0 -w -" | wireshark -k -i -
```

---

## ⚡ Minimum Starter Filter Sets

Ready-to-paste filters for common scenarios.

| Scenario | Filter |
|----------|--------|
| **General troubleshooting** | `tcp \|\| udp.port == 53` |
| **Threat hunting** | `tcp.flags.syn == 1 \|\| tcp.flags.reset == 1 \|\| icmp \|\| dns` |
| **Isolate one device** | `ip.addr == 192.168.1.XX` |
| **Reduce noise** | `!(arp \|\| icmp \|\| stp \|\| bootp \|\| mdns \|\| ssdp \|\| nbns)` |
| **Outbound internet only** | `ip.src == 192.168.1.0/24 && !(ip.dst == 192.168.0.0/16 \|\| ip.dst == 10.0.0.0/8 \|\| ip.dst == 172.16.0.0/12)` |
| **WPA handshake capture** | `eapol` |
| **BLE security assessment** | `btle \|\| smp \|\| btatt` |

---

## ⚠️ Security & Legal Disclaimer

### 🔴 CRITICAL: Authorized Use Only

```
⚠️ IMPORTANT: AUTHORIZED USE ONLY ⚠️

This documentation is provided for:

✅ AUTHORIZED USES:
   • Network troubleshooting and diagnostics on networks you own/administer
   • Authorized security assessments with written permission
   • Educational use in isolated lab environments
   • Wireless analysis on networks you own or have explicit authorization
   • Security research within legal and ethical boundaries
   • CTF competitions and authorized practice environments
   • Professional penetration testing with signed scope agreements

🚫 STRICTLY PROHIBITED:
   • Capturing or analyzing traffic on networks you do not own or manage
   • Intercepting communications without authorization
   • Cracking WiFi passwords on unauthorized networks
   • Using BLE/Zigbee capture against devices you do not own
   • Any activity violating the Computer Fraud and Abuse Act (CFAA)
   • Any activity violating the Wiretap Act (18 U.S.C. § 2511)
```

### Wireless & Packet Capture Legal Requirements

```
Federal Laws (United States):
• Computer Fraud and Abuse Act (CFAA) - 18 U.S.C. § 1030
  - Unauthorized access to protected computers/networks
  - Penalties: Up to 10 years imprisonment and fines

• Wiretap Act - 18 U.S.C. § 2511
  - Intercepting electronic communications
  - Penalties: Up to 5 years imprisonment and fines

• Electronic Communications Privacy Act (ECPA)
  - Protecting electronic communications
  - Civil and criminal penalties apply

State Laws:
• Most states have additional computer crime statutes
• Unauthorized network access is often classified as a felony
• Civil liability applies in addition to criminal charges
```

### Risk Mitigation

```
✅ Mitigation Strategies:

Authorization:
• Always obtain written authorization before any capture
• Document scope, interfaces, and time windows
• Maintain authorization records for all client work

Technical Controls:
• Capture in isolated lab environments whenever possible
• Apply capture filters at source to minimize unintended data collection
• Delete captures containing sensitive data when no longer needed

Professional Standards:
• Follow ethical guidelines and responsible disclosure practices
• Maintain professional liability insurance for client work
• Document all activities thoroughly
• Consult legal counsel when uncertain about scope
```

---

## 🤝 Contributing

We welcome contributions from security professionals, researchers, and practitioners.

#### Contribution Guidelines

**To Submit Additions or Corrections:**
1. Fork the repository
2. Add or update filters with tested examples
3. Include a brief description of use case and context
4. Submit a pull request with a clear description

**Documentation Standards:**

```markdown
# [Filter Category]

## Overview
Brief description of what these filters are for

## Filters
Tested filter syntax with inline comments

## Use Cases
Authorized scenarios where these filters apply

## Notes
Tips, caveats, hardware requirements
```

**All Contributions Must Include:**
- ✅ Tested filter syntax
- ✅ Clear use case description
- ✅ Authorization requirements noted where applicable
- ✅ Hardware or plugin dependencies documented

---

## 📚 Resources

### Wireshark Documentation

- **Wireshark Display Filter Reference**: https://www.wireshark.org/docs/dfref/
- **Wireshark Capture Filters (BPF)**: https://wiki.wireshark.org/CaptureFilters
- **Wireshark Wiki**: https://wiki.wireshark.org/
- **nRF Sniffer for Wireshark**: https://infocenter.nordicsemi.com/topic/ug_sniffer_ble/

### Protocol & Tool References

- **Ubertooth One**: https://github.com/greatscottgadgets/ubertooth
- **KillerBee (Zigbee)**: https://github.com/riverloopsec/killerbee
- **MikroTik Sniffer Docs**: https://help.mikrotik.com/docs/display/ROS/Packet+Sniffer

### Legal Resources

- **US-CERT**: https://www.cisa.gov/
- **CFAA Guidance**: https://www.justice.gov/criminal-ccips/ccmanual
- **EFF Legal Guide**: https://www.eff.org/issues/coders/reverse-engineering-faq

### Internal Links

- [🏠 Main Repository](../README.md)
- [🎯 START HERE Guide](../START_HERE.md)
- [💻 Cybersecurity Master Guide](../ultimate_cybersecurity_master_guide.md)
- [🔍 OSINT Resources](../OSINT/README.md)
- [✅ Security Checklists](../Checklists/README.md)

---

## 📊 Document Info

```
📁 Document:     wireshark-filters.md
📖 Category:     Network Security / Packet Analysis
🔄 Last Updated: April 2026
👥 Maintained by: Pacific Northwest Computers (PNWC)
📝 Status:       Active
```

---

## 🎓 Best Practices Summary

### Always Remember

**Legal Requirements:**
- ✅ Written authorization before any capture on non-owned networks
- ✅ Compliance with CFAA, Wiretap Act, and local laws
- ✅ Responsible handling and deletion of captured data
- ✅ Proper scope documentation for client engagements

**Technical Safety:**
- ✅ Apply capture filters at source to reduce data collection footprint
- ✅ Use isolated lab or VM environments for analysis
- ✅ Delete pcap files containing sensitive data after analysis
- ✅ Never store captures containing credentials or PII unnecessarily

**Professional Ethics:**
- ✅ Act with integrity and transparency
- ✅ Protect confidential information discovered during captures
- ✅ Report vulnerabilities responsibly
- ✅ Follow industry standards and responsible disclosure

---

<div align="center">

**🦈 Use Wireshark Responsibly: Always Obtain Authorization Before Capturing Traffic**

*Legal, ethical, and authorized use only.*

**Repository**: [ULTIMATE CYBERSECURITY MASTER GUIDE](https://github.com/Pnwcomputers/ULTIMATE-CYBERSECURITY-MASTER-GUIDE)

**Maintained by**: [Pacific Northwest Computers](https://github.com/Pnwcomputers)

---

⚠️ **WARNING: Unauthorized packet capture is illegal and prosecutable** ⚠️

⚠️ **Wiretap Act violations carry up to 5 years imprisonment** ⚠️

⚠️ **Always obtain written authorization before capturing on any network you do not own** ⚠️

⭐ **Star this repo if you find it useful!** ⭐

</div>
