# 🔒 VPN Security Guide

## 🎯 Purpose
Operational guide for VPN selection, configuration, and use by security professionals — focused on Mullvad VPN as the top recommendation, with coverage of kill switch setup, DNS leak prevention, multi-hop, split tunneling, browser hardening, and VPN+Tor stacking strategies.

## ⚙️ Function
Organized by use case: Mullvad app configuration and CLI commands, manual UFW-based kill switch, DNS leak prevention (systemd-resolved), multi-hop routing, Linux policy-based split tunneling, browser hardening (Firefox about:config, WebRTC), VPN→Tor and Tor→VPN stacking, and pre/during/post session operational checklists. Includes a VPN comparison table covering logging, jurisdiction, and open-source status.

## 🏆 Goal
Establish a verifiable, leak-free VPN posture for security operations — covering both routine OSINT work and penetration test recon where exit IP, DNS, and WebRTC leaks would compromise operational security.

## 📋 When to Use
- All OSINT investigations and penetration test recon (never from your home IP)
- Any work on untrusted networks (client sites, hotels, conferences)
- Hiding Tor usage from your ISP (VPN→Tor stack)
- Bypassing Tor blocks on specific sites (Tor→VPN stack)
- Incident response IOC lookups that must not tip off threat actors

This guide covers VPN selection, configuration, operational usage, and integration with other privacy tools for both daily use and sensitive security work.

> **For OSINT and penetration testing operations: ALWAYS use a third-party network. Never conduct security work from your home IP or client networks.**

---

## Table of Contents

1. [Why Mullvad](#1-why-mullvad)
2. [Mullvad Setup & Configuration](#2-mullvad-setup--configuration)
3. [Kill Switch & Leak Prevention](#3-kill-switch--leak-prevention)
4. [DNS Security](#4-dns-security)
5. [Multi-Hop Connections](#5-multi-hop-connections)
6. [Split Tunneling](#6-split-tunneling)
7. [Mullvad on Linux (CLI)](#7-mullvad-on-linux-cli)
8. [Browser Hardening](#8-browser-hardening)
9. [VPN + Tor — Stacking Strategies](#9-vpn--tor--stacking-strategies)
10. [VPN for Security Operations](#10-vpn-for-security-operations)
11. [Leak Testing & Verification](#11-leak-testing--verification)
12. [Operational Checklist](#12-operational-checklist)
13. [VPN Comparison — Quick Reference](#13-vpn-comparison--quick-reference)

---

## 1. Why Mullvad

**Mullvad** is the top recommendation for privacy-conscious users and security professionals.

| Feature                    | Mullvad                                              |
| -------------------------- | ---------------------------------------------------- |
| Logging policy             | No logs — independently audited                      |
| Account system             | Random 16-digit number — no email, no name           |
| Payment                    | Cash, Monero, Bitcoin, card (cash preferred)         |
| Infrastructure             | Owned servers — not rented (reduces third-party risk)|
| Client code                | Open source — auditable                              |
| Protocol support           | WireGuard, OpenVPN, DAITA                            |
| Multi-hop                  | ✅ Built-in                                          |
| Kill switch                | ✅ Built-in ("Always require VPN")                   |
| Split tunneling            | ✅ Built-in                                          |
| DAITA (anti-fingerprinting)| ✅ Unique to Mullvad — pads traffic patterns          |
| Port forwarding            | ❌ Removed in 2023 (improves anonymity)              |
| Price                      | €5/month flat — no upsells, no tiers                 |
| Audit history              | Cure53, Assured AB — public reports available        |

---

## 2. Mullvad Setup & Configuration

### 2.1 Download

- **Official only**: https://mullvad.net/download
- Verify the signature before installing on sensitive systems

### 2.2 Recommended App Settings

~~~
Settings → VPN Settings:
  ✅ Always require VPN (kill switch)
  ✅ Auto-connect on launch
  ✅ Local network sharing → OFF (unless needed for LAN access)
  ✅ Enable IPv6 → OFF (unless you've verified no leaks)

Settings → Tunnel Protocol:
  → WireGuard (preferred — faster, modern, smaller attack surface)
  → OpenVPN (fallback for restricted networks)

Settings → WireGuard Settings:
  ✅ Multihop → configure entry/exit country pair
  ✅ DAITA → ON (obfuscates traffic shape/timing patterns)
  ✅ Quantum-resistant tunnels → ON (if available in your version)

Settings → DNS:
  → Use Mullvad's DNS (blocks ads + malware by category)
  → Custom: 10.64.0.1 (Mullvad's in-tunnel DNS)
~~~

### 2.3 Server Selection

~~~
# Best practices for server selection:
- Choose exit country appropriate to your activity
- Avoid 5/9/14-Eyes countries for sensitive work
  (US, UK, CA, AU, NZ, DE, FR, SE, NO, DK, NL, BE, IT, ES, JP)
- Use a country with strong privacy laws:
  Switzerland, Iceland, Panama, Romania, Malaysia
- For OSINT: pick an exit matching the target's region
  (avoid looking like a foreign probe)
~~~

---

## 3. Kill Switch & Leak Prevention

The kill switch blocks all traffic if the VPN tunnel drops — prevents accidental deanonymization.

### 3.1 Mullvad App Kill Switch

~~~
Settings → VPN Settings → Always require VPN → ON
~~~

This uses the OS firewall to block non-VPN traffic at the system level.

### 3.2 Linux — UFW-Based Kill Switch (Manual / Backup)

Use this as a belt-and-suspenders layer or if running Mullvad CLI without the GUI:

~~~bash
# Flush existing rules
sudo ufw reset
sudo ufw default deny outgoing
sudo ufw default deny incoming

# Allow VPN tunnel only
# WireGuard (UDP 51820)
sudo ufw allow out on wg0
sudo ufw allow out to any port 51820 proto udp

# OpenVPN (UDP 1194 or TCP 443)
# sudo ufw allow out to any port 1194 proto udp
# sudo ufw allow out to any port 443 proto tcp

# Allow local loopback
sudo ufw allow out on lo
sudo ufw allow in on lo

# Allow LAN (optional — remove for strict isolation)
# sudo ufw allow out to 192.168.0.0/16
# sudo ufw allow in from 192.168.0.0/16

sudo ufw enable
sudo ufw status verbose
~~~

### 3.3 Verify Kill Switch is Working

~~~bash
# 1. Connect to Mullvad
# 2. Kill the VPN tunnel manually (not disconnect — kill the process)
sudo pkill mullvad-daemon   # or disconnect interface

# 3. Try to reach the internet — should fail
curl https://api.ipify.org   # should time out or refuse

# 4. Reconnect and verify IP changed
curl https://api.ipify.org
~~~

---

## 4. DNS Security

Unencrypted or misdirected DNS is one of the most common VPN leak vectors.

### 4.1 Mullvad DNS Options

~~~
Settings → DNS → Select content blockers:
  ✅ Block ads
  ✅ Block trackers
  ✅ Block malware
  ✅ Block gambling (optional)
  ✅ Block social media (optional for high-security ops)

Custom DNS (in-tunnel): 10.64.0.1
~~~

### 4.2 DNS Leak Prevention on Linux

~~~bash
# Check current DNS resolver
resolvectl status
cat /etc/resolv.conf

# Lock DNS to VPN interface (systemd-resolved)
sudo resolvectl dns wg0 10.64.0.1
sudo resolvectl domain wg0 "~."    # route all DNS queries to this interface

# Verify
resolvectl status wg0
~~~

### 4.3 Encrypted DNS (When VPN is Off)

| Provider         | Address                        | Protocol          |
| ---------------- | ------------------------------ | ----------------- |
| Mullvad          | `dns.mullvad.net` (`194.242.2.2`) | DoH, DoT      |
| Cloudflare       | `1.1.1.1` / `1.0.0.1`         | DoH, DoT          |
| NextDNS          | Custom per account             | DoH, DoT, DoQ     |
| Quad9            | `9.9.9.9`                      | DoH, DoT (blocks malware)|

~~~bash
# Test DNS over HTTPS manually
curl -H "accept: application/dns-json" \
  "https://cloudflare-dns.com/dns-query?name=example.com&type=A"
~~~

---

## 5. Multi-Hop Connections

Multi-hop routes your traffic through two servers in different countries — the entry server sees your IP, the exit server sees your traffic destination, and neither knows both.

~~~
[You] → [Entry Server (Country A)] → [Exit Server (Country B)] → [Destination]
         (knows your real IP)         (sees the traffic)
~~~

### 5.1 Enable in Mullvad App

~~~
Settings → WireGuard Settings → Multihop → Enable
Select:
  Entry location: your region or a trusted country
  Exit location: target region or privacy-friendly country
~~~

### 5.2 When to Use Multi-Hop

~~~
✅ High-sensitivity OSINT investigations
✅ Penetration test recon (hides your true ISP/region from exit logs)
✅ Accessing resources in countries with active surveillance
✅ Any operation where single-server compromise is a concern

❌ Not needed for routine privacy browsing (adds latency)
❌ Avoid for latency-sensitive work (VoIP, real-time tools)
~~~

---

## 6. Split Tunneling

Allows specific apps or IP ranges to bypass the VPN tunnel — useful when a work tool requires your real IP, or you need LAN access.

### 6.1 Mullvad App Split Tunneling

~~~
Settings → Split Tunneling → Enable
Add applications to exclude:
  - Remote support tools that need your real IP
  - Local network management tools
  - Any app that actively blocks VPN connections
~~~

### 6.2 Linux — Policy-Based Routing (Manual)

~~~bash
# Route specific traffic outside VPN (example: exclude 192.168.1.0/24 from tunnel)
sudo ip rule add to 192.168.1.0/24 lookup main priority 100

# Route specific app outside VPN using cgroups (advanced)
sudo cgcreate -g net_cls:/novpn
sudo cgset -r net_cls.classid=0x100001 novpn
sudo iptables -t mangle -A OUTPUT -m cgroup --cgroup 0x100001 -j MARK --set-mark 1
sudo ip rule add fwmark 1 lookup main

# Run an app outside VPN
sudo cgexec -g net_cls:/novpn curl https://api.ipify.org
~~~

> **Security note**: Split tunneling creates a dual-path network state. Any app excluded from the tunnel can see and potentially expose your real IP. Use minimally.

---

## 7. Mullvad on Linux (CLI)

### 7.1 Install Mullvad CLI

~~~bash
# Add Mullvad repo (Debian/Ubuntu)
curl -fsSLo /usr/share/keyrings/mullvad-keyring.asc \
  https://repository.mullvad.net/deb/mullvad-keyring.asc

echo "deb [signed-by=/usr/share/keyrings/mullvad-keyring.asc arch=$( dpkg --print-architecture )] \
  https://repository.mullvad.net/deb/stable $(lsb_release -cs) main" | \
  sudo tee /etc/apt/sources.list.d/mullvad.list

sudo apt update && sudo apt install -y mullvad-vpn
~~~

### 7.2 CLI Commands

~~~bash
# Account
mullvad account login <ACCOUNT_NUMBER>
mullvad account get

# Connection
mullvad connect
mullvad disconnect
mullvad reconnect
mullvad status

# Server selection
mullvad relay list
mullvad relay set location us        # US exit
mullvad relay set location se-got    # Gothenburg, Sweden
mullvad relay set tunnel-protocol wireguard

# Kill switch
mullvad lockdown-mode set on         # block traffic when disconnected
mullvad always-on-vpn set on         # auto-reconnect

# Multi-hop
mullvad relay set multihop enable
mullvad relay set location us        # exit
mullvad bridge set location se       # entry (bridge = entry for multihop)

# DNS
mullvad dns set default              # use Mullvad DNS
mullvad dns set custom 10.64.0.1     # manual in-tunnel DNS

# Auto-connect on boot
sudo systemctl enable mullvad-daemon
mullvad auto-connect set on
~~~

---

## 8. Browser Hardening

A VPN protects your IP — browser fingerprinting and WebRTC can still expose you.

### 8.1 Recommended Browsers

| Browser      | Privacy Level | Notes                                                  |
| ------------ | ------------- | ------------------------------------------------------ |
| **Firefox**  | ⭐⭐⭐⭐       | Best extension support, highly configurable             |
| **Brave**    | ⭐⭐⭐⭐       | Chromium-based, built-in shields, good for general use |
| **Tor Browser** | ⭐⭐⭐⭐⭐  | Strongest anonymity, use for sensitive OSINT           |
| Chrome       | ⭐             | Avoid — heavy Google telemetry                         |
| Edge         | ⭐             | Avoid — Microsoft telemetry                            |

### 8.2 Essential Extensions

| Extension            | Purpose                                          |
| -------------------- | ------------------------------------------------ |
| **uBlock Origin**    | Ad/tracker blocking — use "hard mode" for ops    |
| **Privacy Badger**   | Adaptive tracker blocking (EFF)                  |
| **Canvas Blocker**   | Blocks canvas fingerprinting                     |
| **LocalCDN**         | Serves CDN resources locally (reduces tracking)  |

> Do NOT use HTTPS Everywhere — it's deprecated. Modern browsers handle HTTPS-first natively.

### 8.3 Firefox about:config Hardening

~~~
# Open: about:config in Firefox address bar

# WebRTC leak prevention (most important with VPN)
media.peerconnection.enabled                    → false

# Fingerprinting resistance
privacy.resistFingerprinting                    → true
privacy.fingerprintingProtection                → true

# Tracking protection
privacy.trackingprotection.enabled              → true
privacy.trackingprotection.socialtracking.enabled → true

# DNS
network.trr.mode                                → 3   (DoH only)
network.trr.uri                                 → https://dns.quad9.net/dns-query

# Telemetry — all off
toolkit.telemetry.enabled                       → false
datareporting.healthreport.uploadEnabled        → false
browser.crashReports.unsubmittedCheck.enabled   → false

# Geolocation
geo.enabled                                     → false

# Safe browsing (sends URLs to Google — disable for air-gapped ops)
browser.safebrowsing.malware.enabled            → false  # tradeoff — assess your risk
browser.safebrowsing.phishing.enabled           → false
~~~

### 8.4 Disable WebRTC (Chrome/Brave)

~~~
# Brave: brave://flags/#disable-webrtc-encryption  (not recommended — use extension)
# Better: Settings → Privacy → WebRTC IP handling → Disable non-proxied UDP
# Or install: WebRTC Leak Shield or WebRTC Control extension
~~~

---

## 9. VPN + Tor — Stacking Strategies

### 9.1 VPN → Tor (Recommended)

~~~
[You] → [VPN] → [Tor Entry] → [Tor Middle] → [Tor Exit] → [Destination]
~~~

- Your ISP sees encrypted VPN traffic — not that you're using Tor
- Tor entry guard sees VPN exit IP — not your real IP
- **Best for**: Hiding Tor usage from ISP, countries that block Tor

~~~bash
# Setup: Connect Mullvad first, then launch Tor Browser
# Tor Browser automatically uses the VPN tunnel
mullvad connect && tor-browser
~~~

### 9.2 Tor → VPN (Less Common)

~~~
[You] → [Tor] → [VPN] → [Destination]
~~~

- Destination sees VPN IP — not Tor exit
- VPN provider sees Tor exit IP — not your real IP
- **Best for**: Bypassing sites that block Tor exit nodes
- **Requires**: VPN that accepts connections from Tor (Mullvad supports this)

### 9.3 When NOT to Stack

~~~
❌ Routine browsing — unnecessary complexity, performance hit
❌ When Tor's anonymity model is sufficient
❌ When the VPN provider is untrusted (Tor → bad VPN = worse than Tor alone)
✅ High-risk investigations where ISP-level Tor detection is a concern
✅ Countries with active Tor blocking
~~~

---

## 10. VPN for Security Operations

### 10.1 OSINT & Reconnaissance

~~~
RULE: Never conduct OSINT from your home IP or client networks.

Preferred stack for OSINT:
  [OSINT VM] → [Mullvad VPN] → [Internet]

Enhanced stack for sensitive targets:
  [OSINT VM] → [Mullvad Multihop] → [Tor Browser] → [Internet]

Server selection for OSINT:
  - Exit in the target's country/region (reduces "foreign probe" flags)
  - Rotate exit servers between investigation sessions
  - Use a fresh "New Identity" in Tor Browser per target
~~~

### 10.2 Penetration Testing & Red Team

~~~
RULE: ALWAYS document your VPN IP in your scope agreement and change logs.

Pre-engagement:
  [ ] Confirm VPN IP is in scope or pre-authorized
  [ ] Log VPN server and IP used at start of each session
  [ ] Rotate server if you need a different source IP

During engagement:
  [ ] Mullvad connected before any recon tooling starts
  [ ] Kill switch confirmed ON
  [ ] Verify exit IP before starting (curl api.ipify.org)
  [ ] Log timestamped commands with exit IP for chain of custody

Tools that respect proxy settings:
  proxychains4 nmap -sT -Pn <target>
  proxychains4 theHarvester -d <domain> -b all
  proxychains4 nikto -h <target>
~~~

### 10.3 Client Network Considerations

~~~
✅ Use Mullvad on any untrusted or client-provided network
✅ Use obfuscation if on a corporate network with DPI
✅ Enable multi-hop if client network has logging
✅ Separate browser profiles per client engagement
✅ Use VMs for client work — snapshot before and after
❌ Never conduct personal or other-client work on a client's network
❌ Never trust hotel/conference/coffee shop Wi-Fi without VPN
~~~

### 10.4 Incident Response Work

~~~
- Connect Mullvad before accessing any external threat intel resources
- Route all IOC lookups (VirusTotal, Shodan, Censys) through VPN
  (prevents tipping off threat actors that their IOCs are being investigated)
- Use different exit countries for different lookups to reduce correlation
- Do NOT connect to C2 infrastructure directly — always through VPN + VM isolation
~~~

---

## 11. Leak Testing & Verification

Run these checks at the start of every sensitive session.

### 11.1 Quick Session Verification

~~~bash
# 1. Confirm VPN is connected
mullvad status

# 2. Verify exit IP (should NOT be your real IP)
curl https://api.ipify.org

# 3. Confirm Mullvad exit IP matches expected server
curl https://am.i.mullvad.net/json | python3 -m json.tool

# 4. Check DNS is routing through tunnel (dns.mullvad.net is Mullvad's public DoH endpoint)
curl -H "accept: application/dns-json" \
  "https://dns.mullvad.net/dns-query?name=whoami.akamai.net&type=A"
~~~

### 11.2 Leak Test Sites

| Test                | URL                              | Checks                         |
| ------------------- | -------------------------------- | ------------------------------ |
| Mullvad check       | https://mullvad.net/check        | IP, DNS, WebRTC, IPv6 all-in-1 |
| DNS leak test       | https://dnsleaktest.com          | DNS resolver origin            |
| IP leak test        | https://ipleak.net               | IP, DNS, WebRTC, IPv6          |
| BrowserLeaks        | https://browserleaks.com         | Full fingerprint suite         |
| WebRTC leak         | https://browserleaks.com/webrtc  | WebRTC IP exposure             |
| IPv6 leak           | https://ipv6leak.com             | IPv6 exposure check            |

### 11.3 CLI Leak Tests

~~~bash
# IPv6 leak check (should fail or return VPN IPv6 if enabled)
curl -6 https://api64.ipify.org 2>/dev/null || echo "No IPv6 (good if IPv6 disabled)"

# DNS leak — verify resolver is Mullvad's
dig +short myip.opendns.com @resolver1.opendns.com

# WebRTC — no CLI equivalent, use browser test at browserleaks.com/webrtc

# Full check via Mullvad API
curl -s https://am.i.mullvad.net/json | python3 -c "
import json, sys
d = json.load(sys.stdin)
print(f'IP:          {d[\"ip\"]}')
print(f'Mullvad:     {d[\"mullvad_exit_ip\"]}')
print(f'Country:     {d[\"country\"]}')
print(f'City:        {d[\"city\"]}')
print(f'ISP:         {d[\"organization\"]}')
"
~~~

---

## 12. Operational Checklist

### Pre-Session

~~~
[ ] Mullvad connected and verified (mullvad status)
[ ] Exit IP confirmed — NOT your home IP (curl api.ipify.org)
[ ] Kill switch ON (Settings → Always require VPN)
[ ] DNS routing through Mullvad (dnsleaktest.com)
[ ] WebRTC disabled in browser
[ ] IPv6 confirmed not leaking
[ ] Correct browser profile loaded (not personal profile)
[ ] Correct VM snapshot loaded (if applicable)
~~~

### During Session

~~~
[ ] Do not log into personal accounts
[ ] Do not mix personal and operational browsing
[ ] Rotate exit server between investigation targets
[ ] Log your VPN exit IP and timestamp for chain of custody (pen tests)
[ ] Monitor mullvad status if connection is unstable
~~~

### Post-Session

~~~
[ ] Disconnect Mullvad (or leave connected — do not go unprotected)
[ ] Clear browser history/cache/cookies if on shared system
[ ] Export/save evidence and notes before VM rollback
[ ] Snapshot VM if state should be preserved
[ ] Rotate to a different Mullvad server for next session
~~~

---

## 13. VPN Comparison — Quick Reference

| Provider     | Logs    | Jurisdiction  | Open Source | Price/mo | Notes                               |
| ------------ | ------- | ------------- | ----------- | -------- | ----------------------------------- |
| **Mullvad**  | No      | Sweden        | ✅ Full      | €5 flat  | **Top pick** — anonymous accounts   |
| ProtonVPN    | No      | Switzerland   | ✅ Full      | $4–10    | Good alternative, free tier exists  |
| IVPN         | No      | Gibraltar     | ✅ Full      | $6–10    | Privacy-focused, anonymous accounts |
| ExpressVPN   | Claimed | BVI           | ❌ Partial  | $8–13    | Acquired by Kape — trust concerns   |
| NordVPN      | Claimed | Panama        | ❌          | $4–12    | Past breach — use with caution      |
| PIA          | Claimed | US (5-Eyes)   | ✅ Partial  | $2–7     | US jurisdiction — avoid for ops     |
| Any "free"   | Yes     | Varies        | ❌          | $0       | Avoid — you are the product         |

> **Jurisdiction note**: Sweden is technically 14-Eyes, but Mullvad's no-log policy has been validated under legal pressure — Swedish authorities have seized Mullvad servers and obtained nothing usable. Architecture matters more than jurisdiction.

---

## Additional Resources

- **Mullvad Documentation**: https://mullvad.net/help
- **Mullvad Privacy Guides**: https://mullvad.net/blog
- **Privacy Guides (community)**: https://www.privacyguides.org
- **PrivacyTests.org**: Browser privacy comparison matrix
- **Audit reports**: https://mullvad.net/en/blog/tag/audits

---

## Related Files
- [TOR.md](TOR.md) — Tor Browser and daemon guide: VPN→Tor stacking, proxychains, .onion services
- [virtualmachines.md](virtualmachines.md) — Privacy VMs (Tails, Whonix, Qubes) that integrate with or replace VPN-based anonymity
- [../OSINT/](../OSINT/) — OSINT workflows requiring Mullvad or Tor→VPN for anonymity

*Last Updated: 2026-06-08*
*Maintained by: Pacific Northwest Computers (PNWC)*
