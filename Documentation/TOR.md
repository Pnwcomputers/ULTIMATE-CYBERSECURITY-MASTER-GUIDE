# 🧅 Tor: Connection & Browser Guide

## 🎯 Purpose
Reference guide for deploying and operating Tor for anonymous network access - covering both Tor Browser (GUI) and the Tor daemon (system-level SOCKS5 proxy via port 9050) for OSINT investigations, anonymous reconnaissance, and privacy-sensitive incident response work.

## ⚙️ Function
Organized by deployment model: Tor Browser installation and hardening (security levels, about:config settings), Tor daemon setup and torrc configuration, proxychains integration for proxying any CLI tool, bridges and censorship circumvention (obfs4, Snowflake, meek-azure, WebTunnel), .onion service access and hosting, connection verification, and OPSEC checklists.

## 🏆 Goal
Establish reliable, anonymous network connectivity that prevents IP/DNS leaks, survives adversarial ISP environments, and provides documented OPSEC procedures for security professionals conducting authorized investigations.

## 📋 When to Use
- OSINT investigations requiring IP anonymity (run from a dedicated VM)
- Accessing .onion services or SecureDrop instances
- Proxying CLI security tools (theHarvester, amass, sqlmap) through Tor via proxychains
- Circumventing Tor censorship with bridges
- Combining with Mullvad VPN for VPN→Tor stacking

This document covers both the **Tor daemon** (system-level, CLI) and **Tor Browser** (GUI) for use in OSINT investigations, anonymous reconnaissance, and privacy-sensitive incident response work.

> **OPSEC Note**: Tor provides *anonymity*, not complete security. Combine with disciplined operational behavior. For OSINT work, always operate from a dedicated VM - never your daily-driver OS.

---

## Table of Contents

1. [What is Tor?](#1-what-is-tor)
2. [Tor Browser - Installation & Setup](#2-tor-browser--installation--setup)
3. [Tor Daemon (CLI) - System-Level Connection](#3-tor-daemon-cli--system-level-connection)
4. [Proxychains + Tor](#4-proxychains--tor)
5. [Bridges & Censorship Circumvention](#5-bridges--censorship-circumvention)
6. [.onion Services](#6-onion-services)
7. [Verifying Your Connection](#7-verifying-your-connection)
8. [Tor Browser Security Settings](#8-tor-browser-security-settings)
9. [Troubleshooting](#9-troubleshooting)
10. [OPSEC Checklist](#10-opsec-checklist)
11. [Quick Reference - Key URLs](#11-quick-reference--key-urls)

---

## 1. What is Tor?

**Tor (The Onion Router)** routes traffic through a volunteer-operated relay network using layered encryption. Each relay decrypts one layer and forwards to the next - no single relay knows both origin and destination.

~~~
[You] → [Guard/Entry Relay] → [Middle Relay] → [Exit Relay] → [Destination]
          (knows your IP)                          (knows destination)
~~~

**Two deployment models covered here:**

| Mode             | Use Case                                                      |
| ---------------- | ------------------------------------------------------------- |
| **Tor Browser**  | Anonymous web browsing, .onion sites, one-click GUI setup     |
| **Tor Daemon**   | System-wide or per-tool proxying via SOCKS5 (127.0.0.1:9050)  |

---

## 2. Tor Browser - Installation & Setup

### 2.1 Install on Linux (Debian/Ubuntu)

**Method 1: Official tarball (recommended - always current)**

~~~bash
# Download the LATEST version from: https://www.torproject.org/download/
# Replace VERSION with the current release (e.g., 14.5 - check the site)
VERSION="14.5"
wget "https://www.torproject.org/dist/torbrowser/${VERSION}/tor-browser-linux-x86_64-${VERSION}.tar.xz"

# Verify signature (recommended)
gpg --auto-key-locate nodefault,wkd --locate-keys torbrowser@torproject.org
gpg --verify "tor-browser-linux-x86_64-${VERSION}.tar.xz.asc"

# Extract and launch
tar -xvJf "tor-browser-linux-x86_64-${VERSION}.tar.xz"
cd tor-browser/
./start-tor-browser.desktop
~~~

**Method 2: apt (Tor Project repo)**

~~~bash
# Add Tor Project repo
sudo apt install -y apt-transport-https
echo "deb [signed-by=/usr/share/keyrings/tor-archive-keyring.gpg] https://deb.torproject.org/torproject.org $(lsb_release -cs) main" | \
  sudo tee /etc/apt/sources.list.d/tor.list

# Add signing key
wget -qO- https://deb.torproject.org/torproject.org/A3C4F0F979CAA22CDBA8F512EE8CBC9E886DDD89.asc | \
  gpg --dearmor | sudo tee /usr/share/keyrings/tor-archive-keyring.gpg > /dev/null

sudo apt update && sudo apt install -y tor torbrowser-launcher deb.torproject.org-keyring
torbrowser-launcher
~~~

### 2.2 Install on Windows / Mac

1. Go to **https://www.torproject.org** - official site only
2. Download for your OS
3. Windows: run `.exe` installer | Mac: drag `.dmg` to Applications
4. Launch Tor Browser

### 2.3 Install on Android

- **Google Play**: Search "Tor Browser" by The Tor Project
- **F-Droid**: Preferred for privacy - no Google dependency

> **iOS**: No official Tor Browser. Use **Onion Browser** (less hardened).

### 2.4 First Launch & Connection

~~~
Launch Tor Browser
  └─> "Connect"               ← direct connection, most users
  └─> "Configure Connection"  ← if Tor is blocked in your country
        └─> "Tor is censored in my country"
              └─> Select bridge type (obfs4 recommended)
              └─> Connect
~~~

**Connection time**: 10–30 seconds on first launch.

---

## 3. Tor Daemon (CLI) - System-Level Connection

The Tor daemon runs a **SOCKS5 proxy on 127.0.0.1:9050** that any tool can route through.

### 3.1 Install

~~~bash
sudo apt install -y tor
~~~

### 3.2 Start / Stop / Status

~~~bash
sudo systemctl start tor
sudo systemctl stop tor
sudo systemctl enable tor       # start on boot
sudo systemctl status tor
sudo journalctl -u tor -f       # follow logs
~~~

### 3.3 torrc - Configuration File

~~~bash
sudo nano /etc/tor/torrc
~~~

**Useful torrc options:**

~~~
# SOCKS5 proxy (default - usually already set)
SocksPort 9050

# Control port (needed for circuit management tools)
ControlPort 9051
HashedControlPassword <hash>   # generate with: tor --hash-password yourpassword

# DNS resolution through Tor
DNSPort 5353
AutomapHostsOnResolve 1

# Logging
Log notice file /var/log/tor/notices.log

# Exit node country restriction (use sparingly - reduces anonymity)
# ExitNodes {us},{gb}
# StrictNodes 1

# Exclude specific countries
# ExcludeExitNodes {cn},{ru}
~~~

**Generate a hashed control password:**

~~~bash
tor --hash-password "yourpassword"
# Copy output into torrc HashedControlPassword line
sudo systemctl restart tor
~~~

### 3.4 Use Tor SOCKS5 with curl / wget

~~~bash
# curl through Tor
curl --socks5-hostname 127.0.0.1:9050 https://check.torproject.org/api/ip

# wget through Tor
wget -e "https_proxy=socks5://127.0.0.1:9050" https://example.com

# Test your exit IP
curl --socks5-hostname 127.0.0.1:9050 https://api.ipify.org
~~~

### 3.5 Use Tor with Python (requests)

~~~python
import requests

proxies = {
    'http':  'socks5h://127.0.0.1:9050',
    'https': 'socks5h://127.0.0.1:9050',
}

r = requests.get('https://check.torproject.org/api/ip', proxies=proxies)
print(r.json())
~~~

> `socks5h://` - the `h` means DNS resolution happens on the Tor side (prevents DNS leaks). Always use `socks5h`, not `socks5`.

---

## 4. Proxychains + Tor

**Proxychains** forces any CLI tool through Tor's SOCKS5 proxy - useful for OSINT tools that don't natively support proxy settings.

### 4.1 Install

~~~bash
sudo apt install -y proxychains4
~~~

### 4.2 Configure

~~~bash
sudo nano /etc/proxychains4.conf
~~~

~~~
# Recommended settings
strict_chain
proxy_dns              # DNS through proxy - prevents leaks
quiet_mode

[ProxyList]
socks5  127.0.0.1  9050
~~~

### 4.3 Usage

~~~bash
# Prefix any command with proxychains4
proxychains4 curl https://api.ipify.org
proxychains4 nmap -sT -Pn target.com
proxychains4 theHarvester -d target.com -b google
proxychains4 sherlock username
proxychains4 amass enum -passive -d target.com
proxychains4 sqlmap -u "http://target.com/page?id=1"
~~~

> **Note**: `nmap` SYN scans (`-sS`) do not work through SOCKS - use TCP connect scan (`-sT`) with `-Pn` to skip ping.

### 4.4 Proxychains + Burp Suite (dual proxy chain)

~~~
# /etc/proxychains4.conf for Burp → Tor chain
strict_chain
[ProxyList]
http    127.0.0.1  8080    # Burp Suite first
socks5  127.0.0.1  9050    # then Tor
~~~

---

## 5. Bridges & Censorship Circumvention

Use bridges when Tor is blocked or when you want to hide Tor usage from your ISP.

### 5.1 Bridge Types

| Bridge Type  | Description                                      | Best For                        |
| ------------ | ------------------------------------------------ | ------------------------------- |
| `obfs4`      | Obfuscates traffic to look random                | Most use cases, ISP blocking    |
| `Snowflake`  | Routes through volunteer WebRTC proxies          | Heavy censorship (CN, IR, RU)   |
| `meek-azure` | Disguises as Microsoft Azure traffic             | Very restrictive networks       |
| `WebTunnel`  | Mimics HTTPS to a website                        | Deep packet inspection bypass   |

### 5.2 Get Bridges

~~~
# Option 1: Built into Tor Browser - Configure Connection → Get Bridges
# Option 2: Email bridges@torproject.org from Gmail/Riseup
# Option 3: https://bridges.torproject.org
~~~

### 5.3 Add Bridges to torrc (Daemon)

~~~bash
sudo nano /etc/tor/torrc
~~~

~~~
UseBridges 1
ClientTransportPlugin obfs4 exec /usr/bin/obfs4proxy
Bridge obfs4 <IP>:<PORT> <FINGERPRINT> cert=<CERT> iat-mode=0
~~~

~~~bash
sudo apt install -y obfs4proxy
sudo systemctl restart tor
~~~

---

## 6. .onion Services

**.onion** addresses are only accessible via Tor. Both client and server are anonymized.

### 6.1 Useful .onion Sites for OSINT / Security Work

| Service              | .onion Address                                                                   |
| -------------------- | -------------------------------------------------------------------------------- |
| DuckDuckGo           | `https://duckduckgogg42xjoc72x3sjasowoarfbgcmvfimaftt6twagswzczad.onion`        |
| Tor Project          | `http://2gzyxa5ihm7nsggfxnu52rck2vv4rvmdlkiu3zzui5du4xyclen53wid.onion`         |
| ProtonMail           | `https://protonmailrmez3lotccipshtkleegetolb73fuirgj7r4o4vfu7ozyd.onion`        |
| Facebook             | `https://www.facebookwkhpilnemxj7asaniu7vnjjbiltxjqhye3mhbshg7kx5tfyd.onion`  |
| SecureDrop (Freedom) | `http://sdolvtfhatvsysc6l34d65ymdwxcujausv7k5jk4cy5ttzhjoi6fzvyd.onion`        |

### 6.2 Host an .onion Service (Tor Daemon)

~~~bash
sudo nano /etc/tor/torrc
~~~

~~~
HiddenServiceDir /var/lib/tor/hidden_service/
HiddenServicePort 80 127.0.0.1:8080
~~~

~~~bash
sudo systemctl restart tor
sudo cat /var/lib/tor/hidden_service/hostname   # your .onion address
~~~

---

## 7. Verifying Your Connection

### 7.1 Tor Browser

~~~
Visit: https://check.torproject.org
Expected: "Congratulations. This browser is configured to use Tor."
~~~

### 7.2 CLI / Daemon

~~~bash
# Check exit IP (should NOT be your real IP)
curl --socks5-hostname 127.0.0.1:9050 https://api.ipify.org

# Check via Tor Project API
curl --socks5-hostname 127.0.0.1:9050 https://check.torproject.org/api/ip
# Expected: {"IsTor":true,"IP":"x.x.x.x"}

# Check for DNS leaks - a true DNS leak test resolves unique subdomains,
# so run the browser-based "Extended Test" at https://dnsleaktest.com
# For a quick CLI check that traffic (incl. DNS) exits through Tor:
curl --socks5-hostname 127.0.0.1:9050 https://am.i.mullvad.net/json
~~~

### 7.3 Verify Tor Process

~~~bash
# Confirm tor is listening
ss -tlnp | grep 9050
netstat -tlnp | grep tor

# Check tor log for "Bootstrapped 100%"
sudo journalctl -u tor | grep "Bootstrapped"
~~~

---

## 8. Tor Browser Security Settings

### 8.1 Security Levels

Access via: **Shield icon (top-right) → Change Security Settings**

| Level        | JavaScript | Fonts/Media      | Recommended For                        |
| ------------ | ---------- | ---------------- | -------------------------------------- |
| **Standard** | Enabled    | All enabled      | General browsing                       |
| **Safer**    | HTTP only  | Some restricted  | Most OSINT work - **recommended**      |
| **Safest**   | Disabled   | Heavily restricted| High-risk investigations              |

### 8.2 Key Settings & Behaviors

~~~
✅ Use DuckDuckGo (default) - not Google
✅ New Identity (broom icon) - fresh circuits + clear state
✅ New Circuit for this Site (lock icon → connection info)
✅ Maximize window - prevents screen size fingerprinting
✅ HTTPS-Only mode enabled by default

❌ Do NOT install extensions
❌ Do NOT resize window (fingerprinting risk)
❌ Do NOT log into personal accounts
❌ Do NOT open downloaded files while connected
❌ Do NOT torrent over Tor
~~~

### 8.3 about:config Hardening (Advanced)

~~~
about:config in address bar

privacy.resistFingerprinting         → true   (usually default)
network.proxy.socks_remote_dns       → true   (DNS through Tor)
javascript.enabled                   → false  (if using Safest manually)
geo.enabled                          → false
media.peerconnection.enabled         → false  (disables WebRTC - leak risk)
~~~

---

## 9. Troubleshooting

| Problem                     | Cause                              | Fix                                                                 |
| --------------------------- | ---------------------------------- | ------------------------------------------------------------------- |
| Tor won't connect           | ISP blocking / firewall            | Use bridges - obfs4 or Snowflake                                    |
| Very slow speeds            | Normal - 3 relay hops              | Use "New Circuit", avoid large downloads                            |
| CAPTCHA on every site       | Exit node reputation               | "New Identity" or "New Circuit for this Site"                       |
| Site blocks Tor             | Active Tor IP blocklist            | New circuit, or use .onion version if available                     |
| `proxychains4` DNS leaking  | Missing `proxy_dns` in config      | Add `proxy_dns` to `/etc/proxychains4.conf`                         |
| Tor daemon not starting     | Port conflict or config error      | `sudo journalctl -u tor -f` to read errors                          |
| `curl` through Tor fails    | Wrong proxy flag                   | Use `--socks5-hostname`, NOT `--socks5` (prevents DNS leak)         |
| Clock skew errors in torrc  | System time off                    | `sudo timedatectl set-ntp true`                                     |

---

## 10. OPSEC Checklist

~~~
[ ] Operating from a dedicated OSINT VM - not daily-driver OS
[ ] Tor Browser fully updated before starting
[ ] Security level set to "Safer" or "Safest" for sensitive work
[ ] DuckDuckGo used as default search - not Google
[ ] Not logged into any personal accounts
[ ] New Identity created at start of each new investigation target
[ ] Downloaded files NOT opened while Tor is active
[ ] No browser extensions installed
[ ] Window maximized (not custom-resized)
[ ] DNS verified routing through Tor (check.torproject.org)
[ ] WebRTC disabled (media.peerconnection.enabled = false)
[ ] VPN *not* stacked unless specifically required (VPN→Tor or Tor→VPN each have tradeoffs)
[ ] Physical location considered (coffee shop Tor use still ties you to that location)
~~~

---

## 11. Quick Reference - Key URLs

| Purpose                  | URL                                      |
| ------------------------ | ---------------------------------------- |
| Official download        | https://www.torproject.org               |
| Verify Tor connection    | https://check.torproject.org             |
| IP leak test             | https://ipleak.net                       |
| DNS leak test            | https://dnsleaktest.com                  |
| Get bridges              | https://bridges.torproject.org           |
| Tor Browser manual       | https://support.torproject.org         |
| Support                  | https://support.torproject.org           |
| Tor metrics / relay list | https://metrics.torproject.org           |

---

## Related Files
- [README.md](README.md) - Documentation section index: all guides and cheat sheets in this directory
- [VPN.md](VPN.md) - Mullvad VPN guide: VPN→Tor stacking, kill switch, DNS leak prevention
- [virtualmachines.md](virtualmachines.md) - Recommended OSINT VMs (Tails, Whonix, Trace Labs VM) for isolated Tor usage
- [../OSINT/](../OSINT/) - OSINT techniques that should be run from behind Tor or VPN

*Last Updated: 2026-06-08*
*Maintained by: Pacific Northwest Computers (PNWC)*
