# 🐷 Snort — Signature-Based IDS/IPS

<div align="center">

**The original open-source IDS — still relevant, but harder to install cleanly than its modern alternative**

*Part of the [ULTIMATE CYBERSECURITY MASTER GUIDE](../../README.md) · [Incident Response](../README.md) · [IDS & IPS](./README.md) section*

![Blue Team](https://img.shields.io/badge/Operations-Blue_Team-blue?style=for-the-badge)
![IDS/IPS](https://img.shields.io/badge/Framework-IDS_%2F_IPS-darkred?style=for-the-badge)
![Snort](https://img.shields.io/badge/Engine-Snort-orange?style=for-the-badge)

</div>

---

## 🎯 Purpose
Guide for deploying [Snort](https://www.snort.org/), the original open-source signature-based IDS/IPS, now maintained by Cisco. Covers every install path people actually try, honestly documents where the official packaging currently falls short, and gives the informed choice between sticking with Snort and moving to [Suricata](./suricata+zeek.md) instead.

## ⚙️ Function
Covers the four install paths (default repos, official Snort repo, from-source build, Snort 3 release package), rule configuration, running in IDS vs. IPS mode, and — because it's the honest outcome of a real attempt — when and why to pivot to Suricata instead.

## 🏆 Goal
Get a working decision, not just a working install: know which install path is worth trying first on your platform, and recognize quickly when Snort's current packaging friction means your time is better spent on Suricata.

## 📋 When to Use
- You specifically need Snort (existing rule sets, organizational standard, familiarity) rather than an open choice of engine
- `sudo apt install snort` fails or isn't available on your distro and you need the alternative paths
- You hit `gpg: no valid OpenPGP data found` adding Snort's official repository — this guide's gotcha section covers it directly
- Deciding, with full information, whether to keep pushing on Snort or switch to [Suricata](./suricata+zeek.md)

> 📝 **Note:** A real attempt at this exact install hit a broken official repository key and ultimately moved to Suricata successfully instead. That outcome is documented honestly below rather than glossed over — this guide will get you a working Snort if the paths below work for your platform, but won't pretend the path is as smooth as Suricata's currently is.

---

## 📋 Table of Contents

- [Snort vs. Suricata — The Honest Comparison](#-snort-vs-suricata--the-honest-comparison)
- [Deployment Workflow](#-deployment-workflow)
- [Installation](#-installation)
- [Configuration](#-configuration)
- [Running in IDS vs. IPS Mode](#-running-in-ids-vs-ips-mode)
- [Common Gotchas](#-common-gotchas)
- [When to Pivot to Suricata](#-when-to-pivot-to-suricata)
- [⚠️ Security Notes](#️-security-notes)
- [Resources](#-resources)

---

## 🎯 Snort vs. Suricata — The Honest Comparison

| | Snort | Suricata |
|---|---|---|
| Detection engine | Single-threaded (Snort 2) / limited multi-threading (Snort 3) | Native multi-threading throughout |
| Rule language | Its own, large community rule ecosystem (Talos/Snort rules) | Compatible with Snort-style rules, plus its own extensions (`http.uri`, `dns.query`, etc.) |
| Official package availability | Inconsistent across distros/versions — see gotchas below | Available in standard Debian/Ubuntu repos, actively maintained |
| Protocol-aware inspection | Present but less extensive | Deeper protocol decoders (TLS, HTTP/2, DNS) |
| Maintainer | Cisco (via Talos) | Open Information Security Foundation (OISF) |

Both are legitimate, capable engines. The practical difference this repo's own experience surfaced is **packaging friction**, not detection capability — see [Common Gotchas](#-common-gotchas).

---

## 🚀 Deployment Workflow

```text
1. Try the simple path first:
   └─> sudo apt update && sudo apt install snort
   └─> If this works and gives a current-enough version, you're done
       with install — skip to Configuration.

2. If not available or too old, try the official repo:
   └─> Add Snort's apt repository and key.
   └─> KNOWN ISSUE: the key URL has been unreliable — see gotchas
       before spending much time here.

3. If the official repo fails, choose:
   └─> Build from source (Snort 2.9.x — dependency-heavy, slow).
   └─> Install the Snort 3 .deb release directly from GitHub.
   └─> OR: pivot to Suricata (see When to Pivot, below).

4. Configure:
   └─> Set HOME_NET/EXTERNAL_NET, enable local.rules.
   └─> Write or import detection rules.

5. Validate in IDS (alert-only) mode first:
   └─> Never jump straight to IPS/blocking mode.

6. Only after validation, consider IPS mode:
   └─> Understand this requires inline placement (NFQUEUE or AF_PACKET).
```

---

## 🔧 Installation

### Option 1: Default distro repos (try this first)

```bash
sudo apt update
sudo apt install snort
```

Whether this works — and how current the resulting version is — varies significantly by distro and release. If it fails or installs something too old for your needs, move to the next option.

### Option 2: Snort's official repository

```bash
sudo apt install wget apt-transport-https
sudo mkdir -p /etc/apt/keyrings

# Modern, non-deprecated keyring method
curl -fsSL https://www.snort.org/downloads/snort/snort.gpg.key | sudo gpg --dearmor -o /etc/apt/keyrings/snort.gpg
echo "deb [signed-by=/etc/apt/keyrings/snort.gpg] https://www.snort.org/downloads/snort/debian stable main" | sudo tee /etc/apt/sources.list.d/snort.list

sudo apt update
sudo apt install snort
```

> ⚠️ **This is the step most likely to fail.** See [Common Gotchas](#-common-gotchas) — the key URL has returned invalid/empty data during at least one real attempt. Don't sink much time here before falling back to Option 3 or 4.

### Option 3: Build from source

Only worth it if the packaged options above don't work for your platform:

```bash
sudo apt update
sudo apt install build-essential libpcap-dev libpcre3-dev libdumbnet-dev bison flex zlib1g-dev

cd /tmp
wget https://www.snort.org/downloads/snort/snort-2.9.20.tar.gz
tar -xzf snort-2.9.20.tar.gz
cd snort-2.9.20
./configure --enable-sourcefire
make
sudo make install
```

Check [snort.org/downloads](https://www.snort.org/downloads) for the current version number before running this — `2.9.20` may not be current by the time you read this.

### Option 4: Snort 3 release package (current major version)

```bash
wget https://github.com/snort3/snort3/releases/download/<current-version>/snort3-<current-version>-1.debian12.amd64.deb
sudo dpkg -i snort3-<current-version>-1.debian12.amd64.deb
sudo apt install -f   # resolve any dependency issues
```

Check the [Snort 3 releases page](https://github.com/snort3/snort3/releases) for the current version and matching Debian release before downloading.

---

## ⚙️ Configuration

Edit `/etc/snort/snort.conf`:

```bash
# Set your network
var HOME_NET 192.168.1.0/24
var EXTERNAL_NET !$HOME_NET

# Enable your local rules file
include $RULE_PATH/local.rules
```

Example custom rules in `/etc/snort/rules/local.rules`:

```
# Alert on port scan activity
alert tcp any any -> $HOME_NET any (msg:"Port Scan Detected"; \
  flags:S; detection_filter:track by_src, count 20, seconds 60; \
  sid:1000001;)

# Alert on a classic SQL injection pattern
alert tcp any any -> $HOME_NET 80 (msg:"SQL Injection Attempt"; \
  content:"' OR '1'='1"; nocase; sid:1000002;)

# Alert on ICMP ping sweep activity
alert icmp any any -> $HOME_NET any (msg:"ICMP Ping Sweep"; \
  itype:8; detection_filter:track by_src, count 10, seconds 10; \
  sid:1000003;)
```

For writing more advanced rules, tuning performance, and Zeek-complement detection logic, this repo's [Tradecraft/network-detection.md](https://github.com/Pnwcomputers/ULTIMATE-CYBERSECURITY-MASTER-GUIDE/blob/main/Tradecraft/network-detection.md) covers Suricata-flavored rule writing that maps closely onto Snort's own rule syntax — the underlying concepts (content matching, flow tracking, thresholding) transfer directly.

---

## ▶️ Running in IDS vs. IPS Mode

**IDS (alert-only) — always start here:**

```bash
snort -A console -q -c /etc/snort/snort.conf -i eth0
```

**IPS (inline blocking) — only after validating in IDS mode:**

```bash
snort -Q -c /etc/snort/snort.conf -i eth0
```

The `-Q` flag switches Snort to inline/NFQUEUE mode, which requires the box to actually sit on the network path (traffic routed through it via `iptables`/`nftables` NFQUEUE rules) rather than just watching a copy of traffic. As with every IDS/IPS in this repo: **validate in alert-only mode for at least 1–2 weeks before enabling blocking** — see the general [IDS & IPS guide](./README.md) for why this matters.

---

## 🩹 Common Gotchas

| Symptom | Cause | Fix |
|---|---|---|
| `sudo apt install snort` — package not found | Not all distro/release combinations carry a current Snort package | Try Option 2 (official repo), or skip straight to Option 3/4 |
| `wget ... snort.gpg.key \| sudo apt-key add -` → `Warning: apt-key is deprecated` | `apt-key` is deprecated on current Debian/Ubuntu | Use the modern keyring method instead (`gpg --dearmor` into `/etc/apt/keyrings/`, referenced via `signed-by=` in the sources list) — shown in Option 2 above |
| `curl ... snort.gpg.key \| gpg --dearmor` → `gpg: no valid OpenPGP data found` | The key URL returned invalid/empty data during a real attempt at this exact step — this is the actual real-world failure point, not a typo in the command | Don't sink much time retrying this specific URL; move to Option 3 (source build), Option 4 (Snort 3 `.deb`), or pivot to Suricata entirely — see below |
| `./configure && make` from source takes a long time and/or fails on missing headers | The 2.9.x source build has a real, somewhat fragile native-dependency list | Confirm every package in the `apt install build-essential libpcap-dev ...` line actually installed before running `configure`; this path is inherently more fragile than a package manager install |
| Snort 3 `.deb` fails with dependency errors | Downloaded a release built for a different Debian/Ubuntu version than what's running | Match the `.deb` filename's distro tag to `lsb_release -cs`/`cat /etc/os-release` before downloading |

---

## 🔀 When to Pivot to Suricata

If you've hit the broken-repo-key gotcha above, or the source build isn't cooperating, it's worth being honest about the trade-off rather than burning more time: a real deployment attempt hit exactly this wall and successfully moved to Suricata instead, on the same hardware, for the same purpose (network IDS alongside an OPNsense-based home network). Suricata:

- Installs cleanly from standard Debian/Ubuntu repos with a single `apt install suricata`
- Is natively multi-threaded, which matters more than it sounds on constrained hardware like a Raspberry Pi
- Has its own full deployment guide in this repo: **[IDS & IPS: Suricata & Zeek](./suricata+zeek.md)**

This isn't a blanket "always use Suricata instead" — if you have an organizational reason to standardize on Snort specifically (existing Talos rule licensing, existing infrastructure, team familiarity), the paths above will get you there. But if you're choosing an engine freely and just hit the packaging wall, that's a legitimate signal, not a reason to keep fighting the installer.

---

## ⚠️ Security Notes

```
═══════════════════════════════════════════════════════════════
                    ⚠️ CRITICAL WARNING ⚠️
═══════════════════════════════════════════════════════════════

► VALIDATE BEFORE BLOCKING. IPS (-Q, inline/NFQUEUE) mode is an
  availability risk, not just a security control — a misfiring
  rule can drop legitimate traffic. Run alert-only for at least
  1-2 weeks before enabling inline blocking, same as every other
  IDS/IPS in this repo.

► VERIFY THIRD-PARTY DOWNLOADS. When fetching a Snort 3 release
  or a source tarball, confirm the URL is the official
  snort.org/GitHub release page — don't follow a link from a
  random tutorial without checking it matches.

► KEEP RULES CURRENT. An IDS with a stale ruleset gives false
  confidence. Whichever install path you use, establish a rule
  update cadence (Snort's official rule feeds require a free or
  paid Talos subscription depending on rule tier).

═══════════════════════════════════════════════════════════════
```

---

## 📚 Resources

- **Snort official site:** [snort.org](https://www.snort.org/)
- **Snort 3 GitHub releases:** [github.com/snort3/snort3/releases](https://github.com/snort3/snort3/releases)
- **Snort rule documentation (Talos):** [snort.org/documents](https://www.snort.org/documents)

---

<div align="center">

## Related Files
- [IDS&IPS/README.md](./README.md) - Sub-section index and platform comparison
- [IDS&IPS/suricata+zeek.md](./suricata%2Bzeek.md) - The modern alternative this guide's real-world attempt pivoted to
- [Tradecraft/network-detection.md](https://github.com/Pnwcomputers/ULTIMATE-CYBERSECURITY-MASTER-GUIDE/blob/main/Tradecraft/network-detection.md) - Rule-writing depth that transfers directly from Suricata syntax to Snort's
- [Homelab/HomeLab_Setup.md](https://github.com/Pnwcomputers/ULTIMATE-CYBERSECURITY-MASTER-GUIDE/blob/main/Homelab/HomeLab_Setup.md) - VLAN/firewall placement context for where an IDS/IPS sits in a lab network

---

**🛡️ Use These Resources Responsibly**

*Detection first, blocking second.*

**Repository**: [ULTIMATE CYBERSECURITY MASTER GUIDE](https://github.com/Pnwcomputers/ULTIMATE-CYBERSECURITY-MASTER-GUIDE)

**Maintained by**: [Pacific Northwest Computers](https://github.com/Pnwcomputers)

⭐ **Star this repo if you find it useful!** ⭐

</div>
