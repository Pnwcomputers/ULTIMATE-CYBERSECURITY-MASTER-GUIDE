# 🛡️ Intrusion Detection & Intrustion Prevention (IDS/IPS) with Suricata & Zeek

<div align="center">

**Signature-based blocking + protocol-level network security monitoring, standalone or on a firewall VM**

*Part of the [ULTIMATE CYBERSECURITY MASTER GUIDE](../README.md)*

![Blue Team](https://img.shields.io/badge/Operations-Blue_Team-blue?style=for-the-badge)
![IDS/IPS](https://img.shields.io/badge/Framework-IDS_%2F_IPS-darkred?style=for-the-badge)
![Suricata](https://img.shields.io/badge/Engine-Suricata_%7C_Zeek-orange?style=for-the-badge)

</div>

---

## 🎯 Purpose
Guide for deploying an open-source network Intrusion Detection/Prevention System — Suricata for signature-based detection and inline blocking, Zeek for protocol-level network security monitoring (NSM) — either standalone on Linux or via a firewall VM's built-in package (OPNsense/pfSense).

## ⚙️ Function
Covers choosing IDS-only (passive/tap) vs IPS (inline/blocking) deployment mode, standalone Suricata install on Debian/Ubuntu, the OPNsense built-in Suricata path, rule management, Zeek as a complementary NSM layer, validation/testing, and the gotchas that actually cost time during a real build.

## 🏆 Goal
Get a homelab or small-network operator from bare hardware to a validated, alert-tuned IDS — with a clear, informed path to IPS (active blocking) only after the detection side has been proven safe.

## 📋 When to Use
- Standing up network-level threat detection from scratch, on a dedicated box or a firewall VM
- Deciding whether to run Suricata inline (IPS) or as a passive tap (IDS only)
- An update or package install on a Suricata-hosting firewall VM hangs or behaves oddly
- Extending detection with Zeek's protocol logs for hunting/forensics beyond signature alerts

> 📝 **Note:** This guide is informational/educational, covering the general deployment path rather than one specific live network. Where a real build surfaced a non-obvious gotcha, it's called out explicitly.

---

## 📋 Table of Contents

- [IDS vs IPS: What You're Actually Choosing](#-ids-vs-ips-what-youre-actually-choosing)
- [Engine Comparison](#️-engine-comparison)
- [Deployment Workflow](#-deployment-workflow)
- [Standalone Suricata (Debian/Ubuntu)](#-standalone-suricata-debianubuntu)
- [Suricata on OPNsense/pfSense](#-suricata-on-opnsensepfsense)
- [Rule Management](#-rule-management)
- [Zeek as a Complementary NSM Layer](#-zeek-as-a-complementary-nsm-layer)
- [Validation & Testing](#-validation--testing)
- [Common Gotchas](#-common-gotchas)
- [⚠️ Security Notes](#️-security-notes)
- [Resources](#-resources)

---

## 🎯 IDS vs IPS: What You're Actually Choosing

| Mode | What it does | Failure behavior | Deployment |
|---|---|---|---|
| **IDS** (Intrusion *Detection*) | Passively inspects a copy of traffic, generates alerts | Fails safe — a crashed sensor just stops alerting, traffic keeps flowing | Tap/SPAN/mirror port, or `af-packet` in IDS mode |
| **IPS** (Intrusion *Prevention*) | Sits inline, actively drops/rejects matching traffic in real time | Fails differently depending on config — can fail open (bypass) or fail closed (outage) | Inline bridge, or `af-packet`/NFQUEUE in IPS mode |

**The practical rule:** always start in IDS/alert-only mode, run it for at least 1–2 weeks against real traffic, review false positives, and only then flip to IPS/blocking. An aggressive ruleset in blocking mode on day one can take down legitimate traffic — DNS, software updates, VoIP, and anything using an uncommon-but-valid pattern are common false-positive sources.

---

## 🗂️ Engine Comparison

| Engine | Type | Blocking (IPS) | Strength | Weakness |
|---|---|---|---|---|
| **Suricata** | Signature + protocol-aware | ✅ Yes (native) | Multi-threaded, deep packet inspection, large community ruleset (ET Open) | Signature-based — blind to genuinely novel traffic patterns |
| **Snort** | Signature-based | ✅ Yes (native) | Mature, huge rule ecosystem, well documented | Historically single-threaded; scales worse on busy links than Suricata |
| **Zeek** (formerly Bro) | Protocol/anomaly analysis | ❌ No — detection/logging only | Rich structured logs (`conn.log`, `dns.log`, `ssl.log`, JA3/JA3S) for hunting and forensics | Not an inline blocker; steeper scripting learning curve |

For a from-scratch build, **Suricata is the default choice** for the IDS/IPS role itself — native multi-threading and both detection and blocking in one engine. **Zeek runs alongside it**, not instead of it, for the deep protocol visibility Suricata's rule-matching doesn't give you. This mirrors how full NSM stacks (e.g. Security Onion) combine them rather than picking one.

---

## 🚀 Deployment Workflow

```text
1. Placement Decision:
   └─> IDS only (safest start): tap/SPAN/mirror port, passive af-packet.
   └─> IPS (active blocking): inline bridge or NFQUEUE, only after IDS-mode validation.

2. Engine Install:
   └─> Standalone Linux (apt install suricata), OR
   └─> Firewall VM's built-in package (OPNsense Services -> Intrusion Detection).

3. Interface Configuration:
   └─> Confirm actual interface names on your platform (eth0 vs em0/em1, etc.)
       before touching af-packet config — a wrong interface name is the
       single most common reason capture just doesn't happen.

4. Rule Deployment:
   └─> suricata-update / ruleset download (ET Open, Abuse.ch).
   └─> Leave IPS mode OFF. Run alert-only.

5. Validation:
   └─> testmynids.org test, or pcap replay against known-bad traffic.
   └─> Watch alerts for 1-2 weeks; tune out false positives.

6. IPS Cutover (optional, once validated):
   └─> Enable inline/blocking mode.
   └─> Watch closely for the first 24-48 hours for anything legitimate
       getting dropped.

7. Extend Visibility:
   └─> Add Zeek on the same tap/mirror for protocol-level logs.
   └─> Forward alerts to a SIEM (see Resources below).
```

---

## 🔧 Standalone Suricata (Debian/Ubuntu)

### Install

```bash
sudo apt update
sudo apt install -y suricata
```

### Identify your capture interface

```bash
ip -br link
```

Don't assume `eth0` — cloud images, Proxmox VMs (`ens18`, `enp6s18`, etc.), and physical NICs on different distros all name interfaces differently. Confirm it before editing config.

### Configure `af-packet` capture

Edit `/etc/suricata/suricata.yaml`:

```yaml
vars:
  address-groups:
    HOME_NET: "[10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16]"

af-packet:
  - interface: enp6s18        # your actual interface, not a placeholder
    cluster-id: 99
    cluster-type: cluster_flow
    defrag: yes
    use-mmap: yes
    ring-size: 200000
```

This runs Suricata in **passive IDS mode** — it inspects a copy of traffic and alerts, without sitting inline.

### For IPS (inline blocking) on standalone Linux

Two common patterns:

- **NFQUEUE** — traffic is routed through Suricata via `iptables`/`nftables`, Suricata accepts or drops each packet:
  ```bash
  sudo iptables -I FORWARD -j NFQUEUE --queue-num 0
  ```
  Then set `suricata.yaml`'s `nfq` section and run Suricata with `-q 0` in IPS mode.
- **AF_PACKET IPS mode (bridge)** — two NICs bridged, Suricata inspects and forwards/drops between them. Requires the box to sit physically/logically inline on the network path.

Either way, **do not enable inline mode until you've validated in IDS/alert-only mode first** (see [Validation & Testing](#-validation--testing)).

### Enable and start

```bash
sudo suricata-update
sudo systemctl enable --now suricata
sudo systemctl status suricata
```

---

## 🔩 Suricata on OPNsense/pfSense

Both OPNsense and pfSense ship Suricata as a built-in package — no separate install needed. This is a common path for a firewall-integrated IDS/IPS since the traffic is already flowing through the box.

### 1. Enable and configure

**Services → Intrusion Detection → Administration:**

| Setting | Value |
|---|---|
| Enable IDS/IPS | ✅ |
| IPS Mode | ❌ leave unchecked initially — alert-only first |
| Promiscuous Mode | ✅ |
| Pattern Matcher | `Hyperscan` |
| Interfaces to Protect | LAN, WAN (or whichever segments you want visibility on) |

Save, then **Services → Intrusion Detection → Download**, enable the **ET Open/Emerging Threats** and **Abuse.ch** rulesets, and click **Download & Update Rules** (takes 5–10 minutes).

Click **Apply** on the Administration page to start Suricata.

### 2. Fix the interface name mismatch

This is the gotcha that actually cost time in a real build: the config can default to a generic interface name (`eth0`) that doesn't exist on a BSD-based firewall — physical/virtual NICs there use driver-based names (`em0`, `em1`, `igb0`, etc., depending on the underlying hardware or virtio/e1000 emulation).

From the OPNsense shell (console option 8, or SSH):

```bash
mkdir -p /var/log/suricata /var/run/suricata
chmod 755 /var/log/suricata /var/run/suricata

# Check what's actually configured
cat /usr/local/etc/suricata/suricata.yaml | grep -A 20 "af-packet:"
```

If it shows `eth0` instead of your real interfaces:

```bash
ee /usr/local/etc/suricata/suricata.yaml
```

```yaml
af-packet:
  - interface: em0
    threads: auto
    cluster-id: 98
    cluster-type: cluster_flow
  - interface: em1
    threads: auto
    cluster-id: 99
    cluster-type: cluster_flow
```

Save (Ctrl+C → save changes and exit), then re-apply from the Administration page and confirm it's running:

```bash
service suricata status
tail -50 /var/log/suricata/suricata_*.log
```

Look for `Engine started` at the end of the log — that's success.

### 3. Enable IPS mode (only after validating)

**Services → Intrusion Detection → Administration → IPS Mode → check → Save → Apply.**

> ⚠️ Do this only after running alert-only for 1–2 weeks with no false positives on legitimate traffic. Flipping this on day one is how you find out DNS or a software updater matches a rule you didn't expect.

### 4. Email alerting (optional)
**System → Settings → Notifications** — SMTP host/port/credentials...

### pfSense-specific differences

pfSense and OPNsense share FreeBSD roots, but Suricata isn't built in on pfSense the way it is on OPNsense — you install it as a package first:

**System → Package Manager → Available Packages** → search "Suricata" → **Install**.

Once installed, the menu path is also different from OPNsense:

| | OPNsense | pfSense |
|---|---|---|
| Package install | Built in, nothing to install | **System → Package Manager → Available Packages** first |
| Configuration menu | Services → Intrusion Detection | **Services → Suricata** |
| Per-interface setup | One combined interface list | **Services → Suricata → Interfaces → Add** (one entry per interface you want monitored) |
| Inline/IPS mode | `af-packet` IPS mode, toggled in Administration | **Netmap-based Inline Mode** — requires a NIC/driver with netmap support; check pfSense's Suricata docs for supported drivers before enabling, don't assume it works on your NIC |

Same discipline applies regardless of platform: enable as IDS, watch alerts, tune out false positives, **then** consider inline/IPS mode — a noisy rule in blocking mode can cut off legitimate traffic on a live firewall, including your own management access.

---

## 📜 Rule Management

```bash
# Update rules (standalone Linux)
suricata-update

# List and enable rule sources
suricata-update list-sources
suricata-update enable-source et/open          # Emerging Threats (free)
suricata-update enable-source abuse.ch/sslbl   # SSL Blacklist

# Test rules against a pcap before trusting them live
suricata -r capture.pcap -l /tmp/logs/ -c /etc/suricata/suricata.yaml

# Validate config/rule syntax
suricata --engine-analysis -c /etc/suricata/suricata.yaml
```

For writing custom rules, tuning performance (CPU affinity, `af-packet` ring sizing), and a working set of example detection rules (C2 stagers, DNS tunneling, download cradles), see the full reference: **[Tradecraft/network-detection.md](https://github.com/Pnwcomputers/ULTIMATE-CYBERSECURITY-MASTER-GUIDE/blob/main/Tradecraft/network-detection.md)** — this guide intentionally doesn't duplicate that material.

---

## 🔍 Zeek as a Complementary NSM Layer

Zeek doesn't block anything — it turns raw traffic into structured, high-fidelity protocol logs (`conn.log`, `dns.log`, `http.log`, `ssl.log` with JA3/JA3S fingerprints, `files.log` with hashes) that are far more useful for hunting and forensics than either a signature match alone or a raw pcap. Run it on the same tap/mirror interface as Suricata — they don't conflict, since both just read a copy of the traffic.

```bash
sudo apt install -y zeek
# or, for the latest release:
echo 'deb http://download.opensuse.org/repositories/security:/zeek/xUbuntu_24.04/ /' | \
  sudo tee /etc/apt/sources.list.d/security:zeek.list
curl -fsSL https://download.opensuse.org/repositories/security:zeek/xUbuntu_24.04/Release.key | \
  gpg --dearmor | sudo tee /etc/apt/trusted.gpg.d/security_zeek.gpg > /dev/null
sudo apt update && sudo apt install -y zeek
```

Set the capture interface in `/opt/zeek/etc/node.cfg` (standalone mode), same interface-name-verification caution as Suricata applies here too.

If you only have a single NIC on a VM/appliance and no mirror port available, running Zeek directly on a firewall VM that already sees all routed traffic (rather than trying to mirror to a separate box) avoids needing extra port-mirroring infrastructure.

For the full log reference table, `zeek-cut` analysis one-liners, JA3/JA3S fingerprinting, and Zeek detection scripts, see **[Tradecraft/network-detection.md](https://github.com/Pnwcomputers/ULTIMATE-CYBERSECURITY-MASTER-GUIDE/blob/main/Tradecraft/network-detection.md)** — again, not duplicated here.

---

## ✅ Validation & Testing

**From a client device on the network — never from the sensor/firewall itself:**

```bash
curl http://testmynids.org/uid/index.html
```

Expected: the page returns `uid=0(root) gid=0(root) groups=0(root)`, and a corresponding alert (commonly named something like *"GPL ATTACK_RESPONSE id check returned root"*) should appear in **Services → Intrusion Detection → Alerts** (OPNsense/pfSense) or your Suricata log (standalone). If the alert shows up, detection is working end-to-end.

**Pcap replay** is the other reliable check, useful for validating custom rules before they ever see live traffic:

```bash
suricata -r known_bad_traffic.pcap -l /tmp/logs/ -c /etc/suricata/suricata.yaml
```

---

## 🩹 Common Gotchas

| Symptom | Cause | Fix |
|---|---|---|
| No alerts at all, engine reports running | Interface name in config doesn't match the real capture interface | Verify with `ip -br link` (Linux) or check the actual driver name (`em0`/`em1`, not `eth0`) on BSD-based firewalls |
| Testing from the sensor/firewall itself produces nothing | Suricata/Zeek can only inspect traffic passing *through* the box, not traffic *originating from* it | Test from a separate client device on the network |
| Firmware/package update hangs on a Suricata-hosting firewall VM | IDS/IPS (and similar deep-inspection packages) can be memory-hungry; a VM sized for basic routing runs out of headroom during package installs | Check actual free RAM (not just what's allocated) before assuming a network/mirror problem; temporarily stopping the IDS service during updates can free enough memory to complete them |
| Legitimate traffic gets blocked right after enabling IPS mode | Ruleset too aggressive for real-world traffic patterns, enabled before adequate observation | Revert to alert-only, review what specifically fired, exclude/tune that rule, re-enable IPS only after a clean observation window |
| High CPU/dropped packets under load | Single-threaded config or undersized `ring-size` on a busy link | Enable CPU affinity and multi-threading (`af-packet` `threads: auto`), see the performance-tuning YAML in [Tradecraft/network-detection.md](https://github.com/Pnwcomputers/ULTIMATE-CYBERSECURITY-MASTER-GUIDE/blob/main/Tradecraft/network-detection.md) |

---

## ⚠️ Security Notes

```
═══════════════════════════════════════════════════════════════
                    ⚠️ CRITICAL WARNING ⚠️
═══════════════════════════════════════════════════════════════

► IPS (blocking) mode is an availability risk, not just a
  security control. A misfiring rule in inline mode can take
  down legitimate traffic — DNS, updates, VoIP, anything with an
  uncommon-but-valid pattern. Always validate in alert-only mode
  first, for at least 1-2 weeks against real traffic.

► An IDS/IPS box on a network path is a high-value target. Keep
  it patched, restrict management access, and don't expose its
  web UI/SSH to anything but a trusted management network.

► Free rulesets (ET Open, Abuse.ch) are a starting point, not a
  complete solution. Review what's actually enabled rather than
  assuming default rulesets match your environment's risk
  profile.

═══════════════════════════════════════════════════════════════
```

---

## 📚 Resources

- **Suricata docs:** [docs.suricata.io](https://docs.suricata.io)
- **Zeek docs:** [docs.zeek.org](https://docs.zeek.org)
- **Emerging Threats rules:** [rules.emergingthreats.net](https://rules.emergingthreats.net)
- **OPNsense IDS/IPS documentation:** [docs.opnsense.org](https://docs.opnsense.org)
- **NIDS test endpoint:** [testmynids.org](http://testmynids.org)

---

<div align="center">

## Related Files
- [Tradecraft/network-detection.md](https://github.com/Pnwcomputers/ULTIMATE-CYBERSECURITY-MASTER-GUIDE/blob/main/Tradecraft/network-detection.md) - Rule writing, Zeek log analysis, C2/lateral-movement detection deep dive (the depth this guide intentionally doesn't duplicate)
- [IncidentResponse/SIEM/wazuh.md](https://github.com/Pnwcomputers/ULTIMATE-CYBERSECURITY-MASTER-GUIDE/blob/main/IncidentResponse/SIEM/wazuh.md) - Forward Suricata/Zeek alerts into a SIEM for correlation and dashboards
- [IncidentResponse/log_agg.md](https://github.com/Pnwcomputers/ULTIMATE-CYBERSECURITY-MASTER-GUIDE/blob/main/IncidentResponse/log_agg.md) - Centralized log collection, including firewall log forwarding
- [Homelab/HomeLab_Setup.md](https://github.com/Pnwcomputers/ULTIMATE-CYBERSECURITY-MASTER-GUIDE/blob/main/Homelab/HomeLab_Setup.md) - VLAN segmentation and firewall placement context for a lab deployment
- [IncidentResponse/IDS/nzyme_wids.md](https://github.com/Pnwcomputers/ULTIMATE-CYBERSECURITY-MASTER-GUIDE/blob/main/IncidentResponse/IDS/nzyme_wids.md) - The wireless-domain counterpart to this wired/network IDS/IPS guide

---

**🛡️ Use These Resources Responsibly**

*Detection first, blocking second.*

**Repository**: [ULTIMATE CYBERSECURITY MASTER GUIDE](https://github.com/Pnwcomputers/ULTIMATE-CYBERSECURITY-MASTER-GUIDE)

**Maintained by**: [Pacific Northwest Computers](https://github.com/Pnwcomputers)

⭐ **Star this repo if you find it useful!** ⭐

</div>
