# 🧅 Security Onion: Turnkey Network Security Monitoring

<div align="center">

**Suricata + Zeek + Elastic Stack + Wazuh + CyberChef, pre-integrated into one appliance-style platform**

*Part of the [ULTIMATE CYBERSECURITY MASTER GUIDE](../../README.md) · [Incident Response](../README.md) · [IDS & IPS](./README.md) section*

![Blue Team](https://img.shields.io/badge/Operations-Blue_Team-blue?style=for-the-badge)
![NSM](https://img.shields.io/badge/Framework-Network_Security_Monitoring-darkred?style=for-the-badge)
![Security Onion](https://img.shields.io/badge/Platform-Security_Onion-orange?style=for-the-badge)

</div>

---

## 🎯 Purpose
Guide for deploying [Security Onion](https://securityonion.net/), a free, open-source Linux distro that pre-integrates network security monitoring (Suricata, Zeek), a full Elastic Stack for search and dashboards, host visibility (Elastic Agent, Sysmon), and analyst tooling (CyberChef, PCAP retrieval, case management) into a single ISO-based platform.

## ⚙️ Function
Covers the node-type architecture (Standalone/Eval/Import vs. distributed Manager+Sensor+Search), hardware sizing per node type, the ISO installation flow, sniffing-interface planning, and where the pieces you already know from this repo's standalone [Suricata & Zeek](./suricata+zeek.md) guide live inside Security Onion's integrated setup.

## 🏆 Goal
Give an informed sizing and architecture decision *before* burning a full ISO install cycle on hardware that turns out to be undersized — this is the single most common way people waste time with Security Onion.

## 📋 When to Use
- You've already worked with standalone Suricata/Zeek and want the integrated dashboards, alerting, and case-management layer without building it yourself
- You want the NSM (network security monitoring) equivalent of what [T-Pot](./tpot.md) is for honeypots — pre-integrated, appliance-style, dashboards included
- You have dedicated hardware to spare (this is **not** a Raspberry Pi project — see sizing below) and want full packet capture retention alongside alerts

---

## 📋 Table of Contents

- [What Security Onion Actually Is](#-what-security-onion-actually-is)
- [Architecture & Node Types](#️-architecture--node-types)
- [Hardware Sizing](#-hardware-sizing)
- [Installation](#-installation)
- [Post-Install Configuration](#-post-install-configuration)
- [Where the Pieces You Already Know Live](#-where-the-pieces-you-already-know-live)
- [Common Gotchas](#-common-gotchas)
- [⚠️ Security Notes](#️-security-notes)
- [Resources](#-resources)

---

## 🎯 What Security Onion Actually Is

Security Onion isn't a new detection engine — it's the same Suricata and Zeek covered in this repo's [standalone guide](./suricata+zeek.md), plus:

- **Elastic Stack** (Elasticsearch, Logstash, Kibana) for storage, search, and dashboards
- **Elastic Agent** and **Sysmon** integration for host-level visibility alongside network data
- **Strelka** for file scanning/extraction
- **CyberChef**, **NetworkMiner**, and **Wireshark** bundled for analyst workflows
- **Sigma** and **YARA** rule support layered on top of Suricata's own signature rules
- **IDH (Intrusion Detection Honeypot)** nodes — a lightweight, purpose-built honeypot role baked into the platform, conceptually similar to this repo's [Honeypots](../Honeypots/README.md) guides but managed as part of the Security Onion grid

Think of it as: everything you'd otherwise assemble by hand from this repo's Suricata/Zeek and SIEM guides, pre-wired together and given a management console.

---

## 🏗️ Architecture & Node Types

Security Onion supports everything from a single evaluation VM to a fully distributed enterprise deployment. Pick the smallest type that fits your actual need — sizing scales up dramatically with each step:

| Type | What it is | Use case |
|---|---|---|
| **Import** | Minimal processes to import PCAP/EVTX files and review them | Forensic analysis of files you already have, not live monitoring |
| **Eval** | Single machine sniffing live traffic, no Logstash/Redis (lower RAM) | Homelab, evaluation, temporary — **not for production** |
| **Standalone** | Manager + sensor components on one box, production-capable | Small-to-medium single-sensor deployments |
| **Distributed** (Manager + Sensor + Search nodes) | Roles split across multiple machines | Larger networks, higher traffic volumes, need to scale search/storage independently |
| **IDH node** | Dedicated lightweight honeypot node | Very low resource requirement (1 GB RAM), complements the main grid |

**Start with Eval or Standalone.** Distributed deployments only make sense once you actually need to scale search/storage independently of sniffing capacity — don't reach for it prematurely.

---

## 🖥️ Hardware Sizing

This is where most first attempts go wrong — Security Onion is **not** lightweight, even at its smallest production-capable size:

| Node Type | CPU cores | RAM | Storage | NICs |
|---|---|---|---|---|
| Import | 2 | 4 GB | 100 GB | 1 |
| Eval | 4 | 8 GB | 200 GB | 2 |
| **Standalone** | **4** | **24 GB** | **200 GB** | **2** |
| Manager | 4 | 16 GB | 200 GB | 1 |
| Search node | 4 | 16 GB | 200 GB | 1 |
| Sensor | 4 | 12 GB | 200 GB | 2 |
| IDH node | 2 | 1 GB | 12 GB | 1 |

**Critical detail easy to miss:** even the "minimum" Standalone spec (24 GB RAM) explicitly may need swap space to avoid instability at that floor — the docs themselves recommend 32 GB+ if monitoring any real traffic volume. This is not a project to try to squeeze onto a Pi or a small VM the way OpenCanary or standalone Suricata can be.

**NIC planning:** you need one interface with an IP for management, and a **separate** interface with no IP dedicated to sniffing (fed by a TAP or SPAN port). Security Onion automatically disables NIC offload features (`tso`, `gso`, `gro`) on sniffing interfaces so Suricata/Zeek see accurate traffic — don't try to "fix" this yourself.

**Storage for full packet capture** scales fast: a sustained 50 Mbps link works out to roughly 540 GB/day of raw PCAP. Size storage against your actual retention requirement, not just the OS install.

**CPU architecture:** x86-64 only — Security Onion explicitly does not support ARM, so this rules out Raspberry Pi hardware entirely for the main grid (the IDH honeypot role is the exception, given its minimal footprint).

---

## 🔧 Installation

1. **Review Hardware and Release Notes** on the [official docs](https://docs.securityonion.net/en/3/main/hardware/) before downloading anything — confirm your target hardware actually meets the node type you're planning.
2. **Download and verify the ISO** from the official [Download page](https://docs.securityonion.net/en/3/main/download/) — verify the checksum, don't skip this on a security tool.
3. **Boot the ISO** on hardware meeting the minimum specs for your chosen node type.
4. **Follow the installer prompts** to completion, then reboot.
5. **Log in** with the username/password set during install. Setup starts automatically.

If Setup doesn't auto-start (e.g. after manually exiting it), restart it explicitly:

```bash
sudo SecurityOnion/setup/so-setup iso
```

6. Proceed through **Configuration** — choose your node type (Import / Eval / Standalone / Distributed manager-first), set network interfaces (management vs. sniffing), and complete the guided setup.

> ⚠️ **Get the hostname right the first time.** Setup generates certificates based on the hostname during install, and changing the hostname afterward is not supported. This isn't a "fix it later" setting.

For a distributed deployment, install and fully configure the **Manager** node first, then join **Sensor**/**Search** nodes to it — nodes are approved via **Administration → Grid Members** on the Manager after they attempt to join.

---

## ⚙️ Post-Install Configuration

- **Security Onion Console (SOC)** is your main web UI — alerts, dashboards, hunt, cases, detections, PCAP retrieval, and grid administration all live here.
- **Kibana** is available underneath SOC for deeper Elastic-native dashboarding.
- Add host-level visibility via **Elastic Agent** (cross-platform) or **Sysmon** (Windows) — this is what correlates network alerts with endpoint activity.
- Rule sources (Suricata/NIDS rules, **Sigma**, **YARA**) are managed centrally rather than per-engine, which is the main practical improvement over hand-rolling the same stack yourself.

---

## 🔗 Where the Pieces You Already Know Live

If you've already worked through this repo's other guides, Security Onion's components map directly:

| You already know this from... | It shows up in Security Onion as... |
|---|---|
| [Suricata & Zeek](./suricata+zeek.md) | The NIDS/NSM engine layer — same engines, centrally managed rules and config |
| [SIEM: ELK Stack](https://github.com/Pnwcomputers/ULTIMATE-CYBERSECURITY-MASTER-GUIDE/blob/main/IncidentResponse/SIEM/elk_stack.md) | The Elasticsearch/Logstash/Kibana backend, pre-wired to ingest Suricata/Zeek output automatically |
| [SIEM: Wazuh](https://github.com/Pnwcomputers/ULTIMATE-CYBERSECURITY-MASTER-GUIDE/blob/main/IncidentResponse/SIEM/wazuh.md) | Available as a host-visibility/EDR-style integration option |
| [Honeypots](../Honeypots/README.md) | The IDH (Intrusion Detection Honeypot) node type — a purpose-built, low-resource honeypot role in the grid |
| [Endpoint Visibility: Sysmon](https://github.com/Pnwcomputers/ULTIMATE-CYBERSECURITY-MASTER-GUIDE/blob/main/IncidentResponse/Endpoint-Visibility/Windows/sysmon.md) | Ingested directly as a host-visibility source |

This is the practical value proposition: if you understand Suricata, Zeek, and ELK from this repo's other guides already, you're not learning new detection concepts here — you're learning how Security Onion wires the pieces together and manages them centrally.

---

## 🩹 Common Gotchas

| Symptom | Cause | Fix |
|---|---|---|
| Standalone install is unstable / services keep restarting | Hardware sized at the bare 24 GB RAM floor, no swap configured | Add swap space, or better, provision 32 GB+ if monitoring any real traffic — the docs are explicit that the minimum is genuinely minimal |
| Suricata/Zeek show dropped packets or inaccurate traffic view | NIC offload features (`tso`/`gso`/`gro`) weren't disabled on the sniffing interface | The installer does this automatically on interfaces it identifies as sniffing-only (no IP) — confirm the interface has no IP assigned if this persists |
| Can't change the hostname after a botched initial setup | Certificates were generated against the original hostname during install; this is explicitly unsupported to change later | Reinstall rather than fight it — this is a documented hard limitation, not a bug to work around |
| Distributed sensor won't join the manager | Node approval step skipped | Check **Administration → Grid Members → Pending Members** on the Manager and explicitly Review/Accept the joining node |
| Running out of disk far faster than expected | Full packet capture retention wasn't sized against actual traffic volume | Recalculate storage needs against your real average bandwidth (see the 50 Mbps → ~540 GB/day example above), not just the OS install size |
| Tried it on a Raspberry Pi or other ARM hardware | Security Onion is x86-64 only | Use x86-64 hardware for the main grid; ARM isn't supported at all (the lightweight IDH honeypot role is the only ARM-friendly-adjacent piece, and even that assumes an x86-64 grid it joins) |

---

## ⚠️ Security Notes

```
═══════════════════════════════════════════════════════════════
                    ⚠️ CRITICAL WARNING ⚠️
═══════════════════════════════════════════════════════════════

► THIS PLATFORM SEES EVERYTHING. A Security Onion deployment
  with full packet capture retains complete network traffic
  content, not just metadata. Treat its storage and access
  controls accordingly — this is one of the most sensitive
  systems you can run on a network.

► DEDICATED MANAGEMENT NETWORK RECOMMENDED. Keep the management
  interface off the general network where possible; SOC and
  Kibana access should be restricted to trusted administrators.

► GET THE HOSTNAME RIGHT BEFORE INSTALLING. Certificates are
  tied to it permanently — there is no supported migration path
  if you get this wrong.

► SIZE STORAGE FOR YOUR ACTUAL RETENTION NEEDS BEFORE DEPLOYING,
  not after. Running out of disk on a system holding full packet
  captures of your network traffic is a worse failure mode than
  most other tools in this repo.

═══════════════════════════════════════════════════════════════
```

---

## 📚 Resources

- **Security Onion docs:** [docs.securityonion.net](https://docs.securityonion.net/en/3/main/)
- **Security Onion GitHub:** [github.com/Security-Onion-Solutions/securityonion](https://github.com/Security-Onion-Solutions/securityonion)
- **Security Onion Solutions (official appliances/support):** [securityonionsolutions.com](https://securityonionsolutions.com)
- **Community support (GitHub Discussions):** linked from the official docs site

---

<div align="center">

## Related Files
- [IDS&IPS/README.md](./README.md) - Sub-section index and platform comparison
- [IDS&IPS/suricata+zeek.md](./suricata%2Bzeek.md) - The standalone version of this platform's core detection engines
- [Honeypots/tpot.md](../Honeypots/tpot.md) - The honeypot-domain equivalent of this "everything pre-integrated" approach
- [Honeypots/README.md](../Honeypots/README.md) - Including the IDH honeypot role this platform can run natively
- [IncidentResponse/SIEM/elk_stack.md](https://github.com/Pnwcomputers/ULTIMATE-CYBERSECURITY-MASTER-GUIDE/blob/main/IncidentResponse/SIEM/elk_stack.md) - The standalone version of the backend this platform bundles
- [IncidentResponse/SIEM/wazuh.md](https://github.com/Pnwcomputers/ULTIMATE-CYBERSECURITY-MASTER-GUIDE/blob/main/IncidentResponse/SIEM/wazuh.md) - Available as a host-visibility integration alongside this platform

---

**🛡️ Use These Resources Responsibly**

*Detection first, blocking second.*

**Repository**: [ULTIMATE CYBERSECURITY MASTER GUIDE](https://github.com/Pnwcomputers/ULTIMATE-CYBERSECURITY-MASTER-GUIDE)

**Maintained by**: [Pacific Northwest Computers](https://github.com/Pnwcomputers)

⭐ **Star this repo if you find it useful!** ⭐

</div>
