
# 🛡️ IDS & IPS Deployment Guides

<div align="center">

**Intrusion Detection & Prevention — wireless and wired, passive and inline**

*Part of the [ULTIMATE CYBERSECURITY MASTER GUIDE](../../README.md) · [Incident Response](../README.md) section*

![Blue Team](https://img.shields.io/badge/Operations-Blue_Team-blue?style=for-the-badge)
![IDS/IPS](https://img.shields.io/badge/Framework-IDS_%2F_IPS-darkred?style=for-the-badge)
![Self-Hosted](https://img.shields.io/badge/Deployment-Self--Hosted-green?style=for-the-badge)

</div>

---

## 🎯 Purpose
Index for the IDS/IPS sub-section — self-hosted intrusion detection and prevention build guides covering both the wireless domain (nzyme) and the wired/network domain (Suricata + Zeek), so a blue teamer can stand up real-time threat visibility across an entire environment, not just one slice of it.

## ⚙️ Function
Links to a full build guide per domain — hardware/platform requirements, install and configuration, driver and interface gotchas that actually cost time in real builds, alert tuning, and validation/testing — plus guidance on which guide covers which layer of the network.

## 🏆 Goal
Enable a practitioner to go from bare hardware to a validated, alert-tuned detection stack covering both RF/wireless and wired network traffic, without re-discovering the same driver, interface-naming, and false-positive-tuning problems each build runs into.

## 📋 When to Use
- Standing up wireless or wired intrusion detection from scratch in a homelab or small network
- Deciding whether a given alert needs the wireless guide (rogue APs, deauth, evil twins) or the wired guide (network-based signatures, protocol anomalies)
- Choosing between IDS-only (passive/alerting) and IPS (inline/blocking) deployment
- Extending an existing detection stack with a second domain (e.g. you have wired IDS/IPS and want wireless coverage, or vice versa)

---

## 📋 Table of Contents

- [Overview](#-overview)
- [Guide Comparison](#️-guide-comparison)
- [Deployment Guides](#-deployment-guides)
- [Which Guide Do I Need?](#-which-guide-do-i-need)
- [Deployment Workflow](#-deployment-workflow)
- [⚠️ Security Notes](#️-security-notes)
- [Contributing](#-contributing)
- [Resources](#-resources)

---

## 🎯 Overview

**IDS** (Intrusion Detection) passively watches traffic and alerts on suspicious activity. **IPS** (Intrusion Prevention) sits inline and can actively block it. Both terms apply equally to wireless (RF/802.11) and wired (Ethernet/IP) traffic — but the hardware, software, and failure modes involved are different enough that they're covered as separate guides here.

This sub-section provides **hands-on, from-a-real-build guides**, not vendor doc summaries. Where a build hit a genuine gotcha (a driver crashing under load, an interface name that doesn't match what the config expects, a ruleset that needs validation before it's trusted to block traffic), that gotcha is documented explicitly rather than glossed over.

> [!TIP]
> New to network visibility generally? Start with the log-aggregation prerequisite in
> [../log_agg.md](../log_agg.md), then pick a domain below.

---

## 🗂️ Guide Comparison

| Guide | Domain | Engine(s) | Blocking (IPS) | Deployment Complexity |
|---|---|---|---|---|
| 📡 **[nzyme_wids.md](./nzyme_wids.md)** | Wireless (802.11) | nzyme | ❌ Detection only | 🟡 MEDIUM |
| 🛡️ **[suricata+zeek.md](./suricata+zeek.md)** | Wired/Network | Suricata + Zeek | ✅ Suricata supports inline blocking | 🟡 MEDIUM |

---

## 📚 Deployment Guides

### 📡 [nzyme WIDS](./nzyme_wids.md)
Wireless Intrusion Detection System — a Proxmox VM node plus Raspberry Pi tap sensors with USB adapters. Covers node install on Ubuntu Server + PostgreSQL, the 2.4/5 GHz band-split sensor strategy, out-of-tree DKMS driver fixes for adapter chipsets that crash under channel hopping, and alert-tuning heuristics for telling a real rogue AP from RF noise. Detection-only — nzyme does not block wireless traffic.

### 🛡️ [Suricata & Zeek](./suricata+zeek.md)
Wired/network Intrusion Detection **and** Prevention — Suricata for signature-based detection with native inline blocking, Zeek as a complementary protocol-level NSM layer. Covers standalone Suricata install on Debian/Ubuntu (both passive `af-packet` and inline NFQUEUE/bridge patterns), the OPNsense/pfSense built-in package path, rule management, and the validation steps to run before ever flipping on blocking mode.

---

## 🤔 Which Guide Do I Need?

```text
Investigating a rogue access point, evil twin, or deauth attack?
  └─> nzyme_wids.md — this is the wireless domain.

Investigating a C2 beacon, malware signature hit, or protocol anomaly
on the wire?
  └─> suricata+zeek.md — this is the wired/network domain.

Want to actively block malicious traffic, not just alert on it?
  └─> suricata+zeek.md — nzyme is detection-only; Suricata supports IPS.

Building complete coverage from scratch?
  └─> Deploy both. They monitor different layers and don't overlap —
      a wireless rogue AP won't show up in Suricata, and a wired C2
      beacon won't show up in nzyme.
```

---

## 🚀 Deployment Workflow

```text
1. Prerequisites
   └─> Provision hardware/VMs per the per-guide requirements.
   └─> Read the visibility primer in ../log_agg.md.

2. Stand up detection (IDS mode)
   └─> Follow one guide end-to-end — install, configure, validate.
   └─> Run alert-only / detection-only first. Do not enable Suricata's
       IPS/blocking mode until this phase has been observed clean.

3. Tune alerts
   └─> Watch real traffic for at least 1-2 weeks.
   └─> Distinguish real threats from environmental noise / false positives
       (see each guide's alert-triage / common-gotchas section).

4. Extend to prevention (optional, wired only)
   └─> Once validated, enable Suricata's inline/IPS mode.
   └─> Watch closely for the first 24-48 hours for legitimate traffic
       getting dropped.

5. Centralize
   └─> Forward alerts from both domains into a SIEM — see
       ../SIEM/README.md — for correlation across wireless and wired
       events in one place.
```

---

## ⚠️ Security Notes

```text
═══════════════════════════════════════════════════════════════
                    ⚠️ CRITICAL WARNING ⚠️
═══════════════════════════════════════════════════════════════

1. VALIDATE BEFORE BLOCKING
   ► IPS (blocking) mode is an availability risk, not just a
     security control. Always run new detection in alert-only
     mode first and observe real traffic before enabling blocking.

2. THIRD-PARTY "FIXES"
   ► Be cautious of any "fix" that has you replace a project's
     official binaries with a third-party build, especially one
     that has you silence or edit a FAILING TEST to force it to
     pass. That is a red flag for tampered software regardless of
     source, and has no place on a security monitoring appliance.

3. EXPOSURE
   ► IDS/IPS management interfaces (node UIs, firewall web UIs)
     must never be exposed to the internet unauthenticated.

4. AUTHORIZATION
   ► Only deploy sensors/taps on networks you own or are
     explicitly authorized, in writing, to monitor.
═══════════════════════════════════════════════════════════════
```

---

## 🤝 Contributing

Contributions from SOC analysts, wireless security researchers, and detection engineers are welcome.

**What we accept:**
- ✅ Additional platform coverage (e.g. Snort, Kismet, Zenarmor/Sensei)
- ✅ Custom Suricata rules or nzyme alert-tuning heuristics
- ✅ Driver/hardware compatibility updates as adapters and kernels change
- ✅ Real gotchas from an actual build — the more specific, the better

**Guidelines:**
1. Sanitize any real network details (SSIDs, IPs, MACs) before sharing.
2. Document the platform **version** your config was tested against.
3. Submit a PR describing the defensive value.

---

## 📚 Resources

- **nzyme docs:** <https://docs.nzyme.org>
- **Suricata docs:** <https://docs.suricata.io>
- **Zeek docs:** <https://docs.zeek.org>
- **Emerging Threats rules:** <https://rules.emergingthreats.net>
- **NIDS test endpoint:** <http://testmynids.org>
- **MITRE ATT&CK (detection mapping):** <https://attack.mitre.org/>

---

## 🔗 Quick Links

- [⬅️ Incident Response section](../README.md)
- [📥 Log Aggregation primer](../log_agg.md)
- [📊 SIEM Deployment Guides](../SIEM/README.md)
- [🚷 Wireless Intrusion / Rogue AP IR procedure](../network_intrusion.md)
- [🏠 Main Repository](../../README.md)

---

<div align="center">

**🛡️ Visibility is the foundation of defense — deploy these tools ethically and legally.**

*Maintained by [Pacific Northwest Computers (PNWC)](https://github.com/Pnwcomputers)*

</div>

---
[⬅️ Back to Master Index](../../README.md) | [🎯 Role Navigation](../../START_HERE.md) | [Legal Notice](../../LEGAL.md)
