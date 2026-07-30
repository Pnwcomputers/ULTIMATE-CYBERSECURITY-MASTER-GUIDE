# 👁️ Endpoint Visibility (EDR / Telemetry)

<div align="center">

**Host-level instrumentation — turn endpoints into rich telemetry sources for detection and hunting**

*Part of the [ULTIMATE CYBERSECURITY MASTER GUIDE](../../README.md) · [Incident Response](../README.md) section*

![Blue Team](https://img.shields.io/badge/Operations-Blue_Team-blue?style=for-the-badge)
![Telemetry](https://img.shields.io/badge/Focus-Endpoint_Telemetry-orange?style=for-the-badge)
![Windows | Linux](https://img.shields.io/badge/Platforms-Windows_%7C_Linux-green?style=for-the-badge)

</div>

---

## 🎯 Purpose
Index for the Endpoint Visibility sub-section — deployment and configuration guides for the host-level instrumentation that feeds a SIEM: Windows Sysmon, Linux auditd/syslog, and cross-platform Osquery.

## ⚙️ Function
Links to a guide per instrumentation source — installation, configuration, the key events/queries that matter for detection, and how to forward the resulting telemetry into a SIEM.

## 🏆 Goal
Enable a defender to instrument Windows and Linux hosts so that process, network, file, and authentication activity is captured with enough fidelity to detect and reconstruct an attack.

## 📋 When to Use
- Standing up endpoint telemetry before (or alongside) a [SIEM](../SIEM/README.md)
- Deciding what to log on Windows (Sysmon) vs Linux (auditd) hosts
- Adding SQL-based, on-demand host inspection with Osquery for threat hunting
- Tuning event volume so detections fire without drowning the SIEM in noise

---

## 📋 Table of Contents

- [Overview](#overview)
- [Instrumentation Sources](#instrumentation-sources)
- [Deployment Guides](#deployment-guides)
- [Deployment Workflow](#deployment-workflow)
- [⚠️ Monitoring, Consent & Legal Warning](#️-monitoring-consent--legal-warning)
- [Contributing](#contributing)
- [Resources](#resources)

---

## 🎯 Overview

A SIEM is only as good as the telemetry it ingests. **Endpoint visibility** is the practice of instrumenting hosts so that security-relevant activity — process creation, network connections, file writes, image loads, logons — is recorded in a form you can search and alert on.

This sub-section covers the three sources that do most of the heavy lifting in a homelab or small SOC. They are complementary: Sysmon and auditd provide **continuous event streams**, while Osquery provides **on-demand, point-in-time inspection** of host state.

> [!TIP]
> Deploy an event stream first (Sysmon on Windows, auditd on Linux), forward it
> to your [SIEM](../SIEM/README.md), then layer Osquery on top for interactive
> hunting.

---

## 🗂️ Instrumentation Sources

| Source | Guide | Platform | Model | Best For |
|--------|-------|----------|-------|----------|
| 🪟 **Sysmon** | **[Windows/sysmon.md](./Windows/sysmon.md)** | Windows | Continuous event stream | Rich process/network/file/DNS tracing |
| 🐧 **Auditd / Syslog** | **[Linux/auditd_syslog.md](./Linux/auditd_syslog.md)** | Linux | Continuous event stream | Kernel-level syscall & file/session auditing |
| 🔎 **Osquery** | **[Linux/osquery.md](./Linux/osquery.md)** | Cross-platform | On-demand SQL queries | Interactive threat hunting & host state |

---

## 📚 Deployment Guides

### 🪟 [Windows Sysmon](./Windows/sysmon.md)
Deploy and configure **Sysmon** with community configs (SwiftOnSecurity, Olaf Hartong). Covers install/update, the configuration XML structure, and the critical event IDs — **1** (process create), **3** (network), **7** (image load), **8** (CreateRemoteThread), **10** (process access), **11** (file create), **22** (DNS) — plus hashing, SIEM forwarding, and a detection use case per event type. The single highest-value Windows telemetry source.

### 🐧 [Linux Auditd & Syslog](./Linux/auditd_syslog.md)
Harden Linux logging with **auditd** and **rsyslog/syslog-ng**. Covers auditd rule syntax (syscall auditing, file-access watches, user-session tracking), pre-built rule sets (STIG, CIS), log forwarding to a SIEM, parsing with `ausearch`/`aureport`, and common detection use cases.

### 🔎 [Osquery](./Linux/osquery.md)
Instrument hosts as a **SQL-queryable** surface. Covers installation (with the modern `signed-by` apt keyring), configuration, and queries for proactive threat hunting and monitoring — ideal for asking ad-hoc questions ("which processes have a deleted binary on disk?") across a fleet.

---

## 🚀 Deployment Workflow

```text
1. Instrument
   └─> Windows: install Sysmon with a curated config (Olaf Hartong / SwiftOnSecurity).
   └─> Linux:   load an auditd rule set (CIS/STIG) + configure rsyslog forwarding.

2. Forward
   └─> Ship events to your SIEM (Winlogbeat/Filebeat, or the SIEM's own agent).
   └─> Confirm events index correctly — see ../SIEM/README.md.

3. Hunt on demand
   └─> Add Osquery for interactive, SQL-based host inspection.

4. Tune
   └─> Trim noisy events; keep the high-signal IDs. Map detections to MITRE ATT&CK.
```

---

## ⚠️ Monitoring, Consent & Legal Warning

```text
═══════════════════════════════════════════════════════════════
              ⚠️  DEPLOY TELEMETRY ONLY WITH AUTHORIZATION  ⚠️
═══════════════════════════════════════════════════════════════

► Only install agents/telemetry on systems you own or are explicitly
  authorized (in writing) to monitor. Endpoint monitoring can capture
  keystrokes, commands, and personal data.

► Covert monitoring of users/employees without proper notice can violate
  wiretap/interception, privacy, and labor laws — coordinate with legal/HR.

► Forwarded logs often contain PII/credentials; protect the SIEM and
  transport (TLS) accordingly, and follow GDPR/HIPAA/CCPA where applicable.
═══════════════════════════════════════════════════════════════
```

---

## 🤝 Contributing

Contributions from detection engineers and SOC analysts are welcome.

**What we accept:**
- ✅ Sysmon config tweaks and per-event-ID detection notes
- ✅ auditd rule sets and rsyslog/syslog-ng forwarding configs
- ✅ Useful Osquery packs/queries for hunting
- ✅ SIEM field-mapping notes

**Guidelines:**
1. Sanitize sample events of real PII/credentials.
2. Note the OS/tool **version** tested.
3. Describe the detection value in your PR.

---

## 📚 Resources

- **Sysmon (Sysinternals):** <https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon>
- **sysmon-modular (Olaf Hartong):** <https://github.com/olafhartong/sysmon-modular>
- **auditd / Linux Audit:** <https://github.com/linux-audit/audit-documentation/wiki>
- **Osquery docs:** <https://osquery.readthedocs.io/>
- **MITRE ATT&CK (data sources):** <https://attack.mitre.org/datasources/>

---

## 🔗 Quick Links

- [⬅️ Incident Response section](../README.md)
- [📊 SIEM deployment guides](../SIEM/README.md)
- [🔎 Digital Forensics](../Digital-Forensics/README.md)
- [📥 Log Aggregation primer](../log_agg.md)
- [📖 Glossary](../../GLOSSARY.md) (EDR, IoC, TTP, Sysmon…)
- [🏠 Main Repository](../../README.md)

---

<div align="center">

**🛡️ Visibility is the foundation of defense — instrument hosts ethically and legally.**

*Maintained by [Pacific Northwest Computers (PNWC)](https://github.com/Pnwcomputers)*

</div>

---
[⬅️ Back to Master Index](../../README.md) | [🎯 Role Navigation](../../START_HERE.md) | [Legal Notice](../../LEGAL.md)
