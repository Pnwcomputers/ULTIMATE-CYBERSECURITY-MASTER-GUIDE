# 📊 SIEM Deployment Guides

<div align="center">

**Self-hosted SIEM build guides — centralize logs, detect threats, and hunt adversaries**

*Part of the [ULTIMATE CYBERSECURITY MASTER GUIDE](../../README.md) · [Incident Response](../README.md) section*

![Blue Team](https://img.shields.io/badge/Operations-Blue_Team-blue?style=for-the-badge)
![SIEM](https://img.shields.io/badge/Tools-SIEM_%7C_XDR-orange?style=for-the-badge)
![Self-Hosted](https://img.shields.io/badge/Deployment-Self--Hosted-green?style=for-the-badge)

</div>

---

## 🎯 Purpose
Index for the SIEM sub-section — self-hosted deployment guides for the four most common security log-aggregation platforms (ELK Stack, Wazuh, Splunk, Graylog), so a blue teamer can pick a platform and stand it up for a homelab or small SOC.

## ⚙️ Function
Links to a full build guide per platform — server prep, Docker/package deployment, firewall rules, Windows/Linux agent enrollment, data inputs, dashboards, and detection rules — plus a comparison table and a decision aid for choosing between them.

## 🏆 Goal
Enable a practitioner to deploy a working SIEM that ingests endpoint, server, and network telemetry and surfaces security-relevant events through dashboards and alerts — without wading through four separate vendor doc sites.

## 📋 When to Use
- Standing up a SIEM or centralized log server from scratch in a homelab or small environment
- Choosing between ELK, Wazuh, Splunk, and Graylog for a given use case
- Enrolling Windows (Winlogbeat/Sysmon) or Linux (Filebeat/auditd) agents into a log pipeline
- Building detection rules and dashboards after telemetry is flowing

---

## 📋 Table of Contents

- [Overview](#overview)
- [Platform Comparison](#platform-comparison)
- [Deployment Guides](#deployment-guides)
- [Which SIEM Should I Choose?](#which-siem-should-i-choose)
- [Deployment Workflow](#deployment-workflow)
- [⚠️ Security, Privacy & Legal Warning](#️-security-privacy--legal-warning)
- [Contributing](#contributing)
- [Resources](#resources)

---

## 🎯 Overview

A **SIEM** (Security Information and Event Management) platform is the central nervous system of a blue-team operation: it ingests logs from endpoints, servers, and network devices, normalizes them, and lets you search, correlate, alert, and hunt across the whole environment.

This sub-section provides **hands-on, self-hosted build guides** for the four platforms you are most likely to run in a homelab or small SOC. Each guide is standalone — server preparation, deployment, firewalling, agent enrollment, and initial detections — and each pins known-good versions so the walkthrough stays internally consistent.

> [!TIP]
> New to log aggregation? Start with the visibility prerequisite in
> [../log_agg.md](../log_agg.md), then pick a platform below. **Wazuh** (all-in-one)
> and **Splunk Free** are the gentlest starting points.

---

## 🗂️ Platform Comparison

| Platform | Guide | Stack / Engine | Deployment Complexity | Best For |
|----------|-------|----------------|-----------------------|----------|
| 🦁 **Wazuh** | **[wazuh.md](./wazuh.md)** | Wazuh manager + OpenSearch/Elasticsearch | 🟡 MEDIUM | Unified SIEM/XDR: detection, FIM, vuln scan & compliance in one tool |
| 🔷 **Splunk** | **[splunk.md](./splunk.md)** | Splunk indexer + Universal Forwarders | 🟢 LOW | Fastest to stand up; SPL search power; Free tier (500 MB/day) |
| 🦌 **ELK Stack** | **[elk_stack.md](./elk_stack.md)** | Elasticsearch + Logstash + Kibana + Beats | 🟡 MEDIUM | Maximum flexibility and custom dashboards/pipelines |
| 🟢 **Graylog** | **[graylog.md](./graylog.md)** | Graylog + MongoDB + OpenSearch | 🟡 MEDIUM | Lightweight, stream-based routing; clean log-management UX |

---

## 📚 Deployment Guides

### 🦁 [Wazuh](./wazuh.md)
Unified **SIEM/XDR** on a single open-source platform. Covers all-in-one install, agent enrollment (Windows/Linux), built-in detection rules, **File Integrity Monitoring (FIM)**, vulnerability detection, active response, and compliance dashboards (PCI-DSS, GDPR, HIPAA, CIS), plus OpenSearch/Elasticsearch integration. The most feature-complete single-package option.

### 🔷 [Splunk](./splunk.md)
Deploys **Splunk Free (500 MB/day)** or Enterprise trial. Covers indexer/search-head install, **Universal Forwarder** setup for Windows/Linux, index and sourcetype design, **SPL** query writing (`stats`, `eval`, `transaction`, `lookup`), Splunk Security Essentials, saved searches/alerts, and BOSS of the SOC (BOTS) training data. Lowest barrier to a first working search.

### 🦌 [ELK Stack](./elk_stack.md)
The classic **Elasticsearch + Logstash + Kibana** stack via Docker Compose. Covers cluster setup, **Beats** deployment (Filebeat/Winlogbeat/Auditbeat), Logstash pipelines, index lifecycle management, Kibana Lens dashboards, Elastic SIEM detection rules, and performance tuning. Most flexible, most assembly required.

### 🟢 [Graylog](./graylog.md)
A lighter-weight log-management platform (**Graylog + MongoDB + OpenSearch**). Covers server setup, GELF/Syslog/Beats **inputs**, **streams and processing pipelines** for routing security logs away from operational noise, alert conditions/notifications, dashboards, and index rotation/retention.

---

## 🤔 Which SIEM Should I Choose?

```text
Want the most in one package (SIEM + EDR + FIM + compliance)?
  └─> Wazuh — single agent, built-in rules, compliance dashboards.

Brand new and want a working search fastest?
  └─> Splunk Free — easiest install, best query language (SPL), 500 MB/day cap.

Want maximum control over ingestion, parsing, and dashboards?
  └─> ELK Stack — most flexible, but you assemble the pieces.

Want lightweight log management with clean stream routing?
  └─> Graylog — gentler on resources than full ELK.
```

> [!NOTE]
> All four are production-capable. For a **homelab first SIEM**, Wazuh or Splunk
> Free get you to value fastest; choose ELK or Graylog when you need custom
> pipelines or want to learn the Elastic/OpenSearch ecosystem directly.

---

## 🚀 Deployment Workflow

```text
1. Prerequisites
   └─> Provision a VM (see the per-guide sizing; SIEMs are RAM-hungry).
   └─> Read the visibility primer in ../log_agg.md.

2. Stand up the platform
   └─> Follow one guide end-to-end (server prep → deploy → firewall).

3. Enroll agents
   └─> Windows: Winlogbeat + Sysmon.   Linux: Filebeat + auditd (or Wazuh agent).
   └─> Confirm events are indexing in the dashboard.

4. Detect & hunt
   └─> Add detection rules / saved searches; generate test attacks from a lab
       VM and trace the chain. Pair with the IR playbooks in ../../PlayBooks/.
```

See also endpoint instrumentation: [Osquery](../Endpoint-Visibility/Linux/osquery.md) for SQL-based host telemetry that feeds any of these platforms.

---

## ⚠️ Security, Privacy & Legal Warning

```text
═══════════════════════════════════════════════════════════════
                    ⚠️  BLUE-TEAM DATA HANDLING  ⚠️
═══════════════════════════════════════════════════════════════

SIEMs aggregate highly sensitive data. Operate them responsibly.

1. DATA PRIVACY & COMPLIANCE (PII/PHI)
   ► Logs routinely capture credentials, PII, and PHI.
   ► Never upload real organizational logs to public repos or sandboxes.
   ► Sanitize/anonymize before sharing for educational purposes.
   ► Mishandling can breach GDPR, HIPAA, CCPA, and PCI-DSS.

2. AUTHORIZATION
   ► Only deploy agents/forwarders on systems you own or are explicitly
     authorized (in writing) to monitor. Covert monitoring can be construed
     as unlawful interception/wiretapping.

3. EXPOSURE
   ► SIEM web UIs and Elasticsearch/OpenSearch APIs must never be exposed to
     the internet unauthenticated — follow the firewall steps in each guide.
═══════════════════════════════════════════════════════════════
```

---

## 🤝 Contributing

Contributions from SOC analysts and detection engineers are welcome.

**What we accept:**
- ✅ Detection content (SIGMA rules, SPL, KQL, Elastic/OpenSearch queries)
- ✅ Parser/pipeline configs (Logstash, Graylog pipelines, Wazuh decoders)
- ✅ Dashboards and hardening/tuning tips
- ✅ Version-compatibility updates as platforms release new majors

**Guidelines:**
1. Sanitize any sample logs of real PII/credentials.
2. Document the platform **version** your config was tested against.
3. Submit a PR describing the defensive value.

---

## 📚 Resources

- **Sigma (detection rules):** <https://github.com/SigmaHQ/sigma>
- **Wazuh docs:** <https://documentation.wazuh.com/>
- **Elastic Security docs:** <https://www.elastic.co/guide/en/security/current/index.html>
- **Splunk Docs & SPL reference:** <https://docs.splunk.com/>
- **Graylog docs:** <https://go2docs.graylog.org/>
- **MITRE ATT&CK (detection mapping):** <https://attack.mitre.org/>

---

## 🔗 Quick Links

- [⬅️ Incident Response section](../README.md)
- [📥 Log Aggregation primer](../log_agg.md)
- [👁️ Osquery endpoint visibility](../Endpoint-Visibility/Linux/osquery.md)
- [📘 Blue Team Playbooks](../../PlayBooks/README.md)
- [📖 Glossary](../../GLOSSARY.md) (SIEM, EDR, IoC, SOAR, Sigma…)
- [🏠 Main Repository](../../README.md)

---

<div align="center">

**🛡️ Visibility is the foundation of defense — deploy these tools ethically and legally.**

*Maintained by [Pacific Northwest Computers (PNWC)](https://github.com/Pnwcomputers)*

</div>

---
[⬅️ Back to Master Index](../../README.md) | [🎯 Role Navigation](../../START_HERE.md) | [Legal Notice](../../LEGAL.md)
