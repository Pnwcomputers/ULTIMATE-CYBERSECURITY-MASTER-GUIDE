# 🚨 Incident Response & Log Aggregation

## 🎯 Purpose
Index for the Incident Response section - covering blue team operations, log aggregation infrastructure, network intrusion detection and response, DFIR processes, and SIEM integration guides.

## ⚙️ Function
Links to log aggregation and visibility setup (log_agg.md), wireless/network intrusion response procedures (network_intrusion.md), and provides an attack taxonomy, tool ecosystem reference, playbook overview, and SIEM configuration guidance.

## 🏆 Goal
Enable blue team operators to quickly find the right IR procedure, log source configuration, or detection rule for an active or suspected incident.

## 📋 When to Use
- Starting incident response work: find the right playbook or log configuration file
- Setting up a new SIEM or log aggregation infrastructure from scratch
- Responding to a wireless intrusion, rogue AP, or physical plant hack scenario

<div align="center">

**Blue Team operations, threat detection, digital forensics, and standardized response procedures**

*Part of the [ULTIMATE CYBERSECURITY MASTER GUIDE](../README.md)*

[![Blue Team](https://img.shields.io/badge/Operations-Blue_Team-blue?style=for-the-badge&logo=shield)]()
[![DFIR](https://img.shields.io/badge/Framework-DFIR-darkred?style=for-the-badge)]()
[![SIEM](https://img.shields.io/badge/Tools-SIEM_%7C_EDR-orange?style=for-the-badge)]()
[![Forensics](https://img.shields.io/badge/Analysis-Digital_Forensics-green?style=for-the-badge)]()

</div>

---

## 📋 Table of Contents

- [Overview](#overview)
- [Tool & Infrastructure Categories](#tool--infrastructure-categories)
- [Deployment & Operations Workflow](#deployment--operations-workflow)
- [⚠️ CRITICAL Security, Privacy & Legal Warning](#️-critical-security-privacy--legal-warning)
- [Contributing](#contributing)
- [Resources](#resources)

---

## 🎯 Overview

Welcome to the **Incident Response (IR)** and Digital Forensics section. This directory focuses strictly on **visibility, detection, and defense**. It provides the architecture, configurations, and standard operating procedures (SOPs) required to ingest telemetry, hunt for adversaries, and respond to active threats systematically.

**Core Objectives:**
* **[Centralize Logs](/IncidentResponse/log_agg.md):** Ingest data from endpoints, servers, and network devices into a SIEM.
* **[Detect Threats](/IncidentResponse/SIEM):** Write SIGMA rules and custom alerts to catch malicious activity generated in your environment.
* **[Analyze Artifacts](/IncidentResponse/Digital-Forensics):** Perform digital forensics on memory (RAM) and disk images to establish timelines and indicators of compromise (IoCs).
* **[Standardize Response](/PlayBooks/BlueTeam_IncResp_Enhanced.md):** Utilize playbooks to handle specific incidents (e.g., Ransomware, Insider Threat) consistently and thoroughly.

---

## 🗂️ Tool & Infrastructure Categories

### 📊 Log Aggregation & SIEM

Central nervous systems for security telemetry.

| Platform / Guide | Description | Deployment Complexity |
|------------------|-------------|-----------------------|
| **[ELK Stack (Elastic)](/IncidentResponse/SIEM/elk_stack.md)** | Docker compose files and configs for Elasticsearch, Logstash, and Kibana. | 🟡 MEDIUM |
| **[Wazuh](/IncidentResponse/SIEM/wazuh.md)** | Deployment guides for the Wazuh manager, agent registration, and rule tuning. | 🟡 MEDIUM |
| **[Splunk](/IncidentResponse/SIEM/splunk.md)** | Setup for Splunk Free/Enterprise trial and creating optimal data indexes. | 🟢 LOW |
| **[Graylog](/IncidentResponse/SIEM/graylog.md)** | Configuration for lightweight, scalable log management and parsing. | 🟡 MEDIUM |

---

### 👁️ Endpoint Visibility (EDR)

Instrumentation for host-level telemetry.

| Tool / OS | Description | Integration |
|-----------|-------------|-------------|
| **[Windows (Sysmon)](/IncidentResponse/Endpoint-Visibility/Windows/sysmon.md)** | Installation scripts and configs (SwiftOnSecurity/Olaf Hartong) for granular event tracing (Process creation, network connections). | High |
| **[Linux (Auditd/Syslog)](/IncidentResponse/Endpoint-Visibility/Linux/auditd_syslog.md)** | Hardening logging configurations for Linux servers and standardizing syslog output. | Medium |
| **[Osquery](/IncidentResponse/Endpoint-Visibility/Linux/osquery.md)** | SQL-powered operating system instrumentation for proactive threat hunting. | High |

---

### 🕸️ Network Security Monitoring (NSM)

Visibility into East/West and North/South traffic flows.

| Technology | Focus Area | Common Tools |
|------------|------------|--------------|
| **Zeek (Bro)** | Connection logging, protocol analysis, and metadata extraction. | Zeek, RITA |
| **IDS / IPS** | Signature-based network threat detection and prevention. | Suricata, Snort |
| **Packet Capture** | Workflows for capturing and analyzing raw `.pcap` files. | Wireshark, TShark, TCPDump |

---

### 📘 IR Playbooks & SOPs

Step-by-step containment, eradication, and recovery guides.

| Playbook | Scenario | Focus |
|----------|----------|-------|
| **Malware Outbreak** | Ransomware / Worms | Isolation, identification, and eradication steps. |
| **[Phishing Analysis](/PlayBooks/sop_phishing_analysis.md)** | Malicious Emails | Header analysis, attachment detonation, URL scanning. |
| **[Unauthorized Access](/PlayBooks/unauth_access.md)** | Compromised Credentials | Investigating brute force and impossible travel alerts. |
| **[Wireless Intrusion](/IncidentResponse/network_intrusion.md)** | Rogue APs / Network Breaches | Investigating unauthorized access to local/private networks. |

---

### 🔎 Digital Forensics

Post-incident artifact extraction and timeline reconstruction.

| Domain | Description | Primary Tools |
|--------|-------------|---------------|
| **[Memory Analysis](/IncidentResponse/Digital-Forensics/Memory)** | Cheatsheets for extracting malware, processes, and keys from RAM. | Volatility, Rekall |
| **[Disk Forensics](/IncidentResponse/Digital-Forensics/Disks)** | Guides for parsing NTFS artifacts, registry hives, and event logs. | Autopsy, KAPE, FTK Imager |
| **[Live Response](/IncidentResponse/Digital-Forensics/LiveData/live_data_collection.md)** | Scripts for gathering volatile data safely from a compromised host. | KAPE, Custom Scripts |

---

## 🚀 Deployment & Operations Workflow

### Building the Lab & Testing

```text
1. Infrastructure Standup:
   └─> Choose a SIEM (Wazuh or ELK recommended for beginners).
   └─> Deploy the centralized log server using the guides in `/SIEM/`.

2. Telemetry Ingestion:
   └─> Deploy Agents (Sysmon + Winlogbeat, or Wazuh Agent) to your Homelab VMs.
   └─> Verify logs are indexing correctly in your SIEM dashboard.

3. Attack Simulation (Red -> Blue):
   └─> Generate noise! Run an attack from your Kali machine against a target VM.
   └─> Execute a reverse shell, run a port scan, or drop an EICAR file.

4. Threat Hunting & Analysis:
   └─> Pivot to your SIEM. 
   └─> Write queries to trace the attack chain (Initial Access -> Execution -> C2).
   └─> Trigger alerts and follow the corresponding IR Playbook to "respond."
```

---

## ⚠️ CRITICAL Security, Privacy & Legal Warning

### 🔴 BLUE TEAM LEGAL & ETHICAL GUIDELINES

```
═══════════════════════════════════════════════════════════════
                    ⚠️ CRITICAL WARNING ⚠️
═══════════════════════════════════════════════════════════════

While this section focuses on DEFENSE, mishandling incident data, logs, 
and malware carries significant legal, regulatory, and operational risks.

1. DATA PRIVACY & COMPLIANCE (PII/PHI)
   ► Log aggregators often capture highly sensitive data (Passwords, PII, PHI).
   ► DO NOT upload sensitive organizational data to public log repositories.
   ► Violating data handling procedures can breach GDPR, HIPAA, CCPA, and PCI-DSS.
   ► Always anonymize or sanitize logs before sharing for educational purposes.

2. MALWARE HANDLING
   ► Analyzing live malware (Phishing attachments, Ransomware binaries) is dangerous.
   ► NEVER detonate malware on a production or host-connected network.
   ► DO NOT upload proprietary, targeted malware to public sandboxes (e.g., VirusTotal) 
     as it alerts the attacker that they have been detected.
   ► Only analyze malware in strictly isolated, host-only virtual environments.

3. CHAIN OF CUSTODY (For Professional Responders)
   ► If analyzing a real-world breach that may involve law enforcement:
   ► DO NOT use standard live-response scripts that overwrite volatile memory.
   ► Follow strict Chain of Custody (CoC) procedures.
   ► Ensure write-blockers are used for disk imaging.
   ► Mishandling evidence renders it inadmissible in court.

4. EDUCATIONAL USE ONLY
   ► These resources are for learning defensive security in authorized environments.
   ► DO NOT use forensic tools on systems you do not own or lack explicit 
     written permission to analyze. (Deploying EDR/Forensic tools without consent 
     can be legally construed as unauthorized access/wiretapping).

═══════════════════════════════════════════════════════════════
```

---

## 🤝 Contributing

We welcome contributions from SOC Analysts, Threat Hunters, and Incident Responders. 

**What We Accept:**
- ✅ Custom SIGMA rules or SIEM queries (Splunk SPL, KQL, Elastic Lucene).
- ✅ DFIR cheatsheets and artifact mapping (e.g., Windows Registry persistence locations).
- ✅ Playbooks for emerging threats.
- ✅ Hardening configs for endpoints.

**Submission Guidelines:**
1. Fork the repository.
2. Ensure any shared logs or PCAPs are completely sanitized of real-world PII/credentials.
3. Document prerequisites and tool versions for SIEM configurations.
4. Submit a Pull Request with a clear description of the defensive value.

---

## 📚 Resources

### Frameworks & Methodologies
- **NIST SP 800-61 Rev. 2:** [Computer Security Incident Handling Guide](https://csrc.nist.gov/publications/detail/sp/800-61/rev-2/final)
- **MITRE ATT&CK:** [Adversary Tactics, Techniques, and Common Knowledge](https://attack.mitre.org/)
- **SANS IR Poster:** [Incident Response & Digital Forensics](https://www.sans.org/posters/)

### Tools & Communities
- **Sigma Rules:** [Generic Signature Format for SIEM Systems](https://github.com/SigmaHQ/sigma)
- **The DFIR Report:** [Real-world attack timelines and artifact analysis](https://thedfirreport.com/)
- **Blue Team Labs Online:** [BTLO Defensive Cyber Range](https://blueteamlabs.online/)

---

## 🔗 Quick Links

### Internal Links
- [🏠 Main Repository](../README.md)
- [🎯 START HERE Guide](../START_HERE.md)
- [💻 Cybersecurity Master Guide](../ultimate_cybersecurity_master_guide.md)
- [🏠 Homelab Setup](../Homelab/README.md)
- [✅ Security Checklists](../Checklists/README.md)
- [📚 Documentation](../Documentation/README.md)
- [🔒 OPSEC Guidelines](../OPSEC/README.md)

---

## 📊 Repository Statistics

```
📁 Categories: SIEM, EDR, NSM, Forensics, Playbooks
🔍 Focus: Threat Hunting, Log Aggregation, Artifact Analysis
💻 Core Platforms: Windows, Linux, ELK, Wazuh, Splunk
🔄 Last Updated: June 2026
👥 Maintained by: Pacific Northwest Computers (PNWC)
📝 Status: Active - Defensive Operations Ready
```

---

<div align="center">

## Related Files
- [log_agg.md](log_agg.md) - Log aggregation and SIEM feed configuration (the visibility prerequisite for all IR work)
- [network_intrusion.md](network_intrusion.md) - Wireless intrusion / rogue AP / plant hack IR procedure (Scenario IR-NET-001)
- [../Documentation/wireshark.md](../Documentation/wireshark.md) - Wireshark filters for the PCAP analysis referenced in network_intrusion.md
- [../Documentation/bjorn_pi.md](../Documentation/bjorn_pi.md) - Bjorn Pi is exactly the kind of "plant" device described in IR-NET-001
- [../Homelab/](../Homelab/) - Homelab lab setup where this IR infrastructure would be deployed and tested

---

**🛡️ DEFEND FORWARD. HUNT TIRELESSLY. 🛡️**

*Visibility is the foundation of security. You cannot defend against what you cannot see.*

**Repository**: [ULTIMATE CYBERSECURITY MASTER GUIDE](https://github.com/Pnwcomputers/ULTIMATE-CYBERSECURITY-MASTER-GUIDE)

**Maintained by**: [Pacific Northwest Computers](https://github.com/Pnwcomputers)

---

⭐ **Star this repo if you find it useful for your Blue Team operations!** ⭐

</div>
