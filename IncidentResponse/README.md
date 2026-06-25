# 🚨 Incident Response & Log Aggregation

Welcome to the **Incident Response (IR)** section of the **ULTIMATE-CYBERSECURITY-MASTER-GUIDE**. This branch focuses on **Blue Team operations**: detecting threats, aggregating logs, analyzing artifacts, and standardizing response procedures.

## 🎯 Purpose
This section focuses on **visibility and defense**. It provides the resources to:
* **[Centralize Logs:](/IncidentResponse/log_agg.md)** Ingest data from endpoints, servers, and network devices into a SIEM.
* **[Detect Threats:](/IncidentResponse/SIEM)** Write SIGMA rules and alerts to catch malicious activity generated in the lab.
* **[Analyze Artifacts:](/IncidentResponse/Digital-Forensics)** Perform forensics on memory (RAM) and disk images.
* **[Standardized Response:](/PlayBooks/BlueTeam_IncResp_Enhanced.md)** Use Playbooks to handle incidents (e.g., Phishing, Ransomware) consistently.

## 📂 Directory Contents

### 📊 Log Aggregation & SIEM
* **[ELK Stack (Elastic):](/IncidentResponse/SIEM/elk_stack.md)** Docker compose files and configs for Elasticsearch, Logstash, and Kibana.
* **[Wazuh:](/IncidentResponse/SIEM/wazuh.md)** Deployment guides for the Wazuh manager and agent registration.
* **[Splunk:](/IncidentResponse/SIEM/splunk.md)** Setup for Splunk Free/Enterprise trial and creating indexes.
* **[Graylog:](/IncidentResponse/SIEM/graylog.md)** Configuration for lightweight log management.

### 👁️ Endpoint Visibility (EDR)
* **Windows [(Sysmon)](/IncidentResponse/Endpoint-Visibility/Windows/sysmon.md):** Installation scripts and configuration files (e.g., SwiftOnSecurity or Olaf Hartong configs) for granular event tracing.
* **Linux [(Auditd/Syslog)](/IncidentResponse/Endpoint-Visibility/Linux/auditd_syslog.md):** Hardening logging configurations for Linux servers.
* **[Osquery](/IncidentResponse/Endpoint-Visibility/Linux/osquery.md):** SQL-powered operating system instrumentation.

### 🕸️ Network Monitoring (NSM)
* **Zeek (Bro):** Scripts for analyzing network traffic logs.
* **Suricata/Snort:** IDS/IPS rule management and implementation.
* **Packet Capture:** Workflows for capturing and analyzing `.pcap` files with Wireshark/TShark.

### 📘 IR Playbooks & SOPs
Step-by-step guides for specific incident types:
* **Malware Outbreak:** Isolation, identification, and eradication steps.
* **[Phishing Analysis:](/PlayBooks/sop_phising_analysis.md)** Header analysis, attachment detonation, and URL scanning.
* **[Unauthorized Access:](/PlayBooks/unauth_access.md)** Investigating brute force and impossible travel alerts.
* **[Wireless Intrusion & Unauthorized Network Access:](/IncidentResponse/network_intrusion.md)** Investigating unauthorized access to local or private networks.

### 🔎 Digital Forensics
* **[Memory Analysis](/IncidentResponse/Digital-Forensics/Memory):** Cheatsheets for using **Volatility** to analyze RAM dumps.
* **[Disk Forensics](/IncidentResponse/Digital-Forensics/Disks):** Guides for **Autopsy** and **KAPE** (Kroll Artifact Parser and Extractor).
* **[Live Response](/IncidentResponse/Digital-Forensics/Live%20Data/live_data_collection.md):** Scripts for gathering volatile data from a compromised host.

## 🚀 Getting Started
1.  **Choose a [SIEM](/IncidentResponse/SIEM):** Start by deploying a central log server (recommend **Wazuh** or **ELK** for beginners) using the guides in the `SIEM/` folder.
2.  **Deploy [Agents](/IncidentResponse/Endpoint-Visibility):** Install agents (Sysmon + Winlogbeat, or Wazuh Agent) on your **Homelab** VMs.
3.  **[Generate Noise:](/PlayBooks)** Run an attack from your Kali box (from the Homelab branch) against a target VM.
4.  **Analyze:** Go to your SIEM dashboard and attempt to trace the attack chain.

## ⚠️ Disclaimer
**Educational Use Only:**
These resources are for learning defensive security and authorized research.
* **Do not** upload sensitive personal data (PII) to public log repositories.
* **Do not** use forensic tools on systems you do not own or have permission to analyze.

---
*Part of the [Pnwcomputers/ULTIMATE-CYBERSECURITY-MASTER-GUIDE](https://github.com/Pnwcomputers/ULTIMATE-CYBERSECURITY-MASTER-GUIDE)*
