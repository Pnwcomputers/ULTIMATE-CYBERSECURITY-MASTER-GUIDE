# 🚨 Incident Response & Log Aggregation

Welcome to the **Incident Response (IR)** section of the **ULTIMATE-CYBERSECURITY-MASTER-GUIDE**. This branch focuses on **Blue Team operations**: detecting threats, aggregating logs, analyzing artifacts, and standardizing response procedures.

## 🎯 Purpose
This section focuses on **visibility and defense**. It provides the resources to:
* **[Centralize Logs:](/Incident%20Response/log_agg.md)** Ingest data from endpoints, servers, and network devices into a SIEM.
* **[Detect Threats:](/Incident%20Response/SIEM)** Write SIGMA rules and alerts to catch malicious activity generated in the lab.
* **[Analyze Artifacts:](/Incident%20Response/Digital-Forensics)** Perform forensics on memory (RAM) and disk images.
* **[Standardized Response:](/PlayBooks/BlueTeam_IncResp_Enhanced.md)** Use Playbooks to handle incidents (e.g., Phishing, Ransomware) consistently.

## 📂 Directory Contents

### 📊 Log Aggregation & SIEM
* **[ELK Stack (Elastic):](/Pnwcomputers/ULTIMATE-CYBERSECURITY-MASTER-GUIDE/blob/main/Incident%20Response/SIEM/elk_stack.md)** Docker compose files and configs for Elasticsearch, Logstash, and Kibana.
* **[Wazuh:](/Pnwcomputers/ULTIMATE-CYBERSECURITY-MASTER-GUIDE/blob/main/Incident%20Response/SIEM/wazuh.md)** Deployment guides for the Wazuh manager and agent registration.
* **[Splunk:](/Pnwcomputers/ULTIMATE-CYBERSECURITY-MASTER-GUIDE/blob/main/Incident%20Response/SIEM/splunk.md)** Setup for Splunk Free/Enterprise trial and creating indexes.
* **[Graylog:](/Pnwcomputers/ULTIMATE-CYBERSECURITY-MASTER-GUIDE/blob/main/Incident%20Response/SIEM/graylog.md)** Configuration for lightweight log management.

### 👁️ Endpoint Visibility (EDR)
* **Windows [(Sysmon)](/Pnwcomputers/ULTIMATE-CYBERSECURITY-MASTER-GUIDE/blob/main/Incident%20Response/Endpoint-Visibility/Windows/sysmon.md):** Installation scripts and configuration files (e.g., SwiftOnSecurity or Olaf Hartong configs) for granular event tracing.
* **Linux [(Auditd/Syslog)](/Pnwcomputers/ULTIMATE-CYBERSECURITY-MASTER-GUIDE/blob/main/Incident%20Response/Endpoint-Visibility/Linux/auditd_syslog.md):** Hardening logging configurations for Linux servers.
* **[Osquery](/Pnwcomputers/ULTIMATE-CYBERSECURITY-MASTER-GUIDE/blob/main/Incident%20Response/Endpoint-Visibility/Linux/osquery.md):** SQL-powered operating system instrumentation.

### 🕸️ Network Monitoring (NSM)
* **Zeek (Bro):** Scripts for analyzing network traffic logs.
* **Suricata/Snort:** IDS/IPS rule management and implementation.
* **Packet Capture:** Workflows for capturing and analyzing `.pcap` files with Wireshark/TShark.

### 📘 IR Playbooks & SOPs
Step-by-step guides for specific incident types:
* **Malware Outbreak:** Isolation, identification, and eradication steps.
* **[Phishing Analysis:](/Pnwcomputers/ULTIMATE-CYBERSECURITY-MASTER-GUIDE/blob/main/PlayBooks/sop_phising_analysis.md)** Header analysis, attachment detonation, and URL scanning.
* **[Unauthorized Access:](/Pnwcomputers/ULTIMATE-CYBERSECURITY-MASTER-GUIDE/blob/main/PlayBooks/unauth_access.md)** Investigating brute force and impossible travel alerts.

### 🔎 Digital Forensics
* **[Memory Analysis](/Pnwcomputers/ULTIMATE-CYBERSECURITY-MASTER-GUIDE/tree/main/Incident%20Response/Digital-Forensics/Memory):** Cheatsheets for using **Volatility** to analyze RAM dumps.
* **[Disk Forensics](/Pnwcomputers/ULTIMATE-CYBERSECURITY-MASTER-GUIDE/tree/main/Incident%20Response/Digital-Forensics/Disks):** Guides for **Autopsy** and **KAPE** (Kroll Artifact Parser and Extractor).
* **[Live Response](/Pnwcomputers/ULTIMATE-CYBERSECURITY-MASTER-GUIDE/blob/main/Incident%20Response/Digital-Forensics/Live%20Data/live_data_collection.md):** Scripts for gathering volatile data from a compromised host.

## 🚀 Getting Started
1.  **Choose a [SIEM](/Pnwcomputers/ULTIMATE-CYBERSECURITY-MASTER-GUIDE/tree/main/Incident%20Response/SIEM):** Start by deploying a central log server (recommend **Wazuh** or **ELK** for beginners) using the guides in the `SIEM/` folder.
2.  **Deploy [Agents](/Pnwcomputers/ULTIMATE-CYBERSECURITY-MASTER-GUIDE/tree/main/Incident%20Response/Endpoint-Visibility):** Install agents (Sysmon + Winlogbeat, or Wazuh Agent) on your **Homelab** VMs.
3.  **[Generate Noise:](/Pnwcomputers/ULTIMATE-CYBERSECURITY-MASTER-GUIDE/tree/main/PlayBooks)** Run an attack from your Kali box (from the Homelab branch) against a target VM.
4.  **Analyze:** Go to your SIEM dashboard and attempt to trace the attack chain.

## ⚠️ Disclaimer
**Educational Use Only:**
These resources are for learning defensive security and authorized research.
* **Do not** upload sensitive personal data (PII) to public log repositories.
* **Do not** use forensic tools on systems you do not own or have permission to analyze.

---
*Part of the [Pnwcomputers/ULTIMATE-CYBERSECURITY-MASTER-GUIDE](https://github.com/Pnwcomputers/ULTIMATE-CYBERSECURITY-MASTER-GUIDE)*
