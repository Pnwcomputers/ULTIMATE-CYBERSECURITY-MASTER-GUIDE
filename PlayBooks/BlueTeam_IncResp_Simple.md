# Incident Response Playbook

## 1. Purpose & Scope

### Purpose:

Define standardized, repeatable processes for detecting, analyzing, containing, and recovering from security incidents.

### Scope:

Covers any incident impacting on-premise or cloud systems—including malware infections, data exfiltration, unauthorized access, denial-of-service, insider threats, and supply-chain compromises—across all corporate assets (endpoints, servers, network devices, cloud workloads, OT) under 24×7 monitoring.

---

## 2. Roles & Responsibilities

| Role | Responsibilities |
|------|-----------------|
| **Incident Response Lead** | Coordinates IR activities; liaises with management and execs. |
| **SOC Analyst I** | Monitors alerts; performs initial triage and escalates. |
| **SOC Analyst II / Threat Hunter** | Deep-dive investigations; proactive hunting and hypothesis testing. |
| **Forensic Analyst** | Collects and analyzes endpoint & network artifacts. |
| **Malware Analyst** | Reverse-engineers suspicious binaries; produces IOCs. |
| **Remediation Engineer** | Implements containment, eradication, and recovery actions. |
| **Communications Officer** | Manages internal/external notifications (legal, PR, stakeholders). |

---

## 3. Preparation

### 1. Asset Inventory
- Maintain an up-to-date CMDB of critical systems, endpoints, applications, network segments, and owners.

### 2. Baseline & Logging
- Ensure all servers/endpoints forward logs (Syslog, Windows Events) to your SIEM (Splunk, Elastic) with ≥ 90 days retention.
- Deploy host-based EDR (CrowdStrike, SentinelOne) and network IDS/IPS (Suricata, Zeek).

### 3. Tooling & Access
- Validate admin access to forensic workstations, evidence lockers, VPN jump boxes, and ticketing system.
- Predefine escalation contacts (legal, PR, executive).

### 4. Playbook Testing
- Schedule quarterly tabletop exercises covering phishing, ransomware, insider threats, and DDoS.

---

## 4. Identification

### 4.1 Alert Triage

**Dashboard Prioritization:**
- Sort by risk score and asset criticality; investigate all High/Critical alerts within 15 minutes.

**Common SIGs:**
- Unusual authentication bursts (EventCode 4625 spikes)
- New/unsigned services or scheduled tasks
- Outbound connects to known C2 IPs/domains

### 4.2 Initial Data Collection

**Endpoint:**
- Process listing (`pslist`), network (`netstat -anob`), autoruns.
- Snapshot memory (FTK Imager, Magnet RAM Capture).

**Network:**
- Export PCAPs from Zeek for the relevant timeframe.
- Query Suricata EVE JSON logs for matching signatures.

---

## 5. Containment

### 5.1 Short-Term

- **Isolate Host:** Disable network adapter or move to quarantine VLAN via EDR.
- **Block IOCs:** Push firewall rules or EDR blocklists for malicious IPs/domains.

### 5.2 Long-Term

- **Credentials:** Reset impacted accounts; enforce MFA everywhere.
- **Patching:** Apply emergency OS/app patches if exploitation leveraged a known CVE.

---

## 6. Eradication

- **Persistence Removal:** Identify and delete malicious services, scheduled tasks, registry run-keys.
- **Forensic Validation:** Re-scan endpoints with updated signatures and confirm no malware artifacts remain (registry, startup folders, memory).

---

## 7. Recovery

- **System Restoration:** Restore from known-good backups where needed.
- **Integrity Check:** Validate checksums (e.g., `sha256sum`) of critical binaries.
- **Functional Testing:** Ensure services start, user logons succeed, and network connectivity is normal.
- **Monitoring Enhancement:** Tune SIEM correlation rules to detect similar TTPs in future.

---

## 8. Lessons Learned

1. **After-Action Review (AAR):** Convene within one week of incident closure.
2. **Documentation:** Record timeline, root cause, detection gaps, and action items.
3. **Playbook Updates:** Incorporate new detection rules, tooling changes, and threshold adjustments.
4. **Training:** Deliver focused SOC/IT training on newly observed TTPs.

---

## 9. Appendices

### A. Sample SIEM Queries

**Failed Logon Spike (Splunk):**

```splunk
index=windows EventCode=4625
| timechart span=5m count by Account_Name
| where count > 50
```

**DNS Beacon Detection (Elastic DSL):**

```json
GET /_search
{
  "query": {
    "bool": {
      "must": [
        { "match": { "dns.question.name": "suspicious-domain.com" } }
      ]
    }
  }
}
```

### B. Evidence Collection Checklist

- ☐ Hostname, IP, OS version
- ☐ Running processes & services
- ☐ Network connections & firewall rules
- ☐ Volatile data (memory, swap)
- ☐ Non-volatile data (logs, registry hives)

---

## Next Steps:

1. Replace placeholders with your tool names, contact lists, and policies.
2. Integrate into your ticketing workflows (e.g., ServiceNow) and SOC runbooks.
3. Review quarterly and after every incident to keep the playbook current.
