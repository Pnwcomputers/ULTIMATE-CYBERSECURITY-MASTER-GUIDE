# Incident Response Playbook (Enhanced)

## 1. Purpose & Scope

### Purpose:

Define standardized, repeatable processes—aligned to NIST SP 800-61 r2 and ISO/IEC 27035—for detecting, analyzing, containing, and recovering from security incidents.

### Scope:

Covers any incident impacting on-prem or cloud systems—including malware, data exfiltration, unauthorized access, DoS, insider threats, and supply-chain compromises—across all corporate assets (endpoints, servers, network devices, cloud workloads, OT) under 24×7 monitoring.

---

## 2. Roles & Responsibilities

| Role | Responsibilities |
|------|-----------------|
| **Incident Response Lead** | Coordinates IR per NIST SP 800-61; liaises with C-Suite, Legal, and PR. |
| **SOC Analyst I** | Monitors Splunk ES / QRadar / Elastic Security; performs initial triage & escalation. |
| **SOC Analyst II / Threat Hunter** | Deep-dive investigations with MITRE ATT&CK mapping; proactive hunting via Velociraptor / RedELK. |
| **Forensic Analyst** | Collects/analyzes artifacts with FTK Imager, Magnet RAM Capture, OSForensics. |
| **Malware Analyst** | Reverse-engineers binaries using Ghidra, IDA Pro; produces YARA rules & IOCs. |
| **Remediation Engineer** | Implements containment & remediation with Carbon Black EDR, Microsoft Defender. |
| **Communications Officer** | Manages notifications (in-house Legal counsel, PR agency, external regulators). |

---

## 3. Preparation

### 1. Asset Inventory
- CMDB (ServiceNow) tracking all servers, endpoints, applications, network segments, business owners.

### 2. Baseline & Logging
- **SIEM:** Splunk Enterprise Security, IBM QRadar, or Elastic Security with ≥ 90 days retention.
- **EDR:** CrowdStrike Falcon, Microsoft Defender for Endpoint.
- **Network IDS/IPS:** Suricata and Zeek deployed on Security Onion or Corelight.

### 3. Tooling & Access
- Ensure IR team has privileged SSH/RDP, admin accounts on forensic workstations, evidence locker (Azure Blob/SharePoint), VPN jump boxes, and ticketing (ServiceNow/Jira Service Desk).

### Escalation Contacts:

| Stakeholder | Name / Team | Email | Phone |
|-------------|-------------|-------|-------|
| Chief Information Security Officer (CISO) | Jane Doe | j.doe@company.com | +1 555-1234 |
| Legal Counsel | Acme Law LLP | security@acmelaw.com | +1 555-2345 |
| PR Agency | BrightPoint Communications | press@brightpoint.com | +1 555-3456 |
| IT Operations Manager | John Smith | j.smith@company.com | +1 555-4567 |
| External Law Enforcement Liaison | FBI Cyber Division (Seattle) | sfoc@ic.fbi.gov | +1 206-622-0460 |

### 4. Playbook Testing
- Quarterly tabletop exercises following NIST SP 800-84: phishing, ransomware, insider threat, DDoS scenarios.

---

## 4. Identification

### 4.1 Alert Triage

**Dashboard Prioritization:**
- Splunk ES risk-based alerts, QRadar Offense severity, Elastic Security DETECTION_ENGINE_RULE severity.
- Investigate all High/Critical alerts within 15 minutes (per CIS Control 19).

**Common SIGs:**
- Windows Event 4625 spikes (failed logons)
- Creation of new/unsigned services or scheduled tasks (Sysmon Event 1/7)
- Outbound to known C2 IPs/domains (using MISP/AlienVault OTX feeds)

### 4.2 Initial Data Collection

**Endpoint:**
- `pslist`, `netstat -anob`, Autoruns, Sysinternals Procmon.
- Memory snapshot with FTK Imager or Magnet RAM Capture.

**Network:**
- PCAP export via Zeek (`zeek-cut`) or Security Onion's CapME.
- Query Suricata EVE JSON logs for matching `sid` or `threshold`.

---

## 5. Containment

### 5.1 Short-Term

**Isolate Host:**
- Use CrowdStrike Falcon quarantine or disable NIC via Microsoft Defender quarantine.

**Block IOCs:**
- Push Palo Alto Networks/Checkpoint firewall rules or EDR blocklists for malicious IPs/domains.

### 5.2 Long-Term

**Credentials:**
- Reset impacted AD accounts via Microsoft Entra ID, enforce Azure MFA.

**Patching:**
- Emergency patch management via WSUS/Intune or Red Hat Satellite for Linux.

---

## 6. Eradication

**Persistence Removal:**
- Remove malicious services, scheduled tasks, WMI filters; clean registry Run keys.

**Forensic Validation:**
- Re-scan with updated CrowdStrike/Defender signatures; verify absence of artifacts in `%ProgramData%`, `HKLM\Software\Microsoft\Windows\CurrentVersion\Run`.

---

## 7. Recovery

**System Restoration:**
- Restore from Veeam or Rubrik backups tagged "known-good."

**Integrity Check:**
- Verify executable hashes against internal repository (Artifactory) or VirusTotal.

**Functional Testing:**
- Confirm service availability (Nagios/Icinga), AD logon tests, and user acceptance.

**Monitoring Enhancement:**
- Update Splunk correlation searches or Elastic detection rules to cover observed TTPs.

---

## 8. Lessons Learned

1. **After-Action Review (AAR):**
   - Convene within 7 days of closure; follow ISO/IEC 27035-2 guidelines.

2. **Documentation:**
   - Record timeline, root cause, detection/respond gaps, and assigned remediation action items.

3. **Playbook Updates:**
   - Version control in Git; tag updates with incident ID.

4. **Training:**
   - SOC refresher on new TTPs—e.g., host-based hunting labs via RangeForce or Cyberbit.

---

## 9. Appendices

### A. Sample SIEM Queries

**Failed Logon Spike (Splunk ES):**

```splunk
index=wineventlog sourcetype=WinEventLog:Security EventCode=4625
| bin _time span=5m
| stats count by _time, user
| where count > 50
```

**DNS Beacon Detection (Elastic Security):**

```json
GET /logs-dns-*/_search
{
  "query": {
    "bool": {
      "must": [
        { "term": { "dns.question.name": "suspicious-domain.com" } }
      ]
    }
  }
}
```

### B. Evidence Collection Checklist

- ☐ Hostname, IP, OS version (via `systeminfo` / `uname -a`)
- ☐ Running processes & services (`tasklist` / `ps aux`)
- ☐ Network connections & firewall rules (`netstat -an`, `iptables -L`)
- ☐ Volatile data: memory dump, pagefile, swap
- ☐ Non-volatile data: event logs, Windows registry hives, application logs

---

## Next Steps:

1. Replace sample contacts with your internal teams.
2. Integrate into ServiceNow/Jira workflows with checklists and automations.
3. Review and rehearse quarterly to ensure readiness.
