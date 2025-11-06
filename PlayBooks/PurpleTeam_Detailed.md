# Purple Team Playbook (Detailed)

## Purpose & Scope

### Purpose:

Bring Red-Team attack techniques and Blue-Team detections together in repeatable, measurable exercises—leveraging Python, PowerShell, Batch, and dedicated frameworks—to harden your environment against real adversaries.

### Scope:

All enterprise platforms (Windows, Linux, macOS, cloud), tooling (SIEM, EDR, network sensors), and controls (firewalls, IAM, email gateways) under 24×7 monitoring. Exercises span initial access, persistence, lateral movement, data exfiltration, and cleanup phases.

---

## Key Tools & Frameworks

| Category | Tool / Framework | Purpose |
|----------|-----------------|---------|
| **Attack Simulation** | Atomic Red Team, Caldera, Metasploit | MITRE-mapped TTP emulation & orchestration |
| **Detection Engineering** | Sigma, YARA, OSQuery | Cross-platform rule/sig development |
| **Hunting & Visibility** | Velociraptor, CrowdStrike Falcon, Sysmon | Endpoint telemetry & proactive querying |
| **Network Analysis** | Zeek, Suricata, SecurityOnion | Packet capture, IDS/IPS, full-stack monitoring |
| **Collaboration & Tracking** | MITRE Engage, Jira, ServiceNow | Exercise planning, ticketing, and AAR tracking |
| **Lab Automation** | Docker, Vagrant, Ansible, Packer | Build reproducible test environments |
| **Reporting & Metrics** | Splunk Phantom, TheHive, ELK Dashboards | Automated report generation & KPI dashboards |

---

## Process Workflow

### 1. Planning & Scoping
- Select TTPs mapped to your highest-risk ATT&CK techniques
- Define objectives (e.g., "confirm detection of PowerShell obfuscation," "measure DTTR for lateral movement")
- Assign roles: Red-Team Lead, Detection Engineer, SOC Liaison

### 2. Environment Provisioning
- Spin up isolated lab via Vagrant/Docker or full VM infra (Terraform + Ansible)
- Deploy baseline sensor stack (Sysmon, OSQuery, Zeek, Suricata, EDR agent)

### 3. Attack Development
- Craft or customize scripts in Python/PowerShell/Batch
- Integrate with Atomic Red Team or Caldera for orchestration and repeatability

### 4. Execution & Data Collection
- Run attack scripts against lab targets at scheduled times
- Stream logs to SIEM (Splunk/Elastic) and centralize EDR/NDR telemetry

### 5. Detection Validation & Tuning
- Verify existing alerts fire; capture false negatives/positives
- Write or refine Sigma/YARA rules, SIEM correlation searches, EDR detection policies

### 6. Remediation & Hardening
- Apply recommended configuration changes (e.g., enable Script Block Logging, tighten audit policies)
- Automate remediation via Ansible playbooks or Group Policy

### 7. Reporting & Metrics
- Populate dashboards:
  - **Coverage:** Percentage of tested TTPs with working detections
  - **Latency:** Mean Time to Detect (MTTD) and Respond (MTTR)
- Document Exercise Report in Jira/ServiceNow with findings, rules created, and action items

### 8. Iterate & Expand
- Incorporate new TTPs (e.g., DCSync, Kerberoasting)
- Schedule monthly micro-exercises and quarterly full Purple-Team campaigns

---

## Example Playbook Entries

### 🔍 TTP: Obfuscated PowerShell (T1059.001)

| Field | Details |
|-------|---------|
| **Goal** | Validate detection of Base64-encoded, obfuscated PS payload |
| **Attack Method** | Caldera "ps-obfuscation" plugin or custom PowerShell `-EncodedCommand` |
| **Detection Rule** | Sigma rule matching `Process.CommandLine` against `-EncodedCommand` |
| **Hunting Query** | OSQuery: `select * from processes where command LIKE '%EncodedCommand%';` |
| **Result** | Alert fired; correlation search tuned to ignore known-good workflows |

### 🔍 TTP: Lateral Movement via SMB (T1021.002)

| Field | Details |
|-------|---------|
| **Goal** | Measure detection of remote SMB session creation via `Invoke-Command` |
| **Attack Method** | Python script using `pywinrm` or PowerShell `New-PSSession \\host` |
| **Detection Rule** | YARA rule for SMB session opening; SIEM correlation on `EventID=5140` |
| **Hunting Query** | Splunk: `index=wineventlog EventCode=5140` |
| **Result** | Coverage gap found; new rule deployed, tested, and validated |

---

## Advanced Enhancements

### Continuous Integration:
- Integrate your Purple-Team tests into a CI pipeline (GitHub Actions, GitLab CI) to automatically spin up the lab, run scripts, and validate detections on every commit

### Threat Intelligence Feedback:
- Consume real-time IOCs from MISP/OTX; inject them into exercises to simulate evolving adversary behavior

### Automated AAR Generation:
- Use Splunk Phantom or TheHive playbooks to gather logs, screenshots, and rule diff snapshots to auto-generate Post-Exercise Reports

### Kill-Chain Visualization:
- Map each exercise run onto a live MITRE ATT&CK Navigator layer to visually track detection coverage and identify gaps

---

## Collaboration & Governance

### Stakeholder Briefings:
Monthly "Purple Team Sync" with SOC, IR, Engineering, and Risk teams to review metrics and roadmap

### Policy Alignment:
Ensure tests reflect corporate security policies (CIS Benchmarks, NIST 800-53) and regulatory requirements (PCI-DSS, HIPAA)

### Knowledge Base:
Maintain a shared Confluence/Git repo of scripts, detection rules, exercise logs, and remediation guides

---

## Security and Ethical Considerations ⚠️

**IMPORTANT**: These tools are for **authorized security testing only**. Unauthorized use is illegal.

* **Marauder Use:** Get **written permission** before testing any network. Only test networks you own or have explicit authorization to test.
* **Cracking Use:** All cracking attempts (Hashcat) must be done in an **isolated lab environment** against hashes you are authorized to possess.
* **Legal Compliance:** Strictly comply with all local laws and regulations.

**Legal Use Cases:**
* Penetration testing with client authorization.
* Testing your own home or lab network security.
* Security research in isolated lab environments.

---

## Conclusion

With this expanded playbook, you now have a full lifecycle—planning, execution, validation, remediation, and governance—capable of evolving alongside both attacker techniques and your defensive tooling. Let me know if you'd like code snippets for CI integration, sample Sigma rules, or a templated AAR document!
