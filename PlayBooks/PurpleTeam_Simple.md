# Purple Team Playbook (Simple)

This playbook is designed to be modular and expandable - so you can plug in new techniques, scripts, and lessons learned over time. It's practical and organized for your own lab or for professional purple team exercises.

**Your living guide for designing, executing, and improving detection and defense.**

---

## 🎯 Purpose

Integrate offensive and defensive techniques to continuously test, measure, and improve detection and response capabilities.

## ⚙️ Function

A three-role, lab-first exercise cycle (Red Operator attacks → Blue Analyst monitors/tunes → Purple Facilitator coordinates and documents) run against a defined lab environment (isolated network, EDR, SIEM, Atomic Red Team/CALDERA/Metta). This is the **entry-level version** - for the same purple-team concept with named enterprise tooling, formal workflow phases, and reporting/metrics dashboards, see `PurpleTeam_Detailed.md`; for a scripting-focused variant built around Python/PowerShell/Batch attack scripts specifically, see `PurpleTeam_Multi-Scrip.md`.

## 🏆 Goal

Get a small team or individual practitioner running a first purple team exercise in a home lab or small environment without needing enterprise SIEM/EDR licensing or a formal exercise framework first.

## 📋 When to Use

- Standing up your first purple team exercise in a personal lab or small org
- Validating that basic detection coverage (SIEM ingestion, EDR alerting) actually works before investing in a formal program
- Training new red or blue team members on the collaborative purple-team concept

### Scope:
- Simulate real-world attacker tactics (Red Team)
- Validate detection and log coverage (Blue Team)
- Tune and test SIEM rules, EDR alerts, and response playbooks
- Document tests and outcomes for audit & improvement

---

## Roles

| Role | Responsibility |
|------|----------------|
| 🕵️ Red Operator | Design & run attack simulations |
| 🛡️ Blue Analyst | Monitor SIEM, review alerts, fine-tune detection |
| 🤝 Purple Facilitator | Coordinate exercises, document findings, drive improvements |

---

## Lab Environment

### ✅ Components:

- Isolated test network
- Endpoint hosts (Windows/Linux)
- EDR installed
- SIEM ingesting logs
- C2 / automation tools (Atomic Red Team, CALDERA, Metta)

---

## Common Tools

| Category | Tool | Purpose |
|----------|------|---------|
| Simulations | Atomic Red Team, CALDERA, Metta | Run TTPs |
| C2 | Mythic, Cobalt Strike (licensed) | Advanced Red testing |
| SIEM | Elastic, Splunk, Graylog | Log collection & detection |
| EDR | Defender ATP, CrowdStrike | Endpoint telemetry |
| Scripting | Python, PowerShell | Custom tests & automations |

---

## Execution Workflow

### 🗂️ Step 1 - Select TTP

✅ Pick from MITRE ATT&CK  
✅ Document tactic, technique ID, scenario  
✅ Example: T1110 - Brute Force

### 🗂️ Step 2 - Simulate

✅ Run manual or automated attack:

```powershell
Invoke-AtomicTest T1110
```

OR

```python
# Python custom brute force tester
import requests

# loop over creds
```

### 🗂️ Step 3 - Monitor

✅ Confirm:
- Logs generated?
- SIEM parsing correct fields?
- Alert fired?

### 🗂️ Step 4 - Document

Record:

| Field | Example |
|-------|---------|
| TTP ID | T1110 |
| Attack Script | Atomic Red Team |
| SIEM Rule | Brute Force Detection |
| Outcome | Pass/Fail |
| False Positives | Yes/No |
| Improvement | Add user lockout |

### 🗂️ Step 5 - Tune

✅ Adjust:
- Detection thresholds
- Log source configs
- Parser mappings

✅ Re-run until detection is reliable.

---

## Example Playbook Entries

### ✅ Playbook Entry - Brute Force Test

| Item | Details |
|------|---------|
| TTP | T1110 - Brute Force |
| Goal | Confirm SIEM detects repeated login failures |
| Method | Atomic Red Team `Invoke-AtomicTest T1110` |
| Logs | Auth logs, Windows Event 4625 |
| SIEM Rule | Failed Login Attempts > 5 |
| Expected | Alert in SIEM dashboard |
| Notes | Verify lockout policy |

### ✅ Playbook Entry - Malicious PowerShell

| Item | Details |
|------|---------|
| TTP | T1059 - Command and Scripting Interpreter |
| Goal | Detect suspicious PowerShell |
| Method | Python script to run `Invoke-WebRequest` |
| Logs | PowerShell logs, Process CommandLine |
| SIEM Rule | Process: powershell.exe with suspicious flags |
| Expected | SIEM alert |
| Notes | Tune for false positives (legit scripts) |

### ✅ Playbook Entry - DNS Tunneling

| Item | Details |
|------|---------|
| TTP | T1071.004 - Application Layer Protocol: DNS |
| Goal | Detect unusual DNS query patterns |
| Method | Python script to simulate repeated encoded DNS queries |
| Logs | DNS server logs |
| SIEM Rule | Excessive DNS TXT or long queries |
| Expected | Alert or log spike |
| Notes | Validate against legit big TXT queries (CDN, etc) |

---

## Reporting & Metrics

| Metric | Goal |
|--------|------|
| 📈 Coverage | % of ATT&CK techniques tested |
| 🚨 Alert Accuracy | True positives vs false positives |
| ⏱️ Response Time | Time from detection to triage |
| 📑 Documentation | Detailed test evidence per TTP |

---

## Improvement & Backlog

### ✅ Maintain a Purple Team Backlog:

| TTP | Status | Next Test Date | Notes |
|-----|--------|----------------|-------|
| T1003 - Credential Dumping | Not Tested | July 2025 | Needs lab config |
| T1547 - Persistence | Tested | Quarterly | Verify detection resilience |

---

## Automation Ideas

### ✅ Use:

- Python scripts to run tests nightly
- Jenkins or GitLab CI to run pipelines
- Alerts → Slack, Teams, or Email

### ✅ Example:

```bash
0 2 * * * python3 ~/purple/run_tests.py
```

---

## 🔑 Tips

✅ Test in a safe, isolated lab  
✅ Always get written approvals for live network tests  
✅ Version-control scripts & rules  
✅ Share findings with blue team for tuning  
✅ Log everything - repeatable evidence is gold!

---

## 📎 Template: New Playbook Entry

Use this for each new TTP test:

| Field | Example |
|-------|---------|
| TTP ID | |
| Tactic | |
| Goal | |
| Method | |
| Tools | |
| Log Source | |
| SIEM Rule | |
| Expected Result | |
| Actual Result | |
| Improvement | |
| Next Steps | |

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
