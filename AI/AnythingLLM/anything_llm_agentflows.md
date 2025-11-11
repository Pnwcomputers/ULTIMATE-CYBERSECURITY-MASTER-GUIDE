# AnythingLLM AgentFlow Workflow Examples

## Overview

This document provides practical workflow examples using AnythingLLM custom AgentFlows for cybersecurity assessments and penetration testing. These workflows demonstrate how to chain together multiple flows to accomplish common security tasks efficiently.

### Available AgentFlows

The following custom AgentFlows are referenced in these workflows:

- **CompanyOSINT** - Gathers public information about target companies
- **DomainRecon** - Performs comprehensive domain reconnaissance
- **EmailOSINT** - Investigates email addresses and usernames across platforms
- **GitHubSecrets** - Searches GitHub for exposed credentials and sensitive data
- **BreachChecker** - Checks domains/emails against known data breaches
- **NmapAnalyzer** - Analyzes Nmap scan results and provides recommendations
- **CVELookup** - Retrieves CVE details and exploitability information
- **VulnReportGenerator** - Creates professional vulnerability reports
- **ThreatIntelCheck** - Checks IP/domain reputation against threat intelligence

---

## Common Workflow Patterns

### 1. Pre-Engagement OSINT

**Purpose:** Gather intelligence before active testing begins

**Workflow Steps:**
1. **CompanyOSINT** → Identify company structure, employee information, and email formats
   - Input: `company_name`, `domain`
2. **DomainRecon** → Map attack surface and discover subdomains
   - Input: `domain`
3. **EmailOSINT** → Investigate key personnel emails for breach history
   - Input: Key personnel emails from CompanyOSINT
4. **GitHubSecrets** → Search for exposed credentials and secrets
   - Input: `target_domain`
5. **BreachChecker** → Identify compromised accounts and leaked data
   - Input: `domain`

**Output:** Comprehensive pre-engagement intelligence report

---

### 2. Network Penetration Test

**Purpose:** Complete network security assessment workflow

**Workflow Steps:**
1. **Nmap Scan** - Execute comprehensive port and service scan
   ```bash
   nmap -sV -sC -p- target.com -oN scan.txt
   ```

2. **NmapAnalyzer** → Parse scan results and prioritize findings
   - Input: `scan_results` (from scan.txt), `target_info`

3. **CVELookup** → Research each identified CVE
   - Input: `cve_id`, `system_context`
   - Repeat for each CVE discovered

4. **VulnReportGenerator** → Document each finding professionally
   - Input: `finding_title`, `finding_details`, `affected_systems`, `client_name`
   - Repeat for each vulnerability

5. **Compile Final Report** - Aggregate all findings into deliverable

**Output:** Professional penetration test report ready for client delivery

---

### 3. Incident Response

**Purpose:** Rapid investigation of security incidents

**Workflow Steps:**
1. **ThreatIntelCheck** → Assess suspicious IP addresses
   - Input: Suspicious IP from logs/alerts

2. **DomainRecon** → Investigate attacker domains
   - Input: Attacker domain (if identified)

3. **EmailOSINT** → Research associated email addresses
   - Input: Email addresses from investigation

4. **BreachChecker** → Identify compromised accounts
   - Input: Domain or email addresses

**Output:** Incident analysis with threat actor attribution and impact assessment

---

## Quick Flow Combinations

### Quick Vulnerability Assessment
**Use Case:** Fast initial security check

```
Nmap Scan
    ↓
NmapAnalyzer (prioritize findings)
    ↓
CVELookup (research critical CVEs)
    ↓
VulnReportGenerator (document findings)
```

---

### Deep OSINT Package
**Use Case:** Comprehensive intelligence gathering

```
CompanyOSINT (company intelligence)
    ↓
EmailOSINT (key personnel investigation)
    ↓
GitHubSecrets (credential exposure)
    ↓
BreachChecker (breach history)
```

---

### Network Mapping
**Use Case:** Attack surface enumeration

```
DomainRecon (discover assets)
    ↓
Nmap Scan (active scanning)
    ↓
ThreatIntelCheck (verify IPs)
    ↓
NmapAnalyzer (analyze results)
```

---

### Report Generation Sprint
**Use Case:** Batch document multiple findings

```
All vulnerability findings
    ↓
VulnReportGenerator (repeat for each)
    ↓
VulnReportGenerator (repeat for each)
    ↓
VulnReportGenerator (repeat for each)
    ↓
Compile into final report
```

---

### General OSINT Assessment
**Use Case:** Standard reconnaissance workflow

**Workflow Steps:**
1. **CompanyOSINT** → Determine email format and company structure
2. **EmailOSINT** → Investigate key personnel emails for exposed data
3. **DomainRecon** → Map complete attack surface including subdomains
4. **GitHubSecrets** → Identify exposed credentials in public repositories

**Output:** Complete OSINT intelligence package

---

## Usage Notes

### Best Practices

- Always ensure you have **proper authorization** before executing these workflows
- **Document each step** as you progress through workflows
- Use **descriptive inputs** for better analysis quality
- **Chain workflows** based on findings from previous steps
- **Save outputs** from each flow for final report compilation

### Workflow Customization

These workflows can be:
- **Modified** to suit specific engagement types
- **Combined** for comprehensive assessments
- **Abbreviated** for time-sensitive tasks
- **Extended** with additional flows as needed

### Tips for Effective Use

1. **Start broad, narrow down** - Begin with OSINT, then focus on discovered assets
2. **Prioritize findings** - Use NmapAnalyzer and CVELookup to identify critical issues first
3. **Document continuously** - Run VulnReportGenerator for each finding immediately
4. **Verify results** - Cross-reference flow outputs with manual testing
5. **Iterate as needed** - Loop back through workflows when new information emerges

---

## Example Complete Engagement

**Scenario:** External penetration test for Acme Corporation

### Phase 1: Reconnaissance (Week 1)
```
CompanyOSINT → company: Acme Corporation, domain: acme.com
DomainRecon → domain: acme.com
GitHubSecrets → target: acme.com
BreachChecker → domain: acme.com
EmailOSINT → emails discovered from CompanyOSINT
```

### Phase 2: Active Scanning (Week 2)
```
nmap -sV -sC -p- acme.com -oN acme-scan.txt
NmapAnalyzer → scan_results: acme-scan.txt
ThreatIntelCheck → IPs discovered from scan
```

### Phase 3: Vulnerability Analysis (Week 2)
```
CVELookup → each CVE from NmapAnalyzer
Manual testing of discovered services
Additional targeted scans
```

### Phase 4: Reporting (Week 3)
```
VulnReportGenerator → each finding documented
Compile all outputs into final report
Executive summary creation
Client presentation preparation
```

---

**Document Version:** 1.0  
**Last Updated:** November 2025  
**Author:** Pacific Northwest Computers  
**Purpose:** AnythingLLM AgentFlow workflow reference guide
