# VulnReportGenerator AgentFlow

## Flow Information

**Name:** `VulnReportGenerator`

**Description:**
```
Converts raw vulnerability findings into professional, client-ready report sections 
with executive summaries, technical details, and remediation steps.
```

**Purpose:** Professional vulnerability documentation for penetration test reports

---

## Flow Variables

Define these variables in the "Flow Variables" section:

| Variable Name | Initial Value | Description |
|---------------|---------------|-------------|
| `finding_title` | (empty) | Concise vulnerability name |
| `finding_details` | (empty) | Technical details and evidence |
| `affected_systems` | (empty) | Impacted systems/assets |
| `client_name` | (empty) | Client/company name |
| `exec_summary` | (empty) | Executive summary output |
| `technical_section` | (empty) | Technical findings output |
| `remediation` | (empty) | Remediation steps output |
| `final_report` | (empty) | Complete formatted report |

---

## Flow Blocks

### Block 1: LLM Instruction - Executive Summary

**Block Type:** LLM Instruction

**Instruction:**
```
Write a non-technical executive summary for ${client_name}:

Vulnerability: ${finding_title}
Systems: ${affected_systems}

Create 2-3 paragraph executive summary focusing on:
- Business impact in non-technical terms
- Risk to operations, data, or customers
- Urgency and priority level
- High-level recommendation

Write for C-level executives who need to understand:
- Why this matters to the business
- What could happen if exploited
- Why they should prioritize fixing it

Avoid technical jargon. Focus on business risk and impact.
```

**Result Variable:** `exec_summary`

**Purpose:** Non-technical summary for management

---

### Block 2: LLM Instruction - Technical Findings

**Block Type:** LLM Instruction

**Instruction:**
```
Write technical findings section:

Title: ${finding_title}
Details: ${finding_details}
Affected: ${affected_systems}

Include:
- Vulnerability classification (OWASP, CWE)
- CVE references (if applicable)
- CVSS scoring (if applicable)
- Technical description of the vulnerability
- How it was discovered
- Exploitation scenarios with technical details
- Attack vectors and prerequisites
- Potential impact (CIA triad)
- Screenshots/evidence references (mention if evidence exists in details)

Format for security professionals who will remediate the issue.
Use proper security terminology.
```

**Result Variable:** `technical_section`

**Purpose:** Detailed technical analysis

---

### Block 3: LLM Instruction - Remediation Steps

**Block Type:** LLM Instruction

**Instruction:**
```
Create remediation section:

Vulnerability: ${finding_title}
Technical Analysis: ${technical_section}

Provide step-by-step remediation with verification steps:

## Immediate Actions
1. [First priority steps]
2. [Emergency mitigations if needed]

## Short-term Remediation
1. [Specific fix steps with commands/configurations]
2. [Patch versions or configuration changes]
3. [Alternative approaches if primary fix unavailable]

## Verification Steps
1. [How to verify fix is successful]
2. [Testing procedures]
3. [Re-scan recommendations]

## Long-term Improvements
1. [Preventive measures]
2. [Security hardening]
3. [Policy or process changes]

Each step should be:
- Specific and actionable
- Include commands where applicable
- Note any downtime requirements
- Estimate time/effort required
- Specify who should perform action (sysadmin, developer, etc.)
```

**Result Variable:** `remediation`

**Purpose:** Actionable fix procedures

---

### Block 4: LLM Instruction - Format Final Report

**Block Type:** LLM Instruction

**Instruction:**
```
Format final report section:

# Vulnerability Report: ${finding_title}
Client: ${client_name}

## Executive Summary
${exec_summary}

## Technical Findings
${technical_section}

## Remediation Steps
${remediation}

Format professionally with proper markdown:
- Use clear headers
- Bold key terms
- Use code blocks for commands
- Include severity ratings
- Professional security assessment tone

Ensure all sections flow together cohesively.
```

**Result Variable:** `final_report`

**Direct Output:** Enabled (toggle on)

**Purpose:** Complete formatted report section

**Note:** Enable "Direct Output" so this block returns content directly to chat

---

### Block 5: Flow Complete

**Block Type:** Flow Complete

**Configuration:**
- Flow will end here and return results

---

## Usage Instructions

### Basic Usage

```
@agent use VulnReportGenerator flow
finding_title: SQL Injection in Customer Portal
finding_details: The search parameter is vulnerable to SQL injection
affected_systems: portal.acme.com (192.168.1.10)
client_name: Acme Corporation
```

### Detailed Example

```
@agent use VulnReportGenerator flow

finding_title: Unauthenticated Remote Code Execution via Apache Path Traversal

finding_details: Apache HTTP Server version 2.4.49 contains CVE-2021-41773, 
allowing path traversal and remote code execution. Tested with payload 
/cgi-bin/.%2e/.%2e/.%2e/.%2e/bin/sh and successfully executed commands. 
CVSS Score: 9.8 Critical. Public exploits available including Metasploit module. 
Can read arbitrary files including /etc/passwd and execute system commands 
with apache user privileges.

affected_systems: Production web servers WEB01 (203.0.113.10), 
WEB02 (203.0.113.11), Staging server STAGE01 (10.0.1.50)

client_name: Acme Corporation
```

### Expected Output

Complete professional report section including:
- Executive summary suitable for C-level
- Technical findings with CVEs and exploitation details
- Step-by-step remediation procedures
- Verification steps
- All sections formatted in markdown

---

## Integration with Other Flows

**Typical Workflow:**

1. **NmapAnalyzer** - Discover vulnerabilities
2. **CVELookup** - Research CVE details
3. **VulnReportGenerator** (this flow) - Document finding
4. Repeat for each vulnerability
5. Compile all reports into final deliverable

**Example Pipeline:**
```
NmapAnalyzer → finds MySQL 5.5.62 exposed
    ↓
CVELookup → CVE-2016-6662 details
    ↓
Manual testing → confirms vulnerability
    ↓
VulnReportGenerator:
  - finding_title: "Exposed MySQL Database with Multiple CVEs"
  - finding_details: [test results + CVE info]
  - affected_systems: "db01.acme.com"
  - client_name: "Acme Corporation"
    ↓
Professional report section ready for client
```

---

## Finding Title Best Practices

### Good Titles (Specific and Descriptive):

- `"SQL Injection in Customer Search Function"`
- `"Exposed Remote Desktop Protocol (RDP) Services"`
- `"Critical Apache Vulnerability (CVE-2021-41773)"`
- `"Missing Security Headers on Web Applications"`
- `"Outdated WordPress with Multiple Known Vulnerabilities"`

### Bad Titles (Too Vague):

- `"Security Issue"` ❌
- `"Web Vulnerability"` ❌
- `"Problem Found"` ❌
- `"Critical Bug"` ❌

---

## Finding Details Best Practices

### Include:

✅ **Version Numbers:**
```
Apache HTTP Server 2.4.49, MySQL 5.5.62
```

✅ **Port Numbers and IPs:**
```
Port 3306 exposed on 203.0.113.10
```

✅ **CVE References:**
```
CVE-2021-41773 (CVSS 9.8 Critical)
```

✅ **Proof of Concept:**
```
Tested with payload: id=1' OR '1'='1
Result: All customer records returned
```

✅ **Evidence:**
```
Screenshot evidence in Appendix A
Command output shows /etc/passwd contents
```

### Avoid:

❌ Vague descriptions: "security issue found"
❌ Missing technical details
❌ No evidence or testing results
❌ Unclear impact

---

## Notes and Considerations

### Professional Standards

- **Tone:** Professional, objective, factual
- **Language:** Clear and precise, avoid ambiguity
- **Evidence:** Always reference testing and proof
- **Accuracy:** Verify all technical details
- **Consistency:** Use consistent terminology

### Report Quality

- **Executive Summary:** Written for non-technical audience
- **Technical Section:** Detailed enough for remediation team
- **Remediation:** Specific, actionable, testable steps
- **Completeness:** All necessary information included

### Client Considerations

- **Sensitivity:** Some findings may be embarrassing
- **Tone:** Constructive, helpful (not accusatory)
- **Priorities:** Help client understand urgency
- **Feasibility:** Consider client's resources and constraints

---

## Optimization Tips

### For Better Executive Summaries:

1. **Focus on Business Impact:**
   ```
   GOOD: "Customer data including payment information could be 
   accessed by unauthorized parties, leading to regulatory fines 
   and reputational damage."
   
   BAD: "SQL injection vulnerability exists."
   ```

2. **Quantify Risk When Possible:**
   ```
   "50,000 customer records at risk"
   "Potential GDPR fine up to 4% of annual revenue"
   "Recovery costs estimated at $500K+"
   ```

### For Better Technical Sections:

1. **Include All Context:**
   - How discovered (scan, manual test, code review)
   - Exploitation difficulty (trivial, moderate, complex)
   - Prerequisites (authentication, network access)
   - Impact (data exposure, system compromise, DoS)

2. **Reference Standards:**
   - OWASP Top 10 classifications
   - CWE (Common Weakness Enumeration)
   - CVSS scores
   - Industry frameworks (PCI-DSS, NIST)

### For Better Remediation:

1. **Be Specific:**
   ```
   GOOD: "Upgrade Apache to version 2.4.51 or later using:
   apt-get update && apt-get install apache2"
   
   BAD: "Update the web server"
   ```

2. **Include Verification:**
   ```
   "Verify patch with: apache2 -v
   Expected output: Server version: Apache/2.4.51"
   ```

3. **Consider Constraints:**
   - Maintenance windows
   - Dependencies
   - Rollback plans
   - Testing requirements

---

## Troubleshooting

| Issue | Solution |
|-------|----------|
| Generic executive summary | Add business context to finding_details |
| Technical section lacks depth | Include CVEs, CVSS, exploitation details |
| Vague remediation steps | Specify exact commands, versions, procedures |
| Inconsistent tone | Review and edit for professionalism |
| Missing key information | Ensure all required details in finding_details |

---

## Advanced Usage

### Multiple Findings Batch Processing

**Create template file:**
```bash
# findings-list.txt
Finding 1: SQL Injection|details...|systems...|client
Finding 2: XSS Vulnerability|details...|systems...|client
Finding 3: Exposed Database|details...|systems...|client
```

**Process each:**
```bash
# For each line in findings-list.txt
@agent use VulnReportGenerator flow
[paste finding details]
```

**Save outputs:**
```bash
finding-001-sql-injection.md
finding-002-xss.md
finding-003-exposed-db.md
```

### Report Compilation

**After generating all findings:**
```bash
# Combine all findings
cat finding-*.md > full-report-findings.md

# Add:
- Executive summary (overall)
- Methodology section
- Scope section
- Appendices
- Deliver to client
```

---

## Example Complete Output

**Input:**
```
finding_title: Exposed MySQL Database
finding_details: MySQL 5.5.62 on port 3306, internet-accessible, weak password
affected_systems: db01.acme.com (203.0.113.10)
client_name: Acme Corporation
```

**Output:**
```markdown
# Vulnerability Report: Exposed MySQL Database
Client: Acme Corporation

## Executive Summary

Acme Corporation's database server is currently exposed to the internet with 
inadequate security controls, creating a critical risk to customer data and 
business operations. An attacker could gain unauthorized access to sensitive 
information including customer records, financial data, and proprietary business 
information. This vulnerability poses immediate risk of data breach, regulatory 
non-compliance (GDPR, PCI-DSS), and potential business disruption.

Given the critical nature of this finding and the ease of exploitation, 
immediate remediation is strongly recommended within 24-48 hours.

## Technical Findings

**Vulnerability:** Exposed MySQL Database (Internet-Accessible)
**Affected System:** db01.acme.com (203.0.113.10)
**Severity:** Critical (CVSS: 9.8)

[... detailed technical analysis ...]

## Remediation Steps

### Immediate Actions (Priority 1 - Within 24 hours)

1. **Block External Access**
   - Configure firewall to block inbound port 3306
   - Restrict to internal IPs only
   - Verification: `nmap -p 3306 203.0.113.10` from external network

[... complete remediation steps ...]
```

---

## Post-Flow Actions

**After generating report:**

1. **Review Quality:**
   - Read executive summary (does it make sense to non-tech?)
   - Check technical details (accurate and complete?)
   - Verify remediation steps (actionable and specific?)

2. **Format for Delivery:**
   - Add to master report document
   - Include screenshots/evidence
   - Number findings consistently
   - Add table of contents entry

3. **Client Review:**
   - Technical review with client IT team
   - Executive briefing with management
   - Q&A and clarifications
   - Remediation timeline discussion

---

## Version History

- **v1.0** - Initial flow with three-section report generation
- Purpose: Professional vulnerability documentation
- Last Updated: November 2025

---

## Related Flows

- **NmapAnalyzer** - Discover vulnerabilities to document
- **CVELookup** - Research CVE details for technical section
- **ThreatIntelCheck** - Add threat context
- **CompanyOSINT** - Understand client business context
