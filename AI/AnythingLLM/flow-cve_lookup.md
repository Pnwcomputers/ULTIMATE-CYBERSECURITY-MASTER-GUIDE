# CVELookup AgentFlow

_Reviewed: 2026-11-11 for source quality and risk-model accuracy. The configured AgentFlow has **not** been run against live NVD, CISA, or vendor APIs in this review._

## 🎯 Purpose
AnythingLLM AgentFlow for CVE research and analysis - takes a CVE ID or affected software/version and returns structured vulnerability intelligence including CVSS score, affected versions, PoC availability, and patch status.

## ⚙️ Function
The flow as documented scrapes an NVD **web page** into an LLM input, then proposes analysis and remediation. The blocks shown below do **not** independently query CVE.org, ExploitDB, vendor advisories, or CISA KEV. Those sources require separate lookups and provenance checks. A generated statement about patches or active exploitation is **unverified** until an analyst checks an authoritative source.

## 🏆 Goal
Rapidly contextualize a CVE during engagement scoping, vulnerability scanning triage, or threat intelligence research without manually navigating multiple databases.

## 📋 When to Use
Triaging scanner output during a vulnerability assessment; researching a CVE found in a target's environment; building remediation priority recommendations. **Do not use an LLM-only flow as evidence of an affected product, available patch, or active exploitation.**

## Evidence & Verification Gate

| Question | Authoritative check | Reporting requirement |
|---|---|---|
| Is this a valid CVE with a reliable description? | CVE.org/CNA and [NVD CVE API 2.0](https://nvd.nist.gov/developers/vulnerabilities) | Record source URL, retrieved UTC time, status and source-provided published/modified fields |
| Which CVSS score applies? | Vendor/CNA or NVD with [FIRST CVSS](https://www.first.org/cvss/v4.0/) | Preserve **version, score, vector and source**; v4.0 is different from v3.1; never infer a missing score |
| Are we affected? | Vendor advisory, product edition/version, feature flags and deployed configuration | Confirm exact asset inventory and preconditions; state unknown when not established |
| Is it exploited in the wild? | [CISA KEV](https://www.cisa.gov/known-exploited-vulnerabilities-catalog), vendor incident advisories or separately corroborated reports | **KEV listed** is affirmative evidence; **not listed** is **not** proof of no exploitation |
| Is a patch or mitigation available? | Vendor release note/security bulletin | Include exact fixed version/build, URL, date, restart/rollback requirements |
| What is the urgency? | Business impact, exposure, affected assets, confirmed exploitation and existing controls | Distinguish CVSS severity from environmental risk and client-specific SLAs |

Use [Repository Verification Protocol](../../Documentation/REPOSITORY-VERIFICATION-PROTOCOL.md) for unknown-data handling and proof levels.


## Flow Information

**Name:** `CVELookup`

**Description:**
```
Takes CVE IDs, scrapes NIST NVD for details, and provides exploitability 
assessment with remediation guidance tailored to specific system context.
```

**Purpose:** CVE intelligence and remediation planning

---

## Flow Variables

Define these variables in the "Flow Variables" section:

| Variable Name | Initial Value | Description |
|---------------|---------------|-------------|
| `cve_id` | CVE-2024-XXXX | CVE identifier to lookup |
| `system_context` | (empty) | Affected system details |
| `nvd_data` | (empty) | Scraped NVD information |
| `analysis` | (empty) | CVE analysis results |
| `remediation_plan` | (empty) | Remediation steps |

---

## Flow Blocks

### Block 1: Web Scraping - NIST NVD

**Block Type:** Web Scraping

**Configuration:**
- **URL:** `https://nvd.nist.gov/vuln/detail/${cve_id}`
- **Capture Page Content As:** Text content only
- **Content Summarization:** Enabled (recommended)
- **Result Variable:** `nvd_data`

**Purpose:** Retrieve official CVE details from NIST

**Note:** Ensure variable syntax is `${cve_id}` not `{{cve_id}}`

---

### Block 2: LLM Instruction - Analyze CVE

**Block Type:** LLM Instruction

**Instruction:**
```
Analyze this CVE for ${system_context}:

CVE Data from NVD: ${nvd_data}

Extract and format:

## CVE Overview
- **CVE ID:** ${cve_id}
- **Published Date:** [date]
- **Last Modified:** [date]
- **Status:** [ANALYZED/AWAITING ANALYSIS]

## CVSS Scoring
- **CVSS Version:** [4.0, 3.1, 3.0, or not provided]
- **Published Score/Severity:** [exact source value or not available]
- **Published Vector:** [exact source vector or not available]
- **Source:** [vendor/CNA/NVD URL and retrieval date]
- **Attack Vector, Complexity, Privileges, Interaction:** [only the metrics actually defined by the cited CVSS version]
- **CVSS v4 only:** [Attack Requirements; Vulnerable System and Subsequent System impact as published]
- **CVSS v3.x only:** [Scope and v3.x CIA impact as published]
- **Uncertainty:** [missing data, disputed severity, and applicability questions]

## Affected Systems
- **Vendor:** [vendor name]
- **Product:** [product name]
- **Affected Versions:** [list all affected versions]
- **Fixed Versions:** [list patched versions]

## Vulnerability Description
[Clear explanation of the vulnerability]

## Exploitability Assessment
Based on **verified source evidence**, not CVSS alone:
- **Evidence state:** [Confirmed / Unconfirmed / Unknown, with URL and timestamp]
- **Environmental Risk:** [provisional rating only after exposure and asset context are known]
- **Exploit Maturity:**
  - Public exploits available: [Yes/No]
  - Exploit frameworks (Metasploit/ExploitDB): [availability]
  - Proof of concept: [Yes/No]
  - Active exploitation in wild: [Confirmed by named source with link / Not established (including no KEV entry) / Unknown]
- **Technical Skill Required:** [Low/Medium/High]
- **Special Conditions:** [any requirements for exploitation]

## Real-World Impact for ${system_context}
Analyze specific impact for the described system:
- **Applicability:** [Does this CVE affect your specific configuration?]
- **Risk Level:** [CRITICAL/HIGH/MEDIUM/LOW for your environment]
- **Exploitation Scenario:** [How would this be exploited in your context?]
- **Data at Risk:** [What could an attacker access?]
- **Business Impact:** [Potential consequences]

## Technical Details
- **CWE:** [CWE ID and name]
- **Vulnerability Type:** [e.g., SQL Injection, RCE, XSS, etc.]
- **Attack Complexity Details:** [technical explanation]

Do not invent versions, advisory URLs, patches, scores, test results or exploitation evidence. For each material assertion include a source URL and retrieval date, and label missing fields \"Not verified\". Distinguish an example from actual observed output. Explain where a source conflicts with another.

Format clearly for a **draft** security assessment report requiring analyst sign-off.
```

**Result Variable:** `analysis`

**Purpose:** Extract and analyze CVE details

---

### Block 3: LLM Instruction - Remediation Planning

**Block Type:** LLM Instruction

**Instruction:**
```
Based on this analysis, provide remediation steps:

CVE: ${cve_id}
Analysis: ${analysis}
System Context: ${system_context}

Create comprehensive remediation plan:

## Immediate Actions (Priority 1 - Within 24 hours)

For CRITICAL/HIGH severity:
1. **Assessment**
   - Verify if system is affected
   - Check current version/configuration
   - Identify all affected instances
   - Review logs for exploitation attempts

2. **Containment** (if actively exploited)
   - Isolate affected systems
   - Block attack vectors at firewall
   - Implement emergency WAF rules
   - Enable enhanced monitoring

3. **Emergency Mitigation**
   - Apply temporary workarounds
   - Disable vulnerable features if possible
   - Implement compensating controls
   - Restrict network access

## Patching Strategy (Priority 2 - Within 1 week)

1. **Patch Availability**
   - Current version: [from system_context]
   - Target version: [fixed version]
   - Patch source: [vendor URL]
   - Release notes: [link if available]

2. **Testing Plan**
   - Test in development environment
   - Verify application compatibility
   - Document rollback procedure
   - Schedule maintenance window

3. **Deployment Steps**
   - Step-by-step patching procedure
   - Pre-patch backups required
   - Post-patch verification steps
   - Rollback triggers and process

## Compensating Controls

If patching is delayed or not possible:

1. **Network-Level Controls**
   - Firewall rule recommendations
   - Network segmentation
   - VPN requirements
   - Access control lists

2. **Application-Level Controls**
   - Web Application Firewall rules
   - Input validation
   - Security headers
   - Rate limiting

3. **Monitoring & Detection**
   - Log collection requirements
   - SIEM alert rules
   - Indicators of compromise (IOCs)
   - Incident response triggers

## Long-Term Improvements (Within 1 month)

1. **Security Hardening**
   - Configuration best practices
   - Principle of least privilege
   - Disable unnecessary features
   - Security header implementation

2. **Ongoing Maintenance**
   - Update schedule establishment
   - Vulnerability management process
   - Patch testing procedures
   - Change management integration

## Verification Steps

After remediation:
1. **Verify Patch Installation**
   - Version check commands
   - Configuration validation
   - Service restart verification

2. **Security Testing**
   - Vulnerability re-scan
   - Penetration testing
   - Exploit verification (safe tests)

3. **Documentation**
   - Update asset inventory
   - Document changes made
   - Update runbooks
   - Inform stakeholders

## Timeline Recommendations

Based on CVSS score and exploitability:
- **CRITICAL (9.0-10.0):** Patch within 24-48 hours
- **HIGH (7.0-8.9):** Patch within 1 week
- **MEDIUM (4.0-6.9):** Patch within 1 month
- **LOW (0.1-3.9):** Patch during next maintenance cycle

For ${system_context}, recommend: [specific timeline based on context]

## Resource Requirements

- **Personnel:** [roles needed - sysadmin, DBA, etc.]
- **Downtime:** [estimated downtime required]
- **Budget:** [if commercial patches/tools needed]
- **External Support:** [vendor support, consultants]

## References

- **NVD:** https://nvd.nist.gov/vuln/detail/${cve_id}
- **Vendor Advisory:** [if available]
- **Exploit Database:** [if relevant]
- **Additional Resources:** [security blogs, analyses]

Format as actionable remediation plan suitable for change management request.
```

**Result Variable:** `remediation_plan`

**Purpose:** Provide actionable remediation guidance

---

### Block 4: Flow Complete

**Block Type:** Flow Complete

**Configuration:**
- Flow will end here and return results

---

## Reproducible Source Lookup (Outside The AgentFlow)

The web-scraping block may be blocked, summarized incorrectly or show outdated content. Use the documented NVD **2.0** JSON API for a machine-readable reference and independently compare CNA/vendor information. This command is an **example**, not a previously observed live result. It requires `curl` and `jq`, and still depends on provider availability and rate limits.

~~~bash
CVE_ID=CVE-2021-44228  # Real, publicly documented identifier used here as an example
curl --fail --silent --show-error --retry 2 --max-time 30 --get \
  --data-urlencode "cveId=${CVE_ID}" \
  'https://services.nvd.nist.gov/rest/json/cves/2.0' \
  | jq '.vulnerabilities[0].cve | {id, published, lastModified, vulnStatus, metrics, references}'
~~~

Do not treat a missing result as "no vulnerability"; NVD can have processing or availability delays. A `jq` pipeline can also mask an upstream HTTP failure unless the shell enables pipeline failure checking (for example, `set -o pipefail` under Bash). Validate the response's `vulnerabilities` array and its `id` before making decisions.

For claims of real exploitation, consult the live [CISA KEV catalog](https://www.cisa.gov/known-exploited-vulnerabilities-catalog); for a fix, use the vendor's own affected/fixed version advisory. When comparing CVSS, **do not translate v3 Scope to v4**: CVSS v4 removes Scope and introduces Attack Requirements and differentiated impact to vulnerable/subsequent systems.

**Deadline caution:** The relative timelines and severity-triggered actions in Block 3 are examples only. Set the real remediation deadline through confirmed exploitation, exposure, asset criticality, maintenance constraints, contractual obligations and applicable policy. A fixed "Critical = within 24 hours" is not a universal regulatory rule or safe substitute for triage.

---

## Usage Instructions

### Basic Usage

```
@agent use CVELookup flow
cve_id: CVE-2021-44228
system_context: Java application servers running Log4j 2.14.1
```

### Detailed Context

```
@agent use CVELookup flow
cve_id: CVE-2023-23397
system_context: Microsoft Exchange Server 2019 on Windows Server 2019,
500 mailboxes, internet-facing, handles sensitive customer communications,
cannot patch until next maintenance window (2 weeks)
```

### Expected Output

**analysis** - Technical CVE details:
- CVSS scoring breakdown
- Affected versions
- Exploitability assessment
- Real-world impact for your system

**remediation_plan** - Actionable steps:
- Immediate containment actions
- Patching strategy with specific versions
- Compensating controls if patching delayed
- Verification procedures
- Timeline recommendations

---

## Integration with Other Flows

**Typical Workflow:**

1. **NmapAnalyzer** - Identifies services and versions
2. **CVELookup** (this flow) - Research each CVE
3. **VulnReportGenerator** - Document findings
4. Compile comprehensive penetration test report

**Example:**
```
NmapAnalyzer finds: Apache 2.4.49
    ↓
CVELookup: CVE-2021-41773 
    ↓
Analysis: CVSS 9.8, RCE, public exploits available
    ↓
VulnReportGenerator: Professional client report
```

---

## Example Inputs and Outputs

### Example 1: Log4Shell

**Input:**
```
cve_id: CVE-2021-44228
system_context: Production Java application using Log4j 2.14.1, 
processes customer orders, PCI-DSS environment
```

**Output Highlights:**
```
CVSS Score: 10.0 CRITICAL
Attack Vector: Network, no authentication required
Exploitability: CRITICAL - Widespread active exploitation
Public Exploits: Yes (Metasploit, multiple PoCs)

Immediate Actions:
1. Upgrade Log4j to 2.17.1 immediately
2. Set LOG4J_FORMAT_MSG_NO_LOOKUPS=true
3. Remove JndiLookup class from classpath
4. Monitor for ${jndi:ldap://...} in logs

Timeline: Emergency patching within 24 hours
```

### Example 2: Windows Vulnerability

**Input:**
```
cve_id: CVE-2017-0144
system_context: Windows Server 2008 R2 domain controllers, 
cannot be patched due to legacy application dependencies
```

**Output Highlights:**
```
CVSS Score: 8.1 HIGH
Attack Vector: Network, no authentication
Exploitability: HIGH - EternalBlue, WannaCry, NotPetya

Compensating Controls (since patching not possible):
1. Disable SMBv1 protocol completely
2. Segment network - isolate legacy servers
3. Implement strict firewall rules (block ports 139, 445)
4. Deploy IDS signatures for EternalBlue
5. Enhanced logging and monitoring
6. Consider application containerization for legacy app

Timeline: Implement controls within 48 hours
```

---

## Notes and Considerations

### Legal and Ethical

- ⚠️ **Research Only** - Do not exploit CVEs without authorization
- **Responsible Disclosure** - Report findings to affected organizations
- **Client Communication** - Share critical CVEs immediately
- **Documentation** - Keep records of all CVE research

### Technical Considerations

- **NVD Availability:**
  - NVD may be slow to update
  - New CVEs may have limited details
  - Cross-reference with vendor advisories

- **Version Specificity:**
  - Be precise about affected versions
  - Check if workarounds are version-specific
  - Verify patch versions solve the issue

- **False Applicability:**
  - CVE may not apply to your specific configuration
  - Check all conditions for exploitability
  - Vendor may have clarifications

---

## Optimization Tips

### For Better Results:

1. **Detailed System Context:**
   ```
   GOOD: "Apache 2.4.49 on Ubuntu 20.04, reverse proxy for 
   internal applications, handles authentication, internet-facing"
   
   BAD: "web server"
   ```

2. **Include Constraints:**
   ```
   "Windows Server 2016, cannot patch for 3 months due to 
   vendor support requirements, need compensating controls"
   ```

3. **Mention Data Sensitivity:**
   ```
   "Database server with customer PII, GDPR scope, 
   healthcare data, HIPAA compliance required"
   ```

### For Better Analysis:

1. **Cross-Reference Sources:**
   - NIST NVD (authoritative)
   - Vendor security advisories
   - CISA Known Exploited Vulnerabilities
   - ExploitDB, GitHub for PoCs

2. **Check Exploit Maturity:**
   - Metasploit modules available?
   - Public proof-of-concept code?
   - Active scanning detected?
   - Ransomware using this CVE?

3. **Consider Context:**
   - Internet-facing vs internal
   - Authentication requirements
   - Data sensitivity
   - Business criticality

---

## Troubleshooting

| Issue | Solution |
|-------|----------|
| CVE not found in NVD | Very new CVE; check vendor advisory directly |
| Generic analysis | Provide more detailed system_context |
| Wrong CVE ID format | Use format CVE-YYYY-NNNNN (e.g., CVE-2021-44228) |
| No remediation steps | NVD may lack details; check vendor site |
| NVD scraping fails | NVD may be down; try again later or use API |
| Variable not substituting | Check syntax: ${cve_id} not {{cve_id}} |

---

## Alternative Data Sources

### If NVD is unavailable:

**VulnDB (requires subscription):**
```
URL: https://vulndb.cyberriskanalytics.com/vulnerabilities/${cve_id}
```

**CVE.org:**
```
URL: https://cve.org/CVERecord?id=${cve_id}
```

**Vendor-Specific (examples):**
```
Microsoft: https://msrc.microsoft.com/update-guide/vulnerability/${cve_id}
RedHat: https://access.redhat.com/security/cve/${cve_id}
Ubuntu: https://ubuntu.com/security/${cve_id}
```

---

## Post-Flow Actions

**After CVE lookup:**

1. **Assess Urgency:**
   - Critical + public exploit = Emergency
   - High + no patch = Immediate compensating controls
   - Medium + patch available = Schedule maintenance

2. **Communicate:**
   - Notify client of critical findings
   - Provide remediation timeline
   - Discuss compensating controls if patching delayed

3. **Document:**
   - Use VulnReportGenerator to create formal finding
   - Include CVE details in penetration test report
   - Create change management request for patching

4. **Verify:**
   - After remediation, verify vulnerability is resolved
   - Re-scan with vulnerability scanner
   - Update documentation

---

## Real-World Use Cases

### Penetration Testing
- Research CVEs discovered during scans
- Understand exploitability before testing
- Document findings with official CVE data

### Vulnerability Management
- Prioritize patch deployment
- Assess risk of unpatched systems
- Create remediation plans

### Incident Response
- Understand exploited vulnerabilities
- Determine scope of potential compromise
- Plan containment and remediation

### Change Management
- Justify emergency patching
- Provide technical details for change requests
- Document security improvements

---

## Version History

- **v1.0** - Initial flow with NVD scraping and analysis
- Purpose: CVE intelligence for security assessments
- Last Updated: November 2025

---

## Related Flows

- **NmapAnalyzer** - Discover services and potential CVEs
- **VulnReportGenerator** - Document CVE findings
- **ThreatIntelCheck** - Correlate with threat intelligence
- **BreachChecker** - Check if CVE led to breaches

## Related Files
- [README.md](README.md) - AnythingLLM AgentFlow index
- [flow-nmap_analyzer.md](flow-nmap_analyzer.md) - Nmap findings that trigger CVE lookups
- [flow-vulnreport_gen.md](flow-vulnreport_gen.md) - CVE data feeds into vulnerability reports
- [flow-threat_intel.md](flow-threat_intel.md) - Threat intel on active CVE exploitation
