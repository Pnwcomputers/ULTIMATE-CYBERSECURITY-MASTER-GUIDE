# NmapAnalyzer AgentFlow

## Flow Information

**Name:** `NmapAnalyzer`

**Description:**
```
Analyzes Nmap scan results, identifies critical findings, and provides next-step 
recommendations based on security best practices.
```

**Purpose:** Automated port scan analysis and vulnerability prioritization

---

## Flow Variables

Define these variables in the "Flow Variables" section:

| Variable Name | Initial Value | Description |
|---------------|---------------|-------------|
| `scan_results` | (empty) | Raw Nmap scan output |
| `target_info` | (empty) | Target description/context |
| `parsed_findings` | (empty) | Structured vulnerability table |
| `recommendations` | (empty) | Next steps and tool suggestions |

---

## Flow Blocks

### Block 1: LLM Instruction - Parse Scan Results

**Block Type:** LLM Instruction

**Instruction:**
```
Analyze the following Nmap scan results and extract structured data:

Scan Results: ${scan_results}
Target: ${target_info}

Format as markdown table:
| Port | Service | Version | Risk | Notes |

Categorize each finding by risk level:
- **CRITICAL:** Services with known critical vulnerabilities
- **HIGH:** Outdated versions with exploits available
- **MEDIUM:** Services that should not be exposed
- **LOW:** Standard services with no obvious issues

Include specific observations:
- Exact version numbers
- End-of-life (EOL) software
- Default configurations
- Unnecessary services
- Missing security features
- Known CVE associations
```

**Result Variable:** `parsed_findings`

**Purpose:** Extract structured vulnerability data from raw scan

---

### Block 2: LLM Instruction - Generate Recommendations

**Block Type:** LLM Instruction

**Instruction:**
```
Based on these scan findings, provide actionable recommendations:

Findings: ${parsed_findings}
Target Context: ${target_info}

Provide:

## Top 3 Critical Items
[Prioritize by severity and exploitability]

## Next Reconnaissance Steps
Suggest specific commands or tools:
- Further enumeration techniques
- Service-specific scans
- Vulnerability scanning tools
- Manual testing approaches

## Exploitation Possibilities
For each critical/high finding:
- Known exploits (with CVE references)
- Exploitation difficulty
- Potential impact
- Proof-of-concept availability

## Required Tools
List specific tools for deeper analysis:
- Vulnerability scanners (Nessus, OpenVAS)
- Service-specific tools (sqlmap, nikto, enum4linux)
- Exploitation frameworks (Metasploit modules)
- Manual testing utilities

## Security Observations
- Authentication mechanisms
- Encryption status
- Access controls
- Configuration issues
- Best practice violations

Format as actionable penetration testing guidance.
```

**Result Variable:** `recommendations`

**Purpose:** Provide next steps for penetration testing

---

### Block 3: Flow Complete

**Block Type:** Flow Complete

**Configuration:**
- Flow will end here and return results

---

## Usage Instructions

### Basic Usage

```
@agent use NmapAnalyzer flow
scan_results: [paste your Nmap output]
target_info: Production web server - authorized test
```

### With File Output

```bash
# Run Nmap scan
nmap -sV -sC -p- target.com -oN scan.txt

# Use flow
@agent use NmapAnalyzer flow
scan_results: 
[paste contents of scan.txt]

target_info: Client XYZ external infrastructure assessment
```

### Expected Output

**parsed_findings** - Structured table:
| Port | Service | Version | Risk | Notes |
|------|---------|---------|------|-------|
| 3306 | MySQL | 5.5.62 | CRITICAL | EOL version, publicly accessible |
| 21 | FTP | vsftpd 3.0.3 | HIGH | Anonymous login enabled |
| 80 | HTTP | Apache 2.4.41 | MEDIUM | No HTTPS redirect |

**recommendations** - Actionable guidance:
- Top priority items
- Specific exploitation steps
- Tool recommendations
- Next testing phases

---

## Integration with Other Flows

**Typical Workflow:**

1. Run Nmap scan
2. **NmapAnalyzer** (this flow) - Parse and prioritize findings
3. **CVELookup** - Research each identified CVE
4. **VulnReportGenerator** - Document each vulnerability
5. Compile final penetration test report

**Example Pipeline:**
```
nmap scan
    ↓
NmapAnalyzer → identifies MySQL 5.5.62 with CVE-2016-6662
    ↓
CVELookup → CVE-2016-6662 details and remediation
    ↓
VulnReportGenerator → Professional finding documentation
```

---

## Nmap Command Reference

### Recommended Scan Commands

**Quick Service Detection:**
```bash
nmap -sV -p 21,22,23,25,80,443,3306,3389,8080 target.com
```

**Comprehensive Scan:**
```bash
nmap -sV -sC -p- target.com -oN scan.txt
```

**Vulnerability Scan:**
```bash
nmap -sV --script vuln target.com
```

**Stealth Scan:**
```bash
nmap -sS -sV -T2 target.com
```

**UDP Scan:**
```bash
nmap -sU -sV --top-ports 100 target.com
```

**OS Detection:**
```bash
nmap -O -sV target.com
```

---

## Example Inputs and Outputs

### Example 1: Web Server Scan

**Input:**
```
scan_results:
PORT    STATE SERVICE  VERSION
22/tcp  open  ssh      OpenSSH 7.4
80/tcp  open  http     Apache httpd 2.4.49
443/tcp open  ssl/http Apache httpd 2.4.49

target_info: External web server for e-commerce site
```

**Output:**
```
PARSED FINDINGS:
| Port | Service | Version | Risk | Notes |
|------|---------|---------|------|-------|
| 443 | HTTPS | Apache 2.4.49 | CRITICAL | CVE-2021-41773 - Path traversal RCE |
| 80 | HTTP | Apache 2.4.49 | CRITICAL | CVE-2021-41773 - Path traversal RCE |
| 22 | SSH | OpenSSH 7.4 | LOW | Slightly outdated but no critical CVEs |

RECOMMENDATIONS:
Top 3 Critical Items:
1. Apache 2.4.49 - Immediate patching required (CVE-2021-41773)
2. HTTP port 80 open - Should redirect to HTTPS
3. Verify SSH key-only authentication

Next Steps:
- Test CVE-2021-41773 exploit (Metasploit module available)
- Check for directory traversal manually
- Enumerate web application

Required Tools:
- Metasploit (exploit/multi/http/apache_normalize_path_rce)
- Nikto for web server scanning
- dirb/gobuster for directory enumeration
```

### Example 2: Database Server Scan

**Input:**
```
scan_results:
PORT     STATE SERVICE  VERSION
3306/tcp open  mysql    MySQL 5.5.62
22/tcp   open  ssh      OpenSSH 8.2p1

target_info: Database server - should be internal only
```

**Output:**
```
PARSED FINDINGS:
| Port | Service | Version | Risk | Notes |
|------|---------|---------|------|-------|
| 3306 | MySQL | 5.5.62 | CRITICAL | EOL (2018), internet-accessible, multiple CVEs |
| 22 | SSH | OpenSSH 8.2p1 | LOW | Current version, no issues |

RECOMMENDATIONS:
Top 3 Critical Items:
1. MySQL exposed to internet - CRITICAL misconfig
2. MySQL 5.5.62 EOL with known CVEs
3. Potential data breach risk

Next Steps:
- Attempt MySQL connection (test weak passwords)
- Check for anonymous access
- Enumerate databases and tables
- Test for SQL injection if web app present

Required Tools:
- mysql command-line client
- hydra for password attacks
- sqlmap for injection testing
- Nessus for full vulnerability scan
```

---

## Notes and Considerations

### Legal and Ethical

- ⚠️ **Authorization Required** - Only scan authorized targets
- **Scope Compliance** - Stay within engagement boundaries
- **Documentation** - Document all scans in engagement notes
- **Rate Limiting** - Respect target's resources

### Technical Considerations

- **Scan Quality:**
  - Use `-sV` for version detection
  - Use `-sC` for default scripts
  - Full port scan `-p-` takes longer but is comprehensive

- **False Positives:**
  - Version detection isn't always accurate
  - Verify critical findings manually
  - Cross-reference with other tools

- **Output Size:**
  - Large scans may hit token limits
  - Break into smaller IP ranges if needed
  - Enable summarization for very large scans

---

## Optimization Tips

### For Better Analysis:

1. **Include Version Information:**
   - Always use `-sV` flag
   - Version numbers are critical for CVE mapping

2. **Use Script Scanning:**
   - `-sC` runs default Nmap scripts
   - Provides additional service information
   - Detects common misconfigurations

3. **Provide Context:**
   - Describe target type (web server, database, etc.)
   - Mention if internal or external
   - Note if production or development
   - Include authorization status

### For Better Recommendations:

1. **Specific Target Info:**
   ```
   target_info: Production e-commerce platform processing credit cards, 
   PCI-DSS scope, external-facing, authorized pen test 2024-11-15
   ```

2. **Include Multiple Hosts:**
   - Scan entire subnet
   - Analyze patterns across systems
   - Identify systemic issues

3. **Combine with Vulnerability Scans:**
   - Run Nmap first for discovery
   - Follow with Nessus/OpenVAS for deeper analysis
   - Use NmapAnalyzer to prioritize targets

---

## Troubleshooting

| Issue | Solution |
|-------|----------|
| Generic analysis | Provide more detailed target_info |
| Missing CVEs | Use `--script vuln` for vulnerability detection |
| Unclear priorities | Include business context in target_info |
| Token limit exceeded | Scan smaller IP ranges or summarize results |
| No service versions | Ensure `-sV` flag was used in scan |
| Incomplete scan | Use `-p-` for all ports, not just common ones |

---

## Advanced Usage

### Combining Multiple Scans

**Scan different port ranges:**
```bash
# Quick scan common ports
nmap -sV -p 21,22,23,25,80,443,3389 target.com -oN quick.txt

# Full port scan
nmap -sV -p- target.com -oN full.txt

# UDP scan
nmap -sU --top-ports 100 target.com -oN udp.txt
```

**Analyze all together:**
```
@agent use NmapAnalyzer flow
scan_results:
[paste quick.txt]
[paste full.txt]
[paste udp.txt]

target_info: Complete port analysis - all protocols
```

### Subnet Scanning

```bash
# Scan entire subnet
nmap -sV 192.168.1.0/24 -oN subnet-scan.txt

# Analyze results
@agent use NmapAnalyzer flow
scan_results: [paste subnet-scan.txt]
target_info: Internal network - identify all services across 192.168.1.0/24
```

---

## Post-Flow Actions

**After analyzing scan:**

1. **Prioritize Targets:**
   - Focus on CRITICAL and HIGH findings first
   - Identify quick wins
   - Plan testing approach

2. **Research CVEs:**
   - Use CVELookup flow for each identified CVE
   - Understand exploitability
   - Check for public exploits

3. **Deep Dive Testing:**
   - Service-specific enumeration
   - Vulnerability validation
   - Exploitation attempts (authorized)

4. **Documentation:**
   - Use VulnReportGenerator for each finding
   - Build evidence package
   - Prepare client deliverable

---

## Integration Examples

### Full Pen Test Workflow:

```
1. Initial Scan:
   nmap -sV -sC -p- target.com -oN initial.txt

2. Analysis:
   @agent use NmapAnalyzer
   → Identifies: MySQL 5.5.62 (CVE-2016-6662), Apache 2.4.49 (CVE-2021-41773)

3. CVE Research:
   @agent use CVELookup cve_id: CVE-2021-41773
   → Gets exploit details, CVSS 9.8

4. Manual Testing:
   Test exploits, verify vulnerabilities

5. Documentation:
   @agent use VulnReportGenerator
   finding_title: Critical Apache Path Traversal
   → Professional report section

6. Compile Report:
   Aggregate all findings into final deliverable
```

---

## Version History

- **v1.0** - Initial flow with parsing and recommendations
- Purpose: Automated Nmap scan analysis for penetration testing
- Last Updated: November 2025

---

## Related Flows

- **ThreatIntelCheck** - Verify discovered IPs
- **CVELookup** - Research identified CVEs
- **VulnReportGenerator** - Document findings
- **DomainRecon** - Pre-scan reconnaissance
