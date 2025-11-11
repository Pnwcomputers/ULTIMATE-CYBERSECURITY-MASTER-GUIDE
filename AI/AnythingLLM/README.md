# AnythingLLM AgentFlow Documentation

## Overview

This directory contains complete technical documentation for recreating all custom AgentFlows used in cybersecurity assessments and penetration testing. Each flow is documented with full configuration details, block specifications, and usage instructions.

---

## Available Flow Documentation

### 🔍 OSINT & Reconnaissance Flows

#### [CompanyOSINT](flow-CompanyOSINT.md)
**Purpose:** Gathers public information about target companies  
**Outputs:** Email formats, employees, tech stack, social media presence  
**Use Cases:** Pre-engagement intelligence, company profiling  
**Blocks:** 6 (3 web scraping, 3 LLM)

#### [DomainRecon](flow-DomainRecon.md)
**Purpose:** Performs comprehensive domain reconnaissance  
**Outputs:** Subdomains, DNS records, certificates, security posture  
**Use Cases:** Attack surface mapping, asset discovery  
**Blocks:** 6 (4 web scraping, 1 LLM, 1 complete)

#### [EmailOSINT](flow-EmailOSINT.md)
**Purpose:** Investigates email addresses and usernames across platforms  
**Outputs:** Breach history, social media accounts, security awareness assessment  
**Use Cases:** Social engineering prep, breach verification  
**Blocks:** 6 (1 API call, 1 web scraping, 3 LLM, 1 complete)  
**Requirements:** HaveIBeenPwned API key

#### [GitHubSecrets](flow-GitHubSecrets.md)
**Purpose:** Searches GitHub for exposed credentials and sensitive data  
**Outputs:** Exposed secrets, API keys, risk assessment  
**Use Cases:** Credential exposure detection, pre-engagement OSINT  
**Blocks:** 5 (2 web scraping, 2 LLM, 1 complete)

#### [BreachChecker](flow-BreachChecker.md)
**Purpose:** Checks domains/emails against known data breaches  
**Outputs:** Breach history, exposed data types, risk analysis  
**Use Cases:** Domain-wide breach assessment, credential exposure  
**Blocks:** 4 (2 API calls, 1 LLM, 1 complete)  
**Requirements:** HaveIBeenPwned API key

---

### 🎯 Scanning & Analysis Flows

#### [NmapAnalyzer](flow-NmapAnalyzer.md)
**Purpose:** Analyzes Nmap scan results and provides recommendations  
**Outputs:** Parsed findings table, prioritized risks, next steps  
**Use Cases:** Port scan analysis, vulnerability prioritization  
**Blocks:** 3 (2 LLM, 1 complete)

#### [ThreatIntelCheck](flow-ThreatIntelCheck.md)
**Purpose:** Checks IP/domain reputation against threat intelligence  
**Outputs:** Threat score, BLOCK/MONITOR/ALLOW recommendation  
**Use Cases:** IP reputation checking, incident response  
**Blocks:** 5 (1 API call, 1 web scraping, 2 LLM, 1 complete)  
**Requirements:** VirusTotal API key (recommended)

---

### 🔐 Vulnerability Management Flows

#### [CVELookup](flow-CVELookup.md)
**Purpose:** Retrieves CVE details and exploitability information  
**Outputs:** CVSS analysis, exploitability assessment, remediation plan  
**Use Cases:** CVE research, vulnerability analysis  
**Blocks:** 4 (1 web scraping, 2 LLM, 1 complete)

#### [VulnReportGenerator](flow-VulnReportGenerator.md)
**Purpose:** Creates professional vulnerability reports  
**Outputs:** Executive summary, technical findings, remediation steps  
**Use Cases:** Report writing, client deliverables  
**Blocks:** 5 (4 LLM, 1 complete)

---

## Quick Reference

### By Use Case

**Pre-Engagement Phase:**
1. CompanyOSINT
2. DomainRecon
3. EmailOSINT
4. GitHubSecrets
5. BreachChecker

**Active Testing Phase:**
1. NmapAnalyzer
2. ThreatIntelCheck
3. CVELookup

**Reporting Phase:**
1. VulnReportGenerator

### By Complexity

**Simple (3-4 blocks):**
- NmapAnalyzer
- CVELookup
- BreachChecker

**Medium (5-6 blocks):**
- GitHubSecrets
- ThreatIntelCheck
- EmailOSINT
- DomainRecon
- VulnReportGenerator

**Complex (6+ blocks):**
- CompanyOSINT

### API Keys Required

**Essential:**
- **HaveIBeenPwned API Key** - Required for EmailOSINT and BreachChecker
  - Get at: https://haveibeenpwned.com/API/Key
  - Cost: $3.50/month (as of 2025)

**Recommended:**
- **VirusTotal API Key** - Required for ThreatIntelCheck
  - Get at: https://www.virustotal.com/gui/join-us
  - Free tier: 4 req/min, 500/day

**Optional:**
- **AbuseIPDB API Key** - Improves ThreatIntelCheck
  - Get at: https://www.abuseipdb.com/register
  - Free tier: 1,000 checks/day

- **WhoisXML API Key** - Improves DomainRecon
- **SecurityTrails API Key** - Improves DomainRecon

---

## File Structure

```
/mnt/user-data/outputs/
├── anythingllm-workflow-examples.md    # Workflow combinations guide
├── flow-CompanyOSINT.md                # Company intelligence
├── flow-DomainRecon.md                 # Domain reconnaissance
├── flow-EmailOSINT.md                  # Email investigation
├── flow-GitHubSecrets.md               # GitHub credential scanning
├── flow-BreachChecker.md               # Breach verification
├── flow-NmapAnalyzer.md                # Nmap scan analysis
├── flow-ThreatIntelCheck.md            # IP/domain reputation
├── flow-CVELookup.md                   # CVE intelligence
├── flow-VulnReportGenerator.md         # Report generation
└── README-AgentFlows.md                # This file
```

---

## How to Use This Documentation

### For Recreation

1. **Choose a flow** from the list above
2. **Open the corresponding .md file**
3. **Follow the "Flow Variables" section** - Set up all variables
4. **Follow the "Flow Blocks" section** - Create each block in order
5. **Configure each block** exactly as documented
6. **Save and publish** the flow
7. **Test** using examples in "Usage Instructions"

### For Reference

- **Quick lookup** of flow configuration
- **Troubleshooting** common issues
- **API setup** instructions
- **Integration patterns** with other flows

### For Modification

- Each flow can be customized
- Add additional data sources
- Modify prompts for different output formats
- Chain with custom flows

---

## Common Issues & Solutions

### Variable Substitution
**Problem:** Variables show as `{{variable}}` instead of values  
**Solution:** Use `${variable}` syntax in URLs and prompts

### API Authentication
**Problem:** 401/403 errors from APIs  
**Solution:** Verify API keys are correct and active

### Rate Limiting
**Problem:** "Quota exceeded" or "Too many requests"  
**Solution:** Wait between requests, upgrade to paid tiers

### Web Scraping Failures
**Problem:** Scraping returns errors or empty data  
**Solution:** Check if site blocks bots, consider API alternatives

### Large Output Truncation
**Problem:** "Result too long, truncated"  
**Solution:** Enable content summarization, break into smaller queries

---

## Best Practices

### Flow Creation

1. **Start Simple** - Create basic flow, test, then enhance
2. **Test Each Block** - Verify each block works before adding next
3. **Use Meaningful Names** - Clear variable and block names
4. **Document As You Go** - Note any customizations made
5. **Version Control** - Keep notes on flow versions and changes

### Flow Usage

1. **Verify Authorization** - Always have permission before scanning
2. **Respect Rate Limits** - Don't exceed API quotas
3. **Validate Results** - Cross-check critical findings
4. **Document Findings** - Keep records of all flows run
5. **Secure API Keys** - Never commit keys to repositories

### Integration

1. **Chain Flows Logically** - Follow reconnaissance → analysis → reporting
2. **Save Intermediate Outputs** - Useful for troubleshooting
3. **Batch Processing** - Run similar flows together
4. **Automate Common Tasks** - Script repetitive flow usage

---

## Maintenance

### Regular Updates

- **Quarterly Review** - Check if APIs still work
- **Update API Keys** - Rotate keys as needed
- **Refresh Prompts** - Improve based on output quality
- **Add New Sources** - Incorporate new threat intel feeds

### Monitoring

- **Track Success Rate** - Note failed flows
- **Monitor API Quotas** - Avoid exhausting limits
- **Review Output Quality** - Ensure prompts still effective
- **User Feedback** - Improve based on actual usage

---

## Support & Resources

### Documentation
- Each flow .md file contains complete technical details
- Workflow examples: `anythingllm-workflow-examples.md`
- Usage patterns and best practices included

### External Resources
- **AnythingLLM Docs:** Check official documentation for updates
- **API Documentation:** Refer to provider docs for API changes
- **Security Communities:** OSINT forums, security subreddits

### Troubleshooting
- Check individual flow documentation "Troubleshooting" section
- Review "Known Issues" sections for common problems
- Test with example inputs provided in each flow doc

---

## Version Information

**Documentation Version:** 1.0  
**Last Updated:** November 2025  
**Created By:** Pacific Northwest Computers  
**Purpose:** Complete AgentFlow recreation guide

---

## Contributing

### Adding New Flows

When creating new flows, document:
1. Flow purpose and use case
2. All variables with descriptions
3. Each block configuration with exact settings
4. Complete prompts and instructions
5. Usage examples
6. Integration patterns
7. Troubleshooting tips

### Updating Existing Flows

When modifying flows:
1. Update corresponding .md file
2. Note version changes
3. Document what changed and why
4. Update usage examples if needed
5. Test thoroughly before documenting

---

## License & Usage

**Purpose:** Internal use for cybersecurity assessments  
**Authorization:** Only use flows on authorized targets  
**Compliance:** Follow all applicable laws and regulations  
**Ethical Use:** Responsible disclosure of all findings

---
