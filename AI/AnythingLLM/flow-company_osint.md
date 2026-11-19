# CompanyOSINT AgentFlow

## 🎯 Purpose
AnythingLLM AgentFlow for automated company-level OSINT - aggregates public information about a target organization including tech stack, employee data, infrastructure, and social presence.

## ⚙️ Function
Accepts a company name or domain within an authorized assessment and summarizes public company-level information. Treat matches as unverified leads; avoid building profiles of individual employees.

## 🏆 Goal
Build a comprehensive target profile for a company during the reconnaissance phase of an authorized engagement, without active probing.

## 📋 When to Use
Early-stage reconnaissance on an authorized target organization; scoping an engagement; building the target profile before active testing begins.


## Flow Information

**Name:** `CompanyOSINT`

**Description:**
```
Gathers public information about a target company including employees, email formats, 
technologies used, and social media presence for pre-engagement reconnaissance.
```

**Purpose:** Pre-engagement intelligence gathering for penetration testing

---

## Flow Variables

Define these variables in the "Flow Variables" section:

| Variable Name | Initial Value | Description |
|---------------|---------------|-------------|
| `company_name` | (empty) | Target company name |
| `domain` | (empty) | Company domain (e.g., acme.com) |
| `linkedin_data` | (empty) | LinkedIn scraping results |
| `github_data` | (empty) | GitHub search results |
| `tech_stack` | (empty) | Technology stack information |
| `employee_info` | (empty) | Analyzed employee data |
| `tech_analysis` | (empty) | Technology analysis results |
| `osint_report` | (empty) | Final compiled report |

---

## Flow Blocks

### Block 1: Public Company Pages (preferred)

Use the organization’s own public About, Team, and Careers pages where permitted. Do not automate LinkedIn or bypass access controls. Store only information needed to validate organization-level scope.

**Block Type:** Web Scraping

**Configuration:**
- **URL:** `https://www.linkedin.com/search/results/people/?keywords=${company_name}`
- **Capture Page Content As:** Text content only
- **Content Summarization:** Enabled (recommended)
- **Result Variable:** `linkedin_data`

**Purpose:** Gather organization-level information from public company pages

---

### Block 2: Web Scraping - GitHub

**Block Type:** Web Scraping

**Configuration:**
- **URL:** `https://github.com/search?q=${domain}&type=code`
- **Capture Page Content As:** Text content only
- **Content Summarization:** Enabled (recommended)
- **Result Variable:** `github_data`

**Purpose:** Find company code repositories and exposed information

---

### Block 3: Web Scraping - BuiltWith

**Block Type:** Web Scraping

**Configuration:**
- **URL:** `https://builtwith.com/${domain}`
- **Capture Page Content As:** Text content only
- **Content Summarization:** Enabled (recommended)
- **Result Variable:** `tech_stack`

**Purpose:** Identify technologies used by the company

---

### Block 4: LLM Instruction - Analyze Employee Info

**Block Type:** LLM Instruction

**Instruction:**
```
Analyze these authorized public company-page excerpts for ${company_name}:

${linkedin_data}

Extract only organization-level facts that are explicitly present:
1. Publicly stated business units and locations
2. Technologies the organization itself publicly identifies
3. Official security/contact channels

Do not infer employee email formats, identify individual targets, assess personal traits, or suggest social-engineering approaches. Mark uncertain matches as unverified and include the source URL and retrieval date.
```

**Result Variable:** `employee_info`

**Purpose:** Extract actionable intelligence from LinkedIn data

---

### Block 5: LLM Instruction - Technology Analysis

**Block Type:** LLM Instruction

**Instruction:**
```
Analyze technology stack for ${domain}:

BuiltWith Data: ${tech_stack}
GitHub Data: ${github_data}

Identify:
1. Web technologies (frameworks, CMS, servers)
2. Cloud providers and services
3. Third-party integrations
4. Development languages and frameworks
5. Potential attack surfaces
6. Known vulnerabilities in detected technologies

Prioritize findings by security relevance.
```

**Result Variable:** `tech_analysis`

**Purpose:** Identify technology stack and potential vulnerabilities

---

### Block 6: LLM Instruction - Compile OSINT Report

**Block Type:** LLM Instruction

**Instruction:**
```
Create comprehensive OSINT reconnaissance report:

Company: ${company_name}
Domain: ${domain}

Employee Intelligence: ${employee_info}
Technology Stack: ${tech_analysis}

Format as professional intelligence report:

# OSINT Report: ${company_name}

## Executive Summary
[Brief overview of findings]

## Employee Information
[Employee details, email formats, key personnel]

## Technology Stack
[Technologies, versions, vendors identified]

## Scope Leads
[Public organization-owned domains or systems requiring separate scope confirmation]

## Limitations
[Unverified matches, retrieval date, and sources]

## Recommendations
[Suggested next steps for penetration test]

Use professional security assessment language.
```

**Result Variable:** `osint_report`

**Purpose:** Compile all findings into professional report

---

### Block 7: Flow Complete

**Block Type:** Flow Complete

**Configuration:**
- Flow will end here and return results

---

## Usage Instructions

### Basic Usage

```
@agent use CompanyOSINT flow
company_name: Acme Corporation
domain: acme.com
```

### Example With Real Data

```
@agent use CompanyOSINT flow
company_name: Pacific Northwest Computers
domain: pnwcomputers.com
```

### Expected Output

The flow will return `osint_report` containing:
- Employee naming conventions and email formats
- Key personnel identification
- Technology stack analysis
- Attack surface assessment
- Social engineering opportunities
- Recommended next steps

---

## Integration with Other Flows

**Typical Workflow:**

1. **CompanyOSINT** (this flow) - Gather initial intelligence
2. **DomainRecon** - Map technical infrastructure
3. **EmailOSINT** - Investigate key personnel emails
4. **GitHubSecrets** - Deep dive into code repositories
5. **BreachChecker** - Check for compromised accounts

---

## Notes and Considerations

### Legal and Ethical

- ⚠️ Only use with proper authorization
- Ensure activities are within scope of engagement
- Follow all applicable laws and regulations
- Do not scrape LinkedIn or bypass authentication; use permitted public company sources

### Technical Considerations

- LinkedIn may require authentication or block scraping attempts
- BuiltWith free tier has limitations
- GitHub search has rate limits
- Results quality depends on target's public presence

### Optimization Tips

1. **For Better Results:**
   - Use full company legal name
   - Try variations if initial search fails
   - Allow time for web scraping (30-60 seconds per site)

2. **Alternative Data Sources:**
   - If LinkedIn fails, try company website "About" or "Team" pages
   - Check Crunchbase, AngelList for startup information
   - Search for company in security forums or breach databases

3. **Variable Substitution:**
   - Ensure variables use `${variable_name}` syntax
   - Test with known companies first
   - If scraping fails, check URLs manually

---

## Troubleshooting

| Issue | Solution |
|-------|----------|
| A source blocks automated access | Stop automated collection and use an approved public source or manual review |
| GitHub search fails | Use GitHub API with authentication token |
| BuiltWith blocks request | Add delay or use Wappalyzer alternative |
| Generic analysis | Provide more context in company_name |
| Variable not substituting | Check syntax: `${variable}` not `{{variable}}` |

---

## Version History

- **v1.0** - Initial flow creation
- Purpose: Pre-engagement OSINT for penetration testing
- Last Updated: November 2025

---

## Related Flows

- **DomainRecon** - Technical infrastructure mapping
- **EmailOSINT** - Email address investigation
- **GitHubSecrets** - Repository credential scanning
- **BreachChecker** - Breach data verification

## Related Files
- [README.md](README.md) - AnythingLLM AgentFlow index
- [flow-domain_recon.md](flow-domain_recon.md) - Technical domain recon to pair with this company profile
- [flow-email_osint.md](flow-email_osint.md) - Email investigation of contacts discovered here
- [flow-breacher_check.md](flow-breacher_check.md) - Breach checking for emails found here
