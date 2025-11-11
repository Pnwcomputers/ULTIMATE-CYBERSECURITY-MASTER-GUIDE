# BreachChecker AgentFlow

## Flow Information

**Name:** `BreachChecker`

**Description:**
```
Checks if company email domain or specific addresses appear in known data breaches 
for security awareness assessment and credential exposure verification.
```

**Purpose:** Domain-wide breach detection and exposure assessment

---

## Flow Variables

Define these variables in the "Flow Variables" section:

| Variable Name | Initial Value | Description |
|---------------|---------------|-------------|
| `domain_or_email` | (empty) | Target domain or email address |
| `breach_data` | (empty) | Breach account data from HIBP |
| `paste_data` | (empty) | Paste site data from HIBP |
| `risk_report` | (empty) | Complete risk assessment |

---

## Flow Blocks

### Block 1: API Call - HaveIBeenPwned Breach Check

**Block Type:** API Call

**Configuration:**
- **Method:** GET
- **URL:** `https://haveibeenpwned.com/api/v3/breachedaccount/${domain_or_email}`
- **Headers:**
  ```json
  {
    "hibp-api-key": "YOUR_HIBP_API_KEY",
    "user-agent": "Security-Assessment"
  }
  ```
- **Result Variable:** `breach_data`

**Purpose:** Check breached accounts database

**Note:** Requires HaveIBeenPwned API key

---

### Block 2: API Call - HaveIBeenPwned Pastes

**Block Type:** API Call

**Configuration:**
- **Method:** GET
- **URL:** `https://haveibeenpwned.com/api/v3/pasteaccount/${domain_or_email}`
- **Headers:**
  ```json
  {
    "hibp-api-key": "YOUR_HIBP_API_KEY",
    "user-agent": "Security-Assessment"
  }
  ```
- **Result Variable:** `paste_data`

**Purpose:** Check paste sites (Pastebin, GitHub gists, etc.)

**Note:** Pastebin dumps often contain credential lists

---

### Block 3: LLM Instruction - Analyze Breach Impact

**Block Type:** LLM Instruction

**Instruction:**
```
Analyze comprehensive breach exposure for ${domain_or_email}:

Breach Data: ${breach_data}
Paste Site Data: ${paste_data}

Provide detailed breach impact assessment:

## Breach Summary

### Total Exposure
- Total unique breaches: [count]
- Total paste site appearances: [count]
- Date range: [earliest] to [most recent]
- Overall risk level: [CRITICAL/HIGH/MEDIUM/LOW]

### Breach Timeline
List breaches chronologically:
- [Date] - [Breach Name] - [Data exposed]

## Breach Details

For each breach, provide:

### [Breach Name]
- **Date:** [breach date]
- **Accounts affected:** [number]
- **Breach severity:** [rating]
- **Data types exposed:**
  - Passwords (plaintext/hashed/algorithm)
  - Email addresses
  - Usernames
  - Personal information (names, addresses, DOB)
  - Phone numbers
  - Security questions/answers
  - Payment information
  - IP addresses
  - Physical addresses
  - Social media profiles
  - Other sensitive data

- **Breach source:** [website/service name]
- **Verification status:** [Verified/Unverified]

## Paste Site Exposure

For each paste:
- **Paste ID:** [identifier]
- **Source:** [Pastebin/Slexy/Ghostbin/etc.]
- **Date:** [when posted]
- **Email count:** [how many emails in paste]
- **Content type:** [credential dump/database leak/other]

## Risk Assessment

### Password Reuse Risk
- **Risk Level:** [HIGH/MEDIUM/LOW]
- **Reasoning:** [analysis of exposed passwords and hashing]
- **Exploitation likelihood:** [percentage or rating]
- **Credential stuffing risk:** [HIGH/MEDIUM/LOW]

### Account Takeover Likelihood
- **Risk Level:** [HIGH/MEDIUM/LOW]
- **Attack vectors:** [list potential attack methods]
- **Target accounts:** [which accounts at risk]

### Identity Theft Potential
- **Risk Level:** [HIGH/MEDIUM/LOW]
- **Exposed PII:** [list personal information exposed]
- **Impact:** [describe identity theft risks]

### Social Engineering Risk
- **Risk Level:** [HIGH/MEDIUM/LOW]
- **Exposed information useful for:**
  - Phishing campaigns
  - Pretexting attacks
  - Password reset social engineering
  - Security question bypass

### Compliance Impact
- **Regulatory concerns:**
  - GDPR implications
  - CCPA requirements
  - PCI-DSS impact (if payment data exposed)
  - HIPAA considerations (if health data exposed)
  - Industry-specific regulations

## Data Type Analysis

### Passwords
- Total breaches with passwords: [count]
- Plaintext passwords: [count]
- Hashed passwords: [count and algorithms]
- Password cracking difficulty: [easy/moderate/hard]

### Personal Information
- Names: [exposed in X breaches]
- Addresses: [exposed in X breaches]
- Phone numbers: [exposed in X breaches]
- Dates of birth: [exposed in X breaches]

### Financial Data
- Credit card information: [yes/no]
- Payment methods: [exposed types]
- Banking information: [yes/no]

## Recommendations

### Immediate Actions (Within 24 hours)
1. **Password Reset:** Change passwords for affected accounts
2. **Enable MFA:** Activate multi-factor authentication everywhere possible
3. **Account Monitoring:** Check recent activity on exposed accounts
4. **Security Alerts:** Enable breach notifications

### Short-term Actions (Within 1 week)
1. **Password Manager:** Implement unique passwords for all accounts
2. **Security Audit:** Review all account security settings
3. **Password Policy:** Update to enforce strong, unique passwords
4. **User Education:** Train users on breach implications

### Long-term Actions (Within 1 month)
1. **Continuous Monitoring:** Implement breach monitoring service
2. **Incident Response Plan:** Develop breach response procedures
3. **Security Awareness:** Regular user security training
4. **Zero Trust:** Consider passwordless authentication

### For Organizations
1. **User Notification:** Inform affected employees of exposure
2. **Policy Review:** Update security policies
3. **Credential Rotation:** Force password changes across organization
4. **Monitoring:** Implement dark web monitoring for domain
5. **Insurance:** Consider cyber insurance if not already covered

## Evidence for Reporting

### Summary Statistics
- Total breaches: [X]
- Total accounts exposed: [Y]
- Oldest breach: [date]
- Most recent breach: [date]
- Highest severity breach: [name]

### Critical Breaches (Passwords/Financial Data)
List breaches requiring immediate attention

### Supporting Documentation
- HIBP breach references
- Paste site URLs (if appropriate to share)
- Timeline visualization suggestion

Format as professional security assessment suitable for client presentation or internal reporting.
```

**Result Variable:** `risk_report`

**Purpose:** Comprehensive breach analysis and remediation guidance

---

### Block 4: Flow Complete

**Block Type:** Flow Complete

**Configuration:**
- Flow will end here and return results

---

## Usage Instructions

### Domain-Wide Check

```
@agent use BreachChecker flow
domain_or_email: acme.com
```

### Specific Email Check

```
@agent use BreachChecker flow
domain_or_email: john.doe@acme.com
```

### Expected Output

The flow will return `risk_report` containing:
- Complete list of breaches affecting domain/email
- Detailed analysis of exposed data
- Risk assessment for various attack vectors
- Prioritized remediation recommendations
- Compliance considerations
- Evidence for client reporting

---

## Integration with Other Flows

**Typical Workflow:**

1. **CompanyOSINT** - Identify company domain and key personnel
2. **BreachChecker** (this flow) - Check domain-wide exposure
3. **EmailOSINT** - Deep dive on specific exposed emails
4. **VulnReportGenerator** - Document findings for client

**Security Assessment:**
1. **BreachChecker** → Identify exposed credentials
2. **CVELookup** → Check if exposed services are vulnerable
3. Combine findings for comprehensive risk picture

**Incident Response:**
1. Suspect credential compromise
2. Run BreachChecker to verify exposure
3. Determine scope and timeline
4. Execute remediation plan

---

## API Key Setup

### HaveIBeenPwned API Key

**Required for this flow**

1. **Get API Key:**
   - Visit: https://haveibeenpwned.com/API/Key
   - Subscribe ($3.50/month as of 2025)
   - Receive key via email

2. **Add to Flow:**
   - Replace `YOUR_HIBP_API_KEY` in both blocks
   - Keep key secure (don't commit to git)

3. **Rate Limits:**
   - 10 requests per minute with API key
   - Respect limits to maintain access

---

## Alternative Configurations

### Without API Key (Limited)

**Replace Block 1 with web scraping:**

```
Block Type: Web Scraping
URL: https://haveibeenpwned.com/domain/${domain_or_email}
Capture: Text content only
Result Variable: breach_data
```

**Limitations:**
- May require CAPTCHA solving
- Less reliable than API
- Potential blocking
- No paste site data

### Additional Data Sources

**Add DeHashed Integration (requires subscription):**

```
Block Type: API Call
Method: GET
URL: https://api.dehashed.com/search?query=domain:${domain_or_email}
Headers: {
  "Accept": "application/json",
  "Authorization": "Bearer YOUR_DEHASHED_API_KEY"
}
Result Variable: dehashed_data
```

**Add Intelligence X (requires account):**

```
Block Type: API Call
Method: GET
URL: https://2.intelx.io/phonebook/search?k=YOUR_KEY&term=${domain_or_email}
Result Variable: intelx_data
```

---

## Notes and Considerations

### Legal and Ethical

- ⚠️ **Authorization Required** - Only check domains you're authorized to assess
- **Data Privacy** - HIBP data is sensitive; handle appropriately
- **Responsible Disclosure** - Report findings to affected organization
- **No Exploitation** - Don't use exposed credentials without permission
- **Compliance** - Follow breach notification laws if required

### Technical Considerations

- **Domain vs. Email:**
  - Domain check: Shows all breaches affecting @domain.com
  - Email check: Shows breaches for specific address
  
- **Historical Data:**
  - HIBP contains historical breaches (some very old)
  - Recent breaches more relevant for active threats
  
- **Data Verification:**
  - HIBP verifies major breaches
  - Some pastes unverified
  - Cross-reference when possible

### Data Sensitivity

- **Report Handling:** Breach reports contain PII
- **Secure Storage:** Encrypt reports at rest
- **Access Control:** Limit who can view findings
- **Retention:** Follow data retention policies
- **Client Notification:** Inform client promptly of exposure

---

## Optimization Tips

### For Better Results:

1. **Check Multiple Formats:**
   - company.com
   - @company.com
   - Variations (company.co, company.net)

2. **Check Key Personnel:**
   - CEO/executives
   - IT staff
   - Security team
   - After domain check, investigate specific high-value emails

3. **Historical Analysis:**
   - Note breach dates
   - Recent breaches more concerning
   - Old breaches may have been addressed

### For Better Assessment:

1. **Prioritize Active Threats:**
   - Recent breaches (last 12 months)
   - Plaintext passwords
   - Financial data exposure
   - Healthcare information

2. **Consider Context:**
   - Industry-specific risks
   - Regulatory requirements
   - Company size and maturity
   - Existing security posture

3. **Actionable Recommendations:**
   - Focus on what client can do now
   - Prioritize by risk and feasibility
   - Provide specific steps

---

## Troubleshooting

| Issue | Solution |
|-------|----------|
| No breaches found | Good news! Domain may not be breached |
| API authentication fails | Verify API key is correct and active |
| Rate limit exceeded | Wait 1 minute between requests |
| Domain returns no data | Try specific email addresses instead |
| Too much data | Focus analysis on recent/critical breaches |
| Conflicting breach data | HIBP is authoritative source; trust it |

---

## Real-World Examples

### Example 1: Domain-Wide Assessment
```
Input: acme.com
Result: 
- 1,234 email addresses exposed
- 15 major breaches affecting domain
- Most recent: Acme Breach (2024)
- Critical: Plaintext passwords exposed in 3 breaches
Action: Force password reset for all users
```

### Example 2: Executive Email Check
```
Input: ceo@company.com
Result:
- 8 breaches found
- LinkedIn breach (2012) - hashed passwords
- Adobe breach (2013) - passwords, payment info
- Collection #1 (2019) - plaintext passwords
Action: Immediate password change, enable MFA
```

### Example 3: Paste Site Discovery
```
Input: startup.com
Result:
- 0 major breaches
- 2 paste site appearances
- Pastebin dump (2023) - 50 credentials
- Employee credentials exposed in combo list
Action: Reset affected passwords, investigate compromise
```

---

## Post-Flow Actions

**After discovering breaches:**

1. **Immediate Response (Day 1):**
   - Notify client of findings
   - Recommend immediate password changes
   - Enable MFA on critical accounts
   - Monitor for unauthorized access

2. **Short-term (Week 1):**
   - Force organization-wide password reset
   - Audit recent account activity
   - Implement breach monitoring
   - Security awareness communication

3. **Long-term (Month 1):**
   - Implement continuous monitoring
   - Update security policies
   - User security training
   - Consider identity protection services

---

## Reporting Template

### Executive Summary Format:

```
Breach Exposure Assessment for [Company]

FINDINGS:
- X email addresses from @domain.com found in Y breaches
- Most critical: [breach name] exposed [data types]
- Overall risk: [HIGH/MEDIUM/LOW]

IMMEDIATE ACTIONS:
1. [First priority action]
2. [Second priority action]
3. [Third priority action]

IMPACT:
- Credential stuffing risk
- Account takeover potential
- Compliance implications

TIMELINE:
- Oldest breach: [date]
- Most recent: [date]
- Active threat window: [duration]
```

---

## Version History

- **v1.0** - Initial flow with HIBP breach and paste checking
- Purpose: Domain-wide breach exposure assessment
- Last Updated: November 2025

---

## Related Flows

- **CompanyOSINT** - Identify company domain and personnel
- **EmailOSINT** - Deep dive on specific addresses
- **GitHubSecrets** - Check for exposed credentials in code
- **VulnReportGenerator** - Document breach findings
- **ThreatIntelCheck** - Correlate with threat intelligence
