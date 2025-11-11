# EmailOSINT AgentFlow

## Flow Information

**Name:** `EmailOSINT`

**Description:**
```
Investigates email addresses or usernames across multiple platforms to find accounts, 
breaches, and public information for social engineering assessments.
```

**Purpose:** Email address intelligence and breach verification

---

## Flow Variables

Define these variables in the "Flow Variables" section:

| Variable Name | Initial Value | Description |
|---------------|---------------|-------------|
| `email_or_username` | (empty) | Target email address or username |
| `haveibeenpwned_data` | (empty) | Breach data from HIBP |
| `social_media_data` | (empty) | Social media search results |
| `breach_summary` | (empty) | Analyzed breach information |
| `social_profile` | (empty) | Social media profile analysis |
| `final_report` | (empty) | Complete intelligence report |

---

## Flow Blocks

### Block 1: API Call - HaveIBeenPwned Breach Check

**Block Type:** API Call

**Configuration:**
- **Method:** GET
- **URL:** `https://haveibeenpwned.com/api/v3/breachedaccount/${email_or_username}`
- **Headers:**
  ```json
  {
    "hibp-api-key": "YOUR_HIBP_API_KEY",
    "user-agent": "PenTest-Research"
  }
  ```
- **Result Variable:** `haveibeenpwned_data`

**Purpose:** Check if email appears in known data breaches

**API Key:** Get free key at https://haveibeenpwned.com/API/Key

**Note:** HaveIBeenPwned requires API key for automated queries

---

### Block 2: Web Scraping - Social Media Search

**Block Type:** Web Scraping

**Configuration:**
- **URL:** `https://www.google.com/search?q="${email_or_username}"+site:linkedin.com+OR+site:twitter.com+OR+site:facebook.com`
- **Capture Page Content As:** Text content only
- **Content Summarization:** Enabled
- **Result Variable:** `social_media_data`

**Purpose:** Find associated social media accounts

**Alternative URLs:**
- `https://www.google.com/search?q="${email_or_username}"+site:github.com`
- `https://www.google.com/search?q="${email_or_username}"+inurl:profile`

---

### Block 3: LLM Instruction - Breach Analysis

**Block Type:** LLM Instruction

**Instruction:**
```
Analyze breach data for ${email_or_username}:

${haveibeenpwned_data}

Provide comprehensive breach analysis:

## Breach Summary
- Total number of breaches found
- Most recent breach date
- Oldest breach date

## Breached Services
List each breached service with:
- Service name
- Breach date
- Number of accounts affected
- Severity level

## Data Types Exposed
Categorize exposed data:
- Passwords (hashed/plaintext)
- Email addresses
- Personal information (names, addresses, phone)
- Financial data
- Security questions/answers
- IP addresses
- Other sensitive data

## Risk Assessment
- Password reuse risk level (High/Medium/Low)
- Account takeover likelihood
- Identity theft potential
- Social engineering implications

## Recommendations
- Immediate actions required
- Account security improvements
- Monitoring suggestions

Format professionally for security assessment report.
```

**Result Variable:** `breach_summary`

**Purpose:** Analyze and contextualize breach data

---

### Block 4: LLM Instruction - Social Media Profile Analysis

**Block Type:** LLM Instruction

**Instruction:**
```
Analyze social media presence for ${email_or_username}:

${social_media_data}

Extract intelligence:

## Confirmed Social Media Accounts
List each identified account with:
- Platform (LinkedIn, Twitter, Facebook, GitHub, etc.)
- Profile URL (if found)
- Account status (active/inactive)
- Verification status

## Public Information Shared
Identify publicly visible information:
- Personal details (location, birthday, relationships)
- Professional information (employer, job title, skills)
- Interests and activities
- Connections and associations
- Photos and media
- Contact information

## Security Awareness Indicators
Assess target's security posture:
- Privacy settings (public vs. private)
- Information oversharing
- Security-related posts or discussions
- Technology literacy indicators
- Security tool usage mentions

## Social Engineering Opportunities
Identify potential vectors:
- Topics of interest for phishing themes
- Trusted contacts/relationships
- Behavioral patterns
- Emotional triggers
- Professional concerns

## OPSEC Assessment
- Information disclosure rating
- Privacy consciousness
- Digital footprint size
- Security awareness level

⚠️ Note: Use only for authorized security assessments
```

**Result Variable:** `social_profile`

**Purpose:** Create social engineering intelligence profile

---

### Block 5: LLM Instruction - Compile Final Report

**Block Type:** LLM Instruction

**Instruction:**
```
Create comprehensive email/username intelligence report:

Target: ${email_or_username}

Breach Data: ${breach_summary}
Social Media Intelligence: ${social_profile}

Format as professional OSINT report:

# OSINT Intelligence Report
## Target: ${email_or_username}

### Executive Summary
[Brief overview of findings and risk level]

### Breach History
${breach_summary}

### Social Media Presence
${social_profile}

### Overall Security Posture
[Assessment of target's security awareness and digital hygiene]

### Social Engineering Vectors
[Potential attack methods based on gathered intelligence]

### Recommendations for Testing
[Suggested approaches for authorized social engineering assessment]

### Defensive Recommendations
[If reporting to target: steps to improve security posture]

---
*Report generated for authorized security assessment*
*Date: [Current date]*
```

**Result Variable:** `final_report`

**Purpose:** Compile all intelligence into deliverable format

---

### Block 6: Flow Complete

**Block Type:** Flow Complete

**Configuration:**
- Flow will end here and return results

---

## Usage Instructions

### Basic Usage

```
@agent use EmailOSINT flow
email_or_username: john.doe@target.com
```

### Username Search

```
@agent use EmailOSINT flow
email_or_username: johndoe
```

### Expected Output

The flow will return `final_report` containing:
- Complete breach history with data exposed
- Social media account discovery
- Public information analysis
- Security awareness assessment
- Social engineering opportunities
- Recommendations

---

## Integration with Other Flows

**Typical Workflow:**

1. **CompanyOSINT** - Identify key personnel and email formats
2. **EmailOSINT** (this flow) - Investigate specific individuals
3. **BreachChecker** - Cross-verify breach data
4. **GitHubSecrets** - Check for code commits under username

**Social Engineering Assessment:**
1. **CompanyOSINT** → Get target list
2. **EmailOSINT** → Profile each target
3. Compile social engineering strategy

---

## API Key Setup

### HaveIBeenPwned API Key

**Required for Block 1**

1. Visit: https://haveibeenpwned.com/API/Key
2. Subscribe ($3.50/month as of 2025)
3. Receive API key via email
4. Add to flow: Replace `YOUR_HIBP_API_KEY` with actual key

**Rate Limits:**
- 10 requests per minute with API key
- Respect rate limits to avoid blocking

---

## Alternative Configurations

### Without HaveIBeenPwned API

**Replace Block 1 with web scraping:**

```
Block Type: Web Scraping
URL: https://haveibeenpwned.com/account/${email_or_username}
Capture: Text content only
Result Variable: haveibeenpwned_data
```

**Note:** May be blocked or require CAPTCHA

### Additional Intelligence Sources

**Add Block for Paste Sites:**

```
Block Type: API Call
Method: GET
URL: https://haveibeenpwned.com/api/v3/pasteaccount/${email_or_username}
Headers: {"hibp-api-key": "YOUR_KEY"}
Result Variable: paste_data
```

**Add Block for DeHashed (requires subscription):**

```
Block Type: API Call
Method: GET
URL: https://api.dehashed.com/search?query=email:${email_or_username}
Headers: {
  "Accept": "application/json",
  "Authorization": "Bearer YOUR_DEHASHED_KEY"
}
Result Variable: dehashed_data
```

---

## Notes and Considerations

### Legal and Ethical

- ⚠️ **Authorization Required** - Only use with written permission
- **Privacy Laws** - Respect GDPR, CCPA, and local privacy regulations
- **Data Handling** - Secure storage and proper disposal of PII
- **Purpose Limitation** - Use only for authorized security assessments
- **Informed Consent** - Target organization must authorize investigation

### Technical Considerations

- **False Positives** - Common names/usernames may return unrelated results
- **Rate Limiting** - HIBP has request limits even with API key
- **Google CAPTCHA** - Social media search may trigger CAPTCHA
- **Account Privacy** - Private social media accounts won't show details

### Data Sensitivity

- **PII Handling** - Treat discovered information as confidential
- **Report Security** - Encrypt reports containing personal data
- **Retention** - Follow data retention policies
- **Disclosure** - Report findings only to authorized parties

---

## Optimization Tips

### For Better Breach Detection:

1. **Try Variations:**
   - email@domain.com
   - email+tag@domain.com
   - Alternative email formats

2. **Cross-Reference:**
   - Check multiple breach databases
   - Verify findings with target
   - Look for credential reuse patterns

### For Better Social Media Discovery:

1. **Use Multiple Search Engines:**
   - Google
   - Bing
   - DuckDuckGo (privacy-focused)

2. **Try Different Search Queries:**
   - `"email" site:linkedin.com`
   - `"username" profile`
   - `"firstname lastname" company`

3. **Check Additional Platforms:**
   - GitHub (developer profiles)
   - Stack Overflow (technical users)
   - Reddit (usernames)
   - Medium (bloggers)

---

## Troubleshooting

| Issue | Solution |
|-------|----------|
| HIBP returns no data | Email may not be breached; verify email is correct |
| API authentication fails | Check API key is valid and properly formatted |
| Social media search blocked | Google CAPTCHA triggered; try manual search |
| Too much irrelevant data | Use more specific search terms or filters |
| Generic analysis | Provide additional context about target |
| Rate limit exceeded | Wait 1 minute between requests for HIBP |

---

## Post-Flow Actions

**After running EmailOSINT:**

1. **Verify Findings** - Confirm breach data is accurate
2. **Document Results** - Add to engagement documentation
3. **Assess Risk** - Determine if passwords should be tested
4. **Report Responsibly** - Notify client of serious exposures
5. **Update Target List** - Refine social engineering targets

---

## Use Cases

### Penetration Testing
- Identify compromised credentials for password spraying
- Build social engineering pretexts
- Discover forgotten accounts
- Map target's digital footprint

### Security Awareness Training
- Demonstrate breach exposure to employees
- Educate on password reuse risks
- Show social media oversharing consequences

### Incident Response
- Investigate compromised accounts
- Track attacker email addresses
- Correlate breach timelines

### Red Team Operations
- Profile high-value targets
- Craft convincing phishing campaigns
- Identify trust relationships

---

## Version History

- **v1.0** - Initial flow with HIBP and social media search
- Purpose: Email intelligence for authorized assessments
- Last Updated: November 2025

---

## Related Flows

- **CompanyOSINT** - Identify target emails
- **BreachChecker** - Domain-wide breach checking
- **GitHubSecrets** - Username code search
- **VulnReportGenerator** - Document findings
