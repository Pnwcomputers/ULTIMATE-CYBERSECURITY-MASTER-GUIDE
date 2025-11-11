# GitHubSecrets AgentFlow

## Flow Information

**Name:** `GitHubSecrets`

**Description:**
```
Searches GitHub for accidentally exposed credentials, API keys, and sensitive 
information related to target domain or company.
```

**Purpose:** Discover exposed secrets in public code repositories

---

## Flow Variables

Define these variables in the "Flow Variables" section:

| Variable Name | Initial Value | Description |
|---------------|---------------|-------------|
| `target_domain` | (empty) | Target domain or company name |
| `github_search_results` | (empty) | GitHub code search results |
| `commit_data` | (empty) | Commit history search results |
| `secret_findings` | (empty) | Identified secrets and credentials |
| `risk_assessment` | (empty) | Risk analysis and recommendations |

---

## Flow Blocks

### Block 1: Web Scraping - GitHub Code Search

**Block Type:** Web Scraping

**Configuration:**
- **URL:** `https://github.com/search?q=${target_domain}+password+OR+api_key+OR+secret&type=code`
- **Capture Page Content As:** Text content only
- **Content Summarization:** Enabled (recommended)
- **Result Variable:** `github_search_results`

**Purpose:** Search public code for exposed credentials

**Search Pattern Explanation:**
- `${target_domain}` - Target organization
- `password OR api_key OR secret` - Common credential keywords
- `type=code` - Search in code files

---

### Block 2: Web Scraping - GitHub Commit History

**Block Type:** Web Scraping

**Configuration:**
- **URL:** `https://github.com/search?q=${target_domain}+remove+password+OR+remove+key&type=commits`
- **Capture Page Content As:** Text content only
- **Content Summarization:** Enabled
- **Result Variable:** `commit_data`

**Purpose:** Find credentials in deleted/removed commits

**Note:** Developers often commit secrets then try to remove them - but they remain in git history

---

### Block 3: LLM Instruction - Identify Secrets

**Block Type:** LLM Instruction

**Instruction:**
```
Analyze GitHub search results for ${target_domain}:

Code Search Results: ${github_search_results}
Commit History: ${commit_data}

Identify and categorize exposed secrets:

## Credentials Found

### 1. Passwords and Authentication
- Plain text passwords
- Hashed passwords (note algorithm)
- Default/hardcoded credentials
- SSH private keys
- PGP private keys

### 2. API Keys and Tokens
- AWS Access Keys (AKIA...)
- Google API keys
- GitHub Personal Access Tokens
- Slack tokens
- Stripe API keys
- OAuth tokens
- JWT secrets

### 3. Database Credentials
- Database connection strings
- MySQL/PostgreSQL credentials
- MongoDB URIs
- Redis passwords
- Database hostnames and ports

### 4. Cloud Provider Credentials
- AWS credentials (access key + secret)
- Azure connection strings
- Google Cloud service account keys
- DigitalOcean tokens
- Heroku API keys

### 5. Third-Party Service Keys
- SendGrid API keys
- Twilio credentials
- PayPal API credentials
- Mailgun keys
- Analytics tracking IDs

### 6. Internal Information
- Internal IP addresses
- Internal hostnames/URLs
- VPN configurations
- Network diagrams
- Architecture details

### 7. Configuration Files
- .env files with secrets
- config.json with credentials
- docker-compose with passwords
- Kubernetes secrets
- Ansible vault passwords

## Risk Classification

For each finding, assign:
- **CRITICAL:** Active production credentials with high privilege
- **HIGH:** Valid credentials with significant access
- **MEDIUM:** Expired/limited credentials or internal info
- **LOW:** Test/development credentials or public info

## Evidence

For each high-risk finding:
- Repository name and URL
- File path
- Line number
- Commit hash
- Date committed
- Committer username

Flag CRITICAL and HIGH findings immediately for urgent action.
```

**Result Variable:** `secret_findings`

**Purpose:** Extract and classify exposed secrets

---

### Block 4: LLM Instruction - Risk Assessment

**Block Type:** LLM Instruction

**Instruction:**
```
Assess security risk of exposed secrets for ${target_domain}:

Findings: ${secret_findings}

Provide comprehensive risk assessment:

## Executive Summary
- Total secrets found: [number]
- Critical findings: [number]
- High-risk findings: [number]
- Overall risk level: [CRITICAL/HIGH/MEDIUM/LOW]

## Critical Findings Requiring Immediate Action

For each CRITICAL finding:
1. **Type of secret** (AWS key, database password, etc.)
2. **Location** (repository, file, line)
3. **Exposure duration** (date first committed)
4. **Potential impact** (what attacker could access)
5. **Immediate remediation** (rotate key, revoke token, etc.)

## Impact Analysis

Describe potential consequences:
- Unauthorized system access
- Data breach possibilities
- Financial impact
- Compliance violations
- Reputational damage

## Remediation Priority

### Priority 1 (Immediate - Within 1 hour)
[CRITICAL items requiring immediate action]

### Priority 2 (Urgent - Within 24 hours)
[HIGH risk items]

### Priority 3 (Important - Within 1 week)
[MEDIUM risk items]

## Remediation Steps

For exposed credentials:
1. **Immediately rotate/revoke** all exposed credentials
2. **Audit access logs** for unauthorized use
3. **Remove secrets** from repository history using git-filter-branch or BFG
4. **Scan for compromise** - check if credentials were used
5. **Implement secrets management** (AWS Secrets Manager, HashiCorp Vault)

For exposed internal information:
1. **Assess sensitivity** of exposed information
2. **Review network segmentation** if internal IPs exposed
3. **Update security policies** to prevent future exposure

## Prevention Recommendations

1. **Pre-commit hooks** - Install git-secrets or similar tools
2. **Secrets scanning** - Use GitHub Advanced Security or third-party tools
3. **Developer training** - Educate on secure coding practices
4. **Code review process** - Review all commits for secrets
5. **Environment variables** - Use env vars, never hardcode secrets
6. **Secret management** - Implement enterprise secrets management

## Evidence for Client Notification

Provide details to share with client:
- List of exposed repositories
- Types of data compromised
- Recommended urgent actions
- Timeline for remediation

Format as professional security incident report.
```

**Result Variable:** `risk_assessment`

**Purpose:** Provide actionable remediation guidance

---

### Block 5: Flow Complete

**Block Type:** Flow Complete

**Configuration:**
- Flow will end here and return results

---

## Usage Instructions

### Basic Usage

```
@agent use GitHubSecrets flow
target_domain: acme.com
```

### Company Name Search

```
@agent use GitHubSecrets flow
target_domain: Acme Corporation
```

### Expected Output

The flow will return `risk_assessment` containing:
- Complete list of exposed secrets
- Risk classification for each finding
- Impact analysis
- Prioritized remediation steps
- Prevention recommendations
- Evidence for client notification

---

## Integration with Other Flows

**Typical Workflow:**

1. **CompanyOSINT** - Identify company domains and repositories
2. **GitHubSecrets** (this flow) - Scan for exposed secrets
3. **EmailOSINT** - Investigate developer accounts
4. **ThreatIntelCheck** - Check if exposed IPs are malicious
5. **VulnReportGenerator** - Document findings for client

**Incident Response:**
1. Discover potential breach
2. Run GitHubSecrets to check for credential exposure
3. Cross-reference with access logs
4. Determine scope of compromise

---

## Advanced Search Patterns

### Alternative Block 1 URLs for Specific Secrets:

**AWS Credentials:**
```
https://github.com/search?q=${target_domain}+AKIA&type=code
```

**Private Keys:**
```
https://github.com/search?q=${target_domain}+BEGIN+RSA+PRIVATE+KEY&type=code
```

**Database Passwords:**
```
https://github.com/search?q=${target_domain}+filename:.env+password&type=code
```

**API Keys:**
```
https://github.com/search?q=${target_domain}+api_key+OR+apikey+OR+api-key&type=code
```

**Configuration Files:**
```
https://github.com/search?q=${target_domain}+filename:config.json+OR+filename:.env&type=code
```

---

## Notes and Considerations

### Legal and Ethical

- ⚠️ **Public Data Only** - GitHub public repositories are fair game
- **Responsible Disclosure** - Report findings to target organization
- **No Exploitation** - Do not use discovered credentials without authorization
- **Document Everything** - Keep evidence of findings
- **Client Notification** - Inform client immediately of critical findings

### Technical Considerations

- **Rate Limiting** - GitHub limits search queries
- **Authentication** - GitHub API provides better results (requires token)
- **False Positives** - Test/demo credentials may appear
- **Repository Forks** - Same secrets may appear in multiple forks
- **Content Size** - Search results can be extensive

### Common False Positives

- Example/demo code with fake credentials
- Test repositories with dummy data
- Documentation showing credential formats
- Third-party code repositories
- Archived/unmaintained projects

---

## Optimization Tips

### For Better Results:

1. **Use GitHub API (Advanced):**
   ```
   Block Type: API Call
   Method: GET
   URL: https://api.github.com/search/code?q=${target_domain}+password
   Headers: {"Authorization": "token YOUR_GITHUB_TOKEN"}
   ```

2. **Search Multiple Patterns:**
   - Run flow multiple times with different keywords
   - password, secret, api_key, token, credentials

3. **Check Organization Repositories:**
   - `https://github.com/orgs/${target_domain}/repositories`
   - Focus on organization's official repos

4. **Review Recent Commits:**
   - Prioritize recent commits (more likely to be active)
   - Check commit dates in findings

### For Better Analysis:

1. **Validate Findings:**
   - Check if credentials are still active
   - Test database connections (with authorization)
   - Verify API keys work

2. **Check Git History:**
   - Secrets may be removed from HEAD but remain in history
   - Use `git log` to find when secret was added

3. **Automated Tools:**
   - TruffleHog - Deep git history scanning
   - GitLeaks - Pattern-based secret detection
   - git-secrets - Pre-commit hook

---

## Troubleshooting

| Issue | Solution |
|-------|----------|
| No results found | Domain may not have public repos; try company name |
| Too many results | Narrow search with specific keywords |
| Rate limit exceeded | Wait or use GitHub API with authentication |
| False positives | Filter test repos in LLM analysis |
| Can't access repos | Repo may be private; only public repos searchable |
| Generic findings | Add more specific domain terms to search |

---

## Post-Flow Actions

**After discovering secrets:**

1. **Immediate Actions:**
   - Document all findings with screenshots
   - Notify client immediately of critical findings
   - Recommend emergency credential rotation

2. **Verification:**
   - Test if credentials are still active (with authorization)
   - Check access logs for unauthorized use
   - Determine blast radius

3. **Remediation:**
   - Help client rotate exposed credentials
   - Remove secrets from git history
   - Implement secrets management solution

4. **Prevention:**
   - Recommend pre-commit hooks
   - Implement automated secret scanning
   - Provide developer training

---

## Additional Search Targets

### File Types to Check:
- `.env` files
- `config.json`
- `settings.py`
- `application.properties`
- `.npmrc`
- `.pypirc`
- `docker-compose.yml`
- `kubernetes/*.yaml`

### Keyword Variations:
- password, passwd, pwd
- api_key, apikey, api-key, key
- secret, token, auth
- username, user, login
- database, db, connection
- aws_access_key, aws_secret
- private_key, ssh_key

---

## Real-World Examples

### Example 1: AWS Key Discovery
```
Finding: AWS Access Key in .env file
Location: github.com/company/webapp/blob/main/.env
Impact: Full AWS account access, potential data breach
Action: Immediate key rotation, audit CloudTrail logs
```

### Example 2: Database Credentials
```
Finding: Production database password in config.json
Location: github.com/company/api/blob/main/config/production.json
Impact: Direct database access with customer PII
Action: Change password, review database access logs
```

### Example 3: API Keys
```
Finding: Stripe API key in payment processor code
Location: github.com/company/payments/blob/main/stripe.js
Impact: Unauthorized payment processing, financial loss
Action: Revoke key, audit transactions, implement secrets vault
```

---

## Version History

- **v1.0** - Initial flow with code and commit search
- Purpose: Discover exposed credentials for security assessment
- Last Updated: November 2025

---

## Related Flows

- **CompanyOSINT** - Identify target repositories
- **EmailOSINT** - Investigate developer accounts
- **DomainRecon** - Discover additional domains to search
- **VulnReportGenerator** - Document exposed secrets
- **BreachChecker** - Check if credentials were breached
