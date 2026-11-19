# GitHubSecrets AgentFlow

## 🎯 Purpose
AnythingLLM AgentFlow for reviewing **pre-redacted secret-scanning alerts** from repositories an organization owns or is explicitly authorized to assess. The flow reports exposure metadata for owner remediation; it must never ingest or reproduce a credential value.

## ⚙️ Function
Uses owner-approved secret-scanning alert metadata. Raw public code, commit content, and credential values stay in the scanner's authorized environment and never enter the LLM context.

## 🏆 Goal
Review possible credential exposure in authorized repositories and provide redacted remediation metadata to the owner.

## 📋 When to Use
- OSINT phase of an authorized engagement: checking target's GitHub for exposed secrets
- Threat intelligence: monitoring for your own organization's accidental credential exposure
- Authorized assessment to identify possible secret exposure for the repository owner; never use or validate a discovered credential without separately documented authorization

## Flow Information

**Name:** `GitHubSecrets`

**Description:**
```
Summarizes pre-redacted secret-scanning alerts for an authorized organization. The flow never receives or returns credential values.
```

**Purpose:** Summarize redacted alerts from approved repository scans

---

## Flow Variables

Define these variables in the "Flow Variables" section. Populate the result variables only with **redacted scanner metadata**, never raw code, source snippets, secret values, private keys, passwords or full tokens:

| Variable Name | Initial Value | Description |
|---------------|---------------|-------------|
| `target_domain` | (empty) | Target domain or company name |
| `github_search_results` | (empty) | Pre-redacted alert metadata: type, repository, path, line, commit and scanner alert ID |
| `commit_data` | (empty) | Pre-redacted historical alert metadata; no source lines or values |
| `secret_findings` | (empty) | Redacted findings only; no credential values |
| `risk_assessment` | (empty) | Risk analysis and recommendations |

---

## Flow Blocks

> [!CAUTION]
> **Never pass raw secret-scanner output, code lines, private keys, passwords or tokens to the LLM.** Use a trusted scanner and redact locally before populating flow variables. If redaction cannot be verified, stop and keep the result out of the flow. Restrict this process to repositories owned by the organization or explicitly in the written assessment scope.


### Block 1: Authorized Repository Scope and Secret Scan

**Block Type:** Owner-approved secret-scanning input

1. Confirm that each repository is owned by the organization or listed in the signed assessment scope.
2. Use GitHub secret-scanning alerts or an approved scanner to inspect current files and reachable history.
3. Configure local preprocessing to remove every secret value and source-code excerpt before any result enters AnythingLLM.
4. Populate `github_search_results` with alert ID, repository URL, file path, line, commit and detected secret type only.

**Do not scrape raw code search results into the agent context.** Code-search snippets and commit pages can contain active credentials. Verify that the source can produce redacted metadata before continuing.

---

### Block 2: Historical Exposure Metadata

**Block Type:** Owner-approved scanner output

Review scanner alerts for current and historical commits. Populate `commit_data` with redacted metadata only: finding ID, repository, path, line, commit identifier, exposure date if known, and secret category. Do not include the matched string, a prefix/suffix, a private key, or a source excerpt.

Ordinary deletion in a later commit does not remove earlier reachable history. A coordinated history rewrite may remove data from repository refs, but existing clones, forks, caches and other copies can retain it. Revoke or rotate the exposed credential regardless of history cleanup.

---

### Block 3: LLM Instruction - Identify Secrets

**Block Type:** LLM Instruction

**Instruction:**
```
Analyze only these pre-redacted findings for the authorized organization ${target_domain}:

Scanner alert metadata: ${github_search_results}
Historical exposure metadata: ${commit_data}

Do not infer or reproduce secret values. Return only finding ID, repository, path, line/commit, detected secret category, scanner confidence, and owner remediation status. Do not include usernames or unrelated personal data unless specifically required by the engagement.

## Secret Categories

Use only scanner-provided categories, such as cloud key, API token, password, private key, database credential, certificate, or sensitive configuration. A pattern match is not proof that a secret is active. Do not test, authenticate with, decode, or attempt to validate a finding.

## Risk Classification

The scanner pattern does not establish that a credential is valid or active. Base severity on owner-confirmed status, scope and exposure evidence:
- **CRITICAL:** Owner-confirmed active credential with high privilege or broad production access
- **HIGH:** Credible exposure with material potential access; validity or privileges remain unconfirmed
- **MEDIUM:** Limited-scope, expired or test credential confirmed by the owner, or sensitive internal metadata
- **LOW:** Confirmed non-secret example or low-impact metadata

Use **unconfirmed** when validity is unknown; do not test a credential by signing in.

## Evidence

For each high-risk finding:
- Repository name and URL
- File path
- Line number
- Commit hash
- Date committed
- Owner-approved incident reference, if needed for follow-up

Flag CRITICAL and HIGH findings immediately for urgent action.
```

**Result Variable:** `secret_findings`

**Purpose:** Classify redacted exposure metadata

---

### Block 4: LLM Instruction - Risk Assessment

**Block Type:** LLM Instruction

**Instruction:**
```
Assess security risk of exposed secrets for ${target_domain}:

Findings: ${secret_findings}

Provide a concise assessment using the redacted findings only. Do not request, recover, include, or validate credential values:

## Executive Summary
- Total secrets found: [number]
- Critical findings: [number]
- High-risk findings: [number]
- Overall risk level: [CRITICAL/HIGH/MEDIUM/LOW]

## Critical Findings Requiring Immediate Action

For each CRITICAL finding:
1. **Detected category** reported by the scanner (do not print the value or partial value)
2. **Location** (repository, file, line and commit)
3. **Exposure window** if supported by history evidence
4. **Potential impact** as a qualified hypothesis, not a claim of successful use
5. **Owner action** (revoke/rotate through the authorized secret owner and review access logs)

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
1. **Revoke or rotate** confirmed exposed credentials through the authorized owner; do this even if repository history is later rewritten.
2. **Review access logs** for possible unauthorized use through the credential owner’s incident process.
3. If history cleanup is approved, use a coordinated `git-filter-repo` rewrite and follow GitHub’s sensitive-data-removal guidance; coordinate collaborators and note that clones, forks, caches and other copies may still contain the data.
4. **Scan for compromise** using authorized provider logs; do not test credentials by logging in.
5. **Adopt secret management** and push protection appropriate to the repository.

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

Use only an organization-owned or explicitly authorized repository scope. `owned-example.invalid` is a documentation placeholder and does not resolve to a live organization.

```
@agent use GitHubSecrets flow
target_domain: owned-example.invalid
```

### Company Name Search

```
@agent use GitHubSecrets flow
target_domain: Owned Example Organization
```

### Expected Output

The flow will return `risk_assessment` containing:
- Redacted finding IDs, secret categories and repository locations; never secret values
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

## Approved Scanner Metadata Filters

Configure the organization-approved scanner to look for its supported categories (cloud keys, service tokens, private keys, database credentials and sensitive configuration) **only in the authorized repository scope**. Review findings in the scanner interface and export metadata only: alert ID, category, repository, path, line, commit and status. Keep matched values and source excerpts in the restricted scanner environment; do not paste code-search URLs, snippets or raw output into AnythingLLM.


---

## Notes and Considerations

### Legal and Ethical

- **Authorization** - Public accessibility does not itself authorize credential testing, use, or unrestricted processing; limit work to repositories owned by the organization or explicitly listed in scope
- **Responsible Handling** - Follow the owner's approved security-reporting channel and data-handling policy
- **No Credential Use** - Never authenticate with a discovered value; notify the authorized owner so it can be revoked or rotated
- **Minimize Evidence** - Keep only redacted alert metadata in the report; store raw scanner evidence only in approved restricted storage
- **Client Notification** - Use the engagement's incident escalation path for urgent findings

### Technical Considerations

- **Rate Limiting** - GitHub limits search queries
- **Authentication** - Use the organization's approved integration with least-privilege access; never place a GitHub token in prompts, URLs, screenshots or flow output
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

## Related Files
- [README.md](README.md) - AnythingLLM section index
- [anything_llm_agentflows.md](anything_llm_agentflows.md) - Parent AgentFlows index
- [../../OSINT/scripts/Domain_IP_Recon.md](../../OSINT/scripts/Domain_IP_Recon.md) - Domain recon to generate targets for this flow
