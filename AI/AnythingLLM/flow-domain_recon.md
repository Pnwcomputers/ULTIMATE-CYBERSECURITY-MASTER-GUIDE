# DomainRecon AgentFlow

## Flow Information

**Name:** `DomainRecon`

**Description:**
```
Performs comprehensive domain reconnaissance including subdomains, DNS records, 
certificates, and historical data for attack surface mapping.
```

**Purpose:** Map complete attack surface and discover hidden assets

---

## Flow Variables

Define these variables in the "Flow Variables" section:

| Variable Name | Initial Value | Description |
|---------------|---------------|-------------|
| `domain` | (empty) | Target domain (e.g., example.com) |
| `cert_data` | (empty) | Certificate transparency data |
| `subdomain_data` | (empty) | Discovered subdomains |
| `security_headers` | (empty) | Security headers analysis |
| `whois_data` | (empty) | WHOIS registration data |
| `recon_report` | (empty) | Final reconnaissance report |

---

## Flow Blocks

### Block 1: Web Scraping - Certificate Transparency

**Block Type:** Web Scraping

**Configuration:**
- **URL:** `https://crt.sh/?q=%.${domain}`
- **Capture Page Content As:** Text content only
- **Content Summarization:** Enabled
- **Result Variable:** `cert_data`

**Purpose:** Discover subdomains via SSL certificate logs

**Note:** crt.sh provides certificate transparency logs showing all issued certificates

---

### Block 2: Web Scraping - Reverse IP Lookup

**Block Type:** Web Scraping

**Configuration:**
- **URL:** `https://viewdns.info/reverseip/?host=${domain}&t=1`
- **Capture Page Content As:** Text content only
- **Content Summarization:** Enabled
- **Result Variable:** `subdomain_data`

**Purpose:** Find other domains hosted on same IP address

---

### Block 3: Web Scraping - Security Headers

**Block Type:** Web Scraping

**Configuration:**
- **URL:** `https://securityheaders.com/?q=https://${domain}&hide=on&followRedirects=on`
- **Capture Page Content As:** Text content only
- **Content Summarization:** Enabled
- **Result Variable:** `security_headers`

**Purpose:** Analyze security posture via HTTP headers

---

### Block 4: Web Scraping - WHOIS Information

**Block Type:** Web Scraping

**Configuration:**
- **URL:** `https://www.whois.com/whois/${domain}`
- **Capture Page Content As:** Text content only
- **Content Summarization:** Enabled
- **Result Variable:** `whois_data`

**Purpose:** Gather domain registration information

**Alternative (API):** If you have WhoisXML API key:
- **Method:** GET
- **URL:** `https://www.whoisxmlapi.com/whoisserver/WhoisService?apiKey=YOUR_KEY&domainName=${domain}&outputFormat=JSON`

---

### Block 5: LLM Instruction - Analyze Reconnaissance Data

**Block Type:** LLM Instruction

**Instruction:**
```
Analyze comprehensive domain reconnaissance for ${domain}:

Certificate Transparency Data: ${cert_data}
Reverse IP Data: ${subdomain_data}
Security Headers: ${security_headers}
WHOIS Information: ${whois_data}

Extract and organize:

## Subdomains Discovered
List all discovered subdomains with categorization:
- Production subdomains
- Development/staging environments (dev, test, staging, uat)
- Administrative interfaces (admin, panel, dashboard)
- API endpoints
- Mail servers
- Other interesting targets

## IP Addresses & Hosting
- Primary IP addresses
- Hosting provider identification
- Geographic location
- Shared hosting information
- CDN usage

## Security Posture
- Security headers present/missing
- SSL/TLS configuration quality
- Certificate authorities used
- Expired or wildcard certificates
- HSTS, CSP, X-Frame-Options analysis

## Domain Registration
- Registrar information
- Registration and expiration dates
- Nameservers
- Registrant details (if public)
- Privacy protection status

## Attack Surface Assessment
- High-priority targets (admin panels, dev sites)
- Potential information disclosure
- Misconfigured services
- Outdated or vulnerable technologies

## Recommendations
- Prioritized list of targets for further testing
- Suggested reconnaissance tools
- Next steps in assessment

Format as professional reconnaissance report.
```

**Result Variable:** `recon_report`

**Purpose:** Synthesize all reconnaissance data into actionable intelligence

---

### Block 6: Flow Complete

**Block Type:** Flow Complete

**Configuration:**
- Flow will end here and return results

---

## Usage Instructions

### Basic Usage

```
@agent use DomainRecon flow
domain: target.com
```

### Example With Real Data

```
@agent use DomainRecon flow
domain: example.com
```

**Note:** Do NOT include "www." or "https://" - just the domain name

### Expected Output

The flow will return `recon_report` containing:
- Complete list of discovered subdomains
- IP addresses and hosting information
- Security posture assessment
- Domain registration details
- Prioritized attack surface mapping
- Recommended next steps

---

## Integration with Other Flows

**Typical Workflow:**

1. **CompanyOSINT** - Gather company intelligence
2. **DomainRecon** (this flow) - Map technical infrastructure
3. **ThreatIntelCheck** - Verify discovered IPs
4. **NmapAnalyzer** - Scan discovered subdomains
5. **CVELookup** - Research vulnerabilities in discovered services

---

## Alternative URLs (If Primary Fails)

### Certificate Transparency Alternatives:
- `https://crt.sh/?q=%.${domain}&output=json` (JSON format)
- `https://transparencyreport.google.com/https/certificates` (manual lookup)

### Subdomain Discovery Alternatives:
- `https://api.hackertarget.com/hostsearch/?q=${domain}` (API, free tier)
- `https://sonar.omnisint.io/subdomains/${domain}` (Project Sonar)

### Security Headers Alternatives:
- Manual check: `curl -I https://${domain}`
- `https://observatory.mozilla.org/analyze/${domain}` (Mozilla Observatory)

---

## Notes and Considerations

### Legal and Ethical

- ⚠️ Reconnaissance must be authorized
- Certificate transparency logs are public data
- Respect rate limits on free services
- Some WHOIS data may be privacy-protected

### Technical Considerations

- **Rate Limiting:** Free services may throttle requests
- **Variable Syntax:** Use `${domain}` not `{{domain}}`
- **Content Size:** Certificate logs can be large; summarization recommended
- **Timeout:** Allow 30-60 seconds per web scraping block

### Data Quality

- **Best Results:** Well-established domains with history
- **Limited Results:** New domains or privacy-focused organizations
- **False Positives:** Certificate logs may show expired/unused domains

---

## Optimization Tips

### For Better Subdomain Discovery:

1. **Combine Multiple Sources:**
   - crt.sh for certificate-based discovery
   - ViewDNS for reverse IP lookup
   - HackerTarget API for DNS enumeration

2. **Follow Up with Active Scanning:**
   ```bash
   # After flow completes, scan discovered subdomains
   for subdomain in $(cat discovered-subdomains.txt); do
       nmap -sV $subdomain
   done
   ```

3. **Check for Wildcard DNS:**
   - Test random subdomains to detect wildcards
   - Filter out false positives

### For Better Analysis:

1. **Prioritize Development Environments:**
   - dev.*, staging.*, test.*, uat.*
   - Often less secured than production

2. **Focus on Administrative Interfaces:**
   - admin.*, panel.*, dashboard.*
   - cpanel.*, webmail.*
   - Higher value targets

3. **Identify Technology Stack:**
   - Look for technology-specific subdomains
   - jenkins.*, gitlab.*, jira.*

---

## Troubleshooting

| Issue | Solution |
|-------|----------|
| No subdomains found | Domain may be new; try alternative sources |
| crt.sh returns too much data | Enable summarization; filter by recent certs |
| WHOIS data redacted | Expected for privacy-protected domains |
| Security headers fail | Domain may not exist; check manually first |
| Variable not substituting | Verify syntax: `${domain}` in URL field |
| Web scraping timeout | Increase timeout or try API alternatives |

---

## Advanced Configuration

### Using APIs Instead of Web Scraping

**If you have API keys, replace web scraping blocks:**

**SecurityTrails API (Subdomain Discovery):**
```
Block Type: API Call
Method: GET
URL: https://api.securitytrails.com/v1/domain/${domain}/subdomains
Headers: {
  "APIKEY": "YOUR_SECURITYTRAILS_KEY"
}
Result Variable: subdomain_data
```

**WhoisXML API (Better WHOIS Data):**
```
Block Type: API Call
Method: GET
URL: https://www.whoisxmlapi.com/whoisserver/WhoisService?apiKey=YOUR_KEY&domainName=${domain}&outputFormat=JSON
Result Variable: whois_data
```

---

## Post-Flow Actions

**After running DomainRecon:**

1. **Export discovered subdomains** to file for further scanning
2. **Run ThreatIntelCheck** on discovered IP addresses
3. **Scan high-priority targets** with Nmap
4. **Check development environments** for exposed information
5. **Document findings** for client report

---

## Version History

- **v1.0** - Initial flow creation with web scraping
- **v1.1** - Added security headers analysis (recommended)
- Purpose: Attack surface mapping and subdomain discovery
- Last Updated: November 2025

---

## Related Flows

- **CompanyOSINT** - Company intelligence gathering
- **ThreatIntelCheck** - IP reputation checking
- **NmapAnalyzer** - Port scanning discovered assets
- **GitHubSecrets** - Code repository investigation
