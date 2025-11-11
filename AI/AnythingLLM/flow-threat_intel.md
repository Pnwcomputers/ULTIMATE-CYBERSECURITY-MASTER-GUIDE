# ThreatIntelCheck AgentFlow

## Flow Information

**Name:** `ThreatIntelCheck`

**Description:**
```
Checks IP address or domain reputation against multiple threat intelligence 
sources and provides risk assessment with block/monitor/allow recommendation.
```

**Purpose:** Threat intelligence and IP reputation analysis

---

## Flow Variables

Define these variables in the "Flow Variables" section:

| Variable Name | Initial Value | Description |
|---------------|---------------|-------------|
| `indicator` | (empty) | IP address or domain to check |
| `indicator_type` | IP | Type: IP or Domain |
| `vt_data` | (empty) | VirusTotal API response |
| `abuse_data` | (empty) | AbuseIPDB web scraping results |
| `threat_score` | (empty) | Calculated threat score |
| `recommendation` | (empty) | Final recommendation |

---

## Flow Blocks

### Block 1: API Call - VirusTotal

**Block Type:** API Call

**Configuration:**
- **Method:** GET
- **URL:** `https://www.virustotal.com/api/v3/ip_addresses/${indicator}`
- **Headers:**
  ```json
  {
    "x-apikey": "YOUR_VIRUSTOTAL_API_KEY"
  }
  ```
- **Result Variable:** `vt_data`

**Purpose:** Check IP reputation against VirusTotal database

**Important:** 
- Variable syntax must be `${indicator}` (not `{{indicator}}`)
- Get free API key at https://www.virustotal.com/gui/join-us
- Free tier: 4 requests/minute, 500/day

**For Domains:**
- Change URL to: `https://www.virustotal.com/api/v3/domains/${indicator}`

---

### Block 2: Web Scraping - AbuseIPDB

**Block Type:** Web Scraping

**Configuration:**
- **URL:** `https://www.abuseipdb.com/check/${indicator}`
- **Capture Page Content As:** Text content only
- **Content Summarization:** Enabled (recommended)
- **Result Variable:** `abuse_data`

**Purpose:** Check IP against abuse reports database

**Note:** AbuseIPDB provides community-driven abuse reports

**Alternative (API):**
```
Method: GET
URL: https://api.abuseipdb.com/api/v2/check?ipAddress=${indicator}
Headers: {
  "Key": "YOUR_ABUSEIPDB_API_KEY",
  "Accept": "application/json"
}
```

---

### Block 3: LLM Instruction - Calculate Threat Score

**Block Type:** LLM Instruction

**Instruction:**
```
Calculate threat score for ${indicator_type}: ${indicator}

VirusTotal Data: ${vt_data}
AbuseIPDB Data: ${abuse_data}

Analyze and calculate overall threat score:

## VirusTotal Analysis
- **Detection Ratio:** [X/Y vendors flagged as malicious]
- **Categories:** [malware, phishing, spam, etc.]
- **Last Analysis Date:** [date]
- **Community Votes:**
  - Malicious: [count]
  - Harmless: [count]
- **Reputation Score:** [score if available]

## AbuseIPDB Analysis
- **Abuse Confidence Score:** [percentage]
- **Total Reports:** [count]
- **Last Reported:** [date]
- **Report Categories:**
  - Port scanning
  - Hacking attempts
  - Brute force
  - DDoS
  - Spam
  - Other malicious activity
- **Country:** [location]
- **ISP/Organization:** [owner]

## Historical Context
- First seen: [date]
- Activity timeline: [pattern of abuse]
- Known campaigns: [associated threats]

## Threat Intelligence
- **Known threat actor:** [Yes/No]
- **Botnet membership:** [Yes/No/Unknown]
- **C2 infrastructure:** [Yes/No/Unknown]
- **Tor exit node:** [Yes/No]
- **VPN/Proxy:** [Yes/No]
- **Legitimate service:** [Yes/No - e.g., Google, Cloudflare]

## Overall Threat Score
Calculate 0-100 score based on:
- VirusTotal detections (weight: 40%)
- AbuseIPDB confidence (weight: 40%)
- Historical activity (weight: 10%)
- Community consensus (weight: 10%)

**Threat Score:** [0-100]

**Risk Level:**
- 0-25: LOW
- 26-50: MEDIUM
- 51-75: HIGH
- 76-100: CRITICAL

Format as structured threat intelligence report.
```

**Result Variable:** `threat_score`

**Purpose:** Aggregate threat intelligence into single score

---

### Block 4: LLM Instruction - Generate Recommendation

**Block Type:** LLM Instruction

**Instruction:**
```
Based on threat intelligence for ${indicator}:

Threat Score Analysis: ${threat_score}
VirusTotal Data: ${vt_data}
AbuseIPDB Data: ${abuse_data}

Provide actionable security recommendation:

## Recommendation Summary

**Action:** [BLOCK / MONITOR / ALLOW / INVESTIGATE]

**Confidence:** [HIGH / MEDIUM / LOW]

**Urgency:** [IMMEDIATE / URGENT / ROUTINE / INFORMATIONAL]

## Detailed Analysis

### Risk Assessment
- **Primary Threat:** [main concern]
- **Attack Vectors:** [how this IP could be used maliciously]
- **Target Profile:** [who would be targeted]
- **Impact if Compromised:** [potential damage]

### Historical Behavior
- **Pattern:** [consistent malicious / sporadic / legitimate with issues]
- **Sophistication:** [APT-level / organized crime / script kiddie]
- **Targeting:** [indiscriminate / targeted / opportunistic]

### Current Status
- **Active Threat:** [Yes/No/Unknown]
- **Recent Activity:** [timeframe of latest reports]
- **Trending:** [increasing/stable/decreasing activity]

## Recommended Actions

### If BLOCK (Threat Score 76-100 or confirmed malicious)
1. **Immediate Actions:**
   - Add to firewall block list
   - Block at perimeter (edge firewall/IDS)
   - Add to proxy blacklist
   - Update endpoint security rules

2. **Verification:**
   - Check logs for any recent connections from this IP
   - Review successful authentication attempts
   - Scan any systems that communicated with this IP
   - Check for indicators of compromise (IOCs)

3. **Monitoring:**
   - Alert on any future connection attempts
   - Track similar IPs in same subnet
   - Monitor for related threat indicators

4. **Timeline:** Implement within 1 hour

### If MONITOR (Threat Score 51-75 or suspicious but unclear)
1. **Enhanced Logging:**
   - Enable detailed logging for this IP
   - Capture all connection attempts
   - Log protocol and payload data
   - Set alert thresholds

2. **Analysis:**
   - Review traffic patterns
   - Analyze requested resources
   - Check against known attack signatures
   - Correlate with other security events

3. **Escalation Criteria:**
   - Block if malicious activity confirmed
   - Continue monitoring for [timeframe]
   - Re-assess threat score weekly

4. **Timeline:** Implement within 24 hours

### If ALLOW (Threat Score 0-25 or legitimate service)
1. **Low-Risk Indicators:**
   - List reasons why this is considered safe
   - Note: legitimate services, CDN, known good

2. **Periodic Review:**
   - Recheck reputation quarterly
   - Monitor for status changes
   - Update allow lists as needed

3. **Documentation:**
   - Document allow decision
   - Note business justification
   - Set review date

### If INVESTIGATE (Threat Score 26-50 or unclear data)
1. **Additional Checks:**
   - WHOIS lookup for registration details
   - Reverse DNS lookup
   - Check against additional threat feeds
   - Contact ISP/abuse@ if appropriate
   - Search security forums/blogs

2. **Technical Analysis:**
   - Packet capture if connection established
   - Malware analysis if files downloaded
   - Traffic behavior analysis
   - SSL certificate inspection

3. **Decision Timeline:**
   - Complete investigation within 48 hours
   - Escalate to BLOCK or MONITOR based on findings

## Justification

Provide clear reasoning for recommendation:
- **Key Factors:** [main decision drivers]
- **Confidence Basis:** [why we're confident in this assessment]
- **Alternative Considerations:** [edge cases or special circumstances]
- **Risk/Benefit Analysis:** [trade-offs of this decision]

## Additional Context

### For Security Team
- IOC information to add to SIEM
- Correlation opportunities with existing logs
- Similar indicators to watch for

### For Network Team
- Firewall rule specifications
- ACL modifications needed
- Performance impact considerations

### For Management
- Business risk summary
- Resource requirements
- Compliance implications

## References

- **VirusTotal:** https://www.virustotal.com/gui/ip-address/${indicator}
- **AbuseIPDB:** https://www.abuseipdb.com/check/${indicator}
- **Additional Intel:** [other relevant sources]

Format as actionable security decision document.
```

**Result Variable:** `recommendation`

**Purpose:** Provide clear action plan for security team

---

### Block 5: Flow Complete

**Block Type:** Flow Complete

**Configuration:**
- Flow will end here and return results

---

## Usage Instructions

### IP Address Check

```
@agent use ThreatIntelCheck flow
indicator: 192.0.2.45
indicator_type: IP
```

### Domain Check

```
@agent use ThreatIntelCheck flow
indicator: malicious-site.com
indicator_type: Domain
```

**Note:** For domain checks, modify Block 1 URL to use `/domains/` endpoint

### Expected Output

**threat_score** - Aggregated analysis:
- VirusTotal detections
- AbuseIPDB confidence score
- Overall threat level (0-100)
- Risk categorization

**recommendation** - Action plan:
- Clear action (BLOCK/MONITOR/ALLOW/INVESTIGATE)
- Justification with evidence
- Implementation steps
- Timeline
- Verification procedures

---

## Integration with Other Flows

**Typical Workflow:**

1. **NmapAnalyzer** - Discovers external IPs
2. **ThreatIntelCheck** (this flow) - Verify each IP
3. **VulnReportGenerator** - Document malicious IPs
4. Firewall rule implementation

**Incident Response:**
```
Suspicious activity detected
    ↓
Extract IP from logs
    ↓
ThreatIntelCheck → Threat Score: 85 (CRITICAL)
    ↓
Recommendation: BLOCK immediately
    ↓
Implement firewall rule
    ↓
Investigate compromised systems
```

---

## API Key Setup

### VirusTotal API Key (Recommended)

**Free Tier:**
1. Visit: https://www.virustotal.com/gui/join-us
2. Create free account
3. Go to: https://www.virustotal.com/gui/user/[username]/apikey
4. Copy API key
5. Add to flow: Replace `YOUR_VIRUSTOTAL_API_KEY`

**Limitations:**
- 4 requests/minute
- 500 requests/day
- Basic API features

**Premium (Optional):**
- Higher rate limits
- Advanced features
- Historical data
- Paid plans available

### AbuseIPDB API Key (Optional)

**Free Tier:**
1. Visit: https://www.abuseipdb.com/register
2. Create account
3. Generate API key
4. Free tier: 1,000 checks/day

**To Use API Instead of Scraping:**
- Replace Block 2 (Web Scraping) with API Call
- Better reliability than web scraping
- Structured JSON response

---

## Known Issues and Fixes

### Issue 1: Variable Not Substituting

**Problem:** URL shows `{{indicator}}` instead of actual IP

**Fix:** Use `${indicator}` syntax in URL field
```
✅ CORRECT: https://www.virustotal.com/api/v3/ip_addresses/${indicator}
❌ WRONG:   https://www.virustotal.com/api/v3/ip_addresses/{{indicator}}
```

### Issue 2: 404 Error from VirusTotal

**Possible Causes:**
- Wrong variable syntax
- Missing API key
- Invalid IP format
- IP not in VirusTotal database (rare)

**Fix:**
1. Verify URL uses `${indicator}`
2. Confirm API key is valid
3. Test IP manually: https://www.virustotal.com/gui/ip-address/8.8.8.8

### Issue 3: Rate Limit Exceeded

**Error:** "Quota exceeded"

**Fix:**
- Wait 1 minute between requests (free tier: 4/minute)
- Upgrade to paid tier
- Cache results for repeated checks

---

## Notes and Considerations

### Legal and Ethical

- ⚠️ **Legitimate IPs** - Some IPs may be legitimate but flagged incorrectly
- **False Positives** - Cloud providers, CDNs may have mixed reputation
- **Context Matters** - Consider business use case before blocking
- **Documentation** - Keep records of blocking decisions

### Technical Considerations

- **CDNs and Proxies:**
  - Cloudflare, Akamai IPs may show mixed reputation
  - Shared infrastructure can flag legitimate services
  - Check specific URL/domain, not just IP

- **Dynamic IPs:**
  - Residential ISP IPs change frequently
  - Historical data may not reflect current user
  - Be cautious with CGNAT addresses

- **Tor Exit Nodes:**
  - Often flagged as malicious
  - May be legitimate privacy-conscious users
  - Policy decision on whether to block

### Data Quality

- **VirusTotal:**
  - Most authoritative source
  - High false positive rate for shared hosting
  - Focus on recent detections

- **AbuseIPDB:**
  - Community-driven reports
  - Can have reporting bias
  - Good for scanning/brute force detection

---

## Optimization Tips

### For Better Results:

1. **Check Multiple IPs:**
   - Run for all suspicious IPs
   - Look for patterns (same subnet, ASN)
   - Correlate with other incidents

2. **Verify Context:**
   ```
   indicator: 8.8.8.8
   → Threat Score: 0 (Google DNS)
   → Don't block legitimate services!
   ```

3. **Cross-Reference Sources:**
   - VirusTotal + AbuseIPDB
   - Add other feeds if needed
   - Check WHOIS for ownership

### For Better Recommendations:

1. **Consider Business Impact:**
   - Blocking CDN IP breaks website
   - Monitoring adds SOC workload
   - Balance security vs usability

2. **Set Clear Thresholds:**
   - Define risk tolerance
   - Automate based on score
   - Escalation procedures

3. **Document Decisions:**
   - Why blocked/allowed
   - Business justification
   - Review timeline

---

## Troubleshooting

| Issue | Solution |
|-------|----------|
| API authentication fails | Verify API key is correct and active |
| No data returned | IP may not be in databases (uncommon) |
| Conflicting assessments | VirusTotal high, AbuseIPDB low - investigate further |
| Generic recommendation | Provide more context about the source of the IP |
| Web scraping fails | AbuseIPDB may block; use API instead |
| Domain check fails | Ensure Block 1 URL uses /domains/ endpoint |

---

## Real-World Examples

### Example 1: Known Malicious IP

**Input:**
```
indicator: 45.142.213.xxx
indicator_type: IP
```

**Output:**
```
Threat Score: 92 (CRITICAL)

VirusTotal: 45/89 vendors flagged as malicious
- Categories: malware distribution, C2, phishing

AbuseIPDB: 98% abuse confidence
- 2,847 reports in 90 days
- Categories: Hacking, port scan, brute force

Recommendation: BLOCK IMMEDIATELY
- Add to firewall deny list
- Check logs for any connections from this IP
- Scan systems that communicated with it
- Timeline: Within 1 hour
```

### Example 2: Legitimate Service

**Input:**
```
indicator: 8.8.8.8
indicator_type: IP
```

**Output:**
```
Threat Score: 0 (LOW)

VirusTotal: 0/89 vendors flagged
- Owner: Google LLC
- Service: Public DNS

AbuseIPDB: 0% abuse confidence
- 0 reports
- Harmless: Yes

Recommendation: ALLOW
- This is Google's public DNS server
- Legitimate infrastructure
- No action required
```

### Example 3: Suspicious But Unclear

**Input:**
```
indicator: 192.0.2.100
indicator_type: IP
```

**Output:**
```
Threat Score: 45 (MEDIUM)

VirusTotal: 3/89 vendors flagged (mixed opinion)
AbuseIPDB: 35% abuse confidence
- 12 reports in 30 days
- Port scanning reported

Recommendation: INVESTIGATE
- Enable enhanced logging
- Monitor for 48 hours
- Check traffic patterns
- Escalate to BLOCK if malicious activity confirmed
```

---

## Post-Flow Actions

**After threat intelligence check:**

1. **If BLOCK Recommended:**
   - Implement firewall rule
   - Document block reason
   - Set up alerting for connection attempts
   - Review logs for past connections

2. **If MONITOR Recommended:**
   - Configure enhanced logging
   - Set SIEM alerts
   - Review regularly
   - Re-assess after monitoring period

3. **If ALLOW:**
   - Document decision
   - Add to whitelist if appropriate
   - Schedule periodic re-check

4. **If INVESTIGATE:**
   - Assign to security analyst
   - Gather additional intelligence
   - Make final decision within timeline

---

## Additional Intelligence Sources

**Can be added as additional blocks:**

### AlienVault OTX
```
API Call:
URL: https://otx.alienvault.com/api/v1/indicators/IPv4/${indicator}/general
```

### Shodan
```
API Call:
URL: https://api.shodan.io/shodan/host/${indicator}?key=YOUR_KEY
```

### GreyNoise
```
API Call:
URL: https://api.greynoise.io/v3/community/${indicator}
Headers: {"key": "YOUR_KEY"}
```

---

## Version History

- **v1.0** - Initial flow with VirusTotal and AbuseIPDB
- **v1.1** - Fixed variable substitution issue (important)
- Purpose: IP/domain reputation checking for security assessments
- Last Updated: November 2025

---

## Related Flows

- **NmapAnalyzer** - Discover IPs to check
- **DomainRecon** - Discover domains to verify
- **VulnReportGenerator** - Document malicious indicators
- **CompanyOSINT** - Correlate with target intelligence
