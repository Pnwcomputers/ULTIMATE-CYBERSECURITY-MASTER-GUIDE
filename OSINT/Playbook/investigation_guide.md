# OSINT Investigation Procedures Guide

This guide provides step-by-step procedures for conducting thorough OSINT investigations on scam and fraud cases.

## Table of Contents

1. [Pre-Investigation Checklist](#pre-investigation-checklist)
2. [Email Investigation Procedure](#email-investigation-procedure)
3. [Phone Investigation Procedure](#phone-investigation-procedure)
4. [Domain Investigation Procedure](#domain-investigation-procedure)
5. [IP Address Investigation Procedure](#ip-address-investigation-procedure)
6. [Username Investigation Procedure](#username-investigation-procedure)
7. [Cryptocurrency Investigation Procedure](#cryptocurrency-investigation-procedure)
8. [Evidence Preservation](#evidence-preservation)
9. [Report Generation](#report-generation)
10. [Abuse Reporting Workflow](#abuse-reporting-workflow)

---

## Pre-Investigation Checklist

Before starting any investigation:

- [ ] Create a new case with unique Case ID
- [ ] Document the incident/complaint in case notes
- [ ] Verify you have legal authorization to investigate
- [ ] Check that required tools are installed (`./osint_investigator.sh --status`)
- [ ] Verify API keys are configured
- [ ] Ensure adequate storage for evidence

### Recommended Case ID Format

```
YYYY-NNN-TYPE

Examples:
- 2024-001-PHISHING
- 2024-002-ROMANCE_SCAM
- 2024-003-TECH_SUPPORT
- 2024-004-INVESTMENT_FRAUD
```

---

## Email Investigation Procedure

### Objective
Identify accounts associated with an email address, discover breach exposure, and gather intelligence for abuse reporting.

### Step-by-Step Procedure

#### Step 1: Account Discovery with Holehe

```bash
holehe target@email.com --only-used
```

**What to look for:**
- Registered accounts on social media platforms
- Partial recovery emails/phone numbers
- Account creation indicators

**Document:** List of discovered accounts

#### Step 2: Breach Database Search

```bash
h8mail -t target@email.com -o breach_results.csv
```

**What to look for:**
- Previous breaches containing the email
- Associated passwords (for correlation, not misuse)
- Related email addresses

**Document:** Breach exposure summary

#### Step 3: HaveIBeenPwned Check (if API configured)

The toolkit automatically queries HIBP when the API key is set.

**What to look for:**
- Breach names and dates
- Data types exposed
- Pattern of compromise

#### Step 4: Email Verification

```bash
# Hunter.io verification (via toolkit)
# Or manual: curl "https://api.hunter.io/v2/email-verifier?email=target@email.com&api_key=YOUR_KEY"
```

**What to look for:**
- Deliverable status
- MX records
- SMTP check results
- Disposable email detection

#### Step 5: Email Header Analysis (if headers available)

If you have the original scam email:

1. Extract full headers from email client
2. Analyze routing path
3. Identify originating IP
4. Check SPF/DKIM/DMARC alignment
5. Look for spoofing indicators

**Tools:** mxtoolbox.com, emailheaders.net

#### Step 6: Domain Extraction

Extract the domain from the email address and proceed to Domain Investigation.

---

## Phone Investigation Procedure

### Objective
Identify carrier, validate number, and discover associated online presence.

### Step-by-Step Procedure

#### Step 1: Number Validation

```bash
phoneinfoga scan -n "+1234567890"
```

**What to look for:**
- Country and carrier
- Line type (mobile, VoIP, landline)
- Valid number confirmation

#### Step 2: Carrier Lookup

The phonenumbers library provides detailed carrier information:

```python
import phonenumbers
from phonenumbers import carrier, geocoder

pn = phonenumbers.parse("+1234567890")
print(carrier.name_for_number(pn, 'en'))
print(geocoder.description_for_number(pn, 'en'))
```

#### Step 3: VoIP Detection

VoIP numbers are commonly used by scammers. Check for:
- Google Voice
- TextNow
- Burner app numbers
- Twilio/other API numbers

#### Step 4: Reverse Lookup

Use multiple sources:
- PhoneInfoga built-in searches
- Truecaller (manual check)
- Caller ID databases
- Social media search with phone number

#### Step 5: Document Findings

Record:
- Full number with country code
- Carrier name
- Line type
- VoIP indicator
- Any associated names/addresses

---

## Domain Investigation Procedure

### Objective
Map the complete infrastructure behind a scam domain, identify hosting providers, and gather abuse contacts.

### Step-by-Step Procedure

#### Step 1: WHOIS Lookup

```bash
whois scam-domain.com
```

**What to look for:**
- Registrant information (often privacy-protected)
- Registrar name and abuse contact
- Registration date (recent = suspicious)
- Nameservers
- Expiration date

**Document:** Registrar abuse contact for reporting

#### Step 2: DNS Record Collection

```bash
# A Records (IP addresses)
dig +short scam-domain.com A

# MX Records (mail servers)
dig +short scam-domain.com MX

# TXT Records (SPF, verification)
dig +short scam-domain.com TXT

# NS Records (nameservers)
dig +short scam-domain.com NS
```

**Document:** All IP addresses for IP investigation

#### Step 3: Subdomain Enumeration

```bash
subfinder -d scam-domain.com -silent -o subdomains.txt
```

**What to look for:**
- admin.* subdomains
- api.* subdomains
- mail.* subdomains
- Hidden panels or services

#### Step 4: Technology Stack Detection

```bash
cat subdomains.txt | httpx -td -server -title -asn
```

**What to look for:**
- Web server type
- CMS platform
- Hosting provider
- CDN usage (may mask origin)

#### Step 5: Historical Analysis

```bash
# Wayback Machine URLs
echo scam-domain.com | waybackurls > historical_urls.txt

# Certificate Transparency
curl -s "https://crt.sh/?q=%25.scam-domain.com&output=json" | jq
```

**What to look for:**
- Previous content/pages
- Earlier registration
- SSL certificate history
- Related domains on same certificate

#### Step 6: theHarvester (Email Discovery)

```bash
theHarvester -d scam-domain.com -l 500 -b all
```

**What to look for:**
- Email addresses associated with domain
- Employee names
- Related domains/hosts

---

## IP Address Investigation Procedure

### Objective
Identify the hosting provider, abuse contacts, and reputation of IP addresses.

### Step-by-Step Procedure

#### Step 1: ASN and Abuse Contact Lookup

```bash
asn 1.2.3.4
```

**This provides:**
- ASN number and name
- Network range
- Abuse contact email
- Country
- RPKI status

**Document:** Abuse email for reporting

#### Step 2: Geolocation

```bash
curl -s "http://ip-api.com/json/1.2.3.4" | jq
```

**What to look for:**
- Country and city
- ISP name
- Organization
- Proxy/VPN/hosting detection

#### Step 3: Reputation Check

**Shodan (if API configured):**
```bash
curl -s "https://api.shodan.io/shodan/host/1.2.3.4?key=YOUR_KEY" | jq
```

**AbuseIPDB:**
```bash
curl -s "https://api.abuseipdb.com/api/v2/check?ipAddress=1.2.3.4&maxAgeInDays=90" \
  -H "Key: YOUR_KEY" | jq
```

**What to look for:**
- Previous abuse reports
- Confidence score
- Types of abuse
- Open ports/services

#### Step 4: Port Scan (Quick)

```bash
nmap -F -T4 --open 1.2.3.4
```

**What to look for:**
- Web servers (80, 443)
- Mail servers (25, 587)
- Remote access (22, 3389)
- Unusual services

#### Step 5: Reverse DNS

```bash
dig -x 1.2.3.4 +short
host 1.2.3.4
```

**What to look for:**
- Hostname reveals hosting provider
- Shared hosting indicators
- VPS/cloud provider names

---

## Username Investigation Procedure

### Objective
Discover all accounts associated with a username across social media and other platforms.

### Step-by-Step Procedure

#### Step 1: Maigret (Comprehensive - 2500+ sites)

```bash
maigret scammer_username --pdf --html -o ./username_results/
```

**What to look for:**
- Active social media accounts
- Forum registrations
- Dating site profiles
- Professional profiles
- Gaming accounts

#### Step 2: Sherlock (Fast - 400+ sites)

```bash
sherlock scammer_username --csv
```

Use as secondary verification for Maigret results.

#### Step 3: Manual Verification

Visit discovered profiles to:
- Confirm the account is actually the target
- Screenshot active profiles
- Document profile information
- Note connections/followers
- Check post history

#### Step 4: Profile Analysis

For each confirmed profile:

1. **Bio/Description:** Contact info, links, claims
2. **Profile Photo:** Reverse image search
3. **Post History:** Timeline, patterns
4. **Connections:** Friends, followers, groups
5. **Activity:** Posting frequency, times

#### Step 5: Reverse Image Search

```bash
# Use Google Images, TinEye, Yandex
# Or: https://images.google.com
# Upload profile photos to find other uses
```

---

## Cryptocurrency Investigation Procedure

### Objective
Trace cryptocurrency transactions and identify connections to known scam wallets.

### Step-by-Step Procedure

#### Step 1: Address Type Identification

- **Bitcoin:** Starts with 1, 3, or bc1
- **Ethereum:** Starts with 0x (40 hex chars)
- **Litecoin:** Starts with L, M, or 3

#### Step 2: Scam Database Check

Manual checks:
- https://www.bitcoinabuse.com/reports/ADDRESS
- https://www.chainabuse.com/address/ADDRESS
- https://cryptoscamdb.org/search

#### Step 3: Blockchain Explorer Analysis

**Bitcoin:**
```bash
curl -s "https://blockchain.info/rawaddr/ADDRESS?limit=50" | jq
```

Check:
- Total received/sent
- Number of transactions
- First/last transaction dates
- Balance

**Ethereum:**
```bash
curl -s "https://api.etherscan.io/api?module=account&action=txlist&address=ADDRESS&apikey=YOUR_KEY" | jq
```

#### Step 4: Transaction Tracing

For significant addresses:
1. Identify first funding source
2. Track outgoing transactions
3. Look for exchange deposits
4. Note clustering with other addresses

#### Step 5: Documentation

Record:
- Full address
- Blockchain type
- Total value transacted
- Abuse database results
- Transaction screenshots

---

## Evidence Preservation

### Golden Rules

1. **Hash Everything:** SHA256 hash immediately upon collection
2. **Timestamp Everything:** UTC timestamps for all evidence
3. **Document Chain of Custody:** Log who collected what and when
4. **Multiple Copies:** Original + working copy
5. **Integrity Verification:** Regular hash checks

### URL Archiving Procedure

```bash
# 1. Monolith (self-contained HTML)
monolith https://scam-site.com -o evidence_$(date +%Y%m%d_%H%M%S).html

# 2. Screenshot
cutycapt --url=https://scam-site.com --out=screenshot_$(date +%Y%m%d_%H%M%S).png

# 3. Wayback Machine
waybackpy --url "https://scam-site.com" --save

# 4. Hash the evidence
sha256sum evidence_*.html screenshot_*.png > evidence_hashes.txt
```

### Evidence Log Entry

Add to evidence_log.md:
```markdown
| 2024-01-15 10:30:00 UTC | Archive | Scam homepage capture | abc123... | monolith |
```

---

## Report Generation

### Final Report Contents

1. **Executive Summary**
   - Case overview
   - Key findings
   - Recommended actions

2. **Investigation Targets**
   - All identifiers investigated
   - Connection between identifiers

3. **Detailed Findings**
   - Per-identifier results
   - Tool outputs
   - Analysis notes

4. **Evidence Inventory**
   - File list with hashes
   - Chain of custody log

5. **Abuse Contacts**
   - Registrar
   - Hosting provider
   - ISP

6. **Recommendations**
   - Abuse reports to file
   - Law enforcement referral
   - Client advisories

---

## Abuse Reporting Workflow

### Step 1: Identify Responsible Parties

From investigation, compile:
- Domain registrar abuse email
- Hosting provider abuse email
- Email provider abuse address
- Upstream ISP (if identifiable)

### Step 2: Prepare Abuse Report

Use template from toolkit:
```
./osint_investigator.sh → Reports Menu → Generate Abuse Report Template
```

Include:
- Nature of abuse (phishing, scam, malware)
- Specific URLs/IPs/domains
- Timeline of activity
- Evidence (references, not attachments)
- Your contact information

### Step 3: Submit Reports

**Domain Registrar:**
- Submit via registrar's abuse portal
- Reference domain name
- Request suspension/takedown

**Hosting Provider:**
- Email to abuse contact from ASN lookup
- Include IP addresses and URLs
- Request content removal

**Email Provider:**
- Forward original scam email
- Report via provider's abuse form
- Request account termination

### Step 4: Document Submissions

Record in case file:
- Date/time of submission
- Recipient
- Method (email, web form)
- Reference/ticket number
- Attachments sent

### Step 5: Follow Up

- Wait 48-72 hours for initial response
- Follow up if no response
- Document all communications
- Escalate if necessary

---

## IC3 Submission Checklist

For FBI Internet Crime Complaint Center (ic3.gov):

- [ ] Victim information
- [ ] Suspect information (all identifiers)
- [ ] Financial loss amount
- [ ] Payment methods used
- [ ] Communication records
- [ ] Investigation report (PDF)
- [ ] Evidence hashes
- [ ] Timeline of events

Submit at: https://www.ic3.gov/

---

*Document version: 1.0*
*Last updated: 2024*
