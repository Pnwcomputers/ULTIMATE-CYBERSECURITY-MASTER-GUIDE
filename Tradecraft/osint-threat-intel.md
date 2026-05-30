# OSINT & Threat Intelligence — Deep Dive

> **Scope:** Open-source intelligence methodology, tooling, and threat intelligence platforms. Covers passive recon, active enumeration, people/organization research, infrastructure mapping, and threat intel operationalization.

---

## Table of Contents

1. [OSINT Methodology](#osint-methodology)
2. [Passive Reconnaissance](#passive-reconnaissance)
3. [DNS & Infrastructure Enumeration](#dns--infrastructure-enumeration)
4. [Web & Application Recon](#web--application-recon)
5. [People & Organization Intelligence](#people--organization-intelligence)
6. [Social Media Intelligence (SOCMINT)](#social-media-intelligence-socmint)
7. [Dark Web & Breach Data](#dark-web--breach-data)
8. [Threat Intelligence Platforms](#threat-intelligence-platforms)
9. [Threat Intel Operationalization](#threat-intel-operationalization)
10. [OPSEC for Investigators](#opsec-for-investigators)
11. [Defensive Applications](#defensive-applications)

---

## OSINT Methodology

### The Intelligence Cycle

```
 ┌─────────────────────────────────────────────────────┐
 │  1. Planning     → Define requirements, scope        │
 │  2. Collection   → Gather raw data from sources      │
 │  3. Processing   → Parse, deduplicate, normalize     │
 │  4. Analysis     → Extract meaning, identify gaps    │
 │  5. Dissemination → Report findings, act on intel    │
 │  6. Feedback     → Refine collection based on gaps   │
 └─────────────────────────────────────────────────────┘
```

### Defining Requirements

Before starting any OSINT collection:

- **Key Intelligence Questions (KIQs):** What do you need to answer?
- **Scope:** Target organization(s), individuals, infrastructure, time range
- **Legal authorization:** Confirm you have legal standing for investigation
- **Source prioritization:** Which sources are most relevant to the target?
- **OPSEC requirements:** How sensitive is the investigation?

### Intelligence Types

| Type | Description | Examples |
|---|---|---|
| OSINT | Open-source intelligence | Web, social media, public records |
| SIGINT | Signals intelligence | RF, packet captures |
| HUMINT | Human intelligence | Social engineering, interviews |
| GEOINT | Geospatial intelligence | Satellite imagery, maps |
| FININT | Financial intelligence | Corporate filings, transactions |

---

## Passive Reconnaissance

Passive recon involves no direct contact with the target — no packets sent to target systems.

### Google Dorking

```
# Site-specific search
site:target.com

# Find exposed files
site:target.com filetype:pdf OR filetype:xlsx OR filetype:docx

# Find login portals
site:target.com inurl:login OR inurl:portal OR inurl:admin

# Exposed credentials/config files
site:target.com filetype:env OR filetype:config OR filetype:cfg

# Find subdomains
site:*.target.com -site:www.target.com

# Cached pages (evades target logging)
cache:target.com

# Find specific text on pages
site:target.com "internal use only" OR "confidential"

# Exposed directories
site:target.com intitle:"index of"

# Find tech stack clues
site:target.com intext:"powered by" OR intext:"built with"
```

### Shodan

```bash
# Search by organization
org:"Target Corporation"

# Search by hostname
hostname:target.com

# Find specific services
org:"Target" port:3389           # RDP
org:"Target" port:22 product:OpenSSH
org:"Target" http.title:"admin"  # Admin panels
org:"Target" ssl.cert.subject.cn:"target.com"

# Find industrial/IoT
org:"Target" product:"Schneider Electric"
org:"Target" device:"webcam"

# Vulnerable services
vuln:CVE-2021-44228              # Log4Shell exposed

# Shodan CLI
shodan search --fields ip_str,port,org,hostnames "org:Target"
shodan host <IP>
shodan domain target.com
```

### Censys

```bash
# Search certificates
parsed.names: target.com

# Search services by org
autonomous_system.organization: "Target Corp"

# Find specific software
services.software.product: "Microsoft Exchange"

# Censys CLI
censys search "parsed.names: target.com" --index certificates
censys view <IP>
```

### WHOIS & Registration Data

```bash
# WHOIS lookup
whois target.com
whois <IP>

# Bulk WHOIS
for domain in $(cat domains.txt); do whois $domain | grep -i "registrant\|admin\|tech"; done

# Historical WHOIS (requires service account)
# DomainTools, WhoisXML API, SecurityTrails

# IP WHOIS
whois -h whois.arin.net <IP>     # ARIN (Americas)
whois -h whois.ripe.net <IP>     # RIPE (Europe)
whois -h whois.apnic.net <IP>    # APNIC (Asia-Pacific)
```

### Certificate Transparency

CT logs record every issued TLS certificate — excellent for subdomain discovery:

```bash
# crt.sh
curl -s "https://crt.sh/?q=%25.target.com&output=json" | jq -r '.[].name_value' | sort -u

# Certificate search tools
amass enum -passive -d target.com
subfinder -d target.com -silent

# certspotter
curl -s "https://api.certspotter.com/v1/issuances?domain=target.com&include_subdomains=true&expand=dns_names" | jq -r '.[].dns_names[]'
```

---

## DNS & Infrastructure Enumeration

### Subdomain Enumeration

```bash
# Passive (no direct contact with target)
amass enum -passive -d target.com
subfinder -d target.com
assetfinder --subs-only target.com
findomain -t target.com

# Certificate transparency
ctfr.py -d target.com

# DNS brute force (active — makes DNS queries)
amass enum -brute -d target.com -w /opt/wordlists/subdomains-top1million.txt
gobuster dns -d target.com -w /opt/SecLists/Discovery/DNS/bitquark-subdomains-top100000.txt

# Combine and deduplicate
cat amass.txt subfinder.txt assetfinder.txt | sort -u > all_subdomains.txt
```

### DNS Records

```bash
# Full DNS enumeration
dig target.com ANY
dig target.com MX
dig target.com TXT        # SPF, DMARC, DKIM, domain verification tokens
dig target.com NS
dig target.com SOA

# Reverse DNS
dig -x <IP>
host <IP>

# Zone transfer attempt (rarely works, worth trying)
dig axfr target.com @ns1.target.com

# DNS history (passive)
securitytrails.com
passivedns.mnemonic.no
community.riskiq.com (PassiveTotal)
```

### ASN & IP Range Mapping

```bash
# Find ASN from organization name
# https://bgp.he.net — search by org name

# Get IP ranges for an ASN
whois -h whois.radb.net -- '-i origin AS12345'
curl -s "https://api.bgpview.io/asn/12345/prefixes" | jq '.data.ipv4_prefixes[].prefix'

# Reverse lookup all IPs in a range
nmap -sL 192.168.1.0/24 | grep "Nmap scan report"

# shodan
shodan search "net:192.168.1.0/24"
```

### MX Records & Email Infrastructure

```bash
# Identify email service providers
dig target.com MX

# Common MX indicators:
# *.google.com       → Google Workspace
# *.outlook.com      → Microsoft 365
# *.mimecast.com     → Mimecast (email security gateway)
# *.proofpoint.com   → Proofpoint
# *.barracuda.com    → Barracuda

# Find email security posture via TXT
dig target.com TXT | grep -i "spf\|dmarc\|dkim"

# DMARC
dig _dmarc.target.com TXT

# SPF analysis — identify authorized senders
# p=none  → monitoring only (no enforcement)
# p=quarantine → quarantine failing mail
# p=reject → reject failing mail (strongest)
```

---

## Web & Application Recon

### Technology Fingerprinting

```bash
# whatweb
whatweb -a 3 https://target.com

# Wappalyzer CLI
wappalyzer https://target.com

# BuiltWith (web): https://builtwith.com/target.com

# Manual headers inspection
curl -I https://target.com | grep -i "server\|x-powered-by\|x-aspnet\|via"

# Nikto (active scan)
nikto -h https://target.com -ssl
```

### Web Archive & Historical Data

```bash
# Wayback Machine
curl "http://timetravel.mementoweb.org/api/json/20230101000000/https://target.com"

# Waybackurls — extract all historical URLs
waybackurls target.com | sort -u > wayback_urls.txt

# Find old admin panels, exposed files, decommissioned services
cat wayback_urls.txt | grep -i "admin\|login\|backup\|config\|\.env\|\.git"

# gau — get all URLs from multiple sources
gau target.com | sort -u
```

### Git & Source Code Exposure

```bash
# Search GitHub for target
# https://github.com/search?q=target.com&type=code

# Trufflehog — scan for secrets in git history
trufflehog git https://github.com/targetorg/repo
trufflehog github --org=targetorg

# Gitrob — find sensitive files in GitHub repos
gitrob targetorg

# Search for hardcoded credentials
# Dorks:
# site:github.com "target.com" password
# site:github.com "target.com" api_key
# site:github.com "target.com" secret
# site:pastebin.com "target.com"
```

### Job Postings as Intelligence

Job postings reveal technology stack, internal tools, infrastructure, and team structure:

```
"We use Kubernetes, Terraform, and AWS" → Cloud infrastructure details
"Experience with CrowdStrike required" → EDR vendor
"Our data team uses Snowflake and dbt"  → Data stack
"Familiarity with Jira/Confluence"      → Ticketing/wiki platform
```

Search: `site:linkedin.com/jobs OR site:indeed.com "target company" "engineer"`

---

## People & Organization Intelligence

### Corporate Structure

```bash
# SEC EDGAR (US public companies)
# https://efts.sec.gov/LATEST/search-index?q="target+company"
# 10-K (annual), 10-Q (quarterly), DEF 14A (proxy — exec names, salaries)

# OpenCorporates — global company data
curl "https://api.opencorporates.com/v0.4/companies/search?q=Target+Corp"

# LinkedIn company structure
# → Employee count by department
# → Org chart via LinkedIn Sales Navigator
# → Recent hires / departures (signals of change)

# Crunchbase — funding, acquisitions, investors
https://www.crunchbase.com/organization/target-company

# FOIA requests (US federal entities)
https://www.foiaonline.gov/
```

### Email Permutation & Verification

```bash
# Hunter.io — find email format and addresses
curl "https://api.hunter.io/v2/domain-search?domain=target.com&api_key=KEY"

# Email permutation
# Common formats: firstname.lastname@, f.lastname@, firstnamel@, firstname@
# Tools: EmailHippo, Hunter, Snov.io

# Verify email without sending
# SMTP verification (verify MX, then RCPT TO without sending)
smtp-user-enum -M RCPT -u firstname.lastname -d target.com -D target.com -t mail.target.com
```

### Key Personnel Research

```bash
# LinkedIn profile enumeration
# Search: site:linkedin.com/in "target company" "security engineer"

# Twitter/X: Find employees discussing internal issues
# site:twitter.com "target company" OR "workingatTarget"

# GitHub: Find employee repos
# site:github.com "target.com" in:profile

# Conference talks: Find presentations by target employees
# site:youtube.com OR site:slideshare.net "target company" devcon security
```

---

## Social Media Intelligence (SOCMINT)

### Twitter/X

```bash
# Advanced search operators
from:username since:2023-01-01 until:2024-01-01
to:@username
#hashtag filter:media

# OSINT tools
twint -u username --since 2023-01-01 --output tweets.csv --csv
snscrape twitter-user username > tweets.json

# Geolocation from media
# Use InVID/WeVerify browser extension to check image metadata
# ExifTool on downloaded images
exiftool image.jpg | grep -i "GPS\|Location\|Latitude\|Longitude"
```

### Instagram / Facebook / LinkedIn

```bash
# Instagram
# Picuki.com — view without account
# Imginn.com — view posts and stories
# Osintgram — pip install osintgram

# Facebook
# Facebook Advanced Search: facebook.com/search/
# Sowsearch.info — search by phone, email

# LinkedIn
# Search without login: site:linkedin.com/in "John Smith" "Target Corp"
# Proxycurl API — scrape LinkedIn profiles
```

### Image Reverse Search & Geolocation

```bash
# Reverse image search
# Google Images: images.google.com (drag/drop or URL)
# Yandex Images: yandex.com/images (best for faces)
# TinEye: tineye.com
# PimEyes: pimeyes.com (face recognition — legal/ethical use only)

# Geolocation from imagery
# SunCalc.org — determine time of day from shadows
# PeakFinder — identify mountains
# GeoGuessr-style techniques: signs, foliage, architecture, road markings
```

---

## Dark Web & Breach Data

### Breach Data Sources

```bash
# HaveIBeenPwned API
curl "https://haveibeenpwned.com/api/v3/breachedaccount/user@target.com" \
  -H "hibp-api-key: YOUR_KEY"

# DeHashed (credential search)
curl -H 'Accept: application/json' \
  -u "email:api_key" \
  "https://api.dehashed.com/search?query=domain%3Atarget.com&size=100"

# IntelX (intelligence X)
# https://intelx.io/ — search pastes, dark web, file sharing

# Leak-Lookup
# Flare.io (commercial)
# SpyCloud (commercial)
```

### Dark Web Monitoring

```bash
# Tor Browser for manual investigation
# OnionSearch — search dark web indexes
python3 onionsearch.py "target company credentials"

# Ahmia.fi — clearnet dark web search engine
curl "https://ahmia.fi/search/?q=target+company"

# Key forums/markets to monitor (for CTI purposes):
# Exploit.in, XSS.is, BreachForums (frequently seized/relaunched)
# RaaS sites: LockBit, ALPHV/BlackCat leak sites

# Commercial services:
# Recorded Future, Flashpoint, Intel 471
```

---

## Threat Intelligence Platforms

### Open Source / Free

| Platform | URL | Strengths |
|---|---|---|
| VirusTotal | virustotal.com | File/URL/IP/domain reputation |
| AlienVault OTX | otx.alienvault.com | IOC sharing, threat pulses |
| AbuseIPDB | abuseipdb.com | IP reputation, abuse reports |
| URLScan.io | urlscan.io | URL/domain analysis, screenshots |
| Shodan | shodan.io | Internet-facing asset intelligence |
| Censys | censys.io | Certificate/host intelligence |
| GreyNoise | greynoise.io | Internet background noise filtering |
| Pulsedive | pulsedive.com | IOC enrichment |
| OpenCTI | github.com/OpenCTI-Platform | Self-hosted CTI platform |
| MISP | misp-project.org | Threat sharing platform |

### Commercial

| Platform | Strengths |
|---|---|
| Recorded Future | Comprehensive, predictive intel |
| Mandiant Advantage | Threat actor tracking, dark web |
| CrowdStrike Falcon X | Integrated with EDR |
| Flashpoint | Criminal forum monitoring |
| Intel 471 | Threat actor profiling |
| Digital Shadows | Attack surface + dark web |

### VirusTotal Workflows

```bash
# CLI usage
vt file <hash>
vt url https://suspicious-url.com
vt ip 1.2.3.4
vt domain evil.com

# Search for related infrastructure
vt search "entity:domain name:*.evil.com"

# Find files communicating with C2
vt search "behaviour_network:evil.com"

# Hunt for similar malware samples
vt search "tag:trojan AND size:50kb+ AND type:peexe AND fs:2024-01-01+"
```

### MISP Integration

```python
# Pull IOCs from MISP for SIEM ingestion
from pymisp import PyMISP

misp = PyMISP('https://your-misp-instance', 'API_KEY', ssl=True)

# Search recent events
events = misp.search(last='7d', type_attribute='ip-dst', pythonify=True)
for event in events:
    for attr in event.attributes:
        print(f"{attr.type}: {attr.value} | {event.info}")

# Export IOCs as flat list for firewall/SIEM
iocs = misp.search(type_attribute='ip-dst', to_ids=True, pythonify=True)
ips = [attr.value for event in iocs for attr in event.attributes]
```

---

## Threat Intel Operationalization

### IOC Lifecycle

```
Collection → Validation → Enrichment → Scoring → Deployment → Expiration
```

**IOC Scoring Factors:**
- Source reliability (1–5 scale)
- Recency (fresh IOCs score higher)
- Context (is this targeted or generic noise?)
- Confidence (corroborated by multiple sources?)
- Fidelity (high false-positive potential?)

### IOC Formats

```xml
<!-- STIX 2.1 (JSON) — standard for IOC exchange -->
{
  "type": "indicator",
  "id": "indicator--12345",
  "pattern": "[ipv4-addr:value = '1.2.3.4']",
  "pattern_type": "stix",
  "valid_from": "2024-01-01T00:00:00Z",
  "labels": ["malicious-activity"]
}
```

```bash
# TAXII — transport protocol for STIX feeds
# cabby — TAXII client
cabby discovery --host taxii.example.com --port 443 --use-https
cabby collection-management --host taxii.example.com --port 443 --use-https
```

### Threat Actor Profiling

When building a threat actor profile, document:

```
Name / Aliases:
Suspected origin:
Motivation: (financial, espionage, hacktivism, disruption)
Target sectors:
TTPs (MITRE ATT&CK):
    Initial Access: T1566.001 (Spearphishing)
    Execution: T1059.001 (PowerShell)
    Persistence: T1053.005 (Scheduled Task)
    ...
Known tooling:
    - Tool name, purpose, detection
Infrastructure indicators:
    - C2 IPs/domains
    - Registrar patterns
    - Certificate fingerprints
Campaign history:
    - Date, target, method
Detection rules: (Sigma, YARA, Snort)
References:
```

---

## OPSEC for Investigators

### Isolation Architecture

```
[Analyst Workstation] 
    → [VPN / Tor] 
        → [Dedicated Research VM] 
            → [Burner accounts / Sock puppets] 
                → [Target investigation]
```

- Never investigate from your real IP
- Use dedicated VMs that can be snapshotted/restored
- Separate browsers per investigation
- Use temporary email/phone for account creation
- Do not log into personal accounts on investigation infrastructure

### Browser OPSEC

```bash
# Firefox hardening for OSINT
# Extensions:
#   uBlock Origin — ad/tracker blocking
#   Canvas Blocker — prevent fingerprinting
#   User-Agent Switcher — change browser fingerprint
#   Cookie AutoDelete
#   Privacy Badger

# Tor Browser — for anonymized browsing
# Whonix — OS-level Tor routing
```

### Operational Security Checklist

```
☐ Verified VPN/Tor is active before starting
☐ Using dedicated VM, not host OS
☐ Browser fingerprint randomized
☐ No personal accounts logged in
☐ Research VM isolated from production network
☐ Screen recording/logging is on for evidence chain
☐ Notes are dated, sourced, and attributed
☐ Evidence is hashed for integrity (sha256sum)
```

---

## Defensive Applications

### External Attack Surface Mapping

Run the same passive recon against your own organization:

```bash
# Map your own attack surface
amass enum -passive -d yourcompany.com
subfinder -d yourcompany.com
shodan search org:"Your Company"
certspotter yourcompany.com
trufflehog github --org=yourcompany   # Find leaked credentials
```

### Threat Intel Integration with SIEM

```bash
# Convert MISP IOCs to Suricata/Snort rules
misp2suri --misp-url https://misp.local --misp-key KEY --out /etc/suricata/rules/misp.rules

# OpenCTI → ElasticSIEM connector
# GitHub: OpenCTI-Platform/connectors/elastic-siem

# Block at DNS (Pi-hole / OPNsense Unbound)
# Use threat feeds: Abuse.ch URLHaus, Emerging Threats
curl -s https://urlhaus.abuse.ch/downloads/hostfile/ | grep -v "^#" >> /etc/pihole/custom.list
```

### Proactive Brand Monitoring

```bash
# Monitor for new domains typosquatting your brand
dnstwist --registered yourcompany.com

# Certificate transparency monitoring
# certstream.calidog.io — real-time CT log stream
python3 certstream_monitor.py --keyword yourcompany

# Monitor paste sites for leaked data
# Pastebin, GitHub Gist, JustPaste.it
# Commercial: PwnDB, Spycloud
```

---

## OSINT Tool Platform Reference

Most OSINT tools are Linux-native but many run on Windows. This section clarifies platform availability and Windows-specific setup for the full toolset.

### Windows OSINT Environment

**Buscador VM** (deprecated but concept lives on) — A dedicated OSINT Linux VM preconfigured with tools. The modern equivalent is building your own via a base Ubuntu VM + the tools below. On Windows, use WSL2 or a dedicated VM.

**OSINT on Windows — recommended setup:**

```powershell
# Install WSL2 for Linux tool access on Windows
wsl --install -d Ubuntu

# Or use a dedicated Kali/Ubuntu VM in VirtualBox/VMware
# Kali Linux has most OSINT tools pre-installed under kali-tools-information-gathering

# Install Python-based OSINT tools natively on Windows
pip install shodan           # Shodan CLI
pip install censys           # Censys CLI
pip install theHarvester     # theHarvester
pip install trufflehog       # TruffleHog git scanner
pip install dnstwist         # Domain typosquatting monitor
pip install h8mail           # Email breach hunter
pip install holehe            # Email account checker
pip install maigret           # Username search
pip install phoneinfoga       # Phone number OSINT

# Install go-based tools (requires Go on Windows)
# https://go.dev/dl/
go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install github.com/tomnomnom/assetfinder@latest
go install github.com/lc/gau/v2/cmd/gau@latest
go install github.com/tomnomnom/waybackurls@latest
```

### Maltego (Windows/Linux/macOS)

Maltego is one of the few OSINT tools that runs better on Windows than Linux — it's a Java-based GUI platform for link analysis and relationship mapping.

```
# Download: https://www.maltego.com/downloads/
# Available for Windows (installer), Linux (AppImage/deb), macOS

# Free tier: Maltego CE (Community Edition)
# - 12 results per transform (enough for recon work)
# - Requires free account registration

# Install transforms (data source connectors):
# Maltego → Transform Hub → Install:
#   Shodan           ← maps IPs, services, banners
#   VirusTotal       ← file/domain/IP reputation
#   HaveIBeenPwned   ← breach data lookups
#   FullContact      ← person/email enrichment
#   WhoisXML         ← domain registration data
#   PassiveTotal     ← passive DNS, certificate data
#   GitHub           ← find repos linked to targets

# Core Maltego workflow:
# 1. Start with seed entity (domain, email, person, IP)
# 2. Run transforms → expand graph with related entities
# 3. Follow relationships to uncover infrastructure, personnel, accounts
# 4. Export graph as image or report
```

### SpiderFoot (Windows/Linux)

SpiderFoot automates OSINT collection from 200+ sources. Has both a web UI and CLI.

```powershell
# Windows install
pip install spiderfoot
spiderfoot -l 127.0.0.1:5001    # Start web UI
# Open browser: http://127.0.0.1:5001

# Linux install (same)
pip3 install spiderfoot
python3 -m spiderfoot -l 127.0.0.1:5001

# CLI scan (no UI)
spiderfoot -s target.com -t INTERNET_NAME -o tab > results.txt

# Key module categories:
# Footprint   — passive recon (DNS, WHOIS, certificates, Shodan)
# Investigate — active checks (port scan, crawl, brute force subdomains)
# Passive     — no direct contact with target
```

### Recon-ng (Windows/Linux)

A full-featured web reconnaissance framework with a console interface similar to Metasploit.

```powershell
# Windows install
pip install recon-ng
recon-ng

# Linux install
sudo apt install recon-ng
# or
git clone https://github.com/lanmaster53/recon-ng.git
cd recon-ng && pip3 install -r REQUIREMENTS

# Inside recon-ng console:
[recon-ng][default] > marketplace install all   # install all modules
[recon-ng][default] > workspaces create target_corp
[recon-ng][default] > db insert domains         # add seed domain
[recon-ng][default] > modules load recon/domains-hosts/hackertarget
[recon-ng][default] > run                       # enumerate subdomains

# Key modules:
# recon/domains-hosts/brute_hosts       — subdomain brute force
# recon/hosts-ports/shodan_ip           — Shodan port data
# recon/domains-contacts/whois_pocs     — WHOIS contact extraction
# recon/profiles-profiles/namechk       — username availability check
# reporting/html                        — generate HTML report
```

### theHarvester (Windows/Linux)

Passive email, subdomain, and name harvesting from public sources.

```powershell
# Windows
pip install theHarvester
theHarvester -d target.com -b all -l 500 -f results.html

# Linux
sudo apt install theharvester
# or pip3 install theHarvester

# Common usage
theHarvester -d target.com -b google,bing,yahoo,linkedin,twitter -l 200
theHarvester -d target.com -b shodan -l 100    # requires Shodan API key
theHarvester -d target.com -b all -f report    # output HTML + XML report

# Key sources (-b):
# google, bing, yahoo          — search engine results
# linkedin                     — LinkedIn email/name harvest
# twitter                      — Twitter account harvest
# shodan                       — Shodan infrastructure data
# certspotter, crtsh            — certificate transparency
# dnsdumpster                  — DNS records
# all                          — all sources (slow but thorough)
```

### Shodan CLI (Windows/Linux)

```powershell
# Install on Windows or Linux
pip install shodan

# Initialize with API key
shodan init YOUR_API_KEY

# Core commands
shodan search org:"Target Corp"
shodan search "hostname:target.com"
shodan host 1.2.3.4              # full host report
shodan domain target.com         # DNS + subdomains + services
shodan stats "org:Target"        # aggregate statistics
shodan scan submit 192.168.1.0/24  # on-demand scan (uses scan credits)

# Save results
shodan search --fields ip_str,port,org,hostnames "org:Target" > shodan_results.csv

# Alert on new exposed services (monitor mode)
shodan alert create "Target Monitor" 1.2.3.4/24
shodan alert list
```

### Censys CLI (Windows/Linux)

```powershell
# Install
pip install censys

# Configure
censys config    # prompts for API ID and secret

# Search hosts
censys search "autonomous_system.organization: Target Corp" --index hosts

# Search certificates
censys search "parsed.names: target.com" --index certificates

# View specific host
censys view 1.2.3.4 --index hosts

# Python API (for scripting)
python3 << 'EOF'
from censys.search import CensysHosts
h = CensysHosts()
results = h.search("autonomous_system.organization: Target Corp", per_page=100)
for host in results:
    print(host['ip'], host.get('services', []))
EOF
```

### amass (Windows/Linux)

The most comprehensive subdomain enumeration tool. Runs on both platforms.

```powershell
# Windows install
# Download binary from https://github.com/owasp-amass/amass/releases
# Or via Go:
go install github.com/owasp-amass/amass/v4/...@master

# Linux install
sudo apt install amass
# or snap:
snap install amass

# Passive enumeration (no direct contact with target)
amass enum -passive -d target.com -o subdomains.txt

# Active enumeration with brute force
amass enum -active -brute -d target.com -w /usr/share/wordlists/subdomains.txt

# Use API keys for more results (configure in ~/.config/amass/datasources.yaml)
# Supports: Shodan, Censys, VirusTotal, SecurityTrails, WhoisXML, etc.

# Visualize the attack surface
amass viz -d3 -d target.com -o viz.html   # Interactive D3 graph
amass viz -dot -d target.com -o viz.dot   # Graphviz format
```

### trufflehog (Windows/Linux)

Scans git repositories and other sources for leaked credentials and secrets.

```powershell
# Windows install
pip install trufflehog
# or binary from https://github.com/trufflesecurity/trufflehog/releases

# Linux
curl -sSfL https://raw.githubusercontent.com/trufflesecurity/trufflehog/main/scripts/install.sh | sh

# Scan a GitHub org for leaked secrets
trufflehog github --org=targetorg --only-verified

# Scan a specific repo
trufflehog git https://github.com/targetorg/repo --only-verified

# Scan local directory
trufflehog filesystem /path/to/cloned/repos --only-verified

# Scan S3 bucket
trufflehog s3 --bucket=target-bucket

# Output formats
trufflehog github --org=targetorg --json    # machine-readable
trufflehog github --org=targetorg --csv     # spreadsheet-friendly
```

### dnstwist (Windows/Linux)

Finds typosquatting, phishing, and lookalike domains targeting your brand.

```powershell
# Windows
pip install dnstwist

# Linux
pip3 install dnstwist
# or: sudo apt install dnstwist

# Find registered lookalike domains
dnstwist --registered target.com

# Check for MX records (phishing-ready domains)
dnstwist --registered --mxcheck target.com

# Check for fuzzy hashing similarity (visual lookalikes)
dnstwist --registered --ssdeep target.com

# Output to CSV for reporting
dnstwist --registered --format csv target.com > lookalikes.csv

# JSON output for integration
dnstwist --registered --format json target.com > lookalikes.json

# Common permutation types found:
# Homoglyph      — rn vs m, 0 vs o, 1 vs l
# Bitsquatting   — single bit flip in ASCII
# Transposition  — targe.tcom
# Omission       — targt.com
# Addition       — targets.com
```

### h8mail (Windows/Linux)

Searches breach databases for email addresses associated with a target domain.

```powershell
# Install on Windows or Linux
pip install h8mail

# Search for emails from a domain in known breaches
h8mail -t target.com

# Search specific email
h8mail -t employee@target.com

# Use with API keys for more sources (HaveIBeenPwned, Hunter.io, etc.)
# Configure in h8mail.ini:
# [hibp]
# api_key = YOUR_KEY

h8mail -t target.com -c h8mail.ini

# Output to file
h8mail -t target.com --output results.csv
```

### OSINT VM Setup (Trace Labs / Kali)

For a fully pre-configured Linux OSINT environment:

```bash
# Kali Linux — includes most OSINT tools under information-gathering
sudo apt install kali-tools-information-gathering

# Key tools installed:
# maltego, recon-ng, theharvester, amass, spiderfoot,
# dnsx, subfinder, gobuster, whatweb, nikto, nmap,
# dmitry, fierce, dnsenum, dnsrecon, enum4linux

# Trace Labs OSINT VM — specialized for investigations
# https://www.tracelabs.org/initiatives/osint-vm
# Based on Kali, adds investigation-specific tools and workflows
```

### Tool Platform Summary

| Tool | Windows | Linux | Notes |
|---|---|---|---|
| **Maltego** | ✅ native installer | ✅ AppImage/deb | Best on Windows — Java GUI |
| **SpiderFoot** | ✅ `pip install` | ✅ `pip3 install` | Web UI on both |
| **Recon-ng** | ✅ `pip install` | ✅ `apt install` | Console UI, Metasploit-like |
| **theHarvester** | ✅ `pip install` | ✅ `apt install` | CLI, passive focused |
| **Shodan CLI** | ✅ `pip install` | ✅ `pip3 install` | Requires API key |
| **Censys CLI** | ✅ `pip install` | ✅ `pip3 install` | Requires API key |
| **amass** | ✅ binary/Go | ✅ `apt install` | Best passive subdomain tool |
| **subfinder** | ✅ Go binary | ✅ Go/apt | Fast, API-key driven |
| **trufflehog** | ✅ pip/binary | ✅ install script | Secret scanning |
| **dnstwist** | ✅ `pip install` | ✅ `pip3/apt` | Brand monitoring |
| **h8mail** | ✅ `pip install` | ✅ `pip3 install` | Breach data hunting |
| **gobuster** | ✅ Go binary | ✅ `apt install` | DNS/dir brute force |
| **waybackurls** | ✅ Go binary | ✅ Go binary | Historical URL harvest |
| **gau** | ✅ Go binary | ✅ Go binary | URL harvest from multiple sources |
| **OSINT VM (Kali)** | ❌ (use WSL2 or VM) | ✅ native | Full pre-configured environment |

---

## References

- [OSINT Framework](https://osintframework.com/)
- [Bellingcat OSINT Toolkit](https://docs.google.com/spreadsheets/d/18rtqh8EG2q1xBo2cLNyhIDuK9jrPGwYr9DI2UncoqJQ/edit)
- [MITRE ATT&CK: Reconnaissance](https://attack.mitre.org/tactics/TA0043/)
- [SANS OSINT Poster](https://www.sans.org/security-resources/posters/open-source-intelligence-gathering/)
- [IntelTechniques](https://inteltechniques.com/tools/)
- [Trace Labs CTF (missing persons OSINT)](https://www.tracelabs.org/)
- [OSINT Curious](https://osintcurio.us/)
- [Maltego](https://www.maltego.com/)
- [SpiderFoot](https://github.com/smicallef/spiderfoot)
- [Recon-ng](https://github.com/lanmaster53/recon-ng)
- [theHarvester](https://github.com/laramies/theHarvester)
- [amass](https://github.com/owasp-amass/amass)
- [trufflehog](https://github.com/trufflesecurity/trufflehog)
- [dnstwist](https://github.com/elceef/dnstwist)
- [Shodan CLI](https://cli.shodan.io/)
- [Censys CLI](https://github.com/censys/censys-python)
