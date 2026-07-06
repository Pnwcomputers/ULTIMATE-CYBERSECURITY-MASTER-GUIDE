# OSINT (Open Source Intelligence) Basic/General Guide

### [Click Here For The Advanced OSINT Guide](/Tradecraft/osint-threat-intel.md) 

## Table of Contents
1. [Introduction to OSINT](#introduction-to-osint)
2. [OSINT Methodology & Framework](#osint-methodology--framework)
3. [Core OSINT Tools](#core-osint-tools)
4. [OSINT by Category](#osint-by-category)
5. [OSINT VM Setup](#osint-vm-setup)
6. [Investigation Procedures by Identifier Type](#investigation-procedures-by-identifier-type)
7. [Investigation Workflows](#investigation-workflows)
8. [Evidence Preservation & Chain of Custody](#evidence-preservation--chain-of-custody)
9. [Abuse Reporting Workflow](#abuse-reporting-workflow)
10. [OSINT Best Practices & OPSEC](#osint-best-practices--opsec)
11. [Legal & Ethical Considerations](#legal--ethical-considerations)
12. [Resources & Learning](#resources--learning)

---

## Introduction to OSINT

**Open Source Intelligence (OSINT)** refers to the collection and analysis of information gathered from publicly available sources. OSINT is used across multiple domains including:

- **Cybersecurity**: Threat intelligence, vulnerability research, and attack surface mapping
- **Law Enforcement**: Investigations, missing persons cases, and criminal intelligence
- **Corporate Security**: Competitor analysis, due diligence, and brand protection
- **Journalism**: Investigative reporting and fact-checking
- **Personal Security**: Background checks and reputation monitoring

### What Makes Intelligence "Open Source"?

- **Publicly accessible data** from the internet, social media, public records
- **Legally obtained** without hacking, unauthorized access, or social engineering
- **Ethically collected** respecting privacy laws and terms of service

---

## OSINT Methodology & Framework

### The OSINT Cycle

~~~
1. Requirements Definition
   └─> Define objectives and intelligence questions

2. Source Identification  
   └─> Identify relevant data sources

3. Data Collection
   └─> Gather information from sources

4. Data Processing
   └─> Organize, filter, and prepare data

5. Analysis
   └─> Connect dots, identify patterns

6. Dissemination
   └─> Present findings in actionable format

7. Feedback
   └─> Refine approach based on results
~~~

### OSINT Framework Structure

The OSINT Framework categorizes investigations by:
- **Username** - Social media presence, online accounts
- **Email Address** - Account enumeration, breach data
- **Domain Name** - DNS records, WHOIS, website info
- **IP Address** - Geolocation, network information
- **Phone Number** - Carrier lookup, social media links
- **Person** - Public records, social profiles
- **Company** - Corporate records, employees, infrastructure
- **Cryptocurrency** - Wallet tracing, scam database lookups

---

## Core OSINT Tools

### Email & Username Investigation

#### **theHarvester**
~~~bash
# Email, subdomain, and name harvesting
theHarvester -d target.com -l 500 -b all

# Specific source (Google, Bing, LinkedIn, etc.)
theHarvester -d target.com -b google
~~~
- **Use Case**: Email addresses, subdomains, names, IPs
- **Sources**: Google, Bing, PGP servers, LinkedIn, Twitter
- **GitHub**: https://github.com/laramies/theHarvester

#### **Sherlock**
~~~bash
# Search for username across social media platforms
sherlock username

# Export results to file
sherlock username -o results.txt

# Search specific sites
sherlock username --site Twitter
~~~
- **Use Case**: Username search across 400+ social networks
- **Speed**: Fast batch searching
- **GitHub**: https://github.com/sherlock-project/sherlock

#### **Maigret**
~~~bash
# Advanced username OSINT (better than Sherlock for some cases)
maigret username

# With permutations
maigret username --use-disabled-sites

# Full export with reports
maigret username --pdf --html -o ./username_results/
~~~
- **Use Case**: Username enumeration with additional data extraction (2500+ sites)
- **GitHub**: https://github.com/soxoj/maigret

#### **Blackbird**
~~~bash
# Username enumeration - alternative/complement to Sherlock & Maigret
blackbird -u username
~~~
- **Use Case**: Username search across additional platforms not covered by Sherlock
- **GitHub**: https://github.com/p1ngul1n0/blackbird

#### **H8mail**
~~~bash
# Email OSINT & breach hunting
h8mail -t target@email.com

# With API keys for breach databases
h8mail -t target@email.com -k <API_KEY>

# Export results to CSV
h8mail -t target@email.com -o breach_results.csv
~~~
- **Use Case**: Email breach correlation, password leaks
- **GitHub**: https://github.com/khast3x/h8mail

#### **Holehe**
~~~bash
# Check if email is used on different sites
holehe target@email.com

# Show only services where the email is registered
holehe target@email.com --only-used
~~~
- **Use Case**: Determine which services an email is registered on
- **GitHub**: https://github.com/megadose/holehe

### Phone Number Intelligence

#### **PhoneInfoga**
~~~bash
# Phone number OSINT
phoneinfoga scan -n +1234567890
~~~
- **Use Case**: Carrier lookup, number validation, social media connections
- **Features**: International format support, reputation checks
- **GitHub**: https://github.com/sundowndev/phoneinfoga

### Domain & Network Reconnaissance

#### **Recon-ng**
~~~bash
# Full-featured web reconnaissance framework
recon-ng
[recon-ng][default] > workspaces create target_company
[recon-ng][target_company] > marketplace install all
[recon-ng][target_company] > modules search
~~~
- **Use Case**: Comprehensive reconnaissance automation
- **Modules**: DNS, WHOIS, breaches, social media, more
- **GitHub**: https://github.com/lanmaster53/recon-ng

#### **Amass**
~~~bash
# Network mapping and asset discovery (OWASP)
amass enum -d target.com

# Passive mode (no active scanning)
amass enum -passive -d target.com

# With DNS bruteforcing
amass enum -brute -d target.com
~~~
- **Use Case**: Subdomain enumeration, DNS mapping, network discovery
- **Features**: Integration with 50+ data sources
- **GitHub**: https://github.com/owasp-amass/amass

#### **Subfinder**
~~~bash
# Fast subdomain discovery
subfinder -d target.com

# With specific sources
subfinder -d target.com -sources virustotal,shodan

# Silent output for piping
subfinder -d target.com -silent
~~~
- **Use Case**: Subdomain enumeration for attack surface mapping
- **GitHub**: https://github.com/projectdiscovery/subfinder

#### **httpx (ProjectDiscovery)**
~~~bash
# Probe live hosts and fingerprint web stack
httpx -l subdomains.txt -td -server -title -asn -status-code

# Single target with technology detection
echo target.com | httpx -td -server -title

# Pipeline: subfinder → httpx
subfinder -d target.com -silent | httpx -td -server -title -asn
~~~
- **Use Case**: Live host probing, tech stack fingerprinting, ASN lookup
- **Pairs With**: subfinder → httpx pipeline for attack surface mapping
- **GitHub**: https://github.com/projectdiscovery/httpx

#### **waybackurls**
~~~bash
# Pull all historical URLs known to the Wayback Machine
echo target.com | waybackurls > historical_urls.txt

# Combined with subfinder for full historical surface
subfinder -d target.com -silent | waybackurls | sort -u
~~~
- **Use Case**: Historical URL discovery, deleted endpoint recovery
- **GitHub**: https://github.com/tomnomnom/waybackurls

#### **asn (CLI Tool)**
~~~bash
# One-shot ASN, network range, and abuse contact lookup
asn 8.8.8.8
asn target.com
~~~
- **Use Case**: Quick ASN identification, abuse email discovery for reporting
- **GitHub**: https://github.com/nitefood/asn

### Web Crawling & Analysis

#### **Photon**
~~~bash
# Incredibly fast web crawler for OSINT
python photon.py -u https://target.com -o output -l 3 -t 100

# Extract specific data types
python photon.py -u https://target.com --dns --keys --emails
~~~
- **Use Case**: URL extraction, JavaScript files, endpoint discovery
- **Speed**: Multi-threaded, extremely fast
- **GitHub**: https://github.com/s0md3v/Photon

#### **SpiderFoot**
~~~bash
# Automated OSINT collection
spiderfoot -s target.com
~~~
- **Use Case**: Comprehensive automated OSINT (100+ modules)
- **Integration**: DNS, emails, social media, dark web, more
- **Features**: GUI and CLI versions available
- **GitHub**: https://github.com/smicallef/spiderfoot

### Evidence Capture & Archival

#### **Monolith**
~~~bash
# Archive a webpage as a single self-contained HTML file (evidence preservation)
monolith https://target-site.com -o evidence_$(date +%Y%m%d_%H%M%S).html

# With JavaScript execution
monolith -j https://target-site.com -o archived.html
~~~
- **Use Case**: Forensic-quality web page archival, evidence preservation
- **GitHub**: https://github.com/Y2Z/monolith

#### **CutyCapt**
~~~bash
# CLI screenshot capture for evidence
cutycapt --url=https://target.com --out=screenshot_$(date +%Y%m%d_%H%M%S).png
~~~
- **Use Case**: Headless screenshot capture, evidence documentation

#### **WaybackPy**
~~~bash
# Submit pages to the Wayback Machine for archiving
waybackpy --url "https://target-site.com" --save
~~~
- **Use Case**: Programmatic Wayback Machine submission for evidence preservation
- **GitHub**: https://github.com/akamhy/waybackpy

### Link Analysis & Data Mining

#### **Maltego**
- **Use Case**: Visual link analysis, relationship mapping
- **Features**: Transform hub with 100+ data integrations
- **Data Sources**: DNS, WHOIS, social media, public records
- **Editions**: Community (free), Classic, XL
- **Website**: https://www.maltego.com

### Additional Essential Tools

#### **Metagoofil**
~~~bash
# Metadata extraction from documents
metagoofil -d target.com -t pdf,doc,xls -l 100 -o output -f results.html
~~~
- **Use Case**: Extract metadata from public documents
- **Information**: Authors, software versions, internal paths

#### **WhatWeb**
~~~bash
# Website fingerprinting
whatweb target.com

# Aggressive mode
whatweb target.com -a 3
~~~
- **Use Case**: Identify web technologies, CMS, frameworks

---

## OSINT by Category

### Search Engines & Dorking

#### **Google Dorking**
~~~
site:target.com filetype:pdf
site:target.com inurl:admin
site:target.com intitle:"index of"
"@target.com" site:pastebin.com
site:*.target.com -www
~~~

#### **Specialized Search Engines**
- **Shodan** (https://shodan.io) - Search engine for Internet-connected devices
- **Censys** (https://censys.io) - Internet-wide scanning and analysis
- **GreyNoise** (https://greynoise.io) - Internet background noise intelligence
- **Hunter.io** (https://hunter.io) - Email finder and verification
- **Have I Been Pwned** (https://haveibeenpwned.com) - Breach notification service

#### **Additional Intelligence Platforms**
- **CriminalIP** (https://www.criminalip.io) - Cyber threat intelligence with IP/domain reputation
- **Netlas** (https://netlas.io) - Internet-wide scanning, similar to Shodan/Censys
- **FullHunt** (https://fullhunt.io) - Attack surface discovery and monitoring
- **ZoomEye** (https://www.zoomeye.org) - Cyberspace search engine (strong outside US)
- **AbuseIPDB** (https://www.abuseipdb.com) - Crowdsourced IP abuse database
- **SecurityTrails** (https://securitytrails.com) - DNS history, passive DNS, subdomain data
- **WhoisXML API** (https://whoisxmlapi.com) - WHOIS data + DNS intelligence
- **DNSDumpster** (https://dnsdumpster.com) - Free DNS recon and research
- **URLScan.io** (https://urlscan.io) - URL/website scanning with screenshots
- **crt.sh** (https://crt.sh) - Certificate transparency log search

~~~bash
# Certificate transparency - find related domains via shared certs
curl -s "https://crt.sh/?q=%25.target.com&output=json" | jq '.[].name_value' | sort -u
~~~

### Social Media OSINT

#### **Tools**
- **Sherlock** - Username search across platforms
- **Social-Analyzer** - Profile analysis across social networks
- **TweetDeck** / **TweetBeaver** - Twitter OSINT
- **Instagram OSINT** tools (various)
- **LinkedIn Intelligence** - Sales Navigator, profile scraping

#### **Techniques**
- Username correlation across platforms
- Profile picture reverse image search
- Connection mapping and network analysis
- Metadata extraction from posts
- Geolocation from photos and posts

### Geolocation & Imagery

#### **Tools**
- **Google Earth Pro** - Historical imagery, elevation data
- **Google Street View** - Ground-level imagery
- **Yandex Maps** - Alternative mapping (strong in Russia/Eastern Europe)
- **Baidu Maps** - China-focused mapping
- **Bing Maps** - Microsoft's mapping service
- **EXIF data extractors** - Photo metadata analysis

#### **Techniques**
- Reverse image search (Google, Yandex, TinEye)
- Shadow analysis for time/location verification
- Landmark identification
- EXIF GPS coordinate extraction
- Cross-referencing multiple map sources

### Dark Web & Deep Web OSINT

#### **Access Tools**
- **Tor Browser** - Access .onion sites
- **I2P** - Alternative anonymous network
- **Tails OS** - Privacy-focused live operating system

#### **Search & Discovery**
- **Ahmia.fi** - .onion search engine
- **DarkSearch.io** - Dark web search
- **OnionLand Search** - Deep web search engine
- **Hunchly** - Evidence capture for web browsing

### Company & Business Intelligence

#### **Sources**
- **Company registries** (state/national business databases)
- **SEC EDGAR** - US public company filings
- **LinkedIn** - Employee enumeration
- **Glassdoor** / **Indeed** - Company reviews, salaries
- **Crunchbase** - Startup and investment data
- **ZoomInfo** / **RocketReach** - Contact information databases

### Public Records & Government Data

#### **US Sources**
- **PACER** - Federal court records
- **State court systems** - Civil and criminal records
- **Property records** - County assessor databases
- **Corporate registrations** - Secretary of State databases
- **Professional licenses** - State licensing boards

### Breach Data & Leaked Information

#### **Tools & Databases**
- **Have I Been Pwned** - Email breach notification
- **DeHashed** - Breach search engine (paid)
- **LeakPeek** / **Snusbase** - Breach databases
- **IntelX** - Data breach search
- **Leak-Lookup** - Breach search engine
- **Pastebin monitoring** - Automated paste site scanning

### Cryptocurrency Intelligence

#### **Scam Databases**
- **BitcoinAbuse** (https://www.bitcoinabuse.com) - Reports of scam Bitcoin addresses
- **ChainAbuse** (https://www.chainabuse.com) - Multi-chain abuse reporting
- **CryptoScamDB** (https://cryptoscamdb.org) - Known crypto scams and malicious addresses

#### **Blockchain Explorers**
- **blockchain.info** - Bitcoin blockchain explorer
- **Etherscan** (https://etherscan.io) - Ethereum blockchain explorer
- **BlockCypher** - Multi-chain explorer
- **OXT** / **Breadcrumbs** - Bitcoin cluster analysis tools

---

## OSINT VM Setup

### Recommended OSINT Distributions

#### **Buscador VM**
- **Creator**: Michael Bazzell (IntelTechniques)
- **Based on**: Ubuntu
- **Tools**: 100+ pre-installed OSINT tools
- **Use Case**: General OSINT investigations
- **Download**: https://inteltechniques.com/buscador/

#### **Trace Labs OSINT VM**
- **Purpose**: Search and rescue operations
- **Tools**: Curated set for finding missing persons
- **Community**: Active Trace Labs community
- **Download**: https://www.tracelabs.org/initiatives/osint-vm

#### **CSI Linux**
- **Focus**: Digital forensics and OSINT
- **Features**: Enterprise-grade tools, regular updates
- **Website**: https://csilinux.com

#### **Tsurugi Linux**
- **Focus**: DFIR (Digital Forensics and Incident Response)
- **OSINT Tools**: Comprehensive suite included
- **Website**: https://tsurugi-linux.org

### DIY OSINT VM Build

#### **Base System**
~~~bash
# Start with Ubuntu/Debian base
sudo apt update && sudo apt upgrade -y

# Install dependencies
sudo apt install -y python3 python3-pip git curl wget \
    build-essential libssl-dev libffi-dev python3-dev
~~~

#### **Install Core OSINT Tools**
~~~bash
# theHarvester
git clone https://github.com/laramies/theHarvester
cd theHarvester
pip3 install -r requirements.txt

# Sherlock
git clone https://github.com/sherlock-project/sherlock
cd sherlock
pip3 install -r requirements.txt

# Recon-ng
pip3 install recon-ng

# SpiderFoot
git clone https://github.com/smicallef/spiderfoot
cd spiderfoot
pip3 install -r requirements.txt

# Amass
go install -v github.com/owasp-amass/amass/v4/...@latest

# Photon
git clone https://github.com/s0md3v/Photon
cd Photon
pip3 install -r requirements.txt

# Maigret
pip3 install maigret

# H8mail
pip3 install h8mail

# Holehe
pip3 install holehe

# PhoneInfoga
# Download latest release from GitHub
~~~

#### **Evidence & Archival Tools**
~~~bash
# Monolith - self-contained HTML archives
cargo install monolith

# CutyCapt - CLI screenshots
sudo apt install -y cutycapt

# WaybackPy - Wayback Machine submission
pip3 install waybackpy
~~~

#### **Additional Utilities**
~~~bash
# Network tools
sudo apt install -y nmap masscan whois dnsutils netcat

# Web tools
sudo apt install -y curl wget httpie jq

# Image/media tools
sudo apt install -y exiftool ffmpeg

# Document tools
sudo apt install -y metagoofil
~~~

### Automation Script
~~~bash
#!/bin/bash
# OSINT VM Quick Setup Script

# Update system
sudo apt update && sudo apt upgrade -y

# Install base dependencies
sudo apt install -y python3 python3-pip git curl wget \
    build-essential libssl-dev libffi-dev python3-dev \
    golang-go nmap masscan whois dnsutils exiftool cutycapt

# Create tools directory
mkdir -p ~/osint-tools
cd ~/osint-tools

# Install Python OSINT tools
pip3 install recon-ng maigret h8mail holehe waybackpy

# Clone and setup Git-based tools
git clone https://github.com/laramies/theHarvester && \
    cd theHarvester && pip3 install -r requirements.txt && cd ..

git clone https://github.com/sherlock-project/sherlock && \
    cd sherlock && pip3 install -r requirements.txt && cd ..

git clone https://github.com/smicallef/spiderfoot && \
    cd spiderfoot && pip3 install -r requirements.txt && cd ..

git clone https://github.com/s0md3v/Photon && \
    cd Photon && pip3 install -r requirements.txt && cd ..

# Install Go tools
go install -v github.com/owasp-amass/amass/v4/...@latest
go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install -v github.com/projectdiscovery/httpx/v2/cmd/httpx@latest
go install -v github.com/tomnomnom/waybackurls@latest

echo "OSINT VM setup complete!"
echo "Tools installed in ~/osint-tools/"
~~~

---

## Investigation Procedures by Identifier Type

### Email Investigation Procedure

#### Step 1: Account Discovery
~~~bash
# Find services where this email is registered
holehe target@email.com --only-used
~~~

#### Step 2: Breach Database Search
~~~bash
# Local breach hunting
h8mail -t target@email.com -o breach_results.csv

# HIBP API (if key available)
curl -H "hibp-api-key: YOUR_KEY" \
  "https://haveibeenpwned.com/api/v3/breachedaccount/target@email.com"
~~~

#### Step 3: Email Verification
~~~bash
# Verify deliverability via Hunter.io
curl "https://api.hunter.io/v2/email-verifier?email=target@email.com&api_key=YOUR_KEY"
~~~

#### Step 4: Email Header Analysis

If you have the original email source:

1. Extract full headers from your email client
2. Analyze the `Received:` chain for routing path
3. Identify the originating IP (bottom-most `Received` header)
4. Check **SPF / DKIM / DMARC** alignment
5. Look for spoofing indicators (Return-Path mismatch, etc.)

**Tools**: https://mxtoolbox.com/EmailHeaders.aspx, https://www.google.com/search?q=email+header+analyzer

#### Step 5: Domain Extraction

Extract the email's domain and proceed to the Domain Investigation Procedure.

---

### IP Address Investigation Procedure

#### Step 1: ASN and Abuse Contact
~~~bash
# One-shot ASN, network range, and abuse contact
asn 1.2.3.4
~~~

#### Step 2: Geolocation
~~~bash
# Free, no API key
curl -s "http://ip-api.com/json/1.2.3.4" | jq

# Cleaner output, free tier
curl -s "https://ipinfo.io/1.2.3.4" | jq
~~~

#### Step 3: Reputation Check
~~~bash
# AbuseIPDB
curl -s "https://api.abuseipdb.com/api/v2/check?ipAddress=1.2.3.4&maxAgeInDays=90" \
  -H "Key: YOUR_KEY" -H "Accept: application/json" | jq

# Shodan host details
curl -s "https://api.shodan.io/shodan/host/1.2.3.4?key=YOUR_KEY" | jq
~~~

#### Step 4: Reverse DNS & Port Discovery
~~~bash
dig -x 1.2.3.4 +short
nmap -F -T4 --open 1.2.3.4
~~~

**Document for reporting**: ASN, abuse email, hosting provider, open services.

---

### Domain Investigation Procedure

#### Step 1: WHOIS & Registrar Identification
~~~bash
whois scam-domain.com
~~~

**Capture**: registrar abuse contact (critical for takedown requests).

#### Step 2: DNS Record Collection
~~~bash
dig +short scam-domain.com A
dig +short scam-domain.com MX
dig +short scam-domain.com TXT
dig +short scam-domain.com NS
~~~

#### Step 3: Subdomain Enumeration + Live Probe
~~~bash
subfinder -d scam-domain.com -silent -o subs.txt
cat subs.txt | httpx -td -server -title -asn
~~~

#### Step 4: Historical Analysis
~~~bash
# Historical URLs
echo scam-domain.com | waybackurls > historical_urls.txt

# Certificate transparency - find related domains
curl -s "https://crt.sh/?q=%25.scam-domain.com&output=json" | jq
~~~

#### Step 5: Tech Stack & Content Discovery
~~~bash
whatweb -a 3 https://scam-domain.com
~~~

---

### Cryptocurrency Investigation Procedure

#### Step 1: Address Type Identification

| Cryptocurrency | Address Format |
|----------------|----------------|
| **Bitcoin** | Starts with `1`, `3`, or `bc1` |
| **Ethereum** | Starts with `0x` followed by 40 hex chars |
| **Litecoin** | Starts with `L`, `M`, or `3` |
| **Monero** | Starts with `4` or `8`, 95 chars long |
| **Solana** | Base58-encoded, ~44 chars |

#### Step 2: Scam Database Lookups

Public databases for known fraudulent addresses:
- **BitcoinAbuse**: https://www.bitcoinabuse.com/reports/ADDRESS
- **ChainAbuse**: https://www.chainabuse.com/address/ADDRESS
- **CryptoScamDB**: https://cryptoscamdb.org/search

#### Step 3: Blockchain Explorer Analysis

**Bitcoin:**
~~~bash
curl -s "https://blockchain.info/rawaddr/ADDRESS?limit=50" | jq
~~~

**Ethereum (Etherscan API):**
~~~bash
curl -s "https://api.etherscan.io/api?module=account&action=txlist&address=ADDRESS&apikey=YOUR_KEY" | jq
~~~

**Examine:**
- Total received / sent
- Number of transactions
- First and last transaction timestamps
- Current balance
- Linked addresses (transaction graph)

#### Step 4: Transaction Tracing

For significant addresses:
1. Identify the **first funding source** (often reveals on/off-ramp)
2. Track outgoing transactions
3. Look for **exchange deposits** (cluster analysis tools like OXT, Breadcrumbs)
4. Note address clustering - wallets controlled by the same entity

#### Step 5: Documentation

Record:
- Full address (case-sensitive for some chains)
- Blockchain type and explorer URL
- Total value transacted (in crypto and approx. fiat)
- Scam database results (with screenshots)
- Transaction screenshots with timestamps

---

### Phone Number Investigation Procedure

#### Step 1: Number Validation & Carrier
~~~bash
phoneinfoga scan -n "+15551234567"
~~~

#### Step 2: Programmatic Carrier Lookup
~~~python
import phonenumbers
from phonenumbers import carrier, geocoder

pn = phonenumbers.parse("+15551234567")
print(carrier.name_for_number(pn, 'en'))
print(geocoder.description_for_number(pn, 'en'))
~~~

#### Step 3: VoIP Detection

VoIP numbers are frequently used by scammers. Check for:
- Google Voice
- TextNow
- Burner app numbers
- Twilio / other API-based numbers

VoIP detection is built into PhoneInfoga and most carrier lookup APIs.

#### Step 4: Social Media Cross-Reference

- Search the number on major social platforms (some allow phone search)
- Truecaller (manual web check)
- Reverse phone lookup services

---

### Username Investigation Procedure

#### Step 1: Wide Net - Maigret (2500+ sites)
~~~bash
maigret target_username --pdf --html -o ./username_results/
~~~

#### Step 2: Fast Verification - Sherlock (400+ sites)
~~~bash
sherlock target_username --csv
~~~

#### Step 3: Additional Coverage - Blackbird
~~~bash
blackbird -u target_username
~~~

#### Step 4: Manual Profile Verification

For each discovered profile:
1. **Bio/Description**: contact info, links, claims
2. **Profile Photo**: reverse image search (Google, Yandex, TinEye)
3. **Post History**: timeline, posting patterns, time zones
4. **Connections**: friends, followers, group memberships
5. **Activity**: frequency, language patterns, devices

---

## Investigation Workflows

### Workflow 1: Person Investigation

~~~
1. Start with Known Information
   └─> Name, email, username, location

2. Username Enumeration
   └─> Sherlock / Maigret / Blackbird across social platforms

3. Email Investigation
   └─> Holehe (account registration)
   └─> H8mail (breach data)
   └─> theHarvester (associated domains)

4. Social Media Deep Dive
   └─> Profile analysis
   └─> Connection mapping
   └─> Content timeline review

5. Phone Number (if available)
   └─> PhoneInfoga for carrier/validation
   └─> Social media association

6. Geolocation Analysis
   └─> Photo EXIF data
   └─> Check-ins and tagged locations
   └─> Google Maps / Street View verification

7. Compile Timeline
   └─> Chronological activity mapping
   └─> Pattern identification

8. Report Generation
   └─> Document findings
   └─> Visualize relationships (Maltego)
~~~

### Workflow 2: Domain/Company Investigation

~~~
1. Initial Reconnaissance
   └─> WHOIS lookup
   └─> DNS enumeration

2. Subdomain Discovery
   └─> Amass (comprehensive)
   └─> Subfinder (fast scan)
   └─> Certificate transparency logs (crt.sh)

3. Live Host Probing
   └─> httpx (tech stack + ASN)
   └─> WhatWeb (technology fingerprint)

4. Email Harvesting
   └─> theHarvester (emails from domain)
   └─> LinkedIn (employee enumeration)

5. Web Application Analysis
   └─> Photon (crawling & endpoint discovery)
   └─> waybackurls (historical data)
   └─> Wayback Machine (page history)

6. Employee Enumeration
   └─> LinkedIn scraping
   └─> Email pattern identification
   └─> Social media presence

7. Infrastructure Mapping
   └─> Shodan / Censys (exposed assets)
   └─> IP ranges and netblocks
   └─> Cloud service identification

8. Breach Data Review
   └─> Have I Been Pwned
   └─> DeHashed / breach databases
   └─> Pastebin monitoring

9. Report & Visualization
   └─> Attack surface map
   └─> Risk assessment
   └─> Maltego relationship diagram
~~~

### Workflow 3: Threat Intelligence Gathering

~~~
1. IOC (Indicator of Compromise) Collection
   └─> IP addresses, domains, hashes

2. Passive DNS Analysis
   └─> Historical resolution data
   └─> Related infrastructure

3. Malware Analysis Research
   └─> Sandbox reports (ANY.RUN, Hybrid Analysis)
   └─> VirusTotal intelligence

4. Threat Actor Attribution
   └─> Dark web forums
   └─> Paste sites
   └─> Social media monitoring

5. Vulnerability Intelligence
   └─> CVE databases
   └─> Exploit-DB
   └─> GitHub repository searches

6. Infrastructure Correlation
   └─> Shared hosting analysis
   └─> SSL certificate tracking (crt.sh)
   └─> WHOIS privacy service patterns

7. Reporting & Sharing
   └─> IOC feeds
   └─> Threat reports
   └─> MISP/STIX format sharing
~~~

### Workflow 4: Scam / Fraud Investigation

~~~
1. Triage & Authorization
   └─> Document the complaint
   └─> Verify legal authority to investigate
   └─> Assign case ID (YYYY-NNN-TYPE)

2. Initial Identifier Collection
   └─> Email addresses, phone numbers, domains, URLs
   └─> Crypto wallet addresses
   └─> Social media handles
   └─> Bank account / payment processor info (if applicable)

3. Per-Identifier Investigation (parallel)
   ├─> Emails → holehe, h8mail, HIBP
   ├─> Phones → phoneinfoga, carrier lookup
   ├─> Domains → whois, dig, subfinder + httpx, waybackurls
   ├─> IPs → asn, geolocation, AbuseIPDB
   ├─> Usernames → maigret, sherlock, blackbird
   └─> Crypto → scam databases, blockchain explorers

4. Infrastructure Correlation
   └─> Shared hosting, SSL certs (crt.sh)
   └─> Common WHOIS data
   └─> Reused images / templates
   └─> Cross-referenced indicators

5. Evidence Preservation
   └─> Archive all pages (monolith)
   └─> Screenshot all profiles (cutycapt)
   └─> Hash everything (SHA256)
   └─> Wayback Machine submissions

6. Report Generation
   └─> Executive summary
   └─> Per-identifier findings
   └─> Evidence inventory with hashes
   └─> Abuse contacts compiled

7. Abuse Reporting
   └─> Registrar takedown request
   └─> Hosting provider notification
   └─> Email/social platform reports
   └─> IC3 submission (if applicable)

8. Follow-Up & Closure
   └─> Track response from each report
   └─> Re-verify takedowns
   └─> Update case file
   └─> Archive case
~~~

---

## Evidence Preservation & Chain of Custody

### Golden Rules

1. **Hash everything** - SHA256 immediately upon collection
2. **Timestamp everything** - UTC timestamps for all evidence
3. **Document chain of custody** - log who collected what and when
4. **Multiple copies** - original + working copy in separate locations
5. **Integrity verification** - periodic hash re-checks

### Web Page Archival Procedure

~~~bash
# 1. Self-contained HTML archive (preserves layout, images, CSS)
monolith https://target-site.com -o evidence_$(date +%Y%m%d_%H%M%S).html

# 2. Full-page screenshot
cutycapt --url=https://target-site.com --out=screenshot_$(date +%Y%m%d_%H%M%S).png

# 3. Push to Wayback Machine (third-party witness)
waybackpy --url "https://target-site.com" --save

# 4. Generate hash manifest
sha256sum evidence_*.html screenshot_*.png > evidence_hashes_$(date +%Y%m%d).txt
~~~

### Suggested Case Structure

A consistent directory structure for each investigation:

~~~
~/OSINT_Cases/
└── CASE-ID/
    ├── case_info.md              # Metadata, objectives, authorization
    ├── case_notes.md             # Investigation notes, timeline
    ├── evidence_log.md           # Chain of custody table
    ├── evidence/
    │   ├── screenshots/
    │   ├── archives/             # monolith HTML, wget mirrors
    │   ├── files/                # downloaded artifacts
    │   └── hashes/               # SHA256 manifests
    ├── reports/
    │   ├── interim/
    │   ├── final/
    │   └── abuse_reports/
    └── raw_data/
        ├── email/
        ├── domain/
        ├── ip/
        ├── phone/
        ├── username/
        └── crypto/
~~~

### Suggested Case ID Format

~~~
YYYY-NNN-TYPE

Examples:
- 2025-001-PHISHING
- 2025-002-INVESTMENT_FRAUD
- 2025-003-TECH_SUPPORT_SCAM
- 2025-004-ROMANCE_SCAM
~~~

### Evidence Log Entry Format

| Timestamp (UTC)         | Type       | Description           | SHA256        | Source/Tool |
|-------------------------|------------|-----------------------|---------------|-------------|
| 2025-01-15 10:30:00 UTC | Archive    | Scam homepage capture | abc123def...  | monolith    |
| 2025-01-15 10:31:42 UTC | Screenshot | Login page            | 9f8e7d6...    | cutycapt    |

---

## Abuse Reporting Workflow

When an investigation identifies hostile infrastructure, the goal shifts from intelligence collection to **disruption**. This section covers the reporting workflow for getting malicious infrastructure taken down.

### Step 1: Identify Responsible Parties

From your investigation, compile contacts for:
- **Domain registrar** abuse email (from WHOIS)
- **Hosting provider** abuse email (from ASN lookup)
- **Email provider** abuse address (Gmail, Outlook, Proton, etc.)
- **Upstream ISP** (if identifiable separately from hosting)
- **Social media platform** abuse/trust & safety contacts
- **Payment processor** (if money is involved - Stripe, PayPal, crypto exchange)

### Step 2: Prepare the Report

Each report should include:

~~~
✅ Nature of abuse (phishing, scam, malware, CSAM, etc.)
✅ Specific URLs, IPs, and domains
✅ Timeline of observed activity (with UTC timestamps)
✅ Evidence references (don't attach - reference your hash manifest)
✅ Your contact information for follow-up
✅ Statement that you are reporting in good faith
~~~

### Step 3: Submission Channels

| Recipient Type | Channel |
|----------------|---------|
| Domain Registrar | Registrar's abuse portal or `abuse@registrar.tld` |
| Hosting Provider | `abuse@host.tld` (from ASN/WHOIS) |
| Email Provider | Provider's abuse form (Gmail: https://support.google.com/mail/contact/abuse) |
| Social Media | Platform-specific reporting flow |
| Cloudflare-fronted | https://www.cloudflare.com/abuse/form |

### Step 4: Document Submissions

In your case file, record:
- Date/time submitted (UTC)
- Recipient
- Method (email, web form, API)
- Reference/ticket number returned
- Files referenced or attached
- Follow-up reminder (typically 48-72 hours)

### Step 5: Follow Up

- **48–72 hours**: initial response window
- **No response**: send a polite follow-up
- **Still no action**: escalate to upstream provider or registry operator
- **CDN-fronted scams**: report to the CDN (Cloudflare/Akamai) with origin IP if known

### IC3 Submission (FBI Internet Crime Complaint Center)

For US-based victims or US-impacting crimes, submit to https://www.ic3.gov/.

**Required information:**

~~~
✅ Victim information (with consent)
✅ Suspect information - all known identifiers
✅ Financial loss amount (if applicable)
✅ Payment methods used (wire, crypto, gift cards, etc.)
✅ Communication records (preserved with hashes)
✅ Investigation report (PDF format)
✅ Evidence hash manifest
✅ Timeline of events (UTC)
~~~

### International Equivalents

| Country | Reporting Body |
|---------|---------------|
| 🇺🇸 USA | IC3 (ic3.gov), FTC (reportfraud.ftc.gov) |
| 🇬🇧 UK | Action Fraud (actionfraud.police.uk) |
| 🇨🇦 Canada | CAFC (antifraudcentre.ca) |
| 🇦🇺 Australia | Scamwatch (scamwatch.gov.au) |
| 🇪🇺 EU | Europol (europol.europa.eu), national CERT |

---

## OSINT Best Practices & OPSEC

### Operational Security (OPSEC)

#### **Network Isolation**
~~~
✅ ALWAYS use a VPN or Tor for OSINT activities
✅ Consider using a separate network/ISP for sensitive investigations
✅ Use VM snapshots to maintain clean states
✅ Rotate IP addresses frequently
~~~

#### **Browser Security**
~~~
✅ Use dedicated browsers for OSINT (separate from personal use)
✅ Disable JavaScript when possible
✅ Clear cookies and cache regularly
✅ Use privacy-focused browsers (Brave, Firefox with hardening)
✅ Employ browser isolation techniques
~~~

#### **Account Management**
~~~
✅ Use burner accounts for social media reconnaissance
✅ Never use personal accounts for investigations
✅ Create detailed sock puppet personas
✅ Use separate email addresses for each persona
✅ Use virtual phone numbers (Google Voice, Burner apps)
~~~

#### **Identity Protection**
~~~
✅ Use VPN + Tor for maximum anonymity
✅ Avoid logging into personal accounts during investigations
✅ Don't cross-contaminate personas
✅ Use privacy-focused email services (ProtonMail, Tutanota)
✅ Employ unique payment methods (prepaid cards, crypto)
~~~

### Data Management

#### **Organization**
~~~
✅ Use consistent folder/file naming conventions
✅ Timestamp all collected data
✅ Maintain chain of custody for evidence
✅ Document sources for all information
✅ Use tools like Hunchly or Maltego for case management
~~~

#### **Documentation**
~~~
✅ Screenshot everything (with timestamps)
✅ Archive web pages (archive.is, Wayback Machine)
✅ Record video for dynamic content
✅ Log all commands and queries used
✅ Maintain detailed investigation notes
~~~

#### **Evidence Preservation**
~~~
✅ Use write-blockers for forensic data
✅ Calculate and verify file hashes
✅ Store multiple copies in different locations
✅ Encrypt sensitive investigation data
✅ Follow proper chain of custody procedures
~~~

### Verification & Validation

~~~
✅ Cross-reference information from multiple sources
✅ Verify with primary sources when possible
✅ Be aware of misinformation and fake profiles
✅ Check dates and timestamps for relevance
✅ Consider cultural and linguistic context
✅ Document confidence levels for findings
~~~

---

## Legal & Ethical Considerations

### Legal Framework

#### **Computer Fraud and Abuse Act (CFAA) - US**
- Prohibits unauthorized access to computer systems
- OSINT should only collect *publicly available* information
- Do not circumvent access controls or authentication

#### **General Data Protection Regulation (GDPR) - EU**
- Regulates collection and processing of personal data
- Applies to EU residents' data regardless of investigator location
- Be aware of "right to be forgotten" implications

#### **Terms of Service (ToS)**
- Respect website terms of service
- Many sites prohibit scraping or automated collection
- Violating ToS can lead to legal action

### Ethical Guidelines

#### **Core Principles**
1. **Respect Privacy**: Don't collect information beyond investigation scope
2. **Do No Harm**: Consider potential consequences of your investigation
3. **Be Transparent**: Understand who you're working for and why
4. **Legal Compliance**: Follow all applicable laws and regulations
5. **Professional Standards**: Maintain objectivity and accuracy

#### **Red Lines - Never Cross**
~~~
🚫 Hacking or unauthorized access to systems
🚫 Social engineering or pretexting
🚫 Doxxing or harassment
🚫 Accessing private/protected information
🚫 Circumventing security measures
🚫 Impersonation for malicious purposes
🚫 Sharing intelligence for illegal purposes
~~~

### Use Cases & Justification

#### **Legitimate Use Cases**
✅ Cybersecurity threat intelligence
✅ Law enforcement investigations (with proper authority)
✅ Corporate due diligence
✅ Investigative journalism
✅ Academic research
✅ Missing persons cases (authorized)
✅ Fraud prevention
✅ Background checks (with consent)

#### **Prohibited Use Cases**
🚫 Stalking or harassment
🚫 Identity theft
🚫 Corporate espionage (illegal methods)
🚫 Blackmail or extortion
🚫 Unauthorized private investigation
🚫 Doxxing for retaliation
🚫 Invasion of privacy without justification

---

## Resources & Learning

### Training & Certifications

#### **Michael Bazzell - IntelTechniques**
- Website: https://inteltechniques.com
- Books: "Open Source Intelligence Techniques" series
- Training: Online courses and workshops
- Podcast: "The Privacy, Security, & OSINT Show"

#### **Trace Labs**
- Website: https://www.tracelabs.org
- Focus: OSINT for missing persons
- Competitions: CTF-style OSINT challenges
- Community: Active Discord and forums

#### **SANS Institute**
- **SEC487**: Open Source Intelligence Gathering and Analysis
- Focus: Professional OSINT techniques
- Certification: GOSI (GIAC Open Source Intelligence)

#### **Other Training Platforms**
- **Udemy**: Various OSINT courses
- **Cybrary**: Free cybersecurity training including OSINT
- **TCM Security**: Practical OSINT courses
- **TryHackMe**: OSINT learning paths and challenges

### Books & Publications

1. **"Open Source Intelligence Techniques" by Michael Bazzell**
   - The definitive OSINT handbook
   - Updated regularly with new techniques

2. **"OSINT Handbook" by i-intelligence**
   - Free resource from Dutch intelligence agency
   - Practical methodologies and tools

3. **"Social Engineering: The Science of Human Hacking" by Christopher Hadnagy**
   - Relevant for understanding social OSINT

4. **"The Art of Invisibility" by Kevin Mitnick**
   - Privacy and anonymity techniques

### Communities & Forums

- **Reddit**: r/OSINT, r/SocialEngineering
- **Discord**: Trace Labs, OSINT Curious, various security servers
- **Twitter**: #OSINT hashtag, follow practitioners
- **Sector035.nl**: OSINT articles and weekly newsletter
- **OSINT Framework**: https://osintframework.com

### Practice & CTF Challenges

#### **OSINT Challenges**
- **TraceLabs CTF**: Missing persons OSINT competitions
- **Sector035**: Regular OSINT exercises and quizzes
- **Bellingcat's Online Investigation Toolkit**: Case studies
- **Geolocating Images**: Various challenge sites
- **OSINTQuiz**: Twitter-based challenges

#### **Hands-On Practice Sites**
- **OSINT Challenge**: https://www.osintchallenge.com
- **CTFtime.org**: OSINT categories in CTF competitions
- **HackTheBox**: Some machines include OSINT elements
- **TryHackMe**: Dedicated OSINT rooms

### Blogs & News Sources

- **Bellingcat**: https://www.bellingcat.com
- **IntelTechniques by Michael Bazzell**: https://inteltechniques.com/blog
- **Sector035**: https://sector035.nl
- **OSINT Curious**: https://osintcurio.us
- **Aware Online**: https://www.aware-online.com

### Essential Bookmarks

#### **OSINT Frameworks & Collections**
- **OSINT Framework**: https://osintframework.com
- **Awesome OSINT**: https://github.com/jivoi/awesome-osint
- **OSINT Handbook**: https://www.i-intelligence.eu/wp-content/uploads/2016/11/2016_November_Open-Source-Intelligence-Tools-and-Resources-Handbook.pdf

#### **Verification Tools**
- **InVID Verification Plugin**: Video verification
- **FotoForensics**: Image forensics and analysis
- **Jeffrey's Exif Viewer**: EXIF data extraction
- **TinEye**: Reverse image search

#### **Archive Services**
- **Internet Archive / Wayback Machine**: https://archive.org
- **Archive.today**: https://archive.is
- **Perma.cc**: https://perma.cc

---

## Quick Reference: OSINT Tool Cheat Sheet

### Email Investigation
~~~bash
# theHarvester - Email harvesting
theHarvester -d target.com -b all

# Holehe - Email registration check
holehe target@example.com --only-used

# H8mail - Breach hunting
h8mail -t target@example.com
~~~

### Username Investigation
~~~bash
# Sherlock - Username search
sherlock username

# Maigret - Advanced username OSINT
maigret username

# Blackbird - Additional coverage
blackbird -u username
~~~

### Domain Reconnaissance
~~~bash
# Amass - Comprehensive subdomain enum
amass enum -d target.com

# Subfinder - Fast subdomain discovery  
subfinder -d target.com

# Subfinder → httpx pipeline
subfinder -d target.com -silent | httpx -td -server -title -asn

# theHarvester - Domain emails & subdomains
theHarvester -d target.com -b google

# crt.sh - Certificate transparency
curl -s "https://crt.sh/?q=%25.target.com&output=json" | jq '.[].name_value' | sort -u
~~~

### IP Investigation
~~~bash
# ASN + abuse contact
asn 1.2.3.4

# Geolocation
curl -s "https://ipinfo.io/1.2.3.4" | jq

# Reverse DNS
dig -x 1.2.3.4 +short
~~~

### Web Crawling & Historical Analysis
~~~bash
# Photon - Fast web crawler
python photon.py -u https://target.com

# waybackurls - Historical URL discovery
echo target.com | waybackurls

# Wget - Website mirroring
wget -r -l 2 -P output/ https://target.com
~~~

### Evidence Preservation
~~~bash
# Self-contained HTML archive
monolith https://target.com -o evidence_$(date +%Y%m%d_%H%M%S).html

# Screenshot
cutycapt --url=https://target.com --out=screenshot.png

# Submit to Wayback Machine
waybackpy --url "https://target.com" --save

# Hash manifest
sha256sum evidence_*.html screenshot_*.png > evidence_hashes.txt
~~~

### Automation
~~~bash
# Recon-ng - Framework
recon-ng
workspaces create target
marketplace install all
modules search

# SpiderFoot - Auto OSINT
spiderfoot -s target.com
~~~

---

## Credits & Acknowledgments

This OSINT guide incorporates knowledge, tools, and methodologies from the following individuals and organizations:

### Key Contributors

#### **Michael Bazzell**
- IntelTechniques OSINT resources
- Buscador VM
- Open Source Intelligence Techniques book series

#### **Trace Labs**
- OSINT VM for search & rescue
- Community-driven OSINT competitions

#### **Tool Developers**
- **Christian Martorella** - theHarvester
- **Sherlock Project Team** - Sherlock
- **Steve Micallef** - SpiderFoot
- **Tim Tomes** - Recon-ng
- **OWASP Team** - Amass
- **s0md3v** - Photon
- **ProjectDiscovery Team** - Subfinder, Nuclei, httpx
- **Soxoj** - Maigret
- **p1ngul1n0** - Blackbird
- **khast3x** - H8mail
- **megadose** - Holehe
- **sundowndev** - PhoneInfoga
- **tomnomnom** - waybackurls
- **nitefood** - asn CLI tool
- **Y2Z** - Monolith
- **akamhy** - WaybackPy

#### **Organizations**
- **Bellingcat** - Open source investigative journalism
- **OWASP** - Open Web Application Security Project
- **Paterva** - Maltego development
- **Sector035** - OSINT education and resources

### Additional Resources
- **OSINT Framework**: Comprehensive tool directory
- **Awesome OSINT**: Curated list on GitHub
- **OSINT Curious**: Community project and podcast

---

## Legal Disclaimer

~~~
⚠️ IMPORTANT: Legal and Ethical Use Only

This OSINT guide is provided for:
✅ Educational purposes
✅ Authorized security research
✅ Legal investigations with proper authority
✅ Ethical intelligence gathering

PROHIBITED USES:
🚫 Stalking, harassment, or doxxing
🚫 Unauthorized access to systems or data
🚫 Violations of privacy laws or regulations
🚫 Any illegal activities

ALWAYS:
- Obtain proper authorization before conducting investigations
- Respect privacy and data protection laws
- Follow website terms of service
- Act ethically and responsibly
- Consider the impact of your investigations

The authors and contributors of this guide assume no liability
for misuse of the information or tools described herein.

When in doubt, consult with legal counsel.
~~~

---

## Contributing to This Guide

This OSINT guide is part of the **ULTIMATE CYBERSECURITY MASTER GUIDE** maintained by Pacific Northwest Computers (PNWC). 

To contribute:
1. Submit issues or pull requests on GitHub
2. Share new tools, techniques, or resources
3. Provide feedback on existing content
4. Help maintain tool links and accuracy

**Repository**: https://github.com/Pnwcomputers/ULTIMATE-CYBERSECURITY-MASTER-GUIDE

---

**Last Updated**: June 2026  
**Maintained by**: Pacific Northwest Computers (PNWC)

*Use this knowledge responsibly and ethically.*
