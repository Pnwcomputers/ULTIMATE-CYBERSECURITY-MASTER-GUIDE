# OSINT (Open Source Intelligence) Basic/General Guide

### [Click Here For The Advanced OSINT Guide](Tradecraft/osint-threat-intel.md) 

## Table of Contents
1. [Introduction to OSINT](#introduction-to-osint)
2. [OSINT Methodology & Framework](#osint-methodology--framework)
3. [Core OSINT Tools](#core-osint-tools)
4. [OSINT by Category](#osint-by-category)
5. [OSINT VM Setup](#osint-vm-setup)
6. [Investigation Workflows](#investigation-workflows)
7. [OSINT Best Practices & OPSEC](#osint-best-practices--opsec)
8. [Legal & Ethical Considerations](#legal--ethical-considerations)
9. [Resources & Learning](#resources--learning)

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

```
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
```

### OSINT Framework Structure

The OSINT Framework categorizes investigations by:
- **Username** - Social media presence, online accounts
- **Email Address** - Account enumeration, breach data
- **Domain Name** - DNS records, WHOIS, website info
- **IP Address** - Geolocation, network information
- **Phone Number** - Carrier lookup, social media links
- **Person** - Public records, social profiles
- **Company** - Corporate records, employees, infrastructure

---

## Core OSINT Tools

### Email & Username Investigation

#### **theHarvester**
```bash
# Email, subdomain, and name harvesting
theHarvester -d target.com -l 500 -b all

# Specific source (Google, Bing, LinkedIn, etc.)
theHarvester -d target.com -b google
```
- **Use Case**: Email addresses, subdomains, names, IPs
- **Sources**: Google, Bing, PGP servers, LinkedIn, Twitter
- **GitHub**: https://github.com/laramies/theHarvester

#### **Sherlock**
```bash
# Search for username across social media platforms
sherlock username

# Export results to file
sherlock username -o results.txt

# Search specific sites
sherlock username --site Twitter
```
- **Use Case**: Username search across 400+ social networks
- **Speed**: Fast batch searching
- **GitHub**: https://github.com/sherlock-project/sherlock

#### **Maigret**
```bash
# Advanced username OSINT (better than Sherlock for some cases)
maigret username

# With permutations
maigret username --use-disabled-sites
```
- **Use Case**: Username enumeration with additional data extraction
- **GitHub**: https://github.com/soxoj/maigret

#### **H8mail**
```bash
# Email OSINT & breach hunting
h8mail -t target@email.com

# With API keys for breach databases
h8mail -t target@email.com -k <API_KEY>
```
- **Use Case**: Email breach correlation, password leaks
- **GitHub**: https://github.com/khast3x/h8mail

#### **Holehe**
```bash
# Check if email is used on different sites
holehe target@email.com
```
- **Use Case**: Determine which services an email is registered on
- **GitHub**: https://github.com/megadose/holehe

### Phone Number Intelligence

#### **PhoneInfoga**
```bash
# Phone number OSINT
phoneinfoga scan -n +1234567890
```
- **Use Case**: Carrier lookup, number validation, social media connections
- **Features**: International format support, reputation checks
- **GitHub**: https://github.com/sundowndev/phoneinfoga

### Domain & Network Reconnaissance

#### **Recon-ng**
```bash
# Full-featured web reconnaissance framework
recon-ng
[recon-ng][default] > workspaces create target_company
[recon-ng][target_company] > marketplace install all
[recon-ng][target_company] > modules search
```
- **Use Case**: Comprehensive reconnaissance automation
- **Modules**: DNS, WHOIS, breaches, social media, more
- **GitHub**: https://github.com/lanmaster53/recon-ng

#### **Amass**
```bash
# Network mapping and asset discovery (OWASP)
amass enum -d target.com

# Passive mode (no active scanning)
amass enum -passive -d target.com

# With DNS bruteforcing
amass enum -brute -d target.com
```
- **Use Case**: Subdomain enumeration, DNS mapping, network discovery
- **Features**: Integration with 50+ data sources
- **GitHub**: https://github.com/owasp-amass/amass

#### **Subfinder**
```bash
# Fast subdomain discovery
subfinder -d target.com

# With specific sources
subfinder -d target.com -sources virustotal,shodan
```
- **Use Case**: Subdomain enumeration for attack surface mapping
- **GitHub**: https://github.com/projectdiscovery/subfinder

### Web Crawling & Analysis

#### **Photon**
```bash
# Incredibly fast web crawler for OSINT
python photon.py -u https://target.com -o output -l 3 -t 100

# Extract specific data types
python photon.py -u https://target.com --dns --keys --emails
```
- **Use Case**: URL extraction, JavaScript files, endpoint discovery
- **Speed**: Multi-threaded, extremely fast
- **GitHub**: https://github.com/s0md3v/Photon

#### **SpiderFoot**
```bash
# Automated OSINT collection
spiderfoot -s target.com
```
- **Use Case**: Comprehensive automated OSINT (100+ modules)
- **Integration**: DNS, emails, social media, dark web, more
- **Features**: GUI and CLI versions available
- **GitHub**: https://github.com/smicallef/spiderfoot

### Link Analysis & Data Mining

#### **Maltego**
- **Use Case**: Visual link analysis, relationship mapping
- **Features**: Transform hub with 100+ data integrations
- **Data Sources**: DNS, WHOIS, social media, public records
- **Editions**: Community (free), Classic, XL
- **Website**: https://www.maltego.com

### Additional Essential Tools

#### **Metagoofil**
```bash
# Metadata extraction from documents
metagoofil -d target.com -t pdf,doc,xls -l 100 -o output -f results.html
```
- **Use Case**: Extract metadata from public documents
- **Information**: Authors, software versions, internal paths

#### **WhatWeb**
```bash
# Website fingerprinting
whatweb target.com

# Aggressive mode
whatweb target.com -a 3
```
- **Use Case**: Identify web technologies, CMS, frameworks

---

## OSINT by Category

### Search Engines & Dorking

#### **Google Dorking**
```
site:target.com filetype:pdf
site:target.com inurl:admin
site:target.com intitle:"index of"
"@target.com" site:pastebin.com
site:*.target.com -www
```

#### **Specialized Search Engines**
- **Shodan** (https://shodan.io) - Search engine for Internet-connected devices
- **Censys** (https://censys.io) - Internet-wide scanning and analysis
- **GreyNoise** (https://greynoise.io) - Internet background noise intelligence
- **Hunter.io** (https://hunter.io) - Email finder and verification
- **Have I Been Pwned** (https://haveibeenpwned.com) - Breach notification service

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
- **Pastebin monitoring** - Automated paste site scanning

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
```bash
# Start with Ubuntu/Debian base
sudo apt update && sudo apt upgrade -y

# Install dependencies
sudo apt install -y python3 python3-pip git curl wget \
    build-essential libssl-dev libffi-dev python3-dev
```

#### **Install Core OSINT Tools**
```bash
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
go install -v github.com/owasp-amass/amass/v3/...@master

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
```

#### **Additional Utilities**
```bash
# Network tools
sudo apt install -y nmap masscan whois dnsutils netcat

# Web tools
sudo apt install -y curl wget httpie jq

# Image/media tools
sudo apt install -y exiftool ffmpeg

# Document tools
sudo apt install -y metagoofil
```

### Automation Script
```bash
#!/bin/bash
# OSINT VM Quick Setup Script

# Update system
sudo apt update && sudo apt upgrade -y

# Install base dependencies
sudo apt install -y python3 python3-pip git curl wget \
    build-essential libssl-dev libffi-dev python3-dev \
    golang-go nmap masscan whois dnsutils exiftool

# Create tools directory
mkdir -p ~/osint-tools
cd ~/osint-tools

# Install Python OSINT tools
pip3 install recon-ng maigret h8mail holehe

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
go install -v github.com/owasp-amass/amass/v3/...@master
go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest

echo "OSINT VM setup complete!"
echo "Tools installed in ~/osint-tools/"
```

---

## Investigation Workflows

### Workflow 1: Person Investigation

```
1. Start with Known Information
   └─> Name, email, username, location

2. Username Enumeration
   └─> Sherlock / Maigret across social platforms

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
```

### Workflow 2: Domain/Company Investigation

```
1. Initial Reconnaissance
   └─> WHOIS lookup
   └─> DNS enumeration

2. Subdomain Discovery
   └─> Amass (comprehensive)
   └─> Subfinder (fast scan)
   └─> Certificate transparency logs

3. Email Harvesting
   └─> theHarvester (emails from domain)
   └─> LinkedIn (employee enumeration)

4. Web Application Analysis
   └─> Photon (crawling & endpoint discovery)
   └─> WhatWeb (technology stack)
   └─> Wayback Machine (historical data)

5. Employee Enumeration
   └─> LinkedIn scraping
   └─> Email pattern identification
   └─> Social media presence

6. Infrastructure Mapping
   └─> Shodan / Censys (exposed assets)
   └─> IP ranges and netblocks
   └─> Cloud service identification

7. Breach Data Review
   └─> Have I Been Pwned
   └─> DeHashed / breach databases
   └─> Pastebin monitoring

8. Report & Visualization
   └─> Attack surface map
   └─> Risk assessment
   └─> Maltego relationship diagram
```

### Workflow 3: Threat Intelligence Gathering

```
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
   └─> SSL certificate tracking
   └─> WHOIS privacy service patterns

7. Reporting & Sharing
   └─> IOC feeds
   └─> Threat reports
   └─> MISP/STIX format sharing
```

---

## OSINT Best Practices & OPSEC

### Operational Security (OPSEC)

#### **Network Isolation**
```
✅ ALWAYS use a VPN or Tor for OSINT activities
✅ Consider using a separate network/ISP for sensitive investigations
✅ Use VM snapshots to maintain clean states
✅ Rotate IP addresses frequently
```

#### **Browser Security**
```
✅ Use dedicated browsers for OSINT (separate from personal use)
✅ Disable JavaScript when possible
✅ Clear cookies and cache regularly
✅ Use privacy-focused browsers (Brave, Firefox with hardening)
✅ Employ browser isolation techniques
```

#### **Account Management**
```
✅ Use burner accounts for social media reconnaissance
✅ Never use personal accounts for investigations
✅ Create detailed sock puppet personas
✅ Use separate email addresses for each persona
✅ Use virtual phone numbers (Google Voice, Burner apps)
```

#### **Identity Protection**
```
✅ Use VPN + Tor for maximum anonymity
✅ Avoid logging into personal accounts during investigations
✅ Don't cross-contaminate personas
✅ Use privacy-focused email services (ProtonMail, Tutanota)
✅ Employ unique payment methods (prepaid cards, crypto)
```

### Data Management

#### **Organization**
```
✅ Use consistent folder/file naming conventions
✅ Timestamp all collected data
✅ Maintain chain of custody for evidence
✅ Document sources for all information
✅ Use tools like Hunchly or Maltego for case management
```

#### **Documentation**
```
✅ Screenshot everything (with timestamps)
✅ Archive web pages (archive.is, Wayback Machine)
✅ Record video for dynamic content
✅ Log all commands and queries used
✅ Maintain detailed investigation notes
```

#### **Evidence Preservation**
```
✅ Use write-blockers for forensic data
✅ Calculate and verify file hashes
✅ Store multiple copies in different locations
✅ Encrypt sensitive investigation data
✅ Follow proper chain of custody procedures
```

### Verification & Validation

```
✅ Cross-reference information from multiple sources
✅ Verify with primary sources when possible
✅ Be aware of misinformation and fake profiles
✅ Check dates and timestamps for relevance
✅ Consider cultural and linguistic context
✅ Document confidence levels for findings
```

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
```
🚫 Hacking or unauthorized access to systems
🚫 Social engineering or pretexting
🚫 Doxxing or harassment
🚫 Accessing private/protected information
🚫 Circumventing security measures
🚫 Impersonation for malicious purposes
🚫 Sharing intelligence for illegal purposes
```

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
```bash
# theHarvester - Email harvesting
theHarvester -d target.com -b all

# Holehe - Email registration check
holehe target@example.com

# H8mail - Breach hunting
h8mail -t target@example.com
```

### Username Investigation
```bash
# Sherlock - Username search
sherlock username

# Maigret - Advanced username OSINT
maigret username
```

### Domain Reconnaissance
```bash
# Amass - Comprehensive subdomain enum
amass enum -d target.com

# Subfinder - Fast subdomain discovery  
subfinder -d target.com

# theHarvester - Domain emails & subdomains
theHarvester -d target.com -b google
```

### Web Crawling
```bash
# Photon - Fast web crawler
python photon.py -u https://target.com

# Wget - Website mirroring
wget -r -l 2 -P output/ https://target.com
```

### Automation
```bash
# Recon-ng - Framework
recon-ng
workspaces create target
marketplace install all
modules search

# SpiderFoot - Auto OSINT
spiderfoot -s target.com
```

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
- **khast3x** - H8mail
- **megadose** - Holehe
- **sundowndev** - PhoneInfoga

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

```
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
```

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

**Last Updated**: November 2024  
**Maintained by**: Pacific Northwest Computers (PNWC)

*Use this knowledge responsibly and ethically.*
