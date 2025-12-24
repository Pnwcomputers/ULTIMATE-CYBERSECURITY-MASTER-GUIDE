# OSINT Investigator Playbook

A comprehensive, menu-driven OSINT investigation toolkit designed for investigating scams, fraud, and cybercrime. Built for use on Tsurugi Linux and other OSINT-focused distributions.

## 🆕 New Features (v2.1)

- **🌐 Web Interface** - Browser-based UI using Flask (`python3 web_interface.py`)
- **📝 Abuse Report Generator** - Draft emails for registrars, hosts, ISPs, social media, IC3
- **🔗 Toolkit Integration** - Connect with existing scripts (scammer_audit.sh, email_audit.sh, phone_audit.sh)

## 🎯 Purpose

This toolkit is designed for:
- **Scam/Fraud Investigation** - Gather evidence on scammers targeting your clients
- **Abuse Reporting** - Generate reports for domain registrars, hosting providers, and ISPs
- **IC3 Submissions** - Create documented evidence packages for FBI Internet Crime Complaint Center
- **Client Reports** - Professional investigation reports with chain of custody documentation

## ✨ Features

### Investigation Modules

| Module | Description | Tools Used |
|--------|-------------|------------|
| 📧 **Email** | Account discovery, breach search, verification | Holehe, h8mail, HIBP API, Hunter.io |
| 📱 **Phone** | Carrier lookup, number validation, OSINT | PhoneInfoga, phonenumbers, Veriphone |
| 🌐 **Domain** | WHOIS, DNS, subdomains, tech stack, history | Subfinder, httpx, theHarvester, waybackurls |
| 🔢 **IP Address** | Geolocation, ASN, abuse contacts, reputation | ASN tool, Shodan, AbuseIPDB, Censys |
| 👤 **Username** | Social media enumeration across 2500+ sites | Maigret, Sherlock, Blackbird |
| 💰 **Crypto** | Wallet analysis, scam database checks | Blockchain APIs, BitcoinAbuse |

### Core Capabilities

- **Case Management** - Create, save, and resume investigations
- **Evidence Logging** - Automatic chain of custody documentation
- **Hash Verification** - SHA256 manifests for all evidence
- **URL Archiving** - Multiple methods (Monolith, wget, Wayback Machine)
- **Report Generation** - Markdown and PDF output
- **Abuse Report Templates** - Ready-to-send templates for providers
- **API Integration** - 15+ intelligence APIs supported

## 📋 Requirements

- **OS**: Tsurugi Linux, Ubuntu 22.04+, Debian 12+, Kali Linux
- **Python**: 3.8+
- **Go**: 1.19+ (for ProjectDiscovery tools)
- **RAM**: 4GB minimum, 8GB recommended
- **Storage**: 10GB+ for tools and evidence

## 🚀 Quick Start

### 1. Clone Repository

```bash
git clone https://github.com/Pnwcomputers/osint-playbook.git
cd osint-playbook
```

### 2. Install Dependencies

```bash
# Full installation (recommended)
sudo ./install_dependencies.sh --full

# Minimal installation (Python tools only)
sudo ./install_dependencies.sh --minimal
```

### 3. Configure API Keys

```bash
# Interactive configuration
./osint_investigator.sh --config

# Or manually edit
nano ~/.config/osint-investigator/api_keys.conf
```

### 4. Run the Playbook

```bash
./osint_investigator.sh
```

## 📁 Directory Structure

```
osint-playbook/
├── osint_investigator.sh      # Main playbook script
├── install_dependencies.sh     # Dependency installer
├── README.md                   # This file
├── LICENSE                     # License file
├── .gitignore                  # Git ignore rules
└── docs/
    ├── API_SETUP.md            # API configuration guide
    ├── INVESTIGATION_GUIDE.md  # Investigation procedures
    └── TOOLS_REFERENCE.md      # Tool documentation
```

### Case Directory Structure

When you create a case, the following structure is generated:

```
~/OSINT_Cases/
└── CASE-ID/
    ├── case_info.json          # Case metadata
    ├── case_notes.txt          # Investigation notes
    ├── evidence_log.md         # Chain of custody log
    ├── .case_state             # Saved investigation state
    ├── evidence/
    │   ├── screenshots/        # Page screenshots
    │   ├── archives/           # Web archives
    │   ├── files/              # Downloaded files
    │   └── hashes/             # Hash manifests
    ├── reports/
    │   ├── interim/            # Work-in-progress reports
    │   ├── final/              # Final investigation reports
    │   └── abuse_reports/      # Abuse report templates
    ├── logs/                   # Tool output logs
    └── raw_data/
        ├── email/              # Email investigation data
        ├── domain/             # Domain investigation data
        ├── ip/                 # IP investigation data
        ├── phone/              # Phone investigation data
        ├── username/           # Username investigation data
        ├── crypto/             # Cryptocurrency investigation data
        └── company/            # Company investigation data
```

## 🔑 API Configuration

The toolkit supports multiple APIs for enhanced intelligence gathering:

### Required APIs (Free Tier Available)

| API | Purpose | Get Key |
|-----|---------|---------|
| **Shodan** | IP/Port intelligence | [shodan.io](https://shodan.io) |
| **VirusTotal** | Malware/URL analysis | [virustotal.com](https://virustotal.com) |
| **HaveIBeenPwned** | Breach data | [haveibeenpwned.com/API](https://haveibeenpwned.com/API/Key) |

### Recommended APIs

| API | Purpose | Get Key |
|-----|---------|---------|
| **Hunter.io** | Email discovery/verification | [hunter.io](https://hunter.io) |
| **SecurityTrails** | Domain intelligence | [securitytrails.com](https://securitytrails.com) |
| **Censys** | Host/certificate search | [censys.io](https://censys.io) |
| **AbuseIPDB** | IP reputation | [abuseipdb.com](https://abuseipdb.com) |
| **Intelligence X** | Deep search | [intelx.io](https://intelx.io) |
| **ProjectDiscovery** | Cloud platform | [cloud.projectdiscovery.io](https://cloud.projectdiscovery.io) |

### Configuration File

API keys are stored in `~/.config/osint-investigator/api_keys.conf`:

```bash
# Example configuration
export SHODAN_API_KEY="your_key_here"
export VIRUSTOTAL_API_KEY="your_key_here"
export HAVEIBEENPWNED_API_KEY="your_key_here"
# ... additional keys
```

⚠️ **Security**: This file is chmod 600 by default. Never commit real API keys!

## 📖 Usage Guide

### Creating a New Case

1. Launch the toolkit: `./osint_investigator.sh`
2. Select `[1] Create New Case`
3. Enter a Case ID (e.g., `2024-001-PHISHING`)
4. The case directory structure is created automatically

### Running a Full Investigation

1. Create or load a case
2. Select `[4] Investigation Menu`
3. Select `[A] Run Full Investigation (All-in-One)`
4. Enter all available data:
   - Email addresses
   - Phone numbers
   - Domains
   - IP addresses
   - Usernames
   - Cryptocurrency addresses
   - URLs to archive
5. The toolkit runs all applicable modules automatically

### Individual Investigations

Run specific modules as needed:

```
Investigation Menu:
  [1] Email Investigation      - Holehe, h8mail, HIBP
  [2] Phone Investigation      - PhoneInfoga, carrier lookup
  [3] Domain Investigation     - WHOIS, DNS, subdomains, history
  [4] IP Investigation         - Geolocation, ASN, reputation
  [5] Username Investigation   - Maigret, Sherlock (2500+ sites)
  [6] Crypto Investigation     - Blockchain analysis
  [7] Archive URLs             - Monolith, Wayback Machine
```

### Generating Reports

1. Select `[5] Reports & Documentation`
2. Choose report type:
   - `[1] Final Investigation Report` - Comprehensive report with all findings
   - `[2] Abuse Report Template` - Ready-to-send abuse report
3. Reports are saved in `CASE_DIR/reports/`

## 🔧 Tool Reference

### Email Investigation

```bash
# Holehe - Check email registration on 120+ sites
holehe target@email.com --only-used

# h8mail - Breach database search
h8mail -t target@email.com -o breaches.csv

# theHarvester - Email discovery from domain
theHarvester -d targetdomain.com -l 500 -b all
```

### Phone Investigation

```bash
# PhoneInfoga - Comprehensive phone OSINT
phoneinfoga scan -n "+1234567890"
phoneinfoga serve -p 8080  # Web interface
```

### Domain Investigation

```bash
# Subfinder - Subdomain enumeration
subfinder -d target.com -o subdomains.txt

# httpx - Probe for technologies
cat subdomains.txt | httpx -td -server -title

# waybackurls - Historical URLs
echo target.com | waybackurls > history.txt
```

### IP Investigation

```bash
# ASN - Abuse contact lookup
asn 1.2.3.4

# Quick geolocation
curl http://ip-api.com/json/1.2.3.4
```

### Username Investigation

```bash
# Maigret - 2500+ sites with PDF output
maigret username --pdf --html

# Sherlock - 400+ sites
sherlock username --csv
```

## 📝 Evidence Handling

### Chain of Custody

All evidence is automatically logged to `evidence_log.md`:

```markdown
| Timestamp | Type | Description | Hash (SHA256) | Source |
|-----------|------|-------------|---------------|--------|
| 2024-01-15 10:30:00 UTC | Screenshot | Homepage capture | a1b2c3d4... | cutycapt |
```

### Hash Verification

Every collected file gets a hash manifest:

```
File: /evidence/screenshot.png
Generated: 2024-01-15 10:30:00 UTC
MD5:    d41d8cd98f00b204e9800998ecf8427e
SHA1:   da39a3ee5e6b4b0d3255bfef95601890afd80709
SHA256: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
```

### URL Archiving

URLs are preserved using multiple methods:
1. **Monolith** - Single self-contained HTML file
2. **wget mirror** - Complete site copy
3. **Screenshot** - Visual capture with timestamp
4. **Wayback Machine** - Independent third-party archive

## 🚨 Abuse Reporting

### Domain Registrar

Use WHOIS data to identify the registrar, then:
1. Find abuse contact in WHOIS output
2. Use generated abuse report template
3. Include evidence hashes and screenshots

### Hosting Provider

1. IP investigation reveals hosting provider
2. ASN tool provides abuse contact
3. Submit with documented evidence

### IC3 Submission

The toolkit generates IC3-ready documentation:
- Timestamped evidence
- Hash verification
- Complete investigation narrative
- All discovered identifiers

## ⚠️ Legal & Ethical Considerations

- Only investigate with proper authorization
- Document your legal basis for investigation
- Respect privacy laws in your jurisdiction
- This toolkit is for defensive investigation only
- Do not use for unauthorized access or harassment

## 🤝 Contributing

Contributions welcome! Please:
1. Fork the repository
2. Create a feature branch
3. Submit a pull request

## 📄 License

MIT License - See LICENSE file for details.

## 👤 Author

**PNW Computers**
- Email: jon@pnwcomputers.com
- Phone: 360-624-7379
- Website: [pnwcomputers.com](https://pnwcomputers.com)

## 🙏 Acknowledgments

- [ProjectDiscovery](https://projectdiscovery.io) - subfinder, httpx, dnsx, nuclei
- [Megadose](https://github.com/megadose) - Holehe
- [khast3x](https://github.com/khast3x) - h8mail
- [soxoj](https://github.com/soxoj) - Maigret
- [Sherlock Project](https://github.com/sherlock-project) - Sherlock
- [sundowndev](https://github.com/sundowndev) - PhoneInfoga
- [nitefood](https://github.com/nitefood) - ASN tool

## 🌐 Web Interface

Launch the browser-based interface:

```bash
# From command line
python3 web_interface.py

# Or from the main menu
./osint_investigator.sh
# Select [W] Launch Web Interface
```

Then open http://localhost:5000 in your browser.

**Features:**
- Dashboard with case statistics
- Create and manage cases
- Quick investigation tools
- Abuse report generation
- API key configuration
- Mobile-responsive design

**Requirements:**
- Python 3.8+
- Flask (auto-installed if missing)

## 📝 Abuse Report Generator

Generate professional abuse reports ready to submit:

```bash
# Interactive mode
./abuse_report_generator.sh

# Generate all reports for a case
./abuse_report_generator.sh /path/to/case

# Configure reporter information
./abuse_report_generator.sh --config
```

**Report Types:**
| Type | Description | Recipients |
|------|-------------|------------|
| Domain Registrar | Malicious domain reports | GoDaddy, Namecheap, etc. |
| Hosting Provider | Phishing/scam hosting | AWS, DigitalOcean, etc. |
| Email Provider | Scam email accounts | Gmail, Outlook, ProtonMail |
| ISP | Network abuse | Comcast, AT&T, etc. |
| Social Media | Fake profiles | Facebook, Instagram, Twitter |
| IC3 Worksheet | FBI complaint prep | ic3.gov |

**Auto-Detection:**
- Finds abuse contacts via WHOIS
- Identifies registrars from domain lookup
- Maps IPs to hosting providers via ASN

## 🔗 Toolkit Integration

Connect with your existing OSINT scripts:

```bash
# Auto-detect existing scripts
./toolkit_integration.sh --detect

# Configure paths manually
./toolkit_integration.sh --config

# Show integration status
./toolkit_integration.sh --status
```

**Supported Scripts:**
- `scammer_audit.sh` - Domain/IP investigation
- `email_audit.sh` - Email address analysis
- `phone_audit.sh` - Phone number lookup
- `theHarvester` - Email/subdomain harvesting
- `victim_osint_toolkit.sh` - Forensics tools

**Integration from Main Menu:**
1. Run `./osint_investigator.sh`
2. Select `[6] Integrated Tools`
3. Run individual tools or all at once

## 📁 Complete File List

```
osint-playbook/
├── osint_investigator.sh       # Main playbook (CLI menu)
├── web_interface.py            # Flask web UI
├── abuse_report_generator.sh   # Abuse report drafts
├── toolkit_integration.sh      # Connect existing scripts
├── install_dependencies.sh     # Dependency installer
├── example_api_keys.conf       # API key template
├── README.md                   # This file
├── .gitignore                  # Git ignore rules
└── docs/
    └── INVESTIGATION_GUIDE.md  # Detailed procedures
```

## 🚀 Quick Start

```bash
# 1. Clone/extract the toolkit
git clone https://github.com/Pnwcomputers/osint-playbook.git
cd osint-playbook

# 2. Install dependencies
sudo ./install_dependencies.sh --full

# 3. Configure APIs
cp example_api_keys.conf ~/.config/osint-investigator/api_keys.conf
nano ~/.config/osint-investigator/api_keys.conf

# 4. Run CLI interface
./osint_investigator.sh

# OR run web interface
python3 web_interface.py
```

## 🎯 Complete Investigation Workflow

1. **Create Case** → Assign case ID, enter targets
2. **Run Investigations** → Email, Phone, Domain, IP, Username modules
3. **Integrate Tools** → Run scammer_audit, theHarvester, etc.
4. **Generate Reports** → Final report, abuse reports, IC3 worksheet
5. **Archive Evidence** → Screenshots, hashes, Wayback Machine
6. **Submit Reports** → Use generated drafts to contact providers
