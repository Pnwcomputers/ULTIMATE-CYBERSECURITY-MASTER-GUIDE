# 🔍 Comprehensive OSINT Investigator Cheat Sheet

> [!IMPORTANT]
> **Reviewed October 31, 2026.** These are starting points, not guarantees that every external service/API is reachable or offers the same data today. Verify current flags with `tool --help` and follow rate limits, privacy law, written authorization and provider terms. Avoid uploading private evidence, credentials or confidential identifiers to unknown lookup services. Use the [OSINT playbook](./Playbook/README.md) for case setup, [full methodology](./OSINT_GUIDE.md) for context and [privacy/OPSEC](../OPSEC/README.md) before collecting.

## 🎯 Purpose
Quick-reference OSINT cheat sheet covering tools, commands, and services integrated into the OSINT Investigator Playbook for rapid investigation lookup.

## ⚙️ Function
Tabular reference for: domain/IP tools (whois, nslookup, Shodan, Censys, theHarvester), email tools (HaveIBeenPwned, Hunter.io, EmailRep), social media OSINT, image OSINT (reverse search, ExifTool), dark web search, and Google dork operators.

## 🏆 Goal
Serve as a working reference during an active investigation - covering what tool to use for which data type and the key commands/URLs without having to dig through longer guides.

## 📋 When to Use
- During an active OSINT investigation needing a quick tool lookup
- Preparing for a recon engagement and reviewing available tools
- Quick reference for Google dork syntax or API endpoint formats

This page is the **quick-command index** for the five investigation phases; detailed methodologies and tool catalogs live in the links above. Preserve raw results, source URLs, capture times and case IDs before filtering or exporting.

---

## 🎯 Phase 1: Identity & Social Hunting
*Used when you have a **Username**, **Real Name**, or **Email Address**.*

### Tool Overview
| Tool | Purpose |
| :--- | :--- |
| **[Sherlock](https://github.com/sherlock-project/sherlock)** | Searches supported websites for username matches; false positives and website breakage are common. |
| **[Maigret](https://bellingcat.gitbook.io/toolkit/more/all-tools/maigret)** | Advanced username OSINT (extracts profile data). |
| **[Blackbird](https://github.com/p1ngul1n0/blackbird)** | Additional username coverage across platforms. |
| **[Holehe](https://github.com/megadose/holehe)** | Tries to infer account existence through service responses; may be unreliable, rate-limited or privacy sensitive. |
| **[h8mail](https://github.com/khast3x/h8mail)** | Queries supported breach-related sources; availability and lawful access vary. Never publish recovered personal data. |
| **[theHarvester](https://github.com/laramies/theharvester)** | Scrapes emails and names from public search engines. |

### Quick Commands
```bash
# --- Email Investigation ---
theHarvester -d example.com -b all          # General email harvesting
holehe target@example.com --only-used      # Email registration check
h8mail -t target@example.com               # Breach hunting

# --- Username Investigation ---
sherlock username                          # Standard username search
maigret username                           # Advanced username OSINT
blackbird -u username                      # Additional coverage search
```

---

## 🌐 Phase 2: Infrastructure & Domain Analysis
*Used when you have a **Domain**, **IP Address**, or **URL**.*

### Tool Overview
| Tool | Purpose |
| :--- | :--- |
| **[Amass](https://github.com/owasp-amass/amass)** | Deep DNS enumeration and sub-domain mapping. |
| **[Subfinder](https://github.com/projectdiscovery/subfinder)** | Fast subdomain discovery. |
| **[Shodan](https://www.shodan.io/)** | Identifies open ports and running services on a server. |
| **[WhoisXML](https://www.whoisxmlapi.com/)** | (API Integrated) Retrieves ownership history and registrar info. |
| **[AbuseIPDB](https://www.abuseipdb.com/)**| (API Integrated) Checks if an IP is a known source of fraud/spam. |

### Quick Commands
```bash
# --- Domain Reconnaissance ---
amass enum -d example.com                   # Comprehensive subdomain enumeration
subfinder -d example.com                    # Fast subdomain discovery
subfinder -d example.com -silent | httpx -td -server -title -asn # Subfinder → httpx pipeline
theHarvester -d example.com -b google       # Domain emails & subdomains via Google

# Certificate transparency via crt.sh
curl -s "https://crt.sh/?q=%25.target.com&output=json" | jq '.[].name_value' | sort -u

# --- IP Investigation ---
asn 1.2.3.4                                # ASN + abuse contact
curl -s "https://ipinfo.io/1.2.3.4" | jq   # Geolocation lookup
dig -x 1.2.3.4 +short                      # Reverse DNS lookup
shodan host 1.2.3.4                        # Service and port identification
```

---

## 🕷️ Phase 3: Web Crawling & Historical Analysis
*Used for mapping web assets, finding hidden endpoints, and viewing past versions of sites.*

### Tool Overview & Commands
| Tool | Purpose | Command / Usage |
| :--- | :--- | :--- |
| **[Photon](https://github.com/s0md3v/photon)** | Crawls site for secret keys, files, and URLs. | `python photon.py -u https://target.com` |
| **[waybackurls](https://github.com/tomnomnom/waybackurls)**| Historical URL discovery via Wayback Machine. | `echo target.com \| waybackurls` |
| **[Wget](https://osintteam.blog/master-real-world-web-app-enumeration-with-curl-wget-and-bash-a-step-by-step-guide-5f74ab34e795)** | Complete website mirroring for offline review. | `wget -r -l 2 -P output/ https://target.com` |

---

## 📱 Phase 4: Communication Intelligence
*Used when you have a **Phone Number**.*

### Tool Overview & Commands
| Tool | Purpose | Command / Usage |
| :--- | :--- | :--- |
| **[PhoneInfoga](https://github.com/sundowndev/phoneinfoga)** | Checks carrier, location, and reputation. | `phoneinfoga scan -n <number>` |
| **[Google Dorking](https://tryhackme.com/room/googledorking)**| Manual lookup for linked social profiles. | `site:facebook.com "number"` |

---

## 📊 Phase 5: Analysis & Automation
*Used for **Visualizing** links and **Automating** the workflow.*

### Tool Overview
| Tool | Purpose |
| :--- | :--- |
| **[SpiderFoot](https://github.com/smicallef/spiderfoot)** | Runs 100+ modules automatically against a single target. |
| **[Recon-ng](https://github.com/lanmaster53/recon-ng)** | A framework to manage targets in a local database. |
| **[Maltego](https://www.maltego.com/)** | Drag-and-drop link analysis to see connections between entities. |

### Quick Commands
```bash
# --- Recon-ng Framework ---
recon-ng                                   # Launch framework
workspaces create target                   # Create a new workspace
marketplace install all                    # Install all modules
modules search                             # Search available modules

# --- SpiderFoot ---
spiderfoot -s target.com                   # Auto OSINT execution against a target
```

---

## 💾 Evidence Preservation & Playbook Operations
*Crucial steps for ensuring findings are documented, hashed, and forensically sound.*

### Investigator Playbook Configuration
*   **Initialize Case:** Select `[1]` in the main menu to set up forensic directories.
*   **Log Location:** `${HOME}/.config/osint-investigator/logs/`
*   **API Config:** Confirm the playbook's current configuration method; store keys in private, permission-restricted files or environment variables. Never commit API keys or raw investigation data.
*   **Evidence Export:** Move all critical findings to `${CASE_DIR}/evidence/` for the final report.

### Preservation Commands
```bash
# Capture a self-contained HTML archive of a webpage
monolith https://target.com -o evidence_$(date +%Y%m%d_%H%M%S).html

# Capture a full-page screenshot
cutycapt --url=https://target.com --out=screenshot.png

# Force a target page to be archived in the Wayback Machine
waybackpy --url "https://target.com" --save

# Generate a Hash Manifest to prove file integrity
sha256sum evidence_*.html screenshot_*.png > evidence_hashes.txt
```

---

## 🛠️ Essential Linux Commands for OSINT
Native utilities that are invaluable during an investigation:
*   **[DNS Lookup:](https://www.cyberciti.biz/faq/unix-linux-dns-lookup-command/)** `dig example.com A +short`
*   **[Owner Lookup:](https://www.kali.org/tools/whois/)** `whois <domain>`
*   **[File Extraction:](https://developers.redhat.com/articles/2022/09/14/beginners-guide-regular-expressions-grep)** `grep -r "regex" ./raw_data/`
*   **[Metadata Check:](https://exiftool.org/)** `exiftool image.jpg`

---
> **⚠️ Disclaimer:** Use network privacy tools when appropriate, but a VPN or Tor connection does **not** grant authorization, erase service logs, or override lawful processing and access requirements.

## Related Files
- [README.md](README.md) - OSINT section index
- [OSINT_GUIDE.md](OSINT_GUIDE.md) - Full methodology context
- [OSINT_TOOLS_CATALOG.md](OSINT_TOOLS_CATALOG.md) - Detailed tool descriptions
- [Playbook/README.md](Playbook/README.md) - Playbook that uses these tools
