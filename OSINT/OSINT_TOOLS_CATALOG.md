# 🛠️ Core OSINT Toolkit
The playbook integrates the following industry-standard tools for deep reconnaissance:

| Tool | Category | Primary Function |
| :--- | :--- | :--- |
| **theHarvester** | Recon | Email, subdomain, and host harvesting. |
| **Sherlock** | Social | Username search across 400+ platforms. |
| **Recon-ng** | Framework | Modular web-reconnaissance and data management. |
| **Amass** | Infrastructure | In-depth DNS enumeration and attack surface mapping. |
| **SpiderFoot** | Automation | Automated OSINT collection from 100+ sources. |
| **Maltego** | Analysis | Visual link analysis and relationship mapping. |
| **Photon** | Crawler | High-speed extraction of URLs, keys, and files. |
| **H8mail** | Breach | Email breach hunting and credential leak analysis. |
| **Holehe** | Verification | Email-to-account registration enumeration. |
| **PhoneInfoga** | Phone | Phone number intelligence and carrier tracking. |

---

# 🔑 Configuration & APIs
The framework leverages several high-authority databases. Ensure your API keys are configured in `${HOME}/.config/osint-investigator/api_keys.conf`:

## 1. PRIMARY INTELLIGENCE & THREAT RECON
* **Shodan**: IoT and Device Search
* **VirusTotal**: Malware and URL Intelligence
* **Censys**: Host & Certificate Intelligence
* **SecurityTrails**: DNS & Domain History
* **ZoomEye**: Cyberspace Search Engine
* **Criminal IP**: CTI & IP Scoring

## 2. SCANNING & ASSET DISCOVERY
* **FullHunt**: Attack Surface Mapping
* **Netlas**: Internet Scanning Data
* **ProjectDiscovery**: Nuclei & Cloud Automation

## 3. EMAIL, BREACH & IDENTITY
* **HaveIBeenPwned**: Data Breach Intelligence
* **Hunter.io**: Professional Email Discovery
* **EmailRep**: Email Reputation
* **Intelligence X**: Deep Web & Archive Search
* **LeakLookup**: Credential Breach Search

## 4. DOMAIN & INFRASTRUCTURE
* **WhoisXML API**: WHOIS Data & Domain Research
* **DNSDumpster**: DNS Mapping
* **URLScan.io**: Website Analysis

## 5. PHONE & IDENTITY VERIFICATION
* **Numverify**: Phone Validation
* **Veriphone**: Global Phone Lookup
* **AbstractAPI**: Identity & Location Validation

## 6. BLOCKCHAIN & ABUSE TRACKING
* **Etherscan**: Ethereum Explorer
* **BlockCypher**: Multi-chain Crypto Data
* **AbuseIPDB**: IP Reputation & Blacklist Reporting

---

## 🚀 Installation & Usage

### Prerequisites
* **OS:** Tsurugi Linux (Recommended), Ubuntu, or Debian; Bare-metal or VM.
* **Dependencies:** `bash` (4+), `dig`, `whois`, `curl`, `jq`.
