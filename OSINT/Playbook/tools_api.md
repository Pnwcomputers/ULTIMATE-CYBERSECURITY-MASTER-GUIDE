# 🛠️ Core OSINT Toolkit
The playbook integrates the following industry-standard tools for deep reconnaissance:

| Tool | Category | Primary Function |
| :--- | :--- | :--- |
| [**theHarvester**](https://github.com/laramies/theHarvester) | Recon | Email, subdomain, and host harvesting. |
| [**Sherlock**](https://github.com/sherlock-project/sherlock) | Social | Username search across 400+ platforms. |
| [**Recon-ng**](https://github.com/lanmaster53/recon-ng) | Framework | Modular web-reconnaissance and data management. |
| [**Amass**](https://github.com/owasp-amass/amass) | Infrastructure | In-depth DNS enumeration and attack surface mapping. |
| [**SpiderFoot**](https://github.com/smicallef/spiderfoot) | Automation | Automated OSINT collection from 100+ sources. |
| [**Maltego**](https://www.maltego.com/) | Analysis | Visual link analysis and relationship mapping. |
| [**Photon**](https://github.com/s0md3v/Photon) | Crawler | High-speed extraction of URLs, keys, and files. |
| [**H8mail**](https://github.com/khast3ze/h8mail) | Breach | Email breach hunting and credential leak analysis. |
| [**Holehe**](https://github.com/megadose/holehe) | Verification | Email-to-account registration enumeration. |
| [**PhoneInfoga**](https://github.com/sundowndev/phoneinfoga) | Phone | Phone number intelligence and carrier tracking. |

---

# 🔑 Configuration & APIs
The framework leverages several high-authority databases. Ensure your API keys are configured in `${HOME}/.config/osint-investigator/api_keys.conf`:

## 1. PRIMARY INTELLIGENCE & THREAT RECON
* [**Shodan**](https://www.shodan.io/): IoT and Device Search
* [**VirusTotal**](https://www.virustotal.com/): Malware and URL Intelligence
* [**Censys**](https://censys.io/): Host & Certificate Intelligence
* [**SecurityTrails**](https://securitytrails.com/): DNS & Domain History
* [**ZoomEye**](https://www.zoomeye.org/): Cyberspace Search Engine
* [**Criminal IP**](https://www.criminalip.io/): CTI & IP Scoring

## 2. SCANNING & ASSET DISCOVERY
* [**FullHunt**](https://fullhunt.io/): Attack Surface Mapping
* [**Netlas**](https://netlas.io/): Internet Scanning Data
* [**ProjectDiscovery**](https://projectdiscovery.io/): Nuclei & Cloud Automation

## 3. EMAIL, BREACH & IDENTITY
* [**HaveIBeenPwned**](https://haveibeenpwned.com/API/Key): Data Breach Intelligence
* [**Hunter.io**](https://hunter.io/): Professional Email Discovery
* [**EmailRep**](https://emailrep.io/): Email Reputation
* [**Intelligence X**](https://intelx.io/): Deep Web & Archive Search
* [**LeakLookup**](https://leak-lookup.com/): Credential Breach Search

## 4. DOMAIN & INFRASTRUCTURE
* [**WhoisXML API**](https://www.whoisxmlapi.com/): WHOIS Data & Domain Research
* [**DNSDumpster**](https://dnsdumpster.com/): DNS Mapping
* [**URLScan.io**](https://urlscan.io/): Website Analysis

## 5. PHONE & IDENTITY VERIFICATION
* [**Numverify**](https://numverify.com/): Phone Validation
* [**Veriphone**](https://veriphone.io/): Global Phone Lookup
* [**AbstractAPI**](https://www.abstractapi.com/): Identity & Location Validation

## 6. BLOCKCHAIN & ABUSE TRACKING
* [**Etherscan**](https://etherscan.io/): Ethereum Explorer
* [**BlockCypher**](https://www.blockcypher.com/): Multi-chain Crypto Data
* [**AbuseIPDB**](https://www.abuseipdb.com/): IP Reputation & Blacklist Reporting
