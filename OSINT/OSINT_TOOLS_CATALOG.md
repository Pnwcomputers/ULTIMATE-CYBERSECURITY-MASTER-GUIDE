## 🛠️ Core OSINT Toolkit
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

## 🔑 Configuration & APIs
The framework leverages several high-authority databases. Ensure your API keys are configured in `${HOME}/.config/osint-investigator/api_keys.conf`:

* **Shodan**: IoT and server infrastructure analysis.
* **VirusTotal**: Malicious domain and file reputation.
* **Have I Been Pwned**: Credential exposure tracking.
* **AbuseIPDB**: IP reputation and fraud reporting.
* **WhoisXML**: Historical WHOIS and domain ownership.

---

## 🚀 Installation & Usage

### Prerequisites
* **OS:** Tsurugi Linux (Recommended), Ubuntu, or Debian; Bare-metal or VM.
* **Dependencies:** `bash` (4+), `dig`, `whois`, `curl`, `jq`.
