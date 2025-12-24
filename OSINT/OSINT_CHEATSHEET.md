# 🔍 OSINT Investigator Cheat Sheet

A quick-reference guide for the tools and services integrated into the **OSINT Investigator Playbook v2.1**.

---

## 🎯 Phase 1: Identity & Social Hunting
*Used when you have a **Username**, **Real Name**, or **Email Address**.*

| Tool | Command/Usage | Purpose |
| :--- | :--- | :--- |
| **Sherlock** | `sherlock <username>` | Finds accounts on 400+ social networks. |
| **Holehe** | `holehe <email>` | Checks if an email is registered on sites (IG, Twitter, etc). |
| **h8mail** | `h8mail -t <email>` | Finds passwords/breach data associated with an email. |
| **theHarvester** | `theHarvester -d <domain> -b google` | Scrapes emails and names from public search engines. |

---

## 🌐 Phase 2: Infrastructure & Domain Analysis
*Used when you have a **Domain**, **IP Address**, or **URL**.*

| Tool | Command/Usage | Purpose |
| :--- | :--- | :--- |
| **Amass** | `amass enum -d <domain>` | Deep DNS enumeration and sub-domain mapping. |
| **Photon** | `photon -u <url>` | Crawls site for secret keys, files, and hidden URLs. |
| **WhoisXML** | (API Integrated) | Retrieves ownership history and registrar info. |
| **AbuseIPDB** | (API Integrated) | Checks if an IP is a known source of fraud or spam. |
| **Shodan** | `shodan host <IP>` | Identifies open ports and running services on a server. |

---

## 📱 Phase 3: Communication Intelligence
*Used when you have a **Phone Number**.*

| Tool | Command/Usage | Purpose |
| :--- | :--- | :--- |
| **PhoneInfoga** | `phoneinfoga scan -n <number>` | Checks carrier, location, and reputation. |
| **Google Dorking** | `site:facebook.com "number"` | Manual lookup for linked social profiles. |

---

## 📊 Phase 4: Analysis & Automation
*Used for **Visualizing** links and **Automating** the workflow.*

| Tool | Purpose |
| :--- | :--- |
| **SpiderFoot** | Runs 100+ modules automatically against a single target. |
| **Recon-ng** | A framework to manage targets in a local database. |
| **Maltego** | Drag-and-drop link analysis to see connections between entities. |

---

## 📂 Investigator Playbook Commands
*Shortcut keys and logic from `osint_investigator.sh`.*

* **Initialize Case:** Select `[1]` in the main menu to set up forensic directories.
* **Log Location:** `${HOME}/.config/osint-investigator/logs/`
* **API Config:** Edit `api_keys.conf` to enable Shodan, VT, and HIBP.
* **Evidence Export:** Move all critical findings to `${CASE_DIR}/evidence/` for the final report.

---

## 🛠️ Essential Linux Commands for OSINT
* **DNS Lookup:** `dig <domain> ANY`
* **Owner Lookup:** `whois <domain>`
* **File Extraction:** `grep -r "regex" ./raw_data/`
* **Metadata Check:** `exiftool image.jpg`

---
**Disclaimer:** Ensure all research is conducted via a VPN/Tor and follows legal guidelines for your jurisdiction.
