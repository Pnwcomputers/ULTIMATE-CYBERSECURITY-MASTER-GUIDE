# WIRELESS & NETWORK SECURITY AUDIT PLAYBOOK
## Professional Penetration Testing Procedures

**Version 1.0**  
**Last Updated: October 2025**

---

## TABLE OF CONTENTS

1. [Pre-Engagement Checklist](#section-1-pre-engagement-checklist)
2. [Wireless-Specific Testing Procedures](#section-2-wireless-specific-testing-procedures)
3. [Internal Network Testing Procedures](#section-3-internal-network-testing-procedures)
4. [External Perimeter Testing Procedures](#section-4-external-perimeter-testing-procedures)
5. [Documentation Standards During Testing](#section-5-documentation-standards-during-testing)
6. [Evidence Collection & Screenshot Requirements](#section-6-evidence-collection--screenshot-requirements)
7. [Post-Testing Analysis & Reporting](#section-7-post-testing-analysis--reporting)
8. [Tool Reference Guide](#section-8-tool-reference-guide)

---

## SECTION 1: PRE-ENGAGEMENT CHECKLIST

### Before Beginning Any Assessment:

- [ ] Obtain signed authorization letter with specific scope
- [ ] Verify emergency contact information (client POC, technical lead)
- [ ] Confirm testing windows and blackout periods
- [ ] Document all MAC addresses and serial numbers of testing devices
- [ ] Ensure all tools are updated and functioning
- [ ] Verify VPN/secure channel for data exfiltration
- [ ] Brief team on rules of engagement and legal boundaries
- [ ] Establish secure storage for collected evidence
- [ ] Configure timestamping on all devices
- [ ] Backup all tool configurations

### Critical Legal Documentation Required:

- Signed Statement of Work (SOW)
- Rules of Engagement (ROE) document
- Authorization to Test letter on company letterhead
- NDA and liability waiver
- Emergency stop procedures documented

---

## SECTION 2: WIRELESS-SPECIFIC TESTING PROCEDURES

### 2.1 PASSIVE RECONNAISSANCE PHASE

**Objective:** Identify wireless networks, access points, clients, and security configurations without actively engaging targets.

**Tools:** Pwnagotchi, Kismet, Wireshark, Kali (airmon-ng, airodump-ng)

#### Procedure:

**STEP 1: Environmental Survey**

- Deploy Pwnagotchi in AUTO mode for passive learning
- Position device in multiple physical locations throughout facility
- Duration: Minimum 2-4 hours per location
- Document:
  - All SSIDs discovered (hidden and broadcast)
  - BSSID (MAC addresses) of access points
  - Channel utilization
  - Signal strength measurements (RSSI)
  - Encryption types (Open, WEP, WPA, WPA2, WPA3)
  - Client devices and their associations

**STEP 2: Passive Packet Capture**

- Enable monitor mode on wireless interface:
  ```bash
  # airmon-ng start wlan0
  ```
- Begin packet capture on all channels:
  ```bash
  # airodump-ng wlan0mon
  ```
- Alternate tool: Launch Kismet for comprehensive logging
- Capture duration: Minimum 4 hours for thorough analysis
- Save all .cap files with timestamps

**STEP 3: Client Device Enumeration**

- Identify all client devices connected to target networks
- Document MAC addresses and manufacturers
- Note client roaming behavior and preferred networks
- Capture probe requests to identify previously connected networks

#### Documentation Requirements:

- CSV export of all discovered networks
- Signal strength heatmap (if using multiple collection points)
- Timestamp logs of all activities
- Photographs of physical locations where testing occurred

### 2.2 ACTIVE WIRELESS TESTING PHASE

**Objective:** Actively test wireless security controls, authentication mechanisms, and network access.

**Tools:** WiFi Pineapple, ESP32 Marauder, Kali Linux, Wireshark

#### Procedure:

**STEP 1: Rogue Access Point Testing (Evil Twin)**

Using WiFi Pineapple:
- Configure SSID to match target network
- Set up captive portal if testing credential harvesting
- Enable karma attack to test client auto-association
- Monitor client connection attempts
- Document:
  - Number of clients that connected
  - Time to first connection
  - Credentials captured (hash only, never plaintext in report)
  - Client device types that connected

**STEP 2: Deauthentication Testing**

Using ESP32 Marauder or Kali:
- Purpose: Test network resilience and capture handshakes
- Select target AP and associated clients
- Execute controlled deauth attack:
  ```bash
  # aireplay-ng --deauth 10 -a [AP_MAC] wlan0mon
  ```
- Capture WPA handshakes during reconnection
- Document:
  - Time to client reconnection
  - Whether IDS/IPS detected the attack
  - Success rate of handshake capture
  - Any alerts generated

**STEP 3: WPS Vulnerability Testing**

Using Reaver/Bully on Kali:
- Scan for WPS-enabled access points:
  ```bash
  # wash -i wlan0mon
  ```
- Attempt WPS PIN attack on authorized targets:
  ```bash
  # reaver -i wlan0mon -b [BSSID] -vv
  ```
- Document WPS lock-out behavior
- Test for Pixie Dust vulnerability

**STEP 4: Captive Portal Bypass Testing**

- Test DNS tunneling capabilities
- Attempt MAC address spoofing
- Test VLAN hopping if applicable
- Document any bypass methods discovered

**STEP 5: Wireless IDS/IPS Testing**

- Generate various attack signatures
- Verify detection and response
- Test alert thresholds and tuning
- Document detection rates

### 2.3 POST-CAPTURE ANALYSIS

**Objective:** Analyze captured data for security weaknesses.

**Tools:** Wireshark, Hashcat, Aircrack-ng

#### Procedure:

**STEP 1: Handshake Analysis**

- Verify handshake validity:
  ```bash
  # aircrack-ng -J output captured.cap
  ```
- Attempt dictionary attack (with pre-approved wordlist):
  ```bash
  # aircrack-ng -w wordlist.txt captured.cap
  ```
- For reporting: Document time to crack (if successful)
- Note: Never include actual passwords in reports

**STEP 2: Traffic Analysis**

- Open .cap files in Wireshark
- Filter for unencrypted traffic:
  - HTTP credentials
  - Clear-text protocols (FTP, Telnet)
  - Sensitive data leakage
- Identify misconfigured devices
- Check for vendor default configurations

**STEP 3: Client Security Analysis**

- Analyze probe requests for security risks
- Identify devices using weak security protocols
- Document devices attempting to connect to suspicious SSIDs

---

## SECTION 3: INTERNAL NETWORK TESTING PROCEDURES

### 3.1 NETWORK DISCOVERY & ENUMERATION

**Objective:** Map internal network topology and identify active hosts.

**Tools:** Nmap, Netdiscover, Responder, Kali Linux tools

#### Procedure:

**STEP 1: Host Discovery**

- Perform network sweep:
  ```bash
  # nmap -sn 192.168.1.0/24
  # netdiscover -r 192.168.1.0/24
  ```
- Document all active hosts with IP and MAC addresses
- Identify network segmentation
- Create network diagram

**STEP 2: Port Scanning**

- Comprehensive port scan of discovered hosts:
  ```bash
  # nmap -sS -sV -O -p- --script=default [target]
  ```
- Quick scan for common ports:
  ```bash
  # nmap -T4 -F [target]
  ```
- Identify:
  - Operating systems
  - Running services and versions
  - Open ports and their purposes
  - Potential vulnerabilities

**STEP 3: Service Enumeration**

- SMB enumeration:
  ```bash
  # enum4linux -a [target]
  # smbclient -L //[target]
  ```
- SNMP enumeration:
  ```bash
  # snmp-check [target]
  ```
- DNS enumeration:
  ```bash
  # dnsenum [domain]
  # fierce -dns [domain]
  ```

**STEP 4: Network Protocol Analysis**

Using Wireshark:
- Capture internal network traffic
- Identify:
  - Broadcast/multicast traffic
  - LLMNR/NBT-NS poisoning opportunities
  - Clear-text credentials
  - Misconfigured VLANs
  - Spanning tree topology
  - Internal routing protocols

### 3.2 VULNERABILITY ASSESSMENT

**Objective:** Identify security weaknesses in internal systems.

**Tools:** Nmap NSE scripts, Metasploit, OpenVAS (optional)

#### Procedure:

**STEP 1: Automated Vulnerability Scanning**

- Run Nmap vulnerability scripts:
  ```bash
  # nmap --script vuln [target]
  ```
- Check for common vulnerabilities:
  - MS17-010 (EternalBlue)
  - SMBv1 enabled
  - Weak SSL/TLS configurations
  - Default credentials
  - Unpatched services

**STEP 2: Web Application Identification**

- Identify internal web applications
- Check for:
  - Default admin panels
  - Directory listings
  - Version disclosure
  - Common web vulnerabilities

**STEP 3: Credential Exposure Testing**

Using Responder:
- Listen for LLMNR/NBT-NS/MDNS queries:
  ```bash
  # responder -I eth0 -rdwv
  ```
- Capture NTLMv2 hashes
- Attempt hash cracking offline
- Document weak password policies

### 3.3 PRIVILEGE ESCALATION & LATERAL MOVEMENT

**Objective:** Test ability to escalate privileges and move laterally.

**Tools:** Metasploit, P4wnP1, various post-exploitation tools

#### Procedure:

**STEP 1: Initial Access Testing**

Using P4wnP1 (if physical access testing is in scope):
- Deploy as USB Rubber Ducky equivalent
- Test HID attack scenarios:
  - Payload execution
  - Credential harvesting
  - Backdoor installation
  - USB attack surface awareness
- Document:
  - Success/failure rates
  - AV/EDR detection
  - User security awareness effectiveness

**STEP 2: Post-Exploitation Enumeration**

After gaining initial access (authorized):
- Enumerate user privileges
- Check for unpatched software
- Identify sensitive data stores
- Map network shares and permissions
- Document findings

**STEP 3: Lateral Movement Testing**

- Test SMB relay attacks (if authorized)
- Attempt pass-the-hash attacks
- Test for Kerberoasting opportunities
- Verify network segmentation effectiveness

---

## SECTION 4: EXTERNAL PERIMETER TESTING PROCEDURES

### 4.1 RECONNAISSANCE

**Objective:** Gather information about external attack surface.

**Tools:** Nmap, Shodan, theHarvester, DNSrecon, Kali Linux

#### Procedure:

**STEP 1: OSINT Gathering**

- DNS enumeration:
  ```bash
  # dnsenum [domain]
  # dnsrecon -d [domain]
  ```
- Subdomain discovery:
  ```bash
  # sublist3r -d [domain]
  # amass enum -d [domain]
  ```
- Email harvesting:
  ```bash
  # theHarvester -d [domain] -b all
  ```
- Shodan/Censys queries for exposed services

**STEP 2: External Network Mapping**

- Identify public IP ranges
- Perform port scanning on external IPs:
  ```bash
  # nmap -sS -sV -Pn -p- [external_IP]
  ```
- Document:
  - Exposed services
  - SSL/TLS configurations
  - Service banners and versions
  - Potential entry points

### 4.2 EXTERNAL VULNERABILITY ASSESSMENT

**Objective:** Identify vulnerabilities in external-facing systems.

**Tools:** Nmap, SSLScan, Nikto, various web testing tools

#### Procedure:

**STEP 1: Web Application Testing**

- Directory/file brute forcing
- SSL/TLS configuration testing:
  ```bash
  # sslscan [target]
  # testssl.sh [target]
  ```
- Check for:
  - Outdated software versions
  - Known CVEs
  - Security header misconfigurations
  - Information disclosure

**STEP 2: VPN/Remote Access Testing**

- Identify VPN technologies in use
- Test for:
  - Default credentials
  - Known vulnerabilities
  - Weak encryption
  - Information leakage

**STEP 3: Email Security Testing**

- SPF/DKIM/DMARC verification
- Mail server security testing
- Open relay testing (authorized)

---

## SECTION 5: DOCUMENTATION STANDARDS DURING TESTING

### 5.1 REAL-TIME DOCUMENTATION REQUIREMENTS

All testing activities must be documented in real-time with the following standards:

#### TIMESTAMP FORMAT:

- All entries must include: `YYYY-MM-DD HH:MM:SS [Timezone]`
- Use synchronized time source (NTP)
- Document timezone in all logs

#### ACTIVITY LOG STRUCTURE:

For each testing activity, document:

```
[TIMESTAMP] - Activity Initiated
Tool: [Tool name and version]
Target: [IP/Hostname/SSID]
Purpose: [What you're testing]
Command/Action: [Exact command or action taken]
Result: [Outcome]
Screenshot Reference: [Filename]
Notes: [Any relevant observations]
```

**Example Entry:**
```
2025-10-23 14:32:15 PST - Wireless Network Scan Initiated
Tool: Airodump-ng v1.7
Target: Corporate Network Vicinity (Building A)
Purpose: Identify all wireless networks and access points
Command: airodump-ng wlan0mon --output-format csv --write corp_scan_001
Result: Discovered 12 access points, 34 client devices
Screenshot: IMG_20251023_143215_airodump.png
Notes: Strong WPA2 encryption on all corporate APs, detected one rogue AP
```

### 5.2 EVIDENCE CHAIN OF CUSTODY

Maintain strict chain of custody for all evidence:

#### Required Information:

- Evidence ID number (sequential)
- Date and time collected
- Collector name
- Evidence description
- Storage location
- Hash values (SHA-256) of all captured files
- Transfer records (if applicable)

#### Digital Evidence Storage:

- Store all evidence on encrypted drives
- Maintain backup copies
- Never modify original evidence files
- Use write-blocking where appropriate

### 5.3 TESTING NOTES FORMAT

Maintain a master testing log with sections:

#### DAILY LOG STRUCTURE:

```
Date: [YYYY-MM-DD]
Tester(s): [Names]
Testing Location: [Physical location]
Testing Phase: [Wireless/Internal/External/Other]
Weather Conditions: [If relevant for wireless testing]

Activities Summary:
[Bulleted list of major activities]

Findings Summary:
[Bulleted list of significant findings]

Issues Encountered:
[Any problems, anomalies, or deviations from plan]

Follow-up Required:
[Items needing additional testing or clarification]
```

---

## SECTION 6: EVIDENCE COLLECTION & SCREENSHOT REQUIREMENTS

### 6.1 SCREENSHOT STANDARDS

#### Required Elements in Every Screenshot:

1. Timestamp visible (system clock or terminal timestamp)
2. Tool name and version visible
3. Command or action being performed visible
4. Complete output/results visible
5. Target information visible (IP/SSID/hostname)
6. Your terminal prompt showing authenticated user (if applicable)

#### Screenshot Naming Convention:

`[DATE]_[TIME]_[TOOL]_[TARGET]_[DESCRIPTION].png`

**Example:** `20251023_1432_nmap_192.168.1.1_port_scan.png`

#### Minimum Screenshot Requirements:

**For Each Vulnerability Found:**
- Initial discovery screenshot
- Detailed information screenshot
- Proof of concept/exploitation screenshot (if applicable)
- Remediation verification screenshot (if retesting)

**For Network Scans:**
- Scan initiation (showing full command)
- Scan results overview
- Detailed results of interesting findings
- Scan completion with statistics

**For Wireless Testing:**
- Network discovery results
- Handshake capture confirmation
- Client connection attempts
- Deauthentication attack results
- Rogue AP connection logs

### 6.2 PACKET CAPTURE REQUIREMENTS

#### For All Wireless Testing:

- Save full packet captures (.pcap/.cap format)
- Include only authorized network traffic
- Hash all capture files immediately after collection
- Document capture duration and statistics
- Filter and save separate files for specific findings

#### Capture File Naming:

`[DATE]_[TIME]_[INTERFACE]_[LOCATION]_[DESCRIPTION].pcap`

#### Required Metadata:

- Start/end timestamps
- Interface used
- Capture filter applied (if any)
- Total packets captured
- File size
- SHA-256 hash

### 6.3 LOG FILE COLLECTION

#### Required Logs to Collect:

**Tool Logs:**
- All terminal output saved to log files
- Use script/screen logging:
  ```bash
  # script testing_session_$(date +%Y%m%d_%H%M%S).log
  ```
- Save tool-specific logs (Metasploit logs, Nmap XML output, etc.)

**System Logs (if provided by client):**
- IDS/IPS alerts during testing
- Firewall logs showing blocked/allowed connections
- Authentication logs
- System event logs

**Custom Tool Logs:**
- Pwnagotchi session logs and captured handshakes
- WiFi Pineapple logging database
- Responder captured hashes and logs
- Any custom script output

### 6.4 EVIDENCE ORGANIZATION

#### Directory Structure for Each Engagement:

```
[CLIENT_NAME]_[ENGAGEMENT_DATE]/
├── 01_Planning/
│   ├── Authorization_Letter.pdf
│   ├── Scope_Document.pdf
│   └── Rules_of_Engagement.pdf
├── 02_Reconnaissance/
│   ├── OSINT/
│   ├── Network_Diagrams/
│   └── Findings_Summary.txt
├── 03_Wireless_Testing/
│   ├── Packet_Captures/
│   ├── Screenshots/
│   ├── Logs/
│   ├── Handshakes/
│   └── Wireless_Findings.txt
├── 04_Internal_Testing/
│   ├── Network_Scans/
│   ├── Screenshots/
│   ├── Logs/
│   ├── Vulnerability_Evidence/
│   └── Internal_Findings.txt
├── 05_External_Testing/
│   ├── Port_Scans/
│   ├── Screenshots/
│   ├── Logs/
│   └── External_Findings.txt
├── 06_Exploitation_POCs/
│   ├── Screenshots/
│   ├── Scripts_Used/
│   └── POC_Documentation.txt
├── 07_Raw_Evidence/
│   ├── evidence_manifest.csv
│   └── [All original evidence files with hashes]
└── 08_Final_Report/
    ├── Draft_Report.docx
    ├── Final_Report.pdf
    └── Executive_Summary.pdf
```

#### Evidence Manifest (CSV Format):

`Evidence_ID, Filename, SHA256_Hash, Date_Collected, Collector, Description`

---

## SECTION 7: POST-TESTING ANALYSIS & REPORTING

### 7.1 VULNERABILITY CLASSIFICATION

Use CVSS v3.1 scoring for all technical findings. Use the following risk rating system:

#### CRITICAL (CVSS 9.0-10.0):
- Requires immediate remediation
- Examples: Unauthenticated remote code execution, complete system compromise

#### HIGH (CVSS 7.0-8.9):
- Requires urgent remediation (within 30 days)
- Examples: Authenticated RCE, critical data exposure, weak wireless encryption

#### MEDIUM (CVSS 4.0-6.9):
- Requires remediation within 90 days
- Examples: Information disclosure, missing security controls, outdated software

#### LOW (CVSS 0.1-3.9):
- Requires remediation within 180 days
- Examples: Minor misconfigurations, informational findings

#### INFORMATIONAL:
- No immediate risk but worth noting
- Best practice recommendations

### 7.2 FINDING DOCUMENTATION TEMPLATE

For Each Finding:

```
Title: [Clear, concise title]
Risk Rating: [Critical/High/Medium/Low/Informational]
CVSS Score: [If applicable]

Description:
[Clear explanation of what was found]

Impact:
[Business and technical impact explanation]

Affected Assets:
[List all affected systems, networks, or devices]

Evidence:
[Reference to screenshots, logs, packet captures]
- Screenshot 1: [filename and description]
- Packet Capture: [filename and description]
- Log File: [filename and description]

Steps to Reproduce:
1. [Detailed steps]
2. [Including commands used]
3. [That allow client to verify]

Remediation Recommendations:
Short-term:
- [Immediate actions to mitigate risk]

Long-term:
- [Strategic improvements]

References:
[CVE numbers, vendor advisories, industry standards]
```

### 7.3 REPORT STRUCTURE

#### Executive Summary (2-3 pages):
- Engagement overview
- Scope and methodology
- Key findings summary
- Overall risk posture assessment
- Strategic recommendations

#### Technical Findings (Detailed):
- Organized by severity
- Each finding with full documentation as per template above
- Clear remediation guidance

#### Methodology Section:
- Tools used (with versions)
- Testing procedures followed
- Timeline of activities

#### Appendices:
- Detailed scan results
- Network diagrams
- Tool output samples (sanitized)
- Glossary of terms

---

## SECTION 8: TOOL REFERENCE GUIDE

### 8.1 PWNAGOTCHI

**Purpose:** Automated WPA handshake capture using AI  
**Use Cases:** Passive wireless reconnaissance, long-term monitoring  
**Key Commands:** Configure via web UI, AUTO/MANU modes  
**Documentation:** All captured handshakes saved to `/root/handshakes/`  
**Evidence:** Session logs, captured .pcap files with handshakes

### 8.2 BJORN (IF APPLICABLE)

**Purpose:** Multi-functional wireless security testing platform  
**Use Cases:** Combined wireless assessment tool  
**Key Features:** Check device-specific capabilities and documentation

### 8.3 WIFI PINEAPPLE

**Purpose:** Wireless auditing platform for authorized testing  
**Use Cases:** Rogue AP testing, evil twin attacks, wireless MitM  
**Key Modules:** PineAP, Recon, Logging  
**Access:** Web interface at `172.16.42.1:1471`  
**Evidence:** Database exports, client connection logs, captured credentials

### 8.4 ESP32 MARAUDER

**Purpose:** Portable wireless attack/testing device  
**Use Cases:** Deauth attacks, beacon flooding, probe sniffing  
**Key Commands:** Access via serial or web interface  
**Evidence:** Terminal logs of attacks, statistics

### 8.5 P4WNP1 A.L.O.A

**Purpose:** HID attack platform and network implant  
**Use Cases:** Physical penetration testing, USB attack simulation  
**Key Features:** Rubber Ducky payloads, WiFi backdoor, Bluetooth attacks  
**Access:** Web interface when deployed  
**Evidence:** Payload execution logs, collected credentials, screenshots

### 8.6 KALI LINUX TOOLS

#### Aircrack-ng Suite:
- **airmon-ng:** Enable monitor mode
- **airodump-ng:** Capture wireless traffic
- **aireplay-ng:** Inject packets, deauth attacks
- **aircrack-ng:** WPA/WPA2 cracking

#### Nmap:
- Port scanning, service enumeration, OS detection
- NSE scripts for vulnerability detection
- Key flags: `-sS` (SYN scan), `-sV` (version detection), `-O` (OS detection)

#### Wireshark:
- Deep packet inspection and protocol analysis
- Filter syntax: `ip.addr`, `tcp.port`, `wlan.fc.type`
- Export options: PDFs of packet details, CSV summaries

#### Metasploit:
- Exploitation framework
- Use only with explicit authorization
- Document all modules used

#### Other Key Tools:
- **Responder:** LLMNR/NBT-NS poisoning
- **enum4linux:** SMB enumeration
- **Nikto:** Web server scanning
- **Burp Suite:** Web application testing

### 8.7 TOOL VERSION TRACKING

Maintain a tools manifest for each engagement:

| Tool Name | Version | Last Updated | Purpose |
|-----------|---------|--------------|---------|
| Kali Linux | 2024.3 | 2024-09-15 | Primary testing platform |
| Nmap | 7.94 | 2024-08-01 | Network scanning |
| Wireshark | 4.2.0 | 2024-07-20 | Packet analysis |
| [etc.] | | | |

---

## PROFESSIONAL STANDARDS & ETHICS

**Remember at all times:**

- Only test systems explicitly authorized in writing
- Stop testing immediately if requested by client
- Protect all client data with encryption
- Never retain client data longer than necessary for reporting
- Report critical vulnerabilities immediately (out-of-band)
- Maintain professional insurance and certifications
- Follow industry standards (PTES, OWASP, OSSTMM)
- Document everything - if it's not documented, it didn't happen

---

## EMERGENCY PROCEDURES

**If you cause a system outage or incident:**

1. Stop all testing immediately
2. Contact client emergency contact
3. Document exact circumstances of incident
4. Preserve all evidence related to incident
5. Assist in restoration efforts as requested
6. Include incident in final report with full transparency

---

## END OF PLAYBOOK

This playbook should be reviewed and updated quarterly to reflect:

- New tools and techniques
- Updated security standards
- Lessons learned from engagements
- Client feedback
- Industry best practices

**Document Control:**
- **Version:** 1.0
- **Created:** October 2025
- **Next Review:** January 2026
- **Owner:** Pacific Northwest Computers

For questions or suggestions, contact: [Your Contact Information]
