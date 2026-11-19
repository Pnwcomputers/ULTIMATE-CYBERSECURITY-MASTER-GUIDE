# Cybersecurity Comprehensive Cliff Notes

**Reference index and audit status:** [Reviewed cheat sheets and references](./Documentation/CHEATSHEET-REFERENCE-AUDIT-2026-10-31.md).

> [!NOTE]
> **Selected reference audit: October 31, 2026.** This is a historical multi-topic compendium, not a guarantee every pasted command works with the latest tool release. Some sections are intentionally preserved as legacy demonstrations; use the [official OWASP Top 10:2025](https://top10.owasp.org/2025/) for current categories, [Arch/Debian cheat sheets](Documentation/ArchLinux_CheatSheet.md) for safe system commands, and [Wireshark reference](Documentation/wireshark.md) for protocol investigations.

> [!CAUTION]
> **Authorized use only.** The techniques below are for authorized security
> testing, education, and defensive research. Using them against systems you do
> not own or lack explicit written permission to test is illegal. See
> [LEGAL.md](LEGAL.md).

## Compiled Study Guide from Professional Resource Library

---

## Table of Contents
1. [Ethical Hacking Fundamentals](#ethical-hacking-fundamentals)
2. [Reconnaissance & Information Gathering](#reconnaissance--information-gathering)
3. [Network Security & Exposure Management](#network-security--exposure-management)
4. [Web Application Security](#web-application-security)
5. [Endpoint Security and Incident Response](#endpoint-security-and-incident-response)
6. [Exploitation Frameworks: Defensive Use](#exploitation-frameworks-defensive-use)
7. [Wireless Network Security](#wireless-network-security)
8. [Social Engineering](#social-engineering)
9. [Cryptography Essentials](#cryptography-essentials)
10. [Digital Forensics](#digital-forensics)
11. [Penetration Testing Methodology](#penetration-testing-methodology)
12. [OSCP Preparation](#oscp-preparation)

---

## 🎯 Purpose
A concise defensive reference. [ultimate_cybersecurity_master_guide.md](ultimate_cybersecurity_master_guide.md) covers broader methodology; this guide highlights safe review, detection, and response practices.

## ⚙️ Function
12 topic sections mirroring the master guide's core lifecycle (recon through OSCP prep) but stripped to bullet points and command snippets, plus a dedicated "Quick Reference Commands" section at the end. Differs from [ultimate_cybersecurity_master_guide.md](ultimate_cybersecurity_master_guide.md) and [ENHANCED_MASTER_GUIDE.md](ENHANCED_MASTER_GUIDE.md) by omitting explanation/context in favor of density - no prose walkthroughs, just what to run and when.

## 🏆 Goal
A command or concept can be located and copy-pasted in seconds without reading surrounding narrative.

## 📋 When to Use
During security reviews, defensive study, or authorized assessments when you need a concise reminder of core concepts and response steps.

## Ethical Hacking Fundamentals

### Core Concepts
- **Definition**: Authorized assessment of systems, applications, or data to identify and validate security weaknesses within an approved scope
- **Purpose**: Identify vulnerabilities before malicious actors exploit them
- **Legal Framework**: Always obtain written authorization before testing

### Types of Hackers
- **White Hat**: Ethical hackers working with authorization
- **Black Hat**: Malicious hackers breaking laws
- **Gray Hat**: Operate in between, sometimes without authorization but without malicious intent

### Ethical Hacking Phases
1. **Reconnaissance**: Information gathering
2. **Scanning**: Identifying live systems and open ports
3. **Gaining Access**: Exploiting vulnerabilities
4. **Attacker persistence behaviors**: Study persistence indicators to improve prevention and detection; do not establish persistence during an assessment unless explicitly authorized.
5. **Evidence preservation and response**: Preserve logs and artifacts. Treat attempts to conceal activity as behaviors to detect, not routine assessment steps.

### Key Principles
- **Confidentiality**: Information accessible only to authorized parties
- **Integrity**: Data remains unaltered
- **Availability**: Systems remain accessible when needed
- **Non-Repudiation**: Actions cannot be denied

---

## Reconnaissance & Information Gathering

### Passive Reconnaissance
**Goal**: Gather information without directly interacting with target

#### OSINT (Open Source Intelligence)
- **Search Engines**: Google dorking, Bing, DuckDuckGo
- **Social Media**: LinkedIn, Twitter, Facebook for employee info
- **Public Records**: WHOIS, DNS records, company registrations
- **Website Analysis**: Archive.org, built-with tools

#### Key Tools
- **theHarvester**: Email, subdomain, and name discovery
- **Maltego**: Link analysis and data mining
- **Shodan**: Internet of Things search engine
- **Recon-ng**: Web reconnaissance framework
- **SpiderFoot**: Automated OSINT gathering

#### Google Dorking Examples
```
site:target.com filetype:pdf
site:target.com inurl:admin
site:target.com intitle:"index of"
site:target.com ext:sql | ext:txt
```

### Active Reconnaissance
**Goal**: Direct interaction to gather information

#### DNS Enumeration
```bash
# Zone Transfer
dig axfr @nameserver domain.com
host -t ns domain.com

# Subdomain discovery
dnsrecon -d domain.com
dnsenum domain.com
```

#### Network Scanning
```bash
# Ping sweep
nmap -sn 192.168.1.0/24

# Port scanning
nmap -sS -p- -T4 target.com
nmap -sV -O target.com
```

---

## Network Security & Exposure Management

Network testing should begin with a written asset list, an approved time window, and an agreed rate and impact limit. Use the organization's authorized inventory and vulnerability-management tools; review findings against service ownership and business context before remediation.

### Defensive review checklist

- Identify internet-facing services and confirm each has an owner and business need.
- Compare observed services with the approved asset inventory.
- Review firewall, VPN, DNS, and authentication logs for unexpected access.
- Prioritize known exploited vulnerabilities and externally reachable management services.
- Coordinate active validation with system owners; stop if availability or scope is uncertain.


---

## Web Application Security

Use an authorized test environment with synthetic accounts and data. Prefer code review, a staging copy, and non-destructive validation. Record the affected route, expected behavior, observed behavior, and remediation.

### Review areas

- **Access control:** Verify users can access only the records and actions allowed by their role.
- **Input handling:** Use parameterized database access and context-aware output encoding. Validate on the server.
- **Session and request integrity:** Use secure, HTTP-only, same-site cookies; require anti-CSRF protections for state-changing requests.
- **File handling:** Allowlist required formats, inspect content rather than trusting extensions, store uploads outside executable paths, and enforce size limits.
- **Server-side requests:** Restrict outbound destinations and block access to local, link-local, and metadata services.
- **Dependencies and configuration:** Track supported versions, remove debug features, and keep secrets out of source and logs.

Use the current OWASP Top 10 as a starting point, then map findings to the relevant application controls and threat model.


---

## Endpoint Security and Incident Response

### Credential protection

Store passwords with a slow, unique salt-based password hashing function such as Argon2id, scrypt, or appropriately configured bcrypt. Do not store plaintext passwords or reuse production credentials in labs. Protect privileged credentials with phishing-resistant MFA, managed service identities, and least privilege.

### Endpoint review

- Inventory local administrators, services, scheduled tasks, startup entries, and security-control status.
- Investigate unexpected changes using endpoint telemetry and approved baselines.
- Monitor unusual parent-child process relationships, script interpreters, unsigned binaries, and unexpected outbound connections.
- Preserve relevant logs and volatile evidence before containment when practical.
- Rebuild or restore a compromised endpoint from a known-good image after evidence collection and credential rotation.

### Response sequence

Alert and report → validate scope and impact → preserve logs and evidence → contain the affected endpoint → remove the cause and rotate credentials → restore from a known-good state → document lessons.


---

## Exploitation Frameworks: Defensive Use

Frameworks can help reproduce a vulnerability in a deliberately vulnerable, isolated lab or validate a vendor patch under an approved test plan. Their modules can affect availability, expose data, or change a target, so treat every module as a potentially disruptive action.

Before a test, document the exact lab target, approved module and version, expected changes, rollback method, and stop conditions. Do not run exploit, credential-dumping, persistence, webcam, keylogging, or pivoting features against production systems. Prefer vendor advisories, safe configuration checks, and patch verification for routine assessments.

### Validation lifecycle

Vendor advisory → inventory affected versions → apply mitigation or patch → perform a safe version/configuration check → review logs and residual risk.


---

## Wireless Network Security

Assess wireless security through approved configuration review and passive monitoring. Obtain authorization from the network owner and coordinate with nearby tenants because radio testing can affect networks outside the intended scope.

### Configuration and monitoring checklist

- Prefer WPA3 or WPA2-AES; disable WEP, TKIP, and WPS where supported.
- Use unique administrative and network credentials; rotate defaults.
- Enable protected management frames where clients support them.
- Separate guest and IoT devices from administrative systems.
- Monitor for unauthorized access points, unexpected association patterns, and authentication failures.
- Use a controlled lab to study attack behavior; do not capture third-party traffic or induce client disconnections.


---

## Social Engineering

### Phishing Techniques

#### Email Phishing
- **Spear Phishing**: Targeted at specific individuals
- **Whaling**: Targeting high-profile executives
- **Clone Phishing**: Legitimate email replicated with malicious link

#### Phishing Tools
```bash
# SET (Social Engineering Toolkit)
setoolkit

# Gophish
gophish

# King Phisher
king-phisher
```

### Pretexting
- Creating fabricated scenario
- Building trust with target
- Extracting sensitive information

### Baiting
- Offering something enticing
- Infected USB drives
- Free software downloads

### Tailgating/Piggybacking
- Following authorized person through secure entry
- Social manipulation
- Physical security bypass

### Phone-Based Attacks (Vishing)
- Voice phishing
- Caller ID spoofing
- Impersonation

### SMS Phishing (Smishing)
- Text message attacks
- Malicious links
- Urgent requests

### Defense Against Social Engineering
1. **Awareness Training**: Regular security education
2. **Verification**: Always verify unusual requests
3. **Policies**: Clear security policies and procedures
4. **Technical Controls**: Email filtering, multi-factor authentication
5. **Reporting**: Encourage reporting of suspicious activity

---

## Cryptography Essentials

### Encryption Types

#### Symmetric Encryption
- Same key for encryption and decryption
- **Algorithms**: AES, DES, 3DES, Blowfish, RC4
- **Pros**: Fast, efficient for large data
- **Cons**: Key distribution problem

#### Asymmetric Encryption
- Public and private key pair
- **Algorithms**: RSA, ECC, ElGamal, DSA
- **Pros**: Secure key exchange
- **Cons**: Slower than symmetric

### Hash Functions
- One-way functions
- Fixed-length output
- **Algorithms**: MD5, SHA-1, SHA-256, SHA-512, NTLM

#### Hash Characteristics
- **Deterministic**: Same input = same output
- **Collision Resistant**: Hard to find two inputs with same hash
- **Pre-image Resistant**: Can't derive input from hash
- **Avalanche Effect**: Small input change drastically changes hash

### Digital Signatures
```
Message → Hash → Encrypt with Private Key → Digital Signature
Verify → Decrypt with Public Key → Compare Hashes
```

### SSL/TLS
- **SSL**: Secure Sockets Layer (deprecated)
- **TLS**: Transport Layer Security (current standard)
- Versions: TLS 1.0, 1.1 (deprecated), 1.2, 1.3 (recommended)

#### SSL/TLS Testing
```bash
# Test SSL/TLS
sslscan target.com
testssl.sh target.com
nmap --script ssl-enum-ciphers target.com
```

### PKI (Public Key Infrastructure)
- **Certificate Authority (CA)**: Issues certificates
- **Registration Authority (RA)**: Verifies certificate requests
- **Certificate Revocation List (CRL)**: List of revoked certificates
- **OCSP**: Online Certificate Status Protocol

### Steganography
- Hiding data within other data
- **Tools**: steghide, OpenStego, SteganoShark

```bash
# Hide data
steghide embed -cf image.jpg -ef secret.txt

# Extract data
steghide extract -sf image.jpg
```

### Classical Ciphers & Encodings
- Caesar/ROT13, Atbash, Vigenère, Playfair, Morse, Baconian, Polybius, leetspeak and Unicode look-alikes
- Common in CTFs and OSINT; **none are secure** for real data
- Charts, cryptanalysis (frequency analysis, Kasiski, Index of Coincidence) and a Python toolkit: [Cryptography/Classical/](./Cryptography/Classical/)

---

## Digital Forensics

### Digital Forensics Principles
1. **Minimize Data Loss**: Preserve original evidence
2. **Record Everything**: Document all actions
3. **Analyze Without Modification**: Use write blockers
4. **Report Findings**: Comprehensive documentation
5. **Chain of Custody**: Maintain evidence integrity

### Types of Forensics
- **Computer Forensics**: PCs, laptops, servers
- **Mobile Forensics**: Smartphones, tablets
- **Network Forensics**: Traffic analysis, intrusion detection
- **Memory Forensics**: RAM analysis
- **Cloud Forensics**: Cloud infrastructure and services

### Forensics Process

#### 1. Identification
- Identify digital evidence
- Determine scope
- Legal considerations

#### 2. Preservation
```bash
# Create forensic image
dd if=/dev/sda of=image.dd bs=4M
dcfldd if=/dev/sda of=image.dd hash=md5 hashlog=hash.txt

# Verify integrity
md5sum image.dd
sha256sum image.dd
```

#### 3. Collection
- Acquire volatile data first (RAM, running processes)
- Then non-volatile data (hard drives, USB)
- Use write blockers

#### 4. Analysis
```bash
# File system analysis
autopsy
sleuthkit

# Memory analysis
volatility -f memory.dump imageinfo
volatility -f memory.dump --profile=Win10x64 pslist
volatility -f memory.dump --profile=Win10x64 netscan

# Log analysis
grep -r "pattern" /var/log/
```

#### 5. Documentation
- Timeline creation
- Chain of custody forms
- Detailed reports
- Screenshots and evidence photos

#### 6. Presentation
- Clear, non-technical language
- Visual aids
- Expert testimony preparation

### Forensics Tools
```bash
# Disk imaging
dd, dcfldd, FTK Imager

# Analysis
Autopsy, EnCase, FTK, X-Ways

# Memory forensics
Volatility, Rekall

# Network forensics
Wireshark, NetworkMiner, tcpdump

# Mobile forensics
Cellebrite, Oxygen Forensics
```

### Incident Response
```bash
# Volatile data collection order
1. Network connections: netstat -ano
2. Logged-in users: who, w
3. Running processes: ps aux, tasklist
4. Open files: lsof
5. System information: systeminfo, uname -a
6. Memory dump: FTK Imager, winpmem
7. Disk image: dd, dcfldd
```

### Anti-Forensics Techniques (Be Aware Of)
- **Data Wiping**: Secure deletion tools
- **Encryption**: Full disk encryption
- **Steganography**: Hiding data
- **Log Manipulation**: Clearing or modifying logs
- **Timestamp Manipulation**: Changing file times
- **Obfuscation**: Making analysis difficult

---

## Penetration Testing Methodology

### Planning & Scoping
1. **Define Objectives**: What are we testing?
2. **Scope**: IP ranges, domains, systems in/out of scope
3. **Rules of Engagement**: Testing windows, contacts, constraints
4. **Legal Documentation**: Contracts, authorization letters, NDAs

### Information Gathering (Reconnaissance)
- Passive reconnaissance
- Active reconnaissance
- OSINT gathering
- Social media profiling
- DNS enumeration
- Subdomain discovery

### Threat Modeling
- Identify assets
- Determine threats
- Assess vulnerabilities
- Prioritize risks

### Vulnerability Analysis
```bash
# Automated scanners
nessus
openvas
nexpose

# Manual testing
nmap scripts
custom checks
configuration review
```

### Exploitation
- Verify vulnerabilities
- Gain initial access
- Exploit carefully (avoid damage)
- Document all exploits

### Post-Exploitation
- Privilege escalation
- Lateral movement
- Data exfiltration simulation
- Persistence establishment
- Covering tracks (document, don't actually do)

### Reporting
#### Executive Summary
- High-level overview
- Business impact
- Key recommendations
- Risk ratings

#### Technical Details
- Vulnerability details
- Exploitation steps
- Screenshots/evidence
- Remediation steps
- CVSS scores

#### Appendices
- Detailed findings
- Tool outputs
- Raw data
- Methodology

### Report Sections
1. **Introduction**: Scope, methodology, limitations
2. **Executive Summary**: High-level findings
3. **Technical Findings**: Detailed vulnerabilities
4. **Risk Assessment**: Severity ratings
5. **Recommendations**: Prioritized remediation steps
6. **Conclusion**: Summary and next steps

### Severity Ratings
- **Critical**: Immediate threat, easy to exploit
- **High**: Significant risk, moderate difficulty
- **Medium**: Moderate risk, some skill required
- **Low**: Minimal risk, difficult to exploit
- **Informational**: No immediate risk, best practices

---

## OSCP Preparation

### Exam Overview
- **Duration**: 23 hours 45 minutes
- **Format**: 5 machines to compromise
- **Passing**: 70 points minimum
- **Report**: 24 hours after exam ends

### Point Distribution
- **10 points**: Buffer overflow machine
- **25 points**: Two machines (usually)
- **20 points**: Two machines (usually)
- **Total**: 100 points possible

### Key Skills Required

#### Enumeration
- Port scanning (Nmap)
- Web enumeration (Gobuster, Nikto)
- Service enumeration (SMB, FTP, etc.)
- Always enumerate thoroughly

#### Exploitation
- Web application vulnerabilities
- Buffer overflow (mandatory 25 points)
- Privilege escalation (Windows & Linux)
- Password attacks

#### Buffer Overflow
```python
# Basic structure
1. Fuzzing - crash the application
2. Control EIP - find offset
3. Bad characters - identify
4. Find JMP ESP - use mona.py
5. Generate shellcode - msfvenom
6. Exploit - execute payload
```

#### Privilege Escalation
```bash
# Linux
- SUID binaries
- Sudo misconfigurations
- Kernel exploits
- Cron jobs
- PATH hijacking

# Windows
- Unquoted service paths
- Weak file permissions
- AlwaysInstallElevated
- Stored credentials
- Token impersonation
```

### Study Resources
1. **PWK Course Material**: Primary resource
2. **TJ Null's OSCP List**: Practice boxes on HTB/VulnHub
3. **IppSec Videos**: Walkthroughs and techniques
4. **Forums**: Reddit r/oscp, OSCP Discord

### Practice Platforms
- **HackTheBox**: Similar to OSCP machines
- **VulnHub**: Free vulnerable VMs
- **Proving Grounds**: OffSec's practice platform
- **TryHackMe**: Guided learning paths

### Exam Tips
1. **Read Carefully**: Follow all exam restrictions
2. **Document Everything**: Screenshots, commands, timestamps
3. **Time Management**: Don't get stuck on one machine
4. **Buffer Overflow First**: Easy 25 points
5. **Try Harder**: Enumerate more when stuck
6. **Take Breaks**: Stay fresh and focused
7. **Report Quality**: Clear, professional documentation

### Reporting Requirements
- Screenshots with IP addresses and timestamps
- Step-by-step exploitation process
- Proof.txt contents (screenshots)
- Code snippets used
- Professional formatting

### Common Mistakes to Avoid
- **Insufficient enumeration**: Always enumerate more
- **Rabbit holes**: Know when to move on
- **Poor documentation**: Screenshot everything
- **Time mismanagement**: Budget time wisely
- **Not reading restrictions**: Follow all rules
- **Skipping buffer overflow**: Free 25 points

---

## Quick Reference: Defensive Host Checks

Run local checks only on systems you administer. These commands display host configuration; they do not scan or change remote systems.

### Windows

    # Show IP and DNS configuration
    Get-NetIPConfiguration

    # Review firewall profile state
    Get-NetFirewallProfile | Select-Object Name, Enabled, DefaultInboundAction, DefaultOutboundAction

    # Review Defender real-time protection status
    Get-MpComputerStatus | Select-Object AMServiceEnabled, AntivirusEnabled, RealTimeProtectionEnabled

### Linux

    # Show local addresses and routes
    ip address
    ip route

    # Show listening sockets and owning processes (requires appropriate privileges)
    ss -lntup

    # Review recent warning-level system events
    journalctl --since "1 hour ago" --priority warning

### Evidence and escalation

Preserve relevant logs, timestamps, and system identifiers. Follow the incident-response plan for containment and evidence handling. Do not clear logs, disable protections, or transfer data to personal storage as a troubleshooting shortcut.


---

## Conclusion

This comprehensive guide covers the essential topics in cybersecurity and penetration testing. Remember:

1. **Always Have Authorization**: Never test without explicit written permission
2. **Document Everything**: Thorough documentation is crucial
3. **Continuous Learning**: Stay updated with latest vulnerabilities and techniques
4. **Practice Legally**: Use authorized platforms like HTB, TryHackMe, OSCP labs
5. **Ethical Responsibility**: Use skills to protect, not harm

### Next Steps
- Set up your own lab environment
- Practice on CTF platforms
- Join cybersecurity communities
- Pursue certifications (OSCP, CEH, Security+)
- Stay current with security news and advisories

### Resources
- **OWASP**: https://owasp.org
- **MITRE ATT&CK**: https://attack.mitre.org
- **HackTricks**: https://hacktricks.wiki/en
- **PayloadsAllTheThings**: GitHub repository
- **GTFOBins**: https://gtfobins.org
- **LOLBAS**: Living Off The Land Binaries and Scripts

---

*Remember: With great power comes great responsibility. Always use these skills ethically and legally.*

## Related Files
- [README.md](README.md) - Full repo index
- [ultimate_cybersecurity_master_guide.md](ultimate_cybersecurity_master_guide.md) - Full methodology context
- [Documentation/LinuxCheatSheet.md](Documentation/LinuxCheatSheet.md) - Linux commands context
- [Checklists index](Checklists/README.md) - Structured checklists for each phase

---
[⬅️ Back to Master Index](README.md) | [🎯 Role Navigation](START_HERE.md) | [Legal Notice](LEGAL.md)
