# 💻 Security Scripts & Tools

<div align="center">

**Collection of security automation scripts, exploitation tools, and utility programs**

*Part of the [ULTIMATE CYBERSECURITY MASTER GUIDE](../README.md)*

[![Bash](https://img.shields.io/badge/Bash-Scripts-green?style=for-the-badge&logo=gnu-bash)]()
[![PowerShell](https://img.shields.io/badge/PowerShell-Scripts-blue?style=for-the-badge&logo=powershell)]()
[![Python](https://img.shields.io/badge/Python-Scripts-yellow?style=for-the-badge&logo=python)]()
[![C](https://img.shields.io/badge/C-Programs-red?style=for-the-badge&logo=c)]()

</div>

---

## 📋 Table of Contents

- [Overview](#overview)
- [Script Categories](#script-categories)
- [Directory Structure](#directory-structure)
- [How to Use These Scripts](#how-to-use-these-scripts)
- [⚠️ CRITICAL Security & Legal Warning](#️-critical-security--legal-warning)
- [Contributing](#contributing)
- [Resources](#resources)

---

## 🎯 Overview

This directory contains **security automation scripts, penetration testing tools, and utility programs** written in multiple programming languages. These scripts are designed for authorized security testing, research, and educational purposes.

### 🔴 CRITICAL WARNING

```
⚠️ THESE ARE OFFENSIVE SECURITY TOOLS ⚠️

Many scripts in this collection are PENETRATION TESTING and EXPLOITATION tools.
Unauthorized use is a FEDERAL CRIME with severe penalties including imprisonment.

YOU MUST have explicit written authorization before running ANY of these scripts
against systems you do not own or have explicit permission to test.

Using these tools without authorization violates:
• Computer Fraud and Abuse Act (CFAA) - Up to 10 years imprisonment
• State computer crime laws
• International cybercrime laws
• Organizational policies
```

---

## 📂 Directory Structure

### Programming Language Categories

```
Scripts/
├── Bash/           # Bash shell scripts
├── C/              # C programs and utilities
├── GO/             # Go language scripts
├── PowerShell/     # PowerShell scripts (Windows)
├── Python/         # Python scripts and tools
├── SQL/            # SQL scripts and queries
└── YAML/           # YAML configuration files
```

---

## 🗂️ Script Categories

### 1. Bash Scripts

**Location**: `/Scripts/Bash/`

**Types of Scripts:**
- System administration automation
- Network reconnaissance tools
- Security auditing scripts
- Log analysis utilities
- Automated exploitation frameworks
- System enumeration tools

**Common Use Cases:**
- Linux/Unix system administration
- Automated security testing
- Log parsing and analysis
- System monitoring
- Security auditing

**Target Platforms:**
- Linux distributions
- Unix-based systems
- macOS
- WSL (Windows Subsystem for Linux)

---

### 2. C Programs

**Location**: `/Scripts/C/`

**Current Programs:**

| Program | Description | Purpose |
|---------|-------------|---------|
| **get_user.c** | User enumeration utility | System reconnaissance |
| **getuser.c** | User information retrieval | Privilege enumeration |
| **scanner.c** | Network or port scanner | Network reconnaissance |
| **system_sleep.c** | System sleep/suspend utility | System manipulation |
| **systemsleep.c** | System sleep implementation | Testing/manipulation |

**Characteristics:**
- Low-level system access
- High performance execution
- Direct system API calls
- Compiled executables
- Platform-specific implementations

**Security Considerations:**
```
⚠️ C programs have direct system access and can:
   • Access low-level system functions
   • Bypass security controls if misused
   • Cause system instability if buggy
   • Execute with elevated privileges
   • Directly manipulate memory and processes

MUST be compiled and tested in isolated environments before use.
```

---

### 3. PowerShell Scripts

**Location**: `/Scripts/PowerShell/`

**Current Scripts:**

| Script | Description | Risk Level |
|--------|-------------|------------|
| **adlogin.ps1** | Active Directory login/authentication testing | 🔴 HIGH |
| **cred_hunt.ps1** | Credential hunting and discovery | 🔴 HIGH |
| **localbrute.ps1** | Local account brute force tool | 🔴 HIGH |
| **localbrute-extra-mini.ps1** | Compact local brute force variant | 🔴 HIGH |
| **port-scan-tcp.ps1** | TCP port scanning utility | 🟡 MEDIUM |
| **port-scan-tcp-compat.ps1** | Compatible TCP port scanner | 🟡 MEDIUM |
| **port-scan-udp.ps1** | UDP port scanning utility | 🟡 MEDIUM |
| **port_scanner.ps1** | General purpose port scanner | 🟡 MEDIUM |
| **rev_shell.ps1** | Reverse shell utility | 🔴 HIGH |
| **smblogin.ps1** | SMB authentication testing | 🔴 HIGH |
| **smblogin-extra-mini.ps1** | Compact SMB login tester | 🔴 HIGH |
| **system_enum.ps1** | System enumeration script | 🟡 MEDIUM |

**Capabilities:**
- Active Directory security testing
- Credential access and testing
- Network reconnaissance
- Windows system enumeration
- SMB/CIFS protocol testing
- Remote access establishment

**Quick-reference checklists these scripts support:** [Active Directory](../Checklists/ActiveDirectory.md) · [Credential Access](../Checklists/Credential-Access.md) · [Windows Privilege Escalation](../Checklists/Windows-Privilege-Escalation.md)

**Security Considerations:**
```
⚠️ CRITICAL: These PowerShell scripts include:
   • Credential harvesting tools (ILLEGAL without authorization)
   • Brute force attack scripts (ILLEGAL without authorization)
   • Reverse shell utilities (ILLEGAL without authorization)
   • Authentication bypass techniques

Using these scripts without explicit written authorization is a FEDERAL CRIME
under the Computer Fraud and Abuse Act (18 U.S.C. § 1030).

PENALTIES: Up to 10 years imprisonment + significant fines
```

---

### 4. Python Scripts

**Location**: `/Scripts/Python/`

**Current Scripts:**

#### Network & Reconnaissance
| Script | Description | Risk Level |
|--------|-------------|------------|
| **port_scan.py** | Port scanning utility | 🟡 MEDIUM |
| **port_scanner.py** | Network port scanner | 🟡 MEDIUM |
| **perm_scan.py** | Permission scanning tool | 🟡 MEDIUM |
| **perm_scan5.py** | Permission scanner v5 | 🟡 MEDIUM |
| **discover_network.py** | Network discovery tool | 🟡 MEDIUM |
| **network_attack.py** | Network attack framework | 🔴 HIGH |
| **proxy_test.py** | Proxy testing utility | 🟢 LOW |

#### Credential & Authentication
| Script | Description | Risk Level |
|--------|-------------|------------|
| **credit_sniff.py** | Credit card data sniffer | 🔴 HIGH |
| **password_check.py** | Password validation/testing | 🟡 MEDIUM |
| **cred_sniff.py** | Credential sniffing tool | 🔴 HIGH |
| **ftp_sniff.py** | FTP credential sniffer | 🔴 HIGH |

#### Bluetooth & Wireless
| Script | Description | Risk Level |
|--------|-------------|------------|
| **bt-find.py** | Bluetooth device discovery | 🟡 MEDIUM |
| **bt_scan.py** | Bluetooth scanning utility | 🟡 MEDIUM |
| **blue_bug.py** | Bluetooth exploitation tool | 🔴 HIGH |

#### Exploitation & Attack Tools
| Script | Description | Risk Level |
|--------|-------------|------------|
| **bsodshell.py** | Blue Screen of Death exploit | 🔴 HIGH |
| **conficker.py** | Conficker worm-related tool | 🔴 HIGH |
| **dll_inject.py** | DLL injection utility | 🔴 HIGH |
| **evil_batch.py** | Malicious batch generator | 🔴 HIGH |
| **find_ddos.py** | DDoS detection/analysis | 🟡 MEDIUM |
| **rev_shell.py** | Reverse shell utility | 🔴 HIGH |

#### Web & Application Security
| Script | Description | Risk Level |
|--------|-------------|------------|
| **python-webshell-check.py** | Webshell detection tool | 🟡 MEDIUM |
| **firefox_parser.py** | Firefox data parser | 🟡 MEDIUM |
| **imap_parser.py** | IMAP protocol parser | 🟡 MEDIUM |
| **link_parser.py** | Link extraction tool | 🟢 LOW |
| **print_cookies.py** | Cookie extraction utility | 🟡 MEDIUM |

#### Geolocation & Tracking
| Script | Description | Risk Level |
|--------|-------------|------------|
| **geo.py** | Geolocation utility | 🟢 LOW |
| **geo_paint.py** | Geolocation visualization | 🟢 LOW |
| **google_earth_pcap.py** | PCAP to Google Earth | 🟡 MEDIUM |
| **google_json.py** | Google JSON parser | 🟢 LOW |
| **google_jsonlist.py** | Google JSON list parser | 🟢 LOW |
| **google_sniff.py** | Google traffic sniffer | 🟡 MEDIUM |

#### Mobile Device
| Script | Description | Risk Level |
|--------|-------------|------------|
| **iphone_finder.py** | iPhone device discovery | 🟡 MEDIUM |
| **iphone_messages.py** | iPhone message extraction | 🔴 HIGH |

#### Specialized Tools
| Script | Description | Risk Level |
|--------|-------------|------------|
| **hotel_sniff.py** | Hotel network sniffer | 🔴 HIGH |
| **ics_find.py** | Industrial Control System finder | 🔴 HIGH |
| **kitten_test.py** | Testing utility | 🟢 LOW |
| **dup.py** | Duplicate file finder | 🟢 LOW |
| **dump_nmdbs.py** | Database dumping tool | 🔴 HIGH |
| **pdfs_paint.py** | PDF visualization | 🟢 LOW |
| **print_direction.py** | Direction printing utility | 🟢 LOW |

#### Supporting Files
| File | Description |
|------|-------------|
| **pass.txt** | Password list/dictionary |
| **passout.txt** | Password output file |
| **nnb-cities.txt** | Cities database |

**Python Script Characteristics:**
- Extensive network security tools
- Credential harvesting capabilities
- Exploitation frameworks
- Protocol analysis utilities
- Data exfiltration tools
- Reconnaissance utilities

**Security Considerations:**
```
⚠️ EXTREME CAUTION: Python scripts include:
   • Credential sniffers (credit_sniff.py, cred_sniff.py, ftp_sniff.py)
   • Network attack tools (network_attack.py)
   • Exploitation utilities (dll_inject.py, bsodshell.py)
   • Data exfiltration tools (iphone_messages.py, dump_nmdbs.py)
   • Reverse shells (rev_shell.py)
   • ICS/SCADA targeting tools (ics_find.py)

These tools can cause:
   ✗ Unauthorized access (federal crime)
   ✗ Data theft (federal and state crimes)
   ✗ Privacy violations (civil and criminal liability)
   ✗ Network disruption (federal crime)
   ✗ System compromise (federal crime)
   ✗ Critical infrastructure attacks (terrorism charges possible)

USING WITHOUT AUTHORIZATION = FEDERAL PRISON TIME
```

---

### 5. SQL Scripts

**Location**: `/Scripts/SQL/`

**Current Scripts:**

| Script | Description | Risk Level |
|--------|-------------|------------|
| **add_wordpress_admin.sql** | WordPress admin account creation | 🔴 HIGH |
| **wordpress_add_admin.sql** | WordPress admin injection | 🔴 HIGH |

**Purpose:**
- Database manipulation
- WordPress security testing
- Privilege escalation testing
- Database access testing

**Security Considerations:**
```
⚠️ WARNING: SQL Scripts for unauthorized database access
   • Creating admin accounts without authorization is ILLEGAL
   • Database manipulation without permission violates CFAA
   • Unauthorized privilege escalation is a federal crime

ONLY use on systems you own or have explicit written permission to test.
```

---

### 6. YAML Configuration Files

**Location**: `/Scripts/YAML/`

**Purpose:**
- Script configuration files
- Automation playbook definitions
- Tool settings and parameters
- Environment configurations

---

## 📖 How to Use These Scripts

### ⚠️ BEFORE RUNNING ANY SCRIPT

```
MANDATORY CHECKLIST:

☐ Do I OWN the target system?
☐ Do I have WRITTEN authorization to test?
☐ Is the authorization CURRENT and VALID?
☐ Does authorization SPECIFICALLY cover these scripts/techniques?
☐ Have I verified the script won't cause harm?
☐ Do I have rollback/recovery procedures?
☐ Have I tested in an isolated environment first?
☐ Am I prepared to document all activities?
☐ Do I have emergency contacts ready?
☐ Have I reviewed applicable laws and policies?

If you answered NO to ANY question: DO NOT RUN THE SCRIPT
```

### For Security Professionals

```
Authorized Testing Workflow:

1. Authorization Phase:
   └─> Obtain written authorization
   └─> Verify scope includes script usage
   └─> Document authorization details
   └─> Prepare testing environment
   └─> Review scripts before execution

2. Preparation Phase:
   └─> Test scripts in isolated lab first
   └─> Understand exactly what each script does
   └─> Prepare monitoring and logging
   └─> Have rollback procedures ready
   └─> Coordinate with stakeholders

3. Execution Phase:
   └─> Follow authorized scope strictly
   └─> Document all commands and outputs
   └─> Monitor system impact continuously
   └─> Stop immediately if issues occur
   └─> Maintain communication with client

4. Post-Execution Phase:
   └─> Document findings thoroughly
   └─> Provide detailed activity logs
   └─> Recommend remediations
   └─> Secure/delete sensitive data
   └─> Archive documentation properly
```

### For Students & Learners

```
Safe Learning Environments ONLY:

✅ AUTHORIZED Learning:
   • Personal virtual machines YOU created
   • Home lab equipment YOU own
   • University/school labs WITH permission
   • Authorized CTF platforms (HackTheBox, TryHackMe)
   • Bug bounty programs WITHIN scope
   • Dedicated training environments

🚫 NEVER Test On:
   • School/work production systems
   • Your employer's network without written approval
   • Friends' or family members' systems
   • Public WiFi or networks
   • Cloud services without explicit permission
   • Any system you don't own or lack written authorization for
```

### Script Usage Guidelines

#### PowerShell Scripts

```powershell
# EXAMPLE: Running in authorized test environment

# 1. Verify authorization
Get-Content authorization.txt

# 2. Set execution policy (if needed)
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass

# 3. Run script with appropriate parameters
.\script.ps1 -Target "authorized-target.local" -Output "results.txt"

# 4. Document results
Get-Content results.txt | Out-File -FilePath "assessment-report.txt" -Append
```

#### Python Scripts

```python
# EXAMPLE: Running network scanner in authorized environment

# 1. Verify you have authorization
# 2. Activate virtual environment (recommended)
python -m venv venv
source venv/bin/activate  # Linux/Mac
venv\Scripts\activate      # Windows

# 3. Install dependencies
pip install -r requirements.txt

# 4. Run script against authorized target only
python port_scanner.py --target 192.168.1.100 --output scan_results.txt

# 5. Document and secure results
```

#### Bash Scripts

```bash
# EXAMPLE: Running reconnaissance script

# 1. Review script contents first
cat script.sh

# 2. Make executable
chmod +x script.sh

# 3. Run with proper parameters
./script.sh --target authorized-system.local --output results.txt

# 4. Review and document results
cat results.txt
```

---

## ⚠️ CRITICAL Security & Legal Warning

### 🔴 FEDERAL CRIME WARNING

```
═══════════════════════════════════════════════════════════════
                    ⚠️ CRITICAL LEGAL WARNING ⚠️
═══════════════════════════════════════════════════════════════

These scripts contain OFFENSIVE SECURITY TOOLS including:
   • Credential harvesting and theft tools
   • Brute force attack utilities
   • Reverse shells and backdoors
   • Network attack frameworks
   • Exploitation utilities
   • Data exfiltration tools
   • System manipulation programs

USING THESE TOOLS WITHOUT AUTHORIZATION IS A FEDERAL CRIME

Computer Fraud and Abuse Act (18 U.S.C. § 1030)
   ► Unauthorized Access: Up to 10 years imprisonment
   ► Repeat Offense: Up to 20 years imprisonment
   ► Damage Exceeding $5,000: Enhanced penalties
   ► Critical Infrastructure: Terrorism charges possible

Additional Federal Laws:
   • Wire Fraud Act (18 U.S.C. § 1343)
   • Electronic Communications Privacy Act (18 U.S.C. § 2510)
   • Identity Theft and Assumption Deterrence Act
   • Stored Communications Act

State Laws:
   • All 50 states have computer crime statutes
   • Penalties vary by state but often include imprisonment
   • Civil liability in addition to criminal charges

International Laws:
   • UK Computer Misuse Act 1990
   • EU Cybercrime Directive
   • Council of Europe Convention on Cybercrime
   • Varies by jurisdiction

═══════════════════════════════════════════════════════════════
```

### Script-Specific Legal Warnings

#### Credential Harvesting Tools

```
🔴 FEDERAL CRIME: Credential Theft & Unauthorized Access

Scripts: cred_hunt.ps1, credit_sniff.py, cred_sniff.py, ftp_sniff.py

ILLEGAL ACTIVITIES:
   • Capturing credentials without authorization
   • Using captured credentials to access systems
   • Trafficking in stolen passwords
   • Accessing accounts you don't own

LAWS VIOLATED:
   • Computer Fraud and Abuse Act (CFAA)
   • Identity Theft Act
   • Wire Fraud Act
   • State computer crime laws

PENALTIES:
   • 5-15 years imprisonment PER OFFENSE
   • Fines up to $250,000 or more
   • Restitution to victims
   • Asset forfeiture
   • Civil lawsuits

AUTHORIZED USE ONLY:
   ✓ Written authorization from system owner
   ✓ Test accounts created specifically for testing
   ✓ Isolated test environment
   ✓ Immediate secure deletion of captured data post-test
```

#### Brute Force Attack Tools

```
🔴 FEDERAL CRIME: Unauthorized Access Attempts

Scripts: localbrute.ps1, smblogin.ps1, password_check.py

ILLEGAL ACTIVITIES:
   • Brute forcing authentication without permission
   • Attempting unauthorized login
   • Password guessing against live systems
   • Account enumeration without authorization

LAWS VIOLATED:
   • Computer Fraud and Abuse Act
   • Exceeding authorized access provisions
   • State computer trespass laws

PENALTIES:
   • Up to 10 years imprisonment
   • Fines and restitution
   • Civil liability for damages
   • Account lockouts may cause business disruption (aggravating factor)
```

#### Reverse Shell & Remote Access Tools

```
🔴 FEDERAL CRIME: Unauthorized Remote Access

Scripts: rev_shell.ps1, rev_shell.py

ILLEGAL ACTIVITIES:
   • Installing backdoors without authorization
   • Establishing command and control without permission
   • Maintaining unauthorized access
   • Creating persistent access without consent

LAWS VIOLATED:
   • Computer Fraud and Abuse Act
   • Wire Fraud Act (using communications networks)
   • Potentially terrorism statutes for critical infrastructure

PENALTIES:
   • 10-20 years imprisonment
   • Enhanced penalties for critical infrastructure
   • Terrorism charges possible in extreme cases
   • Lifetime supervised release possible
```

#### Network Attack Tools

```
🔴 FEDERAL CRIME: Network Attacks & Disruption

Scripts: network_attack.py, find_ddos.py, bsodshell.py

ILLEGAL ACTIVITIES:
   • Conducting denial of service attacks
   • Network disruption or degradation
   • Causing system crashes
   • Interfering with authorized use

LAWS VIOLATED:
   • Computer Fraud and Abuse Act (damage provisions)
   • State laws against computer tampering
   • Potentially terrorism laws for critical infrastructure

PENALTIES:
   • 10-20 years imprisonment
   • Massive fines (proportional to damage caused)
   • Restitution for business losses
   • Enhanced penalties for critical infrastructure targets
```

#### Data Exfiltration Tools

```
🔴 FEDERAL CRIME: Data Theft & Exfiltration

Scripts: dump_nmdbs.py, iphone_messages.py, print_cookies.py

ILLEGAL ACTIVITIES:
   • Stealing data from systems without authorization
   • Accessing private communications
   • Extracting sensitive information
   • Violating privacy protections

LAWS VIOLATED:
   • Computer Fraud and Abuse Act
   • Stored Communications Act
   • Electronic Communications Privacy Act
   • GDPR (if EU data involved)
   • CCPA (if California data involved)
   • HIPAA (if healthcare data)

PENALTIES:
   • 5-20 years imprisonment
   • Fines up to $250,000+
   • Civil liability under privacy laws
   • Regulatory fines (GDPR: up to 4% global revenue)
```

#### Industrial Control Systems (ICS/SCADA) Tools

```
🔴 EXTREME DANGER: Critical Infrastructure Attacks

Scripts: ics_find.py

ILLEGAL ACTIVITIES:
   • Targeting industrial control systems
   • Attacking critical infrastructure
   • Potentially causing physical harm
   • Endangering public safety

LAWS VIOLATED:
   • Computer Fraud and Abuse Act (enhanced provisions)
   • Critical Infrastructure Protection Act
   • Potentially terrorism statutes
   • Endangerment laws if physical harm results

PENALTIES:
   • 20+ years to LIFE imprisonment
   • Terrorism charges and sentencing enhancements
   • Federal investigation by FBI, DHS, etc.
   • International prosecution possible
   • No statute of limitations for some offenses

⚠️ Attacking critical infrastructure can be prosecuted as TERRORISM
```

---

### Authorization Requirements

#### What Constitutes Valid Authorization?

```
✅ VALID AUTHORIZATION Must Include:

1. Written Documentation:
   □ Signed letter or contract
   □ From person with authority to grant permission
   □ On official letterhead (if corporate)
   □ Dated and current

2. Explicit Scope:
   □ Specific systems, IPs, and networks listed
   □ Specific scripts/techniques authorized
   □ Time windows defined
   □ Out-of-scope items explicitly noted

3. Legal Protection:
   □ Indemnification clause
   □ Liability limitations
   □ Rules of engagement
   □ Incident response procedures
   □ Data handling requirements

4. Contact Information:
   □ Primary contact
   □ Emergency contact (24/7)
   □ Escalation procedures
   □ Legal contact if needed

5. Deliverables:
   □ Reporting requirements
   □ Documentation standards
   □ Timeline for delivery
   □ Confidentiality agreements

🚫 NOT Valid Authorization:
   ✗ Verbal permission only
   ✗ Email without formal agreement
   ✗ "Go ahead and test" messages
   ✗ Implicit permission
   ✗ After-the-fact approval
   ✗ Permission from someone without authority
   ✗ Expired or outdated authorization
```

---

### Risk Considerations

#### Technical Risks

**Running These Scripts Can Cause:**
- System crashes and instability
- Network congestion or outages
- Data corruption or loss
- Account lockouts
- Service disruption
- Detection and blocking by security systems
- Triggering of incident response
- Legal investigation

#### Legal Risks

**Unauthorized Use Results In:**
- Federal criminal charges (CFAA violations)
- State criminal charges
- International prosecution
- Civil lawsuits for damages
- Professional license revocation
- Employment termination
- Industry blacklisting
- Inability to work in technology field
- Criminal record
- Imprisonment

#### Professional Risks

**Career Consequences:**
- Loss of security certifications
- Professional reputation damage
- Termination from current employment
- Inability to pass background checks
- Exclusion from security industry
- Civil judgments affecting finances
- Legal defense costs

---

### Safe Usage Guidelines

#### Create Isolated Test Environment

```
Recommended Lab Setup:

1. Virtualization:
   └─> VMware Workstation/Fusion
   └─> VirtualBox
   └─> Proxmox
   └─> Hyper-V

2. Network Isolation:
   └─> Use host-only or internal networks
   └─> NO internet connectivity for test VMs
   └─> Separate physical network if possible
   └─> Firewall rules preventing external access

3. Target Systems:
   └─> Intentionally vulnerable VMs (Metasploitable, DVWA)
   └─> Your own purpose-built test systems
   └─> CTF platform environments
   └─> Cloud-based lab subscriptions (HTB, THM)

4. Snapshots & Backups:
   └─> Snapshot before testing
   └─> Easy rollback if issues occur
   └─> Keep clean baseline snapshots
   └─> Regular backups of configurations
```

#### Professional Testing Protocol

```
Professional Security Testing Checklist:

Pre-Test:
   ☐ Written authorization obtained and verified
   ☐ Scope reviewed and confirmed with client
   ☐ Scripts tested in isolated lab first
   ☐ Backup and rollback procedures prepared
   ☐ Monitoring and logging configured
   ☐ Emergency contacts documented
   ☐ Insurance coverage verified (E&O policy)
   ☐ Team briefed on scope and procedures

During Test:
   ☐ Follow authorized scope strictly
   ☐ Document every action with timestamp
   ☐ Monitor system health continuously
   ☐ Communicate status to stakeholders
   ☐ Stop immediately if unauthorized scope detected
   ☐ Report critical findings promptly
   ☐ Maintain evidence chain of custody

Post-Test:
   ☐ Compile comprehensive report
   ☐ Provide detailed activity logs
   ☐ Recommend prioritized remediation
   ☐ Securely delete sensitive captured data
   ☐ Archive project documentation
   ☐ Conduct post-engagement review
   ☐ Update methodology based on lessons learned
```

---

### Warranty Disclaimer

```
═══════════════════════════════════════════════════════════════
                    ⚠️ DISCLAIMER OF WARRANTIES ⚠️
═══════════════════════════════════════════════════════════════

These security scripts are provided "AS IS" WITHOUT WARRANTY of any kind,
either expressed or implied, including but not limited to:

• Warranties of accuracy, completeness, or functionality
• Warranties of non-malicious behavior
• Warranties of compatibility or portability
• Warranties of fitness for any particular purpose
• Warranties of legal compliance
• Warranties of safety or non-disruption

THE AUTHORS, CONTRIBUTORS, AND MAINTAINERS:

✗ Make NO guarantees about script functionality or safety
✗ Are NOT responsible for any damages caused by script use
✗ Do NOT warrant scripts are free from bugs or vulnerabilities
✗ Are NOT liable for any legal consequences of misuse
✗ Do NOT provide support for illegal activities
✗ May modify or remove scripts without notice
✗ Disclaim ALL liability for unauthorized use

USERS EXPLICITLY ACKNOWLEDGE AND AGREE:

► They use these scripts entirely at their own risk
► They are solely responsible for obtaining proper authorization
► They must comply with ALL applicable laws and regulations
► They are liable for ALL consequences of script execution
► They understand these are OFFENSIVE SECURITY TOOLS
► They accept that unauthorized use is a FEDERAL CRIME
► They waive any claims against authors/contributors
► They will defend and indemnify authors from any claims

═══════════════════════════════════════════════════════════════
                    ⚠️ CRITICAL REMINDER ⚠️

These scripts contain PENETRATION TESTING and EXPLOITATION tools.

Unauthorized use will result in:
   ✗ Federal criminal charges
   ✗ State criminal charges  
   ✗ Imprisonment (5-20+ years)
   ✗ Massive fines
   ✗ Civil lawsuits
   ✗ Career destruction
   ✗ Criminal record

ALWAYS obtain explicit written authorization before use.

═══════════════════════════════════════════════════════════════
```

---

## 🤝 Contributing

### Contributing Scripts

We welcome contributions from security professionals, but all scripts must meet strict quality and ethical standards.

#### Contribution Guidelines

**To Submit Scripts:**
1. Fork the repository
2. Add scripts to appropriate language directory
3. Include comprehensive documentation
4. Add explicit legal warnings and usage requirements
5. Test thoroughly in isolated environment
6. Ensure code is clean, commented, and professional
7. Submit pull request with detailed description

**Script Quality Standards:**
- ✅ Well-documented with clear comments
- ✅ Professional code quality and style
- ✅ Error handling and input validation
- ✅ Explicit authorization checks/warnings
- ✅ Logging and output formatting
- ✅ Usage instructions included
- ✅ Legal warnings prominent in code
- ✅ No hardcoded credentials or targets

#### What We Accept

**✅ Welcome Contributions:**
- Security automation tools for authorized testing
- Defensive security scripts (detection, monitoring)
- Educational security demonstrations
- Vulnerability scanners with proper warnings
- Security analysis utilities
- Forensics and incident response tools
- CTF and training utilities

**🚫 Will NOT Accept:**
- Malware or trojans
- Scripts designed solely for malicious use
- Exploits without educational/defensive value
- Tools targeting specific organizations
- Scripts with hardcoded targets
- Obfuscated malicious code
- Scripts violating any laws

---

## 📚 Resources

### Safe Learning Platforms

**Authorized Testing Environments:**
- **HackTheBox**: https://www.hackthebox.com/
- **TryHackMe**: https://tryhackme.com/
- **PentesterLab**: https://pentesterlab.com/
- **VulnHub**: https://www.vulnhub.com/
- **OverTheWire**: https://overthewire.org/
- **DVWA**: Damn Vulnerable Web Application
- **Metasploitable**: Intentionally vulnerable VM

### Legal Resources

**Understanding Computer Crime Laws:**
- **CFAA Text**: 18 U.S.C. § 1030
- **DOJ Computer Crime Manual**: https://www.justice.gov/criminal-ccips
- **EFF Cybersecurity**: https://www.eff.org/
- **SANS Acceptable Use Policy**: https://www.sans.org/information-security-policy/

### Professional Development

**Certifications:**
- **OSCP**: Offensive Security Certified Professional
- **CEH**: Certified Ethical Hacker
- **GPEN**: GIAC Penetration Tester
- **GWAPT**: GIAC Web Application Penetration Tester
- **eWPT**: eLearnSecurity Web Penetration Tester

**Training Resources:**
- **Offensive Security**: https://www.offsec.com/
- **SANS Institute**: https://www.sans.org/
- **eLearnSecurity**: https://ine.com/security
- **Cybrary**: https://www.cybrary.it/
- **Pluralsight**: Security training paths

---

## 🔗 Quick Links

### Internal Links
- [🏠 Main Repository](../README.md)
- [🎯 START HERE Guide](../START_HERE.md)
- [💻 Cybersecurity Master Guide](../ultimate_cybersecurity_master_guide.md)
- [🔍 OSINT Resources](../OSINT/README.md)
- [✅ Security Checklists](../Checklists/README.md)
- [📚 Documentation](../Documentation/README.md)
- [🔒 OPSEC Guidelines](../OPSEC/README.md)
- [📄 PDF Library](../PDF/README.md)
- [📘 Playbooks](../PlayBooks/README.md)

### External Resources
- [Offensive Security](https://www.offsec.com/)
- [OWASP](https://owasp.org)
- [NIST Cybersecurity](https://www.nist.gov/cyberframework)
- [SANS Institute](https://www.sans.org/)

---

## 📊 Repository Statistics

```
📁 Script Directories: 7 language categories
💻 Languages: Bash, C, Go, PowerShell, Python, SQL, YAML
🔧 Script Count: 50+ security tools and utilities
⚠️ Risk Level: HIGH - Offensive security tools
🔄 Last Updated: November 2024
👥 Maintained by: Pacific Northwest Computers (PNWC)
📝 Status: Active - Use with EXTREME CAUTION
```

---

## 🎓 Critical Reminders

### ALWAYS REMEMBER

```
1. AUTHORIZATION IS MANDATORY
   ✓ Written authorization required
   ✓ From person with authority to grant
   ✓ Explicitly covers scripts and scope
   ✓ Current and not expired

2. THESE ARE OFFENSIVE TOOLS
   ✓ Designed for penetration testing
   ✓ Can cause system damage
   ✓ Capable of unauthorized access
   ✓ Subject to strict legal regulations

3. LEGAL CONSEQUENCES ARE SEVERE
   ✓ Federal imprisonment (up to 20 years)
   ✓ Massive fines and restitution
   ✓ Civil lawsuits and liability
   ✓ Career-ending consequences

4. TEST SAFELY
   ✓ Use isolated lab environments
   ✓ Test on systems you own
   ✓ Never test production without approval
   ✓ Have rollback procedures ready

5. PROFESSIONAL STANDARDS
   ✓ Document everything
   ✓ Follow ethical guidelines
   ✓ Report responsibly
   ✓ Protect confidentiality
```

---

<div align="center">

**⚠️ USE THESE SCRIPTS RESPONSIBLY AND LEGALLY ⚠️**

*With great power comes great responsibility - and great legal liability.*

**Repository**: [ULTIMATE CYBERSECURITY MASTER GUIDE](https://github.com/Pnwcomputers/ULTIMATE-CYBERSECURITY-MASTER-GUIDE)

**Maintained by**: [Pacific Northwest Computers](https://github.com/Pnwcomputers)

---

🔴 **THESE ARE OFFENSIVE SECURITY TOOLS** 🔴

🔴 **UNAUTHORIZED USE = FEDERAL CRIME** 🔴

🔴 **UP TO 20 YEARS IMPRISONMENT** 🔴

🔴 **WRITTEN AUTHORIZATION MANDATORY** 🔴

---

⭐ **Star this repo if you find it useful (and use it legally!)** ⭐

</div>
