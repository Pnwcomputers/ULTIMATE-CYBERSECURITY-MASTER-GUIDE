> **Runtime status:** The [historical collection](GO/README.md) includes Python 2 examples and an unfinished Go sketch. Listing a script here does not certify that it runs on a current system.

The read-only [Windows Recycle Bin inventory](Python/dump_recyclebin.py) lists entries in
accessible SID folders on the system drive and reports an incomplete result if a folder
cannot be read. It lists storage filenames. Reading original paths and deletion times
requires a separate metadata parser. Use it on systems you are authorized to examine.

# 💻 Security Scripts & Tools
**Legacy script collection:** [Cypherpunk toolkit review](../Documentation/cypherpunk-pentesting-toolkit-review.md) provides safe source attribution and Python 2 → Python 3 modernization cautions. It does not add third-party executables or payloads.




**Documentation references:** [Curated technical docs](../Documentation/curated-technical-docs.md) links to GitHub Docs, Git tutorials, and Go by Example for script review and maintenance; prefer vendor docs for current syntax.

**Secret and dependency checks:** [OpenSSF Scorecard, Gitleaks, Syft and OSV supply-chain workflow](../ContainerSecurity/software-supply-chain-assessment.md) explains versioned inspection and evidence handling for the scripts collection; source code is not automatically safe because it is published.

| Resource | Description |
|---|---|
| [Bash Cheat Sheet](./Bash/bash_scripting_cheat-sheet.md) | Shell syntax and reusable patterns |
| [CLI Field Commands](../Documentation/devhints-cli-field-reference.md) | Everyday command-line reference |
| [Reviewed Reference Index](../Documentation/CHEATSHEET-REFERENCE-AUDIT-2026-10-31.md) | Cross-section cheat sheets |
| [Tool Pinning Policy](./PINNING.md) | Version and dependency controls |
| [Curated Rubber Ducky GitHub Projects](./Ducky/README.md#curated-github-payload-projects--popularity-compatibility--trust) | Popular official/community source libraries, GitHub popularity, firmware compatibility and code-review boundaries |
| [Curated Bash Bunny GitHub Projects](./Bash/BashBunny/README.md#curated-github-bash-bunny-payload-collections--compatibility) | Official/legacy repositories, archived-status checks, helper compatibility and lab review workflow |
| [Hak5 Payload Formats & Sideload Checks](../HardwareHacking/README.md#hak5-payload-ecosystem-official--side-loaded-code) | Cross-device Pager, Mark VII, Bash Bunny, Ducky, Shark Jack, Packet Squirrel and Key Croc runtime distinctions |
| [WiFi Pineapple Pager](../Wardriving/README.md#wifi-pineapple-pager--payloads-sideloading--defensive-labs) | User/Recon/Alert payloads, event handling, controlled installation and rollback |
| [Mark VII Campaign Examples](../Wardriving/README.md#optimized-mark-vii-setup--campaign-configuration) | Five monitored/restricted client wireless assessment runbooks |

Inspect provenance and source before running downloaded scripts.

> **Safer and retired examples:** `Python/app.py` and `Python/web_shell_inj.py`
> are loopback-only upload examples with attachment-only downloads; inspect the current source before use and do not expose the development server to a network.
> `Bash/fake_sudo.sh` exits without prompting for or transmitting a password.
> `Bash/hulkscanner.sh` requires an explicit authorization flag and limits checks to
> ports 1–1024 on one IPv4 address. `Bash/nuclei_web_scanner.sh` requires interactive
> scope confirmation, an explicitly selected local template, and a 5-request-per-second
> cap; it prints findings locally and sends no email.
>
> Additional retired and inert source files include `Bash/profile_hook.sh`, `Bash/web_shell_http_client.sh`, `Bash/BashBunny/cred_harv.txt`, `Bash/BashBunny/network_recon.txt`, `Bash/BashBunny/windows_exfil.txt`, `Ducky/exfil_windowsPC.txt`, and the credential, packet-sniffing, Bluetooth, private-message, process-injection, and password-testing files marked RETIRED below.
>
> Retired in place during the whole-repository review: `Bash/ssh_brute.sh`, `Bash/gnupg_brute.sh`, `Bash/local_user_brute.sh`, `Bash/keylogger.sh`, `Bash/hack-gmail.sh`, `Bash/get-wifi-pass.sh`, `Bash/rev_shell_state_mon.sh`, `Bash/port_hopper.sh`, `Bash/os_command_inj.sh`, `Bash/attack.sh`, `Bash/start-wlan.sh`, `Bash/start-capture.sh`, `Bash/fakemail.sh`, `Bash/admin-panel-sniffer.sh`, `Bash/arp-spoofing-detect.sh`, `Bash/network-monitor.sh`, `Bash/shodan-api.sh`, `Bash/xss-vulnerability-finder.sh`, and the credential-dumping, cookie-reading, shellcode, spam, and unbounded password-guessing Python/GO examples. These paths now contain inert notices; their former code is not present. See [the historical GO archive inventory](GO/ARCHIVE-INVENTORY.md) for per-file dispositions.

<div align="center">

**Curated index of security-related scripts and retired source stubs**

*Part of the [ULTIMATE CYBERSECURITY MASTER GUIDE](../README.md)*

![Bash](https://img.shields.io/badge/Bash-Scripts-green?style=for-the-badge&logo=gnu-bash)
![PowerShell](https://img.shields.io/badge/PowerShell-Scripts-blue?style=for-the-badge&logo=powershell)
![Python](https://img.shields.io/badge/Python-Scripts-yellow?style=for-the-badge&logo=python)
![C](https://img.shields.io/badge/C-Programs-red?style=for-the-badge&logo=c)

</div>

---

**External script sourcing:** [Curated security GitHub collections](../Documentation/awesome-hacking-collections-integration.md) describe useful upstream projects; no linked payload is automatically vetted or installed.


## 📋 Table Of Contents

- [Overview](#-overview)
- [Script Categories](#️-script-categories)
- [Directory Structure](#-directory-structure)
- [How to Use These Scripts](#-how-to-use-these-scripts)
- [⚠️ CRITICAL Security & Legal Warning](#️-critical-security--legal-warning)
- [Contributing](#-contributing)
- [Resources](#-resources)

---

## 🎯 Purpose
A curated entry point for selected script examples in Bash, C, Go, PowerShell, Python, SQL and YAML. It is not a complete inventory or an execution-safety review. Most language folders do not have their own README; inspect each file and its dependencies before use.

## ⚙️ Function
Covers directory structure, selected script categories, usage guidance, authorization boundaries, contributing guidelines, and quick links. Most language subfolders have no separate README. Differs from [Scripts/Bash/BashBunny/README.md](Bash/BashBunny/README.md), [Scripts/Bash/bash_scripting_cheat-sheet.md](Bash/bash_scripting_cheat-sheet.md), and [Scripts/Ducky/README.md](Ducky/README.md), which document a specific script collection or reference topic rather than the folder as a whole. The published repository includes executable scripts in these directories; do not infer availability or safety from a partial local checkout. Review [legacy archive dispositions](GO/ARCHIVE-INVENTORY.md) separately.

## 🏆 Goal
A reader can navigate a partial index, understand that retired entries are inert, and review current source and dependencies before considering any remaining example.

## 📋 When To Use
When looking for an existing script before writing a new one, or when unsure what legal/usage constraints apply to this folder's contents.

## 🎯 Overview

This directory contains historical and current examples across several languages. Some files have been retired as inert stubs; the remaining files are not certified safe or current. Verify each file, dependencies, scope and effects before use.

### ⚠️ Use and Scope

This collection includes read-only utilities, active scanners, and tools that can access or change systems. For active testing, use only targets and methods within your authority and documented scope. Written approval is useful evidence of scope, but the required form and legal rules depend on the engagement and jurisdiction.

The [CFAA statute](https://uscode.house.gov/us/usc/119-134/t18/s1030/) defines multiple offenses with different elements and penalties; not every unauthorized or out-of-policy use of a script is automatically a federal crime. See the [DOJ CFAA charging policy](https://www.justice.gov/jm/jm-9-48000-computer-fraud), which guides federal prosecutors. Other laws, contracts, privacy obligations and organizational rules may also apply.

---

## 📂 Directory Structure

### Programming Language Categories

```
Scripts/
├── Bash/           # Bash shell scripts
├── C/              # C programs and utilities
├── GO/             # Historical mixed-language collection; many Python 2 examples
├── PowerShell/     # PowerShell scripts (Windows)
├── Python/         # Python scripts and retired notices
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
| **get_user.c**, **getuser.c** | Equivalent historical demonstrations that print the current effective user through a shell command | Explain the difference between shell command lookup and a fixed executable path |
| **scanner.c** | Local network discovery with optional Nmap OS fingerprinting; not a port scanner | Authorized local-network inventory |
| **system_sleep.c**, **systemsleep.c** | Equivalent historical demonstrations that wait for 100 seconds using the host's shell `sleep` command | Demonstrate waiting for a subprocess |

The historical examples assume Unix commands. `whoami` reports the effective
user. It does not enumerate users or privileges. A fixed executable path avoids
`PATH` lookup for that command. The examples still invoke a shell, which is
unsuitable as a pattern for privileged code. `sleep` delays the process without
suspending the host.

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

### 3. Powershell Scripts

**Location**: `/Scripts/PowerShell/`

**Selected files (not exhaustive):**

| Script | Description | Risk Level |
|--------|-------------|------------|
| **adlogin.ps1** | RETIRED AND INERT — former Active Directory password spray | ⚫ RETIRED |
| **cred_hunt.ps1** | RETIRED AND INERT — former credential and secret collector | ⚫ RETIRED |
| **localbrute.ps1** | RETIRED AND INERT — former local password guesser | ⚫ RETIRED |
| **localbrute-extra-mini.ps1** | RETIRED AND INERT — former local password guesser | ⚫ RETIRED |
| **port-scan-tcp.ps1** | TCP port scanning utility | 🟡 MEDIUM |
| **port-scan-tcp-compat.ps1** | Compatible TCP port scanner | 🟡 MEDIUM |
| **port-scan-udp.ps1** | UDP port scanning utility | 🟡 MEDIUM |
| **port_scanner.ps1** | General purpose port scanner | 🟡 MEDIUM |
| **rev_shell.ps1** | RETIRED AND INERT — former reverse command shell | ⚫ RETIRED |
| **smblogin.ps1** | RETIRED AND INERT — former SMB password tester | ⚫ RETIRED |
| **smblogin-extra-mini.ps1** | RETIRED AND INERT — former SMB password tester | ⚫ RETIRED |
| **system_enum.ps1** | System enumeration script | 🟡 MEDIUM |

**Scope note:** This index is a selected catalog, not a complete file inventory or a safety certification. Some entries have been retired and remain as inert tombstones. Check the file itself and its local guide before considering any remaining tool.

| Resource | Description |
|---|---|
| [Active Directory Checklist](../Checklists/ActiveDirectory.md) | Directory service assessment |
| [Credential Access Checklist](../Checklists/Credential-Access.md) | Authorized credential testing boundaries |
| [Windows Privilege Escalation Checklist](../Checklists/Windows-Privilege-Escalation.md) | Windows privilege investigation |

**Security Considerations:**
```
⚠️ Several credential collection, password-guessing, and remote-shell entries below are retired and inert. Do not infer that a remaining script is safe from its presence in this index; verify source, scope, and side effects before use. Prefer owner-provided identity reports and synthetic lab data.
```

---

### 4. Python Scripts

**Location**: `/Scripts/Python/`

**Selected files (not exhaustive):**

#### Network & Reconnaissance
| Script | Description | Risk Level |
|--------|-------------|------------|
| **port_scan.py** | Port scanning utility | 🟡 MEDIUM |
| **port_scanner.py** | Network port scanner | 🟡 MEDIUM |
| **proxy_test.py** | Proxy testing utility | 🟢 LOW |

#### Credential & Authentication
| Script | Description | Risk Level |
|--------|-------------|------------|
| **credit_sniff.py** | RETIRED AND INERT — former payment-card data sniffer | ⚫ RETIRED |
| **ftp_sniff.py** | RETIRED AND INERT — former FTP credential sniffer | ⚫ RETIRED |

#### Bluetooth & Wireless
| Script | Description | Risk Level |
|--------|-------------|------------|
| **bt_scan.py** | Bluetooth scanning utility | 🟡 MEDIUM |
| **blue_bug.py** | RETIRED AND INERT — former Bluetooth phonebook access attempt | ⚫ RETIRED |

#### Exploitation & Attack Tools
| Script | Description | Risk Level |
|--------|-------------|------------|
| **conficker.py** | RETIRED AND INERT — former SMB exploitation automation | ⚫ RETIRED |
| **dll_Inject.py** | RETIRED AND INERT — former process DLL injection | ⚫ RETIRED |
| **find_ddos.py** | DDoS detection/analysis | 🟡 MEDIUM |

#### Web & Application Security
| Script | Description | Risk Level |
|--------|-------------|------------|
| **webshell_check.py** | Webshell detection tool | 🟡 MEDIUM |
| **link_parser.py** | Link extraction tool | 🟢 LOW |
| **print_cookies.py** | RETIRED AND INERT — former web-cookie collector | ⚫ RETIRED |

#### Geolocation & Tracking
| Script | Description | Risk Level |
|--------|-------------|------------|
| **google_earth_pcap.py** | PCAP to Google Earth | 🟡 MEDIUM |
| **google_json.py** | Google JSON parser | 🟢 LOW |
| **google_sniff.py** | RETIRED AND INERT — former cleartext search-query capture | ⚫ RETIRED |

#### Mobile Device
| Script | Description | Risk Level |
|--------|-------------|------------|
| **iphone_finder.py** | RETIRED AND INERT — former personal-device tracking | ⚫ RETIRED |
| **iphone_messages.py** | RETIRED AND INERT — former private-message extractor | ⚫ RETIRED |

#### Specialized Tools
| Script | Description | Risk Level |
|--------|-------------|------------|
| **hotel_sniff.py** | RETIRED AND INERT — former guest-identity data sniffer | ⚫ RETIRED |
| **kitten_test.py** | Testing utility | 🟢 LOW |
| **dup.py** | Duplicate file finder | 🟢 LOW |
| **print_direction.py** | Direction printing utility | 🟢 LOW |

#### Supporting Files
| File | Description |
|------|-------------|
| **pass.txt** | Small historical sample strings for offline documentation only; not valid credentials |

**Python Script Characteristics:**
- Mixed historical and current examples
- Network and protocol utilities
- Parsers and local helpers
- Retired entries retained as inert stubs

This is a partial index, not a supported product catalog.

**Security Considerations:**
```
⚠️ Several high-risk Python examples have been replaced with inert retirement notices, including collectors, password testing and process injection. This list is not exhaustive. Do not run a script based only on its filename, table entry or historical description. Review its current source, dependencies and effects first.

Potential operational risks include unintended access, exposure of personal or secret data, service disruption and system changes. Legal and policy consequences depend on authorization, conduct, applicable rules and facts.
```

---

### 5. SQL Scripts

The repository contains no SQL scripts currently. The former static WordPress administrator-creation example was removed because it used a fixed account ID and an obsolete MD5 password hash. Any future database example should use a disposable local lab, avoid embedded credentials, and explain cleanup and version requirements.

---

### 6. YAML Configuration Files

**Location**: `/Scripts/YAML/`

**Purpose:**
- Script configuration files
- Automation playbook definitions
- Tool settings and parameters
- Environment configurations

---

## 📖 How To Use These Scripts

![Authorized script review execution and rollback workflow](../assets/diagrams/safe-script-execution.svg)

*Do not run unreviewed or out-of-scope automation on client systems.*

### ⚠️ Before Running Any Script

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

Review the selected script and its documented parameters first. Do not weaken execution policy to run an unsigned script. Follow the organization-approved signing and execution policy, and record the approved command and output handling.

#### Python Scripts

The repository's `port_scanner.py` accepts a host and inclusive start/end ports as positional arguments. It prints results to the console and has no `--target` or `--output` options:

```console
python port_scanner.py approved-host.example 1 1024  # replace only with a host in scope
```

Use only a host and port range that are explicitly within scope. This repository does not provide a `requirements.txt` for this script; inspect its imports and obtain dependencies from trusted sources before installing them.

#### Bash Scripts

Review a selected script's source, dependencies, expected network or system effects, and documented interface before use. There is no common `--target` or `--output` interface across the collection. Use only the exact host and actions in the approved scope, and capture output through the tool's documented method.

---

## ⚠️ Security, Authorization & Operational Risk

Scripts range from local utilities to active network and system operations. A category or risk label in this index is only a triage aid, not a legal classification or guarantee that a command is safe.

### Establish scope before active testing

For an engagement, record the approving authority, in-scope systems and accounts, allowed techniques, time window, data-handling limits, contacts, stop conditions and rollback plan. Confirm that the person granting permission can authorize the target and that the scope covers the specific method. Written approval is good practice; no single form is a universal legal requirement for every activity.

The [CFAA statute (18 U.S.C. § 1030)](https://uscode.house.gov/us/usc/119-134/t18/s1030/) contains several distinct offenses and penalty provisions. Application depends on statutory elements and facts. The [DOJ charging policy](https://www.justice.gov/jm/jm-9-48000-computer-fraud) is guidance for federal prosecutors, not a complete account of every federal, state, civil or international rule. Avoid relying on blanket claims such as “any unauthorized use is a federal crime” or one fixed prison term.

### Match precautions to the tool

| Tool class | Main operational concern | Safer practice |
|---|---|---|
| Port scanners and discovery tools | Unexpected traffic, alerts or service load | Set a narrow approved target list, rate and time window; stop on instability |
| Login or password testing | Account lockouts, alerts and access to real accounts | Use test accounts in a lab or an explicitly scoped engagement; agree on attempt limits |
| Credential capture or data collection | Exposure of real secrets, personal or regulated data | Use synthetic test data; collect the minimum approved data and protect/delete it under the plan |
| Remote shells or system changes | Persistence, outages or unintended host changes | Use isolated labs or a documented change/rollback procedure on specifically approved systems |
| ICS/SCADA tools | Physical process and safety effects | Do not probe live control systems without owner authorization, engineering review and a safety-approved test plan |

An authorized test can still cause outages or expose data. Use the [script execution workflow](../assets/diagrams/safe-script-execution.svg) to review inputs, target scope, expected effects, monitoring, rollback and output handling before execution.

### Practical checklist

**Before:** validate the target and scope, inspect the script and dependencies, test in an isolated lab where feasible, prepare monitoring and rollback, and identify an escalation contact.

**During:** use the minimum required privileges and activity, record timestamps and commands, monitor service health, and stop if scope is unclear, a control blocks the activity, or unexpected impact appears.

**After:** report results, protect captured data, remove temporary access or test artifacts as agreed, verify recovery, and retain only the records required by the engagement.

### Isolated practice

Use intentionally vulnerable local VMs, CTF environments or systems specifically provided for training. Keep test networks isolated where practical, snapshot targets, and avoid connecting practice tools to unrelated or public systems.
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
🔧 Index: Selected examples; repository tree is authoritative for file presence
⚠️ Risk: Varies by file; review source and effects before use
🔄 Review status: Historical collection under ongoing review
👥 Maintained by: Pacific Northwest Computers (PNWC)
📝 Status: Mixed; some examples are retired and inert
```

---

## 🎓 Critical Reminders

### Always Remember

```
1. CONFIRM AUTHORITY AND SCOPE
   ✓ Confirm permission from the system or account owner
   ✓ Confirm the approval covers the exact systems, accounts, and methods
   ✓ Follow the form of approval required by the owner, policy, and applicable rules
   ✓ Keep scope current; written scope is useful evidence and good practice

2. THESE ARE OFFENSIVE TOOLS
   ✓ Designed for penetration testing
   ✓ Can cause system damage
   ✓ Capable of unauthorized access
   ✓ Subject to strict legal regulations

3. CONSEQUENCES DEPEND ON THE FACTS
   ✓ Conduct may result in criminal, civil, regulatory, contractual, or policy consequences
   ✓ Outcomes depend on the applicable rule, jurisdiction, and evidence
   ✓ Technical harm can include data exposure, service interruption, or system changes
   ✓ Do not infer a specific charge or sentence from this checklist

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

⚠️ **Use scripts only within approved authority and scope.** ⚠️

⚠️ **Legal requirements and consequences depend on the conduct and jurisdiction.** ⚠️

---

⭐ **Star this repo if you find it useful (and use it legally!)** ⭐

</div>

## Related Files
- [../README.md](../README.md) - Main repo index
- [pnwc_install_tools.sh](pnwc_install_tools.sh) - Cross-distro tool installer (apt/pacman/dnf)
- [Bash/bash_scripting_cheat-sheet.md](Bash/bash_scripting_cheat-sheet.md) - Bash scripting reference
- [Bash/BashBunny/README.md](Bash/BashBunny/README.md) - Bash Bunny payload setup & five authorized field assessment labs
- [Ducky/README.md](Ducky/README.md) - USB Rubber Ducky compilation & six safe HID assessment exercises
- [WiFi Pineapple Mark VII](../Wardriving/README.md#wifi-pineapple-mark-vii--authorized-wireless-security-assessment) - complementary wireless Recon & WIDS exercises
- [../Documentation/blackarch.md](../Documentation/blackarch.md) - BlackArch tool installation context

### Python Environment Used By The Tool Installer

`pnwc_install_tools.sh` keeps pip-managed libraries and commands in
`/opt/pnwc-tools/venv`, separate from the system interpreter. After installation,
activate it for a new shell or invoke its binaries by absolute path:

```bash
source /opt/pnwc-tools/venv/bin/activate
```

On Arch-family systems, complete `sudo pacman -Syu` before starting the installer.
The installer asks you to confirm that step and does not refresh package metadata
separately. An unattended run without confirmation stops before installing tools.
