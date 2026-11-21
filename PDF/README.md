# 📄 PDF Reference Library

## 🎯 Purpose
Index of the PDF reference library - curated security PDFs, cheat sheets, and reference guides organized by topic for offline access during engagements, training, and research.

## ⚙️ Function
Indexes categorized PDFs covering: penetration testing methodology, CTF reference sheets, network protocols, exploit development, malware analysis, compliance frameworks (NIST, PCI-DSS, ISO 27001), tool manuals, and course materials - maintained as locally accessible offline references.

## 🏆 Goal
Provide organized offline access to security references for study and reference. These PDFs are third-party or archival materials and may contain outdated commands, vulnerabilities, or legal guidance; verify important details against current primary sources before relying on them.

## 📋 When To Use
- Preparing for an engagement and downloading relevant offline references
- Finding a specific technical PDF (protocol specs, exploit technique papers, tool manuals)
- Building an offline security library for training or certification preparation

<div align="center">

**Organized collection of cybersecurity reference materials, cheat sheets, and technical guides**

*Part of the [ULTIMATE CYBERSECURITY MASTER GUIDE](../README.md)*

![Reference](https://img.shields.io/badge/Reference-PDF%20Library-red?style=for-the-badge)
![Cheat Sheets](https://img.shields.io/badge/Cheat%20Sheets-Quick%20Reference-blue?style=for-the-badge)
![Guides](https://img.shields.io/badge/Guides-Technical%20Documentation-green?style=for-the-badge)

</div>

---

## 📋 Table Of Contents

- [Overview](#-overview)
- [PDF Library Contents](#-pdf-library-contents)
- [Document Categories](#️-document-categories)
- [How to Use These Resources](#-how-to-use-these-resources)
- [Security & Legal Disclaimer](#️-security--legal-disclaimer)
- [Contributing](#-contributing)
- [Resources](#-resources)

---

## 🎯 Overview

This directory contains **curated PDF reference materials, cheat sheets, and technical guides** for cybersecurity professionals, penetration testers, security researchers, and students. These documents provide quick reference information and in-depth technical guidance for various security domains.

**What You'll Find Here:**
- 📝 Penetration testing methodologies and guides
- 🔍 Attack technique references and cheat sheets
- 🌐 Network security and protocol analysis
- 💻 Active Directory and Windows security
- 🐧 Linux privilege escalation techniques
- 🌍 Web application security testing
- 📡 Wireless security and WiFi hacking
- 🔐 SSH and remote access security

---

## 📂 PDF Library Contents

### Active Directory & Windows Security

| PDF | Description | Focus Area |
|-----|-------------|------------|
| **[AD_Attacks_.pdf](./AD_Attacks_.pdf)** | Active Directory attack techniques and exploitation methods | AD Attacks |
| **[AD_Post_Exploitation.pdf](./AD_Post_Exploitation.pdf)** | Post-exploitation techniques in Active Directory environments | Post-Exploitation |

### Penetration Testing Methodologies

| PDF | Description | Focus Area |
|-----|-------------|------------|
| **[Pentest_Guide.pdf](./Pentest_Guide.pdf)** | Comprehensive penetration testing methodology and workflow | General Pentesting |
| **[Pentest_Check_List.pdf](./Pentest_Check_List.pdf)** | Systematic penetration testing checklist | Methodology |
| **[OSCP_Cheat_Sheet.pdf](./OSCP_Cheat_Sheet.pdf)** | OSCP exam-focused commands and techniques | Certification |

### Linux Security & Privilege Escalation

| PDF | Description | Focus Area |
|-----|-------------|------------|
| **[Linux_Privilege_Escalation.pdf](./Linux_Privilege_Escalation.pdf)** | Linux privilege escalation techniques and vectors | Linux PrivEsc |

### Network Security & Analysis

| PDF | Description | Focus Area |
|-----|-------------|------------|
| **[Network_101_1738356173.pdf](./Network_101_1738356173.pdf)** | Networking fundamentals and security concepts | Networking Basics |
| **[Network_Essentials.pdf](./Network_Essentials.pdf)** | Essential networking concepts and protocols | Network Fundamentals |
| **[Wireshark_Cheat_Sheet.pdf](./Wireshark_Cheat_Sheet.pdf)** | Wireshark filters and packet analysis reference | Traffic Analysis |

### Web Application Security

| PDF | Description | Focus Area |
|-----|-------------|------------|
| **[Web_Attacks_.pdf](./Web_Attacks_.pdf)** | Web application attack techniques and vectors | Web Security |
| **[Web_application_Firewall__.pdf](./Web_application_Firewall__.pdf)** | Web Application Firewall (WAF) bypass techniques | WAF Bypass |
| **[IDOR_Guide.pdf](./IDOR_Guide.pdf)** | Insecure Direct Object Reference (IDOR) exploitation | IDOR Attacks |
| **[zero-day-hunter.pdf](./zero-day-hunter.pdf)** | Unverified novelty-style vulnerability-research resource list; non-authoritative | Research (unverified) |
| **[ReactJs_Cheatsheet.pdf](./ReactJs_Cheatsheet.pdf)** | Illustrated React syntax, components and routing examples | Frontend Development |

### Wireless Security

| PDF | Description | Focus Area |
|-----|-------------|------------|
| **[Wi_Fi_hacking__.pdf](./Wi_Fi_hacking__.pdf)** | WiFi hacking techniques and wireless security testing | Wireless Security |

### Remote Access & SSH Security

| PDF | Description | Focus Area |
|-----|-------------|------------|
| **[SSH_Access_.pdf](./SSH_Access_.pdf)** | SSH access techniques and security testing | SSH Security |
| **[ssh-pen-testing.pdf](./ssh-pen-testing.pdf)** | SSH penetration testing methodology | SSH Testing |

### Container Security

| PDF | Description | Focus Area |
|-----|-------------|------------|
| **[docker-pen-test.pdf](./docker-pen-test.pdf)** | Docker container penetration testing techniques | Container Security |

---

## 🗂️ Document Categories

### 1. Active Directory Security

**Coverage:**
- Domain enumeration and reconnaissance
- Kerberos attacks (Kerberoasting, AS-REP roasting)
- Credential theft and pass-the-hash
- Domain privilege escalation
- Post-exploitation persistence
- Lateral movement in AD environments
- GPO abuse and exploitation

**Documents:**
- AD_Attacks_.pdf - Attack vectors and techniques
- AD_Post_Exploitation.pdf - Post-compromise operations

| Resource | Description |
|---|---|
| [Active Directory Checklist](../Checklists/ActiveDirectory.md) | Directory service assessment |
| [Domain Escalation Checklist](../Checklists/Domain-Escalation.md) | Domain escalation assessment |
| [Domain Persistence Checklist](../Checklists/Domain-Persistence.md) | Domain persistence assessment |

**Use Cases:**
- Internal penetration testing
- Red team operations
- Active Directory security assessments
- Domain compromise simulations

---

### 2. Penetration Testing Methodologies

**Coverage:**
- Systematic testing approach
- Reconnaissance and scanning
- Vulnerability assessment
- Exploitation techniques
- Post-exploitation activities
- Reporting and documentation
- OSCP exam preparation

**Documents:**
- Pentest_Guide.pdf - Complete methodology
- Pentest_Check_List.pdf - Systematic checklist
- OSCP_Cheat_Sheet.pdf - Certification reference

**Use Cases:**
- Structured penetration tests
- Certification exam preparation
- Methodology standardization
- Quality assurance checks

---

### 3. Linux Security

**Coverage:**
- Linux privilege escalation vectors
- Kernel exploits
- SUID/SGID binary abuse
- Sudo misconfigurations
- Cron job exploitation
- Capabilities abuse
- Container escapes

**Documents:**
- Linux_Privilege_Escalation.pdf - Comprehensive guide

**Quick-reference checklist:** [Linux Privilege Escalation](../Checklists/Linux-Privilege-Escalation.md)

**Use Cases:**
- Linux security assessments
- Privilege escalation testing
- System hardening validation
- CTF challenges

---

### 4. Network Security

**Coverage:**
- Network protocol fundamentals
- TCP/IP stack analysis
- Network reconnaissance
- Packet capture and analysis
- Wireshark filtering techniques
- Network security concepts
- Traffic analysis

**Documents:**
- Network_101_1738356173.pdf - Fundamentals
- Network_Essentials.pdf - Core concepts
- Wireshark_Cheat_Sheet.pdf - Analysis reference

**Use Cases:**
- Network security assessments
- Traffic analysis and monitoring
- Protocol analysis
- Network troubleshooting

---

### 5. Web Application Security

**Coverage:**
- OWASP Top 10 vulnerabilities
- Web attack vectors and techniques
- WAF bypass methods
- IDOR exploitation
- Zero-day vulnerability hunting
- Frontend framework security (ReactJS)
- API security testing

**Documents:**
- Web_Attacks_.pdf - Attack techniques
- Web_application_Firewall__.pdf - WAF bypass
- IDOR_Guide.pdf - IDOR exploitation
- zero-day-hunter.pdf - Vuln research
- ReactJs_Cheatsheet.pdf - Frontend security

**Use Cases:**
- Web application penetration testing
- Bug bounty hunting
- API security assessments
- Frontend security reviews

---

### 6. Wireless Security

**Coverage:**
- WiFi protocol security
- Wireless network attacks
- WPA/WPA2/WPA3 attacks
- Rogue access point detection
- Wireless reconnaissance
- Deauthentication attacks
- Handshake capture and cracking

**Documents:**
- Wi_Fi_hacking__.pdf - Wireless security testing

**Use Cases:**
- Wireless security assessments
- WiFi penetration testing
- Network security audits
- Wireless policy validation

---

### 7. Remote Access Security

**Coverage:**
- SSH security testing
- SSH enumeration and scanning
- SSH key management
- Brute force attacks
- SSH tunnel exploitation
- Remote access vulnerabilities
- Secure configuration practices

**Documents:**
- SSH_Access_.pdf - SSH security
- ssh-pen-testing.pdf - SSH testing methodology

**Use Cases:**
- Remote access security testing
- SSH configuration reviews
- Key management assessments
- Secure access validation

---

### 8. Container Security

**Coverage:**
- Docker security testing
- Container escape techniques
- Image vulnerability scanning
- Privilege escalation in containers
- Docker API exploitation
- Orchestration security (Kubernetes)
- Container runtime security

**Documents:**
- docker-pen-test.pdf - Container security testing

**Use Cases:**
- Container security assessments
- DevSecOps security testing
- Cloud-native security
- Kubernetes security

---

## 📖 How To Use These Resources

### For Penetration Testers

```
During Assessments:
   └─> Use PDFs as quick reference during testing
   └─> Follow methodologies from penetration testing guides
   └─> Reference cheat sheets for command syntax
   └─> Verify techniques with official documentation

Study & Preparation:
   └─> Review attack technique PDFs
   └─> Practice commands from cheat sheets
   └─> Study for certifications (OSCP, CEH, etc.)
   └─> Build personal knowledge base

Documentation:
   └─> Reference PDFs in engagement reports
   └─> Cite attack techniques properly
   └─> Use as evidence of methodology
   └─> Support findings with technical references
```

### For Security Researchers

```
Research Activities:
   └─> Use vulnerability guides for research direction
   └─> Reference known attack patterns
   └─> Study exploitation techniques
   └─> Analyze security controls

Tool Development:
   └─> Reference attack methodologies
   └─> Understand protocol specifications
   └─> Study exploitation frameworks
   └─> Build proof-of-concepts

Knowledge Building:
   └─> Study multiple attack domains
   └─> Cross-reference techniques
   └─> Build comprehensive understanding
   └─> Stay current with attack trends
```

### For Students & Learners

```
Certification Preparation:
   └─> Study OSCP cheat sheet
   └─> Review penetration testing methodologies
   └─> Practice commands from reference sheets
   └─> Build lab environments for testing

Skill Development:
   └─> Work through attack techniques systematically
   └─> Practice in authorized lab environments
   └─> Build personal reference library
   └─> Document learning progress

Career Development:
   └─> Study professional methodologies
   └─> Understand industry practices
   └─> Prepare for security roles
   └─> Build technical competency
```

### For Blue Team / Defenders

```
Threat Understanding:
   └─> Study attacker techniques and tools
   └─> Understand attack methodologies
   └─> Learn exploitation patterns
   └─> Identify detection opportunities

Detection Development:
   └─> Create detection rules based on techniques
   └─> Build hunting queries
   └─> Develop correlation logic
   └─> Test detection coverage

Security Hardening:
   └─> Understand vulnerabilities to prevent
   └─> Implement mitigations for known attacks
   └─> Validate security controls
   └─> Test defensive posture
```

---

## ⚠️ Security & Legal Disclaimer

### 🔴 Critical: Authorized Use Only

```
⚠️ IMPORTANT: EDUCATIONAL AND AUTHORIZED USE ONLY ⚠️

These PDF reference materials contain security testing techniques for:

✅ AUTHORIZED USES:
   • Educational purposes in controlled environments
   • Authorized penetration testing with written permission
   • Security research in isolated lab settings
   • Professional security assessments with client approval
   • Certification study and preparation (OSCP, CEH, etc.)
   • Training and skill development in authorized contexts
   • Security tool development for defensive purposes
   • CTF competitions and authorized challenges

🚫 STRICTLY PROHIBITED:
   • Unauthorized penetration testing or "hacking"
   • Attacking systems without explicit written permission
   • Using techniques on production systems without approval
   • Applying methods for malicious purposes
   • Testing against systems you don't own or manage
   • Exceeding authorized scope of security assessments
   • Sharing techniques for illegal activities
   • Any violations of computer crime laws
```

---

### Legal Requirements

#### United States

The [Computer Fraud and Abuse Act, 18 U.S.C. § 1030](https://uscode.house.gov/us/usc/119-118/t18/s1030/)
contains multiple offenses with different elements and penalties. Whether it applies
depends on the subsection and facts, including the conduct and authorization. There is
no single sentence or fine that applies to every unauthorized use of a technique.
See the [DOJ charging policy](https://www.justice.gov/jm/jm-9-48000-computer-fraud)
for additional context.

Other federal, state, territorial, tribal, and international laws may apply. Rules for
interception, privacy, data handling, and radio transmissions vary by jurisdiction and
circumstances. Do not infer a legal conclusion from a tool label or checklist.

**Before active testing:**

```
☐ Confirm authority for the systems, accounts, data, and methods in scope
☐ Record approved targets, exclusions, time windows, and stop conditions
☐ Use test data and lab environments where practical
☐ Stop if scope or impact is uncertain
```

### Content-specific Warnings

#### Active Directory Attacks

```
⚠️ WARNING: AD Attack Techniques

LEGAL CONSIDERATIONS:
   • Unauthorized domain enumeration may violate CFAA
   • Credential theft is a serious criminal offense
   • Pass-the-hash attacks constitute unauthorized access
   • Domain privilege escalation outside approved scope may violate applicable law, contract, or policy

REQUIRED AUTHORIZATION:
   ✓ Explicit permission to test Active Directory
   ✓ Approval for credential access techniques
   ✓ Clear scope of which accounts and systems
   ✓ Data handling and destruction procedures

PROHIBITED:
   🚫 Accessing domain resources without authorization
   🚫 Stealing or using credentials without permission
   🚫 Compromising domain controllers without approval
   🚫 Persisting in domain without authorization
```

#### Web Application Attacks

```
⚠️ WARNING: Web Attack Techniques

LEGAL CONSIDERATIONS:
   • Web application testing outside approved scope may violate applicable law, contract, or policy
   • WAF bypass may violate terms of service
   • Testing an IDOR outside approved scope may expose unauthorized data or violate applicable rules
   • Zero-day exploitation without permission is criminal

REQUIRED AUTHORIZATION:
   ✓ Written permission from application owner
   ✓ Clear scope of applications and features
   ✓ Approval for specific attack techniques
   ✓ Data handling requirements

PROHIBITED:
   🚫 Testing websites without permission
   🚫 Exploiting vulnerabilities maliciously
   🚫 Accessing data you're not authorized to view
   🚫 Causing service disruption or data loss
```

#### Wireless Security Testing

```
⚠️ WARNING: WiFi Hacking Techniques

LEGAL CONSIDERATIONS:
   • Unauthorized access may violate computer-misuse or other laws depending on the conduct and jurisdiction
   • Interception may be subject to wiretap/privacy laws; consent and other exceptions vary by jurisdiction
   • Deauthentication attacks may constitute DoS
   • Password guessing or authentication testing outside approved scope may violate applicable law, contract, or policy

REQUIRED AUTHORIZATION:
   ✓ Explicit permission from network owner
   ✓ Written authorization for testing methods
   ✓ Clear scope of networks in testing
   ✓ Time windows and restrictions

PROHIBITED:
   🚫 Testing neighbor's or public WiFi without permission
   🚫 Cracking passwords to gain unauthorized access
   🚫 Intercepting communications without authorization
   🚫 Deauthenticating users on unauthorized networks
```

#### Linux Privilege Escalation

```
⚠️ WARNING: Privilege Escalation Techniques

LEGAL CONSIDERATIONS:
   • Exceeding authorized access may violate the CFAA depending on conduct and statutory elements
   • Exploitation outside approved scope may violate applicable law, contract, or policy
   • Privilege escalation outside approved scope may violate applicable law, contract, or policy
   • Testing without the required authorization may violate applicable rules; requirements vary by context

REQUIRED AUTHORIZATION:
   ✓ Permission to attempt privilege escalation
   ✓ Approval for exploitation techniques
   ✓ Clear scope of systems and accounts
   ✓ Rollback and restoration procedures

PROHIBITED:
   🚫 Escalating privileges without authorization
   🚫 Using exploits on unauthorized systems
   🚫 Installing backdoors or persistence
   🚫 Modifying system configurations without approval
```

---

### Educational Use Guidelines

#### For Students & Learners

**Authorized Learning Environments:**
```
✅ Personal home lab (systems you own)
✅ Virtual machines and isolated networks
✅ School/university lab with explicit permission
✅ CTF competitions and challenges
✅ Bug bounty programs (within scope)
✅ Online learning platforms (HTB, THM, etc.)
```

**Prohibited Activities:**
```
🚫 Testing on school/work production systems
🚫 "Practice" on any unauthorized network
🚫 Testing neighbors' or public WiFi
🚫 Applying techniques to any system without permission
🚫 Accessing accounts or systems you don't own
🚫 Using skills for unauthorized access
```

**Safe Learning Practices:**
```
1. Build your own home lab
2. Use virtual machines exclusively
3. Set up isolated test networks
4. Only test systems you own
5. Obtain explicit permission for everything
6. Document your learning ethically
7. Never test on production systems
8. Follow responsible disclosure
9. Respect intellectual property
10. Stay within legal boundaries always
```

---

### Professional Standards

#### Code Of Ethics

**Core Principles:**

1. **Authorization**: Never use techniques without written permission
2. **Integrity**: Act honestly and transparently
3. **Confidentiality**: Protect information discovered during testing
4. **Competence**: Only use techniques you fully understand
5. **Responsibility**: Accept accountability for all actions
6. **Legal Compliance**: Follow all applicable laws strictly
7. **Do No Harm**: Minimize impact and risk

#### Professional Responsibilities

```
✅ DO:
   • Obtain written authorization before every test
   • Verify authorization is current and valid
   • Document all activities with timestamps
   • Report findings responsibly
   • Protect client and target confidentiality
   • Maintain professional liability insurance
   • Follow industry standards and frameworks
   • Continue professional education

🚫 DON'T:
   • Use techniques without authorization (ever)
   • Exceed authorized scope for any reason
   • Share sensitive findings publicly
   • Use knowledge for personal gain or harm
   • Misrepresent your qualifications
   • Guarantee specific results
   • Disclose vulnerabilities prematurely
   • Ignore ethical considerations
```

---

### Risk Considerations

#### Using These Techniques Carries Risks:

**Legal Risks:**
- Criminal charges under CFAA and state laws
- International prosecution under various laws
- Civil lawsuits for damages
- Professional license revocation
- Employment termination
- Industry blacklisting

**Technical Risks:**
- System crashes or instability
- Data loss or corruption
- Network disruption
- Service outages
- Unintended security compromises
- Detection and response actions

**Professional Risks:**
- Loss of certifications (OSCP, CEH, etc.)
- Reputation damage
- Career limitations
- Legal defense costs
- Insurance claims
- Client/employer trust loss

---

### Warranty Disclaimer

```
⚠️ DISCLAIMER OF WARRANTIES ⚠️

These PDF reference materials are provided "AS IS" without warranty
of any kind, either expressed or implied, including but not limited to:

• Warranties of accuracy or completeness
• Warranties of technique effectiveness
• Warranties of safety or non-disruption
• Warranties of legal compliance
• Warranties of fitness for particular purpose

THE AUTHORS, CONTRIBUTORS, AND MAINTAINERS:
• Make no guarantees about content accuracy
• Are not responsible for damages from use
• Do not warrant techniques will work in all environments
• Are not liable for legal consequences of misuse
• May update or remove content without notice
• Disclaim all liability for unauthorized use

USERS EXPLICITLY ACKNOWLEDGE:
• They use these materials at their own risk
• They are responsible for obtaining authorization
• They must comply with all applicable laws
• They are liable for their testing activities
• They understand legal implications
• They accept all risks of using these techniques

CRITICAL REMINDER:
These PDF documents contain ATTACK TECHNIQUES that can:
   - Cause system disruption or damage
   - Result in criminal prosecution if misused
   - Lead to civil liability and lawsuits
   - Cause professional and personal consequences
   - Violate laws when used without authorization
```

---

### Liability Limitations

**The Authors, Contributors, and Maintainers are NOT liable for:**

- Direct, indirect, incidental, or consequential damages
- Criminal charges resulting from unauthorized use
- Civil lawsuits from testing activities
- System failures, data loss, or service disruption
- Security breaches or compromises
- Privacy violations or regulatory penalties
- Professional consequences or license loss
- Employment termination
- Legal fees or criminal defense costs
- Any damages arising from use of these materials

**Maximum Liability:**
To the extent permitted by law, total liability shall not exceed
the amount paid for these materials (zero for free distribution).

---

## 🤝 Contributing

### How To Contribute PDF Resources

We welcome high-quality PDF contributions from security professionals.

#### Contribution Guidelines

**To Submit PDF Resources:**
1. Fork the repository
2. Ensure PDF is high-quality and relevant
3. Verify content is accurate and current
4. Include appropriate attribution
5. Add comprehensive legal warnings if applicable
6. Test all commands and techniques in authorized environments
7. Submit pull request with description

**Quality Standards:**
- ✅ Clear, readable formatting
- ✅ Accurate technical information
- ✅ Proper attribution and citations
- ✅ Legal and ethical warnings included
- ✅ Organized and well-structured
- ✅ Relevant to cybersecurity professionals
- ✅ Archived and supplemental reference material

#### What We're Looking For

**High Priority:**
- Cloud security (AWS, Azure, GCP) cheat sheets
- API security testing guides
- Container and Kubernetes security
- Authorized authentication-control validation and defensive coverage testing
- EDR/XDR detection engineering and telemetry validation (avoid reusable evasion procedures)
- Zero-trust architecture testing
- DevSecOps security references

---

## 📚 Resources

### Certification Preparation

- **OSCP**: Offensive Security Certified Professional
- **CEH**: Certified Ethical Hacker
- **GPEN**: GIAC Penetration Tester
- **GWAPT**: GIAC Web Application Penetration Tester
- **OSWE**: Offensive Security Web Expert
- **OSEP**: Offensive Security Experienced Penetration Tester

### Methodology Frameworks

- **MITRE ATT&CK**: https://attack.mitre.org/
- **OWASP Testing Guide**: https://owasp.org/www-project-web-security-testing-guide/
- **PTES**: Penetration Testing Execution Standard
- **OSSTMM**: Open Source Security Testing Methodology Manual
- **NIST SP 800-115**: Technical Guide to Information Security Testing

### Additional Resources

- **Offensive Security**: https://www.offsec.com/
- **SANS Institute**: https://www.sans.org/
- **HackTheBox**: https://www.hackthebox.com/
- **TryHackMe**: https://tryhackme.com/
- **PortSwigger Web Security Academy**: https://portswigger.net/web-security

---

## 🔗 Quick Links

### Internal Links
- [🏠 Main Repository](../README.md)
- [🎯 START HERE Guide](../START_HERE.md)
- [💻 Cybersecurity Master Guide](../ultimate_cybersecurity_master_guide.md)
- [🔍 OSINT Resources](../OSINT/README.md)
- [✅ Security Checklists](../Checklists/README.md)
- [💻 Security Scripts & Tools](../Scripts/README.md)
- [📚 Documentation](../Documentation/README.md)
- [🔒 OPSEC Guidelines](../OPSEC/README.md)

### External Resources
- [OWASP Foundation](https://owasp.org)
- [Offensive Security](https://www.offsec.com/)
- [SANS Institute](https://www.sans.org/)
- [NIST Cybersecurity](https://www.nist.gov/cyberframework)

---

## 📊 Repository Statistics

```
📁 Listed PDFs: 18 reference documents
📖 Categories: AD Security, Pentesting, Linux, Network, Web, Wireless, SSH, Docker
🔄 Inventory reviewed: November 2026; document contents are not individually certified as current
👥 Maintained by: Pacific Northwest Computers (PNWC)
📝 Status: Active Library
```

---

## 🎓 Best Practices Summary

### Always Remember

**Legal Requirements:**
- ✅ Written authorization is MANDATORY before using any technique
- ✅ Verify authorization is current and explicitly covers techniques
- ✅ Document all authorization details
- ✅ Maintain proof of authorization during testing
- ✅ Never exceed authorized scope

**Safe Usage:**
- ✅ Use PDFs for reference and learning only
- ✅ Practice techniques in authorized lab environments
- ✅ Test on systems you own or have explicit permission for
- ✅ Build home labs for safe learning
- ✅ Participate in authorized CTF competitions

**Professional Conduct:**
- ✅ Follow ethical guidelines at all times
- ✅ Report findings responsibly
- ✅ Protect confidential information
- ✅ Maintain professional standards
- ✅ Continue education and training

---

## 💬 Feedback & Support

### Questions Or Issues?
- Open an issue on GitHub
- Review legal warnings thoroughly before using
- Ensure you have proper authorization
- Consult legal counsel when uncertain
- Respect response times

### Suggest Improvements
- Recommend high-quality PDF resources
- Report outdated or inaccurate content
- Suggest additional categories
- Share complementary materials
- Help improve documentation quality

---

## 🌟 Acknowledgments

### Content Sources
- Security research community
- Open source security projects
- Professional penetration testers
- Security training organizations
- Certification bodies (Offensive Security, SANS, etc.)

### Knowledge Contributors
- Penetration testing professionals
- Security researchers and analysts
- Tool developers and maintainers
- Training content creators
- Open source community

**Thank you for responsible security research and ethical hacking.**

---

<div align="center">

**📖 Use These Resources Responsibly: Authorization is Required**

*Knowledge is power - use it ethically and legally.*

**Repository**: [ULTIMATE CYBERSECURITY MASTER GUIDE](https://github.com/Pnwcomputers/ULTIMATE-CYBERSECURITY-MASTER-GUIDE)

**Maintained by**: [Pacific Northwest Computers](https://github.com/Pnwcomputers)

---

⚠️ **CRITICAL: These PDFs contain ATTACK TECHNIQUES - Written authorization REQUIRED** ⚠️

⚠️ **Unauthorized activity may violate law, contract, or policy depending on conduct, authorization, and jurisdiction. Obtain the authorization required for your activity and follow the agreed scope.** ⚠️

⚠️ **ALWAYS obtain explicit written authorization before using any technique** ⚠️

⭐ **Star this repo if you find it useful!** ⭐

</div>

## Related Files
- [../README.md](../README.md) - Main repo index
- [../ENHANCED_MASTER_GUIDE.md](../ENHANCED_MASTER_GUIDE.md) - Enhanced master guide with deep-dive references
- [../START_HERE.md](../START_HERE.md) - Starting point for the entire guide


## Review notes (2026-11-19)

These PDFs are imported third-party reference material. The source PDFs have not been modified; use the notes here to avoid treating risky, outdated, or unverified examples as ready-to-run guidance. Perform offensive work only in explicitly authorized environments, and verify commands and tool status against current primary sources.

| PDF | Review note |
|---|---|
| [Web Attacks](./Web_Attacks_.pdf) | Page 38 binds an SSH dynamic SOCKS proxy to all interfaces (`0.0.0.0`); page 5 places an API-key placeholder in a URL query string. Do not use those examples as written. Bind local proxy services to loopback unless there is a reviewed need and network controls; follow the provider's current documented secret handling. |
| [Ethical Hacking Mind Map](../Documentation/Ethical.Hacking.MindMap.pdf) | Page 1 describes defenses as stopping attacks without stating conditions. Treat these as non-guaranteed claims and verify them for the specific environment. The map includes offensive and persistence topics; use only with explicit authorization. |
| [Active Directory Attacks](./AD_Attacks_.pdf) | The guide includes short-link downloads, an execution-policy bypass example, and host-clock changes. Treat as lab-only historical reference; verify canonical source, version, impact, and rollback before using any command. |
| [Network Essentials](./Network_Essentials.pdf) | Telnet management examples appear on pages 23–24 and 33. Do not apply them to production management planes; use SSH and current vendor guidance. |
| [Wi-Fi Hacking Notes](./Wi_Fi_hacking__.pdf) | Undated lab notes include legacy interface commands and wireless attack exercises. Verify current hardware/protocol guidance and use an isolated, authorized lab. |
| [Pentest Checklist](./Pentest_Check_List.pdf) and [Pentest Guide](./Pentest_Guide.pdf) | The checklist relies on short links; the guide warns that some links may fail. Follow canonical sources and confirm they are current. |
| [Zero-Day Hunter](./zero-day-hunter.pdf) | A novelty-style, unverified resource list, not an authoritative guide or vetted route into vulnerability research. |
| [SAST Scanners Cheat Sheet](../Documentation/SAST.Scanners.-.We.Hack.Purple.Cheat.Sheet.pdf) | Dated January 2022; use as a historical tool catalogue and check active support before selecting a scanner. |

### Follow-up reference screening (2026-11-20)

| PDF | Finding and current reference |
| --- | --- |
| [IDOR Guide](./IDOR_Guide.pdf) | Pages 33–35 discuss randomized identifiers and server-side access controls. UUIDs can make enumeration harder. Enforce an object-level authorization check on every request. [OWASP IDOR prevention](https://cheatsheetseries.owasp.org/cheatsheets/Insecure_Direct_Object_Reference_Prevention_Cheat_Sheet.html) |
| [Linux Privilege Escalation](./Linux_Privilege_Escalation.pdf) | Page 4 suggests matching kernel versions to exploit reports. A version string alone gives incomplete evidence of patch status because distributions can backport fixes. Use the installed package release and vendor advisory. [Red Hat security backporting](https://access.redhat.com/security/updates/backporting) |
| [Network 101](./Network_101_1738356173.pdf) | Introductory networking slides with private-address examples. Private address assignment describes address scope. Apply segmentation and firewall policy separately when controlling traffic. [RFC 1918](https://www.rfc-editor.org/rfc/rfc1918) |
| [OSCP Cheat Sheet](./OSCP_Cheat_Sheet.pdf) | Image-based practice notes include tool and exploitation examples. Use OffSec's current guide for exam rules and permitted tools. [OffSec exam guide](https://help.offsec.com/hc/en-us/articles/360040165632-OSCP-Exam-Guide) |
| [Docker Penetration Testing](./docker-pen-test.pdf) | Pages 8–11 discuss remote daemon access, page 16 shows an Ubuntu 16.04 image, and page 20 uses the Docker socket. Treat the environment as historical. Keep the daemon socket restricted and protect approved remote access with SSH or TLS. [Docker daemon access](https://docs.docker.com/engine/security/protect-access/) |
| [SSH Penetration Testing](./ssh-pen-testing.pdf) | Pages 23–25 demonstrate forwarding. Review the actual bind address and forwarding scope, and verify the server host key before using a tunnel. [OpenSSH client configuration](https://man.openbsd.org/ssh_config) |
| [React Cheat Sheet](./ReactJs_Cheatsheet.pdf) | All nine pages are introductory development material. Page 5 uses the array index as a key. Use stable item IDs when items can be inserted, removed or reordered. [React list keys](https://react.dev/learn/rendering-lists) |

The repository contains 20 PDFs, with 18 in this folder and two in `Documentation/`. The follow-up used
embedded text for five references, OCR for the 14-page OSCP sheet, and rendered pages for the nine-page
React sheet. Commands in the PDFs were not executed. See the [repository review log](../REVIEW_2026-11-19.md)
for the scope and limits of the review.
