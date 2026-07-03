# Credential Access
_Credential theft and harvesting techniques mapped to MITRE ATT&CK technique IDs, for red team engagements and blue team detection engineering. Source: Pentest Laboratories._

**Purpose:** Covers the ways credentials get exposed and captured on Windows systems and in Active Directory — from OS-level credential stores to phishing-adjacent prompt injection to Kerberos protocol weaknesses. This is deliberately broader than "password cracking"; several items here (input prompts, password filter DLLs) are about *interception* rather than brute force or offline attack.
 
**Function:** Entries split roughly into three families: (1) memory/disk-based dumping — RDP credential caching, browser-stored credentials, stored credential blobs; (2) protocol-level attacks — AS-REP roasting and Kerberoasting abuse specific weaknesses in how Kerberos issues tickets; (3) active interception — password filter DLLs and fake input prompts capture credentials at the moment of entry rather than after the fact. Each maps to a MITRE ATT&CK technique ID so findings translate directly into a detection-coverage conversation.
 
**Goal:** Establish how many independent paths exist to recover plaintext or crackable credentials from a compromised host or domain, and specifically whether any of them work *without* triggering the alerting most organizations have in place for the obvious ones (e.g., LSASS dumping). The AS-REP/Kerberoasting items in particular test whether accounts are configured in a way that makes offline cracking feasible without ever touching a monitored process.
 
**When & how to use this:** Run immediately after establishing a foothold, before attempting lateral movement — credentials recovered here often determine what's possible next. Start with the passive/low-noise items (stored credentials, browser data) before moving to the noisier active techniques (input prompt phishing, password filter DLL installation), since the latter are more likely to trip EDR or generate a support ticket from a suspicious user.

#### 🛠️ Related scripts: [Scripts/PowerShell/cred_hunt.ps1](../Scripts/PowerShell/cred_hunt.ps1) · [Scripts/PowerShell/localbrute.ps1](../Scripts/PowerShell/localbrute.ps1) · [Scripts/PowerShell/smblogin.ps1](../Scripts/PowerShell/smblogin.ps1)
---
|Code     |Technique               |Mitre     |
|---------|------------------------|----------|
|CA-001   |[Password Filter DLL](https://pentestlab.blog/2020/02/10/credential-access-password-filter-dll/)|[T1556.002](https://attack.mitre.org/techniques/T1556/002/)|
|CA-002   |[Input Prompt](https://pentestlab.blog/2020/03/02/phishing-windows-credentials/)|[T1141](https://attack.mitre.org/techniques/T1141/)|
|CA-003   |[Dumping RDP Credentials](https://pentestlab.blog/2021/05/24/dumping-rdp-credentials/)|[T1003](https://attack.mitre.org/techniques/T1003/)|
|CA-004   |[AS-REP Roasting](https://pentestlab.blog/2024/02/20/as-rep-roasting/)|[T1558.004](https://attack.mitre.org/techniques/T1558/004/)|
|CA-005   |[Dumping Domain Password Hashes](https://pentestlab.blog/2018/07/04/dumping-domain-password-hashes/)|[T1003.003](https://attack.mitre.org/techniques/T1003/003/)|
|CA-006   |[Web Browser Stored Credentials](https://pentestlab.blog/2024/08/20/web-browser-stored-credentials/)|[T1555.003](https://attack.mitre.org/techniques/T1555/003/)|
|CA-007   |[Stored Credentials](https://pentestlab.blog/2017/04/19/stored-credentials/)|[T1552](https://attack.mitre.org/techniques/T1552/)|
|CA-008   |[Golden Ticket](https://pentestlab.blog/2018/04/09/golden-ticket/)|[T1558.001](https://attack.mitre.org/techniques/T1558.001/)|
|CA-009   |[Kerberoasting](https://pentestlab.blog/2018/06/12/kerberoast/)|[T1558.003](https://attack.mitre.org/techniques/T1558/003/)|

---

<div align="center">

**📖 Use These Checklists Responsibly: Authorization is MANDATORY**

*Attack techniques are powerful - use them ethically and legally.*

**Repository**: [ULTIMATE CYBERSECURITY MASTER GUIDE](https://github.com/Pnwcomputers/ULTIMATE-CYBERSECURITY-MASTER-GUIDE)

**Maintained by**: [Pacific Northwest Computers](https://github.com/Pnwcomputers)

---

⚠️ **CRITICAL: These are ATTACK TECHNIQUES - Written authorization is REQUIRED** ⚠️

⚠️ **Unauthorized use is a FEDERAL CRIME with up to 10 years imprisonment** ⚠️

⚠️ **ALWAYS obtain explicit written authorization before using any technique** ⚠️

⭐ **Star this repo if you find it useful!** ⭐

</div>
