# Credential Access
_Credential exposure risks and defensive detection coverage mapped to MITRE ATT&CK technique IDs. Source: Pentest Laboratories._

**Purpose:** Summarizes credential exposure paths that defenders can inventory, monitor, and mitigate on Windows and Active Directory systems. The referenced techniques include credential stores, authentication prompts, password-filter changes, and Kerberos configuration weaknesses.
 
**Function:** Entries group credential risks into local stores, Kerberos configuration, and changes that could intercept authentication. Each maps to MITRE ATT&CK to support a defensive control review: access restrictions, auditing, alert coverage, and credential rotation.
 
**Goal:** Identify and prioritize credential exposure risks without collecting real secrets. Validate monitoring with synthetic accounts and data, and review configuration findings with the system owner.
 
**When & how to use this:** Use this as a defensive hunt and control-review checklist. Do not collect credentials from production users or install interception components as routine testing. If active validation is separately approved, use synthetic accounts in an isolated lab with monitoring and cleanup agreed in advance.

#### Retired examples
The linked credential collection and password-testing scripts are retired inert stubs: [cred_hunt.ps1](../Scripts/PowerShell/cred_hunt.ps1), [localbrute.ps1](../Scripts/PowerShell/localbrute.ps1), and [smblogin.ps1](../Scripts/PowerShell/smblogin.ps1). Do not treat historical filenames as runnable tools.
---
|Code     |Technique               |Mitre     |
|---------|------------------------|----------|
|CA-001   |[Password Filter DLL](https://pentestlab.blog/2020/02/10/credential-access-password-filter-dll/)|[T1556.002](https://attack.mitre.org/techniques/T1556/002/)|
|CA-002   |[Input Prompt](https://pentestlab.blog/2020/03/02/phishing-windows-credentials/)|[T1056.002](https://attack.mitre.org/techniques/T1056/002/)|
|CA-003   |[Dumping RDP Credentials](https://pentestlab.blog/2021/05/24/dumping-rdp-credentials/)|[T1003](https://attack.mitre.org/techniques/T1003/)|
|CA-004   |[AS-REP Roasting](https://pentestlab.blog/2024/02/20/as-rep-roasting/)|[T1558.004](https://attack.mitre.org/techniques/T1558/004/)|
|CA-005   |[Dumping Domain Password Hashes](https://pentestlab.blog/2018/07/04/dumping-domain-password-hashes/)|[T1003.003](https://attack.mitre.org/techniques/T1003/003/)|
|CA-006   |[Web Browser Stored Credentials](https://pentestlab.blog/2024/08/20/web-browser-stored-credentials/)|[T1555.003](https://attack.mitre.org/techniques/T1555/003/)|
|CA-007   |[Stored Credentials](https://pentestlab.blog/2017/04/19/stored-credentials/)|[T1552](https://attack.mitre.org/techniques/T1552/)|
|CA-008   |[Golden Ticket](https://pentestlab.blog/2018/04/09/golden-ticket/)|[T1558.001](https://attack.mitre.org/techniques/T1558/001/)|
|CA-009   |[Kerberoasting](https://pentestlab.blog/2018/06/12/kerberoast/)|[T1558.003](https://attack.mitre.org/techniques/T1558/003/)|

---

<div align="center">

**📖 Use These Checklists Responsibly: Authorization is MANDATORY**

*Attack techniques are powerful - use them ethically and legally.*

**Repository**: [ULTIMATE CYBERSECURITY MASTER GUIDE](https://github.com/Pnwcomputers/ULTIMATE-CYBERSECURITY-MASTER-GUIDE)

**Maintained by**: [Pacific Northwest Computers](https://github.com/Pnwcomputers)

---

⚠️ **Authorized testing only: confirm authority and scope before active testing.** ⚠️

⚠️ **Legal consequences depend on the conduct and applicable law; see [18 U.S.C. §1030](https://uscode.house.gov/us/usc/119-134/t18/s1030/) and [DOJ CFAA charging policy](https://www.justice.gov/jm/jm-9-48000-computer-fraud).** ⚠️

⚠️ **For systems you do not own or administer, confirm authorization in advance and document scope in writing where policy, law, or contract requires it.** ⚠️

⭐ **Star this repo if you find it useful!** ⭐

</div>
## Related Files
- [README.md](README.md) - Checklists section index
