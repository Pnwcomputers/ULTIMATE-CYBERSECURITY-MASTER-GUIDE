# Windows Privilege Escalation
_Common Windows local privilege escalation vectors, from weak service permissions to kernel exploits. Source: Pentest Laboratories._

**Purpose:** Covers the path from a standard/low-privileged user to SYSTEM or local Administrator on a single Windows host — the local counterpart to [Domain Escalation](./Domain-Escalation.md), scoped to one machine rather than the domain. This is the checklist most directly validated by findings from [Windows Build Review](./Windows-Build-Review-Checklist.md); several items here are the exploitation half of misconfigurations that checklist would flag during a passive audit.
 
**Function:** The list spans configuration abuse (weak service permissions, unquoted service paths, insecure registry permissions, Group Policy Preferences — all cases of a legitimate Windows feature configured too loosely) and code-level exploitation (DLL injection/hijacking, Token Manipulation, Hot Potato/token impersonation attacks, and specific named vulnerabilities like HiveNightmare and Intel SYSRET). The token manipulation and Hot Potato-family items specifically abuse Windows' privilege/impersonation model rather than any single misconfiguration — they work by tricking a SYSTEM-level process into authenticating to an attacker-controlled listener.
 
**Goal:** Establish every independent path from the current user context to SYSTEM/Administrator on the host, and — since several of these are the direct result of specific configuration choices — trace each successful escalation back to a concrete, fixable root cause rather than leaving it as an abstract "privilege escalation possible" finding.
 
**When & how to use this:** Run automated enumeration (WinPEAS, PowerUp, or the scripts below) first to shortlist which vectors are actually present, then manually verify and exploit the most promising ones — service misconfigurations and weak registry permissions are typically both more common and lower-risk to test than the named-CVE items like HiveNightmare, which may have narrower applicable version ranges. Cross-reference against [Windows Build Review](./Windows-Build-Review-Checklist.md): findings there (weak service permissions, unquoted paths) often predict exactly which items on this list will succeed.

#### 🛠️ Related scripts: [Scripts/PowerShell/system_enum.ps1](../Scripts/PowerShell/system_enum.ps1) · [Scripts/PowerShell/](../Scripts/PowerShell/)

---
|Code     |Technique               |Mitre     |
|---------|------------------------|----------|
|WPE-01   |[Stored Credentials](https://pentestlab.blog/2017/04/19/stored-credentials/)|[NA](https://attack.mitre.org/)|
|WPE-02   |[Windows Kernel](https://pentestlab.blog/2017/04/24/windows-kernel-exploits/)|[NA](https://attack.mitre.org/)|
|WPE-03   |[DLL Injection](https://pentestlab.blog/2017/04/04/dll-injection/)|[NA](https://attack.mitre.org/)|
|WPE-04   |[Weak Service Permissions](https://pentestlab.blog/2017/03/30/weak-service-permissions/)|[NA](https://attack.mitre.org/)|
|WPE-05   |[DLL Hijacking](https://pentestlab.blog/2017/03/27/dll-hijacking/)|[NA](https://attack.mitre.org/)|
|WPE-06   |[Hot Potato](https://pentestlab.blog/2017/04/13/hot-potato/)|[NA](https://attack.mitre.org/)|
|WPE-07   |[Group Policy Preferences](https://pentestlab.blog/2017/03/20/group-policy-preferences/)|[NA](https://attack.mitre.org/)|
|WPE-08   |[Unquoted Service Path](https://pentestlab.blog/2017/03/09/unquoted-service-path/)|[NA](https://attack.mitre.org/)|
|WPE-09   |[Always Install Elevated](https://pentestlab.blog/2017/02/28/always-install-elevated/)|[NA](https://attack.mitre.org/)|
|WPE-10   |[Token Manipulation](https://pentestlab.blog/2017/04/03/token-manipulation/)|[NA](https://attack.mitre.org/)|
|WPE-11   |[Secondary Logon Handle](https://pentestlab.blog/2017/04/07/secondary-logon-handle/)|[NA](https://attack.mitre.org/)|
|WPE-12   |[Insecure Registry Permissions](https://pentestlab.blog/2017/03/31/insecure-registry-permissions/)|[NA](https://attack.mitre.org/)|
|WPE-13   |[Intel SYSRET](https://pentestlab.blog/2017/06/14/intel-sysret/)|[NA](https://attack.mitre.org/)|
|WPE-14   |[Print Spooler](https://pentestlab.blog/2021/08/02/universal-privilege-escalation-and-persistence-printer/)|[NA](https://attack.mitre.org/)|
|WPE-15   |[HiveNightmare](https://pentestlab.blog/2021/08/16/hivenightmare/)|[NA](https://attack.mitre.org/)|
|WPE-16   |[Resource Based Constrained Delegation](https://pentestlab.blog/2021/10/18/resource-based-constrained-delegation/)|[NA](https://attack.mitre.org/)|

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
