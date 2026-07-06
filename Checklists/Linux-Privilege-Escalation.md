# Linux Privilege Escalation
_Common Linux local privilege escalation vectors._

**Purpose:** Covers the path from an unprivileged shell on a Linux host to root - the standard set of misconfigurations and kernel vulnerabilities that show up repeatedly across real-world Linux systems and CTF-style privilege escalation challenges alike. Unlike the AD-focused checklists in this repo, most items here are host-local rather than network/protocol-based.
 
**Function:** The list spans three categories: kernel-level vulnerabilities (Dirty Cow, Baron Samedit - actual CVEs with specific affected version ranges), misconfiguration abuse (SUID binaries, sudo permissions, cron jobs, PATH hijacking - legitimate system features configured too permissively), and technique classes rather than single bugs (wildcard injection is a pattern that applies to any privileged script calling `tar`/`rsync`/`chown` unsafely, not a single fixed vulnerability).
 
**Goal:** Establish whether a foothold on a Linux system can be escalated to root, and specifically *how* - kernel exploits and sudo/SUID misconfigurations require different remediation entirely (patch the kernel vs. fix a permissions file), so this checklist's real value is in categorizing the finding correctly, not just proving root is reachable.
 
**When & how to use this:** Run automated enumeration first (LinPEAS or similar - see [Homelab/HomeLab_Setup.md](../Homelab/HomeLab_Setup.md) for setup) to shortlist which of these vectors are actually present before manually working through the list - kernel version alone rules out most of the CVE-specific items immediately. Check sudo/SUID/cron misconfigurations before reaching for a kernel exploit; they're lower-risk (no chance of a kernel panic) and far more common in practice.

#### 📄 PDF reference: [Linux_Privilege_Escalation.pdf](../PDF/Linux_Privilege_Escalation.pdf)
---
* [LPE-01 - Dirty Cow](https://dirtycow.ninja/)
* [LPE-02 - SUID Executables](https://pentestlab.blog/2017/09/25/suid-executables/)
* [LPE-03 - Sudo Users](https://gtfobins.github.io/gtfobins/sudo/)
* [LPE-04 - Wildcard Injection](https://hacktricks.wiki/en/linux-hardening/privilege-escalation/wildcards-spare-tricks.html)
* [LPE-05 - Kernel Exploits](https://github.com/lucyoa/kernel-exploits)
* [LPE-06 - Path Hijacking](https://hacktricks.wiki/en/linux-hardening/privilege-escalation/index.html)
* [LPE-07 - Misconfigured Cron jobs](https://hacktricks.wiki/en/linux-hardening/privilege-escalation/index.html)
* [LPE-08 - Baron Samedit](https://blog.qualys.com/vulnerabilities-threat-research/2021/01/26/cve-2021-3156-heap-based-buffer-overflow-in-sudo-baron-samedit)

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
