# Domain Persistence

**Purpose:** Once Domain Admin (or equivalent) is achieved, this checklist covers ways to keep that access alive through password rotations, incident response, and partial remediation — the difference between a compromise that's fixed by resetting one password and one that requires a full domain rebuild to be certain it's gone. Every item here is specifically an AD-native persistence mechanism, not a general Windows backdoor.

**Function:** Entries span a spectrum of stealth and durability: Golden Certificate and Golden Ticket forge Kerberos trust material directly from the krbtgt/CA keys, surviving individual password resets; AdminSDHolder and machine account abuse hijack legitimate AD protection mechanisms to silently maintain privileged group membership; Shadow Credentials and Diamond Ticket are newer, harder-to-detect variants specifically designed to evade the detection logic built for the older, well-known techniques (Diamond Ticket, for instance, exists because Golden Ticket's "TGS request with no matching AS request" detection is now standard).

**Goal:** Determine how many independent, hard-to-detect persistence mechanisms an attacker (or your red team) could plant in a domain, and — critically — whether your incident response process would actually catch and remove all of them. A common IR failure mode is resetting the krbtgt password once (defeats Golden Ticket) while missing AdminSDHolder ACL modifications or shadow credential entries that survive the reset entirely.

**When & how to use this:** Use once you already hold Domain Admin or equivalent rights, as the natural next step after [Domain Escalation](./Domain-Escalation.md). During a red team exercise, plant 2-3 independent mechanisms from different rows of this list (not just Golden Ticket) so the blue team's remediation is genuinely tested rather than solved by a single krbtgt reset. During defensive work, use this as your "did we actually get all of it" checklist after any AD compromise.

#### 📖 Full deep-dive with detection/defense guidance: [Tradecraft/active-directory.md](../Tradecraft/active-directory.md)
#### 📄 PDF references: [AD_Attacks_.pdf](../PDF/AD_Attacks_.pdf) · [AD_Post_Exploitation.pdf](../PDF/AD_Post_Exploitation.pdf)
---
|Code     |Technique               |Mitre     |
|---------|------------------------|----------|
|DP-01   |[Golden Certificate](https://pentestlab.blog/2021/11/15/golden-certificate/)|[NA](https://attack.mitre.org/)|
|DP-02   |[AdminSDHolder](https://pentestlab.blog/2022/01/04/domain-persistence-adminsdholder/)|[NA](https://attack.mitre.org/)|
|DP-03   |[Golden Ticket](https://pentestlab.blog/2018/04/09/golden-ticket/)|[NA](https://attack.mitre.org/)|
|DP-04   |[DCShadow](https://pentestlab.blog/2018/04/16/dcshadow/)|[NA](https://attack.mitre.org/)|
|DP-05   |[Machine Account](https://pentestlab.blog/2022/01/17/domain-persistence-machine-account/)|[NA](https://attack.mitre.org/)|
|DP-06   |[Shadow Credentials](https://pentestlab.blog/2022/02/07/shadow-credentials/)|[NA](https://attack.mitre.org/)|
|DP-07   |[Diamond Ticket](https://hacktricks.wiki/en/windows-hardening/active-directory-methodology/diamond-ticket.html)|[NA](https://attack.mitre.org/)|

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
