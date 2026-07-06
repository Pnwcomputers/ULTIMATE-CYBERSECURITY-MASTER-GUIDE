# Active Directory
_Active Directory attack techniques for red team engagements; golden tickets, skeleton keys, DCShadow, and related AD abuse primitives. Source: Pentest Laboratories (pentestlab.blog)._

**Purpose:** This checklist covers post-compromise abuse of Active Directory's trust model itself - not initial access, but what happens once an attacker (or tester) already has a foothold in the domain and wants to escalate, persist, or move covertly using AD's own mechanisms against it. Every item here targets a structural weakness in how Kerberos, LDAP, or domain replication work by design, not a missing patch.
 
**Function:** Each entry maps to a specific abuse of a legitimate AD feature: golden/skeleton-key tickets abuse Kerberos trust in the KRBTGT account, DCShadow abuses domain replication to write directly to AD without touching event logs on a real DC, SPN discovery and Kerberoasting abuse how service accounts request tickets, and hash dumping abuses how domain credentials are stored and synced. None of these are "exploits" in the CVE sense - they're all abuse of intended functionality, which is exactly why they're hard to patch and easy to miss in a rushed assessment.
 
**Goal:** Establish whether an attacker who compromises a single domain-joined host or low-privileged account can escalate to Domain Admin, and - separately - whether they can then persist that access in a way that survives password resets, account disablement, or even a partial incident response. The golden ticket / skeleton key items specifically test the second question: can compromise become *unkillable* without a full KRBTGT rotation.
 
**When & How to use this:** Run this checklist during any internal or AD-focused engagement, ordered roughly as written - SPN discovery and Kerberoasting first (low-noise, credential-only), then DCShadow and ticket forgery only once you already hold DA-equivalent rights, since those require existing high privilege to execute in the first place. This checklist assumes you're already past initial access; pair it with [Domain Escalation](./Domain-Escalation.md) for the privilege-escalation path *into* DA, and [Domain Persistence](./Domain-Persistence.md) for the broader persistence toolkit beyond just tickets.

#### 📖 Full deep-dive with detection/defense guidance: [Tradecraft/active-directory.md](../Tradecraft/active-directory.md)
#### 📄 PDF references: [AD_Attacks_.pdf](../PDF/AD_Attacks_.pdf) · [AD_Post_Exploitation.pdf](../PDF/AD_Post_Exploitation.pdf)
#### 🛠️ Related scripts: [Scripts/PowerShell/](../Scripts/PowerShell/) (adlogin.ps1, smblogin.ps1)
---
* [AD-001 - Golden Ticket](https://pentestlab.blog/2018/04/09/golden-ticket/)
* [AD-002 - Skeleton Key](https://pentestlab.blog/2018/04/10/skeleton-key/)
* [AD-003 - DCShadow](https://pentestlab.blog/2018/04/16/dcshadow/)
* [AD-004 - SPN Discovery](https://pentestlab.blog/2018/06/04/spn-discovery/)
* [AD-005 - Kerberoast](https://pentestlab.blog/2018/06/12/kerberoast/)
* [AD-006 - Dumping Domain Password Hashes](https://pentestlab.blog/2018/07/04/dumping-domain-password-hashes/)

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
