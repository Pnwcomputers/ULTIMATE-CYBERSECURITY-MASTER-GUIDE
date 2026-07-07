# Domain Escalation
_Active Directory domain escalation techniques (coerced authentication, delegation abuse, ACL abuse) for red team engagements. Source: Pentest Laboratories (note: some newer posts have moved to pentestlaboratories.com under the same team)._

**Purpose:** Covers the path from "domain user with no special rights" to "Domain Admin" - the specific vulnerability classes and misconfigurations that let an attacker climb the privilege ladder within AD rather than techniques for maintaining access once at the top (that's [Domain Persistence](./Domain-Persistence.md)). Several items here (PrintNightmare, PetitPotam) are coerced-authentication techniques: they force a privileged machine account to authenticate to an attacker-controlled listener, which is then relayed for escalation.
 
**Function:** The list splits into two mechanisms: coerced authentication (PrintNightmare, PetitPotam, RemotePotato - force privileged accounts to authenticate where the attacker can capture/relay it) and delegation/ACL abuse (unconstrained delegation, sAMAccountName spoofing, backup operator abuse - exploit legitimate AD permission structures that were configured too broadly). Both mechanisms end at the same place: NTLM relay to a domain controller or direct impersonation of a privileged account.
 
**Goal:** Determine whether a standard, unprivileged domain account can reach Domain Admin without any credential theft at all - purely through protocol coercion and permission misconfiguration. This is often the highest-impact finding in an internal AD assessment because these misconfigurations are common (unconstrained delegation in particular is frequently left over from legacy application setups) and the fix is usually a permissions change, not a patch.
 
**When & how to use this:** Run this after basic domain enumeration (BloodHound is the standard tool for finding candidate ACL/delegation paths) - check for accounts with unconstrained delegation or dangerous ACLs first, since those are often the fastest path and don't require coercion at all. The coercion-based items (PetitPotam, PrintNightmare) become relevant when the ACL graph doesn't offer a direct path and you need to manufacture a privileged authentication event instead.

#### 📖 Full deep-dive with detection/defense guidance: [Tradecraft/active-directory.md](../Tradecraft/active-directory.md)
#### 📄 PDF references: [AD_Attacks_.pdf](../PDF/AD_Attacks_.pdf) · [AD_Post_Exploitation.pdf](../PDF/AD_Post_Exploitation.pdf)
---
|Code     |Technique               |Mitre     |
|---------|------------------------|----------|
|DE-01   |[PrintNightmare](https://pentestlab.blog/2021/08/17/domain-escalation-printnightmare/)|[NA](https://attack.mitre.org/)|
|DE-02   |[PetitPotam](https://pentestlab.blog/2021/09/14/petitpotam-ntlm-relay-to-ad-cs/)|[NA](https://attack.mitre.org/)|
|DE-03   |[RemotePotato](https://pentestlab.blog/2021/05/04/remote-potato-from-domain-user-to-enterprise-admin/)|[NA](https://attack.mitre.org/)|
|DE-04   |[Unconstrained Delegation](https://pentestlab.blog/2022/03/21/unconstrained-delegation/)|[NA](https://attack.mitre.org/)|
|DE-05   |[sAMAccountName Spoofing](https://pentestlab.blog/2022/01/10/domain-escalation-samaccountname-spoofing/)|[NA](https://attack.mitre.org/)|
|DE-06   |[ShadowCoerce](https://pentestlaboratories.com/2022/01/11/shadowcoerce/)|[NA](https://attack.mitre.org/)|
|DE-07   |[Pass the hash - Machine Accounts](https://pentestlab.blog/2022/02/01/machine-accounts/)|[NA](https://attack.mitre.org/)|
|DE-08   |[Backup Operator](https://pentestlab.blog/2024/01/22/domain-escalation-backup-operator/)|[NA](https://attack.mitre.org/)|

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
## Related Files
- [README.md](README.md) - Checklists section index
