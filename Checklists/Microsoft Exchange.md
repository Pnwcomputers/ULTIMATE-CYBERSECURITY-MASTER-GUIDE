# Microsoft Exchange
_Exchange Server attack techniques covering authentication abuse, post-compromise mailbox access, and privilege/domain escalation via Exchange. Source: Pentest Laboratories._

**Purpose:** Covers on-premises Exchange Server specifically as an attack surface — a target that's especially high-value because Exchange servers historically run with disproportionately powerful Active Directory permissions (a legacy of pre-2019 Exchange group policy defaults), making Exchange compromise a common shortcut to domain compromise, not just mailbox access.
 
**Function:** The list follows a natural attack chain: get in (password spraying against Outlook Web Access, NTLM relay against Exchange's authentication endpoints), get code execution (Exchange-specific RCE techniques), then use Exchange's own AD permissions for escalation — the ACL and domain-escalation items exist specifically because Exchange servers were, for years, granted `WriteDACL` rights over the domain object by default, letting anyone who compromises the Exchange server grant themselves DCSync rights.
 
**Goal:** Determine whether Exchange is a stepping stone to full domain compromise rather than an isolated mail-server risk. The ACL-abuse and domain-escalation items in particular test for a specific, well-documented misconfiguration (excessive Exchange group permissions) that many organizations still haven't remediated even after Microsoft's post-2019 guidance to tighten it.
 
**When & how to use this:** Run against on-premises Exchange deployments specifically — this checklist doesn't apply to Exchange Online/Microsoft 365, which has a completely different permission model and attack surface. Start with authentication-layer items (password spraying, NTLM relay) during external/perimeter testing; the post-compromise and domain-escalation items apply once you already have some level of Exchange access and are testing how far that access extends into AD.
---
* [ME-001 - Password Spraying](https://pentestlab.blog/2019/09/05/microsoft-exchange-password-spraying/)
* [ME-002 - NTLM Relay](https://pentestlab.blog/2019/09/09/microsoft-exchange-ntlm-relay/)
* [ME-003 - Mailbox Post Compromise](https://pentestlab.blog/2019/09/11/microsoft-exchange-mailbox-post-compromise/)
* [ME-004 - Privilege Escalation](https://pentestlab.blog/2019/09/16/microsoft-exchange-privilege-escalation/)
* [ME-005 - Code Execution](https://pentestlab.blog/2019/09/10/microsoft-exchange-code-execution/)
* [ME-006 - Domain Escalation - ACL](https://pentestlab.blog/2019/09/12/microsoft-exchange-acl/)
* [ME-007 - Domain Escalation](https://pentestlab.blog/2019/09/04/microsoft-exchange-domain-escalation/)

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
