# Initial Access
_Techniques for gaining initial foothold on a target, mapped to MITRE ATT&CK where applicable. Source: Pentest Laboratories._

**Purpose:** Covers the very first step of an engagement - getting code execution or a foothold on a target that previously had none. This is currently a short, growing list; the single entry (search-ms URI handler abuse) represents a class of technique that abuses how Windows handles custom URI protocol schemes to trick a user into opening what looks like a local file search but actually pulls a malicious file from an attacker-controlled remote share.
 
**Function:** The search-ms technique works by crafting a link (often embedded in a phishing email or malicious webpage) that invokes Windows' `search-ms:` URI handler pointed at a remote WebDAV or SMB share, displaying attacker-controlled file listings inside what appears to be a native Windows Search window - the user believes they're opening a local file when they're actually executing a remote payload.
 
**Goal:** Test whether email/web filtering and user awareness training actually catch URI-handler-based social engineering, which is meaningfully different from (and often missed by) filters tuned for classic macro-laden attachments or straightforward malicious links. This checklist item specifically targets the gap between "we block .exe attachments" and "we understand every way Windows can be tricked into fetching and running remote content."
 
**When & how to use this:** Use during phishing simulation or initial-access-focused red team engagements as one technique in a broader initial access campaign - this is rarely the only vector tested, but it's specifically useful when standard payload delivery methods are already well-detected and you need a technique that doesn't touch disk in the conventional sense. For blue teams, the companion playbook below covers investigating the aftermath once initial access has already occurred.

#### 🔵 Blue-team companion (investigating access after the fact): [PlayBooks/unauth_access.md](../PlayBooks/unauth_access.md)

---

|Code     |Technique               |Mitre     |
|---------|------------------------|----------|
|IA-001   |[search-ms URI Handler](https://pentestlab.blog/2024/01/02/initial-access-search-ms-uri-handler/)|N/A|

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
