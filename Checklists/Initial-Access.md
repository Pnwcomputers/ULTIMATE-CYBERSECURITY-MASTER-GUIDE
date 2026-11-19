# Initial Access
_Defensive review of initial-access techniques and user-deception paths, mapped to MITRE ATT&CK where applicable. Source: Pentest Laboratories._

**Purpose:** This short checklist describes a Windows Search URI (`search-ms:`) pattern that may be abused to make a remote location or attacker-controlled file listing appear in Windows Search. Invoking the URI opens or queries Windows Search; it does not, by itself, execute a file. Code execution depends on later user interaction, the selected file and its handler, system policy, and applicable security updates.
 
**Function:** A crafted URI may open Windows Search with a specified query or search scope, potentially including a remote location. This can support user deception or expose a remote file listing. Review the actual URI, resulting search window, remote access prompts, downloaded file, and user action separately. See Microsoft's [Windows Search protocol documentation](https://learn.microsoft.com/en-us/windows/win32/shell/search-protocol).
 
**Goal:** Help defenders assess email/web filtering, URI handling, remote-file policy, and user reporting. A controlled simulation should use a harmless, owner-approved destination and should measure the URI launch and user decision separately from any file handling.
 
**When & how to use this:** Use as a defensive review or a narrowly scoped, harmless awareness simulation. Do not use a remote payload or claim that opening the URI alone establishes code execution. The blue-team companion below covers investigation and evidence preservation.

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

⚠️ **Authorized testing only: confirm authority and scope before active testing.** ⚠️

⚠️ **Legal consequences depend on the conduct and applicable law; see [18 U.S.C. §1030](https://uscode.house.gov/us/usc/119-134/t18/s1030/) and [DOJ CFAA charging policy](https://www.justice.gov/jm/jm-9-48000-computer-fraud).** ⚠️

⚠️ **For systems you do not own or administer, confirm authorization in advance and document scope in writing where policy, law, or contract requires it.** ⚠️

⭐ **Star this repo if you find it useful!** ⭐

</div>
## Related Files
- [README.md](README.md) - Checklists section index
