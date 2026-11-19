# Domain Persistence

**Purpose:** Once Domain Admin (or equivalent) is achieved, this checklist covers ways to keep that access alive through password rotations, incident response, and partial remediation - the difference between a compromise that's fixed by resetting one password and one that requires a full domain rebuild to be certain it's gone. Every item here is specifically an AD-native persistence mechanism, not a general Windows backdoor.

**Function:** Entries span a spectrum of stealth and durability: Golden Certificate and Golden Ticket forge Kerberos trust material directly from the krbtgt/CA keys, surviving individual password resets; AdminSDHolder and machine account abuse hijack legitimate AD protection mechanisms to silently maintain privileged group membership; Shadow Credentials and Diamond Ticket are additional paths defenders should inventory; detectability depends on implementation, telemetry, and environment, so validate detection notes against your own lab and data.

**Goal:** Help defenders inventory domain persistence paths and validate recovery coverage. In an explicitly approved exercise, simulate only the minimum needed to test detection and remediation, preferably in an isolated lab or dedicated test domain, with a documented rollback and cleanup check.

**When & how to use this:** Use once you already hold Domain Admin or equivalent rights, as the natural next step after [Domain Escalation](./Domain-Escalation.md). For a red-team exercise, use an isolated lab or a specifically approved simulation with explicit target, technique, duration, rollback, and cleanup criteria. Do not treat deployment of multiple live persistence mechanisms as a default test step. During defensive work, use this as your "did we actually get all of it" checklist after any AD compromise.

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

⚠️ **Authorized testing only: confirm authority and scope before active testing.** ⚠️

⚠️ **Legal consequences depend on the conduct and applicable law; see [18 U.S.C. §1030](https://uscode.house.gov/us/usc/119-134/t18/s1030/) and [DOJ CFAA charging policy](https://www.justice.gov/jm/jm-9-48000-computer-fraud).** ⚠️

⚠️ **For systems you do not own or administer, confirm authorization in advance and document scope in writing where policy, law, or contract requires it.** ⚠️

⭐ **Star this repo if you find it useful!** ⭐

</div>
## Related Files
- [README.md](README.md) - Checklists section index
