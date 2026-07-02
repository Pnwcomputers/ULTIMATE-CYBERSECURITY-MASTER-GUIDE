# Environment Breakout Checklist
_Checklist for testing kiosk, thin-client, and restricted desktop environments for breakout to a full shell. No item in this list has an individual write-up in the original source material — every item links to the LOLBAS project (★ general reference), the standard living catalog of living-off-the-land binaries and techniques used for exactly this kind of restricted-environment breakout._

**Purpose:** Covers testing of *restricted* environments specifically — kiosks, Citrix/RDP published applications, locked-down thin clients, and any interface where a user is deliberately confined to a single application or limited desktop. This is a different threat model from typical privilege escalation: the starting point isn't "unprivileged shell access," it's "no shell access at all, just one sanctioned application window."
 
**Function:** The checklist works through breakout in roughly the order an attacker would attempt it: physical access and identification first (what's the platform, what's actually installed), then progressively more invasive escape techniques — abusing file/save dialogs and URI protocol handlers to spawn other processes, crashing the front-end to fall back to a desktop, exploiting browser extensions or Windows shell manipulation, and finally bypassing whatever software/group policy restrictions remain once a shell is reached.
 
**Goal:** Determine whether the restriction is enforced at a level that actually matters (application whitelisting, kernel-level sandboxing) or is purely cosmetic (a locked-down Explorer shell sitting on top of a fully capable, unrestricted OS). The end state being tested is: can a user with access to exactly one sanctioned application reach an arbitrary command shell, and from there, arbitrary code execution.
 
**When & how to use this:** Use this against any kiosk, terminal server published-app, or restricted-shell deployment during a physical or remote engagement — work through the list roughly top-to-bottom, since later items (privilege escalation, AppLocker bypass) generally assume you've already broken out to *some* kind of shell using an earlier item. Pair with [AppLocker Bypass](./AppLocker.md) once you have shell access but application whitelisting is still in the way.

#### 📖 Companion deep-dive on the same LOLBins/LOLScripts: [Tradecraft/lolbins-lolbas.md](../Tradecraft/lolbins-lolbas.md)

---

* [EB-001 - Physical Security of the Device ★](https://lolbas-project.github.io/)
* [EB-002 - Platform Identification and Version Software in Use ★](https://lolbas-project.github.io/)
* [EB-003 - Enumeration of Windows Boxes Available ★](https://lolbas-project.github.io/)
* [EB-004 - Application Enumeration ★](https://lolbas-project.github.io/)
* [EB-005 - Register URI Protocol Handlers Enumeration ★](https://lolbas-project.github.io/)
* [EB-006 - Malicious Browser Addons Installations ★](https://lolbas-project.github.io/)
* [EB-007 - Front-End Interface Crash ★](https://lolbas-project.github.io/)
* [EB-008 - Windows Shell Environment Manipulation ★](https://lolbas-project.github.io/)
* [EB-009 - Binary Planting ★](https://lolbas-project.github.io/)
* [EB-010 - Bypass Software Restriction Policies ★](https://lolbas-project.github.io/)
* [EB-011 - Bypass Local Group Policies ★](https://lolbas-project.github.io/)
* [EB-012 - Privilege Escalation ★](https://lolbas-project.github.io/)
* [EB-013 - Memory dump Analysis ★](https://lolbas-project.github.io/)
* [EB-014 - Bypass AppLocker Rules ★](https://lolbas-project.github.io/)

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
