# Defense Evasion
_Techniques for evading detection and security controls during an engagement, mapped to MITRE ATT&CK. Currently a short list - expand as new techniques are added. Source: Pentest Laboratories._

**Purpose:** A narrow, growing list of specific technique-level evasions - currently just parent-PID spoofing, which makes a malicious process appear to have been launched by a trusted parent (e.g., `explorer.exe` instead of a script host) to defeat process-lineage-based detection rules. This file is intentionally short right now; it's the technique-ID-mapped index that sits alongside the much larger conceptual treatment in [Tradecraft/av-edr-evasion.md](../Tradecraft/av-edr-evasion.md).
 
**Function:** Each entry here is a single, narrow evasion primitive rather than a full evasion strategy - the kind of individual trick that gets chained together with others (obfuscation, injection, unhooking) to build a complete evasion chain. Parent PID spoofing specifically abuses the fact that many EDR detection rules use "what spawned this process" as a trust signal.
 
**Goal:** Test whether a target's EDR/AV is relying on shallow indicators (like literal parent-child process relationships) that can be spoofed, versus deeper behavioral or memory-based detection that doesn't care what the reported parent process is. A successful bypass here is a specific, reproducible finding you can hand to a blue team: "your detection rule trusts a field that's trivially forgeable."
 
**When & how to use this:** Use during red team or purple team engagements specifically to validate individual EDR detection rules rather than as a general "am I detected" test - this checklist is most valuable when you already know which detection logic is deployed and want to test its assumptions directly. Pair with the fuller technique catalog in [Tradecraft/av-edr-evasion.md](../Tradecraft/av-edr-evasion.md) for the broader evasion toolkit (unhooking, AMSI bypass, injection techniques) this short list doesn't yet cover.

#### 📖 Full deep-dive (AV/EDR evasion, detection artifacts, hardening): [Tradecraft/av-edr-evasion.md](../Tradecraft/av-edr-evasion.md)
---
|Code     |Technique               |Mitre     |
|---------|------------------------|----------|
|DE-001   |[Parent PID Spoofing](https://pentestlab.blog/2020/02/24/parent-pid-spoofing/)|[T1134.004](https://attack.mitre.org/techniques/T1134/004/)|

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
