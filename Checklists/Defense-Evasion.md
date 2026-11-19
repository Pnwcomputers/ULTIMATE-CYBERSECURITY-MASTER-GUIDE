# Process Lineage Detection Validation
_A defensive checklist for reviewing process-lineage telemetry and detection coverage. The linked material is historical context, not an implementation guide._

**Purpose:** Assess whether detection logic relies too heavily on a reported parent-process field, and whether other telemetry can reveal inconsistent process lineage.

**Function:** Review the authorized endpoint's available process-creation sources, field semantics, collection gaps, and rule logic. Parent-process spoofing is one ATT&CK technique; it does not make every process field forgeable in the same way or guarantee evasion.

**Goal:** Document which telemetry is collected, what behavior the detection covers, and what remains unverified. A missing alert alone does not prove a bypass; validate event collection and rule conditions first.

**When & how to use this:** Use for defensive rule review or an approved purple-team exercise in an isolated environment. Prefer vendor-supported simulations or synthetic event data. Correlate process lineage across available ETW, Security 4688, and Sysmon data, accounting for product configuration and version. Do not deploy spoofing code on production endpoints.

#### Related defensive reference: [AV/EDR monitoring and hardening](../Tradecraft/av-edr-evasion.md)
---
|Code     |Technique               |Mitre     |
|---------|------------------------|----------|
|DE-001   |[Parent PID Spoofing](https://pentestlab.blog/2020/02/24/parent-pid-spoofing/)|[T1134.004](https://attack.mitre.org/techniques/T1134/004/)|

---

<div align="center">

**Use this checklist for defensive review within documented scope.**

*Focus on telemetry semantics, detection coverage, and evidence quality.*

**Repository**: [ULTIMATE CYBERSECURITY MASTER GUIDE](https://github.com/Pnwcomputers/ULTIMATE-CYBERSECURITY-MASTER-GUIDE)

**Maintained by**: [Pacific Northwest Computers](https://github.com/Pnwcomputers)

---

⚠️ **Any active simulation requires prior authorization and an isolated test plan.** ⚠️

⚠️ **Unauthorized activity may violate applicable law, contracts, or policy depending on the conduct, authorization, and jurisdiction. Obtain written approval and follow the agreed scope.** ⚠️

⚠️ **Prefer benign simulations; record approval, expected evidence, and rollback steps.** ⚠️

⭐ **Star this repo if you find it useful!** ⭐

</div>
## Related Files
- [README.md](README.md) - Checklists section index
