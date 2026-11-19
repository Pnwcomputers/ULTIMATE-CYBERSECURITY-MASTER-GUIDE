# Environment Breakout
_Defensive review prompts for kiosk, thin-client, and restricted desktop deployments. Items marked as prompts below do not have individual supporting write-ups here; the LOLBAS catalog is relevant only to some Windows binary behaviors and is not evidence for physical access, UI crashes, browser extensions, or memory analysis.

**Purpose:** Covers testing of *restricted* environments specifically - kiosks, Citrix/RDP published applications, locked-down thin clients, and any interface where a user is deliberately confined to a single application or limited desktop. This is a different threat model from typical privilege escalation: the starting point isn't "unprivileged shell access," it's "no shell access at all, just one sanctioned application window."
 
**Function:** Organizes review prompts across device custody, platform inventory, URI and file-dialog policy, browser extensions, kiosk-shell resilience, application control, and forensic logging. Use owner-approved test cases and record gaps; this list is not an exploitation procedure.
 
**Goal:** Help defenders determine whether kiosk restrictions are enforced consistently, identify recovery and logging gaps, and prioritize hardening without attempting an unauthorized shell escape.
 
**When & how to use this:** Use during an owner-approved architecture review or controlled resilience test. Confirm the test is isolated, define stop conditions, and do not attempt to escape a production kiosk. Pair with the [application-control checklist](./AppLocker.md) for policy review.

#### 📖 Related defensive reference: [Tradecraft/lolbins-lolbas.md](../Tradecraft/lolbins-lolbas.md) (covers abnormal Windows binary behavior; it does not support every prompt below)

---

* EB-001 — Physical security of the device (assessment prompt; no source cited here)
* EB-002 — Platform identification and software inventory (assessment prompt)
* EB-003 — Authorized platform inventory and configuration review (assessment prompt)
* EB-004 — Application inventory and allowlist coverage (assessment prompt)
* EB-005 — Registered URI protocol handlers and policy review (assessment prompt)
* EB-006 — Browser extension inventory and managed-install policy (assessment prompt)
* EB-007 — Front-end crash recovery and kiosk-session restoration (assessment prompt)
* EB-008 — Windows shell configuration and recovery controls (assessment prompt)
* EB-009 — File association and binary search-path controls (assessment prompt)
* EB-010 — Software Restriction Policy / application-control review (assessment prompt)
* EB-011 — Local and group policy enforcement review (assessment prompt)
* EB-012 — Privilege boundaries and least privilege (assessment prompt)
* EB-013 — Memory acquisition and analysis procedure review (assessment prompt)
* EB-014 — AppLocker / WDAC audit and enforcement review (assessment prompt)

---

<div align="center">

**📖 Use These Checklists Responsibly: Authorization is MANDATORY**

*Attack techniques are powerful - use them ethically and legally.*

**Repository**: [ULTIMATE CYBERSECURITY MASTER GUIDE](https://github.com/Pnwcomputers/ULTIMATE-CYBERSECURITY-MASTER-GUIDE)

**Maintained by**: [Pacific Northwest Computers](https://github.com/Pnwcomputers)

---

⚠️ **CRITICAL: These are ATTACK TECHNIQUES - Written authorization is REQUIRED** ⚠️

⚠️ **Unauthorized activity may violate applicable law, contracts, or policy depending on the conduct, authorization, and jurisdiction. Obtain written approval and follow the agreed scope.** ⚠️

⚠️ **ALWAYS obtain explicit written authorization before using any technique** ⚠️

⭐ **Star this repo if you find it useful!** ⭐

</div>
## Related Files
- [README.md](README.md) - Checklists section index
