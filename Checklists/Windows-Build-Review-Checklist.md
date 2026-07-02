# Windows Build Review Checklist
_Host-level configuration review checklist for Windows build/hardening assessments. No item in this list has an individual write-up in the original source material — every item links to the CIS Microsoft Windows Benchmarks (★ general reference), the industry-standard hardening baseline that covers all 22 of these review areas in one place._

**Purpose:** A configuration-review (not exploitation) checklist for auditing a single Windows host's build against baseline hardening expectations — the kind of assessment done against a "gold image" before mass deployment, or against an existing production host to establish its current security posture. This is fundamentally different in character from the attack-technique checklists elsewhere in this repo: there's no exploit to run here, only configuration to inspect and compare against a known-good baseline.
 
**Function:** The 22 items sweep systematically through a host's attack surface: what's running (active processes, services, network connections), what's exposed (shares, firewall rules, remote management), what's misconfigured (unquoted service paths, weak service permissions — both classic local-privesc vectors), what's missing (patch level, AV, audit logging), and what's policy-controlled (account lockout, local security policy, clear-text password storage). Several items here (weak service permissions, unquoted service paths) directly overlap with [Windows Privilege Escalation](./Windows-Privilege-Escalation.md) — a build review often surfaces the exact misconfiguration a privesc checklist would later exploit.
 
**Goal:** Produce a build-quality baseline score/report for a Windows host or image, independent of whether any specific vulnerability is actively exploited during the assessment — this checklist answers "is this host built to a defensible standard" rather than "can I compromise this host." It's the checklist you run *before* an attack simulation to understand what you're working with, or as a standalone compliance/hardening validation.
 
**When & how to use this:** Run against a representative sample of hosts (or the gold image itself) during a build review engagement, working through items systematically rather than in attack-priority order since there's no exploitation sequencing here — every item is an independent configuration check. Cross-reference findings against [Windows Privilege Escalation](./Windows-Privilege-Escalation.md) and [AppLocker Bypass](./AppLocker.md): a weak service permission or missing AppLocker policy found during build review is a finding here *and* a predicted attack path there.

---

* [WBR-001 - File System Configuration ★](https://www.cisecurity.org/benchmark/microsoft_windows_desktop)
* [WBR-002 - Network Time Protocol ★](https://www.cisecurity.org/benchmark/microsoft_windows_desktop)
* [WBR-003 - Start-up Executables ★](https://www.cisecurity.org/benchmark/microsoft_windows_desktop)
* [WBR-004 - Active Processes ★](https://www.cisecurity.org/benchmark/microsoft_windows_desktop)
* [WBR-005 - Active Network Connections ★](https://www.cisecurity.org/benchmark/microsoft_windows_desktop)
* [WBR-006 - Routing Table ★](https://www.cisecurity.org/benchmark/microsoft_windows_desktop)
* [WBR-007 - Local Services ★](https://www.cisecurity.org/benchmark/microsoft_windows_desktop)
* [WBR-008 - Exploit Mitigation Technologies ★](https://www.cisecurity.org/benchmark/microsoft_windows_desktop)
* [WBR-009 - Weak Service Permissions ★](https://www.cisecurity.org/benchmark/microsoft_windows_desktop)
* [WBR-010 - Unquoted Service Paths ★](https://www.cisecurity.org/benchmark/microsoft_windows_desktop)
* [WBR-011 - Available Shares ★](https://www.cisecurity.org/benchmark/microsoft_windows_desktop)
* [WBR-012 - User Accounts Review ★](https://www.cisecurity.org/benchmark/microsoft_windows_desktop)
* [WBR-013 - Clear-Text Passwords ★](https://www.cisecurity.org/benchmark/microsoft_windows_desktop)
* [WBR-014 - Storage Mechanism of Password Hashes ★](https://www.cisecurity.org/benchmark/microsoft_windows_desktop)
* [WBR-015 - Account Lockout Policy ★](https://www.cisecurity.org/benchmark/microsoft_windows_desktop)
* [WBR-016 - Local Security Policy ★](https://www.cisecurity.org/benchmark/microsoft_windows_desktop)
* [WBR-017 - Events Auditing ★](https://www.cisecurity.org/benchmark/microsoft_windows_desktop)
* [WBR-018 - Host Based Firewall ★](https://www.cisecurity.org/benchmark/microsoft_windows_desktop)
* [WBR-019 - Antivirus Software Review ★](https://www.cisecurity.org/benchmark/microsoft_windows_desktop)
* [WBR-020 - List Available Software ★](https://www.cisecurity.org/benchmark/microsoft_windows_desktop)
* [WBR-021 - Windows Patch Level ★](https://www.cisecurity.org/benchmark/microsoft_windows_desktop)
* [WBR-022 - Remote Management ★](https://www.cisecurity.org/benchmark/microsoft_windows_desktop)

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
