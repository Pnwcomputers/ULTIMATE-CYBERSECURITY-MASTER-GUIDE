# Android Mobile Application Checklist

**Purpose:** A first-pass triage checklist for reviewing an Android APK's client-side security posture before (or instead of) a full OWASP MASTG-scale assessment. It's narrower than MASTG by design — 8 items instead of MASTG's hundreds of test cases — aimed at catching the handful of mistakes that show up in the overwhelming majority of real-world mobile app pentests.
  
**Function:** The checklist splits into two categories: static configuration review (manifest permissions, certificate/signing setup, code obfuscation presence) and runtime/network behavior (WebView implementation, certificate pinning, rooting detection, plaintext data handling). Manifest and WebView issues can be found from the decompiled APK alone; certificate pinning and rooting detection require dynamic testing with a proxy and/or a rooted test device.
  
**Goal:** Determine whether the app leaks sensitive data at rest or in transit, whether it can be trivially repackaged or MITM'd, and whether an attacker with physical access to a rooted device can bypass the app's own defenses. This is fundamentally a "can this app be trusted on a compromised device" checklist, not a backend API security review — server-side findings need a separate methodology.
  
**When & How to use this:** Use during mobile app engagements as an initial pass before diving into MASTG's full test suite, or as a lightweight recurring check between major MASTG-scale assessments (e.g., after each app release). AMA-001/002 (manifest, WebView) can be done from a static APK dump with no device needed; the rest need a test device or emulator with Frida/Objection available.

*Mobile application security review checklist for Android apps:*
- AMA-001, 002, and 008 link to specific pentestlab.blog write-ups.
- AMA-003 links to the specific OWASP MASTG test case.
- AMA-004 through AMA-007 link to the general OWASP MASTG guide
_★ General reference, OWASP restructures individual test IDs periodically, so these point to the stable top-level guide rather than a specific page that could break)._
---
* [AMA-001 - Manifest File Review](https://pentestlab.blog/2017/01/24/security-guidelines-for-android-manifest-files/)
* [AMA-002 - Insecure WebView Implementation](https://pentestlab.blog/2017/02/12/android-webview-vulnerabilities/)
* [AMA-003 - Lack of Certificate Pinning](https://mas.owasp.org/MASTG/tests/android/MASVS-NETWORK/MASTG-TEST-0244/)
* [AMA-004 - No Rooting Detection ★](https://mas.owasp.org/MASTG/)
* [AMA-005 - Application Certificate ★](https://mas.owasp.org/MASTG/)
* [AMA-006 - Lack of Code Obfuscation ★](https://mas.owasp.org/MASTG/)
* [AMA-007 - Plaintext Data ★](https://mas.owasp.org/MASTG/)
* [AMA-008 - APK Payload Injection](https://pentestlab.blog/2017/06/26/injecting-metasploit-payloads-into-android-applications-manually/)

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
