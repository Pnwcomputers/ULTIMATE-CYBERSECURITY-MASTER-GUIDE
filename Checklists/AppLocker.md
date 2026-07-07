# AppLocker Bypass
_Known AppLocker bypass techniques (LOLBins and binary abuse) useful during Windows application whitelisting assessments. Source: Pentest Laboratories._

**Purpose:** Tests whether a Windows AppLocker application-whitelisting policy is actually enforcing what it claims to. AppLocker is frequently deployed with default or overly permissive rules (e.g., allowing anything in `C:\Windows` or signed-by-Microsoft), and every item on this list is a specific technique for executing arbitrary code despite those rules being "on."
 
**Function:** Each entry abuses a signed, whitelisted Windows binary to proxy execution of unsigned attacker code - InstallUtil, Regsvr32, MSBuild, Rundll32, and the rest are all legitimate Microsoft tools that AppLocker's default rules trust by path or publisher, and each has a documented way to make it run arbitrary script or DLL content instead of its intended payload. This is the Windows-specific subset of the broader LOLBins/LOLBAS technique class.
 
**Goal:** Establish whether the deployed AppLocker rule set (path-based, publisher-based, or hash-based) actually stops code execution, or whether it just blocks the naive case of double-clicking an unsigned .exe. A thorough pass through this list often reveals that "AppLocker is enabled" and "AppLocker is effective" are two very different claims.
 
**When & How to use this:** Run this once you have code-execution-but-restricted access on a system with AppLocker (or WDAC) enforced - either during an authorized red team engagement or a defensive control validation exercise. Test the rule set's actual configuration first (`Get-AppLockerPolicy -Effective`) to know which rule *types* apply, since some bypasses only work against path-based rules and are moot against strict publisher/hash rules.

#### 📖 Full deep-dive on the LOLBins used here: [Tradecraft/lolbins-lolbas.md](../Tradecraft/lolbins-lolbas.md)

---

* [AL-01 - InstallUtil](https://pentestlab.blog/2017/05/08/applocker-bypass-installutil/)
* [AL-02 - Regsvr32](https://pentestlab.blog/2017/05/11/applocker-bypass-regsvr32/)
* [AL-03 - Regasm and Regsvcs](https://pentestlab.blog/2017/05/19/applocker-bypass-regasm-and-regsvcs/)
* [AL-04 - MSBuild](https://pentestlab.blog/2017/05/29/applocker-bypass-msbuild/)
* [AL-05 - Rundll32](https://pentestlab.blog/2017/05/23/applocker-bypass-rundll32/)
* [AL-06 - IEExec](https://pentestlab.blog/2017/06/13/applocker-bypass-ieexec/)
* [AL-07 - Control Panel](https://pentestlab.blog/2017/05/24/applocker-bypass-control-panel/)
* [AL-08 - Weak Path Rules](https://pentestlab.blog/2017/05/22/applocker-bypass-weak-path-rules/)
* [AL-09 - BgInfo](https://pentestlab.blog/2017/06/05/applocker-bypass-bginfo)
* [AL-10 - Assembly Load](https://pentestlab.blog/2017/06/06/applocker-bypass-assembly-load/)
* [AL-11 - File Extensions](https://pentestlab.blog/2017/06/12/applocker-bypass-file-extensions/)
* [AL-12 - MSIEXEC](https://pentestlab.blog/2017/06/16/applocker-bypass-msiexec/)
* [AL-13 - MSXSL](https://pentestlab.blog/2017/07/06/applocker-bypass-msxsl/)
* [AL-14 - CreateRestrictedToken](https://pentestlab.blog/2017/07/07/applocker-bypass-createrestrictedtoken/)
* [AL-15 - Cmstp](https://pentestlab.blog/2018/05/10/applocker-bypass-cmstp/)

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
