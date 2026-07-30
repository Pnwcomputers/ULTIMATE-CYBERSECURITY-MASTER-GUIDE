# VoIP Checklist
_Checklist for VoIP/SIP infrastructure assessments. This exact checklist is netbiosX's own list - every item traces back to his companion write-up at pentestlab.blog, which explains each check in detail. VoIP-009 links directly to the default credentials list it references; all other items link to that companion post._

**Purpose:** Covers assessment of Voice over IP / SIP telephony infrastructure - a distinct network stack (signaling via SIP, media via RTP) that's frequently deployed on the same physical or logical network as data traffic and is often overlooked in general network pentests despite carrying sensitive voicemail, call data, and - via toll fraud - a direct financial risk.
 
**Function:** The checklist follows the natural order of a VoIP assessment: network access first (VLAN hopping from data to voice network, since voice VLANs are often assumed-trusted and under-segmented), then enumeration (extension harvesting, SIP authentication capture), then active attack (eavesdropping, RTP injection, CallerID spoofing, default credential testing), and finally application/firmware-level issues (voicemail attacks, phone firmware analysis) that require physical or extended access to individual handsets.
 
**Goal:** Determine whether an attacker who reaches the voice VLAN (often more weakly segmented than the general data network) can intercept calls, spoof caller identity for social engineering, harvest extensions for a targeted vishing campaign, or commit toll fraud through the organization's SIP trunk. Voice traffic interception in particular is a distinct compliance/privacy risk that general network pentests frequently miss entirely.
 
**When & how to use this:** Use during internal network engagements where VoIP/SIP infrastructure is in scope - VLAN hopping (VoIP-001) is the natural first step since most subsequent items assume voice-network access. Default credential testing (VoIP-009) is disproportionately high-yield in practice; many VoIP deployments still ship with vendor-default SIP phone or PBX web-admin credentials that were never rotated.

---

* [VoIP-001 - VLAN hopping from data network to voice network](https://pentestlab.blog/2016/09/18/voip-checklist-for-penetration-testers/)
* [VoIP-002 - Extension Enumeration & Number Harvesting](https://pentestlab.blog/2016/09/18/voip-checklist-for-penetration-testers/)
* [VoIP-003 - Capturing SIP Authentication](https://pentestlab.blog/2016/09/18/voip-checklist-for-penetration-testers/)
* [VoIP-004 - Eavesdropping Calls](https://pentestlab.blog/2016/09/18/voip-checklist-for-penetration-testers/)
* [VoIP-005 - CallerID spoofing](https://pentestlab.blog/2016/09/18/voip-checklist-for-penetration-testers/)
* [VoIP-006 - RTP injection](https://pentestlab.blog/2016/09/18/voip-checklist-for-penetration-testers/)
* [VoIP-007 - Signaling Manipulation](https://pentestlab.blog/2016/09/18/voip-checklist-for-penetration-testers/)
* [VoIP-008 - Identification of insecure services](https://pentestlab.blog/2016/09/18/voip-checklist-for-penetration-testers/)
* [VoIP-009 - Testing for Default Credentials](https://github.com/netbiosX/Default-Credentials/blob/master/VoIP-Default-Password-List.mdown)
* [VoIP-010 - Application level vulnerabilities](https://pentestlab.blog/2016/09/18/voip-checklist-for-penetration-testers/)
* [VoIP-011 - Voice Mail Attacks](https://pentestlab.blog/2016/09/18/voip-checklist-for-penetration-testers/)
* [VoIP-012 - Phone Firmware Analysis](https://pentestlab.blog/2016/09/18/voip-checklist-for-penetration-testers/)

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
