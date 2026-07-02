# Command and Control
_C2 channel techniques and covert communication methods for red team infrastructure, organized by protocol/channel. Most items link to a specific pentestlab.blog write-up. C2-005, C2-010, C2-011, and C2-020 have no dedicated article, so they link to the general pentestlab.blog Command & Control category (★ general reference)._

**Purpose:** A survey of covert communication channels an implant can use to phone home once execution is achieved, organized by carrier protocol/service rather than by C2 framework. Where [Tradecraft/c2-frameworks.md](../Tradecraft/c2-frameworks.md) covers *which tool* to run (Cobalt Strike, Sliver, Havoc), this checklist covers *which channel* the traffic rides on — DNS, HTTPS, WebDAV, cloud storage APIs, social media, even images and JavaScript as a transport.
 
**Function:** Each item represents a different way to blend outbound C2 traffic into normal network noise: DNS and ICMP exploit protocols that are rarely fully inspected; Gmail/DropBox/GitHub/Twitter exploit the fact that traffic to major SaaS platforms is almost never blocked at a corporate firewall; WebSocket, images, and JavaScript exploit the fact that web traffic inspection tools often don't parse payloads embedded in those formats.
 
**Goal:** Determine which covert channels a target's network defenses (firewall egress rules, DNS filtering, TLS inspection, DLP) actually catch versus which ones pass through undetected — this is a detection-evasion assessment as much as an offensive one. For blue teams, this same list doubles as a coverage map: for each channel, "do we have a detection for this" is a fair question to ask.
 
**When & how to use this:** Use during red team engagements after initial access, when establishing a resilient C2 channel is the next objective — test the most "boring"/high-blend-in channels first (HTTPS, DNS) before escalating to more unusual ones (Instagram, images) that are more likely to be a research curiosity than a production-viable channel. For blue/purple teams, use this as a checklist of channels to validate detection coverage against, ideally paired with the Sigma/detection content in [Tradecraft/c2-frameworks.md](../Tradecraft/c2-frameworks.md).

### 📖 Full Deep-dives (Cobalt Strike, etc; Architecture, Detection, etc): [Tradecraft/c2-frameworks.md](../Tradecraft/c2-frameworks.md)

---

* [C2-001 - ICMP](https://pentestlab.blog/2017/07/28/command-and-control-icmp/)
* [C2-002 - DNS](https://pentestlab.blog/2017/09/06/command-and-control-dns/)
* [C2-003 - DropBox](https://pentestlab.blog/2017/08/29/command-and-control-dropbox/)
* [C2-004 - Gmail](https://pentestlab.blog/2017/08/03/command-and-control-gmail/)
* [C2-005 - Github ★](https://pentestlab.blog/category/red-team/command-and-control/)
* [C2-006 - Twitter](https://pentestlab.blog/2017/09/26/command-and-control-twitter/)
* [C2-007 - Website Keyword](https://pentestlab.blog/2017/09/14/command-and-control-website-keyword/)
* [C2-008 - PowerShell](https://pentestlab.blog/2017/08/19/command-and-control-powershell/)
* [C2-009 - Windows COM](https://pentestlab.blog/2017/09/01/command-and-control-windows-com/)
* [C2-009 - WebDAV](https://pentestlab.blog/2017/09/12/command-and-control-webdav/)
* [C2-010 - Error Pages ★](https://pentestlab.blog/category/red-team/command-and-control/)
* [C2-011 - Active Directory ★](https://pentestlab.blog/category/red-team/command-and-control/)
* [C2-012 - HTTPS](https://pentestlab.blog/2017/10/04/command-and-control-https/)
* [C2-013 - Kernel](https://pentestlab.blog/2017/10/02/command-and-control-kernel/)
* [C2-014 - Website](https://pentestlab.blog/2017/11/14/command-and-control-website/)
* [C2-015 - WMI](https://pentestlab.blog/2017/11/20/command-and-control-wmi/)
* [C2-016 - WebSocket](https://pentestlab.blog/2017/12/06/command-and-control-websocket/)
* [C2-017 - Images](https://pentestlab.blog/2018/01/02/command-and-control-images/)
* [C2-018 - Web Interface](https://pentestlab.blog/2018/01/03/command-and-control-web-interface/)
* [C2-019 - JavaScript](https://pentestlab.blog/2018/01/08/command-and-control-javascript/)
* [C2-020 - Instagram ★](https://pentestlab.blog/category/red-team/command-and-control/)
* [C2-021 - Browser](https://pentestlab.blog/2018/06/06/command-and-control-browser/)

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
