# Lateral Movement
_Techniques for moving between systems within a compromised network, mapped to MITRE ATT&CK where applicable. Source: Pentest Laboratories._

**Purpose:** Covers moving from one compromised host to another within a network - the connective tissue between "I own one machine" and "I control the domain." Each item is a distinct protocol or mechanism for remote code execution using credentials or tickets already obtained, ranging from decades-old (Services/PsExec-style) to very recent (BitLocker COM hijacking, disclosed in 2025).
 
**Function:** Entries fall into a few families: service-based (Services, WinRM, RDP - legitimate remote administration protocols used with valid or stolen credentials), Kerberos-based (Kerberoast, AS-REP Roast - recover crackable ticket material that then enables movement), and living-off-the-land/protocol-abuse (WMI, WebClient, Visual Studio DTE, BitLocker - abuse a specific feature's remote-trigger capability rather than a purpose-built admin protocol). The mix matters: the more "administrative" a technique looks (RDP, WinRM), the more likely it's logged and alerted on; the more obscure (BitLocker COM hijacking), the more likely it evades existing detection rules simply because nobody's written one yet.
 
**Goal:** Determine how far a single compromised credential or host can propagate through a network, and specifically whether that propagation is visible to existing monitoring. This checklist doubles as a detection-coverage test: for each technique, "would our SOC see this" is the real question being answered, not just "does this technique work."
 
**When & how to use this:** Use once you have valid credentials or tickets from a [Credential Access](./Credential-Access.md) or [Domain Escalation](./Domain-Escalation.md) step and need to reach additional hosts - start with whichever technique matches the credential type you actually have (NTLM hash → pass-the-hash via Services/WinRM; Kerberos ticket → ticket-based movement) rather than working the list in order. Pair with [Tradecraft/network-detection.md](../Tradecraft/network-detection.md) if you're testing detection coverage rather than pure offense.

#### 📖 Full deep-dive: 
- [Tradecraft/active-directory.md](../Tradecraft/active-directory.md) (Kerberos/AD-based movement)
- [Tradecraft/network-detection.md](../Tradecraft/network-detection.md) (detection side)

---

|Code     |Technique               |Mitre     |
|---------|------------------------|----------|
|LM-001   |[Services](https://pentestlab.blog/2020/07/21/lateral-movement-services/)|[T1021.002](https://attack.mitre.org/techniques/T1021/002/)|
|LM-002   |[WinRM](https://pentestlab.blog/2018/05/15/lateral-movement-winrm/)|[T1021.006](https://attack.mitre.org/techniques/T1021/006/)|
|LM-003   |[RDP](https://pentestlab.blog/2018/04/24/lateral-movement-rdp/)|[T1021.001](https://attack.mitre.org/techniques/T1021/001/)|
|LM-004   |[WMI](https://pentestlab.blog/2017/11/20/command-and-control-wmi/)|[T1047](https://attack.mitre.org/techniques/T1047/)|
|LM-005   |[WebClient](https://pentestlab.blog/2021/10/20/lateral-movement-webclient/)|[N/A](https://attack.mitre.org)|
|LM-006   |[Visual Studio DTE](https://pentestlab.blog/2024/01/15/lateral-movement-visual-studio-dte/)|[T1047](https://attack.mitre.org/techniques/T1047/)|
|LM-007   |[Kerberoast](https://pentestlab.blog/2018/06/12/kerberoast/)|[T1558.003](https://attack.mitre.org/techniques/T1558/003/)|
|LM-008   |[AS-REP Roast](https://pentestlab.blog/2024/02/20/as-rep-roasting/)|[T1558.004](https://attack.mitre.org/techniques/T1558/004/)|
|LM-009   |[BitLocker](https://ipurple.team/2025/08/04/lateral-movement-bitlocker/)|[T1021.003](https://attack.mitre.org/techniques/T1021/003/)|

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
