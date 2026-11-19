# Persistence
_Windows persistence techniques mapped to MITRE ATT&CK, covering registry, service, scheduled task, and application-based persistence mechanisms. Source: Pentest Laboratories._

**Purpose:** A defensive inventory of Windows mechanisms that can make code re-execute after reboot, logon, or another trigger. It is host-level persistence (surviving a reboot or logoff), distinct from [Domain Persistence](./Domain-Persistence.md), which covers persistence at the AD/domain level.
 
**Function:** The techniques cluster into families based on *what* triggers re-execution: logon-time (Winlogon Helper, Registry Run Keys, PowerShell Profile, Screensaver), service-based (New/Modified Service, Port Monitors, Time Providers - all run as SYSTEM), event-driven (WMI Event Subscription - fires on arbitrary system conditions, not just boot/logon), and hijacking-based (DLL Search Order, COM Hijacking, Netsh Helper DLL, DLL Proxy Loading - abuse how Windows locates and loads code rather than registering a new autostart entry at all). Visibility varies by mechanism and telemetry; hijacking techniques can alter legitimate load paths and may require targeted checks.
 
**Goal:** Help defenders inventory relevant autostart locations and validate detection and recovery coverage. This list is not exhaustive; coverage depends on Windows versions, configuration, and telemetry. During a controlled exercise, simulate only the mechanisms necessary to answer a defined test question.
 
**When & how to use this:** During red-team work, use a lab or a specifically approved simulation, one mechanism at a time, with a documented rollback and cleanup verification. Do not plant multiple live mechanisms as the default test approach. During defensive/hunt work, use this as a structured sweep list - most EDR "autoruns"-style tooling covers the registry/service/scheduled-task items natively, but the hijacking-family items (DLL search order, COM hijacking) usually require manual or purpose-built hunting since they don't register in a conventional autostart location.

---

|Code     |Technique               |Mitre     |
|---------|------------------------|----------|
|PE-001   |[Winlogon Helper DLL](https://pentestlab.blog/2020/01/14/persistence-winlogon-helper-dll/)|[T1547.004](https://attack.mitre.org/techniques/T1547/004/)|
|PE-002   |[Port Monitors](https://pentestlab.blog/2019/10/28/persistence-port-monitors/)|[T1547.010](https://attack.mitre.org/techniques/T1547/010/)|
|PE-003   |[Accessibility Features](https://pentestlab.blog/2019/11/13/persistence-accessibility-features/)|[T1546.008](https://attack.mitre.org/techniques/T1546/008/)|
|PE-004   |[Shortcut Modification](https://pentestlab.blog/2019/10/08/persistence-shortcut-modification/)|[T1547.009](https://attack.mitre.org/techniques/T1547/009/)|
|PE-005   |[Modify Existing Service](https://pentestlab.blog/2020/01/22/persistence-modify-existing-service/)|[T1543.003](https://attack.mitre.org/techniques/T1543/003/)|
|PE-006   |[DLL Search Order Hijacking](https://pentestlab.blog/2020/03/04/persistence-dll-hijacking/)|[T1574.001](https://attack.mitre.org/techniques/T1574/001/)|
|PE-007   |[Change Default File Association](https://pentestlab.blog/2020/01/06/persistence-change-default-file-association/)|[T1546.001](https://attack.mitre.org/techniques/T1546/001/)|
|PE-008   |[New Service](https://pentestlab.blog/2019/10/07/persistence-new-service/)|[T1543.003](https://attack.mitre.org/techniques/T1543/003/)|
|PE-009   |[Scheduled Tasks](https://pentestlab.blog/2019/11/04/persistence-scheduled-tasks/)|[T1053.005](https://attack.mitre.org/techniques/T1053/005/)|
|PE-010   |[Service Registry Permission Weakness](https://pentestlab.blog/2020/01/22/persistence-modify-existing-service/)|[T1574.011](https://attack.mitre.org/techniques/T1574/011/)|
|PE-011   |[Registry Run Keys](https://pentestlab.blog/2019/10/01/persistence-registry-run-keys/)|[T1547.001](https://attack.mitre.org/techniques/T1547/001/)|
|PE-012   |[WMI Event Subscription](https://pentestlab.blog/2020/01/21/persistence-wmi-event-subscription/)|[T1546.003](https://attack.mitre.org/techniques/T1546/003/)|
|PE-013   |[Security Support Provider](https://pentestlab.blog/2019/10/21/persistence-security-support-provider/)|[T1547.005](https://attack.mitre.org/techniques/T1547/005/)|
|PE-014   |[AppInit DLLs](https://pentestlab.blog/2020/01/07/persistence-appinit-dlls/)|[T1546.010](https://attack.mitre.org/techniques/T1546/010/)|
|PE-015   |[Component Object Model Hijacking](https://pentestlab.blog/2020/05/20/persistence-com-hijacking/)|[T1546.015](https://attack.mitre.org/techniques/T1546/015/)|
|PE-016   |[Netsh Helper DLL](https://pentestlab.blog/2019/10/29/persistence-netsh-helper-dll/)|[T1546.007](https://attack.mitre.org/techniques/T1546/007/)|
|PE-017   |[Office Application Startup](https://pentestlab.blog/2019/12/11/persistence-office-application-startup/)|[T1137](https://attack.mitre.org/techniques/T1137/)|
|PE-018   |[Application Shimming](https://pentestlab.blog/2019/12/16/persistence-application-shimming/)|[T1546.011](https://attack.mitre.org/techniques/T1546/011/)|
|PE-019   |[Screensaver](https://pentestlab.blog/2019/10/09/persistence-screensaver/)|[T1546.002](https://attack.mitre.org/techniques/T1546/002/)|
|PE-020   |[Image File Execution Options Injection](https://pentestlab.blog/2020/01/13/persistence-image-file-execution-options-injection/)|[T1546.012](https://attack.mitre.org/techniques/T1546/012/)|
|PE-021   |[BITS Jobs](https://pentestlab.blog/2019/10/30/persistence-bits-jobs/)|[T1197](https://attack.mitre.org/techniques/T1197/)|
|PE-022   |[Time Providers](https://pentestlab.blog/2019/10/22/persistence-time-providers/)|[T1547.003](https://attack.mitre.org/techniques/T1547/003/)|
|PE-023   |[PowerShell Profile](https://pentestlab.blog/2019/11/05/persistence-powershell-profile/)|[T1546.013](https://attack.mitre.org/techniques/T1546/013/)|
|PE-024   |[Waitfor](https://pentestlab.blog/2020/02/04/persistence-waitfor/)|N/A|
|PE-025   |[RID Hijacking](https://pentestlab.blog/2020/02/12/persistence-rid-hijacking/)|N/A|
|PE-026   |[AMSI](https://pentestlab.blog/2021/05/17/persistence-amsi/)|N/A|
|PE-027   |[Print Spooler](https://pentestlab.blog/2021/08/02/universal-privilege-escalation-and-persistence-printer/)|N/A|
|PE-028   |[Certificates](https://pentestlab.blog/2021/09/13/account-persistence-certificates/)|N/A|
|PE-029   |[Notepad++](https://pentestlab.blog/2022/02/14/persistence-notepad-plugins/)|N/A|
|PE-030   |[Event Log](https://pentestlab.blog/2024/01/08/persistence-event-log/)|N/A|
|PE-031   |[Event Log Online Help](https://pentestlab.blog/2023/03/07/persistence-event-log-online-help/)|N/A|
|PE-032   |[Context Menu](https://pentestlab.blog/2023/03/13/persistence-context-menu/)|N/A|
|PE-033   |[Service Control Manager](https://pentestlab.blog/2023/03/20/persistence-service-control-manager/)|N/A|
|PE-034   |[DLL Proxy Loading](https://pentestlab.blog/2024/04/03/persistence-dll-proxy-loading/)|N/A|
|PE-035   |[Windows Telemetry](https://pentestlab.blog/2023/11/06/persistence-windows-telemetry/)|N/A|
|PE-036   |[Scheduled Task Tampering](https://pentestlab.blog/2023/11/20/persistence-scheduled-task-tampering/)|N/A|
|PE-037   |[Junction Folder](https://pentestlab.blog/methodologies/red-teaming/persistence/)|N/A|
|PE-038   |[Library Files](https://pentestlab.blog/methodologies/red-teaming/persistence/)|N/A|
|PE-039   |[Disk Clean-up](https://pentestlab.blog/2024/01/29/persistence-disk-clean-up/)|N/A|
|PE-040   |[Windows Setup Script](https://pentestlab.blog/2024/02/05/persistence-windows-setup-script/)|N/A|
|PE-041   |[Visual Studio Code Extensions](https://pentestlab.blog/2024/03/04/persistence-visual-studio-code-extensions/)|N/A|
|PE-042   |[Explorer](https://pentestlab.blog/2024/03/05/persistence-explorer/)|N/A|

---

<div align="center">

**📖 Use These Checklists Responsibly: Authorization is MANDATORY**

*Attack techniques are powerful - use them ethically and legally.*

**Repository**: [ULTIMATE CYBERSECURITY MASTER GUIDE](https://github.com/Pnwcomputers/ULTIMATE-CYBERSECURITY-MASTER-GUIDE)

**Maintained by**: [Pacific Northwest Computers](https://github.com/Pnwcomputers)

---

⚠️ **Authorized testing only: confirm authority and scope before active testing.** ⚠️

⚠️ **Legal consequences depend on the conduct and applicable law; see [18 U.S.C. §1030](https://uscode.house.gov/us/usc/119-134/t18/s1030/) and [DOJ CFAA charging policy](https://www.justice.gov/jm/jm-9-48000-computer-fraud).** ⚠️

⚠️ **For systems you do not own or administer, confirm authorization in advance and document scope in writing where policy, law, or contract requires it.** ⚠️

⭐ **Star this repo if you find it useful!** ⭐

</div>
## Related Files
- [README.md](README.md) - Checklists section index
