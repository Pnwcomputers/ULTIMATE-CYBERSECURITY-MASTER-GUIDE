# 🧰 Tsurugi Bento — Portable DFIR and Live-Response Field Guide

> [!CAUTION]
> **Authorized incident response and evidence handling only.** Running portable applications on a live computer **changes that computer** (USB/PnP artifacts, process execution, memory, logs, timestamps, potentially Defender alerts). Bento is **not** a forensic write blocker, a read-only boot environment, a full forensic workstation or a guarantee of court-admissible evidence. Before using it, obtain authorization, define scope, record your actions, and plan safe evidence storage. See [LEGAL.md](../../LEGAL.md) and [Live Response Collection](./LiveData/live_data_collection.md).

**Product:** [Tsurugi Bento portable DFIR toolkit](https://tsurugi-linux.org/documentation_bento_toolkit.php)  
**Latest official download verified:** `bento_2026.10.7z` (released October 19, 2026; optional in-app updates). **Documentation caveat:** the official tool inventory and changelog still show 2025.8, so inspect actual installed app versions.  
**Last reviewed:** October 26, 2026  
**Location:** [Incident Response](../README.md) → [Digital Forensics](./README.md)  
**Role:** First-response collection, incident triage and preservation; **not deep post-acquisition forensic analysis**.

## 🎯 Purpose

Prepare and operate a portable forensic response kit using Tsurugi **Bento**, with worked **Windows live-response procedures**, example PowerShell commands, app-by-app collection workflows, evidence verification, and a handoff to a deeper analysis workstation.

## ⚙️ Function

Covers original download verification, SyMenu's setup and licensed-tool imports, field USB preparation, scene documentation, volatile-state triage, Sysinternals/Windows artifact investigation, event-log export, memory acquisition, disk imaging decisions, hashing, chain-of-custody notes, field reports, and cleanup.

## 🏆 Goal

Move from **an approved incident** to a **documented, limited, integrity-checked collection** without confusing a portable toolbox with a validated forensic acquisition process.

## 📋 When to use

- Responding on site to a **running Windows workstation** whose state or incident indicators need rapid review.
- Recording **processes, current network connections, persistence, key event logs**, and selected host artifacts before shutdown or remediation.
- Collecting volatile memory or creating a disk image **only when the appropriate tool, permissions, capacity and safe procedure are available**.
- Preparing a reusable first-response USB/SSD and a separate encrypted evidence destination.
- Training responders on a controlled test PC/VM before handling real customer evidence.

**Not the right choice:** forensic imaging of a powered-off source that must stay read-only, long-running complete forensic examinations, active malware execution, or covert/unconsented access. Use appropriate boot/acquisition media, a hardware write blocker when required, and an isolated analysis workstation.

## Table of contents

1. [Understand Bento versus Tsurugi LAB and Acquire](#1-understand-bento-versus-tsurugi-lab-and-acquire)
2. [Download, verify, and prepare the kit](#2-download-verify-and-prepare-the-kit)
3. [First launch, SyMenu, and tool availability](#3-first-launch-symenu-and-tool-availability)
4. [Field readiness and legal authorization](#4-field-readiness-and-legal-authorization)
5. [Create a case and safely select the evidence destination](#5-create-a-case-and-safely-select-the-evidence-destination)
6. [Procedure A: live Windows system and network snapshot](#6-procedure-a-live-windows-system-and-network-snapshot)
7. [Procedure B: persistence, processes and suspicious executables](#7-procedure-b-persistence-processes-and-suspicious-executables)
8. [Procedure C: collect original Windows event logs](#8-procedure-c-collect-original-windows-event-logs)
9. [Procedure D: memory capture and acquisition](#9-procedure-d-memory-capture-and-acquisition)
10. [Procedure E: file/disk acquisitions and hashes](#10-procedure-e-filedisk-acquisitions-and-hashes)
11. [Procedure F: browser, USB and user-activity artifacts](#11-procedure-f-browser-usb-and-user-activity-artifacts)
12. [Practice a complete safe lab exercise](#12-practice-a-complete-safe-lab-exercise)
13. [Preserve, verify and report](#13-preserve-verify-and-report)
14. [Troubleshooting and limitations](#14-troubleshooting-and-limitations)
15. [Sources and adjacent PNWC guides](#15-sources-and-adjacent-pnwc-guides)

---

## 1. Understand Bento versus Tsurugi LAB and Acquire

The Tsurugi project maintains **three different products**; do not mix their operational assumptions.

| Product | What it is | Best use |
|---|---|---|
| **Bento** | A **portable collection of applications**, primarily for Windows, managed via **SyMenu** | **Live response and triage** on an already-running system |
| **Tsurugi Linux [LAB]** | A separately bootable/installable Linux DFIR and OSINT distribution | Full analysis, deeper investigation and other controlled workstation tasks |
| **Tsurugi Acquire** | A separate, lightweight Linux live acquisition image | Selected disk/forensic acquisition scenarios |

Bento's official documentation emphasizes **identification, information gathering, acquisition, seizure and preservation**. It explicitly says the kit is **not intended for extensive forensic analysis** beyond limited live investigation and triage.

Although the project lists some **Linux and macOS utilities**, Bento is **primarily a Windows application suite**. SyMenu and most of the GUI examples in this document are Windows-oriented. **Do not assume the Windows GUI launcher is a native Linux/macOS app**.

- Official: [Bento overview](https://tsurugi-linux.org/bento.php) · [documentation](https://tsurugi-linux.org/documentation_bento_toolkit.php).
- Related platform: [Tsurugi LAB](https://tsurugi-linux.org/tsurugi_linux.php) (separate OS; not installed by Bento).
- For subsequent deep analysis, use [Disk Forensics](./Disks/autopsy_kape.md), [Memory Forensics](./Memory/volatility_cheatsheet.md), or [Reverse Engineering](../../ReverseEngineering/README.md).

## 2. Download, verify, and prepare the kit

### 2.1 Get the official archive

1. Open the [Tsurugi downloads](https://tsurugi-linux.org/downloads.php) page and **choose a listed official mirror**.
2. Identify the current **Bento** archive. When checked on **2026-10-26**, the live downloads page showed **`bento_2026.10.7z`** (October 19, 2026), with an automatic-update capability. Its separate *tools listing and changelog pages* still describe **2025.8**, so do not equate their catalog with a verified 2026.10 executable inventory. **Do not confuse the 26.03 Tsurugi LAB release with the Bento archive version.**
3. The project publishes a **signed `signed_hashes.sha512`** manifest and a PGP public key (short key ID `0x116AD57C`). Independently confirm the full signing-key fingerprint through a trusted channel, verify the manifest signature, then check the digest for **your exact downloaded archive**. Do not accept a mismatch.
4. On a **trusted preparation workstation**, extract the 7z archive with a reputable archiver. Don't execute unknown files before verification.
5. Record kit archive name, date obtained, URL/mirror, manifest/signature verification result, SHA-512, preparation machine, and operator.

**PowerShell on the trusted Windows preparation machine:**

~~~powershell
# Compute, then compare with the digest from the VERIFIED signed manifest.
Get-FileHash -LiteralPath 'C:\Downloads\bento_2026.10.7z' -Algorithm SHA512 |
    Format-List Algorithm, Hash, Path

# Hashing alone DOES NOT verify the identity of the publisher.
# Validate the manifest signature/key using a trusted GPG installation,
# and confirm that the file's digest matches the correct signed entry.
~~~

**Never hard-code** a stale expected digest: the official archive may be replaced or updated. Validate files recovered from a backup as well as newly downloaded archives.

### 2.2 Build a dedicated response drive

Prefer **two separate purposes**:

- **Tool media:** verified, carefully maintained Bento toolkit on a removable SSD/USB. If hardware offers a **genuine write-protect switch**, use it when compatible with your workflow; Windows software "read-only" attributes and the contents of a normal USB alone are not equivalent to a hardware write blocker.
- **Evidence media:** independently labeled, **encrypted**, adequately sized external SSD or approved evidence store with access control. Keep original acquisitions **off the suspect's own system disk**. Confirm the actual drive identity, filesystem and available space; don't assume that the destination will always be `E:`.

Keep the **toolkit itself** out of the original evidence folder. Back up the known-good kit off-site, keep a local version log and test for malicious modifications before each field use.

> [!WARNING]
> Portable applications may create logs, temporary files, caches, registry keys and other side effects **on the host being investigated**. Do not advertise Bento as "forensically invisible" or "no installation, therefore no changes." Starting the toolkit or attaching USB media alters live evidence.

## 3. First launch, SyMenu, and tool availability

### 3.1 Open the menu in a staging Windows VM

1. Extract the archive on a clean preparation system and read any bundled README and application licenses.
2. Find and launch the **SyMenu launcher included in that archive**. Do not assume the launcher's path or executable name without checking the extracted release.
3. Review the **Bento menus**. The [official tool inventory (still labeled 2025.8 as of this review)](https://tsurugi-linux.org/documentation_bento_toolkit_tools_listing.php) lists categories including **Imaging, Hashing, Sys Info, Live IR, Artifacts Analysis, Network, Wi-Fi/Bluetooth, and Other Tools**.
4. Several applications are **listed but not bundled** because of copyright/licensing restrictions. **A menu item is not proof that an app is present or usable.** Test launch and identify each selected tool's publisher, license, version and OS compatibility.
5. On a **trusted online preparation machine**, use SyMenu's **Get new apps** feature to obtain missing tools according to the project's instructions; check vendor download/licensing requirements. Do not update or download during an active evidence collection.
6. Record and re-hash any toolkit modifications. Re-test the menu and procedures in a VM.

**Important:** The official **2025.8 changelog** notes that **Sysinternals tools can be retrieved through the update process**; don't assume they already exist in the archive. Anti-malware software may flag some digital forensic tools; verify provenance and investigate alerts **rather than disabling endpoint protection or adding blanket exclusions**.

### 3.2 Choose tools by forensic objective

This table is based on the official menu inventory **still labeled 2025.8**, not a confirmed 2026.10 package manifest; actual bundled binaries depend on what you've installed.

| Field goal | Menu category / candidate tools | Use and important restriction |
|---|---|---|
| Running processes | **Live IR:** Process Explorer, Process Hacker, CrowdInspect | View process trees, DLLs and parent relationships; **do not kill/suspend** before preservation |
| Persistence/startup | **Live IR → Sysinternals:** Autoruns; **Artifacts Analysis:** scheduled-task and registry viewers | **Observe/export**, don't disable/delete entries during evidence collection |
| Network endpoints | **Network/Wi-Fi:** CurrPorts, LiveTcpUdpWatch, TCPView; built-in `Get-NetTCPConnection` | Current connections; snapshots are transient and don't prove maliciousness |
| Volatile memory | **Imaging:** Magnet RAM Capture, WinPmem, RamCapture | May require separate download/elevation; sensitive, large, and not risk-free |
| Storage images | **Imaging:** FTK Imager Lite, DMDE, other acquisition options | Confirm product-specific capabilities, disk targeting and legal authorization |
| Artifact collecting | **Live IR:** gKAPE, CyLR, AChoir, DFIRTriage | Some tools need separate installations; test config/targets beforehand |
| Event logs | **Artifacts Analysis → Log:** FullEventLogView; native `wevtutil` | Review safely; preserve original `.evtx` through export |
| File hashing | **Hashing:** HashMyFiles, QuickHash GUI; native `Get-FileHash` | SHA-256/SHA-512 of source and destination |
| Local history | **Artifacts Analysis:** browser, JumpListsView, LastActivityView, USBDeview | Personal data; minimize scope and validate tool/version |
| System inventory | **Sys Info:** HWiNFO, WinAudit, WizTree | Live inventory; results not a sector-by-sector forensic image |

**Excluded by default:** credentials/password recovery modules (Mimikatz, LaZagne, browser password viewers and similar entries), credential disclosure, destructive Sysinternals tools, and indiscriminate bulk personal-data gathering. Such tooling needs a **separate documented need, legal authority and protection plan**, not a default triage step.

## 4. Field readiness and legal authorization

**Before attaching the kit to any customer's device**, document:

- Case / ticket ID, evidence custodian, requesting organization, investigator, date/time and local time-zone offset.
- Source hostname, device model/serial or asset number, current power state and encryption status (as observable).
- **Written authorization**, permitted host accounts and actions, authorized collection windows, data types, privacy/retention limits and third-party consent constraints.
- System risk: can the host be isolated? Will powering off destroy volatile state? Is there suspected destructive malware? Should incident command direct actions?
- Tool and evidence drive labels, encryption status, capacity, malware-handling instructions, escalation/rollback contact.
- What **not** to collect: private browsing histories, credentials, personal photos, legal/medical documents, and unrelated personal data outside scope.

**Practical rule:** preserve volatile data early if doing so is safe and justified, but **do not keep using a live compromised machine solely to collect more data** if continued activity is likely to destroy evidence or spread damage. Use the incident response lead's decision tree and [order-of-volatility guide](./LiveData/live_data_collection.md).

## 5. Create a case and safely select the evidence destination

These examples use **Windows PowerShell 5.1+** (available on supported Windows installations). They produce outputs **only on your chosen external evidence drive**, except that reading the live OS and running PowerShell and tools inevitably changes some volatile/system state.

> [!WARNING]
> **`E:` is an illustrative placeholder, not a safe default drive.** Check disk numbers, volume labels, BitLocker/unlock status, free space and drive letters first. Use only your approved **non-source** external evidence destination. Never select the suspect's `C:` drive or a source disk as the output volume.

**Preflight drive check (read-only queries):**

~~~powershell
# Inspect local volumes: identify your encrypted destination by label/size.
Get-Volume | Select-Object DriveLetter, FileSystemLabel, FileSystem,
    SizeRemaining, Size | Format-Table -AutoSize

# Where available, examine the mapping from volume to physical disk.
Get-Disk | Select-Object Number, FriendlyName, SerialNumber, BusType,
    OperationalStatus, Size | Format-Table -AutoSize
~~~

**Only after confirming the external destination by physical identity**:

~~~powershell
# REPLACE E: with YOUR confirmed, non-source, access-controlled evidence volume.
$EvidenceRoot = 'E:\DFIR_Cases'
$CaseId       = 'CASE-2026-001'
$Case         = Join-Path $EvidenceRoot $CaseId

# Verify these paths on the actual system before proceeding.
New-Item -ItemType Directory -Force -Path $Case | Out-Null
'raw','working','logs','reports','scope' | ForEach-Object {
    New-Item -ItemType Directory -Force -Path (Join-Path $Case $_) |
        Out-Null
}

# Record UTC independently of the possibly incorrect system clock.
[DateTime]::UtcNow.ToString('o') |
    Set-Content -LiteralPath (Join-Path $Case 'logs\start_utc.txt')
Get-Date -Format o |
    Set-Content -LiteralPath (Join-Path $Case 'logs\source_local_time.txt')
~~~

Suggested `scope\case-notes.md` content (write privately, not to a public repository):

~~~text
Case ID:
Authority / consent / limitations:
Operator, case owner and contact:
Source device / serial / user context:
Source local time, UTC observation, time-zone offset:
Suspected incident, questions and timeline:
External tool-media identification and SHA-512:
External evidence media identification and encryption:
Collection steps, command/tool versions and operator:
Errors, gaps and known live-host modifications:
Items transferred, hashes and custody receipts:
Findings (observed vs inferred), disposition and retention:
~~~

**Access control:** the case directory inherits the evidence volume's permissions. Encrypt the entire volume and apply restrictive ACLs according to the organization's policy; the folder-creation commands alone do **not** secure the folder.

## 6. Procedure A: live Windows system and network snapshot

**Scenario:** A user reports a suspicious remote-access session or unexpected outbound connection. Begin with a small, read-focused snapshot **before** remediation. Use PowerShell native commands if preferred; corresponding Bento GUI tools can corroborate results.

1. Record authorization, original complaint, clock offset and computer state.
2. Start an **authorized and appropriately privileged PowerShell** session. Some queries need administrator rights; if elevation would materially disrupt an investigation, stop and escalate.
3. Collect inventory, processes, services and TCP endpoints to the **confirmed evidence destination**.
4. Open Bento → **Live IR / Processes** (Process Explorer, if installed) to view process parents, signature and module relationships; save evidence/report or authorized screenshots. Do not kill processes or enable unintended cloud lookups.
5. Open **CurrPorts or TCPView** (if installed) for a point-in-time comparison. A connection table is **not** historical network telemetry.
6. Note errors and whether EDR, endpoint isolation or security software changed visibility.

~~~powershell
# Assumes the case directory and the E: destination were confirmed in `5.
Get-CimInstance Win32_OperatingSystem |
    Select-Object Caption, Version, BuildNumber, OSArchitecture,
        LastBootUpTime |
    Export-Csv -NoTypeInformation -Path "$Case\raw\os.csv"

Get-CimInstance Win32_ComputerSystem |
    Select-Object Name, Domain, Manufacturer, Model, TotalPhysicalMemory |
    Export-Csv -NoTypeInformation -Path "$Case\raw\host.csv"

Get-CimInstance Win32_Process |
    Select-Object ProcessId, ParentProcessId, Name, ExecutablePath,
        CommandLine, CreationDate |
    Export-Csv -NoTypeInformation -Path "$Case\raw\processes.csv"

Get-CimInstance Win32_Service |
    Select-Object Name, State, StartMode, PathName |
    Export-Csv -NoTypeInformation -Path "$Case\raw\services.csv"

Get-NetTCPConnection |
    Select-Object LocalAddress, LocalPort, RemoteAddress, RemotePort,
        State, OwningProcess, CreationTime |
    Export-Csv -NoTypeInformation -Path "$Case\raw\tcp-connections.csv"
~~~

**Interpretation:** Associate PIDs with process start times and parent processes. PIDs are reused; a connection may close between snapshots. Some command lines and process paths reveal sensitive information—restrict report access.

## 7. Procedure B: persistence, processes and suspicious executables

**Scenario:** A machine repeatedly launches an unfamiliar process after logon.

1. In **Live IR → Sysinternals**, launch **Autoruns** (or the included `AutorunsC/AutorunsC64` if installed) to **review** logon, services, scheduled tasks, Winlogon, WMI and other startup entries.
2. **Do not** uncheck, delete, disable, quarantine or auto-repair a suspicious entry during evidence preservation.
3. Use **Process Explorer** to correlate PID, parent, executable path, start time, loaded DLLs and publisher signature. A familiar filename or valid signature does **not** prove benign behavior.
4. Save a CSV through Autoruns' export function if available. If using the command-line tool, follow the **actual bundled binary's syntax** and use a read-only command without VirusTotal submission flags.
5. Export **native Windows scheduled-task metadata**, process and service snapshots for independent corroboration. Note privilege/scope restrictions.
6. Hash **an explicitly selected executable** without running or opening it. Preserve a controlled copy only if permitted; beware of antivirus quarantine or unsafe file sharing.

**Native Windows persistence snapshot (read-focused):**

~~~powershell
Get-CimInstance Win32_StartupCommand |
    Select-Object Name, Command, Location, User |
    Export-Csv -NoTypeInformation -Path "$Case\raw\startup-commands.csv"

Get-ScheduledTask |
    Select-Object TaskName, TaskPath, State |
    Export-Csv -NoTypeInformation -Path "$Case\raw\scheduled-tasks.csv"
~~~

**Example hash of an authorized local sample** (replace the file path; this **reads** the file but does not execute it):

~~~powershell
$SuspiciousFile = 'C:\Lab\test-sample.bin'  # Placeholder; replace only in scope
if (Test-Path -LiteralPath $SuspiciousFile -PathType Leaf) {
    Get-FileHash -LiteralPath $SuspiciousFile -Algorithm SHA256 |
        Export-Csv -NoTypeInformation -Path "$Case\reports\sample-hash.csv"
}
~~~

For signatures/reputation, prefer **local certificate and file-hash inspection first**. Sysinternals **Autoruns/Autorunsc VirusTotal integration may send file hashes or sample files** depending on settings. Keep it **off** until third-party disclosure is approved.

**Follow-up:** [Live Response Collection](./LiveData/live_data_collection.md), [phishing SOP](../../PlayBooks/sop_phishing_analysis.md), [malware/RE guides](../../ReverseEngineering/README.md).

## 8. Procedure C: collect original Windows event logs

**Scenario:** Confirm whether service failures, suspicious logons or remote-access installation occurred around a known incident.

Bento includes event-log viewers such as **FullEventLogView** (subject to availability). Use these to **inspect**, not to replace preservation of the source `.evtx` format.

**Export original live channels with Microsoft's `wevtutil`**, if authorized:

~~~powershell
# Native EVTX exports; require appropriate permission (Security generally
# requires elevation). Outputs must be on approved external evidence media.
wevtutil epl System "$Case\raw\System.evtx"
wevtutil epl Application "$Case\raw\Application.evtx"
wevtutil epl Security "$Case\raw\Security.evtx"

# Write down any errors / access denials; don't claim all exports succeeded.
Get-ChildItem -LiteralPath "$Case\raw" -Filter '*.evtx' |
    Select-Object Name, Length, LastWriteTimeUtc |
    Export-Csv -NoTypeInformation -Path "$Case\reports\evtx-inventory.csv"
~~~

**Never** use `wevtutil cl` or another command to **clear** logs. On servers/high-volume endpoints, large `.evtx` exports can consume substantial space and affect performance. Plan collection size and escalate if permission or disk space is insufficient.

For **non-destructive time-scoped review**, open the exported EVTX in a separate forensic workstation, or use a controlled query on an authorized log. Don't infer a complete incident timeline from a limited channel export or a single Event ID.

## 9. Procedure D: memory capture and acquisition

**Scenario:** A credible active compromise may require volatile memory for malicious processes, injected code, network sessions or encryption state.

The [Bento tools listing](https://tsurugi-linux.org/documentation_bento_toolkit_tools_listing.php) names **Magnet RAM Capture, WinPmem, RamCapture**, and **AVML (Linux)**. Due to licensing or packager availability, each may need a separate installation/import; do not assume it is ready on your media.

**Windows RAM procedure** (adapt to the exact acquisition tool documentation):

1. Obtain approval for memory capture, including potential collection of **passwords, session tokens, private documents and encryption keys** present in RAM.
2. Determine RAM size and ensure **evidence destination free space** comfortably exceeds the expected output. Some tools produce raw memory plus logs; an image can be larger than RAM or fragmented depending on format.
3. Note Windows version, build, time, relevant processes and any suspected malicious activity. Keep source encryption/BitLocker context recorded.
4. Prepare **offline/local output only** on the approved encrypted evidence disk; avoid writing the image onto the suspect's OS disk, network share, cloud sync or untrusted removable media.
5. Select the verified acquisition app in Bento → **Imaging**. Read **its own current help/license** and confirm it supports this OS/version and the desired output format.
6. Start acquisition with operator oversight. Recording RAM **may require a driver, elevate privileges and change system state**; document it.
7. Record start/end UTC, tool/version, output size, warnings/errors, and compute an **output SHA-256** when complete. Verify against a separate copy.
8. Store memory images with strict access; they may hold secrets. Move to an isolated [Volatility analysis workflow](./Memory/volatility_cheatsheet.md).

**Safer documentation example (no RAM capture initiated):**

~~~powershell
# Memory size inventory only. Verify enough encrypted external capacity.
Get-CimInstance Win32_ComputerSystem |
    Select-Object Name, TotalPhysicalMemory |
    Format-List

# AFTER an approved capture, hash the completed image without opening it:
# Get-FileHash -LiteralPath "$Case\raw\memory.raw" -Algorithm SHA256 |
#   Export-Csv -NoTypeInformation -Path "$Case\reports\memory_sha256.csv"
~~~

**Linux/macOS:** Bento is not a cross-platform universal wrapper. For Linux host acquisition, refer to the repository's [Linux live response section](./LiveData/live_data_collection.md), confirm AVML availability and kernel support in that environment, and use native documented instructions. For macOS use compatible forensic collection tools and current platform-specific guidance.

## 10. Procedure E: file/disk acquisitions and hashes

### 10.1 Full physical disk imaging (not a routine "portable file copy")

**Use when:** a complete disk/volume acquisition is specifically justified and safe, with adequate storage, source write-protection policy and legal authority.

1. Record device serial, source capacity, filesystem, current power/encryption state, BitLocker recovery/access status if relevant, and reason for live vs offline acquisition.
2. If the machine can be powered down safely and volatile collection is finished, **prefer an offline acquisition method** using appropriate write protection. A running Windows OS continuously modifies the disk; ordinary Bento file access does not prevent it.
3. In Bento → **Imaging**, check whether **FTK Imager Lite** or another approved imager is installed and supported on the specific OS. Some tools are not distributed in the archive and must be obtained from the vendor.
4. If the acquisition product offers source-image creation, choose the **correct source physical/logical disk** and approved **E01/RAW/other supported** format; never assume every Lite/portable variant has identical GUI choices.
5. Select **approved, separate evidence media** as the image destination (never the source). Record compression/segment settings and any read errors.
6. Use the tool's **verify-image** function if supported, and separately record SHA-256 of the final image or all segments with an independent tool.
7. Preserve original acquisition logs, checksum/report and verified image. Analyze a **duplicate** on a dedicated workstation such as [Tsurugi LAB](https://tsurugi-linux.org/tsurugi_linux.php) or tools in [Disk Forensics](./Disks/autopsy_kape.md).

**Never** run partition repair, `chkdsk /f`, permissions/ownership changes, delete/recovery, antivirus cleaning, or file "optimization" on an evidence source before preserving it.

### 10.2 Focused file-level collection (when full imaging is not necessary)

A logical file copy collects **selected files only**, not unallocated space, deleted data, alternate data streams or all filesystem metadata. Do not call it a forensic disk image.

1. Enumerate authorized filenames/paths; respect privacy scope and ensure you have legitimate access.
2. Use **FastCopy**, **TeraCopy**, or an approved collection tool from Bento's menu *only if installed*. Check copying/mirroring/sync options carefully—**never select a destructive synchronization mode**.
3. Copy to the approved external evidence volume, retain source pathname and metadata where possible, and log skipped/access-denied files and tool options.
4. Hash each collected file and compare with source hashes **where permitted**. If the source remains live, hashes can differ because a file changed during copying.
5. Prefer acquisition tools with documented metadata/ADS preservation and logging when that matters; ad hoc file copy is not equivalent.

**Example: hash one original file and its approved copy without modifying either:**

~~~powershell
$SourceFile = 'C:\Lab\benign-training.txt'      # Authorized example
$CopiedFile = "$Case\raw\benign-training.txt"   # Created by an approved copy step

# Both paths must exist; record errors if either is missing.
if ((Test-Path -LiteralPath $SourceFile -PathType Leaf) -and
    (Test-Path -LiteralPath $CopiedFile -PathType Leaf)) {
    $SourceHash = (Get-FileHash -LiteralPath $SourceFile -Algorithm SHA256).Hash
    $CopyHash   = (Get-FileHash -LiteralPath $CopiedFile -Algorithm SHA256).Hash

    [pscustomobject]@{
        SourcePath  = $SourceFile
        CopyPath    = $CopiedFile
        SourceHash  = $SourceHash
        CopyHash    = $CopyHash
        Match       = ($SourceHash -eq $CopyHash)
        CheckedUtc  = [DateTime]::UtcNow.ToString('o')
    } | Export-Csv -NoTypeInformation -Path "$Case\reports\copy-validation.csv"
}
~~~

## 11. Procedure F: browser, USB and user-activity artifacts

The official Bento menu lists **BrowsingHistoryView, ChromeHistoryView, FirefoxDownloadsView, JumpListsView, LastActivityView, USBDeview/USBLogView, ShellBagsView, UserAssistView** and more, subject to presence and Windows compatibility.

Use these with **a specific incident hypothesis** rather than gathering everything about everyone.

| Question | Bento tool candidates | What to record / caveats |
|---|---|---|
| Did a suspicious attachment download around the reported time? | Browser history/downloads viewers | Timestamp/time zone, browser/user context; cached data can be absent or misleading |
| Did an approved removable device attach during the incident? | USBLogView, USBDeview | Device ID, connection traces, UTC normalization; device history isn't proof of who used it |
| Is there evidence of a particular program being used? | JumpListsView, LastActivityView, UserAssistView | Corroborate with file metadata, event logs and process evidence |
| Does the host show repeated logon/startup behavior? | FullEventLogView, WinLogOnView, Autoruns | Preserve original logs and configuration before change |

**Procedure:**

1. Define the **accounts, times and artifact classes in scope**. Exclude unrelated personal profiles.
2. Launch the selected tool from **Artifacts Analysis** only if the binary is present and approved. Identify user/account, tool/version and data source.
3. Prefer reading **acquired copies** of profile/registry/event data when a tool supports offline mode. Reading a live browser database may encounter locks, temporary files or recent modifications.
4. Save export and observations to `working/`; preserve original acquired source to `raw/` with a SHA-256.
5. Normalize timestamp semantics: browser epoch formats, local time, Windows FILETIME and UTC are **not interchangeable**.
6. Avoid extracting stored browser passwords, cookies, OAuth tokens or unrelated browsing history without separate case approval. Do not place sensitive artifacts in screenshots or publicly shared reports.

## 12. Practice a complete safe lab exercise

Use a **throwaway Windows test VM you own**, with a known-good Bento copy and separate (virtual) evidence disk. This exercise **does not involve real malware, third-party machines or stealth access**.

**Scenario:** "A lab user noticed a new application and wants a concise system snapshot before troubleshooting."

1. **Preflight:** record date, VM name, OS build, tool and evidence volumes, authorization (your lab), and create the case folder using [section 5](#5-create-a-case-and-safely-select-the-evidence-destination).
2. **Generate benign activity:** launch Notepad and create a non-sensitive text file (e.g. `C:\Lab\benign-training.txt`).
3. **System snapshot:** execute the commands in [section 6](#6-procedure-a-live-windows-system-and-network-snapshot); note that Notepad was running during collection.
4. **Persistence check:** in [section 7](#7-procedure-b-persistence-processes-and-suspicious-executables), run the Windows startup commands. Use **Autoruns in observation-only mode** if available; don't disable a single entry.
5. **Event logs:** export System and Application as in [section 8](#8-procedure-c-collect-original-windows-event-logs); expect they may contain other unrelated entries—minimize what goes in the final report.
6. **File-level acquisition:** copy the harmless training file to your **separate evidence disk**. Run the source/copy validation from [section 10.2](#102-focused-file-level-collection-when-full-imaging-is-not-necessary); it should report `Match=True` if contents are unchanged.
7. **Manifest:** create a SHA-256 manifest of **raw/** as in [section 13](#13-preserve-verify-and-report). Confirm all intended evidence files exist, and document failures.
8. **Report:** write a timeline of "started VM → created test file → captured state → exported logs → verified file", including UTC timestamps and any limitations.
9. **Handoff:** mount a **copy** of the evidence disk to the analysis VM, verify hashes again and inspect only the copy.
10. **Post-lab review:** track which tools were missing/required downloading, which actions changed the live host, and whether the collected artifacts can actually answer the test question.

**Completion criteria:** a second investigator can identify every tool/version and dataset, reproduce hash verification, distinguish observed data from interpretation, and see exactly which live-host changes occurred.

## 13. Preserve, verify and report

### 13.1 Generate an independent manifest

Run only **after** acquisition/export processes finish. Hash the contents of `raw/`, and store the manifest in `reports/` so it doesn't hash itself. Do **not** treat a hash file as a signed custody record.

~~~powershell
# Assumes $Case points to the verified external evidence destination.
$Manifest = Get-ChildItem -LiteralPath "$Case\raw" -File -Recurse |
    Get-FileHash -Algorithm SHA256 |
    Select-Object @{Name='RelativePath';Expression={
        $_.Path.Substring((Join-Path $Case 'raw').TrimEnd('\').Length + 1)
    }}, Algorithm, Hash

$Manifest | Export-Csv -NoTypeInformation -Path "$Case\reports\sha256_manifest.csv"
~~~

**Independent check later (on the secured working copy):**

~~~powershell
$Saved = Import-Csv -LiteralPath "$Case\reports\sha256_manifest.csv"
$Root  = Join-Path $Case 'raw'
$Check = foreach ($Row in $Saved) {
    $File = Join-Path $Root $Row.RelativePath
    $Exists = Test-Path -LiteralPath $File -PathType Leaf
    $Actual = if ($Exists) {
        (Get-FileHash -LiteralPath $File -Algorithm SHA256).Hash
    } else { '' }

    [pscustomobject]@{
        RelativePath = $Row.RelativePath
        Exists       = $Exists
        Match        = $Exists -and ($Actual -eq $Row.Hash)
        Expected     = $Row.Hash
        Actual       = $Actual
    }
}
$Check | Export-Csv -NoTypeInformation -Path "$Case\reports\verification.csv"
$Check | Format-Table -AutoSize
~~~

If the manifest and evidence reside on the same writable device, both could be altered. Follow organizational policy for **tamper-evident storage, signatures, immutable/offline copies, and documented custody**. Never publish unredacted customer evidence.

### 13.2 Minimal field report outline

~~~text
CASE-2026-001/
├── scope/
│   └── case-notes.md               # Authorization, scope, operator
├── raw/
│   ├── os.csv
│   ├── processes.csv
│   ├── services.csv
│   ├── tcp-connections.csv
│   ├── System.evtx
│   └── Application.evtx
├── working/                        # Views, annotations, derivatives
├── logs/                           # UTC start/end, exceptions, transfer log
└── reports/
    ├── sha256_manifest.csv
    ├── verification.csv
    ├── findings.md
    └── custody-and-handoff.md
~~~

Report:
- **Observed** artifacts and exact tool/version/command.
- **Time**: recorded source clock vs independent UTC reference; uncertainty.
- **Limitations**: was evidence volatile, incomplete, modified or inaccessible?
- **Findings**: distinguish confirmed facts, hypotheses and alternative explanations.
- **Custody**: who possessed media; transfer time, purpose, hash, location.
- **Response plan**: preserve, isolate, escalate to IR lead, analyze on a dedicated workstation, and recommend follow-on collections/containment.

## 14. Troubleshooting and limitations

| Issue | Safe first check |
|---|---|
| Tool listed in Bento menu won't open | **Listed ≠ bundled**; verify extraction, architecture, license and optional `Get new apps` import on a preparation host. |
| AV/EDR flags an executable | Verify provenance/signature and company policy; **do not blindly disable AV or whitelist all tools**. |
| USB drive letters change | Re-identify disk by **label, physical serial, bus, capacity and approved evidence ID**, not by the sample's `E:` letter. |
| Output disk fills during RAM/imaging | Stop in a controlled manner, log incomplete output, preserve errors; don't overwrite existing evidence. |
| Security log export fails | Document access-denied result, request approved elevation or alternate acquisition; do not tamper with system permissions. |
| PowerShell command unavailable | Check Windows version/PowerShell version/module/elevation; use equivalent approved native tools or record gap. |
| Browser DB/viewer shows no records | Verify supported browser profile, user context, database locks, timestamps and the precise version of the viewer. |
| Source/copy hashes differ | Investigate live-file changes, incomplete copy, AV interference, target filesystem and acquisition method. Don't "fix" the evidence silently. |
| Windows/macOS/Linux portability confusion | Bento is **Windows-first**; Linux/macOS utilities have separate dependencies and workflows. |
| Examiner needs timeline/deep reverse engineering | Export and verify evidence, then use [Disk Forensics](./Disks/autopsy_kape.md), [Memory Forensics](./Memory/volatility_cheatsheet.md) or [Reverse Engineering](../../ReverseEngineering/README.md). |

### Operational limitations to disclose

- A live-host response **cannot make all collection read-only** or freeze volatile state.
- Running additional code can **disturb evidence** and trigger endpoint controls.
- Hash verification proves content equality under the selected hash algorithm, **not the origin, completeness, legality, or custody of the data**.
- Extracted tools from SyMenu may have different **versions, licensing, default upload behavior and permissions**.
- **Credential and password tools** appear in Bento's inventory but are not part of this general-purpose triage workflow.
- This document is a **reviewed procedure**, not a certification that a particular kit build, tool or case method has been field-tested and validated. Pilot test using non-sensitive lab data first.

## 15. Sources and adjacent PNWC guides

### Official Bento and vendor references
- [Tsurugi Bento documentation and scope](https://tsurugi-linux.org/documentation_bento_toolkit.php)
- [Official Bento download/release information](https://tsurugi-linux.org/downloads.php)
- [Bento menu inventory (published page labeled 2025.8)](https://tsurugi-linux.org/documentation_bento_toolkit_tools_listing.php)
- [Bento changelog (last entry currently shown: 2025.8) and Sysinternals update note](https://tsurugi-linux.org/documentation_bento_toolkit_changelog.php)
- [Microsoft Sysinternals: Autoruns](https://learn.microsoft.com/en-us/sysinternals/downloads/autoruns)
- [Microsoft: Get-FileHash](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.utility/get-filehash?view=powershell-5.1)
- [Microsoft: Get-NetTCPConnection](https://learn.microsoft.com/en-us/powershell/module/nettcpip/get-nettcpconnection)
- [Microsoft: wevtutil](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/wevtutil)

### Cross-references in the PNWC guide
- [Digital Forensics index](./README.md) · [Incident Response index](../README.md)
- [Live Response Collection](./LiveData/live_data_collection.md) · [Disk Acquisition and Autopsy/KAPE](./Disks/autopsy_kape.md)
- [Volatility Memory Forensics](./Memory/volatility_cheatsheet.md) · [Phishing Analysis SOP](../../PlayBooks/sop_phishing_analysis.md)
- [Blue Team Incident Response](../../PlayBooks/BlueTeam_IncResp_Enhanced.md) · [Reverse Engineering](../../ReverseEngineering/README.md)
- [SIEM and Log Collection](../SIEM/README.md) · [OPSEC](../../OPSEC/README.md)
- [Main repository](../../README.md) · [Legal Terms](../../LEGAL.md)

---

*Maintained by Pacific Northwest Computers. Source documentation checked October 26, 2026. All command examples are written for an authorized Windows lab/response environment; no claim is made that commands were executed on a specific Bento-equipped machine. Verify the current app versions, vendor licenses, destination identity, collection completeness and custody requirements before operational use.*
