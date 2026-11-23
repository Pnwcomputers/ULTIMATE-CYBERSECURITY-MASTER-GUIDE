# PNWC WinPE: Offline Recovery & Triage

_Integration prepared: 2026-11-23 · Boot & hardware validation: not performed._

[PNWC WinPE Builder](https://github.com/Pnwcomputers/PNWC-WinPE-Builder) is the
companion source repository for building a customized x64 Windows
Preinstallation Environment (WinPE) with a technician launcher and locally
supplied tools. Use its README for current prerequisites, parameters, build
instructions, known limitations and validation status.

## Purpose & Scope

Use the image for authorized Windows deployment and recovery, including access
to an unbootable installation and offline inspection needed for a recovery
decision. Microsoft limits WinPE to deployment and recovery; it is not a
general-purpose operating system or a hardware-validation platform.
Use a supported full operating system for qualification, stress tests and
benchmarking. See [Microsoft's WinPE overview](https://learn.microsoft.com/en-us/windows-hardware/manufacture/desktop/winpe-intro?view=windows-11).

This integration provides a route between the builder and the guide's existing
incident-response procedures. A menu entry or successful download does not prove
that a third-party application works in WinPE.

> [!CAUTION]
> This is a technician recovery environment, not a forensic write blocker.
> Booting another operating system loses the original running system's volatile
> state. Preserve required live evidence before rebooting, and protect source
> disks using a validated acquisition process when evidentiary integrity matters.

## Choose The Right Workflow

| Goal | Recommended Route |
| --- | --- |
| Capture RAM, active connections or running processes | Use [live-data collection](./LiveData/live_data_collection.md) before shutdown; WinPE cannot recreate the previous running state. |
| Recover an unbootable Windows installation | Evaluate PNWC WinPE on a lab clone first, then follow the approved recovery plan. |
| Acquire a source disk for investigation | Follow [disk acquisition & analysis](./Disks/autopsy_kape.md), including write protection, hashes and custody records. |
| Analyze copied EVTX or other artifacts | Use verified copies and the relevant tool workflow; confirm dependencies and rule sets separately. |
| Triage a running endpoint without rebooting | Compare [Tsurugi Bento](./tsurugi-bento-portable-dfir-guide.md) and [Velociraptor collection](./velociraptor-artifact-triage.md). |
| Qualify hardware or run long stress tests | Use the [Hardware Testing](../../HardwareTesting/README.md) full-OS procedures. |

The sequence follows the evidence-preservation principles in
[RFC 3227](https://www.rfc-editor.org/rfc/rfc3227): prioritize transient state,
record actions and preserve collected material. Recovery changes and forensic
acquisition are different decisions; document which is authorized for the case.

## Build Inputs & Distribution

| Input | Handling |
| --- | --- |
| Microsoft ADK & matching WinPE add-on | Obtain from Microsoft using the builder's documented setup route and applicable terms. |
| Storage & network drivers | Supply architecture-compatible, trusted vendor packages needed for the target hardware. |
| Updates | Supply packages applicable to the chosen WinPE/ADK version; record their identities. |
| Third-party tools & rule sets | Obtain through the documented upstream sources; review licenses, versions and WinPE support. |
| Commercial keys & gated packages | Keep in private local storage; do not commit keys, customer data or licensed payloads. |
| ISO, USB or VHD output | Build locally. The source repository is not a bundled Windows image or a grant to redistribute third-party software. |

The builder's source-code license does not replace Microsoft or tool-vendor
terms. Do not assume that a free download permits business use or redistribution.
Review the relevant vendor terms for the exact package and use.

## Field Procedure

1. Record authorization, asset identity, recovery objective and the evidence
   that must survive the intervention. Use the
   [Incident Response index](../README.md) to choose a case workflow.
2. Decide whether RAM or running-system state must be collected before reboot.
   If so, complete and verify that acquisition first.
3. Build and boot-test the exact image on an isolated lab system. Record the
   builder revision, ADK/WinPE version, drivers, updates, tool versions and
   available integrity evidence. Keep failures visible in the build record.
4. Confirm the actual target disks and separate output destination. When
   evidence preservation is required, use validated write protection and
   acquisition tooling before inspecting source media.
5. Use a separate protected destination for reports, acquired artifacts and
   recovery output. The WinPE RAM drive is temporary; do not rely on it for
   retained evidence.
6. Review startup network behavior and connect only as permitted by the case
   plan. Network access, signature updates and remote services require their
   own environment-specific checks.
7. Record commands, timestamps, output paths, hashes and observed failures.
   Preserve original evidence; perform analysis and recovery trials on copies
   where practicable.

## Validation Record

Before field use, retain evidence for the exact image and target platform:

- Successful image creation and boot on the intended firmware mode.
- Required storage and network devices detected with the intended drivers.
- Each required tool launched and exercised on synthetic or duplicate data.
- Reports and acquisition output retained after shutdown on the correct device.
- Source-disk access, write-protection behavior and output hashes checked for
  the chosen acquisition procedure.
- Secure Boot behavior checked against the target firmware and image version,
  rather than inferred from a build flag.
- License, update and tool-source records reviewed for the planned use.

This integration does not claim a completed WinPE build, boot test, tool
compatibility certification or forensic validation. Follow the
[Repository Verification Protocol](../../Documentation/REPOSITORY-VERIFICATION-PROTOCOL.md)
when recording those checks.

## Related Guides

| Resource | Description |
| --- | --- |
| [PNWC WinPE Builder](https://github.com/Pnwcomputers/PNWC-WinPE-Builder) | Canonical source, build instructions, examples and issue tracker. |
| [Digital Forensics Index](./README.md) | Evidence collection, memory, disk and artifact-analysis routes. |
| [Live Response](./LiveData/live_data_collection.md) | Volatile collection before reboot or shutdown. |
| [Disk Forensics](./Disks/autopsy_kape.md) | Acquisition, artifact extraction and analysis. |
| [Hardware Testing](../../HardwareTesting/README.md) | Separate full-OS hardware qualification workflows. |

---

[Back to Master Index](../../README.md) | [Role Navigation](../../START_HERE.md) | [Legal Notice](../../LEGAL.md)
