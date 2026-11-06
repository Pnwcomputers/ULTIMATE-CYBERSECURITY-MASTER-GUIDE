<a id="diagram-and-image-asset-index"></a>
# Diagram & Image Asset Index

_Last reviewed: 2026-11-02 (repository path and placement review; visual content not re-authenticated against live equipment)_

Return to [the main guide](../README.md) or [the visual reference notes](./imageplacement.md).

This folder stores diagrams as shared assets. Embed them in the **topic guide where they clarify a specific procedure** rather than repeating the same figure across multiple unrelated README pages. Captions should identify a diagram as conceptual when it does not describe a validated PNWC deployment.

<a id="integrated-png-and-svg-diagrams"></a>
## Integrated PNG & SVG Diagrams

| Image | Used in | Explanation |
|---|---|---|
| [AD attack paths](./ad_attack_paths.png) | [AD attacks and defenses](../Tradecraft/active-directory.md#kerberos-attacks) | Kerberos and AD risk-path illustration |
| [AI agent architecture](./ai_agent_arch.png) | [AI section](../AI/README.md) | Conceptual file-system-first agent/tool boundaries |
| [Hardware diagnostics](./hardware_diagnostics.png) | [Hardware Testing](../HardwareTesting/README.md) | Reference board-level diagnostic workflow |
| [Network architecture](./network_security_arch.png) | [Homelab](../Homelab/README.md) | Example segmented design, not a verified live topology |
| [RAM versus storage](./ram_vs_storage.png) | [Manjaro test bench](../HardwareTesting/Manjaro_Intel_TestBench.md#5-memory-and-storage-diagnostics) | Introductory CPU/RAM/storage mental model |
| [VM compartmentalization](./vm_compartmentalization.png) | [OPSEC guide](../OPSEC/README.md#principles) | Boundary illustration with important host/guest limitations |
| [Wireless auditing](./wireless_auditing.png) | [Network Audit Playbook](../PlayBooks/NetworkAuditPlayBook.md#section-2-wireless-specific-testing-procedures) | Wireless engagement workflow |
| [Penetration-test lifecycle](./pentest_lifecycle.png) | [Playbooks](../PlayBooks/README.md) | Assessment lifecycle overview |
| [JWrapper abuse case study](./jwrapper_attack.png) | [Incident Response](../IncidentResponse/README.md) | Illustrative remote-access-software abuse path, not proof of infection |
| [FIDO2 / passkey authentication](./fido2-passkey-authentication-flow.svg) | [Hardware keys and passkeys](../Cryptography/security-keys-passkeys.md#what-is-a-security-key) | **New accessible vector figure**, showing registration and sign-in |
| [Encrypted storage boundaries](./encrypted-storage-protection-boundaries.svg) | [Encrypted storage](../Cryptography/encrypted-storage.md#choose-the-right-design) | **New accessible vector figure**, locked versus unlocked data and backup limitations |
| [Journalist source-data lifecycle](./journalist-source-data-lifecycle.svg) | [Press freedom / source protection](../OPSEC/press-freedom/README.md#mission) | **New accessible vector figure**, preservation holds and approved disposition |

## Expanded Topical SVG Diagrams (November 2026)

These 19 newly authored diagrams provide short conceptual overviews beside the relevant guide sections. Each SVG contains a built-in title and description, uses local fonts and shapes only, and deliberately avoids asserting that a particular device, network or lab was tested.

| Diagram | Embedded guide | Purpose |
|---|---|---|
| [SIEM telemetry correlation](./diagrams/siem-telemetry-correlation.svg) | [IncidentResponse/SIEM/README.md](../IncidentResponse/SIEM/README.md) | Collect, normalize, correlate and validate events |
| [Honeypot sensor isolation](./diagrams/honeypot-segmented-logging.svg) | [IncidentResponse/HoneyPot/readme.md](../IncidentResponse/HoneyPot/readme.md) | Decoy isolation, log ingestion and safe triage |
| [Cloud shared responsibility](./diagrams/cloud-shared-responsibility.svg) | [Cloud/README.md](../Cloud/README.md) | Provider/customer security responsibilities |
| [Container trust boundaries](./diagrams/container-security-boundaries.svg) | [ContainerSecurity/README.md](../ContainerSecurity/README.md) | Supply chain and shared-kernel risks |
| [DFIR evidence lifecycle](./diagrams/dfir-evidence-custody.svg) | [IncidentResponse/Digital-Forensics/README.md](../IncidentResponse/Digital-Forensics/README.md) | Authorize, collect, verify, analyze and preserve |
| [OSINT verification](./diagrams/osint-verification-workflow.svg) | [OSINT/README.md](../OSINT/README.md) | Scope, corroborate, protect sources and report |
| [Wireless IDS correlation](./diagrams/wireless-ids-correlation.svg) | [IncidentResponse/IDS&IPS/readme.md](../IncidentResponse/IDS&IPS/readme.md) | Kismet/nzyme event correlation and evidence checks |
| [Web application testing](./diagrams/webapp-assessment-cycle.svg) | [WebAppSecurity/README.md](../WebAppSecurity/README.md) | Scope through retest with safe validation |
| [GRC control evidence](./diagrams/grc-controls-evidence.svg) | [Compliance/README.md](../Compliance/README.md) | Risk, mapping, control implementation and testing |
| [Reverse engineering](./diagrams/reverse-engineering-workflow.svg) | [ReverseEngineering/README.md](../ReverseEngineering/README.md) | Sample intake to defensible findings |
| [Space system segments](./diagrams/space-security-segments.svg) | [SpaceSecurity/README.md](../SpaceSecurity/README.md) | Ground, comms, spacecraft and user trust boundaries |
| [Wardriving data handling](./diagrams/wardriving-collection-lifecycle.svg) | [Wardriving/README.md](../Wardriving/README.md) | Passive survey quality, privacy and disclosure |
| [Data pipeline reliability](./diagrams/data-pipeline-reliability.svg) | [Data-Engineering/Phase2/README.md](../Data-Engineering/Phase2/README.md) | Contract, transformations, security and replay |
| [NanoVNA calibration](./diagrams/nanovna-calibration-plane.svg) | [SDR/nanovna/README.md](../SDR/nanovna/README.md) | Measurement reference plane and uncertainty |
| [Mobile security layers](./diagrams/mobile-security-boundaries.svg) | [Mobile/README.md](../Mobile/README.md) | Device, account, app, network and backups |
| [Incident response stages](./diagrams/incident-response-cycle.svg) | [IncidentResponse/README.md](../IncidentResponse/README.md) | Preparation through recovery and improvement |
| [Assessment checklist lifecycle](./diagrams/checklist-assessment-quality.svg) | [Checklists](../Checklists/README.md) | Authorization, coverage, evidence, QA and closure |
| [Safe script execution](./diagrams/safe-script-execution.svg) | [Scripts](../Scripts/README.md) | Code review, scope approval, rollback and results |
| [uConsole cautious setup](./diagrams/uconsole-six-phase-setup.svg) | [uConsole](../uConsole/README.md) | Model-aware, opt-in six-phase CM5 workflow |

For an auditable record of the visual coverage review and remaining improvements, see [Visual Audit — 2026-11-02](./VISUAL-AUDIT-2026-11-02.md).

## Already Embedded In Hardware Chapters

| Asset | Chapter |
|---|---|
| [Trust boundary](./CollapsingtheTrustBoundary.jpg) | [Hardware Hacking — Chapter 1](../HardwareHacking/Chapter1.md) |
| [UART](./UART.jpg), [SPI](./SPI.jpg), [I²C](./i2c.jpg), [JTAG](./JTAG.jpg), [Shunt setup](./ShuntSetup.jpg) | [Hardware Hacking — Chapter 2](../HardwareHacking/Chapter2.md) |
| [Clock/voltage glitch](./ClockvsVoltage.jpg), [EMFI](./ElectromagneticFaultInjection.jpg), [Laser FI](./LaserFaultInjection.jpg) | [Hardware Hacking — Chapter 3](../HardwareHacking/Chapter3.md) |
| [SPA on RSA](./SPAonRSA.jpg) | [Hardware Hacking — Chapter 4](../HardwareHacking/Chapter4.md) |
| [CPA correlation](./CPACorrelationProcess.jpg) | [Hardware Hacking — Chapter 5](../HardwareHacking/Chapter5.md) |
| [Master guide banner](./cybersecurityguide.png) | [Master README](../README.md) and [START HERE](../START_HERE.md) |

## Additional Asset Awaiting Placement

- [advnacedflows.jpg](./advnacedflows.jpg) — a large image with an ambiguous filename. **Not embedded automatically** because its intended subject has not been visually verified; avoid mismatched or misleading placement. Review the image and rename or document its subject before assigning it.

## Image Guidelines

1. Use a **relative path from the embedding Markdown file**; for a root-level page use `./assets/image.png`, for a one-level-deep section use `../assets/image.png`, and for a two-level-deep section use `../../assets/image.svg`.
2. Provide meaningful Markdown alt text and a short caption, including whether the image is *conceptual* or based on verified deployment/test data.
3. Avoid claiming an illustration proves encryption security, exploitability, network isolation, or real-world device behavior.
4. Keep SVG assets static: no script, animation, external fonts or third-party image dependencies. Preserve the embedded `title` and `desc` for accessibility.
5. When an image is superseded, update all backlinks and run repository lint/link checks. Maintain this table.

---

[Master README](../README.md) | [Role Navigation](../START_HERE.md) | [Visual reference notes](./imageplacement.md)
