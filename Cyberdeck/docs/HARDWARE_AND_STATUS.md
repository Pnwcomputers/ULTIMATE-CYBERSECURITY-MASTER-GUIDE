# Hardware Roles & Implementation Status

[Cyberdeck Home](../README.md) · [Architecture](ARCHITECTURE.md) · [Workflow](ASSESSMENT_WORKFLOW.md)

The roles below are derived from the documented design of a separate PNWC private prototype. **A listed device does not mean that a physical unit was verified, flashed, integrated or tested.**

## Hardware Design Matrix

| Component | Reference Role | Publication/Validation State |
| --- | --- | --- |
| Windows 11 mini PC or supported Linux host | Local operator UI and guided steps | Private prototype feature; **no UI code in this public edition** |
| GL.iNet travel router | Upstream connectivity/repeater/WISP | Manual design; model/firmware/site mode must be established |
| MikroTik RouterOS router | Routed policy and segmented interfaces | Manual design; verify hardware, RouterOS features and port maps |
| ZimaBoard and attached storage | Proposed encrypted local evidence vault | Vault encryption, backup and restore **not proven by this edition** |
| ZimaBlade and Raspberry Pi | Optional local or offline sensors | Manual export/collector roadmap; no autonomous field agents shipped here |
| Kismet, Snort, Wazuh, nzyme | Monitoring and independent detection evidence | External products; no guaranteed packet visibility or integrated deployment |
| Flipper Zero, ESP32, specialist RF boards and Hak5 devices | Optional supervised, scope-qualified observation devices | Manual planning and imported exports only; no payload execution or radio control provided |
| Separate office/VPS sensor | Real outside-in origin | **Planned, not integrated here** |

## Capability Boundaries

| Capability | Private Prototype Documentation | Public Edition |
| --- | --- | --- |
| Local operator dashboard | Implemented as localhost prototype | **Not included** |
| Case records, guided questions, bounded one-IP Nmap | Implemented privately with safety restrictions | **Not included** |
| Device export ingestion and draft reports | Manual/partial private implementation | Documentation and example schema only |
| Device firmware/approval previews | Planning UI, not device drivers | Conceptual reference only |
| Offsite runner, automatic live hardware collection | Planned / partially prototyped | **Not included** |
| Signature provider validation and production evidence vault | Not yet qualified end-to-end | **Not included** |
| Read-only offline SHA-256 manifest of preexisting files | Public helper implemented here | **Included** |

## No Implicit Claims

Passing Python tests verifies only that the local manifest helper behaves as tested. It does not qualify a Wi-Fi chipset, hardware adapter, RouterOS configuration, customer scope, e-signature, IDS deployment, offsite runner or production security assessment.

[Release Checklist](PUBLISHING_AND_RELEASE.md) · [Lab Monitoring Visibility](../../Homelab/proxmox-security-monitoring-visibility.md).
