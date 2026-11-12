# Hardware Roles & Implementation Status

[Cyberdeck Home](../README.md) · [Portable Wireless Field Workflow](PORTABLE_WIRELESS_FIELD_DEVICES.md) · [Device & Platform References](../README.md#device--platform-references) · [Architecture](ARCHITECTURE.md) · [Workflow](ASSESSMENT_WORKFLOW.md)

The roles below are derived from the documented design of a separate PNWC private prototype. **A listed device does not mean that a physical unit was verified, flashed, integrated or tested.**

## Hardware Design Matrix

| Component | Reference Role | Publication/Validation State |
| --- | --- | --- |
| Windows 11 mini PC (exact model unspecified) or supported Linux host | Local operator UI and guided steps | Private prototype feature; **no UI code in this public edition** |
| [GL.iNet travel router](https://www.gl-inet.com/pages/travel-routers) | Upstream connectivity/repeater/WISP | Manual design; model/firmware/site mode must be established |
| [MikroTik RouterOS router](https://manual.mikrotik.com/docs/introduction/) | Routed policy and segmented interfaces | Manual design; verify hardware, RouterOS features and port maps |
| [ZimaBoard](https://www.zimaspace.com/docs/hardware/) and attached storage | Proposed encrypted local evidence vault | Vault encryption, backup and restore **not proven by this edition** |
| [ZimaBlade](https://www.zimaspace.com/docs/hardware/zimablade-overview) and [Raspberry Pi](https://www.raspberrypi.com/products/) | Optional local or offline sensors | Manual export/collector roadmap; no autonomous field agents shipped here |
| [Kismet](https://www.kismetwireless.net/), [Snort](https://www.snort.org/), [Wazuh](https://wazuh.com/), [nzyme](https://www.nzyme.org/) (software) | Monitoring and independent detection evidence | External products; no guaranteed packet visibility or integrated deployment |
| [Flipper Zero](https://flipper.net/products/flipper-zero), [WiFi Pineapple](https://shop.hak5.org/products/wifi-pineapple), [M5StickC Plus2](https://docs.m5stack.com/en/core/StickC-Plus2) with [Bruce](https://github.com/BruceDevices/firmware), and [ESP32 Marauder](https://github.com/justcallmekoko/ESP32Marauder) | Optional supervised wireless/field inventory; [setup, exports and evidence procedure](PORTABLE_WIRELESS_FIELD_DEVICES.md) | **Manual** operation and reviewed exports only; no automatic device control, firmware interchangeability or completed hardware tests |
| Separate office/VPS sensor | Real outside-in origin | **Planned, not integrated here** |

**Hardware identification:** Confirm the specific board, interface and firmware before applying instructions from a linked manufacturer. The [ZimaBlade-to-ZimaBoard SE product update](https://shop.zimaspace.com/blogs/zima-campaign-hub/zimablade-is-now-zimaboard-se-product-update) concerns newer configurations; earlier ZimaBlade owners should use their original specifications. These hyperlinks do **not** imply functional integrations.

### Portable Wireless Device Qualification

The new [wireless field-device runbook](PORTABLE_WIRELESS_FIELD_DEVICES.md) documents Flipper/Marauder companion roles, standalone Marauder, Bruce on M5StickC Plus2, and Pineapple Mark VII/Pager. Every device has its **own** firmware, controller, collection mode, export location and stop action. See [Q15–Q18](ACCEPTANCE_TESTS.md) before any real deployment; nothing in the public release asserts those tests passed.

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

## Public Expansion Status

The public edition also supplies [offline manifest verification](../tools/verify_manifest.py), a [build runbook](BUILD_AND_OPERATIONS.md), an [acceptance matrix](ACCEPTANCE_TESTS.md), qualification/report templates and a [private implementation roadmap](IMPLEMENTATION_ROADMAP.md). These additions qualify no physical equipment and do not update independently unverified private prototype status.

## No Implicit Claims

Passing Python tests verifies only that the local manifest helper behaves as tested. It does not qualify a Wi-Fi chipset, hardware adapter, RouterOS configuration, customer scope, e-signature, IDS deployment, offsite runner or production security assessment.

[Release Checklist](PUBLISHING_AND_RELEASE.md) · [Lab Monitoring Visibility](../../Homelab/proxmox-security-monitoring-visibility.md).
