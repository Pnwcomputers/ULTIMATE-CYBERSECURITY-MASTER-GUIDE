# ESP32 C5 Wardriver: Setup, Modes & Log Validation

> [!CAUTION]
> **Authorized use only.** Use owned devices or an explicitly authorized lab.
> Define permitted collection, transmissions and data retention before testing.
> Read the [legal notice](../LEGAL.md). Device-owner permission does not override radio law.

_Last reviewed: 2026-11-07_

## Purpose

[JCMK ESP32 Dual Band Wardriver](https://github.com/justcallmekoko/ESP32DualBandWardriver)
collects Wi-Fi/BLE survey observations and saves WiGLE-format records to SD.
Use the [field workflow](./field-workflow.md) and [data rules](./data-handling.md).
It is separate from Marauder, Biscuit and the Flipper SigRoam application.

## Select Hardware & Mode

| Item | Requirement / Consequence |
|---|---|
| Board | Documented C5 DevKit/host-board build or LilyGo T-Dongle C5 build. The MCU identifier cannot distinguish their pin maps. |
| Normal mode | Standalone scanner needs SD, GPS and valid fix for the documented logging workflow. |
| Node mode | Forwards observations to a Core; node-local GPS/SD are not required. Do not expect a standalone CSV on the node. |
| Core mode | Receives node observations, applies location and logs; upstream says the Core does not itself collect survey observations. |
| Power | Follow the upstream DevKit 3V3-jumper warning for host-board/3V3-powered builds before energizing the assembly. |

## Installation & Privacy Setup

1. Record the board revision, GPS/SD wiring and power arrangement from the
   upstream hardware tables. Do not copy T-Dongle pins onto the DevKit build.
2. Back up authorized logs/settings. Open the
   [official C5 installer](https://justcallmekoko.github.io/C5WardriverInstaller/)
   in a supported desktop browser and select the exact hardware.
3. For a new device, unknown layout or firmware-family switch, use the documented
   **Clean / first install** route. It erases flash and writes the compatible layout.
4. Use **Update / preserve settings** only for an already compatible layout.
   Wait for completion and power-cycle; check the reported version and peripherals.
5. Review the boot/admin WebUI and saved settings. Disable or leave unconfigured
   WiGLE/WDGWars credentials, dock-trigger uploads and other automatic sharing
   until an explicit disclosure decision has been made. WebUI/network operation transmits.
6. Keep update binaries off the SD root during a normal survey: upstream documents
   automatic installation of a new root `.bin` at boot. Stage updates deliberately.

## Validate One Local Session

1. Select **Normal** for the initial single-device test. Record whether the choice
   was made in the WebUI (persistent) or on-device menu (temporary at review).
2. Acquire a stable GPS fix outdoors in an approved location and confirm SD status.
3. Observe owned APs on permitted 2.4 and 5 GHz channels and an owned BLE beacon.
   One C5 radio does not observe both bands simultaneously; note dwell/hopping limits.
4. Stop collection and download the actual CSV using the documented file/WebUI
   workflow. Inspect expected identifiers, coordinates, time and record types.
5. Preserve the original and hash it. Work from a copy for filtering or deliberate
   upload. Sidecar upload markers are not evidence that a survey row is accurate.

## Troubleshooting

| Symptom | Check |
|---|---|
| No local log | Normal versus Node/Core role, SD health, GPS fix and the designated logger. |
| Only Core is visible | A Core needs collection nodes; its own radio is not an independent survey source in this role. |
| Missing 5 GHz AP | Target/channel plan, regional permissions, channel dwell and firmware version; verify with a known AP. |
| Boots into an unexpected mode | Persistent WebUI mode versus temporary on-device selection and startup settings. |

## Related Guides

| Resource | Use |
|---|---|
| [Piglet](./piglet.md) | Different standalone/Core/Node implementation and file layout |
| [Marauder](./esp32-marauder.md) | Broad wireless toolkit rather than dedicated survey firmware |
| [Biscuit](./biscuit.md) | Phone-centric controller and export workflow |
| [Wardriving Index](./README.md) | Platform selection and field preparation |

## Review Scope

This is an original PNWC setup and benign validation workflow based on the linked
primary documentation. Source and navigation were reviewed; no physical board was
flashed, firmware compiled or radio behavior measured. Confirm current target
manifests and release notes before use; menu names and build requirements can change.

---

[Master Index](../README.md) | [Role Navigation](../START_HERE.md) | [Legal Notice](../LEGAL.md)
