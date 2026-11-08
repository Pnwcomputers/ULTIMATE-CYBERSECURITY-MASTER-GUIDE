# GhostESP Revival: Setup & Wireless Observation Lab

> [!CAUTION]
> **Authorized use only.** Use owned devices or an explicitly authorized lab.
> Define permitted collection, transmissions and data retention before testing.
> Read the [legal notice](../LEGAL.md). Device-owner permission does not override radio law.

_Last reviewed: 2026-11-07_

## Purpose

[GhostESP Revival](https://github.com/GhostESP-Revival/GhostESP) is an ESP-IDF-based
wireless research platform with board UI, serial and other target-dependent
interfaces. It is the maintained successor to the archived original GhostESP.
Use this guide for first installation, bounded Wi-Fi/BLE observations and capture
verification; broad functionality does not imply every build has every feature.

## Choose Hardware & Installation

| Requirement | Check Before Flashing |
|---|---|
| Target | Upstream lists WROOM, S2, S3, C3, C5, C6 and P4 variants; choose the exact board configuration, not just the chip name. |
| Radio | S2 has no Bluetooth; C5-capable builds can use 5 GHz. P4 designs depend on an external radio companion. |
| Storage / GPS | Confirm SD wiring, supported filesystem and GPS source in the board matrix. A GPS column is not proof your physical device contains GNSS. |
| USB / RF / NFC | Native USB and external CC1101/NRF24/NFC functions require their documented ports and peripherals. |

1. Save the previous firmware identity and authorized settings/logs. Record the
   board model, flash/PSRAM size, display and attached modules.
2. Open the [official flasher](https://ghostesp.net/flasher) with a browser and
   connection mode that it supports. Upstream specifically recommends this
   installer or its [release binaries](https://github.com/GhostESP-Revival/GhostESP/releases).
3. Select the exact board and stable release, review the erase warning, connect
   the correct port and complete installation without interrupting power.
4. Reboot, confirm the version and peripherals, and inspect boot/startup settings.
   Disable unneeded automation, uploads, third-party apps and transmit-capable tests.
5. Use [current project documentation](https://docs.ghostesp.net) for command
   syntax. Do not reuse original GhostESP commands or offsets without checking.

## Benign Observation Exercise

1. Prepare one owned access point and one owned BLE beacon. Record known channel,
   BSSID, advertisement identity and the approved collection window.
2. Use the build's observation/scanner interface and confirm both known devices.
   Do not enable active BLE scanning if the exercise requires receive-only collection;
   scan requests, WebUI AP operation and associated network discovery can transmit.
3. Where supported, record a short Wi-Fi or BLE capture to SD or stream it to an
   analysis host. Confirm the actual export format before opening it in Wireshark.
4. Check timestamps, channel/signal metadata and whether the known device appears.
   A graph or device counter alone does not prove that a useful capture was saved.
5. Stop collection, copy the original artifact and record its hash and settings.
   Separate any conversion/export from the preserved original. No upload is required.

## Troubleshooting & Recovery

| Symptom | First Checks |
|---|---|
| No BLE menu | Chip support first; an ESP32-S2 cannot gain BLE from another image. |
| Blank display / missing SD | Exact board target, flash size, wiring and matching assets; avoid random pin changes. |
| Empty capture | Correct band/channel, supported mode, storage and approved test-device activity. Channel hopping can miss frames. |
| Broken after a firmware switch | Back up first, then use the official installer/recovery procedure for the full target layout. |

## Related Workflows

| Resource | Use |
|---|---|
| [Marauder](../Wardriving/esp32-marauder.md) | Alternative wireless toolkit with a different target/client model |
| [Bruce](./bruce_firmware.md) | Alternative multi-radio module workflow |
| [Wardriving Data Handling](../Wardriving/data-handling.md) | Location identifiers, retention and deliberate sharing |
| [Firmware Catalog](./esp32-security-firmware-catalog.md) | Activity notes and broader platform selection |
| [Documentation Index](./README.md) | Return to section navigation |

## Review Scope

This is an original PNWC setup and benign validation workflow based on the linked
primary documentation. Source and navigation were reviewed; no physical board was
flashed, firmware compiled or radio behavior measured. Confirm current target
manifests and release notes before use; menu names and build requirements can change.

---

[Master Index](../README.md) | [Role Navigation](../START_HERE.md) | [Legal Notice](../LEGAL.md)
