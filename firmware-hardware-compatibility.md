# FIRMWARE & HARDWARE COMPATIBILITY CHART

## Device-First Current Selection

Use the [device firmware list](./Documentation/device-firmware-list.md) for named boards, verified project choices and install formats. It complements the project catalog and avoids treating a broad chip-family checkmark as exact board support.

## New Firmware Target Notes

| Resource | Role & Compatibility Boundary |
|---|---|
| [GhostESP Revival](./Documentation/ghostesp-revival.md) | Upstream lists multiple ESP variants, but target configuration determines display, SD, USB and radio support; S2 lacks BLE. |
| [ESP32 Bit Pirate](./HardwareHacking/esp32-bit-pirate.md) | S3-specific documented builds; do not infer compatibility from the unrelated generic BitPirate adapter note. |
| [C5 Wardriver](./Wardriving/esp32-c5-wardriver.md) | C5 DevKit/host-board and T-Dongle are distinct targets despite identical MCU family. |
| [Piglet](./Wardriving/piglet.md) | XIAO S3/C3/C6/C5 and T-Dongle build/profile requirements differ; 5 GHz requires C5. |
| [Pico-Ducky](./HardwareHacking/pico-ducky-lab.md) | Pico-family CircuitPython images and files; not an ESP firmware or Hak5 inject.bin target. |
| [Evil Crow RF V2](./SDR/evil-crow-rf-v2.md) | Dedicated ESP32 + dual-CC1101/NRF board; not a generic board solely because the MCU is ESP32. |

## Current Firmware References

| Resource | Description |
|---|---|
| [ESP32 & Related Firmware Catalog](./Documentation/esp32-security-firmware-catalog.md) | Current upstream target examples, activity notes & compatibility boundaries |
| [Firmware Web Flashers](./Documentation/firmware-web-flashers.md) | Dedicated installers & multi-device upload tools |

> [!WARNING]
> This page no longer contains a compatibility matrix. The retired chart's broad
> checkmarks and historical claims were not confirmation of a specific board,
> release or feature. Use the device-first links below and verify the exact
> target with upstream before buying hardware or flashing.

## Wireless Security Testing Devices
**Plus2 clarification:** [M5StickC Plus2 / HackStarterPack source review](./HardwareHacking/m5stickc-plus2-hackstarterpack.md) notes the separate hardware/accessories. Generic M5Stick-family checkmarks below are not proof of compatibility with a specific firmware version or USB HID.



**ESP32-C5 / Flipper wardriving hardware and firmware pairings:** see the dedicated [Wardriving index](./Wardriving/README.md), [SigRoam / Scout Lite](./Wardriving/sigroam-scout-lite.md), [Marauder](./Wardriving/esp32-marauder.md), [Biscuit](./Wardriving/biscuit.md) and [AWOK Dual C5](./Wardriving/awok-dual-c5-biscuit.md). Their image targets, GPS source and log location differ by operating mode.


**Last Updated:** October 2025  
**Purpose:** Quick reference guide for firmware compatibility across common penetration testing hardware

---

## Purpose

This page routes readers to current, source-specific firmware and hardware
references. It does not certify universal compatibility or summarize every
firmware feature as a tested fact.

## How To Choose A Device

Start with the [Device Firmware List](./Documentation/device-firmware-list.md)
for the exact board and firmware target. Then check the upstream release notes
and the dedicated guide linked from the [ESP32 & Related Firmware Catalog](./Documentation/esp32-security-firmware-catalog.md).
A chip-family match alone does not confirm a board revision, display, storage,
radio module, pin map or firmware build.

## When To Use This Page

Use this page to find current reference material before selecting hardware or
installing firmware. Treat source checks and local fixture tests as distinct
from a physical device test; see the
[Repository Verification Protocol](./Documentation/REPOSITORY-VERIFICATION-PROTOCOL.md).

---

## Wireless Security Testing Devices

**Plus2 clarification:** The [M5StickC Plus2 / HackStarterPack source review](./HardwareHacking/m5stickc-plus2-hackstarterpack.md)
covers that specific device and its accessories. Do not infer firmware
compatibility from a broad M5Stick-family label.

**ESP32-C5 / Flipper wardriving hardware and firmware pairings:** Use the
[Wardriving index](./Wardriving/README.md), [SigRoam / Scout Lite](./Wardriving/sigroam-scout-lite.md),
[Marauder](./Wardriving/esp32-marauder.md), [Biscuit](./Wardriving/biscuit.md)
and [AWOK Dual C5](./Wardriving/awok-dual-c5-biscuit.md). Their targets, GPS
sources and log locations vary by device and operating mode.

## Retired Compatibility Matrix

The older matrix, capability summaries, hardware rankings and purchase-price
estimates have been removed. They combined broad chip-family labels and
unsourced, time-sensitive details without release-specific evidence. Those
checkmarks and rankings should not be treated as compatibility or performance
claims.

Use the current [Device Firmware List](./Documentation/device-firmware-list.md)
and [ESP32 & Related Firmware Catalog](./Documentation/esp32-security-firmware-catalog.md)
instead. Both direct readers to upstream project references and state the
limits of their evidence. A source page can establish what a project documents;
it does not establish that a particular local device or build works.

## Source-Checked Compatibility Notes

Reviewed against project documentation on **November 11, 2026**. The notes below
correct specific errors from the retired chart; they are not hardware test
results.

### Pwnagotchi

The upstream [installation guide](https://pwnagotchi.ai/installation/) identifies
the Raspberry Pi Zero W as its baseline. It says Raspberry Pi 3 and 4 or another
GNU/Linux host may work with configuration changes; it does not establish
Raspberry Pi Zero 2 W as a supported upstream target. Support in a fork or
third-party image must be checked against that project's own release and guide.

The upstream [usage guide](https://pwnagotchi.ai/usage/) distinguishes MANU,
AUTO and AI modes: MANU does not capture handshakes, while AUTO uses configured
behavior and AI mode loads the documented learning component. Do not describe
all modes as passive collection or imply that every fork retains the same AI
behavior. Displays are optional; consult the upstream
[configuration guide](https://pwnagotchi.ai/configuration/) for its specific
supported display implementations.

### P4wnP1 A.L.O.A.

The official Kali [P4wnP1 A.L.O.A. image guide](https://www.kali.org/docs/arm/raspberry-pi-zero-w-p4wnp1-aloa/)
states that this image supports Raspberry Pi Zero W, not Zero 2 W. The upstream
[project README](https://github.com/RoganDawes/P4wnP1_aloa) documents USB device
emulation, HIDScript, Wi-Fi access-point/station configuration, and Bluetooth
stack support. It describes Bluetooth networking features; that is not the same
as a general Bluetooth attack framework. The README also says its included
Nexmon monitor mode is unsupported and may be unstable.

Control is through the project's browser web client or CLI; the README says the
web client is intended to work in mobile and desktop browsers. It does not
document a native smartphone app. Change documented default credentials before
use and keep experiments within an isolated, authorized lab.

## Hardware Selection & Pricing

This page no longer ranks devices as “best” or publishes price estimates.
The earlier prices were not tied to dated vendor listings, and firmware
compatibility depends on exact board revisions and project releases. Check the
manufacturer's specification page and the firmware project's current target
list before purchase.

## Review Record

- **November 11, 2026:** Removed the unsupported universal compatibility
  checkmarks, broad capability claims, device rankings and unverified price
  estimates. Corrected the Pwnagotchi and P4wnP1 notes against their project
  documentation. No physical hardware test was performed.

---

## Related Files
- [README.md](README.md) - Repo index
- [HardwareHacking/](HardwareHacking/) - Hardware hacking tool guides
- [uConsole/README.md](uConsole/README.md) - uConsole compatibility details
- [Documentation/flipper_zero_guide.md](Documentation/flipper_zero_guide.md) - Flipper Zero guide

---
[⬅️ Back to Master Index](README.md) | [🎯 Role Navigation](START_HERE.md) | [Legal Notice](LEGAL.md)
