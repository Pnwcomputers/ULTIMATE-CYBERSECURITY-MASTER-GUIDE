# Pico-Ducky: Safe USB HID Setup & Validation

> [!CAUTION]
> **Authorized use only.** Use owned devices or an explicitly authorized lab.
> Define permitted collection, transmissions and data retention before testing.
> Read the [legal notice](../LEGAL.md). Device-owner permission does not override radio law.

_Last reviewed: 2026-11-07_

## Purpose

[pico-ducky by dbisu](https://github.com/dbisu/pico-ducky) uses CircuitPython on
supported Raspberry Pi Pico boards to emulate a USB keyboard. This lab writes a
fixed phrase in an offline text editor. It needs no shell, credentials, network
access or third-party payload pack.

## Hardware & Compatibility

| Item | Boundary |
|---|---|
| Boards | Upstream documents Pico, Pico W, Pico 2 and Pico 2 W; choose the matching CircuitPython UF2. |
| Files | CircuitPython, its matching-major library bundle and the pico-ducky files are separate artifacts. Keep them from a consistent documented setup. |
| Script format | pico-ducky uses `payload.dd` and a supported DuckyScript subset; Hak5 `inject.bin` is not interchangeable. |
| Wireless variants | Pico W's runtime WebUI is not an ESP ROM flasher. Storage visibility and defaults differ between board variants. |

## Prepare Without Automatic Keystrokes

1. Use an owned disposable/offline host and an empty text editor. Unplug the
   board before wiring. Remove any unreviewed example payloads from the staging folder.
2. On a standard Pico header, upstream's setup mode connects **GP0 (physical pin 1)**
   to **GND (physical pin 3)**. Verify the actual board pinout first and fit this
   jumper while unpowered. Setup mode suppresses payload execution in the reviewed code.
3. Hold BOOTSEL while connecting and follow the upstream UF2 instructions for the
   exact model. Initial bootloader storage and CircuitPython's `CIRCUITPY` drive
   are different states; volume labels can vary by board generation.
4. Keep setup mode in place while installing the matching CircuitPython library
   bundle and required project files. Follow the current README file list instead
   of mixing files from unrelated releases.
5. Write only the benign script below as `payload.dd`. Keep USB mass storage
   visible for this lab; do not enable concealment options. Pico W storage defaults
   can differ, so use the documented setup/recovery path if the drive is absent.

## Fixed-Text Demonstration

```text
REM Authorized offline keyboard-awareness lab only.
DELAY 3000
STRING PNWC authorized HID test
ENTER
```

1. Save the script, safely eject storage, unplug and remove the setup jumper.
2. Focus the empty editor and connect the board. Expect exactly the phrase and
   one newline after the delay. Do not leave another app focused during the test.
3. Unplug immediately if behavior differs. Refit the setup jumper while unpowered
   before reconnecting for inspection. Do not repeatedly retry an unknown script.
4. Record board, CircuitPython/project version, keyboard layout, script hash and
   observed output. Remove the test script or return to setup mode when finished.

## Troubleshooting & Recovery

| Symptom | First Checks |
|---|---|
| Nothing types | Setup jumper still fitted, wrong payload selection, library mismatch, focus or delay. Inspect in setup mode. |
| Wrong symbols | Host keyboard layout and the project's supported layout implementation. |
| Missing storage | Board-specific USB/storage mode, `boot.py` and current upstream recovery instructions; use BOOTSEL only when recovery requires reflashing. |
| Import error / restart loop | Correct UF2 model, matching library-bundle major version and required project files. Preserve permitted files before recovery. |

## Related Guides

| Resource | Use |
|---|---|
| [USB Rubber Ducky Guide](../Scripts/Ducky/README.md) | Separate Hak5 compilation/deployment workflow |
| [Plus2 Lab](./m5stickc-plus2-hackstarterpack.md) | BLE/USB accessory differences on M5Stick hardware |
| [Firmware Catalog](../Documentation/esp32-security-firmware-catalog.md) | WiFi Duck, Pico WiFi Duck, BLE Keyboard and other distinct projects |
| [Hardware Hacking Index](./README.md) | Bench and platform navigation |

## Review Scope

This is an original PNWC setup and benign validation workflow based on the linked
primary documentation. Source and navigation were reviewed; no physical board was
flashed, firmware compiled or radio behavior measured. Confirm current target
manifests and release notes before use; menu names and build requirements can change.

---

[Master Index](../README.md) | [Role Navigation](../START_HERE.md) | [Legal Notice](../LEGAL.md)
