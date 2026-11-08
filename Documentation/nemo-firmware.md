# NEMO Firmware: M5Stack Setup & Observation Lab

> [!CAUTION]
> **Authorized use only.** Use owned devices or an explicitly authorized lab.
> Define permitted collection, transmissions and data retention before testing.
> Read the [legal notice](../LEGAL.md). Device-owner permission does not override radio law.

_Last reviewed: 2026-11-07_

## Purpose

[NEMO by n0xa](https://github.com/n0xa/m5stick-nemo) is a compact M5Stack
Wi-Fi/BLE/IR research toolkit. This guide establishes a board-specific install
and harmless observation test; portal collection, BLE floods and disruptive IR
functions are outside the exercise.

## Hardware & Installation

| Check | Requirement |
|---|---|
| Board identity | Choose the exact M5StickC, Plus, Plus2, Cardputer or documented port. Board names and images are not interchangeable. |
| SD storage | Upstream enables SD by default on Cardputer; StickC-family storage can require an external reader and build changes. |
| USB | Cardputer USB analysis differs from StickC USB-to-serial hardware. An interface classification is not a malware verdict. |
| Installer | Upstream documents M5Burner desktop and release-binary/source routes. No dedicated NEMO browser installer was verified. |

1. Record the device model, existing image, settings and recovery method.
2. Get [M5Burner from M5Stack](https://docs.m5stack.com/en/download). In the
   correct device category, locate NEMO and verify the upstream README's publisher
   identity (`4x0nn` at review). Catalog names alone do not prove provenance.
3. Read the erase warning, select the matching device and flash. Alternatively,
   follow NEMO's exact release/source instructions rather than copying offsets
   from another M5 firmware or assuming a generic binary is merged.
4. Reboot, confirm version, display and button mapping. Inspect stored/startup
   options before choosing an app. Test on a dedicated bench network first.

## First Observation Exercise

1. Prepare an owned AP and BLE advertiser; note their identifiers and the expected
   band/channel. Set a short collection period and exclude other people's data.
2. Select Wi-Fi discovery and confirm the owned AP appears. A network scan can
   transmit probe requests; do not label it receive-only without verifying the mode.
3. On a BLE-capable target, use observation only and confirm the test beacon.
   Advertisement discovery does not demonstrate connection capture or decryption.
4. Optionally test IR with an owned receiver on a separate bench. Use only a
   known benign command and point the emitter away from unrelated equipment.
5. Record version, board, settings, expected devices and observed results. If the
   build provides an export, inspect the saved data instead of relying on counters.

## Interpretation & Recovery

| Observation | What It Does & Does Not Establish |
|---|---|
| A USB device exposes HID | It may be a legitimate keyboard. HID presence alone cannot establish malicious intent. |
| A USB device exposes only storage | That does not prove its firmware or files are safe. Use disposable test equipment. |
| No SD logs on a StickC | Check actual SD hardware/build support; Cardputer behavior does not transfer automatically. |
| Blank screen after install | Recheck the image/model and upstream recovery sequence; do not repeatedly flash unrelated targets. |

## Related Guides

| Resource | Use |
|---|---|
| [Plus2 Lab](../HardwareHacking/m5stickc-plus2-hackstarterpack.md) | Exact Plus2 accessories and wiring boundaries |
| [Bruce](./bruce_firmware.md) | Multi-radio alternatives and external modules |
| [Evil-M5](./evil_m5.md) | Separate firmware family and SD asset requirements |
| [Documentation Index](./README.md) | Section navigation |

## Review Scope

This is an original PNWC setup and benign validation workflow based on the linked
primary documentation. Source and navigation were reviewed; no physical board was
flashed, firmware compiled or radio behavior measured. Confirm current target
manifests and release notes before use; menu names and build requirements can change.

---

[Master Index](../README.md) | [Role Navigation](../START_HERE.md) | [Legal Notice](../LEGAL.md)
