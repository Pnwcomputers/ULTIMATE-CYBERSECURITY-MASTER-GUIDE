# Evil Crow RF V2: Firmware Setup & Receiver Validation

> [!CAUTION]
> **Authorized use only.** Use owned devices or an explicitly authorized lab.
> Define permitted collection, transmissions and data retention before testing.
> Read the [legal notice](../LEGAL.md). Device-owner permission does not override radio law.

_Last reviewed: 2026-11-07_

## Purpose

[Evil Crow RF V2](https://github.com/joelsernamoreno/EvilCrowRF-V2), by Joel Serna
and collaborators, uses an ESP32, two CC1101 narrowband radios and an NRF24L01.
It is a protocol-oriented RF tool, not an IQ-streaming SDR like HackRF. This guide
validates installation and receiver behavior without replaying access-control signals.

**Prerequisites:** [Sub-GHz concepts](./subghz.md), identified hardware revision,
suitable antennas, a controlled RF bench and an owned test transmitter.

## Firmware & Hardware Choices

| Choice | Consequence |
|---|---|
| Vendor default | Use the upstream V2 sketch, dependency versions and SD HTML assets as a matched set. |
| [h-RAT custom firmware](https://github.com/h-RAT/EvilCrowRF_Custom_Firmware_CC1101_FlipperZero) | Separate community implementation linked by vendor upstream; verify V1/V2 wiring, build and file-format support independently. |
| Browser control | Runtime Wi-Fi web panel controls the installed firmware. It is not a verified initial-install web flasher. |
| Radio module | CC1101 handles supported narrowband Sub-GHz signals; NRF24L01 is a different 2.4 GHz transceiver. Neither is universal Bluetooth/Wi-Fi capture hardware. |

## Install A Matched Firmware & Web Interface

1. Record the hardware revision and original image/settings, disconnect targets
   and plan the documented recovery route. Do not assume an arbitrary ESP32 image fits.
2. Follow the upstream README's Arduino core and library requirements. At review,
   its default build specifies ESP32 Dev Module with 4 MB flash; verify all other
   settings and dependency versions in that same source before building.
3. Build/upload the vendor V2 sketch using its documented method. No dedicated
   project web flasher was verified; an unknown community installer is not a substitute
   for checking the exact image and flash layout.
4. Copy the matching `firmware/SD/HTML` directory as upstream instructs. The
   reviewed README recommends a card no larger than 32 GB when troubleshooting.
   Missing assets can yield an empty panel even though the MCU boots.
5. Use an isolated bench Wi-Fi network and the current upstream connection
   instructions. Confirm the assigned address, loaded panel and firmware identity.
   Replace defaults where supported and keep management access off public networks.

## Receiver-Only Bench Exercise

1. Choose an owned transmitter and a permitted band/modulation that the selected
   CC1101 hardware supports. Use a conducted or appropriately shielded arrangement
   with compatible attenuation; do not connect arbitrary signal levels directly.
2. Configure one receiver using the documented frequency, modulation and data-rate
   settings for the known test signal. Keep transmit/replay/jamming functions unused.
3. Send one harmless test event from the owned transmitter. Record receiver
   settings, approximate timing and the captured representation.
4. Repeat a small number of times and compare results with an independent receiver
   where available. A raw pulse log is not an IQ file or a validated protocol decoder.
5. Preserve the original log and settings with a hash. Keep RFID/access-control
   identifiers and captured production signals out of shared examples.

## Troubleshooting & Interpretation

| Symptom | Check |
|---|---|
| Empty web panel | Matching HTML assets, SD insertion/filesystem/card size and network addressing. |
| No received event | Correct radio selected, antenna band, modulation/data rate, wiring and signal level. |
| Unstable or clipped reception | Coupling/distance/attenuation and independent receiver confirmation; more gain is not always better. |
| Custom firmware reads a file differently | Compare supported formats, timing units and target revision; a familiar extension is not proof of compatibility. |

## Related Guides

| Resource | Use |
|---|---|
| [SDR Index](./README.md) | Radio/platform selection |
| [Sub-GHz](./subghz.md) | Narrowband protocols and radio-module boundaries |
| [Bruce](../Documentation/bruce_firmware.md) | Separate ESP32 toolkit with external CC1101/NRF modules |
| [HackRF Playbook](../PlayBooks/HackRFAuditPlayBook.md) | Independent spectrum/IQ evidence and RF bench validation |
| [Firmware Catalog](../HardwareHacking/esp32-security-firmware-catalog.md) | Primary projects, activity notes and install routes |

## Review Scope

This is an original PNWC setup and benign validation workflow based on the linked
primary documentation. Source and navigation were reviewed; no physical board was
flashed, firmware compiled or radio behavior measured. Confirm current target
manifests and release notes before use; menu names and build requirements can change.

---

[Master Index](../README.md) | [Role Navigation](../START_HERE.md) | [Legal Notice](../LEGAL.md)
