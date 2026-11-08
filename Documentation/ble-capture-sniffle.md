# BLE Capture: Sniffle Setup & Scanner Selection

> [!CAUTION]
> **Authorized use only.** Use owned devices or an explicitly authorized lab.
> Define permitted collection, transmissions and data retention before testing.
> Read the [legal notice](../LEGAL.md). Device-owner permission does not override radio law.

_Last reviewed: 2026-11-07_

## Purpose

Choose between advertisement inventory and protocol packet capture, then validate
an owned BLE beacon with [NCC Group Sniffle](https://github.com/nccgroup/Sniffle).
Bluetooth Low Energy (BLE), Bluetooth Classic and USB/BLE keyboard emulation are
different protocols and functions. A device list is not a connection trace.

## Select The Right Firmware

| Project | Appropriate Role & Limits |
|---|---|
| [ESP32-BLECollector](https://github.com/tobozo/ESP32-BLECollector) | Advertisement observations persisted to SQLite on supported ESP32/display/SD hardware. Older dependencies need separate compatibility review. |
| [GhostESP](./ghostesp-revival.md) | Combined Wi-Fi/BLE research; actual capture/export features vary by target and build. |
| [Sniffle](https://github.com/nccgroup/Sniffle) | BLE 4/5 packet capture on supported TI hardware; match PHY, target and host/firmware version. |
| [Ubertooth](https://github.com/greatscottgadgets/ubertooth) | Dedicated Bluetooth research hardware and host stack; not an ESP32 image or a universal BLE 5 decoder. |
| [Btlejack Firmware](https://github.com/virtualabs/btlejack-firmware) | Legacy micro:bit v1/nRF51822 research; PHY and BLE 5 limitations apply. |
| [InternalBlue](https://github.com/seemoo-lab/internalblue) | Broadcom/Cypress chip/ROM-specific instrumentation; not an off-the-shelf sniffer image. |

## Sniffle Setup

1. Select a TI target explicitly listed upstream, such as an appropriate
   CC26x2/CC1352 LaunchPad, supported SONOFF dongle or CatSniffer revision.
   Similar enclosures or chip-family names do not prove pin/bootloader compatibility.
2. Obtain the release's prebuilt firmware and the **matching release-tag host
   code**. Use the documented TI UniFlash/DSLite or device-specific update method.
   Do not write a TI image with an ESP browser uploader.
3. Check the USB bridge and baud-rate variant. Upstream documents special
   921600-baud variants for certain older SONOFF bridges versus the usual
   2000000-baud build. A wrong variant can appear to be a dead serial device.
4. In an isolated Python environment, install the dependencies stated by that
   release. From its `python_cli` directory, inspect the actual help before use:

```bash
python sniff_receiver.py --help
```

5. Confirm serial port, access permissions, firmware/host compatibility and
   receiver settings. Upstream's `scanner.py` can actively scan; it is not the
   receive-only starting point for this exercise.

## Advertisement-Only Validation

1. Use an owned beacon with a known public/static advertisement address for the
   first check; randomized addresses need a separate identification method.
2. Limit collection to that device and a short approved window. For a release
   whose help retains these options, substitute your owned beacon's address:

```bash
# Owned beacon only. Stop promptly after the approved observation window.
python sniff_receiver.py -m 12:34:56:78:9A:BC -a -o owned-beacon.pcap
```

3. `-a` keeps the receiver in advertisement-only operation in the reviewed
   release. Add the documented serial-port/baud options if autodetection is wrong.
4. Stop capture and inspect the PCAP in Wireshark. Confirm address, expected
   advertisement data, timestamps and channel/PHY context where present.
5. Preserve the original PCAP with version, board, receiver settings, time range
   and hash. Keep unrelated observations out of shared examples.

## Interpretation & Troubleshooting

| Finding | Response |
|---|---|
| No packets | Confirm correct serial/baud variant, known beacon activity, address type, selected PHY/channel and supported hardware. |
| Advertisements present, no connection | Expected in advertisement-only mode. Connection following is a different test requiring a permitted connection and appropriate capture setup. |
| Encrypted traffic | Packet capture is not automatic decryption; use a separate authorized key-management and analysis plan. |
| Many changing identifiers | Address randomization and duplicate advertisements complicate device counts. Do not equate addresses with people. |

## Related Guides

| Resource | Use |
|---|---|
| [Documentation Index](./README.md) | Section navigation |
| [Firmware Catalog](../HardwareHacking/esp32-security-firmware-catalog.md) | Source/activity notes and hardware boundaries |
| [Wardriving Data Handling](../Wardriving/data-handling.md) | BLE identifiers, privacy and retention |
| [Wireshark Filters](./wireshark-master-filters.md) | Analysis context; verify protocol fields in the actual capture |

## Review Scope

This is an original PNWC setup and benign validation workflow based on the linked
primary documentation. Source and navigation were reviewed; no physical board was
flashed, firmware compiled or radio behavior measured. Confirm current target
manifests and release notes before use; menu names and build requirements can change.

---

[Master Index](../README.md) | [Role Navigation](../START_HERE.md) | [Legal Notice](../LEGAL.md)
