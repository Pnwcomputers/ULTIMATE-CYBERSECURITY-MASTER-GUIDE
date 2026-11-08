# ESP32 Bit Pirate: Protocol Bench Setup

> [!CAUTION]
> **Authorized use only.** Use owned devices or an explicitly authorized lab.
> Define permitted collection, transmissions and data retention before testing.
> Read the [legal notice](../LEGAL.md). Device-owner permission does not override radio law.

_Last reviewed: 2026-11-07_

## Purpose

[ESP32 Bit Pirate](https://github.com/geo-tp/ESP32-Bit-Pirate), formerly ESP32 Bus
Pirate, turns supported ESP32-S3 boards into a multi-protocol analysis tool.
It is distinct from the [Bus Pirate hardware](./BusPirate.md) and the
[generic serial adapter note](./BitPirate.md). Their pin maps, voltage protection
and commands must not be assumed compatible.

**Prerequisites:** [Electrical fundamentals](./Chapter2.md), known target voltage,
current-limited power where appropriate, a meter and the exact board pin map.

## Board & Interface Selection

| Item | Supported Starting Point / Limit |
|---|---|
| Boards | Upstream lists S3 DevKit/SuperMini, AtomS3 Lite, StampS3, Cardputer/ADV and other named S3 boards; generic targets need the required flash size and a verified pin map. |
| User interface | Serial CLI, project Web Serial tools or configured WebUI; Cardputer has a standalone screen/keyboard workflow. |
| Wired protocols | UART, SPI, I2C, 1-Wire, JTAG/SWD and other modes depend on connections and configuration. Protocol support is not electrical protection. |
| Radio / CAN / RFID | External transceivers, level translation, termination and antennas may be needed. An S3 firmware image alone does not add 5 GHz or 802.15.4 radio hardware. |

## Install & Establish A Baseline

1. Record the board model, flash size, USB port and existing firmware. Disconnect
   the target hardware while flashing and verify the recovery/download-mode procedure.
2. Use the [official web flasher](https://geo-tp.github.io/ESP32-Bit-Pirate/webflasher/)
   and exact board image. Read the erase warning and retain the selected release identity.
3. Open the project's [Web Tools](https://geo-tp.github.io/ESP32-Bit-Pirate/web-tools/)
   or a local serial terminal. The flasher and runtime terminal serve different purposes.
4. Read the firmware's help and [protocol wiki](https://github.com/geo-tp/ESP32-Bit-Pirate/wiki).
   Start in the documented high-impedance/idle mode; do not paste Bus Pirate command sequences.
5. Check the [hardware guide](https://geo-tp.github.io/ESP32-Bit-Pirate/hardware/)
   for the chosen target and map every signal before attaching another board.

## First Lab: Read An Owned UART Output

1. With power off, identify target GND, TX, RX and logic level from documentation
   and measurements. Do not connect mains-referenced or unknown-voltage equipment.
2. Use suitable level conversion if required. Do not connect a target power pin
   simply because it is adjacent to UART. Avoid powering the target from two supplies.
3. Connect common reference and target TX to the configured receiver input first.
   Leave the transmit path disconnected for an initial observation exercise.
4. Configure the documented UART mode, baud, framing and pins. Power the target
   normally and capture its startup output. Do not interrupt boot or send commands.
5. Compare observed output with a known-good console trace. A prompt character
   does not prove root privileges or authorize changing the target.
6. Save the transcript with board/firmware, pin map, voltage, baud and timestamps.
   Return to idle/high impedance and power down before changing connections.

## Troubleshooting & Extension

| Finding | Response |
|---|---|
| Garbled / no UART output | Check reference ground, measured logic level, selected RX pin, baud and framing; inspect with a logic analyzer. |
| Unexpected heat / reset | Remove power immediately; inspect shorts, voltage compatibility and back-power paths. |
| Need I2C / SPI next | Use a sacrificial documented sensor/EEPROM; confirm pull-ups, address/chip select and mode before a read-only baseline. |
| Need write or debug access | Make a verified backup and define restore criteria first. JTAG, flash writes and glitching need a separate approved test plan. |

## Related Guides

| Resource | Use |
|---|---|
| [Hardware Hacking Index](./README.md) | Bench tools and learning sequence |
| [Bus Pirate](./BusPirate.md) | Separate dedicated multi-protocol hardware |
| [Firmware Catalog](./esp32-security-firmware-catalog.md) | Alternative firmware and target boundaries |
| [GhostESP](../Documentation/ghostesp-revival.md) | Wireless observation rather than wired bus analysis |

## Review Scope

This is an original PNWC setup and benign validation workflow based on the linked
primary documentation. Source and navigation were reviewed; no physical board was
flashed, firmware compiled or radio behavior measured. Confirm current target
manifests and release notes before use; menu names and build requirements can change.

---

[Master Index](../README.md) | [Role Navigation](../START_HERE.md) | [Legal Notice](../LEGAL.md)
