# ChimeraBLE: Board Setup & Owned-Device BLE Inspection

> [!CAUTION]
> **Authorized use only.** Use owned hardware and explicitly scoped lab devices.
> Review the [legal notice](../LEGAL.md), radio limits and data-sharing settings.

_Last reviewed: 2026-11-07_

## Purpose

[ChimeraBLE](https://github.com/MatthewKuKanich/ChimeraBLE) is BLE security and
reverse-engineering firmware by Matthew KuKanich. Its central, peripheral and
proxy functions are different activities; this guide starts with bounded discovery
and owned-device metadata inspection, not cloning or interception.

## Targets & Installation

| Build Environment | Documented Target |
|---|---|
| `esp32dev` | Original ESP32 WROOM, serial interface |
| `xiao_esp32c5` | Seeed XIAO ESP32-C5, serial interface |
| `cardputer` | Cardputer ADV, on-device interface; do not assume original Cardputer compatibility |

1. Use upstream's pioarduino/PlatformIO configuration and matching dependencies.
   Record the repository revision, environment and exact device model.
2. Build/upload only the selected environment using upstream instructions. No
   dedicated project web flasher was established; third-party catalog presence is
   separate from upstream endorsement.
3. Review filesystem deployment before `uploadfs`: upstream notes this formats
   LittleFS for the OUI database and can erase saved profiles. Back up first and
   provision the database before creating data you intend to retain.
4. Open the selected serial monitor or Cardputer UI and inspect `help`. The
   documented serial speed is 115200; verify it for the selected release.

## Harmless First Check

1. Prepare an owned BLE beacon in a controlled area and record its known identity.
   Upstream describes `scan` as **active scanning**, which sends requests; this is
   not a receive-only packet-capture exercise.
2. Run a short bounded scan, list the results and inspect only the owned beacon's
   advertisement information. Indices can change after a list refresh.
3. Compare advertised name, service UUIDs, address type and signal level with the
   known device. Manufacturer/fingerprint results are hypotheses, not identity proof.
4. Stop scanning and save only approved observations with version and settings.
   Do not connect, bond, subscribe, clone, write or proxy a device as part of this check.
5. For a later owned-peripheral GATT exercise, define permitted characteristics
   and expected reads separately. GATT enumeration is an active connection; it is
   not equivalent to over-the-air Sniffle capture or automatic decryption.

## Interpretation & Recovery

| Finding | Meaning / Next Check |
|---|---|
| No manufacturer label | OUI database missing, random address or unknown vendor; not evidence of a malicious device. |
| RSSI rises | Rough signal trend affected by body shielding and multipath, not calibrated location or angle of arrival. |
| Files disappeared | Check whether filesystem provisioning reformatted LittleFS. |
| Missing UI | Serial versus Cardputer environment selection and exact board support. |

## Related Guides

| Resource | Use |
|---|---|
| [Sniffle / BLE Capture](./ble-capture-sniffle.md) | Distinguish active GATT inspection from protocol capture |
| [GhostESP](./ghostesp-revival.md) | Broader Wi-Fi/BLE platform |
| [Device Firmware List](./device-firmware-list.md) | Board-first selection |
| [Documentation Index](./README.md) | Section navigation |

## Verification Scope

Primary project documentation and links were reviewed. No firmware build, flash,
hardware compatibility test or radio test was performed. Follow the selected
release's target manifest and recovery instructions, and preserve original logs.

---

[Master Index](../README.md) | [Role Navigation](../START_HERE.md) | [Legal Notice](../LEGAL.md)
