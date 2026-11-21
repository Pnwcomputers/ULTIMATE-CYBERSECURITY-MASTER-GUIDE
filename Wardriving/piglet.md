# Piglet Wardriver: Standalone & Mesh Survey Setup

> [!CAUTION]
> **Authorized use only.** Use owned devices or an explicitly authorized lab.
> Define permitted collection, transmissions and data retention before testing.
> Read the [legal notice](../LEGAL.md). Device-owner permission does not override radio law.

_Last reviewed: 2026-11-07_

## Purpose

[Piglet by Hamspiced](https://github.com/Hamspiced/piglet) combines ESP32 Wi-Fi
surveying, GPS, SD WiGLE CSV logs and a local WebUI. It includes distinct mesh
roles and a minimal PigletNode image. Treat upload automation and mesh forwarding
as separate choices from local collection.

## Match The Build To The Job

| Choice | Hardware & Logging Boundary |
|---|---|
| Standalone Piglet | Documented XIAO S3/C3/C6/C5 or T-Dongle C5 target; configure GPS, SD and optional display for that build. |
| Band support | C5 supports the documented 5 GHz scanning; S3/C3/C6 are not equivalent dual-band radio targets. |
| Piglet Node mode | Forwards observations to a coordinator; upstream notes normal local WiGLE logging is suspended in this mode. |
| PigletNode image | Minimal XIAO C5 build in its own folder; no display/GPS/SD needed locally. It is not the full standalone firmware. |
| Position provenance | Record which device supplied each coordinate. A coordinator's location can differ from the node's radio observation location. |

## Install & Configure Without Automatic Sharing

1. Choose the exact hardware variant and use its upstream wiring table. Identify
   power and logic levels before connecting GPS, SD or display modules.
2. Follow the README's build/release path for that variant. No dedicated browser
   firmware installer was verified. The runtime WebUI's self-update feature is
   distinct from initial firmware installation.
3. Use a FAT32 SD card for the documented standalone workflow. Preserve any
   previous configuration and logs before changing firmware or filesystems.
4. Review `/wardriver.cfg` and the current WebUI. Set `maxBootUploads=0` for the
   initial local-only exercise, leave upload credentials unset, and review all
   home-return, live-upload and startup automation. One disabled setting is not
   proof that every network feature is disabled.
5. Start with ordinary standalone operation; leave `meshModeOnBoot` unset for
   the first check. Core/Node startup can skip the SoftAP setup window.
6. Configure the correct board profile, GPS and SD. Use a private bench network
   for WebUI access and change default access settings where supported.

## Validate Data Before Field Use

1. Record an owned AP's BSSID/channel and the approved location/time window.
2. Obtain a trustworthy GPS fix, start a short survey and inspect display/status
   messages for SD errors. Do not infer data quality solely from a rising count.
3. Stop and download the actual CSV or copy it from SD safely. Confirm expected
   AP identifiers, coordinates, timestamps and header/record format.
4. Retain the original; hash it and keep transformations in separate files. Verify
   exclusions before any WiGLE upload or sharing with another collector.
5. Only then test a mesh role with owned nodes. Confirm the coordinator receives
   observations and produces the expected log; record node identity, role and
   coordinate source. Mesh forwarding via ESP-NOW transmits radio traffic.

## Counter-Surveillance, RF Privacy & Wireshark Validation

Piglet's ordinary survey observations are **not automatically attacks**. An owned AP may appear in a Piglet record without an association or intrusive action. Mesh/ESP-NOW, local SoftAP and certain status/upload functions **do transmit**, however; classify actual traffic rather than labeling every mode "passive."

| Concern | Controlled Check | Correct Interpretation |
|---|---|---|
| Piglet standalone logging | Verify SD WiGLE CSV fields, timestamp/GNSS and consent | Sightings do not prove compromise |
| Mesh Node/Core | Inspect documented radio frames on a test board | ESP-NOW traffic is a separate RF use case |
| BLE observations | Use dedicated supported BLE sniffer if raw PDU needed | Linux BlueZ discovery is not raw over-air sniffing |
| Unexpected external upload | Examine startup policy, WiGLE credentials and logs | Upload permission is independent of observation permission |
| Sensitive identifiers | Minimize SSID/BSSID/GNSS retention | Device location does not identify an operator |

**Wireshark:** a supported 802.11 monitor source can decode `wlan.fc.type_subtype == 0x08` (beacons), but its capture channel, RSSI and antenna placement limit coverage. Do not infer a threat from a matching SSID alone. Follow [Wireshark Master Filters](../Documentation/wireshark-master-filters.md), [Counter-Surveillance](../Documentation/counter-surveillance-wireless-threats.md) and [Hardware/Board Compatibility](../Documentation/sbc-radio-addon-compatibility.md).

## Troubleshooting

| Symptom | First Checks |
|---|---|
| Setup AP absent | Saved home-network connection, elapsed setup window, or Core/Node boot mode. Follow the build's documented recovery route. |
| No node CSV | Node mode may intentionally forward instead of writing locally; inspect the coordinator's records. |
| Unexpected upload | Boot-upload count, stored credentials, home-return, live/dock features and startup configuration; disable sharing before reconnecting. |
| Missing 5 GHz | Confirm the C5 build and lawful channel plan; another XIAO model cannot add the missing radio band. |

## Related Guides

| Resource | Use |
|---|---|
| [C5 Wardriver](./esp32-c5-wardriver.md) | JCMK-specific firmware, mode persistence and installer |
| [Data Handling](./data-handling.md) | Sensitive identifiers, coordinate provenance and sharing |
| [Field Workflow](./field-workflow.md) | Planning and repeatable observation checks |
| [Wardriving Index](./README.md) | Platform comparison |

## Review Scope

This is an original PNWC setup and benign validation workflow based on the linked
primary documentation. Source and navigation were reviewed; no physical board was
flashed, firmware compiled or radio behavior measured. Confirm current target
manifests and release notes before use; menu names and build requirements can change.

---

[Master Index](../README.md) | [Role Navigation](../START_HERE.md) | [Legal Notice](../LEGAL.md)
