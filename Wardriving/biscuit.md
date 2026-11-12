# Biscuit and Biscuit DIY: Phone-Controlled Wardriving

_Last reviewed: 2026-10-22_

> [!CAUTION]
> Biscuit is a multi-function wireless security platform. This guide covers **observation and mapping only**; avoid transmit/injection features during routine inventory. [Legal notice](../LEGAL.md).

## Current Firmware Distribution & Recovery

| Resource | Description / Boundary |
|---|---|
| [Official Browser Flasher](https://flasher.biscuitshop.us/) | Choose exact Pro/Ultra/Crumb/DIY/Node target. Full install and app-only update differ; some devices require both MCUs flashed. |
| [Official DIY Wiki](https://codehedge.github.io/Biscuit-Wiki/devices/diy.html) | Documents 8 MB flash C5 DIY requirements, named boards, SD caveats, app exports and Node Manager limits. |
| [Raw DIY/Node Releases](https://github.com/CodeHedge/diy_node_web_flasher/releases) | Official docs link this distribution, but its archived web-installer source is not evidence of complete current firmware source. |
| [Desktop Recovery Tool](https://github.com/CodeHedge/biscuit_flasher) | Named scripts for Pro, Ultra and Crumb; Crumb is single C5, Pro/Ultra have C5 plus WROOM. This utility explicitly redirects DIY users to the browser flasher. |
| [Other Survey Firmware](./additional-survey-firmware.md) | Compare PORKCHOP, wardriver.uk, C5 Wardriver and Piglet before switching a working device. |

Back up sessions/settings first. Review erase and pairing-reset prompts; remove
stale phone bonds when the selected install resets pairing. For a first test use
an owned AP, phone GPS and inspected app export. SD support for PCAP/portal files
does not imply every DIY build logs wardrive CSV locally. A generic multi-firmware
catalog does not replace vendor-specific multi-MCU instructions.

## Purpose

[Biscuit](https://biscuitshop.us/) uses compatible ESP32 hardware with the **Biscuit Manager** mobile app. Phone GPS, Bluetooth permissions, firmware model and scanning roles determine what the saved wardrive means.

### Architecture and models

| Platform | Architecture | Notes |
| --- | --- | --- |
| Biscuit Pro | ESP32-C5 scanner + separate ESP32-WROOM control/gateway | Dedicated gateway allows the C5 to focus on scanning |
| Biscuit Ultra | Two-chip platform with supported SD logging hardware | Review its exact storage/firmware before use |
| Biscuit Crumb | One ESP32-C5 | Compact single-chip configuration |
| Biscuit DIY | One ESP32-C5 (typically) | Shared Wi-Fi/BLE scanning and BLE phone connection |
| AWOK Dual C5 + Biscuit | Two C5 chips physically; Biscuit firmware typically occupies one | See [independent guide](./awok-dual-c5-biscuit.md) |

A C5 can cover 2.4 and 5 GHz, but its **single Wi-Fi radio cannot scan both bands simultaneously**. With DIY, sharing BLE control and scanning can affect observation completeness. See [Biscuit DIY documentation](https://codehedge.github.io/Biscuit-Wiki/devices/diy.html).

## Obtain and set up hardware

1. Choose the *exact* supported model. For DIY ESP32-C5, verify adequate flash and use the [supported boards list](https://codehedge.github.io/Biscuit-Wiki/devices/diy.html).
2. Charge/power the device, document its current firmware and export/back up any existing sessions.
3. For a new DIY build, open the [Biscuit Web Flasher](https://flasher.biscuitshop.us/) in a Web Serial-capable desktop browser.
4. Select the **actual board model** and firmware target, then follow on-screen USB/BOOT instructions; do not guess binary offsets.
5. Install **Biscuit Manager** on the phone (follow links from the [official project docs](https://codehedge.github.io/Biscuit-Wiki/)).
6. Enable phone Bluetooth, Location and required app permissions; connect to the Biscuit from its device list.
7. Allow phone GPS to fix in an open-sky area and verify the app shows plausible coordinates.
8. Choose a **passive** AP/BLE scan and confirm a known authorized test network is visible.

## First wardrive

1. In Biscuit Manager open the **Wardrive** function.
2. Select **WiFi Only** for AP inventory; use **BT Only** for scoped Bluetooth inventory, or **All** if both were approved and supported.
3. Start a short stationary test and verify network observations, channel/band, signal and valid phone location.
4. Follow the [field procedure](./field-workflow.md). Keep the phone and scanner together; a remotely placed C5 with **phone-provided GPS** will receive misleading coordinates.
5. Stop from the app; review the session in history and export an approved copy.
6. Confirm exported file fields and counts before WiGLE sharing.

> [!NOTE]
> **A Biscuit DIY scan does not automatically create a local WiGLE CSV on every board's SD card.** For Scout Lite reflashed to Biscuit, PINGEQUA specifically documents the **phone session/export** as the storage workflow; its normal SigRoam scanner-card log path does not carry over.

## Optional distributed nodes

Biscuit Node is **different firmware**. A Pro or Ultra can manage supported satellite C5 nodes; a standard DIY board cannot act as a Node Manager. Satellite observations inherit the Manager phone's location, so travel as a single rig. See the [Biscuit Node documentation](https://codehedge.github.io/Biscuit-Wiki/devices/node.html). This is *not* required for basic wardriving.

## Ecosystem Assessment Labs & Deployment Examples

_Source reviewed November 2026; these are documented procedures, not claims of hands-on device testing._

Biscuit **Pro**, **Ultra**, **Crumb**, **DIY**, **Node**, and compatible **AWOK Dual C5** hardware have distinct firmware and management roles. Do not flash one model's image onto another. Always check the [official Biscuit DIY guide](https://codehedge.github.io/Biscuit-Wiki/devices/diy.html), [Node guide](https://codehedge.github.io/Biscuit-Wiki/devices/node.html), [web flasher](https://flasher.biscuitshop.us/), and the [AWOK guide](./awok-dual-c5-biscuit.md).

### Role, Hardware & Data-Source Matrix

| Model/role | Connection | Capture & GPS interpretation |
|---|---|---|
| Biscuit Pro | Biscuit Manager app; multi-MCU | Scanner with independent gateway, phone-location session, eligible Node Manager |
| Biscuit Ultra | Biscuit Manager app; multi-MCU | Review supported SD features; phone-location session, eligible Node Manager |
| Biscuit Crumb | Single C5, app-connected | Shared Wi-Fi/BLE radio and connection duties; not Node Manager |
| Biscuit DIY | One supported ESP32-C5 board, app-connected | Phone session/export is primary wardrive record; SD only if actually fitted/supported |
| Biscuit dedicated Node | Node firmware; paired to Pro/Ultra Manager | Wi-Fi **or** BLE assigned scan role per C5, no direct phone pairing/GPS/local capture |
| AWOK Dual C5 Mini/Touch | Dual C5; Biscuit DIY on documented orange/secondary port | Two independently flashed chips; **no onboard microSD**; Biscuit Manager uses phone location |

ESP32-C5 can scan supported 2.4/5 GHz channels across time, but a **single radio** cannot continuously capture both bands and Bluetooth at once. Avoid reporting throughput or complete RF coverage based solely on scan counts.

### Deployment 1 — Hardware Identity, Safe Flash & Phone Pairing

1. Record model/board revision, microcontroller count, both chip identities on dual-chip hardware, firmware, and app version.
2. Export/back up existing app history, board configuration, and any SD artifacts. Use the **model-specific** web flasher: a Node image is not DIY app-controlled firmware, and Pro/Ultra images may require multiple controllers.
3. Connect using a **data** USB cable and the documented BOOT/RESET flow. Confirm the flasher target before any erase.
4. Install Biscuit Manager through the official source, enable Bluetooth/Location permissions, and pair with the intended device. Avoid pairing the phone to a dedicated Node.
5. Test detection of one owned AP. Disconnect/reconnect once and record firmware identity, device name, successful reconnect and pairing failures.
6. If phone pairing fails after reflash, inspect stale Bluetooth bonds and app permissions *before* overwriting firmware again.

### Deployment 2 — Controlled 2.4/5 GHz AP Survey

1. Use two client-owned lab SSIDs, one on a known 2.4 GHz channel and one on a supported 5 GHz channel. Capture BSSIDs and security from the AP controller.
2. Select **WiFi Only** in Biscuit Manager. Run 2–3 timed stationary scans with the device near the AP.
3. Compare observed channel/band/BSSID and timestamps against controller inventory. Account for channel dwell and multi-BSSID APs.
4. On single-C5 DIY/Crumb models, repeat with an authorized combined scan, then compare count/completeness. BLE communications with the phone can reduce Wi-Fi observation time.
5. A missing AP requires coverage/timing/adapter investigation; it is **not proof** of an insecure or rogue network.

### Deployment 3 — Synthetic BLE Beacon & False Positives

1. Configure one owned BLE advertising beacon with a synthetic name and document its advertising interval when known.
2. Select **BT Only**, observe address type/name/RSSI where the app exposes them, and record first/last seen.
3. Turn the beacon off for a negative-control interval, then restore it. Check whether the session/history retains stale entries.
4. Compare against [OUI-SPY](../Documentation/microcontroller_wifi_testing.md#oui-spy-unified-blue--authorized-detection-labs) as a separate receiver. A vendor OUI or RSSI trend does not establish device identity or distance.
5. Redact bystander MACs and other personal identifiers from any exported client report.

### Deployment 4 — Phone GPS, Wardrive & Export

1. Acquire a plausible **phone** GNSS fix outdoors and keep the phone beside the scanner.
2. Run a short approved route with WiFi Only, noting starting/stopping time, route, band, AP inventory, and app scan mode.
3. Stop the session and verify it appears in **Biscuit Manager history**. Export a local copy and inspect actual columns, record counts and coordinate quality before claiming WiGLE compatibility.
4. Repeat while stationary to estimate GPS drift. If the fix is missing, mark records non-geolocated.
5. Do not substitute a Marauder/SigRoam `wardrive_` SD-log assumption: Biscuit DIY generally uses phone history/export. **Third-party upload is a separate authorization** under [data handling](./data-handling.md).

### Deployment 5 — Pro/Ultra Manager & C5 Node Fleet

1. Use a documented **Pro or Ultra Manager**, and flash the separate **Biscuit Node** firmware to compatible satellite C5 boards. DIY/Crumb are not Node Managers.
2. Connect the **Manager** to Biscuit Manager on the phone; open **Settings → Node Management** and enroll the Node according to upstream.
3. Assign one dedicated C5 Node **Wi-Fi or BLE**, not both simultaneously. Record role, node ID, firmware and site location.
4. Start a short survey and verify Node observations are included in the Manager app session. Location is from the **Manager phone**, not a GPS on the satellite Node.
5. Power off one Node, watch its disconnect/state change and compare the session to a run without it.
6. Update Node firmware only in a maintenance window using the official Node guide; verify return/reconnect. Upstream warns that **extended mode can disable encryption on the Node link**—do not enable without explicit risk review.

### Deployment 6 — Storage and Feature Gates

1. Confirm actual supported SD hardware. **AWOK Dual C5 Mini/Touch do not include onboard SD slots**; not every DIY C5 board has SD.
2. On supported hardware, create one harmless, documented test artifact using a feature that needs SD. Verify file location and digest.
3. Separately export the **phone app session** and distinguish that artifact from SD PCAP/portal resources.
4. Never test credential capture to validate SD; use synthetic text or packet data from owned equipment.
5. Record what was unavailable rather than claiming that every model supports the same capture/portal functions.

### Deployment 7 — AWOK Dual C5 Comparison

1. Follow [AWOK port/firmware mapping](./awok-dual-c5-biscuit.md) to confirm white/display and orange/secondary identities.
2. Configure the orange/secondary C5 for the supported Biscuit DIY build. Keep the other side's firmware independent and only run a non-disruptive scan there if compatible.
3. Observe the same owned AP from both C5s. Label observations with **which MCU**, band, firmware, time and GPS source.
4. When merging evidence, de-duplicate by BSSID and time and do not infer the Biscuit side uses AWOK's physical GNSS: the app's phone location remains the default.
5. Restore serial/pairing configuration and confirm neither side was inadvertently reflashed.

### Deployment 8 — WIDS/SIEM Regression & Client Reporting

1. Create a unique synthetic training SSID on an owned AP and document BSSID, band and on/off window.
2. Observe it in Biscuit Manager, while an independent [Kismet/Wazuh](../IncidentResponse/IDS%26IPS/kismet-wazuh-wireless-lab.md) or [nzyme/Wazuh](../IncidentResponse/IDS%26IPS/nzyme-wazuh-integration.md) sensor monitors.
3. Correlate the **real** alert IDs, scan timestamps, AP controller config and owner asset list. Biscuit is not assumed to provide native Wazuh telemetry.
4. Stop the test AP, verify the event closes/ages out and check a normal authorized AP as a negative control.
5. Export only in-scope redacted evidence and document any false positives or missing sensors.

### Acceptance & Recovery Matrix

| Test | Expected evidence | Failure to investigate |
|---|---|---|
| Flash & pairing | Correct board profile and successful authorized app connection | Wrong MCU/board image, stale phone pairing |
| Wi-Fi scan | Owned AP visible on supported band | Channel dwell, 2.4/5 GHz limitation, scan mode |
| BLE scan | Owned beacon observed and negative control | Radio coexistence, address rotation |
| Wardrive | App history/export and plausible phone GPS | Missing Location permission or poor fix |
| Node fleet | Manager reports assigned Node results | DIY vs Node firmware, missing Pro/Ultra |
| Storage | Supported card/file verified or explicit "not available" | Incorrect assumption about AWOK/DIY SD |
| Dual C5 | Two independent MCU identities and scoped scan logs | Wrong USB port/firmware, duplicate counting |
| WIDS | Independent alert matched to test AP on/off period | Sensor/parser/clock rather than Biscuit itself |

**Client handoff:** preserve written RF scope, operator, exact hardware/firmware/app/Node roles, time zone, approved SSIDs/BSSIDs, phone-GPS provenance, source file checksums, independent verification, negative controls, retention decision, and recovery steps. Disable test transmitters, remove synthetic configuration and inspect saved app pairing before reuse.

## Troubleshooting

| Issue | Checks |
| --- | --- |
| Device doesn't appear | Correct flashed target, device powered, nearby BLE, phone permissions |
| Connect fails | App pairing state; firmware/device match, stale phone Bluetooth pairing after full reflashing |
| Wardrive has no GPS | Phone Location permission, outdoor GNSS, phone power management |
| Expected Wi-Fi band missing | Firmware target, supported channels, C5 dwell, nearby known AP |
| Low combined Wi-Fi/BLE coverage | Single C5 shares scanning with BLE and phone link; try Wi-Fi Only |
| No board SD record | For Biscuit DIY use **app history/export**, not SigRoam/Marauder SD expectations |
| Missing SD-specific features | Actual hardware SD availability; AWOK Dual C5 has no card slot |

## References

- [Official DIY quickstart](https://biscuitshop.us/pages/diy-biscuits)
- [Biscuit wiki](https://codehedge.github.io/Biscuit-Wiki/devices/diy.html)
- [Official web flasher](https://flasher.biscuitshop.us/)
- [PINGEQUA: Scout Lite Biscuit vs SigRoam](https://www.pingequa.com/blogs/guides-tutorials/scout-lite-biscuit-diy-firmware)

## See also

[AWOK Dual C5 + Biscuit](./awok-dual-c5-biscuit.md) · [SigRoam](./sigroam-scout-lite.md) · [Data handling](./data-handling.md)

---

[Back to Wardriving](./README.md) | [Master Index](../README.md) | [Legal Notice](../LEGAL.md)
