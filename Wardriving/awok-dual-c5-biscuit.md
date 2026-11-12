# AWOK Dynamics Dual C5: Biscuit and Independent Firmware Roles

_Last reviewed: 2026-10-22_

> [!CAUTION]
> Only flash firmware built for the exact **hardware model and USB-connected ESP32-C5**. A dual-chip board has two independently programmable targets. Preserve a recovery path and existing data first. This guide's survey workflow is for authorized observation only. [Legal notice](../LEGAL.md).

## Hardware overview

AWOK Dynamics sells the [Dual C5 Mini](https://awokdynamics.com/products/dual-c5-mini) and [Dual C5 Touch](https://awokdynamics.com/). Unlike an ordinary single-chip Biscuit DIY board, the Dual C5 has **two ESP32-C5 devices**. The Mini's vendor listing describes a multi-constellation Airoha 3335 GNSS module connected to both chips, dual 2.4/5 GHz antennas, and hardware sold **without firmware**. The Mini has a screen and physical controls; the Touch uses touchscreen hardware. **Neither has a built-in microSD slot**, per the Biscuit documentation.

The **white** and **orange** USB ports address different C5 sides, not alternative sockets for exactly the same firmware. Follow the hardware-specific flasher's target/port instructions rather than assuming either port is interchangeable.

## Decide on your build before flashing

| Configuration | White/screen side | Orange/secondary side | Operational note |
| --- | --- | --- | --- |
| Manufacturer's example Marauder pairing | `DUAL_MINI_C5.bin` for Mini screen | `esp32c5_devkit.bin` | Vendor-specific example for **Koko firmware**; exact release matters |
| Dual C5 + Biscuit DIY | Independent firmware kept/reinstalled as desired | Biscuit DIY image **for AWOK model / orange-port integration** | Biscuit Manager controls the Biscuit side; phone supplies its wardrive GPS |
| Both sides custom | Exact board-appropriate build | Exact board-appropriate build | Two devices, own firmware and capabilities; test each separately |

> [!IMPORTANT]
> A GNSS receiver physically wired to both ESP32s **does not mean** Biscuit's phone-controlled wardrive automatically consumes the board's GNSS. Biscuit DIY documentation uses the **phone GPS** for its saved app session, and it should be tested as such.

## Flash Biscuit on the supported side

1. Record model (Mini versus Touch), board revision, both C5 firmware versions and the current role of **each** USB port.
2. Save any files, settings and board images you are entitled to retain before reflashing.
3. Disconnect the device from the Flipper/battery accessory and connect the **Biscuit-targeted port** using a working USB data cable.
4. Open the [Biscuit Flasher](https://flasher.biscuitshop.us/) in desktop Chrome/Edge, select **AWOK Dual C5 Mini** or **AWOK Dual C5 Touch** (do not use the generic C5 image).
5. Follow the flasher's USB and BOOT/RESET prompts. Verify it reports a successful write for the intended port.
6. Power-cycle, open **Biscuit Manager** on iOS/Android, grant Location/Bluetooth permissions and connect to the detected board.
7. Inspect Biscuit firmware/device identity and test a harmless scan of your own AP; ensure its phone-GPS location is plausible.
8. If operating the other C5 concurrently, validate its independent serial/control interface and ensure that overlapping scans or other radio use do not create inconsistent logs.

**Do not** copy the Mini's sample Koko `DUAL_MINI_C5.bin` image to a Touch board or an orange C5 without confirming exact compatibility.

## First authorized wardrive

1. Open **Biscuit Manager → Wardrive**, choose WiFi Only (or scoped BT Only/All).
2. Allow the **phone** to acquire GNSS and place it near the board.
3. Start a short survey near a known authorized test AP.
4. Verify observed SSID/BSSID/channel and check the GPS-tagged **app session**.
5. End the survey; export a local copy and inspect it before any optional upload.
6. If logging separately from the non-Biscuit C5, merge only after confirming both records have compatible timestamps, GPS provenance and no accidental double-counting.

**Storage caveat:** Neither AWOK Dual C5 model has onboard microSD. Do not rely on instructions written for Scout Lite's or other boards' microSD-based GPS CSV workflows.

## Dual-MCU Field Validation & Deployment Examples

The [Biscuit ecosystem assessment labs](./biscuit.md#ecosystem-assessment-labs--deployment-examples) cover app pairing, BLE/Wi-Fi/GPS surveys, Node distinctions and WIDS correlation. These **AWOK-specific** steps focus on two independently programmable C5 chips, the separate USB ports and the absence of built-in SD.

### AWOK 1 — Port/Chip Inventory Before Any Flash

1. With the Flipper/backpack disconnected, label the actual physical **white/display** and **orange/secondary** USB connectors based on the board's vendor documentation.
2. Connect only one port at a time to an isolated computer with a data cable. Record USB serial device ID, firmware boot output and build/version.
3. Disconnect and repeat for the other port; capture separate photos/notes for both MCU identities.
4. Check whether existing files, firmware images or settings must be preserved; do not overwrite a dual-radio product with the same generic image on both sides.
5. Confirm a matching recovery image and flasher route for **each** MCU and exact Mini versus Touch hardware.

### AWOK 2 — Biscuit DIY Firmware on Supported C5

1. Use the **orange/secondary** interface with the Biscuit flasher's exact **AWOK Dual C5 Mini** or **AWOK Dual C5 Touch** target—not an unrelated DIY DevKit profile.
2. Follow the documented BOOT/RESET flow and verify flash success only on that port. Reattach power and pair the **Biscuit side** with Biscuit Manager using phone Bluetooth/Location permissions.
3. Start a brief WiFi Only scan of an owned AP, then stop and verify a corresponding **app history** session and local export.
4. Confirm the other C5 still boots its separately intended firmware. A successful scan on the Biscuit side does not prove the display C5 is healthy.
5. Restore saved app credentials/pairing state if needed. **Do not seek SD files:** neither AWOK Mini nor Touch provides built-in microSD.

### AWOK 3 — Two Independent RF Observers, One AP

1. Configure one test AP on a fixed channel, note BSSID, band and time.
2. Collect one short observation from the Biscuit side and, if the other C5 supports a compatible **non-disruptive** scan, one from the display side.
3. Log source MCU, firmware, scan mode, observed BSSID/channel and clock/GNSS provenance independently.
4. Compare scan timestamps and signal levels without assuming simultaneous radio scheduling or sharing GPS. The Biscuit app's **phone GPS** is not automatically replaced by the board-wired GNSS.
5. Deduplicate any merged result by BSSID/time and explain differences as possible scan duty/antenna/timing factors—not conclusively a vulnerability.

### AWOK 4 — Recovery & Client Handoff

1. Reboot each side separately and confirm its intended firmware identity. Do not initiate a second update just because a companion app cannot connect; verify port, power and phone pairing first.
2. Perform a short Biscuit app reconnect, observe the known AP, and verify that the other MCU's display/control still works.
3. Capture a safe firmware/board matrix and backup location. Avoid writing customer credentials or unredacted Wi-Fi scans to a public repo.
4. Disconnect test devices, stop all active functions, restore config and record whether return-to-baseline succeeded.

**Hardware distinction:** an AWOK dual C5 may be physically capable of two independent scans; this does not turn the secondary Biscuit DIY image into a Pro/Ultra **Node Manager**, and it does not add an SD slot or shared firmware state. Follow separate [Marauder hardware targets](https://github.com/justcallmekoko/ESP32Marauder/wiki/Supported-Hardware) if choosing that firmware for the non-Biscuit side.

## Troubleshooting and recovery

| Symptom | Check |
| --- | --- |
| Flasher sees the wrong ESP | White/orange USB port, model selection, serial-port identity |
| Board boots but app does not connect | Biscuit image on supported port, Bluetooth and Location, stale bonds |
| GPS absent in Biscuit map | Phone Location services and app permission; use outdoor fix |
| Other C5 no longer works | Confirm whether you flashed the wrong USB port; recover from original firmware image |
| No SD/PCAP log | Neither Mini nor Touch has built-in microSD; use supported app export |
| Two captures disagree | Radio schedules, time sync, where each obtained location, duplicate sightings |

## References

- [AWOK Dual C5 Mini manufacturer specification](https://awokdynamics.com/products/dual-c5-mini)
- [Official Biscuit DIY setup and AWOK board list](https://biscuitshop.us/pages/diy-biscuits)
- [Biscuit Wiki: AWOK devices and limitations](https://codehedge.github.io/Biscuit-Wiki/devices/diy.html)
- [Biscuit Web Flasher](https://flasher.biscuitshop.us/)

## See also

[Biscuit](./biscuit.md) · [Marauder](./esp32-marauder.md) · [Device-first firmware references](../firmware-hardware-compatibility.md) · [Data handling](./data-handling.md)

---

[Back to Wardriving](./README.md) | [Master Index](../README.md) | [Legal Notice](../LEGAL.md)
