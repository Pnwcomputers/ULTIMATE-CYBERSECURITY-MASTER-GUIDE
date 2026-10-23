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

[Biscuit](./biscuit.md) · [Marauder](./esp32-marauder.md) · [Firmware compatibility](../firmware-hardware-compatibility.md) · [Data handling](./data-handling.md)

---

[Back to Wardriving](./README.md) | [Master Index](../README.md) | [Legal Notice](../LEGAL.md)
