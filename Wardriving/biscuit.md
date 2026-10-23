# Biscuit and Biscuit DIY: Phone-Controlled Wardriving

_Last reviewed: 2026-10-22_

> [!CAUTION]
> Biscuit is a multi-function wireless security platform. This guide covers **observation and mapping only**; avoid transmit/injection features during routine inventory. [Legal notice](../LEGAL.md).

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
