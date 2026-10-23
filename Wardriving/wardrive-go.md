# Wardrive Go: Android and iOS Mobile Surveys

_Last reviewed: 2026-10-22_

> [!CAUTION]
> Conduct only permitted surveys. Android and iOS have **different OS permissions and radio capture capabilities**. A colorful map or device classification is not proof of a threat. Read [LEGAL.md](../LEGAL.md).

## What is Wardrive Go?

[Wardrive Go](https://play.google.com/store/apps/details?id=com.rocketgod.wardrive) by RocketGod (Jeremy Yablan) is a phone-centered wireless-discovery and mapping app with GPS-tagged sessions and user-triggered uploads.

**The Android and iOS variants are not the same capture architecture:**

| Feature | Android | iOS / iPadOS |
| --- | --- | --- |
| Native device discovery | OS-permitted Wi-Fi, BLE and cellular observations, according to device / permissions / restrictions | BLE from the phone; direct Wi-Fi survey requires compatible external firmware such as **iosESP** |
| External hardware | App advertises supported USB OTG Wi-Fi adapters; USB serial ESP32 boards in current versions | [RocketGod iosESP](https://rocketgod.dev/iosESP) ESP32 boards over BLE |
| GPS | Phone GNSS and location services | Phone location/GNSS |
| Results | Live map, sessions, device summaries | Live radar/map, sessions, export |
| Upload | User-requested WiGLE / WDGWars | User-requested WiGLE / WDGWars / Wardrift (where available) |

> [!NOTE]
> OS scanning restrictions, USB-OTG hardware/driver support and vendor app updates can change. Verify capabilities **on your specific phone and release**; don't assume an iPhone can enumerate Wi-Fi APs the way Android can.

## Android: basic survey

1. Install from the [official Google Play listing](https://play.google.com/store/apps/details?id=com.rocketgod.wardrive).
2. Grant the necessary Location, Nearby Devices/Bluetooth, and any Wi-Fi permissions the app requests. Review battery optimization if logging stops when the screen is off.
3. Inspect the phone GNSS readout outdoors.
4. In the app, verify a *known owned AP* and one known BLE device, if included in scope.
5. Begin a new local session using passive discovery and follow the [field checklist](./field-workflow.md).
6. Stop, open the run summary/field report, and export/backup the locally stored findings before sharing.
7. If optional OTG hardware is used, check that the specific chipset and OS version are supported, power/OTG is adequate, and the app actually reports the external source. Do **not** label a driver/adapter as working simply because it powers on.

The current Google Play listing advertises supported USB Wi-Fi monitor-mode adapters and, in recent versions, USB serial ESP32 sources such as Marauder/AWOK. These integrations are **app-specific** and do not mean every external device is supported without configuration.

## iPhone / iPad: iosESP path for Wi-Fi

1. Install the [official App Store version](https://apps.apple.com/us/app/wardrive-go/id6783390938).
2. Grant Bluetooth and Location permissions. Try the phone's BLE observation and map first.
3. For Wi-Fi AP mapping, prepare a **supported ESP32 board flashed with [iosESP](https://rocketgod.dev/iosESP)** for that exact hardware target.
4. Power the board, bring it near the phone and follow the app's supported discovery/connection instructions.
5. Verify that an authorized test AP appears as **Wi-Fi** (not just BLE), with a plausible channel/band.
6. Check phone GPS, start a short session, stop, review and export the logged observations.
7. Advanced multi-board channel distribution and BLE scanning are dependent on the particular iosESP hardware/firmware version; benchmark on a known test network.

## Privacy features and publishing

Current app descriptions mention exclusion zones, device blacklists and `_nomap` handling. Verify exclusions against a **sample export** before sharing data. Credentials for WiGLE/WDGWars are sensitive; a service upload can disclose timestamp + BSSID + GPS coordinates even when the app says it keeps local sessions private.

Device names such as cameras, tracking tags or unusual access points may be inferred heuristically; **do not use them alone as evidence** a device is surveilling anyone.

## Troubleshooting

| Symptom | Likely cause / check |
| --- | --- |
| Android shows few Wi-Fi networks | Location permission, OS scan throttling, device/vendor Wi-Fi restrictions |
| iOS shows BLE but no Wi-Fi | Expected without supported **iosESP external Wi-Fi board** |
| External board appears but no records | Firmware target/version, cable/OTG/BLE link, phone permission, supported chipset |
| GPS jumps / no fix | Outdoors, phone GNSS settings, battery/location restrictions |
| No export / upload counts | Verify run actually saved and is compatible with service formats |
| Upload failed | Check consent, API token, service limits, network, per-service receipt |

## Official sources

- [Wardrive Go Android](https://play.google.com/store/apps/details?id=com.rocketgod.wardrive)
- [Wardrive Go iOS](https://apps.apple.com/us/app/wardrive-go/id6783390938)
- [RocketGod iosESP](https://rocketgod.dev/iosESP)

## See also

[Kismet](./kismet.md) for Linux/monitor adapters · [Biscuit](./biscuit.md) for phone + dedicated C5 · [Privacy and exports](./data-handling.md)

---

[Back to Wardriving](./README.md) | [Master Index](../README.md) | [Legal Notice](../LEGAL.md)
