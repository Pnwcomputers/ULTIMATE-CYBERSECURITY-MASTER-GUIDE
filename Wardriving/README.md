# Wardriving and Wireless Surveying

_Last reviewed: 2026-10-22_

> [!CAUTION]
> **Authorized surveying only.** Define the permitted area, types of collection, device owners, disclosure rules and any transmit-capable features *before* starting. Passive reception is not a blanket permission for active interference, interception or publishing location data. Read the [repository legal notice](../LEGAL.md).

## Purpose

Wardriving is the systematic observation and mapping of wireless infrastructure while moving (by foot, bicycle, vehicle or another safe route). A typical *wireless inventory* records access point identifiers, frequency/channel, received signal strength, observed security configuration, time and optional Global Navigation Satellite System (GNSS) coordinates. Bluetooth Low Energy (BLE) and cellular observations require source-specific capabilities.

This section focuses on **repeatable, minimally invasive Wi-Fi/BLE inventories**, GPS quality, hardware/firmware compatibility, log integrity, and authorized sharing. It does **not** require connecting to detected networks or attempting to access them.

## Start here

1. Learn [field planning, safe operation and verification](./field-workflow.md).
2. Select a platform by its **radio hardware, firmware, GPS source, controller and log location**—these are not interchangeable.
3. Follow exactly one [platform guide](#platform-guides).
4. Validate results against your own/authorized test AP and a known location before collecting in the field.
5. Read [data handling, privacy and WiGLE exports](./data-handling.md) before uploading or publishing.

## Platform guides

| Guide | Controller / interface | Radio and positioning model | Primary record / transfer |
| --- | --- | --- | --- |
| [SigRoam + Scout Lite](./sigroam-scout-lite.md) | Flipper Zero app (FAP) + Scout Lite scanner | ESP32-C5, 2.4/5 GHz, Scout Lite onboard GNSS | Scout Lite microSD WiGLE CSV; optional SigRoam after-stop upload with **dedicated scanner firmware** |
| [ESP32 Marauder](./esp32-marauder.md) | Board screen/CLI or Flipper companion | Hardware-dependent ESP32; GPS and 5 GHz **not universal** | Target-dependent SD or Flipper logging; separate Marauder upload actions |
| [Biscuit](./biscuit.md) | Biscuit Manager phone app | ESP32-C5 variants; phone GPS in standard workflow | App session/map/export; firmware/hardware dependent |
| [AWOK Dual C5 + Biscuit](./awok-dual-c5-biscuit.md) | Dual-C5 board + phone app and/or Flipper | Two ESP32-C5 radios; select firmware **per USB port** | Biscuit Manager for Biscuit-side observations; other side independent |
| [Wardrive Go](./wardrive-go.md) | Android/iOS app | Phone scanning capabilities; optional RocketGod iosESP Wi-Fi boards | App-local sessions/exports, deliberate upload |
| [Kismet](./kismet.md) | Linux host, browser UI or remote sources | Compatible capture interfaces and GPS source (often gpsd) | KismetDB / optional WiGLE CSV / PCAP-NG according to mode |

**The Flipper Zero itself does not contain a Wi-Fi scanning radio.** It needs suitable external wireless hardware. ESP32-C5 can scan 2.4 and 5 GHz, but a *single* C5 Wi-Fi radio does not observe both bands simultaneously.

## Additional starred field-survey platforms

These are **alternatives**, not interchangeable firmware images or extra steps required by the six workflows above:

- [ESP32 DualBand Wardriver](https://github.com/justcallmekoko/ESP32DualBandWardriver) — a dedicated ESP32-C5 wardriving project worth evaluating for a compact dual-band-capable survey build. Verify the exact board, GNSS source, logging format and release requirements; dual-band support does not imply simultaneous scanning.
- [Piglet Wardriver](https://github.com/Hamspiced/piglet) — GPS-tagged Wi-Fi inventory with SD-card WiGLE-format CSV and a local web interface. A useful comparison when an ESP32 and local log review are preferable to a Flipper-driven workflow.
- [OUI Master Database](https://github.com/Ringmast4r/OUI-Master-Database) — optional **post-collection** manufacturer enrichment for MAC addresses observed in a permitted survey. OUI matches are estimates, not proof of a device maker or identity; randomized and locally administered MACs may not resolve.

Keep the [field workflow](./field-workflow.md) and [data-handling rules](./data-handling.md) in force regardless of platform. Do not activate transmit, deauthentication, credential-collection or captive-portal functions during a passive survey.

## Selecting a workflow

| Your primary objective | Start with |
| --- | --- |
| Flipper-first GPS-tagged inventory on Scout Lite | [SigRoam](./sigroam-scout-lite.md) |
| Keep factory firmware and use a broad wireless toolkit | [Marauder](./esp32-marauder.md) |
| Phone map, BLE and a Biscuit device or DIY C5 | [Biscuit](./biscuit.md) |
| Split two C5 chips into distinct firmware roles | [AWOK Dual C5 / Biscuit](./awok-dual-c5-biscuit.md) |
| Smartphone-centric collection / iosESP expansion | [Wardrive Go](./wardrive-go.md) |
| Linux-based professional survey, heterogeneous adapters and auditable source logs | [Kismet](./kismet.md) |

## Collection principles

- **Observe, don't interfere.** Avoid deauthentication, impersonation, beacon injection, credential collection or capture of third-party data as part of an ordinary wardrive.
- **Fix GPS first.** A row without a trustworthy fix cannot reliably support a spatial inventory; a low satellite count or sudden coordinate jump should be annotated.
- **Beware limitations.** Channel hopping misses brief transmissions; apparent unique-device counts vary by MAC randomization and deduplication; RSSI is not calibrated distance.
- **Separate stored records from display counters.** Compare counts and sample rows in the final CSV or database.
- **Respect versions.** A Flipper `.fap` is not ESP32 scanner firmware; a firmware image for one C5 board/port is not automatically correct for another.
- **Protect data.** BSSID + timestamp + coordinates can reveal sensitive sites or movements. A WiGLE upload is a separate disclosure decision.

## Suggested documentation layout

```text
Wardriving/
├── README.md
├── field-workflow.md
├── data-handling.md
├── sigroam-scout-lite.md
├── esp32-marauder.md
├── biscuit.md
├── awok-dual-c5-biscuit.md
├── wardrive-go.md
└── kismet.md
```

## Related repository areas

- [SDR and RF](../SDR/README.md): radio fundamentals, spectrum measurements and antenna diagnostics—not a substitute for Wi-Fi MAC-layer logging.
- [Flipper Zero](../Documentation/flipper_zero_guide.md) and [hardware hacking](../HardwareHacking/README.md): UART, GPIO, power and device compatibility.
- [OPSEC](../OPSEC/README.md): identity, access controls and location-data minimization.
- [Network Audit Playbook](../PlayBooks/NetworkAuditPlayBook.md): define assessment scope and reporting.
- [Incident response](../IncidentResponse/README.md): contextualize rogue AP findings; a new SSID is not by itself proof of maliciousness.

## Project and format references

- [SigRoam](https://github.com/pingequalab/sigroam-wardriving) / [Scout Lite](https://github.com/pingequalab/scout-lite)
- [ESP32 Marauder](https://github.com/justcallmekoko/ESP32Marauder)
- [Biscuit DIY](https://biscuitshop.us/pages/diy-biscuits) / [AWOK Dual C5](https://awokdynamics.com/products/dual-c5-mini)
- [Wardrive Go for Android](https://play.google.com/store/apps/details?id=com.rocketgod.wardrive) / [iOS](https://apps.apple.com/us/app/wardrive-go/id6783390938)
- [Kismet wardrive mode](https://www.kismetwireless.net/docs/readme/configuring/wardrive/) / [WiGLE](https://wigle.net/)

_Core platform guides last verified on 2026-10-22; additional upstream repository references checked on 2026-10-26. Specific releases and UI labels can change. No hardware tests are claimed by these documents._

---

[Master Index](../README.md) | [Start Here](../START_HERE.md) | [Legal Notice](../LEGAL.md)
