# Additional Survey Firmware: PORKCHOP, wardriver.uk & wardriver3000

> [!CAUTION]
> **Authorized use only.** Use owned hardware and explicitly scoped lab devices.
> Review the [legal notice](../LEGAL.md), radio limits and data-sharing settings.

_Last reviewed: 2026-11-07_

## Purpose

These are distinct implementations, not aliases of JCMK C5 Wardriver, Piglet or
Biscuit. Use this selection/setup reference with the [field workflow](./field-workflow.md)
and [data handling](./data-handling.md). Validate logs before any field deployment.

## Project Differences

| Project | Hardware, Installation & Evidence Boundary |
|---|---|
| [M5PORKCHOP](https://github.com/0ct0sec/M5PORKCHOP) | Reviewed upstream documents Cardputer/ADV S3 with optional GPS/SD and an external C5 coprocessor for dual-band functions. PlatformIO target and companion image must match. Do not infer native S3 5 GHz capability from a dual-band feature list. |
| [wardriver.uk Rev3](https://github.com/JosephHewitt/wardriver_rev3) | Dedicated dual-WROOM-32U ESP32 design with different A/B programs, GPS, SD and other peripherals. Stable releases differ from testing/alpha `main`. Arduino source route is recommended by reviewed README; binary route is labelled beta. |
| [wardriver3000](https://github.com/cifertech/wardriver3000) | CiferTech ESP32/OLED/GPS/SD design. Quiet since 2024-04-28 at review; author flags PCB flaws and lists BLE as future work. Do not count it as a maintained dual-band/BLE replacement. |

## PORKCHOP Setup Checks

1. Start with the upstream Cardputer build documentation and its exact release.
   Extra catalog-listed ports may be separate forks with different support.
2. If using C5/GPS accessories, verify wiring, power and the documented companion
   firmware independently; reflashing the Cardputer does not update its coprocessor.
3. Record selected mode, uploads and synchronization settings. Upstream has
   transmit-capable capture/beacon/BLE functions; do not boot unknown automation
   near unrelated networks. Its documented receive-oriented mode still needs a
   mode/configuration review before calling the complete device receive-only.
4. Validate one owned AP and expected position. Inspect actual exported CSV/PCAP,
   timestamp and band; menu statistics alone do not establish usable evidence.

## wardriver.uk Rev3 Setup Checks

1. Identify both physical ESP32 modules and label their A/B roles before flashing.
   Follow the official hardware wiki at [wardriver.uk](https://wardriver.uk/).
2. Choose a stable release and use its `boards.txt` and `libraries.txt` requirements.
   Do not pair A from one release with B from another or assume both run one image.
3. Prepare the documented FAT32 SD card; reviewed README states the device will
   not boot without it. Preserve `cfg.txt`, logs and authorized network settings.
4. Configure local management on a private network and review automatic updates,
   uploads and location fallback. A GSM-database location estimate is not a GNSS fix.
5. Collect a short approved session and inspect the actual CSV against known APs,
   time and position. Both WROOM radios remain 2.4 GHz Wi-Fi hardware.

## Shared Validation & Recovery

| Check | Acceptance Evidence |
|---|---|
| Hardware identity | Exact board revision, radio module, image/companion versions and pin map recorded |
| Local collection | Known owned AP appears in saved records with plausible time, band and coordinates |
| Location source | GNSS, phone, coordinator or fallback database explicitly identified |
| Sharing | No upload/sync credentials or automatic disclosure unless separately approved |
| Recovery | Upstream procedure and matching images saved; no generic offsets reused across projects |

Use wardriver3000's [author documentation](https://cifertech.net/wardriver3000-build-your-own-wardriving-machine/)
and schematic for a historical bench build; assess the documented hardware faults
before powering it. No dedicated browser installer was verified for these three
primary upstreams. A third-party flasher listing does not change that finding.

## Related Guides

| Resource | Use |
|---|---|
| [Biscuit](./biscuit.md) | Phone/session workflow and single/dual-chip differences |
| [C5 Wardriver](./esp32-c5-wardriver.md) | Separate JCMK build and role model |
| [Piglet](./piglet.md) | Separate XIAO/mesh implementation |
| [Wardriving Index](./README.md) | All survey routes |

## Verification Scope

Primary project documentation and links were reviewed. No firmware build, flash,
hardware compatibility test or radio test was performed. Follow the selected
release's target manifest and recovery instructions, and preserve original logs.

---

[Master Index](../README.md) | [Role Navigation](../START_HERE.md) | [Legal Notice](../LEGAL.md)
