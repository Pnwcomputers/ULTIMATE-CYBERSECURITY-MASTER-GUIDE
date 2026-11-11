# Firmware Web Flashers & Installers

> [!CAUTION]
> **Authorized use only.** Flash hardware you own or are authorized to modify.
> Flashing may erase keys, settings and logs. Review [LEGAL.md](../LEGAL.md) and
> identify the exact board, chip, revision and recovery procedure first.

_Last reviewed: 2026-11-07_

## Biscuit Release & Recovery Routes

| Resource | Description / Boundary |
|---|---|
| [Biscuit Release Downloads](https://github.com/CodeHedge/diy_node_web_flasher/releases) | Vendor docs link raw DIY/Node images and layouts here. Installer repository is archived; prefer current vendor flasher and verify release provenance. |
| [Biscuit Desktop Recovery Utility](https://github.com/CodeHedge/biscuit_flasher) | Python utility for named Pro/Ultra/Crumb products; not a browser flasher or the DIY workflow. |

## After Installation: Validate The Selected Firmware

A successful write only verifies part of the setup. Use the
[dedicated firmware lab routes](./esp32-security-firmware-catalog.md#dedicated-setup--validation-guides)
to confirm the board, runtime interface, log destination and a harmless expected
result. In particular, GhostESP capture, C5/Piglet coordinator modes, Pico-Ducky
setup mode and Evil Crow web assets require checks beyond the flash progress bar.

## Purpose

Companion to the [firmware master catalog](./esp32-security-firmware-catalog.md).
Dedicated installers below select builds for a named project. The separate
multi-device/multi-firmware list covers catalog tools and general uploaders.
A flasher can write an incompatible or untrusted image successfully; a completed
write is not evidence that the firmware is safe or supports your hardware.

## Navigation

| Resource | Description |
|---|---|
| [Dedicated Installers](#dedicated-project-installers) | Upstream-associated firmware-to-flasher mappings |
| [Multi-Device / Multi-Firmware](#multi-device--multi-firmware-web-flashers) | Catalog tools, general uploaders & reusable installer framework |
| [Other Update Methods](#other-update-methods) | Desktop, UF2, SD, DFU & host-side workflows |
| [Browser & Image Checks](#browser--image-checks) | Connection prerequisites, image layout & provenance |
| [Verification Notes](#verification-notes) | What was checked & unresolved limitations |

## Dedicated Project Installers

Several dedicated installers support many boards but only one firmware family;
that does not make them multi-firmware catalogs. Links were established from
project READMEs, project wiki installation pages or vendor documentation.

| Firmware / Official Installer | Scope & Important Limits |
|---|---|
| [Bruce Web Flasher](https://bruce.computer/flasher) | [Bruce upstream](https://github.com/BruceDevices/firmware). Select exact M5Stack/LILYGO/CYD or other supported board. Optional RF/NFC hardware is still required. |
| [JCMK Marauder Installer](https://justcallmekoko.github.io/MarauderInstaller/) | [Marauder install wiki](https://github.com/justcallmekoko/ESP32Marauder/wiki/update-firmware) recommends this installer. Board revisions, Flipper accessories, Cardputer and C5 targets have different images. |
| [GhostESP Flasher](https://ghostesp.net/flasher) | [Revival upstream](https://github.com/GhostESP-Revival/GhostESP). Select target and release channel. Upstream explicitly recommends its official flasher or GitHub release binaries over mirrors. |
| [Evil-Flasher](https://7h30th3r0n3.github.io/Evil-Flasher/) | [Evil-M5Project upstream](https://github.com/7h30th3r0n3/Evil-M5Project) links this installer. Supports listed M5/CYD/AWOK targets; also check required SD assets and device-specific features. |
| [ESP32 Bit Pirate Flasher](https://geo-tp.github.io/ESP32-Bit-Pirate/webflasher/) | [Bit Pirate upstream](https://github.com/geo-tp/ESP32-Bit-Pirate), formerly ESP32 Bus Pirate. Select S3 target, flash size and pin mapping; project Web Serial terminal is a different tool. |
| [C5 Wardriver Installer](https://justcallmekoko.github.io/C5WardriverInstaller/) | [Dual Band Wardriver upstream](https://github.com/justcallmekoko/ESP32DualBandWardriver) recommends this installer. Use documented DevKit/host-board or T-Dongle build; GPS/SD wiring matters. |
| [Biscuit Flasher](https://flasher.biscuitshop.us/) | [Official DIY hardware matrix](https://codehedge.github.io/Biscuit-Wiki/devices/diy.html). Vendor firmware for supported Pro/Ultra/Crumb, DIY, AWOK and node models. Some devices have two different MCUs; distinguish full install, update and beta channels. |
| [Scout Lite Installer](https://flash.pingequa.com/devices/scout-lite) | [Vendor hardware documentation](https://github.com/pingequalab/scout-lite). Use Scout Lite-specific options and matching Flipper controller/mode. SigRoam FAP installation is separate from writing an ESP image. |
| [Meshtastic Flasher](https://flasher.meshtastic.org/) | [Firmware upstream](https://github.com/meshtastic/firmware). Multi-board installer for one ecosystem; select MCU, board and region. Non-ESP targets can use different update transports/files. |
| [ExpressLRS Web Flasher](https://expresslrs.github.io/web-flasher/) | [ExpressLRS upstream](https://github.com/ExpressLRS/ExpressLRS). Only supported TX/RX targets and update paths; not every ExpressLRS board uses an ESP serial workflow. |
| [Momentum Web Updater](https://momentum-fw.dev/update/) | [Momentum upstream](https://github.com/Next-Flip/Momentum-Firmware). Flipper Zero updater, not an ESP32 uploader or a flasher for its external Wi-Fi module. |
| [Unleashed Web Installer](https://web.unleashedflip.com/) | [Unleashed upstream](https://github.com/DarkFlippers/unleashed-firmware) links this installer. Updates Flipper Zero itself; the ESP accessory flasher below is a separate service. |
| [HaleHound Installer](https://flash.halehound.com/) | Dedicated project installer linked by [upstream](https://github.com/JesseCHale/HaleHound-CYD); exact CYD/RF-Hat target and peripherals matter. |
| [nyanBOX Installer](https://nyandevices.com/flasher) | Dedicated device installer linked by [upstream](https://github.com/jbohack/nyanBOX); not a generic NRF24 or ESP32 image. |
| [SquachWatch Installer](https://squachwatch.com/) | Dedicated project installer linked by [upstream](https://github.com/skizzophrenic/SquachWatch-CYD); distinguish display controllers and beta targets. |
| [MeshCore Installer](https://meshcore.io/flasher) | Dedicated ecosystem installer linked by [upstream](https://github.com/meshcore-dev/MeshCore); role, LoRa module and region settings differ from Meshtastic. |

## Multi-Device / Multi-Firmware Web Flashers

This is the separate general-purpose list. **Uploader** means you supply a
compatible binary/layout; **catalog** means the tool offers firmware selections;
**framework** means developers must provide a manifest and hosting integration.
None offers universal firmware-to-board compatibility.

| Tool / Primary Source | Type, Device Scope & Firmware Selection |
|---|---|
| [ESP Terminator](https://espterminator.com/) — [author site](https://dagnazty.dev/) | Multi-device catalog/uploader with ESP, Flipper and other target-specific workflows. [Usage guide](./esp-terminator.md); verify each image against upstream, not only the catalog label. |
| [Unleashed ESP Flasher](https://espflasher.unleashedflip.com/) — [upstream association](https://github.com/DarkFlippers/unleashed-firmware) | Multi-firmware catalog for specified WROOM, S2 Flipper Wi-Fi Dev Board and C5 modules. Lists Marauder, GhostESP, FlipperHTTP and target-dependent Blackmagic. Unleashed's endorsement does not establish endorsement by each firmware author; prefer GhostESP's own installer. |
| [ESP Web Tool](https://esptool.spacehuhn.com/) — [Spacehuhn source](https://github.com/SpacehuhnTech/espwebtool) | General uploader for supported ESP32/ESP8266 targets. Supply upstream binaries and correct offsets. The older `esp.huhn.me` address redirects here; do not count it as a second service. |
| [ESPHome Web](https://web.esphome.io/) — [ESPHome Web Tools source](https://github.com/esphome/esp-web-tools) | Browser upload/install interface for supported ESP devices, including local firmware preparation/upload workflows. Not a catalog of all security firmware; verify accepted binary format before use. |
| [Espressif ESP Tool](https://espressif.github.io/esptool-js/) — [esptool-js source](https://github.com/espressif/esptool-js) | Vendor's general browser serial uploader/demo. Supports chips implemented by the current library; manually match binary parts and addresses. A newly released chip may require a newer tool. |
| [ESPConnect](https://thelastoutpostworkshop.github.io/ESPConnect/) — [source](https://github.com/thelastoutpostworkshop/ESPConnect) | General ESP uploader, backup, serial and filesystem interface. README lists ESP32-family targets and limited ESP8266 support. Raw-flash backups may contain secrets; protect them. |
| [Launcher Web Flasher](https://bmorcelli.github.io/Launcher/webflasher.html) — [Launcher source](https://github.com/bmorcelli/Launcher) | **Launcher ecosystem:** browser installer installs Launcher itself across supported M5Stack/LILYGO/other boards. The separate [firmware catalog](https://bmorcelli.github.io/Launcher/catalog.html) supports discovery; Launcher handles supported on-device SD/online firmware changes. Do not assume the web installer directly flashes every catalog item. |
| [ESP Web Tools](https://esphome.github.io/esp-web-tools/) — [source](https://github.com/esphome/esp-web-tools) | Reusable multi-chip/multi-image **installer framework**, not a hosted security-firmware catalog. A site author supplies chip-family manifests, image parts and offsets. Included separately from the ESPHome Web user interface to explain what many dedicated installers use. |

GhostESP's upstream explicitly declines to verify third-party mirrors/flashers.
Use its dedicated official installer or upstream binaries even when a generic
uploader or catalog advertises GhostESP support. Catalog presence alone does not
establish upstream endorsement, freshness or integrity.

## Other Update Methods

| Resource | Why It Is Separate |
|---|---|
| [M5Burner](https://docs.m5stack.com/en/download) | Desktop application and firmware ecosystem; not a browser flasher. NEMO and other M5 projects document this route. Check publisher identity and exact device category. |
| [pico-ducky](https://github.com/dbisu/pico-ducky) | CircuitPython UF2 plus project files on Pico mass storage; different from ESP ROM serial flashing. |
| [WiFi Duck](https://github.com/SpacehuhnTech/WiFiDuck) | ESP8266 plus ATmega32U4 installation. Its runtime browser UI edits scripts; it is not a two-MCU firmware installer. |
| [Sniffle](https://github.com/nccgroup/Sniffle) | TI UniFlash/DSLite and matching firmware/host code; do not upload TI images with an ESP tool. |
| [HackRF](https://github.com/greatscottgadgets/hackrf) | Host tools, firmware update and DFU recovery; not an ESP target. |
| [PortaPack Mayhem](https://github.com/portapack-mayhem/mayhem-firmware) | Project release/update workflow plus matching SD assets; a device web interface is not automatically a verified browser recovery flasher. |
| [Flipper Official Firmware](https://github.com/flipperdevices/flipperzero-firmware) | Follow upstream install/update instructions or qFlipper. Flipper firmware and the ESP accessory firmware require separate update workflows. |
| [Proxmark3](https://github.com/RfidResearchGroup/proxmark3) | Dedicated flashing tool and matching host/firmware builds. |
| [ChameleonUltra](https://github.com/RfidResearchGroup/ChameleonUltra) | Upstream-linked GUI/CLI updater. A browser console alone does not establish firmware-update capability. |

## Browser & Image Checks

1. Use HTTPS and a browser explicitly supported by the chosen installer. Desktop
   Chrome/Edge commonly support Web Serial; Firefox/Safari/mobile support varies
   by API, extension, USB bridge and operating system. Do not assume all browsers
   have the same connection method.
2. Connect a data-capable USB cable and identify the correct USB interface.
   Install a trusted bridge driver only when required. Close other serial monitors.
   Enter BOOT/RESET/download mode according to the board documentation.
3. Check publisher, upstream link, firmware version/channel, exact target,
   flash size, merged versus separate images and documented offsets. Never copy
   offsets from an unrelated board or assume every binary belongs at address zero.
4. Back up authorized data first. Full erase, app-only update and factory image
   are different operations. Confirm whether NVS, pairing data, filesystems and
   SD assets must be restored or replaced.
5. Grant the browser access only to the intended device. Inspect downloaded
   scripts/binaries and hashes/signatures where published. Flashers execute code
   in the browser and can write persistent firmware; a trusted domain alone does
   not prove every listed image was audited.
6. After flashing, confirm device identity/version, reboot normally and run a
   benign functional check. Keep the recovery image and documented recovery path.

## Verification Notes

Installer association was checked against upstream/vendor documentation and the
pages were retrieved on 2026-11-07. All listed dedicated installer pages and
general flasher entrypoints returned HTTP 200 through the review fetches.
This establishes page availability, not a successful serial connection, download,
manifest validation, image authenticity or hardware flash. No device was connected
and no firmware was written.

The local link checker could not validate the Biscuit endpoint's TLS certificate
chain; a separate Firecrawl retrieval returned HTTP 200 with the expected official
installer content and board selection. Treat this as a recorded checker limitation,
not a reason to disable certificate verification. The FCC jammer source linked
from the catalog returned HTTP 403 to the automated checker; it is not counted
as a successfully validated page. A guessed Flipper updater hostname failed DNS
and was excluded; use upstream instructions instead of inferred installer URLs.

Activity metadata for the general tools: ESP Web Tool last push 2026-11-04;
ESP Web Tools 2026-11-02; esptool-js 2026-11-02; ESPConnect 2026-10-15;
Launcher 2026-11-07. All were non-archived at review. These are repository push
dates, not evidence that every firmware entry in their catalogs is maintained.

Recheck upstream ownership, redirects, board manifests, production/beta selection
and browser API requirements when updating this reference. Report inaccessible
sources explicitly rather than treating HTTP 403, TLS failures or DNS errors as
validated links.

## Related Guides

| Resource | Description |
|---|---|
| [Firmware Master Catalog](./esp32-security-firmware-catalog.md) | Projects, supported target examples, use-cases & maintenance signals |
| [Device-First Firmware References](../firmware-hardware-compatibility.md) | Selection links; this page no longer publishes a compatibility matrix |
| [Wardriving](../Wardriving/README.md) | Hardware/controller pairing, GPS & data handling |
| [Hardware Hacking](../HardwareHacking/README.md) | Electronics, debug interfaces & bench foundations |

---

[Back to Master Index](../README.md) | [Role Navigation](../START_HERE.md) | [Legal Notice](../LEGAL.md)
