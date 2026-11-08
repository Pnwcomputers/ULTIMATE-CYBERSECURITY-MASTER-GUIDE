# FancyGotchi & Pwnagotchi: Image, Theme & CYD Project Boundaries

> [!CAUTION]
> **Authorized use only.** Use owned hardware and explicitly scoped lab devices.
> Review the [legal notice](../LEGAL.md), radio limits and data-sharing settings.

_Last reviewed: 2026-11-07_

## Purpose

The name FancyGotchi now appears in different hardware/software contexts.
Identify the project before downloading anything: a Pi theme manager, a Linux
image and an independent ESP32 firmware are not interchangeable artifacts.

## Identify The Project

| Project | Verified Role & Target Limits |
|---|---|
| [V0r-T3x FancyGotchi 2.0](https://github.com/V0r-T3x/Fancygotchi) | Theme manager for Pwnagotchi on Raspberry Pi. Not an ESP32 image or replacement radio stack. README flags Pi Zero W fixes and incomplete Pi 4 documentation; latest repository push 2025-10-26 at review. |
| [jayofelony Pwnagotchi](https://github.com/jayofelony/pwnagotchi) | Separate maintained Linux-image/software lineage. Reviewed default `noai` branch removes the old AI component; Zero W 32-bit support is legacy, with current 64-bit targets listed for Zero 2 W / Pi 3 / 4 / 5. |
| [Xombi3 FancyGotchi CYD Port](https://github.com/Xombi3/Fancygotchi-cyd-port) | Independent ESP32-2432S028R capture firmware; not the Pi theme package. Experimental compatibility should be checked from code/configuration. README includes active deauthentication behavior and board/display-specific wiring. |
| [Bjorn](./bjorn_pi.md) | Different Pi network-service assessment application, not Pwnagotchi firmware or a FancyGotchi theme. |

## Pi Theme Setup & Rollback

1. Record Pi model, CPU/image architecture, Pwnagotchi fork/release, display
   controller/revision, Python environment and installed plugins.
2. Back up the SD image, configuration and themes. Keep captured data and client
   secrets protected; do not distribute a configured image as a theme package.
3. Compare the [FancyGotchi wiki](https://github.com/V0r-T3x/Fancygotchi/wiki)
   prerequisites with the **chosen Pwnagotchi release**. README workarounds from a
   different fork are not a universal compatibility fix. If the pair is unsupported,
   retain the working image rather than modifying core plugin code blindly.
4. Review any installer before executing it, then install the documented matching
   theme/plugin files. Use a disposable SD clone for the first attempt.
5. Keep radio services disabled or in the separately approved lab configuration
   while testing the UI. A friendly screen or theme does not disable Pwnagotchi's
   potentially active authentication/association behavior.
6. Check display refresh, menus, storage, boot service health and logs. If startup
   fails, restore the known SD image/config rather than layering more unrelated fixes.

## Independent CYD Port Review

The CYD project's claimed display driver, SPI assignments, channel-hopping plan
and active startup behavior must be checked against the actual board and source.
The same CYD name can cover different display controllers. No dedicated official
web flasher was verified for this port; do not put its files on a Raspberry Pi
or treat the Pi theme's documentation as its installation procedure.

For any authorized evaluation, use an isolated owned-AP bench and establish
transmit/default behavior before powering the device in an uncontrolled RF area.
This guide does not reproduce its automated deauthentication or cracking workflow.

## Related Guides

| Resource | Use |
|---|---|
| [Pwnagotchi Cheatsheet](./pwnagotchi_cheatsheet.md) | Existing reference; legacy AI/default statements may not match the selected current fork |
| [Device Firmware List](../HardwareHacking/device-firmware-list.md) | Pi versus ESP32/CYD installation paths |
| [Firmware Catalog](../HardwareHacking/esp32-security-firmware-catalog.md) | Source/activity records and broader scope |
| [Documentation Index](./README.md) | Section navigation |

## Verification Scope

Primary project documentation and links were reviewed. No firmware build, flash,
hardware compatibility test or radio test was performed. Follow the selected
release's target manifest and recovery instructions, and preserve original logs.

---

[Master Index](../README.md) | [Role Navigation](../START_HERE.md) | [Legal Notice](../LEGAL.md)
