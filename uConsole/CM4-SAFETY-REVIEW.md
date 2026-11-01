# uConsole CM4/CM5 Safety, Currency and Navigation Review

_Reviewed October 31, 2026 · CM4 automation v2.0 · No live hardware used_

[**uConsole index**](./README.md) · [**CM4 setup**](./CM4-SETUP.md) · [**CM5 setup**](./CM5-SETUP.md) · [**CM5 display recovery**](./CM5-DISPLAY-RECOVERY.md) · [**Parrot CM5**](./PARROT-CM5.md) · [**Scripts index**](./scripts/README.md) · [**Root guide**](../README.md)

## What was wrong and what changed

The previous CM4 installer (v1.2, visible in the Git history before this change) ran a chain of state-changing operations by default. It could add **Kali Rolling package sources to Debian Trixie**, set APT pins, remove `raspberrypi-sys-mods`, remove Python's `EXTERNALLY-MANAGED` marker, install older Debian library packages over plain HTTP, enable `--force-overwrite` in APT, execute online installer scripts as root, install DKMS drivers, alter desktop/boot files, and change GPIO state. These are not generic prerequisites for a healthy uConsole. **Do not reuse or run a saved v1.x copy** of that script.

The [replaced CM4 script](./scripts/uconsole-cm4-setup.sh) now follows the conservative approach:

- **Default:** read-only recognition of CM4 hardware, Debian or native Kali OS identity, and a check for Kali repositories mixed into Debian.
- **Optional `--snapshot`:** private, root-only configuration backup. A *full SD/eMMC/NVMe disk image is still required* for a proper restore.
- **Optional `--with-aio`:** only on an already compatible Debian/Raspberry Pi OS image and only with real AIO hardware installed; prompt, snapshot, then `apt-get -s --no-remove` and opt-in APT installation. APT scripts and dependencies can still affect the system.
- **Optional `--kali-tools`:** Kali tools only on a **native Kali OS**, never on Debian with Kali added.
- **`--dry-run`:** does not modify files or update/download packages; it checks the proposed intent but is **not a full APT transaction simulation** because package indexes could be missing or stale. The real opt-in path performs its own APT simulation after refreshing indexes.
- **Never automated:** `full-upgrade`, APT source/pin changes, forced overwrite, shell-piped downloads, LightDM/AccountsService/cryptsetup modifications, GPIO power changes, DKMS/EEPROM/boot overlays, SD/NVMe cloning, and system reboots.

The prior v1.x script is not retained as an executable repository file; it remains accessible through Git history strictly for incident comparison. The new v2.0 script is intentionally **not a full one-click deployment**.

## Safe device-first procedure

1. Identify the installed **CM4 or CM5**, kernel and image (Rex's Trixie/Bookworm, native Kali, or a supported port). Record `cat /etc/os-release`, `uname -r`, `lsblk -f`, `cat /proc/device-tree/model`, `apt-cache policy`.
2. Take a **tested** storage image with an external computer or other verified recovery workflow. The scripts' config backup cannot restore a broken bootloader or system libraries.
3. Inspect the appropriate guide and run only the `--help` / read-only `--status` path first.
4. For fitted AIO v2 hardware, validate board revision, ribbon cable orientation, carrier board, USB and attached antennas. Check current vendor AIO package guidance; enable one module at a time and measure boot/power consequences.
5. Before optional package installation, review current APT sources, `apt-get -s` removal plans, package signer and architecture; leave desktop/kernel packages untouched unless the known-good image maintainer documents the change.
6. After a change, **power-cycle and verify** keyboard, trackball, screen orientation, panel, Wi-Fi, AIO rails, GPS, RTC and SDR, with an explicit rollback plan.

## CM4 / CM5 and NVMe distinctions

- **CM4 vs CM5 have different UART and RTC device-tree configurations.** Only use the specific overlay shown by the vendor for your **fitted board and OS**. The [HackerGadgets AIO V1/V2 guide](https://hackergadgets.com/pages/hackergadgets-uconsole-rtl-sdr-lora-gps-rtc-usb-hub-all-in-one-extension-board-setup-guide) documents CM4's `i2c-rtc,pcf85063a` and CM5's `i2c-rtc,pcf85063a,i2c_csi_dsi0` with internal RTC disabled.
- The [HackerGadgets `aiov2_ctl` project](https://github.com/hackergadgets/aiov2_ctl) documents GPIO power rails and optional companion apps. Never infer that a detected module is powered properly or that a script automatically enabled USB/GPS/LoRa/SDR.
- **PCIe detection and NVMe boot are different**. The Compute Module EEPROM `BOOT_ORDER` matters, as do CM4 Lite versus eMMC variants and the actual carrier board. Do not tell users to remove the SD card after an unverified clone. Follow [Raspberry Pi's official Compute Module documentation](https://www.raspberrypi.com/documentation/computers/compute-module.html).
- **Parrot CM5** remains an experimental adaptation for an *already booting and display-working* image; it does not transform Debian/Kali into Parrot or prove stock Parrot device compatibility.

## Tests and what they do not establish

The [uConsole GitHub Action](../.github/workflows/cm5-parrot-checks.yml) includes Bash syntax checks and isolated Python regressions for the CM4 safety gates and the pre-existing CM5/Parrot fixture tests. It does not mount or modify a Raspberry Pi, emulate the AIO board, run APT installations, recover a bricked display, measure battery/SDR/GPS, or test real NVMe boot. Manual verification on spare media is required before operational use.

Offline internal Markdown links and lint are tested by repository actions. Official sources and a representative set of vendor repositories were reviewed; **not every external forum/image/download URL has been independently executed or checked for permanence**.

## If you previously ran the v1.x installer

**Do not run v2.0 as a rollback.** Preserve the current disk; collect `/etc/apt/sources.list*`, `/etc/apt/preferences.d`, `dpkg --audit`, `apt-cache policy`, `journalctl -b`, LightDM logs and `/boot/firmware/config.txt`. Restore a known-good image if package mixing or desktop/library ABI damage is extensive. Use the [CM5 display-recovery evidence checklist](./CM5-DISPLAY-RECOVERY.md) as a general model, but **do not apply CM5 overlays to CM4**.

## Sources

- [Official HackerGadgets AIO v2 installation and wiring](https://hackergadgets.com/pages/hackergadgets-uconsole-rtl-sdr-lora-gps-rtc-usb-hub-all-in-one-extension-board-setup-guide)
- [Official HackerGadgets `aiov2_ctl` project](https://github.com/hackergadgets/aiov2_ctl)
- [Raspberry Pi Compute Module hardware and boot EEPROM](https://www.raspberrypi.com/documentation/computers/compute-module.html)
- [Kali repository mixing warning](https://www.kali.org/docs/general-use/kali-apt-sources/)
- [Debian Don't Break Debian](https://wiki.debian.org/DontBreakDebian)
- [ClockworkPi community forums](https://forum.clockworkpi.com/)

[Back to uConsole index](./README.md) · [Back to master guide](../README.md)
