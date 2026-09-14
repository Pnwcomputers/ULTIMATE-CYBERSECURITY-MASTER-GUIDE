# uConsole CM5 Parrot Setup 
##_*Experimental; Use at your OWN RISK!_

## 🎯 Purpose

Provide an experimental Parrot adaptation of the conservative CM5 v1.4 post-flash script.

## ⚙️ Function

The script inventories/backups configuration, optionally installs Parrot tool groups, Rex's AIO package and a selected Wi-Fi DKMS package, then audits package state.

## 🏆 Goal

Set up an **existing Parrot ARM64 installation on CM5** while preserving the working uConsole boot and desktop configuration. Hardware validation is pending.

## 📋 When to Use

Use only after Parrot already boots with working uConsole screen, input, desktop and networking. This script does **not** convert Rex Debian or Kali to Parrot, build a boot image, install a kernel, or establish uConsole compatibility for a generic Parrot Raspberry Pi image. It rejects Debian and Kali, even if Parrot repositories have been added.

## Prerequisites

- Raspberry Pi Compute Module 5 with ARM64 userspace and `ID=parrot` in `/etc/os-release` (case-insensitive).
- Working uConsole kernel/firmware and `/boot/firmware/config.txt` and `cmdline.txt`.
- Existing authenticated package repositories configured for the installed Parrot release. The script does not add repositories, keys or APT pins.
- Bash, Python 3 and standard APT/dpkg utilities.
- A full backup of boot/storage media. The script's root-only configuration snapshot is not a disk image and excludes user home directories.
- For `--with-aio`: fitted AIO hardware and a compatible `hackergadgets-uconsole-aio-board` candidate in existing sources. Compatibility with Parrot is not established by this script.
- For Wi-Fi DKMS: identified adapter chipset, an appropriate package in your sources, and matching headers for the running kernel. The default package name is inherited from CM5 v1.4; availability and driver compatibility must be verified on the device.

## Run

From this directory, review the script first:

```bash
bash ./uconsole-cm5-parrot-setup.sh --help
sudo bash ./uconsole-cm5-parrot-setup.sh --dry-run

# Default: configuration snapshot and package audit, no package installation.
sudo bash ./uconsole-cm5-parrot-setup.sh

# Preview the default information-gathering group using cached APT lists.
sudo bash ./uconsole-cm5-parrot-setup.sh --install-parrot-tools --dry-run

# Install that group; refreshes package metadata and checks the resolver plan.
sudo bash ./uconsole-cm5-parrot-setup.sh --install-parrot-tools

# Other upstream groups (verify available packages on this device).
sudo bash ./uconsole-cm5-parrot-setup.sh --parrot-meta=parrot-tools-wireless --dry-run
sudo bash ./uconsole-cm5-parrot-setup.sh --parrot-meta=parrot-tools-full --dry-run

# Optional AIO package, only when its prerequisites above are met.
sudo bash ./uconsole-cm5-parrot-setup.sh --with-aio --dry-run
```

Remove `--dry-run` from a reviewed selection to execute it. A dry run uses cached package metadata, performs APT simulation and makes no log, backup or state writes. Missing/stale metadata can cause a dry run to fail or differ from the real plan. Normal package runs refresh metadata and check again before installing.

Parrot's [upstream tool definitions](https://github.com/ParrotSec/parrot-tools/blob/master/debian/control) put most tool contents in `Recommends`. This adaptation uses `--install-recommends`; copying v1.4's Kali `--no-install-recommends` behavior would omit much of a Parrot group. APT may still skip unavailable recommendations. An installed metapackage is not proof that every upstream tool exists on ARM64. The full group can be large; review APT's download/storage summary.

## Options

| Option | Behavior |
|---|---|
| `--install-parrot-tools` | Enable `parrot-tools-infogathering`; default off |
| `--parrot-meta=PKG` | Select and enable `parrot-tools` or `parrot-tools-*` |
| `--skip-parrot-tools` | Disable Parrot tool installation |
| `--with-aio` / `--skip-aio` | Enable/disable AIO package; default off |
| `--install-wifi-dkms` | Enable inherited `realtek-rtl88xxau-dkms` default |
| `--wifi-dkms=PKG` | Select and enable an explicitly chosen `*-dkms` package |
| `--skip-wifi-dkms` | Disable driver installation; default off |
| `--hostname=NAME` | Optional hostname change |
| `--phase=PHASE` | Run only preflight, update, parrot_tools, aio, peripherals or finalize; never advances state |
| `--dry-run` | Simulate with cached metadata without writes |
| `--yes` | Skip initial confirmation; all guards still apply |
| `--status` | Read Parrot setup completion marker |
| `--reset` | Archive Parrot markers; not rollback |

Environment variables: `INSTALL_PARROT_TOOLS`, `PARROT_METAPACKAGE`, `INSTALL_AIO`, `INSTALL_WIFI_DKMS`, `WIFI_DKMS_PACKAGE`, `HOSTNAME_NEW`, `DRY_RUN`, `ASSUME_YES`. Boolean values must be `yes` or `no`. Prefer CLI flags because sudo can filter environment variables.

## Safeguards and limits

- Separate `/var/lib/uconsole-parrot-setup` state and `/var/log/uconsole-parrot-setup.log`; original CM5 setup state is not reused.
- Active Kali sources are rejected in legacy and Deb822 formats, including named Kali suites on local mirrors. This is not a complete package-origin audit, and removing repositories does not undo installed foreign packages.
- All selected package groups are simulated before hostname/package changes; each install is simulated again. A failed refresh, unresolved package or rejected plan stops execution.
- A conservative name-based plan check rejects package removals and changes to known kernel, firmware, boot, desktop, authentication, networking and core runtime packages. A blocked plan requires separate image-maintainer review; there is no bypass flag. The list cannot identify every custom vendor package or side effect.
- No full upgrade, forced overwrite, dependency injection from other releases, automatic fix-broken, display rotation, desktop/session replacement, direct boot edits or automatic reboot.
- Package maintainer scripts and unprotected dependency changes remain possible. APT simulation is not a transactional guarantee; do not run another package manager concurrently.
- Default and forced-phase runs still perform preflight and a configuration snapshot. `update` skips upgrades and only applies a requested hostname.
- Completion means selected operations returned successfully; it does not certify every recommended tool, kernel module, desktop, or AIO peripheral. A failure after an earlier successful package operation is not rolled back.
- No automatic source installations of aiov2_ctl, Meshtastic or ADS-B, no radio rail configuration and no boot overlay changes. Use current vendor instructions for those tasks.

## Verification

From the repository root:

```bash
bash -n uConsole/scripts/uconsole-cm5-parrot-setup.sh
python3 -m unittest discover -s uConsole/tests -p 'test_cm5_parrot_setup.py' -v
```

Fixture tests cover OS/source rejection, package-plan protection, correct recommendation handling, dry-run behavior, failure propagation and independent completion state. They do not install packages. The scoped GitHub workflow runs syntax and fixture checks; consult its actual result before use.

No Parrot/CM5 hardware installation has been tested for this version. Validate on spare media: normal boot/login, screen orientation, panel/input, networking, then optional AIO GPS/LoRa/SDR/RTC and driver operation. Record the Parrot version, kernel, screen revision, AIO revision and adapter chipset with the results.

## Related Files

- [Parrot setup script](./uconsole-cm5-parrot-setup.sh)
- [Scripts index](./README.md)
- [Original CM5 script](./uconsole-cm5-setup.sh)
- [CM5 guide](../CM5-SETUP.md)
- [Display recovery](../CM5-DISPLAY-RECOVERY.md)
- [Parrot fixture tests](../tests/test_cm5_parrot_setup.py)
