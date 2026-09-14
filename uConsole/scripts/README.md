# 🛠️ uConsole Setup Scripts

## 🎯 Purpose

Post-flash setup and recovery references for ClockworkPi uConsole systems. Choose the script for your compute module and read its current limitations before running it.

> [!IMPORTANT]
> **CM5 rotation/blank desktop reports:** Use [CM5 display recovery](../CM5-DISPLAY-RECOVERY.md) before rerunning an old installer. The CM5 v1.4 candidate removes risky desktop and cross-distribution changes. Hardware validation is pending. The CM4 script is unchanged and has not been audited by this fix.

## 📂 Scripts

| Script | Scope |
|---|---|
| [uconsole-cm5-parrot-setup.sh](./uconsole-cm5-parrot-setup.sh) | Experimental Parrot CM5 post-flash setup; requires existing Parrot. [Usage and limits](./PARROT-CM5.md) |
| [uconsole-cm5-setup.sh](./uconsole-cm5-setup.sh) | Conservative CM5 setup, proposed v1.4; preserves the image's desktop and boot configuration |
| [uconsole-cm4-setup.sh](./uconsole-cm4-setup.sh) | Legacy CM4 automation; review independently before use |
| [uconsole-repair.sh](./uconsole-repair.sh) | CM4/CM5 boot-overlay repair; not a general desktop recovery tool |

## ⚙️ CM5 v1.4 Behavior

| Phase | Behavior |
|---|---|
| `preflight` | Preserve desktop, authentication and encryption configuration |
| `update` | Skip system upgrade; optionally set hostname |
| `kali_tools` | Install requested metapackage only on native Kali |
| `aio` | Install Rex's AIO board package only with `--with-aio` |
| `peripherals` | Leave boot overlays unchanged; optional Wi-Fi DKMS install |
| `finalize` | Audit package state; require manual device verification |

Environment/source checks and a root-only configuration/package snapshot run before selected operations, including
`--phase`. Default execution does not install packages. It saves a configuration snapshot and successful completion
state; it is not a full backup or desktop repair.

Automatic source installation of `aiov2_ctl`, legacy library downloads, Meshtastic/ADS-B bootstraps, hardware rail
programming and direct overlay edits were removed. Use current [HackerGadgets
instructions](https://hackergadgets.com/pages/hackergadgets-uconsole-rtl-sdr-lora-gps-rtc-usb-hub-all-in-one-extension-board-setup-guide)
and [Rex package guidance](https://forum.clockworkpi.com/t/hackergadgets-aio-board-package/17875) for fitted
hardware. The candidate intentionally reduces the old installer's scope.

APT installations use `--no-remove` and stop on failure. Dependency upgrades and package-maintainer script changes are still possible. Review on spare media before broad use.

## 🚀 Usage

Download or check out the **reviewed candidate**, inspect it, and confirm that `--help` reports v1.4. Downloading from `main` still gives the old script until the change is merged.

```bash
bash ./uconsole-cm5-setup.sh --help
sudo bash ./uconsole-cm5-setup.sh --dry-run
sudo bash ./uconsole-cm5-setup.sh

# Fitted AIO hardware only
sudo bash ./uconsole-cm5-setup.sh --with-aio

# Native Kali only
sudo bash ./uconsole-cm5-setup.sh --install-kali-tools
```

| Option | Meaning |
|---|---|
| `--with-aio` / `--skip-aio` | Enable/disable AIO package installation; default off |
| `--install-kali-tools` / `--skip-kali-tools` | Enable/disable native Kali metapackage; default off |
| `--kali-meta=PKG` | Select and enable a `kali-*` metapackage on native Kali |
| `--install-wifi-dkms` / `--skip-wifi-dkms` | Enable/disable driver package; default off; confirm chipset and matching headers first |
| `--hostname=NAME` | Optional hostname change |
| `--phase=PHASE` | Run one phase; do not advance completion state |
| `--dry-run` | Print planned operations without logs, backups or state writes |
| `--yes` | Accept the initial confirmation; does not bypass safety checks |
| `--status` | Read completion state |
| `--reset` | Archive state markers; does not undo package/configuration changes |

Supported environment options: `INSTALL_AIO`, `INSTALL_KALI_TOOLS`, `INSTALL_WIFI_DKMS`, `KALI_METAPACKAGE`,
`HOSTNAME_NEW`, `DRY_RUN`, `ASSUME_YES`. Boolean values must be `yes` or `no`; `sudo` may filter environment
variables, so CLI flags are preferred.

## 🧭 Existing Installations

v1.4 refuses automatic continuation of legacy setup state. Diagnose and recover the affected system first.
`--reset` is not a rollback. Active Kali sources on Debian are rejected even for resumed/forced operations.
Removing sources does not downgrade already installed packages.

The new installer runs selected operations in one invocation rather than automatically resuming across three
reboots. Reboot manually when appropriate after optional package installations; test login, orientation, panel and
input before adding more software.

## ✅ Verification

From the repository root:

```bash
bash -n uConsole/scripts/uconsole-cm5-setup.sh
python3 -m unittest discover -s uConsole/tests -v
```

Regression tests use isolated fixtures; they do not install packages or exercise physical hardware. Follow the
[device validation checklist](../CM5-DISPLAY-RECOVERY.md#-device-validation) before release.

---

[🏠 uConsole](../README.md) · [📘 CM5 guide](../CM5-SETUP.md) · [🖥️ Display recovery](../CM5-DISPLAY-RECOVERY.md)
