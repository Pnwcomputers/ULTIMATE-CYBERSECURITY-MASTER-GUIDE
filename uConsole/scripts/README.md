# 🛠️ uConsole Setup Scripts

## 🎯 Purpose

Post-flash setup and recovery references for ClockworkPi uConsole systems. Choose the script for your compute module and read its current limitations before running it.

> [!IMPORTANT]
> **CM5 rotation/blank desktop reports:** Use [CM5 display recovery](../CM5-DISPLAY-RECOVERY.md) before rerunning an old installer. The current CM5 v1.4 workflow avoids the risky cross-distribution and desktop changes by default. Hardware validation is pending. The legacy CM4 v1.x installer was replaced by a conservative **CM4 v2.0** script; old backup copies of v1.x must not be run. See [safety review](../CM4-SAFETY-REVIEW.md).

## 📂 Scripts

| Script | Scope |
|---|---|
| [uconsole-cm5-parrot-setup.sh](./uconsole-cm5-parrot-setup.sh) | Experimental Parrot CM5 post-flash setup; requires existing Parrot. [Usage and limits](../PARROT-CM5.md) |
| [uconsole-cm5-setup.sh](./uconsole-cm5-setup.sh) | Conservative CM5 setup, proposed v1.4; preserves the image's desktop and boot configuration |
| [uconsole-cm4-setup.sh](./uconsole-cm4-setup.sh) | **CM4 v2.0** read-only preflight by default; optional AIO package on Debian or toolkit on native Kali, with configuration backup and APT simulation |
| [uconsole-repair.sh](./uconsole-repair.sh) | CM4/CM5 boot-overlay and historical desktop diagnosis **read-only by default**; explicit `--apply` required for changes, not a general desktop recovery tool |

## ⚙️ CM5 V1.4 Behavior

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

## 🚀 CM4 V2.0 Usage

> [!CAUTION]
> Earlier CM4 v1.x automation mixed Kali and Debian repositories, forced package overwrites and executed unchecked remote installers. **Do not run the old v1.x script.** The version below doesn't perform desktop, EEPROM, NVMe or GPIO changes, nor does it guarantee AIO hardware works on every image.

~~~bash
# From repository root; read-only checks
bash uConsole/scripts/uconsole-cm4-setup.sh --help
bash uConsole/scripts/uconsole-cm4-setup.sh --status

# Optional dry-run: verifies hardware, OS and repository family
bash uConsole/scripts/uconsole-cm4-setup.sh --with-aio --dry-run

# If, and only if, the AIO v2 board is fitted to a supported Debian/RPi OS:
sudo bash uConsole/scripts/uconsole-cm4-setup.sh --with-aio

# On native Kali only (not on Debian Trixie):
sudo bash uConsole/scripts/uconsole-cm4-setup.sh --kali-tools

# Separate configuration-only backup, not a substitute for disk imaging
sudo bash uConsole/scripts/uconsole-cm4-setup.sh --snapshot
~~~

The installer refuses hardware other than CM4 and Debian systems containing Kali sources. It requires confirmation for writes, snapshots selected configuration, simulates APT and refuses planned removals. It does not install `aiov2_ctl` from a moving Git branch or write `config.txt`. Follow [CM4 manual hardware steps](../CM4-SETUP.md), [review notes](../CM4-SAFETY-REVIEW.md) and current [HackerGadgets instructions](https://github.com/hackergadgets/aiov2_ctl) after verifying hardware/image compatibility.

## 🚀 CM5 V1.4 Usage

Inspect the currently checked-out CM5 script and confirm `--help` reports v1.4. Do not use an older v1.3 script from a stale local copy.

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

## 🩺 CM4/CM5 Repair Tool: Diagnose First

~~~bash
# Read-only by default; must currently be run as root for full diagnosis
sudo bash uConsole/scripts/uconsole-repair.sh
sudo bash uConsole/scripts/uconsole-repair.sh --diagnose

# Only after reviewing exact diagnosis, backups and restore plan:
sudo bash uConsole/scripts/uconsole-repair.sh --apply
~~~

`--yes` alone **does not permit writes**. With `--apply`, the repair script can still modify boot overlays, APT preferences and desktop state, so it is **not** a safe substitute for restoring a known-good image or the [CM5 display recovery procedure](../CM5-DISPLAY-RECOVERY.md). Do not use it as an automatic fix for an unexplained display problem.

## ✅ Verification

From the repository root:

```bash
bash -n uConsole/scripts/uconsole-cm4-setup.sh
bash -n uConsole/scripts/uconsole-repair.sh
bash -n uConsole/scripts/uconsole-cm5-setup.sh
python3 -m unittest discover -s uConsole/tests -v
```

Regression tests use isolated fixtures; they do not install packages or exercise physical hardware. Follow the
[device validation checklist](../CM5-DISPLAY-RECOVERY.md#-device-validation) before release.

---

[🏠 uConsole](../README.md) · [📘 CM5 guide](../CM5-SETUP.md) · [🖥️ Display recovery](../CM5-DISPLAY-RECOVERY.md)
