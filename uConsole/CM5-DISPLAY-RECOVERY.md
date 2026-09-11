# 🖥️ uConsole CM5: Rotated Screen & Blank Desktop Recovery

<div align="center">

**Diagnose display orientation, desktop sessions, and package changes after setup**

*Part of the [ULTIMATE CYBERSECURITY MASTER GUIDE](../README.md)*

![CM5](https://img.shields.io/badge/Hardware-CM5-blue?style=for-the-badge)
![Recovery](https://img.shields.io/badge/Focus-Desktop_Recovery-orange?style=for-the-badge)
![Validation](https://img.shields.io/badge/Hardware_Testing-Pending-yellow?style=for-the-badge)

</div>

---

## 🎯 Purpose

Help recover a Rex CM5 image that displayed correctly before running `uconsole-cm5-setup.sh`, but now has a rotated
screen or a blank desktop with a mouse pointer. This guide distinguishes confirmed script behavior from possible
causes on an affected device.

## ⚙️ Function

Collect evidence, identify the actual graphical session, compare configuration and package changes, and choose a
targeted recovery path. The revised v1.4 script prevents several risky actions; it does **not** undo an earlier
installation.

## 🏆 Goal

Restore the image's intended desktop and display configuration without guessing connector names, replacing the desktop with a bare compositor, or blindly changing package versions.

## 📋 When to Use

- The screen worked before setup and changed afterward.
- Login succeeds but only the pointer is visible.
- An Xorg rotation workaround improves orientation but does not restore the desktop.
- A system without an AIO board received AIO configuration.

---

## 📋 Table of Contents

- [Findings](#-findings)
- [Collect evidence](#-collect-evidence)
- [Recovery decisions](#-recovery-decisions)
- [Revised installer](#-revised-installer)
- [Device validation](#-device-validation)
- [Reply for affected users](#-reply-for-affected-users)
- [Sources](#-sources)

## 🔎 Findings

The audit reviewed the [v1.3 script at commit
77bff3c](https://github.com/Pnwcomputers/ULTIMATE-CYBERSECURITY-MASTER-GUIDE/blob/77bff3c126a7e4fbbf6a7cd3653f9956782e4c4d/uConsole/scripts/uconsole-cm5-setup.sh).
The exact script version each reporter executed is not yet confirmed.

| Confirmed code behavior | Why it matters |
|---|---|
| If particular session files are absent, preflight can replace `rpd-labwc` with plain `labwc` in LightDM and AccountsService. | Plain Labwc is a compositor, not a complete desktop. A blank screen can be expected without the image's desktop startup configuration. This is a plausible explanation for a cursor without panels. |
| On Debian, preflight adds Kali rolling, even with `--skip-kali-tools`; the next phase performs a forced-overwrite full upgrade. | This can change packages before the optional toolkit phase. The selected-tool pins do not exclude all other Kali packages. |
| The script removes `raspberrypi-sys-mods` if its removal preview passes a partial name check. | Desktop dependencies can be missed. The simulated command also hides errors. A successful preview is not proof that a desktop will survive. |
| AIO installation and UART/SPI/RTC boot changes are unconditional. | The second reported system has no AIO board. These changes are unnecessary there, and boot/display interactions need investigation. |
| The script creates a `pcmanfm-pi` symlink and suppresses a Polkit agent based on assumptions. | Neither action establishes that the expected desktop components or a replacement authentication agent are working. |
| Several command failures do not stop the enclosing phase. | A completed state marker is not evidence that all installations succeeded. |

Labwc documents its blank initial appearance and separate desktop components in its [getting-started
guide](https://labwc.github.io/getting-started.html). Debian documents default package priorities in
[apt_preferences(5)](https://manpages.debian.org/trixie/apt/apt_preferences.5.en.html); unlisted packages are not
automatically denied by another package's pin. Kali explicitly warns against adding its repositories to another
operating system in its [repository documentation](https://www.kali.org/docs/general-use/kali-apt-sources/).

**Still unconfirmed:** which branch ran on each machine, whether packages were replaced/removed, which graphical session is running, and what changed the rotation. The script does not directly write an Xorg rotation rule. Kernel, package, boot configuration, and session changes remain candidates; the reports do not establish a defective CM5, adapter, or kernel.

**Version correction:** Trixie is **Debian 13**. Verify the reported “Debian 14 Trixie” using `/etc/os-release`. Record the actual kernel using `uname -r`; do not infer it from an older image-thread title. [Debian release information](https://www.debian.org/releases/trixie/)

## 🧾 Collect evidence

Stop rerunning v1.3 and avoid further upgrades while diagnosing. Connect through an already configured SSH
connection or switch to a text console with `Ctrl+Alt+F3` (an external keyboard may help). If neither works, shut
down safely and inspect the storage from another Linux system. For eMMC, follow the module/vendor's access
procedure.

Run the following as the **affected desktop user**, using `sudo` only where shown. These commands inspect state;
they do not install packages, rotate the display, or restart services. Some files or services may be absent.

```bash
cat /etc/os-release
uname -a
tr -d '\0' < /proc/device-tree/model
printf '\n'
lsusb
loginctl list-sessions
systemctl status display-manager --no-pager -l
sudo lightdm --show-config

# Installed session names and launch commands
find /usr/share/wayland-sessions /usr/share/xsessions \
  -maxdepth 1 -type f -name '*.desktop' -print \
  -exec grep -E '^(Name|Exec|TryExec)=' {} \;

# Configured/default and remembered session choices
sudo grep -RnsE '^[[:space:]]*(user-session|autologin-session|greeter-session|XSession|Session)=' \
  /etc/lightdm /var/lib/AccountsService/users
cat "$HOME/.dmrc" 2>/dev/null

# Current boot settings and attached display connectors
cat /boot/firmware/config.txt
cat /boot/firmware/cmdline.txt
for connector in /sys/class/drm/card*-*/status; do
  [ -f "$connector" ] || continue
  printf '%s: ' "$connector"
  cat "$connector"
done

# Relevant package versions/candidates and incomplete package operations
sudo dpkg --audit
apt-cache policy labwc lightdm clockworkpi-theme raspberrypi-ui-mods \
  raspberrypi-sys-mods rpd-wayland-core wf-panel-pi pcmanfm libfm-modules

# Package history and setup log: compare with the time the issue started
sudo tail -n 200 /var/log/uconsole-setup.log
sudo zcat -f /var/log/apt/history.log* | tail -n 250
sudo journalctl -b -u lightdm --no-pager -n 150
journalctl --user -b --no-pager -n 150
```

Use `loginctl list-sessions` to identify the **local graphical session**, then replace `SESSION_ID` below with its ID:

```bash
loginctl show-session SESSION_ID -p Name -p Type -p Desktop -p Service -p State
```

An SSH shell's `$XDG_SESSION_TYPE`, `$DISPLAY`, or `$WAYLAND_DISPLAY` is not a reliable description of the local
desktop. User-journal output may be unavailable on some installations; also inspect `/var/log/lightdm/` and
`~/.xsession-errors` if present.

Review logs before sharing: redact usernames, IP addresses, Wi-Fi details, credentials in repository URLs, and
unrelated private data. Share relevant error lines and package transactions, not an unreviewed full system dump.

## 🛠️ Recovery decisions

### 1. Save the current state before changing it

Make a full storage backup if practical, especially before package recovery. A configuration copy alone cannot roll back a package upgrade.

For a small configuration snapshot, run:

```bash
sudo bash <<'BACKUP'
set -e
backup_dir=$(mktemp -d /root/uconsole-display-backup.XXXXXXXX)
chmod 700 "$backup_dir"
for item in /etc/lightdm /etc/X11 /etc/xdg /etc/apt \
  /var/lib/AccountsService/users /boot/firmware/config.txt \
  /boot/firmware/cmdline.txt /var/lib/uconsole-setup; do
  [ ! -e "$item" ] || cp -a --parents "$item" "$backup_dir/"
done
dpkg-query -W > "$backup_dir/packages.tsv"
printf 'Saved configuration to %s\n' "$backup_dir"
BACKUP
```

Also back up the affected user's `~/.config` and `~/.dmrc` if present. Newly created backups describe the broken
state; only a **pre-setup** backup can directly restore the previous configuration. Old script versions did not
consistently save those files.

### 2. Separate session failure from rotation

For a blank screen with a cursor, compare the selected session with the session on the original, matching Rex
image. Check its `.desktop` file and the `Exec=` program. In Labwc, inspect the image's session wrapper and its
system/user autostart files for missing panels, desktop processes, or errors.

If the original desktop session is still installed, select it from the login screen's session menu. If autologin
bypasses the menu, compare and correct the relevant LightDM setting using `sudo lightdm --show-config` to find the
effective file. AccountsService and a user's remembered session may also affect selection. Restore only a session
known to exist and belong to that image. Do not globally replace session names with `labwc`. [LightDM configuration
reference](https://github.com/ubuntu/lightdm/blob/main/data/lightdm.conf)

A file named `90-uconsole-display.conf` under `/etc/X11/xorg.conf.d/` configures **Xorg**. It does not configure a
native Wayland compositor's output. The login greeter and desktop may use different display servers. [Xorg
configuration manual](https://manpages.debian.org/trixie/xserver-xorg-core/xorg.conf.5.en.html)

If you created that file only as an unsuccessful workaround, back it up and move it outside `xorg.conf.d` before
comparing with the original image. Do not move a vendor-provided file merely because its name matches the report.
Configuration quotes must be ordinary ASCII `"`, not typographic `“` and `”`.

For an actual X11 session, `xrandr --query` **inside that graphical session** identifies outputs. For native
Wayland, use the image's compositor/display settings; `wlr-randr` can inspect compatible wlroots outputs when
already installed and run in that session. Neither `DSI-1` nor `DSI-2`, nor one rotation direction, is universal.
First restore the intended session, then configure orientation in the layer that controls it. [wlr-randr
upstream](https://gitlab.freedesktop.org/emersion/wlr-randr)

### 3. Check for cross-distribution package changes

On **Debian**, inspect APT source files and the relevant upgrade transaction. Version strings and `apt-cache
policy` help, but do not reconstruct all historical origins on their own.

The old script created these files when applicable:

- `/etc/apt/sources.list.d/kali.list`
- `/etc/apt/preferences.d/kali-pin`
- `/etc/apt/preferences.d/uconsole-keep-pi-libs`
- `/etc/apt/apt.conf.d/99-force-overwrite`

After backing them up and confirming they came from this setup, disable the added Kali source and remove the
script's pin/forced-overwrite overrides from active APT configuration. A migrated setup may use a `.sources` file:
review its stanzas and use `Enabled: no` for the Kali stanza. Preserve the image's correct Debian, Raspberry Pi,
and Rex sources. **Do not disable Kali sources on a native Kali installation.**

Once sources have been reviewed, `sudo apt-get update` refreshes package indexes. It does **not** restore replaced
packages. Do not run a blanket downgrade, `full-upgrade`, `--force-overwrite`, or `apt --fix-broken install -y` as
an assumed desktop repair. Review the proposed package transaction using `apt-get -s` and use versions appropriate
to the exact image. Missing desktop components and ABI errors require a coherent package set, not just a renamed
binary or a `+rpt` substring check.

If many core packages changed or no reliable original versions/configuration are available, backing up personal
data and restoring a known-good Rex image is a more predictable recovery path. Confirm the desktop works before
installing anything else. Keep the affected storage copy/logs for diagnosis. Do not run v1.3 again after reimaging.

### 4. Review boot changes separately

For a CM5 without the AIO board, compare `config.txt` and `cmdline.txt` with a pre-setup backup or the **same image
release**. The old script added an “AIO v2 Board Configuration (CM5)” block and could remove
`console=serial0,115200` from the command line.

Restore only changes attributable to the unwanted setup. Keep image-specific display overlays and any required
CM5/adapter configuration. Do not copy a generic Raspberry Pi `config.txt` or delete every SPI/I²C/UART line.

For fitted AIO boards, check the current [Rex AIO package
thread](https://forum.clockworkpi.com/t/hackergadgets-aio-board-package/17875) and [HackerGadgets setup
guide](https://hackergadgets.com/pages/hackergadgets-uconsole-rtl-sdr-lora-gps-rtc-usb-hub-all-in-one-extension-board-setup-guide).
Hardware configuration is image/board dependent. The reports do not prove which overlay, if any, caused rotation.

Reboot only after saving work and reviewing changes. Restarting a display manager terminates graphical sessions; it is not required merely to collect diagnostics.

## 🔧 Revised installer

The proposed [v1.4 setup script](./scripts/uconsole-cm5-setup.sh) deliberately reduces automated changes:

- Preserves existing desktop/session, rotation, boot overlays, Polkit agents and cryptsetup settings.
- Does not add repositories, remove `raspberrypi-sys-mods`, disable Python protections, perform full upgrades, or inject older libraries.
- Rejects active Kali sources on Debian and refuses automatic continuation of legacy setup state.
- Makes the AIO package, Kali metapackages and Wi-Fi DKMS package opt-in; Kali tools are allowed only on native Kali.
- Stops on package-command failure. Uses `--no-remove`, which does **not** prevent dependency upgrades or package-maintainer script changes.
- Saves root-only configuration/package snapshots before setup operations. Does not treat those as full image backups.
- Makes dry runs read-only and records completion only after successful selected operations. `--phase` does not advance state.

Default execution primarily inventories/backs up the system. The `update` phase intentionally skips system
upgrades. Automatic upstream `aiov2_ctl` source installation, Meshtastic/ADS-B bootstrap downloads, rail
programming and direct boot edits have been removed; follow the vendor's current instructions for those optional
features. The revised script is **not feature-equivalent to v1.3**.

Review/download the candidate before running it. A command downloading from `main` will still retrieve the old
version until the change is merged. Verify `bash ./uconsole-cm5-setup.sh --help` reports v1.4.

```bash
# Preview; no configuration, log, or state writes
sudo bash ./uconsole-cm5-setup.sh --dry-run

# Preserve the desktop and save configuration; no optional packages
sudo bash ./uconsole-cm5-setup.sh

# Only if the AIO board is installed; review the candidate on spare media first
sudo bash ./uconsole-cm5-setup.sh --with-aio
```

`--reset` only archives state markers. It does not repair packages or undo changes. Resolve a legacy installation
before using it. The revised script runs selected operations in one invocation and does not automatically resume
v1.3 phases across reboots.

“AC1200” is a Wi-Fi speed class, not sufficient chipset identification. Use the USB vendor/product ID and driver
information before enabling `--install-wifi-dkms`; check that headers match `uname -r`. No Wi-Fi driver replacement
is needed to diagnose the desktop.

## ✅ Device validation

Software checks cover shell syntax and isolated regressions for defaults, mixed-source rejection, release
detection, command failures, state handling and dry-run behavior. They do **not** validate CM5 graphics or package
behavior on Rex images.

Before merging/recommending broadly, use spare media or a recoverable image backup:

1. Record image filename/date, `/etc/os-release`, `uname -r`, board configuration and graphical session.
2. Verify orientation, keyboard, trackball and desktop before setup.
3. Run the default candidate on a CM5 without AIO. Confirm desktop/boot configuration and package inventory are unchanged by the default path.
4. Reboot and test login, panel, terminal launch and orientation.
5. On a separate fitted-AIO system, inspect the package simulation, then test `--with-aio` and review package-maintainer changes.
6. Test native Kali tool installation separately; do not infer Debian or other image compatibility from it.

## 💬 Reply for affected users

> Thanks for the detailed reports. I found problems in my setup script that could explain this: it can replace the image's desktop session with plain Labwc, add Kali repositories to Debian before an upgrade, and configure AIO hardware even when the board is absent. A rotation-only workaround would not restore missing desktop components.
>
> Please stop rerunning the old script for now. If you can access SSH or a text console, please share the relevant output from `/etc/os-release`, `uname -r`, `loginctl list-sessions`, `sudo lightdm --show-config`, the installed session files, and the APT transaction around the setup run. Redact private details first. That will help distinguish a wrong session from package or boot-configuration changes.
>
> I have prepared a conservative revision and recovery instructions, but the exact cause on your machines and the revised setup still need device testing. Please keep your original image/storage backup. Also, Trixie is Debian 13; `/etc/os-release` will confirm the installed release.

## 📚 Sources

- [Audited script snapshot](https://github.com/Pnwcomputers/ULTIMATE-CYBERSECURITY-MASTER-GUIDE/blob/77bff3c126a7e4fbbf6a7cd3653f9956782e4c4d/uConsole/scripts/uconsole-cm5-setup.sh)
- [Labwc: getting started](https://labwc.github.io/getting-started.html)
- [Kali: repository guidance](https://www.kali.org/docs/general-use/kali-apt-sources/)
- [Debian: APT preferences](https://manpages.debian.org/trixie/apt/apt_preferences.5.en.html)
- [Debian: Trixie release](https://www.debian.org/releases/trixie/)
- [LightDM: configuration](https://github.com/ubuntu/lightdm/blob/main/data/lightdm.conf)
- [Xorg: configuration manual](https://manpages.debian.org/trixie/xserver-xorg-core/xorg.conf.5.en.html)
- [Rex: Trixie image thread](https://forum.clockworkpi.com/t/trixie-7-1-y-for-the-uconsole-and-devterm/19457)
- [Rex: AIO package thread](https://forum.clockworkpi.com/t/hackergadgets-aio-board-package/17875)
- [HackerGadgets: board setup](https://hackergadgets.com/pages/hackergadgets-uconsole-rtl-sdr-lora-gps-rtc-usb-hub-all-in-one-extension-board-setup-guide)

*Reviewed: 2026-09-11. Static analysis and isolated software tests; physical CM5 validation pending.*

---

[🏠 uConsole Guides](./README.md) · [📘 CM5 Setup](./CM5-SETUP.md) · [📂 Scripts](./scripts/README.md)
