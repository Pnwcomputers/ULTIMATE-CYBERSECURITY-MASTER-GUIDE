# uConsole Automated Setup Scripts

`uconsole-cm4-setup.sh` — Automates the post-flash setup described in [CM4-SETUP.md](../CM4-SETUP.md).
`uconsole-cm5-setup.sh` — Automates the post-flash setup described in [CM5-SETUP.md](../CM5-SETUP.md).

## What They Do

Mirror the manual guides as a phase-aware script with state tracking. Each phase advances a marker file in `/var/lib/uconsole-setup/cm4-state`, so the script can be stopped (or hit a reboot point) and resumed cleanly on the next run.

| Phase | What runs | Reboot after? |
|---|---|---|
| **preflight** | cryptsetup-initramfs hook, LightDM session pinning, `raspberrypi-sys-mods` removal (Trixie), Kali repo + pin (Trixie) | No |
| **update** | First `apt full-upgrade`, hostname set | **Yes** |
| **kali_tools** | Install chosen Kali metapackage (Trixie only) | No |
| **aio** | Install `aiov2_ctl` from git, install `hackergadgets-uconsole-aio-board` + `meshtastic-mui` | **Yes** |
| **peripherals** | config.txt overlays, cmdline.txt console removal, dialout group, DVB-T blacklist, devterm-printer disable, RTL8812AU DKMS, boot rails | **Yes** |
| **finalize** | Verification checks + handoff list of remaining manual steps | No |

## ⚠️ Run This BEFORE Updating

The whole reason this script exists is to pre-empt the breakage that happens when `apt full-upgrade` is run on a fresh Rex image without first hardening LightDM and disabling the cryptsetup-initramfs hook. **Run the script as your first action after the first boot**, not after running `apt update`.

If you've already upgraded and hit the "Failed to start session" screen, see CM4-SETUP.md → Troubleshooting → "Failed to start session" for the recovery procedure, then run this script with `--reset` to start over.

## Quick Start

```bash
# Flash Rex's Kali or Trixie image and boot the uConsole (let it auto-expand + reboot once)
# Log in, open a terminal

# Download the script (raw GitHub URL once you've committed it)
wget https://raw.githubusercontent.com/Pnwcomputers/ULTIMATE-CYBERSECURITY-MASTER-GUIDE/main/uConsole/scripts/uconsole-cm4-setup.sh
chmod +x uconsole-cm4-setup.sh

# Run it — script tells you when to reboot
sudo ./uconsole-cm4-setup.sh

# After each prompted reboot, re-run the same command — it auto-resumes
sudo reboot
# (back from reboot)
sudo ./uconsole-cm4-setup.sh
```

You'll go through three reboots total. The whole process is ~30–45 minutes wall time, mostly waiting on apt.

## Common Flags

```bash
# Skip confirmations (useful for headless / scripted runs)
sudo ./uconsole-cm4-setup.sh --yes

# Choose a bigger Kali toolkit
sudo ./uconsole-cm4-setup.sh --kali-meta=kali-linux-default

# Skip the WiFi DKMS install (no external adapter)
sudo ./uconsole-cm4-setup.sh --skip-wifi-dkms

# Re-run only one phase (state file NOT advanced)
sudo ./uconsole-cm4-setup.sh --phase=peripherals

# See what would happen without making changes
sudo ./uconsole-cm4-setup.sh --dry-run

# Wipe state and start over
sudo ./uconsole-cm4-setup.sh --reset

# Check current progress
sudo ./uconsole-cm4-setup.sh --status
```

## Environment Variables

You can also set these instead of (or alongside) flags:

| Variable | Default | Purpose |
|---|---|---|
| `HOSTNAME_NEW` | `uconsole` | New hostname |
| `KALI_METAPACKAGE` | `kali-tools-top10` | Which Kali metapackage to install |
| `INSTALL_WIFI_DKMS` | `yes` | `no` to skip RTL8812AU DKMS |
| `INSTALL_KALI_TOOLS` | `yes` | `no` to skip Kali tools entirely (Trixie) |
| `ASSUME_YES` | `no` | `yes` to skip all confirmations |
| `DRY_RUN` | `no` | `yes` for dry-run mode |

## What the Script Will NOT Do for You

A few things are deliberately left manual:

- **`passwd`** — security-critical, you choose the password
- **`dpkg-reconfigure tzdata`** — interactive timezone picker
- **Antenna connections** — physical
- **Meshtastic first-time region/channel setup** — region-specific, done via web UI (`https://localhost`)
- **NVMe Battery Board** — hardware mod with ribbon cable orientation that needs eyes-on. See CM4-SETUP.md Step 14.

The script prints all of these as a checklist when Phase 6 (finalize) runs.

## Files the Script Touches

| Path | Purpose |
|---|---|
| `/etc/cryptsetup-initramfs/conf-hook` | Disables initramfs hook |
| `/etc/lightdm/lightdm.conf` | Repoints sessions to labwc + lightdm-gtk-greeter |
| `/var/lib/AccountsService/users/*` | Fixes per-user session pointers |
| `/etc/apt/sources.list.d/kali.list` | (Trixie) Adds Kali repo |
| `/etc/apt/trusted.gpg.d/kali-archive-keyring.gpg` | (Trixie) Kali signing key |
| `/etc/apt/preferences.d/kali-pin` | (Trixie) Pins Kali as primary |
| `/etc/apt/apt.conf.d/99-force-overwrite` | Persistent dpkg force-overwrite |
| `/boot/firmware/config.txt` | Appends AIO v2 overlay block |
| `/boot/firmware/cmdline.txt` | Removes `console=serial0,115200` (backup kept) |
| `/etc/modprobe.d/blacklist-rtl.conf` | DVB-T driver blacklist |
| `/opt/aiov2_ctl/` | Git checkout of aiov2_ctl |
| `/var/lib/uconsole-setup/cm4-state` | Phase tracking |
| `/var/log/uconsole-setup.log` | Full log of every run |

`cmdline.txt` gets backed up with a timestamp suffix before modification.

## If Something Goes Wrong

1. **Check the log** — `/var/log/uconsole-setup.log` has every command and its output.
2. **`--status`** tells you which phase you're stuck at.
3. **Single-phase retry** — `sudo ./uconsole-cm4-setup.sh --phase=<phase>` re-runs one phase without advancing state.
4. **Full reset** — `sudo ./uconsole-cm4-setup.sh --reset` wipes the state file so the next run starts from preflight. (Idempotent operations will skip what's already done; non-idempotent ones may error harmlessly.)
5. **Worst case** — manually follow the corresponding section of [CM4-SETUP.md](../CM4-SETUP.md). The script is intentionally a 1:1 translation of the guide so the same fixes apply.

## Compatibility

- **Rex's Kali 6.12.y** — fully supported, skips the Trixie-specific raspberrypi-sys-mods / Kali repo steps
- **Rex's Trixie 6.12.y** — fully supported, full path including Kali tools layered on top
- **Rex's Bookworm 6.12.y** — should work (similar to Kali path) but not extensively tested
- **DragonOS** — not officially supported; you can run with `--phase=peripherals` only if you just want the config.txt setup

## License & Provenance

Authored as a companion to the [ULTIMATE-CYBERSECURITY-MASTER-GUIDE](https://github.com/Pnwcomputers/ULTIMATE-CYBERSECURITY-MASTER-GUIDE) uConsole documentation.

Hardware specs and package commands sourced and verified against:
- [Rex's HackerGadgets AIO Board Package thread](https://forum.clockworkpi.com/t/hackergadgets-aio-board-package/17875)
- [Rex's Trixie image thread](https://forum.clockworkpi.com/t/trixie-6-12-y-for-the-uconsole-and-devterm/19457)
- [Rex's Kali image thread](https://forum.clockworkpi.com/t/kali-6-12-y-for-the-uconsole-and-devterm/14463)
- [HackerGadgets AIO V1/V2 Setup Guide](https://hackergadgets.com/pages/hackergadgets-uconsole-rtl-sdr-lora-gps-rtc-usb-hub-all-in-one-extension-board-setup-guide)
- [aiov2_ctl README](https://github.com/hackergadgets/aiov2_ctl)
