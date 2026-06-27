# uConsole Automated Setup Scripts (CM4 and CM5)

Two parallel scripts that automate the post-flash setup described in [CM4-SETUP.md](../CM4-SETUP.md) and [CM5-SETUP.md](../CM5-SETUP.md):

| Script | Target | State/Info |
|---|---|---|
| `uconsole-cm4-setup.sh` | Raspberry Pi CM4 | `/var/lib/uconsole-setup/cm4-state` |
| `uconsole-cm5-setup.sh` | Raspberry Pi CM5 | `/var/lib/uconsole-setup/cm5-state` |
| `uconsole-repair.sh` | Raspberry Pi CM4/CM5 | `Wrong script install repair` |

The `uconsole-cm4-setup.sh` and `uconsole-cm5-setup.sh` scripts provide a fully automated, state-tracked installation process. They handle the complex peripheral configuration and package dependencies required for Kali/Debian Trixie environments.

**Recent Script Improvements:**
* **Desktop Stability:** Automatically installs `rtkit` to resolve GDBus/RealtimeKit1 errors associated with `xdg-desktop-portal` under the Labwc compositor.
* **LoRa / Meshtastic Recovery:** Bypasses Debian Trixie dependency drift by automatically fetching `libgpiod2` and `libyaml-cpp0.7` from the Bookworm archives, ensuring `meshtasticd` and `meshtastic-mui` install cleanly without user intervention.
* **ADS-B Hardware Sequencing:** Dynamically powers the SDR hardware rail during execution to allow the `readsb` decoder to bind to the RTL-SDR before initializing the `tar1090` frontend map.
* **Pathing Fixes:** Resolves root `$PATH` dropouts for `aiov2_ctl` via direct binary symlinking.

## What They Do

Mirrors the manual guide as a phase-aware script with state tracking. Each phase advances a marker file in `/var/lib/uconsole-setup/cm4-state`, so the script can be stopped (or hit a reboot point) and resumed cleanly on the next run.

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


## `uconsole-repair.sh` — Fix a Wrong-CM Run

If someone clicks through the "Hardware doesn't appear to be a CMx" warning and runs the wrong setup script for their hardware, the wrong device-tree overlays get written into `/boot/firmware/config.txt`. GPS and RTC won't work, but the failure mode isn't obvious — they'll just see no NMEA sentences and `hwclock -r` returning nothing.

`uconsole-repair.sh` detects and fixes this:

```bash
# Diagnose only (no changes, no prompt)
sudo ./uconsole-repair.sh --diagnose

# Show what would change without writing
sudo ./uconsole-repair.sh --dry-run

# Interactive repair (default)
sudo ./uconsole-repair.sh

# Unattended repair
sudo ./uconsole-repair.sh --yes
```

### What it detects and repairs

| Symptom | Action |
|---|---|
| CM4 hardware but `dtparam=uart0` in config.txt | Removes it, adds `enable_uart=1` |
| CM5 hardware but `enable_uart=1` in config.txt | Removes it, adds `dtparam=uart0` |
| CM4 hardware but CM5-style RTC overlay (with `i2c_csi_dsi0`) | Reverts to plain CM4 form |
| CM5 hardware but CM4-style RTC overlay (no remap) | Swaps in the `i2c_csi_dsi0` remap |
| CM5 hardware missing `dtparam=rtc=off` | Adds it (CM5 internal RTC must be disabled) |
| Wrong-platform "AIO v2 Board Configuration" marker line | Removes it, adds the correct one |
| Stale state file (e.g. `cm4-state` on CM5 hardware) | Removes the stale state file |

### Safety guarantees

- **Always backs up** `config.txt` to `config.txt.bak.repair.<timestamp>` before any modification
- **Idempotent** — running it twice on a healthy config is a no-op
- **Only touches known overlay lines** — manually-added lines elsewhere in `config.txt` are not affected
- **Doesn't touch** `cmdline.txt`, the dialout group, the DVB-T blacklist, the devterm-printer service, DKMS, or anything else that's the same on both CMs
- **Fails closed** — if hardware can't be detected from `/proc/device-tree/model`, refuses to make changes

### When to run it

- After realizing you ran the wrong setup script
- Any time GPS or RTC stop working after a reflash with a different CM module
- Diagnostically — `--diagnose` is read-only and a fast way to confirm `config.txt` matches the hardware


## CM5 vs CM4 Differences (what's in `uconsole-cm5-setup.sh` and not in `uconsole-cm4-setup.sh`)

| Item | CM4 script | CM5 script | Why |
|---|---|---|---|
| GPS serial path | `/dev/ttyS0` | `/dev/ttyAMA0` | Different UART exposed by RPi firmware |
| GPS UART config | `enable_uart=1` | `dtparam=uart0` | CM5 uses the newer dtparam syntax |
| LoRa SPI overlay | `dtparam=spi=on` + `dtoverlay=spi1-1cs` | just `dtoverlay=spi1-1cs` | CM5 SPI is enabled differently |
| RTC overlay | `dtoverlay=i2c-rtc,pcf85063a` | `dtparam=rtc=off` + `dtoverlay=i2c-rtc,pcf85063a,i2c_csi_dsi0` | CM5 has an internal RTC that must be disabled, and i2c0 must be remapped to GPIO38/39 |
| SDR rail at boot | Defaults OFF | Defaults ON | Firmware-level GPIO 7 default |
| NVMe EEPROM | May need update (older CM4s) | Native PCIe, no update normally needed | CM5 architecture |
| SD boot quirks | Generally none | CM5 lite needs specific EEPROM settings if SD won't boot | Per Rex's Trixie thread |

Everything else — pre-flight hardening (cryptsetup, LightDM, raspberrypi-sys-mods, Kali repo+pin), Kali tools install, aiov2_ctl install, AIO board package install, dialout group, DVB-T blacklist, devterm-printer disable, RTL8812AU DKMS, boot rails, verification checks — is identical between the two scripts.

## License & Provenance

Authored as a companion to the [ULTIMATE-CYBERSECURITY-MASTER-GUIDE](https://github.com/Pnwcomputers/ULTIMATE-CYBERSECURITY-MASTER-GUIDE) uConsole documentation.

Hardware specs and package commands sourced and verified against:
- [Rex's HackerGadgets AIO Board Package thread](https://forum.clockworkpi.com/t/hackergadgets-aio-board-package/17875)
- [Rex's Trixie image thread](https://forum.clockworkpi.com/t/trixie-6-12-y-for-the-uconsole-and-devterm/19457)
- [Rex's Kali image thread](https://forum.clockworkpi.com/t/kali-6-12-y-for-the-uconsole-and-devterm/14463)
- [HackerGadgets AIO V1/V2 Setup Guide](https://hackergadgets.com/pages/hackergadgets-uconsole-rtl-sdr-lora-gps-rtc-usb-hub-all-in-one-extension-board-setup-guide)
- [aiov2_ctl README](https://github.com/hackergadgets/aiov2_ctl)
