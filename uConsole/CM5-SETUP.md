# uConsole Setup Guide: CM5 Configuration

## 🎯 Purpose
Complete setup guide for the ClockworkPi uConsole with Raspberry Pi CM5 module - the newer, faster CM5 variant
covering Rex's Kali/Trixie image, HackerGadgets AIO v2 board, and CM5-specific driver differences from the CM4
setup.

## ⚙️ Function
Post-flash configuration for CM5: WiFi adapter drivers (CM5-specific chipset differences), Bluetooth, audio,
display brightness, RTL-SDR, LoRa, GPS, NVMe storage, and the HackerGadgets AIO v2 board - with attention to CM5 vs
CM4 behavioral differences.

## 🏆 Goal
A fully working CM5-based uConsole with all HackerGadgets hardware functional, taking advantage of the CM5's
improved CPU/RAM performance for compute-heavy tasks like SDR processing and AI inference.

## 📋 When to Use
- Initial setup after flashing Rex's Kali or Trixie image to a CM5 module
- When upgrading from CM4 to CM5 and needing to account for driver differences
- Troubleshooting CM5-specific hardware issues (USB, PCIe, WiFi chipset variants)

## *Rex's Kali or Trixie + HackerGadgets AIO v2 Board + HackerGadgets Battery & NVMe Board*

A complete setup guide for building a field-deployable hacking and SIGINT platform using the ClockworkPi uConsole
with a Raspberry Pi CM5, Rex's community images (Kali Linux or Debian Trixie), and the HackerGadgets AIO v2
extension board.

> [!IMPORTANT]
> **CM5 desktop regression:** Earlier script revisions can disrupt the working Rex desktop. Start with [CM5 display recovery](./CM5-DISPLAY-RECOVERY.md) if you have a rotated screen or a blank desktop after login. The proposed v1.4 installer preserves session and boot configuration, skips upgrades, and makes AIO installation opt-in. Hardware validation is pending. See [script usage](./scripts/README.md).
> Do not layer Kali repositories onto Debian or replace the image's desktop with plain Labwc.

---

## Table of Contents

- [Hardware Overview](#hardware-overview)
- [Choosing Your OS: Kali vs Trixie](#choosing-your-os-kali-vs-trixie)
- [Step 1: Flash the OS](#step-1-flash-the-os)
- [Step 2: Preserve the Working Image](#step-2-first-boot---preserve-the-working-image)
- [Step 3: System Update and Initial Configuration](#step-3-system-update-and-initial-configuration)
- [Step 4: Distribution Security Tools](#step-4-security-tools-for-your-distribution)
- [Step 5: Install aiov2_ctl (GPIO Control Tool)](#step-5-install-aiov2_ctl-gpio-control-tool)
- [Step 6: Install the AIO v2 Board Package](#step-6-install-the-aio-v2-board-package)
- [Step 7: Configure GPS (CM5)](#step-7-configure-gps-cm5)
- [Step 8: Configure LoRa / Meshtastic](#step-8-configure-lora--meshtastic)
- [Step 9: Configure RTC (CM5)](#step-9-configure-rtc-cm5)
- [Step 10: Configure SDR](#step-10-configure-sdr)
- [Step 11: GPIO Power Control](#step-11-gpio-power-control)
- [Step 12: WiFi Pentesting Setup](#step-12-wifi-pentesting-setup)
- [Step 13: LAN Pentesting via RJ45](#step-13-lan-pentesting-via-rj45)
- [Step 14: NVMe Battery Board Setup](#step-14-nvme-battery-board-setup)
- [CM5-Specific Notes and Limitations](#cm5-specific-notes-and-limitations)
- [AIO v2 Board: Hardware Reference](#aio-v2-board-hardware-reference)
- [aiov2_ctl: Full Command Reference](#aiov2_ctl-full-command-reference)
- [Meshtastic Web Interface](#meshtastic-web-interface)
- [Boot Automation](#boot-automation)
- [Troubleshooting](#troubleshooting)
- [Resources and Links](#resources-and-links)

---

## 🎯 Purpose
Step-by-step build instructions for the CM5 variant of the uConsole + AIO v2 platform specifically - GPIO pin
behavior, `config.txt` overlays, and known failure modes here are CM5-specific (e.g., `/dev/ttyAMA0` instead of
`/dev/ttyS0`, `dtparam=uart0` instead of `enable_uart=1`, native PCIe NVMe support) and will not match the CM4. Use
this file (not [CM4-SETUP.md](./CM4-SETUP.md)) when your board is a Raspberry Pi Compute Module 5.

## ⚙️ Function
Organized as the same 14 sequential numbered steps as [CM4-SETUP.md](./CM4-SETUP.md) (flash OS → pre-flight
hardening → system update → Kali tools → `aiov2_ctl` install → AIO v2 board package → GPS/LoRa/RTC/SDR
configuration → GPIO power control → WiFi/LAN pentesting setup → NVMe battery board), followed by reference tables
and a Troubleshooting section. Differs from CM4-SETUP.md in GPIO/UART/RTC device-tree overlays, GPS serial port
path, SDR default boot state (HIGH on CM5 vs OFF on CM4), and native PCIe NVMe support; differs from
[README.md](./README.md), which is the folder-level index rather than a build walkthrough. Every step is also
implemented as an idempotent shell script in [`scripts/uconsole-cm5-setup.sh`](./scripts/uconsole-cm5-setup.sh)
(see [scripts/README.md](./scripts/README.md)).

## 🏆 Goal
A working CM5-based uConsole with the AIO v2 board fully configured - RTL-SDR, LoRa/Meshtastic, GPS, and RTC all
functioning, GPIO power control operational, and WiFi/LAN pentesting tooling installed - without the CM5-specific
pitfalls (SD boot failures on old EEPROM, UART/RTC overlay mismatches) this guide's troubleshooting section already
documents.

## 📋 When to Use
When building or repairing a CM5-based uConsole from scratch, or when a specific step (e.g., Meshtastic not
starting, GPS not getting a fix, CM5 lite SD card not booting) needs a manual fix outside of running the automation
script.

---

## Hardware Overview

This guide assumes the following hardware stack:

| Component | Detail |
|---|---|
| **Handheld** | ClockworkPi uConsole |
| **Compute Module** | Raspberry Pi CM5 (with HackerGadgets CM5 adapter board) |
| **Extension Board** | HackerGadgets AIO v2 (RTL-SDR / LoRa / GPS / RTC / USB Hub) |
| **OS** | Rex's Kali Linux or Rex's Debian Trixie (6.12.y kernel) |
| **WiFi Adapter** | External monitor-mode capable adapter (CM5 onboard WiFi does NOT support monitor mode) |

### What the AIO v2 Provides

| Feature | Chip / Spec |
|---|---|
| **RTL-SDR** | R828D + TCXO, 100 kHz–1.74 GHz, 5V bias tee for active antennas/LNAs |
| **LoRa** | SX1262, 860–960 MHz, 22 dBm max output, TCXO, Meshtastic-ready |
| **GPS** | Multi-mode (GPS/BDS/GNSS), active and passive antenna support |
| **RTC** | PCF85063A + CR1220 battery backup |
| **USB Hub** | External USB-C port + internal USB-C + pin header |
| **RJ45 Ethernet** | Gigabit (requires HackerGadgets adapter board from Upgrade Kit) |

> **Critical Assembly Note:** When installing the AIO v2 board, ensure the ribbon cable is oriented correctly as shown in the HackerGadgets documentation. **Never plug in the charger if the ribbon cable is installed the wrong way** - incorrect installation will damage the uConsole mainboard.

### AIO v2 GPIO Map (Verified Against HackerGadgets Official Docs)

These are the **AIO v2** control GPIOs. (AIO v1 used different pins for LoRa and Internal USB - make sure you're working with v2 hardware.)

| Peripheral | GPIO | Notes |
|---|---|---|
| **GPS** | 27 | Pull HIGH to enable |
| **LoRa** | 16 | Pull HIGH to enable |
| **SDR** (RTL-SDR) | 7 | Pull HIGH to enable. **On CM5, this defaults HIGH at boot** - RTL-SDR is detected immediately. On CM4, it defaults OFF. |
| **Internal USB** (USB-C + pin header) | 23 | Pull HIGH to enable |
| **GPS PPS** (output) | 6 | Optional, for microsecond-accurate NTP timing |

---

## Choosing Your OS: Kali vs Trixie

Rex maintains community images for the uConsole that include a custom kernel (record the actual version with `uname
-r`) with all necessary hardware patches for the uConsole display, keyboard, and trackball. His images also include
a custom APT repository required for the `hackergadgets-uconsole-aio-board` package - that package is not available
on stock ClockworkPi or upstream Kali images.

Rex's images include several conveniences that this guide relies on:

- Auto-expanding root filesystem on first boot (no `raspi-config` needed)
- `linux-headers` shipped with the kernel (no separate DKMS headers install)
- A dedicated "drivers" block at the bottom of `/boot/firmware/config.txt` with instructions for enabling overlays

> **CM5 special note from Rex:** The AIO board package was developed primarily for CM5 because enabling SPI for Meshtastic on CM5 needs additional plumbing to keep the display panel working. Using the official `hackergadgets-uconsole-aio-board` package is therefore strongly recommended on CM5 - the manual route is risky.

### Path A: Rex's Kali Image

Choose the native Kali image when you need Kali metapackages. Check which tools are included in that specific
release. Preserve its desktop/session configuration and review package upgrades before applying them.

### Path B: Rex's Trixie Image

Use Debian 13 Trixie with its intended Debian/Raspberry Pi/Rex repositories. Install tools available for that
distribution. For Kali-only workflows, use a separate Kali installation instead of adding Kali rolling to Debian.
The old tool allowlist did not prevent unrelated Kali packages from becoming upgrade candidates. [Kali repository
guidance](https://www.kali.org/docs/general-use/kali-apt-sources/)

### Other Rex Images

| Image | Best For |
|---|---|
| **Bookworm 6.12.y** | Maximum stability, daily driver, most community-tested |
| **DragonOS** | Dedicated SDR/RF analysis (now based on Debian Trixie) |

> **Tip:** Consider keeping Rex's DragonOS on a second SD card for dedicated SDR/RF analysis sessions. It ships with GNU Radio, SDR++, and a broader RF toolkit than the AIO board package alone.

---

## Step 1: Flash the OS

### Download Your Image

**Kali:**
- **Thread:** [Kali 6.12.y for the uConsole and DevTerm](https://forum.clockworkpi.com/t/kali-6-12-y-for-the-uconsole-and-devterm/14463)
- Look for the MEGA or Google Drive link in the first post
- Use the image labeled with kernel **6.12.67** or later (required for the new uConsole screens)
- Default credentials: `kali` / `kali`

**Trixie:**
- **Thread:** [Trixie 6.12.y for the uConsole and DevTerm](https://forum.clockworkpi.com/t/trixie-6-12-y-for-the-uconsole-and-devterm/19457)
- MEGA / Google Drive link in the first post
- Same kernel requirement (6.12.67+)
- Default credentials: `pi` / `clockworkpi`

### Flash the Image

Rex's specific guidance from the forum threads: **use Raspberry Pi Imager directly on the compressed `.xz` file,
and do not apply any custom settings.** Custom settings (hostname, WiFi, SSH) from Pi Imager will cause Rex's
images to fail to boot.

1. Install [Raspberry Pi Imager](https://www.raspberrypi.com/software/) on your host machine.
2. In Pi Imager:
   - **Operating System:** "Use Custom" → select the downloaded `.xz` file directly (do **not** decompress first)
   - **Storage:** your microSD card (16 GB minimum, 32+ GB recommended)
   - Click **Write**. When prompted about custom settings, choose **No** / **Skip**.
3. Insert the microSD card into the uConsole and boot.

> **Linux/`dd` alternative:** If you prefer the command line, decompress with `xz -d <image>.xz` first, then `sudo dd if=<image>.img of=/dev/sdX bs=4M status=progress conv=fsync`. Pi Imager is what Rex specifically recommends, though.

> **CM5 lite SD card boot issue:** If you have a CM5 lite and the SD card won't boot, you likely need an EEPROM update. See [Troubleshooting → CM5 lite SD boot fails](#troubleshooting) before getting frustrated - this is a known issue with a documented fix.

### First Boot

Power on. Rex's images auto-expand the root filesystem on first boot and then reboot once - let that complete. After the second boot:

- Log in with the default credentials
- Open a terminal

Record the working baseline and back up before package changes. Proceed to Step 2.

---

## Step 2: First Boot - Preserve the Working Image

Verify the desktop, panel, input and orientation before setup. Record `/etc/os-release`, `uname -r` and the image
release; back up storage and configuration. Preserve the supplied LightDM/AccountsService session choices,
cryptsetup configuration, Python protections and `raspberrypi-sys-mods`.

Do not switch to a generic Labwc session to preempt a hypothetical failure. If the desktop is already broken, use
[CM5 display recovery](./CM5-DISPLAY-RECOVERY.md) before installing more packages.

## Step 3: System Update and Initial Configuration

Review the image maintainer's current update guidance. After checking repository configuration, inspect a simulation before considering an upgrade:

```bash
sudo apt-get update
apt-get -s upgrade
```

These commands refresh indexes and simulate changes; they do not perform a system upgrade. Check proposed changes
to the kernel, firmware, compositor, display manager and desktop packages. No pin file or forced-overwrite setting
makes every upgrade safe. The v1.4 setup script skips system upgrades.

Set your timezone with `sudo dpkg-reconfigure tzdata` and update your account password using `passwd` as needed.

## Step 4: Security Tools for Your Distribution

On Debian, use tools packaged for Debian and the intended image repositories. Do not add Kali sources or install
Kali metapackages on this host. On a native Kali image, review the selected metapackage and optionally use:

```bash
sudo bash ./uconsole-cm5-setup.sh --install-kali-tools
```

This requires the reviewed v1.4 script. Existing v1.3 state must be investigated before continuing; `--reset` is not a rollback.

**Steps 5–11 and the boot-overlay reference apply only to fitted AIO hardware.** Confirm the current vendor instructions for your board/image before executing hardware changes. The v1.4 script does not automate these manual boot edits or source installers.

## Step 5: Install aiov2_ctl (GPIO Control Tool)

`aiov2_ctl` is HackerGadgets' official control tool for the AIO v2 board. It must be installed *before* the main AIO board package to resolve pathing correctly.

```bash
# Install build/runtime dependencies
sudo apt update
sudo apt install -y python3 python3-pyqt6 git

# Clone and install
git clone https://github.com/hackergadgets/aiov2_ctl.git /opt/aiov2_ctl
cd /opt/aiov2_ctl
sudo python3 ./aiov2_ctl.py --install

# Fix PATH for root environments
sudo ln -sf /usr/local/bin/aiov2_ctl /usr/bin/aiov2_ctl

# Verify
command -v aiov2_ctl && aiov2_ctl --status
```
The install enables the `aiov2-rails-boot.service` so boot-rail settings persist across reboots.

**Fix `.pygpsclient` venv ownership (required for `aiov2_ctl --gui`)**

`python3 ./aiov2_ctl.py --install` creates a Python venv at `~/.pygpsclient/` but runs as root, so the venv files
are root-owned. The regular user can't launch `--gui` until ownership is corrected and PyQt6 is installed inside
the venv:

```bash
# Fix ownership so your regular user owns the venv
sudo chown -R $USER:$USER ~/.pygpsclient

# Install PyQt6 inside the venv (not the system Python)
~/.pygpsclient/bin/pip3 install --ignore-installed PyQt6 --break-system-packages

# Verify
aiov2_ctl --status
```

> **Note:** `aiov2_ctl --gui` requires a physical display. Running it over SSH (with no `DISPLAY`) will fail. Use `--autostart` and reboot to launch the tray icon natively from the desktop.

---

## Step 6: Install the AIO v2 Board Package

Only for a physically installed, supported HackerGadgets AIO board. Check the [current Rex package
instructions](https://forum.clockworkpi.com/t/hackergadgets-aio-board-package/17875) and inspect the proposed
installation:

```bash
sudo apt-get update
apt-get -s --no-remove --install-recommends install hackergadgets-uconsole-aio-board
```

If the repository/package is unavailable or dependencies conflict, stop and resolve the image compatibility
problem. Do not inject Bookworm libraries, purge/retry automatically, force file overwrites, or create a
`pcmanfm-pi` symlink as a desktop workaround.

The reviewed v1.4 script's `--with-aio` option installs this package through APT. Package maintainer scripts can
still change configuration; `--no-remove` does not prevent that. Back up first and test the desktop afterward.
Follow upstream instructions separately for optional controller, Meshtastic and ADS-B features.

---

## Step 7: Configure GPS (CM5)

### CM5-Specific GPS Path
On CM5, the GPS serial port is `/dev/ttyAMA0` (CM4 uses `/dev/ttyS0`).

### Enable the UART in config.txt
Per HackerGadgets' CM5 setup guide, add the following to `/boot/firmware/config.txt`:

```ini
dtparam=uart0
```

### Free the Serial Port from the Console
Edit `/boot/firmware/cmdline.txt` and remove `console=serial0,115200`:

```bash
sudo sed -i 's/console=serial0,115200 \?//' /boot/firmware/cmdline.txt
```

### Add Your User to the dialout Group
```bash
sudo usermod -a -G dialout $USER
```
Log out and back in (or reboot) for the group change to take effect.

---

## Step 8: Configure LoRa / Meshtastic

### Enable SPI1 in config.txt
Add to `/boot/firmware/config.txt` (CM5 does not need `dtparam=spi=on` like CM4):

```ini
dtoverlay=spi1-1cs
```

### Disable the conflicting devterm-printer service
```bash
sudo systemctl stop devterm-printer.service
sudo systemctl disable devterm-printer.service
```

### Power on the LoRa module
```bash
aiov2_ctl LORA on
```

---

## Step 9: Configure RTC (CM5)

The CM5 requires disabling its internal RTC and mapping the AIO board's RTC over `i2c_csi_dsi0`. 

### Enable the RTC overlay (CM5)
Add to `/boot/firmware/config.txt`:

```ini
dtparam=rtc=off
dtparam=i2c_arm=on
dtoverlay=i2c-rtc,pcf85063a,i2c_csi_dsi0
```
Reboot, then verify:

```bash
sudo hwclock -r
sudo aiov2_ctl --sync-rtc
```

---

## Step 10: Configure SDR

### Blacklist the DVB-T kernel driver
The Linux kernel will try to claim the RTL2832U/R828D chip as a TV tuner. Blacklist it:

```bash
echo "blacklist dvb_usb_rtl28xxu" | sudo tee /etc/modprobe.d/blacklist-rtl.conf
sudo rmmod dvb_usb_rtl28xxu 2>/dev/null
```
*Note: On CM5, the SDR rail defaults to HIGH at boot, so the device is immediately available.*

---

## Step 11: GPIO Power Control

Configure peripherals to auto-enable at boot:

```bash
aiov2_ctl --boot-rail GPS on
aiov2_ctl --boot-rail LORA on
aiov2_ctl --boot-rail SDR on

# Verify
aiov2_ctl --boot-rails-status
```

---

## Step 12: WiFi Pentesting Setup

The CM5's onboard WiFi does not support monitor mode. Use an external USB WiFi adapter.

```bash
# Install DKMS driver for RTL8812AU
sudo apt install realtek-rtl88xxau-dkms -y
sudo dkms status | grep rtl88

# Enable monitor mode (wlan1 = external; wlan0 = onboard)
sudo airmon-ng start wlan1
iwconfig wlan1mon
```

---

## Step 13: LAN Pentesting via RJ45

The AIO v2 provides Gigabit Ethernet via the RJ45 port (requires Upgrade Kit adapter).

```bash
# Plug into a target switch, request DHCP
sudo dhclient eth0

# Verify connectivity
ip addr show eth0

# Run Responder for credential capture
sudo responder -I eth0 -wrf
```

---

## Step 14: NVMe Battery Board Setup

### NVMe Software Configuration (CM5)
CM5 features native PCIe lanes. Usually, no EEPROM update is required for basic NVMe recognition. Add to `/boot/firmware/config.txt`:

```ini
dtparam=pciex1=on
```
Reboot and verify:

```bash
lspci                          # Should show the NVMe controller
lsblk                          # Should show nvme0n1
sudo fdisk -l /dev/nvme0n1     # Full partition info
```

---

## CM5-Specific Notes and Limitations

| Item | CM5 Detail |
|---|---|
| GPS Serial Port | `/dev/ttyAMA0` (CM4 uses `/dev/ttyS0`) |
| GPS UART Config | Requires `dtparam=uart0` in `config.txt` (CM4 uses `enable_uart=1`) |
| SPI Config | Requires `dtoverlay=spi1-1cs` (CM4 also needs `dtparam=spi=on`) |
| RTC Config | Must disable internal RTC (`dtparam=rtc=off`) + remap i2c0 via `i2c_csi_dsi0` |
| SDR Boot State | Defaults HIGH (ON) at boot (CM4 defaults OFF) |
| Serial Console | Must remove `console=serial0,115200` from `cmdline.txt` for GPS |
| PCIe / NVMe | Native PCIe support. |

---

## AIO v2 Board: Hardware Reference

### Antenna Connectors
| Label | Purpose | Antenna Type |
|---|---|---|
| SDR | RTL-SDR receiver | Wideband, or frequency-specific |
| LoRa | SX1262 transceiver | 433 or 915 MHz (region-dependent) |
| GPS | GPS/BDS/GNSS receiver | Active or passive GPS antenna |

---

## aiov2_ctl: Full Command Reference

```bash
aiov2_ctl                           # Show current GPIO state
aiov2_ctl --status                  # Detailed status (GPIO + battery + power)
aiov2_ctl <FEATURE> <on|off>        # Toggle: GPS, LORA, SDR, USB
aiov2_ctl --power                   # Live power monitor (Ctrl+C to exit)
aiov2_ctl --watch                   # Compact live GPIO + power line
aiov2_ctl --gui                     # Launch system tray GUI
aiov2_ctl --autostart               # Enable GUI autostart on login
aiov2_ctl --boot-rail <FEAT> on     # Set peripheral to enable at boot
aiov2_ctl --boot-rails-status       # Show all boot rail configurations
aiov2_ctl --sync-rtc                # Write system time to hardware RTC
```

---

## Meshtastic Web Interface

Meshtasticd's web server is enabled by the AIO board package's default config.

1. Browse to `https://localhost` on the uConsole.
2. Accept the self-signed cert ("Proceed to localhost (unsafe)").
3. In the connection dialog, enter `localhost` (not `meshtastic.local`) and click **Connect**.
4. **Config → LoRa → Region:** set your region (US for 915 MHz). Different regions cannot communicate.
5. **Config → LoRa → Modem Preset:** Set to `LongFast` (Standard slot 20 for US).

---

## Boot Automation

### Complete `/boot/firmware/config.txt` Additions (CM5)
These are the overlay/parameter lines this guide adds to the bottom of Rex's `config.txt`:

```ini
# === AIO v2 Board Configuration (CM5) ===

# Enable UART0 for GPS on /dev/ttyAMA0
dtparam=uart0

# SPI for LoRa (SX1262)
dtoverlay=spi1-1cs

# Disable internal RTC and map AIO RTC (PCF85063A)
dtparam=rtc=off
dtparam=i2c_arm=on
dtoverlay=i2c-rtc,pcf85063a,i2c_csi_dsi0

# PCIe for NVMe (only if using NVMe Battery Board)
dtparam=pciex1=on
```

---

## Troubleshooting

### CM5 lite SD card boot fails
CM5 lite modules shipped with older EEPROMs may fail to boot from the SD card. You likely need an EEPROM update
(firmware must be newer than `2025-01-06`). Check the ClockworkPi forums for CM5 recovery/flashing guides.

### "Failed to start session" at LightDM login

Use [CM5 display recovery](./CM5-DISPLAY-RECOVERY.md) to identify the selected session, package changes and startup
errors. Restore the matching image configuration; do not assume generic Labwc, a forced package version, or
suppressing an authentication agent is a universal fix.

### GPS shows no data on `/dev/ttyAMA0`
* Confirm `dtparam=uart0` is in `/boot/firmware/config.txt` and you've rebooted.
* Confirm `console=serial0,115200` is removed from `/boot/firmware/cmdline.txt`.
* Confirm GPS power rail is enabled: `aiov2_ctl GPS on`.

### LoRa / Meshtasticd fails to start
* Verify devterm-printer.service is disabled: `sudo systemctl status devterm-printer.service`.
* Confirm SPI overlay in config.txt: `dtoverlay=spi1-1cs`.
* Check LoRa power rail: `aiov2_ctl LORA on`.

### `libfm` ABI Mismatch (symbol lookup error)

Use [CM5 display recovery](./CM5-DISPLAY-RECOVERY.md) to identify the selected session, package changes and startup
errors. Restore the matching image configuration; do not assume generic Labwc, a forced package version, or
suppressing an authentication agent is a universal fix.

### `aiov2_ctl --gui` fails: "PyQt6 is not installed"

`aiov2_ctl --install` creates a Python venv at `~/.pygpsclient/` as root, so the files are root-owned after the script runs. Fix it:

```bash
# Restore ownership
sudo chown -R $USER:$USER ~/.pygpsclient

# Install PyQt6 inside the venv
~/.pygpsclient/bin/pip3 install --ignore-installed PyQt6 --break-system-packages

# Now try the GUI
aiov2_ctl --gui
```

Also ensure `libxcb-cursor0` is installed - the Qt6 XCB platform plugin won't load without it:

```bash
sudo apt install -y libxcb-cursor0
```

### `aiov2_ctl --gui` errors over SSH

The GUI requires a live display server (`$DISPLAY` / Wayland socket). Running it from an SSH session fails because there is no display. Use `--autostart` instead and reboot:

```bash
aiov2_ctl --autostart
sudo reboot
```

### GDBus error: polkit-mate agent conflict on Labwc

Use [CM5 display recovery](./CM5-DISPLAY-RECOVERY.md) to identify the selected session, package changes and startup
errors. Restore the matching image configuration; do not assume generic Labwc, a forced package version, or
suppressing an authentication agent is a universal fix.

## Resources and Links

* [HackerGadgets AIO V1/V2 Setup Guide](https://hackergadgets.com/pages/hackergadgets-uconsole-rtl-sdr-lora-gps-rtc-usb-hub-all-in-one-extension-board-setup-guide)
* [aiov2_ctl GitHub Repo](https://github.com/hackergadgets/aiov2_ctl)
* [Rex's AIO Board Package Thread](https://forum.clockworkpi.com/t/hackergadgets-aio-board-package/17875)
* [Rex's Trixie Image](https://forum.clockworkpi.com/t/trixie-6-12-y-for-the-uconsole-and-devterm/19457)

## Related Files
- [README.md](README.md) - uConsole section index
- [CM4-SETUP.md](CM4-SETUP.md) - CM4 module variant of this guide
- [scripts/README.md](scripts/README.md) - Automated scripts to run after following this guide
- [../SDR/sdr.md](../SDR/sdr.md) - Using the RTL-SDR built into the uConsole
