# uConsole Setup Guide: CM4 Configuration

> [!CAUTION]
> **CM4 setup safety review — October 31, 2026.** The original CM4 instructions mixed Kali Rolling into Debian Trixie, forced package overwrites, deleted Python's `EXTERNALLY-MANAGED` marker and launched unchecked online installers. Those steps are **retired**, not recommended. The [CM4 v2.0 setup script](./scripts/uconsole-cm4-setup.sh) now performs **read-only checks by default**; optional installation requires explicit flags and a private configuration snapshot. Make a separate full SD/eMMC/NVMe image backup first. See the [uConsole safety review](./CM4-SAFETY-REVIEW.md), [CM5 guide](./CM5-SETUP.md) and [root uConsole index](./README.md).

## 🎯 Purpose
Complete setup guide for the ClockworkPi uConsole with Raspberry Pi CM4 module - covering Rex's Kali/Trixie community image, HackerGadgets AIO v2 board configuration, Battery/NVMe expansion board, and all driver setup.

## ⚙️ Function
Step-by-step post-flash configuration: WiFi adapter drivers, Bluetooth, audio, display brightness, RTL-SDR, LoRa, GPS, RTC, PoE HAT, Meshtastic, NVMe storage setup, and power board configuration specific to the CM4 compute module.

## 🏆 Goal
A fully working CM4-based uConsole with all HackerGadgets hardware functional and Kali or Trixie configured for field pentesting and SIGINT use.

## 📋 When to Use
- Initial setup after flashing Rex's Kali or Trixie image to a CM4 module
- Driver troubleshooting for CM4-specific hardware (WiFi, audio, display)
- Configuring the HackerGadgets AIO v2 board for the first time on CM4

## *Rex's Kali or Trixie + HackerGadgets AIO v2 Board + HackerGadgets Battery & NVMe Board*

A complete setup guide for building a field-deployable hacking and SIGINT platform using the ClockworkPi uConsole with a Raspberry Pi CM4, Rex's community images (Kali Linux or Debian Trixie), and the HackerGadgets AIO v2 extension board.

> **Want to automate this?** Every step in this guide is implemented in [`uconsole-cm4-setup.sh`](./scripts/uconsole-cm4-setup.sh). Run it on a fresh Rex image and it handles all six phases for you - including reboots.
> ```bash
> wget https://raw.githubusercontent.com/Pnwcomputers/ULTIMATE-CYBERSECURITY-MASTER-GUIDE/main/uConsole/scripts/uconsole-cm4-setup.sh
> chmod +x uconsole-cm4-setup.sh
> sudo ./uconsole-cm4-setup.sh
> ```
> See [`scripts/README.md`](./scripts/README.md) for flags and options.

> **Revision note (CM4 v2.0):** Previous v1.2 setup behavior was retired after review. The recommended sequence is **capture baseline → full backup → read-only preflight → simulate any optional changes → perform only approved installation steps → test and document**. A firmware/kernel/desktop update is deliberately not automated.

---

## Table of Contents

- [Hardware Overview](#hardware-overview)
- [Choosing Your OS: Kali vs Trixie](#choosing-your-os-kali-vs-trixie)
- [Step 1: Flash the OS](#step-1-flash-the-os)
- [Step 2: First Boot — Preserve and Audit the Working Image](#step-2-first-boot--preserve-and-audit-the-working-image)
- [Step 3: System Update and Initial Configuration](#step-3-system-update-and-initial-configuration)
- [Step 4: Security Tools for Your Distribution](#step-4-security-tools-for-your-distribution)
- [Step 5: Install aiov2_ctl (GPIO Control Tool)](#step-5-install-aiov2_ctl-gpio-control-tool)
- [Step 6: Install the AIO v2 Board Package](#step-6-install-the-aio-v2-board-package)
- [Step 7: Configure GPS (CM4)](#step-7-configure-gps-cm4)
- [Step 8: Configure LoRa / Meshtastic](#step-8-configure-lora--meshtastic)
- [Step 9: Configure RTC](#step-9-configure-rtc)
- [Step 10: Configure SDR](#step-10-configure-sdr)
- [Step 11: GPIO Power Control](#step-11-gpio-power-control)
- [Step 12: WiFi Pentesting Setup](#step-12-wifi-pentesting-setup)
- [Step 13: LAN Pentesting via RJ45](#step-13-lan-pentesting-via-rj45)
- [Step 14: NVMe Battery Board Setup](#step-14-nvme-battery-board-setup)
- [CM4-Specific Notes and Limitations](#cm4-specific-notes-and-limitations)
- [AIO v2 Board: Hardware Reference](#aio-v2-board-hardware-reference)
- [aiov2_ctl: Full Command Reference](#aiov2_ctl-full-command-reference)
- [Meshtastic Web Interface](#meshtastic-web-interface)
- [Boot Automation](#boot-automation)
- [Troubleshooting](#troubleshooting)
- [Resources and Links](#resources-and-links)

---

## 🎯 Purpose
Step-by-step build instructions for the CM4 variant of the uConsole + AIO v2 platform specifically - GPIO pin numbers, `config.txt` overlays, package names, and known failure modes here are CM4-specific and will not match the CM5. Use this file (not [CM5-SETUP.md](./CM5-SETUP.md)) when your board is a Raspberry Pi Compute Module 4.

## ⚙️ Function
Organized as 14 sequential numbered steps (flash OS → pre-flight hardening → system update → Kali tools → `aiov2_ctl` install → AIO v2 board package → GPS/LoRa/RTC/SDR configuration → GPIO power control → WiFi/LAN pentesting setup → NVMe battery board), followed by reference tables (hardware pinout, `aiov2_ctl` command reference), a Troubleshooting section with 10+ named failure modes and fixes, and a Resources/Links section. Differs from [CM5-SETUP.md](./CM5-SETUP.md) in package names, device-tree overlays, and the CM4-only NVMe/battery board step; differs from [README.md](./README.md), which is the folder-level index and hardware overview rather than a build walkthrough. Every step is also implemented as an idempotent shell script in [`scripts/uconsole-cm4-setup.sh`](./scripts/uconsole-cm4-setup.sh) (see [scripts/README.md](./scripts/README.md)).

## 🏆 Goal
A working CM4-based uConsole with the AIO v2 board fully configured - RTL-SDR, LoRa/Meshtastic, GPS, and RTC all functioning, GPIO power control operational, and WiFi/LAN pentesting tooling installed - without bricking the board or fighting the dependency issues this guide's troubleshooting section already documents.

## 📋 When to Use
When building or repairing a CM4-based uConsole from scratch, or when a specific step (e.g., Meshtastic not starting, GPS not getting a fix, `aiov2_ctl` failing) needs a manual fix outside of running the automation script.

---

## Hardware Overview

This guide assumes the following hardware stack:

| Component | Detail |
|---|---|
| **Handheld** | ClockworkPi uConsole |
| **Compute Module** | Raspberry Pi CM4 (with HackerGadgets CM4 adapter board) |
| **Extension Board** | HackerGadgets AIO v2 (RTL-SDR / LoRa / GPS / RTC / USB Hub) |
| **OS** | Rex's Kali Linux or Rex's Debian Trixie (6.12.y kernel) |
| **WiFi Adapter** | External monitor-mode capable adapter (CM4 onboard WiFi does NOT support monitor mode) |

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
| **SDR** (RTL-SDR) | 7 | Pull HIGH to enable. On CM5, this defaults HIGH at boot. On CM4, it defaults OFF. |
| **Internal USB** (USB-C + pin header) | 23 | Pull HIGH to enable |
| **GPS PPS** (output) | 6 | Optional, for microsecond-accurate NTP timing |

---

## Choosing Your OS: Kali vs Trixie

Rex maintains community images for the uConsole that include a custom kernel (6.12.y) with all necessary hardware patches for the uConsole display, keyboard, and trackball. His images also include a custom APT repository required for the `hackergadgets-uconsole-aio-board` package - that package is not available on stock ClockworkPi or upstream Kali images.

Rex's images include several conveniences that this guide relies on:
- Auto-expanding root filesystem on first boot (no `raspi-config` needed)
- `linux-headers` shipped with the kernel (no separate DKMS headers install)
- A dedicated "drivers" block at the bottom of `/boot/firmware/config.txt` with instructions for enabling overlays

### Path A: Rex's Kali Image (Pentesting Out of the Box)

The full Kali toolchain comes pre-installed: aircrack-ng, bettercap, responder, impacket, crackmapexec, nmap, Wireshark, Metasploit, Burp, etc.
**Pros:** Everything pre-installed, familiar to pentesters.
**Cons:** Rolling updates can affect the uConsole-specific desktop/kernel stack. Back up the known-good image and follow the image maintainer's guidance; the safe setup script never changes the desktop or updates core packages.

### Path B: Rex's Trixie Image + Kali Tools (Recommended)

Debian 13 (Trixie) base with packages from **the image's compatible Debian/Raspberry Pi repositories only**. Install compatible security tools from those repositories, trusted virtual environments or isolated native Kali systems.
**Pros:** Newest packages, cleaner base, better trackball behavior, fewer initramfs/package conflicts.
**Cons:** Some Kali-specific tools/metapackages are unavailable natively. Do **not** add Kali Rolling repositories to Debian; APT pinning cannot guarantee cross-distribution ABI compatibility.

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

Rex's specific guidance from the forum threads: **use Raspberry Pi Imager directly on the compressed `.xz` file, and do not apply any custom settings.** Custom settings (hostname, WiFi, SSH) from Pi Imager will cause Rex's images to fail to boot.
1. Install [Raspberry Pi Imager](https://www.raspberrypi.com/software/) on your host machine.
2. In Pi Imager:
   - **Operating System:** "Use Custom" → select the downloaded `.xz` file directly (do **not** decompress first)
   - **Storage:** your microSD card (16 GB minimum, 32+ GB recommended)
   - Click **Write**. When prompted about custom settings, choose **No** / **Skip**.
3. Insert the microSD card into the uConsole and boot.

> **Linux/`dd` alternative:** If you prefer the command line, decompress with `xz -d <image>.xz` first, then `sudo dd if=<image>.img of=/dev/sdX bs=4M status=progress conv=fsync`. Pi Imager is what Rex specifically recommends, though.

### First Boot

Power on. Rex's images auto-expand the root filesystem on first boot and then reboot once - let that complete. After the second boot:
- Log in with the default credentials
- Open a terminal
**Do NOT run `apt update` or `apt full-upgrade` yet.** Proceed directly to Step 2.

---

## Step 2: First Boot — Preserve and Audit the Working Image

Record the module model, kernel, operating system, desktop session, boot configuration and battery board before installing anything:

~~~bash
cat /etc/os-release
uname -a
cat /proc/device-tree/model
lsblk -o NAME,SIZE,FSTYPE,MOUNTPOINTS,MODEL
findmnt /
dpkg -l lightdm labwc raspberrypi-sys-mods 2>/dev/null || true
grep -nE '^(enable_uart|dtoverlay|dtparam)' /boot/firmware/config.txt
bash ./scripts/uconsole-cm4-setup.sh --status
~~~

Commands above are read-only. A working desktop is an asset worth preserving. Do **not** replace LightDM greeters, remove `raspberrypi-sys-mods`, disable cryptsetup-initramfs or delete the Python `EXTERNALLY-MANAGED` marker as generic preflight steps. Preserve the image's existing UART/RTC/SPI configuration until hardware-specific evidence shows a change is needed.

Before any package action, **image the whole storage device** and record a recovery path. A configuration snapshot (below) is supplementary, not a recovery image.

~~~bash
bash ./scripts/uconsole-cm4-setup.sh --help
bash ./scripts/uconsole-cm4-setup.sh --dry-run --with-aio
sudo bash ./scripts/uconsole-cm4-setup.sh --snapshot
~~~

If `--status` reports wrong/unknown hardware or mixed Kali sources on Debian, **stop**. Do not bypass the check or run the old installer.

## Step 3: System Update and Initial Configuration

Check the image vendor's exact update notes, repository origins and package resolver plan **before** deciding on upgrades:

~~~bash
apt-cache policy
sudo apt-get update
apt-get -s upgrade
~~~

`apt-get update` refreshes package metadata; `apt-get -s upgrade` is a **simulation**, not an upgrade. Inspect proposed kernel, firmware, session, desktop and AIO changes. The v2.0 CM4 setup script deliberately **does not perform an upgrade**, force overwrites, reboot or change the hostname. Do not add Kali Rolling APT sources to Debian, and do not rely on a global `Dpkg::Options::=--force-overwrite` workaround.

Use `sudo dpkg-reconfigure tzdata` and `passwd` only when needed and when the local session is working. If update simulations suggest removing critical dependencies, correct the repository situation first. [Kali official repository warning](https://www.kali.org/docs/general-use/kali-apt-sources/) · [Debian repository mixing warning](https://wiki.debian.org/DontBreakDebian).

## Step 4: Security Tools for Your Distribution

**Debian / Rex Trixie:** install only compatible Debian or Rex-provided tools. A Kali metapackage is not a safe way to add tools to Debian. For a full Kali environment, use a native Kali-supported uConsole image or an isolated Kali virtual/lab host.

**Native Kali image only:** preview an optional metapackage using the v2.0 script; changes require a separate explicit invocation and confirmation:

~~~bash
bash ./scripts/uconsole-cm4-setup.sh --kali-tools --dry-run
sudo bash ./scripts/uconsole-cm4-setup.sh --kali-tools
~~~

The script checks the CM4 model, OS family and APT sources and refuses package removals in its simulation. Package maintainer scripts and compatible dependency updates can still modify the system; keep a full backup. Nothing here guarantees that every package is available for the image's architecture.

---

## Step 5: Install aiov2_ctl (GPIO Control Tool)

`aiov2_ctl` is HackerGadgets' official control tool for the AIO v2 board. It can be installed and verified independently; verify the currently documented vendor sequence for optional companion packages.

```bash
# Install build/runtime dependencies
sudo apt update
sudo apt install -y python3 python3-pyqt6 git

# Clone and install
git clone https://github.com/hackergadgets/aiov2_ctl.git
cd aiov2_ctl
sudo python3 ./aiov2_ctl.py --install

# Fix PATH for root environments
sudo ln -sf /usr/local/bin/aiov2_ctl /usr/bin/aiov2_ctl

# Verify
command -v aiov2_ctl && aiov2_ctl --status
```
The install enables the `aiov2-rails-boot.service` so boot-rail settings persist across reboots.

**Fix `.pygpsclient` venv ownership (required for `aiov2_ctl --gui`)**

`python3 ./aiov2_ctl.py --install` creates a Python venv at `~/.pygpsclient/` but runs as root, so the venv files are root-owned. The regular user can't launch `--gui` until ownership is corrected and PyQt6 is installed inside the venv:

```bash
# Fix ownership so your regular user owns the venv
sudo chown -R $USER:$USER ~/.pygpsclient

# Install PyQt6 inside the venv (not the system Python)
# Use the existing virtual environment's own pip only after checking ownership;
# never use --break-system-packages as a routine repair.

# Verify
aiov2_ctl --status
```

**Enable the system tray GUI on login (optional)**
```bash
aiov2_ctl --autostart
```

> **Note:** `aiov2_ctl --gui` requires a physical display. Running it over SSH (with no `DISPLAY`) will fail. Use `--autostart` and reboot to launch the tray icon natively from the desktop.

---

## Step 6: Install the AIO v2 Board Package (Optional, Hardware Fitted)

Only install the HackerGadgets board package if your **actual uConsole has the AIO v2 hardware**, and its package candidate is present in the image's compatible Debian/Rex sources. Current official vendor instructions recommend `hackergadgets-uconsole-aio-board` and optionally `aiov2_ctl` companion apps. The control utility can be used independently; do not presume your chosen image requires a particular install order.

~~~bash
apt-cache policy hackergadgets-uconsole-aio-board
bash ./scripts/uconsole-cm4-setup.sh --with-aio --dry-run
sudo bash ./scripts/uconsole-cm4-setup.sh --with-aio
~~~

The script backs up selected configuration and simulates APT first; it does not install an unchecked script, fetch incompatible Bookworm `.deb` files over HTTP, purge/retry packages automatically or reconfigure boot overlays. Review any APT result before confirming the proposed installation. The package **may** add services and runtime dependencies; inspect the final desktop and board operation after installation. For additional apps, follow the [current HackerGadgets control utility instructions](https://github.com/hackergadgets/aiov2_ctl) and [official AIO v2 board setup](https://hackergadgets.com/pages/hackergadgets-uconsole-rtl-sdr-lora-gps-rtc-usb-hub-all-in-one-extension-board-setup-guide) instead of executing moving GitHub installer scripts from a shell pipeline.

Do not perform vendor/boot/RTC changes if using an unmodified stock board, a different AIO revision, or unknown image.

---

## Step 7: Configure GPS (CM4)

The AIO board package already installed `pygpsclient` and configured Meshtasticd's GPS section. This step covers the kernel-side serial port setup that the package doesn't do for you.

### CM4-Specific GPS Path
On CM4, the GPS serial port is `/dev/ttyS0` (CM5 uses `/dev/ttyAMA0`).

### Enable the UART in config.txt
Per HackerGadgets' official setup guide, add the following to `/boot/firmware/config.txt`:

```ini
enable_uart=1
```

### Free the Serial Port from the Console
The serial console must be disabled or GPS will be intermittently overwritten by kernel messages. Edit `/boot/firmware/cmdline.txt` and remove `console=serial0,115200`:

```bash
sudo nano /boot/firmware/cmdline.txt
```
Find and delete `console=serial0,115200` from the line. Save and exit. Keep all the other parameters on a single line - `cmdline.txt` is whitespace-sensitive.

### Add Your User to the dialout Group
To read from `/dev/ttyS0` without sudo (required for GUI tools like pygpsclient):

```bash
sudo usermod -a -G dialout $USER
```
Log out and back in (or reboot) for the group change to take effect.

### Power on the GPS Module & Verify
Connect a GPS antenna to the IPEX connector labeled "GPS" on the AIO v2 board.

```bash
aiov2_ctl GPS on
sudo minicom -D /dev/ttyS0 -b 9600
```
You should see `$GNGGA` / `$GNRMC` sentences streaming.

---

## Step 8: Configure LoRa / Meshtastic

The AIO board package already installed Meshtasticd, wrote `/etc/meshtasticd/config.yaml` with the SX1262 pin mappings, and enabled the service.

### Enable SPI1 in config.txt
Add to `/boot/firmware/config.txt`:

```ini
dtparam=spi=on
dtoverlay=spi1-1cs
```

### Disable the conflicting devterm-printer service
The DevTerm printer service uses the same SPI1 GPIO range as the LoRa module:

```bash
sudo systemctl stop devterm-printer.service
sudo systemctl disable devterm-printer.service
```

### Power on the LoRa module
```bash
aiov2_ctl LORA on
```

### Verify the Meshtasticd config
Confirm `/etc/meshtasticd/config.yaml` matches the SX1262 pinout for AIO v2:

```yaml
Lora:
  Module: sx1262
  DIO2_AS_RF_SWITCH: true
  DIO3_TCXO_VOLTAGE: true
  IRQ: 26
  Busy: 24
  Reset: 25
  spidev: spidev1.0
```

### Connect the Antenna
Connect a 433 or 915 MHz antenna (region-dependent) to the IPEX connector labeled "LoRa" on the AIO v2 board.
**Never transmit without an antenna connected - the SX1262's PA can be damaged by reflected power.**

### First-Time Meshtastic Setup (Web UI)
1. Restart the daemon (`sudo systemctl restart meshtasticd`), then open a browser on the uConsole and navigate to `https://localhost`.
2. **Config → LoRa → Region:** Set your region (e.g. US for 915 MHz).
3. **Config → LoRa → Modem Preset:** Set the channel preset. For US LongFast, the standard frequency slot is slot 20.

---

## Step 9: Configure RTC

### Enable the RTC overlay (CM4)
Add to `/boot/firmware/config.txt`:

```ini
dtparam=i2c_arm=on
dtoverlay=i2c-rtc,pcf85063a
```
Reboot, then verify:

```bash
sudo hwclock -r
```

### Sync the RTC to system time
After confirming system time is correct:

```bash
sudo aiov2_ctl --sync-rtc
```
From now on, the RTC will keep time across power-off periods using the CR1220 backup battery.

---

## Step 10: Configure SDR

### Power on the SDR
```bash
aiov2_ctl SDR on
```

### Blacklist the DVB-T kernel driver
The Linux kernel will try to claim the RTL2832U/R828D chip as a DVB-T television tuner, which blocks user-space SDR software from using it. Blacklist the default driver:

```bash
echo "blacklist dvb_usb_rtl28xxu" | sudo tee /etc/modprobe.d/blacklist-rtl.conf
sudo rmmod dvb_usb_rtl28xxu 2>/dev/null
```

### Launch SDR++
Connect a wideband antenna to the IPEX connector labeled "SDR".

```bash
sdrpp
```
In the SDR++ UI:
* **Source dropdown:** select RTL-SDR, then pick the device's serial number from the second dropdown.

### ADS-B Tracking (tar1090)
tar1090 is installed and configured by the AIO board package. Access the web UI at `http://localhost/tar1090` once running. The menu launcher starts `readsb` only while tar1090 is open and stops it on exit.

---

## Step 11: GPIO Power Control

### AIO v2 Control Pin Map (CM4)

| Peripheral | GPIO | CM4 Default at Boot |
|---|---|---|
| GPS | 27 | OFF |
| LoRa | 16 | OFF |
| SDR (RTL-SDR) | 7 | OFF (on CM5, defaults ON) |
| Internal USB (USB-C + pin header) | 23 | OFF |

### Configure Boot Defaults
Set peripherals to auto-enable at boot:

```bash
aiov2_ctl --boot-rail GPS on
aiov2_ctl --boot-rail LORA on
aiov2_ctl --boot-rail SDR on

# Verify
aiov2_ctl --boot-rails-status
```

---

## Step 12: WiFi Pentesting Setup

The CM4's onboard WiFi does not support monitor mode. You need an external USB WiFi adapter.

### Install the DKMS Driver
Driver support is **chipset, USB ID, kernel and distro-specific**. First inspect `lsusb`, `uname -r`, `modinfo` and the candidate package; do not assume every CM4/Rex image has compatible headers, or every adapter uses the same DKMS module:

```bash
# Only if a compatible package exists and the adapter really needs it:
# sudo apt install realtek-rtl88xxau-dkms
sudo dkms status | grep rtl88
```
Plug in the adapter - `iwconfig` should now list it.

### Verify Monitor Mode
```bash
# Enable monitor mode (wlan1 = external; wlan0 = onboard)
sudo airmon-ng start wlan1

# Verify
iwconfig wlan1mon
```

---

## Step 13: LAN Pentesting via RJ45

The AIO v2 provides Gigabit Ethernet via the RJ45 port. This requires the HackerGadgets adapter board from the Upgrade Kit.

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

The HackerGadgets NVMe Battery Board replaces the stock uConsole battery board.

### NVMe Software Configuration (CM4)
Add to `/boot/firmware/config.txt`:

```ini
dtparam=pciex1=on
```
Reboot and verify:

```bash
lspci                          # Should show the NVMe controller
lsblk                          # Should show nvme0n1
sudo fdisk -l /dev/nvme0n1     # Full partition info
```

### NVMe boot and backups: check EEPROM capability first

**Detection is not bootability.** A visible `/dev/nvme0n1` indicates a PCIe/NVMe device, not that the Compute Module's boot EEPROM is configured to try it. CM4 Lite/microSD and eMMC variants also have different boot arrangements. Do not assume an SD-to-NVMe fall-through boot order and do not run `rpi-clone nvme0n1` without validating the clone utility, exact source/target device and a recoverable bootloader configuration.

Read-only assessment:

~~~bash
lsblk -o NAME,SIZE,MODEL,SERIAL,FSTYPE,MOUNTPOINTS
lspci
sudo rpi-eeprom-config  # if installed on your image; inspect BOOT_ORDER
~~~

Consult [Raspberry Pi's official Compute Module boot/EEPROM documentation](https://www.raspberrypi.com/documentation/computers/compute-module.html) for the **specific CM4 carrier board** and boot order. Updating EEPROM, enabling PCIe and cloning a root filesystem are **separate procedures** with data-loss/brick risks. Image and test a spare storage device first; retain the original boot media until a full power-cycle boot and restore are proven.

---

## CM4-Specific Notes and Limitations

| Item | CM4 Detail |
|---|---|
| GPS Serial Port | `/dev/ttyS0` (CM5 uses `/dev/ttyAMA0`) |
| GPS UART Config | Requires `enable_uart=1` in `config.txt` (CM5 uses `dtparam=uart0`) |
| USB Speed | USB 2.0 only (USB 3.0 requires CM5 + Upgrade Kit) |
| GPIO Boot State | All AIO peripherals start OFF (CM5 has GPIO 7/SDR on by default) |
| Stability | Most mature and community-tested configuration |
| Serial Console | Must remove `console=serial0,115200` from `cmdline.txt` for GPS |

---

## AIO v2 Board: Hardware Reference

### Antenna Connectors
| Label | Purpose | Antenna Type |
|---|---|---|
| SDR | RTL-SDR receiver | Wideband, or frequency-specific |
| LoRa | SX1262 transceiver | 433 or 915 MHz (region-dependent) |
| GPS | GPS/BDS/GNSS receiver | Active or passive GPS antenna |

*The antenna mounting kit (sold with some variants) supports up to 7 antennas.*

### RTL-SDR Specs
| Spec | Value |
|---|---|
| Tuner Chip | R828D |
| Frequency Range | 100 kHz – 1.74 GHz |
| Clock | TCXO (temperature-compensated, near-zero drift) |
| Bias Tee | 5V (for active antennas / LNAs) |

### LoRa / SX1262 Specs
| Spec | Value |
|---|---|
| Chip | SX1262 |
| Frequency Band | 860–960 MHz |
| Max Output Power | 22 dBm |
| Clock | TCXO |
| SPI Bus | SPI1 (`spidev1.0`) |

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

### Debug Mode
```bash
AIOV2_CTL_DEBUG=1 aiov2_ctl --status
```
Shows state source labels: `(pinctrl)` for direct hi/lo, `(boot_default)` for fallback, `(unknown)` for unparseable reads.

---

## Meshtastic Web Interface

Meshtasticd's web server is enabled by the AIO board package's default config (Meshtastic 2.3.0+ ships it).

Confirm webserver section in `/etc/meshtasticd/config.yaml`:

```yaml
Webserver:
  Port: 443
  RootPath: /usr/share/meshtasticd/web
```

1. Browse to `https://localhost` on the uConsole.
2. Accept the self-signed cert ("Proceed to localhost (unsafe)").
3. In the connection dialog, enter `localhost` (not `meshtastic.local`) and click **Connect**.
4. **Config → LoRa → Region:** set your region (US for 915 MHz). Different regions cannot communicate.
5. **Messages menu:** send/receive on public channels or between individual nodes.
6. Offline map packs go in `/home/$USER/.portduino/default/maps/`.

---

## Boot Automation

### Recommended Boot Configuration (Field-Ready Profile)
```bash
# Set boot rails
aiov2_ctl --boot-rail GPS on
aiov2_ctl --boot-rail LORA on
aiov2_ctl --boot-rail SDR on

# Tray GUI on login
aiov2_ctl --autostart

# Meshtasticd on boot
sudo systemctl enable meshtasticd.service

# Verify
aiov2_ctl --boot-rails-status
```

### Complete `/boot/firmware/config.txt` Additions
These are the overlay/parameter lines this guide adds to the bottom of Rex's `config.txt` (in the "follow the instructions" driver section). Existing lines from Rex's image stay untouched.

```ini
# === AIO v2 Board Configuration (CM4) ===

# Enable UART0 for GPS on /dev/ttyS0
enable_uart=1

# SPI for LoRa (SX1262)
dtparam=spi=on
dtoverlay=spi1-1cs

# I2C and RTC (PCF85063A)
dtparam=i2c_arm=on
dtoverlay=i2c-rtc,pcf85063a

# PCIe for NVMe (only if using NVMe Battery Board)
dtparam=pciex1=on
# Optional: cap link at Gen 2 for stability with some drives
# dtparam=pciex1_gen=2
```
And in `/boot/firmware/cmdline.txt`:
* Remove `console=serial0,115200` to free `/dev/ttyS0` for GPS.

---

> [!WARNING]
> **Historical troubleshooting recipes below require individual review.** In particular, do not use forced-overwrite APT recovery, unverified cross-release `.deb` downloads, or Kali repositories on Debian. See the [uConsole safety review](./CM4-SAFETY-REVIEW.md) and [CM5 display recovery approach](./CM5-DISPLAY-RECOVERY.md) for evidence-first diagnostics.

## Troubleshooting

### "Failed to start session" at LightDM login
If you hit this on a system that didn't run the pre-flight hardening:

```bash
# Check what LightDM is configured to launch
grep -i "session" /etc/lightdm/lightdm.conf

# Switch user-session and autologin-session to labwc
sudo sed -i \
  -e 's/^user-session=rpd-labwc/user-session=labwc/' \
  -e 's/^autologin-session=rpd-labwc/autologin-session=labwc/' \
  -e 's/^greeter-session=pi-greeter-labwc/greeter-session=lightdm-gtk-greeter/' \
  /etc/lightdm/lightdm.conf

# Fix AccountsService entries
for f in /var/lib/AccountsService/users/*; do
  [ -f "$f" ] && sudo sed -i 's/rpd-labwc/labwc/g' "$f"
done

# Make sure the fallback packages are installed
# Preserve working desktop sessions; install only proven missing dependencies.

# Restart LightDM
sudo systemctl restart lightdm
```

### AIO board package fails with `/tmp` script errors
Symptoms - postinst script can't find `/tmp/readsb-install.sh` or `/tmp/config.yaml`. Fix:

```bash
# Do not purge the AIO package as a blind recovery step; inspect package logs.
sudo apt update
# See Step 6 for opt-in, simulated, reviewed vendor package installation.
# Verify Meshtastic compatibility and vendor-supported package before install.
```

### GPS shows no data on `/dev/ttyS0`
* Confirm `enable_uart=1` is in `/boot/firmware/config.txt` and you've rebooted
* Confirm `console=serial0,115200` is removed from `/boot/firmware/cmdline.txt`
* Confirm GPS power rail is enabled: `aiov2_ctl GPS on`

### LoRa / Meshtasticd fails to start
* Verify devterm-printer.service is disabled: `sudo systemctl status devterm-printer.service`
* Confirm SPI overlays in `config.txt`: `dtparam=spi=on` and `dtoverlay=spi1-1cs`
* Check LoRa power rail: `aiov2_ctl LORA on`
* Review logs: `sudo journalctl -u meshtasticd.service -b`
* Verify `/etc/meshtasticd/config.yaml` has the SX1262 pin mappings

### SDR not detected
* Power: `aiov2_ctl SDR on`
* DVB-T driver blacklisted: `cat /etc/modprobe.d/blacklist-rtl.conf`
* USB device visible: `lsusb | grep -i rtl`

### RTL8812AU adapter not visible
* DKMS module built for your running kernel: `sudo dkms status | grep rtl88`
* If status shows "added" but not "installed" - kernel headers aren't matching. Install the matching `linux-headers-$(uname -r)` and run `sudo dkms autoinstall`.

### uConsole won't boot after AIO v2 installation
* Check the ribbon cable orientation - most common cause
* Refer to the HackerGadgets installation photos for correct orientation
* Never plug in the charger if the ribbon cable is wrong - it will damage the mainboard

### "Unsatisfied dependencies" or version mismatches on Trixie + Kali
Install affected packages from Kali explicitly:

```bash
# Retired: do not install Kali repository packages into Debian.
```
To make the pin permanent:
```bash
sudo tee /etc/apt/preferences.d/kali-pin <<'EOF'
Package: *
Pin: release o=Kali
Pin-Priority: 900
EOF

sudo apt update
```

### Meshtasticd dependency errors on Trixie (`libgpiod2`/`libyaml-cpp0.7`)
If you skipped Step 6 and are trying to install manually:

```bash
# Retired: do not inject cross-release libgpiod2 package from HTTP.
# Retired: do not inject cross-release libyaml-cpp0.7 package from HTTP.
# Unsafe cross-release installation retired. Resolve dependencies using
# supported packages built for this OS/image; do not dpkg -i old Bookworm .debs.
# First inspect APT simulation and package conflicts; do not force an automatic repair.
```

### `aiov2_ctl --gui` fails: "PyQt6 is not installed"

`aiov2_ctl --install` creates a Python venv at `~/.pygpsclient/` as root, so the files are root-owned after the script runs. Fix it:

```bash
# Restore ownership
sudo chown -R $USER:$USER ~/.pygpsclient

# Install PyQt6 inside the venv
# Verify an isolated venv and compatibility; do not bypass Python protections.

# Now try the GUI
aiov2_ctl --gui
```

Also ensure `libxcb-cursor0` is installed - the Qt6 XCB platform plugin won't load without it:

```bash
sudo apt install -y libxcb-cursor0
```

### `aiov2_ctl --gui` errors over SSH

The GUI requires a live display server (`$DISPLAY` / Wayland socket). Running it from an SSH session fails because there is no display. Use `--autostart` instead and reboot - the tray icon will launch natively from the desktop:

```bash
aiov2_ctl --autostart
sudo reboot
```

### GDBus error: polkit-mate agent conflict on Labwc

Symptom: `GDBus.Error:org.freedesktop.PolicyKit1.Error.Failed: An authentication agent already exists for the given subject` in journalctl at login.

Kali metapackages install `polkit-mate-authentication-agent-1`, which conflicts with `lxpolkit` on Labwc. Suppress it with an XDG per-user override (do **not** remove the package - other Kali tools depend on it):

```bash
mkdir -p ~/.config/autostart
cp /etc/xdg/autostart/polkit-mate-authentication-agent-1.desktop ~/.config/autostart/
echo "Hidden=true" >> ~/.config/autostart/polkit-mate-authentication-agent-1.desktop
```

Log out and back in to confirm the error is gone.

---

## Resources and Links

### Forum Threads
| Resource | URL |
|---|---|
| Rex's Kali Image | `https://forum.clockworkpi.com/t/kali-6-12-y-for-the-uconsole-and-devterm/14463` |
| Rex's Bookworm Image | `https://forum.clockworkpi.com/t/bookworm-6-12-y-for-the-uconsole-and-devterm/15847` |
| Rex's Trixie Image | `https://forum.clockworkpi.com/t/trixie-6-12-y-for-the-uconsole-and-devterm/19457` |
| Rex's AIO Board Package Thread | `https://forum.clockworkpi.com/t/hackergadgets-aio-board-package/17875` |
| Updated Images (New Screens) | `https://forum.clockworkpi.com/t/updated-images-for-new-uconsole-screens/21666` |
| AIO v2 Discussion | `https://forum.clockworkpi.com/t/uconsole-aio-v2-rtl-sdr-lora-gps-rtc-usb-hub-usb-3-0-rj45-ethernet/20800` |

### Documentation and Guides
| Resource | URL |
|---|---|
| HackerGadgets AIO V1/V2 Setup Guide | `https://hackergadgets.com/pages/hackergadgets-uconsole-rtl-sdr-lora-gps-rtc-usb-hub-all-in-one-extension-board-setup-guide` |
| aiov2_ctl GitHub Repo | `https://github.com/hackergadgets/aiov2_ctl` |
| uConsole GitHub (Official) | `https://github.com/clockworkpi/uConsole` |
| Rex's GitHub (kernel + APT repo) | `https://github.com/ak-rex` |
| Meshtastic Firmware Releases | `https://github.com/meshtastic/firmware/releases` |

### Products
| Product | URL |
|---|---|
| AIO v2 Board | `https://hackergadgets.com/products/uconsole-aio-v2` |
| uConsole Upgrade Kit | `https://hackergadgets.com/products/uconsole-upgrade-kit` |
| NVMe Battery Board | `https://hackergadgets.com/products/nvme` |

### Community Threads
| Resource | URL |
|---|---|
| Upgrade Kit Discussion | `https://forum.clockworkpi.com/t/hackergadgets-uconsole-upgrade-kit-adding-nvme-ssd-pcie-rj45-ethernet-and-usb-3-0-to-your-uconsole/20019` |
| Power Switch Mod for NVMe Board | `https://forum.clockworkpi.com/t/power-switch-for-hackergadgets-nvme-battery-board/21553` |

### License
This guide is provided as-is for personal reference and community use. Hardware documentation and software referenced herein belong to their respective authors (ClockworkPi, HackerGadgets, Rex, Meshtastic project).

## Related Files
- [README.md](README.md) - uConsole section index
- [CM5-SETUP.md](CM5-SETUP.md) - CM5 module variant of this guide
- [scripts/README.md](scripts/README.md) - Automated scripts to run after following this guide
- [../SDR/sdr.md](../SDR/sdr.md) - Using the RTL-SDR built into the uConsole
