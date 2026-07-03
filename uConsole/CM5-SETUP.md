# uConsole Setup Guide: CM5 Configuration

## *Rex's Kali or Trixie + HackerGadgets AIO v2 Board + HackerGadgets Battery & NVMe Board*

A complete setup guide for building a field-deployable hacking and SIGINT platform using the ClockworkPi uConsole with a Raspberry Pi CM5, Rex's community images (Kali Linux or Debian Trixie), and the HackerGadgets AIO v2 extension board.

> **Want to automate this?** Every step in this guide is implemented in [`uconsole-cm5-setup.sh`](./scripts/uconsole-cm5-setup.sh). Run it on a fresh Rex image and it handles all six phases for you — including reboots.
> ```bash
> wget https://raw.githubusercontent.com/Pnwcomputers/ULTIMATE-CYBERSECURITY-MASTER-GUIDE/main/uConsole/scripts/uconsole-cm5-setup.sh
> chmod +x uconsole-cm5-setup.sh
> sudo ./uconsole-cm5-setup.sh
> ```
> See [`scripts/README.md`](./scripts/README.md) for flags and options.

> **About this revision (audited against forum sources):** The order of operations is "harden first, upgrade second, then install." Every step that used to break a fresh install has been pre-empted before the first `apt full-upgrade`. GPIO pin assignments, GPS UART config (CM5-specific `dtparam=uart0`), the CM5-specific RTC overlay (`dtparam=rtc=off` + `i2c_csi_dsi0` remap), and the relationship between `hackergadgets-uconsole-aio-board` and `aiov2_ctl` have been corrected against the [official HackerGadgets setup guide](https://hackergadgets.com/pages/hackergadgets-uconsole-rtl-sdr-lora-gps-rtc-usb-hub-all-in-one-extension-board-setup-guide) and [Rex's package thread on the ClockworkPi forum](https://forum.clockworkpi.com/t/hackergadgets-aio-board-package/17875).

---

## Table of Contents

- [Hardware Overview](#hardware-overview)
- [Choosing Your OS: Kali vs Trixie](#choosing-your-os-kali-vs-trixie)
- [Step 1: Flash the OS](#step-1-flash-the-os)
- [Step 2: First Boot — Pre-Flight Hardening](#step-2-first-boot--pre-flight-hardening)
- [Step 3: System Update and Initial Configuration](#step-3-system-update-and-initial-configuration)
- [Step 4: Add Kali Tools (Trixie Only)](#step-4-add-kali-tools-trixie-only)
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
Step-by-step build instructions for the CM5 variant of the uConsole + AIO v2 platform specifically — GPIO pin behavior, `config.txt` overlays, and known failure modes here are CM5-specific (e.g., `/dev/ttyAMA0` instead of `/dev/ttyS0`, `dtparam=uart0` instead of `enable_uart=1`, native PCIe NVMe support) and will not match the CM4. Use this file (not [CM4-SETUP.md](./CM4-SETUP.md)) when your board is a Raspberry Pi Compute Module 5.

## ⚙️ Function
Organized as the same 14 sequential numbered steps as [CM4-SETUP.md](./CM4-SETUP.md) (flash OS → pre-flight hardening → system update → Kali tools → `aiov2_ctl` install → AIO v2 board package → GPS/LoRa/RTC/SDR configuration → GPIO power control → WiFi/LAN pentesting setup → NVMe battery board), followed by reference tables and a Troubleshooting section. Differs from CM4-SETUP.md in GPIO/UART/RTC device-tree overlays, GPS serial port path, SDR default boot state (HIGH on CM5 vs OFF on CM4), and native PCIe NVMe support; differs from [README.md](./README.md), which is the folder-level index rather than a build walkthrough. Every step is also implemented as an idempotent shell script in [`scripts/uconsole-cm5-setup.sh`](./scripts/uconsole-cm5-setup.sh) (see [scripts/README.md](./scripts/README.md)).

## 🏆 Goal
A working CM5-based uConsole with the AIO v2 board fully configured — RTL-SDR, LoRa/Meshtastic, GPS, and RTC all functioning, GPIO power control operational, and WiFi/LAN pentesting tooling installed — without the CM5-specific pitfalls (SD boot failures on old EEPROM, UART/RTC overlay mismatches) this guide's troubleshooting section already documents.

## 📋 When to Use
When building or repairing a CM5-based uConsole from scratch, or when a specific step (e.g., Meshtastic not starting, GPS not getting a fix, CM5 lite SD card not booting) needs a manual fix outside of running the automation script.

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

> **Critical Assembly Note:** When installing the AIO v2 board, ensure the ribbon cable is oriented correctly as shown in the HackerGadgets documentation. **Never plug in the charger if the ribbon cable is installed the wrong way** — incorrect installation will damage the uConsole mainboard.

### AIO v2 GPIO Map (Verified Against HackerGadgets Official Docs)

These are the **AIO v2** control GPIOs. (AIO v1 used different pins for LoRa and Internal USB — make sure you're working with v2 hardware.)

| Peripheral | GPIO | Notes |
|---|---|---|
| **GPS** | 27 | Pull HIGH to enable |
| **LoRa** | 16 | Pull HIGH to enable |
| **SDR** (RTL-SDR) | 7 | Pull HIGH to enable. **On CM5, this defaults HIGH at boot** — RTL-SDR is detected immediately. On CM4, it defaults OFF. |
| **Internal USB** (USB-C + pin header) | 23 | Pull HIGH to enable |
| **GPS PPS** (output) | 6 | Optional, for microsecond-accurate NTP timing |

---

## Choosing Your OS: Kali vs Trixie

Rex maintains community images for the uConsole that include a custom kernel (6.12.y) with all necessary hardware patches for the uConsole display, keyboard, and trackball. His images also include a custom APT repository required for the `hackergadgets-uconsole-aio-board` package — that package is not available on stock ClockworkPi or upstream Kali images.

Rex's images include several conveniences that this guide relies on:

- Auto-expanding root filesystem on first boot (no `raspi-config` needed)
- `linux-headers` shipped with the kernel (no separate DKMS headers install)
- A dedicated "drivers" block at the bottom of `/boot/firmware/config.txt` with instructions for enabling overlays

> **CM5 special note from Rex:** The AIO board package was developed primarily for CM5 because enabling SPI for Meshtastic on CM5 needs additional plumbing to keep the display panel working. Using the official `hackergadgets-uconsole-aio-board` package is therefore strongly recommended on CM5 — the manual route is risky.

### Path A: Rex's Kali Image (Pentesting Out of the Box)

The full Kali toolchain comes pre-installed: aircrack-ng, bettercap, responder, impacket, crackmapexec, nmap, Wireshark, Metasploit, Burp, etc.

**Pros:** Everything pre-installed, familiar to pentesters.
**Cons:** Kali rolling upgrades have a history of replacing the RPi-specific LightDM session/greeter without updating `lightdm.conf`, breaking the login screen. Step 2 of this guide pre-empts that.

### Path B: Rex's Trixie Image + Kali Tools (Recommended)

Debian 13 (Trixie) base with the newest upstream packages, plus the Kali rolling repo added on top for pentesting tools.

**Pros:** Newest packages, cleaner base, better trackball behavior, fewer initramfs/package conflicts.
**Cons:** Extra step to add Kali tools. Mixing Kali rolling with Trixie creates dependency-version conflicts unless APT pinning is set up correctly (this guide handles that in Step 2).

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

> **CM5 lite SD card boot issue:** If you have a CM5 lite and the SD card won't boot, you likely need an EEPROM update. See [Troubleshooting → CM5 lite SD boot fails](#troubleshooting) before getting frustrated — this is a known issue with a documented fix.

### First Boot

Power on. Rex's images auto-expand the root filesystem on first boot and then reboot once — let that complete. After the second boot:

- Log in with the default credentials
- Open a terminal

**Do NOT run `apt update` or `apt full-upgrade` yet.** Proceed directly to Step 2.

---

## Step 2: First Boot — Pre-Flight Hardening

This step pre-empts the three issues that historically break a fresh uConsole install on its first upgrade. We fix all three before any `apt full-upgrade` runs.

### 2.1 — Disable the cryptsetup-initramfs hook

The `cryptsetup-initramfs` hook fails on Pi systems (it can't resolve `/dev/root` from `PARTUUID=` cmdlines), which kills dpkg triggers and can corrupt the initramfs mid-upgrade. Unless you're using LUKS (you aren't, on a fresh Rex image), disable the hook:

```bash
sudo mkdir -p /etc/cryptsetup-initramfs
echo "CRYPTSETUP=n" | sudo tee /etc/cryptsetup-initramfs/conf-hook
```

### 2.2 — Pin LightDM to sessions that survive upgrades

Rex's images ship with `user-session=rpd-labwc` and `greeter-session=pi-greeter-labwc` in `/etc/lightdm/lightdm.conf`. Upstream changes often rename or remove these without updating the config file, breaking the GUI login. We apply guarded swaps to fix this:

```bash
# 1. Ensure fallback compositor and greeter are installed
sudo apt update
sudo apt install -y lightdm-gtk-greeter labwc rtkit libxcb-cursor0

# 2. Check session references. If clockworkpi-theme is installed, your image is likely healthy.
# Otherwise, if upstream renamed the session to LXDE-pi-labwc, update lightdm.conf safely:
sudo sed -i \
  -e 's/^user-session=rpd-labwc$/user-session=LXDE-pi-labwc/' \
  -e 's/^autologin-session=rpd-labwc$/autologin-session=LXDE-pi-labwc/' \
  /etc/lightdm/lightdm.conf

# 3. Fix any AccountsService entries to match
for f in /var/lib/AccountsService/users/*; do
  [ -f "$f" ] && sudo sed -i 's/^XSession=rpd-labwc$/XSession=LXDE-pi-labwc/' "$f"
done
```

### 2.3 — (Trixie path only) Remove raspberrypi-sys-mods

> **Kali users:** Skip 2.3 and 2.4. Your image doesn't ship `raspberrypi-sys-mods` and isn't layering Kali on top of Trixie.

`raspberrypi-sys-mods` (preinstalled on Rex's Trixie image) will collide with `kali-defaults` later. However, we must ensure removing it doesn't break the desktop:

```bash
# 1. Dry-run to see what would be removed
sudo apt -s remove raspberrypi-sys-mods

# IMPORTANT: If the output lists load-bearing Pi desktop packages like `rpd-*`, 
# `raspberrypi-ui-mods`, `pi-greeter`, `wf-panel-pi`, or `wayfire`, 
# DO NOT proceed with removal (it will give you a black screen).
# If those show up, SKIP to Step 2.4 and let `--force-overwrite` handle it in Step 3.

# 2. If only safe packages are listed, proceed:
sudo apt remove raspberrypi-sys-mods -y

# 3. Clean up stale diversion
EXTMGD=$(ls /usr/lib/python3.*/EXTERNALLY-MANAGED 2>/dev/null | head -1)
if [ -n "$EXTMGD" ]; then
  sudo rm -f "$EXTMGD"
  sudo dpkg-divert --package raspberrypi-sys-mods --remove --rename "$EXTMGD" 2>/dev/null
fi
```

### 2.4 — (Trixie path only) Add Kali rolling and pin it

Pinning Kali as the primary repo **before** the first big upgrade prevents the dependency-mismatch storm. We use a **NARROW pin** to grab tools while explicitly protecting Pi desktop libraries (`libfm`, `lxpanel`) from ABI-breaking Kali upgrades.

```bash
# Add Kali rolling repo
echo "deb http://http.kali.org/kali kali-rolling main contrib non-free non-free-firmware" \
  | sudo tee /etc/apt/sources.list.d/kali.list

# Import the Kali signing key
curl -fsSL https://archive.kali.org/archive-key.asc \
  | sudo gpg --dearmor -o /etc/apt/trusted.gpg.d/kali-archive-keyring.gpg

# 1. NARROW Kali pin (only Kali tools, block Kali system libs)
sudo tee /etc/apt/preferences.d/kali-pin <<'EOF'
Package: kali-* metasploit-framework
Pin: release o=Kali
Pin-Priority: 990

Package: aircrack-ng* bettercap* hydra* nmap responder impacket-* crackmapexec netexec wireshark* burpsuite sqlmap john* hashcat* gobuster ffuf nikto wpscan
Pin: release o=Kali
Pin-Priority: 990
EOF

# 2. Counter-pin: Keep Pi-archive versions of load-bearing desktop libs
sudo tee /etc/apt/preferences.d/uconsole-keep-pi-libs <<'EOF'
Package: libfm-data libfm-gtk-data libfm-modules libfm4t64 libfm-extra4t64 libfm-gtk3-4t64
Pin: release o=Raspberry Pi Foundation
Pin-Priority: 1001

Package: lxpanel lxpanel-data lxpanel-* libwf-* libwlroots-* wf-panel-pi wayfire
Pin: release o=Raspberry Pi Foundation
Pin-Priority: 1001

Package: pcmanfm raspberrypi-ui-mods rpd-* clockworkpi-theme pi-greeter pi-greeter-* labwc-prompt
Pin: release o=Raspberry Pi Foundation
Pin-Priority: 1001
EOF

sudo apt update
```

---

## Step 3: System Update and Initial Configuration

With Step 2 complete, it is now safe to update the system:

```bash
# First full system upgrade — Step 2 made this safe
sudo apt update
sudo apt full-upgrade -y

# If you see file-ownership collisions, force overwrite once:
sudo apt -o Dpkg::Options::="--force-overwrite" --fix-broken install -y

# Basic config
sudo dpkg-reconfigure tzdata
passwd
sudo hostnamectl set-hostname uconsole

sudo reboot
```

> **Note:** Rex's images already auto-expanded the root filesystem on first boot. `raspi-config --expand-rootfs` is not needed.

After the reboot, log back in. If LightDM hands you a working desktop, Step 2 did its job. 

---

## Step 4: Add Kali Tools (Trixie Only)

> **Skip this step on Rex's Kali image — the tools are already installed.**

The Kali repo and pin were added in Step 2.4. Now install the toolkit:

| Meta-Package | What You Get |
|---|---|
| `kali-tools-top10` | Core 10 tools: nmap, Metasploit, Burp, aircrack-ng, John, sqlmap, etc. |
| `kali-linux-headless` | Larger headless set: good for SSH-only or lightweight desktop use |
| `kali-linux-default` | Full default Kali desktop toolkit — everything you'd get from a Kali ISO |

```bash
# Pick one
sudo apt install kali-tools-top10 -y
# or
sudo apt install kali-linux-headless -y
# or
sudo apt install kali-linux-default -y

# If any file-ownership collisions occur during install:
sudo apt -o Dpkg::Options::="--force-overwrite" --fix-broken install -y
sudo apt full-upgrade -y
```

> **Tip:** Make force-overwrite persistent if you don't want to keep typing it:
> `echo 'Dpkg::Options { "--force-overwrite"; }' | sudo tee /etc/apt/apt.conf.d/99-force-overwrite`

---

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

`python3 ./aiov2_ctl.py --install` creates a Python venv at `~/.pygpsclient/` but runs as root, so the venv files are root-owned. The regular user can't launch `--gui` until ownership is corrected and PyQt6 is installed inside the venv:

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

The `hackergadgets-uconsole-aio-board` package does the heavy lifting: SDR++, tar1090, PyGPSClient, Meshtasticd, the OpenSUSE Meshtastic APT repo, RTC service, and desktop menu entries.

```bash
# 1. Ensure pcmanfm-pi exists for Rex's labwc autostart (Trixie workaround)
if [ ! -e /usr/bin/pcmanfm-pi ] && [ -x /usr/bin/pcmanfm ]; then
  sudo ln -sf /usr/bin/pcmanfm /usr/bin/pcmanfm-pi
fi

# 2. Inject legacy dependencies for Meshtasticd if missing
wget -q -O /tmp/libgpiod2.deb http://ftp.us.debian.org/debian/pool/main/libg/libgpiod/libgpiod2_1.6.3-1+b3_arm64.deb
wget -q -O /tmp/libyaml-cpp0.7.deb http://ftp.us.debian.org/debian/pool/main/y/yaml-cpp/libyaml-cpp0.7_0.7.0+dfsg-8+b1_arm64.deb
sudo dpkg -i /tmp/libgpiod2.deb /tmp/libyaml-cpp0.7.deb

# 3. Power on SDR LIVE so readsb/tar1090 detect it during installation
aiov2_ctl --sdr on
sleep 3

# 4. Install the AIO ecosystem and Web UI
sudo apt update
sudo apt --install-recommends install hackergadgets-uconsole-aio-board -y
sudo apt install meshtastic-mui -y

# 5. Install backend decoders explicitly to ensure aircraft.json generation
sudo bash -c "$(wget -q -O - https://github.com/wiedehopf/adsb-scripts/raw/master/readsb-install.sh)"
sudo bash -c "$(wget -nv -O - https://github.com/wiedehopf/tar1090/raw/master/install.sh)"

sudo reboot
```

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
CM5 lite modules shipped with older EEPROMs may fail to boot from the SD card. You likely need an EEPROM update (firmware must be newer than `2025-01-06`). Check the ClockworkPi forums for CM5 recovery/flashing guides.

### "Failed to start session" at LightDM login
See Step 2.2. If you skipped pre-flight hardening, you'll need to drop to a TTY (`Ctrl+Alt+F2`), install `labwc` / `lightdm-gtk-greeter`, and modify `/etc/lightdm/lightdm.conf` manually.

### GPS shows no data on `/dev/ttyAMA0`
* Confirm `dtparam=uart0` is in `/boot/firmware/config.txt` and you've rebooted.
* Confirm `console=serial0,115200` is removed from `/boot/firmware/cmdline.txt`.
* Confirm GPS power rail is enabled: `aiov2_ctl GPS on`.

### LoRa / Meshtasticd fails to start
* Verify devterm-printer.service is disabled: `sudo systemctl status devterm-printer.service`.
* Confirm SPI overlay in config.txt: `dtoverlay=spi1-1cs`.
* Check LoRa power rail: `aiov2_ctl LORA on`.

### `libfm` ABI Mismatch (symbol lookup error)
If opening pcmanfm or lxpanel yields `symbol lookup error: undefined symbol: fm_cell_renderer_pixbuf_get_scale`, Kali's `libfm` packages have overwritten the Pi-specific ones. Re-apply the counter-pin in Step 2.4 and `sudo apt update && sudo apt install --reinstall libfm-modules lxpanel pcmanfm`.

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

Also ensure `libxcb-cursor0` is installed — the Qt6 XCB platform plugin won't load without it:

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

Symptom: `GDBus.Error:org.freedesktop.PolicyKit1.Error.Failed: An authentication agent already exists for the given subject` in journalctl at login.

Kali metapackages install `polkit-mate-authentication-agent-1`, which conflicts with `lxpolkit` on Labwc. Suppress it with an XDG per-user override:

```bash
mkdir -p ~/.config/autostart
cp /etc/xdg/autostart/polkit-mate-authentication-agent-1.desktop ~/.config/autostart/
echo "Hidden=true" >> ~/.config/autostart/polkit-mate-authentication-agent-1.desktop
```

Log out and back in to confirm the error is gone.

---

## Resources and Links

* [HackerGadgets AIO V1/V2 Setup Guide](https://hackergadgets.com/pages/hackergadgets-uconsole-rtl-sdr-lora-gps-rtc-usb-hub-all-in-one-extension-board-setup-guide)
* [aiov2_ctl GitHub Repo](https://github.com/hackergadgets/aiov2_ctl)
* [Rex's AIO Board Package Thread](https://forum.clockworkpi.com/t/hackergadgets-aio-board-package/17875)
* [Rex's Trixie Image](https://forum.clockworkpi.com/t/trixie-6-12-y-for-the-uconsole-and-devterm/19457)
