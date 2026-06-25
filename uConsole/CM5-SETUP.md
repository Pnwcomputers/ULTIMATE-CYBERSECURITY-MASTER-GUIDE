# uConsole Field Platform Setup Guide: CM5 Configuration

## Rex's Kali or Trixie + HackerGadgets AIO v2 Board

A complete setup guide for building a field-deployable hacking and SIGINT platform using the ClockworkPi uConsole with a Raspberry Pi CM5, Rex's community images (Kali Linux or Debian Trixie), and the HackerGadgets AIO v2 extension board.

---

## Table of Contents

- [Hardware Overview](#hardware-overview)
- [Choosing Your OS: Kali vs Trixie](#choosing-your-os--kali-vs-trixie)
- [Step 1: Flash the OS](#step-1--flash-the-os)
- [Step 2: First Boot and Initial Setup](#step-2--first-boot-and-initial-setup)
- [Step 2.5: Install Kali Tools on Trixie (Trixie Only)](#step-25--install-kali-tools-on-trixie-trixie-only)
- [Step 3: Install the AIO v2 Board Package](#step-3--install-the-aio-v2-board-package)
- [Step 4: Install aiov2_ctl (GPIO Control Tool)](#step-4--install-aiov2_ctl-gpio-control-tool)
- [Step 5: Configure GPS (CM5)](#step-5--configure-gps-CM5)
- [Step 6: Configure LoRa / Meshtasticd](#step-6--configure-lora--meshtasticd)
- [Step 7: Configure RTC](#step-7--configure-rtc)
- [Step 8: Configure SDR](#step-8--configure-sdr)
- [Step 9: GPIO Power Control](#step-9--gpio-power-control)
- [Step 10: WiFi Pentesting Setup](#step-10--wifi-pentesting-setup)
- [Step 11: LAN Pentesting via RJ45](#step-11--lan-pentesting-via-rj45)
- [Step 12: NVMe Battery Board Setup](#step-12--nvme-battery-board-setup)
- [CM5-Specific Notes and Limitations](#cm5-specific-notes-and-limitations)
- [AIO v2 Board: Hardware Reference](#aio-v2-board--hardware-reference)
- [aiov2_ctl: Full Command Reference](#aiov2_ctl--full-command-reference)
- [Meshtasticd Web Interface](#meshtasticd-web-interface)
- [Boot Automation](#boot-automation)
- [Troubleshooting](#troubleshooting)
- [Resources and Links](#resources-and-links)

---

## Hardware Overview

This guide assumes the following hardware stack:

| Component | Detail |
|---|---|
| **Handheld** | ClockworkPi uConsole |
| **Compute Module** | Raspberry Pi CM5 (with HackerGadgets CM5/CM5 adapter board) |
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

> **Critical Assembly Note:** When installing the AIO v2 board, ensure the ribbon cable is oriented correctly as shown in the HackerGadgets documentation. **Never plug in the charger if the ribbon cable is installed the wrong way**: incorrect installation will damage the uConsole mainboard.

---

## Choosing Your OS: Kali vs Trixie

Rex maintains community images for the uConsole that include a custom kernel (6.12.y) with all the necessary hardware patches for the uConsole display, keyboard, and trackball. His images also include a custom APT repository that is **required** for the `hackergadgets-uconsole-aio-board` package: this package is not available on stock ClockworkPi images.

This guide covers two recommended paths:

### Path A: Rex's Kali Image (Pentesting Out of the Box)

The full Kali toolchain comes pre-installed: aircrack-ng, bettercap, responder, impacket, crackmapexec, nmap, Wireshark, Metasploit, Burp, etc. No additional tool installation needed. Best for users who want a ready-made pentest platform.

**Pros:** Everything pre-installed, Kali community support, familiar to pentesters.
**Cons:** Can hit package conflicts with `cryptsetup-initramfs` during AIO board setup (see Step 3). Trackball slightly less responsive than on Bookworm/Trixie.

### Path B: Rex's Trixie Image + Kali Tools (Recommended)

Debian 13 (Trixie) base with the newest upstream packages, plus the Kali rolling repo added on top for pentesting tools. Most current base system, fewer package conflicts, same AIO board support.

**Pros:** Newest packages, cleaner base, fewer initramfs/package conflicts, best trackball behavior alongside Bookworm.
**Cons:** Extra step to add Kali tools. Mixing Kali rolling repo with Trixie can occasionally create version conflicts (mitigated with APT pinning).

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
- Look for the MEGA download link in the first post
- Ensure you grab the image labeled with kernel **6.12.67** or later (new screen support)

**Trixie:**
- **Thread:** [Trixie 6.12.y for the uConsole and DevTerm](https://forum.clockworkpi.com/t/trixie-6-12-y-for-the-uconsole-and-devterm/19457)
- Same process: MEGA link in the first post, kernel 6.12.67+

### Flash the Image

1. Extract the `.7z` archive:
   ```bash
   7z x <image-filename>.7z
   ```

2. Flash to a microSD card (16 GB minimum, 32+ GB recommended):

   **Linux:**
   ```bash
   sudo dd if=<image-filename>.img of=/dev/sdX bs=4M status=progress conv=fsync
   ```

   **Windows/macOS:**
   Use [balenaEtcher](https://etcher.balena.io/) to flash the `.img` file.

3. Insert the microSD card into the uConsole and boot.

---

## Step 2: First Boot and Initial Setup

### Default Credentials

Verify in the forum thread for your image as these may change.

**Kali:**
```
Username: kali
Password: kali
```

**Trixie:**
```
Username: pi
Password: clockworkpi
```

### Post-Boot Setup (Both Images)

```bash
# Update the system
sudo apt update && sudo apt full-upgrade -y

# Set your timezone
sudo dpkg-reconfigure tzdata

# Change the default password
passwd

# Optionally set hostname
sudo hostnamectl set-hostname uconsole

# Expand filesystem if not auto-expanded
sudo raspi-config --expand-rootfs
sudo reboot
```

---

## Step 2.5: Install Kali Tools on Trixie (Trixie Only)

> **Skip this step if you are using Rex's Kali image: the tools are already installed.**

Add the Kali rolling repository and import the signing key:

```bash
# Add the Kali rolling repo
echo "deb http://http.kali.org/kali kali-rolling main contrib non-free non-free-firmware" | sudo tee /etc/apt/sources.list.d/kali.list

# Import the Kali signing key
curl -fsSL https://archive.kali.org/archive-key.asc | sudo gpg --dearmor -o /etc/apt/trusted.gpg.d/kali-archive-keyring.gpg

sudo apt update
```

### Fix dpkg-divert Conflict BEFORE Installing (Required)

The `raspberrypi-sys-mods` package (pre-installed on all Rex images) conflicts with Kali packages in two ways:

1. **Diversion clash:** Both `raspberrypi-sys-mods` and `kali-defaults` try to divert `/usr/lib/python3.13/EXTERNALLY-MANAGED` but to different target filenames, which hard-fails the install.

2. **File ownership collision:** Even after fixing the diversion, `raspberrypi-sys-mods` and Kali's `libpython3.13-stdlib` both claim ownership of the same file, causing `dpkg` to refuse to unpack upgrades.

The cleanest fix is to remove `raspberrypi-sys-mods` entirely before installing any Kali packages. At this point your system is becoming a Kali box with Rex's kernel: `raspberrypi-sys-mods` will just keep fighting you on every upgrade.

```bash
# Remove the conflicting package
sudo apt remove raspberrypi-sys-mods -y

# Clean up any diversion it left behind
sudo rm -f /usr/lib/python3.13/EXTERNALLY-MANAGED
sudo dpkg-divert --package raspberrypi-sys-mods --remove --rename /usr/lib/python3.13/EXTERNALLY-MANAGED 2>/dev/null
```

> **Note:** Check what `apt remove raspberrypi-sys-mods` wants to pull out with it. If it tries to remove kernel or device tree packages, cancel and use the force-overwrite approach instead (see [Troubleshooting](#troubleshooting)).

> **Note:** The Python version in the path (`python3.13`) may differ depending on when you install. Check with `ls /usr/lib/python3.*/EXTERNALLY-MANAGED` if the above path doesn't exist.

### Set Kali as the Primary Package Source (Required)

Once you start installing Kali packages, Kali's versions of core runtime libraries (`libssl3t64`, `libbluetooth3`, `libcurl3t64-gnutls`, Qt6, etc.) get upgraded past what Trixie carries. From that point on, **every** `apt install` that touches those libraries will fail with version mismatch errors unless the packages come from Kali too: including the Meshtasticd `-dev` dependencies in [Step 6](#step-6--configure-lora--meshtasticd) and anything else you install later.

Set Kali as the default high-priority repo **before** installing any Kali packages:

```bash
sudo tee /etc/apt/preferences.d/kali-pin <<'EOF'
Package: *
Pin: release o=Kali
Pin-Priority: 900
EOF

sudo apt update
```

This makes Kali rolling the primary package source. Trixie and Rex's repo fill in anything Kali doesn't carry (like the AIO board package and uConsole-specific kernel packages). Your system is effectively a Kali box running Rex's kernel and hardware patches: which is exactly what you want for a pentest platform.

### Choose Your Toolkit

Pick one based on how much you want installed:

| Meta-Package | What You Get |
|---|---|
| `kali-tools-top10` | Core 10 tools: nmap, Metasploit, Burp, aircrack-ng, John, sqlmap, etc. |
| `kali-linux-headless` | Larger headless set: good for SSH-only or lightweight desktop use |
| `kali-linux-default` | Full default Kali desktop toolkit: everything you'd get from a Kali ISO |

```bash
# Example: install the core top 10
sudo apt install kali-tools-top10 -y

# Or go bigger
sudo apt install kali-linux-headless -y

# If any file ownership collisions occur during install
sudo apt -o Dpkg::Options::="--force-overwrite" --fix-broken install -y
sudo apt full-upgrade -y
```

---

## Step 3: Install the AIO v2 Board Package

Rex's custom APT repo is pre-configured on his images. The AIO board package installs everything needed for the AIO v2 ecosystem in one command.

### Fix cryptsetup-initramfs BEFORE Installing (Critical)

The AIO board package (or its dependency chain) can pull in `cryptsetup-initramfs` as a recommended package. On CM5, the initramfs hook tries to resolve `/dev/root` and hard-fails because the Pi uses `PARTUUID=` in cmdline.txt. This returns exit code 1, which kills the entire `dpkg` post-install trigger and leaves your system in a broken package state. If this happens during a kernel-related package install, **it can corrupt your initramfs and leave the system unbootable.**

Pre-empt this before installing anything:

```bash
sudo mkdir -p /etc/cryptsetup-initramfs
echo "CRYPTSETUP=n" | sudo tee /etc/cryptsetup-initramfs/conf-hook
```

This tells the cryptsetup initramfs hook to skip its root device detection entirely. Unless you are setting up LUKS full-disk encryption, this is exactly what you want.

### Install the Package

```bash
sudo apt update
sudo apt install hackergadgets-uconsole-aio-board -y
sudo reboot
```

### What This Package Installs

| Package | Function |
|---|---|
| `hackergadgets-uconsole-aio-board` | Core AIO v2 integration: GPIO, power rails, RTC support, services, uConsole-specific configuration |
| `meshtastic-mui` | Meshtastic graphical UI for LoRa/Meshtastic devices |
| `sdrpp-brown` | Preconfigured SDR++ build for the uConsole (RF scanning/listening) |
| `tar1090` | ADS-B aircraft tracking web UI (visualizes planes from your SDR feed) |
| `pygpsclient` | GPS monitoring and diagnostics GUI (position, satellites, NMEA data) |

It also sets up supporting services (RTC, GPIO helpers, and desktop menu entries).

---

## Step 4: Install aiov2_ctl (GPIO Control Tool)

`aiov2_ctl` is HackerGadgets' official control tool for the AIO v2 board. It provides both CLI and system tray GUI for toggling peripherals on/off, monitoring power, and configuring boot states.

```bash
# Install dependencies
sudo apt update
sudo apt install -y python3 python3-pyqt6 git

# Clone and install
git clone https://github.com/hackergadgets/aiov2_ctl.git
cd aiov2_ctl
sudo python3 ./aiov2_ctl.py --install

# Verify installation
aiov2_ctl
aiov2_ctl --status
```

### Optional: Install AIO Companion Apps via aiov2_ctl

If you did not install the `hackergadgets-uconsole-aio-board` package in Step 3, you can install the companion apps through `aiov2_ctl`:

```bash
sudo aiov2_ctl --add-apps
```

### Enable GUI Autostart (Recommended)

```bash
aiov2_ctl --autostart
```

This creates an XDG autostart entry so the system tray icon launches on login.

---

## Step 5: Configure GPS (CM5)

### CM5-Specific GPS Path

On CM5, the GPS serial port is `/dev/ttyAMA0` (NOT `/dev/ttyAMA0` which is for CM5).

### Free the Serial Port

The serial console must be disabled or GPS will not work continuously. Edit `/boot/firmware/cmdline.txt` and **remove** `console=serial0,115200`:

```bash
sudo nano /boot/firmware/cmdline.txt
```

Find and delete `console=serial0,115200` from the line. Save and exit.

### Add Serial Port Permissions

To read from `/dev/ttyAMA0` without `sudo` (important for GUI tools like `pygpsclient` running in user-space), add your user to the `dialout` group:

```bash
sudo usermod -a -G dialout $USER
```

> **Note:** You need to log out and back in (or reboot) for the group membership to take effect.

### Enable GPIO for GPS

```bash
# Turn on GPS power rail
aiov2_ctl GPS on

# Or manually via pinctrl:
pinctrl set 27 op dh   # GPIO 27 = GPS
```

### Verify GPS

```bash
# Check for GPS data stream
cat /dev/ttyAMA0

# Or use pygpsclient (installed by the AIO board package)
pygpsclient
```

You should see NMEA sentences streaming. Make sure you have a GPS antenna connected to the IPEX connector labeled "GPS" on the AIO v2 board.

### PPS Output (Advanced)

The GPS has a PPS (pulse-per-second) output on GPIO 6 for microsecond-level timing accuracy. To configure PPS, add to `/boot/firmware/config.txt`:

```
dtoverlay=pps-gpio,gpiopin=6
```

---

## Step 6: Configure LoRa / Meshtasticd

### Prerequisites: SPI and Service Conflicts

Add the following to `/boot/firmware/config.txt`:

```
dtparam=spi=on
dtoverlay=spi1-1cs
```

**Disable the devterm-printer service**: it uses SPI1 GPIO and will conflict with LoRa:

```bash
sudo systemctl stop devterm-printer.service
sudo systemctl disable devterm-printer.service
```

### Enable GPIO for LoRa

```bash
aiov2_ctl LORA on

# Or manually:
pinctrl set 22 op dh   # GPIO 22 = LoRa
```

### Install Meshtasticd Dependencies

> **Trixie + Kali users:** If you haven't set the Kali APT pin from [Step 2.5](#step-25--install-kali-tools-on-trixie-trixie-only), these `-dev` packages will fail with version mismatches against the Kali-upgraded runtime libraries. Either set the pin first or add `-t kali-rolling` to this command.

```bash
sudo apt install libgpiod-dev libyaml-cpp-dev libbluetooth-dev \
  libusb-1.0-0-dev libi2c-dev openssl libssl-dev libulfius-dev liborcania-dev
```

### Install Meshtasticd

The `meshtasticd` binary is not in the standard Debian or Kali repos: download the `.deb` package from the Meshtastic firmware releases page:

```bash
# Download the latest arm64 package (check GitHub for the current version)
wget https://github.com/meshtastic/firmware/releases/download/v2.3.13/meshtasticd_2.3.13_arm64.deb

# Install it
sudo dpkg -i meshtasticd_*_arm64.deb
sudo apt --fix-broken install -y
```

> **Note:** Check the [Meshtastic firmware releases](https://github.com/meshtastic/firmware/releases) page for the latest version. Replace `v2.3.13` with the current release tag.

### Configure Meshtasticd

Edit `/etc/meshtasticd/config.yaml`:

```yaml
Lora:
  Module: sx1262
  DIO2_AS_RF_SWITCH: true
  DIO3_TCXO_VOLTAGE: true
  IRQ: 26
  Busy: 24
  Reset: 25
  spidev: spidev1.0

GPS:
  SerialPath: /dev/ttyAMA0    # CM5 path: use /dev/ttyS0 for CM5

Webserver:
  Port: 443
  RootPath: /usr/share/meshtasticd/web
```

### SX1262 Pin Reference for AIO v2

| Function | GPIO Pin |
|---|---|
| SPI Bus | SPI1 |
| Chip Select | SPI1-CE0 (GPIO 18) |
| DIO2 (RF Switch) | Controlled by SX1262 |
| DIO3 (TCXO Voltage) | Controlled by SX1262 |
| IRQ | GPIO 26 |
| Busy | GPIO 24 |
| Reset | GPIO 25 |

### Create Meshtasticd Systemd Service

```bash
sudo nano /etc/systemd/system/meshtasticd.service
```

```ini
[Unit]
Description=Meshtastic Daemon
After=network.target

[Service]
ExecStart=/usr/sbin/meshtasticd
Restart=always
User=root
Group=root
Type=simple

[Install]
WantedBy=multi-user.target
```

```bash
sudo systemctl daemon-reload
sudo systemctl enable meshtasticd.service
sudo systemctl start meshtasticd.service

# Check status
sudo systemctl status meshtasticd.service
```

### Connect an Antenna

Connect a 433/915 MHz antenna (depending on your region) to the IPEX connector labeled **"LoRa"** on the AIO v2 board.

> **Important:** After first start, open the Meshtastic web interface and set your LoRa region under Config → LoRa. Different regions cannot communicate with each other. For US operation, select **US** (915 MHz band).

---

## Step 7: Configure RTC

The RTC (PCF85063A) requires manual configuration. The CM5 has its own internal RTC that must be disabled first so it doesn't conflict with the AIO v2's external RTC. Add the following to `/boot/firmware/config.txt`:

```
# Disable the CM5 internal RTC
dtparam=rtc=off

# I2C and external RTC: remap i2c0 to GPIO38/39 on CM5
dtparam=i2c_arm=on
dtoverlay=i2c-rtc,pcf85063a,i2c_csi_dsi0
```

Reboot, then verify:

```bash
sudo hwclock -r
```

If successful, you should see the current date/time output.

### Sync System Time to RTC

After confirming your system time is correct (via NTP or manual set):

```bash
# Via aiov2_ctl
sudo aiov2_ctl --sync-rtc

# Or manually
sudo hwclock -w
```

> **Note:** Make sure the CR1220 battery is installed in the RTC socket on the AIO v2 board. If `hwclock -r` returns nothing, check the battery orientation.

---

## Step 8: Configure SDR

### Enable GPIO for SDR

```bash
aiov2_ctl SDR on

# Or manually:
pinctrl set 7 op dh   # GPIO 7 = SDR
```

### Blacklist the DVB-T Kernel Driver

The Linux kernel will try to claim the RTL2832U/R828D chip as a DVB-T television tuner by default, which blocks SDR software from accessing the hardware. Blacklist the default driver:

```bash
# Blacklist the default DVB-T driver
echo "blacklist dvb_usb_rtl28xxu" | sudo tee /etc/modprobe.d/blacklist-rtl.conf

# Remove the module if it's already loaded (or reboot)
sudo rmmod dvb_usb_rtl28xxu 2>/dev/null
```

### Launch SDR++

SDR++ (the `sdrpp-brown` build) is installed by the AIO board package:

```bash
sdrpp
```

Connect an antenna to the IPEX connector labeled **"SDR"** on the AIO v2 board. The RTL-SDR covers 100 kHz to 1.74 GHz with a 5V bias tee for active antennas and LNAs.

### ADS-B Tracking

`tar1090` is installed by the AIO board package and provides a web-based ADS-B aircraft tracking UI. After enabling the SDR and configuring dump1090, access it at `http://localhost/tar1090`.

---

## Step 9: GPIO Power Control

### AIO v2 GPIO Pin Map

| GPIO Pin | Peripheral | Notes |
|---|---|---|
| GPIO 27 | GPS | Pull HIGH to enable |
| GPIO 22 | LoRa | Pull HIGH to enable |
| GPIO 7 | SDR (RTL-SDR) | Pull HIGH to enable |
| GPIO 6 | Internal USB (USB-C + pin header) | Pull HIGH to enable |

### CM5 Boot Behavior

On CM5, **GPIO 7 (SDR) starts powered on by default.** All other peripherals (GPS, LoRa, Internal USB) start powered off and must be explicitly enabled. This means the RTL-SDR will be detected immediately after boot without any GPIO configuration, but GPS and LoRa still need to be turned on.

### Using aiov2_ctl (Recommended)

```bash
# Show current GPIO state
aiov2_ctl

# Show detailed status with battery/power info
aiov2_ctl --status

# Toggle peripherals on/off
aiov2_ctl GPS on
aiov2_ctl LORA on
aiov2_ctl SDR on
aiov2_ctl USB on

aiov2_ctl GPS off
aiov2_ctl SDR off

# Live power monitoring
aiov2_ctl --power

# Compact live GPIO + power view
aiov2_ctl --watch
```

### Configure Boot Defaults

Set peripherals to auto-enable at boot:

```bash
# Set GPS and LoRa to come up automatically
aiov2_ctl --boot-rail GPS on
aiov2_ctl --boot-rail LORA on
aiov2_ctl --boot-rail SDR on

# Check boot rail configuration
aiov2_ctl --boot-rails-status
```

Boot rail settings are applied by the `aiov2-rails-boot.service` (installed automatically with `aiov2_ctl --install`).

### Manual GPIO Control (Without aiov2_ctl)

```bash
# Enable GPS
pinctrl set 27 op dh

# Enable LoRa
pinctrl set 22 op dh

# Enable SDR
pinctrl set 7 op dh

# Enable Internal USB
pinctrl set 6 op dh

# Disable SDR
pinctrl set 7 op dl
```

### GUI Mode

```bash
aiov2_ctl --gui
```

Left-click the tray icon for a status window; right-click for toggle controls. The right-click menu also includes a "Rails on boot" submenu for persistent boot preferences.

---

## Step 10: WiFi Pentesting Setup

The CM5's onboard WiFi **does not support monitor mode**. You need an external USB WiFi adapter.

### Recommended Adapters

| Adapter | Chipset | Notes |
|---|---|---|
| HackerGadgets AC1200 USB-C WiFi Card | RTL8812AU | Sold separately from the Upgrade Kit, monitor mode supported |
| Alfa AWUS036ACH | RTL8812AU | Proven pentesting adapter |
| Alfa AWUS036ACSM | RTL8812AU | Smaller form factor |
| Any RTL8812AU/RTL8814AU adapter | RTL8812AU/RTL8814AU | Widely available, well-supported |

> **Note:** With the Upgrade Kit adapter board, CM5 supports USB 3.0 for external adapters. Without the Upgrade Kit, USB speed is limited to 2.0.

### Install the DKMS Driver (Required on Both Kali and Trixie)

RTL8812AU/RTL8814AU chipsets are **not supported by the mainline Linux kernel**. The driver is a DKMS module that must be installed separately: it is not baked in even on Kali. Without it, `iwconfig` will not see the adapter.

```bash
sudo apt install realtek-rtl88xxau-dkms -y
```

### Verify Monitor Mode

```bash
# List wireless interfaces
iwconfig

# Check adapter capabilities
iw list | grep -A 10 "Supported interface modes"

# Enable monitor mode
sudo airmon-ng start wlan1    # wlan1 = external adapter (wlan0 = onboard)

# Verify
iwconfig wlan1mon
```

### Common Pentest Toolkit

These tools are pre-installed on Kali. On Trixie, install them via the Kali meta-packages in [Step 2.5](#step-25--install-kali-tools-on-trixie-trixie-only).

```bash
# Wireless
aircrack-ng, airodump-ng, aireplay-ng, airmon-ng
bettercap
kismet
wifite

# Network
nmap, masscan
responder
impacket-scripts
crackmapexec / netexec
wireshark / tshark
tcpdump

# Exploitation
metasploit-framework
burpsuite
sqlmap
```

---

## Step 11: LAN Pentesting via RJ45

The AIO v2 provides Gigabit Ethernet via the RJ45 port. This requires the **HackerGadgets adapter board** from the Upgrade Kit: without it, the RJ45 port will not function.

With the adapter board installed, you can use the uConsole as a network tap or drop box:

```bash
# Plug into a target switch, check for DHCP
sudo dhclient eth0

# Verify connectivity
ip addr show eth0

# Quick network scan
sudo nmap -sn 192.168.1.0/24

# Run Responder for credential capture
sudo responder -I eth0 -wrf

# Full port scan
sudo nmap -sS -sV -O -p- 192.168.1.0/24
```

---

## Step 12: NVMe Battery Board Setup

The HackerGadgets NVMe Battery Board replaces the stock uConsole battery board, combining NVMe SSD storage with the battery compartment in a single PCB. This is part of the HackerGadgets Upgrade Kit and requires the HackerGadgets adapter board.

### Hardware Overview

| Feature | Detail |
|---|---|
| NVMe Slot | M.2 M-key, supports 2230 through 2280 form factors |
| Battery | Two variants: dual 18650 holder, or LiPo battery pack |
| Reverse Protection | Improved: no heat generated on reverse battery insertion; warning LED lights up |
| Power Switch Mod | Desolder R14, connect a push-lock switch to J6 for manual on/off control |
| Requires | HackerGadgets adapter board (from Upgrade Kit) |

> **Important:** The NVMe feature requires the HackerGadgets adapter board. The NVMe Battery Board alone will not provide NVMe functionality without it.

### Board Variants

The NVMe Battery Board comes in two configurations:

- **With Dual 18650 Battery Holder**: fits two standard 18650 cells side by side (the more common choice)
- **Without Battery Holder**: designed for use with a LiPo battery pack wired in directly

### Physical Installation

1. Remove the stock uConsole battery board
2. Install the HackerGadgets adapter board (connects the CM5 to the NVMe Battery Board via ribbon cable)
3. Seat the NVMe Battery Board in place of the stock battery board
4. Connect the ribbon cable between the adapter board and the NVMe Battery Board

> **Critical:** Check ribbon cable orientation carefully. An incorrectly installed ribbon cable can prevent boot. If the uConsole won't boot after installation, the cable is likely flipped. **Never plug in the charger with a reversed ribbon cable**: this will damage the mainboard.

5. Insert your NVMe SSD into the M.2 slot (2230 is the most compact; 2242 and 2280 also fit)
6. Install your 18650 batteries or connect your LiPo pack

### NVMe Software Configuration (CM5)

#### Enable PCIe in config.txt

Add the following to `/boot/firmware/config.txt`:

```
dtparam=pciex1
```

Or if your image already has it set to off, change it:

```
dtparam=pciex1=on
```

Reboot and verify the NVMe drive is detected:

```bash
lspci                    # Should show the NVMe controller
lsblk                   # Should show nvme0n1
sudo fdisk -l /dev/nvme0n1   # Full partition info
```

#### CM5 EEPROM: No Update Required

The CM5 has native PCIe and NVMe boot support. Unlike the CM5, **you do not need to update the EEPROM** for NVMe detection or boot. Simply add `dtparam=pciex1` to config.txt and the NVMe drive will be detected automatically.

### Cloning SD Card to NVMe

The easiest way to migrate your working Kali setup from microSD to NVMe:

#### Method 1: rpi-clone (Recommended)

```bash
# Install rpi-clone
git clone https://github.com/billw2/rpi-clone.git
cd rpi-clone
sudo cp rpi-clone /usr/local/sbin/

# Clone SD card to NVMe (device is nvme0n1 inside the uConsole)
sudo rpi-clone nvme0n1
```

Follow the prompts. rpi-clone handles partition resizing and UUID updates automatically.

#### Method 2: SD Card Copier (GUI)

If you're running a desktop environment, the built-in SD Card Copier utility (available in Rex's Trixie and Bookworm) can copy from SD to NVMe. Select your SD card as source and the NVMe drive as destination.

> **Tip from the community:** Consider adding `dtparam=pciex1_gen=2` to config.txt to cap the PCIe link at Gen 2 speed for improved stability. The CM5's PCIe is Gen 2 natively, so this just ensures no negotiation issues with certain drives.

### Booting from NVMe

Once the NVMe drive has a bootable OS image:

#### Option A: NVMe as Primary Boot (Remove SD Card)

If BOOT_ORDER in the EEPROM includes NVMe (`6`), simply remove the microSD card and the CM5 will fall through to NVMe boot.

#### Option B: Dual Boot (SD + NVMe)

Set the EEPROM boot order to SD first, NVMe second (`BOOT_ORDER=0xf61`). This gives you a simple dual-boot setup:

- **SD card inserted** → boots from SD
- **SD card removed** → boots from NVMe

This is useful for keeping different OS configurations (e.g., Kali on NVMe for daily use, DragonOS on an SD card for SDR sessions).

### EEPROM Note (CM5)

The CM5 does not require EEPROM modifications for NVMe boot. If your NVMe drive is not detected, verify `dtparam=pciex1` is set in config.txt and that the ribbon cable between the adapter board and NVMe battery board is correctly oriented.

### Optional: Hardware Power Switch Mod

The NVMe Battery Board includes provision for a physical power switch: a nice feature for field use where you want to fully power down without pulling batteries:

1. Desolder resistor **R14** on the NVMe Battery Board
2. Solder a push-lock (latching) switch to the **J6** pads
3. When the switch is locked → battery power is on
4. When the switch is released → battery power is completely off

A community member documented using an **SMD MSK12C02** slide switch that sits flush at the side panel for a clean, non-destructive, reversible installation.

### Troubleshooting NVMe

**NVMe not detected (`lspci` shows nothing):**

- Verify `dtparam=pciex1=on` (not `off`) in `/boot/firmware/config.txt`
- Reseat the ribbon cable between the adapter board and NVMe battery board: try flipping it if needed
- Try the NVMe drive in a USB enclosure on another machine to confirm the drive itself works
- Check for a faulty ribbon cable (broken traces)

**NVMe detected but won't boot:**

- Ensure a bootable OS image is on the NVMe (flash with Raspberry Pi Imager to a USB enclosure first, then move the drive)
- Check EEPROM boot order includes NVMe: `sudo CM5_ENABLE_RPI_EEPROM_UPDATE=1 rpi-eeprom-config`
- Verify the NVMe partition has boot files: `sudo mount /dev/nvme0n1p1 /mnt && ls /mnt`

**Intermittent boot failures or PCIe errors in dmesg:**

- Add `dtparam=pciex1_gen=2` to config.txt to force Gen 2 negotiation
- Some Gen 4 NVMe drives have link training issues when negotiating down to Gen 2; try a different drive if problems persist

---

## CM5-Specific Notes and Limitations

| Item | CM5 Detail |
|---|---|
| GPS Serial Port | `/dev/ttyAMA0` (CM5 uses `/dev/ttyS0`) |
| USB Speed | USB 3.0 with Upgrade Kit adapter board (USB 2.0 without) |
| GPIO Boot State | GPIO 7 (SDR) starts ON; GPS, LoRa, USB start OFF |
| Stability | Newer, improving rapidly: occasional rough edges vs CM5 |
| RTC Config | Must disable internal RTC: `dtparam=rtc=off` + `dtoverlay=i2c-rtc,pcf85063a,i2c_csi_dsi0` |
| Serial Console | Must remove `console=serial0,115200` from cmdline.txt for GPS |
| SPI Conflict | Must disable `devterm-printer.service` for LoRa |
| Onboard WiFi | Does NOT support monitor mode: external adapter required |
| RJ45 Ethernet | Requires HackerGadgets adapter board from Upgrade Kit |
| PCIe | Native PCIe support: no EEPROM update needed for NVMe |
| Internal RTC | Must be disabled (`dtparam=rtc=off`) to use AIO v2's PCF85063A |

---

## AIO v2 Board: Hardware Reference

### Antenna Connectors

The AIO v2 has three IPEX antenna connectors labeled on the board:

| Label | Purpose | Antenna Type |
|---|---|---|
| **SDR** | RTL-SDR receiver | Wideband antenna or frequency-specific antenna |
| **LoRa** | SX1262 transceiver | 433 or 915 MHz antenna (region-dependent) |
| **GPS** | GPS/BDS/GNSS receiver | Active or passive GPS antenna |

The antenna mounting kit (sold with some variants) supports up to 7 antennas.

### RTL-SDR Specs

| Spec | Value |
|---|---|
| Tuner Chip | R828D |
| Frequency Range | 100 kHz – 1.74 GHz |
| Clock | TCXO (temperature-compensated, near-zero drift) |
| Bias Tee | 5V (for active antennas and LNAs) |

### LoRa / SX1262 Specs

| Spec | Value |
|---|---|
| Chip | SX1262 |
| Frequency Band | 860–960 MHz |
| Max Output Power | 22 dBm |
| Clock | TCXO |
| SPI Bus | SPI1 (spidev1.0) |

---

## aiov2_ctl: Full Command Reference

```
aiov2_ctl                           # Show current GPIO state
aiov2_ctl --status                  # Detailed status (GPIO + battery + power)
aiov2_ctl <FEATURE> <on|off>        # Toggle: GPS, LORA, SDR, USB
aiov2_ctl --power                   # Live power monitor (Ctrl+C to exit)
aiov2_ctl --watch                   # Compact live GPIO + power line
aiov2_ctl --gui                     # Launch system tray GUI
aiov2_ctl --autostart               # Enable GUI autostart on login
aiov2_ctl --no-autostart            # Disable GUI autostart
aiov2_ctl --boot-rail <FEAT> on     # Set peripheral to enable at boot
aiov2_ctl --boot-rail <FEAT> off    # Set peripheral to stay off at boot
aiov2_ctl --boot-rail <FEAT> status # Check boot state for a peripheral
aiov2_ctl --boot-rails-status       # Show all boot rail configurations
aiov2_ctl --sync-rtc                # Write system time to hardware RTC
aiov2_ctl --update                  # Pull latest version and reinstall
sudo aiov2_ctl --add-apps           # Install AIO companion apps
sudo aiov2_ctl --remove-apps        # Remove AIO companion apps
```

### Debug Mode

```bash
AIOV2_CTL_DEBUG=1 aiov2_ctl --status
```

Shows state source labels: `(pinctrl)` for direct hi/lo, `(boot_default)` for fallback, `(unknown)` for unparseable reads.

---

## Meshtasticd Web Interface

Meshtasticd includes a built-in web server (available in Meshtastic firmware 2.3.0+).

1. Ensure the webserver is enabled in `/etc/meshtasticd/config.yaml`:
   ```yaml
   Webserver:
     Port: 443
     RootPath: /usr/share/meshtasticd/web
   ```

2. Open a browser on the uConsole and navigate to `https://localhost`

3. If you get an SSL warning, click "Proceed to localhost (unsafe)"

4. To connect, enter `localhost` in the IP Address field (not `meshtastic.local`)

5. First-time setup: Go to **Config → LoRa** and set your region (e.g., US for 915 MHz)

6. Use the **Messages** menu to send/receive on the public channel or between individual nodes

---

## Boot Automation

### Recommended Boot Configuration

For a field-ready setup, configure all needed peripherals to come up automatically:

```bash
# Set boot rails
aiov2_ctl --boot-rail GPS on
aiov2_ctl --boot-rail LORA on
aiov2_ctl --boot-rail SDR on

# Enable GUI tray on login
aiov2_ctl --autostart

# Enable Meshtasticd on boot
sudo systemctl enable meshtasticd.service

# Verify boot rail config
aiov2_ctl --boot-rails-status
```

### Complete /boot/firmware/config.txt Additions

Add these lines to the end of `/boot/firmware/config.txt` for full AIO v2 support:

```ini
# === AIO v2 Board Configuration (CM5) ===

# SPI for LoRa (SX1262)
dtparam=spi=on
dtoverlay=spi1-1cs

# Disable CM5 internal RTC
dtparam=rtc=off

# I2C and external RTC (PCF85063A): remap i2c0 for CM5
dtparam=i2c_arm=on
dtoverlay=i2c-rtc,pcf85063a,i2c_csi_dsi0

# GPS PPS output (optional: for precision timing)
# dtoverlay=pps-gpio,gpiopin=6
```

---

## Troubleshooting

### GPS shows no data on /dev/ttyAMA0

- Verify `console=serial0,115200` has been **removed** from `/boot/firmware/cmdline.txt`
- Ensure GPS power rail is enabled: `aiov2_ctl GPS on`
- Check antenna connection on the "GPS" IPEX connector
- Try outdoor or near a window for initial satellite fix

### LoRa / Meshtasticd fails to start

- Verify `devterm-printer.service` is disabled: `sudo systemctl status devterm-printer.service`
- Ensure SPI overlays are in config.txt: `dtparam=spi=on` and `dtoverlay=spi1-1cs`
- Check LoRa power rail: `aiov2_ctl LORA on`
- Review logs: `sudo journalctl -u meshtasticd.service -f`
- Verify `/etc/meshtasticd/config.yaml` has correct SX1262 pin mappings

### RTC not responding

- Verify CR1220 battery is installed correctly (check orientation)
- Confirm I2C overlay is in config.txt: `dtoverlay=i2c-rtc,pcf85063a`
- Test with: `sudo hwclock -r`
- Detect I2C device: `sudo i2cdetect -y 1` (should show device at address 0x51)

### SDR not detected

- Enable SDR power: `aiov2_ctl SDR on`
- Check USB device: `lsusb | grep -i rtl`
- Verify antenna connection on the "SDR" IPEX connector

### "Failed to start session" at LightDM login (Trixie + Kali)

After upgrading with Kali packages, the RPi-specific session file `rpd-labwc` may be removed or replaced while LightDM is still configured to use it. Check:

```bash
grep -i "session" /etc/lightdm/lightdm.conf
```

If you see `user-session=rpd-labwc` or `autologin-session=rpd-labwc`, fix it:

```bash
sudo sed -i 's/user-session=rpd-labwc/user-session=labwc/' /etc/lightdm/lightdm.conf
sudo sed -i 's/autologin-session=rpd-labwc/autologin-session=labwc/' /etc/lightdm/lightdm.conf
```

If the Pi greeter is also gone, switch to the standard LightDM GTK greeter:

```bash
sudo sed -i 's/greeter-session=pi-greeter-labwc/greeter-session=lightdm-gtk-greeter/' /etc/lightdm/lightdm.conf
```

Also fix AccountsService if it has a stale session:

```bash
sudo sed -i 's/rpd-labwc/labwc/' /var/lib/AccountsService/users/$USER 2>/dev/null
```

Restart LightDM to apply:

```bash
sudo systemctl restart lightdm
```

### Trackball quirks on Kali

- The trackball can be slightly less responsive on Kali compared to Bookworm or Trixie: this is a known minor issue
- Trixie does not have this problem, which is another reason it makes a good base image
- If problematic on Kali, the Bookworm or Trixie images have the best trackball behavior

### uConsole won't boot after AIO v2 installation

- **Check the ribbon cable orientation**: this is the most common cause
- Refer to the HackerGadgets installation photos for correct orientation
- **Never plug in the charger if the ribbon cable is wrong**: it will damage the mainboard

### Package install fails with "subprocess returned error code 1" (cryptsetup-initramfs)

This is caused by the `cryptsetup-initramfs` hook failing to resolve `/dev/root` on Pi systems. The hook exits non-zero, which kills the dpkg trigger and can leave packages in a broken state.

**If the system still boots:**

```bash
# Fix the root cause
sudo mkdir -p /etc/cryptsetup-initramfs
echo "CRYPTSETUP=n" | sudo tee /etc/cryptsetup-initramfs/conf-hook

# Clean up the broken install state
sudo dpkg --configure -a
sudo apt --fix-broken install -y

# Retry your install
sudo apt install hackergadgets-uconsole-aio-board -y
```

**If the system won't boot (NVMe):**

Boot from a spare SD card (flash any Rex image), then chroot into the NVMe to fix it:

```bash
# Mount the NVMe root and boot partitions
sudo mount /dev/nvme0n1p2 /mnt
sudo mount /dev/nvme0n1p1 /mnt/boot/firmware

# Bind-mount system filesystems for chroot
sudo mount --bind /dev /mnt/dev
sudo mount --bind /sys /mnt/sys
sudo mount --bind /proc /mnt/proc

# Enter the chroot
sudo chroot /mnt /bin/bash

# Inside chroot: fix the cryptsetup issue
mkdir -p /etc/cryptsetup-initramfs
echo "CRYPTSETUP=n" > /etc/cryptsetup-initramfs/conf-hook
dpkg --configure -a
apt --fix-broken install -y
update-initramfs -u -k $(uname -r)
exit

# Unmount everything
sudo umount /mnt/proc /mnt/sys /mnt/dev /mnt/boot/firmware /mnt
```

Remove the SD card and reboot into the NVMe.

**If the system won't boot (SD card):**

Mount the SD card on another machine and apply the fix directly:

```bash
sudo mount /dev/sdX2 /mnt
sudo mkdir -p /mnt/etc/cryptsetup-initramfs
echo "CRYPTSETUP=n" | sudo tee /mnt/etc/cryptsetup-initramfs/conf-hook
sudo umount /mnt
```

Then boot the SD card in the uConsole and run `sudo dpkg --configure -a && sudo apt --fix-broken install -y`.

### Nuclear option: remove cryptsetup-initramfs entirely

If the package state is too mangled to fix in place:

```bash
sudo dpkg --remove --force-remove-reinstreq cryptsetup-initramfs
sudo apt --fix-broken install -y
```

### raspberrypi-sys-mods conflicts with Kali packages (Trixie + Kali Tools)

`raspberrypi-sys-mods` from the Raspberry Pi repo and several Kali packages (`kali-defaults`, `libpython3.13-stdlib`) fight over the same files. This shows up as either a diversion clash or a file ownership error:

```
dpkg-divert: error: 'diversion of /usr/lib/python3.13/EXTERNALLY-MANAGED ...' clashes with ...
```
or:
```
trying to overwrite '/usr/lib/python3.13/EXTERNALLY-MANAGED', which is also in package raspberrypi-sys-mods
```

**Best fix: remove raspberrypi-sys-mods:**

```bash
sudo apt remove raspberrypi-sys-mods -y
sudo apt -o Dpkg::Options::="--force-overwrite" --fix-broken install -y
sudo apt full-upgrade -y
```

**Fallback: if removing raspberrypi-sys-mods would pull out critical packages:**

```bash
# Force dpkg to overwrite the conflicting files
sudo apt -o Dpkg::Options::="--force-overwrite" --fix-broken install -y
sudo apt -o Dpkg::Options::="--force-overwrite" full-upgrade -y
```

You can make the force-overwrite persistent so you don't have to type it every time:

```bash
echo 'Dpkg::Options { "--force-overwrite"; }' | sudo tee /etc/apt/apt.conf.d/99-force-overwrite
```

### "Unsatisfied dependencies" or version mismatches on Trixie + Kali

Once Kali meta-packages are installed, Kali's versions of core runtime libraries (`libssl3t64`, `libbluetooth3`, `libcurl3t64-gnutls`, Qt6, etc.) are upgraded past what Trixie carries. From that point on, any `apt install` that touches those libraries (including `-dev` header packages for compiling Meshtasticd, etc.) will fail with version mismatch errors unless the packages come from Kali.

**Quick fix for a single install:**

```bash
sudo apt install -t kali-rolling <packages> -y
```

**Permanent fix (recommended):**

```bash
sudo tee /etc/apt/preferences.d/kali-pin <<'EOF'
Package: *
Pin: release o=Kali
Pin-Priority: 900
EOF

sudo apt update
```

This makes Kali rolling the primary repo. Trixie and Rex's repo fill in anything Kali doesn't carry. After setting this, regular `apt install` works without `-t kali-rolling`.

---

## Resources and Links

### Forum Threads

| Resource | URL |
|---|---|
| Rex's Kali Image | https://forum.clockworkpi.com/t/kali-6-12-y-for-the-uconsole-and-devterm/14463 |
| Rex's Bookworm Image | https://forum.clockworkpi.com/t/bookworm-6-12-y-for-the-uconsole-and-devterm/15847 |
| Rex's Trixie Image | https://forum.clockworkpi.com/t/trixie-6-12-y-for-the-uconsole-and-devterm/19457 |
| AIO Board Package Thread | https://forum.clockworkpi.com/t/hackergadgets-aio-board-package/17875 |
| Updated Images (New Screens) | https://forum.clockworkpi.com/t/updated-images-for-new-uconsole-screens/21666 |

### Documentation and Guides

| Resource | URL |
|---|---|
| AIO v2 Setup Guide | https://hackergadgets.com/pages/hackergadgets-uconsole-rtl-sdr-lora-gps-rtc-usb-hub-all-in-one-extension-board-setup-guide |
| aiov2_ctl GitHub Repo | https://github.com/hackergadgets/aiov2_ctl |
| uConsole GitHub (Official) | https://github.com/clockworkpi/uConsole |

### Products

| Product | URL |
|---|---|
| AIO v2 Board | https://hackergadgets.com/products/uconsole-aio-v2 |
| uConsole Upgrade Kit | https://hackergadgets.com/products/uconsole-upgrade-kit |
| NVMe Battery Board | https://hackergadgets.com/products/nvme |

### Community Threads

| Resource | URL |
|---|---|
| Upgrade Kit Discussion | https://forum.clockworkpi.com/t/hackergadgets-uconsole-upgrade-kit-adding-nvme-ssd-pcie-rj45-ethernet-and-usb-3-0-to-your-uconsole/20019 |
| Power Switch Mod for NVMe Board | https://forum.clockworkpi.com/t/power-switch-for-hackergadgets-nvme-battery-board/21553 |

---

## License

This guide is provided as-is for personal reference and community use. Hardware documentation and software referenced herein belong to their respective authors (ClockworkPi, HackerGadgets, Rex, Meshtastic project).
