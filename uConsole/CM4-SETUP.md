# uConsole Setup Guide: CM4 Configuration

## *Rex's Kali or Trixie + HackerGadgets AIO v2 Board + HackerGadgets Battery & NVMe Board*

A complete setup guide for building a field-deployable hacking and SIGINT platform using the ClockworkPi uConsole with a Raspberry Pi CM4, Rex's community images (Kali Linux or Debian Trixie), and the HackerGadgets AIO v2 extension board.

> **About this revision (audited against forum sources):** The order of operations is now "harden first, upgrade second, then install." Every step that used to break a fresh install has been pre-empted before the first `apt full-upgrade`. GPIO pin assignments, GPS UART config, and the relationship between `hackergadgets-uconsole-aio-board` and `aiov2_ctl` have been corrected against the [Official HackerGadgets setup guide](https://hackergadgets.com/pages/hackergadgets-uconsole-rtl-sdr-lora-gps-rtc-usb-hub-all-in-one-extension-board-setup-guide) and [Rex's package thread on the ClockworkPi forum](https://forum.clockworkpi.com/t/hackergadgets-aio-board-package/17875).

---

## Table of Contents

- [Hardware Overview](#hardware-overview)
- [Choosing Your OS: Kali vs Trixie](#choosing-your-os-kali-vs-trixie)
- [Step 1: Flash the OS](#step-1-flash-the-os)
- [Step 2: First Boot; Pre-Flight Hardening](#step-2-first-boot--pre-flight-hardening)
- [Step 3: System Update and Initial Configuration](#step-3-system-update-and-initial-configuration)
- [Step 4: Add Kali Tools (Trixie Only)](#step-4-add-kali-tools-trixie-only)
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

> **Critical Assembly Note:** When installing the AIO v2 board, ensure the ribbon cable is oriented correctly as shown in the HackerGadgets documentation. **Never plug in the charger if the ribbon cable is installed the wrong way** — incorrect installation will damage the uConsole mainboard.

### AIO v2 GPIO Map (Verified Against HackerGadgets Official Docs)

These are the **AIO v2** control GPIOs. (AIO v1 used different pins for LoRa and Internal USB — make sure you're working with v2 hardware.)

| Peripheral | GPIO | Notes |
|---|---|---|
| **GPS** | 27 | Pull HIGH to enable |
| **LoRa** | 16 | Pull HIGH to enable |
| **SDR** (RTL-SDR) | 7 | Pull HIGH to enable. On CM5, this defaults HIGH at boot. On CM4, it defaults OFF. |
| **Internal USB** (USB-C + pin header) | 23 | Pull HIGH to enable |
| **GPS PPS** (output) | 6 | Optional, for microsecond-accurate NTP timing |

---

## Choosing Your OS: Kali vs Trixie

Rex maintains community images for the uConsole that include a custom kernel (6.12.y) with all necessary hardware patches for the uConsole display, keyboard, and trackball. His images also include a custom APT repository required for the `hackergadgets-uconsole-aio-board` package — that package is not available on stock ClockworkPi or upstream Kali images.

Rex's images include several conveniences that this guide relies on:

- Auto-expanding root filesystem on first boot (no `raspi-config` needed)
- `linux-headers` shipped with the kernel (no separate DKMS headers install)
- A dedicated "drivers" block at the bottom of `/boot/firmware/config.txt` with instructions for enabling overlays

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

Rex's images ship with `user-session=rpd-labwc` and `greeter-session=pi-greeter-labwc` in `/etc/lightdm/lightdm.conf`. Some upgrade paths replace those packages and remove the session files, leaving LightDM pointing at nothing — "Failed to start session" on next login.

Swap the references now to session names that are stable across Rex's images and Kali rolling:

```bash
# Make sure the fallback compositor and greeter are installed
sudo apt update
sudo apt install -y lightdm-gtk-greeter labwc

# Repoint lightdm.conf
sudo sed -i \
  -e 's/^user-session=rpd-labwc/user-session=labwc/' \
  -e 's/^autologin-session=rpd-labwc/autologin-session=labwc/' \
  -e 's/^greeter-session=pi-greeter-labwc/greeter-session=lightdm-gtk-greeter/' \
  /etc/lightdm/lightdm.conf

# Fix any AccountsService entry that still references rpd-labwc
for f in /var/lib/AccountsService/users/*; do
  [ -f "$f" ] && sudo sed -i 's/rpd-labwc/labwc/g' "$f"
done

# Confirm the session/greeter files exist
ls /usr/share/wayland-sessions/labwc.desktop \
   /usr/share/xgreeters/lightdm-gtk-greeter.desktop
```

If either `ls` line errors out, stop and resolve it before continuing — the upgrade will not install them for you.

### 2.3 — (Trixie path only) Remove raspberrypi-sys-mods

> **Kali users:** Skip 2.3 and 2.4. Your image doesn't ship `raspberrypi-sys-mods` and isn't layering Kali on top of Trixie.

`raspberrypi-sys-mods` (preinstalled on Rex's Trixie image) will collide with `kali-defaults` and `libpython3.13-stdlib` once you add the Kali repo. Remove it now so the first full-upgrade doesn't fight it later:

```bash
# Dry-run to see what would be removed
sudo apt -s remove raspberrypi-sys-mods

# If nothing critical (kernels, device-tree packages) is listed, proceed:
sudo apt remove raspberrypi-sys-mods -y

# Clean up any stale diversion / file
EXTMGD=$(ls /usr/lib/python3.*/EXTERNALLY-MANAGED 2>/dev/null | head -1)
if [ -n "$EXTMGD" ]; then
  sudo rm -f "$EXTMGD"
  sudo dpkg-divert --package raspberrypi-sys-mods --remove --rename "$EXTMGD" 2>/dev/null
fi
```

### 2.4 — (Trixie path only) Add Kali rolling and pin it

Pinning Kali as the primary repo **before** the first big upgrade prevents the dependency-mismatch storm that hits when Kali's newer `libssl3t64`, `libbluetooth3`, `libcurl3t64-gnutls`, Qt6 etc. land on a half-Trixie system:

```bash
# Add Kali rolling repo
echo "deb http://http.kali.org/kali kali-rolling main contrib non-free non-free-firmware" \
  | sudo tee /etc/apt/sources.list.d/kali.list

# Import the Kali signing key
curl -fsSL https://archive.kali.org/archive-key.asc \
  | sudo gpg --dearmor -o /etc/apt/trusted.gpg.d/kali-archive-keyring.gpg

# Pin Kali as primary
sudo tee /etc/apt/preferences.d/kali-pin <<'EOF'
Package: *
Pin: release o=Kali
Pin-Priority: 900
EOF

sudo apt update
```

After this, Kali rolling is the primary package source. Trixie and Rex's repo fill in anything Kali doesn't carry (uConsole kernel, AIO board package).

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

> **Note:** Rex's images already auto-expanded the root filesystem on first boot. `raspi-config --expand-rootfs` is not needed. Confirm with `df -h /` if you're curious — it should show the SD card's full capacity.

After the reboot, log back in. If LightDM hands you a working desktop, Step 2 did its job. If not, see [Troubleshooting → "Failed to start session"](#failed-to-start-session-at-lightdm-login).

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

`aiov2_ctl` is HackerGadgets' official control tool for the AIO v2 board. It is **not** a dependency of the `hackergadgets-uconsole-aio-board` apt package — they're parallel tools — so you need to install it explicitly. The HackerGadgets-recommended install path is via `git clone`.

```bash
# Install build/runtime dependencies
sudo apt update
sudo apt install -y python3 python3-pyqt6 git

# Clone and install
git clone https://github.com/hackergadgets/aiov2_ctl.git
cd aiov2_ctl
sudo python3 ./aiov2_ctl.py --install

# Verify
command -v aiov2_ctl && aiov2_ctl --status
```

The install registers `aiov2_ctl` in `/usr/local/bin` and enables the `aiov2-rails-boot.service` so boot-rail settings persist across reboots.

### Enable the system tray GUI on login (optional)

```bash
aiov2_ctl --autostart
```

Creates `~/.config/autostart/aiov2_ctl.desktop` so the tray icon launches on next login. Left-click for status, right-click for toggles and the "Rails on boot" submenu.

---

## Step 6: Install the AIO v2 Board Package

The `hackergadgets-uconsole-aio-board` package is what does the heavy lifting: it installs and **automatically configures** SDR++, tar1090, PyGPSClient, Meshtasticd, the OpenSUSE Meshtastic APT repo, the RTC service, GPIO helpers, and desktop menu entries. You don't need to install Meshtasticd or set up its repos manually — this package handles it.

Rex's recommended install command from his forum post:

```bash
sudo apt update
sudo apt --install-recommends install hackergadgets-uconsole-aio-board -y
sudo apt install meshtastic-mui -y
sudo reboot
```

The `--install-recommends` flag is important — it pulls in the full configured ecosystem rather than the bare-minimum core.

> **Note:** `meshtastic-mui` is installed separately because it depends on `hackergadgets-uconsole-aio-board` being installed first.

### What This Package Installs and Configures

| Component | Function | Configured By Package? |
|---|---|---|
| `hackergadgets-uconsole-aio-board` | Core AIO v2 integration: GPIO, power rails, RTC, services | Yes |
| `meshtastic-mui` | Meshtastic graphical UI | Yes |
| `sdrpp-brown` | Preconfigured SDR++ build for the uConsole | Yes |
| `tar1090` | ADS-B aircraft tracking web UI | Yes |
| `pygpsclient` | GPS monitoring and diagnostics GUI | Yes |
| `meshtasticd` (from OpenSUSE Meshtastic repo) | Meshtastic daemon | Yes — repo added, daemon installed, `/etc/meshtasticd/config.yaml` written |

After the reboot, the bulk of the configuration in Steps 7–10 has already been done by the package. Those steps now exist mainly to **verify** that the package set things up correctly and to cover the few items it can't handle (cmdline.txt edits, antenna connections, RTC time sync, dialout group membership).

### If the AIO install fails partway through

Rex's package has a known historical issue where `/tmp` scripts occasionally don't survive the postinst trigger, producing errors like:

```
/tmp/readsb-install.sh: No such file or directory
cp: cannot stat '/tmp/config.yaml': No such file or directory
dpkg: error processing package hackergadgets-uconsole-aio-board (--configure):
 installed hackergadgets-uconsole-aio-board package post-installation script subprocess returned error exit status 1
```

Fix: remove and reinstall the package.

```bash
sudo apt purge hackergadgets-uconsole-aio-board -y
sudo apt --install-recommends install hackergadgets-uconsole-aio-board -y
sudo apt install meshtastic-mui -y
```

---

## Step 7: Configure GPS (CM4)

The AIO board package already installed `pygpsclient` and configured Meshtasticd's GPS section. This step covers the kernel-side serial port setup that the package doesn't do for you.

### CM4-Specific GPS Path

On CM4, the GPS serial port is `/dev/ttyS0` (CM5 uses `/dev/ttyAMA0`).

### Enable the UART in config.txt

Per HackerGadgets' official setup guide, add the following to `/boot/firmware/config.txt`:

```
enable_uart=1
```

Rex's images include a clearly-marked driver overlay section at the bottom of `config.txt` — follow the instructions there to add new lines.

### Free the Serial Port from the Console

The serial console must be disabled or GPS will be intermittently overwritten by kernel messages. Edit `/boot/firmware/cmdline.txt` and **remove** `console=serial0,115200`:

```bash
sudo nano /boot/firmware/cmdline.txt
```

Find and delete `console=serial0,115200` from the line. Save and exit. **Keep all the other parameters on a single line** — `cmdline.txt` is whitespace-sensitive.

### Add Your User to the dialout Group

To read from `/dev/ttyS0` without sudo (required for GUI tools like `pygpsclient`):

```bash
sudo usermod -a -G dialout $USER
```

Log out and back in (or reboot) for the group change to take effect.

### Power on the GPS Module

```bash
aiov2_ctl GPS on
```

### Verify GPS

Connect a GPS antenna to the IPEX connector labeled "GPS" on the AIO v2 board.

```bash
# Quick raw NMEA check
sudo minicom -D /dev/ttyS0 -b 9600

# Or use the GUI client (installed by the AIO package)
pygpsclient
```

You should see `$GNGGA` / `$GNRMC` sentences streaming. Initial satellite fix can take several minutes outdoors with a clear sky — much longer indoors or under cover.

### Optional: GPS PPS Output (Microsecond NTP)

The GPS has a PPS (pulse-per-second) output on **GPIO 6**. To enable it, add to `/boot/firmware/config.txt`:

```
dtoverlay=pps-gpio,gpiopin=6
```

See [Austin's nerdy things: microsecond-accurate NTP for Pi with GPS+PPS](https://austinsnerdythings.com/2025/02/14/revisiting-microsecond-accurate-ntp-for-raspberry-pi-with-gps-pps-in-2025/) for the full NTP/chrony setup.

---

## Step 8: Configure LoRa / Meshtastic

The AIO board package already installed Meshtasticd from the OpenSUSE Meshtastic repo, wrote `/etc/meshtasticd/config.yaml` with the SX1262 pin mappings, and enabled the service. This step covers what the package can't do for you: the SPI overlay, the printer-service conflict, the antenna, and the first-time region/channel setup.

### Enable SPI1 in config.txt

Add to `/boot/firmware/config.txt`:

```
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

The AIO board package writes a default `/etc/meshtasticd/config.yaml`. Confirm it matches the SX1262 pinout for AIO v2:

```bash
sudo cat /etc/meshtasticd/config.yaml
```

The `Lora` section should read:

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

If the GPS section is present, the `SerialPath` should be `/dev/ttyS0` (CM4). If it shows `/dev/ttyAMA0`, the package detected CM5 — change it to `/dev/ttyS0` on CM4.

### Connect the Antenna

Connect a 433 or 915 MHz antenna (region-dependent) to the IPEX connector labeled **"LoRa"** on the AIO v2 board.

> **Never transmit without an antenna connected** — the SX1262's PA can be damaged by reflected power.

### Restart Meshtasticd

```bash
sudo systemctl restart meshtasticd
sudo systemctl status meshtasticd
```

If the service fails to start, check `sudo journalctl -u meshtasticd -b` for clues — common causes are the SPI overlay not loaded (reboot first), the printer service still running, or `aiov2_ctl LORA on` not yet executed.

### First-Time Meshtastic Setup (Web UI)

Once the daemon is running, open a browser on the uConsole and navigate to `https://localhost`. Accept the self-signed cert. In the connection dialog, type `localhost` (not `meshtastic.local`) and click Connect.

- **Config → LoRa → Region:** Set your region (e.g. **US** for 915 MHz). Different regions cannot communicate.
- **Config → LoRa → Modem Preset:** Set the channel preset. For US LongFast, the standard frequency slot is **slot 20** — confirm this matches your existing local mesh if you're joining one.
- **Map packs** (downloaded for offline use) go in `/home/$USER/.portduino/default/maps/`

### SX1262 Pin Reference for AIO v2

| Function | GPIO |
|---|---|
| SPI Bus | SPI1 (chip select on SPI1-CE0 / GPIO 18) |
| DIO2 (RF Switch) | Internal to SX1262 |
| DIO3 (TCXO Voltage) | Internal to SX1262 |
| IRQ | GPIO 26 |
| Busy | GPIO 24 |
| Reset | GPIO 25 |

---

## Step 9: Configure RTC

The AIO board package installs the RTC service. This step covers the device tree overlay and the one-time time sync.

### Enable the RTC overlay (CM4)

Add to `/boot/firmware/config.txt`:

```
dtparam=i2c_arm=on
dtoverlay=i2c-rtc,pcf85063a
```

Reboot, then verify:

```bash
sudo hwclock -r
```

Expected output is the current date/time. If the command returns nothing or an error, check that the CR1220 battery is installed correctly and that the device is showing up on the I²C bus:

```bash
sudo i2cdetect -y 1   # Should show a device at address 0x51
```

### Sync the RTC to system time

After confirming system time is correct (via NTP or manual set):

```bash
sudo aiov2_ctl --sync-rtc   # writes system time → RTC via hwclock -w
```

From now on, the RTC will keep time across power-off periods using the CR1220 backup battery.

---

## Step 10: Configure SDR

The AIO board package installs `sdrpp-brown` (Brown's SDR++ build), `tar1090`, and ADS-B / dump1090 plumbing. This step covers the GPIO power-on, blacklisting the DVB-T kernel driver, and using SDR++.

### Power on the SDR

```bash
aiov2_ctl SDR on
```

On CM5 the SDR rail is on by default at boot; on CM4 you have to enable it.

### Blacklist the DVB-T kernel driver

The Linux kernel will try to claim the RTL2832U/R828D chip as a DVB-T television tuner, which blocks user-space SDR software from using it. Blacklist the default driver:

```bash
echo "blacklist dvb_usb_rtl28xxu" | sudo tee /etc/modprobe.d/blacklist-rtl.conf
sudo rmmod dvb_usb_rtl28xxu 2>/dev/null
```

### Launch SDR++

Connect a wideband antenna (or a frequency-specific one) to the IPEX connector labeled **"SDR"** on the AIO v2 board.

```bash
sdrpp
```

In the SDR++ UI:
- **Source dropdown:** select **RTL-SDR**, then pick the device's serial number from the second dropdown
- Tune to a known-good local FM station (e.g. ~95–105 MHz), set **WFM** mode, click play
- You should hear audio and see a waterfall

> **Trixie audio note:** Rex's forum thread mentions you may need to add an audio sink in SDR++'s Module Manager: search `audio`, add `linux_pulseaudio_sink`, then select it under the Sinks menu.

### ADS-B Tracking (tar1090)

`tar1090` is installed and configured by the AIO board package. The package also disables the always-on `readsb` service that would otherwise hold the SDR exclusively — the menu launcher starts `readsb` only while tar1090 is open and stops it on exit. Access the web UI at `http://localhost/tar1090` once running.

---

## Step 11: GPIO Power Control

### AIO v2 Control Pin Map (CM4)

| Peripheral | GPIO | CM4 Default at Boot |
|---|---|---|
| GPS | 27 | OFF |
| LoRa | 16 | OFF |
| SDR (RTL-SDR) | 7 | OFF (on CM5, defaults ON) |
| Internal USB (USB-C + pin header) | 23 | OFF |

> Pulling a pin HIGH enables that peripheral; LOW disables.

### Using aiov2_ctl (Recommended)

```bash
# Show current GPIO state
aiov2_ctl

# Detailed status with battery/power info
aiov2_ctl --status

# Toggle peripherals
aiov2_ctl GPS on
aiov2_ctl LORA on
aiov2_ctl SDR on
aiov2_ctl USB on

aiov2_ctl GPS off
aiov2_ctl SDR off

# Live power monitoring
aiov2_ctl --power

# Compact live GPIO + power view (single line)
aiov2_ctl --watch
```

### Configure Boot Defaults

Set peripherals to auto-enable at boot:

```bash
aiov2_ctl --boot-rail GPS on
aiov2_ctl --boot-rail LORA on
aiov2_ctl --boot-rail SDR on

# Verify
aiov2_ctl --boot-rails-status
```

Boot rail settings are applied by `aiov2-rails-boot.service`, installed automatically with `aiov2_ctl --install`.

### Manual GPIO Control (Without aiov2_ctl)

If you ever need to drive GPIOs directly:

```bash
# Enable GPS
pinctrl set 27 op dh

# Enable LoRa
pinctrl set 16 op dh

# Enable SDR
pinctrl set 7 op dh

# Enable Internal USB
pinctrl set 23 op dh

# Disable any of the above
pinctrl set <N> op dl
```

### GUI Mode

```bash
aiov2_ctl --gui
```

Left-click the tray icon for a status window; right-click for toggle controls. The right-click menu also includes a "Rails on boot" submenu for persistent boot preferences.

---

## Step 12: WiFi Pentesting Setup

The CM4's onboard WiFi does **not** support monitor mode. You need an external USB WiFi adapter.

### Recommended Adapters

| Adapter | Chipset | Notes |
|---|---|---|
| HackerGadgets AC1200 USB-C WiFi Card | RTL8812AU | Sold separately, monitor mode supported |
| Alfa AWUS036ACH | RTL8812AU | Proven pentesting adapter |
| Alfa AWUS036ACSM | RTL8812AU | Smaller form factor |
| Any RTL8812AU/RTL8814AU adapter | RTL8812AU/RTL8814AU | Widely available, well-supported |

> **Note:** CM4 is limited to USB 2.0 regardless of adapter. Fine for packet capture; worth keeping in mind for high-throughput deauth/injection scenarios.

### Install the DKMS Driver

RTL8812AU/RTL8814AU chipsets are not in the mainline Linux kernel — they need a DKMS module. Rex's images ship with `linux-headers` already included for the running kernel, so DKMS should build cleanly:

```bash
sudo apt install realtek-rtl88xxau-dkms -y

# Verify the module built and registered for your kernel
sudo dkms status | grep rtl88
```

If `dkms status` shows the module as `installed` for your kernel, plug in the adapter — `iwconfig` should now list it.

### Verify Monitor Mode

```bash
# List wireless interfaces
iwconfig

# Check adapter capabilities
iw list | grep -A 10 "Supported interface modes"

# Enable monitor mode (wlan1 = external; wlan0 = onboard)
sudo airmon-ng start wlan1

# Verify
iwconfig wlan1mon
```

### Common Pentest Toolkit

These are pre-installed on Kali. On Trixie, install them via the Kali metapackages from Step 4.

```
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

## Step 13: LAN Pentesting via RJ45

The AIO v2 provides Gigabit Ethernet via the RJ45 port. This requires the **HackerGadgets adapter board** from the Upgrade Kit — without it, the RJ45 port will not function.

With the adapter board installed, you can use the uConsole as a network tap or drop box:

```bash
# Plug into a target switch, request DHCP
sudo dhclient eth0

# Verify connectivity
ip addr show eth0

# Quick discovery sweep
sudo nmap -sn 192.168.1.0/24

# Run Responder for credential capture
sudo responder -I eth0 -wrf

# Full port scan
sudo nmap -sS -sV -O -p- 192.168.1.0/24
```

---

## Step 14: NVMe Battery Board Setup

The HackerGadgets NVMe Battery Board replaces the stock uConsole battery board, combining NVMe SSD storage with the battery compartment in a single PCB. Part of the HackerGadgets Upgrade Kit; requires the HackerGadgets adapter board.

### Hardware Overview

| Feature | Detail |
|---|---|
| NVMe Slot | M.2 M-key, supports 2230 through 2280 form factors |
| Battery | Two variants: dual 18650 holder, or LiPo battery pack |
| Reverse Protection | Improved — no heat on reverse battery insertion; warning LED lights up |
| Power Switch Mod | Desolder R14, connect a push-lock switch to J6 for manual on/off |
| Requires | HackerGadgets adapter board (from Upgrade Kit) |

> **Important:** The NVMe feature requires the HackerGadgets adapter board. The NVMe Battery Board alone will not provide NVMe functionality without it.

### Board Variants

- **With Dual 18650 Battery Holder:** fits two standard 18650 cells side by side (more common)
- **Without Battery Holder:** for LiPo battery packs wired in directly

### Physical Installation

1. Remove the stock uConsole battery board.
2. Install the HackerGadgets adapter board (connects the CM4 to the NVMe Battery Board via ribbon cable).
3. Seat the NVMe Battery Board in place of the stock battery board.
4. Connect the ribbon cable between the adapter board and the NVMe Battery Board.

> **Critical:** Check ribbon cable orientation carefully. An incorrectly installed ribbon cable can prevent boot. If the uConsole won't boot after installation, the cable is likely flipped. **Never plug in the charger with a reversed ribbon cable** — this will damage the mainboard.

5. Insert your NVMe SSD into the M.2 slot (2230 is most compact; 2242 and 2280 also fit).
6. Install your 18650 batteries or connect your LiPo pack.

### NVMe Software Configuration (CM4)

Add to `/boot/firmware/config.txt`:

```
dtparam=pciex1=on
```

Reboot and verify:

```bash
lspci                          # Should show the NVMe controller
lsblk                          # Should show nvme0n1
sudo fdisk -l /dev/nvme0n1     # Full partition info
```

### CM4 EEPROM: Do You Need to Update?

Per Rex: **"There's nothing you need to do to the EEPROM with the CM4."** Most CM4 modules from recent years already have NVMe boot enabled in the EEPROM by default.

If your CM4 is older and NVMe isn't detected, check the EEPROM config:

```bash
sudo CM4_ENABLE_RPI_EEPROM_UPDATE=1 rpi-eeprom-config
```

If `BOOT_ORDER` doesn't include `6` (NVMe), see [Updating CM4 EEPROM](#updating-cm4-eeprom-if-needed) below.

### Cloning SD Card to NVMe

#### Method 1: rpi-clone (Recommended)

```bash
git clone https://github.com/billw2/rpi-clone.git
cd rpi-clone
sudo cp rpi-clone /usr/local/sbin/

sudo rpi-clone nvme0n1
```

rpi-clone handles partition resizing and UUID updates automatically.

#### Method 2: SD Card Copier (GUI)

If you have a desktop environment, the built-in SD Card Copier utility (in Rex's Trixie and Bookworm) can copy from SD to NVMe. Source = SD card; destination = NVMe drive.

> **Tip from the community:** Consider adding `dtparam=pciex1_gen=2` to config.txt to cap the PCIe link at Gen 2 speed for improved stability with some drives.

### Booting from NVMe

#### Option A: NVMe as Primary Boot (Remove SD Card)

If BOOT_ORDER includes `6`, remove the SD card and the CM4 will fall through to NVMe.

#### Option B: Dual Boot (SD + NVMe)

Set `BOOT_ORDER=0xf61` in EEPROM — SD card inserted boots from SD, removed boots from NVMe. Useful for keeping different OS configurations (Kali on NVMe daily, DragonOS on SD for SDR sessions).

### Updating CM4 EEPROM (If Needed)

Requires a separate Raspberry Pi or a CM4 IO Board.

```bash
# On a host Pi (not the uConsole)
sudo apt install git libusb-1.0-0-dev pkg-config
git clone --depth=1 https://github.com/raspberrypi/usbboot
cd usbboot
make

cd recovery
nano boot.conf
```

```ini
[all]
BOOT_UART=0
WAKE_ON_GPIO=1
POWER_OFF_ON_HALT=0
BOOT_ORDER=0xf61
ENABLE_SELF_UPDATE=1
```

Apply:

```bash
./update-pieeprom.sh
cd ..
sudo ./rpiboot -d recovery
```

Connect the CM4 (with "disable eMMC boot" jumper set, if applicable) via USB. The EEPROM will be flashed. Disconnect, remove jumper, and NVMe boot is now supported.

### Optional: Hardware Power Switch Mod

For full power-down without pulling batteries:

1. Desolder resistor **R14** on the NVMe Battery Board
2. Solder a push-lock (latching) switch to the **J6** pads
3. Locked → battery power on; released → power off

A community member documented using an **SMD MSK12C02** slide switch that sits flush at the side panel — clean, non-destructive, reversible.

### Troubleshooting NVMe

**NVMe not detected (`lspci` shows nothing):**
- Verify `dtparam=pciex1=on` in `/boot/firmware/config.txt`
- Reseat or flip the ribbon cable between the adapter board and NVMe board
- Test the drive in a USB enclosure on another machine
- Check for a faulty ribbon cable (broken traces)

**NVMe detected but won't boot:**
- Confirm a bootable image is on the NVMe (flash with Pi Imager to a USB enclosure first, then transplant)
- Check EEPROM boot order includes NVMe: `sudo CM4_ENABLE_RPI_EEPROM_UPDATE=1 rpi-eeprom-config`
- Verify the NVMe boot partition has files: `sudo mount /dev/nvme0n1p1 /mnt && ls /mnt`

**Intermittent boot failures or PCIe errors in dmesg:**
- Add `dtparam=pciex1_gen=2` to config.txt
- Some Gen 4 drives have link training issues negotiating down to Gen 2 — try a different drive

---

## CM4-Specific Notes and Limitations

| Item | CM4 Detail |
|---|---|
| GPS Serial Port | `/dev/ttyS0` (CM5 uses `/dev/ttyAMA0`) |
| GPS UART Config | Requires `enable_uart=1` in config.txt (CM5 uses `dtparam=uart0`) |
| USB Speed | USB 2.0 only (USB 3.0 requires CM5 + Upgrade Kit) |
| GPIO Boot State | All AIO peripherals start OFF (CM5 has GPIO 7/SDR on by default) |
| Stability | Most mature and community-tested configuration |
| RTC Config | `dtoverlay=i2c-rtc,pcf85063a` (simpler than CM5 which needs `dtparam=rtc=off` + `i2c_csi_dsi0` remap) |
| Serial Console | Must remove `console=serial0,115200` from cmdline.txt for GPS |
| SPI Conflict | Must disable `devterm-printer.service` for LoRa |
| Onboard WiFi | Does NOT support monitor mode — external adapter required |
| RJ45 Ethernet | Requires HackerGadgets adapter board from Upgrade Kit |

---

## AIO v2 Board: Hardware Reference

### Antenna Connectors

| Label | Purpose | Antenna Type |
|---|---|---|
| **SDR** | RTL-SDR receiver | Wideband, or frequency-specific |
| **LoRa** | SX1262 transceiver | 433 or 915 MHz (region-dependent) |
| **GPS** | GPS/BDS/GNSS receiver | Active or passive GPS antenna |

The antenna mounting kit (sold with some variants) supports up to 7 antennas.

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
sudo aiov2_ctl --add-apps           # Install AIO companion apps (alt path to Step 6)
sudo aiov2_ctl --remove-apps        # Remove AIO companion apps
```

### Debug Mode

```bash
AIOV2_CTL_DEBUG=1 aiov2_ctl --status
```

Shows state source labels: `(pinctrl)` for direct hi/lo, `(boot_default)` for fallback, `(unknown)` for unparseable reads.

---

## Meshtastic Web Interface

Meshtasticd's web server is enabled by the AIO board package's default config (Meshtastic 2.3.0+ ships it).

1. Confirm webserver section in `/etc/meshtasticd/config.yaml`:
   ```yaml
   Webserver:
     Port: 443
     RootPath: /usr/share/meshtasticd/web
   ```
2. Browse to `https://localhost` on the uConsole.
3. Accept the self-signed cert ("Proceed to localhost (unsafe)").
4. In the connection dialog, enter `localhost` (not `meshtastic.local`) and click Connect.
5. **Config → LoRa → Region**: set your region (US for 915 MHz). Different regions cannot communicate.
6. **Messages** menu: send/receive on public channels or between individual nodes.
7. Offline map packs go in `/home/$USER/.portduino/default/maps/`.

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

# GPS PPS output (optional — for precision NTP timing)
# dtoverlay=pps-gpio,gpiopin=6
```

And in `/boot/firmware/cmdline.txt`:

- **Remove** `console=serial0,115200` to free `/dev/ttyS0` for GPS.

---

## Troubleshooting

### "Failed to start session" at LightDM login

This used to be the #1 failure mode of a fresh install. Step 2.2 of this guide pre-empts it by repointing LightDM at sessions that survive Kali rolling upgrades. If you hit it on a system that didn't go through this guide, fix it like so:

```bash
# Check what LightDM is configured to launch
grep -i "session" /etc/lightdm/lightdm.conf

# Switch user-session and autologin-session to labwc
sudo sed -i \
  -e 's/^user-session=rpd-labwc/user-session=labwc/' \
  -e 's/^autologin-session=rpd-labwc/autologin-session=labwc/' \
  -e 's/^greeter-session=pi-greeter-labwc/greeter-session=lightdm-gtk-greeter/' \
  /etc/lightdm/lightdm.conf

# Fix AccountsService entries for any user with a stale session pointer
for f in /var/lib/AccountsService/users/*; do
  [ -f "$f" ] && sudo sed -i 's/rpd-labwc/labwc/g' "$f"
done

# Make sure the fallback greeter and compositor are installed
sudo apt install -y lightdm-gtk-greeter labwc

# Restart LightDM
sudo systemctl restart lightdm
```

If you can't get to a graphical login at all, switch to a TTY with `Ctrl+Alt+F2`, log in there, and run the fix.

### AIO board package fails with /tmp script errors

Symptoms — postinst script can't find `/tmp/readsb-install.sh` or `/tmp/config.yaml`. This is a known historical issue with Rex's package. Fix:

```bash
sudo apt purge hackergadgets-uconsole-aio-board -y
sudo apt update
sudo apt --install-recommends install hackergadgets-uconsole-aio-board -y
sudo apt install meshtastic-mui -y
```

### GPS shows no data on /dev/ttyS0

- Confirm `enable_uart=1` is in `/boot/firmware/config.txt` and you've rebooted
- Confirm `console=serial0,115200` is **removed** from `/boot/firmware/cmdline.txt`
- Confirm GPS power rail is enabled: `aiov2_ctl GPS on`
- Antenna connected to the "GPS" IPEX connector
- Outdoors or near a window for the initial satellite fix
- Your user is in the `dialout` group (logout/login required after `usermod -aG dialout $USER`)

### LoRa / Meshtasticd fails to start

- Verify `devterm-printer.service` is disabled: `sudo systemctl status devterm-printer.service`
- Confirm SPI overlays in config.txt: `dtparam=spi=on` and `dtoverlay=spi1-1cs`
- Check LoRa power rail: `aiov2_ctl LORA on`
- Review logs: `sudo journalctl -u meshtasticd.service -b`
- Verify `/etc/meshtasticd/config.yaml` has the SX1262 pin mappings shown in [Step 8](#step-8-configure-lora--meshtastic)

### RTC not responding

- Verify CR1220 battery is installed correctly (check orientation)
- Confirm I²C overlay in config.txt: `dtoverlay=i2c-rtc,pcf85063a`
- Test with: `sudo hwclock -r`
- Detect device on bus: `sudo i2cdetect -y 1` (look for address `0x51`)

### SDR not detected

- Power: `aiov2_ctl SDR on`
- DVB-T driver blacklisted: `cat /etc/modprobe.d/blacklist-rtl.conf`
- USB device visible: `lsusb | grep -i rtl`
- Antenna on "SDR" IPEX connector

### RTL8812AU adapter not visible

- DKMS module built for your running kernel: `sudo dkms status | grep rtl88`
- If status shows "added" but not "installed" — kernel headers aren't matching. Rex's images normally ship headers; if missing, install the matching `linux-headers-$(uname -r)` and run `sudo dkms autoinstall`
- After install, unplug/replug the adapter and check `dmesg | tail` for `88XXau` initialization
- `iwconfig` should now list it

### Trackball quirks on Kali

- Trackball can be slightly less responsive on Kali than on Bookworm/Trixie — known minor issue
- Bookworm or Trixie give the best trackball behavior if this becomes a problem

### uConsole won't boot after AIO v2 installation

- **Check the ribbon cable orientation** — most common cause
- Refer to the HackerGadgets installation photos for correct orientation
- **Never plug in the charger if the ribbon cable is wrong** — it will damage the mainboard

### Package install fails with "subprocess returned error code 1" (cryptsetup-initramfs)

Shouldn't happen if Step 2.1 was completed before any upgrades. If it did, the `cryptsetup-initramfs` hook is failing to resolve `/dev/root` and killing dpkg post-install triggers.

**If the system still boots:**

```bash
sudo mkdir -p /etc/cryptsetup-initramfs
echo "CRYPTSETUP=n" | sudo tee /etc/cryptsetup-initramfs/conf-hook

sudo dpkg --configure -a
sudo apt --fix-broken install -y
```

**If the system won't boot (NVMe):**

Boot from a spare SD card (flash any Rex image), then chroot into the NVMe:

```bash
sudo mount /dev/nvme0n1p2 /mnt
sudo mount /dev/nvme0n1p1 /mnt/boot/firmware
sudo mount --bind /dev /mnt/dev
sudo mount --bind /sys /mnt/sys
sudo mount --bind /proc /mnt/proc

sudo chroot /mnt /bin/bash

# Inside chroot:
mkdir -p /etc/cryptsetup-initramfs
echo "CRYPTSETUP=n" > /etc/cryptsetup-initramfs/conf-hook
dpkg --configure -a
apt --fix-broken install -y
update-initramfs -u -k $(uname -r)
exit

sudo umount /mnt/proc /mnt/sys /mnt/dev /mnt/boot/firmware /mnt
```

Remove the SD card and reboot.

**If the system won't boot (SD card):**

Mount the SD card on another machine:

```bash
sudo mount /dev/sdX2 /mnt
sudo mkdir -p /mnt/etc/cryptsetup-initramfs
echo "CRYPTSETUP=n" | sudo tee /mnt/etc/cryptsetup-initramfs/conf-hook
sudo umount /mnt
```

Then boot the SD card and run `sudo dpkg --configure -a && sudo apt --fix-broken install -y`.

**Nuclear option — remove cryptsetup-initramfs entirely:**

```bash
sudo dpkg --remove --force-remove-reinstreq cryptsetup-initramfs
sudo apt --fix-broken install -y
```

### raspberrypi-sys-mods conflicts with Kali packages (Trixie + Kali Tools)

Shouldn't occur if Step 2.3 was completed before adding the Kali repo. If it did, you'll see either a diversion clash or a file-ownership error.

**Fix — remove raspberrypi-sys-mods now:**

```bash
sudo apt remove raspberrypi-sys-mods -y
sudo apt -o Dpkg::Options::="--force-overwrite" --fix-broken install -y
sudo apt full-upgrade -y
```

**Fallback — if removing it would pull out critical packages:**

```bash
sudo apt -o Dpkg::Options::="--force-overwrite" --fix-broken install -y
sudo apt -o Dpkg::Options::="--force-overwrite" full-upgrade -y
```

### "Unsatisfied dependencies" or version mismatches on Trixie + Kali

Shouldn't happen if Step 2.4 set the Kali APT pin before any Kali packages were installed. If it did, install affected packages from Kali explicitly:

```bash
sudo apt install -t kali-rolling <packages> -y
```

To make the pin permanent (it should already be from Step 2.4, but if you're on a system that skipped it):

```bash
sudo tee /etc/apt/preferences.d/kali-pin <<'EOF'
Package: *
Pin: release o=Kali
Pin-Priority: 900
EOF

sudo apt update
```

### Meshtasticd dependency errors on Trixie (historical)

When Trixie first launched (Aug 2025), Meshtastic upstream had hardcoded deps on `libgpiod2` and `libyaml-cpp0.7` while Trixie ships `libgpiod3` and `libyaml-cpp0.8`. Meshtastic has since updated for Trixie. If you hit `libgpiod2`/`libyaml-cpp0.7` errors anyway, you're either on a very old Meshtasticd version or the OpenSUSE repo hasn't been updated yet — install the latest `meshtasticd_*_arm64.deb` from [Meshtastic firmware releases](https://github.com/meshtastic/firmware/releases) directly:

```bash
LATEST_URL=$(curl -fsSL https://api.github.com/repos/meshtastic/firmware/releases/latest \
  | grep "browser_download_url.*meshtasticd_.*_arm64.deb" \
  | head -1 \
  | cut -d '"' -f 4)

wget "$LATEST_URL"
sudo apt install -y "./$(basename "$LATEST_URL")"
```

---

## Resources and Links

### Forum Threads

| Resource | URL |
|---|---|
| Rex's Kali Image | https://forum.clockworkpi.com/t/kali-6-12-y-for-the-uconsole-and-devterm/14463 |
| Rex's Bookworm Image | https://forum.clockworkpi.com/t/bookworm-6-12-y-for-the-uconsole-and-devterm/15847 |
| Rex's Trixie Image | https://forum.clockworkpi.com/t/trixie-6-12-y-for-the-uconsole-and-devterm/19457 |
| Rex's AIO Board Package Thread | https://forum.clockworkpi.com/t/hackergadgets-aio-board-package/17875 |
| Updated Images (New Screens) | https://forum.clockworkpi.com/t/updated-images-for-new-uconsole-screens/21666 |
| AIO v2 Discussion | https://forum.clockworkpi.com/t/uconsole-aio-v2-rtl-sdr-lora-gps-rtc-usb-hub-usb-3-0-rj45-ethernet/20800 |

### Documentation and Guides

| Resource | URL |
|---|---|
| HackerGadgets AIO V1/V2 Setup Guide | https://hackergadgets.com/pages/hackergadgets-uconsole-rtl-sdr-lora-gps-rtc-usb-hub-all-in-one-extension-board-setup-guide |
| aiov2_ctl GitHub Repo | https://github.com/hackergadgets/aiov2_ctl |
| uConsole GitHub (Official) | https://github.com/clockworkpi/uConsole |
| Rex's GitHub (kernel + APT repo) | https://github.com/ak-rex |
| Meshtastic Firmware Releases | https://github.com/meshtastic/firmware/releases |

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
