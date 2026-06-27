# uConsole Setup Guide: CM4 Configuration

## *Rex's Kali or Trixie + HackerGadgets AIO v2 Board + HackerGadgets Battery & NVMe Board*

A complete setup guide for building a field-deployable hacking and SIGINT platform using the ClockworkPi uConsole with a Raspberry Pi CM4, Rex's community images (Kali Linux or Debian Trixie), and the HackerGadgets AIO v2 extension board.

> **About this revision (v1.2):** The order of operations is "harden first, upgrade second, then install." This revision includes automated fixes for Trixie dependency drift (Meshtastic), Wayland GDBus errors (`rtkit`), and ADS-B SDR sequencing. Every step that used to break a fresh install has been pre-empted before the first `apt full-upgrade`. 

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
