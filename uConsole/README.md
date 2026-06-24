# 🛠️ uConsole: Setup & Deployment Guides

<div align="center">

**Complete build guides for the ClockworkPi uConsole with HackerGadgets AIO v2 board — SDR, LoRa, GPS, and pentesting in your pocket**

*Part of the [ULTIMATE CYBERSECURITY MASTER GUIDE](../README.md)*

[![CM4](https://img.shields.io/badge/CM4-Supported-blue?style=for-the-badge)]()
[![CM5](https://img.shields.io/badge/CM5-Supported-green?style=for-the-badge)]()
[![AIO v2](https://img.shields.io/badge/AIO_v2-RTL--SDR_%7C_LoRa_%7C_GPS_%7C_RTC-red?style=for-the-badge)]()
[![Kali](https://img.shields.io/badge/Kali-Rolling-557C94?style=for-the-badge)]()
[![Trixie](https://img.shields.io/badge/Debian-Trixie-A81D33?style=for-the-badge)]()

</div>

---

## 📋 Table of Contents

- [Overview](#overview)
- [Setup Guides](#setup-guides)
- [Hardware Stack](#hardware-stack)
- [CM4 vs CM5 — Quick Reference](#cm4-vs-cm5--quick-reference)
- [OS Options](#os-options)
- [AIO v2 Board Capabilities](#aio-v2-board-capabilities)
- [Common Setup Sequence](#common-setup-sequence)
- [Security & Legal Disclaimer](#security--legal-disclaimer)
- [Resources](#resources)

---

## 🎯 Overview

This directory contains **complete, step-by-step build guides** for turning a ClockworkPi uConsole into a field-deployable hacking and SIGINT platform using the HackerGadgets AIO v2 extension board.

**What This Covers:**
- 📡 RTL-SDR setup and configuration (100 kHz – 1.74 GHz)
- 📻 LoRa / Meshtastic mesh networking (SX1262)
- 🛰️ GPS receiver configuration and PPS timing
- ⏰ Hardware RTC with battery backup (PCF85063A)
- 🔌 NVMe storage via the HackerGadgets NVMe Battery Board
- 🌐 Gigabit Ethernet via RJ45 (Upgrade Kit required)
- 📶 WiFi pentesting with external monitor-mode adapters
- 🔧 GPIO power control via `aiov2_ctl`
- 🐧 OS setup for both Kali Linux and Debian Trixie (Rex's images)
- ⚠️ Known package conflicts and fixes (cryptsetup, raspberrypi-sys-mods, dpkg-divert)

### Purpose

These guides serve as:
- **Step-by-step build documentation** — flash to fully operational
- **Hardware reference** — GPIO pinouts, SPI mappings, antenna connectors
- **Troubleshooting playbook** — every issue we've hit and fixed
- **Pentest platform quick-start** — Kali tools, WiFi adapters, LAN drop box config

---

## 📂 Setup Guides

| Guide | Compute Module | Description |
|-------|---------------|-------------|
| **[CM4-SETUP.md](./CM4-SETUP.md)** | Raspberry Pi CM4 | Complete CM4 setup — most mature and community-tested configuration |
| **[CM5-SETUP.md](./CM5-SETUP.md)** | Raspberry Pi CM5 | Complete CM5 setup — USB 3.0, native PCIe, newer SoC |

> **Which guide should I follow?** If you already have your hardware, follow the guide matching your compute module. If you're buying new, see the [comparison table](#cm4-vs-cm5--quick-reference) below.

---

## 🖥️ Hardware Stack

### Core Components

| Component | Detail |
|---|---|
| **Handheld** | ClockworkPi uConsole |
| **Compute Module** | Raspberry Pi CM4 or CM5 (with HackerGadgets adapter board) |
| **Extension Board** | HackerGadgets AIO v2 |
| **OS** | Rex's Kali Linux or Rex's Debian Trixie (6.12.y kernel) |
| **WiFi Adapter** | External monitor-mode capable adapter (RTL8812AU recommended) |

### Optional Components

| Component | Detail |
|---|---|
| **NVMe Battery Board** | HackerGadgets NVMe Battery Board (18650 or LiPo variant) |
| **Upgrade Kit** | HackerGadgets Upgrade Kit (required for RJ45, USB 3.0, NVMe) |
| **AC1200 WiFi Card** | HackerGadgets AC1200 USB-C WiFi Card (sold separately) |

---

## ⚖️ CM4 vs CM5 — Quick Reference

| Feature | CM4 | CM5 |
|---|---|---|
| **GPS Serial Port** | `/dev/ttyS0` | `/dev/ttyAMA0` |
| **USB Speed** | USB 2.0 only | USB 3.0 (with Upgrade Kit) |
| **GPIO Boot State** | All peripherals OFF | GPIO 7 (SDR) ON by default |
| **RTC Config** | `dtoverlay=i2c-rtc,pcf85063a` | `dtparam=rtc=off` + `dtoverlay=i2c-rtc,pcf85063a,i2c_csi_dsi0` |
| **Serial Console** | Remove `console=serial0,115200` from cmdline.txt | Remove `console=serial0,115200` from cmdline.txt |
| **SPI Conflict** | Disable `devterm-printer.service` | Disable `devterm-printer.service` |
| **Onboard WiFi** | No monitor mode | No monitor mode |
| **Community Maturity** | Most tested, most stable | Newer, improving rapidly |
| **PCIe** | Gen 2 (via adapter board) | Native PCIe support |
| **NVMe EEPROM** | Usually fine, some older units need update | Native NVMe boot support |
| **Internal RTC** | None (uses AIO v2's PCF85063A) | Has internal RTC (must disable for AIO v2's RTC) |

### Which Should I Buy?

**Choose CM4 if:** You want the most stable, community-tested configuration with the fewest surprises. Best for first-time uConsole builders.

**Choose CM5 if:** You want USB 3.0 for external adapters, native PCIe for NVMe, and the newer BCM2712 SoC. Better long-term investment, but occasional rough edges.

---

## 🐧 OS Options

Both setup guides cover two primary OS paths:

### Path A: Rex's Kali Image

Full Kali toolchain pre-installed — pentesting-ready out of the box.

| Pros | Cons |
|---|---|
| Everything pre-installed | Can hit `cryptsetup-initramfs` failures |
| Familiar to pentesters | Trackball slightly less responsive |
| Kali community support | N/A |

### Path B: Rex's Trixie + Kali Tools (Recommended)

Debian 13 base with Kali rolling repo layered on top.

| Pros | Cons |
|---|---|
| Newest packages | Extra setup step for Kali tools |
| Fewer package conflicts | Must remove `raspberrypi-sys-mods` |
| Best trackball behavior | Must set Kali APT pin to 900 |
| Cleanest base system | N/A |

### Other Rex Images

| Image | Best For |
|---|---|
| **Bookworm 6.12.y** | Maximum stability, daily driver |
| **DragonOS** | Dedicated SDR/RF analysis (GNU Radio, full RF toolkit) |

---

## 📡 AIO v2 Board Capabilities

### Integrated Peripherals

| Peripheral | Chip / Spec | GPIO Control |
|---|---|---|
| **RTL-SDR** | R828D + TCXO, 100 kHz – 1.74 GHz, 5V bias tee | GPIO 7 |
| **LoRa** | SX1262, 860–960 MHz, 22 dBm, TCXO, Meshtastic-ready | GPIO 22 |
| **GPS** | Multi-mode GPS/BDS/GNSS, active + passive antenna | GPIO 27 |
| **RTC** | PCF85063A + CR1220 battery backup | I2C (always on) |
| **Internal USB** | USB-C + pin header hub | GPIO 6 |
| **RJ45 Ethernet** | Gigabit (requires Upgrade Kit adapter board) | Always on |

### Antenna Connectors

| Label | Purpose | Antenna Type |
|---|---|---|
| **SDR** | RTL-SDR receiver | Wideband or frequency-specific |
| **LoRa** | SX1262 transceiver | 433 or 915 MHz (region-dependent) |
| **GPS** | GPS/BDS/GNSS receiver | Active or passive GPS antenna |

### GPIO Control Tool — aiov2_ctl

All peripherals are controlled via GPIO using `aiov2_ctl` ([GitHub](https://github.com/hackergadgets/aiov2_ctl)):

```
aiov2_ctl                           # Show current GPIO state
aiov2_ctl <FEATURE> <on|off>        # Toggle: GPS, LORA, SDR, USB
aiov2_ctl --status                  # Detailed status (GPIO + battery + power)
aiov2_ctl --gui                     # Launch system tray GUI
aiov2_ctl --boot-rail <FEAT> on     # Auto-enable at boot
aiov2_ctl --sync-rtc                # Write system time to hardware RTC
```

---

## 🔧 Common Setup Sequence

Regardless of CM4 or CM5, the high-level setup flow is the same. Refer to your compute-module-specific guide for exact commands and config values.

```
1. Flash Rex's Image (Kali or Trixie)
   └─> Download from ClockworkPi forum
   └─> Flash with dd or balenaEtcher

2. First Boot & Initial Config
   └─> Change default password
   └─> Set timezone and hostname
   └─> Expand filesystem

3. [Trixie Only] Install Kali Tools
   └─> Remove raspberrypi-sys-mods
   └─> Add Kali repo + signing key
   └─> Set Kali APT pin to 900
   └─> Install kali-tools-top10 or kali-linux-headless

4. Fix cryptsetup-initramfs
   └─> Set CRYPTSETUP=n in conf-hook
   └─> Prevents non-bootable system from initramfs failures

5. Install AIO v2 Board Package
   └─> sudo apt install hackergadgets-uconsole-aio-board

6. Install aiov2_ctl
   └─> Clone from GitHub, run --install

7. Configure GPS
   └─> Free serial port (remove console= from cmdline.txt)
   └─> Add user to dialout group
   └─> Enable GPIO, verify NMEA output

8. Configure LoRa / Meshtasticd
   └─> Enable SPI overlays, disable devterm-printer
   └─> Download and install meshtasticd .deb
   └─> Configure config.yaml with SX1262 pin mapping
   └─> Set LoRa region in web interface

9. Configure RTC
   └─> Add I2C + RTC overlays to config.txt
   └─> Verify with hwclock -r

10. Configure SDR
    └─> Blacklist dvb_usb_rtl28xxu kernel driver
    └─> Enable GPIO, launch SDR++

11. Install WiFi DKMS Driver
    └─> sudo apt install realtek-rtl88xxau-dkms

12. [Optional] NVMe Battery Board
    └─> Enable PCIe in config.txt
    └─> Clone SD to NVMe with rpi-clone
    └─> Configure boot order

13. Set Boot Defaults
    └─> Configure boot rails via aiov2_ctl
    └─> Enable Meshtasticd service
    └─> Enable GUI autostart
```

---

## ⚠️ Security & Legal Disclaimer

### 🔴 Authorized Use Only

```
⚠️ LEGAL AND ETHICAL USE ONLY ⚠️

This platform includes tools and capabilities for:

✅ AUTHORIZED USES:
   • Penetration testing with explicit written authorization
   • Red team operations with organizational approval
   • Security assessments with client permission
   • RF monitoring and analysis on authorized frequencies
   • Mesh networking on licensed or unlicensed bands
   • Security research in isolated lab environments
   • Educational purposes with proper supervision
   • CTF competitions and authorized challenges

🚫 STRICTLY PROHIBITED:
   • Unauthorized penetration testing or network access
   • Intercepting communications without authorization
   • Transmitting on frequencies without proper licensing
   • WiFi deauthentication attacks on networks you don't own
   • Any use violating the Computer Fraud and Abuse Act (CFAA)
   • Any illegal or unethical activities
```

### RF and Radio Compliance

- **LoRa / Meshtastic**: Operates on ISM band (915 MHz US). No license required for low-power operation within FCC Part 15 limits.
- **RTL-SDR**: Receive-only device. Legal to receive in most jurisdictions, but intercepting certain communications (cellular, encrypted, private) may violate wiretapping laws.
- **WiFi Pentesting**: Monitor mode and packet injection are legal ONLY on networks you own or have explicit written authorization to test.

### Warranty Disclaimer

```
These guides are provided "AS IS" without warranty of any kind.

THE AUTHORS:
• Are not responsible for damages from guide use
• Do not warrant techniques will work in all environments
• Are not liable for legal consequences of misuse
• May update content without notice

USERS ACKNOWLEDGE:
• They use these guides at their own risk
• They are responsible for obtaining authorization
• They must comply with all applicable laws
• They are liable for their testing activities
```

---

## 📚 Resources

### Forum Threads

| Resource | URL |
|---|---|
| Rex's Kali Image | https://forum.clockworkpi.com/t/kali-6-12-y-for-the-uconsole-and-devterm/14463 |
| Rex's Trixie Image | https://forum.clockworkpi.com/t/trixie-6-12-y-for-the-uconsole-and-devterm/19457 |
| Rex's Bookworm Image | https://forum.clockworkpi.com/t/bookworm-6-12-y-for-the-uconsole-and-devterm/15847 |
| AIO Board Package | https://forum.clockworkpi.com/t/hackergadgets-aio-board-package/17875 |
| Updated Images (New Screens) | https://forum.clockworkpi.com/t/updated-images-for-new-uconsole-screens/21666 |

### Documentation & Guides

| Resource | URL |
|---|---|
| AIO v2 Setup Guide | https://hackergadgets.com/pages/hackergadgets-uconsole-rtl-sdr-lora-gps-rtc-usb-hub-all-in-one-extension-board-setup-guide |
| aiov2_ctl GitHub | https://github.com/hackergadgets/aiov2_ctl |
| uConsole GitHub (Official) | https://github.com/clockworkpi/uConsole |
| Meshtastic Firmware Releases | https://github.com/meshtastic/firmware/releases |

### Products

| Product | URL |
|---|---|
| AIO v2 Board | https://hackergadgets.com/products/uconsole-aio-v2 |
| uConsole Upgrade Kit | https://hackergadgets.com/products/uconsole-upgrade-kit |
| NVMe Battery Board | https://hackergadgets.com/products/nvme |

---

## 🔗 Quick Links

### Internal Links
- [🏠 Main Repository](../README.md)
- [🎯 START HERE Guide](../START_HERE.md)
- [💻 Cybersecurity Master Guide](../ultimate_cybersecurity_master_guide.md)
- [✅ Security Checklists](../Checklists/README.md)
- [🔍 OSINT Resources](../OSINT/README.md)
- [📚 Documentation](../Documentation/README.md)
- [🔒 OPSEC Guidelines](../OPSEC/README.md)

---

## 📊 Repository Statistics

```
📁 Setup Guides: 2 (CM4, CM5)
📖 Covers: OS setup, AIO v2 board, NVMe, WiFi, LoRa, GPS, SDR, RTC
🔄 Last Updated: June 2026
👥 Maintained by: Pacific Northwest Computers (PNWC)
📝 Status: Active & Growing
```

---

<div align="center">

**📖 Build Responsibly: Authorization is MANDATORY for Pentesting**

*A pocket-sized SIGINT and pentesting platform — use it ethically and legally.*

**Repository**: [ULTIMATE CYBERSECURITY MASTER GUIDE](https://github.com/Pnwcomputers/ULTIMATE-CYBERSECURITY-MASTER-GUIDE)

**Maintained by**: [Pacific Northwest Computers](https://github.com/Pnwcomputers)

---

⚠️ **WiFi pentesting and network attacks require WRITTEN AUTHORIZATION** ⚠️

⚠️ **Unauthorized access is a FEDERAL CRIME under the CFAA** ⚠️

⭐ **Star this repo if you find it useful!** ⭐

</div>
