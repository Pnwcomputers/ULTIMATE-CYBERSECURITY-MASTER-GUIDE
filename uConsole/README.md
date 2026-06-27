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
- [Common Setup Sequence (The 6-Phase Approach)](#common-setup-sequence-the-6-phase-approach)
- [Security & Legal Disclaimer](#security--legal-disclaimer)
- [Resources](#resources)

---

## 🎯 Overview

This directory contains **complete, step-by-step build guides and automated deployment scripts** for turning a ClockworkPi uConsole into a field-deployable hacking and SIGINT platform using the HackerGadgets AIO v2 extension board.

**What This Covers:**
- ⚙️ **Automated setup scripts** (`uconsole-cm5-setup.sh`) for hardened, error-free deployments
- 📡 **RTL-SDR** setup and configuration (100 kHz – 1.74 GHz)
- 📻 **LoRa / Meshtastic** mesh networking (SX1262)
- 🛰️ **GPS** receiver configuration and PPS timing
- ⏰ **Hardware RTC** with battery backup (PCF85063A)
- 🔌 **NVMe storage** via the HackerGadgets NVMe Battery Board
- 🌐 **Gigabit Ethernet** via RJ45 (Upgrade Kit required)
- 📶 **WiFi pentesting** with external monitor-mode adapters
- 🔧 **GPIO power control** via `aiov2_ctl`
- 🐧 **OS setup** for both Kali Linux and Debian Trixie (Rex's images)
- ⚠️ **Known package conflicts and automated fixes** (cryptsetup, LightDM, Trixie dependency drift, `libfm` ABI mismatch)

### Purpose

These guides serve as:
- **Step-by-step build documentation** — Flash to fully operational
- **Hardware reference** — GPIO pinouts, SPI mappings, antenna connectors
- **Troubleshooting playbook** — Every issue we've hit and fixed
- **Pentest platform quick-start** — Kali tools, WiFi adapters, LAN drop box config

---

## 📂 Setup Guides

| Guide | Compute Module | Description |
|-------|---------------|-------------|
| **[CM4-SETUP.md](./CM4-SETUP.md)** | Raspberry Pi CM4 | Complete CM4 manual setup — most mature and community-tested configuration. |
| **[CM5-SETUP.md](./CM5-SETUP.md)** | Raspberry Pi CM5 | Complete CM5 setup — features the `uconsole-cm5-setup.sh` automated installer, USB 3.0, and native PCIe configurations. |

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
| Everything pre-installed | Can hit `cryptsetup-initramfs` failures if not hardened |
| Familiar to pentesters | Trackball slightly less responsive |
| Kali community support | Requires LightDM session pinning |

### Path B: Rex's Trixie + Kali Tools (Recommended)

Debian 13 base with Kali rolling repo layered on top.

| Pros | Cons |
|---|---|
| Newest packages | Extra setup step for Kali tools |
| Fewer package conflicts | Must carefully manage `raspberrypi-sys-mods` |
| Best trackball behavior | Requires precise APT pinning to avoid `libfm` ABI mismatch |
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

```bash
aiov2_ctl                           # Show current GPIO state
aiov2_ctl <FEATURE> <on|off>        # Toggle: GPS, LORA, SDR, USB
aiov2_ctl --status                  # Detailed status (GPIO + battery + power)
aiov2_ctl --gui                     # Launch system tray GUI
aiov2_ctl --boot-rail <FEAT> on     # Auto-enable at boot
aiov2_ctl --sync-rtc                # Write system time to hardware RTC
```

---

## 🔧 Common Setup Sequence (The 6-Phase Approach)

Our latest documentation uses a strict **"Harden first, upgrade second, then install"** methodology to prevent bricked installations. On the CM5, this entire process is automated via `uconsole-cm5-setup.sh`.

```text
Phase 1: Pre-Flight Hardening
   └─> Disable cryptsetup-initramfs to prevent boot failures
   └─> Pin LightDM sessions safely so upgrades don't break the GUI
   └─> [Trixie] Safely manage raspberrypi-sys-mods
   └─> [Trixie] Inject Kali rolling repo with a narrow, protected APT pin

Phase 2: First System Upgrade
   └─> apt full-upgrade (now safe to run)
   └─> Set hostname

Phase 3: Kali Tools Integration
   └─> Install target metapackage (e.g., kali-tools-top10)

Phase 4: AIO Board Ecosystem
   └─> Install aiov2_ctl from source
   └─> Inject legacy dependencies (libgpiod2, libyaml-cpp0.7) if missing
   └─> Install hackergadgets-uconsole-aio-board, meshtastic-mui
   └─> Install ADS-B trackers (readsb, tar1090)

Phase 5: Peripheral Configuration
   └─> Free serial port for GPS UART
   └─> Enable SPI overlays and hardware RTC mappings
   └─> Blacklist DVB-T driver for RTL-SDR
   └─> Disable conflicting services (devterm-printer)
   └─> Set boot rails for GPS, LoRa, and SDR

Phase 6: Finalization & Verification
   └─> Perform automated sanity checks on configs and dependencies
   └─> Manual hand-off: set timezones, passwords, connect antennas
```

---

## ⚠️ Security & Legal Disclaimer

### 🔴 Authorized Use Only

```text
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

```text
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
| Rex's Kali Image | [https://forum.clockworkpi.com/t/kali-6-12-y-for-the-uconsole-and-devterm/14463](https://forum.clockworkpi.com/t/kali-6-12-y-for-the-uconsole-and-devterm/14463) |
| Rex's Trixie Image | [https://forum.clockworkpi.com/t/trixie-6-12-y-for-the-uconsole-and-devterm/19457](https://forum.clockworkpi.com/t/trixie-6-12-y-for-the-uconsole-and-devterm/19457) |
| Rex's Bookworm Image | [https://forum.clockworkpi.com/t/bookworm-6-12-y-for-the-uconsole-and-devterm/15847](https://forum.clockworkpi.com/t/bookworm-6-12-y-for-the-uconsole-and-devterm/15847) |
| AIO Board Package | [https://forum.clockworkpi.com/t/hackergadgets-aio-board-package/17875](https://forum.clockworkpi.com/t/hackergadgets-aio-board-package/17875) |
| Updated Images (New Screens) | [https://forum.clockworkpi.com/t/updated-images-for-new-uconsole-screens/21666](https://forum.clockworkpi.com/t/updated-images-for-new-uconsole-screens/21666) |

### Documentation & Guides

| Resource | URL |
|---|---|
| AIO v2 Setup Guide | [https://hackergadgets.com/pages/hackergadgets-uconsole-rtl-sdr-lora-gps-rtc-usb-hub-all-in-one-extension-board-setup-guide](https://hackergadgets.com/pages/hackergadgets-uconsole-rtl-sdr-lora-gps-rtc-usb-hub-all-in-one-extension-board-setup-guide) |
| aiov2_ctl GitHub | [https://github.com/hackergadgets/aiov2_ctl](https://github.com/hackergadgets/aiov2_ctl) |
| uConsole GitHub (Official) | [https://github.com/clockworkpi/uConsole](https://github.com/clockworkpi/uConsole) |
| Meshtastic Firmware Releases | [https://github.com/meshtastic/firmware/releases](https://github.com/meshtastic/firmware/releases) |

### Products

| Product | URL |
|---|---|
| AIO v2 Board | [https://hackergadgets.com/products/uconsole-aio-v2](https://hackergadgets.com/products/uconsole-aio-v2) |
| uConsole Upgrade Kit | [https://hackergadgets.com/products/uconsole-upgrade-kit](https://hackergadgets.com/products/uconsole-upgrade-kit) |
| NVMe Battery Board | [https://hackergadgets.com/products/nvme](https://hackergadgets.com/products/nvme) |

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

```text
📁 Setup Guides: 2 (CM4, CM5) + 1 Automation Script
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
