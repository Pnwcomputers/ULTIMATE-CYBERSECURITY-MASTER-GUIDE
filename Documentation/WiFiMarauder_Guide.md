# WiFi Marauder Guide

## 🎯 Purpose
Full deep-dive on the ESP32 Marauder firmware and hardware ecosystem — hardware selection, firmware installation, the complete feature set, and defensive/legal guidance. This is the reference document; [WifiMarauder_CheatSheet.md](WifiMarauder_CheatSheet.md) is the quick on-device command lookup once you already own and understand the hardware.

## ⚙️ Function
Fourteen sections covering hardware options and comparison against competing tools (WiFi Pineapple, HackRF, Flipper Zero, Pwnagotchi), firmware installation/flashing, the full menu/feature inventory, advanced attack scenarios, and detection/defense strategies. Unlike the cheat sheet, this file explains *why* and *when*, not just menu paths — read it once when evaluating or first setting up the hardware.

## 🏆 Goal
Choose the right Marauder hardware variant, get it flashed and configured, and understand the full attack/defense surface well enough to run an authorized wireless assessment and brief a client on findings.

## 📋 When to Use
- Evaluating which ESP32 Marauder hardware variant to buy
- First-time firmware flash/setup on new hardware
- Building the defensive/detection section of a wireless assessment deliverable

## Professional Wireless Security Testing with ESP32 Hardware

> **For:** Security professionals, wireless penetration testers, researchers, and enthusiasts  
> **Last Updated:** November 2025  
> **Firmware:** ESP32 Marauder **v1.8.9** (and 1.8.x improvements)  
> **Skill Level:** Intermediate to Advanced wireless security

---

## Table of Contents

1. [Executive Overview](#executive-overview)  
2. [Hardware Options & Selection](#hardware-options--selection)  
3. [Firmware Installation & Setup](#firmware-installation--setup)  
4. [Core Features & Capabilities](#core-features--capabilities)  
5. [WiFi Attack Techniques](#wifi-attack-techniques)  
6. [Bluetooth & BLE Operations](#bluetooth--ble-operations)  
7. [GPS & Wardriving Integration](#gps--wardriving-integration)  
8. [Advanced Attack Scenarios](#advanced-attack-scenarios)  
9. [Integration with External Tools](#integration-with-external-tools)  
10. [Custom Payload Development](#custom-payload-development)  
11. [Detection & Defense Strategies](#detection--defense-strategies)  
12. [Legal Framework & OPSEC](#legal-framework--opsec)  
13. [Troubleshooting & Optimization](#troubleshooting--optimization)  
14. [Community Resources & Development](#community-resources--development)

---

## Executive Overview

### What is WiFi Marauder?

The **ESP32 Marauder** is an advanced wireless security testing platform built on ESP32 microcontrollers. Created by **justcallmekoko**, it transforms affordable hardware into a powerful toolkit for:

- 🔍 **WiFi reconnaissance** and network discovery  
- 📡 **Packet sniffing** and PCAP capture  
- ⚡ **Deauthentication attacks** for security testing  
- 📱 **Bluetooth/BLE** scanning and exploitation  
- 🗺️ **GPS-enabled wardriving** with location tracking  
- 💾 **SD card logging** for extended capture sessions  
- 🎯 **Targeted attacks** against specific devices

### Why Use Marauder?

**Advantages over traditional tools**:
- **Portable:** Pocketable, battery-powered  
- **Affordable:** ~$50–$150 vs. $500+ for commercial tools  
- **Versatile:** WiFi, Bluetooth, GPS in one device  
- **Expandable:** Open-source firmware, active development  
- **Educational:** Learn wireless protocols hands-on  
- **Covert:** Small form factor for authorized testing

**Comparison to similar tools**:

| Feature | Marauder | WiFi Pineapple | HackRF One | Flipper Zero | Pwnagotchi |
|---------|----------|----------------|------------|--------------|------------|
| Price | $50–150 | $200–400 | $350+ | $170 | $50–100 |
| WiFi Attacks | ✅ Full | ✅ Full | ⚠️ Limited | ⚠️ Basic | ✅ Passive |
| Bluetooth | ✅ Yes | ❌ No | ✅ SDR | ✅ Yes | ❌ No |
| GPS | ✅ Optional | ❌ No | ❌ No | ❌ No | ✅ Optional |
| Portability | ✅ Excellent | ⚠️ Good | ⚠️ Fair | ✅ Excellent | ✅ Excellent |
| Battery | ✅ Built-in | ⚠️ External | ❌ No | ✅ Built-in | ✅ Built-in |
| AI/ML | ❌ No | ❌ No | ❌ No | ❌ No | ✅ Yes |

### Core Capabilities

**Offensive Capabilities**  
- Deauthentication flooding (targeted & broadcast)  
- Beacon spam with custom SSIDs (incl. “Funny SSIDs”)  
- Probe request sniffing  
- PMKID capture for WPA2 cracking  
- Evil twin AP / captive portal  
- Bluetooth spam (SwiftPair, Sour Apple)  
- **Association Sleep Attack** (1.8.x)  

**Defensive/Analysis**  
- Signal strength mapping  
- Channel utilization analysis  
- Client device enumeration  
- Rogue AP detection  
- Packet capture to PCAP  
- GPS-tagged wardrive logs + **POI markers** (1.8.x)  

> **New in v1.8.9:** **AirTag Monitor** (with **Last-Seen** timer) and on-device **Select .bin to flash** during self-update.

### Legal & Ethical Framework

⚠️ **CRITICAL WARNING**  
- **ONLY** test networks you own or have **written authorization** to test.  
- Unauthorized attacks are **illegal** in most jurisdictions.  
- You are responsible for complying with all laws and contracts.  
- Use this guide for **educational and authorized** security testing only.

---

## Hardware Options & Selection

### Official/Popular Marauder Hardware

**Option 1: Flipper Zero WiFi Dev Board ($50)**  
- ESP32-S2; 2.4 GHz WiFi; no BT; powered by Flipper.  
- Best for Flipper owners wanting WiFi capabilities.

**Option 2: ESP32 Marauder v6 / v6.1 / v7 ($80–$120)**  
- ESP32-WROOM-32; 2.4 GHz; Bluetooth Classic + BLE; TFT/OLED display; SD on some boards; integrated battery.  
- Best for standalone portable operations.

**Option 3: ESP32 Marauder Mini ($60–$80)**  
- Smaller form factor; OLED; typically no SD; smaller battery.  
- Best for covert testing and pocket carry.

**Option 4: ESP32 Marauder Kits ($100–$150+)**  
- Adds **GPS module**, external antenna connectors, larger battery, case.  
- Best for wardriving and professional assessments.

**Option 5: ESP32-C5 DevKitC-1 (Dual-Band / Wi-Fi 6 capable)**  
- **Dual-band 2.4/5 GHz Wi-Fi 6** silicon; supported by Marauder with a dedicated installer path as of 1.8.x.  
- Ensure regional/DFS compliance when using 5 GHz.

### DIY Builds

**Budget Build (~$30)** and **Advanced Build (~$80)** options (ESP32 DevKit v1/WROVER, OLED/TFT, SD, GPS, charging circuit, external antenna).  
**Antenna Mod:** U.FL pigtail + external omni/panel/Yagi/cantenna for improved gain.

> **Tip:** Keep antenna keep-out clear, add ESD on USB, and proper battery protection.

## JustCallMeKoko Online Stores:
- **[Main Online Store](https://justcallmekokollc.com/)**
- **[Tindie Store](https://www.tindie.com/stores/justcallmekoko/)**
---

## Firmware Installation & Setup

### Prerequisites

- Python 3.7+ (`esptool`, `pyserial`), USB drivers (CH340/CP210x), and `git`.

### Getting the Firmware

- **Stable Release (v1.8.9):** Use the release assets for your board (v4/v6/v6.1/v7/Kit/Mini/Flipper/MultiBoard S3/CYD/M5 Cardputer/**ESP32-C5 DevKit**, etc.).  
- The release page lists exact **binary names** per hardware.

### Flashing Methods

1) **Web Flasher** – via browser serial tools.  
2) **Marauder Flasher (Windows)** – GUI flasher.  
3) **`esptool.py`** – cross-platform CLI (erase + write at `0x10000`, or full layout).  
4) **Arduino IDE** – for development (boards manager + required libraries).

**New in v1.8.9 – On-device self-update picker:** You can **select a `.bin` file from a list** on the device to flash, handy when keeping multiple builds on SD.

### Initial Configuration

- Serial @ 115200 for boot logs and menu.  
- Menu: WiFi (Scan/Attack/Sniff/AP/General), Bluetooth (Scan/Spam/**AirTag Monitor**), GPS (Data/**POI**), Settings/Device, Reboot.  
- AirTag Monitor and GPS menus appear only when supported by hardware.

---

## Core Features & Capabilities

### WiFi Scanning & Sniffing

- **AP Scan / Station Scan** (with **Select All** convenience in 1.8.x).  
- Sniffers: Beacons, Probes, PMKID, PCAP.  
- **Service Discovery & Quick Triage (1.8.x):** **ARP scan**, **SSH scan**, **Telnet scan**, and **new port-scan presets** help quickly profile targets before pivoting to full tools.

### Attacks

- **Deauth** (targeted/broadcast), **Beacon/Probe floods**, Evil Twin/Captive Portal, Rickroll/“Funny SSIDs”.  
- **Association Sleep Attack (1.8.x):** low-airtime association/roaming stress pattern for scoped testing.

### WiFi General / Utilities (1.8.x)

- **SoftAP toggle** to stand up a quick AP for demos/tests.  
- **Join with saved Wi-Fi credentials**.  
- Handy list management (APs/Stations/EP file selection).

### Bluetooth & BLE

- BLE and Classic scanning, spam (SwiftPair, Sour Apple), vendor/manufacturer data parsing.  
- **New – AirTag Monitor (v1.8.9):** detect nearby AirTags and show **Last-Seen** timer to gauge persistence/movement during authorized investigations.

### GPS (if equipped)

- GPS status/data, wardrive logging, and **POI markers** (drop waypoints during surveys for later analysis/heat-mapping).  
- The **GPS menu only shows if a GPS is attached**.

---

## WiFi Attack Techniques

<!-- TODO: Expand with full deauth/beacon/PMKID/Evil Twin workflow detail from WifiMarauder_CheatSheet.md -->
See [WifiMarauder_CheatSheet.md](WifiMarauder_CheatSheet.md) for the condensed on-device workflow reference.

---

## Bluetooth & BLE Operations

### AirTag Monitor (v1.8.9)

**Purpose:** Detect nearby **Apple AirTags** and track **Last-Seen** timing to identify potential trackers persisting around test subjects or areas.  
**Menu:** `Bluetooth → AirTag Monitor`  
**Output:** device ID, RSSI, **Last-Seen** (hh:mm:ss).  
**Field Use:** Walk the route and watch **Last-Seen** shrink/grow; combine with **GPS POIs** to flag recurring spots.

---

## GPS & Wardriving Integration

- GPS wiring (NEO-6M/8M/M9N), TinyGPS++ setup, and logging.  
- **POI Markers:** mark locations during wardrives (e.g., suspicious SSIDs, repeated trackers) for post-processing maps.  

**Data Formats:** KML, WiGLE CSV, and custom JSON.  
**Visualization:** Folium heatmaps; stats (open/WEP/WPA2/WPA3 counts, channel distribution, top OUIs).

---

## Advanced Attack Scenarios

- **Corporate WiFi Assessment** — enumerate all SSIDs, identify open/WEP/WPA2-Personal networks, capture PMKIDs, assess 802.11w/PMF enforcement
- **Red Team Wireless Foothold** — evil twin + captive portal credential capture, then lateral movement on the authenticated network
- **IoT Security Testing** — identify IoT SSIDs and weak-PSK networks via PMKID capture; assess device isolation
- **WiFi Pineapple Emulation** — beacon spam + deauth + KARMA-style attacks replicating Pineapple PineAP behavior
- **Backdoor/Persistence Simulation (lab only)** — demonstrate persistent rogue AP detection gaps in WIDS

---

## Integration with External Tools

- **Wireshark:** live bridge or save PCAP.  
- **Hashcat:** PMKID/handshake cracking.  
- **Kismet:** drone feed mode.  
- **Pwnagotchi:** optional plugin for coordinated scans/deauth.  
- **Quick Network Triaging (1.8.x):** On-device **ARP/SSH/Telnet** scans + **port-scan presets** before deeper enumeration.

---

## Custom Payload Development

- Extend menus and data exports for **AirTag Monitor** and **GPS POI** features.  
- Add API hooks for new bin picker or OTA updater.

---

## Detection & Defense Strategies

- IDS rules for deauth/beacon floods.  
- Behavioral indicators (rapid channel hopping, many SSIDs per MAC, abnormal mgmt-frame rates).  
- Hardening (802.11w PMF, isolation).  
- Client protections (Windows/macOS/Linux).  
- Incident response and containment workflow.

**New BLE Indicator (v1.8.9):** consider **AirTag beacon** patterns and **Last-Seen** trends as contextual indicators during blue-team exercises.

---

## Legal Framework & OPSEC

- **Authorization templates**, scope boundaries, data handling, chain of custody.  
- **OPSEC:** MAC randomization, hostname obfuscation, encrypted storage, secure deletion.  
- **5 GHz (ESP32-C5):** obey DFS/regional RF laws.

---

## Troubleshooting & Optimization

- Boot/flash/display/SD fixes, compilation errors, and SD mount issues.  
- Performance tuning (heap/PSRAM, power management).  
- **GPS Menu Visibility:** shows only when module attached (1.8.9).  
- **Self-Update Bin Picker:** select `.bin` file directly from SD (1.8.9).

---

## Community Resources & Development

- **GitHub:** source, releases, issues, wiki.  
- **Discord:** community and beta testing.  
- **Contribution:** Arduino/CLI environment setup, PR style, code examples.

---

## Appendix A — Updated Menu Map (v1.8.9)

* **Main Menu**
    * **WiFi**
        * **Scan / Sniff**
            * Scan APs (Select All supported)
            * Scan Stations (Select All supported)
            * PMKID / PCAP / Probes / Beacons
            * ARP / SSH / Telnet scans
        * **Attack**
            * Deauth (targeted/broadcast)
            * Beacon Spam (incl. Funny SSIDs)
            * Probe Flood
            * Association Sleep Attack
        * **General**
            * SoftAP on/off
            * Join with saved creds
    * **Bluetooth**
        * Scan (Classic/BLE)
        * Spam (SwiftPair / Sour Apple)
        * AirTag Monitor (Last-Seen)
    * **GPS (if attached)**
        * Data
        * Add POI
    * **Settings / Device**
        * Display / Wi-Fi / MAC settings
        * Select .bin to flash
    * **Reboot**
---

## Conclusion

### Next Steps

1. **Choose hardware** (consider dual-band **ESP32-C5** where appropriate).  
2. **Flash v1.8.9** for your board from the release assets.  
3. **Practice** in a controlled lab or authorized environment.  
4. **Instrument** with Wireshark/Kismet/Hashcat for full workflows.  
5. **Contribute** fixes, docs, and features back to the community.

---

**Guide Version:** 1.0.1 (Updated for v1.8.9)  
**Author:** Security Professional  
**Repository:** https://github.com/justcallmekoko/ESP32Marauder  

**Questions / Issues / Contributions**  
- Open a GitHub issue  
- Join the Discord community  
- Submit PRs for improvements

*****

## Security and Ethical Considerations ⚠️

**IMPORTANT**: These tools are for **authorized security testing only**. Unauthorized use is illegal.

* **Marauder Use:** Get **written permission** before testing any network. Only test networks you own or have explicit authorization to test.
* **Cracking Use:** All cracking attempts (Hashcat) must be done in an **isolated lab environment** against hashes you are authorized to possess.
* **Legal Compliance:** Strictly comply with all local laws and regulations.

**Legal Use Cases:**
* Penetration testing with client authorization.
* Testing your own home or lab network security.
* Security research in isolated lab environments.

---

## Related Files
- [WifiMarauder_CheatSheet.md](WifiMarauder_CheatSheet.md) — Quick-reference on-device commands and post-capture workflow
- [hcxtoolshashcat.md](hcxtoolshashcat.md) — hcxpcapngtool + Hashcat mode 22000 cracking workflow for Marauder captures
- [Aircrack-ng_Commands.md](Aircrack-ng_Commands.md) — Traditional deauth-forced handshake capture with aircrack-ng
- [flipper_zero_guide.md](flipper_zero_guide.md) — Flipper Zero + ESP32 Dev Board running Marauder firmware
- [evil_m5.md](evil_m5.md) — M5Cardputer Evil-M5Project: alternative ESP32 WiFi attack platform
- [pwnagotchi_cheatsheet.md](pwnagotchi_cheatsheet.md) — Pwnagotchi: autonomous passive WiFi capture on Pi

---
