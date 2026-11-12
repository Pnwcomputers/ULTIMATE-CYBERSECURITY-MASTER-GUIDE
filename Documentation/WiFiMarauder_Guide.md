# WiFi Marauder Guide

## Current Installer & Survey Alternatives

Use the [upstream install/update wiki](https://github.com/justcallmekoko/ESP32Marauder/wiki/update-firmware)
and [JCMK installer](https://justcallmekoko.github.io/MarauderInstaller/) for the
exact hardware revision. A Flipper FAP is a separate artifact from its accessory's
ESP firmware. Do not infer supported bands or GPS/SD locations from a family name.

| Resource | Role & Compatibility Boundary |
|---|---|
| [GhostESP Revival](./ghostesp-revival.md) | Alternative multi-function wireless platform; different configuration, capture and export paths. |
| [C5 Wardriver](../Wardriving/esp32-c5-wardriver.md) | Dedicated standalone/Node/Core survey firmware; separate installer and role-dependent logger. |
| [Piglet](../Wardriving/piglet.md) | Standalone and mesh collection with explicit boot/upload automation review. |
| [BLE Capture / Sniffle](./ble-capture-sniffle.md) | Choose advertisement inventory versus connection/PHY-aware BLE packet capture. |

## Firmware Catalog & Installers

| Resource | Description |
|---|---|
| [ESP32 & Related Firmware Catalog](./esp32-security-firmware-catalog.md) | Primary upstream projects, supported targets, use-cases & dated activity notes |
| [Firmware Web Flashers](./firmware-web-flashers.md) | Dedicated installers plus a separate multi-device/multi-firmware reference |

## 🎯 Purpose
Comprehensive guide for ESP32 Marauder firmware covering hardware selection, installation, all core attack and detection features, integration with external tools (Hashcat, Wireshark, Kismet), and detection/defense strategies.

For identifying **legitimate versus spoofed** deauthentication/disassociation frames using passive captures, PMF analysis and corroborating wireless IDS logs, see the separate [Wi-Fi Deauthentication Detection Guide](./wifi-deauthentication-detection.md). Ordinary wireless surveys do not authorize disruptive testing.

## ⚙️ Function
Organized as a reference guide from hardware selection through advanced attack scenarios: WiFi scanning, deauthentication, beacon spam, PMKID capture, evil twin, BLE operations, GPS wardriving, and post-capture Hashcat cracking. For the condensed on-device cheat sheet, see [WifiMarauder_CheatSheet.md](WifiMarauder_CheatSheet.md).

## 🏆 Goal
Enable security professionals to select the right Marauder hardware variant, flash and configure it, execute authorized WiFi security assessments, and integrate captures into a full cracking pipeline.

## 📋 When to Use
- Planning a Marauder deployment and need hardware/firmware selection guidance
- Executing a full WiFi security assessment including post-capture cracking
- Building detection rules for deauth floods, beacon spam, or rogue APs
- Wardriving with GPS-tagged AP discovery for site surveys

## Professional Wireless Security Testing with ESP32 Hardware

> **For:** Security professionals, wireless penetration testers, researchers, and enthusiasts  
> **Original guide baseline:** November 2025  
> **Companion project links checked:** October 26, 2026  
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

### Related ESP32 assessment platforms (separate firmware)

The following starred upstream projects are useful when selecting a **different platform** for an isolated wireless-security lab:

- [GhostESP](https://github.com/GhostESP-Revival/GhostESP) — ESP-IDF-based ESP32 Wi-Fi/BLE research firmware.
- [projectZero](https://github.com/C5Lab/projectZero) — ESP32-C5/Flipper wireless testing with active assessment features; verify board-specific firmware.
- [Adversary](https://github.com/Isonimus/adversary) — ESP32-oriented multiradio/security research, with supported hardware determining which RF capabilities actually exist.
- [WiFiForge](https://github.com/blackhillsinfosec/WifiForge) — a wireless training environment for practicing and detecting Wi-Fi attacks in a controlled lab.

These are **not Marauder installation sources**: never cross-flash a binary without checking the exact board, flash layout, firmware documentation and recovery path. Keep transmission-based tests isolated and explicitly authorized. For inventory-only work, follow [Wardriving](../Wardriving/README.md).

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

All attack techniques require **written authorization** before use. See [WifiMarauder_CheatSheet.md](WifiMarauder_CheatSheet.md) for the condensed command-only reference.

### 1. Reconnaissance — Scan for APs

Before any attack, identify the target's BSSID (AP MAC) and channel.

**Menu:** `WiFi → Scan / Sniff → Scan APs`

- Populates the AP list with BSSID, SSID, channel, RSSI, and encryption type.
- Set the device to the target channel for best capture results:
  `Settings/Device → WiFi Settings → Set Channel`

---

### 2. PMKID / Handshake Capture

The primary passive capture mode. Attempts to grab both PMKID frames and 4-way EAPOL handshakes without sending any deauth frames.

**Menu:** `WiFi → Scan / Sniff → PMKID`

- Capture file is saved to SD card as `YYYYMMDD_TIME.pcapng`.
- PMKID capture works without a client connected to the AP — just needs the AP in range.
- EAPOL handshake requires a client to authenticate during the capture window.

**When to use:** Start here. Passive, no deauth noise, works against WPA2/WPA3.

---

### 3. Deauth Attack — Force Handshake Capture

If PMKID capture yields no usable frames, send deauthentication frames to force connected clients to re-authenticate, triggering a new EAPOL handshake.

**Menu:** `WiFi → Attack → Deauth → Deauth All Clients`

- Select the target AP (BSSID) from the scanned AP list.
- Run PMKID capture (Step 2) simultaneously in the background — the handshake fires when the client reconnects.
- **Targeted deauth:** Choose a specific client STA from the station list instead of "All Clients" to minimize noise.

**When to use:** After a passive capture attempt yields no handshake. More visible — generates 802.11 deauth frames detectable by WIDS.

---

### 4. Beacon Spam

Broadcasts a large number of fake SSIDs (beacon frames) to pollute client probe request logs, trigger WIDS alerts, or collect client probe requests for profiling.

**Menu:** `WiFi → Attack → Beacon Spam → Enable/Disable`

- **Funny SSIDs mode:** Broadcasts a built-in list of joke/provocative SSIDs — useful for social engineering awareness demonstrations.
- **Custom SSID mode:** Broadcast a specific SSID (used as a component of Evil Twin attacks).
- Generates significant RF noise — use with caution in dense environments.

**When to use:** Social engineering demonstrations, WIDS testing, client probe collection during authorized assessments.

---

### 5. Evil Twin (Rogue AP)

Clones a legitimate AP's SSID to lure clients into connecting to a controlled access point, then serves a captive portal to capture credentials or perform a man-in-the-middle attack.

**Marauder's role (RF layer):**
1. Scan and identify the target SSID + BSSID + channel.
2. Use **Beacon Spam** with the cloned SSID on the same channel to broadcast a competing AP.
3. Use **Deauth** against the legitimate AP to force clients to disconnect and probe for reconnection.

**External component required (captive portal):**
- Marauder handles the RF attack layer but does not run a full DHCP/HTTP stack.
- Pair with a Raspberry Pi, laptop running hostapd + dnsmasq, or a WiFi Pineapple to serve the captive portal and capture credentials.
- Alternatively, the [Evil-M5Project (evil_m5.md)](evil_m5.md) on an M5Cardputer provides a built-in captive portal with credential logging.

**When to use:** Red team wireless footholds, credential capture assessments with explicit written authorization. 802.11w/PMF-protected networks are resistant to deauth-based client forcing.

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

## Dedicated Standalone Marauder Deployment Playbook

_Last source review: November 2026. These are procedure designs, not a claim of hands-on firmware testing._

**Architecture:** standalone Marauder runs directly on a supported ESP32 board with a touch display, 5-way control, or USB serial CLI. The [Flipper Zero companion workflow](./flipper_zero_guide.md#flipper-marauder-companion-deployment-labs) uses **separate Flipper application firmware plus the Marauder ESP32 accessory**; the Flipper itself is not running Marauder or gaining an internal Wi-Fi radio. See also [Marauder GPS wardriving](../Wardriving/esp32-marauder.md).

### Hardware, Image & Installer Decision Table

| Owned device | Correct target / operational consideration |
|---|---|
| Marauder v4 | Legacy display variant; application image suffix `_old_hardware.bin` |
| Marauder v6 | Confirm printed PCB revision; suffix `_v6.bin` |
| Marauder v6.1/v6.2 | Revised hardware; suffix `_v6_1.bin` |
| Marauder v7 | Dedicated `_marauder_v7.bin` |
| Marauder v8 (ESP32-C5) | `_v8.bin`, dual-band capability with matching supported hardware |
| Marauder Mini and Mini v3 | Separate `_mini.bin` / `_mini_v3.bin` targets |
| DIY ESP32-C5 / XIAO C5 / T-Dongle C5 | Different build targets; no universal C5 binary |
| Flipper Zero WiFi Dev Board | Use the [Flipper procedure](./flipper_zero_guide.md#flipper-marauder-companion-deployment-labs), suffix `_flipper.bin`, not a display-target binary |

**Verification:** consult the live [Supported Hardware](https://github.com/justcallmekoko/ESP32Marauder/wiki/Supported-Hardware), [Update Firmware](https://github.com/justcallmekoko/ESP32Marauder/wiki/Update-Firmware) and [release assets](https://github.com/justcallmekoko/ESP32Marauder/releases). The table is intentionally not a substitute for those pages. Some images, menus, storage interfaces, BLE support and 5 GHz functions are target-specific.

1. Record chip, complete board model/PCB revision, flash/PSRAM capacity, radio, display type, SD wiring, existing version, and backup of logs.
2. On a dedicated operator computer, launch the upstream [Marauder Installer](https://justcallmekoko.github.io/MarauderInstaller/) or follow that hardware's documented update path. Use a **data** USB cable and stable supply.
3. Select the complete, matching hardware profile. An application `.bin` alone may **not** include the bootloader, partitions and OTA data required for first installation or a partition migration. Never guess flash offsets.
4. Verify boot, menu/display/serial control, physical input, radio scan, SD write, and available GNSS **individually**. Failure to see 5 GHz on a classic ESP32 is not by itself a defect.
5. Keep active radio transmission modes disabled until the test-specific authorization is recorded. Do not infer an observation-only feature is radio silent merely because its name contains "scan".
6. Save a board profile with firmware release URL, binary hash, configuration backup, permitted channels, and operator notes.

### Lab M1 — Known-AP Inventory & Channel Coverage

**Objective:** discover an explicitly owned lab AP and independently confirm its configuration.

1. Record the lab AP's SSID, BSSID, channel and intended WPA2/WPA3 configuration from the controller.
2. Run Marauder's supported Wi-Fi AP scan, beginning with the default observe-only settings. Scan a bounded area and duration, noting if the selected mode sends probe requests.
3. Compare results to the AP controller. Distinguish BSSID from SSID: one SSID may be broadcast from many radios and bands.
4. Retest on a second channel/band **only when the board supports it**. Record missing-band capability rather than incorrectly reporting a missing AP.
5. Capture screenshots or exported logs, scan settings, time, antenna orientation and firmware. An unfamiliar BSSID is **unverified**, not automatically rogue.

**Acceptance:** at least one matching owned BSSID appears; results and exclusions are reproducible.

### Lab M2 — SD Logging & Artifact Integrity

1. Format/prepare the card as specified by the particular Marauder hardware; test the card on a non-client device first.
2. Conduct one short scan of an owned AP, then stop using the firmware's documented controls. Wait for media writes to complete before removing power or SD.
3. Enumerate actual files instead of assuming the board always uses a given directory. On a Linux evidence machine, calculate a digest for **the actual captured file**:

~~~bash
sha256sum /path/to/approved/scan-export.csv
file /path/to/approved/scan-export.csv
~~~

4. Preserve the unmodified original; create redacted analysis copies. Log evidence source, collection time, firmware, path, digest, and chain of custody.
5. If no output appears, check board SD support and scan-versus-save behavior before assuming collection failed.

### Lab M3 — GPS Wardrive & Local-Only Export

1. Verify that GPS is supported, wired and configured for the specific board; acquire an outdoor fix with plausible coordinates.
2. Read the [dedicated wardriving procedure](../Wardriving/esp32-marauder.md#start-a-wi-fi-ap-wardrive) for `wardrive` / `stopscan`, geofence caveats and `wardrive_` output.
3. Walk a short **authorized** route covering a known AP, then stop and verify the generated rows have timestamps, location and BSSID/channel information as expected.
4. Label rows recorded with poor GNSS accuracy; record missing fixes instead of inventing coordinates.
5. Keep sessions **local by default**. WiGLE/third-party upload is a separate data-disclosure authorization; check credentials and upload scope explicitly.

### Lab M4 — BLE Advertisement Awareness (Target-Supported)

1. Confirm the current ESP32 variant and firmware actually offer the BLE feature; an ESP32-S2 WiFi Dev Board is not interchangeable with BLE-capable ESP32 targets.
2. Place an owned BLE beacon near the device. Start an ordinary BLE discovery mode; record advertising name/address type, RSSI, and first/last-seen time **if available**.
3. Move the test beacon to multiple positions and compare RSSI trends, noting shielding and reflections. RSSI alone is not an accurate distance measurement.
4. Clear and preserve only permitted data. A discovered BLE advertisement is neither proof of an exploitable vulnerability nor reliable proof of device ownership.

### Lab M5 — Authorized Rogue-AP Recognition & WIDS Validation

1. Obtain approval for a separate **unique** training SSID such as `PNWC-MARAUDER-LAB-01`, broadcast by an independently controlled test AP. Do **not** clone the customer's SSID.
2. Record time, BSSID, band, channel and owner. Turn on the test AP without involving production clients.
3. Observe it with Marauder; cross-check with [Kismet + Wazuh](../IncidentResponse/IDS%26IPS/kismet-wazuh-wireless-lab.md) or [nzyme + Wazuh](../IncidentResponse/IDS%26IPS/nzyme-wazuh-integration.md) monitoring.
4. Compare actual WIDS alerts and AP-controller inventory. An absent alert may reflect sensor coverage, ingestion or rule configuration.
5. Turn off the test AP, verify disappearance and record cleanup.

### Lab M6 — Defensive Management-Frame Review

1. On an isolated lab AP under administrative control, compare controller settings for WPA2/WPA3, Protected Management Frames (PMF/802.11w) and WPS.
2. Observe security capabilities from Marauder where exposed; **verify settings in the controller** rather than inferring negotiated security from a scan alone.
3. Use controller audit logs and client configuration to evaluate PMF requirements; avoid disruptive deauth or handshake-forcing tests on production systems.
4. Document compatibility exceptions and recommend tested, appropriate controls.

### Standalone vs Flipper Result Matrix

| Question | Standalone Marauder | Flipper Companion + Marauder |
|---|---|---|
| What runs Marauder? | The device's ESP32 | The external ESP32 accessory |
| UI | Supported onboard display/joystick or serial CLI | Flipper app communicates with accessory over UART |
| Firmware artifact | Device-specific standalone image | Board-specific ESP32 image **plus** matching Flipper FAP |
| Logs | Board SD/serial paths depend on firmware | Board SD or Flipper SD depending on build/app feature |
| GNSS | Built-in or board-wired compatible receiver | Only if accessory/wiring/app support it |
| 5 GHz | ESP32-C5 and supported hardware only | Only if the particular attached module/radio supports it |

**Negative control:** scan an in-scope SSID that was deliberately disabled at the AP controller and compare with an enabled SSID. Do not report absence as definitive without coverage, timing and channel notes.

### Evidence, Troubleshooting & Report Criteria

| Symptom | First checks |
|---|---|
| Black/incorrect display after flash | Actual PCB revision, selected binary, display variant and flash layout |
| AP shows on another tool but not Marauder | Band/channel compatibility, scan dwell, antenna and firmware mode |
| BLE function absent | ESP32 chip support and build feature flags |
| Empty GPS file | Fix quality, board wiring, logging state, card presence |
| Flipper companion unavailable | Use the separate [Flipper guide](./flipper_zero_guide.md#flipper-marauder-companion-deployment-labs) |
| Scan results differ from AP controller | Multiple BSSIDs, hidden/roaming configurations, stale observations |

Every delivered finding must include test ID, written scope, exact board/firmware, capture method, timestamp/time zone, observed versus inferred result, evidence hash where applicable, source configuration comparison, mitigation, and retest procedure. Avoid sharing third-party device identifiers, geolocation, or raw personal traffic.

## Advanced Attack Scenarios

- **Corporate WiFi Assessment** - enumerate all SSIDs, identify open/WEP/WPA2-Personal networks, capture PMKIDs, assess 802.11w/PMF enforcement
- **Red Team Wireless Foothold** - evil twin + captive portal credential capture, then lateral movement on the authenticated network
- **IoT Security Testing** - identify IoT SSIDs and weak-PSK networks via PMKID capture; assess device isolation
- **WiFi Pineapple Emulation** - beacon spam + deauth + KARMA-style attacks replicating Pineapple PineAP behavior
- **Backdoor/Persistence Simulation (lab only)** - demonstrate persistent rogue AP detection gaps in WIDS

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

## Appendix A - Historical Menu Map (v1.8.9; Verify Against Installed Firmware)

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
- [README.md](README.md) - Documentation section index: all guides and cheat sheets in this directory
- [WifiMarauder_CheatSheet.md](WifiMarauder_CheatSheet.md) - Quick-reference on-device commands and post-capture workflow
- [hcxtoolshashcat.md](hcxtoolshashcat.md) - hcxpcapngtool + Hashcat mode 22000 cracking workflow for Marauder captures
- [Aircrack-ng_Commands.md](Aircrack-ng_Commands.md) - Traditional deauth-forced handshake capture with aircrack-ng
- [flipper_zero_guide.md](flipper_zero_guide.md) - Flipper Zero + ESP32 Dev Board running Marauder firmware
- [evil_m5.md](evil_m5.md) - M5Cardputer Evil-M5Project: alternative ESP32 WiFi attack platform
- [pwnagotchi_cheatsheet.md](pwnagotchi_cheatsheet.md) - Pwnagotchi: autonomous passive WiFi capture on Pi

---

[Section Index](README.md) | [Master Index](../README.md) | [Legal Notice](../LEGAL.md)
