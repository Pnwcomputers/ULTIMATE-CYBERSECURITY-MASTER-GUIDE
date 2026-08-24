# 📻 SubGhz RF Exploration & Protocol Engineering Guide

<div align="center">

**Manual for multi-band signal capture, protocol reversing, and hardware security testing below 1 GHz and across the 2.4 GHz ISM bands**

*Part of the [ULTIMATE CYBERSECURITY MASTER GUIDE](../README.md)*

![SDR](https://img.shields.io/badge/Hardware-SDR-blue?style=for-the-badge&logo=broadcom)
![RF](https://img.shields.io/badge/Frequencies-Sub_GHz_%26_2.4GHz-green?style=for-the-badge&logo=wifi)
![GNURadio](https://img.shields.io/badge/Software-GNU_Radio-orange?style=for-the-badge)
![Protocols](https://img.shields.io/badge/Focus-Protocol_Reversing-red?style=for-the-badge)

</div>

---

## 🎯 Purpose

Comprehensive bench manual for SubGhz RF exploration - covering educational theory, multi-band signal capture procedures, laboratory logging documentation, software processing pipelines, and protocol architecture breakdowns for embedded, IoT, and access-control systems.

## ⚙️ Function

Walks through the full capture-to-analysis workflow across the major toolsets (Flipper Zero, HackRF One, RTL-SDR, ESP32 Marauder, Bruce firmware), then into GNU Radio flowgraph construction, transceiver chip selection (CC1101 vs. nRF24L01+), IQ troubleshooting, post-processing pipelines (URH, Wireshark, rtl_433), a master device/protocol reference matrix, a protocol profiles dictionary, and a standardized logging template.

## 🏆 Goal

Serve as the practical, repeatable reference for authorized RF security testing - taking a signal from unknown center frequency all the way to a documented, validated protocol breakdown, safely and legally.

## 📋 When to Use

- Identifying an unknown Sub-GHz or 2.4 GHz signal by center frequency and modulation
- Choosing the right capture hardware and modulation settings for a target device
- Reverse engineering a fixed-code vs. rolling-code protocol during an authorized assessment
- Documenting a reproducible capture session for a hardware security audit

---

## 📋 Table of Contents

- [Educational Foundations](#-1-educational-foundations)
- [Core Principles of Sub-GHz RF](#-2-core-principles-of-sub-ghz-rf)
- [Core Sub-GHz Protocol Concepts](#-3-core-sub-ghz-protocol-concepts)
- [Hardware Specific Operations & Flowcharts](#-4-hardware-specific-operations--flowcharts)
- [GNU Radio Flowgraph Guide (HackRF)](#-5-entry-level-gnu-radio-flowgraph-guide-hackrf)
- [Dedicated Hardware Chips: CC1101 vs. nRF24L01+](#-6-dedicated-hardware-chips-cc1101-vs-nrf24l01)
- [Troubleshooting: Clipping & Signal Distortion](#-7-troubleshooting-clipping--signal-distortion)
- [Post-Processing Pipeline](#-8-post-processing-pipeline)
- [Master Device & Protocol Reference Matrix](#-9-master-device--protocol-reference-matrix)
- [Protocol Profiles Dictionary](#-10-protocol-profiles-dictionary)
- [Laboratory Protocol Logging Template](#-11-laboratory-protocol-logging-template)
- [Example Project: Safe Garage Door Analysis](#-12-example-project-safe-garage-door-analysis)
- [⚠️ CRITICAL Security & Legal Warning](#️-critical-security--legal-warning)
- [Resources](#-resources)

---

### 🔴 CRITICAL WARNING

```
⚠️ RADIO FREQUENCY TRANSMISSION IS HEAVILY REGULATED ⚠️

Many procedures in this manual can involve TRANSMITTING radio signals, emulating
captured payloads, or replaying access-control codes. Unauthorized transmission is
a FEDERAL OFFENSE.

YOU MUST have explicit authorization, proper licensing (e.g., HAM Radio License),
and appropriate containment (Faraday bags/cages, dummy loads) before transmitting.

Improper use violates:
• Federal Communications Commission (FCC) Regulations - Massive fines & imprisonment
• Electronic Communications Privacy Act (ECPA) / Wiretap Act
• Federal Aviation Administration (FAA) laws
• Critical Infrastructure protection laws

RECEIVE-ONLY analysis on hardware you own is the default. Do NOT transmit toward
devices you do not own.
```

---

## 🎓 1. Educational Foundations

**The "Who, What, When, and Why" of RF Scanning.**

### What Is It?

SubGhz (Sub-Gigahertz) Radio Frequency (RF) scanning is the systematic monitoring, recording, and interpretation of electromagnetic waves travelling through free space. In the Sub-GHz spectrum (300 MHz to 928 MHz), signals are mostly comprised of short, bursting data packets transmitted by low-power embedded microcontrollers. In the 2.4 GHz spectrum, transmissions rely on complex, high-throughput channel-hopping network architectures.

### Who Uses It?

| Role | Application |
|------|-------------|
| **Embedded Engineers** | Debug wireless transceiver communications and ensure compliance with timing constraints |
| **Security Auditors** | Evaluate whether devices use unencrypted fixed-payload structures vulnerable to intercept or manipulation |
| **IoT Architects** | Measure environmental noise floors, optimize reception ranges, and check packet structures across mesh topologies |

### When Is It Conducted?

- **During Product R&D:** To verify custom hardware transmits strictly within regulatory bandwidth windows.
- **During Security Assessments:** To audit a facility's perimeter defense footprint against physical signal leakage.
- **During Spectrum Deconfliction:** When ambient radio noise or physical boundaries disrupt smart-grid sensors or internal communication networks.

### Why Is It Critical?

Wireless data is inherently public. Unlike hardwired networks, anyone with a cheap receiver can intercept an RF transmission. Understanding how signals are generated, formatted, and parsed is the only path toward developing robust, cryptographically sound wireless hardware defenses.

---

## 📡 2. Core Principles of Sub-GHz RF

- **Wavelength Advantage:** Sub-GHz frequencies feature longer wavelengths than 2.4 GHz or 5 GHz bands, allowing signals to travel farther and penetrate walls efficiently.
- **Low Power Usage:** Ideal for small devices operating on coin-cell batteries for years, as the transmission requires less energy.
- **Modulation Types:** Most legacy sub-GHz devices utilize simple digital modulation schemes:
  - **ASK/OOK:** Amplitude Shift Keying / On-Off Keying (signal turns on and off like Morse code).
  - **FSK/GFSK:** Frequency Shift Keying (signal shifts slightly between two frequencies to represent 1s and 0s).
- **Security Protocols:** Signals generally fall into two security categories:
  - **Fixed Code:** The device transmits the exact same data payload every time (vulnerable to replay attacks).
  - **Rolling Code:** The payload changes with each press using a cryptographic counter (protected against simple replay).

---

## 🧩 3. Core Sub-GHz Protocol Concepts

To thoroughly analyze wireless transmissions, it is essential to understand the underlying code architectures running on target chips.

### Fixed-Code Protocols (e.g., Princeton PT2262/PT2272)

Fixed-code architectures broadcast a static identifier bitstream every time the transmitter is triggered. Because the data structure never changes, any packet captured out of the air remains valid indefinitely. They are commonly found in low-security infrastructure like unencrypted wireless doorbells or older mains switches.

### Rolling-Code Protocols (e.g., Microchip KeeLoq)

Rolling-code protocols use cryptographic algorithms to secure transmissions. Every time a button is pressed, a non-linear encoder alters a portion of the packet payload and increments a synchronized sequence counter. The receiver decrypts the payload and verifies the counter before acting. Replaying an older captured packet will fail because the receiver rejects expired counters.

### Proprietary Broadcast Protocols (e.g., Somfy RTS)

Many industrial and consumer ecosystems deploy customized or proprietary wireless frameworks. These protocols utilize specific preamble patterns, specialized sync bit timings, and custom checksum calculations to isolate their ecosystems from standard commercial hardware. Reverse engineering them requires deep pulse-width analysis to determine payload layouts.

---

## 🔨 4. Hardware Specific Operations & Flowcharts

### Hardware Capability Overview

| Device | Capabilities | Best For | Risk Level |
|--------|--------------|----------|------------|
| **[Flipper Zero](https://flipper.net/)** | Sub-GHz (Tx/Rx) | Field triage, protocol ID, fixed-code emulation | 🟡 MEDIUM |
| **[HackRF One](https://greatscottgadgets.com/hackrf/one/)** | Half-Duplex (Tx/Rx) | Wideband monitoring, custom signal creation | 🔴 HIGH |
| **[RTL-SDR (V3/V4)](https://www.rtl-sdr.com/)** | Receive Only (Rx) | Continuous logging, budget spectrum analysis | 🟢 LOW |
| **[ESP32 Marauder](https://github.com/justcallmekoko/ESP32Marauder)** | 2.4 GHz (Tx/Rx) | Localized Wi-Fi / BT triage, asset discovery | 🟡 MEDIUM |
| **[Bruce Firmware](https://github.com/pr3y/Bruce)** | Multi-band (Tx/Rx) | Consolidated screen-driven diagnostics | 🟡 MEDIUM |

---

### 📌 Flipper Zero (Standalone Portability)

**Best For:** Quick field triage, rapid protocol identification, and basic fixed-code emulation.

```text
                      [ START ]
                          |
            1. Open 'Frequency Analyzer'
                          |
            2. Transmit near Flipper Zero
                          |
             ---> [ Read Frequency ]
            |             |
            |       3. Exit to Sub-GHz Menu
            |             |
            |       4. Select 'Read' or 'Read RAW'
            |             |
            |       5. Set Config to Target Frequency
            |             |
            |       6. Capture Transmission
            |             |
            |             v
    (Signal Weak?) -- [ Evaluate Capture Quality ]
            |             |
           YES            | NO (Signal Clean)
            |             v
            |      [ Determine Code Security ]
            |             |
            |             +---> (Rolling Code) --> [ STOP: Do Not Emulate ]
            |             |
            +-------------+---> (Fixed Code)   --> [ Emulate via Faraday Bag ]
```

#### Detailed Execution Steps

1. **Determine the Center Frequency:** Open `Sub-GHz` -> `Frequency Analyzer`. Hold the target remote 2–3 inches from the left side of the Flipper and click the remote button. Note the strongest recurring frequency.
2. **Choose the Capture Mode:** Back out to the main Sub-GHz menu.
   - *Choose `Read`:* For standard commercial protocols (e.g., Princeton, KeeLoq fixed, Came). The Flipper will attempt to decode the bytes live on screen.
   - *Choose `Read RAW`:* For unknown or complex rolling-code protocols.
3. **Configure Settings:** Click `Config` (Right arrow button) inside your chosen capture menu. Lock the frequency to your target measurement and select the most likely modulation (default to `AM270` or `AM650` for general ASK/OOK devices).
4. **Isolate and Execute:** Move both devices inside an RF shielding container (Faraday bag). Tap the record function on the Flipper, press the remote button once, and stop the recording immediately.
5. **Security Logic Check:** Inspect the file saved on the Flipper's SD card. If a rolling counter or lock icon appears, **do not press emulate** outside of controlled software-defined test environments.

---

### 📌 HackRF One (Advanced Transceiver)

**Best For:** Wideband spectrum monitoring, custom signal creation, and advanced transmission testing.

**Lab Procedures:**

- **Wide Spectrum Sweep:** Pair the HackRF with a computer running GQRX. Set a wide bandwidth (up to 20 MHz) to monitor multiple sub-GHz channels simultaneously.
- **IQ Data Capture:** Use the command line utility `hackrf_transfer -r capture.iq -f 433920000 -s 2000000` to stream pristine, uncompressed analog RF data straight to a file for URH analysis.
- **Custom Transmission:** Load an edited or created IQ file into GNU Radio or URH and utilize `hackrf_transfer -t playback.iq` inside an RF enclosure to broadcast custom payloads.

```
⚠️ HackRF is a TRANSMIT-CAPABLE device. Any playback/Tx procedure must be
   performed into a dummy load or inside a Faraday enclosure - never over the air
   toward equipment you do not own.
```

---

### 📌 Computer-Based RTL-SDR (Affordable Receiving)

**Best For:** Continuous background logging, budget spectrum analysis, and massive automated data gathering.

**Lab Procedures:**

- **Automated Data Harvesting:** Connect an RTL-SDR dongle to a dedicated machine or Raspberry Pi. Run `rtl_433` continuously with the `-F json` flag to pipe decoded sensor data straight into a spreadsheet or database.
- **Signal Triage:** Run SDR# alongside a target remote control to visualize the modulation pattern. Look for clean, distinct on/off blocks to quickly verify an ASK/OOK modulation without needing expensive test gear.

---

### 📌 ESP32 Marauder (Protocol Specialist)

**Best For:** Localized 2.4 GHz traffic triage, asset discovery, and framework mapping.

```text
                           [ START ]
                               |
                1. Connect to Marauder (CLI/GUI)
                               |
                2. Set Mode (Wi-Fi or Bluetooth)
                               |
            +------------------+------------------+
            v                                     v
     [ A. Wi-Fi Path ]                    [ B. Bluetooth Path ]
            |                                     |
   3a. Run 'scan ap'                     3b. Run 'scan-sub' (BLE/BT)
            |                                     |
   4a. Run 'select ap <index>'           4b. Target specific beacon MAC
            |                                     |
   5a. Start raw packet sniff            5b. Monitor payload/RSSI telemetry
   (e.g., 'sniff raw')                           |
            |                                     v
            v                              [ Save Data ]
     [ Export PCAP ]                             |
            |                                     v
            v                             [ Post-Analysis in ]
    [ Run Wireshark ]                     [ Wireshark/Tooling ]
```

#### Detailed Execution Steps

1. **Interface Initialization:** Power on your Marauder hardware. Access the interface via the onboard touchscreen GUI or connect a USB-C cable and initialize a Serial Terminal (baud rate `115200`).
2. **Environment Baseline Scan (Wi-Fi):** Execute `scan ap` to query all nearby Access Points. Once completed, run `list ap` to evaluate a ledger of indexed local systems, security configurations (e.g., WPA2/WPA3), and exact channel alignments.
3. **Targeted Packet Interception:** Pinpoint the lab test router index number from the ledger list. Lock the interface down by typing `select ap <index_number>`. Start recording structural framework management frames using `sniff raw`. Ensure your external SD card is mounted securely.
4. **Data Extraction:** Stop the capture process via the screen interface or by entering a carriage return in your serial window. Unmount the SD card and load the generated `.pcap` log file directly into your workstation computer running Wireshark for decoding.

---

### 📌 Bruce Firmware (Multi-Protocol Suite)

**Best For:** Consolidation of multi-band diagnostic utilities onto a single, screen-driven operational menu.

```text
                           [ START ]
                               |
               1. Boot Device to Bruce Main Menu
                               |
               2. Select Peripheral Control Module
                               |
         +---------------------+---------------------+
         v                     v                     v
   [ A. RF Sub-GHz ]      [ B. Wi-Fi 2.4G ]     [ C. BLE / IR ]
   (Requires CC1101)           |                     |
         |             3b. Target SSID       3c. Open BLE Scanner /
   3a. Set Frequency           |                 Infrared Receiver
   (e.g., 433.92 MHz)  4b. Initialize Packet         |
         |                 Monitor           4c. Capture / Map
   4a. Open Rx / Signal        |                 Beacon Advertisements
       Terminal                v                     |
         |               [ Capture ]                 v
         v                                    [ Output File ]
   [ Save Payload ]
```

#### Detailed Execution Steps

1. **Boot and Module Verification:** Power on the microcontroller host running Bruce firmware. Navigate to the `Settings` panel to verify that your attached physical expansions (e.g., an SPI-connected CC1101 chip or antenna array) are correctly mapped and reporting a "Ready" state.
2. **Sub-GHz Monitoring via Bruce:** Scroll down the main display carousel and select the `Sub-GHz` module. Enter the frequency configuration view. Set the manual stepping target to match your lab environment baseline (e.g., `433.92 MHz`). Select `Receiver`. The terminal screen will output a real-time readout of parsed data packets and RSSI strength metrics.
3. **Wi-Fi Packet Monitoring:** Back out to the main menu and enter the `Wi-Fi` diagnostic suite. Select `Packet Monitor`. This configuration commands the network controller to enter promiscuous mode across a specific radio channel. Observe the live graph tracking ambient frame traffic volume.

---

## 🛠️ 5. Entry-Level GNU Radio Flowgraph Guide (HackRF)

GNU Radio Companion (GRC) allows you to build custom visual processing blocks to interact with your HackRF. Below is the blueprint for a baseline **Sub-GHz OOK Signal Recorder Flowgraph**.

### Block Architecture Setup

Connect the following blocks sequentially in GRC from top to bottom / left to right:

1. **Options Block:** Set `Id` to `sub_ghz_recorder`.
2. **Variable Block (`samp_rate`):** Set `Value` to `2000000` (2 MHz sampling rate, ideal for capturing sub-GHz bursts cleanly).
3. **Variable Block (`center_freq`):** Set `Value` to `433920000` (433.92 MHz).
4. **Osmocom Source (Your HackRF):**
   - `Sample Rate (sps)`: `samp_rate`
   - `Ch0: Frequency (Hz)`: `center_freq`
   - `Ch0: RF Gain (dB)`: `0` (Keep low to prevent clipping)
   - `Ch0: IF Gain (dB)`: `20`
   - `Ch0: BB Gain (dB)`: `20`
5. **QT GUI Sink:** Connect the output of the *Osmocom Source* to this block to visually monitor your waterfall and spectrum analyzer while recording.
6. **File Sink:** Connect the output of the *Osmocom Source* here as well.
   - `File`: Choose a path (e.g., `/home/user/desktop/capture.iq`).
   - `Unbuffered`: Set to `On` to guarantee data writes instantly.

### Running the Procedure

- Press the **Play** icon in GRC to start execution.
- Press your target transmitter button. You will see a spike appear in the QT GUI Sink.
- Click the **Stop** icon immediately after transmission to keep your output file size small and manageable.

```
💡 TIP: Test your flowgraph with the SDR sink DISCONNECTED first to validate
   block wiring before any radio hardware is engaged.
```

---

## 🔌 6. Dedicated Hardware Chips: CC1101 vs. nRF24L01+

When building custom lab sniffers or low-power embedded modules, these physical transceiver breakouts serve distinct operational purposes.

### 📡 CC1101 (The Sub-GHz Agile Transceiver)

- **Multi-Frequency Sniffing:** Can be dynamically programmed via an SPI bus to listen anywhere from 300 MHz to 928 MHz, matching various regional target devices on demand.
- **Legacy Emulation:** Supports ASK, OOK, FSK, and GFSK modulation natively, allowing you to mimic raw analog structures for garage doors, wireless doorbells, and early IoT sensors.
- **Custom Sniffing Terminals:** Used by wiring a chip module to an Arduino or ESP32 using drivers like `SmartRC-CC1101-Driver-Lib` to spit raw timing pulses directly into a serial logging window.

### 📡 nRF24L01+ (The 2.4 GHz Protocol Specialist)

- **Proprietary 2.4 GHz Auditing:** Operates strictly in the 2.4 GHz ISM band. Used heavily to intercept and map packets from cheap commercial drones, RC toys, and custom micro-controller mesh systems.
- **Mousejacking Analysis:** Many early non-Bluetooth wireless peripherals route data over unencrypted nRF24-compatible structures. Custom lab builds using software like *Logitacker* force the nRF24 module into a quasi-promiscuous mode to evaluate peripheral data vulnerabilities.

### Hardware Transceiver Matrix

| Feature | CC1101 Module | nRF24L01+ Module |
| :--- | :--- | :--- |
| **Frequency Range** | 300 MHz – 928 MHz (Highly Flexible) | 2.400 GHz – 2.525 GHz (Fixed) |
| **Modulation Support** | ASK, OOK, 2-FSK, GFSK, MSK | GFSK only |
| **Signal Penetration** | **High** (Easily passes through structures) | **Low** (Blocked easily by walls and water/bodies) |
| **Primary Lab Target** | Smart home sensors, key fobs, garage doors | Wireless mice/keyboards, cheap drones, RC toys |
| **Data Throughput** | Up to 600 kbps | Up to 2 Mbps |

---

## 🧯 7. Troubleshooting: Clipping & Signal Distortion

When capturing raw IQ data, poor signal quality will ruin software demodulation. Use these baseline checks to ensure pristine data captures:

### ⚠️ Clipping (Signal Over-Saturation)

- **The Symptom:** The top and bottom of your signal waveforms look flattened or chopped off in URH, or the entire waterfall turns solid red/white.
- **The Cause:** Your receiver gains are set too high, or your transmitter is physically too close to your SDR antenna.
- **The Fix:** Move the transmitting remote at least 3 to 5 feet away from the SDR antenna. Drop the `RF Gain` or `IF Gain` values down by 10 dB increments until the waveform curves become smooth and distinct.

### ⚠️ DC Offset (The Center Spike)

- **The Symptom:** A massive, permanent spike appears directly in the dead center of your waterfall display, masking nearby signals.
- **The Cause:** An inherent hardware artifact common to zero-IF SDR architectures like the HackRF and RTL-SDR.
- **The Fix:** Never set your hardware target frequency directly to the target device frequency. Instead, use an **Offset Tune**. If your device is at 433.92 MHz, set your SDR center frequency to 433.52 MHz (400 kHz away). Your target signal will now cleanly appear slightly to the right of the center spike, free from distortion.

### ⚠️ Under-Sampling / Alias Signals

- **The Symptom:** Signals appear mirrored or distorted, and parsing tools fail to calculate consistent data pulse widths.
- **The Cause:** Your sample rate is lower than the actual bandwidth of the target signal.
- **The Fix:** Ensure your sample rate is always set to at least `2000000` (2 MHz) for general sub-GHz exploration. This captures the signal and its sidebands with ample resolution.

---

## 💻 8. Post-Processing Pipeline

Once data is captured as a raw `.iq`, `.pcap`, or text log file, choose one of these software paths to extract meaningful protocol intelligence.

| Pipeline | Best For | Risk Level |
|----------|----------|------------|
| **[Universal Radio Hacker (URH)](https://github.com/jopohl/urh)** | Custom, proprietary, or unknown OOK/FSK payloads | 🟡 MEDIUM |
| **[Wireshark](https://www.wireshark.org/)** | 2.4 GHz 802.11 Wi-Fi, BLE beacons, Marauder `.pcap` exports | 🟢 LOW |
| **[rtl_433](https://github.com/merbanan/rtl_433)** | Verifying known commercial telemetry streams instantly | 🟢 LOW |

### Pipeline 1: Universal Radio Hacker (Reverse Engineering Raw Sub-GHz)

**Best For:** Custom, proprietary, or unknown OOK/FSK payloads.

**Process Flow:**

1. **Import:** Select `File` -> `Open` -> Load your `.iq` file.
2. **Isolate:** Adjust the visual sliders to select a single, strong pulse burst. Trim out silent background noise.
3. **Demodulate:** Set the modulation type parameter (`ASK` or `FSK`). Adjust the bit length threshold until the waveform blocks map cleanly into uniform digital pulses.
4. **Interpret:** In the *Analysis* window, look for patterns across sequential captures. Group identical rows to separate static device identifiers from volatile execution bytes.

### Pipeline 2: Wireshark (Network Data Processing)

**Best For:** Automated parsing of 2.4 GHz 802.11 Wi-Fi, BLE beacon packets, or Marauder `.pcap` exports.

**Process Flow:**

1. **Import:** Drag and drop your `.pcap` file directly into the Wireshark UI.
2. **Filter:** Clean up background noise by applying strict display filter logic in the top navigation bar:
   - To view beacon frames: `wlan.fc.type_subtype == 0x08`
   - To view BLE advertising channels: `btle.advertising_address`
3. **Inspect:** Expand the middle packet layer menu to extract the exact hexadecimal hardware MAC address, peripheral capabilities flags, and manufacturer data fields.

### Pipeline 3: rtl_433 CLI Tool (Instant Standard Decoding)

**Best For:** Verifying known commercial telemetry streams instantly.

**Process Flow:**

1. **Verify:** Open a workstation command line console.
2. **Execute:** Run the utility against a previously saved raw file:

   ```bash
   rtl_433 -r raw_capture.cu8
   ```

3. **Review:** The utility automatically reads the pulse timing array, references its internal database of common microchips, and yields parsed decimal telemetry values on screen.

---

## 🗂️ 9. Master Device & Protocol Reference Matrix

The table below serves as a laboratory lookup guide to identify unknown target signals based on their detected center frequency and mapping to known protocol standard architectures.

| Device Category | Target Device Example | Primary Radio Frequency | Primary Protocol Architecture |
| :--- | :--- | :--- | :--- |
| **Automotive Security** | Legacy Vehicle Key Fobs | 315.00 MHz | Princeton / Holtek Fixed Code |
| **Automotive Security** | Modern Vehicle Key Fobs | 433.92 MHz | Microchip KeeLoq Rolling Code |
| **Automotive Telemetry** | Tire Pressure Sensors (TPMS) | 315.00 MHz / 433.92 MHz | Schrader / FSK Telemetry Burst |
| **Residential Access** | Dip-switch Garage Doors | 300.00 MHz – 310.00 MHz | Linear / Multi-Code Fixed Code |
| **Residential Access** | Modern Garage Door Openers | 315.00 MHz / 390.00 MHz | Chamberlain Security+ 2.0 Rolling Code |
| **Residential Access** | Motorized Blinds & Awnings | 433.42 MHz | Somfy RTS (Radio Technology Somfy) |
| **Residential Access** | Commercial Entrance Gates | 868.30 MHz | Came / Nice OOK Fixed & Rolling Code |
| **Smart Automation** | Wireless Doorbell Chimes | 433.92 MHz | Princeton (PT2262 Clone) Fixed Code |
| **Smart Automation** | Legacy Smart Plugs & Relays | 433.92 MHz | Nexa / Intertechno Protocol Profiles |
| **Smart Automation** | Perimeter Window/Door Sensors | 345.00 MHz | Honeywell / Ademco 5800 Series |
| **Smart Automation** | Commercial Intrusion Alarms | 868.00 MHz | Visonic PowerCode / Jeweller Protocol |
| **Environmental Infrastructure** | Backyard Weather Stations | 433.92 MHz / 915.00 MHz | Oregon Scientific / Ambient Weather FSK |
| **Utility Infrastructure** | Smart Grid Power Meters | 915.00 MHz | Itron ERT (Encoder Receiver Transmitter) |
| **Logistics Infrastructure** | Cargo Asset Tracking Tags | 915.00 MHz | EPC Gen2 / ISO 18000-6C RFID |
| **Industrial Mesh** | Industrial IoT Sensor Nodes | 868.00 MHz / 915.00 MHz | LoRaWAN (Long Range Wide Area Network) |
| **Smart Home Mesh** | Interconnected Lighting Arrays | 908.42 MHz / 868.42 MHz | Z-Wave / GFSK Mesh Framework |
| **Peripherals** | Wireless Mice & Keyboards | 2.400 GHz – 2.4835 GHz | Nordic Enhanced ShockBurst (nRF24) |
| **Aviation / Toys** | Commercial Toy RC Drones | 2.400 GHz – 2.4835 GHz | Futaba S-FHSS / FlySky FHSS Protocol |

---

## 📖 10. Protocol Profiles Dictionary

When analyzing signals from the reference matrix above, use this operational dictionary to understand what the specific protocol structure does.

- **Princeton / Holtek (PT2262 Clones):** A foundational legacy fixed-code standard. It uses simple pulse-width modulation (PWM) to broadcast a static 12-bit or 24-bit payload. It features zero cryptographic verification, meaning any captured frame can be replayed instantly.
- **Microchip KeeLoq:** A robust rolling-code standard designed for secure access. It encrypts a 32-bit hopping code block containing a sequence counter using a non-linear block cipher. Receivers track the counter and instantly reject identical or expired values to stop replay attempts.
- **Schrader TPMS:** A localized telemetry protocol deployed inside automotive wheels. It relies on frequency-shift keying (FSK) to send brief packet bursts containing a fixed tire sensor hardware ID alongside sensor values like tire pressure, temperature, and battery life.
- **Chamberlain Security+:** An upgraded residential rolling-code standard. It alternates data transmissions across multiple frequencies (e.g., 315 MHz and 390 MHz simultaneously) while incrementing rolling counters to resist targeted signal blocking or interception.
- **Somfy RTS (Radio Technology Somfy):** A specialized consumer hardware protocol utilizing unencrypted rolling-code layouts. It relies on custom pulse-width patterns and precise bit-timing durations to communicate cleanly with automated window treatments and awnings.
- **Honeywell / Ademco 5800:** A high-reliability security asset protocol. Sensors broadcast rapid, redundant fixed-code bursts containing a hardcoded device index flag, loop channel configurations, and sensor conditions (e.g., closed, open, low battery).
- **Itron ERT:** A municipal utility logging protocol. Devices remain in low-power sleep states, periodically awakening to broadcast short, unencrypted data packets containing total consumption metrics, device indices, and tamper flags to passing utility vehicle receivers.
- **EPC Gen2 / ISO 18000-6C:** An advanced inventory and tracking architecture. Readers emit continuous RF waves to energize nearby passive asset tags, which reply by modulating and backscattering their hardcoded Electronic Product Code (EPC) payloads.
- **LoRaWAN:** A long-range, low-power digital infrastructure framework. It applies chirp spread spectrum (CSS) modulation to transmit sensor telemetry over extreme distances while encrypting all payload traffic behind distinct network and application session keys.
- **Z-Wave:** A highly structured smart-home mesh system. Nodes route low-power control and state confirmation payloads using frequency-shift keying over dedicated sub-GHz bands, keeping home automation channels free from 2.4 GHz Wi-Fi interference.
- **Nordic Enhanced ShockBurst:** A high-speed, proprietary 2.4 GHz payload structure. It offloads packet formatting, addressing, automatic acknowledgment receipts, and retransmission timing loops directly onto the transceiver silicon to preserve host processing resources.

---

## 📝 11. Laboratory Protocol Logging Template

To maintain reproducibility across hardware security audits, document every successful or unparsed capture session using the following standardized Markdown format. Copy the block below into a new file for each session:

~~~markdown
# RF SIGNAL CAPTURE MATRIX LOG: [LOG_ID_NUM]

## 1. Environment Metadata
- **Audit Date/Time:** YYYY-MM-DD HH:MM:SS UTC
- **Physical Location:** [e.g., Lab Bench 2 / Shielded Test Enclosure]
- **Operator ID:** [Initials / Badge Number]

## 2. Target Device Profiling
- **Device Manufacturer / Model:** [e.g., Acme Wireless Plug Gen 3]
- **FCC Identifier (if visible):** [FCC ID String]
- **Hardware Chipset (Internal):** [e.g., Texas Instruments CC1101 Breakout]
- **Expected Security Category:** [ ] Fixed Code  |  [ ] Rolling Code  |  [ ] Encrypted
- **Associated Protocol Signature:** [e.g., Princeton PT2262 / KeeLoq / Somfy RTS]

## 3. Radio Frequency Parameters
- **Target Frequency:** ___________ MHz
- **Detected Bandwidth:** ___________ kHz
- **Estimated Modulation:** [ ] ASK/OOK  |  [ ] 2-FSK  |  [ ] GFSK  |  [ ] Other
- **Measured Base Pulse Width (us):** ___________

## 4. Hardware Capture Configuration
- **Receiver Tool Used:** [ ] Flipper Zero  |  [ ] HackRF One  |  [ ] RTL-SDR  |  [ ] Custom Board
- **Hardware Antenna Variant:** [e.g., Telescopic Tuned 433MHz Whip]
- **Software Center Frequency:** ___________ MHz (Offset applied: Yes/No)
- **Configured Sample Rate:** ___________ Msps
- **Receiver Attenuation/Gain Level:** IF Gain: ____ dB | BB Gain: ____ dB

## 5. Extracted Payload Intelligence
- **Output File Reference:** [path/to/capture_file.iq] or [path/to/flipper.sub]
- **Raw Hexadecimal Payloads (First 3 Samples):**
  1. 0x________________________________________________
  2. 0x________________________________________________
  3. 0x________________________________________________
- **Protocol Structure Breakdown:**
  - [PREAMBLE BITS]     -> ____________________
  - [STATIC DEVICE ID]  -> ____________________
  - [EXECUTION STATE]   -> ____________________
  - [CHECKSUM/CRC]      -> ____________________

## 6. Structural Observations & Integrity Validation
[Document waveform visual clarity here. Note if clipping occurred, if DC offset
masked elements, or if pulse widths remained identical across sequential
transmission instances.]
~~~

---

## 🚪 12. Example Project: Safe Garage Door Analysis

Use this checklist to practice baseline exploration concepts safely on a standard residential garage door system **you own** - without accidentally breaking the remote pairing or breaking local laws.

### Phase 1: Pre-Lab Setup & Safety

- [ ] **Isolate the Receiver:** Place your SDR/Flipper and the garage remote inside your Faraday bag or shielded enclosure if you plan to hit transmit.
- [ ] **Identify System Type:** Look at the back of the garage remote or overhead opener motor unit to check the model specifications.
  - **Legacy (Pre-1995):** Dip-switches present inside the remote battery compartment indicate a Fixed Code system (safe for baseline testing).
  - **Modern (Post-1995):** Brand names like Chamberlain Security+, LiftMaster, or Genie Intellicode indicate a Rolling Code system (requires strict compliance rules).

### Phase 2: Signal Discovery

- [ ] **Run GQRX/SDR#:** Set your center frequency to 315 MHz or 390 MHz (common US garage bands) or 433.92 MHz (EU / common ISM).
- [ ] **Fire the Remote:** Tap the garage button briefly and watch for a sharp transmission spike on the waterfall. Document the exact peak frequency.

### Phase 3: Capturing the Transmission

- [ ] **Open URH or Flipper Read:** Set the configuration to your newly discovered target frequency.
- [ ] **Record the Payload:** Click record and click the remote button once. Stop the recording immediately.
- [ ] **Identify Modulation:** Zoom into the captured wave blocks. Verify if it uses simple OOK (gaps of absolute silence between bursts) or FSK.

### Phase 4: Analysis and Security Validation

- [ ] **Inspect Code Persistence:** Record a second button press into a separate file and line them up side-by-side in your analysis software.
- [ ] **Apply the Validation Rule:**
  - *If the data strings match exactly:* The device is Fixed Code. You can safely emulate this payload into your test motor to complete your validation loop.
  - *If the data strings are different:* The device uses Rolling Codes. **STOP.** Do not emulate or play back either file toward your actual garage door. Replaying an old counter packet can desynchronize your real remote from the receiver, locking you out of your garage until you manually re-pair the system hardware.

---

## ⚠️ CRITICAL Security & Legal Warning

### 🔴 FEDERAL REGULATORY WARNING

```
═══════════════════════════════════════════════════════════════
                    ⚠️ CRITICAL LEGAL WARNING ⚠️
═══════════════════════════════════════════════════════════════

The tools and techniques in this manual govern the physical transmission
and interception of Radio Frequency (RF) energy.

UNAUTHORIZED TRANSMISSION OR INTERCEPTION IS A FEDERAL CRIME.

Federal Communications Commission (FCC) Regulations:
   ► Operating without a license: Fines up to $150,000+ per day.
   ► Jamming Devices: STRICTLY PROHIBITED. Marketing, selling, or using
     a jammer carries massive civil and criminal penalties.
   ► Aviation Interference: Endangering aircraft navigation (GPS spoofing,
     ADS-B injection) can result in federal terrorism charges.

Electronic Communications Privacy Act (ECPA) & Wiretap Act:
   ► Intercepting encrypted or private communications (Cellular, Pagers,
     Private Land Mobile Radio) is a federal felony.
   ► Up to 5 years imprisonment for unauthorized interception.

State Laws:
   ► Many states have distinct laws regarding eavesdropping, wiretapping,
     and the possession of lock bypass tools (which can include SDRs loaded
     with replay attack software).

International Laws:
   ► CEPT/ETSI regulations in Europe.
   ► Ofcom regulations in the UK.
   ► Telecommunications laws vary heavily by country. ALWAYS check local laws.
═══════════════════════════════════════════════════════════════
```

### Attack-Specific Legal Warnings

#### Signal Jamming

```
🔴 FEDERAL CRIME: Intentional Interference

ILLEGAL ACTIVITIES:
   • Jamming Wi-Fi networks (Deauth attacks via RF flooding)
   • GPS Jamming
   • Cellular network disruption
   • Blocking security system heartbeats

LAWS VIOLATED:
   • Communications Act of 1934
   • FCC Rules (47 CFR Part 15)

PENALTIES:
   • Seizure of all equipment
   • Civil fines frequently exceeding $100,000
   • Federal imprisonment
```

#### Replay Attacks (Access Control)

```
🔴 FEDERAL CRIME: Unauthorized Access & Trespassing

ILLEGAL ACTIVITIES:
   • Capturing and re-transmitting a neighbor's garage door signal
   • Spoofing car key fobs (RollJam / RollBack)
   • Bypassing physical RFID/Sub-GHz access control systems

LAWS VIOLATED:
   • Computer Fraud and Abuse Act (CFAA)
   • State trespassing and burglary tool possession laws
   • Auto theft statutes

AUTHORIZED USE ONLY:
   ✓ Written authorization from the property/vehicle owner
   ✓ Testing on hardware explicitly purchased for research
```

### 📖 Before Transmitting Any Signal

```
MANDATORY CHECKLIST:
☐ Am I using a Faraday cage/bag or an RF dummy load?
☐ If transmitting over the air, do I have the appropriate FCC/local license?
☐ Am I operating within the ISM (Industrial, Scientific, Medical) bands?
☐ Am I adhering to the legal power limits (EIRP) for this frequency?
☐ Have I verified I am NOT transmitting on Aviation, Emergency, or Cellular bands?
☐ Do I OWN the target receiving device (e.g., the key fob and the car)?
☐ Have I tested my GNU Radio flowgraph without the SDR sink connected first?
☐ Am I prepared to document all transmission logs?

If you answered NO to ANY question: DO NOT TRANSMIT. USE RECEIVE-ONLY.
```

### Warranty Disclaimer

```
═══════════════════════════════════════════════════════════════
                    ⚠️ DISCLAIMER OF WARRANTIES ⚠️
═══════════════════════════════════════════════════════════════

These RF procedures, flowgraphs, and templates are provided "AS IS" WITHOUT
WARRANTY of any kind, either expressed or implied.

THE AUTHORS, CONTRIBUTORS, AND MAINTAINERS:
✗ Make NO guarantees about procedure functionality or RF safety
✗ Are NOT responsible for damaged hardware (e.g., burnt out SDR amplifiers)
✗ Do NOT warrant compliance with FCC or international RF emission laws
✗ Are NOT liable for any legal consequences of misuse
✗ Do NOT provide support for illegal activities
✗ Disclaim ALL liability for unauthorized transmission or interception

USERS EXPLICITLY ACKNOWLEDGE AND AGREE:
► They use these RF techniques entirely at their own risk
► They are solely responsible for ensuring RF containment and compliance
► They understand that transmitting signals can interfere with critical infrastructure
► They accept that unauthorized use is a FEDERAL CRIME
► They will defend and indemnify authors from any claims
═══════════════════════════════════════════════════════════════
```

---

## 📚 Resources

### Licensing & Legal

- **FCC Part 15 Rules**: [Understanding Unlicensed RF](https://www.fcc.gov/oet/ea/rfdevice)
- **ARRL**: [Get your Amateur Radio (HAM) License](https://www.arrl.org/getting-licensed) (Highly recommended for SDR practitioners)

### Learning SDR & RF

- **Great Scott Gadgets SDR Course**: [HackRF Lessons](https://greatscottgadgets.com/sdr/)
- **GNU Radio Tutorials**: [Guided Tutorials](https://wiki.gnuradio.org/index.php/Guided_Tutorials)
- **RTL-SDR Blog**: [rtl-sdr.com](https://www.rtl-sdr.com/)
- **SigIDWiki**: [Signal Identification Guide](https://www.sigidwiki.com/) (waterfall references and audio samples)

### Tooling

- **Universal Radio Hacker (URH)**: [github.com/jopohl/urh](https://github.com/jopohl/urh)
- **rtl_433**: [github.com/merbanan/rtl_433](https://github.com/merbanan/rtl_433)
- **Inspectrum**: [github.com/miek/inspectrum](https://github.com/miek/inspectrum)
- **Bruce Firmware**: [github.com/pr3y/Bruce](https://github.com/pr3y/Bruce)

---

## 🔗 Quick Links

### Internal Links

- [🏠 Main Repository](../README.md)
- [🎯 START HERE Guide](../START_HERE.md)
- [💻 Cybersecurity Master Guide](../ultimate_cybersecurity_master_guide.md)
- [🔧 Hardware Hacking](../HardwareHacking/README.md)
- [🛰️ Space Security](../SpaceSecurity/README.md)
- [📚 Documentation](../Documentation/README.md)

---

## 📊 Repository Statistics

```
📁 Manual Sections: 13 (Theory, Hardware, Flowgraphs, Pipelines, Reference, Logging)
📻 Target Hardware: Flipper Zero, HackRF, RTL-SDR, ESP32 Marauder, Bruce (CC1101)
📡 Spectrum Coverage: 300 MHz – 928 MHz Sub-GHz + 2.4 GHz ISM
💻 Ecosystems: GNU Radio, URH, Wireshark, rtl_433
⚠️ Risk Level: MEDIUM to HIGH (Transmission-capable procedures)
🔄 Last Updated: August 2026
👥 Maintained by: Pacific Northwest Computers (PNWC)
📝 Status: Active - Proceed with EXTREME CAUTION
```

---

<div align="center">

**⚠️ USE THESE RF TOOLS RESPONSIBLY AND LEGALLY ⚠️**

*The airwaves are public, but transmitting on them is a privilege regulated by law.*

**Repository**: [ULTIMATE CYBERSECURITY MASTER GUIDE](https://github.com/Pnwcomputers/ULTIMATE-CYBERSECURITY-MASTER-GUIDE)

**Maintained by**: [Pacific Northwest Computers](https://github.com/Pnwcomputers)

---

## Related Files

- [sdr.md](sdr.md) - Foundational SDR guide: GNU Radio, hardware, signal analysis, Wi-Fi/BT/cellular/GPS
- [sdr_hacking.md](sdr_hacking.md) - Advanced SDR hacking: SIGINT, protocol reversing, LoRa, TEMPEST, baseband exploitation
- [../Documentation/bruce_firmware.md](../Documentation/bruce_firmware.md) - Bruce firmware: sub-GHz CC1101 operations that complement full-spectrum SDR analysis
- [../Documentation/flipper_zero_guide.md](../Documentation/flipper_zero_guide.md) - Flipper Zero: sub-GHz replay attacks whose signals SDR can capture and analyze
- [../SpaceSecurity/](../SpaceSecurity/) - Space security: satellite communication analysis and GPS spoofing detection - an SDR application

---

🔴 **RADIO TRANSMISSION IS FEDERALLY REGULATED** 🔴

🔴 **UNAUTHORIZED TRANSMISSION = FEDERAL OFFENSE** 🔴

🔴 **NEVER INTERFERE WITH AVIATION OR EMERGENCY SERVICES** 🔴

🔴 **PROPER ISOLATION (DUMMY LOADS/FARADAY) MANDATORY** 🔴

---

⭐ **Star this repo if you find it useful (and use it legally!)** ⭐

</div>
