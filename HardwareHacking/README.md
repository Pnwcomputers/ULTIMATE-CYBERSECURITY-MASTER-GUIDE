# 🔧 Hardware Hacking

<div align="center">

**Physical and electronic attack techniques against embedded systems, microcontrollers, SoCs, and cryptographic hardware**

*Part of the [ULTIMATE CYBERSECURITY MASTER GUIDE](../README.md)*

![Fault Injection](https://img.shields.io/badge/Fault_Injection-Glitching_%7C_EMFI_%7C_Laser-red?style=for-the-badge)
![Side-Channel](https://img.shields.io/badge/Side--Channel-SPA_%7C_DPA_%7C_CPA-blue?style=for-the-badge)
![Interfaces](https://img.shields.io/badge/Interfaces-JTAG_%7C_SWD_%7C_SPI-green?style=for-the-badge)

</div>

---

**Adjacent embedded-security research:** [Awesome Embedded and IoT](https://github.com/fkie-cad/awesome-embedded-and-iot-security), [h4cker hardware](https://github.com/The-Art-of-Hacking/h4cker/tree/master/cybersecurity-domains/hardware-embedded-security) and [project routing](../Documentation/awesome-hacking-collections-integration.md).

## Expanded Device & Firmware Coverage

| Resource | Description / Boundary |
|---|---|
| [Device Firmware List](../Documentation/device-firmware-list.md) | Board-first choices and target limitations. |
| [ESP Terminator](../Documentation/esp-terminator.md) | General catalog/uploader selection and recovery checks. |

## Dedicated Firmware Labs

| Resource | Role & Compatibility Boundary |
|---|---|
| [ESP32 Bit Pirate](./esp32-bit-pirate.md) | S3 firmware install and a read-only UART bench baseline; distinct from Bus Pirate hardware. |
| [Pico-Ducky Lab](./pico-ducky-lab.md) | Pico setup mode and a fixed-text offline HID demonstration. |
| [Flipper Expansion Board Labs](../Documentation/flipper_zero_guide.md#flipper-zero-expansion-boards-selection-setup--field-assessment-labs) | CC1101, nRF24/Si24R1, AWOK Dual C5, Realtek BW16, Poltergeist, RF-safe wiring & eight validation labs. |
| [Evil-M5 Field Labs](../Documentation/evil_m5.md#evil-m5-firmware-qualification--authorized-deployment-labs) | Cardputer/ADV and other M5Stack target setup, eight safe RF/BLE/HID and defensive lab exercises. |
| [LAB5 MonsterC5 / JanOS](../Documentation/microcontroller_wifi_testing.md#lab5-c5-monster--projectzero-janos-field-assessment) | Distinct C5 radio, Cardputer/Tab5/Flipper apps, verified update path and eight tests. |

## Firmware Catalog & Installers

| Resource | Description |
|---|---|
| [ESP32 & Related Firmware Catalog](../Documentation/esp32-security-firmware-catalog.md) | Primary upstream projects, supported targets, use-cases & dated activity notes |
| [Firmware Web Flashers](../Documentation/firmware-web-flashers.md) | Dedicated installers plus a separate multi-device/multi-firmware reference |

## 🎯 Purpose
Index and navigation hub for the Hardware Hacking section - covering physical and electronic attack techniques against embedded systems: JTAG/SWD/UART debug access, fault injection (voltage, clock, EM, laser), side-channel analysis (SPA, DPA, CPA), firmware extraction, and the hardware tools used in each category.

## ⚙️ Function
Links to five chapter guides (threat modeling, electrical fundamentals, fault injection, power analysis theory, power analysis practicals) and seven device guides (Bus Pirate, Bit Pirate, GreatFET One, JTAGulator, LA1010 logic analyzer, HiLetgo logic analyzer, T48 IC programmer). Includes attack category taxonomy, bench equipment reference, and tool ecosystem overview.

## 🏆 Goal
Serve as the entry point for hardware security work - helping practitioners find the right chapter or tool guide for their current task without reading the full guide linearly.

## 📋 When To Use
- Starting a hardware security assessment: choose the right chapter and tool for your target
- Identifying which hardware tool to use for a given protocol or attack type
- Onboarding to hardware hacking: read chapters in order, then reference tool files for specific devices

---

## 📋 Table Of Contents

- [Overview](#-overview)
- [Chapter Guides](#-chapter-guides)
- [Device Setup & Usage Guides](#-device-setup--usage-guides)
- [Attack Categories](#-attack-categories)
- [Bench Equipment Reference](#-bench-equipment-reference)
- [Tool Ecosystem](#️-tool-ecosystem)
- [Security & Legal Disclaimer](#️-security--legal-disclaimer)
- [Resources](#-resources)

---

## 🎯 Overview

Hardware security extends the attack surface beyond software and networks into the **physical domain**: where an attacker who can touch the device has capabilities unavailable over any network. Debug interfaces, power traces, clock signals, and electromagnetic emissions all become vectors for extraction, bypass, and exploitation.

This section provides a **comprehensive reference** for hardware security assessment, from threat modeling and electrical fundamentals through advanced fault injection and side-channel analysis techniques.

**What You'll Find Here:**
- 🎯 Hardware threat modeling: Attacker profiles, asset mapping, countermeasure frameworks
- ⚡ Electrical fundamentals: Logic levels, communication interfaces (UART, SPI, I²C, JTAG/SWD), measurement equipment
- 💥 Fault injection attacks: Voltage glitching, clock glitching, EMFI, laser fault injection, body biasing
- 📊 Side-channel analysis: Timing attacks, Simple Power Analysis (SPA), Differential Power Analysis (DPA)
- 🔬 Power analysis practicals: Measurement setup, trace acquisition, filtering, CPA implementation, visualization
- 🛡️ Countermeasures: Silicon-level, firmware-level, and physical protections
- 📟 **Device-specific guides**: Setup, connection, and usage tutorials for common hardware hacking tools.

---

## High-Profile Hardware Security Case Studies

The [Case Studies Index](../CaseStudies/README.md) gives sourced reports with research timelines, practical limitations and **defensive** responses. Use it alongside the bench guides; a disclosed flaw must not be treated as proof that the particular equipment in front of you is affected.

| Case Study | Relevant Hardware Boundary | Complementary Guide |
|---|---|---|
| [Unsaflok — Three Million Hotel Locks](../CaseStudies/hardware/unsaflok-3m-hotel-locks.md) | RFID credential trust & room authorization | [RFID/NFC](../SDR/rfid.md) |
| [Onity Locks, 2012](../CaseStudies/hardware/onity-locks-2012.md) | Accessible service ports & firmware authorization | [Electrical Interfaces](Chapter2.md) |
| [Tesla Model S Key Fobs, 2018](../CaseStudies/hardware/tesla-model-s-key-fob-2018.md) | RF protocol and key lifecycle | [SDR & RF](../SDR/README.md) |
| [EUCLEAK / YubiKey, 2024](../CaseStudies/hardware/eucleak-yubikey-2024.md) | EM side-channel cryptographic leakage | [Timing & Power Analysis](Chapter4.md) |

---

## 📂 Chapter Guides

| Chapter | Topic | Description |
|---------|-------|-------------|
| **[Chapter1.md](./Chapter1.md)** | Threat Modeling | Attacker profiles, asset categories, objective-to-attack mapping, countermeasure frameworks (silicon/firmware/physical), threat model template |
| **[Chapter2.md](./Chapter2.md)** | Electrical Fundamentals | Ohm's Law, logic levels, communication interfaces (UART, SPI, I²C, JTAG, SWD), oscilloscopes, logic analyzers, shunt resistors, signal integrity |
| **[Chapter3.md](./Chapter3.md)** | Fault Injection Attacks | Voltage glitching, clock glitching, EMFI, laser fault injection, body biasing, injection point identification, parameter sweeping, fault mapping |
| **[Chapter4.md](./Chapter4.md)** | Timing & Power Analysis | Side-channel concepts, timing attacks (string comparison, RSA, cache), Simple Power Analysis (SPA), Differential Power Analysis (DPA) with working code |
| **[Chapter5.md](./Chapter5.md)** | Power Analysis Practicals | Measurement setup, trace acquisition, filtering (low-pass, band-pass), trace alignment (SAD, cross-correlation), CPA implementation, visualization, TVLA, template attacks |

### Reading Order

```
New to hardware hacking?
  └─> Start with Chapter 1 (Threat Modeling) for framework and terminology
  └─> Then Chapter 2 (Electrical Fundamentals) for bench skills
  └─> Then Chapter 3 (Fault Injection): most accessible attack category
  └─> Then Chapters 4–5 (Side-Channel): builds on measurement fundamentals

Experienced practitioner?
  └─> Jump directly to the relevant chapter
  └─> Chapter 3 for glitching campaign setup
  └─> Chapter 5 for CPA implementation and visualization code
  └─> Chapter 1 for threat model documentation template
```

---

## Hak5 USB & Wireless Assessment Workflows

The existing [Bash Bunny payload guide](../Scripts/Bash/BashBunny/README.md#authorized-field-assessment-labs--deployment-examples), [USB Rubber Ducky compilation guide](../Scripts/Ducky/README.md#authorized-hid-injection-field-exercises), and [WiFi Pineapple Mark VII section](../Wardriving/README.md#wifi-pineapple-mark-vii--authorized-wireless-security-assessment) now include authorized deployment labs, detection, troubleshooting and reporting. They remain in their established sections to avoid duplicating instructions. [Pico-Ducky](./pico-ducky-lab.md) is distinct from Hak5 hardware.

### Hak5 Payload Ecosystem: Official & Side-Loaded Code

**Device formats are not interchangeable.** The [WiFi Pineapple Pager](../Wardriving/README.md#wifi-pineapple-pager--payloads-sideloading--defensive-labs) uses `payload.sh` and Pager-specific UI/events. The [Mark VII](../Wardriving/README.md#optimized-mark-vii-setup--campaign-configuration) uses Campaigns and Modules. [Bash Bunny](../Scripts/Bash/BashBunny/README.md) and [Rubber Ducky](../Scripts/Ducky/README.md) have different USB runtimes. Other Hak5 devices have separate official payload repositories and firmware; a matching command name is not sufficient for compatibility.

| Platform | Official source / format | Safe first-use and sideload boundary |
|---|---|---|
| **WiFi Pineapple Pager** | [Official User/Recon/Alert payload library](https://github.com/hak5/wifipineapplepager-payloads); on-device `payload.sh` | Copy a single reviewed local script to the correct **Pager** payload type, start with a no-radio message; do not use Mark VII campaigns |
| **WiFi Pineapple Mark VII** | [Campaigns](https://documentation.hak5.org/wifi-pineapple/ui-overview/campaigns) / [Modules](https://documentation.hak5.org/wifi-pineapple/ui-overview/modules) | Prefer built-in monitor-only campaign; validate module code, API version, package and UI support before third-party installs |
| **Bash Bunny / Mark II** | [Hak5 Bash Bunny payload library](https://github.com/hak5/bashbunny-payloads); Bash `payload.txt` with `ATTACKMODE`, `QUACK` | Review full source/dependencies, copy a benign HID marker into a single staged switch; match device generation and firmware |
| **USB Rubber Ducky (modern/legacy)** | [Official source library](https://github.com/hak5/usbrubberducky-payloads); source `payload.txt` compiled to `inject.bin` | Compile for the **actual** hardware/DuckyScript version and keyboard layout; verify a marker in a blank editor |
| **Shark Jack** | [Official Shark Jack library](https://github.com/hak5/sharkjack-payloads); model-specific Bash/DuckyScript source | Use a spare isolated Ethernet test bench, not a client's switch; review DHCP, routing and any scan/transmit behavior |
| **Shark Jack Display** | [Official Display library](https://github.com/hak5/sharkjackdisplay-payloads); `payload.txt` | Distinct display/menu and payload flow; check exact product revision and `NETMODE` handling before copying sources |
| **Packet Squirrel** | [Official Packet Squirrel library](https://github.com/hak5/packetsquirrel-payloads); `payload.txt` | Inline Ethernet changes the traffic path; test with dedicated two-port lab link and rollback, **not** real production traffic |
| **Key Croc** | [Official Key Croc library](https://github.com/hak5/keycroc-payloads); `payload.txt` | In-line keyboard hardware can capture sensitive input; baseline test only with a synthetic user and approved marker |
| **LAN Turtle** | [Hak5 LAN Turtle documentation](https://docs.hak5.org/) and firmware modules (check exact model) | Separate USB-Ethernet remote administration tooling; no assumption that Shark Jack payload scripts run here |
| **Signal Owl / Screen Crab / Plunder Bug** | [Hak5 documentation index](https://documentation.hak5.org/) | Separate hardware and capture/runtime requirements. Not every Hak5 device has a community `payload.txt` library |

**Popular GitHub collections (curated, not automatically runnable):** [Rubber Ducky projects ranked by relevance, stars & compatibility](../Scripts/Ducky/README.md#curated-github-payload-projects--popularity-compatibility--trust) and [Bash Bunny payload collections & maintenance review](../Scripts/Bash/BashBunny/README.md#curated-github-bash-bunny-payload-collections--compatibility). The guides identify original/archived repositories, distinguish Flipper/O.MG/Arduino references from Hak5 firmware, and explain pinning, code inspection, benign lab acceptance and rollback.

**Important:** the upstream sample collections may include interception, credential harvesting, command-and-control, persistence or disruptive network activity. **Do not bulk-install, automatically run or endorse** all samples. Prefer a fixed-text HID marker, an owned test AP inventory, or an isolated dummy Ethernet link, and only approve more intrusive testing under a separate signed plan.

#### Common Side-Load Review & Rollback Workflow

1. **Select exact platform/firmware and model.** Record payload interpreter, USB/network modes, switch position and the official source repository or versioned download.
2. **Pin a commit/hash**, inspect the source (including bundled shell/PowerShell/Python executables and compressed archives), and verify license, external connections, credentials, dependencies, package installation, persistence, scheduled tasks and elevated operations.
3. **Decide authorization class:** local benign, receive-only survey, active association/network traffic, credential/packet interception, persistent modification. Only benign exercises are default-approved.
4. **Isolate on a known-good bench:** offline disposable workstation with blank editor for HID; lab AP/phone for Wi-Fi; two-device synthetic VLAN/link for network appliances. Snapshot or document rollback before execution.
5. **Stage one payload** using the **device's verified deployment directory**. Do not assume a common root directory or file extension across Hak5 models. On USB devices, safely eject in arming/storage mode; avoid flashing the payload onto firmware partitions.
6. **Observe once:** record USB enumeration, network/routes, emitted RF, local output, log timestamps, and intended versus actual destination. Stop on unexpected transmission, third-party interaction or changes to default route/DNS.
7. **Corroborate:** use host endpoint events/EDR, AP-controller records, Kismet/Wazuh, test switch logs or known USB interface properties. A script exiting zero does not prove any vulnerability.
8. **Rollback, inventory and redact:** stop payloads, disconnect, restore firmware/network configuration, rotate synthetic credentials, hash and securely store allowed artifacts, remove unnecessary copies from the device.

#### Practical Safe Evaluation Examples For Other Hak5 Devices

| Device | Controlled exercise | Expected evidence |
|---|---|---|
| Shark Jack / Shark Jack Display | Connect only to **your lab switch** and validate port link, DHCP address and local interface status without scanning other addresses | Port VLAN/link state, assigned lab IP, switch/host logs and restore |
| Packet Squirrel | Place between two **owned** lab Ethernet endpoints; verify links work in pass-through mode and observe what a deliberate disconnect does | End-to-end link checks, physical link indicators, clean bypass/rollback |
| Key Croc | Connect a **disposable keyboard** and test computer with a synthetic local-only username/marker; keep capture/matches disabled unless essential and approved | Host recognized keyboard, synthetic text, source review and no retained secrets |
| Bunny / Ducky | Type a fixed harmless phrase into a focused blank editor with no terminal or browser open | USB class enumeration, marker, no privilege changes or network transfer |
| Mark VII / Pager | Observe a single owned synthetic AP, then independently verify WIDS controller alert behavior without active impersonation | Correct BSSID/channel/security, actual source events and sanitized result |

#### Model-Specific Troubleshooting

| Symptom | Investigate |
|---|---|
| Payload ignored | Wrong hardware format, firmware interpreter, file path/case, permissions or wrong switch/category |
| Payload appears but errors | Missing device helper functions, incompatible DuckyScript generation, OS/tool dependency or bad CRLF endings |
| OS sees new keyboard unexpectedly | Wrong USB class / `ATTACKMODE` selected; disconnect and restore known-good switch |
| LAN traffic changes | `NETMODE`/routing/bridge behaviour and link negotiation; stop inline device and restore direct cable |
| Unexpected AP or upload | Disable PineAP/alert or event action, disconnect management uplink and audit all scripts |
| Data not saved | Incorrect storage partition, missing media, no completed flush or script path assumption |
| Firmware update breaks payload | Firmware/API changed, packages removed, library helpers changed; restore pinned compatible version |

**Primary sources:** [Hak5 official payload repositories](https://github.com/hak5) · [Pager source](https://github.com/hak5/wifipineapplepager-payloads) · [Shark Jack](https://github.com/hak5/sharkjack-payloads) · [Packet Squirrel](https://github.com/hak5/packetsquirrel-payloads) · [Key Croc](https://github.com/hak5/keycroc-payloads). Do not confuse a source repository's approved pull request with a complete firmware or security certification.

## 📟 Device Setup & Usage Guides

**M5StickC Plus2:** [HackStarterPack integration and safe lab](./m5stickc-plus2-hackstarterpack.md) covers the exact board, CC1101 pinout, benign IR/BLE/HID tests and source review.


For ESP32/Flipper radio accessories used specifically for authorized mapping, see the [Wardriving platform index](../Wardriving/README.md), [Scout Lite + SigRoam](../Wardriving/sigroam-scout-lite.md), [Marauder](../Wardriving/esp32-marauder.md), and [AWOK Dual C5 + Biscuit](../Wardriving/awok-dual-c5-biscuit.md). These cover board revisions, firmware roles and GPS/log locations.


Detailed documentation, reference links, and step-by-step usage tutorials for specific hardware hacking tools on your bench:

| Device Guide | Description |
|--------------|-------------|
| **[BusPirate.md](./BusPirate.md)** | Open-source hacker multi-tool for interfacing with I2C, SPI, UART, and JTAG. |
| **[GreatFETone.md](./GreatFETone.md)** | Extensible open-source hardware tool for logic analysis, I2C/SPI manipulation, and USB RE. |
| **[JTAGulator.md](./JTAGulator.md)** | Hardware tool to brute-force and discover on-chip debug (OCD) interfaces like JTAG/UART. |
| **[BitPirate.md](./BitPirate.md)** | Serial interface bridge for embedded systems recon, fuzzing, and debugging. |
| **[LA1010.md](./LA1010.md)** | Setup and usage for the Innomaker LA1010 100MHz 16-channel USB Logic Analyzer. |
| **[HiLetgo.md](./HiLetgo.md)** | Setup and usage for the HiLetgo 24MHz 8-channel USB Logic Analyzer (Saleae clone). |
| **[T48_TL866-3G.md](./T48_TL866-3G.md)** | Universal IC Programmer guide for dumping and flashing EPROM, MCU, SPI, and NAND Flash. |

---

## ⚡ Attack Categories

### Fault Injection (Active)

Introduce controlled transient errors to bypass security checks, skip instructions, or corrupt comparisons.

| Method | Equipment | Precision | Complexity | Cost |
|--------|-----------|-----------|-----------|------|
| **[Voltage Glitching](https://chipwhisperer.readthedocs.io/en/latest/)** | [MOSFET](https://www.amazon.com/s?k=logic+level+N-channel+MOSFET) + [FPGA](https://www.amazon.com/s?k=FPGA+development+board) or [ChipWhisperer](https://www.newae.com/chipwhisperer) | Medium | Low | $ |
| **[Clock Glitching](https://chipwhisperer.readthedocs.io/en/latest/)** | [FPGA](https://www.amazon.com/s?k=FPGA+development+board) or [ChipWhisperer](https://www.newae.com/chipwhisperer) | High | Medium | $$ |
| **[EMFI](https://chipwhisperer.readthedocs.io/en/latest/ChipSHOUTER/ChipSHOUTER.html)** | [ChipSHOUTER](https://www.newae.com/chipshouter) or custom coil + pulser | Medium-High | Medium | $–$$ |
| **[Laser FI](https://www.keysight.com/us/en/cmp/device-security.html)** | IR laser + XY stage + decapped chip | Very High | High | $$$$ |
| **[Body Biasing](https://link.springer.com/chapter/10.1007/978-3-030-68487-7_11)** | Probe + pulse generator | Medium | Medium | $$ |

### Side-channel Analysis (Passive)

Extract secrets by observing physical emissions during normal operation.

| Technique | Observable | Traces Needed | Target |
|-----------|-----------|---------------|--------|
| **[SPA](https://en.wikipedia.org/wiki/Power_analysis#Simple_power_analysis)** | Power (single trace) | 1–10 | RSA, ECC with visible square/multiply pattern |
| **[DPA](https://en.wikipedia.org/wiki/Power_analysis#Differential_power_analysis) / [CPA](https://chipwhisperer.readthedocs.io/en/latest/)** | Power (statistical) | 100–100,000 | AES, DES, symmetric crypto |
| **[Timing](https://en.wikipedia.org/wiki/Timing_attack)** | Execution time | 100–10,000 | Password comparison, RSA, cache-based |
| **[SEMA](https://en.wikipedia.org/wiki/Electromagnetic_attack)** | EM emissions | 100–10,000 | Same as DPA but contactless |
| **[Template](https://chipwhisperer.readthedocs.io/en/latest/)** | Power (profiled) | 1–10 | Any: requires clone device for profiling |
| **[TVLA](https://chipwhisperer.readthedocs.io/en/latest/)** | Power (assessment) | 1,000–10,000 | Leakage detection: not key recovery |

### Interface Exploitation (Physical Access)

| Interface | Wires | Attack Value | Common Tools |
|-----------|-------|-------------|-------------|
| **[UART](https://learn.sparkfun.com/tutorials/serial-communication/all)** | TX, RX, GND | Boot logs, root shell, U-Boot console | [USB-UART adapter](https://www.amazon.com/s?k=FTDI+USB+UART+Adapter), [logic analyzer](https://www.amazon.com/s?k=24MHz+8CH+USB+Logic+Analyzer) |
| **[JTAG](https://en.wikipedia.org/wiki/JTAG)** | TCK, TMS, TDI, TDO, TRST | CPU halt, memory dump, register access | [J-Link](https://www.amazon.com/s?k=SEGGER+J-Link+EDU), OpenOCD, [JTAGulator](./JTAGulator.md) |
| **[SWD](https://developer.arm.com/documentation/101416/0100/Debug-ports/Serial-Wire-Debug)** | SWDCLK, SWDIO | Same as JTAG (ARM Cortex-M) | [ST-LINK](https://www.amazon.com/s?k=ST-Link+V2), CMSIS-DAP |
| **[SPI](https://learn.sparkfun.com/tutorials/serial-peripheral-interface-spi/all)** | SCLK, MOSI, MISO, CS | Flash dump (firmware extraction) | flashrom, [Bus Pirate](./BusPirate.md), [CH341A](https://www.amazon.com/s?k=CH341A+SPI+Programmer) |
| **[I²C](https://learn.sparkfun.com/tutorials/i2c/all)** | SDA, SCL | EEPROM read/write, PMIC manipulation | i2ctools, [Bus Pirate](./BusPirate.md) |

---

## 🔬 Bench Equipment Reference

### Essential Equipment

| Equipment | Recommended | Budget | Purpose |
|-----------|-------------|--------|---------|
| **[Oscilloscope](https://en.wikipedia.org/wiki/Oscilloscope)** | [Rigol DS1054Z](https://www.amazon.com/s?k=Rigol+DS1054Z) / [Siglent SDS1204X-E](https://www.amazon.com/s?k=Siglent+SDS1204X-E) | $350–$400 | Signal capture, power analysis, glitch verification |
| **[Logic Analyzer](https://en.wikipedia.org/wiki/Logic_analyzer)** | [Innomaker LA1010](./LA1010.md) / [HiLetgo](./HiLetgo.md) / [DSLogic](https://www.amazon.com/s?k=DSLogic+Plus) | $10–$150 | Protocol decode (UART, SPI, I²C, JTAG) |
| **[Multimeter](https://en.wikipedia.org/wiki/Multimeter)** | [Any decent DMM](https://www.amazon.com/s?k=digital+multimeter) | $20–$50 | Voltage/continuity checks |
| **[USB-UART Adapter](https://en.wikipedia.org/wiki/Universal_asynchronous_receiver-transmitter)** | [FTDI FT232R](https://www.amazon.com/s?k=FTDI+FT232RL+USB+to+TTL) / [CP2102](https://www.amazon.com/s?k=CP2102+USB+to+TTL) | $5–$15 | Serial console access |
| **[JTAG/SWD Probe](https://en.wikipedia.org/wiki/JTAG)** | [J-Link EDU](https://www.segger.com/products/debug-probes/j-link/models/j-link-edu/) / [ST-LINK V2](https://www.amazon.com/s?k=ST-Link+V2) | $20–$70 | Debug interface access |
| **[SPI/IC Programmer](https://en.wikipedia.org/wiki/Programmer_(hardware))** | [T48 TL866-3G](./T48_TL866-3G.md) / [Bus Pirate](./BusPirate.md) | $35–$70 | Flash chip read/write & component testing |
| **[Soldering Station](https://en.wikipedia.org/wiki/Soldering)** | [Hakko FX-888D](https://www.amazon.com/s?k=Hakko+FX-888D) | $100 | Component removal, wire attachment |
| **[Hot Air Rework](https://en.wikipedia.org/wiki/Rework_(electronics))** | [Quick 957DW](https://www.amazon.com/s?k=Quick+957DW+hot+air+rework) or equivalent | $100–$200 | IC removal, BGA work |

### Power Analysis & Fault Injection

| Equipment | Recommended | Budget | Purpose |
|-----------|-------------|--------|---------|
| **[ChipWhisperer Lite](https://chipwhisperer.readthedocs.io/en/latest/Capture/ChipWhisperer-Lite.html)** | [NewAE Technology](https://www.mouser.com/c/?q=chipwhisperer-lite) | ~$250 | Integrated glitching + power analysis |
| **[ChipWhisperer Pro](https://chipwhisperer.readthedocs.io/en/latest/Capture/ChipWhisperer-Pro.html)** | [NewAE Technology](https://www.mouser.com/c/?q=chipwhisperer-pro) | ~$1,500 | Higher performance, more glitch options |
| **[ChipSHOUTER](https://chipwhisperer.readthedocs.io/en/latest/ChipSHOUTER/ChipSHOUTER.html)** | [NewAE Technology](https://www.mouser.com/c/?q=chipshouter) | ~$1,000 | Electromagnetic fault injection |
| **[JTAGulator](https://grandideastudio.com/portfolio/security/jtagulator/)** | [Grand Idea Studio (Guide)](./JTAGulator.md) | ~$150 | JTAG/UART pinout brute-force |
| **[Glasgow Interface Explorer](https://github.com/GlasgowEmbedded/glasgow)** | [Open-source FPGA](https://www.crowdsupply.com/1bitsquared/glasgow) | ~$150 | Scriptable multi-protocol interface |
| [**GreatFET One**](https://greatscottgadgets.com/greatfet/one/) | [Great Scott Gadgets (Guide)](./GreatFETone.md) | ~$100 | Multi-purpose interface and bus manipulation |

---

## 🛠️ Tool Ecosystem

### Hardware Tools

| Tool | Purpose | Cost | Reference Guide |
|------|---------|------|-----------------|
| [**ChipWhisperer**](https://www.newae.com/chipwhisperer) | Integrated glitching + power analysis platform | $250–$1,500 | N/A |
| [**ChipSHOUTER**](https://www.newae.com/chipshouter) | EMFI pulse injector | ~$1,000 | N/A |
| [**JTAGulator**](https://grandideastudio.com/portfolio/security/jtagulator/) | JTAG/UART pinout discovery | ~$150 | [JTAGulator.md](./JTAGulator.md) |
| [**Glasgow**](https://github.com/GlasgowEmbedded/glasgow) | FPGA-based scriptable interface explorer | ~$150 | N/A |
| [**Bus Pirate**](https://buspirate.com/) | Interactive multi-protocol interface tool | ~$35 | [BusPirate.md](./BusPirate.md) |
| [**GreatFET One**](https://greatscottgadgets.com/greatfet/one/) | USB/Logic/Interface exploration | ~$100 | [GreatFETone.md](./GreatFETone.md) |
| [**T48 TL866-3G**](https://www.amazon.com/dp/B0BFX9FXGV) | Universal IC Programmer | ~$65 | [T48_TL866-3G.md](./T48_TL866-3G.md) |
| [**LA1010 / HiLetgo**](https://www.amazon.com) | USB Logic Analyzers (100MHz / 24MHz) | $15–$50 | [LA1010.md](./LA1010.md) & [HiLetgo.md](./HiLetgo.md) |

### Software Tools

| Tool | Purpose | Cost |
|------|---------|------|
| [**OpenOCD**](https://openocd.org/) | Open-source JTAG/SWD debug | Free/OSS |
| [**flashrom**](https://www.flashrom.org/) | SPI/parallel flash read/write | Free/OSS |
| [**Ghidra**](../ReverseEngineering/README.md) | Firmware reverse engineering; [local guide](../ReverseEngineering/ghidra-guide-index.md) and [upstream project](https://github.com/NationalSecurityAgency/ghidra) | Free/OSS |
| [**IDA Pro**](https://hex-rays.com/ida-pro) | Firmware reverse engineering | $$$$ |
| [**Binwalk**](https://github.com/ReFirmLabs/binwalk) | Firmware extraction and analysis | Free/OSS |
| [**Sigrok / PulseView**](https://sigrok.org/) | Open-source logic analyzer frontend | Free/OSS |
| [**ChipWhisperer Software**](https://chipwhisperer.readthedocs.io/) | Jupyter-based SCA/FI tutorials | Free/OSS |

### Python Libraries For Side-channel Analysis

| Library | Purpose | URL |
|---------|---------|-----|
| [**scared**](https://github.com/eshard/scared) | Side-channel analysis framework | Free/OSS |
| [**lascar**](https://github.com/Ledger-Donjon/lascar) | Flexible SCA framework (Ledger) | Free/OSS |
| [**SCARR**](https://github.com/decryptofy/scarr) | Side-channel analysis framework (Oregon State) | Free/OSS |
| **NumPy / SciPy / Matplotlib** | Trace processing, filtering, visualization | Free/OSS |

---

## ⚠️ Security & Legal Disclaimer

### 🔴 Critical: Authorized Use Only

```
⚠️ LEGAL AND ETHICAL USE ONLY ⚠️

This section contains hardware attack techniques and methodologies for:

✅ AUTHORIZED USES:
   • Security assessments with explicit written authorization from device owners
   • Red team operations with organizational approval
   • Academic research on owned or authorized hardware
   • Product security evaluation by manufacturers
   • CTF competitions and authorized challenges
   • Personal research on your own hardware
   • Educational purposes with proper supervision

🚫 STRICTLY PROHIBITED:
   • Attacking hardware you do not own or have authorization to test
   • Bypassing DRM or copy protection in violation of DMCA
   • Extracting proprietary firmware or trade secrets without authorization
   • Cloning, counterfeiting, or pirating commercial products
   • Tampering with safety-critical systems (medical, automotive, aviation)
   • Any activity violating CFAA, DMCA, or equivalent laws
   • Any illegal or unethical activities
```

### Applicable Laws

| Law / Regulation | Scope |
|-----------------|-------|
| **CFAA (18 U.S.C. § 1030)** | Unauthorized access to protected computers: includes embedded systems |
| **DMCA (17 U.S.C. § 1201)** | Circumvention of technological protection measures (DRM bypass) |
| **EAR / ITAR** | Export controls on certain cryptographic and defense-related hardware tools |
| **Trade Secret Laws** | Extraction of proprietary firmware or algorithms may constitute misappropriation |
| **EU Cybercrime Directives** | Unauthorized access to computer systems including embedded devices |
| **DMCA § 1201(j)** | Security research exemption: narrow; consult legal counsel |

### Warranty Disclaimer

```
These materials are provided "AS IS" without warranty of any kind.

THE AUTHORS AND CONTRIBUTORS:
• Make no guarantees about technique effectiveness or accuracy
• Are not responsible for damage to hardware during testing
• Are not liable for legal consequences of misuse
• Disclaim all liability for injury from high-voltage equipment
• May update content without notice

USERS EXPLICITLY ACKNOWLEDGE:
• Hardware hacking involves electrical hazards (high voltage, laser, EM pulses)
• Fault injection can permanently damage target devices
• They accept all risks including equipment damage and personal injury
• Authorization must be explicit and from the device owner
```

### ⚡ Safety Warning

```
🔴 ELECTRICAL SAFETY:

Hardware hacking involves potentially dangerous equipment:
   • High-voltage pulse generators (EMFI, LFI)
   • Laser sources (Class 3B/4: eye damage risk)
   • Soldering and hot air rework (burn risk)
   • Chemical decapping agents (fuming acids: fume hood required)

ALWAYS:
   ✓ Wear appropriate PPE (safety glasses, gloves, lab coat)
   ✓ Work in a ventilated area for chemical decapping
   ✓ Use laser safety goggles rated for the correct wavelength
   ✓ Follow your institution's EHS guidelines
   ✓ Never work alone with high-voltage equipment
```

---

## 🤝 Contributing

To contribute to the Hardware Hacking section:

1. Fork the repository
2. Follow the 4-header standard: `## 🎯 Purpose`, `## ⚙️ Function`, `## 🏆 Goal`, `## 📋 When to Use` after every H1
3. Include written authorization reminders for any offensive technique
4. Add electrical and physical safety warnings for hands-on procedures
5. Note the exact tool model, firmware version, and OS environment tested
6. Submit a pull request with a description of the contribution

---

## 📚 Resources

### Books

| Title | Author(s) | Focus |
|-------|-----------|-------|
| *The Hardware Hacker* | Andrew "bunnie" Huang | Hardware hacking philosophy and techniques |
| *Hardware Security: A Hands-on Learning Approach* | Bhunia, Tehranipoor | Academic hardware security |
| *Power Analysis Attacks* | Mangard, Oswald, Popp | DPA/SPA theory and practice |
| *Fault Analysis in Cryptography* | Joye, Tunstall (eds.) | Fault injection theory |

### Online Resources

| Resource | URL |
|----------|-----|
| ChipWhisperer Documentation & Tutorials | [https://chipwhisperer.readthedocs.io/](https://chipwhisperer.readthedocs.io/) |
| Microcorruption CTF (MSP430 exploitation) | [https://microcorruption.com/](https://microcorruption.com/) |
| CHES Conference Proceedings | [https://ches.iacr.org/](https://ches.iacr.org/) |
| Riscure / Keysight Device Security Tools | [https://www.riscure.com/security-tools/](https://www.riscure.com/security-tools/) |
| DEF CON Hardware Hacking Village | [https://dchhv.org/](https://dchhv.org/) |
| Wrong Baud (hardware RE blog) | [https://wrongbaud.github.io/](https://wrongbaud.github.io/) |

<a id="conferences-and-communities"></a>
### Conferences & Communities

| Conference | Focus |
|-----------|-------|
| **CHES** | Cryptographic Hardware and Embedded Systems: leading SCA/FI venue |
| **DEF CON HHV** | Hardware Hacking Village: hands-on workshops and talks |
| **Hardwear.io** | Dedicated hardware security conference |
| **REcon** | Reverse engineering: significant hardware content |
| **USENIX Security** | Academic security: regular hardware security papers |

---

## 🔗 Quick Links

### Internal Links
- [🏠 Main Repository](../README.md)
- [🎯 START HERE Guide](../START_HERE.md)
- [💻 Cybersecurity Master Guide](../ultimate_cybersecurity_master_guide.md)
- [✅ Security Checklists](../Checklists/README.md)
- [🛰️ Space Security](../SpaceSecurity/README.md)
- [🔍 OSINT Resources](../OSINT/README.md)
- [📚 Documentation](../Documentation/README.md)
- [🔒 OPSEC Guidelines](../OPSEC/README.md)

---

## 📊 Repository Statistics

```
📁 Chapters: 5
📖 Covers: Threat modeling, electrical fundamentals, fault injection, side-channel analysis, power analysis
🔄 Last Updated: June 2026
👥 Maintained by: Pacific Northwest Computers (PNWC)
📝 Status: Active & Growing
```

---

<div align="center">

## Related Files
- [../Documentation/Locksport.md](../Documentation/Locksport.md) - Physical lock bypass: complements hardware debug access in full red-team physical assessments
- [../Documentation/bruce_firmware.md](../Documentation/bruce_firmware.md) - Bruce firmware: NFC/RFID and sub-GHz attacks on the wireless protocols used by embedded targets
- [../Documentation/flipper_zero_guide.md](../Documentation/flipper_zero_guide.md) - Flipper Zero: RFID/NFC/sub-GHz tool for the RF-adjacent attack surface of embedded devices
- [../SDR/](../SDR/) - SDR guides: RF analysis of wireless-enabled embedded targets
- [../IncidentResponse/](../IncidentResponse/) - Incident response: detecting hardware-level attacks and evidence collection from embedded devices
- [../Cryptography/phantomdrive-guide.md](../Cryptography/phantomdrive-guide.md) - experimental CH569W hidden encrypted USB firmware research; not audited for client data
- [../Cryptography/solokeys-guide.md](../Cryptography/solokeys-guide.md) - Solo 2 Secure/Hacker firmware-security boundary and authentication use
- [../Mobile/README.md](../Mobile/README.md) - Mobile security section (HID/BadUSB via NetHunter is a mobile hardware attack vector)
- [../Mobile/mobile_pentest_sop.md](../Mobile/mobile_pentest_sop.md) - Mobile pentest SOP (HID and BadUSB attack procedures)

---

**📖 Use These Techniques Responsibly: Authorization is MANDATORY**

*Physical access changes everything: test only what you own or are authorized to assess.*

**Repository**: [ULTIMATE CYBERSECURITY MASTER GUIDE](https://github.com/Pnwcomputers/ULTIMATE-CYBERSECURITY-MASTER-GUIDE)

**Maintained by**: [Pacific Northwest Computers](https://github.com/Pnwcomputers)

---

⚠️ **CRITICAL: These are ATTACK TECHNIQUES - Written authorization is REQUIRED** ⚠️

⚠️ **Unauthorized use is a FEDERAL CRIME with up to 10 years imprisonment** ⚠️

⚠️ **ALWAYS obtain explicit written authorization before using any technique** ⚠️

⭐ **Star this repo if you find it useful!** ⭐

</div>
