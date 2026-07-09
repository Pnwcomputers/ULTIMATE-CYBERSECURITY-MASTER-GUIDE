# 🔧 Hardware Hacking

<div align="center">

**Physical and electronic attack techniques against embedded systems, microcontrollers, SoCs, and cryptographic hardware**

*Part of the [ULTIMATE CYBERSECURITY MASTER GUIDE](../README.md)*

[![Fault Injection](https://img.shields.io/badge/Fault_Injection-Glitching_%7C_EMFI_%7C_Laser-red?style=for-the-badge)]()
[![Side-Channel](https://img.shields.io/badge/Side--Channel-SPA_%7C_DPA_%7C_CPA-blue?style=for-the-badge)]()
[![Interfaces](https://img.shields.io/badge/Interfaces-JTAG_%7C_SWD_%7C_SPI-green?style=for-the-badge)]()

</div>

---

## 🎯 Purpose
Index and navigation hub for the Hardware Hacking section - covering physical and electronic attack techniques against embedded systems: JTAG/SWD/UART debug access, fault injection (voltage, clock, EM, laser), side-channel analysis (SPA, DPA, CPA), firmware extraction, and the hardware tools used in each category.

## ⚙️ Function
Links to five chapter guides (threat modeling, electrical fundamentals, fault injection, power analysis theory, power analysis practicals) and seven device guides (Bus Pirate, Bit Pirate, GreatFET One, JTAGulator, LA1010 logic analyzer, HiLetgo logic analyzer, T48 IC programmer). Includes attack category taxonomy, bench equipment reference, and tool ecosystem overview.

## 🏆 Goal
Serve as the entry point for hardware security work - helping practitioners find the right chapter or tool guide for their current task without reading the full guide linearly.

## 📋 When to Use
- Starting a hardware security assessment: choose the right chapter and tool for your target
- Identifying which hardware tool to use for a given protocol or attack type
- Onboarding to hardware hacking: read chapters in order, then reference tool files for specific devices

---

## 📋 Table of Contents

- [Overview](#overview)
- [Chapter Guides](#chapter-guides)
- [Device Setup & Usage Guides](#device-setup--usage-guides)
- [Attack Categories](#attack-categories)
- [Bench Equipment Reference](#bench-equipment-reference)
- [Tool Ecosystem](#tool-ecosystem)
- [Security & Legal Disclaimer](#security--legal-disclaimer)
- [Resources](#resources)

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

### Purpose

These materials serve as:
- **Assessment methodology** for authorized hardware security testing
- **Bench reference** for measurement setup, probing, and signal capture
- **Attack technique guide** for fault injection and side-channel campaigns
- **Implementation reference** with working Python code for CPA, filtering, alignment, and visualization
- **Training material** for hardware security researchers and red teams
- **Countermeasure guide** for embedded systems designers and security architects

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

## 📟 Device Setup & Usage Guides

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

### Side-Channel Analysis (Passive)

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
| [**Ghidra**](https://github.com/NationalSecurityAgency/ghidra) | Firmware reverse engineering | Free/OSS |
| [**IDA Pro**](https://hex-rays.com/ida-pro/) | Firmware reverse engineering | $$$$ |
| [**Binwalk**](https://github.com/ReFirmLabs/binwalk) | Firmware extraction and analysis | Free/OSS |
| [**Sigrok / PulseView**](https://sigrok.org/) | Open-source logic analyzer frontend | Free/OSS |
| [**ChipWhisperer Software**](https://chipwhisperer.readthedocs.io/) | Jupyter-based SCA/FI tutorials | Free/OSS |

### Python Libraries for Side-Channel Analysis

| Library | Purpose | URL |
|---------|---------|-----|
| [**scared**](https://github.com/eshard/scared) | Side-channel analysis framework | Free/OSS |
| [**lascar**](https://github.com/Ledger-Donjon/lascar) | Flexible SCA framework (Ledger) | Free/OSS |
| [**SCARR**](https://github.com/decryptofy/scarr) | Side-channel analysis framework (Oregon State) | Free/OSS |
| **NumPy / SciPy / Matplotlib** | Trace processing, filtering, visualization | Free/OSS |

---

## ⚠️ Security & Legal Disclaimer

### 🔴 CRITICAL: Authorized Use Only

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

### Conferences and Communities

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
