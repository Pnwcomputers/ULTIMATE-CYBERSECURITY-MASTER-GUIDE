# 🔧 Hardware Hacking

<div align="center">

**Physical and electronic attack techniques against embedded systems, microcontrollers, SoCs, and cryptographic hardware**

*Part of the [ULTIMATE CYBERSECURITY MASTER GUIDE](../README.md)*

[![Fault Injection](https://img.shields.io/badge/Fault_Injection-Glitching_%7C_EMFI_%7C_Laser-red?style=for-the-badge)]()
[![Side-Channel](https://img.shields.io/badge/Side--Channel-SPA_%7C_DPA_%7C_CPA-blue?style=for-the-badge)]()
[![Interfaces](https://img.shields.io/badge/Interfaces-JTAG_%7C_SWD_%7C_UART_%7C_SPI-green?style=for-the-badge)]()
[![Threat Modeling](https://img.shields.io/badge/Threat_Modeling-Assets_%7C_Profiles_%7C_Countermeasures-orange?style=for-the-badge)]()

</div>

---

## 📋 Table of Contents

- [Overview](#overview)
- [Chapter Guides](#chapter-guides)
- [Attack Categories](#attack-categories)
- [Bench Equipment Reference](#bench-equipment-reference)
- [Tool Ecosystem](#tool-ecosystem)
- [Security & Legal Disclaimer](#security--legal-disclaimer)
- [Resources](#resources)

---

## 🎯 Overview

Hardware security extends the attack surface beyond software and networks into the **physical domain** — where an attacker who can touch the device has capabilities unavailable over any network. Debug interfaces, power traces, clock signals, and electromagnetic emissions all become vectors for extraction, bypass, and exploitation.

This section provides a **comprehensive reference** for hardware security assessment, from threat modeling and electrical fundamentals through advanced fault injection and side-channel analysis techniques.

**What You'll Find Here:**
- 🎯 Hardware threat modeling — attacker profiles, asset mapping, countermeasure frameworks
- ⚡ Electrical fundamentals — logic levels, communication interfaces (UART, SPI, I²C, JTAG/SWD), measurement equipment
- 💥 Fault injection attacks — voltage glitching, clock glitching, EMFI, laser fault injection, body biasing
- 📊 Side-channel analysis — timing attacks, Simple Power Analysis (SPA), Differential Power Analysis (DPA)
- 🔬 Power analysis practicals — measurement setup, trace acquisition, filtering, CPA implementation, visualization
- 🛡️ Countermeasures — silicon-level, firmware-level, and physical protections

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
  └─> Then Chapter 3 (Fault Injection) — most accessible attack category
  └─> Then Chapters 4–5 (Side-Channel) — builds on measurement fundamentals

Experienced practitioner?
  └─> Jump directly to the relevant chapter
  └─> Chapter 3 for glitching campaign setup
  └─> Chapter 5 for CPA implementation and visualization code
  └─> Chapter 1 for threat model documentation template
```

---

## ⚡ Attack Categories

### Fault Injection (Active)

Introduce controlled transient errors to bypass security checks, skip instructions, or corrupt comparisons.

| Method | Equipment | Precision | Complexity | Cost |
|--------|-----------|-----------|-----------|------|
| **Voltage Glitching** | MOSFET + FPGA or ChipWhisperer | Medium | Low | $ |
| **Clock Glitching** | FPGA or ChipWhisperer | High | Medium | $$ |
| **EMFI** | ChipSHOUTER or custom coil + pulser | Medium-High | Medium | $–$$ |
| **Laser FI** | IR laser + XY stage + decapped chip | Very High | High | $$$$ |
| **Body Biasing** | Probe + pulse generator | Medium | Medium | $$ |

### Side-Channel Analysis (Passive)

Extract secrets by observing physical emissions during normal operation.

| Technique | Observable | Traces Needed | Target |
|-----------|-----------|---------------|--------|
| **SPA** | Power (single trace) | 1–10 | RSA, ECC with visible square/multiply pattern |
| **DPA / CPA** | Power (statistical) | 100–100,000 | AES, DES, symmetric crypto |
| **Timing** | Execution time | 100–10,000 | Password comparison, RSA, cache-based |
| **SEMA** | EM emissions | 100–10,000 | Same as DPA but contactless |
| **Template** | Power (profiled) | 1–10 | Any — requires clone device for profiling |
| **TVLA** | Power (assessment) | 1,000–10,000 | Leakage detection — not key recovery |

### Interface Exploitation (Physical Access)

| Interface | Wires | Attack Value | Common Tools |
|-----------|-------|-------------|-------------|
| **UART** | TX, RX, GND | Boot logs, root shell, U-Boot console | USB-UART adapter, logic analyzer |
| **JTAG** | TCK, TMS, TDI, TDO, TRST | CPU halt, memory dump, register access | J-Link, OpenOCD, JTAGulator |
| **SWD** | SWDCLK, SWDIO | Same as JTAG (ARM Cortex-M) | ST-LINK, CMSIS-DAP |
| **SPI** | SCLK, MOSI, MISO, CS | Flash dump (firmware extraction) | flashrom, Bus Pirate, CH341A |
| **I²C** | SDA, SCL | EEPROM read/write, PMIC manipulation | i2ctools, Bus Pirate |

---

## 🔬 Bench Equipment Reference

### Essential Equipment

| Equipment | Recommended | Budget | Purpose |
|-----------|-------------|--------|---------|
| **Oscilloscope** | Rigol DS1054Z / Siglent SDS1204X-E | $350–$400 | Signal capture, power analysis, glitch verification |
| **Logic Analyzer** | Saleae Logic 8 / DSLogic | $100–$500 | Protocol decode (UART, SPI, I²C, JTAG) |
| **Multimeter** | Any decent DMM | $20–$50 | Voltage/continuity checks |
| **USB-UART Adapter** | FTDI FT232R / CP2102 | $5–$15 | Serial console access |
| **JTAG/SWD Probe** | J-Link EDU / ST-LINK V2 | $20–$70 | Debug interface access |
| **SPI Programmer** | CH341A / Bus Pirate 5 | $5–$150 | Flash chip read/write |
| **Soldering Station** | Hakko FX-888D | $100 | Component removal, wire attachment |
| **Hot Air Rework** | Quick 957DW or equivalent | $100–$200 | IC removal, BGA work |

### Power Analysis & Fault Injection

| Equipment | Recommended | Budget | Purpose |
|-----------|-------------|--------|---------|
| **ChipWhisperer Lite** | NewAE Technology | ~$250 | Integrated glitching + power analysis |
| **ChipWhisperer Pro** | NewAE Technology | ~$1,500 | Higher performance, more glitch options |
| **ChipSHOUTER** | NewAE Technology | ~$1,000 | Electromagnetic fault injection |
| **JTAGulator** | Grand Idea Studio | ~$150 | JTAG/UART pinout brute-force |
| **Glasgow Interface Explorer** | Open-source FPGA | ~$150 | Scriptable multi-protocol interface |
| **Current Probe** | Tektronix TCP0020 | $$$ | Non-invasive current measurement |

---

## 🛠️ Tool Ecosystem

### Hardware Tools

| Tool | Purpose | Cost |
|------|---------|------|
| [**ChipWhisperer**](https://www.newae.com/chipwhisperer) | Integrated glitching + power analysis platform | $250–$1,500 |
| [**ChipSHOUTER**](https://www.newae.com/chipshooter) | EMFI pulse injector | ~$1,000 |
| [**JTAGulator**](http://www.grandideastudio.com/jtagulator/) | JTAG/UART pinout discovery | ~$150 |
| [**Glasgow**](https://github.com/GlasgowEmbedded/glasgow) | FPGA-based scriptable interface explorer | ~$150 |
| [**Bus Pirate 5**](https://buspirate.com/) | Interactive multi-protocol interface tool | ~$35 |
| [**Saleae Logic**](https://www.saleae.com/) | Logic analyzer with protocol decoders | $100–$500 |

### Software Tools

| Tool | Purpose | Cost |
|------|---------|------|
| [**OpenOCD**](https://openocd.org/) | Open-source JTAG/SWD debug | Free/OSS |
| [**flashrom**](https://www.flashrom.org/) | SPI/parallel flash read/write | Free/OSS |
| [**Ghidra**](https://ghidra-sre.org/) | Firmware reverse engineering | Free/OSS |
| [**IDA Pro**](https://hex-rays.com/ida-pro/) | Firmware reverse engineering | $$$$ |
| [**Binwalk**](https://github.com/ReFirmLabs/binwalk) | Firmware extraction and analysis | Free/OSS |
| [**Sigrok / PulseView**](https://sigrok.org/) | Open-source logic analyzer frontend | Free/OSS |
| [**ChipWhisperer Software**](https://chipwhisperer.readthedocs.io/) | Jupyter-based SCA/FI tutorials | Free/OSS |

### Python Libraries for Side-Channel Analysis

| Library | Purpose | URL |
|---------|---------|-----|
| [**scared**](https://github.com/eshard/scared) | Side-channel analysis framework | Free/OSS |
| [**lascar**](https://github.com/Ledger-Donjon/lascar) | Flexible SCA framework (Ledger) | Free/OSS |
| [**SCApy**](https://github.com/phdphuc/scapy-sca) | Side-channel analysis in Python | Free/OSS |
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
| **CFAA (18 U.S.C. § 1030)** | Unauthorized access to protected computers — includes embedded systems |
| **DMCA (17 U.S.C. § 1201)** | Circumvention of technological protection measures (DRM bypass) |
| **EAR / ITAR** | Export controls on certain cryptographic and defense-related hardware tools |
| **Trade Secret Laws** | Extraction of proprietary firmware or algorithms may constitute misappropriation |
| **EU Cybercrime Directives** | Unauthorized access to computer systems including embedded devices |
| **DMCA § 1201(j)** | Security research exemption — narrow; consult legal counsel |

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
   • Laser sources (Class 3B/4 — eye damage risk)
   • Soldering and hot air rework (burn risk)
   • Chemical decapping agents (fuming acids — fume hood required)

ALWAYS:
   ✓ Wear appropriate PPE (safety glasses, gloves, lab coat)
   ✓ Work in a ventilated area for chemical decapping
   ✓ Use laser safety goggles rated for the correct wavelength
   ✓ Follow your institution's EHS guidelines
   ✓ Never work alone with high-voltage equipment
```

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
| ChipWhisperer Documentation & Tutorials | https://chipwhisperer.readthedocs.io/ |
| Microcorruption CTF (MSP430 exploitation) | https://microcorruption.com/ |
| CHES Conference Proceedings | https://ches.iacr.org/ |
| Riscure Public Training Materials | https://www.riscure.com/security-tools/ |
| DEF CON Hardware Hacking Village | https://dchhv.org/ |
| Wrong Baud (hardware RE blog) | https://wrongbaud.github.io/ |

### Conferences and Communities

| Conference | Focus |
|-----------|-------|
| **CHES** | Cryptographic Hardware and Embedded Systems — leading SCA/FI venue |
| **DEF CON HHV** | Hardware Hacking Village — hands-on workshops and talks |
| **Hardwear.io** | Dedicated hardware security conference |
| **REcon** | Reverse engineering — significant hardware content |
| **USENIX Security** | Academic security — regular hardware security papers |

---

## 🔗 Quick Links

### Internal Links
- [🏠 Main Repository](../README.md)
- [🎯 START HERE Guide](../START_HERE.md)
- [💻 Cybersecurity Master Guide](../ultimate_cybersecurity_master_guide.md)
- [✅ Security Checklists](../Checklists/README.md)
- [🛰️ Space Security](../Space-Security/README.md)
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

**📖 Use These Techniques Responsibly: Authorization is MANDATORY**

*Physical access changes everything — test only what you own or are authorized to assess.*

**Repository**: [ULTIMATE CYBERSECURITY MASTER GUIDE](https://github.com/Pnwcomputers/ULTIMATE-CYBERSECURITY-MASTER-GUIDE)

**Maintained by**: [Pacific Northwest Computers](https://github.com/Pnwcomputers)

---

⚠️ **Hardware attacks can permanently damage devices — test on authorized hardware only** ⚠️

⚠️ **DMCA restrictions may apply to DRM circumvention — consult legal counsel** ⚠️

⚠️ **Electrical safety hazards — follow proper EHS guidelines** ⚠️

⭐ **Star this repo if you find it useful!** ⭐

</div>
