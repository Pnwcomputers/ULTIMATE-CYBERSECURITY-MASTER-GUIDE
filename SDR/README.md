# 📻 Software Defined Radio (SDR) & RF Security

## 🎯 Purpose
Index and entry point for the SDR section — covering foundational SDR theory, GNU Radio, signal intelligence, protocol reversing, and advanced RF security topics across two comprehensive guides.

## ⚙️ Function
Links to sdr.md (foundational guide: IQ sampling, SDR hardware, GNU Radio, Wi-Fi/BT/cellular/GPS analysis) and sdr_hacking.md (advanced guide: SIGINT, protocol reversing, LoRa key cracking, TEMPEST, EM side-channel, firmware baseband exploitation). Includes hardware comparison table, frequency reference, legal framework summary, and tool ecosystem overview.

## 🏆 Goal
Serve as the starting point for SDR work — directing beginners to sdr.md for fundamentals and practitioners with GNU Radio experience to sdr_hacking.md for offensive techniques.

## 📋 When to Use
- Choosing which SDR guide to start with based on experience level
- Hardware selection: comparing RTL-SDR, HackRF, Airspy, PlutoSDR for a specific use case
- Legal/regulatory reference: FCC licensing requirements before transmitting

<div align="center">

**Collection of RF analysis tools, signal capture guides, and SDR exploitation techniques**

*Part of the [ULTIMATE CYBERSECURITY MASTER GUIDE](../README.md)*

[![SDR](https://img.shields.io/badge/Hardware-SDR-blue?style=for-the-badge&logo=broadcom)]()
[![RF](https://img.shields.io/badge/Frequencies-RF_Analysis-green?style=for-the-badge&logo=wifi)]()
[![GNURadio](https://img.shields.io/badge/Software-GNU_Radio-orange?style=for-the-badge)]()
[![Security](https://img.shields.io/badge/Security-Signal_Intelligence-red?style=for-the-badge&logo=hackthebox)]()

</div>

---

## 📋 Table of Contents

- [Overview](#overview)
- [Hardware Ecosystem](#hardware-ecosystem)
- [Software & Tool Categories](#software--tool-categories)
- [Target Frequencies & Protocols](#target-frequencies--protocols)
- [How to Use SDR Tools Safely](#how-to-use-sdr-tools-safely)
- [⚠️ CRITICAL Security & Legal Warning](#️-critical-security--legal-warning)
- [Contributing](#contributing)
- [Resources](#resources)

---

## 🎯 Overview

This directory contains **Software Defined Radio (SDR) configurations, RF reverse engineering tools, GNU Radio flowgraphs, and signal analysis methodologies**. These materials are designed for authorized hardware security testing, signal intelligence (SIGINT) research, and educational purposes.

### 🔴 CRITICAL WARNING

```
⚠️ RADIO FREQUENCY TRANSMISSION IS HEAVILY REGULATED ⚠️

Many techniques in this collection involve TRANSMITTING radio signals, Replay Attacks,
or Signal Jamming. Unauthorized transmission is a FEDERAL OFFENSE.

YOU MUST have explicit authorization, proper licensing (e.g., HAM Radio License), 
and use appropriate containment (Faraday cages, dummy loads) before transmitting.

Using these tools improperly violates:
• Federal Communications Commission (FCC) Regulations - Massive fines & imprisonment
• Electronic Communications Privacy Act (ECPA) / Wiretap Act
• Federal Aviation Administration (FAA) laws
• Critical Infrastructure protection laws
```

---

## 📡 Hardware Ecosystem

### SDR Devices

| Device | Capabilities | Target Use Case | Risk Level |
|--------|--------------|-----------------|------------|
| **[RTL-SDR (V3/V4)](https://www.rtl-sdr.com/)** | Receive Only (Rx) | Sniffing, Reconnaissance, SIGINT | 🟢 LOW |
| **[HackRF One](https://greatscottgadgets.com/hackrf/one/)** | Half-Duplex (Tx/Rx) | Replay attacks, fuzzing, wideband sniffing | 🔴 HIGH |
| **[BladeRF](https://www.nuand.com/) / [USRP](https://www.ettus.com/)** | Full-Duplex (Tx/Rx) | Cell base station spoofing, GPS spoofing | 🔴 EXTREME |
| **[LimeSDR](https://limemicro.com/products/boards/limesdr/)** | Full-Duplex (Tx/Rx) | Advanced telecommunications research | 🔴 EXTREME |
| **[Flipper Zero](https://flipperzero.one/)** | Sub-GHz (Tx/Rx) | IoT replay, access control testing | 🟡 MEDIUM |
| **[Yard Stick One](https://greatscottgadgets.com/yardstickone/)** | Sub-GHz (Tx/Rx) | Proprietary RF protocol exploitation | 🔴 HIGH |

---

## 🗂️ Software & Tool Categories

### 1. Signal Capture & Reconnaissance

**Current Tools & Workflows:**

| Tool / Script | Description | Risk Level |
|--------|-------------|------------|
| **[GQRX](https://gqrx.dk/) / [SDR# (SpyServer)](https://airspy.com/download/)** | General spectrum monitoring and audio demodulation | 🟢 LOW |
| **[rtl_433](https://github.com/merbanan/rtl_433)** | Decoding ISM band devices (weather stations, TPMS, alarms) | 🟢 LOW |
| **[dump1090](https://github.com/flightaware/dump1090)** | ADS-B aviation tracking and decoding | 🟢 LOW |
| **[Kalibrate (kalibrate-rtl)](https://github.com/steve-m/kalibrate-rtl)** | GSM base station frequency calculation | 🟢 LOW |
| **[Kismet](https://www.kismetwireless.net/)** | Wi-Fi / Bluetooth / SDR network discovery | 🟡 MEDIUM |

**Security Considerations:**
```
⚠️ While RECEIVING is generally legal in many jurisdictions, DECODING encrypted 
or private communications (like cellular calls or pager messages) can violate 
the Wiretap Act and ECPA.
```

---

### 2. Reverse Engineering & Analysis

**Current Tools & Workflows:**

| Tool / Script | Description | Risk Level |
|--------|-------------|------------|
| **[Universal Radio Hacker (URH)](https://github.com/jopohl/urh)** | Protocol investigation, demodulation, and bit extraction | 🟡 MEDIUM |
| **[Inspectrum](https://github.com/miek/inspectrum)** | Visual analysis of captured I/Q baseband signals | 🟢 LOW |
| **[GNU Radio](https://www.gnuradio.org/)** | Block-based visual programming for DSP and signal routing | 🟡 MEDIUM |
| **[Baudline](http://www.baudline.com/)** | Time-frequency signal analysis | 🟢 LOW |

---

### 3. Exploitation & Transmission (Active Attacks)

**Current Tools & Workflows:**

| Tool / Script | Description | Risk Level |
|--------|-------------|------------|
| **[Replay Attack Scripts](https://github.com/greatscottgadgets/hackrf/tree/master/firmware/hackrf_usb)** | Capturing and rebroadcasting OOK/ASK signals | 🔴 HIGH |
| **[GPS-SDR-SIM](https://github.com/osqzss/gps-sdr-sim)** | Generating fake GPS constellations for spoofing | 🔴 EXTREME |
| **[gr-gsm](https://github.com/ptrkrysik/gr-gsm) / [srsLTE (srsRAN)](https://www.srsran.com/)** | Rogue base station / IMSI catcher frameworks | 🔴 EXTREME |
| **[RollJam (Sammy Kamkar)](https://samy.pl/rolljam/)** | Rolling code bypass implementation | 🔴 HIGH |
| **[Jamming / Flooding](https://www.fcc.gov/general/jammer-enforcement)** | Overpowering legitimate RF receivers | 🔴 EXTREME |

**Security Considerations:**
```
⚠️ CRITICAL: Active transmission attacks include:
   • GPS Spoofing (Extremely illegal, endangers aviation and maritime navigation)
   • Jamming (Strictly prohibited by the FCC under ALL circumstances)
   • IMSI Catching (Violates wiretap laws and telecom regulations)
   • Access Control Replay (Illegal trespassing/access without authorization)

TRANSMITTING WITHOUT AUTHORIZATION/LICENSING = SEVERE FEDERAL PENALTIES
```

---

## 📖 How to Use SDR Tools Safely

### ⚠️ BEFORE TRANSMITTING ANY SIGNAL

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

### Lab & Bench Setup Rules

```
Safe Hardware Hacking Environments ONLY:

✅ AUTHORIZED Setup:
   • Coaxial cables directly connecting Tx to Rx with inline attenuators
   • Use of 50-ohm Dummy Loads to prevent signal radiation
   • RF shielded tents or Faraday boxes for over-the-air testing
   • Explicit written permission from facility owners

🚫 NEVER Test On/With:
   • Medical telemetry equipment (Pacemakers, hospital devices)
   • Aviation frequencies (1090MHz, 121.5MHz, GPS L1/L2)
   • Emergency services (Police, Fire, EMS radios)
   • Cellular networks (GSM, LTE, 5G) without extreme isolation
   • Your neighbor's garage door, car, or IoT devices
```

---

## ⚠️ CRITICAL Security & Legal Warning

### 🔴 FEDERAL REGULATORY WARNING

```
═══════════════════════════════════════════════════════════════
                    ⚠️ CRITICAL LEGAL WARNING ⚠️
═══════════════════════════════════════════════════════════════

The tools and techniques in this directory govern the physical transmission
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

---

### Warranty Disclaimer

```
═══════════════════════════════════════════════════════════════
                    ⚠️ DISCLAIMER OF WARRANTIES ⚠️
═══════════════════════════════════════════════════════════════

These RF tools and SDR flowgraphs are provided "AS IS" WITHOUT WARRANTY 
of any kind, either expressed or implied.

THE AUTHORS, CONTRIBUTORS, AND MAINTAINERS:

✗ Make NO guarantees about script functionality or RF safety
✗ Are NOT responsible for damaged hardware (e.g., burnt out SDR amplifiers)
✗ Do NOT warrant compliance with FCC or international RF emission laws
✗ Are NOT liable for any legal consequences of misuse
✗ Do NOT provide support for illegal activities
✗ Disclaim ALL liability for unauthorized transmission or interception

USERS EXPLICITLY ACKNOWLEDGE AND AGREE:

► They use these SDR techniques entirely at their own risk
► They are solely responsible for ensuring RF containment and compliance
► They understand that transmitting signals can interfere with critical infrastructure
► They accept that unauthorized use is a FEDERAL CRIME
► They will defend and indemnify authors from any claims

═══════════════════════════════════════════════════════════════
```

---

## 🤝 Contributing

### Contributing SDR Scripts & Flowgraphs

We welcome contributions from RF researchers and security professionals, but all materials must prioritize safety and legality.

**What We Accept:**
- ✅ GNU Radio flowgraphs for DSP education
- ✅ Receive-only (Rx) Python decoding scripts
- ✅ Telemetry parsers for public, unencrypted protocols (Weather, ISM)
- ✅ Hardware modification documentation (filters, antennas)

**🚫 Will NOT Accept:**
- Ready-to-use jamming scripts or flowgraphs
- Malicious IMSI catcher/Stingray deployments
- Scripts containing hardcoded cellular or aviation frequencies for Tx
- Tools designed specifically to steal vehicles

---

## 📚 Resources

### Licensing & Legal

- **FCC Part 15 Rules**: [Understanding Unlicensed RF](https://www.fcc.gov/oet/ea/rfdevice)
- **ARRL**: [Get your Amateur Radio (HAM) License](http://www.arrl.org/getting-licensed) (Highly recommended for SDR practitioners)

### Learning SDR

- **Great Scott Gadgets SDR Course**: [HackRF Lessons](https://greatscottgadgets.com/sdr/)
- **GNU Radio Tutorials**: [Guided Tutorials](https://wiki.gnuradio.org/index.php/Guided_Tutorials)
- **RTL-SDR Blog**: [rtl-sdr.com](https://www.rtl-sdr.com/)
- **SigIDWiki**: [Signal Identification Guide](https://www.sigidwiki.com/) (The Wikipedia of waterfall waterfalls and audio samples)

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
📁 SDR Categories: 3 (Capture, Analysis, Exploitation)
📻 Target Hardware: RTL-SDR, HackRF, LimeSDR, Flipper Zero
💻 Ecosystems: GNU Radio, Python, C++
⚠️ Risk Level: HIGH to EXTREME (Transmission capabilities)
🔄 Last Updated: June 2026
👥 Maintained by: Pacific Northwest Computers (PNWC)
📝 Status: Active - Proceed with EXTREME CAUTION
```

---

<div align="center">

**⚠️ USE THESE SDR TOOLS RESPONSIBLY AND LEGALLY ⚠️**

*The airwaves are public, but transmitting on them is a privilege regulated by law.*

**Repository**: [ULTIMATE CYBERSECURITY MASTER GUIDE](https://github.com/Pnwcomputers/ULTIMATE-CYBERSECURITY-MASTER-GUIDE)

**Maintained by**: [Pacific Northwest Computers](https://github.com/Pnwcomputers)

---

## Related Files
- [sdr.md](sdr.md) — Foundational SDR guide: GNU Radio, hardware, signal analysis, Wi-Fi/BT/cellular/GPS
- [sdr_hacking.md](sdr_hacking.md) — Advanced SDR hacking: SIGINT, protocol reversing, LoRa, TEMPEST, baseband exploitation
- [../Documentation/bruce_firmware.md](../Documentation/bruce_firmware.md) — Bruce firmware: sub-GHz CC1101 operations that complement full-spectrum SDR analysis
- [../Documentation/flipper_zero_guide.md](../Documentation/flipper_zero_guide.md) — Flipper Zero: sub-GHz replay attacks whose signals SDR can capture and analyze
- [../SpaceSecurity/](../SpaceSecurity/) — Space security: satellite communication analysis and GPS spoofing detection — an SDR application

---

🔴 **RADIO TRANSMISSION IS FEDERALLY REGULATED** 🔴

🔴 **UNAUTHORIZED TRANSMISSION = FEDERAL OFFENSE** 🔴

🔴 **NEVER INTERFERE WITH AVIATION OR EMERGENCY SERVICES** 🔴

🔴 **PROPER ISOLATION (DUMMY LOADS/FARADAY) MANDATORY** 🔴

---

⭐ **Star this repo if you find it useful (and use it legally!)** ⭐

</div>
