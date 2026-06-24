# 🛰️ Space Security

<div align="center">

**Offensive and defensive security across ground, space, and user segments of modern space systems**

*Part of the [ULTIMATE CYBERSECURITY MASTER GUIDE](../README.md)*

[![Ground Segment](https://img.shields.io/badge/Ground-Mission_Control_%7C_TT%26C-blue?style=for-the-badge)]()
[![Space Segment](https://img.shields.io/badge/Space-FSW_%7C_OBC_%7C_RTOS-red?style=for-the-badge)]()
[![User Segment](https://img.shields.io/badge/User-SATCOM_%7C_GNSS_%7C_VSAT-green?style=for-the-badge)]()
[![RF](https://img.shields.io/badge/RF-SDR_%7C_CCSDS_%7C_DVB--S2-orange?style=for-the-badge)]()

</div>

---

## 📋 Table of Contents

- [Overview](#overview)
- [Section Guides](#section-guides)
- [Space System Segments](#space-system-segments)
- [Why Space Security Matters Now](#why-space-security-matters-now)
- [Threat Landscape Summary](#threat-landscape-summary)
- [Tools Reference](#tools-reference)
- [Security & Legal Disclaimer](#security--legal-disclaimer)
- [Resources](#resources)

---

## 🎯 Overview

Space systems underpin critical infrastructure worldwide — from GPS-enabled financial trading to military communications to commercial aviation. Yet most operational satellites were designed before modern cybersecurity practices existed, and the expanding commercial space sector has introduced a rapidly growing attack surface across orbital altitudes, radio frequencies, ground infrastructure, and end-user hardware.

This section provides a **comprehensive security reference** covering the entire space domain, organized by segment.

**What You'll Find Here:**
- 📡 Ground segment penetration testing — mission control, TT&C uplink chains, ground station networks
- 🛰️ Space segment security — flight software vulnerabilities, RTOS exploitation, command injection
- 📺 User segment attacks — SATCOM terminal hacking, GNSS spoofing and jamming, VSAT modem analysis
- 📻 RF link analysis — CCSDS protocol dissection, signal interception, passive reconnaissance
- 🔐 Hardening strategies — command authentication, encryption, network segmentation, defense-in-depth
- 📊 Historical incident analysis — Viasat KA-SAT wiper attack, Turla satellite C2, GNSS spoofing campaigns
- 🧪 Testing methodology — legal frameworks, assessment approaches, lab setup for space security research

### Purpose

These materials serve as:
- **Attack surface reference** for authorized space system security assessments
- **Methodology guide** for ground, space, and user segment penetration testing
- **Threat intelligence** on nation-state and criminal targeting of space infrastructure
- **Hardening playbook** for satellite operators, ground system administrators, and SATCOM users
- **Training material** for red/blue teams operating in the space domain
- **Research resource** for CubeSat security, GNSS integrity, and SATCOM terminal analysis

---

## 📂 Section Guides

| Guide | Segment | Description |
|-------|---------|-------------|
| **[PartI.md](./PartI.md)** | Foundations | Space security primer, threat landscape, threat actor categories, STRIDE modeling for space systems, security testing methodology, legal/regulatory framework, and tools overview |
| **[PartII.md](./PartII.md)** | Ground | Ground-space communications, link architecture, frequency bands, CCSDS protocol stack, mission control system architecture, ground segment exploitation, protocol fuzzing, network penetration paths, and hardening controls |
| **[PartIII.md](./PartIII.md)** | Space | Spacecraft software architecture, RTOS platforms (VxWorks, RTEMS, FreeRTOS), flight software vulnerabilities, software upload security, spacecraft hacking scenarios, CubeSat security research, and space segment hardening |
| **[PartIV.md](./PartIV.md)** | User | SATCOM terminal architecture, terminal firmware analysis, VSAT attack surface, GNSS overview and signal weaknesses, jamming and spoofing techniques, real-world GNSS attacks, countermeasures, and industry/regulatory appendices |
| **[Appendices.md](./Appendices.md)** | Reference |  Repo sub-section topic appendices |

### Reading Order

```
New to space security?
  └─> Start with Part I (Foundations) for terminology, threat landscape, and methodology
  └─> Then Part II (Ground) — most attacks originate here
  └─> Then Part IV (User) — highest practical applicability for pentesters
  └─> Then Part III (Space) — advanced/research context

Experienced practitioner?
  └─> Jump directly to the segment relevant to your engagement
  └─> Part II for ground system / mission control assessments
  └─> Part IV for SATCOM terminal testing or GNSS security
  └─> Part III for spacecraft FSW analysis or CubeSat research
```

---

## 🌍 Space System Segments

Every space system consists of three interdependent segments. A compromise of any one segment can cascade across the others.

| Segment | Description | Key Attack Surface | Primary Risk |
|---------|-------------|-------------------|-------------|
| **Ground** | Earth-based infrastructure that commands and controls spacecraft | Mission control systems, TT&C uplink, ground station networks, VPN/remote access | IT/OT lateral movement → command injection |
| **Space** | Spacecraft and payloads in orbit | Onboard computer, flight software, RTOS, communication subsystems | FSW exploitation, malicious uploads |
| **User** | End-user equipment receiving satellite services | SATCOM terminals, GNSS receivers, VSAT modems | Firmware exploitation, GNSS spoofing/jamming |

### Segment Interdependency

```
         ┌─────────────┐
         │   GROUND     │  Mission control, ground stations
         │   SEGMENT    │  TT&C uplink/downlink
         └──────┬───────┘
                │
    Commands ───┤──── Telemetry
                │
         ┌──────┴───────┐
         │    SPACE      │  Satellites, CubeSats
         │   SEGMENT     │  FSW, OBC, payloads
         └──────┬───────┘
                │
   Service ─────┤──── Data
                │
         ┌──────┴───────┐
         │    USER       │  SATCOM terminals, GNSS receivers
         │   SEGMENT     │  VSAT modems, timing systems
         └──────────────┘
```

**Key insight from the Viasat KA-SAT attack (2022):** Attackers compromised the ground segment management plane → issued legitimate provisioning commands → deployed the AcidRain wiper to ~50,000 user terminals across Europe. Ground segment access = mass user segment impact.

---

## 🔴 Why Space Security Matters Now

- **Proliferated LEO constellations** (Starlink, OneWeb, Kuiper) serve millions of users and carry critical infrastructure traffic
- **GNSS is everywhere** — financial systems, power grids, cellular networks, aviation, maritime, and autonomous vehicles all depend on GPS/Galileo/GLONASS timing and positioning
- **Military dependence on commercial SATCOM** — DoD and allied forces rely heavily on commercial satellite communications for operations
- **Nation-state ASAT programs** — Russia, China, Iran, and North Korea actively develop kinetic and cyber capabilities targeting space systems
- **Legacy design** — Most operational GEO satellites were designed and launched before modern cybersecurity practices existed; many lack basic command authentication
- **Expanding attack surface** — CubeSats with open-source FSW, COTS components, and publicly documented protocols lower the barrier for security research and adversarial activity

---

## ⚡ Threat Landscape Summary

| Actor Type | Motivation | Capability | Historical Example |
|------------|-----------|-----------|-------------------|
| **Nation-state** | Strategic advantage, disruption, espionage | Kinetic ASAT, RF jamming/spoofing, cyber intrusion | GRU — Viasat KA-SAT wiper (2022) |
| **Criminal** | Financial gain | Ground segment ransomware, data theft | Ransomware on satellite ground ops |
| **Hacktivist** | Political messaging | Low-level jamming, signal hijacking | Signal hijacking incidents |
| **Researcher** | Disclosure, learning | Variable — CTF, lab research | DEFCON Aerospace Village, Hack-A-Sat |
| **Insider** | Sabotage, espionage | High — privileged access to command systems | Undetected until damage occurs |

### Key Historical Incidents

| Year | Incident | Impact |
|------|---------|--------|
| 2007–2008 | NASA/USGS satellite interference (China alleged) | Multiple TT&C intrusions on ground systems |
| 2018 | Turla (Snake) APT — satellite internet C2 | Covert exfiltration via hijacked satellite links |
| 2022 | Viasat KA-SAT cyberattack (Sandworm) | ~50,000 VSAT modems bricked across Europe |
| 2022–present | GNSS jamming/spoofing in Ukraine/Eastern Europe | Aviation GPS outages, maritime position errors |

---

## 🔧 Tools Reference

### SDR and RF Analysis

| Tool | Purpose | Notes |
|------|---------|-------|
| [**GNU Radio**](https://www.gnuradio.org/) | SDR signal processing framework | Core platform for all RF analysis |
| [**SDR#**](https://airspy.com/download/) / [**GQRX**](https://www.gqrx.dk/) / [**SDR++**](https://github.com/AlexandreRouworworma/SDRPlusPlus) | SDR receiver GUI | Spectrum monitoring and visualization |
| [**gr-satellites**](https://github.com/daniestevez/gr-satellites) | Satellite signal decoder | Supports dozens of amateur/CubeSat formats |
| [**SatDump**](https://github.com/SatDump/SatDump) | Satellite data decoder | NOAA, Meteor, MetOp weather satellites |
| [**HackRF One**](https://greatscottgadgets.com/hackrf/one/) | Full-duplex SDR (1 MHz – 6 GHz) | TX capability — authorized lab use only |
| [**USRP B210**](https://www.ettus.com/all-products/ub210-kit/) | High-performance SDR (70 MHz – 6 GHz) | Research-grade wideband analysis |
| [**RTL-SDR**](https://www.rtl-sdr.com/) | Receive-only SDR (500 kHz – 1.75 GHz) | Passive monitoring, entry-level |

### Ground System and Network

| Tool | Purpose | Notes |
|------|---------|-------|
| [**Wireshark**](https://www.wireshark.org/) | Ground network traffic analysis | Custom CCSDS dissectors available |
| [**COSMOS**](https://github.com/OpenC3/cosmos) | Open-source mission control framework | FSW testing and simulation |
| [**Shodan**](https://www.shodan.io/) / [**Censys**](https://search.censys.io/) | Internet-exposed ground system discovery | Search for exposed MCS interfaces |
| [**boofuzz**](https://github.com/jtpereyda/boofuzz) | Protocol fuzzing | Target CCSDS parsers and ground APIs |

### GNSS Research

| Tool | Purpose | Notes |
|------|---------|-------|
| [**GPS-SDR-SIM**](https://github.com/osqzss/gps-sdr-sim) | GPS L1 C/A signal simulator | TX requires HackRF — shielded enclosure only |
| [**GNSS-SDRLIB**](https://github.com/taroz/GNSS-SDRLIB) | Multi-constellation SDR receiver/generator | Research use |
| [**Spirent GSS7000**](https://www.spirent.com/products/gnss-simulator-gss7000) | Commercial GNSS simulator | Professional lab testing |

### Firmware Analysis

| Tool | Purpose | Notes |
|------|---------|-------|
| [**binwalk**](https://github.com/ReFirmLabs/binwalk) | Firmware extraction | Standard first step for terminal analysis |
| [**QEMU**](https://www.qemu.org/) | Firmware emulation | Dynamic analysis of extracted binaries |
| [**Ghidra**](https://ghidra-sre.org/) / [**IDA**](https://hex-rays.com/ida-pro/) | Reverse engineering | Static analysis of FSW and terminal firmware |

---

## ⚠️ Security & Legal Disclaimer

### 🔴 CRITICAL: Authorized Use Only

```
⚠️ LEGAL AND ETHICAL USE ONLY ⚠️

This section contains attack techniques targeting space systems infrastructure.

✅ AUTHORIZED USES:
   • Security assessments with written authorization from spacecraft operators
   • Red team operations with organizational approval
   • Academic research in shielded RF enclosures or simulation environments
   • Blue team training and detection development
   • CTF competitions (DEFCON Aerospace Village, Hack-A-Sat)
   • Passive RF monitoring within legal boundaries
   • Educational study and professional development

🚫 STRICTLY PROHIBITED:
   • Transmitting RF signals toward operational satellites without authorization
   • Unauthorized access to ground station or mission control systems
   • GNSS jamming or spoofing outside shielded test environments
   • Intercepting protected satellite communications
   • Any activity violating CFAA, FCC regulations, ITAR/EAR, or ITU rules
   • Causing disruption to satellite services or critical infrastructure
   • Any illegal or unethical activities
```

### Applicable Laws and Regulations

| Law / Regulation | Scope |
|-----------------|-------|
| **CFAA (18 U.S.C. § 1030)** | Unauthorized access to satellite ground systems — up to 10 years imprisonment |
| **FCC Part 25/97** | Unauthorized transmission on licensed satellite frequencies — criminal offense |
| **ITAR (22 CFR 120-130)** | Export control on satellite technology, tools, and techniques |
| **EAR (15 CFR 730-774)** | Additional export controls on dual-use space technology |
| **ITU Radio Regulations** | International frequency coordination and harmful interference prohibition |
| **UK Computer Misuse Act 1990** | Unauthorized access to space-related computer systems |
| **EU Cybercrime Directives** | Harmonized computer crime laws covering ground infrastructure |

### Warranty Disclaimer

```
These materials are provided "AS IS" without warranty of any kind.

THE AUTHORS AND CONTRIBUTORS:
• Make no guarantees about technique effectiveness or accuracy
• Are not responsible for damages from unauthorized use
• Are not liable for legal consequences of misuse
• Disclaim all liability for disruption to space systems or services
• May update content without notice

USERS EXPLICITLY ACKNOWLEDGE:
• Space system attacks can disrupt critical infrastructure affecting public safety
• RF transmission without authorization is a federal crime
• ITAR/EAR export controls may apply to tools and techniques described herein
• They accept all risks associated with using these attack methodologies
• Authorization must be explicit, written, and from the spacecraft operator
```

---

## 📚 Resources

### Standards and Guidance

| Resource | Description |
|----------|-------------|
| CCSDS 350.0-G-3 | *The Application of Security to CCSDS Protocols* |
| CCSDS 351.0-M-1 | *Security Architecture for Space Data Systems* |
| NIST SP 800-53 Rev 5 | Control families applicable to space (SA, SI, SC, AU) |
| NIST IR 8270 | *An Overview of Cybersecurity for Commercial Satellite Operations* |
| CISA Guidance | *Space Systems Critical Infrastructure Security and Resilience* |
| Aerospace Corp | *Defending Space Systems from Cyber Threats* |

### Research and Competitions

| Resource | Description |
|----------|-------------|
| [Hack-A-Sat](https://hackasat.com/) | Annual CTF run by US Space Force / Air Force |
| [DEF CON Aerospace Village](https://aerospacevillage.org/) | Aerospace security community and talks |
| [IOActive — SATCOM Security](https://ioactive.com/resources/white-papers/) | Pre-auth RCE research across major SATCOM vendors (2014, 2020) |
| [Black Hat 2020 — Ruben Santamarta](https://www.blackhat.com/us-20/briefings/schedule/#a-decade-after-stuxnet-satcom-is-still-broken-20511) | Revisited SATCOM vulnerabilities; aviation implications |
| [DEFCON 30 (2022) — Starlink](https://www.youtube.com/watch?v=UJgnFSsV2bY) | Physical fault injection; custom firmware execution |

### Online Resources

| Resource | URL |
|----------|-----|
| MITRE ATT&CK for ICS | [https://attack.mitre.org/matrices/ics/](https://attack.mitre.org/matrices/ics/) |
| SatNOGS Network | [https://network.satnogs.org/](https://network.satnogs.org/) |
| Space-Track.org | [https://www.space-track.org/](https://www.space-track.org/) |
| AMSAT | [https://www.amsat.org/](https://www.amsat.org/) |
| CCSDS Publications | [https://public.ccsds.org/Publications/default.aspx](https://public.ccsds.org/Publications/default.aspx) |
| FCC ULS License Search | [https://wireless2.fcc.gov/UlsApp/UlsSearch/searchLicense.jsp](https://wireless2.fcc.gov/UlsApp/UlsSearch/searchLicense.jsp) |

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

### External Resources
- [MITRE ATT&CK](https://attack.mitre.org/)
- [CCSDS Publications](https://public.ccsds.org/Publications/default.aspx)
- [DEF CON Aerospace Village](https://aerospacevillage.org/)
- [Hack-A-Sat](https://hackasat.com/)
- [SatNOGS](https://network.satnogs.org/)

---

## 📊 Repository Statistics

```
📁 Sections: 4 (Foundations, Ground Segment, Space Segment, User Segment)
📖 Chapters: 11 + 2 Appendices
🔄 Last Updated: June 2026
👥 Maintained by: Pacific Northwest Computers (PNWC)
📝 Status: Active & Growing
```

---

<div align="center">

**📖 Use These Techniques Responsibly: Authorization is MANDATORY**

*Space systems are critical infrastructure — treat them accordingly.*

**Repository**: [ULTIMATE CYBERSECURITY MASTER GUIDE](https://github.com/Pnwcomputers/ULTIMATE-CYBERSECURITY-MASTER-GUIDE)

**Maintained by**: [Pacific Northwest Computers](https://github.com/Pnwcomputers)

---

⚠️ **RF transmission toward satellites requires EXPLICIT WRITTEN AUTHORIZATION** ⚠️

⚠️ **Unauthorized access to space systems is a FEDERAL CRIME under the CFAA** ⚠️

⚠️ **ITAR/EAR export controls may apply to satellite security tools and techniques** ⚠️

⭐ **Star this repo if you find it useful!** ⭐

</div>
