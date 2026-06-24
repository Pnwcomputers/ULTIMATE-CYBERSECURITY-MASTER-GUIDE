# 🌍 Part I: Foundations of Space Security

## Chapter 1: A Space Security Primer

#### Space System Segments

Space systems are no longer the exclusive domain of nation-states. Commercial off-the-shelf (COTS) hardware, open-source software stacks, and accessible launch services have lowered barriers dramatically. The result is a diverse and rapidly expanding attack surface spanning orbital altitudes, radio frequencies, ground infrastructure, and end-user hardware.

| Segment | Description | Examples |
|---------|-------------|---------|
| **Ground** | Earth-based infrastructure that commands and receives data from spacecraft | Mission control, ground stations, TT&C systems |
| **Space** | The spacecraft and payloads in orbit | Satellites, CubeSats, ISS modules |
| **User** | End-user equipment that receives satellite services | SATCOM terminals, GNSS receivers, VSATs |

Each segment presents distinct attack surfaces, but they are deeply interdependent — a compromise of any one segment can cascade across the others.

#### Key Terminology

| Term | Definition |
|------|-----------|
| **TT&C** | Telemetry, Tracking, and Command — the control link between ground and spacecraft |
| **LEOP** | Launch and Early Orbit Phase — highest-risk operational window |
| **GEO / MEO / LEO** | Geostationary / Medium Earth / Low Earth Orbit |
| **VSAT** | Very Small Aperture Terminal — compact satellite ground terminal |
| **Transponder** | Spacecraft payload that receives uplink and retransmits on downlink |
| **FHSS / DSSS** | Frequency-Hopping / Direct-Sequence Spread Spectrum — RF modulation schemes |
| **CCSDS** | Consultative Committee for Space Data Systems — dominant space protocol family |

#### Why Space Security Matters Now

- Proliferated LEO constellations (Starlink, OneWeb, Amazon Kuiper) have millions of users and critical infrastructure dependencies
- Military and government systems rely on commercial SATCOM for comms, ISR, and PNT
- GNSS is embedded in financial systems, power grids, cellular networks, and aviation
- Nation-state actors (Russia, China, Iran, North Korea) actively develop ASAT and cyber capabilities targeting space systems
- Most operational satellites were designed before modern cybersecurity practices existed

---

### Chapter 2: The Threat Landscape

#### Threat Actor Categories

| Actor Type | Motivation | Capabilities | Examples |
|------------|-----------|-------------|---------|
| Nation-state | Strategic advantage, disruption, espionage | High — kinetic ASAT, jamming, spoofing, cyber intrusion | GRU (Viasat KA-SAT attack, 2022), China (SC-19 ASAT) |
| Criminal / ransomware | Financial gain | Medium — targeting ground segment IT | Ransomware on satellite ground ops |
| Hacktivist | Political messaging | Low-Medium — jamming, defacement | Signal hijacking incidents |
| Researcher / red team | Disclosure, learning | Variable | DEFCON Aerospace Village CTFs |
| Insider threat | Sabotage, espionage | High (privileged access) | Undetected until damage occurs |

#### Attack Surface by Segment

**Ground Segment:**
- Mission control systems (often Windows-based IT/OT hybrid environments)
- Ground station software and hardware interfaces
- TT&C uplink chains
- Network connectivity between ground nodes
- Supply chain for ground hardware/software

**Space Segment:**
- Onboard computer (OBC) firmware
- Flight software (FSW) — often C/C++, sometimes Ada or SPARK
- Communication subsystems
- Attitude and Orbit Control System (AOCS)
- Power management systems

**User Segment:**
- SATCOM terminal firmware and management interfaces
- GNSS receivers and timing systems
- VSAT modems and network equipment
- RF uplink/downlink paths

#### Historical Incidents

| Year | Incident | Segment | Impact |
|------|---------|---------|--------|
| 1999 | UK MoD satellites commandeered (alleged) | Ground/Space | C2 disruption |
| 2007–2008 | NASA/USGS satellite interference (China alleged) | Ground | Multiple TT&C intrusions |
| 2014 | NOAA/NESDIS satellite ground system compromise | Ground | Network intrusion |
| 2018 | Turla (Snake) APT — satellite internet C2 channel | User | Covert C2 exfil |
| 2022 | Viasat KA-SAT cyberattack (Russia/Sandworm) | Ground/User | ~50,000 modems bricked across Europe |
| 2022 | Starlink jamming in Ukraine | User | Operational disruption |

#### Threat Modeling Space Systems

STRIDE adapted for space-specific contexts:

| STRIDE Category | Space System Example |
|-----------------|---------------------|
| **Spoofing** | Fake TT&C commands, GNSS signal spoofing |
| **Tampering** | FSW modification via uplink, ground system malware |
| **Repudiation** | Lack of command logging on legacy satellites |
| **Information Disclosure** | Unencrypted telemetry intercept |
| **Denial of Service** | RF jamming, uplink flooding, ground system ransomware |
| **Elevation of Privilege** | Command injection to gain unrestricted spacecraft access |

---

### Chapter 3: Security Testing

#### ⚠️ Legal and Regulatory Considerations

Space system security testing operates under strict legal constraints:

- **Radio Communications Act / FCC Part 97/25** — Unauthorized transmission on licensed frequencies is a federal crime
- **Computer Fraud and Abuse Act (CFAA)** — Unauthorized access to satellite ground systems
- **ITAR / EAR** — Export control restrictions apply to satellite technology and related tools
- **International Telecommunications Union (ITU)** — Frequency coordination and interference rules
- **DoD / CMMC** — Requirements for contractors testing defense space systems

> **⚠️ Legal Warning:** Never transmit RF signals toward an operational satellite without explicit written authorization from the spacecraft operator and applicable frequency coordinators. Even passive interception may have legal implications depending on jurisdiction and service type.

#### Testing Methodology

Space security assessments generally follow a segmented approach:

```
Reconnaissance
  └─> Passive RF collection (SDR monitoring, signal analysis)
  └─> OSINT on operator, ground station locations, frequencies
  └─> Protocol identification

Ground Segment Assessment
  └─> External network penetration testing
  └─> TT&C interface analysis (if in-scope)
  └─> Mission control application security review

RF / Link Layer Analysis
  └─> Signal capture and demodulation
  └─> Protocol reverse engineering
  └─> Encryption assessment

User Segment Testing
  └─> SATCOM terminal firmware analysis
  └─> Management interface exploitation
  └─> GNSS receiver spoofing/jamming assessment

Space Segment (Research/Lab Context)
  └─> Onboard software static analysis
  └─> Emulated FSW fuzzing
  └─> Hardware-in-the-loop testing
```

#### Tools Overview

| Tool | Purpose | Notes |
|------|---------|-------|
| **GNU Radio** | SDR signal processing framework | Core platform for RF analysis |
| **SDR# / GQRX** | SDR receiver GUI | Spectrum monitoring |
| **gr-satellites** | Satellite signal decoder | Supports dozens of amateur/CubeSat formats |
| **HackRF One** | Full-duplex SDR (1 MHz – 6 GHz) | TX capability — use only in authorized lab context |
| **USRP** | High-performance SDR platform | Research-grade signal work |
| **SatDump** | Satellite data decoder | NOAA, Meteor, MetOp, etc. |
| **Wireshark** | Ground network traffic analysis | With custom CCSDS dissectors |
| **COSMOS** | Open-source mission control framework | FSW testing and simulation |
| **OpenSatCom** | SATCOM protocol research toolkit | Academic/research use |

---

<div align="center">

**📖 Use These Techniques Responsibly: Authorization is MANDATORY**

*Space systems are critical infrastructure — treat them accordingly.*

**Repository**: [ULTIMATE CYBERSECURITY MASTER GUIDE](https://github.com/Pnwcomputers/ULTIMATE-CYBERSECURITY-MASTER-GUIDE)

**Maintained by**: [Pacific Northwest Computers](https://github.com/Pnwcomputers)

---

⚠️ **RF transmission toward satellites requires EXPLICIT WRITTEN AUTHORIZATION** ⚠️

⚠️ **Unauthorized access to space systems is a FEDERAL CRIME** ⚠️

⚠️ **ITAR/EAR export controls may apply to satellite security tools and techniques** ⚠️

⭐ **Star this repo if you find it useful!** ⭐

</div>
