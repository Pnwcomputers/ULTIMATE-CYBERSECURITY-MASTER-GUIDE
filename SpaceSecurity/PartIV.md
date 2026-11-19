# 📺 Part IV: The User Segment

## 🎯 Purpose
User segment attack guide - covering SATCOM terminal vulnerabilities (Viasat KA-SAT style attacks), GNSS spoofing and jamming, VSAT security assessments, and maritime/aviation satellite terminal exploitation.

## ⚙️ Function
Covers: ODU/IDU terminal architecture, Ku/Ka-band link exploitation, modem firmware extraction and analysis, GNSS spoofing mechanics (civilian GPS L1 C/A is unencrypted), VSAT terminal default credentials and web interface vulnerabilities, and the regulatory landscape for GNSS interference.

## 🏆 Goal
Assess the security of satellite user terminals - the most accessible segment of a space system from an attacker's perspective - identifying credential exposure, firmware vulnerabilities, and GNSS signal integrity weaknesses.

## 📋 When to Use
- Security assessment of a maritime, aviation, or enterprise SATCOM installation
- GNSS spoofing resilience testing in an authorized lab environment
- Understanding how the 2022 Viasat attack worked and how to defend against it
- CubeSat ground terminal security review

## Chapter 10: Attacking SATCOM Terminals

#### Terminal Architecture

```
Satellite
    │
  [RF Link]
    │
Outdoor Unit (ODU)
  ├─ Low-Noise Block Downconverter (LNB)
  └─ Block Upconverter (BUC) [for TX]
    │
  Coax / ODU-IDU cable
    │
Indoor Unit (IDU) / Modem
  ├─ IP gateway / router
  ├─ Management interface (web UI, SNMP, TR-069)
  └─ LAN port → user devices
```

#### Attack Surface

| Component | Attack Vector | Notes |
|-----------|--------------|-------|
| **Web management UI** | Default credentials, authentication bypass, command injection | Common on VSAT modems |
| **SNMP** | SNMPv1/v2c with public community string | Often exposes full config and stats |
| **TR-069 / CWMP** | ACS server compromise → mass terminal takeover | Provisioning protocol; used in Viasat attack |
| **Firmware** | Extraction → analysis → custom image | UART, JTAG, or update file extraction |
| **RF uplink** | Jamming, signal capture | Physical proximity required |
| **Over-the-air updates** | Unsigned firmware delivery | If OTA updates lack integrity checks |

#### Terminal Firmware Analysis

```bash
# Extract firmware from update file or NAND dump
binwalk -e firmware.bin

# Identify architecture and entry point
file rootfs/bin/busybox
strings rootfs/bin/satellite_daemon | grep -E "(password|key|token|secret)"

# Emulate with QEMU for dynamic analysis
qemu-mips-static -L rootfs/ rootfs/bin/satellite_daemon

# Check for hardcoded credentials
grep -r "admin\|root\|password\|default" rootfs/etc/ --include="*.conf"
```

#### Known Vulnerability Classes in SATCOM Terminals

- **Hardcoded credentials** - Factory default admin accounts that cannot be changed (documented in multiple Iridium, Hughes, ViaSat, and Intellian advisories)
- **Pre-auth RCE** - Command injection in web UI before authentication (multiple CVEs across major vendors 2020–2024)
- **Unencrypted management** - HTTP instead of HTTPS; Telnet instead of SSH
- **Insecure firmware updates** - No signature verification on update packages
- **Debug interfaces** - UART/JTAG left exposed in production hardware

#### Notable Research

| Research | Findings |
|----------|---------|
| IOActive - SATCOM Security (2014) | Pre-auth RCE in Iridium, BGAN, Hughes, ViaSat terminals |
| Black Hat 2020 - Ruben Santamarta | Revisited SATCOM vulnerabilities; aviation safety implications |
| DEFCON 30 (2022) - Starlink | Physical fault injection on Starlink dish; custom firmware execution |

---

### Chapter 11: Exploiting Global Navigation Satellite Systems

#### GNSS Overview

| System | Operator | Frequencies |
|--------|----------|------------|
| GPS | USA (Space Force) | L1 (1575.42 MHz), L2 (1227.60 MHz), L5 (1176.45 MHz) |
| GLONASS | Russia | L1 (~1602 MHz), L2 (~1246 MHz) |
| Galileo | EU | E1 (1575.42 MHz), E5 (1176.45 / 1207.14 MHz) |
| BeiDou | China | B1 (1561.098 MHz), B2, B3 |
| NavIC | India | L5, S-band |

#### Signal Characteristics and Weaknesses

GNSS signals arrive at Earth's surface at approximately **-130 dBm** - roughly 20 dB below thermal noise. This extreme weakness makes them trivially susceptible to interference:

- **Open signals and authentication** - GPS L1 C/A is an open civilian signal. Galileo's E1-B navigation message can carry OSNMA authentication data: the Initial Service became operational on July 24, 2025. OSNMA requires a compatible receiver implementation and authenticates navigation-message data; it does not by itself authenticate ranging measurements or guarantee the final position/time solution.
- **Passive reception** - A receiver cannot challenge a satellite over the navigation signal, but lack of an uplink does not rule out broadcast-message authentication such as OSNMA.
- **Public signal structure** - PRN codes and navigation-message formats are public; authentication and encryption are separate properties.

#### Attack Types

**Jamming**

Broadband noise or CW interference on GNSS frequencies. Low technical barrier - cheap jammers widely available (though illegal in most jurisdictions).

- Effective range: meters to kilometers depending on power
- Impact: loss of PNT - navigation, timing systems fail
- Detection: Receiver-specific AGC and carrier-to-noise ratio (C/N₀) changes can flag possible interference. Establish a receiver/band baseline and corroborate across independent sources; these indicators do not identify every jammer or attack.
- Countermeasures: Antenna nulling (CRPA), inertial navigation fallback, multi-frequency receivers

**Spoofing**

Transmitting counterfeit GNSS signals that a receiver accepts as legitimate, causing false position/time output. Technically more complex than jamming.

```
Spoofer generates:
  └─> Valid PRN codes for visible satellites
  └─> Accurate navigation message (ephemeris, almanac)
  └─> Correct Doppler shift for claimed position/velocity
  └─> Higher power than authentic signal

Receiver accepts spoofed signal → reports false position/time
```

Spoofing attack progression:

1. **Meaconing** - Simply re-broadcast authentic signals (introduces delay = false position)
2. **Simple spoofing** - Static false position, no correlation with authentic signal timing
3. **Sophisticated spoofing** - Gradually drag receiver position; preserves carrier phase continuity to avoid detection

**Spoofing Tools (Research Context)**

| Tool | Description |
|------|-------------|
| **GPS-SDR-SIM** | Open-source GPS L1 C/A signal simulator (TX requires HackRF or USRP) |
| **GNSS-SDRLIB** | Multi-constellation SDR receiver and signal generator |
| **Spirent GSS7000** | Commercial GNSS simulator (lab use) |

> **⚠️ Legal and safety warning:** GNSS spoofing or other transmissions may violate spectrum, aviation-safety, and other laws or rules; requirements depend on jurisdiction, service, equipment, and conduct. Do not transmit counterfeit navigation signals over the air. A shielded enclosure can reduce emissions but does not by itself establish legal authorization or compliance. Use an approved simulator or conducted setup under an authorized lab plan.

#### Real-World GNSS Attacks

| Incident | Year | Method | Impact |
|----------|------|--------|--------|
| Russian Black Sea spoofing | 2017–ongoing | Large-scale GPS spoofing | Dozens of ships reported false positions in Moscow |
| Tehran GPS spoofing (RQ-170 capture) | 2011 | Alleged GPS spoof | US drone landed in Iran (disputed) |
| Contested GPS jamming - Ukraine/Eastern Europe | 2022–present | Broadband L1/L2 jamming | Aviation GPS outages across Eastern Europe |
| Dallas ADS-B GPS disruption | 2022 | Ground-based interference | FAA NOTAM; flight delays |

#### GNSS Security Countermeasures

| Countermeasure | Description |
|----------------|-------------|
| **Galileo OSNMA** | Operational service authenticates E1-B navigation-message data on compatible receivers; it does not by itself authenticate ranging measurements or guarantee a position solution |
| **GPS civilian signal authentication research** | Chips-Message Robust Authentication (Chimera) is a research concept combining navigation-data and spreading-code authentication; do not infer operational deployment from the 2017 paper |
| **Multi-constellation / multi-frequency** | Adds signal diversity, but is not proof of authenticity |
| **Receiver Autonomous Integrity Monitoring (RAIM)** | Provides receiver integrity checks, but is only partially effective against some misleading signals; no alert does not prove signal authenticity |
| **Signal strength / AGC / C/N₀ monitoring** | Receiver- and band-specific changes can indicate interference; baseline and corroboration are required, and detection is incomplete |
| **IMU integration** | Inertial cross-checks can reveal some PVT inconsistencies; performance depends on the sensor and error growth |
| **Clock anomaly detection** | Time disagreements can be a clue; corroborate with independently trusted time because network time may also be wrong or spoofed |

![GNSS position solution sources and the different coverage limits of OSNMA, RAIM, AGC/CN0 monitoring, and independent sensor checks](../assets/diagrams/gnss-authentication-and-integrity-boundaries.svg)

*Conceptual coverage map. OSNMA authenticates Galileo navigation-message data on E1-B; RAIM checks consistency; AGC/C/N₀ are receiver-specific interference indicators. No single check proves that the complete navigation solution is authentic.*

Sources: [Galileo OSNMA service description](https://www.gsc-europa.eu/galileo/services/galileo-open-service-navigation-message-authentication-osnma), [OSNMA Service Definition Document](https://www.gsc-europa.eu/sites/default/files/sites/all/files/Galileo-OSNMA-SDD_v1.0.pdf), [Android GNSS spoof/jam detection limits](https://developer.android.com/develop/sensors-and-location/sensors/gnss-spoof-jam), [FAA RAIM advisory](https://www.faa.gov/air_traffic/publications/atpubs/aip_html/part2_enr_section_4.1.html), and [Chimera research paper](https://www.ion.org/publications/abstract.cfm?articleID=15206).

---

## 🏢 Appendix A: The Space Sector

### Industry Overview

| Sector | Key Players | Security Relevance |
|--------|------------|-------------------|
| **Commercial FSS/MSS** | Intelsat, SES, Viasat, Hughes, Inmarsat | Large attack surface; widely used for critical comms |
| **Proliferated LEO** | SpaceX Starlink, Amazon Kuiper, OneWeb | Massive scale; new security models; high-value target |
| **Earth Observation** | Maxar, Planet, Airbus Defence | Intelligence value; imagery manipulation risk |
| **Launch Services** | SpaceX, ULA, Arianespace, Rocket Lab | Supply chain; ground systems |
| **Defense** | Northrop Grumman, L3Harris, Boeing Defense | High-assurance requirements; ITAR-controlled |
| **New Space / CubeSat** | Various; Spire, Swarm, Astro Digital | COTS hardware; limited security; growing attack surface |

### Regulatory and Standards Bodies

| Organization | Role |
|-------------|------|
| **ITU** | International frequency coordination and interference management |
| **FCC** | US licensing for earth stations, satellites, terminals |
| **FAA** | Aviation use of GNSS and SATCOM |
| **NIST** | SP 800-53 controls applicable to federal space systems |
| **CCSDS** | Protocol standards (also security recommendations - CCSDS 350.x series) |
| **CISA** | Space Systems Critical Infrastructure guidance |
| **DoD / NSA** | COMSEC requirements for national security space |

---

## 🔧 Appendix B: Space Systems

### Reference Architectures

#### LEO Smallsat / CubeSat

```
┌───────────────────────────────┐
│         Solar Panels           │
│  ┌─────────────────────────┐  │
│  │    OBC (ARM/LEON/AVR)   │  │
│  │  FSW (RTEMS/FreeRTOS)   │  │
│  ├─────────────────────────┤  │
│  │ ADCS  │ EPS  │ Thermal  │  │
│  ├─────────────────────────┤  │
│  │   Communications        │  │
│  │  UHF TT&C │ S/X payload │  │
│  └─────────────────────────┘  │
└───────────────────────────────┘
```

#### GEO Communications Satellite

```
┌─────────────────────────────────────┐
│          Solar Arrays               │
│  ┌───────────────────────────────┐  │
│  │     Platform / Bus            │  │
│  │  OBC │ AOCS │ Power │ Thermal │  │
│  ├───────────────────────────────┤  │
│  │         Payload               │  │
│  │  Transponders │ Antennas      │  │
│  │  (C/Ku/Ka-band, military X)   │  │
│  └───────────────────────────────┘  │
└─────────────────────────────────────┘
```

### Key Protocols Reference

| Protocol | Layer | Use | Security Notes |
|----------|-------|-----|---------------|
| CCSDS TM | Data Link | Telemetry framing | Often unencrypted; ASM sync trivially identified |
| CCSDS TC | Data Link | Command framing | Authentication optional per CCSDS 351.0 |
| CCSDS Space Packet | Network | Packet routing | APID-based routing; no inherent authentication |
| CCSDS CFDP | Transport | File delivery | Class 2 provides acknowledged delivery; no encryption |
| DVB-S2/S2X | Physical | Broadcast downlink | Conditional access systems (CAS) for pay-TV |
| AX.25 | Data Link | Amateur/CubeSat TT&C | No authentication; widely used in educational sats |
| IP over SATCOM | Network | Broadband terminals | Standard IP vulnerabilities apply |

### SDR Hardware Reference

| Device | Freq Range | TX | Typical Use |
|--------|-----------|-----|------------|
| RTL-SDR | 500 kHz – 1.75 GHz | No | Passive monitoring, GNSS monitoring |
| HackRF One | 1 MHz – 6 GHz | Yes | Full analysis; lab TX |
| USRP B210 | 70 MHz – 6 GHz | Yes | Research-grade wideband |
| Airspy HF+ | 9 kHz – 31 MHz / 60–260 MHz | No | HF, VHF precision |
| LimeSDR | 100 kHz – 3.8 GHz | Yes | Flexible; multi-channel |

---

<div align="center">

**📖 Use These Techniques Responsibly: Authorization is MANDATORY**

## Related Files
- [README.md](README.md) - SpaceSecurity section index
- [PartI.md](PartI.md) - Foundations: threat actors and attack taxonomy for user segment threats
- [PartIII.md](PartIII.md) - Space segment: flight software vulnerabilities
- [../SDR/sdr_hacking.md](../SDR/sdr_hacking.md) - SDR hacking: GPS spoofing and SATCOM signal analysis tools and techniques

*Space systems are critical infrastructure - treat them accordingly.*

**Repository**: [ULTIMATE CYBERSECURITY MASTER GUIDE](https://github.com/Pnwcomputers/ULTIMATE-CYBERSECURITY-MASTER-GUIDE)

**Maintained by**: [Pacific Northwest Computers](https://github.com/Pnwcomputers)

---

⚠️ **RF transmission toward satellites requires EXPLICIT WRITTEN AUTHORIZATION** ⚠️

⚠️ **Unauthorized access or transmission may violate applicable law and service rules; requirements depend on the system, spectrum, conduct, and jurisdiction; see [FCC Part 15](https://www.ecfr.gov/current/title-47/chapter-I/subchapter-A/part-15) and service-specific rules such as [47 CFR § 25.115](https://www.ecfr.gov/current/title-47/section-25.115).** ⚠️

⚠️ **ITAR/EAR export controls may apply to satellite security tools and techniques** ⚠️

⭐ **Star this repo if you find it useful!** ⭐

</div>
