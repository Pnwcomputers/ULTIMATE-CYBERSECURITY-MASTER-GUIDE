# Space Security

> **Scope:** Offensive and defensive security across the three segments of modern space systems — ground, space, and user. This section covers the threat landscape, attack surfaces, exploitation techniques, and hardening strategies for satellite communications, mission control infrastructure, spacecraft software, and GNSS.

---

## Table of Contents

- [Part I: Foundations of Space Security](#part-i-foundations-of-space-security)
  - [Chapter 1: A Space Security Primer](#chapter-1-a-space-security-primer)
  - [Chapter 2: The Threat Landscape](#chapter-2-the-threat-landscape)
  - [Chapter 3: Security Testing](#chapter-3-security-testing)
- [Part II: The Ground Segment](#part-ii-the-ground-segment)
  - [Chapter 4: Ground-Space Communications](#chapter-4-ground-space-communications)
  - [Chapter 5: Mission Control Systems](#chapter-5-mission-control-systems)
  - [Chapter 6: Exploiting Ground Segment Protocols](#chapter-6-exploiting-ground-segment-protocols)
  - [Chapter 7: Hacking Ground Systems](#chapter-7-hacking-ground-systems)
- [Part III: The Space Segment](#part-iii-the-space-segment)
  - [Chapter 8: Onboard Software](#chapter-8-onboard-software)
  - [Chapter 9: Spacecraft Hacking](#chapter-9-spacecraft-hacking)
- [Part IV: The User Segment](#part-iv-the-user-segment)
  - [Chapter 10: Attacking SATCOM Terminals](#chapter-10-attacking-satcom-terminals)
  - [Chapter 11: Exploiting Global Navigation Satellite Systems](#chapter-11-exploiting-global-navigation-satellite-systems)
- [Appendix A: The Space Sector](#appendix-a-the-space-sector)
- [Appendix B: Space Systems](#appendix-b-space-systems)

---

## Part I: Foundations of Space Security

### Chapter 1: A Space Security Primer

#### Overview

Space systems are no longer the exclusive domain of nation-states. Commercial off-the-shelf (COTS) hardware, open-source software stacks, and accessible launch services have lowered barriers dramatically. The result is a diverse and rapidly expanding attack surface spanning orbital altitudes, radio frequencies, ground infrastructure, and end-user hardware.

Space systems are divided into three segments:

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

**Ground Segment**
- Mission control systems (often Windows-based IT/OT hybrid environments)
- Ground station software and hardware interfaces
- TT&C uplink chains
- Network connectivity between ground nodes
- Supply chain for ground hardware/software

**Space Segment**
- Onboard computer (OBC) firmware
- Flight software (FSW) — often C/C++, sometimes Ada or SPARK
- Communication subsystems
- Attitude and Orbit Control System (AOCS)
- Power management systems

**User Segment**
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

Use STRIDE adapted for space-specific contexts:

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

#### Legal and Regulatory Considerations

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

## Part II: The Ground Segment

### Chapter 4: Ground-Space Communications

#### Link Architecture

Every satellite system relies on a chain of RF links between ground and spacecraft:

```
Ground Station (Uplink)
        │
        ▼
  [Transponder / Receiver]
      (Spacecraft)
        │
        ▼
Ground Station (Downlink)
```

Key link types:

| Link | Direction | Purpose |
|------|-----------|---------|
| **Uplink** | Ground → Space | Commands, software uploads, data |
| **Downlink** | Space → Ground | Telemetry, payload data, status |
| **Crosslink / ISL** | Space → Space | Inter-satellite relay (proliferated LEO) |
| **User Link** | Space ↔ User terminal | End-user service delivery |

#### Frequency Bands

| Band | Frequency Range | Typical Use |
|------|----------------|------------|
| L-band | 1–2 GHz | Mobile SATCOM, GNSS |
| S-band | 2–4 GHz | TT&C for many LEO spacecraft |
| C-band | 4–8 GHz | Legacy FSS, broadcast |
| X-band | 8–12 GHz | Military, government |
| Ku-band | 12–18 GHz | Commercial FSS, VSAT |
| Ka-band | 26.5–40 GHz | HTS, broadband (Viasat, Starlink) |
| V/W-band | 40–75 GHz | Next-gen HTS |

#### Signal Security Considerations

- **Unencrypted telemetry** — Many legacy satellites downlink telemetry in cleartext CCSDS frames, allowing passive monitoring of spacecraft health, mode, and configuration
- **Weak or absent command authentication** — Early command systems used MAC codes that are now trivially breakable; some older birds have no authentication at all
- **Signal intercept** — Any sufficiently directional antenna aimed at the correct orbital slot can capture downlink signals; uplink intercept requires proximity to the ground station
- **Replay attacks** — Without command sequence counters, captured command frames can be replayed

#### CCSDS Protocol Stack

The Consultative Committee for Space Data Systems defines the dominant protocol family:

```
┌─────────────────────────────┐
│    Mission-specific app      │  (mission data, health reports)
├─────────────────────────────┤
│     CCSDS CFDP / AOS        │  (file transfer, advanced orbiting)
├─────────────────────────────┤
│    Space Packet Protocol    │  (packet framing, APID routing)
├─────────────────────────────┤
│   TM / TC Transfer Frames   │  (Telemetry / Telecommand frames)
├─────────────────────────────┤
│     Sync & Channel Coding   │  (ASM, LDPC, Reed-Solomon, turbo)
├─────────────────────────────┤
│         RF / Physical       │  (BPSK, QPSK, OQPSK, etc.)
└─────────────────────────────┘
```

Key CCSDS identifiers targeted during analysis:

| Field | Description | Security Relevance |
|-------|-------------|-------------------|
| **APID** | Application Process ID | Routes packets to subsystems; spoofing APIds targets specific spacecraft functions |
| **VCID** | Virtual Channel ID | Multiplexes data streams; may separate encrypted/unencrypted flows |
| **Spacecraft ID (SCID)** | Identifies the target spacecraft | Used to filter commands and telemetry |
| **Sequence Counter** | Monotonic packet counter | Anti-replay; absence is a vulnerability |

---

### Chapter 5: Mission Control Systems

#### Architecture

Modern mission control centers (MCCs) blend IT and operational technology (OT) in ways that introduce significant attack surface:

```
External Networks / Internet
          │
     [Firewall/DMZ]
          │
    Corporate IT Network
          │
     [Air Gap / DMZ]
          │
   Mission Control LAN
    ┌────┴─────┐
    │          │
  MOC/SOC   Ground Station
  (Ops)     Network
```

Common MCC components:

- **Mission Operations Center (MOC)** — Operator consoles, display systems, command generation
- **Flight Dynamics System (FDS)** — Orbit determination, maneuver planning
- **Telemetry Processing System** — Ingests raw frames, decommutates engineering data
- **Command Management System** — Command authorization, sequencing, uplink management
- **Data Archive** — Historical telemetry, products, mission records

#### Technology Stack Vulnerabilities

| Component | Common Technology | Common Issues |
|-----------|------------------|---------------|
| Operator workstations | Windows 10/11, Linux | Unpatched OS, legacy software dependencies |
| MCS applications | COSMOS, ITOS, GMAT, custom | Outdated frameworks, hardcoded credentials |
| Databases | Oracle, PostgreSQL, SQL Server | Weak authentication, excessive privileges |
| Network infrastructure | Cisco, Juniper | Default credentials, unpatched firmware |
| Remote access | VPN, RDP, TeamViewer | Weak MFA, exposed management interfaces |

#### Attack Vectors

- **IT-side intrusion → lateral movement to MCS network** — Most historically successful path (mirrors IT/OT targeting in ICS attacks)
- **Supply chain compromise** — Malicious updates to MCS software or ground station hardware
- **Remote access exploitation** — VPN credential compromise, MFA bypass
- **Insider threat** — Privileged operators with unrestricted command access
- **Removable media** — USB-introduced malware in air-gapped or semi-air-gapped environments

#### Historical Example: Viasat KA-SAT (2022)

The Sandworm/AcidRain attack against Viasat's KA-SAT network demonstrated how ground segment compromise translates directly to user-segment destruction:

1. Attackers gained access to the management network via a misconfigured VPN concentrator
2. Leveraged access to issue legitimate management commands to modems
3. Deployed AcidRain wiper targeting VSAT modems via the provisioning system
4. ~50,000 modems were bricked across Europe; Ukrainian military comms disrupted at war onset

**Lessons:** Management plane access to SATCOM infrastructure = mass end-device impact. Ground segment security directly protects the user segment.

---

### Chapter 6: Exploiting Ground Segment Protocols

#### Passive Reconnaissance

Before any active testing, passive RF collection provides significant intelligence:

```bash
# Capture raw IQ data with HackRF (authorized lab/research use only)
hackrf_transfer -r capture.iq -f 437500000 -s 2000000 -g 40 -l 32

# Use SatDump for known satellite signals
satdump live noaa_hrpt baseband --source airspy --samplerate 6e6 --frequency 1707e6

# gr-satellites for CubeSat/amateur satellite decoding
python -m gr_satellites <satellite-name> --iq /path/to/capture.iq
```

#### CCSDS Frame Analysis

With captured IQ data, work down the protocol stack:

1. **Synchronization** — Find the CCSDS Attached Synchronization Marker (ASM): `0x1ACFFC1D`
2. **Frame delineation** — Transfer frame length is fixed per mission; determine from ASM spacing
3. **Header parsing** — Extract SCID, VCID, frame counter, data field status
4. **Reed-Solomon / LDPC decode** — Strip error correction coding
5. **Space Packet extraction** — Parse APID, sequence flags, packet length
6. **Application data** — Mission-specific; may require protocol documentation or reverse engineering

Wireshark supports CCSDS with appropriate dissectors. Custom dissectors can be written in Lua for mission-specific protocols.

#### Command Injection Concepts

> **⚠️ Authorized testing only.** Uplink injection toward an operational satellite is illegal without operator authorization.

Command injection attack paths in a ground system context:

| Attack Vector | Method | Prerequisite |
|---------------|--------|-------------|
| MCS application exploitation | SQL injection, buffer overflow in command parser | MCS network access |
| Command file manipulation | Modify stored command sequences before uplink | File system access on MCS |
| Uplink interception + modification | MITM between MCS and modulator | Physical/logical access to RF chain |
| Replay of captured commands | Retransmit valid captured frames | Captured command traffic, weak sequence enforcement |
| Rogue ground station | Transmit on licensed frequency | Radio license, directional antenna, frequency/timing knowledge |

#### Protocol Fuzzing

Ground systems that parse telemetry or expose northbound APIs are candidates for fuzzing:

```python
# Conceptual fuzzer for CCSDS Space Packet parser
import boofuzz
import socket

def ccsds_space_packet(apid, data):
    """Build minimal CCSDS Space Packet"""
    version = 0b000
    type_bit = 0  # Telemetry
    sec_hdr = 0
    primary_header = ((version << 13) | (type_bit << 12) | 
                     (sec_hdr << 11) | apid).to_bytes(2, 'big')
    seq_flags = 0b11  # Standalone packet
    seq_count = 0
    seq_field = ((seq_flags << 14) | seq_count).to_bytes(2, 'big')
    data_length = (len(data) - 1).to_bytes(2, 'big')
    return primary_header + seq_field + data_length + data

# Fuzz the data field with boofuzz targeting a ground system parser
```

---

### Chapter 7: Hacking Ground Systems

#### Reconnaissance

OSINT sources for space ground infrastructure:

| Source | Information Available |
|--------|----------------------|
| FCC License Database (ULS) | US earth station licenses, frequencies, coordinates |
| ITU BR IFIC | International frequency notifications, earth station data |
| SatBeams / LyngSat | Transponder plans, EIRP maps |
| NORAD / Space-Track.org | TLE orbital elements for targeting geometry |
| LinkedIn / job postings | Technology stack inference (COSMOS, ITOS, specific SCADA) |
| Shodan / Censys | Internet-exposed ground system interfaces |
| Google Maps / satellite imagery | Physical ground station location confirmation |

#### Network Penetration Path

Ground segment network pentesting follows standard methodology with space-specific considerations:

```
External Recon
    └─> Identify IP ranges (NOC, ground station, corporate)
    └─> Shodan: product:"COSMOS" OR product:"Kratos" OR banner:"Mission Control"
    └─> Certificate transparency for domain enumeration

Initial Access
    └─> VPN/SSL VPN exploitation (CVEs, credential stuffing)
    └─> Exposed RDP / Citrix
    └─> Phishing targeting operations staff

Lateral Movement
    └─> IT network → MCS DMZ → MCS LAN
    └─> Credential harvesting (Mimikatz, secretsdump)
    └─> Service account abuse (privileged for automation)

Mission Impact
    └─> Command system access
    └─> Telemetry manipulation / suppression
    └─> FSW upload capability
    └─> Modem/terminal management access (user segment impact)
```

#### Common Vulnerabilities in Mission Control Applications

- **Hardcoded credentials** in legacy MCS deployments (often installed once and never rotated)
- **Unencrypted internal protocols** — some MCS components communicate via unencrypted UDP/TCP internally
- **Weak authentication** on web-based display systems and dashboards
- **Outdated dependencies** in Java-based or Python-based MCS stacks
- **Insufficient input validation** in command parameter interfaces

#### Defense and Hardening

| Control | Implementation |
|---------|---------------|
| Network segmentation | Strict IT/OT separation; MCS on isolated VLAN with unidirectional data diodes where possible |
| MFA everywhere | Require phishing-resistant MFA (FIDO2/hardware token) for all MCS access |
| Command authentication | Implement CCSDS Telecommand Authentication (TCA) or equivalent |
| Privileged access management | PAM solution for operator accounts; no shared credentials |
| Patch management | Separate patching cadence for MCS vs. IT; test in lab before ops deployment |
| Monitoring | Behavioral analytics on command issuance patterns; anomaly alerting |
| Supply chain | Firmware integrity verification; signed software updates |

---

## Part III: The Space Segment

### Chapter 8: Onboard Software

#### Spacecraft Software Architecture

Spacecraft software is typically layered across several functional domains:

```
┌────────────────────────────────────┐
│        Mission Application          │  Payload control, science, imaging
├────────────────────────────────────┤
│       Flight Software (FSW)         │  Attitude control, power mgmt, thermal
├────────────────────────────────────┤
│    RTOS / Executive / Middleware    │  VxWorks, RTEMS, FreeRTOS, LEON-RTEMS
├────────────────────────────────────┤
│         BSP / Drivers               │  Hardware abstraction layer
├────────────────────────────────────┤
│       Onboard Computer (OBC)        │  RAD750, LEON3/4, ARM Cortex, SPARC
└────────────────────────────────────┘
```

#### Common RTOS Platforms

| RTOS | Usage | Known Issues |
|------|-------|-------------|
| **VxWorks** | Legacy GEO satellites, many heritage platforms | CVE-2019-12255 (URGENT/11 TCP/IP stack bugs); numerous historical CVEs |
| **RTEMS** | Open-source; many CubeSats, NASA missions | Smaller CVE surface but limited security hardening |
| **FreeRTOS** | Proliferated LEO, smallsats | CVE-2018-16528 (SafeRTOS heap overflow) and related |
| **Linux** | Modern commercial satellites | Kernel CVEs; often unpatched in flight due to update risk |
| **INTEGRITY (GHS)** | High-assurance defense platforms | Proprietary; limited public vulnerability data |

#### Flight Software Languages and Vulnerabilities

| Language | Usage | Key Risk |
|----------|-------|---------|
| **C** | Dominant in heritage FSW | Memory safety: buffer overflows, use-after-free, integer overflows |
| **C++** | Modern FSW, NASA F Prime | Same as C plus class/template complexity |
| **Ada / SPARK** | High-assurance (ESA, some DoD) | Formally verified subsets; lower risk but not immune |
| **Python** | Ground tools, some modern smallsats | Injection risks, dependency vulnerabilities |
| **Rust** | Emerging (experimental satellite use) | Memory-safe by design |

#### Software Upload Security

Telecommand software uploads (patches, parameter updates, full FSW loads) represent the highest-risk command type:

- **Integrity verification** — Is the uplinked binary cryptographically signed and verified before execution?
- **Authentication** — Is the command chain that initiates an upload authenticated end-to-end?
- **Rollback protection** — Can an attacker upload a known-vulnerable older version?
- **Execution path** — Is uploaded code loaded into protected memory? Can it overwrite the bootloader?

Many legacy satellites have no meaningful software upload authentication — the only protection is the difficulty of gaining uplink access.

---

### Chapter 9: Spacecraft Hacking

> **Context:** Direct spacecraft hacking in the wild requires either compromise of the ground segment command chain or physical/RF proximity with a transmitter. The scenarios below apply to authorized research, CTF environments, and red team engagements with spacecraft operators.

#### Attack Scenarios

**Scenario 1: Command Injection via Compromised MCS**
- Attacker has achieved MCS access through ground segment compromise
- Issues malformed or malicious telecommand frames through the legitimate uplink chain
- Target: mode changes, FSW upload, AOCS commands (attitude change), power cycling

**Scenario 2: Rogue Uplink (Research/Lab)**
- Attacker operates an SDR-based transmitter aimed at the spacecraft
- Requires: knowledge of uplink frequency, modulation, frame format, and command structure
- Practical for unencrypted CubeSats with publicly documented protocols
- Applicable to the growing body of amateur/educational satellites with open TT&C specs

**Scenario 3: Side-Channel via Telemetry**
- Passive collection of downlinked telemetry reveals operational state
- Can be used for reconnaissance: when is the spacecraft unattended? What mode is it in?
- Timing attacks on encrypted telemetry (traffic analysis)

#### CubeSat Security Research

CubeSats represent the most accessible research target for spacecraft security:

- Many use open-source FSW (OpenSatCom, KubOS, FreeRTOS + custom)
- Frequencies and protocols often published in amateur satellite databases (AMSAT, SatNOGS)
- Some have open command interfaces for ground station operators

```bash
# SatNOGS global ground station network — passive telemetry collection
# https://network.satnogs.org

# Decode AX.25-framed CubeSat telemetry
gr_satellites <satellite-name> --wavfile capture.wav --doppler_csv doppler.csv

# Parse decoded frames with mission-specific decoder
python decode_telemetry.py --frames decoded.json
```

#### Hardening the Space Segment

| Control | Detail |
|---------|--------|
| **Command authentication** | CCSDS Telecommand Authentication (TCA); HMAC or asymmetric signatures on all telecommands |
| **Sequence counters** | Enforce strict monotonic counters; reject replays |
| **Encrypted uplink** | AES-256 or equivalent for all command and data uplinks |
| **Software signing** | Cryptographic signature verification before any FSW load/patch execution |
| **Watchdog timers** | Hardware watchdog to recover from FSW compromise or corruption |
| **Safe mode** | Autonomous safe mode entry on anomaly; limited command set in safe mode |
| **Memory protection** | MPU/MMU enforcement; non-executable data regions |
| **Radiation hardening** | Redundant memory, scrubbing, error-correcting codes (EDAC) — also relevant to fault injection |

---

## Part IV: The User Segment

### Chapter 10: Attacking SATCOM Terminals

#### Terminal Architecture

SATCOM user terminals vary from simple receive-only dishes to full bidirectional VSAT modems. Common architectures:

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

- **Hardcoded credentials** — Factory default admin accounts that cannot be changed (documented in multiple Iridium, Hughes, ViaSat, and Intellian advisories)
- **Pre-auth RCE** — Command injection in web UI before authentication (multiple CVEs across major vendors 2020–2024)
- **Unencrypted management** — HTTP instead of HTTPS; Telnet instead of SSH
- **Insecure firmware updates** — No signature verification on update packages
- **Debug interfaces** — UART/JTAG left exposed in production hardware

#### Notable Research

| Research | Findings |
|----------|---------|
| IOActive — SATCOM Security (2014) | Pre-auth RCE in Iridium, BGAN, Hughes, ViaSat terminals |
| Black Hat 2020 — Ruben Santamarta | Revisited SATCOM vulnerabilities; aviation safety implications |
| DEFCON 30 (2022) — Starlink | Physical fault injection on Starlink dish; custom firmware execution |

---

### Chapter 11: Exploiting Global Navigation Satellite Systems

#### GNSS Overview

GNSS provides positioning, navigation, and timing (PNT) services. Major constellations:

| System | Operator | Frequencies |
|--------|----------|------------|
| GPS | USA (Space Force) | L1 (1575.42 MHz), L2 (1227.60 MHz), L5 (1176.45 MHz) |
| GLONASS | Russia | L1 (~1602 MHz), L2 (~1246 MHz) |
| Galileo | EU | E1 (1575.42 MHz), E5 (1176.45 / 1207.14 MHz) |
| BeiDou | China | B1 (1561.098 MHz), B2, B3 |
| NavIC | India | L5, S-band |

#### Signal Characteristics and Weaknesses

GNSS signals arrive at Earth's surface at approximately **-130 dBm** — roughly 20 dB below thermal noise. This extreme weakness makes them trivially susceptible to interference:

- **Open signals** — Civilian GNSS signals (GPS L1 C/A, Galileo E1-B/C) are unencrypted and unauthenticated by design
- **No uplink** — Receivers are passive; the signal cannot "respond" to verify authenticity
- **Predictable structure** — PRN codes, nav message formats, and satellite ephemeris are all public

#### Attack Types

**Jamming**

Broadband noise or CW interference on GNSS frequencies. Low technical barrier — cheap jammers widely available (though illegal in most jurisdictions).

- Effective range: meters to kilometers depending on power
- Impact: loss of PNT — navigation, timing systems fail
- Detection: GNSS receiver AGC spike; multiple receivers losing fix simultaneously
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

1. **Meaconing** — Simply re-broadcast authentic signals (introduces delay = false position)
2. **Simple spoofing** — Static false position, no correlation with authentic signal timing
3. **Sophisticated spoofing** — Gradually drag receiver position; preserves carrier phase continuity to avoid detection

**Spoofing Tools (Research Context)**

| Tool | Description |
|------|-------------|
| **GPS-SDR-SIM** | Open-source GPS L1 C/A signal simulator (TX requires HackRF or USRP) |
| **GNSS-SDRLIB** | Multi-constellation SDR receiver and signal generator |
| **Spirent GSS7000** | Commercial GNSS simulator (lab use) |

> **⚠️ Legal Warning:** Transmitting counterfeit GNSS signals is illegal under FCC regulations and equivalent international law. GNSS spoofing of aviation, maritime, or emergency services is a federal crime. Testing must occur in a shielded RF enclosure.

#### Real-World GNSS Attacks

| Incident | Year | Method | Impact |
|----------|------|--------|--------|
| Russian Black Sea spoofing | 2017–ongoing | Large-scale GPS spoofing | Dozens of ships reported false positions in Moscow |
| Tehran GPS spoofing (RQ-170 capture) | 2011 | Alleged GPS spoof | US drone landed in Iran (disputed) |
| Contested GPS jamming — Ukraine/Eastern Europe | 2022–present | Broadband L1/L2 jamming | Aviation GPS outages across Eastern Europe |
| Dallas ADS-B GPS disruption | 2022 | Ground-based interference | FAA NOTAM; flight delays |

#### GNSS Security Countermeasures

| Countermeasure | Description |
|----------------|-------------|
| **GPS Signal Authentication (NMA)** | Galileo OSNMA now live; GPS CHIPS-Message authentication in development |
| **Multi-constellation / multi-frequency** | Spoofing all constellations simultaneously is far harder |
| **Receiver Autonomous Integrity Monitoring (RAIM)** | Statistical consistency checks across visible satellites |
| **IMU integration** | Inertial navigation cross-check; anomaly detection on PVT jumps |
| **Signal strength monitoring** | Sudden AGC change indicates jamming; abnormally strong signal indicates spoofing |
| **Clock anomaly detection** | Time jumps inconsistent with receiver dynamics indicate spoofing |

---

## Appendix A: The Space Sector

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
| **CCSDS** | Protocol standards (also security recommendations — CCSDS 350.x series) |
| **CISA** | Space Systems Critical Infrastructure guidance |
| **DoD / NSA** | COMSEC requirements for national security space |

---

## Appendix B: Space Systems

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

## Further Reading

- *Hacking Satellites* — Attify / Black Hat presentations (2014–2024)
- CCSDS 350.0-G-3: *The Application of Security to CCSDS Protocols*
- CCSDS 351.0-M-1: *Security Architecture for Space Data Systems*
- NIST SP 800-53 Rev 5 — Control families applicable to space (SA, SI, SC, AU)
- CISA: *Space Systems Critical Infrastructure Security and Resilience*
- *An Overview of Cybersecurity for Commercial Satellite Operations* — NIST IR 8270
- Aerospace Corporation: *Defending Space Systems from Cyber Threats*
- IOActive: *SATCOM Security* (2014, 2020 revisit)
- DEF CON Aerospace Village proceedings (annual)

---

*Document maintained as part of the ULTIMATE-CYBERSECURITY-MASTER-GUIDE. For corrections or contributions, submit a PR to the repository.*
