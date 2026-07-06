# 🏢 Appendix A: The Space Sector

## 🎯 Purpose
Reference appendices for the Space Security guide - covering industry overview (commercial, defense, NewSpace), regulatory and standards bodies (NIST SP 800-53, CCSDS, ITU), career paths in space security, and further reading resources.

## ⚙️ Function
Contains tabular industry overview (sector/key players/security relevance), regulatory bodies and applicable standards, space security career paths (ground segment security engineer, satellite systems pentester, RF security researcher), and curated resource lists.

## 🏆 Goal
Provide the background context, standards references, and resource pointers that complement the operational content in Parts I-IV - useful for scoping assessments, understanding regulatory constraints, and professional development.

## 📋 When to Use
- Identifying which standards apply to a client's space system (NIST, CCSDS, ITU)
- Career reference: understanding the space security job landscape
- Further reading for any space security topic covered in Parts I-IV

## Industry Overview

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

# 🔧 Appendix B: Space Systems

## Reference Architectures

### LEO Smallsat / CubeSat

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

## ⚠️ Security & Legal Disclaimer

### 🔴 CRITICAL: Authorized Use Only

```
⚠️ LEGAL AND ETHICAL USE ONLY ⚠️

This section contains attack techniques and methodologies for:

✅ AUTHORIZED USES:
   • Security assessments with explicit written authorization from spacecraft operators
   • Red team operations with organizational approval
   • Academic research in shielded RF enclosures or simulation environments
   • Blue team training and detection development
   • CTF competitions (DEFCON Aerospace Village, Hack-A-Sat)
   • Passive RF monitoring within legal boundaries

🚫 STRICTLY PROHIBITED:
   • Transmitting RF signals toward operational satellites without authorization
   • Unauthorized access to ground station or mission control systems
   • GNSS jamming or spoofing outside of shielded test environments
   • Intercepting protected satellite communications
   • Any activity violating CFAA, FCC regulations, ITAR/EAR, or ITU rules
   • Causing disruption to satellite services or critical infrastructure
```

### Legal Framework

| Law / Regulation | Scope |
|-----------------|-------|
| **CFAA (18 U.S.C. § 1030)** | Unauthorized access to satellite ground systems - up to 10 years |
| **FCC Part 25/97** | Unauthorized transmission on licensed satellite frequencies - criminal offense |
| **ITAR (22 CFR 120-130)** | Export control on satellite technology and related security tools |
| **ITU Radio Regulations** | International frequency coordination and harmful interference prohibition |
| **UK Computer Misuse Act** | Unauthorized access to space-related computer systems |
| **EU Cybercrime Directives** | Harmonized computer crime laws covering ground infrastructure |

### Warranty Disclaimer

```
These materials are provided "AS IS" without warranty of any kind.

THE AUTHORS AND CONTRIBUTORS:
• Make no guarantees about technique effectiveness or accuracy
• Are not responsible for damages from unauthorized use
• Are not liable for legal consequences of misuse
• Disclaim all liability for disruption to space systems or services

USERS EXPLICITLY ACKNOWLEDGE:
• Space system attacks can disrupt critical infrastructure
• RF transmission without authorization is a federal crime
• ITAR/EAR restrictions may apply to tools and techniques
• They accept all risks associated with using attack methodologies
```

---

## 📚 Resources

### Standards and Guidance

- CCSDS 350.0-G-3: *The Application of Security to CCSDS Protocols*
- CCSDS 351.0-M-1: *Security Architecture for Space Data Systems*
- NIST SP 800-53 Rev 5 - Control families applicable to space (SA, SI, SC, AU)
- NIST IR 8270: *An Overview of Cybersecurity for Commercial Satellite Operations*
- CISA: *Space Systems Critical Infrastructure Security and Resilience*
- Aerospace Corporation: *Defending Space Systems from Cyber Threats*

### Research and Presentations

- IOActive: *SATCOM Security* (2014, 2020 revisit)
- DEF CON Aerospace Village proceedings (annual)
- Hack-A-Sat CTF competition (annual - US Space Force / Air Force)
- Black Hat 2020 - Ruben Santamarta: Revisiting SATCOM Security

### Online Resources

- [MITRE ATT&CK for ICS](https://attack.mitre.org/matrices/ics/) - Relevant overlap for ground segment OT
- [SatNOGS Network](https://network.satnogs.org/) - Open-source global ground station network
- [Space-Track.org](https://www.space-track.org/) - TLE orbital element data
- [AMSAT](https://www.amsat.org/) - Amateur satellite frequencies and protocols

---

<div align="center">

**📖 Use These Techniques Responsibly: Authorization is MANDATORY**

*Space systems are critical infrastructure - treat them accordingly.*

**Repository**: [ULTIMATE CYBERSECURITY MASTER GUIDE](https://github.com/Pnwcomputers/ULTIMATE-CYBERSECURITY-MASTER-GUIDE)

**Maintained by**: [Pacific Northwest Computers](https://github.com/Pnwcomputers)

---

## Related Files
- [README.md](README.md) - SpaceSecurity section index
- [PartI.md](PartI.md) - Foundations: the operational content these appendices support

⚠️ **RF transmission toward satellites requires EXPLICIT WRITTEN AUTHORIZATION** ⚠️

⚠️ **Unauthorized access to space systems is a FEDERAL CRIME** ⚠️

⚠️ **ITAR/EAR export controls may apply to satellite security tools and techniques** ⚠️

⭐ **Star this repo if you find it useful!** ⭐

</div>
