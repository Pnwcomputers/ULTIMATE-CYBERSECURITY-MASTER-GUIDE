# 🏢 Appendix A: The Space Sector

> [!CAUTION]
> **Authorized use only.** Security assessment and RF material in these appendices
> is for authorized, defensive, and educational use. Test only systems you own or
> have explicit written permission to assess. RF transmission requires separate
> operator and regulatory authorization where applicable. See [LEGAL.md](../LEGAL.md).

## 🎯 Purpose
Reference appendices for the Space Security guide - covering industry overview (commercial, defense, NewSpace), regulatory and standards bodies (NIST SP 800-53, CCSDS, ITU), career paths in space security, and further reading resources.

## ⚙️ Function
Contains tabular industry overview (sector/key players/security relevance), regulatory bodies and applicable standards, space security career paths (ground segment security engineer, satellite systems pentester, RF security researcher), and curated resource lists.

## 🏆 Goal
Provide the background context, standards references, and resource pointers that complement the operational content in Parts I-IV - useful for scoping assessments, understanding regulatory constraints, and professional development.

## 📋 When to Use
- Identifying which standards and rules may apply to a space mission; applicability depends on its jurisdiction, contract, service, and adopted baseline
- Career reference: understanding the space security job landscape
- Further reading for any space security topic covered in Parts I-IV

## Industry Overview

| Sector | Typical system context | Security assessment considerations |
|--------|------------------------|-------------------------------------|
| **Satellite communications** | GEO, MEO, and non-geostationary networks | Separate mission control, network-management, user-terminal, and service-provider trust paths. |
| **Earth observation** | Imaging and environmental-data missions | Review tasking authority, product provenance, data integrity, and customer access controls. |
| **Launch and ground services** | Launch vehicles, range systems, tracking, and mission support | Scope each operator and supplier boundary; do not assume shared systems or controls. |
| **Defense and government** | National-security or public-service missions | Apply the specific contract, classification, mission, and cryptographic requirements. |
| **Small satellites and CubeSats** | Academic, commercial, and government small spacecraft | Assess the actual BOM, ground-station model, operator roles, and available update/recovery path; do not infer weak security from size or cost. |

*This is an illustrative sector map, not a ranking of vendors or a claim that any listed organization has a particular weakness.*

### Regulatory and Standards Bodies

| Organization | Role and applicability |
|-------------|-----------------------|
| **ITU** | International spectrum coordination framework implemented through national administrations; mission and service rules still apply. |
| **FCC** | U.S. authorizations and service rules for applicable satellite, earth-station, and radio operations. |
| **FAA** | U.S. commercial launch and reentry licensing and safety oversight; it is not the general satellite-communications licensing authority. |
| **NIST** | Security publications and control catalogs that apply when adopted by a mission, agency, contract, or policy. |
| **CCSDS** | Space-data standards and security recommendations; applicability depends on the mission profile and adopted standards. |
| **CISA** | U.S. critical-infrastructure cybersecurity guidance and coordination where relevant. |
| **DoD / NSA** | Requirements and cryptographic guidance where required by the applicable U.S. government mission or contract. |

---

## 🔧 Appendix B: Space Systems

### Reference Architectures

#### Representative Spacecraft Architectures

The figure contrasts typical **bus functions** with **mission payloads** in two broad spacecraft classes. It is a conceptual reference, not a design template: subsystem boundaries, redundancy, hardware, software, and communications vary by mission. A component's placement in the figure does not establish its security boundary or prove that a protection is present.

![Side-by-side conceptual comparison of small-satellite and GEO communications spacecraft bus functions and mission payloads](../assets/diagrams/spacecraft-bus-payload-architecture.svg)

For the ground-to-space command and telemetry path, see [Part II](PartII.md). For the user segment and GNSS integrity checks, see [Part IV](PartIV.md).

#### Key Protocols Reference

| Protocol | Layer | Use | Security Notes |
|----------|-------|-----|---------------|
| CCSDS TM | Data Link | Telemetry framing | Protection depends on the mission profile. CCSDS SDLS can provide authentication and/or confidentiality for supported TM frames; synchronization markers are framing, not authentication. |
| CCSDS TC | Data Link | Command framing | Use the mission-defined security profile. SDLS can protect supported TC frames; link authentication is not a substitute for application-level command authorization. |
| CCSDS Space Packet Protocol | Space-packet protocol | Transfers space-application data using services from underlying layers | APID routing does not establish sender identity or command authorization. CCSDS notes that Space Packet Protocol is not a network-layer protocol; security must be supplied by the mission's surrounding layers. |
| CCSDS CFDP | File-delivery application protocol | File delivery and file-management services | CFDP procedures operate over different underlying protocols; CFDP itself has no security mechanisms, so required security services must be supplied by the configured stack. |
| DVB-S2/S2X | Physical/data-link system | Satellite broadcast modulation and coding | Conditional-access controls, when used, are separate service/application mechanisms and are not provided by DVB-S2 modulation itself. |
| AX.25 | Data Link | Amateur/CubeSat links | Do not infer command authenticity or confidentiality from link framing; use mission-specific protections and authorization. |
| IP over SATCOM | Network | Broadband terminals | Standard IP vulnerabilities apply |

#### SDR Hardware Reference

Specifications below identify representative model variants. Frequency coverage describes tuning limits only; it does not guarantee reception quality, usable bandwidth, or regulatory authority.

| Device model | Representative RF coverage | TX capability | Notes |
|---------------|-----------------------------|---------------|-------|
| [RTL-SDR Blog V4](https://www.rtl-sdr.com/about-RTL-SDR/) | 24 MHz–1.766 GHz | No | Other RTL-SDR tuner models have different ranges and gaps. |
| [HackRF One](https://hackrf.readthedocs.io/en/stable/hackrf_one.html) | 1 MHz–6 GHz | Yes; half-duplex | Product range does not establish permission to transmit. |
| [USRP B210](https://files.ettus.com/manual/page_usrp_b200.html) | 70 MHz–6 GHz | Yes; 2 TX / 2 RX | Capabilities and performance depend on configuration and host. |
| [Airspy HF+](https://airspy.com/airspy-hf-plus/) | 9 kHz–31 MHz and 60–260 MHz | No | The HF+ Discovery is a different model with different published low-frequency coverage. |
| [Airspy HF+ Discovery](https://airspy.com/airspy-hf-discovery/) | 0.5 kHz–31 MHz and 60–260 MHz | No | Check the exact receiver model and current manufacturer specifications. |
| [LimeSDR USB](https://limemicro.com/sdr/limesdr-usb/) | 100 kHz–3.8 GHz | Yes; 2 TX / 2 RX | Product range does not establish permission to transmit. |

*Any transmit-capable SDR requires a separate authorization and equipment/spectrum review before transmission. No equipment specifications or performance were tested for this guide.*

---

### ⚠️ Security & Legal Disclaimer

#### 🔴 CRITICAL: Authorized Use Only

> [!CAUTION]
> These materials are for authorized assessment, education, and defensive research.
> Written permission from the system owner is necessary for access testing; it does
> not by itself provide radio-transmission authority. Use the applicable mission,
> service, licensing, spectrum, and export-control requirements for the jurisdiction.
> Requirements vary by conduct, equipment, spectrum, and location; consult qualified
> counsel and the relevant regulator before an engagement.

#### Legal Framework

| Law / regulation | Applicability note |
|------------------|--------------------|
| [CFAA (18 U.S.C. § 1030)](https://uscode.house.gov/us/usc/119-134/t18/s1030/) | Covers specified computer-related conduct. Elements and consequences depend on the subsection, conduct, jurisdiction, and facts. |
| [FCC radio and satellite-service rules](https://www.ecfr.gov/current/title-47) | The applicable part and authorization depend on the station, service, frequency, and operating conditions; rules and exceptions vary. |
| [ITAR (22 CFR Parts 120–130)](https://www.ecfr.gov/current/title-22/chapter-I/subchapter-M) and [EAR (15 CFR Parts 730–774)](https://www.ecfr.gov/current/title-15/subtitle-B/chapter-VII/subchapter-C) | Export-control obligations depend on item/technology classification, destination, recipient, and activity; do not assume all space-security tools or techniques are controlled. |
| [UK Computer Misuse Act 1990](https://www.legislation.gov.uk/ukpga/1990/18/contents) | UK offences and defenses depend on the statutory elements and facts. |
| [EU Directive 2013/40/EU](https://eur-lex.europa.eu/legal-content/EN/TXT/?uri=CELEX%3A32013L0040) | Establishes minimum rules for attacks against information systems; national law implements the directive. |

#### Warranty Disclaimer

```
These materials are provided "AS IS" without warranty of any kind.

THE AUTHORS AND CONTRIBUTORS:
• Make no guarantees about technique effectiveness or accuracy
• Are not responsible for damages from unauthorized use
• Are not liable for legal consequences of misuse
• Disclaim all liability for disruption to space systems or services

USERS SHOULD UNDERSTAND:
• Space-system testing can affect critical services; operational impact depends on the target and method
• RF operation must comply with whichever authorization and technical rules apply to the specific device, service, band, and jurisdiction; some receive-only or license-by-rule cases differ
• Unauthorized operation or harmful interference may prompt regulatory action; criminal or civil consequences depend on the applicable rules and facts
• Export controls may apply to specifically classified items, software, technology, or technical data based on the destination, recipient, and activity
• Testing plans should define authority, scope, safety controls, stop conditions and data handling
```

---

### 📚 Resources

#### Spacecraft Architecture and Link-Security References

- [NASA Small Spacecraft Technology State of the Art: Platforms](https://www.nasa.gov/smallsat-institute/sst-soa/platforms/) - spacecraft platform and bus concepts; architectures vary by mission.
- [NASA Small Spacecraft Avionics](https://www.nasa.gov/smallsat-institute/sst-soa/small-spacecraft-avionics/) - command, data handling, and subsystem interface patterns.
- [CCSDS 350.0-G-3, The Application of Security to CCSDS Protocols](https://ccsds.org/Pubs/350x0g3.pdf) - explains where link-layer and application-layer security services fit.
- [CCSDS 355.0-B-2, Space Data Link Security Protocol](https://ccsds.org/Pubs/355x0b2.pdf) - standardized authentication and confidentiality services for supported space data links.
- [CCSDS 727.0-B-5, CCSDS File Delivery Protocol](https://ccsds.org/Pubs/727x0b5e1.pdf) - states CFDP itself has no security mechanisms and requires the underlying stack to supply needed protection.

#### Standards and Guidance

- CCSDS 350.0-G-3: *The Application of Security to CCSDS Protocols*
- CCSDS 351.0-M-1: *Security Architecture for Space Data Systems*
- NIST SP 800-53 Rev 5 - Control families applicable to space (SA, SI, SC, AU)
- NIST IR 8270: *An Overview of Cybersecurity for Commercial Satellite Operations*
- CISA: *Space Systems Critical Infrastructure Security and Resilience*
- Aerospace Corporation: *Defending Space Systems from Cyber Threats*

#### Research and Presentations

- IOActive: *SATCOM Security* (2014, 2020 revisit)
- DEF CON Aerospace Village proceedings (annual)
- Hack-A-Sat CTF competition (annual - US Space Force / Air Force)
- Black Hat 2020 - Ruben Santamarta: Revisiting SATCOM Security

#### Online Resources

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

### Related Files
- [README.md](README.md) - SpaceSecurity section index
- [PartI.md](PartI.md) - Foundations: the operational content these appendices support

⚠️ **RF transmission toward satellites requires EXPLICIT WRITTEN AUTHORIZATION** ⚠️

⚠️ **Unauthorized access or transmission may violate applicable law and service rules; requirements depend on the system, spectrum, conduct, and jurisdiction; see [FCC Part 15](https://www.ecfr.gov/current/title-47/chapter-I/subchapter-A/part-15) and service-specific rules such as [47 CFR § 25.115](https://www.ecfr.gov/current/title-47/section-25.115).** ⚠️

⚠️ **ITAR/EAR export controls may apply to satellite security tools and techniques** ⚠️

⭐ **Star this repo if you find it useful!** ⭐

</div>
