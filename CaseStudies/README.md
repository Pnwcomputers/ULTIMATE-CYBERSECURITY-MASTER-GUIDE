# 🧩 Cybersecurity Case Studies

<div align="center">

**Historical incidents and security research, explained through evidence and diagrams**

*Part of the [ULTIMATE CYBERSECURITY MASTER GUIDE](../README.md)*

<p align="center">
  <img src="https://img.shields.io/badge/Maintained-Yes-green" alt="Maintained"/>
  <img src="https://img.shields.io/badge/Books%20Referenced-70%2B-blue" alt="Books"/>
  <img src="https://img.shields.io/badge/PNWC%20Internal%20Docs-90%2B-orange" alt="Docs"/>
  <img src="https://img.shields.io/badge/OSINT%20Tools-400%2B-purple" alt="OSINT"/>
  <img src="https://img.shields.io/badge/Scripts-Source_Collection-red" alt="Scripts"/>
  <img src="https://img.shields.io/badge/License-Educational%20Use-yellow" alt="License"/>
  <img src="https://img.shields.io/github/last-commit/Pnwcomputers/ULTIMATE-CYBERSECURITY-MASTER-GUIDE" alt="Last Commit"/>
</p>

</div>

---

**Visuals and navigation reviewed:** November 17, 2026. These are historical accounts and conceptual diagrams, not laboratory reproductions or proof of current exploitability.

## 🎯 Purpose

Provide a dedicated starting point for studying documented cybersecurity incidents
and hardware-security research, from enterprise intrusions to physical-device trust
boundaries.

## ⚙️ Function

Connect each case to its analysis, source material, explanatory visuals, and related
defensive guides. Enterprise incident analyses live in the Enhanced Master Guide;
the detailed hardware cases live in this section.

## 🏆 Goal

Help readers explain what failed, what the evidence actually establishes, and which
engineering or operational lessons apply to a similar system.

## 📋 When To Use

- Learning how an intrusion moves between systems, identities, or physical components.
- Comparing a disclosed vulnerability with a documented incident.
- Preparing a threat-model discussion, security lesson, or defensive review.
- Checking the limits of a historical claim before applying it to a current deployment.

---

## 📋 Table Of Contents

- [Start Here](#start-here)
- [Attack Case Studies](#attack-case-studies-historical-references)
- [Hardware, RFID & Embedded Security](#hardware-rfid--embedded-security)
- [Reading The Visuals](#reading-the-visuals)
- [Case Study Review Checklist](#case-study-review-checklist)
- [Related Guides](#related-guides)

## Start Here

| If You Want To Understand… | Open |
|---|---|
| Worm propagation versus a ransomware payload | [WannaCry](../ENHANCED_MASTER_GUIDE.md#wannacry-breakdown) and [EternalBlue](../ENHANCED_MASTER_GUIDE.md#eternalblue-exploitation) |
| A trusted update becoming an intrusion path | [SolarWinds](../ENHANCED_MASTER_GUIDE.md#solarwinds-attack) and [NotPetya](../ENHANCED_MASTER_GUIDE.md#notpetya-ransomware) |
| Software changing a physical process | [Stuxnet](../ENHANCED_MASTER_GUIDE.md#stuxnet-analysis) |
| A technical foothold becoming financial fraud | [Carbanak](../ENHANCED_MASTER_GUIDE.md#carbanak-apt-campaign) |
| Historical surveillance collection pathways | [Snowden disclosures](../ENHANCED_MASTER_GUIDE.md#edward-snowden-revelations) |
| Physical interfaces and credential trust | [Onity](./hardware/onity-locks-2012.md), [Unsaflok](./hardware/unsaflok-3m-hotel-locks.md), and [DirecTV DSS](./hardware/directv-dss-smart-card-black-sunday.md) |
| Secret recovery and authentication boundaries | [Tesla key fobs](./hardware/tesla-model-s-key-fob-2018.md) and [EUCLEAK](./hardware/eucleak-yubikey-2024.md) |
| Identifying information hidden in ordinary output | [Xerox printer dots](./hardware/xerox-docucolor-machine-identification-code.md) |

---

## Attack Case Studies (Historical References)

Each incident title opens its analysis in the Enhanced Master Guide. The source links provide external background references; the detailed hardware research entries follow below.

| Incident | Type |
|---|---|
| [Stuxnet](../ENHANCED_MASTER_GUIDE.md#stuxnet-analysis) | Nation-state cyberweapon - Iranian nuclear facilities · [Source](https://en.wikipedia.org/wiki/Stuxnet) |
| [WannaCry](../ENHANCED_MASTER_GUIDE.md#wannacry-breakdown) | Global ransomware outbreak · [Source](https://www.cisa.gov/news-events/alerts/2017/05/12/indicators-associated-wannacry-ransomware) |
| [EternalBlue / NSA Leak](../ENHANCED_MASTER_GUIDE.md#eternalblue-exploitation) | NSA exploit leaked by Shadow Brokers · [Source](https://www.microsoft.com/en-us/security/blog/2017/05/12/wannacrypt-ransomware-worm-targets-out-of-date-systems/) |
| [SolarWinds](../ENHANCED_MASTER_GUIDE.md#solarwinds-attack) | Software supply chain compromise · [Source](https://www.cisa.gov/news-events/cybersecurity-advisories/aa20-352a) |
| [Carbanak](../ENHANCED_MASTER_GUIDE.md#carbanak-apt-campaign) | APT banking theft campaign · [Source](https://cloud.google.com/blog/topics/threat-intelligence/behind-the-carbanak-backdoor) |
| [NotPetya](../ENHANCED_MASTER_GUIDE.md#notpetya-ransomware) | Destructive malware disguised as ransomware · [Source](https://www.wired.com/story/notpetya-cyberattack-ukraine-russia-code-crashed-the-world/) |
| [Edward Snowden / NSA](../ENHANCED_MASTER_GUIDE.md#edward-snowden-revelations) | Mass surveillance program revelations · [Source](https://www.theguardian.com/world/edward-snowden) |

## Hardware, RFID & Embedded Security

| Case Study | Published | Primary Failure | Related Guides |
|---|---|---|---|
| [Unsaflok: Three Million Hotel-Lock Exposure](hardware/unsaflok-3m-hotel-locks.md) | March 2024 | RFID keycard and lock authorization weaknesses | [RFID & NFC](../SDR/rfid.md), [Hardware Hacking](../HardwareHacking/README.md) |
| [Onity Hotel-Lock Research](hardware/onity-locks-2012.md) | 2012 | Physical maintenance-port trust boundary | [Hardware Threat Modeling](../HardwareHacking/Chapter1.md) |
| [Tesla Model S Key-Fob Cloning Research](hardware/tesla-model-s-key-fob-2018.md) | September 2018 | Weak proprietary RF immobilizer authentication | [SDR Security](../SDR/README.md) |
| [EUCLEAK: YubiKey/Infineon Side Channel](hardware/eucleak-yubikey-2024.md) | September 2024 | Non-constant-time ECDSA processing | [Side Channels](../HardwareHacking/Chapter4.md), [Security Keys](../Cryptography/security-keys-passkeys.md) |
| [DirecTV DSS Cards & Black Sunday](./hardware/directv-dss-smart-card-black-sunday.md) | January 2001 event | Altered smart-card authorization & operator countermeasures | [Threat Modeling](../HardwareHacking/Chapter1.md) |
| [Xerox DocuColor MIC Decoding](./hardware/xerox-docucolor-machine-identification-code.md) | October 2005 | Undisclosed identifying metadata in physical output | [OPSEC](../OPSEC/README.md) |

The term **“3M hack”** is used here to mean the **approximately three million Saflok doors** reported in Unsaflok research, **not a confirmed incident involving 3M Company**. If a different 3M incident was intended, that needs a separate verified case study.

## Reading The Visuals

Each case includes an original conceptual diagram beside the relevant explanation.
The Xerox case also includes owner-supplied images. Captions identify provenance,
source material, scope, and limits.

| Visual Element | How To Read It |
|---|---|
| Boxes and arrows | A simplified relationship or mechanism; not measured timing or a universal attack sequence. |
| Trust boundaries | Where authority or information crosses between components; not a guarantee about a product. |
| Parallel routes | Different mechanisms that may require different defensive controls. |
| Historical dates and versions | Scope of the cited research; verify the actual deployment before making a present-day claim. |
| Illustrations and synthetic examples | Teaching aids, not incident evidence or laboratory measurements. |

The [image asset index](../assets/README.md) records where these figures are used.
For deeper study, follow each case's source links and distinguish researcher findings,
vendor advisories, court records, and later reporting.

## Case Study Review Checklist

1. Distinguish **disclosed research** from confirmed criminal exploitation; do not imply the latter unless evidence exists.
2. Record which exact devices, deployments, firmware and date were covered by the original research; avoid universal claims.
3. Separate lab reproduction from real-world incident statistics.
4. Attribute dates and versions to the original source. An old patch-deployment percentage is **not** a current compliance rate.
5. Link to related defensive and threat-modeling guides; never publish unauthorized entry techniques, live access credentials or card-cloning recipes.

## Related Guides

| Guide | Use It For |
|---|---|
| [Hardware Hacking](../HardwareHacking/README.md) | Device trust boundaries, physical interfaces, and side channels. |
| [Incident Response](../IncidentResponse/README.md) | Containment, evidence handling, investigation, and recovery. |
| [Reverse Engineering](../ReverseEngineering/README.md) | Understanding implementation behavior and analysis limits. |
| [OPSEC](../OPSEC/README.md) | Identity exposure and information handling. |
| [RFID & NFC](../SDR/rfid.md) | Credential systems and authorized access-control assessment context. |

---

[⬅️ Back To Master Index](../README.md) | [🎯 Role Navigation](../START_HERE.md) | [Legal Notice](../LEGAL.md)
