# 📻 Software Defined Radio (SDR), RF, NFC/RFID, Sub-GHz Security

<div align="center">

**Guides for signal capture, protocol analysis, wireless security research, and authorized RF/contactless assessments**

*Part of the [ULTIMATE CYBERSECURITY MASTER GUIDE](../README.md)*

![SDR](https://img.shields.io/badge/Hardware-SDR-blue?style=for-the-badge&logo=broadcom)
![RF](https://img.shields.io/badge/Frequencies-RF_Analysis-green?style=for-the-badge&logo=wifi)
![NFC](https://img.shields.io/badge/Contactless-NFC_%2F_RFID-blueviolet?style=for-the-badge&logo=nfc)
![GNURadio](https://img.shields.io/badge/Software-GNU_Radio-orange?style=for-the-badge)

</div>

---

## 🎯 Purpose

This README is the entry point for the SDR, RF, and contactless section. It connects **six companion documents and the NanoVNA guide collection** covering SDR fundamentals, HackRF surveys, advanced signal research, Sub-GHz protocols, RFID/NFC, frequency/protocol references, and antenna/RF measurements.

The linked documents contain explanations, examples, and workflows. A tool listed here is not necessarily bundled with the repository, installed on your system, or compatible with every radio.

## ⚙️ Function

Use this index to select a guide, identify suitable hardware and software, find regional frequency references, and understand the prerequisites for receiving, decoding, or testing a signal.

## 🏆 Goal

Move from an RF question to a documented result: identify the relevant band and protocol, validate the receive chain, capture evidence, analyze it with compatible tools, and report conclusions supported by measurements.

## 📋 When to Use

- Learning IQ sampling, antennas, demodulation, or GNU Radio.
- Selecting a receiver, protocol sniffer, RFID reader, or analysis tool.
- Looking up frequency ranges, exact channel centers, and regional differences.
- Investigating interference or analyzing devices within an authorized assessment.
- Planning an end-to-end engagement with the [HackRF Audit Playbook](../PlayBooks/HackRFAuditPlayBook.md).

> **Operating scope:** Start with public broadcasts, provided recordings, or devices within your authorized scope. Transmissions, private communications, and credential interactions require additional checks. See [Safe Workflows](#safe-workflows) and [Security and Legal Boundaries](#security-and-legal-boundaries).

---

## Table of Contents

- [Guides in This Section](#guides-in-this-section)
- [Choose a Starting Point](#choose-a-starting-point)
- [Hardware Ecosystem](#hardware-ecosystem)
- [Software and Tool Categories](#software-and-tool-categories)
- [Target Frequencies and Protocols](#target-frequencies-and-protocols)
- [Safe Workflows](#safe-workflows)
- [Security and Legal Boundaries](#security-and-legal-boundaries)
- [Contributing](#contributing)
- [Resources](#resources)
- [Related Repository Material](#related-repository-material)
- [Section Inventory and Maintenance](#section-inventory-and-maintenance)

## Guides in This Section

| Guide | Level | Focus |
|---|---|---|
| **[SDR Fundamentals](sdr.md)** | 🟢 Foundational | IQ sampling, SDR hardware, antennas, GNU Radio, demodulation, and application chapters on wireless and satellite signals. |
| **[HackRF RF Spectrum and Wireless Security Audits](hackrf.md)** | 🟡 Practical / Bench | Receive-chain validation, spectrum surveys, IQ captures, interference investigation, protocol triage, controlled bench testing, and reporting. |
| **[Sub-GHz RF Exploration and Protocol Engineering](subghz.md)** | 🟡 Practical / Bench | Device capture workflows, OOK/FSK analysis, protocol identification, transceiver selection, and capture logs; also includes selected 2.4 GHz topics. |
| **[RFID and NFC Exploration](rfid.md)** | 🟡 Practical / Bench | LF/HF tag identification, reader selection, supported authentication/key-recovery research, and authorized emulation or cloning workflows. |
| **[Advanced SDR Security Research](sdr_hacking.md)** | 🔴 Advanced | Signal reversing, wireless protocol security, firmware/baseband research, TEMPEST, and electromagnetic side-channel topics. |
| **[Target Frequencies & Protocols MASTER LIST](target_frequencies_protocols.md)** | 🟢 Reference / All Levels | Regional bands, exact channel tables, signal characteristics, hardware limits, decoder selection, and survey documentation. |
| **[NanoVNA Field Guide](nanovna/README.md)** | 🟢 Foundational → 🟡 Practical / Bench | Twelve chapters on H/H4 setup, calibration, antenna testing and tuning, cable/filter measurements, worked examples, and sweep comparison tools. |

> **Companion playbook:** [HackRFAuditPlayBook.md](../PlayBooks/HackRFAuditPlayBook.md) provides the engagement procedure in the PlayBooks section. Related HackRF material also exists in [hackrf.md](hackrf.md); contributors should keep shared procedures and references consistent.

## Choose a Starting Point

| What you need to do | Start here | Follow with |
|---|---|---|
| Check or tune an antenna, cable, or filter | [NanoVNA Field Guide](nanovna/README.md) | [Calibration](nanovna/03-calibration.md), then [antenna testing](nanovna/04-antenna-testing.md). |
| Learn SDR from the beginning | [sdr.md](sdr.md) | A known broadcast receive-chain check. |
| Identify a frequency or choose a decoder | [Master list](target_frequencies_protocols.md) | The relevant protocol guide and exact device documentation. |
| Survey a site or investigate interference | [hackrf.md](hackrf.md) | [HackRF Audit Playbook](../PlayBooks/HackRFAuditPlayBook.md). |
| Analyze an owned remote or wireless sensor | [subghz.md](subghz.md) | IQ/pulse analysis and supported device decoders. |
| Identify an authorized card or tag | [rfid.md](rfid.md) | A reader and antenna appropriate to that frequency and protocol. |
| Research an unfamiliar waveform or implementation | [sdr_hacking.md](sdr_hacking.md) | Controlled experiments and reproducible evidence. |
| Audit Wi-Fi frames, BLE traffic, or Thread/Zigbee | [Master list](target_frequencies_protocols.md) | A compatible protocol sniffer and network configuration. |

---

## Hardware Ecosystem

### SDR and RF Devices

| Device / family | Capabilities | Practical role and limits |
|---|---|---|
| **[NanoVNA-H / H4](nanovna/README.md)** | Vector network analyzer; S11 reflection and S21 transmission | Antenna match, cable and passive-filter measurements. Verify actual hardware/firmware coverage; not a spectrum analyzer or protocol receiver. |
| **[RTL-SDR Blog V3/V4](https://www.rtl-sdr.com/rtl-sdr-quick-start-guide/)** | Receive-only SDR | Broadcast, supported Sub-GHz telemetry, ADS-B, and other signals within the model's range. V3/V4 HF operation differs. Common RTL-SDR tuners do not directly reach 2.4 GHz. |
| **[HackRF One](https://hackrf.readthedocs.io/en/latest/hackrf_one.html)** | Half-duplex RX/TX; specified 1 MHz–6 GHz; up to 20 MS/s complex IQ | Spectrum surveys and waveform captures. Does not directly cover 125/134.2 kHz RFID, the full 6 GHz Wi-Fi band, or wide Wi-Fi channels. |
| **[Airspy](https://airspy.com/)** | Receive-only SDR family | Select the exact model for HF versus VHF/UHF work; coverage and bandwidth differ. |
| **[ADALM-Pluto](https://www.analog.com/en/resources/evaluation-hardware-and-software/evaluation-boards-kits/adalm-pluto.html)** | RX/TX SDR development platform | DSP and RF experiments within its specified range. Unofficial extensions are not guaranteed specifications. |
| **[bladeRF](https://www.nuand.com/), [USRP](https://www.ettus.com/), [LimeSDR](https://www.crowdsupply.com/lime-micro)** | SDR families with model-dependent RX/TX and duplex capabilities | Higher-bandwidth or synchronized research setups; verify the model, RF board, clocking, and host throughput. |
| **[Flipper Zero](https://docs.flipper.net/zero/sub-ghz)** | Sub-GHz packet functions plus separate LF/NFC features | Supported device and credential triage. It is not a general wideband IQ SDR; region, firmware, and protocol support matter. |
| **[YARD Stick One](https://greatscottgadgets.com/yardstickone/)** | Half-duplex Sub-GHz packet transceiver | Supported ASK/OOK/FSK/MSK-family work through rfcat. Official bands: 300–348, 391–464, and 782–928 MHz. It is not a general IQ receiver. |
| **Monitor-mode Wi-Fi / BLE / IEEE 802.15.4 adapters** | Protocol-specific reception | Often the best route to decoded frames. Verify chipset, driver, band, PHY, channel-following, and firmware support. |

**Tuning range is not decoding capability.** Seeing energy at a frequency does not mean the receiver can capture the whole waveform or that software can decode it. HackRF One's 20 MS/s limit represents approximately 20 MHz of nominal instantaneous complex-IQ span, with less useful bandwidth near filter edges. A sweeping survey is not simultaneous recording of the entire sweep range. See the [hardware and capture reference](target_frequencies_protocols.md).

### NFC and RFID Devices

| Device | Role | Limits to check |
|---|---|---|
| **[Proxmark3 / RRG firmware](https://github.com/RfidResearchGroup/proxmark3)** | LF/HF identification, capture, supported reading/writing, and emulation | Hardware revision, antenna tuning, firmware/client match, and exact protocol support. |
| **[Chameleon Ultra](https://github.com/RfidResearchGroup/ChameleonUltra)** | Supported LF/HF credential emulation and reader-side functions | Features depend on firmware and card type; do not assume universal tag support. |
| **[PN532](https://www.nxp.com/products/rfid-nfc/nfc-hf/nfc-readers/nfc-integrated-solution:PN5321A3HN) + [libnfc](https://github.com/nfc-tools/libnfc)** | Selected 13.56 MHz NFC/ISO 14443/FeliCa workflows | Not an LF or UHF reader; do not assume ISO 15693 support. NXP marks PN532 not recommended for new designs. |
| **[Flipper Zero](https://docs.flipper.net/)** | Supported LF credential and HF/NFC identification/emulation | Supported protocol and memory/authentication features vary by card. |
| **[iCopy-X](https://icopy-x.com/)** | Integrated workflows for supported credentials | Product/firmware-specific compatibility; not a guarantee of cloning arbitrary credentials. |
| **Regional UHF EPC reader** | Passive UHF tag inventory and interaction | Required regional channel plan, antenna, and EPC/ISO protocol support; LF/HF tools do not substitute for it. |

**Reading a UID does not reproduce an entire credential.** Protected applications can require keys, counters, or backend validation. A card reader also normally generates an RF field and sends commands even when it does not write tag memory. See [rfid.md](rfid.md).

---

## Software and Tool Categories

Tool roles below describe their intended function. They do not guarantee support for a particular signal, operating system, software version, or hardware combination.

### 1. Signal Capture and Discovery

| Tool | Role | Notes |
|---|---|---|
| **[Gqrx](https://gqrx.dk/) / [SDR#](https://airspy.com/download/)** | Spectrum display and supported audio demodulation | SDR# is the receiver application; SpyServer is a separate remote-server component. |
| **[rtl_433](https://github.com/merbanan/rtl_433)** | Supported sensor, remote, and telemetry decoding | Supports several bands and radio backends; not limited to 433 MHz. |
| **[dump1090](https://github.com/flightaware/dump1090)** | 1090 MHz Mode S / ADS-B reception | Does not decode 978 MHz UAT; use a suitable UAT decoder for that link. |
| **[Kismet](https://www.kismetwireless.net/docs/)** | Discovery and monitoring through supported data sources | Wi-Fi, Bluetooth, and SDR-related support depend on source hardware and helpers. |
| **[Kalibrate-RTL](https://github.com/steve-m/kalibrate-rtl)** | Estimate receiver frequency error using GSM signals | Requires suitable local signals and compatible software; not a general precision calibration guarantee. |
| **[gr-gsm](https://github.com/ptrkrysik/gr-gsm)** | GSM reception and analysis tools | Verify the chosen branch/package and GNU Radio compatibility. It is not accurately described as a turnkey IMSI catcher. |

### 2. Waveform and Protocol Analysis

| Tool | Role |
|---|---|
| **[Universal Radio Hacker](https://github.com/jopohl/urh)** | Waveform inspection, demodulation, bit extraction, and protocol investigation. |
| **[inspectrum](https://github.com/miek/inspectrum)** | Visual IQ analysis and timing measurements. |
| **[GNU Radio](https://www.gnuradio.org/)** | DSP flowgraphs, filtering, demodulation, and custom processing; a hardware sink can transmit. |
| **[Wireshark](https://www.wireshark.org/docs/)** | Supported packet dissection after a compatible capture/decoder pipeline. |
| **[Baudline](https://www.baudline.com/)** | Time/frequency analysis; check platform and input-format support. |

Record the sample rate, center frequency, signed/unsigned representation, bit depth, I/Q order, gain, and software versions with each capture. Incorrect import settings can produce misleading results.

### 3. Controlled RF and Cellular Research

| Resource | Actual role | Assessment boundary |
|---|---|---|
| **[HackRF host tools](https://hackrf.readthedocs.io/en/latest/hackrf_tools.html)** | Hardware control, IQ reception/transmission, and spectrum sweeps | Select receive operations deliberately; validate any transmit path before enabling it. |
| **[srsRAN Project](https://github.com/srsran/srsRAN_Project) / [srsRAN 4G](https://github.com/srsran/srsRAN_4G)** | Distinct open-source cellular stacks with different components and radio-generation support | Use the matching documentation and an authorized test network. These are not simply “IMSI catcher frameworks.” |
| **[GPS-SDR-SIM](https://github.com/osqzss/gps-sdr-sim)** | Generate GPS simulation IQ for receiver research | File generation is separate from RF transmission; any hardware test requires an appropriately controlled setup. |
| **[RollJam research](https://samy.pl/rolljam/)** | Case study in weaknesses affecting some rolling-code implementations | Not a universal rolling-code bypass or a routine field-test procedure. |
| **[FCC jammer guidance](https://www.fcc.gov/enforcement/areas/jammers)** | Regulatory reference on prohibited jammer use | This is guidance, not a software tool or an assessment workflow. |

Use the host-tool documentation and the [controlled bench procedure](../PlayBooks/HackRFAuditPlayBook.md) to distinguish firmware components from the commands used for capture and testing.

### 4. NFC and RFID Analysis

| Tool / family | Role | Important qualification |
|---|---|---|
| **[Proxmark3 / RRG](https://github.com/RfidResearchGroup/proxmark3)** | Supported LF/HF analysis, reading, emulation, and security research | Features are protocol-specific; do not assume success from the frequency alone. |
| **[libnfc](https://github.com/nfc-tools/libnfc), [mfoc](https://github.com/nfc-tools/mfoc), [mfcuk](https://github.com/nfc-tools/mfcuk)** | NFC access and particular MIFARE Classic/Crypto1 research workflows | Distinct projects with different prerequisites; applicability depends on card behavior and reader support. |
| **mfkey-family utilities in compatible RFID toolchains** | Recover candidate MIFARE Classic keys from suitable authentication data | Required nonce/authentication data differs by variant; “one sniffed transaction always yields a key” is incorrect. |
| **[Chameleon Ultra](https://github.com/RfidResearchGroup/ChameleonUltra)** | Supported credential emulation and reader testing | A reproduced UID does not establish that protected application authentication will succeed. |

See [rfid.md](rfid.md) for the detailed workflows and [the master list](target_frequencies_protocols.md) for LF/HF/UHF distinctions.

---

## Target Frequencies and Protocols

### [📡 Target Frequencies & Protocols MASTER LIST](target_frequencies_protocols.md)

The completed master reference contains:

- LF/HF RFID, NFC, UHF EPC, broadcast, amateur, marine, aviation, and weather entries.
- Sub-GHz remotes, telemetry, LoRa/LoRaWAN, Z-Wave, and other building/industrial networks.
- Exact Wi-Fi, BLE, and IEEE 802.15.4 channel tables with regional qualifications.
- Cellular, DECT, GNSS, satellites, drones/Remote ID, UWB, and microwave-system references.
- Capture bandwidth guidance, decoder selection, an evidence ladder, and a survey worksheet.

**Interpretation rules:** Distinguish channel centers from band edges, standardized assignments from device examples, and active services from historical ones. Frequency alone does not identify a protocol, manufacturer, device, or security weakness. LoRa is not synonymous with LoRaWAN; Matter has no dedicated RF frequency.

The list marks NOAA-15/18/19 APT entries as historical following their 2025 retirement. It does not establish which transmitters are active at your location; consult current operator and device records.

---

## Safe Workflows

### Receive and Analyze

1. Define the question, authorized scope, and permitted data handling before capturing.
2. Match the receiver, antenna, filters, bandwidth, and decoder to the signal.
3. Validate reception using a known reference or controlled device event.
4. Capture the necessary data and record settings, time, and limitations.
5. Separate observed energy, candidate protocol, validated decode, device attribution, and demonstrated security findings.
6. Minimize incidental private data; redact identifiers, keys, and sensitive location information before publishing.

No decoded output can mean the wrong channel, unsupported PHY, weak signal, overload, or a missed burst. It does not establish that the device was silent.

### Before Any Transmission or Active Device Test

- [ ] Confirm the exact device/system, permitted actions, test window, and responsible owner.
- [ ] Identify the applicable regulatory basis, equipment requirements, band, power, bandwidth, and operating conditions.
- [ ] Use simulated/file-based processing where it answers the question; keep hardware transmit sinks disabled during setup.
- [ ] For contained RF tests, calculate attenuation and receiver input levels and validate containment at the test frequencies.
- [ ] Check bias-tee voltage, antenna/filter connections, and stop conditions.
- [ ] Avoid interference with unrelated systems; do not radiate disruptive test signals into operational networks.
- [ ] Log test settings, observations, and the restoration of normal operation.

An ISM band, low transmit power, device ownership, or a Faraday bag does not by itself establish permission or adequate containment. A dummy load reduces radiation from its connected RF port; cables, enclosures, and other paths can still leak.

**Receiver protection:** HackRF One documentation specifies a maximum input of **−5 dBm**. Design an appropriate margin and attenuation arrangement; never connect a transmitter directly to an SDR input without checking the power budget. [Manufacturer specifications](https://hackrf.readthedocs.io/en/latest/hackrf_one.html).

### Before Credential Interaction

- [ ] Confirm authorization from the relevant credential/system owner and the exact permitted operations.
- [ ] Identify the tag's frequency, protocol, and application before choosing a tool.
- [ ] Use lab readers and test credentials for writes, emulation, and authentication experiments.
- [ ] Keep operations away from production doors, payment systems, and identity systems unless specifically authorized under an appropriate specialist engagement.
- [ ] Protect dumps, keys, identifiers, and transaction traces as sensitive data.

Read-only memory access can still involve RF transmissions or sensitive information. Do not assume it is appropriate merely because the tool can perform it.

## Security and Legal Boundaries

**Regulatory baseline: United States.** Other jurisdictions can have different reception, transmission, equipment, privacy, and access-control requirements.

| Activity | Boundary |
|---|---|
| Operating a transmitter | Some compliant operations are allowed without an individual license; others require a license or other authorization. Part 15 is conditional, not unrestricted spectrum access. |
| Using an amateur license | A license applies within its service privileges and rules; it does not authorize arbitrary cellular, aviation, commercial, or other transmissions. |
| Receiving, decoding, storing, or sharing traffic | These are separate activities. Unencrypted traffic is not automatically public or unrestricted; applicable exceptions and privacy rules matter. |
| Jamming or disrupting communications | FCC guidance prohibits jammer use by the public. Ownership of nearby equipment or property does not create a general exemption. |
| Testing credentials or access systems | Authorization must cover the credential, relevant system, and intended operation. Possession of a card does not necessarily authorize duplication or access-system testing. |
| Aviation, GNSS, emergency, medical, or other operational systems | Do not introduce disruptive signals. Specialist research requires appropriate authorization and an engineered test environment. |

Sources: [FCC Part 15 rules](https://www.ecfr.gov/current/title-47/chapter-I/subchapter-A/part-15), [amateur service rules](https://www.ecfr.gov/current/title-47/chapter-I/subchapter-D/part-97), [FCC jammer guidance](https://www.fcc.gov/enforcement/areas/jammers), and [18 USC § 2511](https://uscode.house.gov/view.xhtml?req=%28title%3A18%20section%3A2511%29).

This README does not assign blanket criminal classifications, fine amounts, or prison terms to technical activities. Legal consequences depend on the conduct, applicable law, authorization, and other facts. Wi-Fi deauthentication is a protocol-layer action and is not technically identical to RF noise jamming, although either can cause disruption.

### Repository Terms and Warranty Notice

See [LEGAL.md](../LEGAL.md) for repository-wide terms. The materials are provided **as is**, without a guarantee of compatibility, accuracy, hardware safety, or suitability for an engagement. Documentation is not a substitute for current regulations or qualified advice on a specific legal question. This README's review does not validate every legal claim elsewhere in the repository.

---

## Contributing

Contributions should be reproducible, properly sourced, and suitable for education or authorized research.

**Welcome contributions:**

- DSP explanations and GNU Radio examples with documented input/output behavior.
- Receive-only decoders and public or permission-cleared sample captures.
- Defensive RF, interference, and credential-identification workflows.
- Antenna, filter, coupling, and receiver-protection documentation.
- Corrections to frequency tables, regional notes, compatibility, and retired services.

**Submission requirements:**

- State hardware, firmware, software versions, dependencies, and tested limitations.
- Mark transmit-capable examples clearly and keep transmission disabled by default.
- Cite primary sources for frequencies, specifications, and regulatory claims.
- Include authorization assumptions and data-handling requirements where relevant.
- Validate relative links and update this index when adding or renaming a guide.
- Use synthetic or redacted evidence; exclude real keys, credential dumps, and private traffic without permission to publish.

**Not accepted in this section:** deployable jamming/disruption payloads, malicious cellular interception deployments, vehicle-theft workflows, or payment/passport/eID cloning tooling. These are repository contribution boundaries, not a claim that every conceivable research activity has the same legal status.

## Resources

### RF Rules and Specifications

- [FCC radio spectrum allocation guidance](https://www.fcc.gov/engineering-technology/policy-and-rules-division/general/radio-spectrum-allocation).
- [FCC Part 15](https://www.ecfr.gov/current/title-47/chapter-I/subchapter-A/part-15) and [Part 97](https://www.ecfr.gov/current/title-47/chapter-I/subchapter-D/part-97).
- [ARRL amateur licensing information](https://www.arrl.org/getting-licensed).
- [NFC Forum technology overview](https://nfc-forum.org/learn/nfc-technology/).
- [GS1 EPC Gen2 specification](https://ref.gs1.org/standards/gen2/).
- [Master-list primary references](target_frequencies_protocols.md#17-primary-references) for protocol-specific authorities.

### Learning and Implementation References

- [Great Scott Gadgets SDR course](https://greatscottgadgets.com/sdr/).
- [HackRF documentation](https://hackrf.readthedocs.io/en/latest/).
- [GNU Radio tutorials](https://wiki.gnuradio.org/index.php/Tutorials).
- [RTL-SDR setup guide](https://www.rtl-sdr.com/rtl-sdr-quick-start-guide/).
- [Signal Identification Wiki](https://www.sigidwiki.com/wiki/Signal_Identification_Guide) — community waveform examples; corroborate identification with primary documentation and captures.
- [Proxmark3 RRG documentation](https://github.com/RfidResearchGroup/proxmark3/wiki).

## Related Repository Material

| Resource | Relationship |
|---|---|
| [Main repository](../README.md) | Top-level navigation. |
| [START HERE](../START_HERE.md) | General learning and navigation guidance. |
| [Cybersecurity Master Guide](../ultimate_cybersecurity_master_guide.md) | Broader security reference. |
| [HackRF Audit Playbook](../PlayBooks/HackRFAuditPlayBook.md) | Field/bench engagement procedure. |
| [Network Audit Playbook](../PlayBooks/NetworkAuditPlayBook.md) | Network assessment context. |
| [Hardware Hacking](../HardwareHacking/README.md) | Embedded systems, interfaces, and hardware investigation. |
| [Space Security](../SpaceSecurity/README.md) | Satellite and navigation-security context. |
| [Documentation index](../Documentation/README.md) | Additional tool and platform guides. |
| [Bruce firmware](../Documentation/bruce_firmware.md) | Supported embedded RF workflows; external radio hardware determines capabilities. |
| [Flipper Zero guide](../Documentation/flipper_zero_guide.md) | Supported Sub-GHz and LF/HF device workflows. |
| [Repository terms](../LEGAL.md) | Repository-wide terms and use requirements. |

## Section Inventory and Maintenance

| Item | Current inventory |
|---|---|
| Guide entries linked from this index | **7:** six companion documents plus the [NanoVNA guide collection](nanovna/README.md). |
| Markdown files directly in `SDR/` | **7**, including this README; NanoVNA chapters are in the subdirectory. |
| NanoVNA collection | **12 chapters**, a section README, and a tools README in `SDR/nanovna/`. |
| External companion playbook | `PlayBooks/HackRFAuditPlayBook.md`. |
| Coverage | LF/HF RFID, Sub-GHz devices, wireless protocols, wideband SDR, and specialized higher-frequency topics; coverage depends on hardware. |
| Review scope | README inventory, navigation, tool descriptions, selected hardware specifications, and legal wording. Companion guides remain separate technical documents. |
| Last reviewed | September 15, 2026; NanoVNA navigation and inventory added September 18, 2026. |
| Maintainer | [Pacific Northwest Computers / Pnwcomputers](https://github.com/Pnwcomputers). |

**Maintenance note:** Update counts when adding or removing files. Recheck upstream compatibility and service status before relying on older examples. A guide's presence in this index does not establish that every command or security claim in it has been independently validated.

---

<div align="center">

**Learn the signal. Verify the evidence. Respect the scope.**

[ULTIMATE CYBERSECURITY MASTER GUIDE](https://github.com/Pnwcomputers/ULTIMATE-CYBERSECURITY-MASTER-GUIDE) · [Pacific Northwest Computers](https://github.com/Pnwcomputers)

</div>
