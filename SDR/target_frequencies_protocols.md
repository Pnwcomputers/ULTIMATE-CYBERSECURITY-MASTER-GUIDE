# 📡 Target Frequencies & Protocols (MASTER LIST) _*Ongoing Work In Progress*_

**A practical frequency, protocol, and receiver reference for SDR and authorized wireless assessments.**

Part of the [ULTIMATE CYBERSECURITY MASTER GUIDE](../README.md) · [SDR section](README.md)

**Version:** 1.0 · **Prepared:** September 15, 2026  
**Regional baseline:** United States, with explicitly labeled international examples.  
**Scope:** Common signals, device families, and protocol identification starting points. This is a maintained reference, not an exhaustive worldwide allocation table or a list of confirmed local transmitters.

## 🎯 Purpose

Use this list to decide **where to look, what might be present, which receiver or decoder to use, and what additional evidence is needed**. It covers LF/HF identification, broadcast, amateur radio, aviation, marine, Sub-GHz devices, IoT networks, cellular, satellites, Wi-Fi, Bluetooth, and higher-frequency systems.

Frequency is a clue—not a protocol identification. Several unrelated protocols can share one frequency, and one protocol can operate on several bands. Device generation, region, firmware, channel configuration, and regulatory approval all matter.

## Contents

- [1. How to read this list](#1-how-to-read-this-list)
- [2. Receiver and hardware limits](#2-receiver-and-hardware-limits)
- [3. LF, HF, RFID, and NFC](#3-lf-hf-rfid-and-nfc)
- [4. Broadcast and amateur radio](#4-broadcast-and-amateur-radio)
- [5. Aviation, marine, weather, and land mobile](#5-aviation-marine-weather-and-land-mobile)
- [6. Sub-GHz remotes, sensors, and telemetry](#6-sub-ghz-remotes-sensors-and-telemetry)
- [7. LoRa, LoRaWAN, and building networks](#7-lora-lorawan-and-building-networks)
- [8. Wi-Fi, Bluetooth, and 2.4 GHz protocols](#8-wi-fi-bluetooth-and-24-ghz-protocols)
- [9. Cellular and DECT](#9-cellular-and-dect)
- [10. GNSS and satellite reception](#10-gnss-and-satellite-reception)
- [11. Drones, UWB, radar, and microwave systems](#11-drones-uwb-radar-and-microwave-systems)
- [12. Capture bandwidth and signal identification](#12-capture-bandwidth-and-signal-identification)
- [13. Decoder and analysis tool index](#13-decoder-and-analysis-tool-index)
- [14. Local survey worksheet](#14-local-survey-worksheet)
- [15. Common reference mistakes](#15-common-reference-mistakes)
- [16. Repository integration and maintenance](#16-repository-integration-and-maintenance)
- [17. Primary references](#17-primary-references)

## 1. How to read this list

| Label | Meaning |
|---|---|
| **Center** | A carrier or channel center; it does not describe the full occupied bandwidth. |
| **Range** | A band or search span; it does not mean every frequency is a valid channel. |
| **Example** | A common implementation or device frequency; confirm the particular model. |
| **Historical** | Useful for archived captures or older documentation; not an active reception recommendation. |
| **RX** | Receive/observe using an appropriate RF chain. This label does not establish legal permission to intercept communications. |
| **Dedicated** | A protocol-specific reader, receiver, or sniffer is usually more useful than raw SDR IQ. |
| **Variable** | Read the device documentation, standard, license, or configured channel plan before selecting a center or decoder. |

**Units:** 1 MHz = 1,000 kHz; 1 GHz = 1,000 MHz. Frequencies below are in **MHz unless another unit is shown**. Channel spacing, occupied bandwidth, receiver filter width, and sample rate are different quantities.

**Operating scope:** Begin with public broadcasts and your own devices. Obtain appropriate authorization for private system analysis. Reception, decoding, storage, disclosure, and transmission are separate activities with different rules. Device ownership or an amateur license does not authorize arbitrary transmissions in other services. Consult the [FCC allocation guidance](https://www.fcc.gov/engineering-technology/policy-and-rules-division/general/radio-spectrum-allocation) and applicable service rules; this reference is not a transmit permission table.

## 2. Receiver and hardware limits

| Hardware | Useful coverage or role | Material limits |
|---|---|---|
| **HackRF One** | Specified 1 MHz–6 GHz; half-duplex RX/TX; up to 20 MS/s complex IQ | About 20 MHz nominal instantaneous span, with less useful span near filter edges. It cannot capture a complete 80/160/320 MHz Wi-Fi channel, directly receive LF RFID, or cover the full 6 GHz Wi-Fi band. |
| **RTL-SDR Blog V4** | Receive-only; specified approximately 500 kHz–1.766 GHz, including HF through its internal conversion design | Does not directly reach 2.4 GHz Wi-Fi/BLE. Driver support and filters matter. Other RTL-SDR models have different lower-frequency behavior. |
| **Other SDRs: Airspy, SDRplay, Pluto, bladeRF, LimeSDR, USRP** | Select by the exact model's tuning range, usable bandwidth, dynamic range, and clock stability | A product family name does not establish its RF coverage. Unofficial tuning extensions are not guaranteed operating specifications. |
| **CC1101-based hardware** | Chip supports 300–348, 387–464, and 779–928 MHz | Three separate ranges, not continuous 300–928 MHz coverage. Board matching, antenna, firmware, and region can narrow support. No 2.4 GHz or LoRa PHY demodulation. |
| **Flipper Zero / Sub-GHz handhelds** | Supported Sub-GHz packet formats plus separate LF/NFC functions on applicable models | A recognized frequency does not imply supported decoding. Firmware cannot replace missing radio hardware. |
| **Proxmark3 / LF-HF readers** | LF/HF near-field card investigation | Use the appropriate antenna and protocol support. Not a general UHF EPC reader. |
| **PN532** | Selected 13.56 MHz ISO 14443A/B and FeliCa/NFC operations | No 125/134.2 kHz or UHF support; do not assume ISO 15693 support. Existing modules remain useful, but NXP marks PN532 not recommended for new designs. |
| **Monitor-mode Wi-Fi adapter** | 802.11 frames, beacons, channel metadata | Chipset, driver, OS, band, width, and monitor-mode support determine capture capability. |
| **BLE / 802.15.4 / Z-Wave sniffer** | Protocol-aware capture | Verify PHY, firmware, channel-following, and decryption support. One receiver may miss other channels. |
| **UHF RFID reader / UWB development kit** | Backscatter inventory or wideband ranging analysis | Dedicated hardware is generally required for practical protocol work. |

Sources: [HackRF One specifications](https://hackrf.readthedocs.io/en/latest/hackrf_one.html), [RTL-SDR Blog V4](https://www.rtl-sdr.com/rtl-sdr-blog-v4-dongle-initial-release/), [TI CC1101](https://www.ti.com/product/CC1101), [NXP PN532](https://www.nxp.com/products/rfid-nfc/nfc-hf/nfc-readers/nfc-integrated-solution:PN5321A3HN).

**Protect the receiver:** Verify the device's maximum RF input and any bias-tee voltage before connecting equipment. A nearby transmitter or RFID reader can overload a front end. Direct cable connections require a calculated attenuation arrangement, not just an SMA cable.

## 3. LF, HF, RFID, and NFC

Companion: [RFID & NFC guide](rfid.md). Reader-to-tag and tag-to-reader signaling are different; passive tags normally respond to a reader field rather than broadcasting continuously.

| Frequency / type | System or protocol family | RF / identification notes | Practical approach |
|---|---|---|---|
| **125 kHz — example** | EM4100/EM4102-style proximity credentials | Usually amplitude/load-modulated fixed identifiers; exact format varies | LF reader or Proxmark3; confirm frame format |
| **125 kHz — example** | HID Prox / AWID | Common implementations use FSK-related LF signaling | Dedicated LF decoding; distinguish RF framing from credential bit format |
| **125 kHz — example** | Indala | PSK-based LF family | LF hardware with explicit Indala support |
| **125 kHz class — variable** | Automotive immobilizer / passive-entry LF link | Model-specific energizing, wake-up, or challenge-response; LF may be only one part of a multi-radio system | Identify transponder and vehicle documentation first |
| **134.2 kHz — center** | ISO 11784/11785 animal identification | FDX-B and HDX differ in timing and response behavior | Compatible animal-tag reader; do not assume a 125 kHz reader supports both |
| **13.56 — center** | ISO/IEC 14443A | Reader ASK and tag load modulation; MIFARE Classic, Ultralight, NTAG, DESFire families | Identify chip/application; shared RF interface does not imply shared authentication |
| **13.56 — center** | ISO/IEC 14443B | Different Type B framing/modulation from Type A | Reader with explicit Type B support |
| **13.56 — center** | ISO/IEC 15693 / NFC-V | Vicinity tags; distinct protocol from ISO 14443 | ISO 15693-capable reader or suitable Proxmark3 workflow |
| **13.56 — center** | FeliCa / NFC-F | Common 212/424 kbit/s modes | NFC-F-capable reader |
| **13.56 — center** | ISO/IEC 18092 / NFC-DEP | Peer-to-peer NFC transport | Check device and OS support |
| **13.56 — center** | Contactless payment / ePassport / secure identity | Application protocols above the RF interface; cryptographic controls vary | Authorized test credentials and application-specific tools |
| **902–928 — US range** | Passive UHF EPC Gen2 / ISO/IEC 18000-63 | Reader interrogation and tag backscatter; FM0/Miller response coding | Regional UHF reader; SDR for waveform observation |
| **865–868 — European example range** | Passive UHF RFID | Channel and power rules vary; additional upper-band arrangements exist in some countries | Confirm country and reader region |

Protocol references: [NFC Forum technology](https://nfc-forum.org/learn/nfc-technology/), [TI LF transponder front end](https://www.ti.com/product/TMS3705), [RRG Proxmark3 implementation](https://github.com/RfidResearchGroup/proxmark3), [GS1 EPC Gen2](https://ref.gs1.org/standards/gen2/).

**UHF naming update:** Older documents often describe ISO/IEC 18000-63 as “860–960 MHz” or “18000-6C.” GS1's February 2026 Gen2 release 3.0.1 specifies **860–930 MHz**. Neither description permits using the entire span in one country. Read the exact standard revision and the local reader channel plan.

**Credential interpretation:** A UID is not a complete credential. NDEF is a data format, not a modulation. Wiegand commonly describes the reader-to-controller interface or credential format; it is not a universal LF RF protocol. A powered card read is an active interrogation, even if no card memory is changed.

## 4. Broadcast and amateur radio

| Frequency / type | System | Typical signal | Notes / tools |
|---|---|---|---|
| **60 kHz — center, North America** | NIST WWVB | Time code on a LF carrier | LF-capable receiver/loop; outside HackRF One's specified direct coverage |
| **540–1700 kHz — US channel-center span** | AM broadcast | AM, with digital hybrid modes on some stations | AM receiver; US centers normally spaced 10 kHz; 530 kHz also appears in travelers' information references |
| **2.5, 5, 10, 15, 20, 25 — centers** | NIST WWV | AM time announcements and reference signals | HF antenna; check station notices for service status |
| **2.5, 5, 10, 15 — centers** | NIST WWVH | AM time announcements and reference signals | Propagation determines reception |
| **Approximately 2–30 — search span** | HF broadcast and utility services | AM, SSB, digital data | This span includes many different services; use a station schedule and correct sideband |
| **88–108 — US range** | FM broadcast | Wide FM; stereo multiplex and optional RDS/RBDS | Typical first receive-chain check; select a known local station |
| **54–72, 76–88, 174–216, 470–608 — US TV ranges** | Terrestrial television | ATSC 1.0 8-VSB or ATSC 3.0 OFDM | 6 MHz RF channels; displayed/virtual channel can differ from RF channel |
| **174–240 — international example range** | DAB / DAB+ Band III | OFDM multiplexes | Country-specific blocks and actual deployments; not a US broadcast default |
| **1.8–2; 3.5–4; 7–7.3; 14–14.35 — US examples** | 160/80/40/20 m amateur bands | CW, SSB, digital modes | License class, subband, mode, and regional plans matter |
| **10.1–10.15; 18.068–18.168; 21–21.45; 24.89–24.99; 28–29.7 — US examples** | 30/17/15/12/10 m amateur bands | CW, SSB where permitted, digital modes | Use current band plans; these are not mode assignments |
| **50–54; 144–148; 222–225; 420–450 — US examples** | 6 m / 2 m / 1.25 m / 70 cm amateur bands | Analog FM, SSB, packet, digital voice | Local coordination and geographic restrictions can apply |
| **144.390 — North American example center** | APRS terrestrial packet | Commonly 1200 baud AFSK AX.25 over FM | Dire Wolf; other regions use other frequencies |
| **144.800 — European example center** | APRS terrestrial packet | Commonly 1200 baud AFSK AX.25 over FM | Verify local band plan |

Sources: [NIST station reference](https://www.nist.gov/pml/time-and-frequency-division/popular-links/time-frequency-z/time-and-frequency-z-u-w), [FCC allocations](https://www.fcc.gov/engineering-technology/policy-and-rules-division/general/radio-spectrum-allocation), [US amateur rules](https://www.ecfr.gov/current/title-47/chapter-I/subchapter-D/part-97), [ARRL band plans](https://www.arrl.org/band-plan), [WorldDAB technical information](https://www.worlddab.org/dab/technical-specifications), [ATSC standards](https://www.atsc.org/atsc-documents/).

## 5. Aviation, marine, weather, and land mobile

The entries below support reception planning and recognition. They are not laboratory transmit frequencies.

| Frequency / type | Service / protocol | Signal characteristics | Identification / workflow |
|---|---|---|---|
| **118–136.975 — common civil voice center span** | VHF aeronautical voice | AM; regional 25/8.33 kHz channel arrangements | Use published airport/service assignments; channel designator may differ from carrier frequency |
| **121.500 — center** | Civil aviation emergency | AM voice | Recognition only; never use as a test frequency |
| **131.550 — example center** | VHF ACARS | AM-carried MSK data, commonly 2400 bit/s | ACARS decoder; additional channels vary by region/network |
| **136.975 — example center** | VDL Mode 2 | D8PSK packet data | VDL2 decoder; channel use varies |
| **978 — center, US** | UAT ADS-B | Digital UAT link | dump978-compatible receiver; separate from 1090ES |
| **1090 — center** | Mode S / ADS-B extended squitter | Short pulse-position-modulated replies/squitters | dump1090/readsb; Mode S messages are not all ADS-B position reports |
| **156–162 approximately — marine search span** | Maritime VHF voice/data | NFM voice plus dedicated data channels | Consult national channel table; duplex sides differ |
| **156.800 — center** | Marine channel 16 | Distress, safety, and calling voice | Recognition only; do not use for bench testing |
| **156.525 — center** | Marine channel 70 DSC | Digital selective calling | DSC decoder; not a voice channel |
| **161.975 / 162.025 — centers** | AIS 1 / AIS 2 | GMSK, 9600 bit/s | AIS-catcher or equivalent; capture both channels when possible |
| **162.400–162.550 — seven exact centers below** | NOAA Weather Radio | FM voice; SAME alert headers | Good US receive-chain reference; station coverage varies |
| **151.820, 151.880, 151.940, 154.570, 154.600 — US centers** | MURS | Five channels; bandwidth requirements differ | Consult Part 95; not an arbitrary VHF allocation |
| **462/467 MHz channel groups — US** | FRS / GMRS | Primarily FM voice | Overlapping channel families but different equipment, licensing, and repeater rules |
| **26.965–27.405 — US channel-center span** | Citizens Band | AM, SSB, FM as supported and permitted | 40 defined channels with gaps; not a uniform unrestricted tuning grid |
| **Licensed VHF/UHF/700/800 MHz assignments — variable** | P25, DMR, NXDN, conventional FM | Narrowband digital/analog voice and control channels | Use licensed assignments and system configuration; trunking requires following channel grants |
| **Licensed paging channels — variable** | POCSAG / FLEX | FSK-family paging | Characterize only within authorized scope; unencrypted messages can still be private |
| **Regional licensed assignments — variable** | TETRA | Commonly 25 kHz channels; π/4-DQPSK in conventional TETRA modes | Not a single global “TETRA frequency”; dedicated receiver/software |

### NOAA Weather Radio exact centers

| Frequency (MHz) | Frequency (MHz) | Frequency (MHz) |
|---|---|---|
| 162.400 | 162.425 | 162.450 |
| 162.475 | 162.500 | 162.525 |
| 162.550 | — | — |

Use frequency values instead of assuming that different radios number their WX presets identically. Source: [NOAA Weather Radio](https://www.weather.gov/nwr).

### FRS / GMRS center groups

| Group | Centers (MHz) |
|---|---|
| Shared channels 1–7 | 462.5625, 462.5875, 462.6125, 462.6375, 462.6625, 462.6875, 462.7125 |
| Shared channels 8–14 | 467.5625, 467.5875, 467.6125, 467.6375, 467.6625, 467.6875, 467.7125 |
| Shared channels 15–22 / GMRS main outputs | 462.5500, 462.5750, 462.6000, 462.6250, 462.6500, 462.6750, 462.7000, 462.7250 |
| GMRS main repeater inputs | Corresponding main output +5 MHz; these are not FRS transmit channels |

Source: [47 CFR Part 95](https://www.ecfr.gov/current/title-47/chapter-I/subchapter-D/part-95). CTCSS/DCS “privacy codes” control squelch; they do not encrypt audio.

Further references: [FAA ADS-B FAQ](https://www.faa.gov/air_traffic/technology/adsb/faq), [USCG AIS FAQ](https://www.navcen.uscg.gov/ais-frequently-asked-questions), [USCG US VHF channels](https://www.navcen.uscg.gov/us-vhf-channel-information), [ACARS decoder](https://github.com/TLeconte/acarsdec), [VDL2 decoder](https://github.com/szpajder/dumpvdl2), [ETSI TETRA](https://www.etsi.org/technologies/tetra).

## 6. Sub-GHz remotes, sensors, and telemetry

Companion: [Sub-GHz guide](subghz.md). These are **device examples and search starting points**, not reliable brand identification from frequency alone. For a specific unit, check its label, FCC ID/grant, regional manual, and a repeatable capture.

| Frequency / region | Example device or protocol family | Likely waveform | Confirmation needed |
|---|---|---|---|
| **300 / 310 — legacy North American examples** | Selected garage/gate remotes | OOK/ASK | Model and encoder; different families use different carriers |
| **303.75–303.96 — model examples** | Selected ceiling-fan remotes | Short proprietary bursts | Exact transmitter model and measured center |
| **315 — North American example** | Remotes, RKE, some TPMS | OOK/ASK or FSK | Frequency does not distinguish fixed code, rolling code, or telemetry |
| **345 — North American example** | Honeywell/2GIG-compatible sensor families | Proprietary narrowband bursts | Sensor generation and supported decoder |
| **390 — North American example** | Selected garage-door systems | Proprietary burst signaling | Exact Security+ or other protocol version |
| **433.420 — example** | Somfy RTS | OOK, protocol-specific framing | Distinguish RTS from io-homecontrol and regional alternatives |
| **433.920 — common example** | Weather, doorbell, outlet, temperature, leak sensors | OOK/ASK or FSK | Decoder, checksum, and controlled device activation |
| **315 / 433.920 — model/region examples** | TPMS | Model-specific OOK/FSK telemetry | Sensor part number; a vehicle model may have different regional sensors |
| **315 / 390 and other model-specific carriers** | Garage remote protocol families | Fixed, rolling, or more complex formats | Do not assign Security+ 2.0 to every opener on these carriers |
| **433 MHz class / 868 MHz class — regional examples** | Alarm, door/window, occupancy sensors | OOK/FSK and proprietary protocols | Vendor model, firmware, and security generation |
| **868.300 — European example** | Wireless M-Bus S-mode and selected other modes | FSK; mode-dependent framing | Mode and direction; compare decoder documentation |
| **868.950 — European example** | Wireless M-Bus T/C-mode meter transmissions | FSK; mode-dependent encoding | Meter model, link mode, and authorized keys where applicable |
| **169 MHz class — European example** | Wireless M-Bus / metering variants | Narrowband FSK-family modes | Country, exact subchannel, and operating mode |
| **902–928 — US range** | ERT SCM/SCMplus/IDM and other utility telemetry | Protocol-specific FSK/hopping/bursts | Meter model, protocol generation, and channel pattern |
| **916.450 — model example** | Selected Badger ORION devices | FSK telemetry | Not a universal water-meter frequency |
| **433 / 868 / 915 MHz classes — regional examples** | Weather stations and industrial telemetry | OOK, FSK, LoRa, or other PHY | Region and hardware SKU; “weather station” is not a protocol |

The [rtl_433 project](https://github.com/merbanan/rtl_433) supplies a maintained decoder catalog and per-device implementations. Its name does **not** restrict it to 433 MHz. Source-level device definitions are useful evidence; a successful decoder guess should still be validated against repeats, integrity checks, and a known stimulus. Vendor-independent regional metering background: [Radiocrafts Wireless M-Bus](https://radiocrafts.com/products/wireless-m-bus/).

**Security interpretation:** A changing frame is not proof of strong cryptography; an identical frame is not proof that a receiver accepts replay. Record observations separately from conclusions. Consult the [HackRF audit workflow](hackrf.md) for controlled validation.

## 7. LoRa, LoRaWAN, and building networks

| Frequency / region | Family | Physical / channel notes | Capture / analysis approach |
|---|---|---|---|
| **902–928 — US902 plan envelope** | LoRaWAN | Regional uplink/downlink centers below; multiple data rates | LoRa decoder or gateway; capture direction and channel index |
| **863–870 — EU863 plan envelope** | LoRaWAN | Default channels below; network can configure additional channels | Match bandwidth, spreading factor, and region |
| **AU915 / AS923 / IN865 / KR920 / other plans** | LoRaWAN regional variants | Different channel arrangements and country rules | Read the named LoRa Alliance regional plan; “915 radio” is insufficient |
| **Regional LoRa bands — variable** | Raw LoRa | Chirp spread spectrum; not necessarily LoRaWAN | Match bandwidth, spreading factor, coding rate, sync word, and packet format |
| **902–928 US; regional EU433/EU868 settings** | Meshtastic | LoRa-based mesh, not LoRaWAN; preset and frequency slot determine RF center | Read configured region, preset, and slot; use owned-node logs |
| **908.42 / 916 MHz class — US examples** | Z-Wave mesh | Rate/channel-dependent FSK/GFSK | Z-Wave sniffer/controller; inspect actual region and data rate |
| **868.42 MHz class — European example** | Z-Wave mesh | Additional centers depend on rate and region | Do not copy the US channel plan |
| **912 / 920 — US LR centers** | Z-Wave Long Range | Different channel plan and topology from classic mesh | LR-capable diagnostic hardware |
| **868.3 EU / 902 North America / 928 Japan — product examples** | EnOcean | Region-specific low-power packet radios | Verify module generation and regional datasheet |
| **Regional Sub-GHz bands — variable** | Wi-SUN FAN / IEEE 802.15.4g | FSK/OFDM and other supported PHY options; hopping/channel plans vary | Compatible Wi-SUN tools and network configuration |
| **Regional Sub-GHz bands — variable** | Sigfox / mioty | Ultra-narrowband or telegram-splitting approaches | Use regional operator/module plan; not LoRaWAN |

### Selected LoRaWAN channel plans

| Plan / direction | Channel centers | Important distinction |
|---|---|---|
| US902 uplink, 125 kHz channels | **902.3 + 0.2 × n MHz**, n = 0…63 → 902.3…914.9 | 64 channel centers |
| US902 uplink, 500 kHz channels | **903.0 + 1.6 × n MHz**, n = 0…7 → 903.0…914.2 | 8 wider uplink centers |
| US902 downlink, 500 kHz channels | **923.3 + 0.6 × n MHz**, n = 0…7 → 923.3…927.5 | Different frequencies from uplink |
| EU863 default LoRa channels | **868.1, 868.3, 868.5** | Defaults, not the complete allowed channel set |
| EU863 default RX2 | **869.525** | Network configuration can override defaults |

Source: [LoRaWAN Regional Parameters RP002-1.0.5](https://resources.lora-alliance.org/technical-specifications/rp002-1-0-5-lorawan-regional-parameters). These are selected conventional LoRa channel arrangements, not the complete set of PHY options in the specification.

### Meshtastic configuration matters

The current documentation gives **906.875 MHz** for the US factory-default LongFast configuration and **869.525 MHz** for EU868 LongFast. Other presets, firmware, overrides, and channel-slot settings can change the center. Record the device configuration rather than treating a default as permanent. Source: [Meshtastic radio settings](https://meshtastic.org/docs/overview/radio-settings/).

Additional references: [Silicon Labs Z-Wave](https://www.silabs.com/wireless/z-wave), [Z-Wave Alliance LR](https://z-wavealliance.org/what-is-z-wave-long-range-and-how-does-it-differ-from-z-wave/), [EnOcean technical documentation](https://www.enocean.com/en/support/), [Wi-SUN Alliance](https://wi-sun.org/), [Sigfox radio configurations](https://build.sigfox.com/sigfox-radio-configurations-rc), [mioty Alliance technology](https://mioty-alliance.com/technology/).

## 8. Wi-Fi, Bluetooth, and 2.4 GHz protocols

### Protocol families

| Frequency / type | Protocol | Typical physical behavior | Practical analysis |
|---|---|---|---|
| **2.4 GHz band** | 802.11b/g/n/ax and supported newer Wi-Fi modes | DSSS/CCK or OFDM/OFDMA; channel width depends on mode | Monitor-mode adapter for frames; SDR for energy and waveform analysis |
| **Regional 5 GHz bands** | 802.11a/n/ac/ax and newer modes | OFDM/OFDMA; common widths 20/40/80/160 MHz | Country, DFS rules, and adapter support matter |
| **5925–7125 US band envelope** | 6 GHz Wi-Fi, including Wi-Fi 6E/7 | 20/40/80/160 MHz and supported 320 MHz modes | HackRF One covers only the bottom of this range; use 6 GHz-capable hardware |
| **2402–2480 channel centers** | Bluetooth BR/EDR | 79 1 MHz-spaced centers; hopping; GFSK and EDR phase modulation | Classic Bluetooth-aware tools; BLE-only sniffers are insufficient |
| **2402–2480 channel centers** | Bluetooth LE | 40 2 MHz-spaced centers; GFSK with PHY-dependent coding/rate | Primary advertising versus secondary advertising/connected traffic matters |
| **2405–2480 channel centers** | IEEE 802.15.4 2.4 GHz O-QPSK PHY | Channels 11–26; 5 MHz center spacing; 250 kbit/s | Compatible 802.15.4 sniffer; select correct channel |
| **Same 802.15.4 RF channels** | Zigbee | Network/application layers above 802.15.4 | Network keys and commissioning context for authorized payload analysis |
| **Same 802.15.4 RF channels** | Thread / 6LoWPAN | IPv6 mesh above 802.15.4 | Thread-aware decoder and network context |
| **Wi-Fi or Thread; BLE during commissioning** | Matter | Application protocol; no dedicated “Matter RF frequency” | Identify underlying transport first |
| **2.4 GHz band — model-dependent channels** | nRF24 / Enhanced ShockBurst-style peripherals | GFSK, short packets, possible hopping | Exact chip/protocol support; not ordinary BLE or Wi-Fi |
| **2.4 GHz band — profile-dependent** | ANT / ANT+ | Low-power GFSK channels | ANT-capable receiver and device profile |
| **2.4 GHz 802.15.4 channels** | WirelessHART / ISA100.11a | Scheduled/hopping industrial networks | Dedicated industrial tools and authorized network context |

Primary references: [Bluetooth LE physical layer](https://www.bluetooth.com/wp-content/uploads/Files/Specification/HTML/Core-54/out/en/low-energy-controller/physical-layer-specification.html), [Bluetooth LE link layer](https://www.bluetooth.com/wp-content/uploads/Files/Specification/HTML/Core-54/out/en/low-energy-controller/link-layer-specification.html), [NXP 802.15.4 coexistence reference](https://docs.nxp.com/bundle/AN14782/page/topics/coexistence.html), [Thread fundamentals](https://www.threadgroup.org/What-is-Thread/Overview), [CSA Matter](https://csa-iot.org/all-solutions/matter/), [Nordic Enhanced ShockBurst documentation](https://docs.nordicsemi.com/bundle/ncs-latest/page/nrf/protocols/esb/index.html).

### 2.4 GHz Wi-Fi channel centers

For channels 1–13: **center MHz = 2407 + 5 × channel**. Channel 14 is an exception.

| Channel | MHz | Channel | MHz |
|---|---|---|---|
| 1 | 2412 | 8 | 2447 |
| 2 | 2417 | 9 | 2452 |
| 3 | 2422 | 10 | 2457 |
| 4 | 2427 | 11 | 2462 |
| 5 | 2432 | 12 | 2467 |
| 6 | 2437 | 13 | 2472 |
| 7 | 2442 | 14 | 2484 |

US deployments normally use 1–11. Channels 12/13 depend on country; channel 14 is a Japan-specific legacy 802.11b case. Centers are only 5 MHz apart, so adjacent channels overlap. Always record channel width as well as channel number.

### Selected 5 GHz Wi-Fi centers

| Channel group | Centers (MHz), in matching order |
|---|---|
| 36 / 40 / 44 / 48 | 5180 / 5200 / 5220 / 5240 |
| 52 / 56 / 60 / 64 | 5260 / 5280 / 5300 / 5320 |
| 100 / 104 / 108 / 112 | 5500 / 5520 / 5540 / 5560 |
| 116 / 120 / 124 / 128 | 5580 / 5600 / 5620 / 5640 |
| 132 / 136 / 140 / 144 | 5660 / 5680 / 5700 / 5720 |
| 149 / 153 / 157 / 161 / 165 | 5745 / 5765 / 5785 / 5805 / 5825 |

These are selected 20 MHz primary centers. Regional availability, DFS, hardware, and use restrictions apply. This table intentionally does not imply that every channel is enabled in every country or that newer regional extensions are included.

### 6 GHz Wi-Fi centers

For the regular 20 MHz channel grid: **center MHz = 5950 + 5 × channel**, with channel indices **1, 5, 9, …, 233**. The separate channel-2 case at 5935 MHz is not covered by this formula.

| Example channel | Center (MHz) | HackRF One specified tuning coverage |
|---|---|---|
| 1 | 5955 | Center is within range |
| 5 | 5975 | Center is within range |
| 9 | 5995 | Center is within range, but the nominal 20 MHz channel extends above 6 GHz |
| 13 | 6015 | Outside range |
| 233 | 7115 | Outside range |

Country and device class determine permitted use. Do not extrapolate US availability to Europe or other regions. Reaching a center frequency also does not guarantee enough clean bandwidth to decode a full channel. Channel math can be cross-checked in the [Linux wireless frequency conversion implementation](https://github.com/torvalds/linux/blob/master/net/wireless/util.c); operating conditions come from [FCC Part 15](https://www.ecfr.gov/current/title-47/chapter-I/subchapter-A/part-15), not from the formula.

### Bluetooth LE primary advertising channels

| BLE channel | Center (MHz) |
|---|---|
| 37 | 2402 |
| 38 | 2426 |
| 39 | 2480 |

The remaining 37 RF channels support data and secondary advertising. **BLE logical channel numbers are not a simple ascending 2402 + 2 × channel mapping.** A capture on one advertising center does not cover all advertisements or a hopping connection. Source: [Bluetooth link layer channel arrangement](https://www.bluetooth.com/wp-content/uploads/Files/Specification/HTML/Core-54/out/en/low-energy-controller/link-layer-specification.html).

### IEEE 802.15.4 / Zigbee / Thread channel centers

For this 2.4 GHz PHY: **center MHz = 2405 + 5 × (channel − 11)**.

| Channel | MHz | Channel | MHz |
|---|---|---|---|
| 11 | 2405 | 19 | 2445 |
| 12 | 2410 | 20 | 2450 |
| 13 | 2415 | 21 | 2455 |
| 14 | 2420 | 22 | 2460 |
| 15 | 2425 | 23 | 2465 |
| 16 | 2430 | 24 | 2470 |
| 17 | 2435 | 25 | 2475 |
| 18 | 2440 | 26 | 2480 |

The broader IEEE 802.15.4 family also defines other bands and PHYs; this table is specifically the familiar 2.4 GHz O-QPSK channel set. Source: [NXP channel and coexistence reference](https://docs.nxp.com/bundle/AN14782/page/topics/coexistence.html).

## 9. Cellular and DECT

Cellular band edges define possible operating spectrum, not one carrier center or one provider. Verify the locally deployed RAT, channel number, channel bandwidth, duplex direction, and operator configuration. **DL** = base station to user equipment; **UL** = user equipment to base station.

### Selected 5G NR FR1 bands

All ranges below are in MHz. These are standard band definitions, not claims that each band is deployed locally.

| NR band | UL | DL | Duplex |
|---|---|---|---|
| n2 | 1850–1910 | 1930–1990 | FDD |
| n5 | 824–849 | 869–894 | FDD |
| n12 | 699–716 | 729–746 | FDD |
| n25 | 1850–1915 | 1930–1995 | FDD |
| n41 | 2496–2690 | Same range | TDD |
| n48 | 3550–3700 | Same range | TDD |
| n66 | 1710–1780 | 2110–2200 | FDD |
| n71 | 663–698 | 617–652 | FDD |
| n77 | 3300–4200 | Same range | TDD |
| n78 | 3300–3800 | Same range | TDD |
| n79 | 4400–5000 | Same range | TDD |

Source: [3GPP TS 38.101-1 / ETSI V19.3.1, section 5.2](https://www.etsi.org/deliver/etsi_ts/138100_138199/13810101/19.03.01_60/ts_13810101v190301p.pdf). NR band numbers are not Wi-Fi channels. FDD needs separate UL/DL coverage; TDD alternates direction in time. A HackRF One sweep can reveal activity but does not establish subscriber identity, encryption state, or full network configuration.

| System | Frequency selection | RF / practical notes |
|---|---|---|
| GSM / EDGE | Regional operator band and ARFCN | GMSK / 8PSK; a historical assignment does not prove an active network |
| UMTS / WCDMA | Operator band and UARFCN | Wideband CDMA; many deployments have been retired |
| LTE / LTE-M / NB-IoT | E-UTRA band, EARFCN, and deployment mode | LTE uses OFDMA/SC-FDMA; LTE-M and NB-IoT are cellular technologies, not 915 MHz LoRa variants |
| 5G NR | NR band, NR-ARFCN, bandwidth, and subcarrier spacing | Wideband OFDM-family signals; FR1 is not synonymous with “below 6 GHz” |
| 5G NR FR2 | Exact licensed millimeter-wave band | Outside direct HackRF One coverage; specialized RF conversion and bandwidth required |
| **DECT, Europe: 1880–1900 MHz** | Regional carrier plan | Legacy DECT uses TDMA/TDD and commonly GFSK |
| **DECT 6.0, US: 1920–1930 MHz** | US UPCS plan | “6.0” is a product designation, not a 6 GHz frequency |
| DECT NR+ | Exact regional plan and implementation | Different PHY from legacy cordless DECT; do not reuse a legacy decoder blindly |

Use operator-authorized test networks and captures for private cellular analysis. References: [3GPP specifications](https://www.3gpp.org/specifications-technologies/specifications-by-series), [ETSI DECT group](https://www.etsi.org/technical-groups/dect/), [US DECT spectrum specification](https://www.etsi.org/deliver/etsi_ts/102400_102499/102497/01.01.01_60/ts_102497v010101p.pdf), [DECT technical overview](https://www.etsi.org/deliver/etsi_tr/103000_103099/103089/01.01.01_60/tr_103089v010101p.pdf).

## 10. GNSS and satellite reception

| Frequency / type | System | Signal / reception notes | Practical approach |
|---|---|---|---|
| **1575.420 — center** | GPS L1 / Galileo E1 | Spread-spectrum signals; multiple signal components share the center | GNSS receiver or GNSS-SDR with appropriate antenna/filter |
| **1227.600 — center** | GPS L2 | Spread-spectrum navigation signals | Compatible multiband front end |
| **1176.450 — center** | GPS L5 / Galileo E5a | Wider spread-spectrum components than legacy GPS L1 C/A | Adequate receiver bandwidth and supported signal acquisition |
| **1207.140 — center** | Galileo E5b | Spread-spectrum | Compatible GNSS front end |
| **1278.750 — center** | Galileo E6 | Multiple services/components | Signal-specific receiver support and service access |
| **137 MHz class — mission-dependent** | Polar-orbiting weather downlinks, including LRPT missions | Digital weather imagery; center, waveform, and mission status vary | Current mission data, pass prediction, Doppler correction, SatDump |
| **137.620 / 137.9125 / 137.100 — historical** | NOAA-15 / NOAA-18 / NOAA-19 APT | Legacy analog image downlinks | Archived-capture exercises only; satellites retired in 2025 |
| **1694.100 — center** | GOES HRIT/EMWIN | BPSK weather-data broadcast | Directional antenna/dish, filter/LNA, compatible decoder; verify active spacecraft |
| **145 / 435 MHz amateur satellite segments — variable** | Amateur spacecraft telemetry, voice, packet | Mission-specific FM, SSB, FSK, BPSK, and other modes | Confirm downlink versus uplink, schedule, orbit, and mode |
| **L/S/C/Ku/Ka bands — mission-specific** | Satellite communications and data | Narrowband or wideband digital links | Identify exact downlink, polarization, beam, and receiver/converter requirements |

GNSS signals can be below the apparent noise floor of an ordinary waterfall. A missing visible peak is not evidence of missing GNSS reception. Interference investigation should combine spectrum observations with receiver C/N₀, acquisition/tracking status, antenna checks, and timestamps.

**NOAA APT status:** NOAA-18 was passivated June 6, 2025; NOAA-19 was decommissioned August 13, 2025; NOAA-15 followed August 19, 2025. Do not present those three as active beginner reception targets. Source: [NOAA POES retirement announcement](https://www.nesdis.noaa.gov/news/legacy-orbit-noaa-decommissions-the-poes-satellite-constellation).

References: [ESA GPS signal plan](https://gssc.esa.int/navipedia/index.php/GPS_Signal_Plan), [ESA Galileo signal plan](https://gssc.esa.int/navipedia/index.php/Galileo_Signal_Plan), [GOES-R HRIT/EMWIN](https://www.goes-r.gov/users/hrit.html), [SatDump documentation](https://docs.satdump.org/), [AMSAT satellite status](https://www.amsat.org/status/).

## 11. Drones, UWB, radar, and microwave systems

| Frequency / range | System | Identification notes | Hardware implication |
|---|---|---|---|
| **2.4 GHz; selected Wi-Fi implementations also use 5 GHz** | Broadcast Remote ID / Open Drone ID | BLE advertising and Wi-Fi Beacon/NAN transports; distinct from control/video links | Compatible BLE/Wi-Fi receiver and Remote ID decoder |
| **Regional 868/915 MHz and 2.4 GHz hardware variants** | ExpressLRS | Hopping control/telemetry; PHY depends on hardware and packet mode | Match firmware, region, radio chip, and configured mode |
| **2.4 / 5 GHz classes — model-specific** | Proprietary drone control/video | May be OFDM or other proprietary waveforms | A Wi-Fi-like spectrum does not establish ordinary 802.11 compatibility |
| **5.8 GHz class — model-specific** | Analog FPV video | Wide FM video on a selected transmitter channel | Receiver channel tables vary; some product channels lie outside locally permitted use |
| **6.5 / 8 GHz class — common channel families** | IEEE 802.15.4z UWB / FiRa ranging | Very wide impulse-radio channels; channel 5/9 support is common in DW3000-family hardware | Outside HackRF One's specified coverage; dedicated UWB kit |
| **24 GHz / 60 GHz / 76–81 GHz classes — product-specific** | Presence, industrial, and automotive radar | Often FMCW/chirp or other radar waveforms | Millimeter-wave equipment; not a generic Sub-GHz decoder task |
| **60 GHz class** | WiGig / 802.11ad/ay | Directional multi-GHz-wide channels | Dedicated 60 GHz hardware |
| **Frequency varies with electronics and clocks** | Unintentional emissions / EMC / EM leakage | Harmonics, switching noise, broadband emissions | Near-field probes and controlled source correlation; no universal “TEMPEST frequency” |

Sources and implementation references: [Open Drone ID](https://github.com/opendroneid/opendroneid-core-c), [FAA Remote ID](https://www.faa.gov/uas/getting_started/remote_id), [ExpressLRS hardware selection](https://www.expresslrs.org/hardware/hardware-selection/), [Qorvo DW3110 UWB](https://www.qorvo.com/products/p/DW3110), [TI millimeter-wave radar sensors](https://www.ti.com/sensors/mmwave-radar/overview.html).

A Remote ID message is an identification broadcast, not proof that a device can be controlled or that the broadcast contents are authentic. Absence of a decoded message can reflect receiver limitations, channel coverage, range, or protocol support.

## 12. Capture bandwidth and signal identification

### Starting points for receive filters

These are **engineering starting ranges**, not legal emission limits or guaranteed decoder settings. Begin wide enough to see the complete signal, then adjust from measured occupied bandwidth and decoder requirements.

| Signal class | Typical receive/filter starting point | Caution |
|---|---|---|
| CW / narrow HF data | Hundreds of Hz to a few kHz | Doppler, drift, and mode affect the required width |
| SSB voice | About 2.4–3 kHz | Correct sideband and tuning reference required |
| AM voice/broadcast | About 6–15 kHz | Match modulation and interference environment |
| Narrow FM voice | About 10–20 kHz | Deviation and channel spacing are not interchangeable |
| Broadcast FM with stereo/RDS | About 180–250 kHz | Narrow filters can discard stereo/data components |
| OOK/FSK sensor bursts | Tens to hundreds of kHz; some wider | Bit rate, deviation, pulse shaping, and oscillator error matter |
| LoRa | Match configured bandwidth, often 125/250/500 kHz | These are common examples; narrower and other modes exist |
| AIS | Per-channel filter appropriate to its 25 kHz channel | A wider IQ capture can contain both AIS centers, 50 kHz apart |
| BLE | PHY-dependent, roughly MHz-scale | Hopping and extended advertising require channel-aware capture |
| 2.4 GHz 802.15.4 O-QPSK | Roughly 2 MHz-class signal | Leave acquisition/filter margin |
| Wi-Fi | Full configured 20/40/80/160/320 MHz channel | Select hardware with sufficient usable bandwidth, not merely tuning range |
| GNSS | Signal-dependent, from a few MHz to much wider | Acquisition processing and front-end design are critical |

For complex IQ, sample rate describes the **nominal total captured span**, not twice that span. Keep the desired signal inside the receiver's usable filter passband. For example, 2 MS/s complex IQ nominally spans about 2 MHz, with practical edge loss. Real-only sampling has different Nyquist and representation considerations.

### Evidence ladder

1. **Energy observed:** Record time, center, span, gain, antenna, and repeatability.
2. **Waveform characterized:** Measure occupied bandwidth, burst duration, symbol timing, and hopping behavior.
3. **Protocol candidate:** Compare framing and modulation against a documented implementation.
4. **Decode validated:** Require plausible fields, integrity checks where available, and repeat observations.
5. **Device attributed:** Correlate with an owned device's controlled event, configuration, label, or logs.
6. **Security conclusion tested:** Record what was actually demonstrated separately from assumptions about the protocol family.

Waterfall clues are suggestive: OOK often appears as keyed bursts, FSK as multiple frequency states, LoRa as chirps, and OFDM as a broad block. None is unique enough to establish a vendor, device identity, or vulnerability on its own.

**Sweep limitations:** Sweeps sample different frequencies at different times. They can miss short transmissions and cannot substitute for continuous IQ on a selected channel. “No activity observed” must include the observation window, dwell, receiver sensitivity, antenna, and channel coverage.

## 13. Decoder and analysis tool index

Check current project documentation, installed version, input sample format, and hardware support. These are workflow choices, not claims that every tool is installed or every mode has been tested with every SDR.

| Task / protocol | Tools to investigate | Evidence produced |
|---|---|---|
| Spectrum and audio | SDR++, Gqrx, SDR# | Spectrum, audio, selected IQ captures |
| Unknown OOK/FSK/proprietary bursts | URH, inspectrum, GNU Radio | Pulse/symbol timing, candidate frames |
| Supported sensor/remote telemetry | rtl_433 | Structured decoded fields and protocol candidates |
| 1090 MHz ADS-B | readsb, dump1090 | Mode S / ADS-B messages |
| 978 MHz UAT | dump978 | UAT messages |
| AIS | AIS-catcher | AIS messages / NMEA output |
| APRS / AX.25 | Dire Wolf | AX.25 packets |
| ACARS / VDL2 | acarsdec, dumpvdl2 | Aviation data messages within permitted scope |
| Unencrypted authorized digital voice | OP25, supported DSD-family tools | Mode-dependent decoded traffic; no automatic decryption |
| Satellite imagery / telemetry | SatDump; mission-specific tools | Decoded mission products |
| GNSS receiver research | GNSS-SDR plus receiver diagnostics | Acquisition/tracking measurements and navigation solutions |
| Wi-Fi | Monitor-mode adapter, Wireshark, Kismet | 802.11 frames and network metadata |
| BLE | Compatible Sniffle / vendor sniffer, Wireshark | Supported advertising/connection captures |
| Zigbee / Thread | Compatible 802.15.4 sniffer, Wireshark | MAC/network frames; keys may be needed above MAC |
| Z-Wave | Vendor diagnostic sniffer / controller logs | Region/mode-specific frames and network events |
| LoRaWAN | Compatible gateway or PHY decoder and server logs | PHY/MAC observations; authorized keys for payloads |
| LF/HF cards | Proxmark3; protocol-compatible readers | Tag identification and authorized transaction data |
| UHF EPC | Regional UHF reader and vendor diagnostics | Inventory and tag interaction records |
| Remote ID | Open Drone ID-compatible receiver/dissector | Broadcast identity/location messages |

Core project sources: [GNU Radio](https://www.gnuradio.org/), [URH](https://github.com/jopohl/urh), [inspectrum](https://github.com/miek/inspectrum), [rtl_433](https://github.com/merbanan/rtl_433), [readsb](https://github.com/wiedehopf/readsb), [dump978](https://github.com/flightaware/dump978), [AIS-catcher](https://github.com/jvde-github/AIS-catcher), [Dire Wolf](https://github.com/wb2osz/direwolf), [GNSS-SDR](https://gnss-sdr.org/), [Wireshark](https://www.wireshark.org/docs/), [Kismet](https://www.kismetwireless.net/docs/), [Sniffle](https://github.com/nccgroup/Sniffle).

## 14. Local survey worksheet

For a Vancouver/Portland or other local survey, populate this from actual station listings, licensed assignments, owned-device records, and measurements. Do not substitute a generic band table for local attribution.

```yaml
record_id: RF-YYYYMMDD-001
observed_at_utc: ""
location_label: ""          # Avoid publishing private site coordinates
country_region: "US-WA"
scope_reference: ""
device_make_model: ""
device_regulatory_id: ""
frequency_type: "center"    # center | range | example | historical
center_hz: null
observed_span_hz: null
occupied_bandwidth_hz: null
protocol_candidate: "unknown"
modulation_candidate: "unknown"
channel_and_direction: ""   # e.g. BLE 37; LoRaWAN UL; cellular DL
receiver_model: ""
receiver_serial_or_label: ""
antenna_filter_lna: ""
sample_rate_sps: null
sample_format: ""          # Record signed/unsigned, bit depth, I/Q order
gain_settings: ""
clock_ppm_correction: null
capture_duration_seconds: null
capture_file: ""
sha256: ""
decoder_and_version: ""
integrity_checks: ""
controlled_event: ""
confidence: "energy_only"  # waveform | candidate | decoded | attributed
source_url_and_revision: ""
limitations: ""
retention_and_redaction: ""
```

Use the [NOAA station listing](https://www.weather.gov/nwr/station_listing), relevant FAA publications, the device's regulatory records, and authorized network/controller configuration to build a local list. An address, SSID, callsign, or device ID in a decode may be stale or spoofed; corroborate attribution.

## 15. Common reference mistakes

| Mistake | Correct interpretation |
|---|---|
| “433.92 MHz means KeeLoq / garage remote.” | Many unrelated devices use that center. Decode and verify the specific frame. |
| “915 MHz is one protocol channel.” | It is often a regional band label; actual centers and hopping plans differ. |
| “All modern remotes use KeeLoq.” | Authentication and framing are vendor-, generation-, and model-specific. |
| “LoRa equals LoRaWAN.” | LoRa is a PHY family; LoRaWAN and Meshtastic are different higher-level systems. |
| “Zigbee, Thread, and Matter are interchangeable.” | Zigbee and Thread can share a PHY; Matter uses supported IP transports. |
| “A CC1101 covers every frequency from 300 to 928 MHz.” | Its supported ranges have gaps; module hardware can narrow them further. |
| “An RTL-SDR can receive Wi-Fi directly.” | Common RTL-SDR tuners do not reach 2.4 GHz. |
| “HackRF One covers 6 GHz Wi-Fi.” | Only the lowest part of the band is within its specified tuning range. |
| “20 MS/s lets me decode any Wi-Fi channel.” | Tuning range and clean instantaneous bandwidth are separate requirements. |
| “An ISM band permits arbitrary transmission.” | Regional device, emission, power, channel-access, and other rules still apply. |
| “No decoder output means no transmitter.” | Wrong PHY, gain, bandwidth, channel, timing, or unsupported framing can cause silence. |
| “Unencrypted means public.” | Private communications can be unencrypted. Permission and data handling still matter. |
| “NFC read-only means receive-only.” | A reader generally generates a field and sends commands even without writing memory. |
| “A visible carrier proves weak security.” | Security conclusions require protocol and system evidence. |
| “NOAA-15/18/19 APT are current live targets.” | Those missions ended in 2025; use the frequencies for historical references. |

## 16. Repository integration and maintenance

### Companion guides

| File | Use alongside this list |
|---|---|
| [SDR index](README.md) | Section navigation and hardware ecosystem |
| [SDR fundamentals](sdr.md) | IQ, demodulation, antennas, and receiver theory |
| [HackRF guide](hackrf.md) | Survey, capture, interference analysis, and reporting |
| [HackRF Audit Playbook](../PlayBooks/HackRFAuditPlayBook.md) | End-to-end engagement procedure |
| [Sub-GHz guide](subghz.md) | Device captures and proprietary protocol investigation |
| [RFID guide](rfid.md) | LF/HF reader and tag workflows |
| [Advanced SDR guide](sdr_hacking.md) | Deeper waveform and protocol research in an authorized lab |

**Suggested repository path:** `SDR/target_frequencies_protocols.md`

Replace the planned entry in `SDR/README.md` with:

```markdown
- [Target Frequencies & Protocols MASTER LIST](target_frequencies_protocols.md)
```

Add this row to the existing guide table:

```markdown
| **[Target Frequencies & Protocols MASTER LIST](target_frequencies_protocols.md)** | 🟢 Reference / All Levels | Regional frequency tables, channel mappings, protocol identification, receiver limits, decoder selection, and survey logging |
```

### Maintenance rules

- Add a source and a region to every new numeric frequency entry.
- Distinguish exact assignments, implementation examples, and broad search spans.
- Record device model/firmware for proprietary protocols; avoid universal brand claims.
- Recheck active satellite, broadcast, cellular, and regional regulatory status before field use.
- Keep historical entries labeled; never silently imply that a retired service is active.
- Record decoder version and capture evidence before claiming protocol support or device attribution.
- Change this version/date when updating the reference and explain material changes below.

| Version | Date | Changes |
|---|---|---|
| 1.0 | 2026-09-15 | Initial master reference; regional channel tables, receiver constraints, protocol distinctions, historical NOAA APT labeling, and companion-guide links. |

## 17. Primary references

Sources appear beside the relevant tables. Use these authorities when resolving a conflict:

| Question | Preferred source |
|---|---|
| Is operation permitted in this country and service? | National regulator and applicable current service rules; [FCC](https://www.fcc.gov/engineering-technology/policy-and-rules-division/general/radio-spectrum-allocation), [eCFR](https://www.ecfr.gov/current/title-47), and [CEPT/ECC](https://docdb.cept.org/) for relevant European materials |
| What is this exact transmitter certified to do? | Device regulatory grant, manufacturer manual, region/SKU, and firmware configuration |
| What is the normative protocol/channel plan? | Bluetooth SIG, IEEE, 3GPP/ETSI, LoRa Alliance, NFC Forum, GS1, and the relevant protocol organization |
| What can the receiver actually capture? | Manufacturer specifications for the exact model and a validated receive chain |
| Is this station or spacecraft currently active? | Operator status notices and current mission/station records |
| Does this decoder support the observed format? | Current upstream implementation, release notes, and validated captures |

**Verification boundary:** This reference combines standards-based channel definitions, documented device examples, and engineering guidance. It does not claim live RF measurements, local transmitter verification, certification, or end-to-end testing of every listed hardware/software combination. Where a regional or device-specific record disagrees with a generic example here, investigate and update the example rather than forcing the observation to match it.
