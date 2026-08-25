# 💳 RFID & NFC Access Control Exploration & Card Engineering Guide
<div align="center">

**Manual for LF/HF proximity card capture, transponder reverse engineering, and access-control security testing at 125 kHz and 13.56 MHz**
*Part of the [ULTIMATE CYBERSECURITY MASTER GUIDE](../README.md)*

![RFID](https://img.shields.io/badge/Hardware-RFID_%26_NFC-blue?style=for-the-badge&logo=nfc)
![Frequencies](https://img.shields.io/badge/Frequencies-125kHz_%26_13.56MHz-green?style=for-the-badge&logo=contactlesspayment)
![Proxmark3](https://img.shields.io/badge/Software-Proxmark3-orange?style=for-the-badge)
![Protocols](https://img.shields.io/badge/Focus-Card_Cloning_%26_Crypto1-red?style=for-the-badge)
</div>

---

## 🎯 Purpose
Comprehensive bench manual for RFID/NFC access-control exploration - covering educational theory, low- and high-frequency card capture procedures, laboratory logging documentation, key-recovery software pipelines, and transponder architecture breakdowns for physical access, contactless payment, and asset-tracking systems.
## ⚙️ Function
Walks through the full read-to-clone workflow across the major toolsets (Proxmark3, Flipper Zero, Chameleon Ultra, PN532/libnfc, iCopy-X), then into Proxmark3 client operation, reader chip selection (PN532 vs. EM4095/LF front-ends), coupling/tuning troubleshooting, key-recovery pipelines (mfoc, mfcuk, hardnested, mfkey32/64), a master card/protocol reference matrix, a transponder profiles dictionary, and a standardized logging template.
## 🏆 Goal
Serve as the practical, repeatable reference for authorized RFID security testing - taking a card from unknown frequency and chipset all the way to a documented, validated protocol breakdown and (where legally permitted on hardware you own) a verified clone, safely and legally.
## 📋 When to Use
- Identifying an unknown proximity card by operating frequency and chipset
- Choosing the right reader hardware and attack path for a target credential
- Reverse engineering a fixed-ID vs. cryptographically-protected credential during an authorized assessment
- Documenting a reproducible read/crack session for a physical-access security audit

---

## 📋 Table of Contents
- [Educational Foundations](#-1-educational-foundations)
- [Core Principles of RFID & NFC](#-2-core-principles-of-rfid--nfc)
- [Core RFID/NFC Protocol Concepts](#-3-core-rfidnfc-protocol-concepts)
- [Hardware Specific Operations & Flowcharts](#-4-hardware-specific-operations--flowcharts)
- [Entry-Level Proxmark3 Client Guide](#-5-entry-level-proxmark3-client-guide)
- [Dedicated Reader Chips: PN532 vs. EM4095/LF Front-Ends](#-6-dedicated-reader-chips-pn532-vs-em4095lf-front-ends)
- [Troubleshooting: Coupling, Detuning & Failed Reads](#-7-troubleshooting-coupling-detuning--failed-reads)
- [Post-Processing & Key-Recovery Pipeline](#-8-post-processing--key-recovery-pipeline)
- [Master Card & Protocol Reference Matrix](#-9-master-card--protocol-reference-matrix)
- [Transponder Profiles Dictionary](#-10-transponder-profiles-dictionary)
- [Laboratory Protocol Logging Template](#-11-laboratory-protocol-logging-template)
- [Example Project: Safe Access Card Analysis](#-12-example-project-safe-access-card-analysis)
- [⚠️ CRITICAL Security & Legal Warning](#️-critical-security--legal-warning)
- [Resources](#-resources)

---

### 🔴 CRITICAL WARNING

```
⚠️ CLONING ACCESS CREDENTIALS IS HEAVILY REGULATED ⚠️
Many procedures in this manual can involve CLONING physical credentials,
EMULATING captured card data, or WRITING recovered keys onto blank transponders.
Using a cloned credential to enter premises you are not authorized to enter is a
SERIOUS CRIME - regardless of how the card data was obtained.
YOU MUST have explicit written authorization from the credential/property owner,
work only on cards and readers you own or are contracted to test, and keep all
cloning and emulation confined to your bench before you read, write, or emulate.
Improper use violates:
• Computer Fraud and Abuse Act (CFAA) - unauthorized access to protected systems
• State burglary-tool possession and trespassing statutes
• Payment card fraud statutes (EMV / contactless payment cloning)
• Identity theft and access-device fraud laws (18 U.S.C. § 1029)
READ-ONLY analysis on credentials you own is the default. Do NOT read, clone, or
emulate cards you do not own or are not explicitly authorized to test.
```

---

## 🎓 1. Educational Foundations
**The "Who, What, When, and Why" of RFID Analysis.**
### What Is It?
RFID (Radio Frequency Identification) analysis is the systematic reading, recording, and interpretation of the short-range electromagnetic exchanges between a reader and a passive transponder. In the Low-Frequency (LF) spectrum (125–134 kHz), credentials are mostly simple, unencrypted identifiers energized by inductive coupling and read from a few centimeters away. In the High-Frequency (HF) spectrum (13.56 MHz), transponders run structured, sometimes cryptographic protocols (ISO 14443, ISO 15693, FeliCa, NFC) that carry sectored memory, mutual authentication, and NDEF data.

### Who Uses It?
| Role | Application |
|------|-------------|
| **Access Control Engineers** | Validate credential provisioning, reader compatibility, and enrollment workflows against spec |
| **Security Auditors / Red Teams** | Evaluate whether a facility relies on cloneable fixed-ID cards or broken ciphers vulnerable to duplication |
| **Physical Penetration Testers** | Assess badge-cloning exposure and tailgating/credential-capture risk during authorized engagements |

### When Is It Conducted?
- **During Product R&D:** To verify custom readers and enrollment tools write and read credentials exactly as specified.
- **During Security Assessments:** To audit whether a badge population uses legacy fixed-ID or broken-cipher technology.
- **During Migration Planning:** When an organization moves from LF prox or MIFARE Classic to secure HF credentials (DESFire EV3, SEOS) and needs to inventory what is currently deployed.

### Why Is It Critical?
A credential is only as strong as the transponder behind it. Unlike a password, a physical card is presented in the open and can be read at a distance by anyone with the right coil. Understanding how transponders are energized, addressed, authenticated, and parsed is the only path toward selecting and deploying access-control technology that actually resists duplication.
---

## 📡 2. Core Principles of RFID & NFC
- **Inductive Coupling:** Passive transponders have no battery. The reader's antenna generates an alternating field that energizes the tag's coil; the tag replies by load-modulating (backscattering) that same field. Read range is a function of coil tuning and field strength, not transmit power in the SDR sense.
- **Two Distinct Bands:** LF (125–134 kHz) offers short range and good penetration of non-metallic materials with simple, mostly unencrypted protocols. HF (13.56 MHz) offers higher data rates, sectored memory, and cryptographic options, but shorter range and more sensitivity to detuning by metal and the human body.
- **Encoding & Modulation:** LF credentials typically use Manchester, Biphase, or PSK encoding on an ASK/OOK-modulated subcarrier. HF ISO 14443A uses Miller/Manchester coding with a 847.5 kHz subcarrier; ISO 15693 uses a longer-range "vicinity" scheme.
- **Security Categories:** Credentials generally fall into three tiers:
  - **Fixed ID (read-only):** The transponder returns the same static identifier every time (e.g., EM4100, HID Prox). Trivially cloneable.
  - **Broken Cipher:** A once-proprietary cryptographic scheme that has since been publicly defeated (e.g., MIFARE Classic Crypto1, legacy HID iCLASS). Keys are recoverable in seconds to minutes.
  - **Strong Cipher:** Modern authenticated schemes using AES/3DES (e.g., MIFARE DESFire EV2/EV3, MIFARE Plus, SEOS). Not duplicable without the diversified keys.

---

## 🧩 3. Core RFID/NFC Protocol Concepts
To thoroughly analyze contactless credentials, it is essential to understand the memory layouts and authentication models running on target transponders.
### Fixed-ID Transponders (e.g., EM4100, HID Prox)
Fixed-ID architectures broadcast a static identifier the instant they enter a reader's field. There is no memory to write, no key to present, and no challenge-response. Because the identifier never changes and there is no cryptographic verification, any ID read out of the field can be written to a blank writable transponder (like a T5577) and will be accepted indefinitely. They dominate legacy building access and many older parking and elevator systems.
### Sector-Authenticated Transponders (e.g., MIFARE Classic / Crypto1)
MIFARE Classic divides memory into sectors, each guarded by two 48-bit keys (A and B) and access-condition bits. Reading or writing a block requires authenticating to that sector's key using the proprietary Crypto1 stream cipher. Crypto1 has been publicly broken for over a decade: weaknesses in its nonce generation and authentication allow keys to be recovered with the *darkside*, *nested*, and *hardnested* attacks, or extracted from a single sniffed reader-to-card transaction via *mfkey*. Once keys are known, the full card contents can be dumped and rewritten onto a "magic" (Gen1/Gen2) card.
### Strongly-Authenticated Transponders (e.g., MIFARE DESFire, SEOS, iCLASS SE)
Modern credentials use standardized, peer-reviewed ciphers - typically AES-128 or 3DES - with mutual authentication and per-card diversified keys. Applications live in isolated files with their own access rights. Without the master and application keys (which never leave the reader/HSM in a properly deployed system), the card cannot be authenticated to, read, or cloned. Reverse engineering here focuses on the *deployment* (weak key diversification, default keys left in place, keys leaked in reader firmware) rather than the cipher itself.

---

## 🔨 4. Hardware Specific Operations & Flowcharts
### Hardware Capability Overview
| Device | Capabilities | Best For | Risk Level |
|--------|--------------|----------|------------|
| **[Proxmark3 RDV4 / Easy](https://proxmark.com/)** | LF + HF (Read/Write/Sniff/Emulate) | Full LF+HF analysis, key recovery, cloning, sniffing | 🔴 HIGH |
| **[Flipper Zero](https://flipper.net/)** | LF (125 kHz) + HF (13.56 MHz) | Field triage, card ID, fixed-ID emulation | 🟡 MEDIUM |
| **[Chameleon Ultra](https://github.com/RfidResearchGroup/ChameleonUltra)** | HF + LF emulation | Card emulation, MIFARE/NTAG spoofing on the bench | 🟡 MEDIUM |
| **[PN532 + libnfc](https://github.com/nfc-tools/libnfc)** | HF (13.56 MHz Read/Write) | Budget MIFARE Classic cracking (mfoc/mfcuk) | 🟡 MEDIUM |
| **[iCopy-X](https://icopy-x.com/)** | LF + HF (automated clone) | One-touch field cloning of common credentials | 🔴 HIGH |

---

### 📌 Proxmark3 (Reference Bench Tool)
**Best For:** Complete LF and HF analysis, key recovery, sniffing live transactions, and writing verified clones.
```text
                      [ START ]
                          |
            1. Run 'hw tune' (verify antennas)
                          |
            2. Place card flat on antenna
                          |
             ---> [ Identify Band ]
            |             |
            |    3. Try 'lf search' (125 kHz)
            |             |
            |    4. If nothing: 'hf search' (13.56 MHz)
            |             |
            |    5. Read chipset / protocol ID
            |             |
            |             v
  (No/weak read?) -- [ Evaluate Read Quality ]
            |             |
           YES            | NO (Clean read)
            |             v
            |      [ Determine Security Tier ]
            |             |
            |             +---> (Strong Cipher) --> [ STOP: Not duplicable ]
            |             |
            |             +---> (Broken Cipher) --> [ Recover keys -> dump ]
            |             |
            +-------------+---> (Fixed ID)      --> [ Clone to T5577/magic card ]
```

#### Detailed Execution Steps
1. **Verify the Antennas:** In the Proxmark3 client run `hw tune`. Confirm the LF antenna reports a healthy voltage around 125 kHz and the HF antenna a healthy voltage around 13.56 MHz before trusting any "no card found" result.
2. **Determine the Band:** Place the card flat and centered on the correct antenna.
   - *Run `lf search`:* Auto-detects common 125 kHz credentials (EM4100, HID Prox, Indala, AWID, HITAG, T55xx).
   - *Run `hf search`:* Auto-detects 13.56 MHz credentials (ISO 14443A/B, ISO 15693, iCLASS, FeliCa, Topaz).
3. **Fingerprint the Chipset:** For HF, follow up with `hf 14a info` to read the ATQA/SAK/UID and identify the exact chip (MIFARE Classic 1K/4K, Ultralight, NTAG, DESFire). For LF, note the reported protocol and raw ID.
4. **Recover or Read:**
   - *Fixed ID (LF):* No keys needed - proceed to cloning.
   - *Broken cipher (MIFARE Classic):* Run `hf mf autopwn` to attempt the full key-recovery + dump chain automatically.
5. **Security Tier Check:** If the card is DESFire/SEOS/MIFARE Plus (SL3) and authentication fails with no default keys, **stop** - the credential is not duplicable and any read attempt should be logged and reported, not brute-forced.

---

### 📌 Flipper Zero (Standalone Portability)
**Best For:** Quick field triage, rapid card identification, and basic fixed-ID emulation.
```text
                      [ START ]
                          |
            1. Open 'RFID 125 kHz' or 'NFC'
                          |
            2. Hold Flipper flat to the card
                          |
             ---> [ Read Card ]
            |             |
            |       3. Select 'Read'
            |             |
            |       4. Wait for chipset ID
            |             |
            |       5. Save card to SD
            |             |
            |             v
    (No read?) ---- [ Evaluate Capture ]
            |             |
           YES            | NO (Card identified)
            |             v
            |      [ Determine Security Tier ]
            |             |
            |             +---> (MIFARE Classic) -> [ Read keys / dump if known ]
            |             |
            |             +---> (DESFire/secure) -> [ STOP: UID read only ]
            |             |
            +-------------+---> (EM4100/Prox)    -> [ Emulate on bench ]
```

#### Detailed Execution Steps
1. **Pick the Band:** From the main menu choose `125 kHz RFID` for LF prox cards or `NFC` for 13.56 MHz credentials. Choosing the wrong app will read nothing even from a valid card.
2. **Choose the Capture Mode:**
   - *`Read`:* Auto-detects the card technology and stores the identifier/data.
   - *`Read` (NFC):* Attempts ISO 14443A detection; for MIFARE Classic it will try a bundled dictionary of common keys and report which sectors it could open.
3. **Position and Read:** Hold the Flipper's antenna flat against the card. Keep it still - HF reads in particular fail if the card slips out of the coupling zone mid-read.
4. **Save and Inspect:** Save the card to the SD card. Inspect the resulting file: an LF card stores a raw ID; an NFC card stores UID plus any recovered sectors. A DESFire or MIFARE Plus SL3 card will store only the UID and metadata.
5. **Security Tier Check:** Only emulate on your own bench readers. A recovered UID alone is not a clone of a secure credential - do not present it against production access control.

---

### 📌 PN532 + libnfc (Affordable HF Cracking)
**Best For:** Budget MIFARE Classic key recovery and dumping on a workstation.
**Lab Procedures:**
- **Card Identification:** With a PN532 breakout on USB/UART, run `nfc-list` to confirm the reader sees the card and to print the UID, ATQA, and SAK.
- **Key Recovery (offline nonces):** Run `mfoc -O dump.mfd` to launch the *nested* attack, which recovers unknown sector keys given at least one known key (default dictionaries usually supply one). For cards where no key is known, run `mfcuk` to execute the *darkside* attack first, then feed the recovered key into `mfoc`.
- **Dump & Rewrite:** Once keys are recovered, `nfc-mfclassic r a dump.mfd` reads the full card, and `nfc-mfclassic w` writes it to a compatible magic card on the bench.

```
⚠️ mfoc/mfcuk are for MIFARE Classic ONLY. They rely on the broken Crypto1
   cipher and will not touch DESFire, Ultralight C, or MIFARE Plus SL3 cards -
   nor should recovered dumps be written to any credential you do not own.
```

---

### 📌 Chameleon Ultra (Emulation Specialist)
**Best For:** Bench-side emulation of captured cards to validate reader behavior without a physical clone.

```text
                           [ START ]
                               |
                1. Connect to Chameleon (CLI/App)
                               |
                2. Select an emulation slot
                               |
            +------------------+------------------+
            v                                     v
     [ A. HF Path ]                        [ B. LF Path ]
            |                                     |
   3a. Load MIFARE/NTAG dump              3b. Load EM4100/HID ID
            |                                     |
   4a. Set UID + block data              4b. Set raw ID + protocol
            |                                     |
   5a. Present to bench reader           5b. Present to bench reader
            |                                     |
            v                                     v
     [ Observe reader accept/reject ]     [ Observe reader accept/reject ]
```

#### Detailed Execution Steps
1. **Interface Initialization:** Connect the Chameleon Ultra via USB-C or BLE to its companion CLI/app. Confirm the firmware version and the number of available emulation slots.
2. **Load a Captured Credential:** Import a previously captured dump (`.mfd`/`.bin`) or a raw LF identifier into a free slot. Set the UID and, for HF, the block data and access bits.
3. **Emulate Against Your Own Reader:** Present the Chameleon to a **bench reader you own**. Watch whether the reader accepts the emulated credential - this validates whether the captured data constitutes a working clone or only a partial read.
4. **Document the Result:** Record which slot, which credential, and whether the emulation was accepted. This is your evidence for the assessment report; it is not a license to present the emulation against production systems.

---

### 📌 iCopy-X (Automated Cloner)
**Best For:** Consolidated one-touch reading and writing of common LF and HF credentials on the bench.

```text
                           [ START ]
                               |
               1. Boot iCopy-X to Main Menu
                               |
               2. Select Auto Mode / Manual Mode
                               |
         +---------------------+---------------------+
         v                     v                     v
   [ A. LF Clone ]        [ B. HF Clone ]       [ C. Sniff/ID ]
         |                     |                     |
   3a. Read source card   3b. Read source card   3c. Read chipset
         |                     |                     |
   4a. Recover ID         4b. Recover keys        4c. Report tech
         |                     |                     |
   5a. Write to T5577     5b. Write to magic card       |
         v                     v                     v
   [ Verify Clone ]      [ Verify Clone ]      [ Output Report ]
```

### Detailed Execution Steps
1. **Boot and Mode Select:** Power on the iCopy-X and choose Auto Mode for common credentials or Manual Mode for step-by-step control over identification, key recovery, and writing.
2. **Read the Source (your card):** Place the credential you own on the coupling area. The device identifies the technology and, for MIFARE Classic, attempts its bundled key dictionary and nested attack.
3. **Write to a Blank:** Place a compatible blank (T5577 for LF, magic Gen1/Gen2 for HF MIFARE) and write. The device reports success/failure per sector.
4. **Verify:** Re-read the newly written blank and compare it byte-for-byte to the source. An automated cloner still needs manual verification before you trust the result in a report.

---

## 🛠️ 5. Entry-Level Proxmark3 Client Guide
The Proxmark3 client (Iceman/RRG firmware) is the reference environment for LF/HF work. Below is the baseline blueprint for a **read-identify-clone LF workflow** and the equivalent HF key-recovery workflow.

### Command Architecture Setup
Run the following commands in sequence inside the `pm3>` client prompt:
1. **Health Check:** `hw tune` - confirm the LF antenna peaks near 125 kHz and the HF antenna near 13.56 MHz. A detuned antenna is the #1 cause of false "no card" results.
2. **LF Auto-Identify:** `lf search` - place the card on the LF antenna. The client sweeps common demodulators and reports the protocol (e.g., `EM410x ID: 0F00...`).
3. **LF Chipset Detect:** `lf t55xx detect` - determines whether the card is a writable T5577 (a common clone target) versus a read-only factory tag.
4. **HF Auto-Identify:** `hf search` then `hf 14a info` - reads ATQA/SAK/UID and names the exact HF chip.
5. **MIFARE Classic Recovery:** `hf mf autopwn` - runs the full chain (dictionary → darkside → nested/hardnested → dump) and writes recovered keys and card contents to a local file.

### Writing a Verified Clone (hardware you own)
- **LF (EM4100 → T5577):** `lf em 410x clone --id <ID>` writes the recovered identifier onto a blank T5577.
- **HF (MIFARE Classic → magic card):** `hf mf restore` (or `hf mf cload`) writes a recovered dump onto a compatible magic card.
- **Verify every write:** Re-run `lf search` / `hf mf dump` on the newly written blank and diff it against the source before recording the clone as successful.

```
💡 TIP: Run 'hf 14a info' and 'lf search' on a KNOWN blank first to learn what a
   clean, empty transponder looks like before you interpret a real target.
```

---

## 🔌 6. Dedicated Reader Chips: PN532 vs. EM4095/LF Front-Ends
When building custom lab readers or low-cost enrollment stations, these front-end chips serve distinct bands and purposes.

### 📡 PN532 (The 13.56 MHz HF Agile Front-End)
- **Multi-Protocol HF:** Handles ISO 14443A/B, FeliCa, and NFC peer-to-peer / card-emulation modes from a single module over I²C, SPI, or UART.
- **libnfc Native:** First-class support in `libnfc`, making it the go-to for `nfc-list`, `mfoc`, `mfcuk`, and `nfc-mfclassic` on a workstation or Raspberry Pi.
- **Custom Enrollment Terminals:** Wired to an Arduino/ESP32 with Adafruit or Elechouse drivers to build MIFARE/NTAG read-write stations and NDEF kiosks.

### 📡 EM4095 / RDM6300 (The 125 kHz LF Read Specialist)
- **Legacy Prox Reading:** The EM4095 is an analog LF front-end that couples to a 125 kHz coil and hands raw Manchester/Biphase pulses to a microcontroller; the RDM6300 is a cheap pre-baked EM4100 reader module.
- **Fixed-ID Capture:** Ideal for reading EM4100/EM4102 and similar read-only tags into a serial logging window for inventory or enrollment.
- **Custom LF Sniffers:** Wired to an Arduino/ESP32 to timestamp and log tag IDs as they enter the field - the basis of many DIY access loggers.

### Reader Front-End Matrix
| Feature | PN532 Module | EM4095 / RDM6300 Module |
| :--- | :--- | :--- |
| **Frequency** | 13.56 MHz (Fixed HF) | 125 kHz (Fixed LF) |
| **Protocol Support** | ISO 14443A/B, FeliCa, NFC P2P/emulation | EM4100-class Manchester/Biphase read |
| **Read/Write** | **Read + Write + Emulate** | **Read-only** (front-end) |
| **Primary Lab Target** | MIFARE Classic/Ultralight/NTAG, DESFire (auth) | EM4100/EM4102 legacy prox tags |
| **Toolchain** | libnfc (mfoc, mfcuk, nfc-mfclassic) | Arduino/ESP32 serial logging |

---

## 🧯 7. Troubleshooting: Coupling, Detuning & Failed Reads
When reading passive transponders, poor coupling and antenna detuning cause most failures - not "broken" cards. Use these baseline checks before concluding a card is unreadable.

### ⚠️ Weak Coupling / No Read
- **The Symptom:** `lf search` / `hf search` reports no card even though you are holding a valid credential.
- **The Cause:** The card is off-center, tilted, too far from the coil, or (for HF) sitting on a metal surface that spoils the field.
- **The Fix:** Lay the card flat and centered directly on the antenna. Remove the card from any metal surface or wallet, and re-run `hw tune` to confirm the antenna itself is healthy before blaming the card.

### ⚠️ Antenna Detuning (Low Tune Voltage)
- **The Symptom:** `hw tune` reports an LF or HF peak voltage well below the expected healthy range, and reads are intermittent.
- **The Cause:** A damaged, wrong, or poorly-seated antenna, nearby metal, or a coil resonating away from 125 kHz / 13.56 MHz.
- **The Fix:** Reseat the correct antenna, move away from metal and other coils, and confirm the tune peaks near 125 kHz (LF) and 13.56 MHz (HF). Only trust read results once the antenna tunes cleanly.

## ⚠️ Frequency Band Mismatch
- **The Symptom:** A card reads on one tool but not another, or returns nothing regardless of positioning.
- **The Cause:** Presenting an LF (125 kHz) card to an HF (13.56 MHz) reader/app or vice-versa - the two bands are physically incompatible.
- **The Fix:** Confirm the band before reading: try LF and HF searches in turn, and on multi-app tools (Flipper) select the matching `125 kHz RFID` vs `NFC` application. Dual-frequency cards contain two independent chips - read each on its own band.

### ⚠️ Hardened Nonces (Nested Attack Fails)
- **The Symptom:** `hf mf nested` / `mfoc` fails to recover keys on a card that is clearly MIFARE Classic.
- **The Cause:** The card is a "hardened" MIFARE Classic EV1 (or clone) with fixed/filtered nonces that defeat the classic nested attack.
- **The Fix:** Switch to `hf mf hardnested` (or `autopwn`, which selects it automatically). If even one key for one sector is known, the hardnested attack recovers the rest; if no key is known, capture a live reader transaction and recover a key with `mfkey32`/`mfkey64` first.

---

# 💻 8. Post-Processing & Key-Recovery Pipeline
Once a card is read - or a live transaction sniffed - choose one of these software paths to recover keys and extract meaningful credential intelligence.

Pipeline | Best For | Risk Level |
|----------|----------|------------|
| **[Proxmark3 / Iceman firmware](https://github.com/RfidResearchGroup/proxmark3)** | Full LF+HF recovery, sniffing, dumps, cloning | 🔴 HIGH |
| **[libnfc suite (mfoc/mfcuk)](https://github.com/nfc-tools)** | Budget MIFARE Classic key recovery via PN532 | 🟡 MEDIUM |
| **[mfkey32 / mfkey64](https://github.com/RfidResearchGroup/proxmark3)** | Recovering a key from one sniffed reader-card transaction | 🟡 MEDIUM |

### Pipeline 1: Proxmark3 / Iceman (Full Credential Analysis)
**Best For:** End-to-end LF and HF recovery, live sniffing, and verified cloning.
**Process Flow:**
1. **Identify:** `lf search` / `hf search` + `hf 14a info` to fingerprint the chipset.
2. **Recover:** `hf mf autopwn` runs dictionary → darkside → nested/hardnested and saves recovered keys.
3. **Dump:** `hf mf dump` writes the full sectored contents to a local `.bin`/`.eml` file using the recovered keys.
4. **Interpret:** Compare dumps across cards to separate the static UID and issuer data from the per-card credential bytes and access-control payload.

### Pipeline 2: libnfc Suite (PN532 MIFARE Classic Cracking)
**Best For:** Recovering MIFARE Classic keys on a budget PN532 reader.
**Process Flow:**
1. **Confirm:** `nfc-list` verifies the reader sees the card and prints the UID/ATQA/SAK.
2. **Darkside (no known key):** `mfcuk -C -R 0:A -s 250 -S 250` recovers a first sector key when the dictionary supplies none.
3. **Nested (one known key):** `mfoc -O dump.mfd` recovers all remaining sector keys and dumps the card.
4. **Write (bench only):** `nfc-mfclassic w a dump.mfd` writes the dump to a magic card you own for validation.

### Pipeline 3: mfkey (Sniffed-Transaction Key Recovery)
**Best For:** Recovering a sector key from a single legitimate reader-to-card exchange.
**Process Flow:**
1. **Sniff:** On the Proxmark3, run `hf 14a sniff`, present the card to a legitimate reader, then stop the capture.
2. **Extract Nonces:** `hf mf list` (or the sniff trace) yields the `uid`, `nt`, `nr`, and `ar` values from the authentication.
3. **Recover:** Feed those nonces into `mfkey32` (or `mfkey64` for the two-nonce variant); the tool computes the sector key in seconds.

---

## 🗂️ 9. Master Card & Protocol Reference Matrix
The table below serves as a laboratory lookup guide to identify an unknown credential based on its operating frequency and map it to the known transponder architecture.
| Credential Category | Target Device Example | Operating Frequency | Primary Transponder / Protocol |
| :--- | :--- | :--- | :--- |
| **Legacy Building Access** | EM4100/EM4102 Prox Fob | 125 kHz (LF) | EM Microelectronic - Read-Only Fixed ID |
| **Legacy Building Access** | HID ProxCard II / ProxKey | 125 kHz (LF) | HID Prox - Wiegand over FSK, Fixed ID |
| **Legacy Building Access** | Indala (Motorola) | 125 kHz (LF) | Indala - PSK, Fixed ID |
| **Legacy Building Access** | AWID | 125 kHz (LF) | AWID - FSK, Fixed ID |
| **Automotive Immobilizer** | Car Key Transponder | 125–134 kHz (LF) | HITAG2 / Megamos - Challenge-Response |
| **Writable Clone Blank** | T5577 / EM4305 | 125 kHz (LF) | Multi-protocol writable transponder |
| **Building Access (HF)** | MIFARE Classic 1K/4K | 13.56 MHz (HF) | ISO 14443A - Crypto1 (broken) |
| **Building Access (HF)** | HID iCLASS Legacy | 13.56 MHz (HF) | ISO 15693 / Picopass - Weak default keys |
| **Building Access (HF)** | HID iCLASS SE / SEOS | 13.56 MHz (HF) | Secure Element - AES (strong) |
| **Secure Building Access** | MIFARE DESFire EV2/EV3 | 13.56 MHz (HF) | ISO 14443A - AES/3DES (strong) |
| **Transit & Ticketing** | MIFARE Ultralight / EV1 | 13.56 MHz (HF) | ISO 14443A - No/limited crypto |
| **Transit (Asia)** | Sony FeliCa | 13.56 MHz (HF) | JIS X 6319-4 - FeliCa protocol |
| **NFC Tags / Smart Posters** | NTAG213/215/216 | 13.56 MHz (HF) | ISO 14443A - NDEF, no auth |
| **Contactless Payment** | EMV Credit/Debit Card | 13.56 MHz (HF) | ISO 14443 - EMV, cryptographic |
| **Asset / Inventory** | UHF Warehouse Tag | 860–960 MHz (UHF) | EPC Gen2 / ISO 18000-6C (out of LF/HF scope) |
| **Animal / Pet Microchip** | ISO Pet Chip | 134.2 kHz (LF) | ISO 11784/11785 - Read-Only Fixed ID |
| **Passport / eID** | ePassport (ICAO) | 13.56 MHz (HF) | ISO 14443 - BAC/PACE protected |

---

## 📖 10. Transponder Profiles Dictionary
When analyzing credentials from the reference matrix above, use this operational dictionary to understand what each transponder architecture does.
- **EM4100 / EM4102:** The foundational legacy LF standard. A 64-bit read-only identifier is Manchester-encoded and returned continuously while in the field. Zero memory, zero authentication - any captured ID can be written to a T5577 and accepted indefinitely.
- **HID Prox:** A 125 kHz format that FSK-encodes a fixed Wiegand data string (facility code + card number). Read-only and cloneable; the Wiegand payload, not just the raw ID, is what the access panel actually evaluates.
- **Indala / AWID:** Additional legacy LF formats (PSK and FSK respectively) carrying fixed identifiers. Functionally equivalent in security terms to EM4100 - static, unauthenticated, cloneable to writable blanks.
- **HITAG2 / Megamos:** LF automotive immobilizer transponders using proprietary challenge-response crypto. Historically significant for the publicly-disclosed weaknesses that enabled key recovery - the reason modern vehicles moved to stronger schemes.
- **T5577 / EM4305:** Not credentials but *writable* multi-protocol LF transponders. They can be configured to emulate EM4100, HID, Indala, and more - which is exactly why they are the standard clone target and enrollment blank.
- **MIFARE Classic (Crypto1):** Sectored HF memory guarded by 48-bit Crypto1 keys. The cipher is publicly broken: darkside recovers a key with none known, nested/hardnested recover the rest given one, and mfkey extracts a key from one sniffed transaction. Ubiquitous in legacy access and transit despite being duplicable.
- **MIFARE Ultralight / NTAG:** Low-cost HF chips with little or no cryptography. Ultralight is common in disposable transit tickets; NTAG carries NDEF for tap-to-launch and smart posters. Data is generally readable and, for NTAG, writable unless locked.
- **MIFARE DESFire (EV1/EV2/EV3):** Modern HF smartcards with AES/3DES mutual authentication, isolated application files, and per-card diversified keys. Not duplicable without the deployment's keys - the security tier organizations migrate *to*.
- **HID iCLASS:** A 13.56 MHz family. Legacy iCLASS (standard/elite) suffered from weak, sometimes shared default keys that were publicly recovered; iCLASS SE / SEOS moved to a secure element with strong AES and is not duplicable.
- **Sony FeliCa:** A fast HF protocol dominant in Japanese transit and payments. Uses its own command set and mutual authentication; analysis focuses on the service/block structure rather than a broken cipher.
- **EMV Contactless:** Bank cards over ISO 14443. Each tap generates a cryptographically unique transaction (dynamic cryptogram), so the static data is not a usable clone. Attempting to capture or replay payment data is payment-card fraud, full stop.
---

## 📝 11. Laboratory Protocol Logging Template
To maintain reproducibility across access-control audits, document every read, recovery, or clone session using the following standardized Markdown format. Copy the block below into a new file for each session:

# RFID CREDENTIAL CAPTURE MATRIX LOG: [LOG_ID_NUM]
## 1. Environment Metadata
- **Audit Date/Time:** YYYY-MM-DD HH:MM:SS UTC
- **Physical Location:** [e.g., Lab Bench 2 / Client Site - Authorized Area]
- **Operator ID:** [Initials / Badge Number]
- **Authorization Reference:** [Engagement/Ticket # or signed authorization ID]
## 2. Target Credential Profiling
- **Credential Type / Model:** [e.g., HID iCLASS 2k / MIFARE Classic 1K]
- **Marking / Issuer (if visible):** [Printed text, logo, card number]
- **Transponder Chipset:** [e.g., NXP MF1S50 / EM4100 / T5577]
- **Operating Frequency:** [ ] 125 kHz (LF)  |  [ ] 13.56 MHz (HF)  |  [ ] Dual
- **Expected Security Tier:** [ ] Fixed ID  |  [ ] Broken Cipher  |  [ ] Strong Cipher
- **Protocol Signature:** [e.g., EM410x / ISO 14443A Crypto1 / DESFire AES]
## 3. Read Parameters
- **Reader Tool Used:** [ ] Proxmark3  |  [ ] Flipper Zero  |  [ ] PN532/libnfc  |  [ ] Other
- **Antenna Tune (hw tune):** LF: ____ V @ ____ kHz  |  HF: ____ V @ 13.56 MHz
- **UID / Raw ID:** ___________________________________
- **ATQA / SAK (HF):** ATQA: ______  SAK: ______
- **Read Result:** [ ] Full read  |  [ ] Partial (sectors: ____)  |  [ ] UID only
## 4. Key Recovery Configuration (if applicable)
- **Attack Path:** [ ] Dictionary  |  [ ] Darkside (mfcuk)  |  [ ] Nested (mfoc)  |  [ ] Hardnested  |  [ ] mfkey32/64
- **Known Key Source:** [e.g., default FFFFFFFFFFFF / sniffed transaction]
- **Sectors Recovered:** ______ / ______
- **Recovery Time:** ___________ (approx.)
## 5. Extracted Credential Intelligence
- **Output File Reference:** [path/to/dump.mfd] or [path/to/flipper.nfc]
- **Recovered Keys (First 3 Sectors, A/B):**
  1. S0: A=____________ B=____________
  2. S1: A=____________ B=____________
  3. S2: A=____________ B=____________
- **Credential Structure Breakdown:**
  - [UID / SERIAL]        -> ____________________
  - [FACILITY / ISSUER]   -> ____________________
  - [CARD / CREDENTIAL #] -> ____________________
  - [ACCESS BITS / CRC]   -> ____________________
## 6. Cloning & Validation (bench, owned hardware only)
- **Blank Written To:** [ ] T5577  |  [ ] Magic Gen1/Gen2  |  [ ] None
- **Clone Verified vs. Source:** [ ] Byte-identical  |  [ ] Partial  |  [ ] Failed
[Document read clarity, coupling issues, whether the card was hardened, and
whether the emulated/cloned credential was accepted by an OWNED bench reader.]

---

## 🚪 12. Example Project: Safe Access Card Analysis
Use this checklist to practice baseline RFID concepts safely on a credential **you own** - a spare office fob, a blank test card, or a hotel key you are keeping - without touching any production access-control system.

### Phase 1: Pre-Lab Setup & Authorization
- [ ] **Confirm Ownership:** Use only a card you personally own or have written authorization to test. Set aside a blank T5577 (LF) or magic card (HF) as your write target.
- [ ] **Identify System Type:** Look at the card's printed markings and thickness.
  - **Thin, no chip visible, reads at a few cm:** Likely 125 kHz LF (EM4100/HID Prox) - a Fixed-ID system (safe for baseline cloning practice).
  - **"MIFARE", "DESFire", contactless-payment logo:** 13.56 MHz HF - determine the tier before proceeding; secure cards are read-only exercises.

### Phase 2: Identification
- [ ] **Run `hw tune`:** Confirm both antennas are healthy before reading.
- [ ] **Search Both Bands:** Run `lf search`, then `hf search` + `hf 14a info`. Record which band responded and the reported chipset and UID.

### Phase 3: Reading the Credential
- [ ] **Read the Card:** For LF, note the raw ID from `lf search`. For HF MIFARE Classic, run `hf mf autopwn` and record which sectors opened.
- [ ] **Identify the Tier:** Fixed ID (LF prox) vs. broken cipher (MIFARE Classic) vs. strong cipher (DESFire/SEOS, which will refuse authentication).

### Phase 4: Cloning and Security Validation
- [ ] **Clone to a Blank You Own:** For a Fixed-ID LF card, `lf em 410x clone --id <ID>` onto your T5577. For MIFARE Classic, `hf mf restore` onto a magic card.
- [ ] **Apply the Validation Rule:**
  - *If the card is Fixed-ID or MIFARE Classic:* You could clone it in seconds - which is exactly the finding to document. Verify the clone against a **bench reader you own**, never a production door.
  - *If the card is DESFire / SEOS / MIFARE Plus SL3:* Authentication fails and there is nothing to clone. **STOP** and record it as a strong-tier credential - this is the good outcome, and the recommendation is to migrate legacy cards toward it.
---

## ⚠️ CRITICAL Security & Legal Warning
### 🔴 ACCESS-CONTROL & FRAUD WARNING

```
═══════════════════════════════════════════════════════════════
                    ⚠️ CRITICAL LEGAL WARNING ⚠️
═══════════════════════════════════════════════════════════════
The tools and techniques in this manual read, recover keys from, clone, and
emulate physical access credentials and contactless cards.
UNAUTHORIZED USE OF A CLONED CREDENTIAL IS A SERIOUS CRIME.
Computer Fraud and Abuse Act (CFAA):
   ► Using a cloned badge to access a protected system/facility can be charged
     as unauthorized access - felony exposure.
Access Device Fraud (18 U.S.C. § 1029):
   ► Producing, using, or trafficking in counterfeit or unauthorized "access
     devices" (which includes cloned cards) carries heavy federal penalties.
Payment Card Fraud:
   ► Capturing, cloning, or replaying EMV / contactless payment data is fraud
     and identity theft - never a "test."
State Laws:
   ► Burglary-tool possession, trespassing, and eavesdropping statutes vary by
     state and can apply to cloned-credential tools used without authorization.
International Laws:
   ► GDPR and national access-device and computer-misuse laws (e.g., UK Computer
     Misuse Act) apply abroad. ALWAYS check local laws.
═══════════════════════════════════════════════════════════════
```
### Attack-Specific Legal Warnings
#### Badge Cloning (Physical Access)
```
🔴 SERIOUS CRIME: Unauthorized Access & Trespassing
ILLEGAL ACTIVITIES:
   • Reading/cloning a coworker's or stranger's access badge
   • Long-range capture of a credential to duplicate it
   • Using a cloned fob to enter premises you are not authorized to enter
LAWS VIOLATED:
   • Computer Fraud and Abuse Act (CFAA)
   • Access Device Fraud (18 U.S.C. § 1029)
   • State trespassing and burglary-tool possession laws
AUTHORIZED USE ONLY:
   ✓ Written authorization from the property/credential owner
   ✓ Testing on cards and readers explicitly provided for the engagement
```
#### Payment & Identity Cards
```
🔴 FEDERAL CRIME: Payment Fraud & Identity Theft
ILLEGAL ACTIVITIES:
   • Capturing or cloning EMV / contactless bank card data
   • Reading and reselling personal data from eID / passport chips
   • Emulating a captured payment credential at a terminal
LAWS VIOLATED:
   • Access Device Fraud (18 U.S.C. § 1029)
   • Identity theft statutes
   • Payment network rules and financial-fraud law
NEVER acceptable, in any "research" framing, against cards you do not own.
```
### 📖 Before Reading, Cloning, or Emulating Any Card
```
MANDATORY CHECKLIST:
☐ Do I OWN this credential, or have signed authorization to test it?
☐ Am I working on a bench / authorized area, not a live production door?
☐ Am I writing only to blank transponders I own (T5577 / magic card)?
☐ Have I confirmed the card is NOT a payment, passport, or eID chip?
☐ Am I logging every read, recovery, and clone for the assessment report?
☐ Will any emulation be presented ONLY to readers I own?
☐ Have I confirmed local law permits possession/use of these tools here?
If you answered NO to ANY question: DO NOT PROCEED. USE READ-ONLY on owned cards.
```
### Warranty Disclaimer
```
═══════════════════════════════════════════════════════════════
                    ⚠️ DISCLAIMER OF WARRANTIES ⚠️
═══════════════════════════════════════════════════════════════
These RFID procedures, commands, and templates are provided "AS IS" WITHOUT
WARRANTY of any kind, either expressed or implied.
THE AUTHORS, CONTRIBUTORS, AND MAINTAINERS:
✗ Make NO guarantees about procedure functionality or card safety
✗ Are NOT responsible for bricked transponders or damaged readers
✗ Do NOT warrant compliance with any access-control or fraud law
✗ Are NOT liable for any legal consequences of misuse
✗ Do NOT provide support for illegal activities
✗ Disclaim ALL liability for unauthorized reading, cloning, or emulation
USERS EXPLICITLY ACKNOWLEDGE AND AGREE:
► They use these RFID techniques entirely at their own risk
► They are solely responsible for ensuring authorization and legal compliance
► They understand that cloning credentials can facilitate serious crimes
► They accept that unauthorized use is a CRIME
► They will defend and indemnify authors from any claims
═══════════════════════════════════════════════════════════════
```
---

## 📚 Resources
### Legal & Standards
- **ISO/IEC 14443**: [Proximity card standard (HF)](https://www.iso.org/standard/73596.html)
- **ISO/IEC 15693**: [Vicinity card standard (HF)](https://www.iso.org/standard/73602.html)
- **NIST SP 800-116**: [PIV in Physical Access Control](https://csrc.nist.gov/publications/detail/sp/800-116/rev-1/final)
### Learning RFID & NFC
- **Proxmark3 Iceman Wiki**: [RfidResearchGroup/proxmark3](https://github.com/RfidResearchGroup/proxmark3/wiki)
- **Proxmark Forum**: [proxmark.org](http://www.proxmark.org/forum/index.php)
- **NFC / MIFARE background**: [nfc-tools.org](https://nfc-tools.org/)
- **Flipper Zero Docs**: [docs.flipper.net](https://docs.flipper.net/)
### Tooling
- **Proxmark3 (Iceman/RRG)**: [github.com/RfidResearchGroup/proxmark3](https://github.com/RfidResearchGroup/proxmark3)
- **libnfc + mfoc/mfcuk**: [github.com/nfc-tools](https://github.com/nfc-tools)
- **Chameleon Ultra**: [github.com/RfidResearchGroup/ChameleonUltra](https://github.com/RfidResearchGroup/ChameleonUltra)
- **libnfc PN532 tools**: [github.com/nfc-tools/libnfc](https://github.com/nfc-tools/libnfc)

---

## 🔗 Quick Links
### Internal Links
- [🏠 Main Repository](../README.md)
- [🎯 START HERE Guide](../START_HERE.md)
- [💻 Cybersecurity Master Guide](../ultimate_cybersecurity_master_guide.md)
- [🔧 Hardware Hacking](../HardwareHacking/README.md)
- [📻 Sub-GHz RF Guide](subghz.md)
- [📚 Documentation](../Documentation/README.md)

---

## 📊 Repository Statistics
```
📁 Manual Sections: 12 (Theory, Hardware, Client, Chips, Pipelines, Reference, Logging)
💳 Target Hardware: Proxmark3, Flipper Zero, Chameleon Ultra, PN532/libnfc, iCopy-X
📡 Spectrum Coverage: 125 kHz LF + 13.56 MHz HF (ISO 14443 / 15693 / FeliCa)
💻 Ecosystems: Proxmark3 Iceman, libnfc, mfoc/mfcuk, mfkey
⚠️ Risk Level: MEDIUM to HIGH (Cloning & emulation-capable procedures)
🔄 Last Updated: August 2026
👥 Maintained by: Pacific Northwest Computers (PNWC)
📝 Status: Active - Proceed with EXTREME CAUTION
```

---

<div align="center">
**⚠️ USE THESE RFID TOOLS RESPONSIBLY AND LEGALLY ⚠️**
*A credential is presented in the open, but cloning and using one is regulated by law.*
**Repository**: [ULTIMATE CYBERSECURITY MASTER GUIDE](https://github.com/Pnwcomputers/ULTIMATE-CYBERSECURITY-MASTER-GUIDE)
**Maintained by**: [Pacific Northwest Computers](https://github.com/Pnwcomputers)

---

## Related Files
- [subghz.md](subghz.md) - Sub-GHz RF guide: multi-band signal capture, protocol reversing, GNU Radio, replay analysis below 1 GHz
- [sdr.md](sdr.md) - Foundational SDR guide: GNU Radio, hardware, signal analysis, Wi-Fi/BT/cellular/GPS
- [sdr_hacking.md](sdr_hacking.md) - Advanced SDR hacking: SIGINT, protocol reversing, LoRa, TEMPEST, baseband exploitation
- [../Documentation/flipper_zero_guide.md](../Documentation/flipper_zero_guide.md) - Flipper Zero: LF/HF RFID reading and emulation on the same hardware
- [../HardwareHacking/README.md](../HardwareHacking/README.md) - Hardware hacking: bench techniques that complement transponder analysis

---

🔴 **CLONING ACCESS CREDENTIALS CAN FACILITATE SERIOUS CRIMES** 🔴
🔴 **UNAUTHORIZED USE OF A CLONED CARD = A CRIME** 🔴
🔴 **NEVER TOUCH PAYMENT, PASSPORT, OR eID CHIPS YOU DO NOT OWN** 🔴
🔴 **WORK ONLY ON OWNED/AUTHORIZED CARDS AND BENCH READERS** 🔴

---

⭐ **Star this repo if you find it useful (and use it legally!)** ⭐
</div>
