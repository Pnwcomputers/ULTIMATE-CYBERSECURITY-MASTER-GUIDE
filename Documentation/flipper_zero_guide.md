# 🐬 Flipper Zero: Ultimate Field Guide

## FlipperHTTP Network Companion

[FlipperHTTP](https://github.com/jblanked/FlipperHTTP) supplies target-specific
network-bridge firmware and a library used by separate Flipper applications.
It is not Flipper OS and does not add Wi-Fi hardware to the Flipper itself. Use
the exact board-directory installation/wiring instructions, match the companion
app, and keep network credentials out of shared backups. It is a different role
from Marauder or GhostESP survey/capture firmware.

## Firmware & Accessory Update Boundaries

Update the Flipper and its radio accessory as separate devices. The Flipper
itself has no Wi-Fi scanning radio; a firmware change on the Flipper does not add
one. Preserve logs and match companion applications to the accessory firmware.

| Resource | Role & Compatibility Boundary |
|---|---|
| [Official Flipper Firmware](https://github.com/flipperdevices/flipperzero-firmware) | Baseline vendor firmware and documented update/recovery workflow. |
| [Momentum Updater](https://momentum-fw.dev/update/) | Community Flipper firmware; does not flash the external ESP radio. |
| [Unleashed Installer](https://web.unleashedflip.com/) | Community Flipper firmware; separate from its ESP web-flasher catalog. |
| [GhostESP Revival](./ghostesp-revival.md) | Alternative ESP accessory/standalone firmware; verify board and companion-interface support. |
| [Marauder Survey Guide](../Wardriving/esp32-marauder.md) | Existing ESP accessory targets, GPS and evidence workflow. |
| [Scout Lite / SigRoam](../Wardriving/sigroam-scout-lite.md) | Vendor-specific scanner/controller pairing; never write a FAP as an ESP image. |
| [CC1101, nRF24, AWOK, BW16 & Poltergeist Field Labs](#flipper-zero-expansion-boards-selection-setup--field-assessment-labs) | Board selection, GPIO/power safety, app/firmware distinctions and eight authorized labs. |

## 🎯 Purpose
Field guide for the Flipper Zero multi-tool device covering all built-in radios and interfaces for authorized physical penetration testing, IT administration, and security assessment workflows.

## ⚙️ Function
Organized by hardware module: Sub-GHz radio, NFC (13.56 MHz), 125kHz RFID, Infrared, iButton, BadUSB, GPIO, Bluetooth, and WiFi via the ESP32 Dev Board. Covers firmware options (Official, Unleashed, Momentum, RogueMaster), initial setup, the full app catalog, pentesting and IT-admin workflows, and field kit integration with tools like HackRF, Bus Pirate, and ProxMark3.

## 🏆 Goal
Enable IT professionals and penetration testers to use the Flipper Zero effectively across the full range of physical security assessment tasks - from access control badge cloning to wireless handshake capture to BadUSB payload delivery.

## 📋 When to Use
- Physical access control assessments (125kHz RFID/NFC badge reading and cloning)
- Wireless assessments (Sub-GHz fixed-code replay, WiFi handshake capture via Marauder)
- USB HID attacks (BadUSB payloads) during authorized red-team engagements
- IT admin console access to routers and switches via GPIO UART
- Client security awareness demonstrations (BLE spam, IR disruption, unlocked workstation demos)

### *For authorized IT and penetration testing use only*

---

> ⚠️ **Legal Disclaimer**: All techniques in this guide are for use only on systems and devices you own or have **explicit written authorization** to test. Unauthorized interception, cloning, or access of wireless signals, access control systems, or computer systems violates the Computer Fraud and Abuse Act (CFAA), the Electronic Communications Privacy Act (ECPA), and applicable state laws. PNWC accepts no liability for misuse of the information contained herein.

---

## Table of Contents

1. [Hardware Overview](#1-hardware-overview)
2. [Firmware](#2-firmware)
3. [Initial Setup](#3-initial-setup)
4. [Sub-GHz Radio](#4-sub-ghz-radio)
5. [NFC (13.56 MHz)](#5-nfc-1356-mhz)
6. [125kHz RFID](#6-125khz-rfid)
7. [Infrared](#7-infrared)
8. [iButton](#8-ibutton)
9. [BadUSB](#9-badusb)
10. [U2F / FIDO2](#10-u2f--fido2)
11. [GPIO & Hardware Interfaces](#11-gpio--hardware-interfaces)
    - [Expansion Board Setup & Field Labs](#flipper-zero-expansion-boards-selection-setup--field-assessment-labs)
12. [Bluetooth](#12-bluetooth)
13. [WiFi - ESP32 Dev Board](#13-wifi---esp32-dev-board)
14. [Apps - Full Catalog](#14-apps---full-catalog)
15. [Pentesting Workflows](#15-pentesting-workflows)
16. [IT Admin Workflows](#16-it-admin-workflows)
17. [Field Kit Integration](#17-field-kit-integration)
18. [SD Card Organization](#18-sd-card-organization)
19. [Resources & References](#19-resources--references)

---

## 1. Hardware Overview

> **Wi-Fi wardriving requires an external scanner:** A Flipper Zero does not include a native Wi-Fi survey radio. For the PINGEQUA Scout Lite ESP32-C5 board, compatible SigRoam Flipper app/board firmware and microSD/GNSS workflow, see [SigRoam Wardriving](../Wardriving/sigroam-scout-lite.md). For alternate board firmware see [ESP32 Marauder](../Wardriving/esp32-marauder.md) and the [Wardriving overview](../Wardriving/README.md).


### Physical Layout

```
┌─────────────────────────────────────────────┐
│  [←Back]              [Flipper Logo]         │
│                                              │
│  ┌──────────────────────────────────────┐   │
│  │         1.4" LCD Display             │   │
│  │         128 x 64 pixels              │   │
│  └──────────────────────────────────────┘   │
│                                              │
│         [▲]                                  │
│    [◄] [OK] [►]        [●] LED               │
│         [▼]                                  │
│                                              │
│  [Back]              [Power/Lock]            │
└─────────────────────────────────────────────┘
```

### Specifications

| Component | Spec |
|---|---|
| MCU | STM32WB55 (ARM Cortex-M4 @ 64MHz + M0+ BLE co-processor) |
| Display | 1.4" monochrome LCD, 128×64 |
| Sub-GHz Radio | CC1101 (300–928 MHz) |
| NFC | ST25R3916 (13.56 MHz, ISO 14443A/B, ISO 15693) |
| 125kHz RFID | EM4100, HID Prox, Indala, Hitag, etc. |
| Infrared | TX/RX up to 56kHz carrier |
| iButton | 1-Wire protocol (Dallas/Maxim) |
| Bluetooth | BLE 5.0 via STM32WB55 |
| USB | USB 2.0 Full-Speed (HID, CDC, DFU) |
| GPIO | 18 pins (3.3V logic, 5V tolerant inputs) |
| Storage | MicroSD (up to 256GB) |
| Battery | 2000mAh Li-Ion |
| Charging | USB-C, ~2hr full charge |

### GPIO Pinout

```
     3V3  1 ● ● 2  GND
     PA7  3 ● ● 4  PB2
     PA6  5 ● ● 6  PC3
     PA4  7 ● ● 8  PC1
     PB3  9 ● ● 10 PC0
     PB2 11 ● ● 12 GND
     PC6 13 ● ● 14 PC5 (TX)
     PC4 15 ● ● 16 PC3 (RX)
     GND 17 ● ● 18 5V (USB)
```

Key pins for common use:
- **Pin 13/14** - UART TX/RX (serial console work)
- **Pin 15/16** - SPI MOSI/MISO
- **Pin 18** - 5V (from USB only, not battery)
- **Pin 1** - 3.3V regulated output (~20mA max)

---

## 2. Firmware

### Firmware Comparison

| Firmware | Stability | App Count | Sub-GHz Unlock | Custom UI | Best For |
|---|---|---|---|---|---|
| **Official (OFW)** | ★★★★★ | Low | ❌ | ❌ | Warranty / compliance |
| **Unleashed** | ★★★★☆ | High | ✅ | Partial | Daily IT + pentesting |
| **Momentum** | ★★★★☆ | Highest | ✅ | ✅ | Feature-rich builds |
| **RogueMaster** | ★★★☆☆ | Highest | ✅ | ✅ | Max features, less stable |

## [Awesome-Flipper.com Firmware Comparison Guide](https://awesome-flipper.com/firmware/)

### [Official Firmware](https://github.com/flipperdevices/flipperzero-firmware)
- **Source**: flipper.net / qFlipper auto-update
- Stock feature set, regionally restricted Sub-GHz
- Required for warranty claims
- App Catalog access via lab.flipper.net

### [Unleashed Firmware](https://github.com/DarkFlippers/unleashed-firmware)
- **Source**: github.com/DarkFlippers/unleashed-firmware/releases
- Removes Sub-GHz regional frequency restrictions
- Adds extra protocols: CAME, Nice, Ansonic, etc.
- Extra apps bundle in `*e.tgz` release variant
- Compatible with official Flipper App Catalog

### [Momentum Firmware (Recommended)](https://momentum-fw.dev/)
- **Source**: github.com/Next-Flip/Momentum-Firmware/releases
- Fork of Xtreme firmware, actively maintained
- Largest bundled app collection
- Custom themes, UI tweaks, extended settings
- Extra apps in `*e.tgz` or resources package
- Supports custom asset packs

### [RogueMaster](https://github.com/RogueMaster/flipperzero-firmware-wPlugins)
- **Source**: github.com/RogueMaster/flipperzero-firmware-wPlugins
- Maximum features and app count
- Less stable, rolling releases
- Good for experimentation, not field reliance

### Installing Firmware

**Via [qFlipper (recommended)](https://github.com/flipperdevices/qFlipper):**
1. Connect Flipper via USB-C
2. Open qFlipper → click "Install from file"
3. Select the downloaded `.tgz` update package
4. Wait for flash + reboot (~2 minutes)

**Via SD Card (OTA, no PC needed):**
1. Copy update folder to SD card root
2. On Flipper: Settings → Power → Update Firmware
3. Select the update package

**Via CLI/ufbt:**
```bash
pip3 install ufbt
ufbt update --channel=dev   # or release/rc
```

### Getting Extra Apps Without Reflashing

Download the resources package from your firmware's releases page:
```
momentum-f7-resources-<version>.tgz
```
Extract and copy the `apps/` folder to your SD card via qFlipper File Manager.

---

## 3. Initial Setup

### First Boot Checklist

- [ ] Charge to 100% before first use
- [ ] Insert MicroSD card (FAT32 formatted)
- [ ] Flash preferred firmware (Momentum recommended)
- [ ] Set region: Settings → System → Region
- [ ] Set time/date: Settings → System → Date & Time
- [ ] Enable BLE if needed: Settings → Bluetooth
- [ ] Pair with mobile app (Flipper Mobile App - iOS/Android)

### SD Card Setup

Format as FAT32 (exFAT works but FAT32 is more reliable). The firmware will create the directory structure on first boot:

```
SD:/
├── apps/            # .fap app files by category
├── badusb/          # DuckyScript payloads
├── infrared/        # IR remote files (.ir)
├── lfrfid/          # 125kHz RFID saves
├── nfc/             # NFC card saves (.nfc)
├── subghz/          # Sub-GHz captures (.sub)
│   └── assets/      # Protocol databases
├── ibutton/         # iButton key saves
├── dolphin/         # XP/level data
├── logs/            # System logs
└── update/          # Firmware update packages
```

### qFlipper File Manager

Essential for managing SD card contents. Access via:
- qFlipper → SD Card tab → file tree on left
- Drag and drop files to/from your PC
- Right-click for delete, rename, new folder

### Flipper Mobile App

Available on iOS and Android. Enables:
- Remote control via BLE
- File transfer without USB
- App catalog browsing
- firmware update over BLE

---

## 4. Sub-GHz Radio

### Overview

The built-in CC1101 covers **approximately 300–348 MHz, 387–464 MHz and 779–928 MHz** hardware bands (not an unrestricted continuous 300–928 MHz span), with supported operation further limited by firmware, antenna and regional regulations. See [official Sub-GHz specifications](https://docs.flipper.net/zero/sub-ghz).

**Common frequencies:**
| Frequency | Common Use |
|---|---|
| 315 MHz | US/Canada garage doors, automotive remotes |
| 433.92 MHz | European garage doors, weather stations, sensors |
| 868 MHz | European IoT, Z-Wave (EU), LoRa |
| 915 MHz | US ISM band, Z-Wave (US), LoRa |
| 433/868/915 | Alarm sensors, temperature sensors |

### Read (Capture)

**Main Menu → Sub-GHz → Read**

Passive capture mode. The Flipper listens on a configured frequency and decodes signals it recognizes. When a known signal is received, it appears on screen and can be saved.

**Steps:**
1. Sub-GHz → Read
2. Point remote/transmitter at Flipper
3. Press the button on the target device
4. If decoded: press OK to save, give it a name

**Supported protocols (built-in + Unleashed/Momentum extras):**
- Princeton, CAME, Nice Flor, Chamberlain, Linear, Securplus
- Ansonic, Holtek, Doitrand, SMC5326, GangQi
- KeeLoq (fixed code capture - not rolling)
- Star Line automotive (fixed segments)

### Read RAW

**Sub-GHz → Read RAW**

Captures the raw signal waveform without attempting to decode it. Use when:
- Protocol is not recognized
- You want to replay without needing decode
- Analyzing unknown signals

Raw files are larger but more universal. They replay the exact timing of the original signal.

**Settings in RAW mode:**
- Frequency: manually set or use Frequency Analyzer first
- RSSI: signal strength indicator - get close to transmitter

### Send / Replay

**Sub-GHz → Saved → [select file] → Send**

Replays a saved signal. For fixed-code protocols this is a direct replay attack. Holding the send button repeats transmission.

> **Pentest note**: Fixed-code systems (many older garage doors, gates, parking barriers) are vulnerable to replay. Rolling code systems (KeeLoq with sync, HCS series) are not replayed this way.

### Frequency Analyzer

**Sub-GHz → Frequency Analyzer**

Real-time spectrum display. Shows what frequencies are actively transmitting in your environment. Use before capturing to identify:
- What frequency a device operates on
- Whether a signal is present at all
- Interference sources on client sites

### Sub-GHz Bruteforcer (Extra App)

**Apps → Sub-GHz → Sub-GHz Bruteforcer**

Iterates through all possible fixed codes for a given protocol and bit length. Effective against:
- Gate controllers using fixed codes
- Parking barriers
- Simple intercoms
- Older garage door systems

**Usage:**
1. Select protocol (Princeton is most common)
2. Select bit length (typically 24 or 25 bit)
3. Start - Flipper transmits codes sequentially

**Time estimates:**
- 24-bit Princeton: ~45 minutes for full sweep
- 12-bit: seconds

> **Pentest note**: Demonstrate to clients that fixed-code systems can be opened by any attacker with $30 of hardware in under an hour.

### Adding Custom Frequencies

Unleashed and Momentum support frequencies beyond the defaults. Edit:
```
SD:/subghz/assets/setting_user
```

Example entries:
```
Frequency: 303920000
Frequency: 304250000
Frequency: 390000000
```

### Sub-GHz Protocols Reference

| Protocol | Type | Notes |
|---|---|---|
| Princeton | Fixed | Most common 24-bit fixed code |
| CAME | Fixed | Common in EU gate systems |
| Nice Flor S | Rolling | Cannot replay, capture only |
| KeeLoq | Rolling | Automotive, some gates |
| Chamberlain | Rolling | Security+, not replayable |
| Linear | Fixed | Older US systems |
| Holtek HT12X | Fixed | Common RF modules |
| SMC5326 | Fixed | Chinese gate controllers |
| Ansonic | Fixed | Various remotes |
| StarLine | Fixed segments | Russian automotive |

---

## 5. NFC (13.56 MHz)

### Overview

The Flipper's NFC reader (ST25R3916) supports ISO 14443A/B and ISO 15693, covering the vast majority of contactless smart cards used in access control, payment, and transit systems.

**Supported card types:**
| Card Type | Common Use | Read | Clone | Emulate |
|---|---|---|---|---|
| Mifare Classic 1K/4K | Access control (very common) | ✅ | ✅* | ✅ |
| Mifare Ultralight | Transit, events | ✅ | ✅ | ✅ |
| Mifare DESFire | High-security access | UID only | ❌ | UID only |
| NTAG 203/213/215/216 | NFC tags, Amiibo | ✅ | ✅ | ✅ |
| EMV (bank cards) | Payment | UID + metadata | ❌ | ❌ |
| ISO 15693 (iClass) | Corporate access | ✅** | ✅** | ✅** |

*Requires key recovery (MFKey/Mifare Nested app)
**Requires Picopass app

### Reading NFC Cards

**Main Menu → NFC → Read**

Hold card to Flipper's back (NFC antenna area). The Flipper will identify card type and read available data. Save with a descriptive name.

For Mifare Classic, initial read captures the UID and sector structure but locked sectors require key recovery first.

### Emulating NFC Cards

**NFC → Saved → [card] → Emulate**

Flipper presents itself as the saved card to readers. Works well for:
- Mifare Ultralight (full emulation)
- NTAG series (full emulation)
- Mifare Classic (partial - some readers detect timing differences)

### Mifare Classic Key Recovery

Mifare Classic uses 48-bit sector keys (Key A and Key B). Default keys (0xFFFFFFFF, 0xA0A1A2A3A4A5, etc.) are tried automatically. For non-default keys:

**Method 1: MFKey App (requires a real reader)**
1. Install MFKey from Flipper Lab
2. NFC → Detect Reader - hold Flipper near the target reader (badge reader on a door)
3. The reader will challenge the Flipper, which captures the crypto nonces
4. Apps → NFC → MFKey → Run
5. MFKey performs offline CRYPTO1 cryptanalysis to recover the sector keys
6. Return to NFC → Saved → [card] → Read with recovered keys

**Method 2: Mifare Nested (app)**
Performs nested authentication attack to recover keys from a card that has at least one known sector key.

**Method 3: MIFARE Classic Editor**
Manually enter/edit sector keys and data blocks after recovery.

### Writing NFC Cards

**NFC → Saved → [card] → Write**

Writes saved card data to a blank writable card. Requires:
- Mifare Classic: "Magic" Gen1 or Gen2 card (available cheaply online)
- NTAG: Any blank NTAG of correct type
- Ultralight: Blank Ultralight card

**Gen1 vs Gen2 magic cards:**
- Gen1: UID rewritable via backdoor command, detected by some readers
- Gen2: UID rewritable via standard commands, harder to detect
- Use Gen2 for professional pentest deliverables

### Picopass / iClass App

HID iClass is a 13.56 MHz standard common in corporate environments. Not supported by the built-in NFC app - requires the **Picopass** app.

**Install:** Flipper Lab → search "Picopass"

**Capabilities:**
- Read iClass Legacy and iClass SE credentials
- Read Standard and High-security segments
- Save and emulate credentials
- iClass Elite key bruteforce (if Elite key is unknown)

### NFC Workflows for Pentesting

**Physical Access Assessment Workflow:**
1. Covertly read target badge (NFC → Read, brief contact sufficient)
2. Identify card type
3. If Mifare Classic: hold near reader to capture nonces (MFKey)
4. Recover keys, re-read full card data
5. Write to Gen2 magic card as physical evidence
6. Test cloned card at target reader
7. Document: card type, security weakness, affected doors

**Deliverable talking points for clients:**
- Mifare Classic 1K is cryptographically broken (CRYPTO1 cipher, 2008)
- Full key recovery takes ~30 seconds with commodity hardware
- Upgrade path: Mifare DESFire EV2/EV3 or SEOS

---

## 6. 125kHz RFID

### Overview

125kHz RFID (Low Frequency) is the oldest and least secure access control technology still widely deployed. The Flipper reads and emulates all common LF card formats.

**Supported protocols:**
| Protocol | Notes |
|---|---|
| EM4100 / EM4102 | Most common worldwide, read-only |
| HID Prox | Very common in US corporate |
| Indala | Motorola/HID, older deployments |
| AWID | Older US systems |
| Paradox | Security panels |
| Keri | Access control |
| Hitag 1/2/S | More secure, key-protected |
| FDX-B | Animal microchips |
| ioProx | Kantech systems |

### Reading RFID

**Main Menu → 125kHz RFID → Read**

Hold card against Flipper's back. Most LF cards read instantly. Save with descriptive name.

> These cards transmit their ID with zero authentication - any reader in range can capture the credential. This is the lowest tier of access control security.

### Emulating RFID

**125kHz RFID → Saved → [card] → Emulate**

Flipper transmits the stored credential, presenting as the original card. Works against virtually all LF readers since LF systems have no mutual authentication.

### Writing RFID

**125kHz RFID → Saved → [card] → Write**

Writes to T5577 writable cards (extremely cheap, widely available). These blank cards can be programmed to any EM4100/HID Prox/Indala credential.

### Add Manually

**125kHz RFID → Add Manually**

Useful when you know the card number (printed on the card, on a document, etc.) but don't have physical access to the card itself.

### RFID Fuzzer

**Apps → RFID → RFID Fuzzer**

Iterates through credential ranges for a given protocol. Useful for:
- Testing whether a reader accepts sequential or predictable card numbers
- Discovering what credential ranges are active in a system

### Pentesting Notes

125kHz is essentially security theater:
- Cards are read-only and broadcast credentials with no authentication
- Can be read covertly from several centimeters with off-the-shelf hardware
- Cloning takes under 5 seconds with the Flipper
- Virtually all SMB facilities running HID Prox or EM4100 are vulnerable

**Common client scenario**: Visitor badges at front desk use the same format as employee badges - capture visitor badge UID, clone it, present at secured doors.

---

## 7. Infrared

### Overview

The Flipper includes an IR transmitter (950nm LED) and receiver, supporting carrier frequencies up to 56kHz. Covers virtually all consumer IR remote protocols.

**Supported protocols:** NEC, Samsung, RC5, RC6, SIRC, KASEIKYO, RCA, and raw capture for anything else.

### Learning Remotes

**Main Menu → Infrared → Learn New Remote**

Captures IR signals from existing remotes. For each button:
1. Select "Add Button"
2. Name the button
3. Point original remote at Flipper, press button
4. Repeat for each button needed

Saves as `.ir` file on SD card.

### Universal Remotes

**Infrared → Universal Remotes**

Built-in database of common remote codes for:
- TVs (Samsung, LG, Sony, etc.)
- Air conditioners
- Projectors
- Audio equipment

**Pentest / physical assessment use:** Can disable AV equipment, TVs, or projectors in lobbies/conference rooms as part of a physical intrusion demo.

### Infrared Database (UberGuidoZ)

The UberGuidoZ repo (`github.com/UberGuidoZ/Flipper/tree/main/Infrared`) contains hundreds of device-specific IR files. Download relevant ones and place in `SD:/infrared/`.

### Brute Force IR

**Apps → Infrared → Brute Force IR**

Iterates through all known codes for a given device type/brand. Useful for unlocking hotel TVs, testing IR receiver security.

---

## 8. iButton

### Overview

iButton (1-Wire / Dallas keys) are contact-based keys used in some intercom systems, apartment buildings (common in Eastern Europe and Russia), and some industrial access control systems. Less common in the US but still encountered.

**Supported types:**
- DS1990A (RW1990) - most common
- DS1992, DS1996 - memory types
- Cyfral, Metakom - Russian apartment systems

### Reading iButton

**Main Menu → iButton → Read**

Contact the iButton key to the Flipper's iButton connector (bottom of device, next to USB). Reads and saves the key ID.

### Emulating iButton

**iButton → Saved → [key] → Emulate**

Flipper presents the key credential via the iButton connector. Hold Flipper to the reader contact point.

### Writing iButton

**iButton → Saved → [key] → Write**

Writes to blank RW1990 writable keys. Cheap and widely available.

---

## 9. BadUSB

### Overview

When connected via USB, the Flipper can present itself as a USB HID keyboard and type arbitrary keystrokes at machine speed. Uses DuckyScript 1.0 syntax (compatible with Hak5 Rubber Ducky payloads).

### DuckyScript 1.0 Syntax Reference

```
REM          Comment line
DELAY [ms]   Wait in milliseconds
STRING       Type text
ENTER        Press Enter
GUI          Windows key
CTRL         Control key
ALT          Alt key
SHIFT        Shift key
TAB          Tab key
SPACE        Space
BACKSPACE    Backspace
DELETE       Delete
UP/DOWN/LEFT/RIGHT  Arrow keys
F1-F12       Function keys
CAPSLOCK     Caps Lock toggle
HOME / END   Navigation
PAGEUP/PAGEDOWN  Page navigation

Key combos:
GUI r        Windows + R (Run dialog)
CTRL-ALT t   Open terminal (Linux)
CTRL c       Copy
CTRL v       Paste
CTRL-SHIFT ESC  Task Manager
```

### Deploying Payloads

1. Place `.txt` payload files in `SD:/badusb/`
2. Main Menu → BadUSB
3. Select payload file
4. Connect to target USB port
5. Press OK to run

### Payload Writing Tips

- Always start with `DELAY 1000` to give the OS time to recognize the device
- Add generous `DELAY` values after commands that open windows (600-1200ms)
- Use `DELAY 3000` or more after commands that trigger UAC prompts
- Test on your own machine before field deployment
- Keep payloads idempotent where possible (safe to run twice)

### Keyboard Layout

Match the payload's keyboard layout to the target system. Set in:
**Settings → System → USB Keyboard Layout**

Important for special characters - `@`, `\`, `/` vary by locale. US layout is default.

### PNWC Payload Library

See the PNWC BadUSB library (separate document) for a complete set of ready-to-deploy payloads covering:
- Windows full system recon
- Network enumeration
- Security posture audit
- WiFi credential dump
- Active Directory enumeration
- Reverse shells (PS + Bash)
- Privilege escalation checks
- Persistence demonstration
- Data exfil simulation
- Physical security awareness test
- Client intake form auto-fill
- Rapid IT remediation

---

## 10. U2F / FIDO2

### Overview

The Flipper can act as a FIDO U2F hardware security key for two-factor authentication. Useful as a backup 2FA device or for demonstrating hardware token concepts to clients.

**Setup:**
1. Settings → U2F → Enable
2. Connect Flipper via USB
3. Register as a security key on any FIDO U2F-compatible service (Google, GitHub, Cloudflare, etc.)
4. During authentication: press the OK button when prompted

**Limitations:**
- Stores one U2F credential
- Not FIDO2/WebAuthn level - works for U2F only
- No PIN protection (anyone with physical Flipper can authenticate)

**Practical use for IT/security:**
- Demonstrate hardware token value to clients
- Test whether services properly enforce MFA
- Emergency backup factor for personal accounts

---

## 11. GPIO & Hardware Interfaces

### Overview

18 GPIO pins provide access to UART, SPI, I2C, 1-Wire, and general digital I/O. The Flipper can serve as a portable hardware interface tool, logic analyzer, and signal generator.

### UART Terminal (Serial Console)

**Apps → GPIO → UART Terminal**

Presents a serial terminal over the Flipper's GPIO pins. Essential for accessing:
- Router/switch console ports (Cisco, UniFi, MikroTik, pfSense)
- Embedded Linux devices (Raspberry Pi, development boards)
- IoT device debug ports

**GPIO → RJ45 Console Cable (make your own):**
```
Flipper Pin 14 (TX) → RJ45 Pin 3 (RX on Cisco)
Flipper Pin 16 (RX) → RJ45 Pin 6 (TX on Cisco)
Flipper Pin 17 (GND) → RJ45 Pin 8 (GND)
```
Serial settings: 9600/115200 baud, 8N1 (varies by device)

**Cisco default console:** 9600 baud, 8N1, no flow control
**UniFi default console:** 115200 baud, 8N1

### Logic Analyzer

**Apps → GPIO → Logic Analyzer**

Captures digital signal states on GPIO pins. 4-channel capture, useful for:
- Analyzing SPI/I2C/UART traffic on unknown devices
- Timing analysis of digital signals
- Identifying communication protocols on circuit boards

### I2C Tools

Scan and communicate with I2C devices on the bus:
- Scan for device addresses
- Read/write registers
- Useful for hardware hacking sessions alongside Bus Pirate 5

### SPI Tools

Similar to I2C but for SPI devices. Can read SPI flash chips (with appropriate wiring), though the Bus Pirate 5 is more capable for deep hardware work.

### GPIO Tone Generator

**Apps → GPIO → Tone Generator**

Generates square waves on GPIO pins. Useful for:
- Testing audio circuits
- Generating clock signals
- Basic hardware testing

### Wire Tester

**Apps → GPIO → Wire Tester**

Continuity tester using GPIO pins. Quick cable verification tool - handy for network cable checking on client sites.

### Raspberry Pi / SBC Integration

The Flipper can be used as a GPIO expander for Raspberry Pi projects. With `flipperzero-protobuf` and the Flipper's USB serial interface, you can script Flipper actions from Python.

### GPIO Header Modules

Several add-on boards connect to the GPIO header:

| Module | Purpose |
|---|---|
| WiFi Dev Board (ESP32-S2) | WiFi pentesting via Marauder |
| Video Game Module | Flipper gaming (not pentesting use) |
| [nRF24 Module](#lab-b--nrf24-owned-24-ghz-telemetry--channel-awareness) | 2.4 GHz proprietary packet-radio observation; **not** a Wi-Fi or BLE radio |
| [GNSS/GPS Module](#lab-g--gps--external-peripheral-selection) | Location metadata only with supported UART/firmware, reliable fix and real log integration |
| Servo/Motor Driver | Robotics integration |
| [External CC1101](#lab-a--external-cc1101-internal-vs-external-comparison) | Alternative Sub-GHz front-end/antenna for supported bands |
| [AWOK Dual C5](#lab-d--awok-dual-c5-touchmini-two-mcu-identity--observation) | Independent C5 radios and optional Flipper companion interface |
| [BW16 / RTL8720DN](#lab-e--bw16--rtl8720dn-correct-firmware--dual-band-survey) | Realtek 2.4/5 GHz; 5Ghost/FlipperHTTP firmware families |
| [Rabbit-Labs Poltergeist](#lab-f--rabbit-labs-poltergeist-wi-fi-ir--sd-acceptance) | ESP32-C5 2.4/5 GHz, IR, SD and OLED, firmware-dependent |
| [PINGEQUA CC1101+nRF24](#lab-c--pingequa-cc1101--nrf24-two-in-one-module) | Separate Sub-GHz and 2.4 GHz radios; special SPI routing |

---

### Flipper Zero Expansion Boards: Selection, Setup & Field Assessment Labs

_Last documentation/source review: November 2026. This section describes source-backed procedures, **not personally verified hardware tests**._

**Goal:** select, configure, and validate external modules without mixing firmware images, UART pinouts, RF bands, or incompatible Flipper applications. The [official GPIO documentation](https://docs.flipper.net/zero/gpio-and-modules) describes the 18-pin connector, supply rails and pin limits; the [official Sub-GHz documentation](https://docs.flipper.net/zero/sub-ghz) distinguishes built-in and external CC1101 operation. Read both before powering a new board.

> [!IMPORTANT]
> **Flipper firmware**, **Flipper applications (`.fap`)**, and **external radio-board firmware** are separate components. An nRF24 is not a Wi-Fi or Bluetooth sniffer; a CC1101 is not an nRF24; a **BW16 / RTL8720DN is not an ESP32**. Match the exact PCB/revision, power/antenna, firmware target and app. *Never* assume that an ESP32/S2/S3/C5 image runs on an RTL8720DN or that a standalone image works with a Flipper UART companion.

#### Selection & Compatibility Matrix

| Hardware / ecosystem | Actual radio or peripheral | Flipper relationship | Primary source & documentation boundary |
|---|---|---|---|
| **External CC1101** | Sub-GHz SPI transceiver; antenna/module commonly tuned for 315/433/868/915 MHz variants | Uses compatible Sub-GHz app; alternative antenna/front-end, **not a new protocol family** | [Flipper Sub-GHz](https://docs.flipper.net/zero/sub-ghz) · [external-CC1101 wiring example](https://github.com/quen0n/flipperzero-ext-cc1101) |
| **nRF24L01+/Si24R1** | 2.4 GHz proprietary packet-radio class (Enhanced ShockBurst family) | External SPI module with app- and board-specific pin mapping | [PINGEQUA nRF24 support](https://www.pingequa.com/pages/support-flipper-zero-nrf24-module) · [community wiring reference](https://github.com/UberGuidoZ/Flipper/tree/main/GPIO) |
| **PINGEQUA CC1101 + nRF24 2-in-1** | Two chips sharing a GPIO board, **non-default nRF SPI** | [RF Lab](https://github.com/pingequalab/rf-lab) FAP or compatible third-party apps | The nRF device uses `Extra 7` on supported Momentum configurations; other FAPs may hard-code pins |
| **AWOK Dual C5 Touch / Mini** | Two independently programmable ESP32-C5 Wi-Fi radios; on-board GNSS connected to both chips | Independent touchscreen/display and serial/controller roles; verify Flipper link and exact MCU port | [AWOK Dual C5 Touch](https://awokdynamics.com/products/dual-c5-touch) · [AWOK firmware/port guide](../Wardriving/awok-dual-c5-biscuit.md) |
| **BW16 / RTL8720DN** | Realtek AmebaD dual-band Wi-Fi (2.4/5 GHz) | Separate BW16 firmware **and matching Flipper app**, not Marauder ESP32 image | [PINGEQUA 5Ghost flasher](https://flash.pingequa.com/devices/bw16-5ghost) · [Flipper app installer](https://flash.pingequa.com/devices/flipper-pingequa) · [FlipperHTTP BW16](https://github.com/jblanked/FlipperHTTP/tree/main/BW16) |
| **Rabbit-Labs Poltergeist** | ESP32-C5 Wi-Fi, BLE-capable chip, OLED, microSD, IR receiver & high-output IR LEDs | Flipper GPIO accessory **or** USB-C standalone board; functions depend on installed firmware | [Rabbit-Labs Poltergeist](https://rabbit-labs.com/product/rabbit-labs-poltergeist-5ghz-wifi-board/) · [vendor flasher](https://flasher.site/) |
| **Flipper official Wi-Fi Dev Board** | ESP32-S2, 2.4 GHz Wi-Fi only; **no BLE** | Separate ESP firmware + matching FAP | [Marauder for Flipper lab](#flipper-marauder-companion-deployment-labs) |
| **PINGEQUA Scout Lite + SigRoam** | ESP32-C5 2.4/5 GHz and board-specific GNSS/microSD | Flipper FAP drives compatible external firmware; logging location differs with selected image | [SigRoam / Scout Lite](../Wardriving/sigroam-scout-lite.md) |
| **UART, GPS, CAN, RS-232, Video Game & IR expansion** | Depends on specific adapter or peripheral | Flipper GPIO/USB app or companion MCU; no general-purpose universal firmware | [GPIO documentation](https://docs.flipper.net/zero/gpio-and-modules) · exact peripheral vendor/PCB instructions |

**Frequency caution:** the internal CC1101's Flipper-documented hardware bands are approximately **300–348, 387–464, and 779–928 MHz**, not every frequency continuously between 300 and 928 MHz. The **external** module, its filters, matching antenna, local region and firmware limits further constrain usable operation. Adding a higher-gain antenna does not authorize additional transmit power or frequencies.

#### Common Preflight — Every Board

1. **Engagement scope:** written owner/asset authorization, intended receiver, permitted bands/channels, test time, receive/transmit boundaries, evidence retention, stop contact and excluded neighbors.
2. **Identify the stack:** Flipper firmware version/API, FAP name/version, board vendor/model/PCB revision, radio chip(s), current module firmware, any bootloader requirements, SD/GNSS source and exact antenna type.
3. **Photograph and backup** the device labels, wiring, prior firmware and client-owned SD files; redact serials and coordinates from public examples. Compare source releases and **binary checksums**, not just filenames.
4. **Power down before connecting or moving** GPIO boards, attaching antennas or changing jumpers. Do not guess pin 1/orientation, apply 5 V to a 3.3 V peripheral, or feed RS-232 voltage into a UART pin. Verify regulator, battery/power budget and common ground using the board maker's schematic. An RJ45 console *connector* alone does not establish TTL serial voltage.
5. **Pick the correct application** for the installed firmware/API. For vendor-combined modules, check pin/bus conflicts and whether a switch/multiplexer has moved SPI/UART to nonstandard pins.
6. **Start read-only:** boot, UI and device enumeration, then one short observation of an owned test beacon/AP. Leave deauthentication, jamming, BLE spam, credential capture, rogue AP impersonation and unrelated device interactions out of initial acceptance tests.
7. **Preserve evidence:** operator, exact time/time zone, FAP/board versions, allowed channels, test fixture ID, actual results, screenshots, error text and rollback. A scan alone cannot prove a client is compromised.

#### Lab A — External CC1101: Internal-vs-External Comparison

**Purpose:** evaluate reception of one **owned, noncritical, battery-operated 433 MHz test transmitter**, contrasting the Flipper's built-in radio with an external antenna/module. No gate, car, alarm, access lock or emergency device is required.

1. Verify the external module's chip, operating band, antenna match and physical pinout. A 433 MHz module/antenna is not inherently suited for 868 or 915 MHz. Keep the antenna connected throughout the RF test.
2. Power down, seat the verified CC1101 module and restart. Use `Sub-GHz → Radio Settings → Module → External` where the installed firmware exposes this setting; some builds use `Read External` instead.
3. Begin with the **internal** radio: activate the owned test transmitter at a fixed short distance, record signal detection/decoded protocol and an RSSI indicator **if present**.
4. Switch to **external** using the same receive mode, distance, orientation and transmitter. Repeat 3 times, logging internal/external selection and receiver settings.
5. Return to the internal module and confirm reception still works. Remove the expansion with Flipper powered down.
6. Report relative consistency and signal indication, **not a calibrated range increase** from a single reading. A different antenna/front end may improve or worsen a particular test.

**Failure checks:** missing `External` option (firmware/app), unseated SPI, wrong voltage, wrong chip/board pins, defective or mismatched antenna, unsupported band, or a strong nearby transmitter saturating a receiver. Never transmit without an explicitly permitted lab frequency, power and target.

**Wiring example (only for the documented 3.3 V discrete module):** the [quen0n community reference](https://github.com/quen0n/flipperzero-ext-cc1101) maps Flipper **2/MOSI, 3/MISO, 4/CS, 5/SCK, 6/GDO0, 9/3V3 and 11/GND**. This is **not a universal carrier-board pinout**; vendor-assembled boards and combo modules may route pins differently. Validate against the specific PCB before using wires.

#### Lab B — nRF24: Owned 2.4 GHz Telemetry & Channel Awareness

**Purpose:** validate a dedicated nRF24/Si24R1 module using one or two **test-dev-board nRF24 transmitters**, while documenting that a channel observation is not proof of a vulnerable mouse or a Bluetooth/Wi-Fi association.

1. Identify whether the Flipper accessory is bare nRF24, an Si24R1-compatible board, or a dual-module combo. Confirm SPI wiring, `CE`, `CSN` and 3.3 V supply; a 5 V GPIO power pin must **not** feed an unregulated nRF24 radio.
2. Install a **compatible nRF24 channel/spectrum app** from [Flipper's official Apps catalog](https://lab.flipper.net/apps) or the module vendor. Third-party app availability and API compatibility vary across Official, Momentum, Unleashed and RogueMaster builds.
3. Configure a separate owned nRF24 dev board to send a **synthetic, non-sensitive telemetry sequence** on one documented 2.4 GHz channel. Keep distance short, power low and transmission constrained to the test fixture.
4. Observe the test channel using the Flipper accessory's supported **receive/scan** workflow. Turn off the transmitter as a negative control; repeat three times.
5. Record app name/API, nRF type, pin mode, channel, scan duration and presence/absence. Do not claim that a generic 2.4 GHz energy indication decodes a packet or attributes it to one transmitter.
6. Confirm that unrelated BT, BLE or 802.11 activity is *not* automatically identifiable by an nRF24 receiver. For actual Wi-Fi inventory use a supported ESP32-C5/BW16/Kismet radio; for BLE advertisements use a compatible BLE-capable device and scanner.

**Security exercise:** demonstrate why unencrypted proprietary peripherals need vendor firmware updates and appropriate physical trust boundaries; use only test transceivers and synthetic data. Do not run mousejacking, HID injection, protocol spoofing or packet interference against real peripherals.

**Discrete classic nRF24L01+ reference:** one commonly documented scheme uses Flipper pins **2=MOSI, 3=MISO, 4=CSN, 5=SCK, 6=CE, 8=GND, 9=3V3**; IRQ may be disconnected. This is a *reference only*, not a guarantee for Si24R1, powered-PA, combo, or re-routed bus variants. See [UberGuidoZ GPIO collection](https://github.com/UberGuidoZ/Flipper/tree/main/GPIO).

#### Lab C — PINGEQUA CC1101 + nRF24 Two-in-One Module

1. Confirm it is the actual [PINGEQUA 2-in-1 board](https://github.com/pingequalab/rf-lab), not a superficially similar dual-radio product.
2. Choose the module's [RF Lab companion app](https://github.com/pingequalab/rf-lab) that explicitly matches the **Flipper firmware API**. The vendor has distinct FAP builds; an API mismatch is a packaging/compatibility problem, not necessarily a faulty module.
3. Begin with **receive-only** channel observations using your owned nRF24 fixture from Lab B, then switch to receive-only Sub-GHz operation using the CC1101 fixture from Lab A. Record selected chip and expected antenna.
4. If testing an unrelated third-party nRF app on supported Momentum builds, consult PINGEQUA's **`Settings → Protocols → GPIO Pins → NRF24 SPI → Extra 7`** routing instructions; the default SPI route may not work.
5. Switch back to the internal Sub-GHz transceiver and verify neither radio remains active unexpectedly. No transmit/jammer modes are needed for this qualification.

**Interpretation:** two radios on one expansion are not simultaneous general-purpose receivers unless the specific hardware/app implements that; one FAP's success does not prove another FAP's SPI routing or feature compatibility.

#### Lab D — AWOK Dual C5 Touch/Mini: Two-MCU Identity & Observation

**Use the exact [AWOK guide](../Wardriving/awok-dual-c5-biscuit.md) for independent MCU, connector, GNSS and Biscuit imaging details.** AWOK describes the **Dual C5 Touch** as two ESP32-C5-WROOM chips, with an integrated L1/L5 GNSS module communicating to both; one C5 manages the touchscreen, the other is available via CLI/GPIO. This hardware ships **without a universal bundled firmware**, so feature lists from Marauder or Biscuit are not automatic properties of the board.

1. Power down and photograph the PCB/revision. Identify the display-side and secondary-side USB connectors per the model instructions; distinguish Touch from Mini before choosing any image.
2. On an isolated PC, query boot/version information for **each C5 separately** and record the physical port, bootloader mode, image, chip identity and rollback source. Never flash a Mini display binary onto Touch or overwrite both chips with the same generic C5 build.
3. Install only an **upstream-documented** compatible firmware on the intended MCU. If using Biscuit on the documented side, follow [AWOK + Biscuit](../Wardriving/awok-dual-c5-biscuit.md) and the [Biscuit ecosystem workflow](../Wardriving/biscuit.md). If using Marauder, confirm a model-specific target through the [official hardware list](https://github.com/justcallmekoko/ESP32Marauder/wiki/Supported-Hardware).
4. Connect the approved Flipper UART companion only after validating pins/power and FAP compatibility. A working touchscreen on one C5 does **not** demonstrate UART control of the other C5.
5. Run two separate short scans of **one owned test AP**, log which MCU/radio observed it, and compare BSSID, channel, time and band. One ESP32-C5 cannot listen simultaneously to every 2.4/5 GHz channel.
6. If GPS-tagging, identify **whether the source is on-board GNSS or a phone/app location**; Biscuit Manager's standard export uses phone GPS even if AWOK has a wired GNSS receiver. AWOK Mini/Touch do not have an onboard microSD in the reviewed Biscuit configuration.
7. Power off, restore intended firmware roles and compare both C5s to the preflight inventory. Do not merge results without duplicate handling and clock/GNSS provenance.

**Use case:** verify a dual-receiver field survey's auditability; it is not proof of greater RF sensitivity, coordinated capture, or one-click 5 GHz support for every firmware build.

#### Lab E — BW16 / RTL8720DN: Correct Firmware & Dual-Band Survey

**BW16 is a Realtek RTL8720DN (AmebaD) board**, not an ESP32. Common Flipper ecosystems include the [PINGEQUA 5Ghost](https://flash.pingequa.com/devices/bw16-5ghost) firmware/app pair, [jblanked FlipperHTTP](https://github.com/jblanked/FlipperHTTP/tree/main/BW16), and separately distributed third-party R4TKN variants. These are **not interchangeable artifacts**, and an `ESP32Marauder` binary is not a BW16 image.

1. Read the **actual product label/firmware**. Select one verified software family. Back up known-working firmware, UART pinout and FAP revision before changing it.
2. For a PINGEQUA **5Ghost** board, use the [board-specific official flasher](https://flash.pingequa.com/devices/bw16-5ghost) **only if an update/recovery is needed**: many ship preloaded. It documents the Realtek bootloader and safe USB-C data flashing; use its BOOT/RESET path rather than generic ESP32/esptool offsets.
3. Install the matching [5Ghost WiFi Lab FAP](https://flash.pingequa.com/devices/flipper-pingequa) on the Flipper; that app installation does **not** flash BW16 firmware. For **FlipperHTTP**, follow its separate BW16 board directory and compatible FlipperHTTP app/transport. Don't mix these clients.
4. Record UART pins from the **actual carrier**. Bare BW16 FlipperHTTP documentation shows `SERIAL1_TX/PB1 → Flipper pin 14 RX` and `SERIAL1_RX/PB2 → Flipper pin 13 TX`, plus correct supply and ground; pre-assembled modules may route differently. **Never infer wiring from a different module.**
5. On a controlled pair of APs, scan one distinct 2.4 GHz SSID and one 5 GHz SSID. Record BSSID, channel, advertised security and scan time. Check against the AP controller.
6. Repeat with the controlled 5 GHz AP disabled, then enabled. A scan is a visibility test, not a throughput or management-frame security audit.
7. Document BW16 firmware version, FAP/API, both AP configurations, actual bands scanned, antenna, power source and any errors. Retain the initial image for rollback.

**What not to assume:** dual-band means all channels or 2.4/5 GHz simultaneous packet capture; the Flipper itself still cannot scan Wi-Fi without the external board. A third-party board combining **BW16+nRF24** may wire its nRF24 to the **BW16**, not to Flipper SPI; follow the exact vendor firmware and app rather than attempting Lab B's GPIO pinout.

#### Lab F — Rabbit-Labs Poltergeist: Wi-Fi, IR & SD Acceptance

The [Rabbit-Labs Poltergeist](https://rabbit-labs.com/product/rabbit-labs-poltergeist-5ghz-wifi-board/) is an ESP32-C5-based Flipper-compatible **or standalone USB-C** accessory. The vendor lists a dual-band Wi-Fi radio, OLED, microSD, IR receiver, and four high-output 940 nm IR LEDs, with optional firmware-dependent IR routing through Flipper or ESP32 and [GhostESP](https://github.com/GhostESP-Revival/GhostESP). Features may remain unimplemented or change by release: an OLED/IR board label is **not evidence every command exists**.

**Hardware safety from Rabbit-Labs:** some boards have **six LED pads with only four LEDs populated intentionally**. **Do not install additional LEDs**: Rabbit-Labs warns this can draw too much current and damage the Flipper. A pre-flashed/QC-tested board does not guarantee suitability of every optional firmware feature.

1. Record PCB revision, original firmware and OLED state; save SD data/settings. Inspect the IR LEDs/receiver and **do not add components** to empty LED pads.
2. Attach a verified suitable power source and USB-C data cable. If changing firmware, use [Rabbit-Labs' referenced flasher](https://flasher.site/) with the **Poltergeist-specific** target/recovery path; a generic ESP32-C5 image may omit display, IR routing or SD pin mapping.
3. Validate standalone USB operation first: boot/OLED, SD recognition and a short **owned test-AP scan**. Do not initiate captive portals, disruptive association tests or broad active scans.
4. If connecting to Flipper, power down first; verify GPIO/serial wiring and choose the compatible companion FAP for the **installed firmware**. Distinguish Flipper UI issues from Poltergeist firmware issues by testing standalone.
5. Repeat Lab E's short 2.4/5 GHz AP visibility test, recording firmware, radio channel support and 5 GHz coverage caveats.
6. **IR receive-first exercise:** point a harmless owned TV/projector remote at the receiver in a controlled room. If the installed supported GhostESP build exposes IR receiving, record a decoded protocol and button code **without assuming all formats are supported**.
7. **Optional IR transmission:** only with explicit owner permission and a noncritical powered test device, send one known-safe command. Avoid eyes, safety-critical equipment, locks, vehicles and continuous transmission. Account for the vendor's focused high-output IR emitter and elevated power consumption.
8. Test a synthetic file on SD, verify actual exported path, hash it on the evidence workstation and restore the normal configuration. Do not assume Marauder `wardrive_` files are produced by GhostESP/Poltergeist.

**Troubleshooting:** wrong OLED target/image, missing SD filesystem, Flipper UART/FAP mismatch, inadequate power, RF antenna/region/channel, unsupported IR feature, or trying an ESP32-S2-only build on the C5.

#### Lab G — GPS & External Peripheral Selection

- **GPS/GNSS:** choose a documented board/receiver with a known UART baud/pin map, record fix quality/time and compare to a known outdoor position. Do not infer geotagging from the presence of an antenna, a scanner app, or a serial stream alone. The [Scout Lite/SigRoam guide](../Wardriving/sigroam-scout-lite.md) describes a particular GNSS and SD route; the [Biscuit app](../Wardriving/biscuit.md) generally uses phone location.
- **UART / RS-232:** Flipper's exposed UART is a **3.3 V logic** interface. Cisco/RJ45 console pin layouts and voltage conventions vary; use an electrically appropriate converter and check the actual target manual before wiring. A physically compatible cable is not proof of logic-level compatibility.
- **IR blaster/receiver:** verify whether the Flipper or expansion MCU controls the LED, whether a firmware/app route exists and what current is permitted. Start receive-only with an owned remote.
- **CAN / vehicle diagnostics:** require a **CAN transceiver and model-specific adapter** rather than raw GPIO wires. Work on an isolated bench CAN simulator; never send unexplained frames to a moving vehicle or safety-critical system.
- **Video Game Module, storage, NFC/RFID front ends and microcontroller accessories:** treat each as a separate firmware/peripheral target. Never assume a Wi-Fi accessory adds NFC, LF RFID, GPS or USB HID hardware.

#### Lab H — Combined Authorized Field Assessment & Report

**Example client-approved workflow (no disruptive features):**

1. **Asset 1:** use internal CC1101 and an optional verified external module to observe an owned, noncritical RF fixture. Record signal consistency, antenna/band, internal vs external selection.
2. **Asset 2:** observe an owned 2.4 GHz nRF24 telemetry test board and its disabled negative control. Do **not** claim it is BLE or Wi-Fi.
3. **Asset 3:** use either AWOK Dual C5, BW16, Poltergeist or a compatible external ESP32 board to inventory a client-owned 2.4/5 GHz test SSID, verifying BSSIDs and security settings in the controller.
4. **Asset 4:** if the installed board supports GNSS, verify the *actual* location source and file destination. Keep third-party/public upload disabled unless separately authorized.
5. **Blue-team comparison:** correlate time and in-scope SSID/BSSID against [Kismet + Wazuh](../IncidentResponse/IDS%26IPS/kismet-wazuh-wireless-lab.md), [nzyme + Wazuh](../IncidentResponse/IDS%26IPS/nzyme-wazuh-integration.md), or controller logs. These add-ons do **not** automatically export directly into Wazuh.
6. **Closure:** power down each module, remove temporary test SSIDs/transmitters, confirm the Flipper internal functions work, collect redacted results and validate the planned rollback.

| Finding/record | Minimum evidence |
|---|---|
| Authorization | Signed scope, approved assets/bands/channels, operator, start/stop time |
| Hardware | Flipper firmware/API, FAP, board vendor/revision, radio chip, power & antenna |
| Image & app | Exact firmware target, source URL, checksum, update/rollback path |
| Observation | Test fixture ID, band/channel, actual logs, duplicate/GPS handling |
| Corroboration | AP controller, independent RF receiver or WIDS event and time |
| Interpretation | Expected vs observed, false positives, uncertainty and remediation |
| Cleanup | Module removed, default radio restored, evidence redacted/retained |

#### Expansion Board Troubleshooting Matrix

| Symptom | Likely cause & first recovery |
|---|---|
| Flipper reboots or expansion is hot | Power/short/overcurrent, wrong pin orientation; **disconnect and inspect** |
| CC1101 absent or weak | Antenna/band mismatch, wrong SPI/GDO pins, internal/external app option, supply |
| nRF24 app sees no module | SPI/CE/CSN mismatch, 3.3 V instability, FAP/API, non-default combo pins |
| Dual C5 scans mismatch | Independent MCU images, radio scheduling, band/antenna, clocks, GPS provenance |
| BW16 FAP cannot connect | Wrong firmware family, Realtek vs ESP32 image confusion, UART/power/API |
| Poltergeist OLED works, IR fails | Selected firmware has not implemented IR path; check routing and safe power |
| Scan sees no 5 GHz AP | ESP32-S2/nRF24/CC1101 cannot scan it; verify BW16/C5 target, channel and firmware |
| PCAP/CSV missing | Actual board SD/Flipper SD/app export, save mode, clock/fix and media integrity |
| App loads but errors | Firmware API mismatch, different expected hardware or stale FAP |
| Normal Flipper app misbehaves afterward | Exit companion, power down/disconnect expansion, restore default GPIO/radio state |

#### Official & Primary References

- [Flipper GPIO and module safety](https://docs.flipper.net/zero/gpio-and-modules) · [Flipper Sub-GHz and CC1101](https://docs.flipper.net/zero/sub-ghz) · [Apps catalog](https://docs.flipper.net/zero/apps).
- [Community CC1101 pinout](https://github.com/quen0n/flipperzero-ext-cc1101) · [Community nRF24 wiring](https://github.com/UberGuidoZ/Flipper/tree/main/GPIO).
- [PINGEQUA RF Lab / combo pin map](https://github.com/pingequalab/rf-lab) · [nRF24 vendor support](https://www.pingequa.com/pages/support-flipper-zero-nrf24-module).
- [AWOK Dual C5 Touch specification](https://awokdynamics.com/products/dual-c5-touch) · [existing AWOK setup and firmware split](../Wardriving/awok-dual-c5-biscuit.md).
- [PINGEQUA BW16 5Ghost firmware](https://flash.pingequa.com/devices/bw16-5ghost) · [matching Flipper FAP](https://flash.pingequa.com/devices/flipper-pingequa) · [FlipperHTTP BW16](https://github.com/jblanked/FlipperHTTP/tree/main/BW16).
- [Rabbit-Labs Poltergeist and manufacturer warnings](https://rabbit-labs.com/product/rabbit-labs-poltergeist-5ghz-wifi-board/) · [GhostESP project](https://github.com/GhostESP-Revival/GhostESP).
- [Marauder for Flipper](#flipper-marauder-companion-deployment-labs) · [SigRoam](../Wardriving/sigroam-scout-lite.md) · [Sub-GHz & nRF24 overview](../SDR/subghz.md#-6-dedicated-hardware-chips-cc1101-vs-nrf24l01) · [wireless survey index](../Wardriving/README.md).

## 12. Bluetooth

### Overview

BLE 5.0 via the STM32WB55 co-processor. Used for:
- Flipper mobile app connectivity
- BLE HID (Bluetooth keyboard/mouse emulation)
- BLE scanning and advertising
- BLE-based attacks via apps

### BLE Spam (App)

**Apps → Bluetooth → BLE Spam**

Floods nearby devices with BLE advertising packets, triggering pairing/notification popups on:
- **Apple devices**: Fake AirPods pairing, AirTag found nearby, Apple TV setup, Apple Watch pairing
- **Android**: Fast Pair device popups (Samsung, Google Pixel, etc.)
- **Windows**: Swift Pair device popups

**Pentesting use:** Demonstrates BLE attack surface, proximity-based notification spam, and Bluetooth advertising exploitation. Effective physical security awareness demonstration.

**Modes:**
- iOS: AirPods Pro, AirPods Max, various Apple product spoofs
- Android: Fast Pair with various device profiles
- Windows: Swift Pair popups
- Spam All: cycles through all profiles

### Bluetooth Remote

**Apps → Bluetooth → Bluetooth Remote**

Pairs as a BLE HID device and presents a navigation remote. Useful for controlling presentations wirelessly without a dedicated clicker.

### Bad BT (App)

BLE HID keyboard injection - connects wirelessly and injects keystrokes, same as BadUSB but over Bluetooth. Requires pairing first (target must accept connection).

**Use case:** USB ports blocked or disabled on target workstation, but Bluetooth is available.

### BLE Scanner (via Marauder)

With the WiFi Dev Board, Marauder can perform detailed BLE scanning - see BLE section under WiFi Dev Board.

---

## 13. WiFi - ESP32 Dev Board

### Overview

The ESP32-S2-based WiFi Development Board attaches to the Flipper's GPIO header and provides 802.11 b/g/n WiFi capabilities. Flashed with **Marauder firmware**, it becomes a pocket WiFi pentesting platform controlled via the Flipper's UI and screen.

### Hardware Setup

1. Attach WiFi Dev Board to GPIO header (keyed, only fits one way)
2. Flash Marauder firmware onto the ESP32:
   - Windows: Use Spacehuhn's ESP web flasher at `esptool.spacehuhn.com` (general-purpose ESP32 flasher, not Marauder-specific)
   - Or: download Marauder binary from `github.com/justcallmekoko/ESP32Marauder/releases`
3. Install Marauder Companion app on Flipper (Flipper Lab)

### Marauder Firmware Capabilities

#### WiFi Scanning
- **Scan APs**: Lists all visible access points with SSID, BSSID, channel, signal strength, encryption type
- **Scan Stations**: Lists connected client devices
- **Scan AP+Station**: Combined view showing which clients are connected to which APs

#### Deauthentication Attacks
**802.11 deauthentication frames** - disassociates clients from their AP:
- `attack -t deauth` - deauth all scanned APs
- `attack -t deauth -b [BSSID]` - target specific AP
- Select target from scan results in Marauder UI before running attack

> **Pentest use**: Demonstrate that anyone within radio range can forcibly disconnect clients. Effective for showing client why open/public WiFi is dangerous, and why 802.11w (Management Frame Protection) should be enabled.

#### PMKID / Handshake Capture
On compatible targets and explicitly approved laboratory networks, certain capture modes may obtain WPA2-Personal authentication material. This is not equivalent to WPA3-SAE credential recovery:
1. Scan APs → select target
2. `attack -t pmkid` - attempts PMKID collection where supported by AP/client exchange; **PMKIDs are not simply captured from beacons**
3. Or: `attack -t wpa` - captures full 4-way handshake (requires client authentication)
4. Save `.pcap` to SD card
5. Transfer to Kali → `hashcat -m 22000 capture.hc22000 wordlist.txt`

#### Evil Portal (Captive Portal)
Hosts a fake WiFi login page:
1. Configure SSID name in Marauder settings
2. Start Evil Portal
3. The connected ESP32 accessory broadcasts the SSID when supported and deliberately enabled
4. Connecting clients are redirected to captive portal
5. Credentials captured to SD card log

**Included portal templates:**
- Generic WiFi login
- Hotel portal
- Coffee shop portal
- Custom HTML (place in SD card)

#### Beacon Spam
Broadcasts hundreds of fake SSIDs simultaneously:
- Confuses WiFi scanners
- Can be used to broadcast custom SSID messages
- Demonstrates WiFi landscape manipulation

#### Packet Monitor
Real-time channel-by-channel packet activity visualization. Useful for identifying:
- High-traffic channels to avoid or investigate
- Presence of hidden networks
- Anomalous traffic patterns

#### BLE Scanning (via Marauder)
BLE features require a **separate Bluetooth-capable ESP32 accessory and supported Marauder build**. The stock ESP32-S2 Flipper WiFi Dev Board has no Bluetooth support. On supported BLE hardware, observed advertisements may expose manufacturer/service data; availability and logging depend on firmware.

### Marauder Companion App (Flipper)

Provides UI control of Marauder from the Flipper screen without needing a serial terminal. Install from Flipper Lab.

**Menu structure:**
```
Marauder Companion
├── WiFi Attacks
│   ├── Scan APs
│   ├── Scan Stations
│   ├── Deauth Attack
│   ├── PMKID Attack
│   ├── Evil Portal
│   └── Beacon Spam
├── Bluetooth
│   ├── BLE Scan
│   └── BLE Spam
├── Packet Monitor
└── Settings
```

### Flipper Marauder Companion Deployment Labs

**Critical separation:** the Flipper Zero runs its own firmware and the companion application (`.fap`), while a **compatible connected ESP32 board** runs Marauder. The Flipper does **not** contain a Wi-Fi radio. A Flipper Zero WiFi Dev Board (ESP32-S2) takes a Marauder image ending in `_flipper.bin`; a Marauder Dev Board Pro, BFFB, MultiBoard S3 or C5 expansion requires its **own** matching target, not the same image. See the [standalone Marauder field labs](./WiFiMarauder_Guide.md#dedicated-standalone-marauder-deployment-playbook) and [upstream Flipper instructions](https://github.com/justcallmekoko/ESP32Marauder/wiki/Flipper-Zero).

#### F0 — Prepare Flipper & Expansion Separately

1. Note Flipper firmware build, Marauder companion app version, expansion model/PCB revision, ESP32 chip and Marauder version. Photograph the board label without exposing serial numbers publicly.
2. Backup the Flipper SD and any board SD logs. Update the Flipper through its own trusted update path; install a companion application compatible with the **installed Flipper firmware** using [Flipper Lab](https://lab.flipper.net/apps/esp32_wifi_marauder) or a maintained matching build.
3. With the ESP32 expansion disconnected, identify its matching target from [Marauder supported hardware](https://github.com/justcallmekoko/ESP32Marauder/wiki/Supported-Hardware) and use the [official Marauder updater](https://github.com/justcallmekoko/ESP32Marauder/wiki/Update-Firmware) or validated flasher. For the stock Flipper WiFi Dev Board, select `_flipper.bin`; do not use a standalone display image.
4. Power off/reseat the accessory, connect it to the Flipper GPIO header and open the companion app. Confirm supported communication before any field survey. Keep SD/serial logging settings consistent with the installed build.
5. Run **only the owned-test-AP scan** first, not an active attack menu. If the FAP cannot communicate, verify UART, companion/resources, firmware target, power and USB CLI separately.

#### F1 — Companion-Link Acceptance

1. Record the Flipper app and accessory firmware versions side by side.
2. With a known lab AP powered on, open the companion's supported AP scan. Observe one matching BSSID/channel.
3. Repeat after a deliberate app restart to distinguish transient UART errors from persistent firmware mismatch.
4. Record scan result, timing, error messages and missing feature menus. Do not assume older Flipper app screenshots match a current build.

**Pass:** an in-scope AP can be observed reproducibly with no unexpected transmissions, reboot, or loss of operator control.

#### F2 — On-Device Logging & SD Storage Provenance

1. Check whether the **specific app/build** writes to Flipper SD, the external ESP32 SD, or neither. Some boards need an added microSD circuit, and not all app functions save the same artifact.
2. Make one short authorized observation of a synthetic SSID, then stop it and safely close logging.
3. Verify actual filename and storage location. For supported GNSS wardriving, consult the [Marauder GPS guide](../Wardriving/esp32-marauder.md) and record fix status; Wi-Fi AP scans alone do not establish location.
4. Export only the in-scope result, hash the original on the evidence workstation, and note whether a PCAP contains full frames or just summaries.
5. If the Flipper SD remains empty, inspect companion settings and accessory SD support before repeating a scan.

#### F3 — Wi-Fi Security Settings & WIDS Correlation

1. Compare the accessory's observations of a **lab** SSID with the AP controller's WPA2/WPA3, channel and PMF configuration.
2. Create a separate unique training SSID on a client-owned AP, record its BSSID, and observe its appearance from the Flipper app.
3. Compare independent [Kismet + Wazuh](../IncidentResponse/IDS%26IPS/kismet-wazuh-wireless-lab.md) observations to the Flipper/app log and AP controller. A successful match verifies visibility, not exploitability.
4. Stop the test AP and confirm expected disappearance and SIEM alert disposition; preserve redacted evidence.

#### F4 — Lab Wireless Coverage & Radio Capability Checks

1. Place owned test APs on explicitly permitted 2.4 GHz and (when hardware supports it) 5 GHz channels.
2. Use the Flipper companion to record **which** APs actually appear, along with band/channel, antenna orientation and dwell time.
3. A stock ESP32-S2 WiFi Dev Board is **2.4 GHz only** and has **no Bluetooth radio**. Do not interpret failure to detect a 5 GHz AP or BLE tag as a missing network/device.
4. On 5 GHz-capable C5 expansions, confirm the actual model, antenna and firmware build before claiming dual-band coverage.
5. Use external sensors/controller inventory when a full site survey or throughput test is needed.

#### F5 — Peripheral Compatibility & Recovery Drill

1. While the test accessory is disconnected, preserve a known-working firmware image and identify the board's bootloader/recovery path.
2. Install only a confirmed-compatible release, restart the Flipper app, and verify F1's known-AP test.
3. If the connection fails, test the ESP32 directly via supported USB serial CLI; this separates ESP firmware/radio issues from the Flipper companion link.
4. Avoid flashing the wrong partition table, board family or voltage domain. Power down before modifying a breakout. Never treat a failed firmware update as license to erase client data.
5. Document successful rollback and any SD-card integrity warnings.

#### Flipper-Specific Common Failure Matrix

| Symptom | Likely cause & validation |
|---|---|
| "No Marauder" / serial timeout | Unsupported FAP, wrong ESP32 firmware target, loose GPIO connection, serial Log Device conflict or insufficient power |
| Scan works, no stored PCAP | Missing SD, app export path mismatch or unsupported capture mode |
| BLE menu missing on ESP32-S2 | Expected hardware limitation; the S2 cannot run BLE scanning |
| 5 GHz SSID absent | ESP32-S2 cannot scan 5 GHz; check C5 expansion and firmware if applicable |
| Scan data differs from standalone Marauder | Companion app feature coverage, serial transport, storage and build differ |
| Failed reflash/boot loop | Restore exact board firmware and partition layout from the supported installer |

**Reporting:** identify Flipper firmware/FAP and ESP32 firmware separately. Include authorization, BSSID/SSID redaction, timestamps, expected versus actual result, GNSS/storage provenance, USB/UART state, AP configuration evidence, WIDS corroboration and cleanup. Do not equate credential/handshake collection with ordinary reconnaissance or infer WPA3-Enterprise vulnerabilities from a scan.

### Post-Capture: Cracking WPA2

After capturing a handshake `.pcap`:

```bash
# Convert pcap to hashcat format
hcxpcapngtool -o hash.hc22000 -E essids capture.pcap

# Crack with hashcat
hashcat -m 22000 hash.hc22000 /usr/share/wordlists/rockyou.txt

# With rules for better coverage
hashcat -m 22000 hash.hc22000 rockyou.txt -r /usr/share/hashcat/rules/best64.rule

# PMKID only
hashcat -m 22000 hash.hc22000 rockyou.txt --attack-mode 0
```

---

## 14. Apps - Full Catalog

### NFC Apps

| App | Source | Description |
|---|---|---|
| **MFKey** | Flipper Lab | Mifare Classic key recovery via reader nonce capture |
| **MIFARE Classic Editor** | Flipper Lab | Read/write/edit Mifare Classic sector data |
| **NFC Magic** | Flipper Lab | Write to Gen1/Gen2 magic cards for cloning |
| **Mifare Nested** | Unleashed/Momentum | Nested attack for offline key recovery |
| **Picopass** | Flipper Lab | HID iClass card reading and emulation |
| **MFP Reader** | Flipper Lab | Mifare Plus SL3 reader/dumper |
| **NFC Playlist** | Flipper Lab | Cycle through saved NFC cards automatically |
| **NFC Login** | Flipper Lab | Use NFC card as PC login credential via USB HID |

### 125kHz RFID Apps

| App | Source | Description |
|---|---|---|
| **RFID Fuzzer** | Unleashed/Momentum | Brute-force credential ranges |
| **Seader** | Flipper Lab | Raw Wiegand capture via GPIO (connects to real reader) |
| **Wiegand** | Flipper Lab | Wiegand protocol analysis and injection |

### Sub-GHz Apps

| App | Source | Description |
|---|---|---|
| **Sub-GHz Bruteforcer** | Unleashed/Momentum | Fixed-code fuzzing (Princeton, CAME, etc.) |
| **Sub-GHz Remote** | Flipper Lab | Custom remote button layouts for saved signals |
| **Sub-GHz Playlist** | Flipper Lab | Sequence multiple Sub-GHz transmissions |
| **Spectrum Analyzer** | Flipper Lab | Real-time RF spectrum visualization |
| **POCSAG Pager** | Flipper Lab | Decode POCSAG pager messages |
| **Weather Station** | Flipper Lab | Decode 433MHz weather sensor data |
| **Sub-GHz Chat** | Flipper Lab | Text messaging over Sub-GHz (Flipper to Flipper) |

### Infrared Apps

| App | Source | Description |
|---|---|---|
| **Brute Force IR** | Momentum | Iterate through all codes for device type |
| **IR Scope** | Flipper Lab | Visualize raw IR signal waveforms |
| **TV Remote (universal)** | Built-in | Large built-in IR remote database |

### GPIO / Hardware Apps

| App | Source | Description |
|---|---|---|
| **UART Terminal** | Flipper Lab | Serial console via GPIO pins |
| **Logic Analyzer** | Flipper Lab | 4-channel digital signal capture |
| **I2C Scanner** | Flipper Lab | Scan I2C bus for device addresses |
| **SPI Tools** | Flipper Lab | SPI device communication |
| **Tone Generator** | Flipper Lab | Square wave output on GPIO |
| **Wire Tester** | Flipper Lab | Continuity testing |
| **GPIO Unlocker** | Flipper Lab | Unlock 5V on GPIO pin 18 |
| **Oscilloscope** | Flipper Lab | Basic voltage waveform display |
| **PWM** | Flipper Lab | PWM signal generation |
| **Unitemp** | Flipper Lab | Temperature/humidity sensor reading (DHT, DS18B20) |

### WiFi (ESP32) Apps

| App | Source | Description |
|---|---|---|
| **Marauder Companion** | Flipper Lab | Full UI for ESP32 Marauder WiFi attacks |
| **WiFi Scanner** | Flipper Lab | Basic AP scanning |
| **Evil Portal** | Flipper Lab | Standalone captive portal (Marauder-based) |
| **Diabolic Drive** | Flipper Lab | WiFi-controlled BadUSB via ESP32 |

### Bluetooth Apps

| App | Source | Description |
|---|---|---|
| **BLE Spam** | Momentum/Unleashed | BLE advertising spam (iOS/Android/Windows) |
| **Bluetooth Remote** | Built-in | BLE HID remote control |
| **Bad BT** | Momentum/Unleashed | BLE HID keyboard injection |
| **BLE Keyboard** | Flipper Lab | Custom BLE keyboard emulation |
| **FindMy Flipper** | Flipper Lab | Spoof Apple AirTag location beacons |

### BadUSB Apps / Scripts

| File | Description |
|---|---|
| **PNWC Payload Library** | Full suite - see separate documentation |
| **Rubber Ducky scripts** | Compatible with existing Hak5 .txt payloads |
| **UAC bypass demo** | Common UAC bypass demonstration |
| **Windows enumeration** | Quick user/network enumeration |

### Security / Pentesting Apps

| App | Source | Description |
|---|---|---|
| **TOTP Authenticator** | Flipper Lab | Hardware TOTP token (Google Auth compatible) |
| **Password Manager** | Flipper Lab | Local encrypted credential store |
| **U2F** | Built-in | FIDO U2F hardware security key |
| **WiFi Marauder** | ESP32 firmware | Full WiFi attack suite |
| **Seader** | Flipper Lab | Wiegand reader interface for badge capture |

### Productivity / Utility Apps

| App | Source | Description |
|---|---|---|
| **Multi Converter** | Flipper Lab | Unit conversion, base conversion (hex/bin/dec) |
| **Calculator** | Flipper Lab | Basic calculator |
| **Metronome** | Flipper Lab | Timing tool |
| **Barcode Generator** | Flipper Lab | Generate and display barcodes |
| **QR Code** | Flipper Lab | Generate/display QR codes |
| **Resistance Calc** | Flipper Lab | Resistor color band calculator |
| **WAV Player** | Flipper Lab | Audio playback via GPIO (DTMF replay etc.) |
| **Text Viewer** | Flipper Lab | Read text files from SD card |
| **HEX Viewer** | Flipper Lab | Inspect binary files on SD card |

### Games (Non-pentesting)
Portal of Flipper, Doom, Tetris, Snake, Flappy Bird - various on Flipper Lab. Useful for social engineering "hey look at this" openers.

---

## 15. Pentesting Workflows

### Pre-Engagement Prep

Before any physical pentest engagement:

- [ ] Charge Flipper to 100%
- [ ] Verify SD card has all payloads loaded
- [ ] Test BadUSB payloads on your own machine
- [ ] Confirm LHOST/LPORT in reverse shell payloads
- [ ] Verify listener is reachable from test network
- [ ] Load relevant Sub-GHz frequencies for client region
- [ ] Carry blank T5577 RFID cards and Gen2 NFC magic cards

### Physical Access Control Assessment

**Step 1: Reconnaissance**
- Visually identify card readers on target doors
- Note manufacturer logos (HID, Allegion, Bosch, Honeywell)
- Identify card format used by employees (proximity, smart card, iClass)

**Step 2: Card Capture**
- LF (HID Prox / EM4100): `125kHz RFID → Read` - works through wallets/purses at ~5cm
- HF Mifare Classic: `NFC → Read` - brief contact needed
- HF iClass: `Apps → Picopass → Read`

**Step 3: Reader Nonce Capture (Mifare Classic)**
- `NFC → Detect Reader` - hold Flipper near reader
- Captures crypto nonces → `Apps → NFC → MFKey → Run`
- Recovers sector keys in ~30 seconds

**Step 4: Full Card Read**
- Re-read target card with recovered keys
- `NFC → Saved → [card] → Read (full)`

**Step 5: Cloning**
- Write to Gen2 magic card: `NFC → Saved → [card] → Write`
- Test clone at reader
- Write to T5577 for LF cards: `125kHz RFID → Saved → [card] → Write`

**Step 6: Documentation**
- Photograph access readers
- Note card type, reader model, facility code
- Document clone success/failure
- Provide client with physical clone card as evidence

### Wireless Assessment

**Sub-GHz Assessment:**
1. `Sub-GHz → Frequency Analyzer` - identify active frequencies on site
2. `Sub-GHz → Read` - capture gate/door/barrier remotes
3. Test replay on target
4. `Sub-GHz Bruteforcer` - if fixed-code, demonstrate full code space compromise

**WiFi Assessment (with ESP32 Dev Board):**
1. Marauder → Scan APs - enumerate all SSIDs, note encryption types
2. Identify any open networks or WEP (rare but still exists)
3. Marauder → PMKID - capture from all WPA2 targets
4. Marauder → Scan Stations - identify client devices
5. Transfer .pcap to Kali → crack with hashcat
6. Marauder → Deauth - demonstrate forced disconnection
7. Document: open networks, weak passwords, lack of 802.11w

### USB Drop / BadUSB Testing

**Testing physical security:**
1. Plant Flipper at workstations (with authorization)
2. Run `win-lockscreen-awareness-test.txt` on unlocked machines
3. Document which machines were accessible and when
4. Run `win-security-audit.txt` to capture security posture
5. Run `win-sysinfo-full.txt` + `win-network-recon.txt` for full picture

**Authorized reverse shell test:**
1. Pre-position listener: `rlwrap nc -lvnp 4444`
2. Deploy `win-revshell-ps.txt`
3. Demonstrate shell access
4. Run enumeration commands in shell
5. Exit, run `win-cleanup.txt` to remove artifacts

### Social Engineering Demos

**BLE Spam demo (client meeting room):**
1. `Apps → BLE Spam → iOS → AirPods`
2. Everyone's iPhone starts showing AirPods pairing requests
3. Talking point: BLE advertising is untrusted and unauthenticated

**IR demo (boardroom projector):**
1. `Infrared → Universal Remotes → Projector`
2. Demonstrate ability to cut projector feed
3. Talking point: IR receivers are often in boardrooms, anyone can transmit

**Unlocked workstation demo:**
1. Find unlocked machine during walk-through
2. Deploy `win-lockscreen-awareness-test.txt`
3. Machine drops evidence file, shows popup, locks itself
4. Debrief with staff: "Your workstation was unlocked and we ran code on it in under 15 seconds"

### Post-Engagement Cleanup

Always run `win-cleanup.txt` after any engagement to remove:
- All `pnwc_*.txt` output files
- Beacon scripts and logs
- Registry persistence keys
- Temp PowerShell scripts

---

## 16. IT Admin Workflows

### Onsite Client Visit

**Fast intake workflow:**
1. Plug Flipper into client machine
2. Run `win-intake-form.txt` - opens Notepad with auto-filled system info
3. Fill in reported issue while system info populates in background
4. Run `win-inventory.txt` - captures full HW/SW for your records

**Common issue investigation:**
- Slow machine: `win-sysinfo-full.txt` → check process list and startup items
- Network issues: `win-network-recon.txt` → check IP config, DNS, active connections
- Security concern: `win-security-audit.txt` → full posture check in one shot

### Network Troubleshooting

**Identify hosts on client network without Nmap:**
1. Edit `$subnet` in `win-host-discovery.txt`
2. Deploy → get ARP-based host list with DNS and open ports
3. Pairs with your laptop running Nmap for confirmation

**Console access to networking gear:**
- Connect GPIO pins 14/16/17 to RJ45 via console cable
- `Apps → GPIO → UART Terminal`
- Set baud rate (9600 for Cisco, 115200 for UniFi)
- Direct console session without carrying a USB-serial adapter

### Client Security Reviews

**Quick security posture for SMB clients:**
1. Run `win-security-audit.txt` - generates full report
2. Key items to check in output:
   - Defender real-time protection enabled?
   - UAC set to appropriate level?
   - BitLocker enabled on laptops?
   - RDP enabled/disabled as expected?
   - SMB1 disabled?
   - PowerShell logging enabled?

**Active Directory review:**
1. From a domain-joined machine, run `win-ad-enum.txt`
2. Key findings to look for:
   - Password never expires accounts
   - Stale accounts (90+ days no logon)
   - Unauthorized Domain Admin members
   - Weak password policy (length < 12, no lockout)
   - Computers running end-of-life OS

### Field Toolkit Card

Keep this reference on your phone or printed in your bag:

| Scenario | Payload/App |
|---|---|
| Quick system info | win-sysinfo-full.txt |
| Network map | win-host-discovery.txt |
| WiFi passwords | win-wifi-dump.txt |
| Security check | win-security-audit.txt |
| Full AD dump | win-ad-enum.txt |
| Console access | UART Terminal app |
| Badge clone | NFC → Read → Write |
| Gate remote copy | Sub-GHz → Read → Send |
| Client intake | win-intake-form.txt |
| Quick fixes | win-rapid-remediation.txt |
| Clean up | win-cleanup.txt |

---

## 17. Field Kit Integration

### Flipper + Existing Toolkit

| Flipper Capability | Complements | Combined Workflow |
|---|---|---|
| Sub-GHz capture/replay | HackRF One | Flipper grabs signal in field, HackRF does deep analysis back at bench (replay attacks, signal decoding, frequency deviation analysis) |
| BadUSB | Bash Bunny | Flipper for covert quick-deploy (looks like charging), Bunny for complex multi-stage payloads requiring multiple payloads |
| WiFi Marauder | WiFi Pineapple | Flipper for stealthy pocket recon, Pineapple for full engagement (deauth, PineAP, modules) |
| BLE Spam/Scan | Ubertooth One | Flipper demos attack surface to client, Ubertooth captures raw BLE traffic for analysis |
| RFID/NFC | ProxMark3 (if added) | Flipper for quick field reads, ProxMark for advanced LF/HF analysis and attacks |
| GPIO/UART | Bus Pirate 5 | Flipper for quick console access onsite, Bus Pirate for deep JTAG/SWD/SPI hardware work at bench |
| BLE HID | Rubber Ducky | Flipper covers both BadUSB and BLE, Ducky for advanced multi-payload |
| Sub-GHz | Flipper Zero SDR app | Flipper transmits, HackRF verifies signal quality |
| IR | SDR++ with RTL-SDR | Flipper quick replay, SDR for protocol analysis |

### Kali Linux Integration

**Using Flipper with Kali:**
- Post-handshake capture: `hcxpcapngtool` → `hashcat`
- BadUSB as reverse shell entry point → catch shell in `metasploit` or `nc`
- Sub-GHz captures transferred via qFlipper for URH (Universal Radio Hacker) analysis

### Home Lab Integration

**TrueNAS / Proxmox:**
- UART Terminal for serial console to servers without iDRAC/iLO
- Sub-GHz sensors can feed into Home Assistant via Marauder BLE bridge

**Home Assistant:**
- IR blaster integration: Flipper IR files compatible with HA `broadlink` format (with conversion)
- Sub-GHz sensor decoding via Marauder

---

## 18. SD Card Organization

### Recommended Structure

```
SD:/
├── apps/
│   ├── NFC/
│   │   ├── mfkey.fap
│   │   ├── nfc_magic.fap
│   │   ├── mifare_nested.fap
│   │   └── picopass.fap
│   ├── Sub-GHz/
│   │   └── subghz_bruteforcer.fap
│   ├── Bluetooth/
│   │   ├── ble_spam.fap
│   │   └── bad_bt.fap
│   ├── GPIO/
│   │   ├── uart_terminal.fap
│   │   └── logic_analyzer.fap
│   └── Tools/
│       └── totp.fap
├── badusb/
│   ├── windows-recon/
│   ├── windows-pentest/
│   ├── windows-it-admin/
│   ├── linux-recon/
│   ├── network/
│   └── social-engineering/
├── nfc/
│   ├── captures/        # Raw reads from field
│   └── clones/          # Cloned/ready cards
├── subghz/
│   ├── captures/        # Field captures
│   └── raw/             # Raw captures
├── lfrfid/
│   └── captures/
├── infrared/
│   ├── custom/          # Learned remotes
│   └── database/        # UberGuidoZ files
├── ibutton/
└── logs/
```

### Signal Databases to Add

**Sub-GHz signals (UberGuidoZ):**
```
github.com/UberGuidoZ/Flipper/tree/main/Sub-GHz
```
Download and place in `SD:/subghz/`

**Infrared codes (UberGuidoZ):**
```
github.com/UberGuidoZ/Flipper/tree/main/Infrared
```
Place in `SD:/infrared/`

**NFC tools and extra files:**
```
github.com/UberGuidoZ/Flipper/tree/main/NFC
```

---

## 19. Resources & References

### Official Resources

| Resource | URL |
|---|---|
| Flipper Zero official | flipper.net |
| qFlipper download | flipper.net/pages/downloads |
| Flipper Lab (app catalog) | lab.flipper.net |
| Official documentation | docs.flipper.net |

### Firmware

| Firmware | Repository |
|---|---|
| Unleashed | github.com/DarkFlippers/unleashed-firmware |
| Momentum | github.com/Next-Flip/Momentum-Firmware |
| RogueMaster | github.com/RogueMaster/flipperzero-firmware-wPlugins |

### Community Resources

| Resource | URL |
|---|---|
| UberGuidoZ Signal/App Collection | github.com/UberGuidoZ/Flipper |
| Awesome Flipper Zero | github.com/djsime1/awesome-flipperzero |
| Marauder Firmware | github.com/justcallmekoko/ESP32Marauder |
| Flipper subreddit | reddit.com/r/flipperzero |

### App Development

| Resource | URL |
|---|---|
| ufbt build tool | github.com/flipperdevices/flipperzero-ufbt |
| Flipper app SDK | github.com/flipperdevices/flipperzero-firmware |
| App examples | github.com/flipperdevices/flipperzero-firmware/tree/dev/applications/examples |

### Companion Tools

| Tool | Use |
|---|---|
| hashcat | WPA2 handshake cracking |
| hcxpcapngtool | Convert Marauder .pcap to hashcat format |
| Universal Radio Hacker (URH) | Analyze Sub-GHz raw captures |
| CyberChef | Decode/analyze NFC card data |
| MIFARE Classic Tool (Android) | Cross-reference NFC reads |
| Proxmark3 | Advanced LF/HF RFID (complements Flipper) |

### Legal References

- [Computer Fraud and Abuse Act (CFAA) - 18 U.S.C. § 1030](https://www.law.cornell.edu/uscode/text/18/1030)
- [Electronic Communications Privacy Act (ECPA)](https://www.law.cornell.edu/uscode/text/18/part-I/chapter-119)
- [Washington State RCW 9A.90 - Washington Cybercrime Act](https://app.leg.wa.gov/RCW/default.aspx?cite=9A.90) (RCW 9A.52.110 was repealed in 2016; current law is RCW 9A.90.040 computer trespass 1st degree, RCW 9A.90.050 2nd degree)
- [FCC Part 15 - Unlicensed RF devices](https://www.ecfr.gov/current/title-47/chapter-I/subchapter-A/part-15)

---

## Appendix: Quick Command Reference

### Sub-GHz Frequencies

| Frequency | Primary Use | Region |
|---|---|---|
| 315.000 MHz | Garage doors, auto remotes | North America |
| 390.000 MHz | Garage doors | North America |
| 433.920 MHz | EU remotes, sensors, alarms | Europe/Global |
| 434.420 MHz | Some EU systems | Europe |
| 868.350 MHz | Z-Wave EU, alarm sensors | Europe |
| 915.000 MHz | Z-Wave US, LoRa | North America |
| 925.000 MHz | ISM band devices | Global |

### Common NFC Sector Keys (Mifare Classic)

```
FFFFFFFFFFFF  (default, most common)
A0A1A2A3A4A5  (MAD sector default)
B0B1B2B3B4B5
4B0B20107CCB
AABBCCDDEEFF
000000000000
D3F7D3F7D3F7  (NFC Forum)
```

### DuckyScript Key Names

```
Special: ENTER, BACKSPACE, TAB, SPACE, CAPSLOCK, DELETE
Navigation: HOME, END, INSERT, PAGEUP, PAGEDOWN
Arrows: UP, DOWN, LEFT, RIGHT
Function: F1-F12
Modifiers: CTRL, SHIFT, ALT, GUI (Windows key)
Numpad: NUMLOCK, KP_0 through KP_9
```

### Marauder Serial Commands

```
scanap        Scan access points
scanst        Scan stations
stopscan      Stop current scan
attack -t deauth -b [BSSID]   Deauth specific AP
attack -t pmkid               PMKID capture all
stopattack    Stop current attack
list -a       List scanned APs
list -s       List scanned stations
clearlist -a  Clear AP list
clearlist -s  Clear station list
```

---

## Related Files
- [README.md](README.md) - Documentation section index: all guides and cheat sheets in this directory
- [evil_m5.md](evil_m5.md) - M5Cardputer with Evil-M5Project: complementary ESP32-based WiFi attack tool
- [bjorn_pi.md](bjorn_pi.md) - Bjorn Pi: network-service brute-force and exfiltration tool (network layer vs. Flipper's RF layer)
- [bruce_firmware.md](bruce_firmware.md) - Bruce firmware alternative for Cardputer: multi-radio (Sub-GHz, NFC, IR, BLE, FM)
- [WifiMarauder_CheatSheet.md](WifiMarauder_CheatSheet.md) - ESP32 Marauder cheat sheet (the firmware running on Flipper's WiFi Dev Board)
- [WiFiMarauder_Guide.md](WiFiMarauder_Guide.md) - Full Marauder guide for WiFi pentesting workflows
- [LAB5 MonsterC5 / projectZero](microcontroller_wifi_testing.md#lab5-c5-monster--projectzero-janos-field-assessment) - separate C5 JanOS image and `Lab_C5.fap` Flipper controller, **not** a Marauder or Evil-M5 payload
- [hcxtoolshashcat.md](hcxtoolshashcat.md) - Converting Marauder .pcap captures to Hashcat format and cracking WPA2
- [../HardwareHacking/BusPirate.md](../HardwareHacking/BusPirate.md) - Bus Pirate 5: deep hardware interface tool that complements Flipper's GPIO work
- [../HardwareHacking/Chapter1.md](../HardwareHacking/Chapter1.md) - Hardware hacking foundations (UART, SPI, I2C, JTAG)

---

*Pacific Northwest Computers | Vancouver, WA*
*github.com/Pnwcomputers/ULTIMATE-CYBERSECURITY-MASTER-GUIDE*

---
*Guide version: 1.0 | Last updated: 2026*
*For the latest version, see the GitHub repository*
