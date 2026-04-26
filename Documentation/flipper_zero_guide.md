# 🐬 Flipper Zero: Ultimate Field Guide
### Pacific Northwest Computers — PNWC Cybersecurity Master Guide
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
12. [Bluetooth](#12-bluetooth)
13. [WiFi — ESP32 Dev Board](#13-wifi--esp32-dev-board)
14. [Apps — Full Catalog](#14-apps--full-catalog)
15. [Pentesting Workflows](#15-pentesting-workflows)
16. [IT Admin Workflows](#16-it-admin-workflows)
17. [Field Kit Integration](#17-field-kit-integration)
18. [SD Card Organization](#18-sd-card-organization)
19. [Resources & References](#19-resources--references)

---

## 1. Hardware Overview

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
- **Pin 13/14** — UART TX/RX (serial console work)
- **Pin 15/16** — SPI MOSI/MISO
- **Pin 18** — 5V (from USB only, not battery)
- **Pin 1** — 3.3V regulated output (~20mA max)

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

### [RogueMaster](https://rogue-master.net/)
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
- [ ] Pair with mobile app (Flipper Mobile App — iOS/Android)

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

The CC1101 radio covers **300–928 MHz**, making the Flipper capable of receiving and transmitting most common IoT, automotive, and access control frequencies.

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
- KeeLoq (fixed code capture — not rolling)
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
- RSSI: signal strength indicator — get close to transmitter

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
3. Start — Flipper transmits codes sequentially

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
- Mifare Classic (partial — some readers detect timing differences)

### Mifare Classic Key Recovery

Mifare Classic uses 48-bit sector keys (Key A and Key B). Default keys (0xFFFFFFFF, 0xA0A1A2A3A4A5, etc.) are tried automatically. For non-default keys:

**Method 1: MFKey App (requires a real reader)**
1. Install MFKey from Flipper Lab
2. NFC → Detect Reader — hold Flipper near the target reader (badge reader on a door)
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

HID iClass is a 13.56 MHz standard common in corporate environments. Not supported by the built-in NFC app — requires the **Picopass** app.

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

> These cards transmit their ID with zero authentication — any reader in range can capture the credential. This is the lowest tier of access control security.

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

**Common client scenario**: Visitor badges at front desk use the same format as employee badges — capture visitor badge UID, clone it, present at secured doors.

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
- DS1990A (RW1990) — most common
- DS1992, DS1996 — memory types
- Cyfral, Metakom — Russian apartment systems

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

Important for special characters — `@`, `\`, `/` vary by locale. US layout is default.

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
- Not FIDO2/WebAuthn level — works for U2F only
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

Continuity tester using GPIO pins. Quick cable verification tool — handy for network cable checking on client sites.

### Raspberry Pi / SBC Integration

The Flipper can be used as a GPIO expander for Raspberry Pi projects. With `flipperzero-protobuf` and the Flipper's USB serial interface, you can script Flipper actions from Python.

### GPIO Header Modules

Several add-on boards connect to the GPIO header:

| Module | Purpose |
|---|---|
| WiFi Dev Board (ESP32-S2) | WiFi pentesting via Marauder |
| Video Game Module | Flipper gaming (not pentesting use) |
| NRF24 Module | 2.4GHz protocol analysis |
| GPS Module | Location tagging of captures |
| Servo/Motor Driver | Robotics integration |

---

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

BLE HID keyboard injection — connects wirelessly and injects keystrokes, same as BadUSB but over Bluetooth. Requires pairing first (target must accept connection).

**Use case:** USB ports blocked or disabled on target workstation, but Bluetooth is available.

### BLE Scanner (via Marauder)

With the WiFi Dev Board, Marauder can perform detailed BLE scanning — see BLE section under WiFi Dev Board.

---

## 13. WiFi — ESP32 Dev Board

### Overview

The ESP32-S2-based WiFi Development Board attaches to the Flipper's GPIO header and provides 802.11 b/g/n WiFi capabilities. Flashed with **Marauder firmware**, it becomes a pocket WiFi pentesting platform controlled via the Flipper's UI and screen.

### Hardware Setup

1. Attach WiFi Dev Board to GPIO header (keyed, only fits one way)
2. Flash Marauder firmware onto the ESP32:
   - Windows: Use Marauder's web flasher at `esp.huhn.me`
   - Or: download Marauder binary from `github.com/justcallmekoko/ESP32Marauder/releases`
3. Install Marauder Companion app on Flipper (Flipper Lab)

### Marauder Firmware Capabilities

#### WiFi Scanning
- **Scan APs**: Lists all visible access points with SSID, BSSID, channel, signal strength, encryption type
- **Scan Stations**: Lists connected client devices
- **Scan AP+Station**: Combined view showing which clients are connected to which APs

#### Deauthentication Attacks
**802.11 deauthentication frames** — disassociates clients from their AP:
- `deauth -a` — deauth all stations from all APs
- `deauth -b [BSSID]` — target specific AP
- Select from scan results in Marauder UI

> **Pentest use**: Demonstrate that anyone within radio range can forcibly disconnect clients. Effective for showing client why open/public WiFi is dangerous, and why 802.11w (Management Frame Protection) should be enabled.

#### PMKID / Handshake Capture
Captures WPA2 handshakes for offline cracking:
1. Scan APs → select target
2. `attack -t pmkid` — captures PMKID from AP beacon (no client needed)
3. Or: `attack -t wpa` — captures full 4-way handshake (requires client authentication)
4. Save `.pcap` to SD card
5. Transfer to Kali → `hashcat -m 22000 capture.hc22000 wordlist.txt`

#### Evil Portal (Captive Portal)
Hosts a fake WiFi login page:
1. Configure SSID name in Marauder settings
2. Start Evil Portal
3. Flipper broadcasts the SSID
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
More detailed BLE scanning than the built-in BLE app:
- Raw advertising packet capture
- Device fingerprinting
- Manufacturer data display

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

## 14. Apps — Full Catalog

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
| **PNWC Payload Library** | Full suite — see separate documentation |
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
Portal of Flipper, Doom, Tetris, Snake, Flappy Bird — various on Flipper Lab. Useful for social engineering "hey look at this" openers.

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
- LF (HID Prox / EM4100): `125kHz RFID → Read` — works through wallets/purses at ~5cm
- HF Mifare Classic: `NFC → Read` — brief contact needed
- HF iClass: `Apps → Picopass → Read`

**Step 3: Reader Nonce Capture (Mifare Classic)**
- `NFC → Detect Reader` — hold Flipper near reader
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
1. `Sub-GHz → Frequency Analyzer` — identify active frequencies on site
2. `Sub-GHz → Read` — capture gate/door/barrier remotes
3. Test replay on target
4. `Sub-GHz Bruteforcer` — if fixed-code, demonstrate full code space compromise

**WiFi Assessment (with ESP32 Dev Board):**
1. Marauder → Scan APs — enumerate all SSIDs, note encryption types
2. Identify any open networks or WEP (rare but still exists)
3. Marauder → PMKID — capture from all WPA2 targets
4. Marauder → Scan Stations — identify client devices
5. Transfer .pcap to Kali → crack with hashcat
6. Marauder → Deauth — demonstrate forced disconnection
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
2. Run `win-intake-form.txt` — opens Notepad with auto-filled system info
3. Fill in reported issue while system info populates in background
4. Run `win-inventory.txt` — captures full HW/SW for your records

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
1. Run `win-security-audit.txt` — generates full report
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
| qFlipper download | flipperzero.one/update |
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

- [Computer Fraud and Abuse Act (CFAA) — 18 U.S.C. § 1030](https://www.law.cornell.edu/uscode/text/18/1030)
- [Electronic Communications Privacy Act (ECPA)](https://www.law.cornell.edu/uscode/text/18/part-I/chapter-119)
- [Washington State RCW 9A.52.110 — Computer Trespass](https://apps.leg.wa.gov/rcw/default.aspx?cite=9A.52.110)
- [FCC Part 15 — Unlicensed RF devices](https://www.ecfr.gov/current/title-47/chapter-I/subchapter-A/part-15)

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

*Pacific Northwest Computers | Vancouver, WA*
*jon@pnwcomputers.com | 360-624-7379*
*github.com/Pnwcomputers/ULTIMATE-CYBERSECURITY-MASTER-GUIDE*

---
*Guide version: 1.0 | Last updated: 2026*
*For the latest version, see the GitHub repository*
