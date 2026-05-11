# Bruce Firmware: A Multi-Radio Offensive Platform for ESP32 Hardware

> **Reader prerequisites.** This chapter assumes the foundational material from the previous chapter on the M5Cardputer and Evil-M5Project. Bruce runs on the same Cardputer hardware (and many others), targets the same broad threat-modeling space, but goes much wider — into Sub-GHz, NFC/RFID, IR, FM, and 2.4 GHz NRF24 — which substantially expands the legal and regulatory surface. Working familiarity with FCC Part 15 unlicensed operation, basic ISM-band concepts, ham radio rules where applicable, and the wireless attack primitives covered in the Evil-M5 chapter are assumed.

---

## 1. What Bruce is, and where it sits

If Evil-M5Project is the Wi-Fi specialist, **Bruce** is the multi-radio swiss army knife. The same Cardputer that runs Evil-M5 can be reflashed with Bruce and gain — among other things — sub-GHz transmit and replay (with a CC1101), 13.56 MHz NFC read/clone (with a PN532), 125 kHz RFID, IR transmit/receive, FM broadcast, NRF24-based 2.4 GHz operations, BLE spoofing and HID, and a JavaScript interpreter for automating attack sequences.

Bruce is open source under the **AGPL-3.0**, maintained by pr3y with extensive contributions from bmorcelli (cross-device porting and core), IncursioHack (RF/RFID), and a wide contributor base. The project's official home is `https://bruce.computer` and the canonical repositories are `github.com/pr3y/Bruce` and `github.com/BruceDevices/firmware` — both serve the same codebase. As of February 2026 the current release is **Bruce 1.14**, and the project ships frequent point releases.

Where Evil-M5 is wiki-driven and feature-stable, Bruce is release-driven, ships a polished **official Web Flasher** (`https://bruce.computer/flasher`), maintains an active Discord, and has its own ecosystem of open-hardware boards (Smoochiee V2, Bruce RF Reaper). For the practicing security professional, the practical implication is:

- **Use Evil-M5 when the engagement is Wi-Fi-focused.** The captive-portal flow and KARMA tooling are mature and the wiki documents them in operational detail.
- **Use Bruce when you need anything beyond Wi-Fi** — IR for testing a kiosk's remote control, 13.56 MHz cloning of an access badge, CC1101 sub-GHz replay against a garage door or rolling-code target, or BLE HID injection. Bruce's WiFi feature set overlaps with Evil-M5 (Evil Portal, deauth, beacon spam, wardriving, Responder) but is less feature-rich on that one axis.

The two firmwares are not mutually exclusive — flashing back and forth takes a couple of minutes. Many practitioners keep both binaries handy.

---

## 2. Legal and regulatory framework — read before you flash

The Evil-M5 chapter discussed CFAA and 47 USC § 333 as the dominant federal statutes for Wi-Fi attacks. Bruce dramatically widens the regulatory exposure because it exposes the operator to **deliberate RF transmission** on bands beyond 2.4 GHz Wi-Fi. The applicable statutes, with citations:

- **47 U.S.C. § 301** — Requires anyone operating or using a radio transmitter to be licensed or authorized under FCC rules. Operating an unlicensed transmitter on any band — including sub-GHz, FM, or amateur frequencies — is a federal offense.
- **47 U.S.C. § 302a(b)** — Prohibits the manufacture, importation, sale, marketing, *or operation* of devices that fail to comply with FCC interference regulations. Devices designed primarily to jam communications are categorically barred. The FCC has fined CTS Technology $34.9 million for marketing jammers and individual operators $22,000+ for operating them.
- **47 U.S.C. § 333** — Prohibits willful or malicious interference with licensed radio communications. Covers Wi-Fi deauth (as discussed in the Evil-M5 chapter) but also any sub-GHz, NRF24, or FM jamming. First-offense forfeitures can reach $11,000 *per day per violation*.
- **47 U.S.C. § 1030** (CFAA), Wiretap Act, and ECPA — Same considerations as Evil-M5 for credential capture and intercepted traffic.
- **47 CFR Part 15** — Sets the unlicensed-operation rules for ISM bands (433 MHz, 902-928 MHz, 2.4 GHz). The CC1101's typical sub-GHz operation falls under Part 15 power limits when transmitting on 433/915 MHz; *intentional interference* with another device's Part 15 operation is still prohibited under § 333.
- **47 CFR Part 95 / Part 97** — Personal radio services (FRS, GMRS, MURS, CB) and Amateur Radio, respectively. Some sub-GHz frequencies a CC1101 can hit overlap with these allocations; transmitting on them without the required license or service authorization is a violation.
- **47 CFR Part 73** — Broadcast service. The FM Broadcast features in Bruce transmit on the commercial FM band (88-108 MHz). Even at low power, intentional transmission on the FM broadcast band without a license violates Part 73.
- **State analogues** — Washington's RCW chapter 9A.90 (Washington Cybercrime Act, including 9A.90.060 Electronic Data Service Interference) and Oregon's ORS 164.377 (computer crime) cover the digital-side attacks just as for Evil-M5.

A practical rule of thumb: **every feature in Bruce that ends in "Spam," "Jammer," "Replay," or "Broadcast" is presumptively illegal to operate without explicit authorization on the target band.** That is not hyperbole — read the statute citations above. The FCC's "Zero Tolerance" enforcement posture on jammers, established in 2014, has resulted in seizures and forfeitures with the FCC dedicating a tip line (1-855-55-NOJAM) for the public to report jammer operation.

You may use Bruce legally in the following contexts, with the noted caveats:

1. **On your own networks, your own access badges, your own remotes, your own devices**, in a controlled location with no third-party transmissions within reception range. For RF receive-only operations (scan, sniff, spectrum), Part 15's "any device may receive" principle is permissive. For *any* transmission, you need a clear path: device-band authorization (Part 15 ISM, your amateur license, etc.) **and** authorization to transmit at the target (i.e., you own the lock or the lock owner has authorized testing).
2. **Under a signed ROE that explicitly enumerates the radio bands and techniques** — many ROE templates address WiFi but say nothing about sub-GHz or NFC. If you intend to clone a 125 kHz badge or replay a 433 MHz rolling code, the ROE must say so.
3. **In a fully shielded lab** — anechoic chamber, properly attenuated test cabinet, or a sufficiently remote rural location where you can verify no third parties are in receive range. For sub-GHz work, "I'm in my garage" is not sufficient; sub-GHz signals propagate further than 2.4 GHz, and garage-door remotes from neighboring houses may be within receive range.

A blanket personal rule: **the antenna goes on the device only after the scope, the ROE band list, and the physical location have all been verified.** Develop the muscle memory of leaving the CC1101 / NRF24 / FM modules disconnected until they are about to be used.

The Bruce authors publish the firmware for legal red-team and educational use under the AGPL and disclaim responsibility for misuse. So do I. So should you in any deliverable you produce.

A compliance checklist tailored to Bruce's broader regulatory surface appears in Appendix C.

---

## 3. The hardware

### 3.1 Compatible devices

Bruce runs on a substantially wider set of hardware than Evil-M5. The official compatibility matrix as of release 1.14:

| Device | CC1101 (Sub-GHz) | NRF24 (2.4 GHz) | FM Radio | PN532 (NFC) | Mic | BadUSB | RGB | Speaker | Notes |
|---|---|---|---|---|---|---|---|---|---|
| M5Cardputer (and Adv) | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | NS4168 | Most feature-complete M5 target |
| M5StickC PLUS / PLUS2 | ✓ | ✓ | ✓ | ✓ | ✓ | ✓¹ | — | Tone | StickCPlus is the budget option |
| M5Core BASIC / Core2 | ✓ | ✓ | ✓ | ✓ | ✓ | ✓¹ | — | varies | The "stack" form factor |
| M5CoreS3 / CoreS3 SE | ✓ | ✓ | ✓ | ✓ | — | ✓ | — | — | ESP32-S3 successor to Core2 |
| JCZN CYD-2432S028 | ✓ | ✓ | ✓ | ✓ | — | ✓¹ | — | — | "Cheap Yellow Display"; LITE_VERSION for launchers |
| Lilygo T-Embed CC1101 | ✓ (integrated) | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | Best out-of-box sub-GHz support |
| Lilygo T-Embed | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | T-Embed without integrated CC1101 |
| Lilygo T-Display-S3 | ✓ | ✓ | — | — | — | ✓ | — | — | Bare display board |
| Lilygo T-Deck / T-Deck Plus | ✓ | — | — | — | — | ✓ | — | — | QWERTY trackball form |
| Lilygo T-Watch-S3 | — | — | — | — | — | ✓ | — | — | Wearable form factor |
| Lilygo T-LoRa Pager | — | — | — | — | — | ✓ | — | — | LoRa-equipped pager form |
| Smoochiee V2 | ✓ | ✓ | — | ✓ | — | ✓ | — | — | Community open-hardware PCB |
| Bruce RF Reaper | ✓ | ✓ | — | ST25R3916 | — | ✓ | ✓ | — | NFC reader is different IC |
| Generic ESP32-C5 | ✓ | ✓ | — | ✓ | — | — | — | — | New-generation Espressif silicon |

¹ Core, CYD, and StickC BadUSB require additional configuration documented in the Bruce wiki.

The headline implication for your kit: **the Cardputer (especially the Adv revision with the better antenna) is the most feature-complete handheld for Bruce.** If you want the best out-of-box sub-GHz experience and don't already own a Cardputer, the **Lilygo T-Embed CC1101** is the purpose-built choice — its integrated CC1101 + battery + display make it the closest thing to a "Bruce Flipper Zero" on the market.

### 3.2 Required and optional accessories

For the Cardputer running Bruce, beyond the items already needed for Evil-M5:

- **CC1101 module (for sub-GHz).** The M5Stack RF433 T/R unit plugs into the Grove port and gives 433 MHz transmit/receive. For the full 300-348 / 387-464 / 779-928 MHz range, an external CC1101 board wired to the Grove pins. Bruce supports configurable TX/RX pins in the Config menu.
- **PN532 module (for 13.56 MHz NFC).** M5Stack sells a PN532 unit; the firmware also supports PN532Killer variants. Required for any NFC/RFID read, write, or clone operation.
- **NRF24L01+ module (for 2.4 GHz NRF24 features).** Off-the-shelf NRF24 modules wire to the Grove port. Used for the NRF24 jammer and 2.4 GHz spectrum visualizer. Power-sensitive — many cheap NRF24 modules need a decoupling cap or a dedicated regulator to behave.
- **Faraday bag / shielded enclosure.** More important for Bruce than for Evil-M5 because sub-GHz signals propagate much farther than 2.4 GHz. A properly attenuated bench setup is strongly preferred over "I'll just do this in my office."

The Lilygo T-Embed CC1101 includes the CC1101 on the same PCB as the ESP32-S3, eliminating the wiring step. No separate module needed.

---

## 4. The software, in brief

### 4.1 Feature inventory (Cardputer + full module set)

Bruce organizes features into top-level radio domains, plus utility categories. From the project's README and wiki as of release 1.14:

**WiFi (overlaps significantly with Evil-M5)**
- Connect to WiFi / WiFi AP / Disconnect
- WiFi attacks: Beacon Spam, Target Attack (info, target deauth, EvilPortal + deauth), Deauth Flood (multi-target)
- Wardriving (Wigle-format CSV output)
- TelNet, SSH clients
- Raw Sniffer
- TCP Client / TCP Listener
- Evil Portal (captive portal with on-device admin)
- Host scan with TCP port scanning
- Responder (LLMNR/NBT-NS/MDNS poisoner)
- ARP Spoofing / ARP Poisoning
- WireGuard tunneling (operate the device through a remote WireGuard endpoint)
- Brucegotchi (Pwnagotchi-friend + Pwngrid spam: name flooding and "doscreen" of nearby Pwnagotchi devices)

**BLE**
- BLE Scan
- Bad BLE (Ducky scripts delivered over BLE HID)
- BLE Keyboard (Cardputer and T-Deck only — acts as a Bluetooth keyboard for a paired host)
- iOS Spam (the "Apple Juice" advertisement-flood DoS)
- Windows Spam
- Samsung Spam
- Android Spam
- Spam All (cycles through all four)

**Sub-GHz RF (requires CC1101 or compatible module)**
- Scan / Copy (capture an OOK / ASK signal)
- Custom SubGhz replay (Flipper-Zero-style stored-signal replay)
- Spectrum analyzer
- Jammer (Full — continuous square wave; Intermittent — PWM-modulated jam)
- Replay (re-transmit a captured signal)
- Configurable TX pin, RX pin, module type, and frequency

**RFID / NFC**
- Read tag (13.56 MHz via PN532)
- Read 125 kHz (low-frequency RFID)
- Clone tag
- Write NDEF records
- Amiibolink integration (write Amiibo dumps)
- Chameleon integration
- Write / Erase / Save / Load arbitrary data
- (Tag emulation is not yet supported on Cardputer; planned)

**IR**
- TV-B-Gone (cycles power codes for thousands of TV models)
- IR Receiver (capture remote codes)
- Custom IR: NEC, NEC-extended, SIRC, SIRC15, SIRC20, Samsung32, RC5, RC5X, RC6
- Configurable TX/RX pins

**FM**
- Broadcast standard (transmit on the 88-108 MHz commercial FM band — see legal section)
- Broadcast reserved (transmit on the FCC-reserved sub-band)
- Broadcast stop
- (FM spectrum, traffic-announcement hijack, and full config are planned but not yet shipped)

**NRF24 (requires NRF24L01+ module)**
- NRF24 Jammer
- 2.4 GHz spectrum visualizer
- (Mousejack not yet implemented)

**Scripts**
- JavaScript Interpreter (project: Doolittle, by justinknight93). Bruce can execute JS programs from SD card or LittleFS, with access to most of the firmware's offensive primitives. This is the major differentiator vs Evil-M5: you can scripted attack chains in JS instead of menu-driven sequences.

**Connect (ESPNOW)**
- Bruce-to-Bruce file send / receive
- Send / receive commands between paired Bruce devices

**Others**
- Microphone spectrum visualizer
- QR codes (custom, and Brazil PIX-format bank-transfer codes)
- SD Card Manager (image viewer, file info, Wigle uploader, audio player, text viewer)
- LittleFS Manager (browse the internal filesystem)
- WebUI (browser-based control panel: SDCard manager, SPIFFS/LittleFS manager, HTML serving)
- Megalodon (additional Wi-Fi attack mode)
- BadUSB with LittleFS and SDCard payload sources
- USB Keyboard (Cardputer and T-Deck — pass-through HID)
- iButton (1-Wire key emulation/reading)
- LED Control

**Clock**
- RTC support
- NTP-based time adjust (over Wi-Fi)
- Manual time adjust

**Config**
- Brightness, dim time, orientation, UI color, boot sound, restart, sleep

A note on "LITE_VERSION": some devices (particularly CYD-2432S028 and M5StickC PLUS) ship a stripped build for compatibility with the M5Launcher loader. TelNet, SSH, WireGuard, ScanHosts, RawSniffer, Brucegotchi, BLEBacon, BLEScan, and the JS interpreter are excluded from those builds. Cardputer runs the full build by default.

---

## 5. Installation

Bruce ships polished install tooling. There are four supported paths, in order of ease:

### 5.1 Path A — Official Web Flasher (recommended)

The simplest install, no software needed beyond a Chromium-based browser with WebSerial support (Chrome, Edge, Brave, Opera — Firefox and Safari do not implement WebSerial).

1. Navigate to `https://bruce.computer/flasher`.
2. Select your device from the picker (M5Stack / Lilygo / CYD / ESP32 / Custom Boards / Launcher).
3. Put the device into download mode:
   - **Cardputer:** Turn off and unplug from USB. Hold the G0 button (upper-right corner). With G0 still held, connect via USB. Release G0.
   - **M5StickC / PLUS:** Turn off. Connect one end of a jumper wire to GND and the other to G0. Plug in USB. Remove the jumper.
   - **T-Embed / T-Embed CC1101:** Hold the encoder center button while pressing RST. On the CC1101 variant, the RST button is on the board beside the ESP32-S3.
   - **T-Deck:** Hold the trackball/trackpad center while pressing RST (left side).
4. Click **Connect** in the flasher; select the device's serial port.
5. Click **Flash**. The web flasher streams the binary over WebSerial and verifies.
6. On Linux, if the port permissions block you, run: `sudo setfacl -m u::rw /dev/ttyACM0` (or add yourself to the `dialout` group).

The web flasher is the path the Bruce team recommends because it always ships the latest release and handles the device-specific binary selection automatically.

### 5.2 Path B — M5Burner (M5Stack devices only)

For Cardputer, StickC, Core, etc., M5Burner works the same as for Evil-M5:

1. Download M5Burner from `https://docs.m5stack.com/en/download`.
2. Navigate to your device family. Search "Bruce" in the firmware list.
3. **Verify the listing is uploaded by "owner" and has photos** — third-party uploads exist and should be avoided.
4. Click Download → Burn → select port → confirm.

### 5.3 Path C — esptool.py (any supported device, any OS)

The most flexible path. Useful when scripting, when working with custom boards, or when you want a known-state install:

1. Install `esptool.py`: `pip install esptool` (Python 3 required).
2. Download the binary matching your device from the Releases page at `https://github.com/BruceDevices/firmware/releases`. Filenames follow the pattern `Bruce-<device>_<version>.bin`.
3. Put the device into download mode (Cardputer: hold G0 while plugging in USB).
4. Flash:
   ```bash
   esptool.py --port /dev/ttyACM0 write_flash 0x00000 Bruce-Cardputer_1.14.bin
   ```
   Adjust port and filename as needed. On Windows, the port looks like `COM3`.
5. Disconnect and reconnect; the device boots into Bruce.

### 5.4 Path D — Build from source (PlatformIO)

Build from source when you need to track unreleased commits, add a custom payload, or target an unsupported board. Bruce uses PlatformIO, not Arduino IDE:

1. Install Python 3, then VS Code with the PlatformIO IDE extension (or PlatformIO Core CLI).
2. Clone the repository:
   ```bash
   git clone https://github.com/BruceDevices/firmware.git Bruce
   cd Bruce
   ```
3. Open the folder in VS Code. PlatformIO auto-detects `platformio.ini` and configures the build environments.
4. In the PlatformIO sidebar, expand the environment matching your device (e.g., `m5stack-cardputer`, `m5stack-cardputer-adv`, `lilygo-t-embed-cc1101`).
5. Click **Build** to compile, then **Upload** with the device in download mode.
6. The project includes Docker support (`docker-compose.yml`) for reproducible builds on isolated systems.

The partition layouts ship as `custom_4Mb.csv`, `custom_4Mb_full.csv`, `custom_8Mb.csv`, and `custom_16Mb.csv` — pick the one matching your flash size if you need to customize.

### 5.5 SD card preparation

Bruce uses the SD card differently from Evil-M5 — there is no required folder structure for the firmware to boot. SD card content is used by specific modules:

- BadUSB looks for Ducky Script payloads (default extension `.txt`) under a `BadUSB` folder
- Wardriving writes Wigle CSVs into a `wigle` folder
- Sub-GHz, IR, and RFID save/load operations create their own files
- The JS interpreter loads scripts from anywhere on the card or from LittleFS
- The WebUI's file manager can browse and serve from both filesystems

You can run Bruce productively with no SD card at all — most module storage falls back to internal LittleFS — but for wardriving, captured handshakes, and any meaningful operational use, an 8-32 GB FAT32 card is essential.

### 5.6 First boot verification

After flashing and re-powering, you should see:

1. The Bruce banner / boot logo
2. A boot tone (unless disabled)
3. The top-level menu: **WiFi / BLE / RF / RFID / IR / FM / NRF24 / Others / Clock / Connect / Config**
4. A status bar showing battery, time, and WiFi state

If the device boots to a blank screen, the most common cause on Cardputer is a flash-size mismatch — reflash with the correct partition layout.

---

## 6. UI orientation and navigation conventions

Bruce uses different per-device input conventions because it runs on radically different form factors. For the Cardputer specifically:

| Key | Action |
|---|---|
| `Fn` + `;` / `.` / `,` / `/` | Up / Down / Left / Right navigation |
| `Fn` + `` ` `` (backtick) | Escape / back |
| `Enter` | Select / confirm |
| `Backspace` | Clear / cancel input |
| Alphanumerics | Direct text entry where prompted |
| `G0` (top-right button) | Hardware menu shortcut on some firmware screens |

For other devices, the conventions adapt: M5Stick uses the three hardware buttons + power-button-as-back; T-Embed uses the rotary encoder; T-Deck uses its QWERTY keyboard and trackball; T-Watch uses touch. The Bruce UI is consistent in *layout* across devices but the *input mapping* changes — the wiki has per-device pages.

A practical orientation note: Bruce's main menu is wider than Evil-M5's — eight to ten top-level categories vs Evil-M5's flat list of attacks. Spend a few minutes navigating each menu before starting any operational use; muscle memory for "which submenu is the sub-GHz scanner under" matters when you're trying to run an exercise without looking down.

---

## 7. A note on web access — WebUI, WireGuard, TCP listener

Three Bruce features deserve mention up front because, like Evil-M5's Admin WebUI and Reverse TCP Tunnel, they change the device's network posture:

- **WebUI.** Bruce's web interface is reachable from the device's SoftAP or, when joined to a network, on a LAN IP. Through it, you can browse the SD card and LittleFS, run BadUSB payloads, send IR signals, and access most other modules from a browser. Convenient for demos and headless deployments. **Secure it with a strong password.**
- **WireGuard tunneling.** Bruce can join a WireGuard mesh as a client. Combined with a VPS, this gives you out-of-band remote access without the inbound port-forward complexity of the Evil-M5 Reverse TCP Tunnel. Operationally equivalent — and equivalent in legal risk if deployed without authorization.
- **TCP Listener.** A simple TCP server you can run on the device for incoming connections. Used during engagements as a quick-and-dirty exfil endpoint or callback receiver. Easy to leave running by accident; remember to stop it before moving on.

All three are off by default. Leave them off until your use case justifies them.

---

## 8. Module deep-dives

Bruce's feature list is too broad to cover exhaustively. The sections that follow are the modules a security practitioner is most likely to use, with cross-references to Evil-M5 where the technique is identical (e.g., WiFi deauth) and detail where Bruce introduces something Evil-M5 does not (sub-GHz, NFC, IR).

### 8.1 WiFi — the basics, briefly

Bruce's WiFi attack set overlaps almost entirely with Evil-M5: connect, AP mode, beacon spam, target deauth, deauth flood, evil portal (with optional concurrent deauth), wardriving, RAW sniffer, host/port scan, Responder (LLMNR/NBT-NS poisoning).

Procedurally these are near-identical to the Evil-M5 chapter's coverage. Two Bruce-specific notes:

- **Evil Portal** is simpler than Evil-M5's: you supply a portal SSID, an HTML page (or use one of Bruce's defaults), and the device runs the captive flow. Submitted credentials are visible at `http://172.0.0.1/creds` from any connected client and (if SD is available) appended to a creds log file. Bruce's portal templates are sparser than Evil-M5's, but Bruce supports loading any HTML you place on SD.
- **Brucegotchi** is a deliberate cousin to Evil-M5's PwnGridSpam: it can act as a friend to nearby Pwnagotchi devices, flood the local Pwngrid mesh with spurious peer identifiers, and "DoScreen" Pwnagotchi displays with long names and rendered faces. Niche, but the only tool I know of that does this specifically.

If your engagement is primarily a Wi-Fi assessment, Evil-M5 is the more developed tool. If you need WiFi attacks *alongside* sub-GHz or NFC operations, Bruce keeps everything under one menu.

### 8.2 BLE — spoofing, HID, and BLE Spam

**BLE Scan.** Standard BLE advertisement listener. Useful for inventory and for verifying that a target BLE peripheral is in range.

**Bad BLE.** The BLE equivalent of BadUSB. Bruce advertises itself as a Bluetooth HID device; once a host pairs (or auto-connects), Bruce delivers a Ducky Script payload as keystrokes over BLE. Useful in environments where a USB HID device would be visible but a BLE keyboard would not. Same defensive caveats apply: device-control policies that block unknown HID devices defeat this.

**BLE Keyboard.** A more deliberate version of Bad BLE — Bruce acts as a regular BLE keyboard for an authorized host, useful for remote control of a paired laptop. Cardputer and T-Deck only.

**BLE Spam (iOS / Windows / Samsung / Android / All).** This is the consumer-visible "Apple Juice" attack family. Bruce broadcasts crafted BLE advertisements that trigger pairing prompts, AirPods popups, Nearby Share dialogs, or "set up new device" UI on nearby phones. The result is a denial-of-service: target devices become unusable while the spam runs.

**Important caveat on BLE Spam.** This is presumptively a § 333 willful-interference violation in the United States. Even though the BLE advertisements are within Part 15 ISM-band power limits, they are deliberately crafted to disrupt other devices' normal operation. Run it only in a fully isolated environment with no third-party BLE devices in range.

### 8.3 Sub-GHz RF (CC1101)

This is the marquee Bruce capability that Evil-M5 lacks. With a CC1101 attached (either via a Grove module on Cardputer or natively on the T-Embed CC1101), Bruce can scan, capture, replay, and transmit on roughly **300-348 MHz**, **387-464 MHz**, and **779-928 MHz** — encompassing most common garage-door, gate, alarm, weather-station, and ISM-band remote control frequencies. Frequency limits depend on the CC1101 variant.

**Procedure (capture and replay):**
1. Plug the CC1101 module into the configured Grove pins. Set TX pin, RX pin, and module type under **RF → Config**.
2. Set the frequency. For US 433 MHz remotes (garage doors, alarm sensors, weather stations), 433.92 MHz is the typical center. For 915 MHz remotes (some North American door locks, sensors), 915.00 MHz.
3. **RF → Scan/Copy.** The device listens on the configured frequency and shows incoming signals as raw modulation traces. Activate your target remote in the device's vicinity; Bruce captures the burst.
4. Save the capture to SD card or LittleFS if you want to keep it.
5. **RF → Replay.** Select the saved capture; Bruce retransmits it at the configured frequency. If the target device uses fixed-code OOK/ASK modulation, the replay re-triggers it.

**Procedure (jammer):**
1. Configure the frequency in the Config menu.
2. **RF → Jammer Full** transmits a continuous square wave at the configured frequency, blocking reception within the radio's effective range.
3. **RF → Jammer Intermittent** transmits a PWM-modulated jam that defeats some receivers that filter out continuous-carrier interference.

**Legal status.** Operating any of these in unisolated space is illegal. The jammer is unambiguously a § 333 / § 302a violation. Replay of a signal you do not own is unauthorized transmission under § 301. Even the "spectrum" visualizer, which only receives, requires a clean band — though receive-only operation itself does not require authorization, you cannot use what you receive as the input to an unauthorized transmission.

**Defenses.** Rolling-code receivers (KeeLoq, modern Z-Wave / Zigbee security, AES-encrypted protocols) defeat naive replay — the captured code is invalidated by the first replay attempt. Targets that are vulnerable to Bruce's basic replay are *fixed-code OOK/ASK remotes*, which include many cheap garage doors, gate remotes, and toy-grade door locks. The mitigation is: replace fixed-code hardware with rolling-code or encrypted alternatives. Customers running fixed-code access controls deserve to be told this in plain language during an engagement debrief.

### 8.4 NFC and RFID (PN532 + 125 kHz)

With a PN532 attached, Bruce reads, writes, and clones 13.56 MHz MIFARE Classic tags (and other ISO 14443A variants). With a 125 kHz module, it handles the older low-frequency RFID standards common in legacy access control.

**Procedure (read and clone a MIFARE Classic):**
1. **RFID → Config → RFID Module → PN532**. Confirm I²C address; the PN532 default is typically 0x24 or 0x48 depending on jumper configuration.
2. **RFID → Read tag**. Hold the tag against the PN532 antenna; Bruce reads UID, manufacturer block, and any readable sectors.
3. Note any sectors that come back as "auth failed" — those use non-default keys. Bruce can attempt the well-known key dictionary (default keys, MFOC-style attacks) depending on firmware version.
4. **RFID → Clone tag**. Place a writable MIFARE tag against the antenna; Bruce writes the captured data.

**125 kHz operations** are simpler — there is essentially no on-card security on low-frequency RFID, just an ID number. Bruce reads, stores, and replays the ID. Many corporate badge systems still use 125 kHz EM4100 cards, which are trivially cloneable; that's a finding in itself.

**NDEF write** is useful for testing NFC tag deployments — write a URL or contact record to a tag and verify the target device handles it as expected. Less an attack than a diagnostic tool.

**Tag emulation** is *not* currently supported on Cardputer. Some Bruce builds on specific hardware (T-Embed CC1101 with appropriate firmware revision) can emulate basic ISO 14443A. The Bruce team's wiki tracks this; check before relying on it.

**Defenses.** MIFARE Classic with the default keys is the canonical "this should not still be in production" finding in 2026. The fix is migration to MIFARE DESFire, iCLASS SE, or HID Seos. For 125 kHz, the fix is migration off 125 kHz entirely.

### 8.5 IR — TV-B-Gone and Custom IR

The Cardputer has a built-in IR emitter, so no module is needed for IR transmission. Reception requires an external IR receiver wired to a GPIO.

**TV-B-Gone.** Cycles through a database of remote power codes for thousands of TV models. Originally a Mitch Altman invention; ported into Bruce via the HAKRWATCH code base. Press a key, point at a TV, watch it turn off. Useful for waiting-room remediation demonstrations, less useful operationally.

**IR Receiver.** Captures and stores incoming IR codes. Combined with **Custom IR** (which lets you specify NEC, NEC-extended, SIRC, SIRC15, SIRC20, Samsung32, RC5, RC5X, or RC6 encoding and a raw value), you can clone any remote into the Cardputer and use it as a universal replacement. Functional, not attack-focused — but if your engagement involves a target that uses IR-based access control (some legacy door systems do), this is the tool.

**Legal note.** IR is non-radio; no FCC issues. Acting on a target's hardware (e.g., powering off a kiosk you don't control) is a property/access issue, not an RF issue.

### 8.6 FM Broadcast

Bruce can transmit on the 88-108 MHz FM broadcast band when wired to a compatible KT0803-family module. Three modes ship: Broadcast Standard (the public FM band), Broadcast Reserved (the FCC-reserved sub-bands), and Broadcast Stop.

**Useful for:** Demonstrating how trivially an unauthorized transmitter can be set up. The "Mr. Robot demo," where a $20 module pulls live audio into a target environment, is a memorable awareness piece in client briefings.

**Legal status.** Categorically illegal in the United States without an FM broadcast license. 47 CFR Part 73 governs commercial FM broadcasting; § 73.277 requires a station license. Pirate-broadcasting fines are routinely six figures, and the FCC has recently expanded enforcement to property owners who knowingly host unlicensed transmitters. Even at the low power of a CC1101/KT0803, the FCC has prosecuted operators.

If your work requires actually transmitting on FM for a demo, do it inside a fully shielded enclosure or get appropriate authorization. There is no "low-power exemption" that allows hobby FM broadcasting on the commercial band in the US.

### 8.7 NRF24 — 2.4 GHz jammer and spectrum

With an NRF24L01+ module attached, Bruce offers:

- **NRF24 Jammer.** Blasts the 2.4 GHz band, disrupting Wi-Fi, Bluetooth, Zigbee, and other 2.4 GHz consumer protocols within range.
- **2.4 GHz Spectrum.** Receive-only spectrum visualization; useful for confirming a target's channel use.
- Mousejack is listed as planned but not yet implemented as of release 1.14.

**Legal status of the jammer:** Same as the sub-GHz jammer. Categorically illegal under §§ 301, 302a, 333. Don't.

The spectrum visualizer is fine — receive-only Part 15 operation does not require authorization.

### 8.8 BadUSB (and Bad BLE recap)

Bruce's BadUSB implementation supports payloads from either the SD card or the internal LittleFS, with new HID engine refinements relative to early versions:

1. Place a Ducky Script payload (`.txt`) on SD or upload it via the WebUI's LittleFS manager.
2. **Others → BadUSB → Select payload → choose the file.**
3. Plug the Cardputer into the target host. The device enumerates as a USB HID keyboard.
4. **Run.** The payload executes at HID typing speed.

The WebUI exposes payload management in a browser — useful for rapid iteration without ejecting SD or re-uploading.

For Bad BLE, the same payload format works but delivery is over BLE HID instead of USB. The target host must allow pairing or already trust the device.

**Defenses.** Same as covered in the Evil-M5 chapter — USB device-control policy (Windows USB Restrict, macOS USB Restricted Mode, Linux usbguard), EDR rules on rapid-keystroke HID enumeration, and physical security on unattended workstations. For Bad BLE specifically, BLE pairing prompts on modern OSes (iOS, Android, Windows 11, macOS) require user confirmation — that confirmation is the defense, and user training is the mitigation.

### 8.9 JavaScript Interpreter

Bruce's standout differentiator from Evil-M5 is the built-in JavaScript runtime (project name: Doolittle). Scripts live on SD or LittleFS and have programmatic access to most of Bruce's offensive primitives — Wi-Fi scans, BLE operations, BadUSB delivery, IR transmission, screen drawing, and HTTP.

**Typical use cases:**
- **Automated attack chains.** Script a sequence that scans for a specific target SSID, waits until it appears, then triggers an evil portal automatically.
- **Custom payload delivery.** Write a JS wrapper that fingerprints the target host (via BadUSB-typed reconnaissance commands), then selects an appropriate follow-on payload based on the response.
- **Demonstrations.** Build a one-button demo that walks through a complete attack chain for a client briefing without manual menu navigation.

**Procedure:**
1. Place a `.js` file on SD card or in LittleFS.
2. **Others → Scripts → JavaScript Interpreter → select your file.**
3. The script runs; output (depending on what the script does) appears on screen or writes to files.

The Doolittle reference docs and example scripts are in the Bruce wiki's Interpreter page. Note that the JS interpreter is excluded from LITE_VERSION builds (M5Launcher-compatible variants).

### 8.10 WireGuard tunneling

Bruce can join a WireGuard mesh as a peer. Configure with the standard endpoint, public key, allowed IPs, and DNS in the device's config; once connected, any Bruce module that uses the network (HTTP, TCP Listener, SSH client) routes through the tunnel.

**Operational use:** the same as Evil-M5's Reverse TCP Tunnel — out-of-band remote access for a device deployed on a target site during a long-running engagement. WireGuard is cleaner than the Reverse TCP approach because it's a real VPN: standard tooling on the listener side, encrypted by default, and harder to detect than an arbitrary outbound TCP connection.

**Legal status:** identical to Evil-M5's Reverse TCP Tunnel. Persistent remote-access implants require explicit ROE authorization. Don't deploy this without a signed scope.

### 8.11 Connect (ESPNOW)

Two Bruce devices on the same channel can exchange files and commands over ESPNOW (Espressif's proprietary 2.4 GHz peer-to-peer protocol). Niche but useful: a Bruce in a hard-to-reach location can be controlled by another Bruce at close range without joining any Wi-Fi network. The communication uses the Wi-Fi PHY but bypasses 802.11 association entirely.

Use cases are limited but real — covert local control during a physical-access engagement where you want to issue commands to a planted implant without lighting up the target's Wi-Fi.

---

## 9. Playbook — laboratory exercises

These exercises assume the lab setup from the Evil-M5 chapter (target network you own, observer workstation with Wireshark, faraday space for sensitive tests) plus the following additions specific to Bruce's RF features:

- **A target 433 MHz remote** you own — an old garage-door remote, a $5 fixed-code RF kit from a hobby store, or a sacrificial alarm sensor. Confirm it's fixed-code, not rolling-code, before relying on it for replay exercises.
- **A target 125 kHz RFID card** you own — a blank EM4100 keyfob from any access-control supplier, or one you've explicitly been given for testing.
- **A target MIFARE Classic tag** you own — likewise.
- **An SDR receiver** (HackRF, RTL-SDR, or similar) on the observer side, to independently verify Bruce's transmissions.
- **A Faraday enclosure** rated for sub-GHz — most of the cheap Wi-Fi/cellular shielding bags are insufficient at 433 MHz. Verify with your SDR before trusting it.

Exercises 1-5 of the Evil-M5 chapter apply unchanged to Bruce (same Wi-Fi techniques). The exercises below add the Bruce-specific RF, NFC, and IR work.

### Exercise B1 — Sub-GHz scan and identification

**Objective.** Identify the frequency, modulation, and basic structure of a fixed-code 433 MHz remote you own.

**Setup.**
- Bruce device with CC1101 attached and configured.
- Your target remote within a few centimeters.
- Observer SDR running `rtl_433` or `urh` on a workstation, for cross-verification.

**Steps.**
1. Bruce: **RF → Config** → set frequency to 433.92 MHz, module to CC1101, TX/RX pins per your wiring.
2. **RF → Spectrum.** Watch the band; press the target remote a few times. Identify the peak frequency.
3. Adjust the configured frequency if the peak is off-center.
4. **RF → Scan/Copy.** Press the remote; Bruce captures the burst.
5. Verify with the SDR: `rtl_433` should print the decoded protocol if it's a known one (most cheap remotes are EV1527, PT2262, or similar).
6. Save the capture.

**Success criteria.** You can state the exact center frequency, the modulation type (OOK or ASK), and either the decoded protocol name or the raw burst length.

**Debrief.** What does the SDR's decoded output tell you that Bruce's capture does not? When would Bruce's raw capture be more useful than the SDR's protocol-aware decode?

### Exercise B2 — Replay against your own target

**Objective.** Confirm that a captured fixed-code remote signal replays successfully.

**Setup.**
- Same as B1.
- The receiver paired with your remote (the garage-door opener, the alarm panel, or whatever) within transmit range.

**Steps.**
1. Verify in B1 that the target uses fixed-code OOK/ASK. Rolling-code targets will not work here — *and that is a valid finding.*
2. **RF → Replay** → select your saved capture.
3. Transmit; observe the target receiver respond.

**Success criteria.** The receiver responds to Bruce's replay as if the original remote had been pressed.

**Debrief.** Now replace the receiver with a rolling-code variant (or simulate one with a script). Repeat. Document the failure mode. This is the conversation you have with a client whose access control depends on fixed codes.

### Exercise B3 — 125 kHz RFID clone

**Objective.** Clone a 125 kHz EM4100 keyfob and demonstrate the cloned fob unlocks the target reader.

**Setup.**
- Bruce with a 125 kHz module attached, or a separate Proxmark / Chameleon if Bruce's 125 kHz support is limited for your build.
- A 125 kHz target reader you own.
- A blank rewritable 125 kHz fob (T5577 or compatible).

**Steps.**
1. **RFID → Read 125 kHz.** Place the original fob against the antenna; Bruce reads the ID.
2. Note the ID. (You will see it as a 10-digit decimal or 8-hex-digit value depending on display mode.)
3. Place the blank fob against the antenna.
4. **RFID → Clone tag.** Bruce writes the ID to the blank.
5. Test the clone against the target reader.

**Success criteria.** The cloned fob opens the lock.

**Debrief.** Document the time-to-clone (typically under 30 seconds). What client environments still use 125 kHz access control? What is the migration path?

### Exercise B4 — MIFARE Classic read and key recovery

**Objective.** Read a MIFARE Classic tag, identify which sectors use default keys vs custom keys, and (optionally) recover non-default keys.

**Setup.**
- Bruce with PN532 attached.
- A MIFARE Classic tag you own (the cheapest hotel-key clones are good test material; some prepaid transit cards work, but check legality before using them).

**Steps.**
1. **RFID → Read tag.** Bruce reads the UID and attempts the default key list against each sector.
2. Note which sectors authenticate (probably most) and which fail.
3. For failed sectors, attempt a key-recovery procedure (the wiki documents the available attacks; some firmware versions include MFCUK / hardnested support).

**Success criteria.** You can state, sector-by-sector, which keys authenticate. If you ran a key recovery, you can read the previously-unreadable sectors.

**Debrief.** A typical corporate badge system using MIFARE Classic with default keys is full-readable in under a minute. Document the finding format you would use in a client report — including the specific MIFARE-DESFire or iCLASS-SE migration recommendation.

### Exercise B5 — Defensive perspective from the blue team

**Objective.** Detect Exercise B1-B4 activity from a defensive posture.

**Setup.**
- Observer SDR running `rtl_433` and `gqrx` for 433 MHz, on a different machine than the operator.
- An NFC sniffer (a second PN532 in sniffer mode, a Proxmark, or a basic logic-analyzer on the target reader's antenna) for the NFC exercises.

**Steps.**
1. Repeat Exercises B1, B2, B3, B4 while the observer captures.
2. Document what the observer sees: timestamps of transmissions, signal characteristics, any leaked attribution.

**Success criteria.** The observer can independently reconstruct what Bruce did, when, on what frequency, and (for the NFC exercises) what data flowed.

**Debrief.** What sensors would a corporate defender need to detect this in production? What is the realistic cost of building it? In most environments, *nothing* detects RF replay against fixed-code controls because no one is listening — that absence is itself a finding.

### Exercise B6 — JS interpreter automation

**Objective.** Write a JavaScript that chains two Bruce capabilities — for example, scan for a specific SSID, then on first sight, transmit a known IR signal.

**Setup.**
- Bruce with default modules.
- An editor (any text editor; the WebUI lets you upload directly).

**Steps.**
1. Open the Bruce wiki's JS Interpreter page; identify the functions you need.
2. Write a script that loops on `wifi.scan()`, checks for your target SSID, and when found, calls `ir.transmit(...)` with a known code.
3. Upload to SD or LittleFS.
4. **Others → Scripts → JavaScript Interpreter → run.**

**Success criteria.** The chain executes: SSID appears → IR fires.

**Debrief.** How would you adapt this for a client engagement deliverable? What other chains would be operationally useful?

---

## 10. Blue team — defenses against Bruce capabilities

Building on the Evil-M5 defense matrix, the following addresses Bruce's expanded capability set:

| Attack class | Effective control(s) |
|---|---|
| WiFi (deauth, evil portal, beacon spam) | Same as Evil-M5 chapter: PMF, WPA2/3-Enterprise with EAP-TLS, long random PSK if PSK-only, WIDS. |
| BLE Spam (Apple Juice family) | Disable nearby-device popups on personal devices in sensitive environments. Modern iOS/Android have built-in mitigations as of 2024-2025 releases; keep client devices updated. |
| Bad BLE / BLE Keyboard | Block BLE HID device pairing via MDM policy. Disable BLE on workstations where it's not needed. |
| Sub-GHz replay (fixed-code) | Migrate to rolling-code or encrypted protocols. Audit access-control RF for fixed-code reliance. |
| Sub-GHz jammer | Detection requires RF spectrum monitoring (not standard in most environments). Practical mitigation: physical security and tamper detection on the receiver side. |
| NFC clone (MIFARE Classic, 125 kHz) | Migrate to MIFARE DESFire EV3 / iCLASS SE / HID Seos. Audit physical access systems for legacy card support. |
| FM broadcast | Inside-building shielding is overkill; the real control is property-owner awareness and physical access to the antenna location. |
| NRF24 jammer | Same as sub-GHz jammer — RF spectrum monitoring, physical security. |
| BadUSB / Bad BLE | USB and Bluetooth device-control policies (Windows, macOS USB Restricted Mode, Linux usbguard). EDR rules on rapid-keystroke HID enumeration. |
| IR replay against IR access control | Audit any access control that relies on IR. Migrate to encrypted protocols (most IR access systems should not exist in 2026). |
| WireGuard implant | Egress filtering on WireGuard ports (default 51820/UDP). DNS monitoring for unusual outbound queries. Physical-presence audits on long-deployed engagements. |
| ESPNOW between devices | Detection is nearly impossible — ESPNOW uses the Wi-Fi PHY without 802.11 framing. Physical security on the deployment area. |

The pattern from Evil-M5 holds: every individual attack has a known mitigation; the question is whether the target environment has actually deployed it.

---

## 11. Troubleshooting

**Web Flasher won't connect.** Browser doesn't support WebSerial. Use Chrome/Edge/Brave/Opera. Firefox and Safari are not supported.

**Web Flasher connects but fails to flash.** Device not in download mode. For Cardputer, hold G0 while plugging USB; release after the device enumerates.

**M5Burner doesn't find Bruce.** Search for the exact string "Bruce" in your device category. Verify the listing is uploaded by "owner" with photos — community uploads of varying provenance exist.

**Sub-GHz transmit produces nothing.** CC1101 wiring or pin config. Verify TX/RX pins in **RF → Config** match your actual wiring. Test with the Spectrum visualizer first — if you can see signals, RX works; then test TX with an SDR receiver nearby.

**PN532 not detected.** I²C address mismatch. PN532 has two address modes (0x24 / 0x48 depending on jumper). Bruce's RFID Config menu lets you select. Verify with an I²C scanner sketch if needed.

**BadUSB types nothing.** USB CDC mode wrong, or device enumerated as a different USB class. Reflash with the correct partition layout. On Cardputer, USB Mode = HID, USB CDC on Boot = Enabled.

**JS interpreter rejects the script.** Doolittle is a subset of JS — not full ES2020. Check the wiki's Interpreter page for supported syntax. Common pitfalls: `async/await` not supported, no DOM, no Node-style filesystem API (use Bruce's exposed `sd.*` / `lfs.*` instead).

**WiFi attacks behave differently than they did in Evil-M5.** Bruce's WiFi code is a separate codebase from Evil-M5's, even though the techniques are identical. Frame timing, deauth rate, and beacon spam behavior all differ slightly. Treat the two firmwares as siblings, not as a single tool.

**Device boots, then resets repeatedly.** Brown-out: the CC1101 or NRF24 module is drawing more current than the Cardputer's regulator can supply on USB power alone. Use a powered USB hub, charge the battery first, or add a separate 3.3 V supply for the RF module.

---

## 12. Appendix A — Bruce vs Evil-M5: when to use which

| Need | Pick |
|---|---|
| Wi-Fi captive-portal phishing (deepest template library) | Evil-M5 |
| Wi-Fi KARMA / probe-response | Evil-M5 |
| Wi-Fi handshake capture + on-device crack | Evil-M5 (Aircrack module) |
| Wi-Fi attack alongside other radios | Bruce |
| Sub-GHz scan / replay / jam | Bruce |
| 13.56 MHz NFC read / clone / write | Bruce |
| 125 kHz RFID | Bruce |
| IR (TV-B-Gone, custom IR replay) | Bruce |
| FM broadcast (legal caveats!) | Bruce |
| 2.4 GHz NRF24 jam / spectrum | Bruce |
| BLE HID keyboard injection | Bruce |
| BLE Spam (Apple/Windows/Samsung/Android) | Bruce |
| Scripted attack chains in JS | Bruce |
| WireGuard-based persistent remote | Bruce |
| Wardriving with Wigle CSV | Either (Bruce simpler; Evil-M5 supports master/slave for wider channel coverage) |
| BadUSB HID injection | Either |

Most practitioners I know keep both firmwares' binaries on hand and reflash for the day's task. Flashing the Cardputer is a 30-second operation through M5Burner or the Web Flasher; there's no reason to commit to one firmware permanently.

## Appendix B — Cardputer key bindings (Bruce build)

Identical to the Evil-M5 chapter (the Cardputer hardware mapping is the same), with one Bruce-specific note: the G0 button at the upper right doubles as a context-sensitive shortcut in some Bruce menus.

| Context | Keys |
|---|---|
| Menu navigation | `Fn` + `;`/`.`/`,`/`/` for up/down/left/right; `Enter` confirms; `Backspace` cancels |
| Escape / back | `Fn` + `` ` `` |
| Text input | Standard QWERTY; `Shift` and `Fn` for symbols |
| Caps lock toggle | `Fn` + `Shift` |
| Context shortcut | `G0` (top-right hardware button), where supported |

## Appendix C — Pre-flight compliance checklist (Bruce-specific)

In addition to the items from the Evil-M5 chapter's checklist:

- [ ] Written ROE explicitly enumerates every radio band you intend to operate on (e.g., "2.4 GHz Wi-Fi", "433 MHz CC1101", "13.56 MHz NFC", "125 kHz LF RFID", "IR", *not* "wireless attacks generally").
- [ ] ROE explicitly addresses whether any *transmit* operations are authorized (vs receive-only).
- [ ] Jammer features (RF Jammer Full, RF Jammer Intermittent, NRF24 Jammer) are **disabled in your operator workflow** unless the ROE explicitly authorizes jamming *and* you can verify isolation from third-party transmissions. In nearly all cases the right answer is: don't.
- [ ] FM broadcast features are likewise off-limits without specific authorization and shielding.
- [ ] Sub-GHz operations are conducted in a verified-isolated location (SDR-confirmed no third-party signals on the target frequency within range).
- [ ] NFC and 125 kHz cloning operations involve only tags you own or that the client has provided for testing.
- [ ] Captured credentials, RF captures, and NFC dumps are stored encrypted and destroyed per ROE timeline.
- [ ] If WireGuard or TCP Listener will be deployed as a persistent implant, the location and removal date are inventoried.
- [ ] E&O / professional-liability insurance is current.

If any line is unchecked for the operations you intend to run, the affected modules stay off.

## Appendix D — Further reading and resources

- **Bruce project home:** `https://bruce.computer`
- **Bruce Web Flasher:** `https://bruce.computer/flasher`
- **GitHub repos:** `https://github.com/pr3y/Bruce` and `https://github.com/BruceDevices/firmware` (same codebase)
- **Bruce wiki (per-module documentation):** `https://github.com/pr3y/Bruce/wiki`
- **Doolittle JS interpreter project:** `https://github.com/justinknight93/Doolittle`
- **Bruce open-hardware boards:** `https://bruce.computer/boards` (Smoochiee V2, Bruce RF Reaper PCBs)
- **FCC Enforcement Bureau:** `https://www.fcc.gov/enforcement` — read the actual jammer enforcement advisories before operating any transmit feature.
- **FCC Part 15 reference:** `47 CFR Part 15` (unlicensed operation rules)
- **FCC Part 73:** `47 CFR Part 73` (broadcast service rules — applies to FM)
- **47 USC §§ 301, 302a, 333:** the three statutes that bracket every transmit operation Bruce can perform.

---

*This chapter is provided for educational and authorized red-team use only. The Bruce firmware authors, the manufacturers of M5Stack and Lilygo hardware, and the author of this chapter accept no responsibility for misuse. Operating transmitters without authorization, intentionally interfering with licensed radio communications, and accessing computer systems without authorization are crimes in every U.S. state and in most jurisdictions worldwide. The expanded RF feature set in Bruce relative to Evil-M5 dramatically expands the practitioner's exposure to FCC enforcement action. Treat every transmit feature as a regulated activity requiring affirmative authorization before use.*
