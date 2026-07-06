# The M5Cardputer & Evil-M5Project

## 🎯 Purpose
Technical guide for the M5Cardputer running Evil-M5Project firmware - a pocket-sized, keyboard-driven wireless security workstation for authorized WiFi penetration testing, captive portal attacks, and network reconnaissance.

## ⚙️ Function
Covers hardware specifications, firmware installation via M5Burner or Arduino IDE compilation, SD card preparation, UI navigation conventions, and module deep-dives: WiFi scanning, wardriving with GPS, deauthentication, evil twin captive portal, handshake capture, BadUSB, EAPOL/deauth detection, BLE device detection (Wall of Flipper, AirTag, skimmers), and the Reverse TCP Tunnel implant mode. Includes an 8-exercise closed-lab playbook and a blue-team attack/defense table.

## 🏆 Goal
Equip security professionals with a discreet, pocket-portable WiFi attack and detection platform for authorized red-team engagements, client demonstrations, and security training.

## 📋 When to Use
- WiFi security assessments requiring a low-profile tool (Cardputer on a lanyard is not a laptop)
- Client demonstrations of evil twin attacks, deauthentication, and captive portal credential capture
- Security awareness training: show clients their phone connecting to a rogue AP in real time
- Wardriving and passive WiFi reconnaissance with GPS-tagged output
- Defensive monitoring: detecting deauth floods, Flipper Zero BLE, Bluetooth skimmers

> **Reader prerequisites.** This part of the repository assumes working familiarity with [802.11 frame types](https://en.wikipedia.org/wiki/802.11_frame_types) (beacon, probe request/response, deauthentication, EAPOL four-way handshake), basic Linux command-line use, soldering-free hobby electronics, and the legal framework governing wireless testing in your jurisdiction. If any of those are unfamiliar, read the foundations chapters first; the techniques described here can cause real disruption to networks and people if used carelessly or maliciously.

---

## 1. Why this platform matters

The [Cardputer](https://shop.m5stack.com/products/m5stack-cardputer-adv-version-esp32-s3) is, in physical terms, a $30 toy. It is the size of a credit card, has a 1.14-inch screen, a 56-key keyboard, an ESP32-S3 microcontroller, and a microSD slot. It does not look like a serious tool. That is precisely the point.

Loaded with the **[Evil-M5Project](https://github.com/7h30th3r0n3/Evil-M5Project)** firmware by [7h30th3r0n3](https://github.com/7h30th3r0n3), that toy becomes a self-contained, battery-powered wireless security workstation that fits in a shirt pocket. It performs reconnaissance, evil-twin captive-portal attacks, deauthentication, handshake capture, wardriving with GPS, KARMA-style probe response, BadUSB host attacks, and dozens of other operations that; only a few years ago; required either a full Kali laptop with an external Atheros card, a dedicated Pwnagotchi, or a stack of hardware costing ten times as much.

For the practicing security professional, the Cardputer/Evil-M5 combination earns its place in the kit for three reasons:

- **Demonstrative power.** A client board does not understand what an evil twin is until they watch their own phone connect to one in a conference room. The Cardputer's form factor and on-screen feedback make these attacks visceral in a way that a terminal window never will.
- **Discreet site assessments.** A Cardputer on a lanyard is not a laptop. For authorized red-team work where physical-environment realism matters, the device disappears.
- **Education and skills development.** The firmware exposes nearly every technique a junior pentester should be able to recognize on a capture file. Running these attacks against your own lab; and watching the corresponding frames in Wireshark; collapses weeks of theory into an afternoon of practice.

Nothing in this chapter is novel as wireless attack theory. What is novel is the accessibility. That accessibility is the threat model your defensive controls now have to address.

---

## 2. Legal and ethical framework; read before you flash

Wireless attacks of the kind this firmware performs are regulated in the United States primarily by:

- **18 U.S.C. § 1030**; the Computer Fraud and Abuse Act (CFAA). Unauthorized access to a "protected computer" is a federal felony. Wi-Fi networks are protected computers.
- **47 U.S.C. § 333**; willful interference with licensed radio communications, including deauthentication of nearby clients on networks you do not own and have not been authorized to test. The FCC has issued six-figure civil penalties for hotel and convention-center deauth use: Marriott was fined $600,000 in 2014 for blocking guest hotspots at the Gaylord Opryland with deauth frames; Smart City Holdings was fined $750,000 in 2015 for similar conduct at multiple convention centers; M.C. Dean received a $718,000 Notice of Apparent Liability for related activity. The FCC's January 2015 Enforcement Advisory explicitly states that Wi-Fi blocking via deauth is "patently unlawful."
- **State analogues**; Washington's RCW chapter 9A.90 (the Washington Cybercrime Act) covers computer trespass in the first degree (9A.90.040, a Class C felony) and second degree (9A.90.050, a gross misdemeanor), plus electronic data service interference (9A.90.060, particularly relevant for deauth-style disruption). Oregon's ORS 164.377 (computer crime) parallels these and was used as recently as the 2024 *State v. Azar* decision in interpreting authorization. Neither requires a federal interstate-nexus element.
- **Stored communications**; captured credentials, captured handshakes, and intercepted traffic are governed by the Wiretap Act and the Electronic Communications Privacy Act (ECPA).

You may use this platform legally in three contexts:

1. **On hardware and networks you personally own**, in a controlled location, with no client devices present that you do not own.
2. **Under a signed Rules of Engagement (ROE)** with a client who owns the target environment, with a defined scope, defined hours of operation, and a defined point of contact.
3. **In a closed-lab classroom or CTF environment** explicitly configured for the purpose, with no exposure to outside RF traffic of bystanders.

You may **not** legally:

- Deauthenticate clients of nearby networks "just to test"; even briefly, even with no data captured.
- Stand up an evil twin in a public space (coffee shop, hotel lobby, conference venue) to "see who connects."
- Capture WPA handshakes from networks you do not own.
- Run KARMA or probe-response attacks in public, even passively.

A blanket personal rule: **if the closest networks to your antenna are not yours and your ROE does not cover them, the radio stays off.** Use a Faraday bag or a shielded room (an unpowered microwave oven is, in a pinch, surprisingly effective for benchtop testing) when developing or rehearsing techniques.

The firmware author publishes the project for educational and authorized red-team use and disclaims responsibility for misuse. So do I. So should you, in any deliverable you produce while using it.

A practical compliance checklist appears in Appendix C.

---

## 3. The hardware

### 3.1 The M5Cardputer

The M5Stack Cardputer is built around the M5StampS3 module; a removable core board carrying an ESP32-S3FN8; slotted into a card-shaped enclosure with screen, keyboard, microSD, audio, and a detachable battery base. Relevant specifications from M5Stack's reference documentation:

| Component | Specification |
|---|---|
| Core module | M5StampS3 (or Stamp-S3A on the Adv variant) |
| SoC | Espressif ESP32-S3FN8 (Xtensa LX7 dual-core, up to 240 MHz, RISC-V ULP co-processor) |
| Memory | 512 KB SRAM, 384 KB ROM, **no PSRAM** |
| Flash | 8 MB (internal to ESP32-S3FN8 die) |
| Wi-Fi | 2.4 GHz 802.11 b/g/n |
| Bluetooth | BLE 5.0 (+ Bluetooth Mesh) |
| Display | 1.14" TFT, 240 × 135 px, ST7789V2 controller |
| Input | 56-key keyboard (4 × 14 matrix) |
| Storage | microSD slot (FAT32; 8–16 GB recommended) |
| Power | 120 mAh battery in the StampS3 + 1400 mAh battery in the detachable base (~1520 mAh combined). USB-C charging. |
| Expansion | HY2.0-4P Grove port (I²C / GPIO); GPIO breakout on the StampS3 module itself |
| Audio in | SPM1423 digital MEMS microphone |
| Audio out | Cavity speaker driven by an NS4168 I²S amplifier @ 1 W, 8 Ω |
| IR | On-board IR emitter (~410 cm at 0°) |
| Physical | 84.0 × 54.0 × 19.7 mm, 92.3 g |

The "Adv" version (the current SKU at time of writing; M5Stack lists the original as end-of-life) keeps the same ESP32-S3FN8 core but adds an ES8311 audio codec, NS4150B amplifier, 3.5 mm headphone jack, BMI270 6-axis IMU, redesigned 3D antenna, a single 1750 mAh battery (replacing the 120 + 1400 mAh split), and a softer keypress (160 gf vs. 260 gf). Both variants run the Evil-M5 Cardputer firmware. Either is fine; the Adv has noticeably better RF reach thanks to the new antenna.

### 3.2 Required accessories

- **microSD card.** FAT32-formatted, 8–16 GB. The card holds the captive-portal site templates, wardriving logs, theme files, and SSID dictionaries. **The firmware will not function in any useful capacity without it.**
- **USB-C data cable** for flashing and BadUSB use. Confirm it is data-capable; charge-only cables will silently fail flashing.
- **GPS unit (optional but recommended).** Either the M5Stack "GPS-BDS Unit with SMA antenna" (AT6668-based) or the "Atomic GPS Base" (M8030-based) plugs into the Grove port and enables wardriving with Wigle-compatible CSV output. Cheap third-party UART GPS modules also work with a Grove-to-Dupont wiring jumper.
- **RFunit module (optional).** Required only for the Tesla / sub-GHz RF features. Sub-GHz transmission has its own legal considerations beyond the scope of this chapter.
- **A faraday pouch.** Not a joke. You will at some point want to test a behavior without irradiating the neighborhood; a $15 RF-shielded pouch large enough to hold the Cardputer and a victim phone solves that.

### 3.3 The Evil-M5 family

The firmware runs on several M5Stack devices, but feature parity is highest on the Cardputer. The author maintains separate builds for the M5Core2, M5Core3 (CoreS3), AtomS3, Fire, and Evil-Face, with progressively smaller feature sets as device capability declines. The M5StickC Plus 1.1, CYD1USB, and CYD2USB are listed as in-beta targets. The Cardputer build is the canonical target; the source file on the `main` branch is currently `Evil-Cardputer-v1-4-9.ino`, while the M5Burner-distributed build is tagged v1.5.1 (the project releases through M5Burner ahead of source commits). Any procedure in this chapter assumes the Cardputer build unless explicitly noted.

---

## 4. The software, in brief

Evil-M5Project began as a port of the author's earlier M5Core2-based "Evil-M5Core2" tool and has grown into a multi-device wireless security framework. It is open source under the MIT License and hosted at `https://github.com/7h30th3r0n3/Evil-M5Project`. Active development is rapid; expect new features and breaking SD-card layout changes every few months.

The firmware's design philosophy is best understood as "Marauder + Pwnagotchi + Flipper Zero, fused into a single keyboard-driven menu." Where the Flipper hides functionality behind app silos and the Pwnagotchi runs a single autonomous loop, Evil-M5 exposes a flat menu of attacks and reconnaissance modes, each with consistent navigation and on-screen status feedback. The Cardputer's keyboard makes the navigation actually tolerable; every other M5Stack form factor relies on three buttons, which is fine for a demo and grueling for a real engagement.

### 4.1 Feature inventory (Cardputer build)

The features fall into seven functional categories. The table below summarizes them; full procedures for the headliners appear in Section 8.

**Reconnaissance**
- Wi-Fi network scanning (active and passive)
- Wi-Fi channel visualizer
- Probe-request sniffing
- Wardriving (standalone and master-slave with auxiliary ESP32 nodes)
- Network/port scanning
- Full network scan with service enumeration

**Active wireless attacks**
- Deauthentication (manual and automated)
- Evil Twin (clone SSID + captive portal + concurrent deauth)
- Beacon spam (mass fake SSID broadcast)
- Probes attack (forge probe requests)
- KARMA attack (respond to any probed SSID)
- Automated KARMA, KARMA Spear (targeted SSID variant)
- WPA handshake capture (Handshake Master, Check Handshakes)
- WPA2 cracking helper (Aircrack integration)

**Network-level attacks (post-association)**
- DHCP Starvation
- Rogue DHCP server
- Switch DNS / DNS spoofing
- Network Hijacking
- Responder / WPAD abuse / NTLMv2 capture and crack helper
- SSDP poisoning, UPnP mapping and NAT abuse
- LDAP enumeration
- SkyJack (drone hijack)

**Captive portal and credential capture**
- Captive portal management with SD-stored site templates
- Web Siphoning Cookie
- Honeypot mode (with optional webhook reporting)
- Admin WebUI for remote control

**Detection / defensive**
- EAPOL and deauth detection (passive sniffing)
- Wall of Flipper (BLE Flipper Zero detector)
- Wall of AirTag, FindMyEvil (BLE Find My-network detection)
- Skimmer Detector (Bluetooth HC-03/05/06 module detection)
- Open Wi-Fi Checker
- IMSI Catcher (detection)

**Host attacks via USB**
- BadUSB with Ducky Script support
- Mouse Jiggler
- WebUI BadUSB payload editor
- SD-on-USB (expose the SD card as mass storage)

**Implant / remote operation**
- Reverse TCP tunnel (operate the device through a C2 server)
- Bluetooth keyboard (act as HID over BLE)
- UART shell
- LLM chat stream (talk to a remote model from the device)
- EvilChatMesh (mesh chat over Wi-Fi)

This is not exhaustive. The firmware also includes a SIP toolkit, CCTV toolkit, file manager, file print, printer attack, BLE name flood, autodiscover abuse, and the WiFi Dead Drop covert-storage feature. Treat the chapter as a guided tour of the headline capabilities, not a comprehensive command reference; that reference is the project wiki, which you should bookmark.

---

## 5. Installation

There are two supported installation paths. Use M5Burner unless you have a specific reason to compile yourself.

### 5.1 Path A; M5Burner (recommended)

M5Burner is the official M5Stack firmware flashing tool. It hides the entire ESP-IDF toolchain behind a one-click flow and is the lowest-friction path to a working device.

1. Connect the Cardputer to your workstation via USB-C. Wait for the OS to assign a COM/tty device. On Windows, this is usually `COM3` or higher; on Linux/macOS, look for `/dev/ttyUSB0`, `/dev/ttyACM0`, or `/dev/cu.usbmodem*`.
2. Download M5Burner from the M5Stack download center: `https://docs.m5stack.com/en/download`; pick the "UIFLOW FIRMWARE BURNING TOOL" build for your OS.
3. Install and launch M5Burner.
4. In the device list (left pane), navigate to **Cardputer**. In the search bar at the top of the firmware list, type `evil-`. The current Evil-Cardputer build appears in results.
5. Click **Download** to fetch the firmware locally. Once the download completes, the button changes to **Burn**.
6. Click **Burn**, select the correct serial port, leave baud at the default 1500000 (M5Burner handles this automatically), and confirm.
7. When burning completes, **physically disconnect** the Cardputer, reseat the USB cable, and let the device boot. The Evil splash screen should appear within a few seconds.

If the device boots to a blank screen or a "no SD" indicator, that is expected; Step 5.3 below populates the SD card.

### 5.2 Path B; Compile from source

Compile from source when you want to:
- Track unreleased features on the `main` branch
- Patch the firmware for a custom use case
- Change defaults you cannot change at runtime (themes other than via theme.ini, default IPs for the Admin WebUI, etc.)

Procedure:

1. Install the **Arduino IDE** (2.x recommended).
2. Add the ESP32 board manager URL in **File → Preferences → Additional Boards Manager URLs**:
   ```
   https://raw.githubusercontent.com/espressif/arduino-esp32/gh-pages/package_esp32_index.json
   ```
3. In **Tools → Board → Boards Manager**, install **esp32 by Espressif Systems**. The project documentation specifically requires version **2.1.4 or earlier** and warns that 3.x (including the `3.0.0-alpha3` revision) breaks the build on most non-M5 boards. Anything in the 2.x line up to 2.1.4 is safe.
4. Install the M5Stack board package - see `https://docs.m5stack.com/en/arduino/arduino_board` (verify current URL; M5Stack docs restructure periodically) or search M5Stack's Arduino quickstart in their official docs.
5. Install the following libraries via **Library Manager**:
   - `Adafruit_NeoPixel`
   - `ArduinoJson`
   - `ESPping`
   - `IniFile`
   - `M5GFX`
   - `M5Unified`
   - `TinyGPSPlus`
   - `ESP8266Audio` (yes, the ESP8266-named library; it works on ESP32)
6. Clone the repository:
   ```bash
   git clone https://github.com/7h30th3r0n3/Evil-M5Project.git
   cd Evil-M5Project
   ```
7. **Run the deauth prerequisites script** in `utilities/deauth_prerequisites/`. The README describes this as bypassing a check in the Arduino-ESP32 library that would otherwise block raw 802.11 management frames; in practice it patches the relevant library file(s) so deauth and beacon-spam frames can be transmitted. Without running this script, those modules will compile but their frame-injection calls will be silently dropped.
8. For BadUSB, install the libraries described in `utilities/Bad_Usb_Lib/README.md`.
9. Open `Evil-Cardputer-v1-5-1.ino` (or whatever the current release file is named) in the Arduino IDE.
10. Configure board settings under **Tools**:
    - **Board:** M5Cardputer
    - **USB CDC On Boot:** Enabled
    - **Flash Size:** **8 MB (64 Mb)**; this is required, the default is wrong
    - **Partition Scheme:** **8M with spiffs (3MB APP / 1.5MB SPIFFS)**; also required
    - **PSRAM:** **Disabled**; the Cardputer's ESP32-S3FN8 ships without PSRAM hardware; enabling it in the IDE causes boot failures
    - **Upload Speed:** 921600
    - **Port:** the Cardputer's serial port
11. Click **Upload**. First-time compile takes 5–10 minutes; incremental builds are faster.

If you see `Sketch too big` errors, you missed Step 10's flash-size and partition-scheme configuration. Fix and rebuild.

### 5.3 SD card preparation

The firmware is split between the on-flash binary and a data layout on the SD card. As of the v1.4.x series, **the SD content must live in a folder named `evil` at the root of the SD card**, not at the root itself. This is a recent change; older guides may show files at the root.

1. Format a microSD card as **FAT32** (do not use exFAT; the ESP32 SD driver does not handle it).
2. Download the SD card content from the project's `SD-Card-File/` directory in the repo. The fastest way:
   ```bash
   git clone --depth 1 https://github.com/7h30th3r0n3/Evil-M5Project.git
   ```
   then copy `Evil-M5Project/SD-Card-File/*` into an `evil/` folder on the SD card.
3. Resulting layout (per the project's installation wiki, the documented top-level subdirectories are):
   ```
   /evil/
     ├── IMG/         # splash and UI images
     ├── sites/       # captive portal HTML templates
     ├── NTLM/        # Responder/NTLMv2 capture data
     ├── config/      # config.txt and runtime configuration
     ├── theme.ini    # color theme (Cardputer only)
     └── …            # additional folders are created at runtime
   ```
   Runtime modules create their own subdirectories the first time they write output; wardriving logs, EAPOL/handshake captures, captured portal credentials, and BadUSB payloads each land under `/evil/` in module-specific folders. Exact paths shift between firmware revisions; trust the device's own file manager and the wiki for authoritative locations.
4. Customize `theme.ini` if you want non-default colors. Theming is currently Cardputer-only.
5. Insert the SD card before powering the device.

### 5.4 First boot verification

Power on. You should see:

1. A splash image (the project logo, loaded from `/evil/IMG/`).
2. The main menu after ~2 seconds.
3. No "SD card missing" warning. If you see one, power off, reseat the SD card, and confirm it is FAT32 with an `evil/` folder at root.

If you see only a black screen with the Cardputer power LED on, the firmware did not flash correctly; reflash.

---

## 6. UI orientation and navigation conventions

The firmware uses a consistent set of keyboard conventions on the Cardputer. The hardware keyboard has no dedicated arrow keys; directional input uses the Fn layer documented by the M5Cardputer library. Internalize the mapping once and you can navigate any module:

| Key | Action |
|---|---|
| `Fn` + `;` / `.` / `,` / `/` | Up / Down / Left / Right navigation |
| `Fn` + `` ` `` (backtick) | Escape |
| `Enter` | Select / confirm |
| `Backspace` | Cancel / back / clean exit from a running attack |
| `Tab` | Cycle context where applicable |
| `Ctrl` + `Backspace` | Force-quit certain attack loops |
| Alphanumerics | Direct text entry at any input prompt (SSID, password, IPs) |

The screen is small. A typical attack view shows a header (mode name), 4–6 lines of live status, and a footer with the active hotkey. Get used to reading dense single-line indicators; `ch6 -42dBm BSSID:aa:bb:cc:dd:ee:ff` is the kind of line you will be parsing constantly.

---

## 7. A note on the Admin WebUI and Reverse TCP Tunnel

Two features deserve mention up front because they change the operating posture of the device:

- **Admin WebUI.** The device can be configured to serve a control panel on its own SoftAP or to join your network and serve the panel on a LAN IP. The WebUI exposes most attack functions through a browser, allowing operation from a phone or laptop without touching the Cardputer's keyboard. Useful for demos and for setups where the device is hidden. **Secure the WebUI with a strong password** before deploying anywhere a third party can reach it; the default credentials are well-known.
- **Reverse TCP Tunnel.** The device connects outbound to a listener you control (typically a cheap VPS) and exposes a control channel. This converts the device into a remote-controllable implant. Powerful for authorized long-term assessments; legally hazardous everywhere else. **Do not configure this against the public Internet without an ROE.**

Both features are off by default. Leave them off until you have a specific use case.

---

## 8. Module deep-dives

The following sections cover the most consequential modules. Each follows the same structure: what it does, what it produces, how to run it, and what to watch on the wire (or BLE) in parallel for verification.

### 8.1 Wi-Fi network scan

**Purpose.** Build a list of nearby 2.4 GHz APs with BSSID, channel, encryption, and RSSI. The list is the starting input for nearly every other attack; clone, deauth, evil-twin, handshake capture all consume an entry from the scan list.

**Procedure.**
1. From the main menu: `Wi-Fi → Scan WiFi`.
2. The device performs a full-channel sweep (~5 seconds).
3. Browse results with arrow keys. Each entry shows SSID, channel, RSSI, encryption type, and BSSID.
4. `Enter` on an entry opens the per-network menu; clone, set as target, view details, etc.

**Verification.** From an adjacent laptop, run `sudo airodump-ng wlan0mon` and confirm the same APs appear with the same BSSIDs and channels. The Cardputer's results should match within a few dBm and identical BSSID/channel pairs.

### 8.2 Wardriving

**Purpose.** Continuous SSID capture geotagged to GPS coordinates, written to SD card as Wigle-compatible CSV. The output uploads directly to wigle.net or imports into Kismet for offline mapping.

**Procedure.**
1. Plug the GPS Unit into the Grove port. Allow 30–120 seconds for first fix; expect longer under indoor or dense urban cover.
2. From the main menu: `Wardriving → Start`.
3. The screen displays current GPS fix status, current scanning channel, total unique BSSIDs captured, and live SSID counter.
4. The device writes incrementally to a Wigle-format CSV on the SD card under `/evil/` (the filename typically encodes a timestamp).
5. `Backspace` to stop. The file is closed cleanly on exit; do not yank the SD card mid-run.

**Master/Slave scaling.** The Cardputer can act as a master that ingests SSID data from one or more auxiliary ESP32 "slave" nodes (AtomS3, ESP32-C3 with external antenna, WEMOS D1 Mini, ESP32-C5). Each slave locks to a single 2.4 GHz channel and broadcasts captures to the master, eliminating channel-hop blind spots. With 14 slaves you cover all 14 channels concurrently. This is overkill for casual mapping but extremely effective for dense corporate-campus surveys.

**Verification.** Drop the CSV into wigle.net's upload form. The site renders captured APs on the map; cross-reference against a known-location AP to confirm GPS calibration.

### 8.3 Channel visualizer

A spectrum-style overlay of 2.4 GHz channel utilization. Useful for picking a quiet channel to host an evil twin on (you want signal contrast with the legitimate AP, but you do not want a third-party AP camped on top of you). Also useful as a quick "is this corporate Wi-Fi properly planned" diagnostic; a deployment with five APs all on channel 6 advertises itself as poorly tuned.

### 8.4 Probe sniffing and KARMA family

**Background.** When a Wi-Fi client is not associated with an AP, it broadcasts probe requests asking for any of its "preferred network list" (PNL). Many devices broadcast SSIDs of every network they have ever joined; home, airport, hotel, ex's apartment. Probe sniffing captures these. A KARMA attack stands up an AP that responds affirmatively to any probed SSID, tricking the client into auto-associating with what it believes is a known network.

**Probe sniffing.**
1. `Wi-Fi → Sniffing Probes`.
2. The device displays a live-updating list of `SSID; MAC` pairs as they appear.
3. Captures persist to SD on exit; the next module consumes them.

**KARMA Attack.**
1. `Attacks → Karma Attack`. The device starts an AP that replies to all probes with affirmative responses.
2. Clients in the area that have any open or matching network in their PNL begin associating.
3. Once associated, the captive portal flow (Section 8.6) can run on top.

**KARMA Spear** is a targeted variant; instead of responding to everything, the device responds only to a specific SSID you specify. Less noisy, more credible against a target who knows their devices remember "Starbucks WiFi" but is harder to fool with a generic catch-all.

**Defensive observation.** A defender running Kismet on the same channel will see beacons and probe responses from an AP that claims to be every SSID ever requested. This is unmistakable in any half-decent WIDS.

### 8.5 Deauther

**Purpose.** Transmit 802.11 deauthentication frames spoofed from the AP's BSSID, telling target clients to disconnect. Used to force client reconnection (for handshake capture), to herd clients onto an evil twin, or as standalone denial-of-service.

**Procedure.**
1. Scan and select a target network.
2. `Attacks → Deauther`. Choose target type:
   - Broadcast: deauth all clients from the AP
   - Specific client: deauth only the chosen STA (requires prior client sniff)
3. The device begins transmitting deauth frames at a configurable rate.
4. Live count and elapsed time are shown.
5. `Backspace` to stop.

**Auto Deauther** sweeps targets and rotates automatically. Useful for "stress test" demonstrations; reckless and illegal anywhere outside an isolated lab.

**Verification.** On a target STA you own, watch the Wi-Fi indicator. A deauth flood typically causes the device to disconnect and reconnect every 1–3 seconds. In Wireshark, filter `wlan.fc.type_subtype == 0x0c` to isolate deauth frames; expect a continuous flood.

**Critical caveat.** Modern Wi-Fi (802.11w, Protected Management Frames / PMF) was specifically designed to defeat this attack. WPA3 mandates PMF; WPA2 supports it as optional. Against a properly configured corporate WPA2-Enterprise network with PMF required, the Cardputer's deauth has no effect. This is part of why the technique is detectable and increasingly mitigated; and part of why your defensive posture should include enforcing PMF.

### 8.6 Evil Twin (captive portal fake AP + deauth)

This is the marquee feature and the one most likely to appear in your book's "what an attacker can do in 60 seconds" demonstrations.

**Concept.** The device clones a chosen SSID, stands up a SoftAP impersonating it, runs a captive portal that mimics the legitimate network's login or some plausible system prompt ("Router firmware update; please re-enter your Wi-Fi password"), and concurrently deauths clients from the real AP so they roam onto the rogue. Submitted credentials are logged to SD.

**Procedure.**
1. Scan for nearby APs.
2. Select the target SSID. `Enter → Set as Evil Twin target`.
3. (Optional) Set a known password via "Set Password" if you want to mount a KARMA-style attack against a network whose key you already have.
4. Select the captive portal template. Templates live under `/evil/sites/` and are simple HTML/CSS bundles. The project ships with several generics (router-update, captive-portal-login, ISP-rebrand variants). You can write your own; structure is documented in the wiki's Captive Portal Management page.
5. `Attacks → Evil Twin`. The device launches the fake AP, starts deauthing the real AP's BSSID, and begins serving the portal.
6. Status display shows: target SSID, channel, deauth frame count, connected clients.
7. Captured credentials write to a logs file on the SD card under `/evil/` (the wiki refers to a `/logs` endpoint exposed by the Admin WebUI for the same data).
8. `Backspace` exits cleanly.

**What to demonstrate to a client.** Run this in your own lab against your own SSID. Watch a phone you own roam to the rogue. Submit a credential into the portal. Pull the SD card and show the client the file. The reaction is consistent: "wait, that's it?" Yes, that's it. That's the point.

**Defensive measures.** Enterprise WPA2/WPA3 with proper EAP-TLS (mutual cert auth) breaks this technique cleanly; the client validates the server certificate before sending credentials. PSK networks are vulnerable; the mitigation is user training (never enter your Wi-Fi password into a web page) and PMF.

### 8.7 Handshake Master

**Purpose.** Capture WPA/WPA2 four-way handshakes from the air, save them as pcap files on the SD card, and (with the Cracking helper) attempt offline dictionary cracking.

**Procedure.**
1. Scan, target an AP.
2. `Attacks → Handshake Master`. The device runs concurrent passive sniffing on the target channel and a low-rate deauth against the AP to provoke client reconnections.
3. When a complete four-way exchange is captured, the device announces it and writes a pcap file to the SD card (path varies by firmware revision; check the device's file manager).
4. Exit, eject SD, copy the pcap to your workstation.
5. Crack with hashcat:
   ```bash
   hcxpcapngtool -o hash.hc22000 capture.pcap
   hashcat -m 22000 hash.hc22000 wordlist.txt
   ```

The on-device `Aircrack` module performs limited cracking against small wordlists; do not expect to crack a strong PSK on a 240 MHz Xtensa core. Use the device for capture, your workstation or GPU rig for cracking.

**Check Handshakes** validates a captured pcap to confirm the four messages are present and complete. A common failure mode is capturing M1+M2 only; useless for cracking. Verify before walking away from the engagement.

### 8.8 BadUSB

**Purpose.** With the Cardputer plugged into a target host via USB-C, the device enumerates as an HID keyboard and types out a Ducky Script payload. Classic BadUSB. The Cardputer adds a wrinkle: it can also enumerate as USB mass storage and serve the SD card, useful for staging larger payloads that the script then executes locally.

**Procedure.**
1. Place your Ducky Script as a `.txt` file in the BadUSB directory on the SD card (the in-device file picker will list all files in that directory; consult the wiki's BadUSB page for the current path on your firmware version).
2. `BadUSB → Select Payload → <your payload>`.
3. Plug the Cardputer into the target. Confirm enumeration.
4. `BadUSB → Run`. The payload executes at HID typing speed.
5. The WebUI BadUSB editor lets you compose payloads from a browser without touching the SD card; useful for rapid iteration.

**Defensive observation.** Endpoint detection that watches for sudden HID device attachment, especially combined with rapid keystroke entry from an unrecognized vendor ID, catches this trivially. The hardware-level mitigation is to require admin authorization for new HID devices (Windows USB Restrict policy, macOS USB Restricted Mode, Linux usbguard).

### 8.9 EAPOL / Deauth detection (defensive)

**Purpose.** Sit on a chosen channel and log deauthentication and EAPOL frames. Useful as a portable WIDS sensor.

**Procedure.**
1. `Detection → EAPOL/Deauth Detection`.
2. Choose target channel (or all-channel hopping).
3. The device displays per-second deauth and EAPOL counts and writes incidents to SD.

Place the Cardputer near a network you want to monitor and you have a $35 deauth detector. Not a substitute for a real WIDS, but a useful sanity check during incident response and an excellent training aid; students can run the offensive deauth on one Cardputer and see the detection light up on another in real time.

### 8.10 Wall of Flipper, Wall of AirTag, Skimmer Detector

The BLE-side defensive modules:

- **Wall of Flipper.** Detects nearby Flipper Zero devices by their BLE advertisement pattern. The project integrates with K3YOMI's Wall-of-Flippers convention.
- **Wall of AirTag / FindMyEvil.** Detects Apple Find My-network devices in the area, including potentially stalking-deployed AirTags.
- **Skimmer Detector.** Scans for Bluetooth modules commonly found in card skimmers (HC-03, HC-05, HC-06). A walk through a gas station forecourt with this running can identify deployed skimmers in seconds.

These are unambiguously defensive. Run them at conferences, on travel, near ATMs.

### 8.11 Reverse TCP Tunnel

Sketch only: the device connects outbound to a listener of your choosing, registers, and accepts commands. Effectively turns the Cardputer into a beacon-style implant. Setup involves spinning up the project's server-side handler on a VPS (the wiki documents this), configuring the Cardputer with the listener's address, and starting the tunnel from the menu. Operationally, this is how you would deploy a Cardputer hidden in a target site during a long-running engagement.

If you are reading this section to decide whether to use it: confirm your ROE explicitly covers persistent remote-access implants before you flip this switch.

---

## 9. Playbook; laboratory exercises

The following exercises are designed for a closed lab. Each one assumes:

- A target network you own (an old router, factory-reset, with a single client device).
- Your testing Cardputer (the "attacker").
- A workstation running Kali, Wireshark, and an external Wi-Fi adapter in monitor mode (the "observer").
- A second Cardputer in detection mode where applicable (optional but recommended for the full red/blue effect).
- A faraday space if you cannot otherwise isolate from neighbors' networks.

Run them in order; each builds on the previous.

### Exercise 1; Passive recon

**Objective.** Build a baseline inventory of your lab RF environment using only passive techniques.

**Steps.**
1. On the Cardputer, run a Wi-Fi scan. Note all visible SSIDs, channels, BSSIDs, encryption.
2. On the observer workstation, run `airodump-ng wlan0mon` for the same duration.
3. Compare results. Identify any APs visible to one but not the other; account for the difference (antenna gain, channel coverage, scan duration).
4. Run the Cardputer's channel visualizer. Identify the least-utilized channel.

**Success criteria.** You can state, with evidence, how many APs are reachable, on which channels, and which is your target.

**Debrief.** Why might the Cardputer miss APs that the observer sees, and vice versa?

### Exercise 2; Probe sniffing and PNL inference

**Objective.** Capture probe requests from a known client device (your own phone) and infer its preferred network list.

**Steps.**
1. Put the test phone in Wi-Fi-on, not-connected state.
2. Cardputer: `Sniffing Probes`, run for 5 minutes.
3. Review the captured SSID/MAC list.

**Success criteria.** The captured probes include at least one SSID you know is in the phone's PNL.

**Debrief.** Modern iOS and Android randomize probe MAC addresses and reduce broadcast probing. How does your phone's behavior compare to the documented mitigations? What can a defender infer if they know a specific user's typical PNL (home, office, gym)?

### Exercise 3; Targeted deauth with verification

**Objective.** Deauth a single client from your own AP and verify the effect on the wire.

**Steps.**
1. Confirm your target STA is associated to your lab AP.
2. On the observer, start Wireshark with filter `wlan.fc.type_subtype == 0x0c`.
3. On the Cardputer: scan, select target AP, `Deauther → Specific client` (you may need to sniff clients first), select client MAC.
4. Run for 30 seconds.
5. Stop. Observe Wireshark.

**Success criteria.**
- Wireshark shows a continuous flood of deauth frames spoofed from your AP's BSSID to the target STA.
- The target STA's Wi-Fi indicator shows disruption.
- Frame timing matches the Cardputer's reported transmission rate.

**Debrief.** Enable PMF on your AP (if it supports it; most modern routers do, though it is often off by default). Repeat the exercise. What changes?

### Exercise 4; Handshake capture and offline cracking

**Objective.** Capture a complete WPA2 four-way handshake against your lab network and crack a known-weak PSK offline.

**Steps.**
1. Set your lab AP's PSK to a five-character lowercase word from a common wordlist (e.g., `apple`). This is for the exercise only.
2. Cardputer: `Handshake Master`, target your AP.
3. Force the test STA to reconnect (toggle Wi-Fi).
4. Wait for the device to announce a captured handshake.
5. Copy the pcap to your workstation.
6. Convert and crack:
   ```bash
   hcxpcapngtool -o hash.hc22000 capture.pcap
   hashcat -m 22000 hash.hc22000 /usr/share/wordlists/rockyou.txt
   ```

**Success criteria.** Hashcat cracks the PSK and outputs the plaintext.

**Debrief.** Recompute with a 16-character random PSK. How long would brute-force take? Compute the difference using `hashcat -b -m 22000` to benchmark your hardware.

### Exercise 5; Evil Twin demonstration

**Objective.** Mount an evil twin against your lab SSID, capture a credential submission from a device you own, and document what the experience looks like to the user.

**Steps.**
1. Confirm scope: lab only, your network, your device, no bystanders.
2. Cardputer: select your lab AP, configure Evil Twin with a generic router-update captive portal.
3. Launch Evil Twin.
4. On the test device, attempt to use the network. Watch it roam to the rogue. The captive portal will appear (system-triggered on most modern OSes).
5. Submit a fake credential into the portal.
6. Stop the attack. Eject SD. Locate the credential file.

**Success criteria.** The credential file exists on SD, contains the value you submitted, and is timestamped.

**Debrief.** What signals did the device's OS provide that something was off? What would a non-technical user have noticed? How would you, in a client report, communicate this risk in a way that motivates remediation?

### Exercise 6; Detection from the blue side

**Objective.** Detect the previous exercise from a detection-only posture.

**Steps.**
1. Set up a second Cardputer in `EAPOL/Deauth Detection` mode, locked to your lab AP's channel.
2. Replay Exercise 3 (deauth) and Exercise 5 (evil twin).
3. Observe the detection device.

**Success criteria.** The detection Cardputer logs the deauth frames and the channel/SSID disturbance.

**Debrief.** What is the smallest practical sensor footprint that would have detected this in a real corporate environment? What does it cost relative to the equipment that produced the attack?

### Exercise 7; BadUSB on a host you own

**Objective.** Execute a benign Ducky payload on a host you own as a demonstration of HID-injection risk.

**Steps.**
1. Create a Ducky Script file (e.g. `hello.txt`) in the BadUSB folder on the SD card:
   ```
   DELAY 2000
   GUI r
   DELAY 500
   STRING notepad
   ENTER
   DELAY 1000
   STRING Hello from the Cardputer.
   ```
2. Plug the Cardputer into your test workstation.
3. Cardputer: `BadUSB → Select Payload → hello.txt → Run`.
4. Watch the host execute the payload.

**Success criteria.** Notepad opens and types the message. The host's USB device manager shows the Cardputer enumerated as a keyboard.

**Debrief.** Enable Windows' "USB Restrict" policy or macOS USB Restricted Mode. Repeat. What changes? What is the residual risk against an unlocked, unattended workstation?

### Exercise 8; Full kill chain on your lab

**Objective.** Chain reconnaissance, evil twin, credential capture, and post-credential network access into a coherent narrative.

**Steps.**
1. Scan → identify lab SSID.
2. Evil Twin → capture lab PSK from your test device.
3. Configure the Cardputer (or another device) to associate to the legitimate AP using the captured PSK.
4. Run `Scan Network and Port` to enumerate hosts and services.
5. Document the entire chain with timestamps.

**Success criteria.** A narrative timeline that walks from "I was outside your office with nothing" to "I am authenticated on your internal network." That timeline is, more or less, the structure of your engagement deliverable.

**Debrief.** Which controls; at any layer; would have broken the chain? Which of those controls are common in environments you have personally assessed? Which are not?

---

## 10. Blue team; defenses that actually work

For each major attack class, the table below names the control that defeats it. This is the table that belongs in your book's defensive chapter and in any client deliverable.

| Attack class | Effective control(s) |
|---|---|
| Probe sniffing / KARMA | Disable auto-join for open networks. Educate users to forget unused networks. Use OS-level MAC randomization (default on iOS/Android, opt-in on Windows). |
| Deauth flood | 802.11w / PMF required (mandatory on WPA3, available on WPA2). Migrate to WPA3-Enterprise. |
| Evil twin / captive portal phishing | WPA2-Enterprise with EAP-TLS using internal CA. Never use PSK on networks of consequence. User training: never enter Wi-Fi credentials into a webpage. |
| Handshake capture + offline crack | Long, random PSK (≥20 chars) on PSK networks. Migrate to Enterprise. WPA3-SAE resists offline brute force. |
| Beacon spam | Largely a nuisance, not a compromise vector. WIDS will flag it. |
| BadUSB | USB device control (Windows USB Restrict, macOS USB Restricted Mode, Linux usbguard). Physical security on unattended workstations. Endpoint detection rules on sudden HID enumeration + rapid keystroke entry. |
| DHCP starvation / rogue DHCP | Switch-port DHCP snooping. ARP inspection. Static reservations for critical hosts. |
| Responder / NTLMv2 capture | Disable LLMNR, NetBIOS-NS, and mDNS where not required. Enforce SMB signing. |
| Reverse TCP implant | Egress filtering. DNS monitoring for anomalous outbound. Asset inventory and physical sweeps. |

The recurring theme: every control here is either free or already deployed in any mature environment. The attacks succeed because the controls are not turned on, not because the controls do not exist.

---

## 11. Troubleshooting

**Device boots to splash and freezes.** SD card is missing the `evil/` folder or is not FAT32. Reformat, re-populate.

**"Sketch too big" on compile.** Flash size and partition scheme are wrong. Set Flash Size to 8 MB and Partition Scheme to "8M with spiffs (3MB APP / 1.5MB SPIFFS)".

**Deauth module compiles but does nothing.** You skipped `utilities/deauth_prerequisites`. Run it and rebuild.

**Evil Twin captive portal returns "site can't be reached."** SD card missing `/evil/sites/<chosen_site>/`. Confirm the directory exists and contains `index.html` plus referenced assets.

**Wardriving has no GPS fix.** Move outdoors with sky view, allow 60–120 seconds. Verify the GPS Unit's LED behavior (slow blink = searching, faster blink or solid = locked, depending on revision).

**M5Burner can't find the device.** USB-C cable is charge-only. Try another cable. On Windows, install the CH343 / CP210x driver. On Linux, confirm your user is in the `dialout` group: `sudo usermod -aG dialout $USER`.

**Bootloops on first launch after compile.** PSRAM is enabled. Disable it in the Tools menu and reflash.

**Karma attack produces no associations.** Modern phones aggressively avoid this. Confirm with a test device whose probe list you control; older Android with broadcast probing enabled, or any IoT device with a hard-coded preferred network.

**Reverse TCP tunnel doesn't connect.** Listener address is unreachable (NAT, firewall, ISP block on the chosen port). Test connectivity with `nc` from a regular host first.

---

## 12. Appendix A; Adjacent tools and where the Cardputer fits

| Tool | Strength | Weakness vs. Cardputer |
|---|---|---|
| Flipper Zero | Sub-GHz RF, NFC, IR, BLE, polished UX | No Wi-Fi without WiFi Devboard add-on; even with it, fewer Wi-Fi attacks than Evil-M5 |
| WiFi Pineapple | Mature multi-radio Wi-Fi platform | $200+, conspicuous, not pocket-portable |
| Pwnagotchi | Autonomous handshake capture, ML-driven channel selection | Single-purpose; no interactive attacks; needs an external display |
| Marauder (ESP32) | Mature Wi-Fi/BLE feature set on cheap ESP32 boards | No native keyboard; Cardputer is effectively Marauder + keyboard + screen in one device |
| WiFi Coconut | All-channel concurrent capture | Single-purpose hardware, not portable for attacks |
| Kali laptop + Alfa AWUS036ACH | Maximum capability | Maximum visibility; not a covert tool |

The Cardputer is not the best at any single thing on this list. It is, currently, the most capable tool in the smallest, least conspicuous, lowest-cost form factor. That makes it the right choice for demos, training, and authorized red-team work where size and discretion matter; and the wrong choice for sustained Wi-Fi capture campaigns where you want a Coconut, or for sub-GHz work where you want a Flipper or HackRF.

## Appendix B; Useful key bindings (Cardputer build)

| Context | Keys |
|---|---|
| Menu navigation | `Fn` + `;`/`.`/`,`/`/` for up/down/left/right; `Enter` confirms; `Backspace` cancels |
| Escape (back to menu) | `Fn` + `` ` `` |
| Any running attack | `Backspace` for clean exit; `Ctrl` + `Backspace` for force-quit where supported |
| Text entry | Standard QWERTY; symbols via `Shift` and `Fn` layers |
| Caps lock toggle | `Fn` + `Shift` |
| Brightness / volume | Settings menu (no hardware shortcut) |

## Appendix C; Pre-flight compliance checklist

Before powering up the radio on any engagement, confirm:

- [ ] Written ROE signed and on file, covering specifically: Wi-Fi attacks, deauthentication, captive portal credential capture, BadUSB, and any other module you plan to use.
- [ ] Scope explicitly names target SSIDs, target IP ranges, and target hours of operation.
- [ ] Point-of-contact name and number for the client, on your person.
- [ ] Out-of-band communication channel to the client (cell phone) tested.
- [ ] Test environment isolated from non-scope networks (faraday space, RF-isolated room, or geographically remote location with no neighbors).
- [ ] Captured credentials and pcap files will be stored encrypted and destroyed per ROE timeline.
- [ ] Any persistent implants (Reverse TCP Tunnel) inventoried with location and removal date.
- [ ] Insurance and E&O coverage current.

If any line is unchecked, the radio stays off.

## Appendix D; Further reading and project resources

- Project repository: `https://github.com/7h30th3r0n3/Evil-M5Project`
- Project wiki (per-module documentation): `https://github.com/7h30th3r0n3/Evil-M5Project/wiki`
- M5Stack Cardputer product page: `https://shop.m5stack.com/products/m5stack-cardputer-kit-w-m5stampS3`
- M5Burner download: `https://docs.m5stack.com/en/download`
- Wigle (wardriving database): `https://wigle.net`
- Wall of Flipper concept: `https://github.com/K3YOMI/Wall-of-Flippers`
- Reference reading on 802.11w / PMF: IEEE 802.11-2016 §11.11
- Hashcat WPA cracking reference: `https://hashcat.net/wiki/doku.php?id=cracking_wpawpa2`

---

## Related Files
- [flipper_zero_guide.md](flipper_zero_guide.md) - Flipper Zero: complementary multi-radio tool (Sub-GHz, NFC, RFID, IR, iButton, BLE, BadUSB)
- [bjorn_pi.md](bjorn_pi.md) - Bjorn Pi: autonomous network-service attacker (pairs with Evil-M5 for RF + network-layer coverage)
- [bruce_firmware.md](bruce_firmware.md) - Bruce firmware: alternative to Evil-M5 on Cardputer with Sub-GHz, NFC, IR, and FM support
- [WifiMarauder_CheatSheet.md](WifiMarauder_CheatSheet.md) - Marauder command reference (Marauder is a sibling firmware for the same ESP32 hardware)
- [hcxtoolshashcat.md](hcxtoolshashcat.md) - Converting captured .pcap files to Hashcat mode 22000 format for WPA2 cracking
- [Aircrack-ng_Commands.md](Aircrack-ng_Commands.md) - Aircrack-ng for processing handshakes captured by Evil-M5

---

*This chapter is provided for educational and authorized red-team use only. The author of this chapter, the author of Evil-M5Project, and the manufacturer of the M5Cardputer accept no responsibility for misuse. Wireless attacks against networks, devices, or people without explicit written authorization are crimes in every U.S. state and most jurisdictions worldwide. Don't do them.*
