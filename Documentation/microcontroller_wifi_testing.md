# 📡 Microcontroller-Assisted Wireless Assessment Workflow

## Firmware Selection For The Lab

Choose the firmware by the required observation and its evidence output before
introducing controlled activity. Use owned APs/beacons and confirm any scan or
management interface that transmits; none of these names guarantees passive operation.

| Resource | Role & Compatibility Boundary |
|---|---|
| [GhostESP Revival](./ghostesp-revival.md) | Wi-Fi/BLE observation and target-dependent capture; preserve originals before conversion. |
| [C5 Wardriver](../Wardriving/esp32-c5-wardriver.md) | GPS/SD survey sessions; distinguish scanning Nodes from the Core logger. |
| [Piglet](../Wardriving/piglet.md) | Local survey and mesh workflows; review boot, home-return and live upload settings. |
| [NEMO](./nemo-firmware.md) | Compact M5Stack lab; verify board-specific SD and USB functions. |
| [BLE Capture / Sniffle](./ble-capture-sniffle.md) | Independent owned-beacon BLE packet evidence; ESP device discovery is not equivalent. |
| [LAB5 C5 Monster / JanOS](#lab5-c5-monster--projectzero-janos-field-assessment) | Independent ESP32-C5 radio, Cardputer/Tab5/Flipper clients, SD and WebUI validation, eight labs. |
| [Evil-M5](./evil_m5.md#evil-m5-firmware-qualification--authorized-deployment-labs) | Separate M5Stack firmware with board-specific SD and eight qualification labs; not JanOS. |

## 🎯 Purpose
Provide a practical field and lab reference for using Pwnagotchi, ESP32 Marauder-compatible hardware, Flipper Zero, CC1101 radios, MikroTik RouterOS, and a Linux workstation together during authorized wireless-security assessments.

## ⚙️ Function
Organize each device by its role in the assessment lifecycle: automated Wi-Fi discovery, active Wi-Fi testing, Sub-GHz exploration, network-side observation, PCAP export, packet analysis, evidence preservation, and reporting.

## 🏆 Goal
Create a repeatable wireless-testing workflow in which every action is scoped, every capture has a known observation point, and every conclusion is supported by evidence from the correct network or radio layer.

## 📋 When to Use
- Building an isolated wireless-security lab
- Comparing portable microcontroller tools with full Linux-based workflows
- Testing Wi-Fi management-frame protections and client behavior
- Collecting authorized WPA/WPA2 authentication captures
- Examining owned Sub-GHz sensors, remotes, and IoT devices
- Correlating portable-tool activity with MikroTik, Wireshark, and client logs
- Exporting and preserving Pwnagotchi PCAP files for analysis

Portable devices can handle specialized collection and testing tasks in a compact, battery-powered form factor. The Linux workstation remains the primary system for long-term storage, packet analysis, reporting, and controlled password-strength auditing.

> **Important:** Use these tools only on networks, radios, and devices that you own or are explicitly authorized to test. Isolate the lab, define the scope, use the minimum transmit power necessary, and stop immediately if testing affects anything outside the authorized environment.

---

# Wireless Assessment Quick Reference:

| Stage | Recommended Tool | Primary Role | Typical Output |
| :--- | :--- | :--- | :--- |
| Automated Wi-Fi discovery and collection | [Pwnagotchi](https://pwnagotchi.org/getting-started/index.html) | Channel hopping, WPA/WPA2 handshake collection, and PMKID collection | PCAP files and capture metadata |
| Active Wi-Fi testing | [ESP32 Marauder](https://github.com/justcallmekoko/ESP32Marauder)-compatible device | Scanning, packet monitoring, authorized management-frame testing, and captive-portal simulations | Scan results, PCAP files, logs, and observations |
| Sub-GHz exploration | [Flipper Zero](https://flipper.net/) with its internal or an [external CC1101 radio](https://www.amazon.com/dp/B0BY1WVHG2) | Frequency discovery, signal capture, protocol identification, and authorized static-signal testing | Saved Sub-GHz captures and decoded protocol data |
| Network-side observation | [MikroTik RouterOS Device](https://a.co/d/0gQ8joO6) | Router/interface capture, logs, client state, and network-response monitoring | PCAP files, RouterOS logs, and interface statistics |
| Detailed analysis and reporting | [Linux](https://www.linux.org/) workstation | [Wireshark](https://www.wireshark.org/) analysis, timeline correlation, capture preservation, and reporting | Findings, screenshots, notes, and final report |

---

# Microcontroller Wireless Assessment Reference Guide:

Use the portable tools to create controlled activity, MikroTik and an independent monitor-mode sensor to observe the results, and the Linux workstation to preserve and analyze the evidence. Run only one controlled test at a time so each behavior can be tied to a specific action and timestamp.

## 1. Automated Wi-Fi Discovery and Collection: Pwnagotchi

The Pwnagotchi is an automated Wi-Fi auditing platform commonly built around a Raspberry Pi Zero W and powered by Bettercap. It uses an A2C reinforcement-learning model to adjust its channel-hopping and collection behavior based on the surrounding wireless environment.

### 1.1 Workflow Role

- Discover nearby 2.4 GHz access points and clients.
- Collect WPA/WPA2 authentication material for an authorized lab.
- Save captured handshakes and PMKIDs as PCAP files for later analysis.
- Provide a repeatable, portable collection platform that does not require constant terminal interaction.

### 1.2 How It Works

Pwnagotchi listens for authentication activity and attempts to collect EAPOL packets exchanged during WPA/WPA2 four-way handshakes. Depending on its configuration and operating mode, it may also transmit deauthentication or association frames to encourage a client or access point to perform another authentication exchange.

For this reason, **Pwnagotchi should not automatically be described as passive**. It can perform passive collection, but its normal automated behavior may include active frame injection unless those features are disabled or restricted.

### 1.3 Lab Application

1. Configure an isolated test access point and one or more authorized clients.
2. Add all out-of-scope networks and devices to the Pwnagotchi whitelist or exclusion configuration.
3. Record the lab channel, SSID, BSSID, client MAC addresses, and test start time.
4. Run Pwnagotchi during a controlled client connection or reconnection.
5. Export the resulting PCAP files to the Linux workstation.
6. Preserve the original captures and analyze copies with Wireshark or another approved tool.

### 1.4 Practical Limitations

- The Raspberry Pi Zero W radio is 2.4 GHz only. It cannot observe 5 GHz or 6 GHz traffic.
- Capture quality depends on signal strength, channel dwell time, client activity, and whether every handshake message was observed.
- A saved file does not guarantee that the capture is complete or usable.
- WPA3-SAE does not use the same WPA/WPA2 four-way-handshake auditing workflow.
- Hardware support, plugins, and paths can vary between Pwnagotchi images and community-maintained releases.

---

## 2. Active Wi-Fi Testing: ESP32 Marauder and Related Platforms

ESP32 Marauder is a portable Wi-Fi and Bluetooth assessment firmware with capabilities that vary by ESP32 model, board design, firmware release, and build configuration. It can run on supported standalone ESP32 hardware and on certain ESP32-based accessories designed to work with the Flipper Zero.

### 2.1 Workflow Role

- Access-point and station discovery.
- Packet monitoring and supported raw capture.
- PMKID or handshake collection on supported builds.
- Authorized deauthentication-resilience testing.
- Beacon-spam and access-point-list stress testing.
- Captive-portal or Evil Portal simulations for approved awareness testing.

### 2.2 Platform Notes

- A Flipper Zero does **not** gain Wi-Fi capability from its built-in Sub-GHz radio. Marauder requires a compatible external ESP32 Wi-Fi board or module.
- Marauder and Bruce are separate firmware projects. They overlap in some capabilities, but one should not be described as merely running "through" the other.
- M5Stack Cardputer support and individual features depend on the exact firmware build. Verify the current hardware-support matrix before flashing or testing.
- Most classic ESP32 boards are limited to 2.4 GHz Wi-Fi. Newer ESP32 variants may support additional bands, but their capabilities should not be assumed.
- Some Marauder versions lack a display, packet monitor, SD card, or other features available on different hardware revisions.

### 2.3 Lab Application

Use one controlled action at a time so the resulting evidence remains attributable:

1. Start the appropriate capture and logging systems.
2. Record the selected SSID, BSSID, channel, client, firmware version, and test time.
3. Run a short, narrowly scoped test against the isolated lab target.
4. Stop the test before changing any other variable.
5. Save the device logs and captures.
6. Compare client behavior, access-point logs, MikroTik observations, and any independent over-the-air capture.

Useful defensive questions include:

- Does the client reconnect automatically after receiving a management-frame disruption?
- Does the access point log or alert on abnormal deauthentication activity?
- Is Protected Management Frames (802.11w/PMF) available, optional, or required?
- How does the access point behave when many fake SSIDs or beacon frames appear nearby?
- Can users distinguish the approved test network from a simulated captive portal?

> **Captive Portal Safety:** Use lab-only accounts and synthetic credentials. Never collect or retain real passwords. Document participant consent, data handling, and deletion procedures before an awareness exercise.

---

## 3. Sub-GHz Exploration: Flipper Zero and CC1101 Radios

The Flipper Zero includes a Sub-GHz transceiver based on the CC1101. It can also use supported external CC1101 modules, which may provide different antennas, front-end characteristics, or physical placement options.

Sub-GHz operation is separate from standard 2.4 GHz, 5 GHz, and 6 GHz Wi-Fi. Common regional allocations include portions of the 300-348 MHz, 387-464 MHz, and 779-928 MHz ranges, but the frequencies on which transmission is permitted depend on the device, firmware region, local law, power level, modulation, and application.

### 3.1 Workflow Role

- Locate active Sub-GHz signals in authorized frequency ranges.
- Capture known or raw signals from lab devices.
- Identify supported protocols and compare repeated transmissions.
- Evaluate whether an authorized device uses a static code, rolling code, encryption, or another replay-resistant design.
- Test approved static-signal behavior without involving the Wi-Fi network.

### 3.2 Lab Application

Suitable targets include your own wireless sensors, doorbells, remote-controlled outlets, weather sensors, and purpose-built RF test devices. Capture several transmissions from the same device and compare timing, modulation, identifiers, and changing fields.

Signal replay should be limited to owned, isolated, and explicitly authorized static-code devices. Modern rolling-code systems are designed to reject captured transmissions, and careless replay attempts can desynchronize or interfere with real equipment.

### 3.3 Practical Limitations

- An external CC1101 module is not automatically more capable or more accurate than the internal radio.
- Antenna tuning, frequency support, module quality, and firmware support matter more than the presence of an external module alone.
- Receiving a signal does not mean transmission is legal on that frequency.
- Flipper Zero is not a substitute for a calibrated spectrum analyzer or software-defined radio when precise RF measurements are required.

---

## 4. Using MikroTik as the Observation Point

The MikroTik router can serve as a central source of network-side evidence. RouterOS can provide packet captures, wireless registration information, interface counters, logs, client state, DHCP activity, firewall events, and traffic behavior before, during, and after each controlled test.

### 4.1 Important Capture Limitation

A normal RouterOS packet capture is **not automatically a complete over-the-air 802.11 capture**. A capture taken on a routed or bridged interface may show IP traffic and client effects without containing the raw beacon, probe, association, deauthentication, or other management frames transmitted over the air.

To examine raw 802.11 management frames, use one of the following where supported:

- A compatible MikroTik wireless interface and RouterOS wireless-sniffing mode.
- An independent Wi-Fi adapter that supports monitor mode and is locked to the target channel.
- A dedicated wireless sensor or supported capture platform positioned near the test devices.

The precise MikroTik capability depends on the router model, radio chipset, RouterOS version, wireless package, and selected interface. Confirm that the resulting PCAP contains radiotap or 802.11 headers before treating it as an over-the-air capture.

---

## 5. Repeatable End-to-End Lab Procedure

### 5.1 Define and Isolate the Scope

- Record the authorized SSIDs, BSSIDs, client MAC addresses, channels, frequencies, and physical test area.
- Exclude neighboring networks and unrelated devices.
- Use a dedicated lab SSID, synthetic accounts, and non-production clients.
- Disable automatic test behavior that cannot be constrained to the approved targets.

### 5.2 Capture a Baseline

Before transmitting test traffic:

- Start RouterOS logging and the appropriate MikroTik capture.
- Start an independent monitor-mode capture if raw Wi-Fi frames are required.
- Record normal client connectivity, latency, signal level, retransmissions, and roaming behavior.
- Synchronize system clocks or record their offsets.

### 5.3 Run One Controlled Test

Use one device and one test condition at a time. Keep the duration short and record:

- Tool, hardware revision, and firmware version.
- Target SSID, BSSID, client, channel, or Sub-GHz frequency.
- Start and stop times.
- Transmit power and antenna, when known.
- Expected behavior and actual behavior.

### 5.4 Stop and Preserve Evidence

- Stop all transmitting tools.
- Stop the packet captures.
- Export device logs, RouterOS logs, and PCAP files.
- Preserve an untouched original of each capture.
- Calculate file hashes if the captures will support a formal report.

### 5.5 Analyze and Correlate

Useful Wireshark display filters for a raw 802.11 capture include:

| Purpose | Display Filter |
| --- | --- |
| EAPOL authentication traffic | `eapol` |
| All 802.11 management frames | `wlan.fc.type == 0` |
| Beacon frames | `wlan.fc.type_subtype == 0x0008` |
| Deauthentication frames | `wlan.fc.type_subtype == 0x000c` |
| A specific BSSID | `wlan.bssid == aa:bb:cc:dd:ee:ff` |
| A specific station | `wlan.addr == aa:bb:cc:dd:ee:ff` |

Replace the example MAC address with an authorized lab address. These filters require a capture that contains raw 802.11 headers; they will not produce results in an ordinary Ethernet/IP-only PCAP.

Correlate the timestamps across:

- The portable testing device.
- The over-the-air capture sensor.
- MikroTik RouterOS logs and captures.
- The access point's association or security logs.
- The test client's operating-system logs.

---

## 6. Exporting Pwnagotchi PCAP Files

Pwnagotchi commonly stores captures in `/root/handshakes/`. The exact path, account name, IP address, and permissions can differ between images, so verify them on the device before relying on the following example.

### 6.1 Connect over USB

1. Connect the Raspberry Pi's **USB data port** to the workstation with a data-capable cable.
2. Configure the new host network interface as `10.0.0.1/24` if the image uses the traditional Pwnagotchi USB-network configuration.
3. Confirm that the device responds at `10.0.0.2` or its configured `.local` hostname.
4. Connect with the username and credentials configured for your image:

```bash
ssh pi@10.0.0.2
```

Change any default password during initial setup and prefer SSH key authentication.

### 6.2 Verify the Capture Directory

From the Pwnagotchi shell:

```bash
sudo find /root/handshakes -maxdepth 1 -type f -printf '%f\n'
```

If the directory is different, locate the configured handshake directory and substitute that path in the remaining commands.

### 6.3 Create a Transfer Archive

From the Linux, macOS, or Windows workstation, create a temporary archive in the Pwnagotchi user's home directory:

```bash
ssh pi@10.0.0.2 "sudo tar -C /root -czf /home/pi/pwnagotchi-handshakes.tar.gz handshakes && sudo chown pi:pi /home/pi/pwnagotchi-handshakes.tar.gz"
```

Copy the archive to the current directory on the workstation:

```bash
scp pi@10.0.0.2:/home/pi/pwnagotchi-handshakes.tar.gz .
```

Extract it into a dedicated evidence directory:

```bash
mkdir -p pwnagotchi-captures
tar -xzf pwnagotchi-handshakes.tar.gz -C pwnagotchi-captures
```

After confirming that the local archive opens correctly, remove only the temporary transfer copy from the Pwnagotchi user's home directory:

```bash
ssh pi@10.0.0.2 "rm -f /home/pi/pwnagotchi-handshakes.tar.gz"
```

This cleanup command does **not** delete the original files in `/root/handshakes/`.

> **Windows Note:** Current versions of OpenSSH provide `ssh` and `scp`, and current Windows releases commonly include `tar`. WinSCP or another SFTP client can also be used after the files are staged somewhere the configured user can read.

### 6.4 Preserve and Review the Captures

- Keep the exported archive as the untouched source copy.
- Extract a separate working copy for Wireshark analysis.
- Confirm that the BSSID and SSID belong to the authorized lab.
- Remove any accidental out-of-scope captures.
- Perform password-strength testing only against credentials and networks included in the written scope.

---

## 7. Suggested Test Record

Use a consistent record for every lab run:

```text
Test ID:
Date and time:
Authorization/scope reference:
Operator:
Tool and hardware:
Firmware version:
Target SSID/BSSID/device:
Channel or frequency:
Capture sensor and interface:
Test action:
Expected result:
Observed result:
Evidence filenames:
Relevant timestamps:
Mitigation or follow-up:
```

---

## OUI-SPY Unified Blue — Authorized Detection Labs

**Where this belongs:** OUI-SPY is a specialized **defensive/observation** ESP32 platform and detection family, not a variant of Marauder, Bruce, Biscuit, or Raspberry Pi RaspyJack. Its primary references are [OUI-SPY project](https://github.com/colonelpanichacks/oui-spy) and [Unified Blue firmware](https://github.com/colonelpanichacks/oui-spy-unified-blue). Device names, firmware modes and AP credentials change with builds; verify the installed revision. The current Unified Blue upstream describes six numbered modes, including Detector, Foxhunter, Flock-You WiFi, PCAP, Sky Spy and BLE Sniff.

> [!CAUTION]
> Many OUI-SPY **sensor functions are receive-oriented**, but the selector and some dashboards host a **transmitting Wi-Fi access point**. Do not claim the entire device is RF-passive. Do not use it to infer individuals' locations, assert that an OUI alone proves the presence of a particular surveillance system, or collect unrelated personal data. **Remote-ID-Spoofer** and **UniPwn** are **separate projects**, not detection modes automatically bundled in Unified Blue.

### Hardware, Flash & Secure First Boot

1. Identify the exact board (official OUI-SPY / XIAO ESP32-S3 or a separately documented target), flash/PSRAM, buzzer/NeoPixel wiring, power supply and connected GPS if any. An ESP32-C5 build listed for a related project does **not** establish that all Unified Blue S3 features work on C5.
2. Record the existing firmware and configuration. In an isolated operator environment, open the [official Unified Blue Web Flasher](https://colonelpanichacks.github.io/oui-spy-unified-blue/) in a compatible Web Serial desktop browser, or review and build from source if the browser install does not match the board.
3. Inspect flasher prompts and selected target; use a data-capable USB-C cable and stable power. Do not blindly flash generic ESP32-S3 binaries onto a different layout.
4. On first boot, connect only a dedicated operator device to the **mode-selector AP** and follow the upstream README to reach the local web dashboard. Upstream documents factory/default SSID/password pairs; **change configurable defaults** and isolate the AP from production networks.
5. Select a mode, allow the device to reboot, and confirm the active mode via its expected LED/buzzer, serial output or dashboard. After a mode change the old AP may disappear and a **different mode's AP** may appear. Some modes have **no AP**.
6. Record exact firmware commit/release, selected mode, management SSID state, scanner band/capture path and clock behavior. Disable audible indicators where required by the engagement.

### Mode & Measurement Boundary

| Unified Blue mode | Primary use | Important limitation |
|---|---|---|
| Detector | BLE advertisement filters by OUI, name, company identifier, service UUID (as supported) | A match is **candidate classification**, not manufacturer or threat proof |
| Foxhunter | RSSI trend of a known owned BLE beacon | Relative signal strength ≠ reliable meters/location |
| Flock-You WiFi | Observe selected Wi-Fi frame fingerprints and related telemetry | Signature heuristics can false-positive; may require USB-CDC rather than AP |
| PCAP | Short buffered Wi-Fi capture and app download where supported | Memory limited; channel hop and local dashboard modes differ |
| Sky Spy | Observe lawful broadcast drone Remote ID from test hardware | Absence does not prove absence of drones; receiver coverage matters |
| BLE Sniff | BLE advertisement sampling and supported PCAP export | Advertisements only; **not** BLE connected-data-channel decryption/capture |

For PCAP and BLE Sniff, check the build's current Save PCAP/CSV pathway instead of assuming an old USB binary streaming interface still exists. A WebUI-enabled scanner may transmit AP beacons even when sensor observation is passive.

### Lab O1 — Firmware/Selector & Management Exposure

1. Boot on a segregated bench, verify that the selector page opens from one test laptop and identify which Wi-Fi interface/AP is active.
2. Change passwords/settings that are configurable; verify the management AP is unreachable from client production networks.
3. Switch to Detector, then back to selector through the currently documented BOOT-button method. Avoid relying on an exact press duration across releases.
4. Confirm any previously saved AP connection on the phone/laptop does not cause it to auto-connect to the wrong mode after reboot.
5. Record accessible ports, displayed firmware version and exact mode. A test passes only if management access follows the approved network policy.

### Lab O2 — Owned BLE Beacon Signature Calibration

1. Configure an **owned** BLE beacon or development board to advertise a synthetic test name. Do not emulate a real person's tracked device.
2. Add one narrowly scoped signature in Detector using a field actually supported by the installed build (name/OUI/company ID/service UUID).
3. Observe the beacon's presence and first/last-seen/RSSI where exposed. Turn it off and measure stale-observation timeout.
4. Introduce a second owned beacon with a similar name but not the full signature as a **negative control**.
5. Save alert/match method, timestamps, known beacon identity and false-positive rate. Avoid labeling a generic OUI match as a verified surveillance device.

### Lab O3 — BLE RSSI Proximity Demonstration

1. Select your own tagged BLE beacon in Foxhunter and take a 10-second stationary baseline.
2. Move the beacon between two measured locations in the same room while keeping antenna orientation and obstructions documented.
3. Note whether RSSI trends upward/downward; repeat to demonstrate multipath effects.
4. Avoid following unknown personal devices or reporting distance in meters based solely on RSSI.
5. Restore the beacon and clear its training identity from saved configuration when done.

### Lab O4 — Wi-Fi Fingerprint Verification & PCAP Export

1. Use a dedicated test AP, known channel and short observation window. Confirm that PCAP mode is enabled for the installed target and note whether channel hop disables its management AP.
2. Capture **only** brief, approved 802.11 management-frame data and avoid collecting unrelated payloads. Keep the device physically near the lab AP and away from neighboring sites where practical.
3. Export the supported PCAP through the local dashboard or alternate documented path; verify an actual file was produced.
4. Inspect its metadata on an evidence workstation using a read-only tool, e.g.:

~~~bash
file /path/to/authorized-lab.pcap
sha256sum /path/to/authorized-lab.pcap
~~~

5. Compare the known AP's BSSID/channel to capture output. Preserve the original, redact other identifiers and record capture filter/limits.
6. If using a Flock-You signature feature, treat results as candidate detections requiring independent physical/controller confirmation, not conclusive identification.

### Lab O5 — Drone Remote ID Validation With Consented Test Source

1. Confirm regional aviation/privacy rules and use a legitimate owned Remote ID emitter or an approved drone operating lawfully. **Do not spoof someone else's aircraft identity or transmit unauthorized Remote ID signals.**
2. Run Sky Spy in the mode documented for the board. Record sensor position, observation window, distance/obstructions and any visible broadcast ID/type.
3. Independently confirm the test drone's Remote ID output from the operator/controller. Note missing fields rather than fabricating position, altitude or identity.
4. Stop and redact operator identifiers/location if reporting externally. The presence of a message does not alone establish airworthiness, safety or malicious behavior.

### Lab O6 — Defensive Sensor Comparison & SIEM Intake

1. Use a synthetically named BLE beacon and a separate owned Wi-Fi AP, each with documented baseline and on/off periods.
2. Run one mode at a time (Detector, BLE Sniff or Wi-Fi observation). Record actual available output, mode, timestamp and identifiers.
3. Compare with an independent BLE monitor or [Kismet sensor](../Wardriving/kismet.md). If sending results to Wazuh, validate the actual supported transport and parser before claiming integration; direct built-in Wazuh export is **not assumed**.
4. Evaluate false positives by repeating with a nonmatching beacon; store source alert/evidence with stable test IDs.
5. Remove training signatures, restore access-point credentials and retain only in-scope redacted data.

### Triage & Reporting

| Symptom | Check |
|---|---|
| Dashboard disappears after changing modes | Different per-mode SSID or no-AP mode; use USB serial where supported |
| Phone says "no Internet" | Local-only AP is expected; keep phone on the right operator AP |
| No BLE result | Board BLE capability, scan interval/window, advertisement type, RF coexistence |
| No Wi-Fi capture | Selected channel/mode, actual PCAP feature, buffer/export limits |
| Detection not confirmed | Randomized MACs, generic OUIs, wrong vendor fingerprint, stale source |
| Remote ID absent | Receiver range, broadcast protocol/mode, drone emitter and local conditions |

**Report:** board revision, firmware build, active mode, selector/AP state, scoped beacon/AP ID, source type, timestamp, signal limitations, matched signature and method, independent corroboration, file hash if any, false-positive notes, retention and remediation. Keep identifiers of bystanders out of shared reports.

## LAB5 C5 Monster & projectZero JanOS Field Assessment

_Source-checked November 11, 2026 against the [LAB5 / C5Lab project list](https://github.com/C5Lab), [projectZero upstream](https://github.com/C5Lab/projectZero), [projectZero wiki](https://github.com/C5Lab/projectZero/wiki), [M5MonsterC5 Cardputer ADV](https://github.com/C5Lab/M5MonsterC5-CardputerADV) and [M5MonsterC5 Tab5](https://github.com/C5Lab/M5MonsterC5-Tab5). This is a repeatable **lab procedure**, not a claim that the hardware was physically tested._

**Naming:** the user's “LAB5 C5 Monster” refers to LAB5 / C5Lab's **MonsterC5 / M5MonsterC5** ecosystem. The firmware project is **projectZero** (JanOS). LAB5 publishes controller integrations for **M5Cardputer / Cardputer ADV**, **M5Stack Tab5**, **Flipper Zero** and an optional **Mate** web client. This is **not** [Evil-M5Project](./evil_m5.md#evil-m5-firmware-qualification--authorized-deployment-labs), [ESP32 Marauder](./WiFiMarauder_Guide.md), [Bruce](./bruce_firmware.md), or [Biscuit](../Wardriving/biscuit.md). Their binaries and accessory app protocols cannot be swapped without explicit upstream support.

> [!CAUTION]
> The project documents transmit-capable attack features including Wi-Fi impersonation, deauthentication, aggressive management-frame traffic, credential interception and **WPA3-SAE overflow/DoS**. **Do not run them as part of a normal wireless survey or on public/client infrastructure without a separate, impact-assessed ROE.** The labs below use owned APs, receive-oriented observations, synthetic identities, no credential capture, no disruption and offline analysis. A scan menu is not automatically transmit-free; verify the mode used.

### Architecture & Exact Firmware Targets

| Component | Where the code runs | Primary role & compatibility boundary |
|---|---|---|
| **MonsterC5 board** | ESP32-C5-WROOM-1U; **JanOS / projectZero** | Actual 2.4/5 GHz Wi-Fi receiver/transmitter; serial CLI and storage support depend on board revision |
| **M5MonsterC5-CardputerADV** | Cardputer/ADV **controller application** on its own M5StampS3/ESP32-S3 | Display/keyboard UI communicating with **separate** C5 board. Older Cardputer may have separately offered app |
| **M5MonsterC5-Tab5** | Tab5 controller application on Tab5 | Larger display and, for supported releases, offline packet-analysis UI. Not a Cardputer or C5 firmware image |
| **Flipper Zero integration** | Flipper FAP (application) + JanOS on C5 board | Flipper has **no internal Wi-Fi radio**. FAP version/API and JanOS CLI must match |
| **projectZero CLI/Web Serial** | Host browser/serial terminal talking to C5 | Useful for headless qualification and recovery without a working companion UI |
| **LAB5 Mate/WebClient (optional)** | Separate supported ESP32 controller + browser | Management Wi-Fi AP + UART forwarding to Monster; **transmits management beacons** and has a security boundary |

**Dual-band nuance:** ESP32-C5 hardware supports 2.4 and 5 GHz Wi-Fi on selected configurations; a **single radio** cannot observe both bands or all channels simultaneously. The **Cardputer itself remains 2.4 GHz-only**; 5 GHz observations come from the attached MonsterC5. A successful Bluetooth/Wi-Fi scan is not a full channel, throughput or security assessment. Wi-Fi 6 physical capabilities and firmware support vary with ESP-IDF and C5 revision.

### Firmware/Companion Installation & Recovery — Three Separate Paths

**A. JanOS on the ESP32-C5 Monster**

1. Confirm exact LAB5 board PCB, flash size, antenna connection, SD/GNSS options, boot/USB serial port and previous firmware. Preserve existing `/lab/` files and obtain a known-good recovery route **before erase**.
2. Use LAB5's [JanOS flasher](https://c5lab.github.io/projectZero/janos_flash.html), linked from the [projectZero tools](https://c5lab.github.io/projectZero/). Prefer **Main** for a client test fixture unless a development build is explicitly being validated. Note selected manifest, binary name, release/commit and hash when supplied.
3. On an isolated desktop Chromium Web Serial browser, select the actual C5 port. Follow LAB5 instructions for BOOT/RESET and any erase prompt; do **not** use a generic Cardputer or Tab5 binary on the C5.
4. Boot and validate serial output with [Web CLI](https://c5lab.github.io/projectZero/) or a trusted serial terminal **without executing active command presets**. Confirm board identification, firmware and help/info menus; the command syntax changes across JanOS releases. Record the actual version/available commands rather than using copied attack strings.
5. Verify the board can identify an **owned AP** and return to an idle state. Don't flash again until checking serial/power and the controller handshake.

**B. Controller application for M5Cardputer / Cardputer ADV or Tab5**

1. Select the matching [Cardputer ADV app flasher](https://c5lab.github.io/M5MonsterC5-CardputerADV/janos_flash.html) **or** [Tab5 app flasher](https://c5lab.github.io/M5MonsterC5-Tab5/janos_flash.html). Those controller apps and JanOS have distinct project revisions, layouts and display drivers.
2. Back up the controller and any SD logs. Flash the **app for the actual M5Stack target**, not JanOS; confirm installed revision and display/keyboard first.
3. With all devices powered off, mount/connect the MonsterC5 accessory using **LAB5's device-specific power and serial wiring instructions**. Do not invent a UART pinout from a generic ESP32-C5 board; connect compatible voltage levels and common ground.
4. Power on and verify the controller recognizes its separate JanOS device. A working Cardputer display with no C5 responses indicates a **companion transport or firmware version issue**, not necessarily failed JanOS RF hardware.
5. Record controller model and app revision separately from the C5 firmware revision; changes in `show_sniffer_clients` and other commands can break older-client parsing.

**C. Flipper Zero or optional Mate controller**

1. For Flipper, install the **LAB5-specific `Lab_C5.fap`** through the [projectZero tools FAP uploader](https://c5lab.github.io/projectZero/) when compatible with the installed Flipper firmware. Upstream describes this uploader for **Unleashed/Momentum**; do not assume universal official-firmware support.
2. Power down before inserting the correct Flipper adapter. Confirm UART TX/RX mapping and the configured Flipper serial/Log Device state; the FAP is **not** the C5 firmware and cannot add a built-in Wi-Fi radio.
3. For LAB5 Mate/WebClient, review the [separate Mate source](https://github.com/C5Lab/Mate), its **supported boards and UART config**. The client can expose a Wi-Fi AP and browser API, which creates an additional attack surface. Do not put the default management AP on a customer network or enable remote access by default.
4. Confirm controller communication using a version/status check and a short owned-AP scan. Stop/rollback if the wrong application controls an unintended radio or exposes an unsecured management surface.

### LAB5 1 — Firmware, UART & Power Qualification

**Goal:** identify the exact C5 firmware and UI/transport without starting a radio attack.

1. Photograph model/revision (redact serials), record installed JanOS build and controller app version, plus test power supply, antenna, any SD and GNSS wiring.
2. Connect the MonsterC5 by its documented native USB/serial path. Open the LAB5 Web CLI with **no automatic quick-action/attack buttons pressed**.
3. Capture the text from the version/help/status menu if exposed; save a transcript and note **actual** port/baud from upstream. The project documents a UART CLI; **115200 baud** appears in supporting LAB5 Mate examples but may not represent every recovery/board mode.
4. Disconnect/reconnect the controller (Cardputer, Tab5 or Flipper) and record whether the device is detected. Repeat after an approved reboot.
5. **Pass:** correct version/board, readable status, supported control link, no spontaneous active RF modes. **Fail:** unknown firmware, mismatched UART, brownouts or unsolicited transmissions.

### LAB5 2 — 2.4 GHz & 5 GHz Known-AP Inventory

1. Prepare two client-owned test SSIDs with distinct names on supported **2.4 and 5 GHz** channels. Record BSSIDs/channel/security from the AP controller.
2. With the C5 in a verified bounded observation mode, scan one band/channel range at a time as the firmware supports; log **actual CLI/UI mode names**, duration and whether active probes are sent.
3. Compare results with controller data. Repeat at least three runs to account for channel dwell and changing signal propagation.
4. Confirm which device performed the scanning: Monster C5, **not** Cardputer or Flipper. Disable the 5 GHz AP and observe the expected disappearance as a negative control.
5. **Pass:** source-attributed results and documented coverage. **Do not infer** a successful WPA3 security audit from detection of the SSID.

### LAB5 3 — SD Layout, GPS Provenance & Public Upload Safety

The [projectZero wiki](https://github.com/C5Lab/projectZero/wiki) documents, for applicable configurations, `/lab/wardrives/wXXXX.log` WiGLE-style logs and optional `/lab/home.txt`, `/lab/wigle.txt`, `/lab/wdgwars.txt`, and `/lab/white.txt` files. These **are not** Evil-M5's `/evil/` assets, Biscuit app history, or Marauder `wardrive_` files.

1. Verify that the **physical board/host** has a supported SD connection and a genuine GNSS fix; neither a serial C5 radio nor a controller keyboard alone establishes GPS or local storage.
2. For an owned test AP, run a short approved wardrive. Inspect whether an actual `/lab/wardrives/` file exists and contains plausible coordinate/time fields.
3. **Disable/omit automatic public upload and any home-SSID/password trigger files** for the first lab. Do not put real WiGLE API keys or production Wi-Fi passwords onto a shared SD image or public repo.
4. Record where location came from (board GNSS, controller-provided fix, or none), the exact logfile name, and a SHA-256 hash of an unchanged original. Missing GPS does not justify fabricating coordinates.
5. Redact neighboring APs and coordinates before delivering results; public WiGLE/other provider upload requires a separate explicit disclosure approval.

### LAB5 4 — Controlled Sniffer Data & Offline PCAP Validation

1. Use a known test AP and a synthetic lab client, physically separated from customer equipment. Configure a short receive-focused observation window and known channel.
2. Confirm **whether the chosen JanOS build actually saves PCAP** and the exact file destination. Do not assume every UI has continuous PCAP storage or that Tab5 and Flipper save to the same device.
3. Stop capture and preserve the unchanged source file. On a trusted Linux evidence workstation, verify actual file type and hash:

~~~bash
file /path/to/approved-test-capture.pcap
sha256sum /path/to/approved-test-capture.pcap
tshark -r /path/to/approved-test-capture.pcap -c 10
~~~

4. If frames are present, filter for **beacon frames** using `tshark -r /path/to/approved-test-capture.pcap -Y 'wlan.fc.type_subtype == 8'`; a file containing no 802.11 dissector fields may use a different link type or capture format.
5. Compare observed BSSID/channel/times with the AP controller. Do not collect credentials, force reconnection, or crack captures for routine coverage acceptance.
6. For Tab5, [upstream documents an ESPShark offline-analysis workflow](https://github.com/C5Lab/M5MonsterC5-Tab5); this **does not mean** the MonsterC5 radio offers Wireshark parity or access to all encrypted payloads.

### LAB5 5 — Controller UI, Firmware-Skew & Recovery Regression

1. On a disposable setup, record the known-good JanOS revision and corresponding Cardputer/Tab5/Flipper controller app.
2. Validate a harmless status query, one owned-AP scan and stop/return-to-idle with that known-good pair. Save screenshots and serial transcript.
3. Repeat after updating **only one component** during an approved maintenance window, with its matching rollback image preserved.
4. If commands fail or parses differ, compare available JanOS commands with controller expectations. Upstream specifically describes new `show_sniffer_clients` / `start_deauth_station` support as release-dependent; **do not execute the latter active command** to test version alignment.
5. Restore to the matching pair and confirm repeatability. Record exact app + JanOS revisions in the report, not simply “LAB5 current.”

### LAB5 6 — Mate WebUI & Management Plane Isolation

1. If Mate is in scope, deploy a supported **separate controller** on an isolated management segment; configure the documented UART and power appropriately.
2. [Mate's upstream](https://github.com/C5Lab/Mate) describes a web client that broadcasts a management AP, communicates with MonsterC5 over UART and exposes HTTP/REST/WebSocket controls. **A receive-oriented JanOS scan does not make this management AP passive.**
3. Replace defaults when configurable, disable unneeded services, and firewall access. Record port bindings and credentials securely.
4. Verify the approved operator client can access **read-only status**, but a deliberately excluded guest VLAN cannot. Never make management APIs Internet-accessible.
5. Disconnect the WebClient and confirm the MonsterC5 no longer exposes that management path. Restore configuration and rotate any temporary test credentials.

### LAB5 7 — WIDS Correlation & False-Positive Controls

1. Turn on a **unique synthetic SSID** from a client-owned AP for a short authorized window; record BSSID, band, channel and actual start time.
2. Observe it with a C5 scan and, separately, a stationary [Kismet/Wazuh](../IncidentResponse/IDS%26IPS/kismet-wazuh-wireless-lab.md) or [nzyme/Wazuh](../IncidentResponse/IDS%26IPS/nzyme-wazuh-integration.md) sensor.
3. Correlate real source events and alert IDs to AP/controller logs. LAB5 tools do **not** inherently provide a supported, always-on Wazuh integration.
4. Stop the test AP; record whether the independent WIDS inventory ages out normally. A legitimate AP with a similar naming pattern is the negative control.
5. Report signal/channel coverage, clock skew, detection/false-positive results and required improvements. No deauth, rogue AP or SAE overflow mode is required.

### LAB5 8 — Combined Cardputer, Tab5 & Flipper Deployment Decision

Choose a **single** operator UI for one assessment and document it, rather than assuming identical capabilities:

| Operator environment | Suitable lab objective | Key acceptance test |
|---|---|---|
| Cardputer/ADV controller | Keyboard-driven C5 AP inventory and quick field notes | JanOS UART connection, display rendering, scan results and SD location |
| Tab5 controller | Larger display, compatible logs and optional offline PCAP review | Correct Tab5 firmware, source capture import, read-only analysis |
| Flipper with LAB5 FAP | Portable C5 receiver under Flipper control | Matching `Lab_C5.fap`, independent C5 firmware, UART and 2.4/5 GHz test |
| USB serial host without companion | Baseline/recovery, help/status and small owned-AP scan | Correct serial target and exact available commands |
| Optional Mate client | Management dashboard **only on isolated lab AP** | Credential policy, API exposure audit, reversible disable |

**Boundary:** a LAB5 “WPA3 SAE overflow” or deauthentication feature is an **author-described disruptive test mode**, not a safe method of establishing WPA3 weakness in a client's network. Do not claim an available menu item proves an exploitable vulnerability, firmware support on another board, or an authorized test outcome.

### Incident Evidence, Troubleshooting & Cleanup

| Observation | Diagnose before further testing |
|---|---|
| Controller UI starts, radio absent | JanOS board power/UART mapping, mismatched app/firmware, wrong connector |
| 5 GHz AP absent | C5 build/radio/channel/antenna support, timing, controller AP config |
| Flipper FAP unavailable | Flipper firmware/API, documented FAP uploader compatibility, serial Log Device conflict |
| No wardrive/SD output | Board SD hardware, path `/lab/wardrives/`, GPS fix and logging mode |
| Capture cannot open in Wireshark | Link type, incomplete file, export path, old/new JanOS format |
| Unexpected public upload | Stop, remove `/lab/home.txt` or other configured triggers, revoke exposed API keys |
| Mate AP visible in production | Disconnect, isolate, disable access or reimage client controller |
| Lab results disagree with WIDS | Sensor coverage, AP channel dwell, clock, false-positive rules |

**Report record:** written consent, exact site/SSID/BSSID scope, C5 PCB/firmware and controller/FAP versions, SD/antenna/GNSS source, probe/transmit state, start/end UTC, capture path/hash, independent AP/WIDS confirmation, false-positive notes, data sharing approval, clean rollback and retest criteria.

**Primary resources:** [LAB5 organization](https://github.com/C5Lab) · [projectZero / JanOS](https://github.com/C5Lab/projectZero) · [projectZero wiki](https://github.com/C5Lab/projectZero/wiki) · [JanOS + FAP flashers](https://c5lab.github.io/projectZero/) · [Cardputer ADV companion](https://github.com/C5Lab/M5MonsterC5-CardputerADV) · [Tab5 companion](https://github.com/C5Lab/M5MonsterC5-Tab5) · [Mate WebClient](https://github.com/C5Lab/Mate) · [Evil-M5](./evil_m5.md).

## 8. Defensive Takeaways

This workflow is most useful when each portable device has a clearly defined role:

- **Pwnagotchi** automates authorized WPA/WPA2 discovery and capture collection.
- **ESP32 Marauder-compatible hardware** performs short, controlled Wi-Fi tests.
- **Flipper Zero and CC1101 radios** examine non-Wi-Fi Sub-GHz devices.
- **MikroTik RouterOS** records network-side effects, state changes, and supported wireless evidence.
- **An independent monitor-mode sensor** provides raw over-the-air Wi-Fi evidence when the MikroTik capture cannot.
- **The Linux workstation** preserves, correlates, analyzes, and documents the results.

The goal is not simply to generate wireless activity. The goal is to create a repeatable experiment in which every action has a timestamp, every capture has a known vantage point, and every conclusion is supported by evidence from the correct layer.

---

## Security and Ethical Considerations ⚠️

**IMPORTANT**: These tools are for **authorized security testing only**. Deauthentication, beacon flooding, captive-portal testing, and Sub-GHz transmission can disrupt nearby systems or violate laws and regulations. Always:

- Get written permission before testing
- Define the authorized SSIDs, BSSIDs, devices, channels, frequencies, and physical test area
- Use isolated lab networks, non-production clients, and synthetic credentials
- Exclude neighboring networks and unrelated devices
- Follow applicable radio regulations and firmware region restrictions
- Preserve evidence securely and remove accidental out-of-scope captures
- Follow responsible disclosure practices
- Stop testing immediately if anything outside the authorized scope is affected

**Legal Use Cases:**

- Wireless penetration testing with written client authorization
- Security research in an isolated lab environment
- Testing networks, radios, and devices you own
- Controlled employee-awareness exercises with informed approval
- Educational labs and CTF environments designed for wireless testing

---

## Related Resources

- [Pwnagotchi: Introduction](https://pwnagotchi.ai/intro/)
- [Pwnagotchi: Configuration and USB Connectivity](https://pwnagotchi.ai/configuration/)
- [ESP32 Marauder Repository](https://github.com/justcallmekoko/ESP32Marauder)
- [ESP32 Marauder Hardware and Feature Matrix](https://github.com/justcallmekoko/ESP32Marauder/wiki/marauder-versions)
- [ESP32 Marauder Evil Portal Documentation](https://github.com/justcallmekoko/ESP32Marauder/wiki/evilportal)
- [Flipper Zero Sub-GHz Documentation](https://docs.flipper.net/zero/sub-ghz)
- [MikroTik RouterOS Packet Sniffer](https://help.mikrotik.com/docs/spaces/ROS/pages/8323088/Packet+Sniffer)
- [MikroTik RouterOS Wireless Interface Documentation](https://help.mikrotik.com/docs/spaces/ROS/pages/8978446/Wireless+Interface)

---

## Related Files (in this repo)

- [WiFiMarauder_Guide.md](WiFiMarauder_Guide.md) / [WifiMarauder_CheatSheet.md](WifiMarauder_CheatSheet.md) - ESP32 Marauder reference and commands
- [pwnagotchi_cheatsheet.md](pwnagotchi_cheatsheet.md) - Pwnagotchi setup and command reference
- [evil_m5.md](evil_m5.md) / [bruce_firmware.md](bruce_firmware.md) - M5Stack / Cardputer firmware workflows
- [flipper_zero_guide.md](flipper_zero_guide.md) - Flipper Zero (Sub-GHz, Wi-Fi Dev Board)
- [wireshark.md](wireshark.md) - Wireshark filters for analyzing the captured traffic
- [hcxtoolshashcat.md](hcxtoolshashcat.md) - converting captures and auditing handshake strength
- [../Homelab/workflows/self-hosted_network_attacks.md](../Homelab/workflows/self-hosted_network_attacks.md) - full self-hosted wireless lab assessment playbook
- [../SDR/README.md](../SDR/README.md) - RF / Sub-GHz context for the CC1101 role
- [../LEGAL.md](../LEGAL.md) - legal notice and authorized-use terms

*Last Updated: 08-03-2026*
