# Comprehensive Wireless Lab Security Assessment: Master Playbook

This document combines a **Device Operational Guide**, **Red Team (Offensive) Plan**, and **Blue Team (Defensive) Assessment** for an authorized, self-hosted wireless lab.

---

# PART 0: MASTER DEVICE INVENTORY & OPERATIONAL GUIDE

This section details every piece of hardware in your arsenal, its specific role, and general usage instructions.

## 1. Monitoring & Reconnaissance Station
| Device | Role | Use Instructions / Config |
| :--- | :--- | :--- |
| **Raspberry Pi Zero 2 W** <br>*(Kali Linux + USB/Eth Hat)* | **The "Mothership"**<br>Central monitoring, packet capture, and logging. | **Boot:** SSH in via Ethernet or OOB WiFi.<br>**Cmd:** `sudo airmon-ng start wlan0` (internal) or `wlan1` (external).<br>**Run:** `kismet -c wlan1` or `airodump-ng wlan1`. |
| **2x Alfa AWUS036ACS** | **Long-Range Eyes**<br>High-gain packet capture linked to the Kali Pi or Laptop. | **Connect:** Plug into Pi Hat or Laptop.<br>**Driver:** `apt install realtek-rtl88xxau-dkms`.<br>**Mode:** Supports Monitor mode & Packet Injection (5GHz/2.4GHz). |
| **T-Dongle S3** <br>*(ZeroTrace Firmware)* | **Wardriving / Presence**<br>Passive tracking of devices and vendors. | **Boot:** Plug into power bank.<br>**Usage:** Observe screen for "Found Devices" counts. Review logs on SD card later.<br>**Note:** Use with VK172 GPS for geolocation data. |
| **USB VK172 GPS** | **Geolocation**<br>Adds GPS coordinates to packet captures. | **Connect:** Plug into Kali Pi or T-Dongle hub.<br>**Cmd:** `gpsd /dev/ttyACM0`. Verifies location for Kismet/ZeroTrace. |

## 2. WiFi Attacks & Handshake Capture
| Device | Role | Use Instructions / Config |
| :--- | :--- | :--- |
| **Hak5 WiFi Pineapple** | **Rogue AP / MITM**<br>The "Evil Twin" platform. | **Boot:** Power on.<br>**Access:** Web UI at `172.16.42.1:1471`.<br>**Action:** Module > PineAP > Enable. Use **Pineapple Pager** to vibrate on client connect. |
| **Pineapple Pager** | **Physical Alerting**<br>Haptic feedback for Pineapple events. | **Setup:** Connects wirelessly to Pineapple.<br>**Use:** Clip to belt. Vibrates when a victim connects to your Rogue AP. |
| **Pwnagotchi** <br>*(Pi Zero + E-ink)* | **AI Handshake Hunter**<br>Passive/Active learning capture. | **Boot:** Plug into battery. Watch screen.<br>**Status:** Face = Happy (Capturing).<br>**Retrieve:** Connect via USB (Data mode) to `/handshakes` folder. |
| **Bjorn** <br>*(Pi Zero + E-ink)* | **Aggressive Scanner**<br>Network vulnerability scanner/deauther. | **Boot:** Plug into battery.<br>**Action:** Automatically scans/attacks based on `config.yaml`. <br>**Display:** Shows current target and capture status. |
| **M5Stack Fire** <br>*(Purple Hash Monster)* | **PMKID Capture**<br>Captures RSN PMKIDs (WPA2). | **Boot:** Press Red button.<br>**Usage:** Device auto-scans 2.4G. Screen lists captured hashes.<br>**Log:** Hashes saved to SD card. |
| **M5Stack Cardputer** <br>*(Evil-M5)* | **Portable Swiss Army Knife**<br>Deauth, Beacon Spam, Probing. | **Boot:** Power switch.<br>**Menu:** Select `WiFi` > `Scan` > Select Target > `Deauth`.<br>**Keyboard:** Use onboard keys to select menu options. |

## 3. Bluetooth (BLE) & Sub-GHz RF
| Device | Role | Use Instructions / Config |
| :--- | :--- | :--- |
| **M5Stick Pro 2** <br>*(Nemo Firmware)* | **Portable BLE/WiFi Scanner**<br>Handheld recon. | **Boot:** Side button.<br>**Menu:** Select `BLE` to see nearby beacons/tags. Select `WiFi` for deauth list.<br>**Note:** Great for checking "Apple Bleed" (spamming iOS popups). |
| **GeeekPi nRF52840** | **Deep BLE Sniffing**<br>Raw packet analysis. | **Connect:** Plug into PC/Mac.<br>**Software:** Wireshark + Nordic Sniffer Plugin.<br>**Action:** Select "nRF Sniffer" interface in Wireshark to see raw BLE frames. |
| **T-Embed CC1101 #1** <br>*(Bruce Firmware)* | **Multi-Protocol RF**<br>Sub-GHz & WiFi analysis. | **Boot:** Scroll wheel to select.<br>**Menu:** `SubGhz` > `Read`. Captures 433/915MHz signals. |
| **T-Embed CC1101 #2** <br>*(Ghost ESP)* | **ESP-NOW / Beacon Spam**<br>WiFi frame manipulation. | **Boot:** Auto-runs Ghost.<br>**Use:** Generates "Ghost" SSIDs or tests ESP-NOW triggers. |
| **EvilCrow v2** | **RF Replay Attack**<br>Sub-GHz signal recording. | **Access:** Web UI (WiFi AP).<br>**Action:** `Receive` > Press Button 1 to Record > `Transmit` > Press Button 2 to Replay. |
| **YardStick One** | **RF Transceiver**<br>PC-based Radio analysis. | **Connect:** USB to Kali.<br>**Cmd:** `rfcat -r` (interactive python mode).<br>**Use:** Determining exact frequency and modulation of captured signals. |

## 4. Physical & HID (Human Interface Device)
| Device | Role | Use Instructions / Config |
| :--- | :--- | :--- |
| **Rubber Ducky** | **Keystroke Injection**<br>Fast payload delivery. | **Setup:** Encode `payload.txt` to `inject.bin`.<br>**Deploy:** Plug into victim USB. Waits for driver, types script.<br>**Lab Use:** Test if endpoints block new USB keyboards. |
| **Bash Bunny** | **Advanced Exfiltration**<br>Emulates Ethernet/Serial/Storage. | **Switch:** Select Position 1 or 2 (Payloads).<br>**Deploy:** Plug in. LED indicates status (Green = Done).<br>**Loot:** Saved to `udisk/loot` folder. |
| **Raspberry Pi Zero** <br>*(P4wnP1 A.L.O.A + OLED)* | **The "Implant"**<br>Persistent backdoor over USB. | **Connect:** MicroUSB (Data port) to target.<br>**OLED:** Shows IP address and current attack mode.<br>**Access:** Connect via WiFi to P4wnP1 AP, then SSH/Web UI to control. |

---

# PART 1: RED TEAM PLAYBOOK (The "Plan of Attack")

## Phase 1: Passive Reconnaissance (The "Silent" Phase)
*Goal: Map the wireless landscape without transmitting packets that could trigger an IDS.*

### 1. WiFi Mapping & Client Discovery
* **Tool:** Raspberry Pi Zero 2 W (Kali Linux + USB/Ethernet Hat)
* **Action:** Put the interface in Monitor Mode. Run `Kismet` or `Airodump-ng`. This is your "Ground Truth" device.
* **Logging:** Configure Kismet to log to `.kismet` and `.pcap` files.
    * *Command:* `kismet -c wlan1 --log-title lab_audit`

### 2. Automated Handshake Hunting
* **Tool:** Pwnagotchi (Pi Zero with e-ink)
* **Action:** Run passively using reinforcement learning to maximize handshake captures.
* **Logging:** Handshakes saved automatically to `/handshakes`.

### 3. Presence Detection
* **Tool:** T-Dongle S3 (ZeroTrace)
* **Action:** "Wardriving" simulation to identify vendor presence (Apple, Samsung, etc.).

---

## Phase 2: Active Reconnaissance & Signal Analysis
*Goal: Probe the environment to identify specific vulnerabilities.*

### 1. Bluetooth/BLE Enumeration
* **Tool:** M5Stick Pro 2 (Nemo) & GeeekPi nRF52840 Sniffer
* **Action:**
    * **Nemo:** Scan for BLE beacons.
    * **nRF52840:** Sniff raw BLE packets into Wireshark.
* **Logging:** Save `.pcap` files to analyze unencrypted BLE data exchange.

### 2. Sub-GHz Signal Analysis
* **Tool:** T-Embed CC1101 (Bruce/Ghost Firmware) & Yard Stick One
* **Action:** Scan for 433MHz or 915MHz signals (security sensors, remotes).
* **Logging:** Use `rfcat` with Yard Stick One to log raw radio data.

---

## Phase 3: Exploitation (The Attack)
*Goal: Gain access to the network or devices.*

### 1. The "Evil Twin" / Rogue AP
* **Tool:** Hak5 WiFi Pineapple + Pineapple Pager
* **Action:** Launch **PineAP**. Mimic known SSIDs to trick devices into connecting.
* **Logging:** Enable `PineAP Log`. Use `tcpdump` to capture victim traffic.

### 2. WPA/WPA2 Cracking
* **Tool:** M5Stack Fire (Purple Hash Monster) & Bjorn
* **Action:**
    * **Purple Hash Monster:** Capture PMKID.
    * **Bjorn:** Aggressive de-authentication to force 4-way handshakes.
* **Logging:** Export `.pcap` or `.hccapx` files for Hashcat.

### 3. Signal Replay (RF)
* **Tool:** Evil Crow RF V2
* **Action:** Capture and replay signals (e.g., smart plugs).
* **Logging:** Screenshot signal graphs to analyze Rolling vs. Fixed codes.

---

## Phase 4: Physical Access & Persistence
*Goal: Simulate physical intrusion.*

### 1. The BadUSB Attack
* **Tool:** Rubber Ducky or Bash Bunny
* **Action:** "Ducky Script" execution (e.g., exfiltrate WiFi profiles).
* **Logging:** Bash Bunny logs to `loot` folder.

### 2. The "Implant"
* **Tool:** Raspberry Pi Zero (P4wnP1 A.L.O.A.)
* **Action:** Create hidden network interface over USB.
* **Logging:** SSH session logging via `screen` or `tmux`.

---

# PART 2: BLUE TEAM PLAYBOOK (Defensive / Authorized Assessment)

This section focuses on **safe, defensive validation**: discovering what’s present, measuring exposure, and verifying that common *attack classes* are mitigated.

## 0) Rules of Engagement (ROE) and Safety Guardrails

- **Written authorization:** confirm you own the gear/network or have explicit permission.
- **Scope:** define SSIDs, VLANs/subnets, APs, switches, endpoints, IoT, and “out of scope” devices.
- **Impact tolerance:** decide what is allowed (passive listening, active scanning, deauth tests, etc.). Default to **non-disruptive**.
- **Logging & evidence:** enable central logging before you start (router/AP logs, syslog, Zeek/Suricata, packet capture points).
- **Stop conditions:** any sign of instability, repeated client drops, or unexpected critical device behavior.

---

## 1) Lab Inventory and Tooling Map

### Devices mentioned (capabilities, corrected notes)
- **Raspberry Pi Zero 2 W (Kali + USB/Ethernet hat):** great for network discovery, packet capture, and running lightweight recon tooling.
- **Alfa AWUS036ACS adapters:** useful for wireless monitoring/assessment (as drivers support).
- **Hak5 WiFi Pineapple:** commonly used to test **client/AP hardening against rogue AP / “evil twin” scenarios** (defensively: verify protections are in place).
- **Pi Zero running P4wnP1 (USB gadget):** useful for *your own* endpoint hardening tests in controlled conditions.
- **M5Stick / nRF52840 BLE sniffer:** suited for **Bluetooth Low Energy visibility and analysis** (sniffing in your environment).
- **CC1101 radios (T-Embed):** **sub-GHz ISM** exploration (common bands like 315/433/868/915 MHz depending on region).
  * *Note:* CC1101 is not an “802.15.1/SMBus” tool—**802.15.1 is Bluetooth**; **SMBus** is a wired bus based on I²C.
- **Rubber Ducky / Bash Bunny:** best treated as **endpoint security validation tools** (e.g., verifying USB policies, EDR response, least privilege), not “payload delivery platforms.”

---

## 2) Baseline: What “Good” Looks Like

Before testing, define the target posture:

### Wireless baseline
- WPA2/WPA3 enabled appropriately (prefer WPA3 where possible).
- **PMF / 802.11w (Protected Management Frames)** enabled if supported (helps mitigate some management-frame abuse).
- WPS disabled.
- Strong SSID separation (Guest/IoT/Corp) and VLAN segmentation.
- AP firmware up to date; management interfaces not exposed broadly.

### Network baseline
- Default-deny inbound from Guest/IoT to internal segments.
- Separate management VLAN (AP/switch/router admin only).
- DNS filtering and egress control for IoT where possible.
- Central logging (router/AP + host logs) and time sync (NTP).

---

## 3) Phase 1 — Passive Recon (Low Risk)

Goal: observe without changing anything.

### Wireless (monitor-only)
- Identify SSIDs, channels, security modes (WPA2/WPA3), and band usage (2.4/5/6 GHz).
- Confirm whether APs advertise PMF capability and whether clients negotiate it.
- Capture representative management traffic for documentation (limited duration; avoid collecting sensitive payloads).

### Wired / internal visibility
- Identify subnets, gateways, and DHCP/DNS servers.
- Confirm where logging sensors sit (SPAN port, inline tap, or host-based).

**Artifacts to produce**
- Network diagram (SSID → VLAN → subnet → gateway → services).
- Device inventory table (MAC/vendor, IP, hostname, segment, role).
- “Expected vs observed” security settings snapshot.

---

## 4) Phase 2 — Network Enumeration (Controlled Active Scanning)

Goal: map assets and exposure with minimal disruption.

### Host discovery and service mapping
- Enumerate active hosts per subnet.
- Identify open ports/services and tag “shouldn’t be here” findings:
  - Admin panels exposed outside management VLAN
  - SMB/AFP/NFS where not intended
  - Old protocols (Telnet, FTP, SMBv1)

### Vulnerability and configuration review (defensive)
- Check firmware versions (AP/router/switch) and patch status.
- Validate TLS usage on admin interfaces.
- Confirm strong admin auth (unique creds, MFA where supported, no default accounts).

**Artifacts to produce**
- Service inventory (host → port → service → justification).
- Patch/firmware status report.
- “High-risk services” list prioritized by impact + likelihood.

---

## 5) Phase 3 — Wireless Security Controls Validation (Defensive Tests)

Goal: validate you are resilient to common wireless attack *classes* without providing attack recipes.

### Rogue AP / evil twin resilience (defensive checklist)
- Do clients auto-join similarly named SSIDs?
- Are corporate devices configured to **require** correct certificate/known network parameters (if using enterprise auth)?
- Is “auto-join” disabled for sensitive endpoints?
- Are guest networks isolated so a mis-association doesn’t become lateral movement?

### Client isolation and segmentation
- Verify guest network cannot reach internal subnets.
- Verify IoT VLAN cannot reach management VLAN.
- Confirm mDNS/SSDP is controlled (only where required).

### AP hardening checks
- WPS disabled.
- PMF enabled where possible.
- Separate SSIDs for different trust zones.
- Management plane restricted by VLAN/firewall rules.

**Artifacts to produce**
- “Control matrix” showing each protection, where it’s configured, and test evidence.

---

## 6) Phase 4 — BLE / Sub-GHz Surface Mapping (Visibility-First)

Goal: understand what RF surfaces exist in your environment and how you’d defend them.

### BLE (Bluetooth Low Energy) assessment
- Inventory BLE devices (name, MAC/randomization behavior, services advertised).
- Identify risky patterns:
  - No pairing/bonding required for sensitive actions
  - Legacy pairing modes
  - Debug characteristics left enabled
- Validate defensive controls:
  - Firmware updates
  - Pairing restrictions
  - Physical access controls for critical BLE devices

### Sub-GHz exploration (CC1101 class radios)
- Identify whether your environment uses sub-GHz devices (sensors, remotes, alarms, weather stations).
- Document frequencies and device types **only for your own equipment**.
- Defensive focus: determine if critical functions rely on unauthenticated one-way signals and whether mitigations exist (rolling codes, encryption, physical safeguards).

**Artifacts to produce**
- RF asset inventory (BLE + sub-GHz): device, purpose, risk notes, mitigations.

---

## 7) Phase 5 — Endpoint Security Validation (Safe, Controlled)

Tools like USB gadget platforms and keystroke-injection devices can be used defensively to validate endpoint controls:

### What to validate
- USB device control policies (block unknown HID/storage/network adapters).
- EDR/AV detection & response for suspicious process trees and script execution.
- Least privilege: can a standard user change security settings?
- Logging: are events captured (Windows Event Logs, Sysmon, EDR telemetry)?

**Artifacts to produce**
- Endpoint hardening checklist results
- Gaps + recommended controls (Device Control, AppLocker/WDAC, macOS PPPC profiles, etc.)

---

## 8) Logging, Notes, and Evidence Handling

- Maintain a single “case notebook”:
  - Date/time, device used, test performed, scope, observed result
- Store captures responsibly:
  - Minimize retention of sensitive payload data
  - Hash evidence files if you care about integrity tracking
- Correlate:
  - Packet captures ↔ AP logs ↔ DHCP logs ↔ endpoint logs

---

## 9) Reporting Template (What You Hand to “Future You”)

### Executive summary
- What you tested
- Top 5 risks
- Quick wins (30–60 minutes)
- Medium-term fixes (1–4 weeks)

### Technical findings (per item)
- Title
- Affected segment/devices
- Evidence (what you observed)
- Impact
- Likelihood
- Recommended remediation
- Validation steps (how you’ll confirm the fix)

### Remediation backlog
- Prioritized tasks with owners and target dates

---

# Appendix A — Operational Templates

Use the following templates to document your findings as you execute the playbooks.

### 1. `network_map.md`
*Purpose: To visualize the target environment and where your tools sit within it.*

```markdown
# Network Map & Topology

**Date:** 2024-XX-XX
**Observer Device:** Kali Pi Zero 2 W (Monitor Mode)

## High-Level Topology
[ISP Modem] --> [Router/Firewall]
      |
      +--> [Managed Switch]
            |
            +--> VLAN 10 (Mgmt): [AP Admin], [NAS]
            |
            +--> VLAN 20 (Corp/Home): [PC], [Laptop], [Phones]
            |
            +--> VLAN 30 (IoT): [Smart Bulbs], [Cameras] (Isolated)
            |
            +--> [Attacker Tools]: [Kali Pi (Monitor)], [Pineapple (Rogue)]

## Subnet Details
| VLAN ID | Name | Subnet | Gateway | DHCP Range | Notes |
| :--- | :--- | :--- | :--- | :--- | :--- |
| 1 | Native | 192.168.1.0/24 | 192.168.1.1 | None | Switch Mgmt only |
| 10 | Management | 10.0.10.0/24 | 10.0.10.1 | Static | Critical Infra |
| 20 | Home/Corp | 10.0.20.0/24 | 10.0.20.1 | .100 - .200 | Trusted Devices |
| 30 | IoT | 10.0.30.0/24 | 10.0.30.1 | .10 - .250 | **No Internet Access** |
```

### 2. `asset_inventory.csv`
*Purpose: A raw spreadsheet of discovered devices.*

```csv
MAC_Address,IP_Address,Hostname,Vendor,VLAN/SSID,Role,Notes
00:11:22:33:44:55,192.168.1.50,Lab-Router,Ubiquiti,Mgmt,Gateway,Firmware v1.5.6 (Needs Update)
AA:BB:CC:DD:EE:FF,10.0.20.15,My-iPhone,Apple,Home_Secure,Client,Private Address enabled
12:34:56:78:90:AB,10.0.30.5,Unknown-Plug,Tuya/Generic,Home_IoT,IoT,Communicating with cn.tuya.com
DE:AD:BE:EF:00:00,N/A,Kali-Pi-Zero,Raspberry Pi,Monitor,Auditor,My Recon Device
CA:FE:BA:BE:00:00,172.16.42.1,WiFi-Pineapple,Hak5,Rogue_AP,Attacker,Management Interface
00:00:00:00:00:00,N/A,Pwnagotchi,Raspberry Pi,Monitor,Attacker,Handshake Hunter
```

### 3. `wireless_controls_matrix.md`
*Purpose: To audit the security settings of specific SSIDs.*

```markdown
# Wireless Controls Matrix
**Assessment Date:** 2024-XX-XX

## SSID Configuration Audit
| SSID Name | Broadcast? | Auth Type | Encryption | PMF (802.11w) | WPS Status | Frequency | Verdict |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| `Home_Secure` | Yes | WPA3-SAE | AES | Required | Disabled | 5GHz/6GHz | ✅ PASS |
| `Home_IoT` | Yes | WPA2-PSK | AES/TKIP | Optional | **Enabled** | 2.4GHz | ❌ FAIL (WPS) |
| `Guest_WiFi` | No | Open | OWE | Disabled | Disabled | 2.4/5GHz | ⚠️ WARN (Open) |

## Rogue AP Resilience (Evil Twin Test)
| Client Device | Auto-Join Enabled? | Connects to Pineapple? | Notes |
| :--- | :--- | :--- | :--- |
| iPhone 13 | Yes | No | Correctly identified cert mismatch |
| Old IoT Camera | Yes | **Yes** | Device has no cert validation; captured creds |
| Windows Laptop | No | No | GPO Prevents auto-connection to open networks |
```

### 4. `rf_inventory.md`
*Purpose: To log findings from M5Stick (Nemo), CC1101, etc.*

```markdown
# RF & Sub-GHz Inventory
**Tools Used:** M5Stick (Nemo), T-Embed (CC1101), Yard Stick One

## Bluetooth LE (BLE) Findings
| Device Name | MAC Address | RSSI | Services Exposed | Security Risk |
| :--- | :--- | :--- | :--- | :--- |
| `LivingRoom_TV` | Random | -60 | Remote Control, Audio | Low (Pairing req) |
| `Smart_Tag_01` | Fixed | -45 | Location Beacon | Medium (Trackable) |
| `N/A (Smart Lock)`| Fixed | -30 | **Unlock Service** | **Critical** (No bonding required!) |

## Sub-GHz (433/915 MHz) Findings
| Frequency | Modulation | Signal Type | Source | Replay Attack Possible? |
| :--- | :--- | :--- | :--- | :--- |
| 433.92 MHz | ASK/OOK | Remote | Garage Door | No (Rolling Code detected) |
| 315.00 MHz | ASK | Sensor | Door Contact | **Yes** (Fixed code replay worked) |
```

### 5. `findings_report.md`
*Purpose: To document specific vulnerabilities found.*

```markdown
# Technical Finding: [Title]

**Severity:** [Critical/High/Medium/Low]
**Affected Asset:** [Device Name/IP]
**Tool Used:** [e.g., WiFi Pineapple, Bjorn]

## Observation
Describe what was observed. 
*Example: The 'Home_IoT' network was observed broadcasting WPS support. The Reaver tool successfully recovered the pin in 14 minutes.*

## Evidence
* [Insert Screenshot or Log Snippet]
* [Pcap file reference]

## Impact
Describe what an attacker could do.
*Example: An attacker can bypass the WiFi password and gain entry to the IoT VLAN.*

## Remediation
* Disable WPS in the router settings.
* If WPS cannot be disabled, upgrade firmware or replace the router.
```

### 6. `remediation_backlog.md`
*Purpose: To track fixes.*

```markdown
# Remediation Backlog

| ID | Finding | Priority | Owner | Status | Due Date |
| :--- | :--- | :--- | :--- | :--- | :--- |
| 001 | WPS Enabled on IoT VLAN | High | Admin | To Do | 2024-02-01 |
| 002 | Deprecated SSH Key on Pi | Medium | Admin | In Progress | 2024-02-05 |
| 003 | Open Port 80 on Camera | High | Admin | **Fixed** | 2024-01-20 |
```

---

# Appendix B — Quick Wins Checklist

- [ ] Update AP/router/switch firmware
- [ ] Disable WPS everywhere
- [ ] Enable PMF/802.11w where supported
- [ ] Separate Guest/IoT/Management VLANs + enforce firewall rules
- [ ] Lock down management interfaces (VLAN + ACL + MFA)
- [ ] Centralize logs + ensure NTP time sync
- [ ] Endpoint USB controls and script execution policies (where appropriate)
