# Comprehensive Wireless Lab Security Assessment: Red Team & Blue Team Playbooks

This document combines a **Red Team (Offensive)** "Plan of Attack" with a **Blue Team (Defensive)** "Security Assessment" guide. It is designed for authorized, self-hosted lab environments to practice both exploitation and hardening.

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

## Appendix A — Suggested Output Files (Keep It Simple)

- `network_map.md`
- `asset_inventory.csv`
- `wireless_controls_matrix.md`
- `rf_inventory.md`
- `findings_report.md`
- `remediation_backlog.md`

## Appendix B — Quick Wins Checklist

- [ ] Update AP/router/switch firmware
- [ ] Disable WPS everywhere
- [ ] Enable PMF/802.11w where supported
- [ ] Separate Guest/IoT/Management VLANs + enforce firewall rules
- [ ] Lock down management interfaces (VLAN + ACL + MFA)
- [ ] Centralize logs + ensure NTP time sync
- [ ] Endpoint USB controls and script execution policies (where appropriate)
