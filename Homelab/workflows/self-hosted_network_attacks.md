# Comprehensive Wireless Lab Security Assessment: Master Playbook

This document combines a **Device Operational Guide**, **Red Team (Offensive) Plan**, and **Blue Team (Defensive) Assessment** for an authorized, self-hosted wireless lab.

## 🎯 Purpose
Homelab-specific operational playbook that ties together the individual hardware guides in [Documentation/](../../Documentation/) (Pwnagotchi, Bjorn, Evil-M5, Bruce, WiFi Marauder) into one coordinated red-team/blue-team exercise against your own lab network. This is the "how it all fits together" document - for command-level detail on any single device, see its dedicated file in Documentation/.

## ⚙️ Function
Three parts: a device inventory/operational quick-reference table for every tool in the kit (cross-referencing the per-device guides), a phased Red Team playbook (passive recon → active recon → exploitation → physical/persistence), and a parallel Blue Team playbook (ROE, baseline definition, controlled validation phases, reporting templates) that reframes the same devices as defensive-validation tools rather than attack tools.

## 🏆 Goal
Run a full-cycle offense/defense exercise against your own homelab wireless environment using the hardware inventory, and walk away with a completed findings report and remediation backlog (Appendix A templates) rather than just a pile of captures.

## 📋 When to Use
- Running a coordinated red/blue exercise across your full hardware kit rather than one device at a time
- Onboarding a new piece of hardware into the lab and needing to know where it fits in the attack/defense phase model
- Needing the Blue Team framing (Part 2) to validate defenses rather than just attack - useful when the goal is hardening, not just capture

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

## RaspyJack — Raspberry Pi Portable Assessment Workflow

**Project spelling and provenance:** the upstream project is **RaspyJack** (sometimes typed "RaspiJack"), maintained at [7h30th3r0n3/Raspyjack](https://github.com/7h30th3r0n3/Raspyjack), with a distinct [installation wiki](https://github.com/7h30th3r0n3/Raspyjack/wiki/Installation). It is a **Linux/Python application suite for Raspberry Pi**, not a flashable ESP32 binary, Hak5 Shark Jack firmware, or a Flipper Zero application. Integrate it into the lab as a scoped operator-controlled Raspberry Pi workstation, never as an unattended implant.

### Hardware, Layout & Threat Model

| Component | Role / boundary |
|---|---|
| Raspberry Pi Zero 2 W + stable power + microSD | Common reference target; a display is optional if using the WebUI |
| Waveshare 1.44-inch ST7735 or 1.3-inch ST7789 LCD HAT | Supported portable menu controls; pick the right installer display profile |
| USB Ethernet/HUB HAT or lab Ethernet adapter | Isolated management transport; some headless builds require wired connectivity |
| External USB Wi-Fi adapter (optional) | Monitor-capable surveys depend on exact chipset/driver; never infer injection support from the Pi's built-in Wi-Fi |
| Raspberry Pi OS Lite, pinned upstream revision | Host OS; installer changes packages, system services and network configuration |
| WebUI & Payload IDE | **Privileged management surface**; accessible only from an isolated/admin-controlled network, not public Internet |
| `/root/Raspyjack`, `payloads/`, `loot/`, `config/` | Project and evidence locations described upstream; do not put actual client secrets into git |

RaspyJack includes payloads that can affect networks, collect credentials or launch remote-control processes. **Default scope here excludes those capabilities.** An installed toolkit does not authorize executing all included payloads. Review upstream code and each selected script; its feature availability is not guaranteed across versions, display models or optional modules.

### Installation — Clean Disposable Lab First

1. Image a spare SD card with the upstream-compatible Raspberry Pi OS Lite version for your specific Pi. Establish a local admin user, secure SSH, and an isolated lab management network. Never first-install it on a client's production Pi.
2. Verify power, display SPI pinout, Ethernet connectivity and target architecture. Apply system updates and take an SD image or snapshot **before** running a third-party installer.
3. Review the source install script for package repositories, services, root privileges, firewall/proxy changes and web listener bindings. Review the exact revision with `git log -1`.
4. Follow the [upstream installer](https://github.com/7h30th3r0n3/Raspyjack/wiki/Installation) only after approval. The documented path is `/root/Raspyjack`; execute from a local console and select the correct display type. The upstream installer may set up SPI, I²C, systemd units, Wi-Fi/network tools and a WebUI.
5. Reboot in the lab. Confirm expected screen/menu, network interface IDs and health checks; do **not** enable any offensive payloads. Run these read-only checks:

~~~bash
uname -a
cat /etc/os-release
ip -br link
sudo ss -lntp
systemctl --type=service --state=running | grep -Ei 'raspyjack|caddy' || true
~~~

6. Confirm the WebUI is reachable only through a management interface, close unexpected exposed ports, change all credentials/tokens, restrict access with firewall/VLAN rules and verify TLS if configured. Upstream documents `https://<device-ip>/` with an optional `http://<device-ip>:8080` fallback; a working HTTP fallback is **not** secure for untrusted networks.
7. Back up the configured lab image and document the commit, dependency versions, screen/hat, authorized network, remote-access configuration and rollback procedure.

### Lab RJ1 — Console, Services & Configuration Acceptance

1. Start RaspyJack in the isolated lab with all network-invasive payloads disabled.
2. Confirm LCD/joystick operation, device process status and read-only WebUI dashboard access. Identify any open remote management ports through `ss`.
3. Compare installed services with the reviewed installer, and disable anything not needed for this exercise through normal host administration.
4. Test a login failure and an approved login using synthetic credentials. Record authentication/session behavior without collecting real user credentials.
5. Ensure the WebUI is unreachable from a deliberately isolated guest/test VLAN.

**Pass:** a documented, restricted and recoverable management surface. **Fail:** unexpected root-accessible public listener or missing authentication.

### Lab RJ2 — Local Inventory Without Network Scanning

1. From the Pi's terminal, record its own hostname, OS release, interface names/IPs and default routes.
2. Review `payloads/` directory names with `find`/`ls`; do not run them.
3. Create a test folder with a dummy note, exercise the local files/loot browser only if its version supports read-only browsing, then remove the dummy note.
4. Export a version/asset manifest. Use this as the baseline before enabling an optional Ethernet or monitor-mode Wi-Fi adapter.

### Lab RJ3 — Approved Lab Host Discovery

1. Obtain written scope for **one** synthetic lab host IP and approved rate/ports. Confirm the Raspberry Pi is on the right isolated VLAN.
2. Use a low-impact TCP connection check from the Pi to a known service on the controlled test host (such as SSH you configured). For example, `nc -vz -w 2 192.0.2.10 22` is syntax illustration: replace the documentation-only IP with the approved test host.
3. Compare observed reachability with the host firewall and switch/router logs. If blocked, do not broaden scanning without new approval.
4. Record DNS/route changes and whether the Pi can reach excluded VLANs; verify that required segmentation is enforced.

### Lab RJ4 — Read-Only Wireless Adapter Qualification

1. Connect an independently supported Wi-Fi adapter to the Pi on a dedicated isolated lab AP environment.
2. Record `lsusb`, `iw dev` and `ip -br link`. Identify whether **this driver** supports monitor mode; do not assume all branded adapters have identical chipset revisions.
3. Verify owned AP visibility using a passive-capable sensor workflow and an independent AP/controller inventory. If the adapter requires interface reconfiguration, save/restore baseline networking and do not disconnect the management link.
4. Correlate with [Marauder standalone survey](../../Documentation/WiFiMarauder_Guide.md#dedicated-standalone-marauder-deployment-playbook), [Flipper Marauder](../../Documentation/flipper_zero_guide.md#flipper-marauder-companion-deployment-labs), and [Biscuit](../../Wardriving/biscuit.md) as **different collection platforms**, not interchangeable firmware.

### Lab RJ5 — WIDS/Endpoint Telemetry & Evidence Export

1. Create a unique lab SSID on a separate owned AP and record its BSSID, channel, start time and intended security posture.
2. Monitor appearance through a supported, non-disruptive receiver. Where a separate [Kismet sensor](../../Wardriving/kismet.md) and [Wazuh ingestion](../../IncidentResponse/IDS%26IPS/kismet-wazuh-wireless-lab.md) exist, compare their **real logs** to RaspyJack inventory notes.
3. Do not claim RaspyJack directly ships Wazuh alerts: inspect the installed source first, and use a documented external log ingestion path where needed.
4. Turn the AP off, collect negative-control observations, and store only redacted evidence and hashes.

### Lab RJ6 — Operational Recovery & Secure Handoff

1. Save the verified SD image, installed commit, packages, service configuration and hostname; encrypt any assessment artifacts.
2. Test a controlled reboot, management reconnect and restoration to the baseline image on a spare SD card.
3. Ensure no scanning/portal/C2/credential services auto-start. Confirm firewall, routes and WebUI exposure.
4. Delete synthetic data and rotate any temporary admin credentials before putting the Pi into storage or shipping it between job sites.

### Evidence & Deployment Acceptance

| Evidence | Minimum record |
|---|---|
| Host provenance | Pi model, HAT, adapter/chipset, SD image, OS and upstream commit |
| Authorization | Scope, approved VLAN/host/SSID, operator, stop time |
| Management | UI bound address/ports, authentication, firewall isolation |
| Observation | In-scope asset, tool/mode, timestamps, independent confirmation |
| Forensics | Redacted filename, SHA-256 digest, retention and secure transport |
| Rollback | Services stopped, guest isolation confirmed, backup restore tested |

**Failure conditions:** unexpected routes, unsolicited wireless transmissions, privileged remote UI exposure, installer modifying production network services, collection of genuine credentials, or traffic to out-of-scope IPs. Stop and restore the clean image.

### Related Existing Guides

[Portable cyberdeck design](../../PlayBooks/assessment-service-integration-map.md) · [Bjorn Pi](../../Documentation/bjorn_pi.md) · [Marauder](../../Documentation/WiFiMarauder_Guide.md) · [Bruce](../../Documentation/bruce_firmware.md) · [Wireless surveying](../../Wardriving/README.md) · [Network architecture](../README.md)

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
  * *Note:* CC1101 is not an “802.15.1/SMBus” tool-**802.15.1 is Bluetooth**; **SMBus** is a wired bus based on I²C.
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

## 3) Phase 1 - Passive Recon (Low Risk)

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

## 4) Phase 2 - Network Enumeration (Controlled Active Scanning)

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

## 5) Phase 3 - Wireless Security Controls Validation (Defensive Tests)

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

## 6) Phase 4 - BLE / Sub-GHz Surface Mapping (Visibility-First)

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

## 7) Phase 5 - Endpoint Security Validation (Safe, Controlled)

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

# Appendix A - Operational Templates

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

# Appendix B - Quick Wins Checklist

- [ ] Update AP/router/switch firmware
- [ ] Disable WPS everywhere
- [ ] Enable PMF/802.11w where supported
- [ ] Separate Guest/IoT/Management VLANs + enforce firewall rules
- [ ] Lock down management interfaces (VLAN + ACL + MFA)
- [ ] Centralize logs + ensure NTP time sync
- [ ] Endpoint USB controls and script execution policies (where appropriate)

---

# Appendix C - Pro-Tips for Lab Stability

### 1. Time Synchronization (Forensic Integrity)
* **Problem:** Pi Zeros lack RTCs; logs may default to 1970, breaking timeline analysis.
* **Fix:** Install **DS3231 RTC modules** on the Kali Pi and Pwnagotchi, OR ensure an NTP sync via phone tethering occurs immediately upon boot.

### 2. Protecting the "AI" (Pwnagotchi)
* **Problem:** Power cuts corrupt SD cards, destroying the Pwnagotchi's learned "Brain".
* **Fix:** Regularly backup `/root/brain.nn` and `/root/handshakes/` to the Kali Pi or a laptop. Use a "Safe Shutdown" script/button if available.

### 3. De-Confliction (Bjorn vs. Pineapple)
* **Problem:** Bjorn may attack the Pineapple's Rogue AP if not scoped correctly, confusing your own logs.
* **Fix:** Add the Pineapple's MAC address and "Evil Twin" SSIDs to Bjorn's `whitelist.txt` (or equivalent config) so your tools don't fight each other.

## Related Files
- [../../Homelab/HomeLab_Setup.md](../../Homelab/HomeLab_Setup.md) - Homelab infrastructure this workflow runs on
- [../../Documentation/Aircrack-ng_Commands.md](../../Documentation/Aircrack-ng_Commands.md) - Aircrack-ng command reference
- [../../Documentation/wireshark.md](../../Documentation/wireshark.md) - Wireshark for blue team monitoring
- [../../IncidentResponse/network_intrusion.md](../../IncidentResponse/network_intrusion.md) - Network intrusion detection procedures
