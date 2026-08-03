# 📡 Microcontroller-Assisted Wireless Assessment Workflow

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
| Sub-GHz exploration | [Flipper Zero](https://flipper.net/) with its internal or an external CC1101 radio | Frequency discovery, signal capture, protocol identification, and authorized static-signal testing | Saved Sub-GHz captures and decoded protocol data |
| Network-side observation | [MikroTik RouterOS Device](https://a.co/d/0gQ8joO6) | Router/interface capture, logs, client state, and network-response monitoring | PCAP files, RouterOS logs, and interface statistics |
| Detailed analysis and reporting | [Linux](https://www.linux.org/) workstation | Wireshark analysis, timeline correlation, capture preservation, and reporting | Findings, screenshots, notes, and final report |

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

*Last Updated: 08-03-2026*
