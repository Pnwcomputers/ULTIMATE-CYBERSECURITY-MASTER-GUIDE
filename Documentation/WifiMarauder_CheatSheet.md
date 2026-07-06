# ⚡ WiFi Marauder (v1.8.9+) Cheat Sheet 📡

## 🎯 Purpose
On-device command reference for ESP32 Marauder firmware - the pocket-sized WiFi and Bluetooth security testing platform. Covers the capture workflow (on-device) and the post-capture processing pipeline (on Kali/Linux).

## ⚙️ Function
Organized in two phases: on-device capture using the Marauder menu system (AP scanning, handshake/PMKID capture, deauth, beacon spam, GPS wardriving), and post-capture processing using hcxpcapngtool to convert `.pcapng` files to Hashcat mode 22000 format for cracking. See [WiFiMarauder_Guide.md](WiFiMarauder_Guide.md) for the full guide with hardware selection, installation, and advanced scenarios.

## 🏆 Goal
Capture WPA2 handshakes and PMKIDs from target networks (authorized testing only), transfer the `.pcapng` to a Linux workstation, and crack the pre-shared key with Hashcat.

## 📋 When to Use
- Authorized WiFi security assessments requiring a small, portable capture device
- On-site handshake capture when a Kali laptop would be conspicuous
- Wardriving with GPS-tagged AP discovery
- Quick deauth/beacon demonstrations for client security awareness

### Basic Workflow: On-Device Capture

The Marauder handles the packet capture and attack functions directly via its menu.

**1. Set Target Channel**
```text
Menu: Settings/Device -> WiFi Settings -> Set Channel
```
### Set this to match the target AP's channel for best results.

**2. Scan for Networks (Reconnaissance)**
```text
Menu: WiFi -> Scan / Sniff -> Scan APs
```
### Find BSSID (AP MAC) and Channel of the target network.

**3. Capture Handshakes & PMKID (Saved to SD Card)**
```text
Menu: WiFi -> Scan / Sniff -> PMKID
```
### Primary capture mode: Tries to grab PMKID (WPA3/WPA2) and 4-way EAPOL handshakes.
### File is saved to SD card as YYYYMMDD_TIME.pcapng

**4. Deauth Attack (Force Handshake Capture)**
```text
Menu: WiFi -> Attack -> Deauth -> Deauth All Clients
```
### Select the target AP (BSSID) from the list.
### This forces clients to re-authenticate, which triggers a handshake capture (Step 3).

---

## Advanced On-Device Techniques

**Beacon Spam / Reconnaissance**
```text
Menu: WiFi -> Attack -> Beacon Spam -> Enable/Disable
```
### Broadcasts many fake APs (used for client probe request collection or DoS).
### Use 'Funny SSIDs' mode for social engineering tests.

**AirTag/BLE Tracking Device Detection (Defensive)**
```text
Menu: Bluetooth -> AirTag Monitor
```
### Scans for common BLE tracking patterns (AirTags) and reports 'Last-Seen' time.

**Quick Network Triaging**
```text
Menu: WiFi -> Scan / Sniff -> ARP / SSH / Telnet scans
```
### Quickly probe devices on a known local network to assess active services.

**GPS-Tagged Site Survey (Wardriving)**
```text
Menu: GPS -> Wardrive (Start/Stop)
Menu: GPS -> Add POI
```
### Logs all captured data with GPS coordinates to the SD card for mapping.
### POI (Points of Interest) marks specific locations for later review.

---

## Post-Capture Workflow (Requires Linux/Kali)

After capturing the `.pcapng` file on the Marauder's SD card, transfer it to a Linux machine to process it for cracking.

**1. Convert Marauder PCAPNG to Hashcat Format**
```bash
# hcxpcapngtool replaced hcxpcaptool in hcxtools ≥5.3.0
# Mode 22000 is the unified WPA/WPA2/WPA3 format (replaces deprecated modes 16800 and 2500)
# -o: output file, -E: create ESSID list for targeted cracking
hcxpcapngtool -o marauder_hash.hc22000 -E essid_list.txt /path/to/marauder/capture.pcapng
```

**2. WPA/WPA2/WPA3 Cracking with Hashcat**
```bash
# Dictionary attack against the converted hash file
hashcat -m 22000 marauder_hash.hc22000 /path/to/wordlist.txt

# Hybrid attack (Wordlist + 4 digits at the end)
hashcat -m 22000 marauder_hash.hc22000 wordlist.txt -a 6 ?d?d?d?d

# Resume a previous session
hashcat -m 22000 marauder_hash.hc22000 wordlist.txt --session=last_run --status
```

**3. File Analysis & Cleaning**
```bash
# Show info on the captured file (ESSIDs, BSSIDs, packet counts)
# hcxinfo was replaced by hcxpcapngtool --info=stdout in hcxtools ≥5.3.0
hcxpcapngtool --info=stdout /path/to/marauder/capture.pcapng
```

### Merge multiple capture files before conversion
```bash
mergecap -w merged.pcapng capture-*.pcapng
```

*****

## Security and Ethical Considerations ⚠️

**IMPORTANT**: These tools are for **authorized security testing only**. Unauthorized use is illegal.

* **Marauder Use:** Get **written permission** before testing any network. Only test networks you own or have explicit authorization to test.
* **Cracking Use:** All cracking attempts (Hashcat) must be done in an **isolated lab environment** against hashes you are authorized to possess.
* **Legal Compliance:** Strictly comply with all local laws and regulations.

**Legal Use Cases:**
* Penetration testing with client authorization.
* Testing your own home or lab network security.
* Security research in isolated lab environments.

---

## Related Files
- [WiFiMarauder_Guide.md](WiFiMarauder_Guide.md) - Full Marauder guide: hardware selection, firmware installation, advanced attack scenarios
- [hcxtoolshashcat.md](hcxtoolshashcat.md) - Complete hcxtools + Hashcat mode 22000 cracking workflow
- [Aircrack-ng_Commands.md](Aircrack-ng_Commands.md) - Aircrack-ng suite for deauth-forced handshake capture workflows
- [flipper_zero_guide.md](flipper_zero_guide.md) - Flipper Zero + ESP32 Dev Board: running Marauder via the Flipper
- [evil_m5.md](evil_m5.md) - M5Cardputer Evil-M5Project: keyboard-driven WiFi attack platform (sibling to Marauder)
- [pwnagotchi_cheatsheet.md](pwnagotchi_cheatsheet.md) - Pwnagotchi: passive handshake capture on Pi (same pcapng output format)

