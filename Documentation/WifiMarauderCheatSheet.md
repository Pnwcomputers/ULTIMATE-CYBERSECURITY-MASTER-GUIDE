# ⚡ WiFi Marauder (v1.8.9+) Cheat Sheet 📡

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
-m 16800 is the mode for WPA-PMKID/EAPOL (HCX format)
-o: output file, -E: create ESSID list for filtering
hcxpcaptool -o marauder_hash.16800 -E essid_list.txt /path/to/marauder/capture.pcapng
```

**2. WPA/WPA2/WPA3 Cracking with Hashcat**
### Dictionary attack against the converted hash file
```bash
hashcat -m 16800 marauder_hash.16800 /path/to/wordlist.txt
```

### Hybrid attack (Wordlist + 4 digits at the end)
```bash
hashcat -m 16800 marauder_hash.16800 wordlist.txt -a 6 ?d?d?d?d
```

### Resume a previous session
```bash
hashcat -m 16800 marauder_hash.16800 wordlist.txt --session=last_run --status
```

**3. File Analysis & Cleaning**
### Show info on the captured file (ESSIDs, BSSIDs, packet counts)
```bash
hcxinfo -i /path/to/marauder/capture.pcapng
```

### Merge multiple capture files before conversion
```bash
mergecap -w merged.pcapng capture-*.pcapng
```

---

## Security and Ethical Considerations ⚠️ (Marauder/HCX)

**IMPORTANT**: These tools are for **authorized security testing only**. Unauthorized use is illegal.

* **Marauder Use:** Get **written permission** before testing any network. Only test networks you own or have explicit authorization to test.
* **Cracking Use:** All cracking attempts (Hashcat) must be done in an **isolated lab environment** against hashes you are authorized to possess.
* **Legal Compliance:** Strictly comply with all local laws and regulations.

**Legal Use Cases:**
* Penetration testing with client authorization.
* Testing your own home or lab network security.
* Security research in isolated lab environments.

---

