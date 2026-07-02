# HCXTools & Hashcat Cheat Sheet ⚡

## 🎯 Purpose
Command reference for the modern, monitor-mode-free WiFi capture pipeline: `hcxdumptool` → `hcxpcapngtool` → `hashcat` (unified 22000 hash format). This is the newer counterpart to [Aircrack-ng_Commands.md](Aircrack-ng_Commands.md), which covers the classic monitor-mode aircrack-ng suite and still-relevant WEP/WPS attacks this pipeline doesn't do.

## ⚙️ Function
Three-stage pipeline: capture PMKID/EAPOL frames with `hcxdumptool` (no monitor mode required), convert to hashcat's unified `.22000` format with `hcxpcapngtool`, then crack with hashcat mode 22000. Differs from `Aircrack-ng_Commands.md` in that it needs no deauth or monitor mode for PMKID capture and produces one hash format covering PMKID and full handshakes, instead of aircrack-ng's separate WEP/WPA/WPS toolchains.

## 🏆 Goal
Get from a raw WiFi capture to a crackable `.22000` hash file using only the actively-maintained hcxtools/hashcat pipeline, without the classic monitor-mode dance.

## 📋 When to Use
- Clientless PMKID capture against a target AP (no associated clients required)
- Any WPA/WPA2/WPA3 handshake conversion for hashcat, since 22000 is the hash mode hashcat now recommends over the deprecated 2500/16800 modes
- Post-processing capture files pulled off a Marauder, Flipper Zero WiFi board, or other hcxdumptool-based device — see [WifiMarauder_CheatSheet.md](WifiMarauder_CheatSheet.md) and [flipper_zero_guide.md](flipper_zero_guide.md)

*****

**1. Prepare the Interface (Required for HCX Tools)**
```bash
sudo ip link set wlan1 down          # Ensure interface is down
sudo hcxdumptool -i wlan1 -o dump.pcapng --disable_deauthentication # Set adapter (no monitor mode needed!)
```

**2. Capture Management Frames (PMKID & EAPOL)**
### Capture PMKID (mode 4) and EAPOL (mode 1)
```bash
sudo hcxdumptool -i wlan1 -o capture.pcapng -C 60 --check_client_list --enable_status=1
-C 60: Capture for 60 seconds. --enable_status=1: Show status updates.
```

**3. Convert to Hashcat Format**
### Convert PCAPNG (hcxdumptool output) to the unified Hashcat 22000 format (`hcxpcaptool` is deprecated — use `hcxpcapngtool`)
```bash
hcxpcapngtool -o hash.22000 -E essid_list.txt capture.pcapng
```
### -E: Creates an optional list of ESSIDs found in the capture

****

## Advanced Capture Options

**Targeting Specific Networks**
### Target only a specific BSSID on a single channel
```bash
sudo hcxdumptool -i wlan1 -o target.pcapng --bssid AA:BB:CC:DD:EE:FF --channel 6 --enable_status=1
```

**Filtering the Output**
### Capture only PMKID (mode 4) and EAPOL (mode 1/3) packets
### This is the default, but explicitly useful for documentation
```bash
sudo hcxdumptool -i wlan1 -o filtered.pcapng --filtermode 4 --enable_status=1
```

**Capturing Only Beacons & Probe Requests**
### Capture non-EAPOL/PMKID frames for general reconnaissance
```bash
sudo hcxdumptool -i wlan1 -o probes.pcapng --filtermode 3 --enable_status=1
```
---

# Hashcat Cracking (Mode 22000)

**WPA/WPA2/WPA3 (Handshakes and PMKID)**
## Crack the converted HASH file (HC22000 format) using a wordlist
```bash
-m 22000 is the recommended unified mode for WPA-PMKID-PBKDF2/WPA2-EAPOL-PBKDF2, replacing deprecated modes 2500 and 16800
hashcat -m 22000 hash.22000 /path/to/wordlist.txt
```

## Crack a traditional Aircrack-ng .hccapx converted file (WPA-EAPOL, legacy)
```bash
-m 2500 is the deprecated mode for WPA/WPA2 hccapx files — only needed if you're stuck with an old .hccapx and can't reconvert from the original capture
hashcat -m 2500 capture.hccapx /path/to/wordlist.txt
```

**Using Rules for Advanced Cracking**
### Apply a rule file to transform the wordlist (e.g., append numbers, capitalization)
```bash
hashcat -m 22000 hash.22000 wordlist.txt -r rules/best64.rule
```

### Hybrid attack: Wordlist + bruteforce mask for the end of the password
```bash
hashcat -m 22000 hash.22000 wordlist.txt -a 6 ?d?d?d?d
```

**Checking Hash Status**
### Resume a previous cracking session
```bash
hashcat -m 22000 hash.22000 /path/to/wordlist.txt --session=mysession --status
```

### View the passwords successfully cracked (the "cracked" file)
```bash
hashcat -m 22000 hash.22000 --show
```
---

# HCXTools for File Analysis

**File Conversion & Cleaning**
### hcxpcapngtool reads .cap, .pcap, and .pcapng (including gzip-compressed) directly — no separate conversion step is needed
```bash
hcxpcapngtool -o output.22000 capture.cap
```

### Merge multiple PCAPNG files before conversion
```bash
mergecap -w merged.pcapng file1.pcapng file2.pcapng
```

### Clean up handshake files (remove unneeded data, merge, compress)
```bash
wpaclean cleaned.cap capture-01.cap
```

**Inspecting and Filtering Captured Data**
### View info on a converted 22000 hash file, filtered to one ESSID (the legacy `hcxinfo` tool no longer exists — this is the current equivalent)
```bash
hcxhashtool --info=stdout -i hash.22000 --essid=TargetSSID
```

### Filter a hash file down to PMKID-only or EAPOL-only entries (there is no `hcxhash` tool — `hcxhashtool` is the real filtering utility)
```bash
hcxhashtool -i hash.22000 -o pmkid_only.22000 --type=1
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


