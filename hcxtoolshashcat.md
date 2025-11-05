## HCXTools & Hashcat Cheat Sheet (Linux/CLI Focus) ⚡

### Basic Workflow: PMKID & Handshake Capture

**1. Prepare the Interface (Required for HCX Tools)**
----BASH-START----
sudo ip link set wlan1 down          # Ensure interface is down
sudo hcxdumptool -i wlan1 -o dump.pcapng --disable_deauthentication # Set adapter (no monitor mode needed!)
----BASH-END----

**2. Capture Management Frames (PMKID & EAPOL)**
----BASH-START----
# Capture PMKID (mode 4) and EAPOL (mode 1)
sudo hcxdumptool -i wlan1 -o capture.pcapng -C 60 --check_client_list --enable_status=1
# -C 60: Capture for 60 seconds. --enable_status=1: Show status updates.
----BASH-END----

**3. Convert to Hashcat Format**
----BASH-START----
# Convert PCAPNG (hcxdumptool output) to Hashcat HASH format (16800 for PMKID/Handshakes)
hcxpcaptool -o hash.16800 -E essid_list.txt capture.pcapng
# -E: Creates an optional list of ESSIDs found in the capture
----BASH-END----

---

### Advanced Capture Options

**Targeting Specific Networks**
----BASH-START----
# Target only a specific BSSID on a single channel
sudo hcxdumptool -i wlan1 -o target.pcapng --bssid AA:BB:CC:DD:EE:FF --channel 6 --enable_status=1
----BASH-END----

**Filtering the Output**
----BASH-START----
# Capture only PMKID (mode 4) and EAPOL (mode 1/3) packets
# This is the default, but explicitly useful for documentation
sudo hcxdumptool -i wlan1 -o filtered.pcapng --filtermode 4 --enable_status=1
----BASH-END----

**Capturing Only Beacons & Probe Requests**
----BASH-START----
# Capture non-EAPOL/PMKID frames for general reconnaissance
sudo hcxdumptool -i wlan1 -o probes.pcapng --filtermode 3 --enable_status=1
----BASH-END----

---

### Hashcat Cracking (Mode 2500 & 16800)

**WPA/WPA2/WPA3 (Handshakes and PMKID)**
----BASH-START----
# Crack the converted HASH file (HCX format) using a wordlist
# -m 16800 is the mode for WPA-PMKID-PBKDF2/WPA2-EAPOL-PBKDF2
hashcat -m 16800 hash.16800 /path/to/wordlist.txt

# Crack a traditional Aircrack-ng .hccapx converted file (WPA-EAPOL)
# -m 2500 is the mode for WPA/WPA2
hashcat -m 2500 capture.hccapx /path/to/wordlist.txt
----BASH-END----

**Using Rules for Advanced Cracking**
----BASH-START----
# Apply a rule file to transform the wordlist (e.g., append numbers, capitalization)
hashcat -m 16800 hash.16800 wordlist.txt -r rules/best64.rule

# Hybrid attack: Wordlist + bruteforce mask for the end of the password
hashcat -m 16800 hash.16800 wordlist.txt -a 6 ?d?d?d?d
----BASH-END----

**Checking Hash Status**
----BASH-START----
# Resume a previous cracking session
hashcat -m 16800 hash.16800 /path/to/wordlist.txt --session=mysession --status

# View the passwords successfully cracked (the "cracked" file)
hashcat -m 16800 hash.16800 --show
----BASH-END----

---

### HCXTools for File Analysis

**File Conversion & Cleaning**
----BASH-START----
# Convert Aircrack-ng .cap file to PCAPNG format for HCX analysis
aircrack-ng-cap2pcap capture.cap -o output.pcapng

# Merge multiple PCAPNG files before conversion
mergecap -w merged.pcapng file1.pcapng file2.pcapng

# Clean up handshake files (remove unneeded data, merge, compress)
wpaclean cleaned.cap capture-01.cap
----BASH-END----

**Inspecting and Filtering Captured Data**
----BASH-START----
# View unique BSSIDs/ESSIDs found in a capture file
hcxinfo -i capture.pcapng

# Filter out duplicate or low-quality packets before cracking
hcxhash -i capture.pcapng -o unique_hashes.txt -a 3
----BASH-END----
