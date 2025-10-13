# ENHANCED CYBERSECURITY MASTER GUIDE
## Incorporating Personal Notion Knowledge Base + 13 Professional Books

*This enhanced guide combines:*
- ✅ All 13 professional cybersecurity books
- ✅ Your personal Notion knowledge base
- ✅ Custom scripts and tools
- ✅ Playbooks and operational procedures
- ✅ Real-world attack case studies

---

# TABLE OF CONTENTS - ENHANCED EDITION

## NEW SECTIONS FROM YOUR NOTION BASE:

### PART 0: OPERATIONAL SECURITY & SETUP
1. [OPSEC Fundamentals](#opsec-fundamentals)
2. [Virtual Machine Setup](#virtual-machine-setup)
3. [Hardware & Device Arsenal](#hardware--device-arsenal)
4. [Anonymity & Privacy Protection](#anonymity--privacy-protection)

### OSINT MASTERY (YOUR SPECIALIZED CONTENT)
5. [Comprehensive OSINT Resources](#comprehensive-osint-resources)
6. [OSINT Virtual Machines](#osint-virtual-machines)
7. [OSINT Tools & Software](#osint-tools--software)
8. [People Search & Identity Tracing](#people-search--identity-tracing)
9. [Username & Email OSINT](#username--email-osint)
10. [Phone Number Investigation](#phone-number-investigation)
11. [Geolocation & Mapping](#geolocation--mapping)
12. [Image & Metadata Analysis](#image--metadata-analysis)

### REAL-WORLD ATTACK CASE STUDIES
13. [Stuxnet Analysis](#stuxnet-analysis)
14. [WannaCry Breakdown](#wannacry-breakdown)
15. [EternalBlue Exploitation](#eternalblue-exploitation)
16. [SolarWinds Attack](#solarwinds-attack)
17. [Carbanak APT Campaign](#carbanak-apt-campaign)
18. [NotPetya Ransomware](#notpetya-ransomware)
19. [Edward Snowden Revelations](#edward-snowden-revelations)

### TEAM PLAYBOOKS (YOUR OPERATIONAL GUIDES)
20. [Purple Team Playbook (Simple)](#purple-team-playbook-simple)
21. [Purple Team Playbook (Detailed)](#purple-team-playbook-detailed)
22. [Blue Team Playbook (Generic)](#blue-team-playbook-generic)
23. [Blue Team Playbook (Detailed)](#blue-team-playbook-detailed)
24. [Detection Rule Pipelines](#detection-rule-pipelines)
25. [SIEM Ingestion](#siem-ingestion)

### CUSTOM SCRIPTS & AUTOMATION
26. [Black Hat Bash Lab Build](#black-hat-bash-lab-build)
27. [Network Automation Scripts](#network-automation-scripts)
28. [System Administration Scripts](#system-administration-scripts)
29. [Python Security Toolkits](#python-security-toolkits)
30. [PowerShell Security Tools](#powershell-security-tools)

---

# PART 0: OPERATIONAL SECURITY & SETUP

## OPSEC Fundamentals

### Critical OPSEC Rules (From Your Notion)

**ALWAYS USE:**
- ✅ 3rd Party Network for Operations
- ✅ No-Logging VPN or Proxy
- ✅ Virtual Machine (NEVER bare metal!)
- ✅ Compartmentalized environments
- ✅ Clean snapshots between engagements

**NEVER:**
- ❌ Use personal/corporate networks for OPs
- ❌ Run security tools on bare metal
- ❌ Mix personal and operational identities
- ❌ Reuse infrastructure across engagements
- ❌ Leave traces on physical systems

### OPSEC Layers

```
Layer 1: Physical Security
├── Secure location
├── No surveillance cameras
├── Faraday cage (if needed)
└── Secure hardware disposal

Layer 2: Network Security
├── VPN (Mullvad, ProtonVPN)
├── Tor for additional anonymity
├── Third-party networks (coffee shops, public WiFi)
└── MAC address randomization

Layer 3: Virtual Security
├── Dedicated VM per operation
├── Snapshot before and after
├── No clipboard sharing with host
└── Network isolation

Layer 4: Identity Security
├── Separate personas
├── Burner accounts
├── Anonymous payment methods
└── No PII linkage

Layer 5: Data Security
├── Encrypted storage (VeraCrypt)
├── Secure deletion (shred, srm)
├── No cloud sync
└── Air-gapped backups
```

### OPSEC Checklist

**Before Every Operation:**
- [ ] VM snapshot created
- [ ] VPN connected and verified
- [ ] No personal accounts logged in
- [ ] Tor configured (if needed)
- [ ] MAC address randomized
- [ ] GPS disabled on devices
- [ ] Metadata stripping tools ready
- [ ] Communication channels secured
- [ ] Emergency wipe procedures ready

**During Operation:**
- [ ] Minimize digital footprint
- [ ] Use throwaway accounts only
- [ ] No identifying information shared
- [ ] Document everything in secured notes
- [ ] Maintain cover story
- [ ] Monitor for detection

**After Operation:**
- [ ] Wipe VM or restore snapshot
- [ ] Delete temporary files
- [ ] Clear browser history/cookies
- [ ] Verify no traces left
- [ ] Archive findings securely
- [ ] Burn accounts if compromised

---

## Virtual Machine Setup

### Recommended Operating Systems (From Your Notion)

#### For Offensive Security:
```bash
# Kali Linux - Primary offensive OS
wget https://cdimage.kali.org/kali-2024.3/kali-linux-2024.3-virtualbox-amd64.7z

# BlackArch - Alternative with 2500+ tools
# Based on Arch Linux
curl -O https://blackarch.org/ova/blackarch-linux-2024.iso

# Parrot Security OS
# Lightweight alternative to Kali
wget https://download.parrot.sec/parrot/iso/5.3/Parrot-security-5.3_amd64.iso
```

#### For OSINT Investigations:
```bash
# Buscador OSINT VM (IntelTechniques)
# Custom Ubuntu with pre-configured OSINT tools
# Download from: inteltechniques.com/buscador

# Trace Labs OSINT VM
wget https://www.tracelabs.org/initiatives/osint-vm

# OSINT VM Automated Setup Script:
wget https://uvm:317@inteltechniques.com/osintvm/install.sh
chmod +x install.sh && ./install.sh
```

#### For General Purpose:
- **Debian** - Stable, security-focused
- **Ubuntu LTS** - User-friendly, well-supported
- **Tails** - For maximum anonymity
- **Whonix** - All traffic through Tor

### Pimp My Kali Script

```bash
#!/bin/bash
# Enhanced Kali Linux setup script

echo "[*] Updating system..."
apt update && apt upgrade -y
apt dist-upgrade -y

echo "[*] Installing essential tools..."
apt install -y \
    git curl wget \
    python3-pip \
    golang \
    docker.io \
    virtualenv \
    terminator \
    tmux \
    vim \
    burpsuite \
    metasploit-framework \
    nmap \
    wireshark \
    john \
    hashcat \
    hydra \
    sqlmap \
    nikto \
    dirb \
    gobuster \
    wfuzz \
    ffuf \
    amass \
    subfinder \
    nuclei \
    bloodhound \
    neo4j \
    crackmapexec \
    evil-winrm \
    responder \
    impacket-scripts \
    powershell-empire \
    covenant \
    chisel \
    ligolo-ng

echo "[*] Installing Python tools..."
pip3 install \
    impacket \
    ldap3 \
    pwntools \
    ropper \
    keystone-engine \
    unicorn \
    capstone \
    scapy \
    requests \
    beautifulsoup4 \
    selenium

echo "[*] Installing Go tools..."
go install github.com/projectdiscovery/nuclei/v2/cmd/nuclei@latest
go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install github.com/projectdiscovery/httpx/cmd/httpx@latest
go install github.com/tomnomnom/waybackurls@latest

echo "[*] Setting up directories..."
mkdir -p ~/tools
mkdir -p ~/wordlists
mkdir -p ~/engagements
mkdir -p ~/scripts

echo "[*] Downloading wordlists..."
cd ~/wordlists
wget https://github.com/danielmiessler/SecLists/archive/master.zip
unzip master.zip
rm master.zip

echo "[*] Installing custom tools..."
cd ~/tools

# Install LinPEAS and WinPEAS
git clone https://github.com/carlospolop/PEASS-ng.git

# Install PowerSploit
git clone https://github.com/PowerShellMafia/PowerSploit.git

# Install Nishang
git clone https://github.com/samratashok/nishang.git

# Install privilege escalation awesome scripts
git clone https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite.git

# Install PayloadsAllTheThings
git clone https://github.com/swisskyrepo/PayloadsAllTheThings.git

echo "[*] Configuring Metasploit..."
msfdb init
systemctl enable postgresql
systemctl start postgresql

echo "[*] Configuring VIM..."
cat > ~/.vimrc << 'VIMRC'
syntax on
set number
set tabstop=4
set shiftwidth=4
set expandtab
set autoindent
VIMRC

echo "[*] Configuring Bash aliases..."
cat >> ~/.bashrc << 'ALIASES'

# Custom aliases
alias ll='ls -alh'
alias update='sudo apt update && sudo apt upgrade -y'
alias ports='netstat -tulanp'
alias myip='curl ifconfig.me'
alias serve='python3 -m http.server 8000'

# Pentesting shortcuts
alias nse='ls /usr/share/nmap/scripts/'
alias web='cd ~/engagements/web'
alias network='cd ~/engagements/network'
alias ad='cd ~/engagements/activedirectory'
ALIASES

echo "[*] Installing Oh My Zsh..."
sh -c "$(curl -fsSL https://raw.github.com/ohmyzsh/ohmyzsh/master/tools/install.sh)"

echo "[+] Kali setup complete!"
echo "[+] Reboot recommended"
```

---

## Hardware & Device Arsenal

### Essential Hardware (From Your Notion)

#### All-In-One (AIO) Devices
```
FlipperZero
├── RFID/NFC cloning
├── Sub-GHz radio
├── IR transmitter
├── BadUSB
├── GPIO for hardware hacking
└── U2F authentication

WiFi Pineapple (Hak5)
├── Rogue AP creation
├── Man-in-the-middle
├── Credential harvesting
├── Deauth attacks
└── Network reconnaissance
```

#### Network Devices
- **WiFi Pineapple** - Rogue access point
- **LAN Turtle** - Network implant
- **Packet Squirrel** - Packet capture device
- **Shark Jack** - Network reconnaissance
- **ThrowingStars** - LAN tap

#### RF Devices
- **HackRF One** - Software Defined Radio
- **RTL-SDR** - Cheap SDR receiver
- **Ubertooth One** - Bluetooth sniffing
- **YardStick One** - Sub-GHz transceiver
- **Proxmark3** - RFID/NFC research

#### USB Devices
- **Rubber Ducky** - Keystroke injection
- **Bash Bunny** - Multi-function attack tool
- **O.MG Cable** - Malicious USB cable
- **USB Killer** - Hardware destruction device

#### WiFi & Network Devices
- **Alfa AWUS036ACH** - High-power WiFi adapter
- **TP-Link TL-WN722N** - Monitor mode WiFi
- **Panda PAU09** - Budget WiFi adapter

---

## Anonymity & Privacy Protection

### VPN Setup (No-Logging Providers)

#### Recommended VPNs:
1. **Mullvad VPN**
   - Anonymous signup (no email required)
   - Accept cryptocurrency
   - Open source clients
   - No logs policy

```bash
# Install Mullvad on Linux
wget https://mullvad.net/download/app/deb/latest
sudo apt install ./mullvad-vpn_*_amd64.deb

# Connect
mullvad connect

# Check status
mullvad status
```

2. **ProtonVPN**
   - Based in Switzerland
   - Secure Core servers
   - Free tier available

3. **IVPN**
   - Anonymous accounts
   - Multi-hop connections
   - Open source

### Tor Setup

```bash
# Install Tor
apt install tor torbrowser-launcher

# Configure Tor system-wide
cat >> /etc/tor/torrc << 'TORRC'
SOCKSPort 9050
ControlPort 9051
CookieAuthentication 1
TORRC

# Start Tor service
systemctl start tor
systemctl enable tor

# Use proxychains with Tor
echo "socks5 127.0.0.1 9050" >> /etc/proxychains4.conf

# Test
proxychains4 curl https://check.torproject.org/api/ip
```

### MAC Address Randomization

```bash
#!/bin/bash
# Randomize MAC address

INTERFACE="wlan0"  # Change to your interface

# Take interface down
ip link set dev $INTERFACE down

# Generate random MAC
NEW_MAC=$(openssl rand -hex 6 | sed 's/\(..\)/\1:/g; s/.$//')

# Set new MAC
ip link set dev $INTERFACE address $NEW_MAC

# Bring interface up
ip link set dev $INTERFACE up

echo "[+] MAC address changed to: $NEW_MAC"
```

---

# OSINT MASTERY

## Comprehensive OSINT Resources

### OSINT Methodology (From Your Notion)

```
Phase 1: Requirement Definition
└── What information do we need?
    ├── Person identification
    ├── Infrastructure mapping
    ├── Organizational structure
    └── Digital footprint

Phase 2: Collection
└── Passive information gathering
    ├── Search engines
    ├── Social media
    ├── Public records
    └── Domain/IP intelligence

Phase 3: Processing
└── Organize and structure data
    ├── Timeline creation
    ├── Relationship mapping
    ├── Data validation
    └── Pattern identification

Phase 4: Analysis
└── Extract meaningful intelligence
    ├── Link analysis
    ├── Geospatial analysis
    ├── Network analysis
    └── Behavioral patterns

Phase 5: Dissemination
└── Present findings
    ├── Executive summary
    ├── Detailed report
    ├── Visual diagrams (Maltego)
    └── Actionable intelligence
```

### OSINT VM Setup

```bash
#!/bin/bash
# Automated OSINT VM Setup

echo "[*] Installing OSINT tools..."

# Base tools
apt install -y \
    python3-pip \
    git \
    tor \
    torbrowser-launcher \
    exiftool \
    ffmpeg \
    tesseract-ocr \
    h tracking-cli \
    whois \
    dnsutils \
    curl \
    wget

# Python OSINT tools
pip3 install \
    theHarvester \
    sherlock-project \
    holehe \
    h8mail \
    phoneinfoga \
    toutatis \
    ghunt \
    socialscan \
    maigret \
    twint \
    instaloader

# Install Maltego Community Edition
wget https://maltego-downloads.s3.us-east-2.amazonaws.com/linux/Maltego.v4.X.X_linux.zip
unzip Maltego.v4.X.X_linux.zip
sudo ./install.sh

# Install SpiderFoot
git clone https://github.com/smicallef/spiderfoot.git
cd spiderfoot
pip3 install -r requirements.txt

# Install Recon-ng
git clone https://github.com/lanmaster53/recon-ng.git
cd recon-ng
pip3 install -r REQUIREMENTS

# Install OSRFramework
pip3 install osrframework

# Install Photon
git clone https://github.com/s0md3v/Photon.git
cd Photon
pip3 install -r requirements.txt

# Install subfinder
GO111MODULE=on go get -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder

# Install Amass
go install -v github.com/OWASP/Amass/v3/...@master

echo "[+] OSINT VM setup complete!"
```

## People Search & Identity Tracing

### Primary Resources (From Your Notion):

```python
#!/usr/bin/env python3
# people_search.py - Automated people search

import requests
from bs4 import BeautifulSoup
import json

SEARCH_ENGINES = {
    'pipl': 'https://pipl.com',
    'spokeo': 'https://www.spokeo.com',
    'truepeoplesearch': 'https://www.truepeoplesearch.com',
    'whitepages': 'https://www.whitepages.com',
    'fastpeoplesearch': 'https://www.fastpeoplesearch.com',
}

def search_person(name, location=None):
    """Search for person across multiple databases"""
    results = {}
    
    for engine, url in SEARCH_ENGINES.items():
        print(f"[*] Searching {engine}...")
        try:
            # Implement search logic per site
            # Note: Many sites require manual access or paid APIs
            results[engine] = search_engine(engine, name, location)
        except Exception as e:
            print(f"[-] Error with {engine}: {e}")
    
    return results

def generate_report(results, output_file='person_report.html'):
    """Generate HTML report of findings"""
    html = f"""
    <html>
    <head><title>Person Search Report</title></head>
    <body>
    <h1>Person Search Results</h1>
    <h2>Target: {results['name']}</h2>
    """
    
    for engine, data in results['searches'].items():
        html += f"<h3>{engine}</h3>"
        html += f"<pre>{json.dumps(data, indent=2)}</pre>"
    
    html += "</body></html>"
    
    with open(output_file, 'w') as f:
        f.write(html)
    
    print(f"[+] Report saved to {output_file}")

# Example usage
if __name__ == "__main__":
    target_name = "John Doe"
    target_location = "New York, NY"
    
    results = search_person(target_name, target_location)
    generate_report(results)
```

### Username OSINT

```bash
#!/bin/bash
# username_osint.sh - Search username across platforms

USERNAME=$1

if [ -z "$USERNAME" ]; then
    echo "Usage: $0 <username>"
    exit 1
fi

echo "[*] Searching for username: $USERNAME"

# Sherlock - username search
echo "[*] Running Sherlock..."
python3 ~/tools/sherlock/sherlock $USERNAME

# WhatsMyName
echo "[*] Running WhatsMyName..."
python3 ~/tools/whatsmyname/whatsmyname.py -u $USERNAME

# Maigret
echo "[*] Running Maigret..."
maigret $USERNAME

# Social Searcher
echo "[*] Checking Social Searcher..."
curl "https://www.social-searcher.com/search-users/?q=$USERNAME"

# Namechk
echo "[*] Checking Namechk..."
curl "https://namechk.com/$USERNAME"

echo "[+] Username OSINT complete!"
```
