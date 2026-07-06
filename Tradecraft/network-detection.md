# Network Detection & Packet Analysis - Deep Dive

> **Scope:** Network-based threat detection, packet capture and analysis, protocol anomaly detection, IDS/IPS tuning, traffic baselining, and network forensics methodology.

✅ **Related offensive-side checklists:** [Lateral Movement](../Checklists/Lateral-Movement.md) · [Command and Control](../Checklists/Command%26Control.md)

---

## Table of Contents

1. [Detection Architecture](#detection-architecture)
2. [Packet Capture Fundamentals](#packet-capture-fundamentals)
3. [Wireshark Analysis](#wireshark-analysis)
4. [tcpdump Field Reference](#tcpdump-field-reference)
5. [Zeek (Bro) for Detection](#zeek-bro-for-detection)
6. [Suricata IDS/IPS](#suricata-idsips)
7. [Protocol Anomaly Detection](#protocol-anomaly-detection)
8. [C2 Traffic Detection](#c2-traffic-detection)
9. [Lateral Movement Detection](#lateral-movement-detection)
10. [DNS-Based Detection](#dns-based-detection)
11. [Encrypted Traffic Analysis](#encrypted-traffic-analysis)
12. [Network Forensics](#network-forensics)
13. [Baselining & Anomaly Detection](#baselining--anomaly-detection)

---

## Detection Architecture

### Sensor Placement

```
Internet
    │
    ▼
[Edge Firewall / IDS Sensor A]   ← North/south traffic
    │
    ▼
[DMZ]
    │
    ▼
[Internal Firewall / IDS Sensor B]  ← DMZ-to-internal
    │
    ▼
[Core Switch SPAN Port / IDS Sensor C]  ← East/west (lateral movement)
    │
    ├──► [Server VLAN]
    ├──► [Workstation VLAN]
    └──► [OT/IoT VLAN]
```

**Capture methods:**

| Method | Pros | Cons |
|---|---|---|
| SPAN/mirror port | No inline risk, flexible | Can drop packets at high throughput |
| Network TAP | Hardware, lossless, passive | Physical install required |
| Inline IPS | Active blocking possible | Single point of failure risk |
| Agent-based (EDR) | Per-host visibility | Coverage gaps on unmanaged devices |
| NetFlow/IPFIX | Low overhead, scalable | No payload - metadata only |

### NSM Stack Components

```
Raw Packets → [Capture] → [Parser/Decoder] → [Detection Engine] → [Alert/Log]
                                │
                                └──► [PCAP Storage for Forensics]
                                └──► [Flow Records for Trending]
                                └──► [Protocol Logs (Zeek)]
```

Common stacks:
- **Security Onion** - Zeek + Suricata + Elasticsearch + Kibana (full NSM)
- **Zeek + ELK** - Custom deployment
- **Arkime (Moloch)** - Full packet capture + search
- **ntopng** - Flow analysis and visualization

---

## Packet Capture Fundamentals

### tcpdump Essentials

```bash
# Capture on interface, write to file
tcpdump -i eth0 -w capture.pcap

# Capture with timestamps, verbose, no DNS resolution
tcpdump -i eth0 -tttt -vv -n -w capture.pcap

# Capture specific host
tcpdump -i eth0 host 192.168.1.100 -w host.pcap

# Capture specific port
tcpdump -i eth0 port 443 -w tls.pcap

# Capture subnet
tcpdump -i eth0 net 192.168.1.0/24

# Capture traffic between two hosts
tcpdump -i eth0 host 192.168.1.10 and host 192.168.1.20

# Capture non-standard ports (suspicious outbound)
tcpdump -i eth0 'tcp and not port 80 and not port 443 and not port 22' -w suspicious.pcap

# Capture by TCP flags
tcpdump -i eth0 'tcp[tcpflags] & tcp-syn != 0'   # SYN packets
tcpdump -i eth0 'tcp[tcpflags] == tcp-rst'        # RST only

# Capture DNS
tcpdump -i eth0 port 53 -nn

# Rotate captures every 100MB
tcpdump -i eth0 -C 100 -w capture_%Y%m%d_%H%M%S.pcap

# Read and filter existing PCAP
tcpdump -r capture.pcap -n 'host 192.168.1.100 and port 443'
```

### tshark (CLI Wireshark)

```bash
# Display summary of packets
tshark -r capture.pcap

# Follow TCP stream
tshark -r capture.pcap -q -z follow,tcp,ascii,0

# Extract HTTP hosts
tshark -r capture.pcap -Y "http.request" -T fields -e http.host -e http.request.uri

# Extract DNS queries
tshark -r capture.pcap -Y "dns.flags.response == 0" -T fields -e dns.qry.name | sort | uniq -c | sort -rn

# Extract TLS SNI
tshark -r capture.pcap -Y "tls.handshake.type == 1" -T fields -e tls.handshake.extensions_server_name

# Export objects (HTTP files)
tshark -r capture.pcap --export-objects http,/tmp/extracted/

# Statistics: conversations
tshark -r capture.pcap -q -z conv,tcp

# Statistics: protocol hierarchy
tshark -r capture.pcap -q -z io,phs

# Filter and convert
tshark -r large.pcap -Y "ip.addr == 10.0.0.1" -w filtered.pcap
```

---

## Wireshark Analysis

### Essential Display Filters

```
# Basic host/port
ip.addr == 192.168.1.100
ip.src == 192.168.1.100
tcp.port == 4444
udp.port == 53

# TCP flags
tcp.flags.syn == 1 && tcp.flags.ack == 0   # SYN scan detection
tcp.flags.rst == 1                           # Connection resets
tcp.flags == 0x002                           # SYN only

# HTTP
http.request.method == "POST"
http.response.code == 200
http.host contains "suspicious"
http.user_agent contains "curl"

# DNS
dns.qry.name contains "evil"
dns.qry.type == 16                           # TXT records
dns.resp.len > 200                           # Unusually large DNS responses (DNS tunnel)

# TLS
tls.handshake.type == 1                      # ClientHello
tls.handshake.extensions_server_name contains "evil"
!tls && tcp.port == 443                      # Non-TLS on 443 (suspicious)

# SMB
smb2.cmd == 5                                # SMB2 Create (file open/create)
smb2.filename contains ".exe"

# Kerberos
kerberos.msg_type == 10                      # AS-REQ
kerberos.msg_type == 30                      # TGS-REQ (Kerberoasting)

# ICMP tunneling indicators
icmp && frame.len > 100                      # Unusually large ICMP (tunnel)

# Long connections (C2 beacons)
tcp.time_relative > 300 && tcp.len < 100     # Long idle connection with small data
```

### Wireshark Analysis Workflow

```
1. Protocol Hierarchy Statistics
   Statistics → Protocol Hierarchy
   → Identify unexpected protocols (IRC, Tor, non-standard high ports)

2. Conversations
   Statistics → Conversations → TCP/UDP/IP
   → Sort by bytes: find data exfiltration candidates
   → Sort by duration: find long-lived C2 connections

3. Endpoints
   Statistics → Endpoints
   → Identify unexpected external IPs

4. Follow TCP/UDP Stream
   Right-click packet → Follow → TCP Stream
   → Read full session content

5. Expert Info
   Analyze → Expert Information
   → Find anomalies: malformed packets, retransmissions, unusual sequences

6. IO Graph
   Statistics → IO Graph
   → Visualize traffic patterns, identify beacon timing
```

---

## Zeek (Bro) for Detection

Zeek generates high-fidelity protocol logs from network traffic - far more useful than raw PCAPs for detection at scale.

### Key Log Files

| Log | Contents |
|---|---|
| `conn.log` | All connections: src/dst IP, port, bytes, duration, state |
| `dns.log` | DNS queries and responses |
| `http.log` | HTTP requests: method, host, URI, user-agent, response code |
| `ssl.log` | TLS metadata: SNI, issuer, JA3/JA3S fingerprints |
| `files.log` | Files transferred: MD5/SHA1/SHA256, MIME type |
| `x509.log` | Certificate details |
| `smtp.log` | Email metadata |
| `notice.log` | Zeek-generated alerts |
| `weird.log` | Protocol anomalies |
| `dpd.log` | Dynamic Protocol Detection - protocol mismatches |

### Zeek Log Analysis with zeek-cut

```bash
# Extract columns from Zeek logs
cat conn.log | zeek-cut id.orig_h id.resp_h id.resp_p proto bytes duration

# Find long-duration, low-byte connections (C2 heartbeat)
cat conn.log | zeek-cut duration orig_bytes resp_bytes id.orig_h id.resp_h id.resp_p \
  | awk '$1 > 300 && $2 < 1000 {print}' | sort -rn

# Find connections to new/rare IPs
cat conn.log | zeek-cut id.resp_h | sort | uniq -c | sort -n | head -20

# DNS: find high-volume query sources
cat dns.log | zeek-cut id.orig_h query | sort | uniq -c | sort -rn | head -20

# DNS: find long domain names (DGA or DNS tunnel)
cat dns.log | zeek-cut query | awk 'length($0) > 50' | sort | uniq

# HTTP: find non-browser user agents
cat http.log | zeek-cut id.orig_h user_agent uri | grep -v "Mozilla" | head -20

# TLS: extract JA3 fingerprints
cat ssl.log | zeek-cut id.orig_h id.resp_h server_name ja3 ja3s | head -20

# Files: find executables downloaded
cat files.log | zeek-cut mime_type sha256 filename tx_hosts \
  | grep -i "application/x-dosexec\|application/x-executable"
```

### Zeek Detection Scripts

```zeek
# Detect long-duration, low-data connections (C2 beacon indicator)
event connection_state_remove(c: connection) {
    if (c$duration > 5 min && c$orig$size < 10000 && c$resp$size < 10000) {
        NOTICE([$note=Notice::Weird,
                $msg=fmt("Possible C2 beacon: %s -> %s:%s duration=%s",
                    c$id$orig_h, c$id$resp_h, c$id$resp_p, c$duration),
                $conn=c]);
    }
}

# Detect DNS over non-standard port
event new_connection(c: connection) {
    if (c$id$resp_p == 53/tcp || c$id$resp_p == 53/udp) {
        if (c$id$resp_h !in Site::local_nets) {
            NOTICE([$note=Notice::Weird,
                    $msg=fmt("DNS to external server: %s", c$id$resp_h),
                    $conn=c]);
        }
    }
}
```

### JA3 / JA3S Fingerprinting

JA3 fingerprints TLS ClientHello; JA3S fingerprints the ServerHello. Useful for identifying malware families regardless of C2 IP/domain rotation.

```bash
# Extract JA3 from PCAP
ja3 -a capture.pcap

# Look up known malicious JA3 hashes
# https://sslbl.abuse.ch/ja3-fingerprints/
# https://github.com/salesforce/ja3

# Common malicious JA3 hashes:
# 51c64c77e60f3980eea90869b68c58a8 - Metasploit/Meterpreter
# 6734f37431670b3ab4292b8f60f29984 - CobaltStrike default
# a0e9f5d64349fb13191bc781f81f42e1 - Emotet

# Search in Zeek ssl.log
cat ssl.log | zeek-cut ja3 id.orig_h server_name | grep "6734f37431670b3ab4292b8f60f29984"
```

---

## Suricata IDS/IPS

### Rule Structure

```
action proto src_ip src_port direction dst_ip dst_port (options)

# Example rules:

# Detect Cobalt Strike default stager request
alert http $HOME_NET any -> $EXTERNAL_NET any (
    msg:"CS Default Stager URI";
    flow:established,to_server;
    http.uri;
    content:"/ca";
    depth:3;
    http.user_agent;
    content:"Mozilla/5.0 (compatible\; MSIE 9.0\; Windows NT 6.1\; WOW64\; Trident/5.0\; BOIE9\;ENUS)";
    classtype:trojan-activity;
    sid:9000001;
    rev:1;
)

# Detect DNS TXT record response (potential DNS tunnel)
alert dns any any -> any any (
    msg:"Large DNS TXT Response - Possible Tunnel";
    dns.query;
    pcre:"/\.(onion|bit|bazar|coin|lib|emc|cyb|fur|bbs|geek)$/i";
    classtype:policy-violation;
    sid:9000002;
    rev:1;
)

# Detect PowerShell download cradle
alert http $HOME_NET any -> $EXTERNAL_NET any (
    msg:"PowerShell Download Cradle";
    flow:established,to_server;
    http.user_agent;
    content:"PowerShell";
    nocase;
    classtype:trojan-activity;
    sid:9000003;
    rev:1;
)
```

### Rule Management

```bash
# Update Suricata rules
suricata-update

# List available rule sources
suricata-update list-sources

# Enable specific sources
suricata-update enable-source et/open        # Emerging Threats (free)
suricata-update enable-source et/pro         # Emerging Threats Pro
suricata-update enable-source abuse.ch/sslbl # SSL Blacklist

# Test rules against PCAP
suricata -r capture.pcap -l /tmp/logs/ -c /etc/suricata/suricata.yaml

# Test rule syntax
suricata --engine-analysis -c /etc/suricata/suricata.yaml
```

### Performance Tuning

```yaml
# /etc/suricata/suricata.yaml key settings

# Set home network
vars:
  address-groups:
    HOME_NET: "[10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16]"

# Threading
threading:
  set-cpu-affinity: yes
  cpu-affinity:
    - management-cpu-set:
        cpu: [0]
    - worker-cpu-set:
        cpu: ["all"]

# AF-Packet (high-performance capture)
af-packet:
  - interface: eth0
    cluster-id: 99
    cluster-type: cluster_flow
    defrag: yes
    use-mmap: yes
    ring-size: 200000
```

---

## Protocol Anomaly Detection

### HTTP Anomalies

```bash
# Non-standard user agents
cat http.log | zeek-cut user_agent | sort | uniq -c | sort -rn
# Alert: curl, python-requests, Go-http-client, empty UA

# Unusually large POST bodies (data staging/exfil)
cat http.log | zeek-cut method request_body_len id.orig_h uri \
  | awk '$1 == "POST" && $2 > 1000000 {print}'

# HTTP to non-80/443 ports
cat conn.log | zeek-cut service id.resp_p id.orig_h id.resp_h \
  | awk '$1 == "http" && $2 != 80 && $2 != 8080 {print}'

# Beacon-like regular intervals
# Analyze conn.log with Python to detect low standard deviation in intervals
python3 analyze_beacon.py --log conn.log --threshold 0.1
```

### SMB Anomalies

```bash
# SMB lateral movement indicators
# Zeek smb_files.log
cat smb_files.log | zeek-cut id.orig_h id.resp_h name action \
  | grep -i "\.exe\|\.dll\|\.ps1\|\.bat"

# SMB login attempts (password spray)
cat smb_mapping.log | zeek-cut id.orig_h id.resp_h path \
  | sort | uniq -c | sort -rn

# Admin share access
cat smb_mapping.log | zeek-cut path | grep -i "admin\$\|c\$\|ipc\$"
```

### Kerberos Anomalies

```bash
# Kerberoasting: TGS-REQ for RC4-encrypted service tickets
# Look for encryption type 23 (RC4-HMAC) in TGS-REQ
cat kerberos.log | zeek-cut id.orig_h request_type cipher service \
  | awk '$2 == "TGS" && $3 == "rc4-hmac" {print}'

# AS-REP Roasting: AS-REQ without pre-auth
cat kerberos.log | zeek-cut id.orig_h request_type error_msg \
  | awk '$2 == "AS" && $3 == "KDC_ERR_PREAUTH_REQUIRED" {print}'

# Golden Ticket: Kerberos ticket with unusually long validity
# Detect via Windows Event ID 4769 + ticket options analysis
```

---

## C2 Traffic Detection

### Beacon Interval Analysis

```python
#!/usr/bin/env python3
"""
Detect beaconing behavior from Zeek conn.log
Looks for connections with low jitter (consistent interval)
"""
import sys
from collections import defaultdict
import statistics

connections = defaultdict(list)

with open('conn.log') as f:
    for line in f:
        if line.startswith('#'):
            continue
        fields = line.strip().split('\t')
        if len(fields) < 5:
            continue
        ts, src, dst, dport = float(fields[0]), fields[2], fields[4], fields[5]
        key = (src, dst, dport)
        connections[key].append(ts)

# Analyze intervals
for (src, dst, dport), timestamps in connections.items():
    if len(timestamps) < 10:  # Need enough data points
        continue
    
    timestamps.sort()
    intervals = [timestamps[i+1] - timestamps[i] for i in range(len(timestamps)-1)]
    
    mean_interval = statistics.mean(intervals)
    stdev_interval = statistics.stdev(intervals) if len(intervals) > 1 else 0
    jitter_ratio = stdev_interval / mean_interval if mean_interval > 0 else 0
    
    # Low jitter + regular interval = potential beacon
    if jitter_ratio < 0.15 and 30 < mean_interval < 3600 and len(timestamps) > 15:
        print(f"[BEACON?] {src} -> {dst}:{dport} | "
              f"interval={mean_interval:.1f}s | jitter={jitter_ratio:.3f} | "
              f"count={len(timestamps)}")
```

### Domain Generation Algorithm (DGA) Detection

```python
#!/usr/bin/env python3
"""
Simple DGA domain detection using entropy and n-gram analysis
"""
import math
from collections import Counter

def calculate_entropy(domain):
    """Shannon entropy of domain string"""
    if not domain:
        return 0
    counter = Counter(domain)
    length = len(domain)
    return -sum((count/length) * math.log2(count/length) 
                for count in counter.values())

def is_dga_candidate(domain):
    """Heuristic DGA detection"""
    parts = domain.split('.')
    if len(parts) < 2:
        return False
    
    label = parts[0]  # Check leftmost label
    
    # DGA indicators:
    # 1. High entropy (random-looking)
    entropy = calculate_entropy(label)
    if entropy > 3.5:
        return True
    
    # 2. Unusual length (DGA often 10-25 chars)
    if 10 <= len(label) <= 25:
        # 3. High consonant ratio
        consonants = sum(1 for c in label.lower() if c in 'bcdfghjklmnpqrstvwxyz')
        if consonants / len(label) > 0.7:
            return True
    
    return False

# Process Zeek DNS log
with open('dns.log') as f:
    for line in f:
        if line.startswith('#'):
            continue
        fields = line.strip().split('\t')
        if len(fields) < 9:
            continue
        query = fields[9]
        if is_dga_candidate(query):
            print(f"[DGA?] {query}")
```

---

## Lateral Movement Detection

### Network Indicators

```bash
# Detect port scanning (many connections to many ports)
cat conn.log | zeek-cut id.orig_h id.resp_h id.resp_p conn_state \
  | awk '$4 == "REJ" || $4 == "S0"' \
  | awk '{print $1" "$2}' | sort | uniq -c | sort -rn | head -20

# Detect SMB spread (one host connecting to many via SMB)
cat conn.log | zeek-cut id.orig_h id.resp_h id.resp_p \
  | awk '$3 == 445' \
  | awk '{print $1" "$2}' | sort -u \
  | awk '{print $1}' | sort | uniq -c | sort -rn

# WMI lateral movement (DCOM port 135 + dynamic high ports)
cat conn.log | zeek-cut id.orig_h id.resp_h id.resp_p service \
  | awk '$3 == 135 || ($3 > 49152 && $4 == "dce_rpc")'
```

### Windows Event Log Correlation

```powershell
# Detect pass-the-hash (NTLM logon type 3 from workstation to workstation)
Get-WinEvent -LogName Security -FilterXPath `
  "*[System[EventID=4624] and EventData[Data[@Name='LogonType']='3'] and EventData[Data[@Name='AuthenticationPackageName']='NTLM']]" |
  Where-Object { $_.Properties[18].Value -notlike '*$' } |
  Select-Object TimeCreated, @{n='Source';e={$_.Properties[19].Value}},
                @{n='TargetUser';e={$_.Properties[5].Value}}

# Detect service installation on remote host (PsExec indicator)
Get-WinEvent -ComputerName TARGET -LogName System -FilterXPath `
  "*[System[EventID=7045]]" |
  Select-Object TimeCreated, @{n='ServiceName';e={$_.Properties[0].Value}},
                @{n='ServiceFile';e={$_.Properties[1].Value}}
```

---

## DNS-Based Detection

### DNS Tunneling Detection

DNS tunneling encodes data in DNS queries/responses to exfiltrate data or establish C2 over DNS.

```bash
# High-frequency queries to single domain (tunnel indicator)
cat dns.log | zeek-cut query id.orig_h \
  | awk '{print $2" "$1}' | sort | uniq -c \
  | awk '{print $1" "$2" "$3}' | sort -rn | head -20

# Long subdomain labels (data encoded in subdomain)
cat dns.log | zeek-cut query \
  | awk -F. '{if(length($1) > 30) print}' | sort | uniq

# High entropy subdomains (random-looking = encoded data)
cat dns.log | zeek-cut query | python3 -c "
import sys, math
from collections import Counter

for line in sys.stdin:
    domain = line.strip()
    sub = domain.split('.')[0]
    if len(sub) < 8:
        continue
    counts = Counter(sub)
    entropy = -sum((v/len(sub)) * math.log2(v/len(sub)) for v in counts.values())
    if entropy > 3.8:
        print(f'{entropy:.2f} {domain}')
"

# DNS query type distribution anomalies
cat dns.log | zeek-cut qtype_name | sort | uniq -c | sort -rn
# Alert: unusually high NULL, TXT, or MX query counts
```

### DNS RPZ (Blocking at Resolver)

```bash
# Configure Response Policy Zone in Unbound/BIND
# Block known malicious domains via threat intel feed

# Unbound RPZ integration
# /etc/unbound/unbound.conf
rpz:
    name: "rpz.local"
    zonefile: "/etc/unbound/rpz.zone"
    rpz-log: yes

# Generate RPZ zone from Abuse.ch feed
curl -s https://urlhaus.abuse.ch/downloads/rpz/ > /etc/unbound/rpz.zone
unbound-control reload
```

---

## Encrypted Traffic Analysis

Even without decryption, encrypted traffic metadata reveals a lot.

### TLS Metadata Analysis

```bash
# Certificate validity - self-signed or very short validity (C2 indicator)
cat x509.log | zeek-cut id certificate.subject certificate.issuer certificate.not_valid_after \
  | awk '$2 == $3 {print "[SELF-SIGNED]", $1, $2}'

# Certificates issued minutes/hours ago (fresh C2 infra)
cat x509.log | zeek-cut certificate.not_valid_before id \
  | sort | tail -n 20

# Look for C2-typical certificate patterns
# C2 certs often have:
#   - Generic CN (mail.microsoft.com, update.windows.com - lookalikes)
#   - Issued by Let's Encrypt to newly registered domain
#   - Short validity (90 day LE certs are normal, but combined with other IOCs...)
cat ssl.log | zeek-cut id.resp_h server_name issuer \
  | grep "Let's Encrypt" | head -20
```

### Traffic Volume Fingerprinting

```bash
# Even without payload, packet sizes reveal protocol
# SSH: 64-1500 byte packets in regular patterns
# HTTPS: variable, bursty
# C2 beacon: small consistent check-ins, larger response bursts

# Extract packet size distribution per flow
tshark -r capture.pcap -T fields -e ip.src -e ip.dst -e tcp.dstport -e frame.len \
  | awk '{print $1"->"$2":"$3, $4}' | sort
```

---

## Network Forensics

### Incident Response Packet Capture

```bash
# Capture traffic from suspected compromised host
tcpdump -i eth0 host SUSPECT_IP -w /evidence/suspect_$(date +%Y%m%d_%H%M%S).pcap

# Capture all traffic (ring buffer - last 10GB retained)
tcpdump -i eth0 -C 1000 -W 10 -w /evidence/ring_capture_%Y%m%d_%H%M%S.pcap

# Extract all files from HTTP traffic
tcpflow -r capture.pcap -o /evidence/extracted/ -e httpbody

# Reconstruct TCP sessions
tcpflow -r capture.pcap -o /evidence/sessions/ 'host SUSPECT_IP'
```

### PCAP Analysis Workflow (Incident)

```
1. Frame overview
   tshark -r capture.pcap -q -z io,phs

2. Identify all communicating hosts
   tshark -r capture.pcap -q -z conv,ip | sort -k1 -rn | head -30

3. Extract all DNS queries
   tshark -r capture.pcap -Y "dns.flags.response == 0" -T fields -e dns.qry.name | sort -u

4. Extract all HTTP hosts + URIs
   tshark -r capture.pcap -Y "http.request" -T fields -e http.host -e http.request.uri

5. Extract all TLS SNI
   tshark -r capture.pcap -Y "tls.handshake.type==1" -T fields -e tls.handshake.extensions_server_name | sort -u

6. Identify data exfiltration candidates
   tshark -r capture.pcap -q -z conv,tcp | awk '$7 > 1000000' | sort -k7 -rn

7. Extract files
   tshark -r capture.pcap --export-objects http,/tmp/files/
   tshark -r capture.pcap --export-objects smb,/tmp/smb_files/

8. Hash extracted files
   sha256sum /tmp/files/* | tee /evidence/file_hashes.txt

9. Submit hashes to VirusTotal
   while read hash file; do vt file $hash; done < /evidence/file_hashes.txt
```

### Arkime (Full PCAP Search)

```bash
# Arkime provides indexed full-packet search at scale

# Search queries in Arkime UI:
ip.src == 192.168.1.100
http.uri == "/malicious/path"
tls.ja3 == "6734f37431670b3ab4292b8f60f29984"
dns.query == "evil.domain.com"
port.dst == 4444

# Export PCAP from Arkime for specific session
# Via API
curl "http://arkime:8005/api/session/SESSIONID/pcap" -o session.pcap
```

---

## Baselining & Anomaly Detection

### Establish Normal Behavior

```bash
# Baseline: which external IPs does each internal host talk to?
cat conn.log | zeek-cut id.orig_h id.resp_h \
  | awk '!($2 ~ /^(10\.|172\.(1[6-9]|2[0-9]|3[0-1])\.|192\.168\.)/)' \
  | sort | uniq > baseline_external_connections.txt

# Baseline: normal ports in use
cat conn.log | zeek-cut id.resp_p service | sort | uniq -c | sort -rn > baseline_ports.txt

# Baseline: DNS resolvers used
cat dns.log | zeek-cut id.resp_h | sort | uniq -c | sort -rn
# Alert on non-standard resolvers (8.8.8.8 from internal hosts = DNS bypass)

# Baseline: normal process network connections (via EDR telemetry)
# Look for new/unusual processes making network connections
```

### Statistical Anomaly Detection

```python
#!/usr/bin/env python3
"""
Flag hosts with connection counts outside 3 standard deviations
from the daily baseline
"""
import statistics
from collections import Counter

# Load today's connection counts per source IP
with open('conn.log') as f:
    src_ips = [line.split('\t')[2] for line in f if not line.startswith('#')]

today_counts = Counter(src_ips)

# Compare against baseline (load from database or previous period)
# baseline_mean and baseline_stdev would come from historical data
baseline_mean = 500
baseline_stdev = 150
threshold = baseline_mean + (3 * baseline_stdev)

for ip, count in today_counts.most_common():
    if count > threshold:
        print(f"[ANOMALY] {ip}: {count} connections (threshold: {threshold:.0f})")
```

---

## Windows-Native Network Detection Tools

The sections above are Linux/NSM-stack heavy. This section covers the native Windows toolset - what you use when you're on a Windows endpoint or domain without a full Security Onion deployment.

### Netsh - Built-in Packet Capture

`netsh trace` is a built-in Windows packet capture mechanism, no install required. Output is `.etl` format, convertible to PCAP.

```powershell
# Start a capture - no third-party tools needed
netsh trace start capture=yes tracefile=C:\Temp\capture.etl maxsize=500 overwrite=yes

# Capture filtered to specific IP
netsh trace start capture=yes IPv4.Address=192.168.1.100 tracefile=C:\Temp\host_capture.etl

# Capture on specific interface
netsh trace start capture=yes CaptureInterface="Ethernet" tracefile=C:\Temp\eth_capture.etl

# Stop capture
netsh trace stop

# Convert .etl to .pcap for Wireshark analysis
# Method 1: etl2pcapng (Microsoft tool)
etl2pcapng.exe capture.etl capture.pcap

# Method 2: pktmon (Windows 10 2004+ built-in)
pktmon start --capture --file C:\Temp\pktmon.etl
pktmon stop
pktmon etl2pcap C:\Temp\pktmon.etl --out C:\Temp\capture.pcap
```

### pktmon - Windows Packet Monitor

`pktmon` is built into Windows 10 (2004+) and Windows Server 2019+. More capable than netsh trace for live filtering.

```powershell
# List network components (adapters, switches, filters)
pktmon list

# Capture all traffic
pktmon start --capture

# Filter to specific port (e.g., catch C2 on unusual port)
pktmon filter add -p 4444
pktmon filter add -p 8080
pktmon start --capture

# Filter to specific IP
pktmon filter add -i 192.168.1.100
pktmon start --capture

# Real-time display (like tcpdump on Windows)
pktmon start --capture --pkt-size 0 --log-mode real-time

# Stop and convert
pktmon stop
pktmon etl2pcap pktmon.etl --out capture.pcap
pktmon etl2txt pktmon.etl          # Human-readable text output

# Show current filters
pktmon filter list

# Clear filters
pktmon filter remove
```

### TCPView - Live Connection Monitoring

Sysinternals TCPView shows all active TCP/UDP connections with the owning process - essential for spotting C2 beacons in real time.

```powershell
# Install via winget
winget install Microsoft.Sysinternals.TCPView

# Or download directly from Sysinternals Live
\\live.sysinternals.com\tools\tcpview.exe

# What to look for:
# - Processes making unexpected outbound connections
# - ESTABLISHED connections to unusual ports (4444, 8080, 8443, etc.)
# - Processes with LISTEN on unexpected ports (backdoor listener)
# - svchost.exe connecting to non-Microsoft IPs
# - Short-lived connections at regular intervals (beacon pattern)
```

### Defender for Endpoint - Network Telemetry (KQL)

Microsoft Defender for Endpoint captures network events per-process. Hunt via the Advanced Hunting console in the M365 Defender portal.

```kusto
// Find processes making connections to unusual ports
DeviceNetworkEvents
| where Timestamp > ago(24h)
| where RemotePort !in (80, 443, 53, 8080, 8443)
| where InitiatingProcessFileName !in~ ("svchost.exe", "lsass.exe", "services.exe")
| summarize count(), RemotePorts=make_set(RemotePort) by
    DeviceName, InitiatingProcessFileName, RemoteIP
| where count_ > 5
| order by count_ desc

// Hunt for beacon timing - low jitter regular connections
DeviceNetworkEvents
| where Timestamp > ago(1h)
| where ActionType == "ConnectionSuccess"
| summarize
    ConnectionCount = count(),
    FirstSeen = min(Timestamp),
    LastSeen = max(Timestamp)
    by DeviceName, InitiatingProcessFileName, RemoteIP, RemotePort
| extend DurationMinutes = datetime_diff('minute', LastSeen, FirstSeen)
| extend ConnectionsPerMinute = ConnectionCount * 1.0 / DurationMinutes
| where ConnectionCount > 10 and DurationMinutes > 5
| where ConnectionsPerMinute between (0.5 .. 5.0)   // 1 connection per 12-120 sec = beacon range
| order by ConnectionCount desc

// Find DNS queries to high-entropy / DGA-like domains
DeviceEvents
| where ActionType == "DnsQueryResponse"
| extend DnsQuery = tostring(AdditionalFields.DnsQueryString)
| where strlen(DnsQuery) > 30
| where DnsQuery !contains "microsoft" and DnsQuery !contains "windows"
| summarize QueryCount=count() by DeviceName, DnsQuery, InitiatingProcessFileName
| order by QueryCount desc

// Find processes with unusual network + process injection combo
DeviceEvents
| where ActionType == "CreateRemoteThreadApiCall"
| join kind=inner (
    DeviceNetworkEvents
    | where RemotePort !in (80, 443)
) on $left.InitiatingProcessId == $right.InitiatingProcessId
| project Timestamp, DeviceName, InitiatingProcessFileName,
          TargetProcessFileName=tostring(AdditionalFields.TargetProcessName),
          RemoteIP, RemotePort
```

### Windows Firewall Logging

Windows Firewall can log all allowed/blocked connections natively - lightweight and always available.

```powershell
# Enable firewall logging for both profiles
netsh advfirewall set currentprofile logging filename "C:\Windows\System32\LogFiles\Firewall\pfirewall.log"
netsh advfirewall set currentprofile logging maxfilesize 32768
netsh advfirewall set currentprofile logging droppedconnections enable
netsh advfirewall set currentprofile logging allowedconnections enable

# View the log (tab-delimited)
Get-Content "C:\Windows\System32\LogFiles\Firewall\pfirewall.log" |
    Select-Object -Skip 3 |
    ConvertFrom-Csv -Delimiter ' ' -Header date,time,action,protocol,src-ip,dst-ip,src-port,dst-port,size,tcpflags,tcpsyn,tcpack,tcpwin,icmptype,icmpcode,info,path |
    Where-Object { $_.action -eq "ALLOW" -and $_.dst-port -notin @("80","443","53") } |
    Select-Object time,protocol,'src-ip','dst-ip','src-port','dst-port' |
    Format-Table -AutoSize

# Firewall log fields:
# date time action protocol src-ip dst-ip src-port dst-port size ...
# ALLOW = connection permitted
# DROP  = connection blocked
```

### NetworkMiner (Windows/Linux) - PCAP File Analysis

NetworkMiner reconstructs sessions from PCAP files and extracts files, credentials, and hostnames. Runs on Windows natively; also works on Linux via Mono.

```powershell
# Windows - download from https://www.netresec.com/?page=NetworkMiner
# Open PCAP file → automatically:
#   - Reconstructs TCP sessions
#   - Extracts transferred files (HTTP downloads, SMB transfers)
#   - Identifies hosts by OS fingerprint
#   - Extracts credentials from cleartext protocols
#   - Lists all DNS queries and responses

# Linux install (via Mono)
sudo apt install mono-complete
wget https://www.netresec.com/?download=NetworkMiner -O NetworkMiner.zip
unzip NetworkMiner.zip
mono NetworkMiner.exe
```

### Event Tracing for Windows (ETW) - Direct Consumer

Beyond what EDRs collect, you can subscribe to ETW providers directly for custom detection pipelines on Windows.

```powershell
# List all available ETW providers
logman query providers | Select-String "Network\|DNS\|Firewall\|TCP"

# Key providers for network detection:
# Microsoft-Windows-TCPIP                    - TCP/IP stack events
# Microsoft-Windows-DNS-Client               - DNS query/response events
# Microsoft-Windows-Windows Firewall With Advanced Security - FW events
# Microsoft-Windows-WebIO                    - WinHTTP/WinInet requests
# Microsoft-Windows-WinRM                    - WinRM lateral movement
# Microsoft-Windows-SMBClient/Operational    - SMB client activity
# Microsoft-Windows-SMBServer/Operational    - SMB server activity

# Enable DNS debug log (captures all DNS queries on the system)
# On DNS Server role:
Set-DnsServerDiagnostics -All $true
# Log location: C:\Windows\System32\dns\dns.log

# Enable DNS client event log (all clients)
wevtutil sl Microsoft-Windows-DNS-Client/Operational /e:true

# Read DNS client events
Get-WinEvent -LogName "Microsoft-Windows-DNS-Client/Operational" |
    Select-Object TimeCreated,
        @{n='Query';e={$_.Properties[0].Value}},
        @{n='Result';e={$_.Properties[2].Value}} |
    Where-Object { $_.Query -ne "" } |
    Sort-Object TimeCreated -Descending |
    Format-Table -AutoSize
```

### Sysmon Network Events

Sysmon Event ID 3 captures every TCP/UDP connection with process context. Far more useful than raw firewall logs for correlation.

```xml
<!-- Sysmon config for network event capture -->
<!-- Add to your sysmon config XML under EventFiltering -->

<!-- Event 3: Network connections - capture outbound, filter noise -->
<NetworkConnect onmatch="exclude">
    <!-- Exclude known-good system processes -->
    <Image condition="is">C:\Windows\System32\svchost.exe</Image>
    <DestinationPort condition="is">443</DestinationPort>
    <!-- Add your own exclusions for known-good apps -->
</NetworkConnect>

<!-- Capture DNS queries via Event 22 -->
<DnsQuery onmatch="include">
    <QueryName condition="contains">.</QueryName>  <!-- all queries -->
</DnsQuery>
```

```powershell
# Hunt Sysmon network events via PowerShell
Get-WinEvent -LogName "Microsoft-Windows-Sysmon/Operational" -FilterXPath `
    "*[System[EventID=3] and EventData[Data[@Name='DestinationPort']!='443' and Data[@Name='DestinationPort']!='80']]" |
    ForEach-Object {
        [PSCustomObject]@{
            Time    = $_.TimeCreated
            Process = $_.Properties[4].Value
            DstIP   = $_.Properties[14].Value
            DstPort = $_.Properties[15].Value
        }
    } | Format-Table -AutoSize

# Hunt DNS events (Sysmon Event 22)
Get-WinEvent -LogName "Microsoft-Windows-Sysmon/Operational" -FilterXPath `
    "*[System[EventID=22]]" |
    ForEach-Object {
        [PSCustomObject]@{
            Time    = $_.TimeCreated
            Process = $_.Properties[4].Value
            Query   = $_.Properties[0].Value
            Result  = $_.Properties[1].Value
        }
    } | Where-Object { $_.Query.Length -gt 40 } |   # long domains = DGA/tunnel
    Format-Table -AutoSize
```

### Tool Platform Summary

| Tool | Windows | Linux | Best For |
|---|---|---|---|
| **Wireshark** | ✅ GUI installer | ✅ `apt install wireshark` | Interactive PCAP analysis |
| **tshark** | ✅ bundled with Wireshark | ✅ `apt install tshark` | CLI PCAP analysis, scripting |
| **tcpdump** | ❌ (use pktmon) | ✅ native | Live capture, scripting |
| **pktmon** | ✅ built-in (Win10 2004+) | ❌ | Windows live capture, no install |
| **netsh trace** | ✅ built-in | ❌ | Windows capture, always available |
| **NetworkMiner** | ✅ native | ✅ via Mono | PCAP session reconstruction |
| **TCPView** | ✅ Sysinternals | ❌ (use ss/netstat) | Live connection monitoring |
| **Zeek** | ✅ (limited) | ✅ primary platform | Protocol log generation |
| **Suricata** | ✅ installer | ✅ `apt install suricata` | IDS/IPS rules engine |
| **Security Onion** | ❌ | ✅ dedicated distro | Full NSM stack |
| **Arkime** | ❌ | ✅ Linux server | Full packet search at scale |
| **ntopng** | ✅ installer | ✅ packages available | Flow analysis dashboard |
| **ja3** | ✅ Python/pip | ✅ Python/pip | TLS fingerprinting |

---

## References

- [Security Onion Documentation](https://docs.securityonion.net/)
- [Zeek Documentation](https://docs.zeek.org/)
- [Suricata Documentation](https://suricata.readthedocs.io/)
- [Emerging Threats Rules](https://rules.emergingthreats.net/)
- [SANS Network Forensics Cheat Sheet](https://www.sans.org/blog/tools-for-network-forensics/)
- [Arkime (Moloch)](https://arkime.com/)
- [JA3 Fingerprints Database](https://sslbl.abuse.ch/ja3-fingerprints/)
- [MITRE ATT&CK: Exfiltration Over C2](https://attack.mitre.org/tactics/TA0010/)
- [Wireshark Display Filter Reference](https://www.wireshark.org/docs/dfref/)
- [pktmon Documentation (Microsoft)](https://docs.microsoft.com/en-us/windows-server/networking/technologies/pktmon/pktmon)
- [NetworkMiner](https://www.netresec.com/?page=NetworkMiner)
- [Sysmon Network Events - SwiftOnSecurity config](https://github.com/SwiftOnSecurity/sysmon-config)
- [Microsoft Defender for Endpoint Advanced Hunting](https://docs.microsoft.com/en-us/microsoft-365/security/defender-endpoint/advanced-hunting-overview)
- [etl2pcapng](https://github.com/microsoft/etl2pcapng)
