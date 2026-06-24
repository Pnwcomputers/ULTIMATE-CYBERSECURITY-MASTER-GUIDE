# 📊 Log Aggregation & Visibility Guide

**Effective incident response begins long before an incident occurs.** This guide covers establishing the logging infrastructure and visibility required to detect, investigate, and respond to security events. Without proper log aggregation, you're flying blind.

This guide focuses on configuring critical log sources to feed into your SIEM (Wazuh, ELK Stack, Splunk, or similar).

---

## 🎯 Why Log Aggregation Matters

| Without Centralized Logging | With Centralized Logging |
|-----------------------------|--------------------------|
| Logs scattered across devices | Single pane of glass visibility |
| Manual correlation required | Automated correlation and alerting |
| Evidence lost due to rotation | Long-term retention and searchability |
| Attackers can clear local logs | Tamper-resistant central storage |
| Reactive incident discovery | Proactive threat detection |

---

## 📋 Required Log Sources Overview

| Source | Log Type | What We're Looking For |
|--------|----------|------------------------|
| Wireless IDS (Kismet/Zeek) | alert / wireless | New BSSID broadcasting known SSID; Deauthentication frames; Signal strength anomalies |
| DHCP Server | dhcpd / leases | New MAC addresses; Suspicious hostnames (e.g., `kali-linux`, `parrot`) |
| RADIUS / NAC | auth.log | Failed authentication attempts; MAC spoofing alerts; Policy violations |
| Network Switches | SNMP / Syslog | Port status changes; Port security violations; Unknown MACs |
| Firewalls | traffic / threat | Denied connections; IPS alerts; Geo-anomalies |
| DNS Servers | query logs | Unusual queries; Known-bad domains; High-entropy names (DGA) |
| Active Directory | Security Event Log | Authentication events; Group changes; Privilege escalation |
| Endpoints (Sysmon) | Sysmon Operational | Process creation; Network connections; File/Registry changes |

---

## 🏗️ Part 1: Architecture Overview

### Typical Log Flow

```
┌─────────────────┐     ┌─────────────────┐     ┌─────────────────┐
│   Log Sources   │────▶│   Aggregation   │────▶│      SIEM       │
│                 │     │     Layer       │     │                 │
│ • Switches      │     │                 │     │ • Wazuh         │
│ • Firewalls     │     │ • Rsyslog       │     │ • ELK Stack     │
│ • DHCP/DNS      │     │ • Logstash      │     │ • Splunk        │
│ • Wireless IDS  │     │ • Filebeat      │     │ • Graylog       │
│ • Endpoints     │     │ • Fluentd       │     │                 │
└─────────────────┘     └─────────────────┘     └─────────────────┘
```

### Network Considerations

| Component | Recommended Placement |
|-----------|----------------------|
| SIEM Server | Management VLAN, isolated segment |
| Log Collectors | Each network segment/site |
| Listening Stations | Strategic locations (wireless coverage) |

### Port Requirements

| Protocol | Port | Purpose |
|----------|------|---------|
| Syslog (UDP) | 514 | Traditional syslog |
| Syslog (TCP) | 514 | Reliable syslog |
| Syslog (TLS) | 6514 | Encrypted syslog |
| Beats | 5044 | Filebeat/Winlogbeat to Logstash |
| Wazuh Agent | 1514 | Agent to Manager |
| SNMP Traps | 162 | Network device alerts |

---

## 📡 Part 2: Wireless IDS (Kismet)

Kismet provides passive wireless monitoring to detect rogue access points, deauthentication attacks, and unauthorized devices.

### Deployment Scenario

A Raspberry Pi running Kismet positioned to monitor your wireless environment, forwarding alerts to your SIEM.

### Hardware Requirements

| Component | Specification |
|-----------|---------------|
| Device | Raspberry Pi 4 (2GB+ RAM) |
| WiFi Adapter | Monitor mode capable (Alfa AWUS036ACH recommended) |
| Storage | 32GB+ SD card |
| Power | PoE HAT or standard power supply |

### Step 2.1: Install Kismet on Raspberry Pi

```bash
# Update system
sudo apt update && sudo apt upgrade -y

# Add Kismet repository
wget -O - https://www.kismetwireless.net/repos/kismet-release.gpg.key | sudo apt-key add -
echo "deb https://www.kismetwireless.net/repos/apt/release/$(lsb_release -cs) $(lsb_release -cs) main" | sudo tee /etc/apt/sources.list.d/kismet.list

# Install Kismet
sudo apt update
sudo apt install -y kismet

# Add user to kismet group
sudo usermod -aG kismet $USER
```

### Step 2.2: Configure Kismet

Edit `/etc/kismet/kismet.conf`:

```ini
# Define the wireless interface (replace wlan1 with your monitor-capable interface)
source=wlan1:name=MonitorStation

# Enable logging
log_prefix=/var/log/kismet/
log_types=kismet,pcapng,alert

# Alert configuration
alertbacklog=50

# Enable alert logging
alert=ADHOCCONFLICT
alert=APSPOOF
alert=BSSTIMESTAMP
alert=CHANCHANGE
alert=DEAUTHFLOOD
alert=DISASSOCTRAFFIC
alert=LONGSSID
alert=LUCENTTEST
alert=MABORANGE
alert=NETSTUMBLER
alert=NULLPROBERESP
alert=PROBENOJOIN
```

### Step 2.3: Configure Kismet Alert Forwarding

Create `/etc/kismet/kismet_alerts.conf`:

```ini
# Forward alerts to syslog
alertsyslog=true
alertsyslogfacility=local5
```

### Step 2.4: Forward Kismet Alerts via Rsyslog

Create `/etc/rsyslog.d/60-kismet.conf`:

```bash
# Forward Kismet alerts to SIEM
local5.* @192.168.1.50:514
```

Restart services:

```bash
sudo systemctl restart rsyslog
sudo systemctl enable kismet
sudo systemctl start kismet
```

### Step 2.5: Create Kismet Systemd Service

Create `/etc/systemd/system/kismet.service`:

```ini
[Unit]
Description=Kismet Wireless IDS
After=network.target

[Service]
Type=simple
User=kismet
ExecStart=/usr/bin/kismet --no-ncurses
Restart=on-failure
RestartSec=10

[Install]
WantedBy=multi-user.target
```

Enable the service:

```bash
sudo systemctl daemon-reload
sudo systemctl enable kismet
sudo systemctl start kismet
```

### Key Kismet Alerts to Monitor

| Alert | Indication |
|-------|------------|
| `APSPOOF` | Possible Evil Twin / Rogue AP |
| `DEAUTHFLOOD` | Deauthentication attack in progress |
| `BSSTIMESTAMP` | AP impersonation attempt |
| `CHANCHANGE` | Unexpected channel hopping |
| `ADHOCCONFLICT` | Possible ad-hoc network attack |

---

## 🌐 Part 3: DHCP Server Logging

DHCP logs reveal new devices joining the network and can identify suspicious hostnames commonly used by penetration testing distributions.

### ISC DHCP Server (Linux)

#### Step 3.1: Enable Verbose Logging

Edit `/etc/dhcp/dhcpd.conf`:

```conf
# Enable verbose logging
log-facility local7;

# Example subnet configuration
subnet 192.168.1.0 netmask 255.255.255.0 {
    range 192.168.1.100 192.168.1.200;
    option routers 192.168.1.1;
    option domain-name-servers 192.168.1.10;
}
```

#### Step 3.2: Configure Rsyslog for DHCP

Create `/etc/rsyslog.d/50-dhcpd.conf`:

```bash
# Log DHCP locally and forward to SIEM
local7.* /var/log/dhcpd.log
local7.* @192.168.1.50:514
```

Restart services:

```bash
sudo systemctl restart rsyslog
sudo systemctl restart isc-dhcp-server
```

### Windows DHCP Server

#### Enable DHCP Audit Logging

```powershell
# Enable audit logging via PowerShell
Set-DhcpServerAuditLog -Enable $true -Path "C:\Windows\System32\dhcp"

# Or via DHCP Management Console:
# Right-click server → Properties → General → Enable DHCP audit logging
```

#### Forward Windows DHCP Logs

Option 1: Use Wazuh Agent with the following in `ossec.conf`:

```xml
<localfile>
    <location>C:\Windows\System32\dhcp\DhcpSrvLog-*.log</location>
    <log_format>syslog</log_format>
</localfile>
```

Option 2: Use NXLog to forward:

```conf
<Input dhcp_logs>
    Module im_file
    File "C:\\Windows\\System32\\dhcp\\DhcpSrvLog-*.log"
</Input>

<Output siem>
    Module om_udp
    Host 192.168.1.50
    Port 514
</Output>

<Route dhcp_to_siem>
    Path dhcp_logs => siem
</Route>
```

### Suspicious DHCP Hostnames to Alert On

Create detection rules for these common penetration testing hostnames:

| Pattern | Indication |
|---------|------------|
| `kali*` | Kali Linux |
| `parrot*` | Parrot Security OS |
| `blackarch*` | BlackArch Linux |
| `pentoo*` | Pentoo Linux |
| `commando*` | Commando VM |
| `flare*` | FLARE VM |
| `remnux*` | REMnux |
| `attack*` | Generic attack system |

---

## 🔐 Part 4: RADIUS / NAC Logging

RADIUS logs provide authentication visibility and can detect MAC spoofing and unauthorized access attempts.

### FreeRADIUS Configuration

#### Step 4.1: Enable Detailed Logging

Edit `/etc/freeradius/3.0/radiusd.conf`:

```conf
log {
    destination = syslog
    syslog_facility = local6
    
    # Enable detailed logging
    auth = yes
    auth_badpass = yes
    auth_goodpass = no
    
    # Log failed authentications with reason
    msg_denied = "Access denied for user %{User-Name}"
}
```

#### Step 4.2: Configure Syslog Forwarding

Create `/etc/rsyslog.d/55-radius.conf`:

```bash
# RADIUS logs to SIEM
local6.* /var/log/radius/radius.log
local6.* @192.168.1.50:514
```

Restart services:

```bash
sudo systemctl restart rsyslog
sudo systemctl restart freeradius
```

### Cisco ISE Syslog Configuration

Configure remote syslog targets via the ISE admin console:

1. Navigate to **Administration → System → Logging → Remote Logging Targets**
2. Add your SIEM server IP and port
3. Configure log categories:
   - Failed Attempts
   - Passed Authentications
   - RADIUS Diagnostics
   - Posture and Client Provisioning

### Windows NPS (Network Policy Server)

#### Enable NPS Logging

```powershell
# Enable SQL or text-based logging
Set-NpsAccountingConfiguration -LogAccountingPackets $true -LogAuthenticationPackets $true

# Configure log location
Set-NpsAccountingConfiguration -LogFileFolder "C:\Windows\System32\LogFiles\NPS"
```

#### Forward NPS Logs

Add to Wazuh agent `ossec.conf`:

```xml
<localfile>
    <location>C:\Windows\System32\LogFiles\NPS\IN*.log</location>
    <log_format>syslog</log_format>
</localfile>
```

### Key RADIUS Events to Monitor

| Event | Indication |
|-------|------------|
| Multiple failed auths (same MAC) | Brute force attempt |
| Successful auth after failures | Possible credential compromise |
| MAC not in database | Unknown device |
| MAC/User mismatch | Potential MAC spoofing |
| Auth from unusual location | Lateral movement |

---

## 🔌 Part 5: Network Switch Logging

Switch logs provide visibility into physical network changes, port security violations, and potential unauthorized device connections.

### Cisco IOS Configuration

```cisco
! Configure logging buffer
logging buffered 64000 informational

! Configure syslog server
logging host 192.168.1.50 transport udp port 514
logging facility local4
logging source-interface Vlan10

! Enable port security logging
interface range GigabitEthernet0/1-24
    switchport port-security
    switchport port-security maximum 2
    switchport port-security violation restrict
    switchport port-security aging time 60

! Enable SNMP traps
snmp-server enable traps port-security
snmp-server enable traps link-status
snmp-server host 192.168.1.50 version 2c public

! Log link status changes
interface range GigabitEthernet0/1-24
    logging event link-status
```

### HP/Aruba ProCurve Configuration

```
; Configure syslog
logging 192.168.1.50
logging facility local4
logging severity info

; Enable SNMP traps
snmp-server host 192.168.1.50 community "public" trap-level all

; Port security
port-security 1-24 learn-mode static
port-security 1-24 action send-alarm
```

### Juniper EX Series Configuration

```junos
set system syslog host 192.168.1.50 any info
set system syslog host 192.168.1.50 facility-override local4

set ethernet-switching-options secure-access-port interface ge-0/0/1 mac-limit 2
set ethernet-switching-options secure-access-port interface ge-0/0/1 mac-limit action log
```

### Key Switch Events to Monitor

| Event | OID/Log Message | Indication |
|-------|-----------------|------------|
| Port Security Violation | `PSECURE_VIOLATION` | Unknown MAC on secured port |
| Link Up/Down | `IF-MIB::linkDown` | Physical connection change |
| MAC Move | `MACMOVE-6-NOTIF` | Device moved between ports |
| STP Topology Change | `STP-4-TOPO_CHANGE` | Network topology change |
| VLAN Change | `VLAN_CREATE/DELETE` | VLAN configuration change |

---

## 🔥 Part 6: Firewall Logging

Firewall logs provide perimeter visibility and are essential for detecting external attacks and data exfiltration.

### pfSense / OPNsense

#### Configure Remote Syslog

Navigate to **Status → System Logs → Settings**:

| Setting | Value |
|---------|-------|
| Remote log servers | `192.168.1.50:514` |
| Remote Syslog Contents | Firewall Events, DHCP, DNS, System |
| Log Firewall Default Blocks | Enabled |

Or via shell:

```bash
# Edit /etc/syslog.conf
*.* @192.168.1.50:514
```

### iptables/nftables (Linux)

#### Enable Logging for Dropped Packets

```bash
# iptables - Log dropped packets
iptables -A INPUT -j LOG --log-prefix "IPTables-Dropped: " --log-level 4
iptables -A INPUT -j DROP

# nftables equivalent
nft add rule inet filter input counter log prefix \"nftables-drop: \" drop
```

#### Configure Rsyslog for Firewall Logs

Create `/etc/rsyslog.d/60-firewall.conf`:

```bash
:msg, contains, "IPTables-Dropped:" /var/log/firewall.log
:msg, contains, "IPTables-Dropped:" @192.168.1.50:514
```

### Windows Firewall

#### Enable Firewall Logging

```powershell
# Enable logging for dropped and successful connections
Set-NetFirewallProfile -Profile Domain,Public,Private -LogBlocked True -LogAllowed True -LogFileName "%systemroot%\system32\LogFiles\Firewall\pfirewall.log" -LogMaxSizeKilobytes 32768
```

#### Forward via Wazuh Agent

Add to `ossec.conf`:

```xml
<localfile>
    <location>C:\Windows\System32\LogFiles\Firewall\pfirewall.log</location>
    <log_format>syslog</log_format>
</localfile>
```

---

## 🖥️ Part 7: DNS Server Logging

DNS logs reveal malicious domain lookups, C2 communication, and data exfiltration via DNS tunneling.

### BIND DNS Server

#### Enable Query Logging

Edit `/etc/bind/named.conf.options`:

```conf
logging {
    channel query_log {
        file "/var/log/bind/query.log" versions 3 size 50m;
        severity info;
        print-time yes;
        print-category yes;
        print-severity yes;
    };
    
    channel security_log {
        file "/var/log/bind/security.log" versions 3 size 50m;
        severity dynamic;
        print-time yes;
    };
    
    category queries { query_log; };
    category security { security_log; };
};
```

#### Forward DNS Logs via Rsyslog

Create `/etc/rsyslog.d/55-dns.conf`:

```bash
# DNS query logs
module(load="imfile")
input(type="imfile" File="/var/log/bind/query.log" Tag="dns-query" Facility="local3")

local3.* @192.168.1.50:514
```

### Windows DNS Server

#### Enable DNS Debug Logging

```powershell
# Enable DNS debug logging
Set-DnsServerDiagnostics -All $true -EnableLoggingForLocalLookupEvent $true -EnableLoggingForPluginDllEvent $true -EnableLoggingForRecursiveLookupEvent $true -EnableLoggingForRemoteServerEvent $true -EnableLoggingForServerStartStopEvent $true -EnableLoggingForTombstoneEvent $true -EnableLoggingForZoneDataWriteEvent $true -EnableLoggingForZoneLoadingEvent $true

# Or enable analytical logging
Set-DnsServerDiagnostics -EnableLoggingForPluginDllEvent $true
```

#### Forward via Wazuh

Add to `ossec.conf`:

```xml
<localfile>
    <location>Microsoft-Windows-DNSServer/Analytical</location>
    <log_format>eventchannel</log_format>
</localfile>
```

### Suspicious DNS Patterns to Alert On

| Pattern | Indication |
|---------|------------|
| High-entropy subdomains | DNS tunneling / DGA |
| TXT record queries to unusual domains | C2 communication |
| Queries to known-bad domains | Malware callback |
| High query volume from single host | DNS exfiltration |
| Queries for `.onion`, `.bit` | Tor/alternative DNS |

---

## 🔄 Part 8: Central Rsyslog Server Configuration

Set up a central rsyslog server to receive logs from all sources before forwarding to your SIEM.

### Step 8.1: Install Rsyslog

```bash
sudo apt update
sudo apt install -y rsyslog rsyslog-gnutls
```

### Step 8.2: Configure Rsyslog to Receive Remote Logs

Edit `/etc/rsyslog.conf`:

```bash
# Load required modules
module(load="imudp")
module(load="imtcp")
module(load="imfile")

# UDP listener on 514
input(type="imudp" port="514")

# TCP listener on 514
input(type="imtcp" port="514")

# TLS listener on 6514 (optional, for secure transport)
# Requires certificate configuration
```

### Step 8.3: Create Log Sorting Rules

Create `/etc/rsyslog.d/10-remote-logs.conf`:

```bash
# Template for log file naming
template(name="RemoteLogs" type="string" string="/var/log/remote/%HOSTNAME%/%PROGRAMNAME%.log")

# Sort incoming logs by source
if $fromhost-ip != '127.0.0.1' then {
    action(type="omfile" dynaFile="RemoteLogs")
}

# Forward everything to SIEM (Wazuh example)
*.* action(type="omfwd" target="192.168.1.50" port="514" protocol="tcp")
```

### Step 8.4: Configure Log Rotation

Create `/etc/logrotate.d/remote-logs`:

```
/var/log/remote/*/*.log {
    daily
    rotate 30
    compress
    delaycompress
    missingok
    notifempty
    create 0640 syslog adm
    sharedscripts
    postrotate
        /usr/lib/rsyslog/rsyslog-rotate
    endscript
}
```

### Step 8.5: Start and Enable Rsyslog

```bash
sudo systemctl restart rsyslog
sudo systemctl enable rsyslog

# Verify listening
sudo ss -tulnp | grep 514
```

---

## 📈 Part 9: SIEM-Specific Configuration

### Wazuh Manager

Wazuh natively supports syslog input. Verify the configuration in `/var/ossec/etc/ossec.conf`:

```xml
<ossec_config>
    <remote>
        <connection>syslog</connection>
        <port>514</port>
        <protocol>udp</protocol>
        <allowed-ips>192.168.1.0/24</allowed-ips>
    </remote>
</ossec_config>
```

Restart the manager:

```bash
sudo systemctl restart wazuh-manager
```

### ELK Stack (Logstash)

Create `/etc/logstash/conf.d/01-syslog-input.conf`:

```ruby
input {
    syslog {
        port => 514
        type => "syslog"
    }
}

filter {
    if [type] == "syslog" {
        grok {
            match => { "message" => "%{SYSLOGTIMESTAMP:syslog_timestamp} %{SYSLOGHOST:syslog_hostname} %{DATA:syslog_program}(?:\[%{POSINT:syslog_pid}\])?: %{GREEDYDATA:syslog_message}" }
        }
        date {
            match => [ "syslog_timestamp", "MMM  d HH:mm:ss", "MMM dd HH:mm:ss" ]
        }
    }
}

output {
    elasticsearch {
        hosts => ["localhost:9200"]
        index => "syslog-%{+YYYY.MM.dd}"
    }
}
```

### Splunk

Configure a syslog input in `inputs.conf`:

```ini
[udp://514]
connection_host = dns
sourcetype = syslog
index = network

[tcp://514]
connection_host = dns
sourcetype = syslog
index = network
```

### Graylog

Configure a Syslog UDP input via the web interface:

1. Navigate to **System → Inputs**
2. Select **Syslog UDP** from the dropdown
3. Configure:
   - Bind address: `0.0.0.0`
   - Port: `514`
   - Store full message: Yes

---

## ✅ Part 10: Verification and Testing

### Verify Log Flow

#### Test Syslog from Linux Host

```bash
# Send a test message
logger -n 192.168.1.50 -P 514 "Test log message from $(hostname)"
```

#### Test from Network Device

```cisco
! Cisco IOS
send log "Test message from switch"
```

#### Check Reception on Central Server

```bash
# Watch incoming logs
tail -f /var/log/remote/*/*.log

# Check for specific source
grep "Test" /var/log/syslog
```

### Verify SIEM Ingestion

#### Wazuh

```bash
# Check Wazuh logs
tail -f /var/ossec/logs/ossec.log

# Search for recent events
/var/ossec/bin/wazuh-logtest
```

#### ELK Stack

```bash
# Query Elasticsearch
curl -X GET "localhost:9200/syslog-*/_search?q=*&size=10&pretty"
```

### End-to-End Test Script

Create `test-log-flow.sh`:

```bash
#!/bin/bash
SIEM_IP="192.168.1.50"
TIMESTAMP=$(date +%Y%m%d%H%M%S)
TEST_MSG="LOG_FLOW_TEST_$TIMESTAMP"

echo "Sending test message: $TEST_MSG"
logger -n $SIEM_IP -P 514 "$TEST_MSG"

echo "Waiting 10 seconds for processing..."
sleep 10

echo "Check your SIEM for message containing: $TEST_MSG"
```

---

## ❗ Part 11: Troubleshooting

### Logs Not Arriving

**Check network connectivity:**
```bash
nc -zvu 192.168.1.50 514
telnet 192.168.1.50 514
```

**Verify firewall rules:**
```bash
# On SIEM server
sudo ufw status
sudo iptables -L -n | grep 514
```

**Check rsyslog is listening:**
```bash
sudo ss -tulnp | grep rsyslog
```

**Review rsyslog errors:**
```bash
sudo journalctl -u rsyslog -f
```

### High Log Volume Issues

**Identify top talkers:**
```bash
# Count logs by source
cat /var/log/syslog | awk '{print $4}' | sort | uniq -c | sort -rn | head -20
```

**Rate limit noisy sources:**
```bash
# In rsyslog.conf
if $fromhost-ip == '192.168.1.100' then {
    action(type="omfile" file="/var/log/noisy-host.log")
    stop
}
```

### Log Parsing Failures

**Test log format:**
```bash
# Wazuh log testing
/var/ossec/bin/wazuh-logtest < sample-log.txt

# Logstash testing
/usr/share/logstash/bin/logstash -e 'input { stdin {} } output { stdout { codec => rubydebug } }' < sample-log.txt
```

### Time Synchronization Issues

Ensure all devices use NTP:

```bash
# Check NTP status
timedatectl status

# Configure NTP
sudo timedatectl set-ntp true
```

On network devices:
```cisco
! Cisco IOS
ntp server 192.168.1.10
clock timezone EST -5
service timestamps log datetime msec localtime show-timezone
```

---

## 🛡️ Part 12: Security Considerations

### Encrypt Log Transport

Configure TLS for rsyslog:

**On the server** (`/etc/rsyslog.d/tls.conf`):

```bash
# Load TLS module
module(load="imtcp" StreamDriver.Name="gtls" StreamDriver.Mode="1" StreamDriver.Authmode="anon")

# TLS certificates
global(
    DefaultNetstreamDriver="gtls"
    DefaultNetstreamDriverCAFile="/etc/rsyslog-certs/ca.pem"
    DefaultNetstreamDriverCertFile="/etc/rsyslog-certs/server-cert.pem"
    DefaultNetstreamDriverKeyFile="/etc/rsyslog-certs/server-key.pem"
)

# TLS listener
input(type="imtcp" port="6514" StreamDriver.Mode="1" StreamDriver.Authmode="anon")
```

**On clients** (`/etc/rsyslog.d/tls-client.conf`):

```bash
global(
    DefaultNetstreamDriver="gtls"
    DefaultNetstreamDriverCAFile="/etc/rsyslog-certs/ca.pem"
)

action(type="omfwd" target="192.168.1.50" port="6514" protocol="tcp" StreamDriver="gtls" StreamDriverMode="1" StreamDriverAuthMode="anon")
```

### Protect Log Integrity

**Immutable logs:**
```bash
# Set immutable attribute on log files
sudo chattr +a /var/log/remote/*/*.log
```

**Centralized storage with write-once capability:**
Consider forwarding to a dedicated log storage system with WORM (Write Once Read Many) capability.

### Access Control

Restrict access to log servers and files:

```bash
# Restrict log directory permissions
sudo chmod 750 /var/log/remote
sudo chown syslog:adm /var/log/remote
```

---

## 📚 Additional Resources

- [Rsyslog Documentation](https://www.rsyslog.com/doc/)
- [Wazuh Log Collection](https://documentation.wazuh.com/current/user-manual/capabilities/log-data-collection/)
- [Elastic Common Schema](https://www.elastic.co/guide/en/ecs/current/index.html)
- [SANS Log Management Cheat Sheet](https://www.sans.org/posters/log-management-cheat-sheet/)

---

## 🗂️ Quick Reference

### Log Source Summary

| Source | Port | Protocol | Facility |
|--------|------|----------|----------|
| Kismet (Wireless IDS) | 514 | UDP/TCP | local5 |
| DHCP Server | 514 | UDP/TCP | local7 |
| RADIUS | 514 | UDP/TCP | local6 |
| Network Switches | 514 | UDP/TCP | local4 |
| Firewalls | 514 | UDP/TCP | local0 |
| DNS Servers | 514 | UDP/TCP | local3 |

### Rsyslog Quick Commands

| Command | Purpose |
|---------|---------|
| `systemctl restart rsyslog` | Restart rsyslog service |
| `rsyslogd -N1` | Check configuration syntax |
| `logger -n <IP> -P 514 "test"` | Send test message |
| `tcpdump -i eth0 port 514` | Capture syslog traffic |

### Verification Checklist

- [ ] All log sources configured with remote syslog
- [ ] Central rsyslog server receiving logs
- [ ] Logs forwarding to SIEM
- [ ] Parsing rules validated
- [ ] Time synchronization confirmed
- [ ] Log retention policy implemented
- [ ] Alerting rules configured
- [ ] TLS encryption enabled (if required)

---

*Part of the Incident Response & Log Aggregation Branch*
