# 🔷 Splunk SIEM Deployment Guide

**Splunk** is a powerful commercial platform for log aggregation, search, and security analytics. While enterprise licensing can be costly, Splunk offers a **Free** tier (500 MB/day indexing) and **Enterprise Trial** (60 days, full features) that are perfect for homelabs, training, and small deployments.

This guide covers deploying Splunk Enterprise, configuring inputs, installing the Universal Forwarder on endpoints, and setting up security monitoring.

---

## 🎯 Splunk Editions Comparison

| Feature | Splunk Free | Enterprise Trial | Enterprise |
|---------|-------------|------------------|------------|
| Daily Index Volume | 500 MB | Unlimited | Licensed |
| Duration | Perpetual | 60 days | Licensed |
| Alerting | ❌ | ✅ | ✅ |
| User Authentication | ❌ | ✅ | ✅ |
| Clustering | ❌ | ✅ | ✅ |
| Apps/Add-ons | Limited | ✅ | ✅ |
| Support | Community | Trial | Licensed |

> **Tip:** For a homelab SIEM, the Free tier is often sufficient. Start with the Enterprise Trial to explore all features, then convert to Free if you don't need alerting.

---

## 📋 Prerequisites

### Server Requirements

| Component | Minimum | Recommended |
|-----------|---------|-------------|
| OS | Ubuntu 20.04/22.04, RHEL 8/9 | Ubuntu 22.04 LTS |
| RAM | 4 GB | 8 GB+ |
| CPU | 2 vCPUs | 4 vCPUs |
| Storage | 50 GB | 200 GB+ SSD |

### Network Requirements

| Port | Purpose |
|------|---------|
| 8000 | Splunk Web UI |
| 8089 | Splunk Management/REST API |
| 9997 | Forwarder receiving (indexer) |
| 8088 | HTTP Event Collector (HEC) |
| 514 | Syslog (if configured) |

### Account Requirements

Create a free Splunk account at [splunk.com](https://www.splunk.com/) to download software.

---

## 🛠️ Part 1: Server Preparation

### Step 1.1: Update System

```bash
sudo apt update && sudo apt upgrade -y
```

### Step 1.2: Configure System Limits

Splunk requires increased file descriptor limits:

```bash
# Add limits for splunk user
cat << 'EOF' | sudo tee -a /etc/security/limits.conf
splunk soft nofile 65535
splunk hard nofile 65535
splunk soft nproc 20480
splunk hard nproc 20480
EOF

# Disable THP (Transparent Huge Pages)
echo 'never' | sudo tee /sys/kernel/mm/transparent_hugepage/enabled
echo 'never' | sudo tee /sys/kernel/mm/transparent_hugepage/defrag

# Make THP change persistent
cat << 'EOF' | sudo tee /etc/rc.local
#!/bin/bash
echo 'never' > /sys/kernel/mm/transparent_hugepage/enabled
echo 'never' > /sys/kernel/mm/transparent_hugepage/defrag
exit 0
EOF
sudo chmod +x /etc/rc.local
```

### Step 1.3: Create Splunk User

```bash
# Create dedicated user
sudo useradd -m -s /bin/bash splunk

# Create installation directory
sudo mkdir -p /opt/splunk
sudo chown splunk:splunk /opt/splunk
```

---

## 🚀 Part 2: Splunk Enterprise Installation

### Method 1: Manual Installation (Recommended)

#### Step 2.1: Download Splunk

1. Go to [splunk.com/download](https://www.splunk.com/en_us/download/splunk-enterprise.html)
2. Select **Linux** → **.deb** (for Ubuntu) or **.rpm** (for RHEL)
3. Download the package

Or via wget (replace with current version):

```bash
# Download Splunk (check website for latest URL)
cd /tmp
wget -O splunk-9.2.0-linux-2.6-amd64.deb "https://download.splunk.com/products/splunk/releases/9.2.0/linux/splunk-9.2.0-linux-2.6-amd64.deb"
```

#### Step 2.2: Install Splunk

**Debian/Ubuntu:**

```bash
sudo dpkg -i /tmp/splunk-*.deb
```

**RHEL/CentOS:**

```bash
sudo rpm -i /tmp/splunk-*.rpm
```

#### Step 2.3: Set Ownership

```bash
sudo chown -R splunk:splunk /opt/splunk
```

#### Step 2.4: Initial Start and Configuration

```bash
# Start Splunk and accept license
sudo -u splunk /opt/splunk/bin/splunk start --accept-license

# You'll be prompted to create admin credentials
# Username: admin
# Password: <your-strong-password>
```

#### Step 2.5: Enable Boot Start

```bash
# Enable systemd service
sudo /opt/splunk/bin/splunk enable boot-start -user splunk -systemd-managed 1

# Verify service
sudo systemctl status Splunkd
```

### Method 2: Docker Installation

Create `docker-compose.yml`:

```yaml
version: '3.8'

services:
  splunk:
    image: splunk/splunk:latest
    container_name: splunk
    environment:
      - SPLUNK_START_ARGS=--accept-license
      - SPLUNK_PASSWORD=YourStrongPassword123!
      - SPLUNK_LICENSE_URI=Free
    ports:
      - "8000:8000"
      - "8089:8089"
      - "9997:9997"
      - "8088:8088"
      - "514:514/udp"
    volumes:
      - splunk-var:/opt/splunk/var
      - splunk-etc:/opt/splunk/etc
    restart: unless-stopped

volumes:
  splunk-var:
  splunk-etc:
```

Start the container:

```bash
docker compose up -d
docker compose logs -f
```

### Step 2.6: Access Splunk Web

Open your browser:

```
http://<SERVER-IP>:8000
```

Login with the credentials you created during installation.

---

## 🔥 Part 3: Firewall Configuration

### UFW (Ubuntu)

```bash
sudo ufw allow 8000/tcp comment "Splunk Web UI"
sudo ufw allow 8089/tcp comment "Splunk Management"
sudo ufw allow 9997/tcp comment "Splunk Forwarder Receiving"
sudo ufw allow 8088/tcp comment "Splunk HEC"
sudo ufw allow 514/udp comment "Syslog"
sudo ufw reload
```

### Firewalld (RHEL/CentOS)

```bash
sudo firewall-cmd --permanent --add-port=8000/tcp
sudo firewall-cmd --permanent --add-port=8089/tcp
sudo firewall-cmd --permanent --add-port=9997/tcp
sudo firewall-cmd --permanent --add-port=8088/tcp
sudo firewall-cmd --permanent --add-port=514/udp
sudo firewall-cmd --reload
```

---

## 📥 Part 4: Configure Data Inputs

### Step 4.1: Enable Receiving (for Forwarders)

1. Navigate to **Settings → Forwarding and receiving**
2. Click **Configure receiving**
3. Click **New Receiving Port**
4. Enter port: `9997`
5. Click **Save**

Or via CLI:

```bash
sudo -u splunk /opt/splunk/bin/splunk enable listen 9997 -auth admin:YourPassword
```

### Step 4.2: Configure Syslog Input

**Via Web UI:**

1. Navigate to **Settings → Data inputs**
2. Click **UDP** → **New Local UDP**
3. Port: `514`
4. Source type: `syslog`
5. Index: `main` (or create a dedicated index)
6. Click **Next** → **Review** → **Submit**

**Via inputs.conf:**

Create `/opt/splunk/etc/system/local/inputs.conf`:

```ini
[udp://514]
connection_host = dns
sourcetype = syslog
index = main

[tcp://514]
connection_host = dns
sourcetype = syslog
index = main
```

Restart Splunk:

```bash
sudo systemctl restart Splunkd
```

### Step 4.3: Enable HTTP Event Collector (HEC)

HEC allows applications to send data via HTTP/HTTPS.

1. Navigate to **Settings → Data inputs**
2. Click **HTTP Event Collector**
3. Click **Global Settings**
4. Set **All Tokens** to **Enabled**
5. Click **Save**
6. Click **New Token**
7. Name: `default-hec-token`
8. Click **Next** → Select indexes → **Review** → **Submit**
9. Copy the generated token

---

## 📊 Part 5: Create Indexes

Organize your data with dedicated indexes.

### Via Web UI

1. Navigate to **Settings → Indexes**
2. Click **New Index**
3. Configure:
   - Index Name: `windows`
   - Max Size: `50 GB`
   - Retention: `30 days`
4. Click **Save**

Create these recommended indexes:

| Index Name | Purpose |
|------------|---------|
| `windows` | Windows Event Logs |
| `linux` | Linux system logs |
| `network` | Firewall, switch, router logs |
| `sysmon` | Sysmon events |
| `dns` | DNS query logs |
| `web` | Web server access logs |

### Via CLI

```bash
sudo -u splunk /opt/splunk/bin/splunk add index windows -maxDataSize auto_high_volume -auth admin:YourPassword
sudo -u splunk /opt/splunk/bin/splunk add index linux -auth admin:YourPassword
sudo -u splunk /opt/splunk/bin/splunk add index network -auth admin:YourPassword
sudo -u splunk /opt/splunk/bin/splunk add index sysmon -auth admin:YourPassword
```

---

## 🖥️ Part 6: Windows Universal Forwarder Deployment

The Splunk Universal Forwarder (UF) is a lightweight agent that ships logs to Splunk.

### Step 6.1: Download Universal Forwarder

Download from [splunk.com/download/universal-forwarder](https://www.splunk.com/en_us/download/universal-forwarder.html)

Or via PowerShell:

```powershell
# Download (check website for current version)
$url = "https://download.splunk.com/products/universalforwarder/releases/9.2.0/windows/splunkforwarder-9.2.0-x64-release.msi"
Invoke-WebRequest -Uri $url -OutFile "$env:TEMP\splunkforwarder.msi"
```

### Step 6.2: Install with Configuration

**Interactive Installation:**

```powershell
Start-Process msiexec.exe -ArgumentList "/i $env:TEMP\splunkforwarder.msi AGREETOLICENSE=Yes /quiet" -Wait
```

**Silent Installation with Pre-configuration:**

```powershell
# Install with deployment server or direct indexer configuration
$msiArgs = @(
    "/i"
    "$env:TEMP\splunkforwarder.msi"
    "AGREETOLICENSE=Yes"
    "RECEIVING_INDEXER=<SPLUNK-SERVER-IP>:9997"
    "SPLUNKUSERNAME=admin"
    "SPLUNKPASSWORD=YourForwarderPassword123!"
    "WINEVENTLOG_SEC_ENABLE=1"
    "WINEVENTLOG_SYS_ENABLE=1"
    "WINEVENTLOG_APP_ENABLE=1"
    "/quiet"
)
Start-Process msiexec.exe -ArgumentList $msiArgs -Wait
```

### Step 6.3: Configure Inputs

Create `C:\Program Files\SplunkUniversalForwarder\etc\system\local\inputs.conf`:

```ini
# ==================== Windows Event Logs ====================

[WinEventLog://Security]
disabled = 0
index = windows
sourcetype = WinEventLog:Security

[WinEventLog://System]
disabled = 0
index = windows
sourcetype = WinEventLog:System

[WinEventLog://Application]
disabled = 0
index = windows
sourcetype = WinEventLog:Application

# ==================== Sysmon Events ====================

[WinEventLog://Microsoft-Windows-Sysmon/Operational]
disabled = 0
index = sysmon
sourcetype = XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
renderXml = true

# ==================== PowerShell Logging ====================

[WinEventLog://Microsoft-Windows-PowerShell/Operational]
disabled = 0
index = windows
sourcetype = WinEventLog:PowerShell

[WinEventLog://Windows PowerShell]
disabled = 0
index = windows
sourcetype = WinEventLog:PowerShell

# ==================== Windows Defender ====================

[WinEventLog://Microsoft-Windows-Windows Defender/Operational]
disabled = 0
index = windows
sourcetype = WinEventLog:Defender
```

### Step 6.4: Configure Outputs

Create `C:\Program Files\SplunkUniversalForwarder\etc\system\local\outputs.conf`:

```ini
[tcpout]
defaultGroup = splunk-indexers

[tcpout:splunk-indexers]
server = <SPLUNK-SERVER-IP>:9997

[tcpout-server://<SPLUNK-SERVER-IP>:9997]
```

### Step 6.5: Restart Forwarder

```powershell
# Restart service
Restart-Service SplunkForwarder

# Verify status
Get-Service SplunkForwarder
```

---

## 🐧 Part 7: Linux Universal Forwarder Deployment

### Step 7.1: Download and Install

**Debian/Ubuntu:**

```bash
# Download (check website for current version)
wget -O /tmp/splunkforwarder.deb "https://download.splunk.com/products/universalforwarder/releases/9.2.0/linux/splunkforwarder-9.2.0-linux-2.6-amd64.deb"

# Install
sudo dpkg -i /tmp/splunkforwarder.deb
```

**RHEL/CentOS:**

```bash
wget -O /tmp/splunkforwarder.rpm "https://download.splunk.com/products/universalforwarder/releases/9.2.0/linux/splunkforwarder-9.2.0-linux-2.6-x86_64.rpm"

sudo rpm -i /tmp/splunkforwarder.rpm
```

### Step 7.2: Configure Forwarder

```bash
# Accept license and set credentials
sudo /opt/splunkforwarder/bin/splunk start --accept-license

# Add forward server
sudo /opt/splunkforwarder/bin/splunk add forward-server <SPLUNK-SERVER-IP>:9997 -auth admin:YourPassword

# Add monitored files
sudo /opt/splunkforwarder/bin/splunk add monitor /var/log/syslog -index linux -sourcetype syslog
sudo /opt/splunkforwarder/bin/splunk add monitor /var/log/auth.log -index linux -sourcetype linux_secure
sudo /opt/splunkforwarder/bin/splunk add monitor /var/log/audit/audit.log -index linux -sourcetype linux_audit
```

### Step 7.3: Configure via Files

Create `/opt/splunkforwarder/etc/system/local/inputs.conf`:

```ini
[monitor:///var/log/syslog]
disabled = false
index = linux
sourcetype = syslog

[monitor:///var/log/auth.log]
disabled = false
index = linux
sourcetype = linux_secure

[monitor:///var/log/secure]
disabled = false
index = linux
sourcetype = linux_secure

[monitor:///var/log/audit/audit.log]
disabled = false
index = linux
sourcetype = linux_audit

[monitor:///var/log/messages]
disabled = false
index = linux
sourcetype = syslog
```

Create `/opt/splunkforwarder/etc/system/local/outputs.conf`:

```ini
[tcpout]
defaultGroup = splunk-indexers

[tcpout:splunk-indexers]
server = <SPLUNK-SERVER-IP>:9997
```

### Step 7.4: Enable Boot Start

```bash
sudo /opt/splunkforwarder/bin/splunk enable boot-start -user splunk
sudo systemctl start SplunkForwarder
sudo systemctl status SplunkForwarder
```

---

## 🔎 Part 8: Essential Splunk Apps

### Install Apps from Splunkbase

1. Navigate to **Apps → Find More Apps**
2. Search for the app
3. Click **Install**
4. Enter your Splunk.com credentials

### Recommended Security Apps

| App | Purpose | Link |
|-----|---------|------|
| **Splunk Security Essentials** | Pre-built security detections | [Splunkbase](https://splunkbase.splunk.com/app/3435) |
| **Sysmon Add-on** | Parse Sysmon events | [Splunkbase](https://splunkbase.splunk.com/app/5709) |
| **Windows Add-on** | Parse Windows events | [Splunkbase](https://splunkbase.splunk.com/app/742) |
| **Linux Add-on** | Parse Linux events | [Splunkbase](https://splunkbase.splunk.com/app/833) |
| **MITRE ATT&CK App** | Map detections to ATT&CK | [Splunkbase](https://splunkbase.splunk.com/app/4617) |
| **SA-Investigator** | Investigation workspace | [Splunkbase](https://splunkbase.splunk.com/app/3749) |

### Install via CLI

```bash
# Download app from Splunkbase, then:
sudo -u splunk /opt/splunk/bin/splunk install app /path/to/app.tgz -auth admin:YourPassword
sudo systemctl restart Splunkd
```

---

## 📊 Part 9: Splunk Search (SPL) Basics

### Search Processing Language (SPL)

#### Basic Search Structure

```spl
index=<index> sourcetype=<sourcetype> <search_terms>
| <command1>
| <command2>
| <command3>
```

#### Time Modifiers

```spl
earliest=-24h latest=now
earliest=-7d@d latest=@d
earliest=01/01/2024:00:00:00 latest=01/31/2024:23:59:59
```

### Security-Focused Searches

#### Failed Windows Logins

```spl
index=windows sourcetype="WinEventLog:Security" EventCode=4625
| stats count by Account_Name, Source_Network_Address
| sort -count
| head 20
```

#### Successful Logins from Unusual Locations

```spl
index=windows sourcetype="WinEventLog:Security" EventCode=4624 Logon_Type=10
| stats count by Account_Name, Source_Network_Address
| sort -count
```

#### Sysmon Process Creation

```spl
index=sysmon EventCode=1
| table _time, Computer, User, Image, CommandLine, ParentImage
| sort -_time
```

#### Encoded PowerShell Detection

```spl
index=sysmon EventCode=1 Image="*powershell.exe"
| where match(CommandLine, "(?i)(-enc|-encodedcommand|frombase64string)")
| table _time, Computer, User, CommandLine
```

#### Network Connections to External IPs

```spl
index=sysmon EventCode=3 
| where NOT cidrmatch("10.0.0.0/8", DestinationIp) AND NOT cidrmatch("192.168.0.0/16", DestinationIp) AND NOT cidrmatch("172.16.0.0/12", DestinationIp)
| stats count by Image, DestinationIp, DestinationPort
| sort -count
```

#### LSASS Access (Credential Dumping)

```spl
index=sysmon EventCode=10 TargetImage="*lsass.exe"
| table _time, Computer, SourceImage, SourceUser, GrantedAccess
```

#### New Service Installation

```spl
index=windows sourcetype="WinEventLog:System" EventCode=7045
| table _time, ComputerName, Service_Name, Service_File_Name, Service_Type
```

#### Registry Run Key Modifications

```spl
index=sysmon EventCode=13 TargetObject="*CurrentVersion\\Run*"
| table _time, Computer, User, Image, TargetObject, Details
```

### Dashboard Searches

#### Top Talkers by Event Count

```spl
index=* earliest=-24h
| stats count by host
| sort -count
| head 10
```

#### Events Over Time

```spl
index=windows earliest=-7d
| timechart span=1h count by EventCode
```

#### Authentication Summary

```spl
index=windows sourcetype="WinEventLog:Security" (EventCode=4624 OR EventCode=4625)
| eval Status=if(EventCode=4624, "Success", "Failure")
| stats count by Status, Account_Name
| sort -count
```

---

## 🚨 Part 10: Alerting (Enterprise Only)

### Create a Basic Alert

1. Run a search that returns results you want to alert on
2. Click **Save As → Alert**
3. Configure:
   - Title: `Multiple Failed Logins`
   - Permissions: `Private` or `Shared in App`
   - Alert type: `Scheduled` or `Real-time`
   - Trigger condition: `Number of Results > 5`
   - Trigger Actions: Email, Webhook, Run Script

### Example Alert: Brute Force Detection

**Search:**
```spl
index=windows sourcetype="WinEventLog:Security" EventCode=4625
| stats count by Account_Name, Source_Network_Address
| where count > 10
```

**Schedule:** Every 15 minutes

**Trigger:** When number of results > 0

### Example Alert: Suspicious Process

**Search:**
```spl
index=sysmon EventCode=1
| where match(Image, "(?i)(mimikatz|procdump|psexec|cobalt)")
| table _time, Computer, User, Image, CommandLine
```

**Schedule:** Real-time

**Trigger:** When number of results > 0

---

## 🔄 Part 11: Data Retention Management

### Configure Index Retention

Edit `/opt/splunk/etc/system/local/indexes.conf`:

```ini
[windows]
homePath = $SPLUNK_DB/windows/db
coldPath = $SPLUNK_DB/windows/colddb
thawedPath = $SPLUNK_DB/windows/thaweddb
maxDataSize = auto_high_volume
maxTotalDataSizeMB = 50000
frozenTimePeriodInSecs = 2592000  # 30 days

[linux]
homePath = $SPLUNK_DB/linux/db
coldPath = $SPLUNK_DB/linux/colddb
thawedPath = $SPLUNK_DB/linux/thaweddb
maxTotalDataSizeMB = 20000
frozenTimePeriodInSecs = 2592000  # 30 days

[sysmon]
homePath = $SPLUNK_DB/sysmon/db
coldPath = $SPLUNK_DB/sysmon/colddb
thawedPath = $SPLUNK_DB/sysmon/thaweddb
maxTotalDataSizeMB = 100000
frozenTimePeriodInSecs = 7776000  # 90 days
```

### Monitor Index Usage

```spl
| dbinspect index=* 
| stats sum(sizeOnDiskMB) as "Size (MB)" by index
| sort -"Size (MB)"
```

---

## ❗ Part 12: Troubleshooting

### Splunk Won't Start

**Check logs:**
```bash
tail -f /opt/splunk/var/log/splunk/splunkd.log
```

**Common issues:**

| Error | Solution |
|-------|----------|
| `Splunk has not been started` | Run `/opt/splunk/bin/splunk start` |
| `License violation` | Check license usage, reduce indexing |
| `Port already in use` | Change ports in web.conf/server.conf |
| `Insufficient disk space` | Free space or adjust retention |

### Forwarder Not Sending Data

**Check forwarder status:**
```bash
# Linux
/opt/splunkforwarder/bin/splunk list forward-server

# Windows
& "C:\Program Files\SplunkUniversalForwarder\bin\splunk.exe" list forward-server
```

**Test connectivity:**
```bash
# From forwarder to indexer
nc -zv <SPLUNK-IP> 9997
telnet <SPLUNK-IP> 9997
```

**Check forwarder logs:**
```bash
# Linux
tail -f /opt/splunkforwarder/var/log/splunk/splunkd.log

# Windows
Get-Content "C:\Program Files\SplunkUniversalForwarder\var\log\splunk\splunkd.log" -Tail 50
```

### No Data in Search

1. **Verify time range:** Adjust the time picker
2. **Check index:** Ensure you're searching the correct index
3. **Verify data input:** Settings → Data inputs → check status
4. **Check forwarder:** Run `| metadata type=hosts` to see reporting hosts

### License Exceeded (Free Tier)

```spl
# Check daily indexing volume
index=_internal source=*license_usage.log type=Usage
| timechart span=1d sum(b) as bytes
| eval GB=round(bytes/1024/1024/1024, 2)
```

**Solutions:**
- Filter unnecessary events at the forwarder level
- Reduce log verbosity on sources
- Upgrade to Enterprise Trial/License

---

## 🛡️ Part 13: Security Hardening

### Change Default Ports

Edit `/opt/splunk/etc/system/local/web.conf`:

```ini
[settings]
httpport = 8443
enableSplunkWebSSL = true
```

### Enable SSL

```bash
# Generate self-signed certificate
sudo -u splunk /opt/splunk/bin/splunk createssl server-cert -d /opt/splunk/etc/auth

# Or use your own certificates
```

### Configure Authentication

**LDAP Integration:**

1. Navigate to **Settings → Authentication Methods**
2. Select **LDAP**
3. Configure LDAP server settings
4. Map LDAP groups to Splunk roles

**SAML Integration:**

1. Navigate to **Settings → Authentication Methods**
2. Select **SAML**
3. Upload IdP metadata
4. Configure attribute mapping

### Audit Logging

Enable audit logging in `/opt/splunk/etc/system/local/audit.conf`:

```ini
[auditTrail]
privateKey = $SPLUNK_HOME/etc/auth/audit/private.pem
publicKey = $SPLUNK_HOME/etc/auth/audit/public.pem
```

---

## 📚 Part 14: Additional Resources

### Documentation

- [Splunk Documentation](https://docs.splunk.com/)
- [Splunk Search Reference](https://docs.splunk.com/Documentation/Splunk/latest/SearchReference)
- [Splunk Security Essentials](https://docs.splunk.com/Documentation/SSE/latest)

### Community & Training

- [Splunk Community](https://community.splunk.com/)
- [Splunk Education](https://www.splunk.com/en_us/training.html)
- [Splunk Fundamentals 1](https://www.splunk.com/en_us/training/courses/splunk-fundamentals-1.html) (Free)
- [Boss of the SOC (BOTS)](https://www.splunk.com/en_us/blog/security/boss-of-the-soc-bots-v5-dataset-released.html) (Practice datasets)

### Detection Content

- [Splunk Security Content](https://github.com/splunk/security_content)
- [Sigma Rules](https://github.com/SigmaHQ/sigma) (convertible to SPL)
- [Atomic Red Team](https://github.com/redcanaryco/atomic-red-team)

---

## 🗂️ Quick Reference

### Service Commands

| OS | Start | Stop | Restart | Status |
|----|-------|------|---------|--------|
| Linux (Splunk) | `systemctl start Splunkd` | `systemctl stop Splunkd` | `systemctl restart Splunkd` | `systemctl status Splunkd` |
| Linux (Forwarder) | `systemctl start SplunkForwarder` | `systemctl stop SplunkForwarder` | `systemctl restart SplunkForwarder` | `systemctl status SplunkForwarder` |
| Windows (Forwarder) | `Start-Service SplunkForwarder` | `Stop-Service SplunkForwarder` | `Restart-Service SplunkForwarder` | `Get-Service SplunkForwarder` |

### CLI Commands

| Command | Purpose |
|---------|---------|
| `splunk start` | Start Splunk |
| `splunk stop` | Stop Splunk |
| `splunk restart` | Restart Splunk |
| `splunk status` | Check status |
| `splunk add monitor <path>` | Add file monitoring |
| `splunk add forward-server <ip:port>` | Add forward server |
| `splunk list forward-server` | List forward servers |
| `splunk btool inputs list` | Debug inputs configuration |

### File Locations

| Component | Path |
|-----------|------|
| Splunk Home | `/opt/splunk/` |
| Forwarder Home | `/opt/splunkforwarder/` (Linux) or `C:\Program Files\SplunkUniversalForwarder\` (Windows) |
| Local Config | `$SPLUNK_HOME/etc/system/local/` |
| Apps | `$SPLUNK_HOME/etc/apps/` |
| Logs | `$SPLUNK_HOME/var/log/splunk/` |
| Data | `$SPLUNK_HOME/var/lib/splunk/` |

### Common SPL Commands

| Command | Purpose | Example |
|---------|---------|---------|
| `stats` | Calculate statistics | `stats count by host` |
| `table` | Format output as table | `table _time, host, message` |
| `sort` | Sort results | `sort -count` (descending) |
| `head` | Return first N results | `head 10` |
| `timechart` | Time-based chart | `timechart span=1h count` |
| `where` | Filter with expressions | `where count > 10` |
| `eval` | Create/modify fields | `eval GB=bytes/1024/1024/1024` |
| `rex` | Extract with regex | `rex field=message "user=(?<user>\w+)"` |
| `dedup` | Remove duplicates | `dedup host, user` |
| `transaction` | Group related events | `transaction host maxspan=5m` |

---

*Part of the Incident Response & Log Aggregation Branch*
