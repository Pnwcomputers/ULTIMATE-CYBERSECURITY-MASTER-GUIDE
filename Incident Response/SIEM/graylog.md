# 🟢 Graylog SIEM Deployment Guide

**Graylog** is an open-source log management platform designed for collecting, indexing, and analyzing log data. It combines the power of Elasticsearch (or OpenSearch) for storage with an intuitive web interface for search and visualization. Graylog is lighter weight than ELK and offers a more streamlined experience for log aggregation and SIEM use cases.

This guide covers deploying Graylog using Docker and configuring it to receive logs from various sources.

---

## 🎯 Why Graylog?

| Feature | Graylog | ELK Stack |
|---------|---------|-----------|
| Setup Complexity | Lower | Higher |
| Resource Usage | Lighter | Heavier |
| Web Interface | Purpose-built | Kibana (general purpose) |
| Alerting | Built-in (even in free) | Requires configuration |
| Stream Processing | Native | Via Logstash |
| Learning Curve | Gentler | Steeper |

### Graylog Editions

| Feature | Open (Free) | Operations | Security |
|---------|-------------|------------|----------|
| Log Collection | ✅ | ✅ | ✅ |
| Alerting | ✅ | ✅ | ✅ |
| Dashboards | ✅ | ✅ | ✅ |
| LDAP/AD Auth | ✅ | ✅ | ✅ |
| Archiving | ❌ | ✅ | ✅ |
| Anomaly Detection | ❌ | ✅ | ✅ |
| SIEM Features | ❌ | ❌ | ✅ |
| Audit Logging | ❌ | ✅ | ✅ |

> **For homelab/learning:** Graylog Open is excellent and free.

---

## 📋 Prerequisites

### Server Requirements

| Component | Minimum | Recommended |
|-----------|---------|-------------|
| OS | Ubuntu 20.04/22.04 LTS | Ubuntu 22.04 LTS |
| RAM | 4 GB | 8 GB+ |
| CPU | 2 vCPUs | 4 vCPUs |
| Storage | 50 GB | 200 GB+ SSD |

### Architecture Components

Graylog requires three components:

| Component | Purpose |
|-----------|---------|
| **MongoDB** | Stores configuration and metadata |
| **OpenSearch/Elasticsearch** | Stores and indexes log messages |
| **Graylog Server** | Processing, web interface, API |

### Network Requirements

| Port | Service | Purpose |
|------|---------|---------|
| 9000 | Graylog Web | Web interface & API |
| 1514 | Graylog | Syslog TCP input |
| 1514/udp | Graylog | Syslog UDP input |
| 5044 | Graylog | Beats input |
| 12201 | Graylog | GELF TCP input |
| 12201/udp | Graylog | GELF UDP input |
| 9200 | OpenSearch | Search engine (internal) |
| 27017 | MongoDB | Database (internal) |

---

## 🛠️ Part 1: Server Preparation

### Step 1.1: Update System

```bash
sudo apt update && sudo apt upgrade -y
```

### Step 1.2: Install Docker

```bash
# Install dependencies
sudo apt install -y apt-transport-https ca-certificates curl gnupg lsb-release

# Add Docker GPG key
curl -fsSL https://download.docker.com/linux/ubuntu/gpg | sudo gpg --dearmor -o /usr/share/keyrings/docker-archive-keyring.gpg

# Add Docker repository
echo "deb [arch=$(dpkg --print-architecture) signed-by=/usr/share/keyrings/docker-archive-keyring.gpg] https://download.docker.com/linux/ubuntu $(lsb_release -cs) stable" | sudo tee /etc/apt/sources.list.d/docker.list > /dev/null

# Install Docker
sudo apt update
sudo apt install -y docker-ce docker-ce-cli containerd.io docker-compose-plugin

# Add user to docker group
sudo usermod -aG docker $USER
newgrp docker
```

### Step 1.3: Configure System Limits

```bash
# Increase virtual memory for OpenSearch
sudo sysctl -w vm.max_map_count=262144
echo "vm.max_map_count=262144" | sudo tee -a /etc/sysctl.conf
sudo sysctl -p
```

### Step 1.4: Create Directory Structure

```bash
mkdir -p ~/graylog/{data,config}
mkdir -p ~/graylog/data/{mongodb,opensearch,graylog}
cd ~/graylog
```

---

## 🚀 Part 2: Docker Compose Deployment

### Step 2.1: Generate Password Secret and Hash

Graylog requires a `password_secret` (for encryption) and a `root_password_sha2` (admin password hash).

```bash
# Generate password secret (minimum 16 characters)
pwgen -N 1 -s 96

# Generate SHA256 hash of your admin password
echo -n "YourAdminPassword123!" | sha256sum | cut -d" " -f1
```

Save both values for the next step.

### Step 2.2: Create Docker Compose File

Create `docker-compose.yml`:

```yaml
version: '3.8'

services:
  # MongoDB for Graylog configuration storage
  mongodb:
    image: mongo:6.0
    container_name: graylog-mongodb
    volumes:
      - mongodb_data:/data/db
    networks:
      - graylog-network
    restart: unless-stopped

  # OpenSearch for log storage and indexing
  opensearch:
    image: opensearchproject/opensearch:2.12.0
    container_name: graylog-opensearch
    environment:
      - cluster.name=graylog-cluster
      - node.name=opensearch-node1
      - discovery.type=single-node
      - bootstrap.memory_lock=true
      - "OPENSEARCH_JAVA_OPTS=-Xms2g -Xmx2g"
      - DISABLE_SECURITY_PLUGIN=true
      - DISABLE_INSTALL_DEMO_CONFIG=true
    ulimits:
      memlock:
        soft: -1
        hard: -1
      nofile:
        soft: 65535
        hard: 65535
    volumes:
      - opensearch_data:/usr/share/opensearch/data
    networks:
      - graylog-network
    restart: unless-stopped

  # Graylog Server
  graylog:
    image: graylog/graylog:5.2
    container_name: graylog
    environment:
      # CHANGE THESE VALUES
      - GRAYLOG_PASSWORD_SECRET=<YOUR_PASSWORD_SECRET_HERE>
      - GRAYLOG_ROOT_PASSWORD_SHA2=<YOUR_SHA256_HASH_HERE>
      - GRAYLOG_HTTP_EXTERNAL_URI=http://<YOUR_SERVER_IP>:9000/
      # MongoDB connection
      - GRAYLOG_MONGODB_URI=mongodb://mongodb:27017/graylog
      # OpenSearch connection
      - GRAYLOG_ELASTICSEARCH_HOSTS=http://opensearch:9200
      # Timezone
      - GRAYLOG_ROOT_TIMEZONE=America/Los_Angeles
      # Email (optional)
      # - GRAYLOG_TRANSPORT_EMAIL_ENABLED=true
      # - GRAYLOG_TRANSPORT_EMAIL_HOSTNAME=smtp.example.com
      # - GRAYLOG_TRANSPORT_EMAIL_PORT=587
      # - GRAYLOG_TRANSPORT_EMAIL_USE_AUTH=true
      # - GRAYLOG_TRANSPORT_EMAIL_AUTH_USERNAME=user@example.com
      # - GRAYLOG_TRANSPORT_EMAIL_AUTH_PASSWORD=password
    entrypoint: /usr/bin/tini -- wait-for-it opensearch:9200 -- /docker-entrypoint.sh
    volumes:
      - graylog_data:/usr/share/graylog/data
    networks:
      - graylog-network
    depends_on:
      - mongodb
      - opensearch
    ports:
      # Graylog web interface and REST API
      - "9000:9000"
      # Syslog TCP
      - "1514:1514"
      # Syslog UDP
      - "1514:1514/udp"
      # GELF TCP
      - "12201:12201"
      # GELF UDP
      - "12201:12201/udp"
      # Beats
      - "5044:5044"
    restart: unless-stopped

volumes:
  mongodb_data:
  opensearch_data:
  graylog_data:

networks:
  graylog-network:
    driver: bridge
```

### Step 2.3: Create Environment File (Alternative)

Instead of inline environment variables, create `.env`:

```bash
# Graylog Configuration
GRAYLOG_PASSWORD_SECRET=yourverylongsecretatleast16characters1234567890
GRAYLOG_ROOT_PASSWORD_SHA2=5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8
GRAYLOG_HTTP_EXTERNAL_URI=http://192.168.1.50:9000/
GRAYLOG_ROOT_TIMEZONE=America/Los_Angeles
```

Update docker-compose.yml to use the env file:

```yaml
graylog:
  env_file:
    - .env
```

### Step 2.4: Start the Stack

```bash
# Start all services
docker compose up -d

# Monitor startup (wait for "Graylog server up and running")
docker compose logs -f graylog
```

Startup typically takes 1-2 minutes.

### Step 2.5: Access Graylog Web Interface

Open your browser:

```
http://<SERVER-IP>:9000
```

**Default Credentials:**
- Username: `admin`
- Password: The password you hashed in Step 2.1

---

## 🔥 Part 3: Firewall Configuration

### UFW (Ubuntu)

```bash
sudo ufw allow 9000/tcp comment "Graylog Web UI"
sudo ufw allow 1514/tcp comment "Graylog Syslog TCP"
sudo ufw allow 1514/udp comment "Graylog Syslog UDP"
sudo ufw allow 5044/tcp comment "Graylog Beats"
sudo ufw allow 12201/tcp comment "Graylog GELF TCP"
sudo ufw allow 12201/udp comment "Graylog GELF UDP"
sudo ufw reload
```

### Firewalld (RHEL/CentOS)

```bash
sudo firewall-cmd --permanent --add-port=9000/tcp
sudo firewall-cmd --permanent --add-port=1514/tcp
sudo firewall-cmd --permanent --add-port=1514/udp
sudo firewall-cmd --permanent --add-port=5044/tcp
sudo firewall-cmd --permanent --add-port=12201/tcp
sudo firewall-cmd --permanent --add-port=12201/udp
sudo firewall-cmd --reload
```

---

## 📥 Part 4: Configure Data Inputs

Graylog uses "Inputs" to receive log data. Configure these via the web interface.

### Step 4.1: Create Syslog UDP Input

1. Navigate to **System → Inputs**
2. Select **Syslog UDP** from the dropdown
3. Click **Launch new input**
4. Configure:
   - Node: Select your Graylog node
   - Title: `Syslog UDP`
   - Bind address: `0.0.0.0`
   - Port: `1514`
5. Click **Save**

### Step 4.2: Create Syslog TCP Input

1. Select **Syslog TCP** from dropdown
2. Click **Launch new input**
3. Configure:
   - Title: `Syslog TCP`
   - Bind address: `0.0.0.0`
   - Port: `1514`
4. Click **Save**

### Step 4.3: Create Beats Input

For Winlogbeat/Filebeat:

1. Select **Beats** from dropdown
2. Click **Launch new input**
3. Configure:
   - Title: `Beats Input`
   - Bind address: `0.0.0.0`
   - Port: `5044`
4. Click **Save**

### Step 4.4: Create GELF Input

GELF (Graylog Extended Log Format) supports structured logging:

1. Select **GELF UDP** from dropdown
2. Click **Launch new input**
3. Configure:
   - Title: `GELF UDP`
   - Bind address: `0.0.0.0`
   - Port: `12201`
4. Click **Save**

### Step 4.5: Verify Inputs

After creating inputs, they should show as "RUNNING" with a green indicator.

---

## 🌊 Part 5: Streams and Pipelines

### Understanding Streams

Streams route messages based on rules. Think of them as filters that categorize incoming logs.

### Create a Windows Events Stream

1. Navigate to **Streams**
2. Click **Create Stream**
3. Configure:
   - Title: `Windows Events`
   - Description: `All Windows Event Log messages`
   - Index Set: Default
4. Click **Save**
5. Click **Manage Rules** for the new stream
6. Add Rule:
   - Field: `source`
   - Type: `match regular expression`
   - Value: `.*` (or specific hostname pattern)
   - Inverted: No
7. Click **Save**
8. Click **Start Stream** (on the Streams page)

### Create Additional Streams

| Stream Name | Rule Field | Rule Type | Rule Value |
|-------------|------------|-----------|------------|
| Linux Syslog | `facility` | `match exactly` | `local0` through `local7` |
| Network Devices | `source` | `match regular expression` | `^(switch\|router\|fw).*` |
| Sysmon Events | `winlog_channel` | `match exactly` | `Microsoft-Windows-Sysmon/Operational` |
| Authentication | `EventID` | `match exactly` | `4624` or `4625` |

### Processing Pipelines

Pipelines process and enrich messages.

#### Step 5.1: Create a Pipeline

1. Navigate to **System → Pipelines**
2. Click **Manage rules** → **Create Rule**
3. Create a rule to extract fields:

```
rule "Extract Windows EventID"
when
    has_field("EventID")
then
    let event_id = to_string($message.EventID);
    set_field("event_id_string", event_id);
end
```

4. Create a Pipeline:
   - Click **Manage pipelines** → **Add new pipeline**
   - Name: `Windows Processing`
   - Connect to stream: `Windows Events`
5. Add the rule to a stage in the pipeline

#### Example: GeoIP Enrichment

```
rule "GeoIP Lookup"
when
    has_field("src_ip") AND NOT cidr_match("10.0.0.0/8", to_ip($message.src_ip))
then
    let geo = geoip_lookup(to_string($message.src_ip));
    set_field("src_geo_country", geo["country"]["iso_code"]);
    set_field("src_geo_city", geo["city"]["name"]);
end
```

---

## 🖥️ Part 6: Windows Agent Deployment (Winlogbeat)

### Step 6.1: Install Winlogbeat

```powershell
# Download Winlogbeat
$version = "8.12.0"
Invoke-WebRequest -Uri "https://artifacts.elastic.co/downloads/beats/winlogbeat/winlogbeat-$version-windows-x86_64.zip" -OutFile "$env:TEMP\winlogbeat.zip"

# Extract
Expand-Archive -Path "$env:TEMP\winlogbeat.zip" -DestinationPath "C:\Program Files"
Rename-Item "C:\Program Files\winlogbeat-$version-windows-x86_64" "C:\Program Files\Winlogbeat"
```

### Step 6.2: Configure Winlogbeat for Graylog

Edit `C:\Program Files\Winlogbeat\winlogbeat.yml`:

```yaml
winlogbeat.event_logs:
  - name: Security
    event_id: 4624, 4625, 4634, 4648, 4672, 4688, 4697, 4698, 4720, 4726, 4728, 4732, 4756, 4768, 4769, 4776
    ignore_older: 72h

  - name: System
    event_id: 7045, 7040, 1074, 6005, 6006
    ignore_older: 72h

  - name: Microsoft-Windows-Sysmon/Operational
    ignore_older: 72h

  - name: Microsoft-Windows-PowerShell/Operational
    event_id: 4103, 4104
    ignore_older: 72h

processors:
  - add_host_metadata: ~

# Output to Graylog Beats input
output.logstash:
  hosts: ["<GRAYLOG-SERVER-IP>:5044"]

logging.level: info
logging.to_files: true
logging.files:
  path: C:\ProgramData\winlogbeat\logs
  name: winlogbeat
  keepfiles: 7
```

### Step 6.3: Install and Start Service

```powershell
cd "C:\Program Files\Winlogbeat"

# Test configuration
.\winlogbeat.exe test config -e

# Install service
.\install-service-winlogbeat.ps1

# Start service
Start-Service winlogbeat
```

---

## 🐧 Part 7: Linux Agent Deployment

### Option 1: Configure Rsyslog

Edit `/etc/rsyslog.d/60-graylog.conf`:

```bash
# Forward all logs to Graylog via UDP
*.* @<GRAYLOG-SERVER-IP>:1514;RSYSLOG_SyslogProtocol23Format

# Or via TCP (more reliable)
*.* @@<GRAYLOG-SERVER-IP>:1514;RSYSLOG_SyslogProtocol23Format
```

Restart rsyslog:

```bash
sudo systemctl restart rsyslog
```

### Option 2: Install Filebeat

```bash
# Install Filebeat
curl -L -O https://artifacts.elastic.co/downloads/beats/filebeat/filebeat-8.12.0-amd64.deb
sudo dpkg -i filebeat-8.12.0-amd64.deb
```

Configure `/etc/filebeat/filebeat.yml`:

```yaml
filebeat.inputs:
  - type: log
    enabled: true
    paths:
      - /var/log/syslog
      - /var/log/auth.log
      - /var/log/secure
    fields:
      log_type: syslog

  - type: log
    enabled: true
    paths:
      - /var/log/audit/audit.log
    fields:
      log_type: audit

output.logstash:
  hosts: ["<GRAYLOG-SERVER-IP>:5044"]
```

Start Filebeat:

```bash
sudo systemctl enable filebeat
sudo systemctl start filebeat
```

### Option 3: Use GELF (Docker Logging)

Configure Docker to send logs directly to Graylog:

```bash
# Run container with GELF logging
docker run --log-driver=gelf \
  --log-opt gelf-address=udp://<GRAYLOG-SERVER-IP>:12201 \
  --log-opt tag="{{.Name}}" \
  nginx
```

Or in `docker-compose.yml`:

```yaml
services:
  webapp:
    image: nginx
    logging:
      driver: gelf
      options:
        gelf-address: "udp://<GRAYLOG-SERVER-IP>:12201"
        tag: "webapp"
```

---

## 🔍 Part 8: Searching in Graylog

### Basic Search Syntax

```
# Simple keyword search
error

# Field-specific search
source:webserver

# Wildcards
source:web*

# Boolean operators
error AND source:webserver
error OR warning
NOT debug

# Phrases
"authentication failed"

# Ranges
http_response_code:[400 TO 599]
timestamp:["2024-01-01 00:00:00" TO "2024-01-31 23:59:59"]

# Exists check
_exists_:user_id
```

### Security-Focused Searches

#### Failed Logins (Windows)

```
EventID:4625
```

#### Successful Logins (Windows)

```
EventID:4624
```

#### Sysmon Process Creation

```
EventID:1 AND winlog_channel:"Microsoft-Windows-Sysmon/Operational"
```

#### PowerShell Execution

```
EventID:4104 OR (EventID:1 AND Image:*powershell*)
```

#### Network Connections (Sysmon)

```
EventID:3 AND NOT DestinationIp:10.* AND NOT DestinationIp:192.168.*
```

#### Suspicious Processes

```
EventID:1 AND (Image:*cmd.exe OR Image:*powershell.exe) AND ParentImage:*WINWORD.EXE
```

### Saved Searches

1. Run your search
2. Click **Save** (bookmark icon)
3. Name your search
4. Access from **Search → Saved Searches**

---

## 📊 Part 9: Dashboards

### Create a Dashboard

1. Navigate to **Dashboards**
2. Click **Create new dashboard**
3. Name: `Security Overview`
4. Click **Create**

### Add Widgets

#### Widget 1: Message Count Over Time

1. Click **Edit** on dashboard
2. Click **Create**
3. Select **Aggregation**
4. Configure:
   - Visualization: **Line Chart** or **Area Chart**
   - Rows: **timestamp** (Date Histogram)
   - Metrics: **count()**
5. Click **Create**

#### Widget 2: Top Source Hosts

1. Click **Create**
2. Select **Aggregation**
3. Configure:
   - Visualization: **Data Table**
   - Rows: **source** (Terms)
   - Metrics: **count()**
   - Sort: By metric, Descending
5. Click **Create**

#### Widget 3: Authentication Events

1. Click **Create**
2. Configure:
   - Search Query: `EventID:(4624 OR 4625)`
   - Visualization: **Pie Chart**
   - Rows: **EventID** (Terms)
   - Metrics: **count()**

#### Widget 4: Failed Login Map

1. Click **Create**
2. Configure:
   - Search Query: `EventID:4625 AND _exists_:src_geo_country`
   - Visualization: **World Map**
   - Rows: **src_geo_country**
   - Metrics: **count()**

### Dashboard Templates

Graylog Content Packs can provide pre-built dashboards. Check **System → Content Packs** for available options.

---

## 🚨 Part 10: Alerting

### Create an Alert

1. Navigate to **Alerts → Event Definitions**
2. Click **Create Event Definition**

### Example: Multiple Failed Logins

**Step 1: Event Details**
- Title: `Multiple Failed Logins`
- Description: `Alerts when multiple login failures from same source`
- Priority: `High`

**Step 2: Condition**
- Condition Type: **Aggregation**
- Search Query: `EventID:4625`
- Streams: (Select your Windows stream)
- Group by: `source` OR `IpAddress`
- Search within: `5 minutes`
- Execute every: `1 minute`
- Create alert when: **count() >= 5**

**Step 3: Fields** (optional)
Add fields to include in the alert.

**Step 4: Notifications**
- Add notification (email, HTTP, Slack, etc.)

### Example: Suspicious PowerShell

**Condition:**
- Search Query: `EventID:1 AND Image:*powershell* AND (CommandLine:*-enc* OR CommandLine:*downloadstring* OR CommandLine:*bypass*)`
- Create alert when: **count() > 0**

### Notification Channels

#### Configure Email Notifications

1. Navigate to **System → Configurations → Notification Settings**
2. Or set via environment variables:

```yaml
# In docker-compose.yml
- GRAYLOG_TRANSPORT_EMAIL_ENABLED=true
- GRAYLOG_TRANSPORT_EMAIL_HOSTNAME=smtp.gmail.com
- GRAYLOG_TRANSPORT_EMAIL_PORT=587
- GRAYLOG_TRANSPORT_EMAIL_USE_AUTH=true
- GRAYLOG_TRANSPORT_EMAIL_USE_TLS=true
- GRAYLOG_TRANSPORT_EMAIL_AUTH_USERNAME=your@gmail.com
- GRAYLOG_TRANSPORT_EMAIL_AUTH_PASSWORD=yourapppassword
- GRAYLOG_TRANSPORT_EMAIL_FROM_EMAIL=graylog@yourdomain.com
```

#### Configure Slack Notifications

1. Navigate to **Alerts → Notifications**
2. Click **Create Notification**
3. Select **Slack Notification**
4. Configure webhook URL and channel

---

## 💾 Part 11: Index Management

### Configure Index Sets

1. Navigate to **System → Indices**
2. Click **Create Index Set**
3. Configure:
   - Title: `Security Logs`
   - Index prefix: `security`
   - Index rotation: **Time-based** (e.g., Daily)
   - Retention: **Delete** after X indices

### Retention Strategies

| Strategy | Description | Use Case |
|----------|-------------|----------|
| Delete | Remove old indices | Limited storage |
| Close | Close but keep on disk | Occasional access needed |
| Archive | Move to cold storage | Compliance requirements |

### Configure Retention

1. Click on an Index Set
2. Click **Edit**
3. Set rotation strategy:
   - **Time-based:** Rotate daily/weekly
   - **Size-based:** Rotate at X GB
4. Set retention:
   - **Index count:** Keep last N indices
   - **Time:** Keep indices for X days

### Check Index Health

1. Navigate to **System → Indices**
2. View index status (green/yellow/red)
3. Check index size and document count

---

## 🔐 Part 12: Security Hardening

### Enable HTTPS

#### Generate Certificates

```bash
# Create certificate directory
mkdir -p ~/graylog/certs

# Generate self-signed certificate
openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
  -keyout ~/graylog/certs/graylog.key \
  -out ~/graylog/certs/graylog.crt \
  -subj "/CN=graylog.local"

# Create PKCS12 keystore
openssl pkcs12 -export -in ~/graylog/certs/graylog.crt \
  -inkey ~/graylog/certs/graylog.key \
  -out ~/graylog/certs/graylog.p12 \
  -name graylog -password pass:changeme
```

#### Update Docker Compose

```yaml
graylog:
  volumes:
    - ~/graylog/certs:/usr/share/graylog/data/certs:ro
  environment:
    - GRAYLOG_HTTP_ENABLE_TLS=true
    - GRAYLOG_HTTP_TLS_CERT_FILE=/usr/share/graylog/data/certs/graylog.crt
    - GRAYLOG_HTTP_TLS_KEY_FILE=/usr/share/graylog/data/certs/graylog.key
    - GRAYLOG_HTTP_EXTERNAL_URI=https://<YOUR_SERVER_IP>:9000/
```

### Configure LDAP/AD Authentication

1. Navigate to **System → Authentication → Authenticators**
2. Click **Create Authenticator**
3. Select **LDAP**
4. Configure:
   - Server URL: `ldap://dc.example.com:389`
   - System Username: `CN=svc_graylog,OU=Service Accounts,DC=example,DC=com`
   - System Password: (password)
   - Search Base DN: `OU=Users,DC=example,DC=com`
   - User Search Pattern: `(&(objectClass=user)(sAMAccountName={0}))`
5. Map LDAP groups to Graylog roles

### Create Role-Based Access

1. Navigate to **System → Authentication → Roles**
2. Create custom roles:
   - **Security Analyst:** Read access to security streams
   - **Admin:** Full access
   - **Auditor:** Read-only to all

---

## ❗ Part 13: Troubleshooting

### Graylog Won't Start

**Check logs:**
```bash
docker compose logs graylog
```

**Common issues:**

| Error | Solution |
|-------|----------|
| `waiting for opensearch` | Wait longer or check OpenSearch logs |
| `Password secret too short` | Ensure 16+ character secret |
| `Invalid MongoDB URI` | Check MongoDB is running |
| `No master` | OpenSearch cluster issue |

### No Messages Appearing

1. **Check inputs are running:**
   - Navigate to **System → Inputs**
   - Verify status shows "RUNNING"

2. **Test syslog connectivity:**
```bash
# Send test message
echo "<14>Test message from $(hostname)" | nc -u -w1 <GRAYLOG-IP> 1514
logger -n <GRAYLOG-IP> -P 1514 "Test message"
```

3. **Check Graylog logs:**
```bash
docker compose logs -f graylog | grep -i "received"
```

### Search Returns No Results

1. **Check time range:** Default is 5 minutes
2. **Check stream selection:** Messages may be in different stream
3. **Verify index:** **System → Indices** - check document count
4. **Check for processing errors:** **System → Processing Status**

### High Memory Usage

```bash
# Reduce OpenSearch heap
# In docker-compose.yml, change:
- "OPENSEARCH_JAVA_OPTS=-Xms1g -Xmx1g"
```

### Slow Searches

1. Add field indexes to frequently searched fields
2. Reduce time range of searches
3. Use more specific queries
4. Consider upgrading hardware

---

## 📚 Part 14: Additional Resources

### Documentation

- [Graylog Documentation](https://docs.graylog.org/)
- [Graylog Marketplace](https://marketplace.graylog.org/)
- [Graylog GitHub](https://github.com/Graylog2/graylog2-server)

### Content Packs

Content Packs bundle inputs, extractors, streams, and dashboards:

- [Windows Event Log Pack](https://marketplace.graylog.org/)
- [Linux Syslog Pack](https://marketplace.graylog.org/)
- [Network Security Monitoring](https://marketplace.graylog.org/)

### Community

- [Graylog Community](https://community.graylog.org/)
- [Graylog Slack](https://graylog.org/community-slack/)

---

## 🗂️ Quick Reference

### Docker Commands

| Command | Purpose |
|---------|---------|
| `docker compose up -d` | Start stack |
| `docker compose down` | Stop stack |
| `docker compose logs -f graylog` | Follow Graylog logs |
| `docker compose restart graylog` | Restart Graylog only |
| `docker compose exec graylog bash` | Shell into container |

### Graylog API

| Endpoint | Purpose |
|----------|---------|
| `GET /api/system` | System overview |
| `GET /api/system/inputs` | List inputs |
| `GET /api/streams` | List streams |
| `GET /api/search/universal/relative` | Execute search |

Example API call:

```bash
curl -u admin:password "http://localhost:9000/api/system/overview"
```

### Input Ports Reference

| Port | Protocol | Input Type |
|------|----------|------------|
| 1514 | TCP/UDP | Syslog |
| 5044 | TCP | Beats |
| 12201 | TCP/UDP | GELF |
| 5555 | TCP | Raw plaintext |

### Search Operators

| Operator | Example | Description |
|----------|---------|-------------|
| `AND` | `error AND nginx` | Both terms |
| `OR` | `error OR warning` | Either term |
| `NOT` | `NOT debug` | Exclude term |
| `""` | `"exact phrase"` | Exact match |
| `*` | `fail*` | Wildcard |
| `:` | `source:server1` | Field match |
| `[]` | `level:[1 TO 5]` | Range |
| `_exists_:` | `_exists_:user` | Field exists |

### Common Environment Variables

| Variable | Purpose | Example |
|----------|---------|---------|
| `GRAYLOG_PASSWORD_SECRET` | Encryption key | 96 character string |
| `GRAYLOG_ROOT_PASSWORD_SHA2` | Admin password hash | SHA256 hash |
| `GRAYLOG_HTTP_EXTERNAL_URI` | External URL | `http://ip:9000/` |
| `GRAYLOG_MONGODB_URI` | MongoDB connection | `mongodb://host:27017/graylog` |
| `GRAYLOG_ELASTICSEARCH_HOSTS` | OpenSearch URL | `http://opensearch:9200` |
| `GRAYLOG_ROOT_TIMEZONE` | Server timezone | `America/New_York` |

---

*Part of the Incident Response & Log Aggregation Branch*
