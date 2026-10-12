# 🦌 ELK Stack SIEM Deployment Guide

> **SECURITY STATUS — ISOLATED LAB ONLY**
>
> This walkthrough is undergoing security remediation. Existing examples
> include plaintext connections, sample credentials, and privileged service
> accounts. Do not deploy them unchanged, expose them to the internet, or
> use real incident data.
>
> Production use requires separately validated TLS, least-privilege service
> identities, protected secrets, supported versions, network restrictions,
> and operational testing. A warning banner or loopback binding alone
> does not satisfy those requirements.

## 🎯 Purpose
ELK Stack SIEM deployment guide - covering Elasticsearch, Logstash, and Kibana installation, Beats configuration, index templates, dashboards, and detection rule setup for a self-hosted security operations platform.

## ⚙️ Function
Covers: Elasticsearch cluster setup, Kibana configuration, Logstash pipelines, Filebeat/Winlogbeat/Auditbeat deployment, index lifecycle management, Kibana Lens dashboards, Elasticsearch SIEM detection rules, and performance tuning for security data volumes.

## 🏆 Goal
Deploy a fully functional self-hosted SIEM on the ELK Stack that ingests Sysmon, auditd, network, and application logs and surfaces security-relevant events through dashboards and detection rules.

## 📋 When to Use
- Building a self-hosted SIEM for a homelab or small SOC
- Setting up threat detection infrastructure for a purple team exercise
- Learning SIEM operations for professional development
- Centralizing security logs from multiple endpoints and network devices

**The ELK Stack** (, Logstash, Kibana) is a powerful open-source platform for log aggregation, search, and visualization. Combined with Beats agents, it forms a complete SIEM solution capable of ingesting data from endpoints, network devices, and applications.

This guide provides an isolated-lab ELK example for learning deployment and telemetry workflows. It is not a validated production deployment.

---

## 🎯 What is the ELK Stack?

| Component | Purpose |
|-----------|---------|
| **** | Distributed search and analytics engine; stores and indexes logs |
| **Logstash** | Data processing pipeline; parses, transforms, and enriches logs |
| **Kibana** | Visualization and dashboarding; query interface for  |
| **Beats** | Lightweight data shippers; collect and forward logs to the stack |

### ELK vs Elastic Security

Elastic (the company) offers **Elastic Security** (formerly SIEM) as part of their stack. This guide focuses on the core ELK components, but the same deployment can be extended with Elastic Security features.

---

## 📋 Prerequisites

### Server Requirements

| Component | Minimum | Recommended |
|-----------|---------|-------------|
| OS | Ubuntu 20.04/22.04 LTS | Ubuntu 22.04 LTS |
| RAM | 8 GB | 16 GB+ |
| CPU | 4 vCPUs | 8 vCPUs |
| Storage | 100 GB | 500 GB+ SSD |

> **Note:** Elasticsearch is memory-intensive. For production, allocate 50% of system RAM to the JVM heap (up to 32 GB).

### Software Requirements

- A supported, security-patched Docker Engine release, version 28.0.0
  or newer. Older releases have a documented limitation where peers on
  the same Layer-2 network can reach ports published to localhost.
- Docker Compose 2.0+
- Git

### Network Requirements

| Port | Service | Purpose |
|------|---------|---------|
| 9200 |  | REST API |
| 9300 |  | Node communication |
| 5601 | Kibana | Web interface |
| 5044 | Logstash | Beats input |
| 5000 | Logstash | TCP/UDP syslog input |
| 9600 | Logstash | Monitoring API |

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

 requires increased system limits:

```bash
# Increase virtual memory
sudo sysctl -w vm.max_map_count=262144
echo "vm.max_map_count=262144" | sudo tee -a /etc/sysctl.conf

# Increase file descriptors
echo "* soft nofile 65535" | sudo tee -a /etc/security/limits.conf
echo "* hard nofile 65535" | sudo tee -a /etc/security/limits.conf

# Apply changes
sudo sysctl -p
```

### Step 1.4: Create Directory Structure

```bash
mkdir -p ~/elk-stack/{,logstash,kibana,filebeat}
mkdir -p ~/elk-stack/logstash/{config,pipeline}
mkdir -p ~/elk-stack/elasticsearch/data
cd ~/elk-stack
```

---

## 🚀 Part 2: Docker Compose Deployment

### Step 2.1: Create Docker Compose File

> **Note:** This guide pins Elastic Stack `8.12.0` for a known-good, internally consistent config. Elastic has since released the `9.x` line - check the [Elastic Stack release notes](https://www.elastic.co/guide/en/elastic-stack/current/index.html) before deploying, since major-version upgrades can change default `xpack.*` settings and config syntax used below.

Create `docker-compose.yml`:

```yaml
version: '3.8'

services:
  elasticsearch:
    image: docker.elastic.co/elasticsearch/elasticsearch:8.12.0
    container_name: elasticsearch
    environment:
      - node.name=es-node-1
      - cluster.name=elk-cluster
      - discovery.type=single-node
      - bootstrap.memory_lock=true
      - xpack.security.enabled=true
      - xpack.security.enrollment.enabled=true
      - ELASTIC_PASSWORD=${ELASTIC_PASSWORD:?Set ELASTIC_PASSWORD in .env (see Step 2.2)}
      - "ES_JAVA_OPTS=-Xms4g -Xmx4g"
    ulimits:
      memlock:
        soft: -1
        hard: -1
      nofile:
        soft: 65535
        hard: 65535
    volumes:
      - elasticsearch-data:/usr/share/elasticsearch/data
    ports:
      - "127.0.0.1:9200:9200"
      - "127.0.0.1:9300:9300"
    networks:
      - elk-network
    healthcheck:
      # $$ makes the variable expand inside the container, so the password is not
      # written into the rendered compose config or `docker inspect` output.
      test: ["CMD-SHELL", "curl -s -u \"elastic:$$ELASTIC_PASSWORD\" http://localhost:9200/_cluster/health | grep -q 'green\\|yellow'"]
      interval: 30s
      timeout: 10s
      retries: 5

  logstash:
    image: docker.elastic.co/logstash/logstash:8.12.0
    container_name: logstash
    environment:
      # Least privilege: Logstash writes with its own role-limited user (Step 2.6),
      # never with the elastic superuser.
      - LOGSTASH_WRITER_PASSWORD=${LOGSTASH_WRITER_PASSWORD:?Set LOGSTASH_WRITER_PASSWORD in .env (see Step 2.2)}
    volumes:
      - ./logstash/config/logstash.yml:/usr/share/logstash/config/logstash.yml:ro
      - ./logstash/pipeline:/usr/share/logstash/pipeline:ro
    ports:
      - "127.0.0.1:5044:5044"
      - "127.0.0.1:5000:5000/tcp"
      - "127.0.0.1:5000:5000/udp"
      - "127.0.0.1:9600:9600"
    networks:
      - elk-network
    depends_on:
      elasticsearch:
        condition: service_healthy

  kibana:
    image: docker.elastic.co/kibana/kibana:8.12.0
    container_name: kibana
    environment:
      - ELASTICSEARCH_HOSTS=http://elasticsearch:9200
      - ELASTICSEARCH_USERNAME=kibana_system
      - ELASTICSEARCH_PASSWORD=${KIBANA_PASSWORD:?Set KIBANA_PASSWORD in .env (see Step 2.2)}
      - xpack.security.enabled=true
      - xpack.encryptedSavedObjects.encryptionKey=${ENCRYPTION_KEY:?Set ENCRYPTION_KEY in .env (see Step 2.2)}
    ports:
      - "127.0.0.1:5601:5601"
    networks:
      - elk-network
    depends_on:
      elasticsearch:
        condition: service_healthy

volumes:
  elasticsearch-data:
    driver: local

networks:
  elk-network:
    driver: bridge
```

### Step 2.2: Generate the Environment File

Do not reuse sample values. Generate unique random secrets on the Docker host.
This creates `.env` with owner-only permissions (`0600`) and refuses to overwrite
an existing file:

```bash
python3 - <<'PY'
import os, secrets

names = ("ELASTIC_PASSWORD", "KIBANA_PASSWORD", "LOGSTASH_WRITER_PASSWORD")
lines = [f"{n}={secrets.token_urlsafe(32)}" for n in names]
# Kibana requires an encryption key of at least 32 characters.
lines.append(f"ENCRYPTION_KEY={secrets.token_hex(32)}")

# O_EXCL fails instead of overwriting an existing .env; 0o600 is owner read/write only.
fd = os.open(".env", os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
with os.fdopen(fd, "w") as fh:
    fh.write("\n".join(lines) + "\n")
print("Created .env (mode 0600). Values were not printed.")
PY
```

> ⚠️ **Security:** Never commit `.env` to version control (add it to `.gitignore`),
> never paste its values into tickets or chat, and keep a copy in your password manager.
> Rotate the values if the file is ever exposed. Compose refuses to start when a
> required variable is missing, so there are no insecure fallback defaults.

### Step 2.3: Create Logstash Configuration

Create `logstash/config/logstash.yml`:

```yaml
http.host: "0.0.0.0"
xpack.monitoring.enabled: false
pipeline.workers: 2
pipeline.batch.size: 125
```

### Step 2.4: Create Logstash Pipeline

Create `logstash/pipeline/main.conf`:

```ruby
# ============================================
# INPUT SECTION
# ============================================
input {
  # Beats input (Filebeat, Winlogbeat, etc.)
  beats {
    port => 5044
    ssl => false
  }

  # Syslog input (TCP)
  tcp {
    port => 5000
    type => "syslog"
    codec => plain
  }

  # Syslog input (UDP)
  udp {
    port => 5000
    type => "syslog"
    codec => plain
  }
}

# ============================================
# FILTER SECTION
# ============================================
filter {
  # Parse syslog messages
  if [type] == "syslog" {
    grok {
      match => { "message" => "%{SYSLOGTIMESTAMP:syslog_timestamp} %{SYSLOGHOST:syslog_hostname} %{DATA:syslog_program}(?:\[%{POSINT:syslog_pid}\])?: %{GREEDYDATA:syslog_message}" }
      add_field => [ "received_at", "%{@timestamp}" ]
    }
    date {
      match => [ "syslog_timestamp", "MMM  d HH:mm:ss", "MMM dd HH:mm:ss" ]
      target => "@timestamp"
    }
  }

  # Parse Windows Event Logs (from Winlogbeat)
  if [agent][type] == "winlogbeat" {
    mutate {
      add_field => { "log_source" => "windows" }
    }
  }

  # Parse Sysmon events
  if [winlog][channel] == "Microsoft-Windows-Sysmon/Operational" {
    mutate {
      add_field => { "log_source" => "sysmon" }
    }
    
    # Extract Sysmon event ID for easier filtering
    if [winlog][event_id] {
      mutate {
        add_field => { "sysmon_event_id" => "%{[winlog][event_id]}" }
      }
    }
  }

  # Parse Filebeat logs
  if [agent][type] == "filebeat" {
    mutate {
      add_field => { "log_source" => "filebeat" }
    }
  }

  # GeoIP enrichment for source IPs
  if [source][ip] {
    geoip {
      source => "[source][ip]"
      target => "[source][geo]"
    }
  }

  # Add timestamp processing
  if ![timestamp] {
    mutate {
      add_field => { "timestamp" => "%{@timestamp}" }
    }
  }
}

# ============================================
# OUTPUT SECTION
# ============================================
output {
  # Send to Elasticsearch
  elasticsearch {
    hosts => ["http://elasticsearch:9200"]
    user => "logstash_writer"
    password => "${LOGSTASH_WRITER_PASSWORD}"
    index => "%{[@metadata][beat]}-%{[@metadata][version]}-%{+YYYY.MM.dd}"
    
    # For non-beat inputs, use a default index
    # index => "logstash-%{+YYYY.MM.dd}"
  }

  # Debug output (comment out in production)
  # stdout {
  #   codec => rubydebug
  # }
}
```

### Step 2.5: Start Elasticsearch First

Kibana and Logstash authenticate with accounts that do not have passwords yet, so
start Elasticsearch alone and wait until it reports healthy:

```bash
docker compose up -d elasticsearch
docker compose ps elasticsearch   # wait for "healthy" (can take 1-2 minutes)
```

### Step 2.6: Set Service Account Passwords and the Logstash Role

Set the `kibana_system` password and create a least-privilege Logstash writer
from the values in `.env`. Passwords travel on stdin rather than on a command
line, and the `elastic` credentials are read from the container's own environment:

```bash
set -a; . ./.env; set +a    # .env contains only the generated KEY=value lines

# Kibana's service account
printf '{"password":"%s"}' "$KIBANA_PASSWORD" |
  docker compose exec -T elasticsearch sh -c \
  'curl -sS -u "elastic:$ELASTIC_PASSWORD" -H "Content-Type: application/json" \
   -X POST http://localhost:9200/_security/user/kibana_system/_password -d @-'

# Role that can only write the indices Logstash creates
docker compose exec -T elasticsearch sh -c \
  'curl -sS -u "elastic:$ELASTIC_PASSWORD" -H "Content-Type: application/json" \
   -X PUT http://localhost:9200/_security/role/logstash_writer -d @-' <<'JSON'
{
  "cluster": ["manage_index_templates", "monitor"],
  "indices": [
    {
      "names": ["winlogbeat-*", "filebeat-*", "logstash-*"],
      "privileges": ["create_index", "create", "write"]
    }
  ]
}
JSON

# User bound to that role
printf '{"password":"%s","roles":["logstash_writer"]}' "$LOGSTASH_WRITER_PASSWORD" |
  docker compose exec -T elasticsearch sh -c \
  'curl -sS -u "elastic:$ELASTIC_PASSWORD" -H "Content-Type: application/json" \
   -X POST http://localhost:9200/_security/user/logstash_writer -d @-'

unset KIBANA_PASSWORD LOGSTASH_WRITER_PASSWORD ELASTIC_PASSWORD ENCRYPTION_KEY
```

Each call returns a JSON acknowledgement. The password endpoint is
`POST /_security/user/<name>/_password`, as described in Elastic's
*Set passwords for native and built-in users* documentation. If Logstash later logs
`403` errors, the role lacks a privilege your pipeline needs (for example ILM
management when Beats-managed ILM is enabled): adjust the index names and
privileges for your pipeline instead of falling back to the `elastic` superuser.
Check the Logstash security documentation for your Elastic version.

Now start the remaining services:

```bash
docker compose up -d
docker compose logs -f   # Ctrl-C stops following; allow 2-3 minutes to initialize
```

### Step 2.7: Verify Deployment

```bash
# Check container status
docker compose ps

# Test Elasticsearch
docker compose exec -T elasticsearch sh -c \
  'curl -sS -u "elastic:$ELASTIC_PASSWORD" "http://localhost:9200/_cluster/health?pretty"'

# Test Kibana (may take a minute to fully start)
curl -I http://localhost:5601
```

### Step 2.8: Access Kibana

Open your browser:

```
http://127.0.0.1:5601
```

Open this address in a browser running on the Docker host.
On another computer, 127.0.0.1 refers to that computer, not the ELK host.
Remote administrative access requires a separately secured access method.

**Login:**
- Username: `elastic`
- Password: the `ELASTIC_PASSWORD` value from your `.env` (copy it from your password manager; do not print it in shared terminals)

---

## 🔥 Part 3: Firewall Configuration

This lab example intentionally binds published ports to the Docker host's
loopback interface. Do not add broad firewall allowances, router port
forwards, or public reverse-proxy access for these plaintext examples.

Validate the actual Docker networking and host firewall behavior before
using the lab. Do not enable direct routing to the container network.

Remote Windows/Linux agents cannot use these loopback-only host mappings.
The remote-agent sections below require a separately designed and tested
TLS-protected ingestion path; they are not ready-to-run instructions for
this local-only configuration.

---

## 🖥️ Part 4: Windows Agent Deployment (Winlogbeat)

Winlogbeat ships Windows Event Logs to Logstash/Elasticsearch.

### Step 4.1: Download Winlogbeat

```powershell
# Download Winlogbeat
$version = "8.12.0"
Invoke-WebRequest -Uri "https://artifacts.elastic.co/downloads/beats/winlogbeat/winlogbeat-$version-windows-x86_64.zip" -OutFile "$env:TEMP\winlogbeat.zip"

# Extract
Expand-Archive -Path "$env:TEMP\winlogbeat.zip" -DestinationPath "C:\Program Files"
Rename-Item "C:\Program Files\winlogbeat-$version-windows-x86_64" "C:\Program Files\Winlogbeat"
```

### Step 4.2: Configure Winlogbeat

Edit `C:\Program Files\Winlogbeat\winlogbeat.yml`:

```yaml
# ==================== Winlogbeat Configuration ====================

winlogbeat.event_logs:
  # Windows Security Events
  - name: Security
    event_id: 4624, 4625, 4634, 4648, 4672, 4688, 4697, 4698, 4699, 4700, 4701, 4702, 4719, 4720, 4722, 4723, 4724, 4725, 4726, 4728, 4732, 4735, 4738, 4740, 4756, 4767, 4768, 4769, 4771, 4776, 4778, 4779, 4798, 4799, 5140, 5145
    ignore_older: 72h

  # Windows System Events
  - name: System
    event_id: 7045, 7040, 7036, 1074, 6005, 6006
    ignore_older: 72h

  # Sysmon Events (if installed)
  - name: Microsoft-Windows-Sysmon/Operational
    ignore_older: 72h

  # PowerShell Logging
  - name: Microsoft-Windows-PowerShell/Operational
    event_id: 4103, 4104, 4105, 4106
    ignore_older: 72h

  # Windows Defender
  - name: Microsoft-Windows-Windows Defender/Operational
    ignore_older: 72h

# ==================== Processors ====================

processors:
  - add_host_metadata:
      when.not.contains.tags: forwarded
  - add_cloud_metadata: ~

# ==================== Output ====================

# Output to Logstash
output.logstash:
  hosts: ["<ELK-SERVER-IP>:5044"]

# Alternative: Direct to Elasticsearch
# output.elasticsearch:
#   hosts: ["<ELK-SERVER-IP>:9200"]
#   username: "<beats-writer-user>"
#   password: "${BEATS_WRITER_PASSWORD}"   # store in the Beats keystore; never a literal password

# ==================== Logging ====================

logging.level: info
logging.to_files: true
logging.files:
  path: C:\ProgramData\winlogbeat\logs
  name: winlogbeat
  keepfiles: 7
  permissions: 0640
```

### Step 4.3: Install Winlogbeat Service

Open PowerShell as Administrator:

```powershell
cd "C:\Program Files\Winlogbeat"

# Test configuration
.\winlogbeat.exe test config -c .\winlogbeat.yml -e

# Install service
.\install-service-winlogbeat.ps1

# Start service
Start-Service winlogbeat

# Verify status
Get-Service winlogbeat
```

### Step 4.4: Load Kibana Dashboards (Optional)

```powershell
# Load pre-built dashboards
.\winlogbeat.exe setup --dashboards -E output.elasticsearch.hosts=["<ELK-SERVER-IP>:9200"] -E output.elasticsearch.username=<setup-user> -E output.elasticsearch.password=$env:ES_SETUP_PASSWORD
```

---

## 🐧 Part 5: Linux Agent Deployment (Filebeat)

Filebeat ships log files from Linux systems.

### Step 5.1: Install Filebeat

**Debian/Ubuntu:**

```bash
# Import GPG key
wget -qO - https://artifacts.elastic.co/GPG-KEY-elasticsearch | sudo gpg --dearmor -o /usr/share/keyrings/elasticsearch-keyring.gpg

# Add repository
echo "deb [signed-by=/usr/share/keyrings/elasticsearch-keyring.gpg] https://artifacts.elastic.co/packages/stable/apt stable main" | sudo tee /etc/apt/sources.list.d/elastic-8.x.list

# Install Filebeat
sudo apt update
sudo apt install -y filebeat
```

**RHEL/CentOS:**

```bash
# Import GPG key
sudo rpm --import https://artifacts.elastic.co/GPG-KEY-elasticsearch

# Add repository
cat << EOF | sudo tee /etc/yum.repos.d/elastic.repo
[elastic-8.x]
name=Elastic repository for 8.x packages
baseurl=https://artifacts.elastic.co/packages/stable/yum
gpgcheck=1
gpgkey=https://artifacts.elastic.co/GPG-KEY-elasticsearch
enabled=1
autorefresh=1
type=rpm-md
EOF

# Install Filebeat
sudo yum install -y filebeat
```

### Step 5.2: Configure Filebeat

Edit `/etc/filebeat/filebeat.yml`:

```yaml
# ==================== Filebeat Configuration ====================

filebeat.inputs:
  # System logs
  - type: log
    enabled: true
    paths:
      - /var/log/syslog
      - /var/log/messages
    fields:
      log_type: syslog

  # Authentication logs
  - type: log
    enabled: true
    paths:
      - /var/log/auth.log
      - /var/log/secure
    fields:
      log_type: auth

  # Apache/Nginx logs
  - type: log
    enabled: true
    paths:
      - /var/log/apache2/*.log
      - /var/log/nginx/*.log
      - /var/log/httpd/*.log
    fields:
      log_type: webserver

  # Audit logs
  - type: log
    enabled: true
    paths:
      - /var/log/audit/audit.log
    fields:
      log_type: audit

# ==================== Filebeat Modules ====================

filebeat.config.modules:
  path: ${path.config}/modules.d/*.yml
  reload.enabled: true
  reload.period: 10s

# ==================== Processors ====================

processors:
  - add_host_metadata:
      when.not.contains.tags: forwarded
  - add_cloud_metadata: ~
  - add_docker_metadata: ~

# ==================== Output ====================

# Output to Logstash
output.logstash:
  hosts: ["<ELK-SERVER-IP>:5044"]

# ==================== Logging ====================

logging.level: info
logging.to_files: true
logging.files:
  path: /var/log/filebeat
  name: filebeat
  keepfiles: 7
  permissions: 0640
```

### Step 5.3: Enable Filebeat Modules

```bash
# List available modules
sudo filebeat modules list

# Enable useful modules
sudo filebeat modules enable system
sudo filebeat modules enable auditd
sudo filebeat modules enable iptables

# For web servers
sudo filebeat modules enable apache   # or nginx
```

### Step 5.4: Start Filebeat

```bash
# Test configuration
sudo filebeat test config

# Test output connectivity
sudo filebeat test output

# Enable and start service
sudo systemctl enable filebeat
sudo systemctl start filebeat

# Check status
sudo systemctl status filebeat
```

---

## 📊 Part 6: Kibana Configuration

### Step 6.1: Create Data Views (formerly Index Patterns)

1. Navigate to **Stack Management → Data Views** (Kibana 8.x+; was "Index Patterns" in Kibana 7.x)
2. Click **Create data view**
3. Enter pattern: `winlogbeat-*` → Click **Next step**
4. Select `@timestamp` as the time field → Click **Save data view to Kibana**
5. Repeat for `filebeat-*` and `logstash-*`

### Step 6.2: Import Security Dashboards

Elastic provides pre-built dashboards:

```bash
# From the ELK server
docker exec -it kibana /bin/bash

# Load Winlogbeat dashboards
/usr/share/kibana/bin/kibana-plugin install <dashboard-url>
```

Or import via Kibana UI:
1. Navigate to **Stack Management → Saved Objects**
2. Click **Import**
3. Upload dashboard JSON files

### Step 6.3: Create Detection Rules

Navigate to **Security → Rules → Create new rule**

**Example: Failed Login Detection**

```json
{
  "name": "Multiple Failed Logins",
  "description": "Detects multiple failed login attempts",
  "type": "threshold",
  "query": "event.code:4625",
  "threshold": {
    "field": "source.ip",
    "value": 5
  },
  "severity": "medium",
  "risk_score": 50
}
```

**Example: Suspicious PowerShell**

```json
{
  "name": "Encoded PowerShell Command",
  "description": "Detects Base64 encoded PowerShell execution",
  "type": "query",
  "query": "process.command_line:*-enc* OR process.command_line:*-encodedcommand* OR process.command_line:*FromBase64String*",
  "severity": "high",
  "risk_score": 75
}
```

---

## 🔍 Part 7: Useful Kibana Queries (KQL)

### Process Analysis

```kql
# All Sysmon Process Creation events
winlog.channel:"Microsoft-Windows-Sysmon/Operational" and winlog.event_id:1

# PowerShell execution
process.name:"powershell.exe" or process.name:"pwsh.exe"

# Processes from temp directories
process.executable:*\\Temp\\* or process.executable:*\\tmp\\*

# Command with encoded content
process.command_line:*-enc* or process.command_line:*base64*
```

### Authentication Analysis

```kql
# Failed Windows logins
winlog.event_id:4625

# Successful logins
winlog.event_id:4624

# Logins from specific user
winlog.event_id:4624 and winlog.event_data.TargetUserName:"administrator"

# RDP logins (LogonType 10)
winlog.event_id:4624 and winlog.event_data.LogonType:10
```

### Network Analysis

```kql
# Sysmon network connections
winlog.event_id:3

# Connections to external IPs
winlog.event_id:3 and not destination.ip:10.* and not destination.ip:192.168.* and not destination.ip:172.16.*

# Connections on suspicious ports
destination.port:(4444 or 5555 or 6666 or 8080 or 8443)
```

### Threat Hunting

```kql
# LSASS access (credential dumping)
winlog.event_id:10 and winlog.event_data.TargetImage:*lsass.exe*

# Scheduled task creation
winlog.event_id:4698

# Service installation
winlog.event_id:7045 or winlog.event_id:4697

# Registry Run key modifications
winlog.event_id:13 and winlog.event_data.TargetObject:*CurrentVersion\\Run*
```

---

## 🔄 Part 8: Index Lifecycle Management (ILM)

Manage index retention to control storage.

### Create ILM Policy

Navigate to **Stack Management → Index Lifecycle Policies → Create policy**

**Example: 30-Day Retention**

```json
{
  "policy": {
    "phases": {
      "hot": {
        "min_age": "0ms",
        "actions": {
          "rollover": {
            "max_age": "1d",
            "max_primary_shard_size": "50gb"
          }
        }
      },
      "warm": {
        "min_age": "7d",
        "actions": {
          "shrink": {
            "number_of_shards": 1
          },
          "forcemerge": {
            "max_num_segments": 1
          }
        }
      },
      "delete": {
        "min_age": "30d",
        "actions": {
          "delete": {}
        }
      }
    }
  }
}
```

### Apply Policy to Indices

```bash
# Via API
curl -X PUT "localhost:9200/_ilm/policy/logs-policy" \
  -H 'Content-Type: application/json' \
  --user elastic \
  -d @ilm-policy.json
```

---

## 🛡️ Part 9: Security Hardening

### Enable TLS/SSL

#### Generate Certificates

```bash
# Create certs directory
mkdir -p ~/elk-stack/certs
cd ~/elk-stack/certs

# Generate CA
docker exec -it elasticsearch /usr/share/elasticsearch/bin/elasticsearch-certutil ca --out /usr/share/elasticsearch/config/elastic-stack-ca.p12 --pass ""

# Generate node certificate
docker exec -it elasticsearch /usr/share/elasticsearch/bin/elasticsearch-certutil cert --ca /usr/share/elasticsearch/config/elastic-stack-ca.p12 --out /usr/share/elasticsearch/config/elastic-certificates.p12 --pass ""
```

#### Update Docker Compose for TLS

Add to elasticsearch service environment:

```yaml
environment:
  - xpack.security.http.ssl.enabled=true
  - xpack.security.http.ssl.keystore.path=/usr/share/elasticsearch/config/elastic-certificates.p12
  - xpack.security.transport.ssl.enabled=true
  - xpack.security.transport.ssl.keystore.path=/usr/share/elasticsearch/config/elastic-certificates.p12
```

### Create Dedicated Users

```bash
# Create a read-only analyst user
curl -X POST "localhost:9200/_security/user/analyst" \
  -H 'Content-Type: application/json' \
  --user elastic \
  -d '{
    "password": "<generate-a-unique-password>",
    "roles": ["viewer", "kibana_admin"],
    "full_name": "Security Analyst"
  }'
```

### Network Segmentation

- Place ELK stack in a dedicated management VLAN
- Use firewall rules to restrict access to ports 9200/5601
- Consider using a reverse proxy (nginx) for Kibana

---

## ❗ Part 10: Troubleshooting

### Elasticsearch Won't Start

**Check logs:**
```bash
docker compose logs elasticsearch
```

**Common issues:**

| Error | Solution |
|-------|----------|
| `max virtual memory areas too low` | Run `sysctl -w vm.max_map_count=262144` |
| `unable to lock JVM memory` | Add `memlock` ulimits to docker-compose |
| `disk watermark exceeded` | Free disk space or adjust watermarks |

**Adjust disk watermarks:**
```bash
curl -X PUT "localhost:9200/_cluster/settings" \
  -H 'Content-Type: application/json' \
  --user elastic \
  -d '{
    "persistent": {
      "cluster.routing.allocation.disk.watermark.low": "90%",
      "cluster.routing.allocation.disk.watermark.high": "95%"
    }
  }'
```

### Logstash Not Receiving Data

**Check Logstash logs:**
```bash
docker compose logs logstash
```

**Test pipeline:**
```bash
# Send test message
echo "test message" | nc -q0 localhost 5000

# Check if received
curl --user elastic "localhost:9200/logstash-*/_search?pretty"
```

### Beats Not Shipping

**Test connectivity:**
```bash
# From Windows (PowerShell)
Test-NetConnection -ComputerName <ELK-IP> -Port 5044

# From Linux
nc -zv <ELK-IP> 5044
```

**Check beat logs:**
```bash
# Filebeat
tail -f /var/log/filebeat/filebeat

# Winlogbeat
Get-Content "C:\ProgramData\winlogbeat\logs\winlogbeat" -Tail 50
```

### Kibana Shows "No Results Found"

1. Verify index pattern matches data indices
2. Check time range selector (top right)
3. Verify data is actually in Elasticsearch:
```bash
curl --user elastic "localhost:9200/_cat/indices?v"
```

---

## 📚 Part 11: Additional Resources

### Documentation

- [Elastic Documentation](https://www.elastic.co/guide/index.html)
- [Elasticsearch Reference](https://www.elastic.co/guide/en/elasticsearch/reference/current/index.html)
- [Kibana Guide](https://www.elastic.co/guide/en/kibana/current/index.html)
- [Beats Documentation](https://www.elastic.co/guide/en/beats/libbeat/current/index.html)

### Security Content

- [Elastic Detection Rules](https://github.com/elastic/detection-rules)
- [Sigma Rules](https://github.com/SigmaHQ/sigma) (convertible to Elastic queries)
- [Elastic Security Labs](https://www.elastic.co/security-labs/)

### Community

- [Elastic Community](https://discuss.elastic.co/)
- [Elastic GitHub](https://github.com/elastic)

---

## 🗂️ Quick Reference

### Docker Commands

| Command | Purpose |
|---------|---------|
| `docker compose up -d` | Start stack |
| `docker compose down` | Stop stack |
| `docker compose logs -f` | Follow all logs |
| `docker compose logs elasticsearch` | View specific service logs |
| `docker compose restart logstash` | Restart single service |

### Elasticsearch API

| Endpoint | Purpose |
|----------|---------|
| `GET /_cluster/health` | Cluster health status |
| `GET /_cat/indices?v` | List all indices |
| `GET /_cat/nodes?v` | List cluster nodes |
| `DELETE /index-name` | Delete an index |
| `GET /index-name/_search` | Search an index |

### File Locations

| Component | Config Location |
|-----------|-----------------|
| Winlogbeat | `C:\Program Files\Winlogbeat\winlogbeat.yml` |
| Filebeat | `/etc/filebeat/filebeat.yml` |
| Logstash Pipeline | `~/elk-stack/logstash/pipeline/` |

### Service Commands

| OS | Service | Start | Stop | Status |
|----|---------|-------|------|--------|
| Windows | Winlogbeat | `Start-Service winlogbeat` | `Stop-Service winlogbeat` | `Get-Service winlogbeat` |
| Linux | Filebeat | `systemctl start filebeat` | `systemctl stop filebeat` | `systemctl status filebeat` |

---

*Part of the Incident Response & Log Aggregation Branch*

## Related Files
- [../README.md](../README.md) - IncidentResponse section index
- [graylog.md](graylog.md) - Alternative self-hosted SIEM
- [wazuh.md](wazuh.md) - Wazuh integrates natively with ELK
- [splunk.md](splunk.md) - Commercial SIEM alternative
- [../Endpoint-Visibility/Windows/sysmon.md](../Endpoint-Visibility/Windows/sysmon.md) - Primary data source for Windows logs
- [../../Homelab/HomeLab_Setup.md](../../Homelab/HomeLab_Setup.md) - Homelab where ELK runs
