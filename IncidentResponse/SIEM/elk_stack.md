# 🦌 ELK Stack SIEM Deployment Guide

**The ELK Stack** (Elasticsearch, Logstash, Kibana) is a powerful open-source platform for log aggregation, search, and visualization. Combined with Beats agents, it forms a complete SIEM solution capable of ingesting data from endpoints, network devices, and applications.

This guide covers deploying a production-ready ELK Stack using Docker and configuring agents to forward security telemetry.

---

## 🎯 What is the ELK Stack?

| Component | Purpose |
|-----------|---------|
| **Elasticsearch** | Distributed search and analytics engine; stores and indexes logs |
| **Logstash** | Data processing pipeline; parses, transforms, and enriches logs |
| **Kibana** | Visualization and dashboarding; query interface for Elasticsearch |
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

- Docker Engine 20.10+
- Docker Compose 2.0+
- Git

### Network Requirements

| Port | Service | Purpose |
|------|---------|---------|
| 9200 | Elasticsearch | REST API |
| 9300 | Elasticsearch | Node communication |
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

Elasticsearch requires increased system limits:

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
mkdir -p ~/elk-stack/{elasticsearch,logstash,kibana,filebeat}
mkdir -p ~/elk-stack/logstash/{config,pipeline}
mkdir -p ~/elk-stack/elasticsearch/data
cd ~/elk-stack
```

---

## 🚀 Part 2: Docker Compose Deployment

### Step 2.1: Create Docker Compose File

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
      - ELASTIC_PASSWORD=${ELASTIC_PASSWORD:-changeme}
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
      - "9200:9200"
      - "9300:9300"
    networks:
      - elk-network
    healthcheck:
      test: ["CMD-SHELL", "curl -s -u elastic:${ELASTIC_PASSWORD:-changeme} http://localhost:9200/_cluster/health | grep -q 'green\\|yellow'"]
      interval: 30s
      timeout: 10s
      retries: 5

  logstash:
    image: docker.elastic.co/logstash/logstash:8.12.0
    container_name: logstash
    environment:
      - xpack.monitoring.elasticsearch.hosts=http://elasticsearch:9200
      - xpack.monitoring.elasticsearch.username=elastic
      - xpack.monitoring.elasticsearch.password=${ELASTIC_PASSWORD:-changeme}
    volumes:
      - ./logstash/config/logstash.yml:/usr/share/logstash/config/logstash.yml:ro
      - ./logstash/pipeline:/usr/share/logstash/pipeline:ro
    ports:
      - "5044:5044"
      - "5000:5000/tcp"
      - "5000:5000/udp"
      - "9600:9600"
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
      - ELASTICSEARCH_PASSWORD=${KIBANA_PASSWORD:-changeme}
      - xpack.security.enabled=true
      - xpack.encryptedSavedObjects.encryptionKey=${ENCRYPTION_KEY:-a]V@e3~:zK7L!mP9$fGhT2wX5yB8nC4q}
    ports:
      - "5601:5601"
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

### Step 2.2: Create Environment File

Create `.env`:

```bash
# Elasticsearch superuser password
ELASTIC_PASSWORD=YourStrongPassword123!

# Kibana system user password
KIBANA_PASSWORD=YourKibanaPassword123!

# Encryption key for Kibana saved objects (32+ characters)
ENCRYPTION_KEY=a]V@e3~:zK7L!mP9$fGhT2wX5yB8nC4qR1sU6vD0
```

> ⚠️ **Security:** Change these default passwords immediately and never commit `.env` to version control.

### Step 2.3: Create Logstash Configuration

Create `logstash/config/logstash.yml`:

```yaml
http.host: "0.0.0.0"
xpack.monitoring.elasticsearch.hosts: ["http://elasticsearch:9200"]
xpack.monitoring.enabled: true
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
    user => "elastic"
    password => "${ELASTIC_PASSWORD}"
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

### Step 2.5: Start the Stack

```bash
# Start all services
docker compose up -d

# Monitor startup
docker compose logs -f

# Wait 2-3 minutes for full initialization
```

### Step 2.6: Set Up Kibana System User Password

After Elasticsearch starts, set the kibana_system password:

```bash
# Reset kibana_system password
docker exec -it elasticsearch /usr/share/elasticsearch/bin/elasticsearch-reset-password -u kibana_system -i

# Enter the password from your .env file when prompted
```

### Step 2.7: Verify Deployment

```bash
# Check container status
docker compose ps

# Test Elasticsearch
curl -u elastic:YourStrongPassword123! http://localhost:9200/_cluster/health?pretty

# Test Kibana (may take a minute to fully start)
curl -I http://localhost:5601
```

### Step 2.8: Access Kibana

Open your browser:

```
http://<SERVER-IP>:5601
```

**Login:**
- Username: `elastic`
- Password: Your `ELASTIC_PASSWORD` from `.env`

---

## 🔥 Part 3: Firewall Configuration

### UFW (Ubuntu)

```bash
sudo ufw allow 9200/tcp comment "Elasticsearch API"
sudo ufw allow 5601/tcp comment "Kibana Web UI"
sudo ufw allow 5044/tcp comment "Logstash Beats"
sudo ufw allow 5000/tcp comment "Logstash Syslog TCP"
sudo ufw allow 5000/udp comment "Logstash Syslog UDP"
sudo ufw reload
```

### Firewalld (RHEL/CentOS)

```bash
sudo firewall-cmd --permanent --add-port=9200/tcp
sudo firewall-cmd --permanent --add-port=5601/tcp
sudo firewall-cmd --permanent --add-port=5044/tcp
sudo firewall-cmd --permanent --add-port=5000/tcp
sudo firewall-cmd --permanent --add-port=5000/udp
sudo firewall-cmd --reload
```

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
#   username: "elastic"
#   password: "YourStrongPassword123!"

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
.\winlogbeat.exe setup --dashboards -E output.elasticsearch.hosts=["<ELK-SERVER-IP>:9200"] -E output.elasticsearch.username=elastic -E output.elasticsearch.password=YourStrongPassword123!
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
echo "deb [signed-by=/usr/share/keyrings/elasticsearch-keyring.gpg] https://artifacts.elastic.co/packages/8.x/apt stable main" | sudo tee /etc/apt/sources.list.d/elastic-8.x.list

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
baseurl=https://artifacts.elastic.co/packages/8.x/yum
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

### Step 6.1: Create Index Patterns

1. Navigate to **Stack Management → Index Patterns**
2. Click **Create index pattern**
3. Enter pattern: `winlogbeat-*` → Click **Next step**
4. Select `@timestamp` as the time field → Click **Create index pattern**
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
  -u elastic:YourStrongPassword123! \
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
  -u elastic:YourStrongPassword123! \
  -d '{
    "password": "AnalystPassword123!",
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
  -u elastic:YourStrongPassword123! \
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
curl -u elastic:YourStrongPassword123! "localhost:9200/logstash-*/_search?pretty"
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
curl -u elastic:YourStrongPassword123! "localhost:9200/_cat/indices?v"
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
