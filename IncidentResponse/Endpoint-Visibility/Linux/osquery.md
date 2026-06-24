# 🔎 Osquery Deployment Guide

**Osquery** is an open-source tool developed by Facebook that exposes operating system information as a relational database. Using SQL queries, you can interrogate endpoints to gather security-relevant data about processes, users, network connections, file changes, and more. It's like having a SQL interface to your entire fleet of endpoints.

This guide covers deploying Osquery on Windows and Linux, configuring security-focused queries, and integrating with your SIEM.

---

## 🎯 Why Osquery?

| Feature | Benefit |
|---------|---------|
| **SQL Interface** | Query system state using familiar SQL syntax |
| **Cross-Platform** | Windows, Linux, macOS support |
| **Low Overhead** | Lightweight agent with minimal performance impact |
| **Scheduled Queries** | Continuously monitor for security events |
| **Fleet Management** | Manage thousands of endpoints centrally |
| **Extensible** | Custom tables and extensions |

### What Can Osquery Monitor?

| Category | Examples |
|----------|----------|
| **Processes** | Running processes, command lines, parent/child relationships |
| **Users** | Logged-in users, user accounts, group memberships |
| **Network** | Open ports, active connections, listening services |
| **Files** | File integrity, hashes, permissions |
| **Hardware** | USB devices, PCI devices, disk encryption |
| **Configuration** | Startup items, scheduled tasks, services |
| **Containers** | Docker containers, images, volumes |

---

## 📋 Prerequisites

### Supported Operating Systems

| OS | Supported Versions |
|----|-------------------|
| Windows | 10, 11, Server 2016/2019/2022 |
| Ubuntu | 18.04, 20.04, 22.04 |
| Debian | 10, 11, 12 |
| CentOS/RHEL | 7, 8, 9 |
| macOS | 10.14+ |

### System Requirements

| Component | Minimum |
|-----------|---------|
| RAM | 512 MB available |
| Disk | 100 MB |
| CPU | Minimal (scheduled queries) |

---

## 🛠️ Part 1: Installation

### Linux Installation (Debian/Ubuntu)

```bash
# Add osquery repository
export OSQUERY_KEY=1484120AC4E9F8A1A577AEEE97A80C63C9D8B80B
sudo apt-key adv --keyserver keyserver.ubuntu.com --recv-keys $OSQUERY_KEY
sudo add-apt-repository 'deb [arch=amd64] https://pkg.osquery.io/deb deb main'

# Install osquery
sudo apt update
sudo apt install -y osquery
```

### Linux Installation (RHEL/CentOS)

```bash
# Add osquery repository
curl -L https://pkg.osquery.io/rpm/GPG | sudo tee /etc/pki/rpm-gpg/RPM-GPG-KEY-osquery
sudo yum-config-manager --add-repo https://pkg.osquery.io/rpm/osquery-s3-rpm.repo
sudo yum-config-manager --enable osquery-s3-rpm

# Install osquery
sudo yum install -y osquery
```

### Windows Installation

#### Method 1: MSI Installer

Download from [osquery.io/downloads](https://osquery.io/downloads/official/):

```powershell
# Download installer
$url = "https://pkg.osquery.io/windows/osquery-5.11.0.msi"
Invoke-WebRequest -Uri $url -OutFile "$env:TEMP\osquery.msi"

# Install silently
Start-Process msiexec.exe -ArgumentList "/i $env:TEMP\osquery.msi /quiet /qn" -Wait
```

#### Method 2: Chocolatey

```powershell
choco install osquery -y
```

### Verify Installation

```bash
# Linux
osqueryi --version

# Windows (PowerShell)
& "C:\Program Files\osquery\osqueryi.exe" --version
```

---

## 🖥️ Part 2: Interactive Mode (osqueryi)

Osqueryi is the interactive shell for ad-hoc queries.

### Start Interactive Shell

```bash
# Linux
sudo osqueryi

# Windows (run as Administrator)
& "C:\Program Files\osquery\osqueryi.exe"
```

### Basic Commands

```sql
-- List available tables
.tables

-- Get table schema
.schema processes

-- Show help
.help

-- Exit
.exit
```

### Essential Security Queries

#### Running Processes

```sql
-- All running processes
SELECT pid, name, path, cmdline, uid, gid 
FROM processes;

-- Processes with network connections
SELECT DISTINCT p.name, p.path, p.cmdline 
FROM processes p
JOIN process_open_sockets pos ON p.pid = pos.pid;

-- Processes running from temp directories
SELECT pid, name, path, cmdline 
FROM processes 
WHERE path LIKE '/tmp/%' 
   OR path LIKE '/var/tmp/%'
   OR path LIKE '%\\Temp\\%'
   OR path LIKE '%\\AppData\\Local\\Temp\\%';

-- Processes with suspicious names (common malware)
SELECT pid, name, path, cmdline 
FROM processes 
WHERE name IN ('nc', 'ncat', 'netcat', 'nmap', 'mimikatz', 'pwdump');
```

#### Network Connections

```sql
-- All listening ports
SELECT DISTINCT l.port, l.address, l.protocol, p.name, p.path
FROM listening_ports l
JOIN processes p ON l.pid = p.pid
ORDER BY l.port;

-- Established connections
SELECT s.pid, p.name, s.local_address, s.local_port, 
       s.remote_address, s.remote_port, s.state
FROM process_open_sockets s
JOIN processes p ON s.pid = p.pid
WHERE s.state = 'ESTABLISHED'
ORDER BY p.name;

-- Connections to external IPs
SELECT s.pid, p.name, s.remote_address, s.remote_port
FROM process_open_sockets s
JOIN processes p ON s.pid = p.pid
WHERE s.remote_address NOT LIKE '127.%'
  AND s.remote_address NOT LIKE '10.%'
  AND s.remote_address NOT LIKE '192.168.%'
  AND s.remote_address NOT LIKE '172.16.%'
  AND s.remote_address != ''
  AND s.remote_address != '0.0.0.0'
  AND s.remote_address != '::';
```

#### User and Authentication

```sql
-- Logged in users
SELECT * FROM logged_in_users;

-- Local user accounts
SELECT uid, gid, username, description, directory, shell 
FROM users;

-- Users in sudo/admin groups (Linux)
SELECT u.username, g.groupname
FROM users u
JOIN user_groups ug ON u.uid = ug.uid
JOIN groups g ON ug.gid = g.gid
WHERE g.groupname IN ('sudo', 'wheel', 'admin');

-- Windows local admins
SELECT * FROM user_groups 
WHERE groupname = 'Administrators';

-- Recently created users (by UID range)
SELECT * FROM users WHERE uid > 1000 ORDER BY uid DESC;
```

#### Persistence Mechanisms

```sql
-- Startup items (Linux)
SELECT name, path, args, source 
FROM startup_items;

-- Cron jobs (Linux)
SELECT * FROM crontab;

-- Systemd units (Linux)
SELECT id, description, load_state, active_state, sub_state, path 
FROM systemd_units 
WHERE active_state = 'active';

-- Scheduled tasks (Windows)
SELECT name, action, path, enabled, last_run_time, next_run_time 
FROM scheduled_tasks 
WHERE enabled = 1;

-- Windows services
SELECT name, display_name, path, start_type, status 
FROM services 
WHERE start_type = 'AUTO_START';

-- Autoruns (Windows)
SELECT name, path, source 
FROM autoexec;
```

#### File System

```sql
-- SUID binaries (Linux - potential privilege escalation)
SELECT path, mode, uid, gid 
FROM suid_bin;

-- World-writable files in /etc (Linux)
SELECT path, mode 
FROM file 
WHERE path LIKE '/etc/%' 
  AND mode LIKE '%7';

-- Recently modified files
SELECT path, mtime, size 
FROM file 
WHERE path LIKE '/tmp/%' 
  AND mtime > (strftime('%s', 'now') - 3600);

-- Files with suspicious extensions (Windows)
SELECT path, filename, size, mtime 
FROM file 
WHERE path LIKE 'C:\\Users\\%\\Downloads\\%'
  AND (filename LIKE '%.exe' 
    OR filename LIKE '%.dll' 
    OR filename LIKE '%.ps1' 
    OR filename LIKE '%.bat');
```

#### Browser Artifacts

```sql
-- Chrome extensions
SELECT * FROM chrome_extensions;

-- Firefox addons
SELECT * FROM firefox_addons;

-- Browser history (sample - be careful with privacy)
SELECT url, title, visit_count, last_visit_time 
FROM chrome_visits 
LIMIT 10;
```

---

## ⚙️ Part 3: Daemon Configuration (osqueryd)

Osqueryd runs as a service, executing scheduled queries and logging results.

### Step 3.1: Create Configuration Directory

```bash
# Linux
sudo mkdir -p /etc/osquery
sudo mkdir -p /var/log/osquery

# Windows (created during installation)
# C:\Program Files\osquery\
```

### Step 3.2: Create Main Configuration

Create `/etc/osquery/osquery.conf` (Linux) or `C:\Program Files\osquery\osquery.conf` (Windows):

```json
{
  "options": {
    "config_plugin": "filesystem",
    "logger_plugin": "filesystem",
    "logger_path": "/var/log/osquery",
    "disable_logging": "false",
    "log_result_events": "true",
    "schedule_splay_percent": "10",
    "pidfile": "/var/run/osquery/osqueryd.pidfile",
    "events_expiry": "3600",
    "database_path": "/var/osquery/osquery.db",
    "verbose": "false",
    "worker_threads": "2",
    "enable_monitor": "true",
    "schedule_default_interval": "3600"
  },

  "schedule": {
    "system_info": {
      "query": "SELECT hostname, cpu_type, cpu_brand, physical_memory FROM system_info;",
      "interval": 3600
    },
    "processes": {
      "query": "SELECT pid, name, path, cmdline, cwd, uid, gid, on_disk FROM processes;",
      "interval": 300
    },
    "listening_ports": {
      "query": "SELECT DISTINCT l.port, l.protocol, l.address, p.pid, p.name, p.path FROM listening_ports l JOIN processes p ON l.pid = p.pid;",
      "interval": 300
    },
    "open_sockets": {
      "query": "SELECT pid, remote_address, remote_port, local_address, local_port FROM process_open_sockets WHERE remote_address != '' AND remote_address != '0.0.0.0' AND remote_address != '::';",
      "interval": 60
    },
    "logged_in_users": {
      "query": "SELECT * FROM logged_in_users;",
      "interval": 300
    },
    "crontab": {
      "query": "SELECT * FROM crontab;",
      "interval": 3600,
      "platform": "posix"
    },
    "scheduled_tasks": {
      "query": "SELECT name, action, path, enabled FROM scheduled_tasks WHERE enabled = 1;",
      "interval": 3600,
      "platform": "windows"
    },
    "startup_items": {
      "query": "SELECT * FROM startup_items;",
      "interval": 3600
    },
    "shell_history": {
      "query": "SELECT * FROM shell_history;",
      "interval": 900,
      "platform": "posix"
    }
  },

  "decorators": {
    "load": [
      "SELECT uuid AS host_uuid FROM system_info;",
      "SELECT hostname AS hostname FROM system_info;"
    ]
  },

  "packs": {
    "security-pack": "/etc/osquery/packs/security.conf"
  }
}
```

### Step 3.3: Create Security Query Pack

Create `/etc/osquery/packs/security.conf`:

```json
{
  "platform": "all",
  "queries": {
    
    "process_events": {
      "query": "SELECT auid, pid, uid, euid, gid, egid, owner_uid, owner_gid, cmdline, path, time FROM process_events;",
      "interval": 60,
      "description": "Process execution events"
    },

    "socket_events": {
      "query": "SELECT action, pid, path, remote_address, remote_port, local_address, local_port, time FROM socket_events WHERE action = 'connect';",
      "interval": 60,
      "description": "Network connection events"
    },

    "file_events": {
      "query": "SELECT target_path, category, action, md5, sha256, time FROM file_events;",
      "interval": 60,
      "description": "File integrity monitoring events"
    },

    "user_events": {
      "query": "SELECT * FROM user_events;",
      "interval": 60,
      "description": "User login/logout events"
    },

    "suid_bin_changes": {
      "query": "SELECT path, mode, uid, gid FROM suid_bin;",
      "interval": 3600,
      "description": "SUID binaries",
      "platform": "posix"
    },

    "kernel_modules": {
      "query": "SELECT name, size, used_by, status FROM kernel_modules;",
      "interval": 3600,
      "description": "Loaded kernel modules",
      "platform": "posix"
    },

    "windows_services_change": {
      "query": "SELECT name, display_name, path, start_type, status FROM services;",
      "interval": 300,
      "description": "Windows services",
      "platform": "windows"
    },

    "usb_devices": {
      "query": "SELECT * FROM usb_devices;",
      "interval": 300,
      "description": "Connected USB devices"
    },

    "browser_extensions": {
      "query": "SELECT * FROM chrome_extensions;",
      "interval": 3600,
      "description": "Chrome browser extensions"
    },

    "authorized_keys": {
      "query": "SELECT * FROM authorized_keys;",
      "interval": 3600,
      "description": "SSH authorized keys",
      "platform": "posix"
    },

    "known_hosts": {
      "query": "SELECT * FROM known_hosts;",
      "interval": 3600,
      "description": "SSH known hosts",
      "platform": "posix"
    },

    "iptables": {
      "query": "SELECT * FROM iptables;",
      "interval": 3600,
      "description": "Iptables rules",
      "platform": "linux"
    },

    "dns_resolvers": {
      "query": "SELECT * FROM dns_resolvers;",
      "interval": 3600,
      "description": "DNS resolver configuration"
    },

    "etc_hosts": {
      "query": "SELECT * FROM etc_hosts;",
      "interval": 3600,
      "description": "Hosts file entries"
    }
  }
}
```

### Step 3.4: Configure File Integrity Monitoring (FIM)

Add to `osquery.conf`:

```json
{
  "file_paths": {
    "etc": [
      "/etc/%%"
    ],
    "binaries": [
      "/usr/bin/%%",
      "/usr/sbin/%%",
      "/bin/%%",
      "/sbin/%%"
    ],
    "sensitive": [
      "/etc/passwd",
      "/etc/shadow",
      "/etc/sudoers",
      "/etc/ssh/sshd_config"
    ],
    "cron": [
      "/etc/cron.d/%%",
      "/var/spool/cron/crontabs/%%"
    ],
    "tmp": [
      "/tmp/%%",
      "/var/tmp/%%"
    ]
  },
  "file_accesses": ["etc", "sensitive"],
  "exclude_paths": {
    "etc": [
      "/etc/mtab",
      "/etc/resolv.conf"
    ]
  }
}
```

---

## 🚀 Part 4: Start the Daemon

### Linux

```bash
# Enable and start osqueryd
sudo systemctl enable osqueryd
sudo systemctl start osqueryd

# Check status
sudo systemctl status osqueryd

# View logs
sudo tail -f /var/log/osquery/osqueryd.results.log
```

### Windows

```powershell
# Start service
Start-Service osqueryd

# Set to automatic start
Set-Service osqueryd -StartupType Automatic

# Check status
Get-Service osqueryd
```

### Verify Daemon is Running

```bash
# Check if daemon is generating logs
tail /var/log/osquery/osqueryd.results.log

# Sample output (JSON format)
# {"name":"processes","hostIdentifier":"hostname","calendarTime":"Mon Jan 15 12:00:00 2024 UTC","unixTime":1705320000,"epoch":0,"counter":0,"numerics":false,"columns":{"cmdline":"/usr/sbin/sshd -D","name":"sshd","path":"/usr/sbin/sshd","pid":"1234"},"action":"added"}
```

---

## 📤 Part 5: Forward Logs to SIEM

### Option 1: Filebeat

Install Filebeat and configure `/etc/filebeat/filebeat.yml`:

```yaml
filebeat.inputs:
  - type: log
    enabled: true
    paths:
      - /var/log/osquery/osqueryd.results.log
    json.keys_under_root: true
    json.add_error_key: true
    fields:
      log_type: osquery
    fields_under_root: true

output.logstash:
  hosts: ["<SIEM-IP>:5044"]
```

### Option 2: Rsyslog

Configure osquery to log to syslog. Update `osquery.conf`:

```json
{
  "options": {
    "logger_plugin": "syslog",
    "logger_syslog_facility": "19"
  }
}
```

Then forward via rsyslog:

```bash
# /etc/rsyslog.d/60-osquery.conf
local3.* @@<SIEM-IP>:514
```

### Option 3: Wazuh Integration

Wazuh can read osquery logs directly. Add to `/var/ossec/etc/ossec.conf`:

```xml
<localfile>
    <log_format>json</log_format>
    <location>/var/log/osquery/osqueryd.results.log</location>
</localfile>
```

### Option 4: Fleetdm (Fleet Management)

For managing multiple endpoints, consider [Fleet](https://fleetdm.com/):

```bash
# Fleet provides centralized osquery management
# https://fleetdm.com/docs/deploying/introduction
```

---

## 🏢 Part 6: Enterprise Deployment

### Windows Deployment via GPO

#### Create Deployment Package

1. Download MSI from osquery.io
2. Create a network share: `\\fileserver\osquery$`
3. Copy MSI and configuration files

#### GPO Software Installation

1. Open Group Policy Management
2. Create new GPO: `Osquery Deployment`
3. Navigate to: **Computer Configuration → Policies → Software Settings → Software Installation**
4. Right-click → **New → Package**
5. Browse to MSI on network share
6. Select **Assigned**

#### Deploy Configuration via GPO

Use GPO Preferences to copy config files:

1. **Computer Configuration → Preferences → Windows Settings → Files**
2. Add source: `\\fileserver\osquery$\osquery.conf`
3. Add destination: `C:\Program Files\osquery\osquery.conf`

### Linux Deployment via Ansible

Create `deploy_osquery.yml`:

```yaml
---
- name: Deploy Osquery
  hosts: all
  become: yes
  
  tasks:
    - name: Add osquery repository (Debian)
      apt_repository:
        repo: 'deb [arch=amd64] https://pkg.osquery.io/deb deb main'
        state: present
      when: ansible_os_family == "Debian"

    - name: Install osquery
      package:
        name: osquery
        state: present

    - name: Deploy osquery configuration
      copy:
        src: files/osquery.conf
        dest: /etc/osquery/osquery.conf
        owner: root
        group: root
        mode: '0644'
      notify: Restart osqueryd

    - name: Deploy security pack
      copy:
        src: files/packs/security.conf
        dest: /etc/osquery/packs/security.conf
        owner: root
        group: root
        mode: '0644'
      notify: Restart osqueryd

    - name: Enable and start osqueryd
      service:
        name: osqueryd
        state: started
        enabled: yes

  handlers:
    - name: Restart osqueryd
      service:
        name: osqueryd
        state: restarted
```

Run deployment:

```bash
ansible-playbook -i inventory.ini deploy_osquery.yml
```

---

## 🔍 Part 7: Threat Hunting Queries

### Detect Persistence

```sql
-- New scheduled tasks (Windows)
SELECT name, action, path, enabled, date_created 
FROM scheduled_tasks 
WHERE date_created > datetime('now', '-1 day');

-- Suspicious startup items
SELECT * FROM startup_items 
WHERE path LIKE '%powershell%' 
   OR path LIKE '%cmd%' 
   OR path LIKE '%wscript%'
   OR path LIKE '%cscript%';

-- New cron jobs (Linux)
SELECT * FROM crontab 
WHERE command LIKE '%curl%' 
   OR command LIKE '%wget%' 
   OR command LIKE '%nc %'
   OR command LIKE '%/dev/tcp%';

-- Suspicious systemd services
SELECT id, path, fragment_path 
FROM systemd_units 
WHERE fragment_path LIKE '/tmp/%' 
   OR fragment_path LIKE '/var/tmp/%'
   OR fragment_path LIKE '/dev/shm/%';
```

### Detect Credential Access

```sql
-- Processes accessing sensitive files (Linux)
SELECT p.name, p.path, p.cmdline, pof.path AS file_accessed
FROM processes p
JOIN process_open_files pof ON p.pid = pof.pid
WHERE pof.path IN ('/etc/shadow', '/etc/passwd', '/etc/sudoers');

-- LSASS access attempts (Windows)
SELECT p.name, p.path, p.cmdline 
FROM processes p
WHERE p.name = 'lsass.exe';

-- Mimikatz indicators
SELECT * FROM processes 
WHERE cmdline LIKE '%sekurlsa%' 
   OR cmdline LIKE '%kerberos::list%'
   OR cmdline LIKE '%lsadump%'
   OR name LIKE '%mimikatz%';
```

### Detect Lateral Movement

```sql
-- RDP connections (Windows)
SELECT * FROM logged_in_users 
WHERE type = 'remote';

-- SSH connections (Linux)
SELECT * FROM logged_in_users 
WHERE tty LIKE 'pts%';

-- New SSH authorized keys
SELECT * FROM authorized_keys;

-- PsExec-like activity
SELECT * FROM processes 
WHERE name IN ('psexec.exe', 'psexesvc.exe', 'paexec.exe', 'winexesvc.exe')
   OR cmdline LIKE '%\\admin$%'
   OR cmdline LIKE '%\\c$%';
```

### Detect Exfiltration

```sql
-- Large outbound connections
SELECT s.pid, p.name, p.path, s.remote_address, s.remote_port
FROM process_open_sockets s
JOIN processes p ON s.pid = p.pid
WHERE s.remote_address NOT LIKE '127.%'
  AND s.remote_address NOT LIKE '10.%'
  AND s.remote_address NOT LIKE '192.168.%'
  AND s.remote_port IN (21, 22, 80, 443, 8080, 8443);

-- DNS tunneling indicators
SELECT * FROM processes 
WHERE cmdline LIKE '%dns%tunnel%'
   OR cmdline LIKE '%iodine%'
   OR cmdline LIKE '%dnscat%';

-- Cloud storage processes
SELECT * FROM processes 
WHERE name IN ('dropbox', 'onedrive', 'googledrive', 'megasync', 'rclone');
```

### Detect Defense Evasion

```sql
-- Processes with deleted binaries
SELECT pid, name, path, cmdline 
FROM processes 
WHERE on_disk = 0;

-- Hidden files in temp (Linux)
SELECT path, filename, size, mtime 
FROM file 
WHERE (path LIKE '/tmp/.%' OR path LIKE '/var/tmp/.%')
  AND type = 'regular';

-- Timestomped files (mtime before ctime)
SELECT path, mtime, ctime 
FROM file 
WHERE path LIKE '/tmp/%' 
  AND mtime < ctime;

-- Disabled security products (Windows)
SELECT name, display_name, status, start_type 
FROM services 
WHERE (name LIKE '%defender%' 
    OR name LIKE '%symantec%' 
    OR name LIKE '%mcafee%'
    OR name LIKE '%crowdstrike%')
  AND status != 'RUNNING';
```

---

## 📊 Part 8: Osquery Tables Reference

### Process Tables

| Table | Description | Platform |
|-------|-------------|----------|
| `processes` | Running processes | All |
| `process_events` | Process execution events | All |
| `process_open_files` | Files opened by processes | All |
| `process_open_sockets` | Network sockets | All |
| `process_memory_map` | Process memory regions | All |

### Network Tables

| Table | Description | Platform |
|-------|-------------|----------|
| `listening_ports` | Listening network ports | All |
| `socket_events` | Socket connection events | Linux/macOS |
| `interface_addresses` | Network interface IPs | All |
| `routes` | Routing table | All |
| `arp_cache` | ARP cache | All |
| `dns_resolvers` | DNS configuration | All |

### User Tables

| Table | Description | Platform |
|-------|-------------|----------|
| `users` | Local user accounts | All |
| `groups` | Local groups | All |
| `user_groups` | User-group memberships | All |
| `logged_in_users` | Currently logged in users | All |
| `last` | Login history | Linux/macOS |
| `user_events` | User login/logout events | Linux |

### File System Tables

| Table | Description | Platform |
|-------|-------------|----------|
| `file` | File metadata | All |
| `file_events` | FIM events | All |
| `hash` | File hashes | All |
| `suid_bin` | SUID binaries | Linux/macOS |
| `authorized_keys` | SSH authorized keys | Linux/macOS |

### Persistence Tables

| Table | Description | Platform |
|-------|-------------|----------|
| `startup_items` | Startup programs | All |
| `crontab` | Cron jobs | Linux/macOS |
| `scheduled_tasks` | Scheduled tasks | Windows |
| `services` | Windows services | Windows |
| `systemd_units` | Systemd services | Linux |
| `launchd` | Launch daemons | macOS |

### System Tables

| Table | Description | Platform |
|-------|-------------|----------|
| `system_info` | System information | All |
| `os_version` | OS version details | All |
| `kernel_info` | Kernel information | Linux |
| `kernel_modules` | Loaded kernel modules | Linux |
| `drivers` | Loaded drivers | Windows |
| `uptime` | System uptime | All |

---

## ❗ Part 9: Troubleshooting

### Osquery Won't Start

```bash
# Check configuration syntax
osqueryd --config_check --config_path /etc/osquery/osquery.conf

# Run in foreground with verbose output
sudo osqueryd --verbose --config_path /etc/osquery/osquery.conf --disable_watchdog

# Check logs
sudo journalctl -u osqueryd -f
```

### High Resource Usage

```json
// Reduce query frequency in osquery.conf
{
  "options": {
    "worker_threads": "1",
    "schedule_default_interval": "7200"
  }
}
```

```bash
# Identify expensive queries
# Check /var/log/osquery/osqueryd.INFO for timing info
```

### Queries Not Returning Data

```bash
# Test query interactively
sudo osqueryi --config_path /etc/osquery/osquery.conf

# Check table availability
.schema <table_name>

# Verify events are enabled
SELECT * FROM osquery_events;

# Check for errors
SELECT * FROM osquery_info;
```

### Permission Denied Errors

```bash
# Ensure osqueryd runs as root
ps aux | grep osquery

# Check file permissions
ls -la /etc/osquery/
ls -la /var/log/osquery/
ls -la /var/osquery/
```

---

## 🛡️ Part 10: Security Hardening

### Protect Configuration Files

```bash
# Linux
sudo chown root:root /etc/osquery/osquery.conf
sudo chmod 600 /etc/osquery/osquery.conf

# Restrict osquery database
sudo chmod 700 /var/osquery/
```

### Enable TLS for Fleet

If using Fleet for central management:

```json
{
  "options": {
    "tls_hostname": "fleet.company.com",
    "tls_server_certs": "/etc/osquery/fleet.crt",
    "enroll_secret_path": "/etc/osquery/enroll_secret",
    "config_plugin": "tls",
    "logger_plugin": "tls"
  }
}
```

### Audit Osquery Access

```bash
# Monitor osquery binary execution
# Add to audit rules:
-w /usr/bin/osqueryi -p x -k osquery_interactive
-w /usr/bin/osqueryd -p x -k osquery_daemon
```

---

## 📚 Part 11: Additional Resources

### Documentation

- [Osquery Documentation](https://osquery.readthedocs.io/)
- [Osquery Schema](https://osquery.io/schema/)
- [Osquery GitHub](https://github.com/osquery/osquery)

### Query Packs

- [Osquery Packs](https://github.com/osquery/osquery/tree/master/packs)
- [Palantir osquery-configuration](https://github.com/palantir/osquery-configuration)
- [Chainguard osquery-defense-kit](https://github.com/chainguard-dev/osquery-defense-kit)

### Fleet Management

- [Fleet (FleetDM)](https://fleetdm.com/)
- [Kolide Fleet](https://github.com/kolide/fleet)

### Community

- [Osquery Slack](https://osquery.slack.com/)
- [Osquery GitHub Discussions](https://github.com/osquery/osquery/discussions)

---

## 🗂️ Quick Reference

### Commands

| Command | Purpose |
|---------|---------|
| `osqueryi` | Interactive SQL shell |
| `osqueryd` | Run as daemon |
| `osqueryd --config_check` | Validate configuration |
| `osqueryctl start` | Start daemon (alternative) |

### Interactive Shell Commands

| Command | Purpose |
|---------|---------|
| `.tables` | List all tables |
| `.schema <table>` | Show table schema |
| `.mode line` | Line output format |
| `.mode pretty` | Pretty output format |
| `.help` | Show help |
| `.exit` | Exit shell |

### Configuration Locations

| OS | Configuration | Logs | Database |
|----|--------------|------|----------|
| Linux | `/etc/osquery/osquery.conf` | `/var/log/osquery/` | `/var/osquery/` |
| Windows | `C:\Program Files\osquery\osquery.conf` | `C:\Program Files\osquery\log\` | `C:\Program Files\osquery\osquery.db` |
| macOS | `/var/osquery/osquery.conf` | `/var/log/osquery/` | `/var/osquery/` |

### Service Commands

| OS | Start | Stop | Status |
|----|-------|------|--------|
| Linux | `systemctl start osqueryd` | `systemctl stop osqueryd` | `systemctl status osqueryd` |
| Windows | `Start-Service osqueryd` | `Stop-Service osqueryd` | `Get-Service osqueryd` |
| macOS | `sudo osqueryctl start` | `sudo osqueryctl stop` | `sudo osqueryctl status` |

### Common Security Tables

| Table | Use Case |
|-------|----------|
| `processes` | Running processes |
| `listening_ports` | Open ports |
| `process_open_sockets` | Network connections |
| `logged_in_users` | Active sessions |
| `crontab` / `scheduled_tasks` | Persistence |
| `startup_items` | Autoruns |
| `file_events` | File integrity |
| `users` | Account enumeration |

---

*Part of the Incident Response & Log Aggregation Branch*
