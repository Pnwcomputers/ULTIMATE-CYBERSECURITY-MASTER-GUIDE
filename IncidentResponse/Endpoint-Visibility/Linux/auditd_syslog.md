
# 🐧 Linux Auditd & Syslog Hardening Guide

**Auditd** (Linux Audit Daemon) and **Syslog** are foundational components for Linux security monitoring. Auditd provides granular kernel-level auditing of system calls, file access, and user activity, while Syslog aggregates application and system logs. Together, they form the backbone of Linux endpoint visibility.

This guide covers configuring both systems for security monitoring and forwarding logs to your SIEM.

---

## 🎯 Auditd vs Syslog: Understanding the Difference

| Feature | Auditd | Syslog |
|---------|--------|--------|
| **Purpose** | Kernel-level auditing | Application/system logging |
| **Data Source** | System calls, file access, auth | Application messages, services |
| **Granularity** | Very detailed | Varies by application |
| **Performance Impact** | Higher (configurable) | Lower |
| **Compliance** | PCI-DSS, HIPAA, SOX | General logging |
| **Log Location** | `/var/log/audit/audit.log` | `/var/log/syslog`, `/var/log/messages` |

### When to Use Each

- **Auditd:** Security monitoring, compliance, forensics, detecting unauthorized access
- **Syslog:** General system health, application debugging, service monitoring
- **Both:** Comprehensive visibility (recommended for security)

---

## 📋 Prerequisites

### Supported Systems

| Distribution | Auditd Package | Syslog Package |
|--------------|----------------|----------------|
| Ubuntu/Debian | `auditd` | `rsyslog` |
| RHEL/CentOS/Rocky | `audit` | `rsyslog` |
| Fedora | `audit` | `rsyslog` |
| SUSE | `audit` | `rsyslog` |

### Requirements

- Root or sudo access
- SIEM server configured to receive logs
- Network connectivity to SIEM (port 514 or custom)

---

## 🛠️ Part 1: Auditd Installation and Configuration

### Step 1.1: Install Auditd

**Debian/Ubuntu:**

```bash
sudo apt update
sudo apt install -y auditd audispd-plugins
```

**RHEL/CentOS/Rocky:**

```bash
sudo yum install -y audit audit-libs audispd-plugins
# Or on RHEL 8+/Rocky
sudo dnf install -y audit audispd-plugins
```

### Step 1.2: Enable and Start Auditd

```bash
sudo systemctl enable auditd
sudo systemctl start auditd

# Verify status
sudo systemctl status auditd

# Check audit rules are loaded
sudo auditctl -l
```

### Step 1.3: Understand Auditd Configuration Files

| File | Purpose |
|------|---------|
| `/etc/audit/auditd.conf` | Daemon configuration (log size, rotation) |
| `/etc/audit/rules.d/*.rules` | Audit rules (what to monitor) |
| `/etc/audit/audit.rules` | Compiled rules (auto-generated) |
| `/etc/audisp/plugins.d/` | Dispatcher plugins (forwarding) |

---

## 📜 Part 2: Auditd Rules Configuration

### Understanding Audit Rules

Audit rules define what activities to monitor. There are three types:

| Type | Flag | Purpose | Example |
|------|------|---------|---------|
| Control | `-D`, `-b`, `-f` | Configure audit system | `-b 8192` (buffer size) |
| File Watch | `-w` | Monitor file/directory access | `-w /etc/passwd` |
| System Call | `-a` | Monitor specific syscalls | `-a always,exit -S execve` |

### Step 2.1: Create Security-Focused Rules

Create `/etc/audit/rules.d/99-security.rules`:

```bash
## ============================================
## Linux Audit Rules for Security Monitoring
## ============================================

## First, clear existing rules
-D

## Set buffer size (increase for busy systems)
-b 8192

## Set failure mode (1=printk, 2=panic)
-f 1

## ============================================
## Self Auditing (Audit Configuration Changes)
## ============================================

## Monitor audit configuration changes
-w /etc/audit/ -p wa -k audit_config
-w /etc/libaudit.conf -p wa -k audit_config
-w /etc/audisp/ -p wa -k audit_config

## Monitor audit tools
-w /sbin/auditctl -p x -k audit_tools
-w /sbin/auditd -p x -k audit_tools
-w /usr/sbin/auditctl -p x -k audit_tools

## ============================================
## Authentication and Authorization
## ============================================

## Monitor authentication files
-w /etc/passwd -p wa -k identity
-w /etc/shadow -p wa -k identity
-w /etc/group -p wa -k identity
-w /etc/gshadow -p wa -k identity
-w /etc/security/opasswd -p wa -k identity

## Monitor PAM configuration
-w /etc/pam.d/ -p wa -k pam_config
-w /etc/security/ -p wa -k pam_config

## Monitor sudo configuration
-w /etc/sudoers -p wa -k sudo_config
-w /etc/sudoers.d/ -p wa -k sudo_config

## Monitor SSH configuration
-w /etc/ssh/sshd_config -p wa -k sshd_config
-w /etc/ssh/ssh_config -p wa -k ssh_config
-w /root/.ssh/ -p wa -k ssh_keys

## ============================================
## Privilege Escalation
## ============================================

## Monitor setuid/setgid
-a always,exit -F arch=b64 -S setuid -S setgid -S setreuid -S setregid -k privilege_escalation
-a always,exit -F arch=b32 -S setuid -S setgid -S setreuid -S setregid -k privilege_escalation

## Monitor sudo usage
-a always,exit -F path=/usr/bin/sudo -F perm=x -k sudo_execution
-a always,exit -F path=/usr/bin/su -F perm=x -k su_execution

## Monitor privilege changes
-a always,exit -F arch=b64 -S seteuid -S setfsuid -k privilege_modification
-a always,exit -F arch=b32 -S seteuid -S setfsuid -k privilege_modification

## ============================================
## Process Execution
## ============================================

## Monitor all process execution (equivalent to Sysmon Event ID 1)
-a always,exit -F arch=b64 -S execve -k process_execution
-a always,exit -F arch=b32 -S execve -k process_execution

## Monitor specific suspicious binaries
-w /usr/bin/wget -p x -k suspicious_download
-w /usr/bin/curl -p x -k suspicious_download
-w /usr/bin/nc -p x -k netcat
-w /usr/bin/ncat -p x -k netcat
-w /usr/bin/netcat -p x -k netcat
-w /usr/bin/nmap -p x -k recon_tool
-w /usr/bin/base64 -p x -k encoding
-w /usr/bin/python -p x -k scripting
-w /usr/bin/python3 -p x -k scripting
-w /usr/bin/perl -p x -k scripting
-w /usr/bin/ruby -p x -k scripting

## ============================================
## Network Activity
## ============================================

## Monitor network socket creation
-a always,exit -F arch=b64 -S socket -F a0=2 -k network_socket_ipv4
-a always,exit -F arch=b32 -S socket -F a0=2 -k network_socket_ipv4
-a always,exit -F arch=b64 -S socket -F a0=10 -k network_socket_ipv6
-a always,exit -F arch=b32 -S socket -F a0=10 -k network_socket_ipv6

## Monitor network connections
-a always,exit -F arch=b64 -S connect -k network_connect
-a always,exit -F arch=b32 -S connect -k network_connect

## Monitor hosts file changes
-w /etc/hosts -p wa -k hosts_file
-w /etc/resolv.conf -p wa -k dns_config

## ============================================
## File System Monitoring
## ============================================

## Monitor temporary directories (malware staging)
-w /tmp/ -p wa -k tmp_activity
-w /var/tmp/ -p wa -k tmp_activity
-w /dev/shm/ -p wa -k shm_activity

## Monitor cron (persistence)
-w /etc/cron.d/ -p wa -k cron_config
-w /etc/cron.daily/ -p wa -k cron_config
-w /etc/cron.hourly/ -p wa -k cron_config
-w /etc/cron.monthly/ -p wa -k cron_config
-w /etc/cron.weekly/ -p wa -k cron_config
-w /etc/crontab -p wa -k cron_config
-w /var/spool/cron/ -p wa -k cron_jobs

## Monitor systemd (persistence)
-w /etc/systemd/ -p wa -k systemd_config
-w /lib/systemd/ -p wa -k systemd_config
-w /usr/lib/systemd/ -p wa -k systemd_config

## Monitor init scripts (persistence)
-w /etc/init.d/ -p wa -k init_scripts
-w /etc/rc.local -p wa -k rc_local

## ============================================
## Kernel and Modules
## ============================================

## Monitor kernel module loading
-a always,exit -F arch=b64 -S init_module -S finit_module -k kernel_module_load
-a always,exit -F arch=b32 -S init_module -S finit_module -k kernel_module_load
-a always,exit -F arch=b64 -S delete_module -k kernel_module_unload
-a always,exit -F arch=b32 -S delete_module -k kernel_module_unload

## Monitor modprobe configuration
-w /etc/modprobe.d/ -p wa -k modprobe_config

## Monitor kernel parameters
-w /etc/sysctl.conf -p wa -k sysctl_config
-w /etc/sysctl.d/ -p wa -k sysctl_config

## ============================================
## Time and Locale (Anti-Forensics)
## ============================================

## Monitor time changes
-a always,exit -F arch=b64 -S adjtimex -S settimeofday -S clock_settime -k time_change
-a always,exit -F arch=b32 -S adjtimex -S settimeofday -S clock_settime -k time_change

## Monitor timezone changes
-w /etc/localtime -p wa -k time_change
-w /etc/timezone -p wa -k time_change

## ============================================
## Log Tampering (Anti-Forensics)
## ============================================

## Monitor log files
-w /var/log/audit/ -p wa -k audit_logs
-w /var/log/auth.log -p wa -k auth_log
-w /var/log/secure -p wa -k auth_log
-w /var/log/syslog -p wa -k syslog
-w /var/log/messages -p wa -k syslog
-w /var/log/wtmp -p wa -k login_log
-w /var/log/btmp -p wa -k login_log
-w /var/log/lastlog -p wa -k login_log

## ============================================
## Container Activity
## ============================================

## Monitor Docker
-w /usr/bin/docker -p x -k docker
-w /var/lib/docker/ -p wa -k docker_data
-w /etc/docker/ -p wa -k docker_config

## Monitor containerd
-w /usr/bin/containerd -p x -k containerd
-w /usr/bin/ctr -p x -k containerd

## ============================================
## Make Rules Immutable (Optional - Requires Reboot to Change)
## ============================================
## Uncomment to prevent rule changes without reboot
# -e 2
```

### Step 2.2: Load the Rules

```bash
# Check rules syntax
sudo augenrules --check

# Load rules
sudo augenrules --load

# Verify rules are loaded
sudo auditctl -l | head -20

# Check rule count
sudo auditctl -l | wc -l
```

### Step 2.3: Alternative Rule Sets

For pre-built security-focused rules, consider:

**STIG (Security Technical Implementation Guide) Rules:**

```bash
# Download STIG rules
sudo wget -O /etc/audit/rules.d/90-stig.rules \
  https://raw.githubusercontent.com/linux-audit/audit-userspace/master/rules/30-stig.rules
```

**Laurel (MITRE ATT&CK Focused):**

```bash
# Laurel transforms audit logs into JSON with ATT&CK tagging
# https://github.com/threathunters-io/laurel
```

---

## ⚙️ Part 3: Auditd Daemon Configuration

### Step 3.1: Configure auditd.conf

Edit `/etc/audit/auditd.conf`:

```ini
#
# Auditd Configuration for Security Monitoring
#

# Log file location
log_file = /var/log/audit/audit.log

# Log file format (RAW or ENRICHED)
log_format = ENRICHED

# Log group (for permissions)
log_group = adm

# Priority boost for audit daemon
priority_boost = 4

# Flush frequency (INCREMENTAL_ASYNC recommended for performance)
flush = INCREMENTAL_ASYNC

# How often to flush (in records)
freq = 50

# Maximum log file size (MB)
max_log_file = 100

# Number of log files to keep
num_logs = 10

# Action when max log file reached
max_log_file_action = ROTATE

# Space left on partition (MB) before warning
space_left = 200

# Action when space_left reached
space_left_action = SYSLOG

# Admin space left (MB) - critical
admin_space_left = 50

# Action when admin_space_left reached
admin_space_left_action = SUSPEND

# Action when disk is full
disk_full_action = SUSPEND

# Action on disk error
disk_error_action = SUSPEND

# Name format for logs (HOSTNAME adds hostname)
name_format = HOSTNAME

# TCP listen for remote logging (0 = disabled)
tcp_listen_port = 0

# Max TCP connections
tcp_max_per_addr = 1
```

### Step 3.2: Restart Auditd

```bash
# Restart to apply changes
sudo systemctl restart auditd

# Verify configuration
sudo auditctl -s
```

---

## 📤 Part 4: Forward Audit Logs to SIEM

### Option 1: Audisp Syslog Plugin

Edit `/etc/audisp/plugins.d/syslog.conf`:

```ini
active = yes
direction = out
path = /sbin/audisp-syslog
type = always
args = LOG_LOCAL6
format = string
```

Then configure rsyslog to forward (see Part 6).

### Option 2: Audisp Remote Plugin

For direct forwarding to a remote audit server:

Edit `/etc/audisp/plugins.d/au-remote.conf`:

```ini
active = yes
direction = out
path = /sbin/audisp-remote
type = always
format = string
```

Configure `/etc/audisp/audisp-remote.conf`:

```ini
remote_server = <SIEM-IP>
port = 60
transport = tcp
```

### Option 3: Filebeat

Install Filebeat and configure `/etc/filebeat/filebeat.yml`:

```yaml
filebeat.inputs:
  - type: log
    enabled: true
    paths:
      - /var/log/audit/audit.log
    fields:
      log_type: auditd
    multiline:
      pattern: '^type='
      negate: true
      match: after

output.logstash:
  hosts: ["<SIEM-IP>:5044"]
```

### Option 4: Wazuh Agent

Wazuh automatically collects audit logs. Verify in `/var/ossec/etc/ossec.conf`:

```xml
<localfile>
    <log_format>audit</log_format>
    <location>/var/log/audit/audit.log</location>
</localfile>
```

---

## 📊 Part 5: Rsyslog Configuration

### Step 5.1: Install Rsyslog

Most systems have rsyslog pre-installed:

```bash
# Verify installation
rsyslogd -v

# Install if needed (Debian/Ubuntu)
sudo apt install -y rsyslog

# Install if needed (RHEL/CentOS)
sudo yum install -y rsyslog
```

### Step 5.2: Understand Rsyslog Configuration

| File | Purpose |
|------|---------|
| `/etc/rsyslog.conf` | Main configuration |
| `/etc/rsyslog.d/*.conf` | Drop-in configuration files |

### Step 5.3: Configure Local Logging

Edit `/etc/rsyslog.conf` or create `/etc/rsyslog.d/50-default.conf`:

```bash
#
# Rsyslog Local Logging Configuration
#

# Log auth messages (important for security)
auth,authpriv.*                 /var/log/auth.log

# System messages
*.*;auth,authpriv.none          -/var/log/syslog

# Kernel messages
kern.*                          -/var/log/kern.log

# Emergency messages to all users
*.emerg                         :omusrmsg:*

# Log cron activity
cron.*                          /var/log/cron.log

# Daemon messages
daemon.*                        -/var/log/daemon.log

# Mail system
mail.*                          -/var/log/mail.log

# User messages
user.*                          -/var/log/user.log
```

---

## 📤 Part 6: Forward Syslog to SIEM

### Step 6.1: Configure Remote Forwarding

Create `/etc/rsyslog.d/60-remote.conf`:

```bash
#
# Forward logs to SIEM
#

# Load TCP module for reliable delivery
module(load="omfwd")

# Template for forwarding (optional - adds hostname)
template(name="ForwardFormat" type="string"
    string="<%PRI%>%TIMESTAMP% %HOSTNAME% %syslogtag%%msg%\n")

# Forward all logs via TCP (more reliable)
*.* action(type="omfwd"
    target="<SIEM-IP>"
    port="514"
    protocol="tcp"
    template="ForwardFormat"
    queue.type="LinkedList"
    queue.filename="siem_fwd"
    queue.maxdiskspace="1g"
    queue.saveonshutdown="on"
    action.resumeRetryCount="-1"
    action.resumeInterval="30")

# Alternative: Forward via UDP (less reliable but simpler)
# *.* @<SIEM-IP>:514

# Forward only specific facilities
# auth,authpriv.* @@<SIEM-IP>:514
# kern.* @@<SIEM-IP>:514
```

### Step 6.2: Forward Audit Logs via Rsyslog

Create `/etc/rsyslog.d/61-audit.conf`:

```bash
#
# Forward audit logs to SIEM
#

# Forward audit facility (if using audisp syslog plugin)
local6.* action(type="omfwd"
    target="<SIEM-IP>"
    port="514"
    protocol="tcp")
```

### Step 6.3: Restart Rsyslog

```bash
# Test configuration
sudo rsyslogd -N1

# Restart service
sudo systemctl restart rsyslog

# Verify status
sudo systemctl status rsyslog
```

### Step 6.4: Test Forwarding

```bash
# Send test message
logger -t TEST "This is a test message from $(hostname)"

# Check local log
tail /var/log/syslog | grep TEST

# Verify on SIEM server
# Check your SIEM for the test message
```

---

## 🔒 Part 7: Security Hardening

### Harden Rsyslog

```bash
# Restrict permissions on log files
sudo chmod 640 /var/log/syslog
sudo chmod 640 /var/log/auth.log
sudo chown root:adm /var/log/*.log

# Restrict rsyslog configuration
sudo chmod 640 /etc/rsyslog.conf
sudo chmod 640 /etc/rsyslog.d/*.conf
```

### Harden Auditd

```bash
# Restrict audit log permissions
sudo chmod 600 /var/log/audit/audit.log
sudo chown root:root /var/log/audit/audit.log

# Make audit rules immutable (requires reboot to change)
# Add to end of rules file:
# -e 2
```

### Enable Log Compression

Edit `/etc/logrotate.d/rsyslog`:

```
/var/log/syslog
/var/log/auth.log
/var/log/kern.log
{
    rotate 14
    daily
    compress
    delaycompress
    missingok
    notifempty
    create 640 root adm
    sharedscripts
    postrotate
        /usr/lib/rsyslog/rsyslog-rotate
    endscript
}
```

---

## 🔍 Part 8: Analyzing Audit Logs

### Using ausearch

```bash
# Search by key
sudo ausearch -k process_execution

# Search by user
sudo ausearch -ua root

# Search by time range
sudo ausearch -ts today -te now

# Search for failed events
sudo ausearch --success no

# Search for specific syscall
sudo ausearch -sc execve

# Search for file access
sudo ausearch -f /etc/passwd
```

### Using aureport

```bash
# Summary report
sudo aureport --summary

# Authentication report
sudo aureport -au

# Failed authentication
sudo aureport -au --failed

# Executable report
sudo aureport -x

# File access report
sudo aureport -f

# Anomaly report
sudo aureport --anomaly

# Generate report for specific time
sudo aureport -ts yesterday -te today
```

### Parse Audit Log Fields

Audit log entry example:

```
type=SYSCALL msg=audit(1641234567.123:456): arch=c000003e syscall=59 success=yes exit=0 a0=55f4e8a2c8c0 a1=55f4e8a2c900 a2=55f4e8a2d940 a3=7ffc12345678 items=2 ppid=1234 pid=5678 auid=1000 uid=0 gid=0 euid=0 suid=0 fsuid=0 egid=0 sgid=0 fsgid=0 tty=pts0 ses=1 comm="sudo" exe="/usr/bin/sudo" key="sudo_execution"
```

| Field | Description |
|-------|-------------|
| `type` | Record type (SYSCALL, PATH, EXECVE, etc.) |
| `msg` | Timestamp and event ID |
| `arch` | Architecture (c000003e = x86_64) |
| `syscall` | System call number (59 = execve) |
| `success` | Whether call succeeded |
| `ppid` | Parent process ID |
| `pid` | Process ID |
| `auid` | Audit UID (original login user) |
| `uid` | Effective user ID |
| `comm` | Command name |
| `exe` | Full executable path |
| `key` | Rule key that triggered this |

---

## 📋 Part 9: Important Log Files Reference

### Authentication Logs

| Log File | Content | Distribution |
|----------|---------|--------------|
| `/var/log/auth.log` | Authentication events | Debian/Ubuntu |
| `/var/log/secure` | Authentication events | RHEL/CentOS |
| `/var/log/faillog` | Failed login attempts | All |
| `/var/log/lastlog` | Last login info | All |
| `/var/log/wtmp` | Login records (binary) | All |
| `/var/log/btmp` | Failed login records (binary) | All |

### System Logs

| Log File | Content |
|----------|---------|
| `/var/log/syslog` | General system messages (Debian) |
| `/var/log/messages` | General system messages (RHEL) |
| `/var/log/kern.log` | Kernel messages |
| `/var/log/dmesg` | Boot messages |
| `/var/log/daemon.log` | Daemon messages |

### Application Logs

| Log File | Content |
|----------|---------|
| `/var/log/apache2/` | Apache web server |
| `/var/log/nginx/` | Nginx web server |
| `/var/log/mysql/` | MySQL database |
| `/var/log/postgresql/` | PostgreSQL database |

---

## ❗ Part 10: Troubleshooting

### Auditd Not Starting

```bash
# Check status
sudo systemctl status auditd

# Check for rule errors
sudo augenrules --check

# View auditd logs
sudo journalctl -u auditd

# Test rules manually
sudo auditctl -R /etc/audit/rules.d/99-security.rules
```

### High CPU Usage

```bash
# Check audit backlog
sudo auditctl -s

# If backlog is full, increase buffer
sudo auditctl -b 16384

# Reduce noisy rules
# Comment out high-volume rules like execve monitoring
```

### Logs Not Forwarding

```bash
# Test rsyslog configuration
sudo rsyslogd -N1

# Check rsyslog errors
sudo journalctl -u rsyslog

# Test network connectivity
nc -zv <SIEM-IP> 514

# Send test message
logger -n <SIEM-IP> -P 514 "Test message"
```

### Disk Space Issues

```bash
# Check log sizes
du -sh /var/log/*

# Rotate logs manually
sudo logrotate -f /etc/logrotate.conf

# Vacuum old journal logs
sudo journalctl --vacuum-time=7d
```

---

## 📚 Part 11: Additional Resources

### Documentation

- [Linux Audit Documentation](https://access.redhat.com/documentation/en-us/red_hat_enterprise_linux/8/html/security_hardening/auditing-the-system_security-hardening)
- [Rsyslog Documentation](https://www.rsyslog.com/doc/)
- [aureport Man Page](https://man7.org/linux/man-pages/man8/aureport.8.html)
- [ausearch Man Page](https://man7.org/linux/man-pages/man8/ausearch.8.html)

### Rule References

- [STIG Audit Rules](https://github.com/linux-audit/audit-userspace/tree/master/rules)
- [Neo23x0 Auditd Rules](https://github.com/Neo23x0/auditd)
- [Florian Roth's Best Practices](https://github.com/Neo23x0/auditd/blob/master/audit.rules)

### Tools

- [Laurel](https://github.com/threathunters-io/laurel) - Transform audit logs to JSON with ATT&CK mapping
- [go-audit](https://github.com/slackhq/go-audit) - Alternative audit daemon with JSON output

---

## 🗂️ Quick Reference

### Auditd Commands

| Command | Purpose |
|---------|---------|
| `auditctl -l` | List current rules |
| `auditctl -s` | Show audit status |
| `auditctl -D` | Delete all rules |
| `auditctl -w /path -p rwxa -k key` | Add file watch |
| `augenrules --load` | Load rules from rules.d |
| `ausearch -k <key>` | Search by key |
| `aureport --summary` | Generate summary report |

### Rsyslog Commands

| Command | Purpose |
|---------|---------|
| `rsyslogd -N1` | Check configuration |
| `systemctl restart rsyslog` | Restart rsyslog |
| `logger "message"` | Send test message |
| `logger -n <ip> -P <port> "msg"` | Send remote test |

### Common Audit Keys

| Key | What It Monitors |
|-----|------------------|
| `identity` | User/group file changes |
| `pam_config` | PAM configuration |
| `sudo_execution` | sudo usage |
| `process_execution` | All process execution |
| `network_connect` | Network connections |
| `cron_config` | Scheduled task changes |
| `time_change` | System time modifications |

### Service Commands

| Action | Command |
|--------|---------|
| Start Auditd | `systemctl start auditd` |
| Stop Auditd | `systemctl stop auditd` |
| Restart Auditd | `systemctl restart auditd` |
| Start Rsyslog | `systemctl start rsyslog` |
| Restart Rsyslog | `systemctl restart rsyslog` |

---

*Part of the Incident Response & Log Aggregation Branch*
