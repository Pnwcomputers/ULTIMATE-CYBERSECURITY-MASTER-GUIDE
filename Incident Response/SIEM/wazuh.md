# 🦁 Wazuh Deployment Guide

**Wazuh** is an open-source security platform providing unified XDR (Extended Detection and Response) and SIEM (Security Information and Event Management) capabilities. It monitors endpoints, detects threats, identifies vulnerabilities, and ensures compliance across your infrastructure.

This guide covers deploying the Wazuh Manager using Docker and installing agents on Windows and Linux endpoints.

---

## 📋 Prerequisites

### Server Requirements

| Component | Minimum | Recommended |
|-----------|---------|-------------|
| OS | Ubuntu 20.04/22.04 LTS | Ubuntu 22.04 LTS |
| RAM | 4 GB | 8 GB |
| CPU | 2 vCPUs | 4 vCPUs |
| Storage | 50 GB | 100 GB+ |

### Software Requirements

- Docker Engine 20.10+
- Docker Compose 1.29+

### Network Requirements

Ensure the following ports are accessible on your Wazuh Manager:

| Port | Protocol | Purpose |
|------|----------|---------|
| 443 | TCP | Wazuh Dashboard (HTTPS) |
| 1514 | TCP | Agent communication |
| 1515 | TCP | Agent enrollment |
| 55000 | TCP | Wazuh API |

---

## 🛠️ Part 1: Preparing the Server

### Step 1.1: Update the System

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

# Add your user to the docker group
sudo usermod -aG docker $USER
```

Log out and back in for group changes to take effect, or run `newgrp docker`.

### Step 1.3: Verify Docker Installation

```bash
docker --version
docker compose version
```

---

## 🚀 Part 2: Deploying the Wazuh Manager (Docker)

### Step 2.1: Clone the Wazuh Docker Repository

```bash
git clone https://github.com/wazuh/wazuh-docker.git -b v4.7.0
cd wazuh-docker/single-node
```

> **Note:** Check [Wazuh releases](https://github.com/wazuh/wazuh-docker/releases) for the latest stable version and adjust the branch tag accordingly.

### Step 2.2: Increase vm.max_map_count

The Wazuh Indexer (OpenSearch) requires increased virtual memory limits:

```bash
# Apply immediately
sudo sysctl -w vm.max_map_count=262144

# Make persistent across reboots
echo "vm.max_map_count=262144" | sudo tee -a /etc/sysctl.conf
```

### Step 2.3: Generate SSL Certificates

```bash
docker compose -f generate-indexer-certs.yml run --rm generator
```

This creates self-signed certificates in the `config/wazuh_indexer_ssl_certs/` directory.

### Step 2.4: Start the Wazuh Stack

```bash
docker compose up -d
```

Monitor the startup process:

```bash
docker compose logs -f
```

Wait 2-3 minutes for all services to initialize. You'll see health checks passing in the logs.

### Step 2.5: Verify All Containers Are Running

```bash
docker compose ps
```

Expected output shows three healthy containers:
- `single-node-wazuh.manager-1`
- `single-node-wazuh.indexer-1`
- `single-node-wazuh.dashboard-1`

### Step 2.6: Access the Dashboard

Open your browser and navigate to:

```
https://<SERVER-IP>
```

**Default Credentials:**
- Username: `admin`
- Password: `SecretPassword`

> ⚠️ **Security Warning:** Change the default password immediately after first login via **Settings → Security → Internal Users**.

---

## 🔥 Part 3: Firewall Configuration

### UFW (Ubuntu)

```bash
sudo ufw allow 443/tcp comment "Wazuh Dashboard"
sudo ufw allow 1514/tcp comment "Wazuh Agent Communication"
sudo ufw allow 1515/tcp comment "Wazuh Agent Enrollment"
sudo ufw allow 55000/tcp comment "Wazuh API"
sudo ufw reload
sudo ufw status
```

### Firewalld (RHEL/CentOS)

```bash
sudo firewall-cmd --permanent --add-port=443/tcp
sudo firewall-cmd --permanent --add-port=1514/tcp
sudo firewall-cmd --permanent --add-port=1515/tcp
sudo firewall-cmd --permanent --add-port=55000/tcp
sudo firewall-cmd --reload
```

---

## 🖥️ Part 4: Windows Agent Deployment

### Method 1: Dashboard-Generated Command (Recommended)

1. Log into the Wazuh Dashboard
2. Navigate to **Agents → Deploy new agent**
3. Select **Windows** as the operating system
4. Enter your Wazuh Manager IP address
5. Optionally assign an agent name and group
6. Copy the generated PowerShell command

### Method 2: Manual Installation

#### Step 4.1: Download the Agent

Download from an elevated PowerShell prompt:

```powershell
Invoke-WebRequest -Uri https://packages.wazuh.com/4.x/windows/wazuh-agent-4.7.0-1.msi -OutFile $env:TEMP\wazuh-agent.msi
```

#### Step 4.2: Install with Configuration

```powershell
msiexec.exe /i $env:TEMP\wazuh-agent.msi /q WAZUH_MANAGER="<MANAGER-IP>" WAZUH_REGISTRATION_SERVER="<MANAGER-IP>" WAZUH_AGENT_NAME="<HOSTNAME>"
```

Replace:
- `<MANAGER-IP>` with your Wazuh server's IP address
- `<HOSTNAME>` with a descriptive name for this endpoint

#### Step 4.3: Start the Wazuh Service

```powershell
NET START WazuhSvc
```

#### Step 4.4: Verify Service Status

```powershell
Get-Service WazuhSvc
```

### Windows Agent File Locations

| Item | Path |
|------|------|
| Installation Directory | `C:\Program Files (x86)\ossec-agent\` |
| Configuration File | `C:\Program Files (x86)\ossec-agent\ossec.conf` |
| Log File | `C:\Program Files (x86)\ossec-agent\ossec.log` |

---

## 🐧 Part 5: Linux Agent Deployment

### Step 5.1: Add the Wazuh Repository

**Debian/Ubuntu:**

```bash
curl -s https://packages.wazuh.com/key/GPG-KEY-WAZUH | gpg --no-default-keyring --keyring gnupg-ring:/usr/share/keyrings/wazuh.gpg --import && chmod 644 /usr/share/keyrings/wazuh.gpg

echo "deb [signed-by=/usr/share/keyrings/wazuh.gpg] https://packages.wazuh.com/4.x/apt/ stable main" | tee /etc/apt/sources.list.d/wazuh.list

apt update
```

**RHEL/CentOS:**

```bash
rpm --import https://packages.wazuh.com/key/GPG-KEY-WAZUH

cat > /etc/yum.repos.d/wazuh.repo << EOF
[wazuh]
gpgcheck=1
gpgkey=https://packages.wazuh.com/key/GPG-KEY-WAZUH
enabled=1
name=EL-\$releasever - Wazuh
baseurl=https://packages.wazuh.com/4.x/yum/
protect=1
EOF
```

### Step 5.2: Install the Agent

**Debian/Ubuntu:**

```bash
WAZUH_MANAGER="<MANAGER-IP>" apt install -y wazuh-agent
```

**RHEL/CentOS:**

```bash
WAZUH_MANAGER="<MANAGER-IP>" yum install -y wazuh-agent
```

### Step 5.3: Enable and Start the Service

```bash
systemctl daemon-reload
systemctl enable wazuh-agent
systemctl start wazuh-agent
```

### Step 5.4: Verify Agent Status

```bash
systemctl status wazuh-agent
```

### Linux Agent File Locations

| Item | Path |
|------|------|
| Installation Directory | `/var/ossec/` |
| Configuration File | `/var/ossec/etc/ossec.conf` |
| Log File | `/var/ossec/logs/ossec.log` |

---

## 🔍 Part 6: Verification and Testing

### Check Agent Status in Dashboard

1. Log into the Wazuh Dashboard
2. Navigate to **Agents**
3. Verify your agent appears with status **Active**

### Generate a Test Alert

On the Windows agent, trigger a test alert by creating a test file:

```powershell
# This simulates suspicious activity that Wazuh will detect
echo "test" > C:\Users\Public\eicar-test.txt
```

On Linux:

```bash
# Simulate a failed SSH login attempt
logger -t sshd "Failed password for invalid user admin from 192.168.1.100 port 22 ssh2"
```

Check the **Security Events** section in the dashboard for corresponding alerts.

---

## 🔧 Part 7: Common Configuration Tasks

### Changing the Admin Password

1. Navigate to **Settings → Security → Internal Users**
2. Select the `admin` user
3. Click **Edit** and set a new password

### Adding Agent Groups

Groups allow you to apply specific configurations to sets of agents:

1. Navigate to **Management → Groups**
2. Click **Add new group**
3. Name the group (e.g., `windows-servers`, `linux-workstations`)
4. Assign agents to groups during deployment or via the dashboard

### Modifying Agent Configuration

Edit the `ossec.conf` file on the agent to customize:
- Log collection sources
- File integrity monitoring paths
- Active response settings

After changes, restart the agent service.

---

## ❗ Part 8: Troubleshooting

### Agent Not Connecting

**Check agent logs:**

Windows:
```powershell
Get-Content "C:\Program Files (x86)\ossec-agent\ossec.log" -Tail 50
```

Linux:
```bash
tail -50 /var/ossec/logs/ossec.log
```

**Common issues:**
- Firewall blocking ports 1514/1515
- Incorrect manager IP in agent configuration
- Certificate/enrollment issues

### Agent Shows "Disconnected"

1. Verify network connectivity: `ping <MANAGER-IP>`
2. Test port accessibility: `nc -zv <MANAGER-IP> 1514`
3. Restart the agent service
4. Check manager logs: `docker compose logs wazuh.manager`

### Dashboard Not Loading

```bash
# Check container status
docker compose ps

# View dashboard logs
docker compose logs wazuh.dashboard

# Restart the stack if needed
docker compose restart
```

### Re-enrolling an Agent

If an agent needs to be re-enrolled:

Windows:
```powershell
NET STOP WazuhSvc
Remove-Item "C:\Program Files (x86)\ossec-agent\client.keys" -Force
# Re-run the enrollment command
NET START WazuhSvc
```

Linux:
```bash
systemctl stop wazuh-agent
rm /var/ossec/etc/client.keys
# Re-run the enrollment
systemctl start wazuh-agent
```

---

## 🛡️ Part 9: Security Hardening

### Change Default Passwords

Update passwords for all internal users:
- `admin`
- `kibanaserver`
- `kibanaro`

### Enable HTTPS Certificate Validation

For production, replace self-signed certificates with certificates from a trusted CA or your internal PKI.

### Restrict API Access

Edit the Wazuh API configuration to limit access by IP address or require client certificates.

### Regular Updates

Keep Wazuh components updated:

```bash
cd wazuh-docker/single-node
docker compose pull
docker compose up -d
```

---

## 📚 Additional Resources

- [Wazuh Documentation](https://documentation.wazuh.com/)
- [Wazuh GitHub Repository](https://github.com/wazuh/wazuh)
- [Wazuh Ruleset](https://github.com/wazuh/wazuh-ruleset)
- [Wazuh Slack Community](https://wazuh.com/community/join-us-on-slack/)

---

## 🗂️ Quick Reference

### Docker Commands

| Command | Purpose |
|---------|---------|
| `docker compose up -d` | Start the stack |
| `docker compose down` | Stop the stack |
| `docker compose restart` | Restart all containers |
| `docker compose logs -f` | Follow all logs |
| `docker compose ps` | Show container status |

### Agent Service Commands

| OS | Start | Stop | Status |
|----|-------|------|--------|
| Windows | `NET START WazuhSvc` | `NET STOP WazuhSvc` | `Get-Service WazuhSvc` |
| Linux | `systemctl start wazuh-agent` | `systemctl stop wazuh-agent` | `systemctl status wazuh-agent` |

---

*Part of the Incident Response & Log Aggregation Branch*
