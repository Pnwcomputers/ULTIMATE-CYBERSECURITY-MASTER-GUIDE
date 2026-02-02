# 🦁 Wazuh Setup Guide

**Wazuh** is an open-source security platform that provides unified XDR and SIEM protection for endpoints and cloud workloads. This guide covers deploying the Wazuh Manager (server) and installing agents on endpoints.

## 📋 Prerequisites
* **Server:** Ubuntu 22.04 LTS (Recommended: 4GB RAM, 2 vCPUs).
* **Client:** Windows 10/11 or Server VM (Target).

## 🚀 Part 1: Deploying the Manager (Docker)
The easiest way to spin up the manager is via Docker Compose.

1.  **Clone the repository:**
    ```bash
    git clone [https://github.com/wazuh/wazuh-docker.git](https://github.com/wazuh/wazuh-docker.git) -b v4.7.0
    cd wazuh-docker/single-node
    ```
2.  **Generate certificates:**
    ```bash
    docker-compose -f generate-indexer-certs.yml run --rm generator
    ```
3.  **Start the stack:**
    ```bash
    docker-compose up -d
    ```
4.  **Access the Dashboard:**
    * URL: `https://<SERVER-IP>`
    * Default User: `admin`
    * Default Password: `SecretPassword`

## 🕵️ Part 2: Agent Deployment (Windows)
1.  Log into your Wazuh Dashboard.
2.  Navigate to **"Add Agent"**.
3.  Select **Windows** and input the Wazuh Server IP.
4.  Run the generated PowerShell command on your target VM:
    ```powershell
    Invoke-WebRequest -Uri [https://packages.wazuh.com/4.x/windows/wazuh-agent-4.7.0-1.msi](https://packages.wazuh.com/4.x/windows/wazuh-agent-4.7.0-1.msi) -OutFile ${env:tmp}\wazuh-agent.msi; ...
    ```
5.  Start the service:
    ```powershell
    NET START WazuhSvc
    ```

## 🔍 Verification
Check the **"Agents"** tab in the dashboard. You should see your Windows VM listed as `Active`.

---
*Part of the Incident Response & Log Aggregation Branch*
