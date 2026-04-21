# 🦞 OpenClaw on TrueNAS SCALE — Complete Setup Guide

## 🤖 AI Resources

<div align="center">

**AI, Machine Learning, and Generative Intelligence resources applied to cybersecurity**

*Part of the [ULTIMATE CYBERSECURITY MASTER GUIDE](../README.md)*

[![AI Models](https://img.shields.io/badge/AI_Models-Checklists-purple?style=for-the-badge)]()
[![ML Use Cases](https://img.shields.io/badge/ML_Use_Cases-Security-blue?style=for-the-badge)]()
[![GenAI Security](https://img.shields.io/badge/GenAI-Cybersecurity-green?style=for-the-badge)]()

</div>

---

## What is OpenClaw?

OpenClaw is a free, open-source AI agent framework that runs on your own hardware. Think of it as a personal AI assistant — like having a local version of ChatGPT that you control completely, connected to your messaging apps, files, and services.

**What it can do:**
- Chat via Telegram, Discord, WhatsApp, Slack, Signal, and 50+ other platforms from a single agent
- Read and write files, run shell commands, browse the web, and manage your calendar
- Connect to multiple AI providers simultaneously (Anthropic, Google, Groq, local Ollama models) and route tasks to the best/cheapest model automatically
- Remember context across sessions and schedule automated tasks with cron jobs
- Extend functionality with community-built skills (ClawHub) for homelab management, GitHub, Notion, media servers, and more
- Run 100% locally with Ollama — no data leaves your network

**Why self-host it?**
- Your conversations stay on your hardware
- Use free tiers of Groq and Gemini for most tasks, reserving paid APIs (like Claude) for complex work
- Integrate with your existing homelab infrastructure
- Full control over models, tools, and data

- Companion Documents
This repository includes three guides. Start here, then refer to the others once setup is complete:
FileDescriptionREADME.md (this file)Full installation and configuration guide for TrueNAS SCALEuse_cases.mdReal-world example prompts organized by workflow — personal, IT support, blue team, red team, purple team, OSINT, and moreagen_skill_config.mdPre-built agent personas, skill configurations, cron jobs, and automation setups ready to apply to your instance

---

## Companion Documents
 
This repository includes three guides. Start here, then refer to the others once setup is complete:
 
| File | Description |
|------|-------------|
| **README.md** *(this file)* | Full installation and configuration guide for TrueNAS SCALE |
| **[use_cases.md](use_cases.md)** | Real-world example prompts organized by workflow — personal, IT support, blue team, red team, purple team, OSINT, and more |
| **[agent_skill_config.md](agent_skill_config.md)** | Pre-built agent personas, skill configurations, cron jobs, and automation setups ready to apply to your instance |

---

## Table of Contents

- [Prerequisites](#prerequisites)
- [Part 1: Install OpenClaw from App Catalog](#part-1-install-openclaw-from-app-catalog)
- [Part 2: Run the Setup Wizard](#part-2-run-the-setup-wizard)
- [Part 3: Configure AI Providers](#part-3-configure-ai-providers)
- [Part 4: Verify All Providers](#part-4-verify-all-providers)
- [Part 5: Set Default Model and Tools Profile](#part-5-set-default-model-and-tools-profile)
- [Part 6: Security Hardening](#part-6-security-hardening)
- [Part 7: NPMplus Reverse Proxy with HTTPS](#part-7-npmplus-reverse-proxy-with-https)
- [Part 8: Device Pairing](#part-8-device-pairing)
- [Local Access Without HTTPS](#local-access-without-https)
- [Troubleshooting](#troubleshooting)
- [Reference: Key Commands](#reference-key-commands)

---

## Prerequisites

- [TrueNAS SCALE](https://www.truenas.com/truenas-community-edition/) 25.04+
- [NPMplus](https://github.com/ZoeyVid/NPMplus) installed and running (for HTTPS reverse proxy)
- [OPNsense](https://opnsense.org/) or similar router
- A [DuckDNS](https://www.duckdns.org/) (or other [DDNS](https://www.cloudflare.com/learning/dns/glossary/dynamic-dns/)) domain pointed at your public IP
- [Ollama](https://ollama.com/) running somewhere on your network (optional, for local inference)
- [API keys](https://www.ibm.com/think/topics/api-key) for: Anthropic, Groq, Google Gemini (all have free tiers)

---

## Part 1: Install OpenClaw from App Catalog

### 1.1 Find the App

Go to **Apps → Discover** in the TrueNAS UI and search for **OpenClaw** (Community train).

### 1.2 Generate a Gateway Token

Before installing, generate a strong random token:

```bash
openssl rand -hex 32
```

Save this token — you'll need it throughout setup and to connect to the dashboard.

### 1.3 Configuration Settings

Fill in the app installer form as follows:

**OpenClaw Configuration:**
| Field | Value |
|-------|-------|
| Authentication Mode | Shared bearer token (recommended) |
| Gateway Token | *(your generated token)* |
| Proxy Trusted Proxies | Your TrueNAS/NPMplus IP (e.g. `10.0.1.149`) |

**Network Configuration:**
| Field | Value |
|-------|-------|
| Port Bind Mode | Publish port on the host for external access |
| Port Number | `30262` |
| Host Network | Unchecked |

**User and Group Configuration:**
| Field | Value |
|-------|-------|
| User ID | `568` |
| Group ID | `568` |

**Storage Configuration:**

> ⚠️ **CRITICAL: Leave storage type as `ixVolume` — do NOT change to Host Path.**
>
> There is a known bug in OpenClaw 2026.3.2+ where the config init container fails when using Host Path storage. The ixVolume option (TrueNAS managed storage) is the only storage type that works reliably with the TrueNAS Community app.

**Resources Configuration:**
| Field | Value |
|-------|-------|
| CPUs | `4` |
| Memory (MB) | `6144` |

### 1.4 Add Environment Variables

In the **Additional Environment Variables** section, add all provider API keys before installing:

| Name | Value |
|------|-------|
| `ANTHROPIC_API_KEY` | `sk-ant-...` |
| `GROQ_API_KEY` | `gsk_...` |
| `GEMINI_API_KEY` | `AIza...` |
| `OLLAMA_API_KEY` | `ollama-local` |
| `OLLAMA_BASE_URL` | `http://YOUR_OLLAMA_IP:11434` |

> **Note:** Use `OLLAMA_BASE_URL` — not `OLLAMA_HOST`. The `OLLAMA_HOST` variable is ignored by this version of OpenClaw.

Click **Install** and wait for the app to show as Running (green) in Apps → Installed.

---

## Part 2: Run the Setup Wizard

### 2.1 Anthropic

```bash
sudo docker exec -it ix-openclaw-openclaw-1 node /app/openclaw.mjs onboard --auth-choice anthropic
```

At each prompt:
- Security disclaimer → **Yes**
- Setup mode → **QuickStart**
- Config handling → **Use existing values**
- Channel setup → **Skip for now**

### 2.2 Google Gemini

```bash
sudo docker exec -it ix-openclaw-openclaw-1 node /app/openclaw.mjs onboard --auth-choice google
```

At each prompt:
- Security disclaimer → **Yes**
- Setup mode → **QuickStart**
- Config handling → **Use existing values**
- Use existing `GEMINI_API_KEY` → **Yes**
- Web search provider → **Gemini (Google Search)**
- Channel setup → **Skip for now**

### 2.3 Groq

```bash
sudo docker exec -it ix-openclaw-openclaw-1 node /app/openclaw.mjs onboard --auth-choice groq
```

At each prompt:
- Security disclaimer → **Yes**
- Setup mode → **QuickStart**
- Config handling → **Use existing values**
- Channel setup → **Skip for now**

> **Note:** The Groq wizard often completes without actually registering Groq models. If `models list` doesn't show Groq afterward, the manual fix in Part 3 is required.

### 2.4 Ollama

```bash
sudo docker exec -it ix-openclaw-openclaw-1 node /app/openclaw.mjs onboard --auth-choice ollama
```

At each prompt:
- Security disclaimer → **Yes**
- Setup mode → **QuickStart**
- Config handling → **Use existing values**
- Ollama mode → **Local only**
- Ollama base URL → `http://YOUR_OLLAMA_IP:11434` *(no `/v1` suffix)*
- Select a model from the discovered list
- Channel setup → **Skip for now**

---

## Part 3: Configure AI Providers

### 3.1 Fix Groq (Manual Config Edit)

The Groq wizard often completes without registering models. Fix this by editing the config file directly on the TrueNAS host:

```bash
sudo python3 -c "
import json
path = '/mnt/.ix-apps/app_mounts/openclaw/config/.openclaw/openclaw.json'
with open(path) as f:
    config = json.load(f)

config['auth']['profiles']['groq:default'] = {'provider': 'groq', 'mode': 'api_key'}
config['plugins']['entries']['groq'] = {'enabled': True}
config['agents']['defaults']['models']['groq/llama-3.3-70b-versatile'] = {}

with open(path, 'w') as f:
    json.dump(config, f, indent=2)
print('Done')
"
```

Validate the JSON:

```bash
sudo python3 -c "import json; json.load(open('/mnt/.ix-apps/app_mounts/openclaw/config/.openclaw/openclaw.json')); print('Valid')"
```

> ⚠️ **Important:** Never use `config set` to add nested provider objects like `models.providers.groq`. OpenClaw's schema validator rejects partial provider entries written one field at a time. Always use the Python direct-edit method above for provider configuration.

### 3.2 Fix Ollama API Key

The Ollama wizard sets the API key to the literal string `"OLLAMA_API_KEY"` instead of resolving the value. Fix it:

```bash
sudo docker exec -it ix-openclaw-openclaw-1 node /app/openclaw.mjs config set models.providers.ollama.apiKey "ollama-local"
```

### 3.3 Add Ollama Models to Allowlist

Check what models you have available:

```bash
curl -s http://YOUR_OLLAMA_IP:11434/api/tags
```

Then add your models to the agents allowlist:

```bash
sudo python3 -c "
import json
path = '/mnt/.ix-apps/app_mounts/openclaw/config/.openclaw/openclaw.json'
with open(path) as f:
    config = json.load(f)

# Replace with your actual model name from the api/tags output
config['agents']['defaults']['models']['ollama/YOUR_MODEL_NAME:latest'] = {}

with open(path, 'w') as f:
    json.dump(config, f, indent=2)
print('Done')
"
```

---

## Part 4: Verify All Providers

Restart the app from the TrueNAS UI (Stop → Start), then verify:

```bash
sudo docker exec -it ix-openclaw-openclaw-1 node /app/openclaw.mjs models list
```

Expected output:

```
Model                                      Input      Ctx      Local Auth  Tags
google/gemini-3.1-pro-preview              text+image 1024k    no    yes   default,configured
anthropic/claude-opus-4-7                  text+image 977k     no    yes   configured
anthropic/claude-haiku-4-5                 text+image 195k     no    yes   configured
ollama/YOUR_MODEL:latest                   text       8k       no    yes   configured
groq/llama-3.3-70b-versatile               text       128k     no    yes   configured
```

All four providers should be listed. If any are missing, revisit the relevant section in Part 3.

---

## Part 5: Set Default Model and Tools Profile

Set Groq as the default model to minimize API costs:

```bash
sudo docker exec -it ix-openclaw-openclaw-1 node /app/openclaw.mjs config set agents.defaults.model.primary "groq/llama-3.3-70b-versatile"
```

Set the tools profile. Valid values are `minimal`, `coding`, `messaging`, or `full`:

```bash
sudo docker exec -it ix-openclaw-openclaw-1 node /app/openclaw.mjs config set tools.profile full
```

---

## Part 6: Security Hardening

Run the built-in security audit:

```bash
sudo docker exec -it ix-openclaw-openclaw-1 node /app/openclaw.mjs security audit
```

Fix the flagged issues:

```bash
# Add rate limiting against brute force attacks
sudo docker exec -it ix-openclaw-openclaw-1 node /app/openclaw.mjs config set gateway.auth.rateLimit '{"maxAttempts":10,"windowMs":60000,"lockoutMs":300000}'

# Lock down allowed origins to your HTTPS domain and local IP
sudo docker exec -it ix-openclaw-openclaw-1 node /app/openclaw.mjs config set gateway.controlUi.allowedOrigins '["https://openclaw.yourdomain.duckdns.org","http://YOUR_TRUENAS_IP:30262"]'
```

Restart the app from the TrueNAS UI to apply changes.

---

## Part 7: NPMplus Reverse Proxy with HTTPS

### 7.1 Create a Proxy Host

In the NPMplus UI go to **Hosts → Proxy Hosts → Add Proxy Host**.

**Details tab:**
| Field | Value |
|-------|-------|
| Domain Name | `openclaw.yourdomain.duckdns.org` |
| Scheme | `http` |
| Forward Hostname/IP | Your TrueNAS IP |
| Forward Port | `30262` |

Click the **gear icon ⚙️** next to Forward Port and paste this into the advanced config box:

```nginx
proxy_http_version 1.1;
proxy_set_header Upgrade $http_upgrade;
proxy_set_header Connection "upgrade";
proxy_set_header Host $host;
proxy_set_header X-Real-IP $remote_addr;
proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
proxy_set_header X-Forwarded-Proto $scheme;
more_clear_headers Alt-Svc;
proxy_read_timeout 3600s;
proxy_send_timeout 3600s;
proxy_connect_timeout 60s;
```

> ⚠️ The `proxy_http_version 1.1` line is critical. WebSockets require HTTP/1.1 and will fail silently with HTTP/2 or HTTP/3.

**TLS tab:**
| Field | Value |
|-------|-------|
| TLS Certificate | Request a new Certificate |
| Force HTTPS | ✅ Enabled |
| HTTP/2 Support | ❌ Disabled |
| HTTP/3 Support | ❌ Disabled |
| Use DNS Challenge | ✅ Enabled (required for DuckDNS) |

Enable **Use DNS Challenge** and enter your DuckDNS token from `https://www.duckdns.org`.

### 7.2 Local DNS Override (OPNsense Unbound)

To access the HTTPS domain locally without hairpin NAT issues, add a host override in OPNsense:

Go to **Services → Unbound DNS → Host Overrides → +** and add:

| Field | Value |
|-------|-------|
| Host | `openclaw` |
| Domain | `yourdomain.duckdns.org` |
| Type | `A (IPv4 address)` |
| IP address | Your TrueNAS IP (e.g. `10.0.1.149`) |

Save and apply Unbound. Verify:

```bash
nslookup openclaw.yourdomain.duckdns.org YOUR_OPNSENSE_IP
```

Should return your TrueNAS LAN IP, not your public WAN IP. Add overrides for all your other NPMplus proxy hosts using the same pattern.

### 7.3 Port Forwarding

Forward external ports 80 and 443 from your router WAN to NPMplus on your TrueNAS. Confirm NPMplus port mappings:

```bash
sudo docker ps | grep npmplus
```

---

## Part 8: Device Pairing

### 8.1 Access the Web UI

Open `https://openclaw.yourdomain.duckdns.org` in your browser.

### 8.2 Connect to the Gateway

On the Gateway Dashboard enter:
- **WebSocket URL:** `wss://openclaw.yourdomain.duckdns.org`
- **Gateway Token:** *(your token from Part 1)*

Click **Connect**. The dashboard will show "pairing required".

### 8.3 Approve the Pairing Request

```bash
# List pending pairing requests
sudo docker exec -it ix-openclaw-openclaw-1 node /app/openclaw.mjs devices list

# Approve using the Request UUID from the output
sudo docker exec -it ix-openclaw-openclaw-1 node /app/openclaw.mjs devices approve YOUR-REQUEST-UUID
```

You are now connected to the OpenClaw dashboard.

---

## Local Access Without HTTPS

If you need to access the dashboard locally over HTTP before HTTPS is fully configured, use the Chrome browser flag to allow WebSocket device identity on insecure origins:

1. Go to `chrome://flags/#unsafely-treat-insecure-origin-as-secure`
2. Add `http://YOUR_TRUENAS_IP:30262`
3. Enable the flag and relaunch Chrome

Then access via the tokenized URL which pre-fills your gateway token automatically:

```
http://YOUR_TRUENAS_IP:30262/#token=YOUR_GATEWAY_TOKEN
```

---

## Troubleshooting

### App fails to start: `config service exit 1`

This is a known bug in OpenClaw 2026.3.2+ triggered by Host Path storage.

**Fix:** Delete the app and reinstall using **ixVolume** storage (the default). Do not change the storage type to Host Path.

### App fails to start after editing config file

The config file has invalid JSON or failed schema validation.

**Fix:** Restore from the automatic backup OpenClaw creates before every edit:

```bash
# Find the config file
sudo find /mnt/.ix-apps -name "openclaw.json" 2>/dev/null

# Restore from backup
sudo cp /mnt/.ix-apps/app_mounts/openclaw/config/.openclaw/openclaw.json.bak \
        /mnt/.ix-apps/app_mounts/openclaw/config/.openclaw/openclaw.json

# Validate
sudo python3 -c "import json; json.load(open('/mnt/.ix-apps/app_mounts/openclaw/config/.openclaw/openclaw.json')); print('Valid')"
```

Then start the app from the TrueNAS UI.

### `config set` fails with schema validation error

OpenClaw requires all fields of a provider entry to be present simultaneously. Setting nested provider objects one field at a time always fails validation.

**Fix:** Use the Python direct-edit method from Part 3.

### Ollama shows "could not be reached at 127.0.0.1:11434"

The `OLLAMA_HOST` environment variable is not supported by this version.

**Fix:** In the TrueNAS app environment variables, use `OLLAMA_BASE_URL` instead of `OLLAMA_HOST`.

### WebSocket disconnected (1006) through NPMplus

HTTP/2 or HTTP/3 is being negotiated, which breaks WebSocket upgrades.

**Fix:** Ensure `proxy_http_version 1.1` is in the NPMplus advanced config, and that HTTP/2 and HTTP/3 are disabled in the TLS tab. Also ensure your Unbound DNS override is resolving the domain to your local TrueNAS IP — if the domain resolves to your WAN IP, traffic hairpins through NAT and the connection fails.

### Certificate request fails with Internal Error in NPMplus

Port 80 is not accessible from the internet for the HTTP-01 ACME challenge.

**Fix:** Use the **DNS Challenge** option in NPMplus TLS settings with your DuckDNS token.

### `devices list` fails with gateway closed (1006)

The gateway process isn't running inside the container.

**Fix:**

```bash
sudo docker exec -d ix-openclaw-openclaw-1 node /app/openclaw.mjs gateway run
```

Wait a few seconds then retry `devices list`.

---

## Reference: Key Commands

```bash
# Check running containers
sudo docker ps | grep openclaw

# View all configured models
sudo docker exec -it ix-openclaw-openclaw-1 node /app/openclaw.mjs models list

# Get a config value
sudo docker exec -it ix-openclaw-openclaw-1 node /app/openclaw.mjs config get gateway.port

# Set a simple config value
sudo docker exec -it ix-openclaw-openclaw-1 node /app/openclaw.mjs config set KEY VALUE

# Run security audit
sudo docker exec -it ix-openclaw-openclaw-1 node /app/openclaw.mjs security audit

# List paired devices
sudo docker exec -it ix-openclaw-openclaw-1 node /app/openclaw.mjs devices list

# Approve a device pairing
sudo docker exec -it ix-openclaw-openclaw-1 node /app/openclaw.mjs devices approve UUID

# View raw config file
sudo cat /mnt/.ix-apps/app_mounts/openclaw/config/.openclaw/openclaw.json

# Validate config JSON
sudo python3 -c "import json; json.load(open('/mnt/.ix-apps/app_mounts/openclaw/config/.openclaw/openclaw.json')); print('Valid')"

# Restore config from backup
sudo cp /mnt/.ix-apps/app_mounts/openclaw/config/.openclaw/openclaw.json.bak \
        /mnt/.ix-apps/app_mounts/openclaw/config/.openclaw/openclaw.json

# View app lifecycle logs
sudo grep openclaw /var/log/app_lifecycle.log | tail -20

# Check environment variables in container
sudo docker exec -it ix-openclaw-openclaw-1 env | grep -E "GROQ|GEMINI|OLLAMA|ANTHROPIC"

# View container logs
sudo docker logs ix-openclaw-openclaw-1 2>&1 | tail -30
```

---

## Cost Optimization

| Provider | Cost | Best For |
|----------|------|----------|
| Groq | Free tier (generous) | Default for most tasks — fast Llama 3.3 70B |
| Google Gemini | Free tier | Long context tasks (1M token window) |
| Ollama (local) | Free forever | Sensitive tasks, offline use |
| Anthropic (Claude) | Paid | Complex reasoning, long documents |

The **Adaptive** model mode in the dashboard automatically routes to a stronger model only when the task requires it, keeping costs minimal.

---

## Next Steps

- **Set up Telegram** for mobile access from anywhere:
  ```bash
  sudo docker exec -it ix-openclaw-openclaw-1 node /app/openclaw.mjs onboard --auth-choice telegram
  ```
- **Install the TrueNAS skill** from ClawHub to manage your homelab via OpenClaw
- **Rotate your API keys** — Groq and Gemini keys were visible in shell history during initial setup
- **Run periodic health checks:**
  ```bash
  sudo docker exec -it ix-openclaw-openclaw-1 node /app/openclaw.mjs security audit
  ```

---

*Deployment environment: TrueNAS SCALE 25.04 · Dell R630 · OPNsense · NPMplus · Ollama · OpenClaw 2026.4.15*
