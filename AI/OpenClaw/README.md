# OpenClaw on TrueNAS SCALE — Setup Guide

A battle-tested, step-by-step guide to installing and configuring OpenClaw on TrueNAS SCALE with multiple AI providers. Based on a real production deployment on a Dell R630 running TrueNAS SCALE with OPNsense, NPMplus, and Ollama.

---

## Table of Contents

- [Prerequisites](#prerequisites)
- [Part 1: Prepare ZFS Datasets](#part-1-prepare-zfs-datasets)
- [Part 2: Install OpenClaw from App Catalog](#part-2-install-openclaw-from-app-catalog)
- [Part 3: Run the Setup Wizard](#part-3-run-the-setup-wizard)
- [Part 4: Configure AI Providers](#part-4-configure-ai-providers)
  - [Anthropic (Claude)](#anthropic-claude)
  - [Google Gemini](#google-gemini)
  - [Groq](#groq)
  - [Ollama (Local)](#ollama-local)
- [Part 5: Fix Config and Verify Providers](#part-5-fix-config-and-verify-providers)
- [Part 6: Set Default Model and Tools Profile](#part-6-set-default-model-and-tools-profile)
- [Part 7: Security Hardening](#part-7-security-hardening)
- [Part 8: NPMplus Reverse Proxy with HTTPS](#part-8-npmplus-reverse-proxy-with-https)
- [Part 9: Device Pairing](#part-9-device-pairing)
- [Troubleshooting](#troubleshooting)
- [Reference: Key Commands](#reference-key-commands)

---

## Prerequisites

- TrueNAS SCALE (tested on 25.04+)
- NPMplus installed and running (for HTTPS reverse proxy)
- OPNsense or similar router with DNS override capability
- A dyndns (or other DDNS) domain pointed at your public IP
- Ollama running on your network (optional, for local inference)
- API keys for: Anthropic, Groq, Google Gemini (all free tiers work)

---

## Part 1: Prepare ZFS Datasets

Create dedicated ZFS datasets for OpenClaw config and workspace storage. Substitute `STORAGE_POOL` with your actual pool name.

```bash
zfs create STORAGE_POOL/Apps
zfs create STORAGE_POOL/Apps/openclaw
zfs create STORAGE_POOL/Apps/openclaw/config
zfs create STORAGE_POOL/Apps/openclaw/workspace
```

> **Note:** Do NOT pre-create these as host paths and then use Host Path in the app installer — this causes the config init container to fail. Use the ixVolume approach in Part 2 instead.

---

## Part 2: Install OpenClaw from App Catalog

### 2.1 Find the App

Go to **Apps → Discover** in the TrueNAS UI and search for **OpenClaw** (Community train).

### 2.2 Generate a Gateway Token

Before installing, generate a strong random token you'll use to authenticate to the gateway:

```bash
openssl rand -hex 32
```

Save this token — you'll need it throughout setup.

### 2.3 Configuration Settings

Fill in the app installer form as follows:

**OpenClaw Configuration:**
| Field | Value |
|-------|-------|
| Authentication Mode | Shared bearer token (recommended) |
| Gateway Token | *(your generated token)* |
| Proxy Trusted Proxies | Your NPMplus/TrueNAS IP (e.g. `10.1.1.1`) |

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

> ⚠️ **CRITICAL:** Leave storage type as **ixVolume** (do NOT change to Host Path). Using Host Path triggers a known init container bug in OpenClaw 2026.3.2+ that prevents the app from starting.

**Resources Configuration:**
| Field | Value |
|-------|-------|
| CPUs | `4` |
| Memory (MB) | `6144` |

### 2.4 Add Environment Variables

In the **Additional Environment Variables** section, add all provider API keys upfront:

| Name | Value |
|------|-------|
| `ANTHROPIC_API_KEY` | `sk-ant-...` |
| `GROQ_API_KEY` | `gsk_...` |
| `GEMINI_API_KEY` | `AIza...` |
| `OLLAMA_API_KEY` | `ollama-local` |
| `OLLAMA_BASE_URL` | `http://YOUR_OLLAMA_IP:11434` |

Click **Install**.

---

## Part 3: Run the Setup Wizard

Once the app is running (green in Apps → Installed), run the onboarding wizard for each provider.

### 3.1 Anthropic

```bash
sudo docker exec -it ix-openclaw-openclaw-1 node /app/openclaw.mjs onboard --auth-choice anthropic
```

Work through the prompts. Select **Yes** to the security disclaimer, **QuickStart** mode, and **Use existing values** for config handling.

### 3.2 Google Gemini

```bash
sudo docker exec -it ix-openclaw-openclaw-1 node /app/openclaw.mjs onboard --auth-choice google
```

When prompted, confirm use of the existing `GEMINI_API_KEY` environment variable. Set Gemini as the web search provider when asked.

### 3.3 Groq

```bash
sudo docker exec -it ix-openclaw-openclaw-1 node /app/openclaw.mjs onboard --auth-choice groq
```

> **Note:** The Groq wizard may not prompt for the API key if it detects the env var. If it completes without registering Groq models, see [Part 5](#part-5-fix-config-and-verify-providers).

### 3.4 Ollama

```bash
sudo docker exec -it ix-openclaw-openclaw-1 node /app/openclaw.mjs onboard --auth-choice ollama
```

When prompted for the Ollama base URL, enter: `http://YOUR_OLLAMA_IP:11434` (no `/v1` suffix — OpenClaw uses the native Ollama API).

Select **Local only** mode and choose your model from the discovered list.

---

## Part 4: Configure AI Providers

### Anthropic (Claude)

Anthropic is configured via the wizard. Verify it's working:

```bash
sudo docker exec -it ix-openclaw-openclaw-1 node /app/openclaw.mjs models list --provider anthropic
```

### Google Gemini

Gemini is configured via the wizard. Verify:

```bash
sudo docker exec -it ix-openclaw-openclaw-1 node /app/openclaw.mjs models list --provider google
```

### Groq

If Groq didn't register during the wizard, add it manually by editing the config file directly on the TrueNAS filesystem. First find the config file:

```bash
sudo find /mnt/.ix-apps -name "openclaw.json" 2>/dev/null
```

Then edit it with Python (which handles JSON booleans correctly):

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

Validate the JSON before restarting:

```bash
sudo python3 -c "import json; json.load(open('/mnt/.ix-apps/app_mounts/openclaw/config/.openclaw/openclaw.json')); print('Valid')"
```

### Ollama (Local)

After the wizard, fix the API key (wizard sets it to the literal string instead of the value):

```bash
sudo docker exec -it ix-openclaw-openclaw-1 node /app/openclaw.mjs config set models.providers.ollama.apiKey "ollama-local"
```

Add your Ollama models to the agents allowlist using the Python method:

```bash
sudo python3 -c "
import json
path = '/mnt/.ix-apps/app_mounts/openclaw/config/.openclaw/openclaw.json'
with open(path) as f:
    config = json.load(f)

# Add your actual Ollama model names here
config['agents']['defaults']['models']['ollama/YOUR_MODEL_NAME:latest'] = {}

with open(path, 'w') as f:
    json.dump(config, f, indent=2)
print('Done')
"
```

Check available Ollama models first:

```bash
sudo docker exec -it ix-openclaw-openclaw-1 curl -s http://YOUR_OLLAMA_IP:11434/api/tags
```

---

## Part 5: Fix Config and Verify Providers

After all provider setup, restart the app from the TrueNAS UI (Stop → Start), then verify all providers are loaded:

```bash
sudo docker exec -it ix-openclaw-openclaw-1 node /app/openclaw.mjs models list
```

Expected output should show all four providers:

```
Model                                      Input      Ctx      Local Auth  Tags
google/gemini-3.1-pro-preview              text+image 1024k    no    yes   default,configured
anthropic/claude-opus-4-7                  text+image 977k     no    yes   configured
anthropic/claude-haiku-4-5                 text+image 195k     no    yes   configured
ollama/YOUR_MODEL:latest                   text       8k       no    yes   configured
groq/llama-3.3-70b-versatile               text       128k     no    yes   configured
```

> **Important:** Never use `config set` with nested provider objects (e.g. `models.providers.groq`) — OpenClaw's config validator rejects partially-written provider entries. Always use the Python direct-edit method for adding custom provider blocks.

---

## Part 6: Set Default Model and Tools Profile

Set Groq as the default model to minimize API costs (Groq has a generous free tier):

```bash
sudo docker exec -it ix-openclaw-openclaw-1 node /app/openclaw.mjs config set agents.defaults.model.primary "groq/llama-3.3-70b-versatile"
```

Set the tools profile (valid values: `minimal`, `coding`, `messaging`, `full`):

```bash
# For IT/cybersecurity work
sudo docker exec -it ix-openclaw-openclaw-1 node /app/openclaw.mjs config set tools.profile full
```

---

## Part 7: Security Hardening

Run the built-in security audit:

```bash
sudo docker exec -it ix-openclaw-openclaw-1 node /app/openclaw.mjs security audit
```

Fix the flagged issues:

```bash
# Disable dangerous host-header origin fallback
sudo docker exec -it ix-openclaw-openclaw-1 node /app/openclaw.mjs config set gateway.controlUi.dangerouslyAllowHostHeaderOriginFallback false

# Disable insecure auth (requires HTTPS access going forward)
sudo docker exec -it ix-openclaw-openclaw-1 node /app/openclaw.mjs config set gateway.controlUi.allowInsecureAuth false

# Add rate limiting against brute force
sudo docker exec -it ix-openclaw-openclaw-1 node /app/openclaw.mjs config set gateway.auth.rateLimit '{"maxAttempts":10,"windowMs":60000,"lockoutMs":300000}'

# Lock down allowed origins to your HTTPS domain only
sudo docker exec -it ix-openclaw-openclaw-1 node /app/openclaw.mjs config set gateway.controlUi.allowedOrigins '["https://YOUR_DOMAIN"]'
```

Restart the app to apply security changes.

> ⚠️ After disabling `allowInsecureAuth`, you must access OpenClaw via HTTPS only. Local IP access will no longer work.

---

## Part 8: NPMplus Reverse Proxy with HTTPS

### 8.1 Create a Proxy Host

In the NPMplus UI, go to **Hosts → Proxy Hosts → Add Proxy Host**.

**Details tab:**
| Field | Value |
|-------|-------|
| Domain Name | `openclaw.yourdomain.dyndns.org` |
| Scheme | `http` |
| Forward Hostname/IP | Your TrueNAS IP (e.g. `10.0.1.149`) |
| Forward Port | `30262` |

Click the **gear icon ⚙️** next to the Forward Port and add this in the advanced config box:

```nginx
proxy_set_header Upgrade $http_upgrade;
proxy_set_header Connection "upgrade";
proxy_set_header Host $host;
proxy_set_header X-Real-IP $remote_addr;
proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
proxy_set_header X-Forwarded-Proto $scheme;
```

**TLS tab:**
| Field | Value |
|-------|-------|
| TLS Certificate | Request a new Certificate |
| Force HTTPS | ✅ Enabled |
| HTTP/2 Support | ✅ Enabled |
| Use DNS Challenge | ✅ Enabled (required for dyndns) |

For Dyndns, enable **Use DNS Challenge** and enter your dyndns token.

### 8.2 Local DNS Override (OPNsense)

To access the HTTPS domain locally without hairpin NAT, add a host override in OPNsense:

Go to **Services → Unbound DNS → Host Overrides** and add:

| Field | Value |
|-------|-------|
| Host | `openclaw` |
| Domain | `yourdomain.dyndns.org` |
| IP | Your TrueNAS IP (e.g. `10.0.1.149`) |

Save and apply. Now `https://openclaw.yourdomain.dyndns.org` resolves locally.

### 8.3 Port Forwarding

On your router, forward external ports 80 and 443 to your TrueNAS IP on NPMplus's listening ports (check with `sudo docker ps | grep npmplus` to confirm port mappings).

---

## Part 9: Device Pairing

### 9.1 Access the Web UI

Open `https://openclaw.yourdomain.dyndns.org` in your browser.

### 9.2 Connect

On the Gateway Dashboard:
- **WebSocket URL:** `wss://openclaw.yourdomain.dyndns.org`
- **Gateway Token:** *(your token from Part 2)*
- Click **Connect**

### 9.3 Approve the Pairing Request

When the browser shows "pairing required", approve it from the CLI:

```bash
# List pending pairing requests
sudo docker exec -it ix-openclaw-openclaw-1 node /app/openclaw.mjs devices list

# Approve the pending request (use the Request UUID from the output)
sudo docker exec -it ix-openclaw-openclaw-1 node /app/openclaw.mjs devices approve YOUR-REQUEST-UUID
```

You're now connected to the OpenClaw dashboard.

---

## Troubleshooting

### App fails to start: `config service exit 1`

This is a known bug in OpenClaw 2026.3.2+ where the config init container calls `systemctl --user` which fails in a Docker container.

**Fix:** Use **ixVolume** storage instead of Host Path. Delete the app, reinstall with default ixVolume storage.

### App fails after config file edit: `config service exit 1`

The config file has invalid JSON or a schema validation error.

**Fix:** Restore from the automatic backup:

```bash
# Find config file location
sudo find /mnt/.ix-apps -name "openclaw.json" 2>/dev/null

# Restore backup
sudo cp /mnt/.ix-apps/app_mounts/openclaw/config/.openclaw/openclaw.json.bak \
        /mnt/.ix-apps/app_mounts/openclaw/config/.openclaw/openclaw.json

# Validate
sudo python3 -c "import json; json.load(open('/mnt/.ix-apps/app_mounts/openclaw/config/.openclaw/openclaw.json')); print('Valid')"
```

### `config set` fails with "Unrecognized key: llm"

The `llm` prefix doesn't exist in this version. Use `models.providers` for custom providers, or the wizard/auth profile approach for built-in providers (Anthropic, Groq, Gemini).

### `config set` fails with schema validation on provider objects

OpenClaw requires all mandatory provider fields simultaneously. You cannot set nested provider objects one field at a time.

**Fix:** Use the Python direct-edit method described in [Part 4](#part-4-configure-ai-providers).

### `devices list` fails with gateway closed (1006)

The gateway process isn't running or is bound to a different port.

**Check what's running:**
```bash
sudo docker exec -it ix-openclaw-openclaw-1 sh -c "ps aux | grep openclaw"
```

**Start gateway in background:**
```bash
sudo docker exec -d ix-openclaw-openclaw-1 node /app/openclaw.mjs gateway run
```

### Ollama shows "could not be reached at 127.0.0.1:11434"

The `OLLAMA_HOST` environment variable is ignored by this version. Use `OLLAMA_BASE_URL` instead.

In TrueNAS app config, set:
- `OLLAMA_BASE_URL` = `http://YOUR_OLLAMA_IP:11434`
- `OLLAMA_API_KEY` = `ollama-local`

### Certificate request fails (Internal Error in NPMplus)

Port 80 is not accessible for the HTTP-01 ACME challenge. Use the **DNS Challenge** option in NPMplus TLS settings and provide your dyndns token.

---

## Reference: Key Commands

```bash
# Check running containers
sudo docker ps | grep openclaw

# View all configured models
sudo docker exec -it ix-openclaw-openclaw-1 node /app/openclaw.mjs models list

# Get a config value
sudo docker exec -it ix-openclaw-openclaw-1 node /app/openclaw.mjs config get gateway.port

# Set a config value
sudo docker exec -it ix-openclaw-openclaw-1 node /app/openclaw.mjs config set KEY VALUE

# Run security audit
sudo docker exec -it ix-openclaw-openclaw-1 node /app/openclaw.mjs security audit

# List paired devices
sudo docker exec -it ix-openclaw-openclaw-1 node /app/openclaw.mjs devices list

# Approve a device pairing
sudo docker exec -it ix-openclaw-openclaw-1 node /app/openclaw.mjs devices approve UUID

# View config file path
sudo docker exec -it ix-openclaw-openclaw-1 node /app/openclaw.mjs config file

# View raw config file (from TrueNAS host)
sudo cat /mnt/.ix-apps/app_mounts/openclaw/config/.openclaw/openclaw.json

# Validate config JSON
sudo python3 -c "import json; json.load(open('/mnt/.ix-apps/app_mounts/openclaw/config/.openclaw/openclaw.json')); print('Valid')"

# View app lifecycle logs
sudo grep openclaw /var/log/app_lifecycle.log | tail -20

# Check env vars in container
sudo docker exec -it ix-openclaw-openclaw-1 env | grep -E "GROQ|GEMINI|OLLAMA|ANTHROPIC"
```

---

## Cost Optimization Tips

- **Use Groq as primary** — free tier with fast Llama 3.3 70B inference
- **Use Gemini as fallback** — free tier with 1M token context window
- **Reserve Claude** for tasks that genuinely need it (complex reasoning, long context)
- **Use local Ollama** for sensitive tasks or when offline
- The **Adaptive** model mode in the dashboard automatically routes to stronger models only when needed

---

## Next Steps

- Set up Telegram for mobile access: `sudo docker exec -it ix-openclaw-openclaw-1 node /app/openclaw.mjs onboard --auth-choice telegram`
- Install the TrueNAS skill from ClawHub to let OpenClaw manage your homelab
- Run `openclaw doctor` periodically to check for issues
- Rotate API keys after initial setup (Groq and Gemini keys appeared in shell history during setup)

---

*Guide written based on a production deployment on TrueNAS SCALE 25.04, Dell R630, OPNsense, NPMplus, and Ollama. OpenClaw version 2026.4.15.*
