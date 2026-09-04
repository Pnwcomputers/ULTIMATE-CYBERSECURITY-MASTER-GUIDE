# 🍯 T-Pot — The All-In-One Multi-Honeypot Platform

<div align="center">

**20+ honeypots, Elastic Stack dashboards, and an attack map — orchestrated as Docker containers**

*Part of the [ULTIMATE CYBERSECURITY MASTER GUIDE](../../README.md) · [Incident Response](../README.md) · [Honeypots](./README.md) section*

![Blue Team](https://img.shields.io/badge/Operations-Blue_Team-blue?style=for-the-badge)
![Honeypot](https://img.shields.io/badge/Framework-Deception_Tech-darkred?style=for-the-badge)
![T-Pot](https://img.shields.io/badge/Platform-T--Pot-orange?style=for-the-badge)

</div>

---

## 🎯 Purpose
Guide for deploying [T-Pot](https://github.com/telekom-security/tpotce), a community-driven, multiarch (amd64/arm64) all-in-one honeypot platform that bundles 20+ individual honeypots (Cowrie, Dionaea, Honeytrap, and more) plus Elastic Stack dashboards, an animated attack map, and supporting security tools, all orchestrated via Docker.

## ⚙️ Function
Covers hardware/OS sizing, the supported-distro installation path, the difference between Hive and Sensor (distributed) deployments, first-start and remote access, customizing which honeypots run, and the maintenance model — updates, backups, and known issues.

## 🏆 Goal
Get from a clean OS install to a fully dashboarded multi-honeypot deployment, understanding the resource commitment and placement decisions T-Pot requires *before* you start rather than discovering them mid-install.

## 📋 When to Use
- You've validated the honeypot concept with something lighter (e.g. [OpenCanary](./opencanary.md)) and want broader protocol coverage with less manual config
- You want out-of-the-box dashboards and an attack map rather than building your own log analysis
- You have a spare machine with real resources (8-16 GB RAM, 128+ GB disk) to dedicate
- You're running a distributed deployment: honeypots on remote **Sensors**, dashboards centralized on a **Hive**

---

## 📋 Table of Contents

- [What T-Pot Actually Is](#-what-t-pot-actually-is)
- [System Requirements](#-system-requirements)
- [Placement](#-placement)
- [Installation](#-installation)
- [Hive vs. Sensor (Distributed) Deployment](#-hive-vs-sensor-distributed-deployment)
- [First Start & Remote Access](#-first-start--remote-access)
- [Customizing Which Honeypots Run](#-customizing-which-honeypots-run)
- [Maintenance](#-maintenance)
- [Common Gotchas](#-common-gotchas)
- [⚠️ Security Notes](#️-security-notes)
- [Resources](#-resources)

---

## 🎯 What T-Pot Actually Is

T-Pot isn't a single honeypot — it's an orchestration layer. It runs Docker images for **23+ individual honeypot projects** (Cowrie, Dionaea, ConPot, Honeytrap, ADBHoney, Heralding, Log4Pot, and many more), each in its own container, plus:

- **Elastic Stack** (Elasticsearch + Logstash + Kibana) for storing and visualizing every event
- **An animated attack map** and **CyberChef** for on-the-fly data analysis
- **Suricata, P0f, and Fatt** for network security monitoring on top of the honeypot layer
- **Spiderfoot** for OSINT automation
- Optional **LLM-based honeypots** (Beelzebub, Galah) that use Ollama or ChatGPT to generate dynamic responses to attacker commands

This is the "go big" option in the [Honeypots](./README.md) comparison — where [OpenCanary](./opencanary.md) gives you broad-but-shallow service emulation on minimal hardware, T-Pot gives you deep, per-protocol honeypots plus a full analysis stack, at the cost of real resources and a dedicated, isolated machine.

---

## 🖥️ System Requirements

| T-Pot Type | RAM | Storage | Description |
|---|---|---|---|
| **Hive** | 16 GB | 256 GB SSD | Runs everything: honeypots, tools, and the Elastic Stack. More honeypots/sensors/data → more RAM and storage needed. |
| **Sensor** | 8 GB | 128 GB SSD | Hosts only the honeypots and transmits log data to a Hive. Storage depends on attack volume — logs persist for 30 days by default. |

Also required: a **single NIC** (T-Pot is designed around one interface with the default route), an IPv4 address, and a working, non-proxied internet connection.

**Supported OS images** (must be a **minimal/netinstall/server** install — never a desktop environment, which conflicts with T-Pot's ports): current releases of Debian, Ubuntu Server, AlmaLinux, Fedora Server, openSUSE Tumbleweed, Rocky Linux, and RHEL 10. Raspberry Pi 4 (8 GB) is supported via Raspberry Pi OS 64-bit Lite.

---

## 📍 Placement

Get familiar with T-Pot in a VM first before exposing anything to the internet — a fresh deployment on an isolated network segment is the right starting point. Once ready for production placement: **T-Pot only captures attacks if it's actually reachable by attackers.** Put it in an unfiltered zone where TCP/UDP traffic is forwarded to it, but protect the *management* ports specifically — forward the honeypot port range to T-Pot while restricting ports above 64000 (SSH, WebUI) to trusted IPs only.

---

## 🔧 Installation

### One-liner (fastest path)

```bash
env bash -c "$(curl -sL https://github.com/telekom-security/tpotce/raw/master/install.sh)"
```

### Or, git clone first

```bash
git clone https://github.com/telekom-security/tpotce
cd tpotce
./install.sh
```

Run as a **non-root** user — the installer escalates via `sudo` when needed. Depending on your distro, the installer will:

- Abort *before changing anything* if a running service occupies the DNS or SMTP ports the honeypots need
- Move SSH to `tcp/64295`
- Disable the DNS Stub Listener (avoids port conflicts)
- Add Docker's repository and install Docker
- Add convenience aliases (`dps`/`dpsw` for container overviews, `dim` for images)
- Install a `tpot.service` systemd unit so T-Pot starts/stops automatically

Follow the prompts, check the installer's output for port conflicts, then reboot:

```bash
sudo reboot
```

### Unattended installation

For automated/cloud provisioning:

```bash
./install.sh -s -t <type> [-u <webuser>] [-p <password>]
```

`-t` accepts: `h` (hive), `s` (sensor), `l` (llm), `i` (mini), `m` (mobile), `t` (tarpit). `-s` requires passwordless `sudo` for the installing user — grant it first:

```bash
echo "$(whoami) ALL=(ALL) NOPASSWD:ALL" | sudo tee /etc/sudoers.d/$(whoami)
sudo chmod 440 /etc/sudoers.d/$(whoami)
```

Remove that sudoers file after installation if you don't want to keep it.

---

## 🏗️ Hive vs. Sensor (Distributed) Deployment

- **Standard / Hive** — everything (honeypots, tools, Elastic Stack) on one host. Install this first regardless of your end goal.
- **Distributed** — a **Hive** (install standard first) plus one or more **Sensors**, which run only the honeypots and forward logs to the Hive.

Deploying a Sensor requires planning certificates *before* you start — the Hive's self-signed cert is only valid for the IP it was generated against, and Logstash validates it strictly. If your Hive needs to be reachable on multiple IPs (private + public NAT, or a domain name), regenerate the certificate with the correct SANs first (see the [official distributed deployment docs](https://github.com/telekom-security/tpotce#planning-and-certificates) for the exact `openssl` command). Skipping this planning step is the most common source of "Sensor won't connect to Hive" issues.

Once planned:

```bash
# On the Sensor, generate an SSH key and deploy it to the Hive
ssh-keygen
ssh-copy-id -p 64295 <sensor_ssh_user>@<sensor_ip>

# On the Hive
cd ~/tpotce
./deploy.sh
```

---

## 🚀 First Start & Remote Access

After reboot, log in and check container status:

```bash
dps       # formatted overview of running containers
dpsw 5    # same, refreshed every 5 seconds
dim       # locally available images, with age
```

| Access | How |
|---|---|
| SSH | `ssh -l <os_username> -p 64295 <your.ip>` |
| T-Pot WebUI (landing page, links to everything below) | `https://<your.ip>:64297` |
| Kibana dashboards | Via the WebUI → "Kibana" |
| Attack Map | Via the WebUI → "Attack Map" |
| CyberChef, Elasticvue, Spiderfoot | Via the WebUI |

Note the **two separate account types** — this is, per T-Pot's own docs, the single most common source of authentication confusion: your **OS user** (set during OS install, used for SSH) is distinct from the **WEB_USER** (set via `genuser.sh`, used for every web-based tool).

---

## 🎛️ Customizing Which Honeypots Run

The default Standard/Hive install runs a broad selection. To run a specific subset:

```bash
cd ~/tpotce/compose
python3 customizer.py
```

This walks you through selecting honeypots/tools and warns about port conflicts between selections you've made. Then:

```bash
sudo systemctl stop tpot
cp docker-compose-custom.yml ~/tpotce/docker-compose.yml
sudo systemctl start tpot
```

Pre-built compose profiles also exist in `~/tpotce/compose/` for common cases: `mini.yml` (lighter footprint), `sensor.yml`, `mobile.yml`, `tarpit.yml`, `llm.yml` (Beelzebub/Galah).

---

## 🔧 Maintenance

```bash
# Update to the latest release (writes a backup first, automatically)
~/tpotce/update.sh -y

# List and restore backups
~/tpotce/restore.sh -l
~/tpotce/restore.sh -f <archive> -y

# Factory reset (keeps the OS, wipes T-Pot's own data/state)
sudo systemctl stop tpot
sudo rm -rf ~/tpotce/data
cd ~/tpotce && git reset --hard
~/tpotce/install.sh
```

T-Pot adds a **daily reboot** by default (`sudo crontab -e` to adjust) to clean up Docker resources. `update.sh` backs up your `.env`, `docker-compose.yml`, and the data that lives nowhere else (install UUID, nginx cert, host keys) before touching anything — read its output, it explains exactly what it's doing at each step.

---

## 🩹 Common Gotchas

| Symptom | Cause | Fix |
|---|---|---|
| Installer aborts immediately | Something already occupies the DNS/SMTP ports T-Pot's honeypots need | Identify and stop/reconfigure the conflicting service before re-running the installer |
| Docker images fail to download | Docker Hub's anonymous-pull rate limit exhausted on a shared/frequently-used IP | `docker login` with a free Docker account to raise the limit |
| T-Pot networking fails entirely | T-Pot expects a single NIC and grabs the interface with the default route — this doesn't always succeed on multi-NIC hosts | Run T-Pot on single-NIC hardware/VMs only |
| Elastic Stack keeps crashing or never receives logs | Elasticsearch and Logstash are RAM-hungry; this is almost always a resource problem, not a config problem | `docker logs -f <container>` on `logstash`/`elasticsearch`, check RAM with `htop`, verify you meet the sizing table above |
| `update.sh` seems to loop, repeatedly restarting itself | Known issue on 24.04.0 comparing itself against the wrong branch reference; current versions fix this | If you hit it, `Ctrl-C`, then restore `.env` from the *first* backup written during the loop before re-running a current `update.sh -y -b master` |
| Distributed Sensor won't connect to Hive | Logstash strictly validates the Hive's cert; the default self-signed cert is only valid for the single IP it was generated against | Regenerate the Hive's cert with all relevant IPs/domains as SANs *before* deploying any Sensor, per the Planning and Certificates step above |

---

## ⚠️ Security Notes

```
═══════════════════════════════════════════════════════════════
                    ⚠️ CRITICAL WARNING ⚠️
═══════════════════════════════════════════════════════════════

► T-Pot is provided "as is" without any commitment to support —
  per the project's own disclaimer, a system compromise can never
  be fully ruled out. Run it in dedicated, isolated hardware with
  nothing else of value reachable from it.

► RESTRICT MANAGEMENT PORTS. The honeypot port range should be
  open to attackers by design, but SSH (64295) and the WebUI
  (64297) should only be reachable from trusted management IPs.

► DATA SUBMISSION IS ON BY DEFAULT. T-Pot submits captured data
  to a community backend (Sicherheitstacho) unless you explicitly
  opt out by removing the `ewsposter` service from your compose
  file. Decide deliberately rather than leaving the default in
  place without knowing it's there.

► HONEYPOTS SHOULD NEVER HOST SENSITIVE DATA. This applies with
  extra force to a platform running 20+ services simultaneously —
  more surface area, same rule.

═══════════════════════════════════════════════════════════════
```

---

## 📚 Resources

- **T-Pot GitHub:** [github.com/telekom-security/tpotce](https://github.com/telekom-security/tpotce)
- **T-Pot Issues:** [github.com/telekom-security/tpotce/issues](https://github.com/telekom-security/tpotce/issues)
- **T-Pot Discussions:** [github.com/telekom-security/tpotce/discussions](https://github.com/telekom-security/tpotce/discussions)
- **Sicherheitstacho (community attack data):** [sicherheitstacho.eu](https://www.sicherheitstacho.eu/start/main)

---

<div align="center">

## Related Files
- [Honeypots/README.md](./README.md) - Sub-section index and platform comparison
- [Honeypots/opencanary.md](./opencanary.md) - The lighter-weight starting point this guide's "go big" option builds on
- [Honeypots/cowrie.md](./cowrie.md) - T-Pot bundles Cowrie as one of its 20+ honeypots; this is the standalone deployment
- [Honeypots/dionaea.md](./dionaea.md) - T-Pot bundles Dionaea as well; this is the standalone deployment
- [IncidentResponse/SIEM/README.md](https://github.com/Pnwcomputers/ULTIMATE-CYBERSECURITY-MASTER-GUIDE/blob/main/IncidentResponse/SIEM/README.md) - For comparison against building your own SIEM instead of T-Pot's bundled Elastic Stack

---

**🛡️ Use These Resources Responsibly**

*Every hit is real — there's no legitimate reason to touch a honeypot.*

**Repository**: [ULTIMATE CYBERSECURITY MASTER GUIDE](https://github.com/Pnwcomputers/ULTIMATE-CYBERSECURITY-MASTER-GUIDE)

**Maintained by**: [Pacific Northwest Computers](https://github.com/Pnwcomputers)

⭐ **Star this repo if you find it useful!** ⭐

</div>
