# 📡 DIY WiFi Intrusion Detection with nzyme

<div align="center">

**Proxmox VM node + Raspberry Pi tap sensors, built and debugged for real**

*Part of the [ULTIMATE CYBERSECURITY MASTER GUIDE](../README.md)*

![Blue Team](https://img.shields.io/badge/Operations-Blue_Team-blue?style=for-the-badge)
![WIDS](https://img.shields.io/badge/Framework-WIDS-darkred?style=for-the-badge)
![nzyme](https://img.shields.io/badge/Platform-nzyme-orange?style=for-the-badge)

</div>

---

## 🎯 Purpose
Guide for deploying [nzyme](https://nzyme.org), an open-source WiFi/network defense platform, as a self-hosted Wireless Intrusion Detection System (WIDS) — node on a VM, sensors on Raspberry Pi taps with USB adapters.

## ⚙️ Function
Covers node install on Ubuntu Server + PostgreSQL, tap deployment on Pi 3B hardware with Alfa USB adapters, the 2.4/5 GHz band-split sensor strategy, out-of-tree driver fixes for chipsets that crash under channel hopping, and alert-tuning heuristics for telling real rogue-AP activity from RF noise.

## 🏆 Goal
Get a homelab operator from bare hardware to a working, alert-tuned WIDS without re-discovering the driver and Postgres gotchas that eat the most time.

## 📋 When to Use
- Standing up wireless network visibility from scratch on Pi + Proxmox hardware
- A tap's Access Points page stays empty despite the adapter showing `type monitor`
- Triaging a WiFi alert and deciding whether it's a real rogue AP or environmental noise

---

## 📋 Table of Contents

- [Architecture](#-architecture)
- [Hardware & Adapter Reference](#️-hardware--adapter-reference)
- [Deployment Workflow](#-deployment-workflow)
- [Node Install](#-node-install-ubuntu-server-2404)
- [Tap Driver & Config](#-tap-driver--config)
- [Common Failure Modes](#-common-failure-modes)
- [Alert Triage](#-alert-triage)
- [⚠️ Security Note on Third-Party Fixes](#️-security-note-on-third-party-fixes)
- [Resources](#-resources)

---

## 🎯 Architecture

nzyme splits into two components:

| Component | Role | Where it runs |
|---|---|---|
| **nzyme-node** | Web UI, alerting/analysis engine, talks to PostgreSQL | Proxmox VM (Ubuntu Server 24.04) |
| **nzyme-tap** | Lightweight Rust capture agent, ships summarized data upstream | Raspberry Pi + USB WiFi adapter |

**Band-splitting, not redundancy.** A single adapter channel-hops and is blind to any given channel most of the time. Two identical taps fight over the same hopping gaps — dedicating one tap per band roughly doubles effective frame capture instead:

| Tap | Band | Channels |
|---|---|---|
| `pi3b-wifi-1` | 2.4 GHz only | 1, 6, 11 (non-overlapping) |
| `pi3b-wifi-2` | 5 GHz only | 36–165 (non-DFS range) |

A spare, more capable board (e.g. a Pi 5) is better spent as an **Ethernet tap** off a mirror/SPAN port, or a second clustered node, than as a third WiFi tap — taps store nothing on disk, so extra CPU/SSD is wasted on that role.

---

## 🗂️ Hardware & Adapter Reference

### Minimum Specs

| Role | Hardware | OS |
|---|---|---|
| Node | 4 GB RAM / 4 cores / 25 GB disk (VM) | Ubuntu Server 24.04 + PostgreSQL 16 |
| Tap | Raspberry Pi 3B or better | Raspberry Pi OS Lite 64-bit (headless) |

### Adapter Compatibility

| Status | Adapters |
|---|---|
| ✅ Known good | Alfa AWUS036NH, AWUS051NH v2, AWUS036NEH, AWUS036ACM, AWUS036AXML · Panda PAU05/06/07/09/0D · Intel AX210/AX211/AX411 (onboard; WiFi 6 currently broken by a driver region bug) |
| 🟡 Community-confirmed | Alfa AWUS036ACS · CSL USB 2.0 300 Mbit |
| ❌ Known bad | Nineplus AX1800 (rtl8832au) · EDUP AX5400M (rtw8852cu) — neither enters monitor mode |

The MediaTek **AWUS036ACM** (`mt76` driver) is the safest "just works" pick if buying fresh. Realtek 8812AU/8821AU-chipset Alfas are common and usable but may need the driver swap in [Tap Driver & Config](#-tap-driver--config).

---

## 🚀 Deployment Workflow

```text
1. Node Standup:
   └─> Ubuntu Server 24.04 VM, PostgreSQL 16, create nzyme DB/role.
   └─> Install nzyme-node .deb, configure listen/external URIs, migrate DB.

2. Tap Identification:
   └─> lsusb / iw dev to identify actual chipset + driver (not just adapter name).
   └─> Test monitor mode directly before writing any tap config.

3. Driver Correction (if needed):
   └─> Confirm which in-kernel driver claimed the device (rtl8xxxu vs rtw88).
   └─> Install the matching morrownr out-of-tree DKMS driver, reboot, re-verify.

4. Tap Configuration:
   └─> Create the tap in the node UI, copy the leader secret.
   └─> Install nzyme-tap .deb, set leader_secret/leader_uri + one active
       wifi_interfaces block per band split above.

5. Validation & Tuning:
   └─> Watch journalctl for a clean bootstrap (no kernel traces).
   └─> Confirm Access Points populates in the node UI.
   └─> Tune alerts against real traffic — see Alert Triage below.
```

---

## 🔧 Node Install (Ubuntu Server 24.04)

### PostgreSQL

```bash
sudo apt update && sudo apt install -y postgresql-16
```

### Database, User, Grant

```bash
sudo -u postgres psql
```

```sql
CREATE DATABASE nzyme;
CREATE USER nzyme WITH ENCRYPTED PASSWORD 'YOUR_STRONG_PW';
GRANT ALL PRIVILEGES ON DATABASE nzyme TO nzyme;
\c nzyme
GRANT CREATE ON SCHEMA public TO nzyme;
\q
```

> **The gotcha:** `GRANT CREATE ON SCHEMA public TO nzyme` is what everyone skips. On PostgreSQL 15+, `public` no longer grants `CREATE` to non-owners by default, so migration fails without it. Run `\c nzyme` **first** — running the grant while still connected to `postgres` throws a misleading `invalid integer value "ON" for connection option "port"` error from psql misparsing the paste.

Check for an existing install before assuming a clean slate:
```bash
sudo -u postgres psql -tc "\l" | grep -i nzyme
sudo -u postgres psql -tc "\du" | grep -i nzyme
```

### Install & Configure

```bash
wget <url_to_node_deb_from_go.nzyme.org/downloads>
sudo dpkg -i nzyme-node_<version>.deb
sudo nano /etc/nzyme/nzyme.conf
```

| Key | Value |
|---|---|
| `general.database_path` | `postgresql://localhost:5432/nzyme?user=nzyme&password=YOUR_STRONG_PW` |
| `interfaces.rest_listen_uri` | `https://0.0.0.0:22900/` |
| `interfaces.http_external_uri` | `https://10.0.1.x:22900/` (VM's LAN IP) |

nzyme is **HTTPS-only** — it will not answer on plain HTTP. `/etc/default/nzyme` sets JVM heap to `-Xms1g -Xmx1g` by default; raise only if you see heap OOM under load.

### Migrate, Enable, Start

```bash
sudo nzyme --migrate-database   # run before first start and after every future upgrade
sudo systemctl enable --now nzyme
sudo journalctl -u nzyme -f     # wait for "Started web interface and REST API at [...]"
```

Visit `https://10.0.1.x:22900/` (self-signed cert warning is expected) and create your first admin user.

---

## 🔩 Tap Driver & Config

### 1. Identify the actual chipset/driver

Don't trust the adapter's marketing name — the same USB product ID can bind to different kernel drivers.

```bash
lsusb
iw dev
readlink -f /sys/class/net/wlan1/device/driver
```

### 2. Test monitor mode directly

```bash
sudo iw list | grep -A 12 "Supported interface modes"
sudo ip link set wlan1 down
sudo iw dev wlan1 set type monitor
sudo ip link set wlan1 up
iw dev wlan1 info
```

| Result | Meaning |
|---|---|
| `type monitor` shows cleanly | Stock driver handles it — skip to tap config |
| `set type monitor` errors (`Operation not supported (-95)`) | Out-of-tree driver required — see below |

### 3. Fix a driver that crashes under hopping

An adapter can report `type monitor` fine and even capture briefly, while the tap's Access Points page stays empty. Check for kernel oopses:

```bash
dmesg | grep -iE "rtw88|call trace"
```

Repeated oopses clustered right after tap startup = driver instability under channel hopping, not a config error. The same `0bda:0811` "8812AU/8821AU" USB label can be bound to **either** `rtl8xxxu` (genuine 8812AU) or `rtw88` (8821AU single-stream variant) — confirm which with `readlink`/`dmesg` before picking a fix:

| Bound driver | Actual chipset | morrownr repo |
|---|---|---|
| `rtl8xxxu` | 8812AU | [`8812au-20210820`](https://github.com/morrownr/8812au-20210820) |
| `rtw88` | 8821AU | [`8821au-20210708`](https://github.com/morrownr/8821au-20210708) |

```bash
sudo apt update
sudo apt install -y linux-headers-rpi-v8 dkms git build-essential bc
# fallback order if linux-headers-rpi-v8 isn't found:
#   raspberrypi-kernel-headers, then linux-headers-$(uname -r)

git clone https://github.com/morrownr/8821au-20210708.git   # match your chipset
cd 8821au-20210708
sudo ./install-driver.sh
```

`install-driver.sh` blacklists the conflicting in-kernel driver, builds via DKMS, and prompts for reboot — accept defaults, disable power management. After reboot:

```bash
lsmod | grep -E "8821|8812|rtw88|rtl8xxxu"
```

> ⚠️ **Kernel-drift trap:** DKMS builds against the kernel running *at install time*. If `apt upgrade` staged a newer kernel than the one currently booted, the Pi reboots into a kernel the module wasn't built for. DKMS should auto-rebuild — verify with `sudo dkms status`, and if needed: `sudo dkms autoinstall && sudo modprobe 8821au`. **This recurs on every future kernel update** — check this first if a tap goes dark after a routine `apt upgrade`.

### 4. Create the tap and configure

In the node UI: **Settings → Authentication → Organizations → Default Organization → Tenants → Default Tenant → Taps → Create.** Copy the generated leader secret.

```bash
sudo dpkg -i nzyme-tap_<version>.deb
sudo nano /etc/nzyme/nzyme-tap.conf
```

```toml
leader_secret = "PASTE_LEADER_SECRET_HERE"
leader_uri = "https://10.0.1.x:22900/"
accept_insecure_certs = true
```

Only **one** `[wifi_interfaces.*]` block active per tap — rename the template to your real interface name from `ip link`, and set every other block `active = false`.

<table>
<tr><th>2.4 GHz tap</th><th>5 GHz tap</th></tr>
<tr><td>

```toml
[wifi_interfaces.wlan1]
active = true
channel_width_hopping_mode = "full"
channels_2g = [1, 6, 11]
channels_5g = []
channels_6g = []
```

</td><td>

```toml
[wifi_interfaces.wlan1]
active = true
channel_width_hopping_mode = "full"
channels_2g = []
channels_5g = [36,40,44,48,52,56,60,64,
  100,104,108,112,116,120,124,128,132,
  136,140,144,149,153,157,161,165]
channels_6g = []
```

</td></tr>
</table>

> `channels_6g = []` — **always empty** unless you have a genuine 6 GHz adapter. A misconfigured 6g block directly caused a crash-loop in this build.

```bash
sudo systemctl enable --now nzyme-tap
sudo journalctl -u nzyme-tap -f
```

Clean startup:
```
[nzyme_tap] Bootstrap complete.
[wireless::dot11::capture_helpers] Device [wlan1] is now down.
[wireless::dot11::capture_helpers] Enabling monitor mode on interface [wlan1] ...
[wireless::dot11::capture_helpers] Device [wlan1] is now in monitor mode.
[wireless::dot11::capture_helpers] Device [wlan1] is now up.
[nzyme_tap] Node hello submitted.
```

No kernel trace interrupting it, "Node hello submitted" at the end. **WiFi → Access Points** populates within a few minutes (reporting is batched — give it time).

---

## 🩹 Common Failure Modes

| Symptom | Cause | Fix |
|---|---|---|
| Adapter shows up, libpcap reports it down immediately | `wpa_supplicant`/NetworkManager fighting nzyme-tap for the interface | Stop `wpa_supplicant`, or exclude the tap's interface specifically from NetworkManager (not a blanket mask, if the Pi needs WiFi elsewhere) |
| `journalctl -u nzyme-tap` shows `-- No entries --` | Raspberry Pi OS Lite's non-persistent, in-RAM journal wiped on restart | Check `systemctl status nzyme-tap` for real uptime; `ls -la /var/log/journal/` to check persistence |
| Access Points empty, driver unclear | Need ground truth on whether the radio hears anything at all | `sudo timeout 15 tcpdump -i wlan1 -c 30` after `iw dev wlan1 set channel 6` — beacons scrolling = driver/radio fine, problem is upstream |

---

## 🎯 Alert Triage

| Pattern | Verdict |
|---|---|
| "Unapproved client" MAC that's your own gateway's OUI ±1 with the locally-administered bit set | Phantom — many APs present a second locally-administered MAC for a secondary radio/guest network |
| Single, repeated signal-track alert on a BSSID you control, in an RF-noisy space | Environmental — multipath + multiple APs on the same SSID at different distances, not an attack |
| **Cluster** of alert types together (unexpected BSSID + unexpected fingerprint + signal anomaly, close in time) | Treat as a real rogue-AP/evil-twin event |

**Principle:** tune thresholds around clustering, not individual blips. A lone alert of one type on a confirmed-owned BSSID is noise far more often than it's an attack.

---

## ⚠️ Security Note on Third-Party Fixes

```
═══════════════════════════════════════════════════════════════
                    ⚠️ CRITICAL WARNING ⚠️
═══════════════════════════════════════════════════════════════

nzyme is under active development — its GitHub issues and Discord
are the right venue for bugs without a known fix.

► Be cautious of "fixes" that replace the actual nzyme-tap/nzyme
  binaries with third-party patched builds.
► A build process that has you silence or edit a FAILING TEST to
  force a build to "pass" is a red flag for tampered software —
  regardless of who or what produced it — and has no place on a
  security monitoring appliance.
► If in doubt: reinstall from the official .deb and file an issue
  upstream instead of running an unvetted binary you can't verify.

═══════════════════════════════════════════════════════════════
```

---

## 📚 Resources

- **nzyme docs:** [docs.nzyme.org](https://docs.nzyme.org)
- **nzyme downloads:** [go.nzyme.org/downloads](https://go.nzyme.org/downloads)
- **morrownr driver repos:** [github.com/morrownr](https://github.com/morrownr)

---

<div align="center">

## Related Files
- [network_intrusion.md](network_intrusion.md) - Wireless intrusion / rogue AP IR procedure once nzyme raises an alert
- [log_agg.md](log_agg.md) - Feeding nzyme alerts into a broader SIEM pipeline
- [../Homelab/](../Homelab/) - Homelab infrastructure this WIDS deployment lives in

---

**🛡️ Use These Resources Responsibly**

*Visibility is the foundation of security.*

**Repository**: [ULTIMATE CYBERSECURITY MASTER GUIDE](https://github.com/Pnwcomputers/ULTIMATE-CYBERSECURITY-MASTER-GUIDE)

**Maintained by**: [Pacific Northwest Computers](https://github.com/Pnwcomputers)

⭐ **Star this repo if you find it useful!** ⭐

</div>
