# 🍯 Open-Source Honeypot Deployment with OpenCanary

<div align="center">

**Deception-based intrusion detection on a Raspberry Pi — built from real trial and error**

*Part of the [ULTIMATE CYBERSECURITY MASTER GUIDE](../../README.md) · [Incident Response](../README.md) section*

![Blue Team](https://img.shields.io/badge/Operations-Blue_Team-blue?style=for-the-badge)
![Honeypot](https://img.shields.io/badge/Framework-Deception_Tech-darkred?style=for-the-badge)
![OpenCanary](https://img.shields.io/badge/Platform-OpenCanary-orange?style=for-the-badge)

</div>

---

## 🎯 Purpose
Guide for deploying [OpenCanary](https://github.com/thinkst/opencanary), a lightweight open-source honeypot, as an early-warning deception layer that emulates real services (SSH, FTP, HTTP, Telnet, MySQL, SMB) and alerts the moment anyone touches them — because nothing legitimate should ever talk to a honeypot.

## ⚙️ Function
Covers why OpenCanary was the tool that actually worked after two other honeypots failed, install and dependency troubleshooting, multi-service configuration, safely running a honeypot on a common port without losing real SSH access, email alerting, and log analysis.

## 🏆 Goal
Get a low-resource honeypot running and logging real attacker interaction — reliably, on hardware as modest as a Raspberry Pi 3B — without burning hours on the installer dead-ends this guide already walked into so you don't have to.

## 📋 When to Use
- Standing up a low-interaction honeypot to catch and log automated attack traffic
- A "which honeypot should I actually use" decision — this documents why the popular first picks (HoneyPi, Cowrie) aren't always the smooth path
- Placing a honeypot on a Pi or small VM with limited resources
- Deciding what to do with a spare device on your network (see [Homelab/HomeLab_Setup.md](https://github.com/Pnwcomputers/ULTIMATE-CYBERSECURITY-MASTER-GUIDE/blob/main/Homelab/HomeLab_Setup.md)'s honeypot-device option)

> 📝 **Note:** This guide is informational/educational, covering the general deployment path rather than one specific live network.

---

## 📋 Table of Contents

- [What a Honeypot Actually Buys You](#-what-a-honeypot-actually-buys-you)
- [Why OpenCanary (and Not the First Two Things Tried)](#-why-opencanary-and-not-the-first-two-things-tried)
- [Deployment Workflow](#-deployment-workflow)
- [Installation](#-installation)
- [Freeing the Ports the Honeypot Needs](#-freeing-the-ports-the-honeypot-needs)
- [Configuration](#-configuration)
- [Running It](#-running-it)
- [Email Alerting](#-email-alerting)
- [Log Analysis](#-log-analysis)
- [Common Gotchas](#-common-gotchas)
- [⚠️ Security Notes](#️-security-notes)
- [Resources](#-resources)

---

## 🎯 What a Honeypot Actually Buys You

A honeypot isn't a detector for *your* network's real traffic — it's a decoy with no legitimate reason to ever be touched. Any connection attempt against it is, by definition, either a misconfiguration or an attacker/scanner. That makes its signal-to-noise ratio far better than almost any other detection source: a honeypot alert doesn't need tuning the way a Suricata ruleset or a wireless IDS alert does, because there's no legitimate baseline traffic to distinguish it from.

This makes it a strong **complement** to (not a replacement for) the detection layers covered elsewhere in this repo — see the [IDS/IPS guides](https://github.com/Pnwcomputers/ULTIMATE-CYBERSECURITY-MASTER-GUIDE/blob/main/IncidentResponse/IDS%26IPS/README.md) for signature/protocol-based detection on real production traffic.

---

## 🔍 Why OpenCanary (and Not the First Two Things Tried)

Three honeypots were actually attempted on a Pi 3B, in this order:

| Attempt | Result |
|---|---|
| **HoneyPi** | Installer script ran and exited cleanly, but never created a running service or log file — nothing to show for it, no clear error to debug either |
| **Cowrie** | `git clone` repeatedly produced an incomplete repository — missing the `bin/cowrie` executable script needed to even start the install process |
| **OpenCanary** | Installed successfully after resolving a chain of Python dependency issues (see [Installation](#-installation)) — this is the one that actually worked |

**The takeaway:** Cowrie is usually cited as the "best balance" honeypot for a Pi, and on a healthy environment it likely is. But if you hit a silently-broken installer or a mysteriously incomplete git clone, don't burn hours re-trying the same tool — **OpenCanary is a legitimate, lighter-weight fallback**, not a downgrade. It's pure Python, has fewer moving parts, and emulates more services out of the box (SSH, FTP, HTTP, HTTPS, Telnet, MySQL, MSSQL, SMB, RDP, TFTP, NTP, SNMP, and more) than an SSH/Telnet-only honeypot like Cowrie.

---

## 🚀 Deployment Workflow

```text
1. Prep:
   └─> Pick hardware (a Pi 3B is sufficient) and isolate it — a honeypot
       should never sit on the same trust level as production systems.
   └─> Decide which service ports it will emulate.

2. Free the ports:
   └─> If emulating SSH on port 22, move the box's REAL SSH daemon to a
       different port FIRST, before starting the honeypot.

3. Install:
   └─> pip-install OpenCanary; work through the dependency chain
       (pkg_resources/setuptools, simplejson, twisted, pyOpenSSL).

4. Configure:
   └─> Edit /etc/opencanaryd/opencanary.conf — enable the services you
       want, set realistic banners.

5. Start & validate:
   └─> Start the daemon, confirm each emulated service actually bound
       to its port, connect from a SEPARATE machine to generate a test
       hit, confirm it logs.

6. Alert & persist:
   └─> Configure email alerting for real-time notification.
   └─> Add a systemd unit so it survives reboots.

7. Monitor:
   └─> Review logs regularly; every hit is signal, not noise.
```

---

## 🔧 Installation

### System dependencies

```bash
sudo apt update
sudo apt install -y python3-pip python3-dev libssl-dev libffi-dev
```

### Install OpenCanary

Modern Debian/Ubuntu-based systems (including current Raspberry Pi OS) block system-wide `pip installs` by default (PEP 668). You'll hit an `error: externally-managed-environment` without the flag below:

```bash
sudo pip3 install opencanary --break-system-packages --no-deps
```

`--no-deps` is deliberate here — installing OpenCanary's full dependency list in one shot on a system with Debian-managed Python packages can trigger a package conflict:

```
Attempting uninstall: urllib3
error: uninstall-no-record-file
× Cannot uninstall urllib3 2.3.0
```

This happens because `urllib3` (and similar packages) is already installed by `apt`, and pip can't safely uninstall a package it didn't install. Installing with `--no-deps` first, then resolving each missing dependency individually as OpenCanary complains about it, sidesteps the conflict entirely.

### Work through the dependency chain

OpenCanary will fail at startup one missing module at a time — install each as it surfaces:

```bash
# opencanaryd --copyconfig fails with:  ModuleNotFoundError: No module named 'pkg_resources'
sudo pip3 install setuptools --break-system-packages

# opencanaryd --start fails with:  ModuleNotFoundError: No module named 'simplejson'
sudo pip3 install simplejson --break-system-packages

# opencanaryd --start fails with:  .../opencanaryd: line 48: /usr/local/bin/twistd: No such file or directory
sudo pip3 install twisted --break-system-packages
```

Depending on your exact Python/OS combination you may also need `pyOpenSSL`:

```bash
sudo pip3 install pyopenssl --break-system-packages
```

> If you'd rather avoid touching system-managed Python packages at all, a virtual environment (`python3 -m venv ~/opencanary-env`) is the cleaner alternative — install OpenCanary inside it instead of using `--break-system-packages`. The trade-off is you'll need to activate that venv (or reference its full binary path) in whatever systemd unit later starts the daemon.

---

## 🔌 Freeing the Ports the Honeypot Needs

**Do this before starting OpenCanary if you're emulating SSH on port 22.** Attackers and automated scanners overwhelmingly target the *standard* ports — putting the honeypot's SSH listener on a high port like 8022 will make it nearly invisible to the exact scanning traffic it exists to catch.

Move the box's real SSH daemon off port 22 first:

```bash
sudo nano /etc/ssh/sshd_config
# Change: Port 22   ->   Port 2222
sudo systemctl restart sshd
```

Confirm you can still reach the real SSH service on the new port **before** proceeding — getting locked out of a headless Pi over this is an easy, avoidable mistake:

```bash
ssh -p 2222 user@<pi-ip>
```

Only once that's confirmed working should OpenCanary be configured to bind port 22.

---

## ⚙️ Configuration

Generate the default config, then edit it:

```bash
sudo opencanaryd --copyconfig
sudo nano /etc/opencanaryd/opencanary.conf
```

A working multi-service configuration:

```json
{
    "device.node_id": "opencanary-1",
    "ip.ignorelist": [],
    "git.enabled": false,

    "ssh.enabled": true,
    "ssh.port": 22,
    "ssh.version": "SSH-2.0-OpenSSH_5.1p1 Debian-5ubuntu1",

    "ftp.enabled": true,
    "ftp.port": 21,
    "ftp.banner": "FTP server ready",

    "http.enabled": true,
    "http.port": 80,
    "http.banner": "Apache/2.2.22 (Ubuntu)",
    "httpproxy.enabled": false,

    "telnet.enabled": true,
    "telnet.port": 23,
    "telnet.banner": "Welcome",

    "mysql.enabled": true,
    "mysql.port": 3306,
    "mysql.banner": "5.5.43-0ubuntu0.14.04.1",

    "smb.enabled": true,
    "smb.auditfile": "/var/log/samba-audit.log",
    "smb.domain": "corp",

    "portscan.enabled": true,

    "redis.enabled": false,
    "rdp.enabled": false,
    "sip.enabled": false,
    "snmp.enabled": false,
    "ntp.enabled": false,
    "tftp.enabled": false,
    "tcpbanner.enabled": false,
    "mssql.enabled": false,
    "vnc.enabled": false,

    "logger": {
        "class": "PyLogger",
        "kwargs": {
            "formatters": { "plain": { "format": "%(message)s" } },
            "handlers": {
                "console": {
                    "class": "logging.StreamHandler",
                    "stream": "ext://sys.stdout"
                },
                "file": {
                    "class": "logging.FileHandler",
                    "filename": "/var/tmp/opencanary.log"
                }
            }
        }
    }
}
```

Enable only the services that make sense for what you're trying to attract — a wider spread (as above) catches more scanner types, but every additional emulated service is one more thing to keep an eye on. Realistic banners matter: a default/generic banner is more likely to tip off a careful attacker that it's a decoy.

---

## ▶️ Running It

```bash
sudo opencanaryd --start
sudo opencanaryd --status
```

Expect a startup warning like this — it's normal, not an error, since binding to low ports (22, 80, 21) requires root:

```
WARNING: OpenCanary will not drop root user or group privileges after launching.
Set both --uid=nobody and --gid=nogroup (or another low privilege user/group) to silence this warning.
```

### Persist across reboots

```bash
sudo nano /etc/systemd/system/opencanary.service
```

```ini
[Unit]
Description=OpenCanary Honeypot
After=network.target

[Service]
Type=forking
ExecStart=/usr/local/bin/opencanaryd --start
ExecStop=/usr/local/bin/opencanaryd --stop
Restart=on-failure

[Install]
WantedBy=multi-user.target
```

```bash
sudo systemctl daemon-reload
sudo systemctl enable opencanary
```

### Validate from a separate machine

**Never test from the honeypot host itself** — connect from a different device on the network:

```bash
ssh root@<honeypot-ip>
```

Any credentials, real or fake — you're not trying to log in, you're trying to generate a logged hit. Confirm it landed:

```bash
tail -f /var/tmp/opencanary.log
```

---

## 📧 Email Alerting

OpenCanary can email on every hit via its config's `handlers` block:

```json
"handlers": {
    "SMTP": {
        "class": "logging.handlers.SMTPHandler",
        "mailhost": ["smtp.gmail.com", 587],
        "fromaddr": "you@example.com",
        "toaddrs": ["you@example.com"],
        "subject": "OpenCanary Alert",
        "credentials": ["you@example.com", "your-app-password"],
        "secure": []
    }
}
```

**Gmail-specific gotcha:** an app password is displayed with spaces in Google's UI for readability (`abcd efgh ijkl mnop`) but must be entered **without spaces** wherever you actually use it. This trips people up because it's easy to copy the displayed, spaced version verbatim.

---

## 🔍 Log Analysis

OpenCanary logs structured JSON — one event per line:

```bash
# Live tail
tail -f /var/tmp/opencanary.log

# Recent activity
tail -100 /var/tmp/opencanary.log

# Total events
wc -l /var/tmp/opencanary.log

# Filter by attack type
grep "ssh.login_attempt" /var/tmp/opencanary.log
grep "ftp.login_attempt" /var/tmp/opencanary.log
grep "portscan" /var/tmp/opencanary.log

# Unique attacker source IPs, ranked by frequency
grep "src_host" /var/tmp/opencanary.log | grep -oP '"src_host": "\K[^"]+' | sort | uniq -c | sort -rn
```

For centralizing these logs into a SIEM alongside your other detection sources, see **[IncidentResponse/log_agg.md](https://github.com/Pnwcomputers/ULTIMATE-CYBERSECURITY-MASTER-GUIDE/blob/main/IncidentResponse/log_agg.md)** and **[IncidentResponse/SIEM/README.md](https://github.com/Pnwcomputers/ULTIMATE-CYBERSECURITY-MASTER-GUIDE/blob/main/IncidentResponse/SIEM/README.md)**.

---

## 🩹 Common Gotchas

| Symptom | Cause | Fix |
|---|---|---|
| `error: externally-managed-environment` on `pip install` | PEP 668 blocking system-wide pip installs on modern Debian/Ubuntu | Add `--break-system-packages`, or use a venv |
| `uninstall-no-record-file` on `urllib3` (or similar) during install | pip trying to uninstall a package that `apt`, not pip, originally installed | Install with `--no-deps` first, then add missing modules individually as errors surface |
| `ModuleNotFoundError: No module named 'pkg_resources'` | `setuptools` missing/incompatible with the Python version | `pip3 install setuptools --break-system-packages` |
| `ModuleNotFoundError: No module named 'simplejson'` | Dependency not pulled in by `--no-deps` install | `pip3 install simplejson --break-system-packages` |
| `.../opencanaryd: line 48: /usr/local/bin/twistd: No such file or directory` | `twisted` (which provides `twistd`) missing | `pip3 install twisted --break-system-packages` |
| Honeypot barely gets any hits | Emulated services on non-standard ports (e.g. SSH on 8022) | Move real SSH off 22 first, then run the honeypot's SSH listener *on* 22 — scanners target standard ports |
| Locked out of the box after moving SSH | Didn't verify the new SSH port worked before restarting the daemon | Always test the new port from a second terminal/session before closing the original one |
| Installer runs, "succeeds," nothing is actually running | Some pre-packaged honeypot installers (not OpenCanary specifically) exit cleanly without creating the service they claim to | Verify with `systemctl status <service>` and check for an actual log file being written, don't trust installer exit codes alone |

---

## ⚠️ Security Notes

```
═══════════════════════════════════════════════════════════════
                    ⚠️ CRITICAL WARNING ⚠️
═══════════════════════════════════════════════════════════════

► ISOLATE IT. A honeypot exists to be attacked — never place it on
  the same network segment/trust level as production systems. If
  it's compromised (rare with a low-interaction honeypot like
  OpenCanary, but not impossible), it should have nothing
  reachable worth pivoting to.

► DON'T LOCK YOURSELF OUT. Moving real SSH off port 22 to make
  room for the honeypot is safe ONLY if you verify the new port
  works from a separate session before you rely on it.

► LOW-INTERACTION ≠ ZERO-RISK. OpenCanary simulates services
  rather than running real vulnerable ones (unlike some
  high-interaction honeypots), which keeps risk low — but keep it
  patched and don't assume "it's just a honeypot" means it's safe
  to neglect.

► EVERY HIT IS A REAL EVENT. There's no legitimate reason for
  anything to touch a honeypot. Don't let alerts pile up unread —
  the signal-to-noise ratio here is better than almost any other
  detection source in this repo.

═══════════════════════════════════════════════════════════════
```

---

## 📚 Resources

- **OpenCanary GitHub:** [github.com/thinkst/opencanary](https://github.com/thinkst/opencanary)
- **OpenCanary docs:** [opencanary.readthedocs.io](https://opencanary.readthedocs.io)
- **Canarytokens (complementary project, same maintainers):** [canarytokens.org](https://canarytokens.org)
- **Cowrie (alternative, SSH/Telnet-focused):** [github.com/cowrie/cowrie](https://github.com/cowrie/cowrie)

---

<div align="center">

## Related Files
- [IncidentResponse/IDS&IPS/README.md](https://github.com/Pnwcomputers/ULTIMATE-CYBERSECURITY-MASTER-GUIDE/blob/main/IncidentResponse/IDS%26IPS/README.md) - Signature/protocol-based detection on real traffic, the complement to this deception-based approach
- [IncidentResponse/log_agg.md](https://github.com/Pnwcomputers/ULTIMATE-CYBERSECURITY-MASTER-GUIDE/blob/main/IncidentResponse/log_agg.md) - Centralized log collection, including wireless IDS forwarding patterns applicable here too
- [IncidentResponse/SIEM/README.md](https://github.com/Pnwcomputers/ULTIMATE-CYBERSECURITY-MASTER-GUIDE/blob/main/IncidentResponse/SIEM/README.md) - Forward honeypot alerts into a SIEM for correlation with other detection sources
- [PlayBooks/unauth_access.md](https://github.com/Pnwcomputers/ULTIMATE-CYBERSECURITY-MASTER-GUIDE/blob/main/PlayBooks/unauth_access.md) - Unauthorized-access investigation playbook; a honeypot trigger is explicitly a low-severity classification there
- [Homelab/HomeLab_Setup.md](https://github.com/Pnwcomputers/ULTIMATE-CYBERSECURITY-MASTER-GUIDE/blob/main/Homelab/HomeLab_Setup.md) - Repurposing spare lab hardware as a honeypot device

---

**🛡️ Use These Resources Responsibly**

*Every hit is real. There's no legitimate reason to touch a honeypot.*

**Repository**: [ULTIMATE CYBERSECURITY MASTER GUIDE](https://github.com/Pnwcomputers/ULTIMATE-CYBERSECURITY-MASTER-GUIDE)

**Maintained by**: [Pacific Northwest Computers](https://github.com/Pnwcomputers)

⭐ **Star this repo if you find it useful!** ⭐

</div>
