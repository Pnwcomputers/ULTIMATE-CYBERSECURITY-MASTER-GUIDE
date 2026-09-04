# 🚫 Fail2Ban — Log-Triggered Automatic Banning

<div align="center">

**Watches your logs, bans the IPs that earn it — the lightest-weight IPS in this repo**

*Part of the [ULTIMATE CYBERSECURITY MASTER GUIDE](../../README.md) · [Incident Response](../README.md) · [IDS & IPS](./README.md) section*

![Blue Team](https://img.shields.io/badge/Operations-Blue_Team-blue?style=for-the-badge)
![IDS/IPS](https://img.shields.io/badge/Framework-IDS_%2F_IPS-darkred?style=for-the-badge)
![Fail2Ban](https://img.shields.io/badge/Engine-Fail2Ban-orange?style=for-the-badge)

</div>

---

## 🎯 Purpose
Guide for deploying [Fail2Ban](https://github.com/fail2ban/fail2ban), a lightweight log-monitoring IPS that watches log files for patterns indicating brute-force or abusive behavior and automatically bans the offending IP via firewall rules — the simplest, lowest-overhead entry in this repo's IDS/IPS lineup.

## ⚙️ Function
Covers install, the jail/filter/action configuration model, protecting SSH (the most common use case) plus other common services, testing a jail actually works, and the operational commands for inspecting and manually unbanning.

## 🏆 Goal
Get automatic, log-driven banning running on any Linux box in minutes — this is the tool to reach for when a full Suricata/Snort deployment is overkill for the actual problem (SSH brute-forcing, web-login stuffing) you're trying to stop.

## 📋 When to Use
- Any internet-facing Linux box with SSH exposed — this is close to a default-should-have for that alone
- Protecting web app login forms (Apache/nginx auth), mail servers, or any other service with a parseable log of failed attempts
- You want *some* automatic response to brute-forcing without deploying a full network IDS/IPS stack
- A honeypot or IDS from elsewhere in this repo flagged repeated brute-force attempts and you want the actual mitigation, not just visibility

---

## 📋 Table of Contents

- [Where This Fits](#-where-this-fits)
- [Deployment Workflow](#-deployment-workflow)
- [Installation](#-installation)
- [The Jail / Filter / Action Model](#-the-jail--filter--action-model)
- [Protecting SSH](#-protecting-ssh)
- [Protecting Other Services](#-protecting-other-services)
- [Validating & Operating](#-validating--operating)
- [Common Gotchas](#-common-gotchas)
- [⚠️ Security Notes](#️-security-notes)
- [Resources](#-resources)

---

## 🎯 Where This Fits

Fail2Ban is not a replacement for [Suricata/Snort](./suricata+zeek.md) or [Security Onion](./security-onion.md) — it doesn't inspect packets or understand protocols. It's a **log watcher with a trigger finger**: it tails log files, matches known failure patterns via regex filters, and when a source IP crosses a threshold, it bans that IP at the firewall for a configured duration. That narrow scope is exactly its value — near-zero resource overhead, works on any box with a log file and a firewall, and covers the single most common real-world attack pattern (credential brute-forcing) that a full NIDS is arguably overkill for.

---

## 🚀 Deployment Workflow

```text
1. Install:
   └─> apt install fail2ban (or your distro's equivalent).

2. Copy the default config to your override file:
   └─> jail.conf -> jail.local. Never edit jail.conf directly —
       package updates will overwrite it.

3. Set your baseline [DEFAULT] policy:
   └─> ignoreip (your own management IPs — don't lock yourself out),
       bantime, findtime, maxretry.

4. Enable the jails you need:
   └─> [sshd] first, always. Add others (apache-auth, nginx-http-auth,
       postfix, etc.) as needed for services actually running.

5. Restart and validate:
   └─> systemctl restart fail2ban
   └─> Deliberately fail auth a few times from a test IP, confirm
       the ban actually happens.

6. Operate:
   └─> fail2ban-client status <jail> to check state.
   └─> Unban manually when you lock out something legitimate.
```

---

## 🔧 Installation

```bash
sudo apt-get update
sudo apt-get install -y fail2ban
sudo systemctl enable fail2ban
sudo systemctl start fail2ban
```

Key files, all under `/etc/fail2ban/`:

| File | Purpose |
|---|---|
| `fail2ban.conf` | Global daemon settings — don't edit |
| `fail2ban.local` | Your overrides to the above, if needed |
| `jail.conf` | Default jail definitions — don't edit |
| `jail.local` | **Your jail overrides — edit this one** |
| `filter.d/` | Regex filter definitions (one per service type) |
| `action.d/` | Ban action definitions (iptables, sendmail, etc.) |

The pattern throughout Fail2Ban's config is the same as much of this repo's other tooling: never edit the `.conf` shipped by the package, always override in the matching `.local` file so package updates don't silently discard your changes.

---

## 🧩 The Jail / Filter / Action Model

- A **jail** ties a service to a filter and a response — "watch this log, using this pattern, and do this when it matches."
- A **filter** is the regex that recognizes a failure in that service's log format.
- An **action** is what happens on a match — almost always an `iptables`/`nftables` ban, optionally combined with an email notification.

Baseline `[DEFAULT]` section in `jail.local`:

```ini
[DEFAULT]
# Never ban these — your own management IPs, always
ignoreip = 127.0.0.1/8 ::1 192.168.1.0/24

# How long a ban lasts (seconds)
bantime = 3600

# The window failures are counted within (seconds)
findtime = 600

# Failures allowed before a ban triggers
maxretry = 5

# Optional email on ban (needs working local mail/SMTP)
# destemail = you@example.com
# sender = fail2ban@example.com
# mta = sendmail
# action = %(action_mwl)s
```

**Set `ignoreip` before enabling anything else.** This is the single most important line in the file — get it wrong and you can ban your own management access.

---

## 🔒 Protecting SSH

The default, and most common, use case:

```ini
[sshd]
enabled = true
port = ssh
filter = sshd
logpath = /var/log/auth.log
maxretry = 3
bantime = 3600
findtime = 600
```

> **Distro-specific log path:** Ubuntu/Debian use `/var/log/auth.log`. RHEL/AlmaLinux/Rocky use `/var/log/secure` and typically need `backend = systemd` added to the jail since auth logging goes through journald by default rather than a flat file. Confirm which applies to your distro before assuming the Ubuntu path is universal.

If you moved SSH to a non-standard port (a pattern used elsewhere in this repo's honeypot guides — see [Cowrie](../Honeypots/cowrie.md) and [OpenCanary](../Honeypots/opencanary.md)), update `port` to match.

---

## 🌐 Protecting Other Services

Fail2Ban ships filters for dozens of services out of the box. A couple of common additions:

```ini
[apache-auth]
enabled = true
port = http,https
filter = apache-auth
logpath = /var/log/apache2/error.log
maxretry = 5
bantime = 3600

[nginx-http-auth]
enabled = true
port = http,https
filter = nginx-http-auth
logpath = /var/log/nginx/error.log
maxretry = 5
bantime = 3600
```

Only enable jails for services actually running on the box — an enabled jail watching a log file that never gets written to is harmless but pointless.

---

## ✅ Validating & Operating

**Check jail status:**

```bash
sudo fail2ban-client status sshd
```

Output shows currently-failed counts, total failures, and the list of currently-banned IPs.

**See the actual firewall rules Fail2Ban created:**

```bash
sudo iptables -L f2b-sshd -n --line-numbers
```

**Manually unban an IP** (e.g. you locked out something legitimate, or a test ban you triggered on purpose):

```bash
sudo fail2ban-client set sshd unbanip <ip-address>
```

**Dump the fully-resolved effective config** — invaluable when a jail isn't behaving as expected, since it shows the merged result of `jail.conf` → `jail.local` → `jail.d/*.conf`:

```bash
sudo fail2ban-client -d
```

**Test a filter's regex against real log lines** before trusting it in production — a bad regex either misses real attacks or bans legitimate users:

```bash
fail2ban-regex /var/log/auth.log /etc/fail2ban/filter.d/sshd.conf
```

---

## 🩹 Common Gotchas

| Symptom | Cause | Fix |
|---|---|---|
| Locked out of your own SSH session | Your own IP wasn't in `ignoreip` and you triggered the threshold (common while testing) | Add your management IP(s) to `ignoreip` *before* testing; if already locked out, access via console/out-of-band and run the unban command above |
| Jail shows `enabled = true` but never bans anything | `logpath` points at a file that doesn't exist or isn't being written on this distro (e.g. Ubuntu-style path used on RHEL) | Confirm the actual log path/backend for your specific distro — see the SSH section's distro-specific note above |
| Edits to `jail.conf` disappear after a package update | `jail.conf` is the package-managed default, meant to be read-only | Always edit `jail.local` (or drop files in `jail.d/`) instead — never `jail.conf` directly |
| Filter doesn't match despite obviously-failed log lines present | Log format differs slightly from what the bundled filter regex expects (common after a service version upgrade) | Use `fail2ban-regex` against the actual log file and filter to see exactly where the match fails |
| Bans aren't persistent across service restarts | This is expected default behavior — Fail2Ban's ban list is in-memory unless configured otherwise | Acceptable for most use cases; if persistence matters, look into Fail2Ban's database (`dbfile`) settings rather than assuming this is a bug |

---

## ⚠️ Security Notes

```
═══════════════════════════════════════════════════════════════
                    ⚠️ CRITICAL WARNING ⚠️
═══════════════════════════════════════════════════════════════

► SET ignoreip BEFORE ANYTHING ELSE. This is the single most
  common way people lock themselves out of their own systems
  with this tool. Add every management IP you access the box
  from before enabling any jail.

► THIS IS A COMPLEMENT, NOT A REPLACEMENT. Fail2Ban stops
  simple brute-forcing; it does nothing against a slow, low-and-
  slow attack that stays under the threshold, or an attacker
  rotating source IPs. Pair it with the other detection layers
  in this repo, don't treat it as sufficient on its own.

► TEST FROM A SEPARATE SESSION. When validating a new jail,
  trigger the failure condition from a connection you're
  prepared to lose — never from the only session you have open
  to the box.

═══════════════════════════════════════════════════════════════
```

---

## 📚 Resources

- **Fail2Ban GitHub:** [github.com/fail2ban/fail2ban](https://github.com/fail2ban/fail2ban)
- **Bundled filter/jail reference:** `/etc/fail2ban/jail.conf` and `/etc/fail2ban/filter.d/` on any installed system — the shipped comments are thorough and version-accurate for your install

---

<div align="center">

## Related Files
- [IDS&IPS/README.md](./README.md) - Sub-section index and platform comparison
- [IDS&IPS/suricata+zeek.md](./suricata%2Bzeek.md) - Full network-level IDS/IPS for when log-based banning alone isn't enough
- [Honeypots/opencanary.md](../Honeypots/opencanary.md) - A honeypot's SSH-port-move pattern this guide's SSH jail should be updated to match
- [Homelab/HomeLab_Setup.md](https://github.com/Pnwcomputers/ULTIMATE-CYBERSECURITY-MASTER-GUIDE/blob/main/Homelab/HomeLab_Setup.md) - Broader firewall/segmentation context this tool operates within

---

**🛡️ Use These Resources Responsibly**

*Detection first, blocking second.*

**Repository**: [ULTIMATE CYBERSECURITY MASTER GUIDE](https://github.com/Pnwcomputers/ULTIMATE-CYBERSECURITY-MASTER-GUIDE)

**Maintained by**: [Pacific Northwest Computers](https://github.com/Pnwcomputers)

⭐ **Star this repo if you find it useful!** ⭐

</div>
