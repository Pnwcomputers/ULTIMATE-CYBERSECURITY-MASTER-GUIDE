# 🍯 Cowrie — High-Fidelity SSH/Telnet Honeypot

<div align="center">

**Records real attacker commands and keystrokes, not just connection attempts**

*Part of the [ULTIMATE CYBERSECURITY MASTER GUIDE](../../README.md) · [Incident Response](../README.md) · [Honeypots](./README.md) section*

![Blue Team](https://img.shields.io/badge/Operations-Blue_Team-blue?style=for-the-badge)
![Honeypot](https://img.shields.io/badge/Framework-Deception_Tech-darkred?style=for-the-badge)
![Cowrie](https://img.shields.io/badge/Platform-Cowrie-orange?style=for-the-badge)

</div>

---

## 🎯 Purpose
Guide for deploying [Cowrie](https://github.com/cowrie/cowrie), a medium-to-high interaction SSH and Telnet honeypot that emulates a full UNIX shell in Python, logs brute-force attempts, and records the complete interactive session an attacker has once they're "in" — commands typed, files downloaded via wget/curl, and files uploaded via SFTP/SCP.

## ⚙️ Function
Covers the current, simplified pip-based install path, listening on port 22 without losing real SSH access, configuration basics, and log/session analysis — plus why an older git-clone-based install can fail in ways this guide's pip path avoids entirely.

## 🏆 Goal
Get Cowrie capturing full attacker sessions reliably, understanding what makes it meaningfully different from a low-interaction honeypot like [OpenCanary](./opencanary.md) — and why that difference is worth the extra install complexity for forensic/research purposes.

## 📋 When to Use
- You want to see *what an attacker actually does* after a successful-looking login, not just that they tried
- Building a dataset of real-world SSH brute-force credentials and post-auth behavior
- An earlier attempt at Cowrie failed via `git clone` producing an incomplete repository — the pip path below sidesteps that entirely
- Forensic/research use where session replay (`bin/playlog`) matters

---

## 📋 Table of Contents

- [Cowrie vs. a Low-Interaction Honeypot](#-cowrie-vs-a-low-interaction-honeypot)
- [Deployment Workflow](#-deployment-workflow)
- [Installation (pip — recommended)](#-installation-pip--recommended)
- [Configuration](#-configuration)
- [Listening on Port 22](#-listening-on-port-22)
- [Running & Validating](#-running--validating)
- [Log & Session Analysis](#-log--session-analysis)
- [Common Gotchas](#-common-gotchas)
- [⚠️ Security Notes](#️-security-notes)
- [Resources](#-resources)

---

## 🎯 Cowrie vs. a Low-Interaction Honeypot

[OpenCanary](./opencanary.md) tells you *that* something touched a fake SSH port. Cowrie goes further — in its default **shell mode**, it emulates an entire fake Debian filesystem in Python, so once an attacker's brute-forced credentials "work," Cowrie lets them believe they're in a real shell while recording every command. In **proxy mode**, it can instead forward the session to a real backend system to observe genuine attacker behavior against something closer to production. This depth is exactly why it takes more setup than a pure connection-logger — there's a full fake environment to configure and maintain.

---

## 🚀 Deployment Workflow

```text
1. System prep:
   └─> Install build dependencies (cryptography/bcrypt need to compile).
   └─> Create a dedicated, non-root user — Cowrie refuses to start as root.

2. Install:
   └─> pip install into a venv (recommended path, Cowrie 3.0.0+).
   └─> git clone only if you need to modify Cowrie itself.

3. Initialize & configure:
   └─> `cowrie init` to create the state directory and config template.
   └─> Edit etc/cowrie.cfg for the settings you want to change.

4. Free port 22 (if you want it):
   └─> Move any real SSH server off 22 FIRST.
   └─> Pick one of: iptables redirect, authbind, or setcap.

5. Start & validate:
   └─> `cowrie start`, connect from ANOTHER machine to test.
   └─> Confirm session logs in ./var/log/cowrie/.

6. Analyze:
   └─> Replay sessions with bin/playlog.
   └─> Inspect downloaded/uploaded artifacts under var/lib/cowrie/downloads/.
```

---

## 🔧 Installation (pip — recommended)

This is the path most operators should use — it requires Cowrie 3.0.0 or later and avoids the git-clone/build-from-source path entirely.

### Step 1: System dependencies

Cowrie itself is pure Python, but several dependencies (`cryptography`, `cffi`, `bcrypt`) have native components that need to compile on install:

```bash
sudo apt-get install python3-pip python3-venv libssl-dev libffi-dev build-essential libpython3-dev python3-minimal authbind
```

### Step 2: Create a dedicated user

Cowrie **refuses to start as root** — this is deliberate:

```bash
sudo adduser --disabled-password cowrie
sudo su - cowrie
```

### Step 3: Install into a venv

```bash
mkdir ~/my-honeypot && cd ~/my-honeypot
python3 -m venv cowrie-env
source cowrie-env/bin/activate
python -m pip install --upgrade pip
python -m pip install cowrie
```

The venv lives *inside* the honeypot directory alongside `etc/` and `var/`, keeping each honeypot instance self-contained — useful if you ever want to run more than one on the same box.

### Step 4: Initialize the state directory

```bash
cowrie init
```

This writes `./etc/cowrie.cfg` from the bundled template and creates `var/log/cowrie/`, `var/lib/cowrie/downloads/`, `var/lib/cowrie/tty/`, and `var/run/`. SSH host keys are generated on first start. **This is not idempotent** — re-running `cowrie init` on an already-initialized directory refuses rather than overwriting your edits.

> **If your Cowrie release predates 3.0.0**, the pip path above isn't available — you'll need the source-checkout path instead (`git clone`, then `pip install -e '.[dev]'` inside a venv), which additionally needs `git` and `docker.io` (the latter only if rebuilding the bundled filesystem).

---

## ⚙️ Configuration

Cowrie loads config in layers — later layers override earlier ones, and your `etc/cowrie.cfg` only needs the keys you actually want to change:

1. Bundled defaults (`cowrie.cfg.dist`, shipped inside the package)
2. `/etc/cowrie/cowrie.cfg` (system-wide, if present)
3. `./etc/cowrie.cfg` (your state directory — the one you'll actually edit)
4. `./cowrie.cfg` (alternate flat layout)

Minimal example — enabling Telnet alongside the default SSH:

```ini
[telnet]
enabled = true
```

---

## 🔌 Listening on Port 22

Cowrie defaults to port 2222. To catch the bulk of automated scanning traffic, it needs to be on port 22 — which means moving any real SSH server off that port *first*. Three approaches, pick one:

### iptables (system-wide redirect, runs as root)

```bash
sudo iptables -t nat -A PREROUTING -p tcp --dport 22 -j REDIRECT --to-port 2222
# nftables equivalent:
sudo nft add rule ip nat prerouting tcp dport 22 redirect to 2222
```

> Test from **another host** — these redirect rules don't apply to loopback connections.

### authbind (run as the non-root cowrie user, bind directly to 22)

```bash
sudo apt-get install authbind
sudo touch /etc/authbind/byport/22
sudo chown cowrie:cowrie /etc/authbind/byport/22
sudo chmod 770 /etc/authbind/byport/22
```

Set in `etc/cowrie.cfg`:
```ini
[ssh]
listen_endpoints = tcp:22:interface=0.0.0.0
```

Start with:
```bash
AUTHBIND_ENABLED=yes cowrie start
```

### setcap (grant Python the bind-low-port capability)

```bash
setcap cap_net_bind_service=+ep /usr/bin/python3
```

Then set the same `listen_endpoints` change as above.

---

## ▶️ Running & Validating

```bash
cowrie start
```

Cowrie operates relative to the **current working directory** — logs, PID file, and state are all relative to wherever you ran `cowrie start` from. Stop/start commands must be issued from that same directory:

```bash
cd ~/my-honeypot
cowrie stop
```

### Test from a separate machine

```bash
ssh -p 2222 root@<honeypot-ip>
```

Check `etc/userdb.txt` if authentication unexpectedly succeeds or fails — rules are processed top-to-bottom, first match wins.

---

## 🔍 Log & Session Analysis

All activity — login attempts and full shell commands — lands in `./var/log/cowrie/cowrie.log`. Downloaded/uploaded files are preserved under `var/lib/cowrie/downloads/` for later inspection (consider running suspicious samples through the malware-handling guidance in this repo's [Incident Response](https://github.com/Pnwcomputers/ULTIMATE-CYBERSECURITY-MASTER-GUIDE/blob/main/IncidentResponse/README.md) section rather than opening them directly).

**Session replay**, one of Cowrie's standout features — recorded sessions play back with original timing:

```bash
bin/playlog var/lib/cowrie/tty/<session-id>
```

For forwarding Cowrie's output elsewhere, the project ships ready-made integration guides (ELK, Graylog, Datadog, Splunk, Prometheus, Azure Sentinel, and SQL) — see [Resources](#-resources).

---

## 🩹 Common Gotchas

| Symptom | Cause | Fix |
|---|---|---|
| `git clone` produces an incomplete repo, missing expected files | Network/clone interruption, or attempting the source-checkout path when the simpler pip path would have worked | Use the pip-install path above unless you specifically need to modify Cowrie's source |
| `ERROR: cowrie is not initialized in this directory` | Running `cowrie start` from the wrong directory, or never ran `cowrie init` | `cd` into your actual state directory, or run `cowrie init` there first |
| `twistd: unknown command: cowrie` with a Python stack trace | A dependency is missing/broken | Reinstall inside the venv; check the trace for the specific missing module |
| Same error, no stack trace | Wrong virtualenv activated (or none) | Confirm `source cowrie-env/bin/activate` was run in the current shell |
| `CryptographyDeprecationWarning: ... has been deprecated` | Harmless upstream deprecation notice from the `cryptography` package | Safe to ignore |
| Real SSH becomes unreachable after setting up iptables redirect | Real SSH wasn't moved off 22 before the redirect rule was added | Move real SSH to a different port and verify it works *before* adding any redirect rule |

---

## ⚠️ Security Notes

```
═══════════════════════════════════════════════════════════════
                    ⚠️ CRITICAL WARNING ⚠️
═══════════════════════════════════════════════════════════════

► HONEYPOTS ARE DESIGNED TO BE ACCESSED. Cowrie's own documentation
  is direct about this: this could result in compromise of the
  host if the honeypot has vulnerabilities or is misconfigured.
  Isolate it accordingly — no shared trust with production systems.

► DON'T LOCK YOURSELF OUT. Redirecting port 22 without first
  moving your real SSH server, and verifying the new port works
  from a separate session, is the single most common way to get
  locked out of a headless box during this exact setup.

► DOWNLOADED SAMPLES ARE REAL MALWARE. Files captured under
  var/lib/cowrie/downloads/ are attacker-supplied payloads.
  Handle them per this repo's malware-handling guidance — never
  execute them on a host-connected network.

► PROXY MODE FORWARDS TO A REAL BACKEND. If using proxy mode to
  observe attacker behavior against a genuine system, that
  backend needs its own isolation — proxy mode is not a
  detection-only feature.

═══════════════════════════════════════════════════════════════
```

---

## 📚 Resources

- **Cowrie GitHub:** [github.com/cowrie/cowrie](https://github.com/cowrie/cowrie)
- **Cowrie docs:** [docs.cowrie.org](https://docs.cowrie.org)
- **Output integration guides** (ELK, Graylog, Datadog, Splunk, Prometheus, Sentinel, SQL): linked from the docs site above
- **Cowrie Slack community:** linked from the GitHub README

---

<div align="center">

## Related Files
- [Honeypots/README.md](./README.md) - Sub-section index and platform comparison
- [Honeypots/opencanary.md](./opencanary.md) - The lower-interaction honeypot this guide is a step up from
- [Honeypots/tpot.md](./tpot.md) - T-Pot bundles Cowrie as one of its 20+ honeypots, if you want it alongside many others
- [IncidentResponse/SIEM/README.md](https://github.com/Pnwcomputers/ULTIMATE-CYBERSECURITY-MASTER-GUIDE/blob/main/IncidentResponse/SIEM/README.md) - Forward Cowrie's session logs into a SIEM using the project's own output plugins

---

**🛡️ Use These Resources Responsibly**

*Every hit is real — there's no legitimate reason to touch a honeypot.*

**Repository**: [ULTIMATE CYBERSECURITY MASTER GUIDE](https://github.com/Pnwcomputers/ULTIMATE-CYBERSECURITY-MASTER-GUIDE)

**Maintained by**: [Pacific Northwest Computers](https://github.com/Pnwcomputers)

⭐ **Star this repo if you find it useful!** ⭐

</div>
