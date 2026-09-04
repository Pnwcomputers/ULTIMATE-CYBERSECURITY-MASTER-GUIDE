# 🍯 HoneyPi — Simple Internal-Network Honeypot (PSAD-based)

<div align="center">

**A Raspberry Pi that just watches for port scans, FTP, Telnet, and VNC probes on YOUR internal network**

*Part of the [ULTIMATE CYBERSECURITY MASTER GUIDE](../../README.md) · [Incident Response](../README.md) · [Honeypots](./README.md) section*

![Blue Team](https://img.shields.io/badge/Operations-Blue_Team-blue?style=for-the-badge)
![Honeypot](https://img.shields.io/badge/Framework-Deception_Tech-darkred?style=for-the-badge)
![HoneyPi](https://img.shields.io/badge/Platform-HoneyPi-orange?style=for-the-badge)

</div>

---

## ⚠️ Read This First: There Are Multiple Unrelated "HoneyPi" Projects

Before anything else — **the name "HoneyPi" is genuinely ambiguous on GitHub**, and this collision has caused real, confusing failures during at least one actual deployment attempt. There are at least three unrelated projects sharing this name:

| Project | What it actually is | Is it a security honeypot? |
|---|---|---|
| **[mattymcfatty/HoneyPi](https://github.com/mattymcfatty/HoneyPi)** (TrustFoundry, 2017) | PSAD + a small Python script emulating vulnerable services, for **internal-network intrusion detection** | ✅ Yes — this is the one this guide covers |
| **[Honey-Pi/HoneyPi](https://github.com/Honey-Pi/HoneyPi)** | An **IoT beehive-scale monitoring platform** — GPIO sensors reporting to ThingSpeak | ❌ No — nothing to do with security at all |
| **[binkybear/HoneyPi](https://github.com/binkybear/HoneyPi)** | A thin bash wrapper script intended to install *other* honeypot projects (Cowrie, etc.) | 🟡 Sort of — it's an installer, not a honeypot itself |

**Why this matters:** if you search "HoneyPi raspberry pi" and grab an installer, verify which of these you actually got *before* you spend time debugging it. A real deployment attempt ran an installer that completed with no errors, but never created a running service or log file — which is exactly the expected behavior if the **Honey-Pi/HoneyPi** beehive-monitoring installer was run by mistake, since it was never designed to produce a security-relevant service in the first place. Check `cat` on the install script or `README.md` before running it if there's ever ambiguity — the beehive project's README talks about GPIO sensors and ThingSpeak; the actual security HoneyPi's talks about PSAD and iptables.

---

## 🎯 Purpose
Guide for deploying the original [mattymcfatty/HoneyPi](https://github.com/mattymcfatty/HoneyPi) (TrustFoundry, 2017) — a simple honeypot combining [PSAD](https://github.com/mrash/psad) (Port Scan Attack Detection) with a small Python script that opens enticing-looking ports, purpose-built for **internal**-network intrusion detection rather than internet-facing threat intelligence collection.

## ⚙️ Function
Covers what makes this honeypot's philosophy different (internal placement, port-scan detection as a first-class signal), the interactive whiptail-based installer, the real script issues you're likely to hit on a modern OS, and email alerting via msmtp.

## 🏆 Goal
Get a working internal-network tripwire running, while being upfront that this is a **2017, largely unmaintained** project — set expectations accordingly, and know when to fall back to [OpenCanary](./opencanary.md) instead.

## 📋 When to Use
- You specifically want **port-scan detection** as a signal — most other low-interaction honeypots in this repo don't treat scanning itself as a first-class event the way PSAD does
- You want something for the **internal** network (catching lateral movement / an already-present attacker), not an internet-facing decoy
- You're prepared to troubleshoot an unmaintained, several-years-old codebase, or willing to fall back to OpenCanary if it doesn't cooperate

---

## 📋 Table of Contents

- [Why This Honeypot Exists](#-why-this-honeypot-exists)
- [Deployment Workflow](#-deployment-workflow)
- [Installation](#-installation)
- [The Interactive Installer](#-the-interactive-installer)
- [Common Gotchas](#-common-gotchas)
- [If It Doesn't Cooperate](#-if-it-doesnt-cooperate)
- [⚠️ Security Notes](#️-security-notes)
- [Resources](#-resources)

---

## 🎯 Why This Honeypot Exists

Per the original author's own reasoning (TrustFoundry, 2017): most honeypots are built for the *external* perimeter — collecting threat intelligence from internet-wide scanning. HoneyPi was built for the opposite problem: catching an attacker who is **already on the internal network**, which is exactly what a penetration tester does during lateral movement. It flags four specific TTPs (Tactics, Techniques, and Procedures):

1. Port scanning activity
2. FTP connection attempts
3. Telnet connection attempts
4. VNC connection attempts

**PSAD does most of the actual work** — it's a mature, standalone port-scan-detection tool that HoneyPi wraps with an installer and a small Python decoy script. If you outgrow HoneyPi's simplicity, PSAD itself remains a legitimate standalone tool worth knowing.

---

## 🚀 Deployment Workflow

```text
1. Confirm you have the right project:
   └─> mattymcfatty/HoneyPi specifically — see the warning above.

2. Prepare the Pi:
   └─> A dedicated Raspberry Pi running Raspbian/Raspberry Pi OS.
   └─> Understand the installer WILL modify iptables — don't run
       this on a Pi doing other network-facing work.

3. Download & run the installer:
   └─> wget the archive, unzip, run honeyPiInstaller.sh.
   └─> Follow the interactive whiptail prompts.

4. Choose notification method:
   └─> Email (via msmtp), a custom script, or blinking a GPIO LED.

5. Validate:
   └─> Trigger a port scan or FTP/Telnet/VNC connection attempt
       from ANOTHER machine.
   └─> Confirm PSAD logs it and (if configured) the alert fires.

6. If the bundled Python script fails on a modern OS:
   └─> Expect syntax/encoding issues (see Gotchas) — this project
       is unmaintained since 2017 and predates current Python 3.
```

---

## 🔧 Installation

```bash
wget https://github.com/mattymcfatty/HoneyPi/archive/master.zip
unzip master.zip
cd HoneyPi-master
chmod +x *.sh
sudo ./honeyPiInstaller.sh
```

**Before running this:** understand that it will change your `iptables` configuration and install several packages system-wide. Don't run it on a Pi you're using for anything else.

---

## 🖥️ The Interactive Installer

`honeyPiInstaller.sh` uses `whiptail` dialogs to walk you through setup:

1. **Name your honeypot** — something that sounds like a legitimate, enticing target (alphanumeric, under 24 characters, no spaces)
2. **Package installation** — `psad`, `msmtp`, `msmtp-mta`, `python-twisted`, `iptables-persistent`, `libnotify-bin`, `fwsnort`, `raspberrypi-kernel-headers`
3. **Choose a notification method:**
   - **Email** — configured via `msmtp`; the installer has Gmail defaults pre-filled if you use Gmail
   - **Script** — execute a custom script of your choosing on trigger
   - **Blink** — flash a light on the Pi's GPIO (the same GPIO-driven-response idea used in the original blog post's toy-siren demo)

**Gmail app password gotcha (applies here too):** if you choose email notification and use Gmail, the app password must be entered without spaces even though Google's UI displays it with spaces for readability — the same trap documented in the [OpenCanary guide](./opencanary.md#-email-alerting).

---

## 🩹 Common Gotchas

| Symptom | Cause | Fix |
|---|---|---|
| Installer runs cleanly, nothing is actually created | You likely ran the **wrong "HoneyPi"** — the unrelated IoT beehive-monitoring project | Verify you're using `mattymcfatty/HoneyPi` specifically (see the warning at the top) |
| The bundled Python decoy script (`mattshoneypot.py`) throws syntax errors or encoding issues | The project is unmaintained since 2017 and was written for an older Python — modern Raspberry Pi OS ships Python 3 versions the script wasn't tested against | Inspect the script's shebang/encoding declaration first; patching a few years-old syntax issues is sometimes faster than debugging further, but if it snowballs, treat this as a sign to fall back to a maintained project |
| PSAD is "tricky to set up" (the original author's own words) | PSAD itself is a mature, capable, but non-trivial tool with its own configuration depth | Read PSAD's own documentation directly if HoneyPi's wrapper doesn't get you where you need — treating PSAD as the real tool and HoneyPi as a thin convenience layer around it sets expectations correctly |
| `iptables` rules from the installer conflict with existing firewall config | The installer assumes a relatively clean Pi | Run this only on a dedicated, otherwise-unused Pi, exactly as the installer's own warning states |

---

## 🔀 If It Doesn't Cooperate

This is a genuinely old, unmaintained project. If you hit repeated script failures that don't resolve quickly:

- **[OpenCanary](./opencanary.md)** is the actively-maintained, lower-friction alternative for straightforward connection-attempt logging — it doesn't have PSAD's specific port-scan-detection depth, but it installs far more predictably on a current OS.
- **PSAD standalone** (skip HoneyPi's wrapper entirely) if what you actually want is the port-scan detection specifically, without the decoy-script portion.
- **[Cowrie](./cowrie.md)** if what you actually want is deep SSH/Telnet session capture rather than simple connection logging.

There's no shame in swapping tools mid-troubleshooting — the real build history behind this repo's [OpenCanary guide](./opencanary.md) did exactly that after both HoneyPi and Cowrie hit dead ends in the same session.

---

## ⚠️ Security Notes

```
═══════════════════════════════════════════════════════════════
                    ⚠️ CRITICAL WARNING ⚠️
═══════════════════════════════════════════════════════════════

► VERIFY THE PROJECT BEFORE RUNNING ITS INSTALLER. "HoneyPi"
  collides with at least one completely unrelated project. Read
  the installer script or README before running anything with
  root access and iptables-modifying behavior.

► THIS WILL MODIFY YOUR IPTABLES CONFIGURATION. Per the original
  author's own warning: don't run this on a Pi doing other
  network-facing work.

► UNMAINTAINED SINCE 2017. Treat this as a project you may need
  to patch yourself, not one with active upstream support. Budget
  troubleshooting time accordingly, or use a maintained
  alternative if that time isn't available.

► ISOLATE IT LIKE ANY OTHER HONEYPOT. Internal placement doesn't
  reduce the isolation requirement — if anything it increases it,
  since it sits closer to systems that matter.

═══════════════════════════════════════════════════════════════
```

---

## 📚 Resources

- **HoneyPi (the real one) GitHub:** [github.com/mattymcfatty/HoneyPi](https://github.com/mattymcfatty/HoneyPi)
- **Original announcement/writeup (TrustFoundry, 2017):** [trustfoundry.net — HoneyPi: An easy honeypot for a Raspberry Pi](https://trustfoundry.net/2017/08/22/honeypi-easy-honeypot-raspberry-pi/)
- **PSAD (the tool doing most of the work):** [github.com/mrash/psad](https://github.com/mrash/psad)

---

<div align="center">

## Related Files
- [Honeypots/README.md](./README.md) - Sub-section index and platform comparison
- [Honeypots/opencanary.md](./opencanary.md) - The actively-maintained fallback if this project doesn't cooperate on a modern OS
- [Honeypots/cowrie.md](./cowrie.md) - For deep SSH/Telnet session capture instead of simple connection logging
- [IncidentResponse/network_intrusion.md](https://github.com/Pnwcomputers/ULTIMATE-CYBERSECURITY-MASTER-GUIDE/blob/main/IncidentResponse/network_intrusion.md) - Investigation procedure once this honeypot's internal placement catches something

---

**🛡️ Use These Resources Responsibly**

*Every hit is real — there's no legitimate reason to touch a honeypot.*

**Repository**: [ULTIMATE CYBERSECURITY MASTER GUIDE](https://github.com/Pnwcomputers/ULTIMATE-CYBERSECURITY-MASTER-GUIDE)

**Maintained by**: [Pacific Northwest Computers](https://github.com/Pnwcomputers)

⭐ **Star this repo if you find it useful!** ⭐

</div>
