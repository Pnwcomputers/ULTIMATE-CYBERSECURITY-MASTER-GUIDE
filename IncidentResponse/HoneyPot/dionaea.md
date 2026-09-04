# 🍯 Dionaea — Malware-Capturing Honeypot

<div align="center">

**Catches the actual payload, not just the login attempt**

*Part of the [ULTIMATE CYBERSECURITY MASTER GUIDE](../../README.md) · [Incident Response](../README.md) · [Honeypots](./README.md) section*

![Blue Team](https://img.shields.io/badge/Operations-Blue_Team-blue?style=for-the-badge)
![Honeypot](https://img.shields.io/badge/Framework-Deception_Tech-darkred?style=for-the-badge)
![Dionaea](https://img.shields.io/badge/Platform-Dionaea-orange?style=for-the-badge)

</div>

---

## 🎯 Purpose
Guide for deploying [Dionaea](https://github.com/DinoTools/dionaea), a low-interaction honeypot purpose-built to capture the actual malware **payloads** dropped by automated exploit attempts against network services (SMB, FTP, MySQL, TFTP, MQTT, and more) — not just a record that someone connected.

## ⚙️ Function
Covers the officially-recommended Docker deployment path, the from-source build alternative and its considerably longer dependency list, port planning, and where captured samples land for later analysis.

## 🏆 Goal
Get Dionaea capturing real exploit payloads reliably, with the Docker path so the honeypot's own dependency complexity doesn't become the thing you're troubleshooting.

## 📋 When to Use
- You want actual malware **samples**, not just connection metadata — a natural complement to [OpenCanary](./opencanary.md) or [Cowrie](./cowrie.md)
- Studying what's actively being dropped against exposed SMB/database/file-transfer services on the internet
- Building a small malware collection pipeline for research (with all the handling caution that implies)

---

## 📋 Table of Contents

- [Dionaea vs. Connection-Logging Honeypots](#-dionaea-vs-connection-logging-honeypots)
- [Deployment Workflow](#-deployment-workflow)
- [Installation — Docker (recommended)](#-installation--docker-recommended)
- [Installation — From Source (alternative)](#-installation--from-source-alternative)
- [Ports & Services](#-ports--services)
- [Where Captured Samples Land](#-where-captured-samples-land)
- [Common Gotchas](#-common-gotchas)
- [⚠️ Security Notes](#️-security-notes)
- [Resources](#-resources)

---

## 🎯 Dionaea vs. Connection-Logging Honeypots

OpenCanary tells you someone tried FTP/SMB/MySQL credentials against a fake service. Dionaea goes a step further for the services it emulates: it's specifically designed to let an automated exploit attempt **complete** far enough that the attacker's tooling delivers its actual payload — a malware binary, a worm, a dropper — which Dionaea then captures to disk for analysis. This makes it the honeypot of choice when the question is "what's actually being distributed," not just "who's scanning."

---

## 🚀 Deployment Workflow

```text
1. Choose install path:
   └─> Docker (recommended — official image, no dependency chain to fight).
   └─> From source (only if you need to modify Dionaea itself).

2. Plan ports:
   └─> Dionaea binds a wide spread of common service ports (FTP, SMB,
       MySQL, MQTT, TFTP, and more). Confirm nothing else on the host
       needs them.

3. Deploy:
   └─> docker run with the full port mapping, or docker-compose.

4. Validate:
   └─> Confirm the container is listening on the expected ports.
   └─> Generate a benign test connection from ANOTHER machine.

5. Monitor:
   └─> Captured binaries and logs land under the container's /opt/dionaea
       data path — mount it to a host volume so nothing is lost on
       container restart.

6. Handle samples with care:
   └─> Treat everything captured as live malware (see Security Notes).
```

---

## 🐳 Installation — Docker (recommended)

Dionaea's own documentation points to the official Docker image for most users rather than the from-source build — it sidesteps a lengthy native-dependency list entirely.

```bash
docker run --rm -it \
  -p 21:21 -p 42:42 -p 69:69/udp -p 80:80 -p 135:135 \
  -p 443:443 -p 445:445 -p 1433:1433 -p 1723:1723 \
  -p 1883:1883 -p 1900:1900/udp -p 3306:3306 \
  -p 5060:5060 -p 5060:5060/udp -p 5061:5061 -p 11211:11211 \
  dinotools/dionaea
```

Or persist config and data with `docker-compose`:

```yaml
version: '3.8'
services:
  dionaea:
    image: dinotools/dionaea
    restart: always
    ports:
      - "21:21"
      - "42:42"
      - "69:69/udp"
      - "80:80"
      - "135:135"
      - "443:443"
      - "445:445"
      - "1433:1433"
      - "1723:1723"
      - "1883:1883"
      - "1900:1900/udp"
      - "3306:3306"
      - "5060:5060"
      - "5060:5060/udp"
      - "5061:5061"
      - "11211:11211"
    volumes:
      - ./etc:/opt/dionaea/etc/dionaea
      - ./data:/opt/dionaea/var
```

To customize which services run, drop service/handler YAML files into the mounted config path rather than editing inside the container:

```
conf/your-service.yaml    -> /opt/dionaea/etc/dionaea/services-enabled/
conf/your-ihandler.yaml   -> /opt/dionaea/etc/dionaea/ihandlers-enabled/
```

Available image tags: `latest` (most recent stable), `x.y.z` (pinned version), `edge` (built on every push to default branch), `nightly` (built every night).

---

## 🛠️ Installation — From Source (alternative)

Only worth doing if you need to modify Dionaea itself, or Docker genuinely isn't an option on your platform. The dependency list is long — expect this to take real troubleshooting time compared to the Docker path:

```bash
git clone https://github.com/DinoTools/dionaea.git
cd dionaea

sudo apt-get install \
  build-essential cmake check cython3 \
  libcurl4-openssl-dev libemu-dev libev-dev libglib2.0-dev \
  libloudmouth1-dev libnetfilter-queue-dev libnl-3-dev \
  libpcap-dev libssl-dev libtool libudns-dev \
  python3 python3-dev python3-bson python3-yaml python3-boto3 \
  fonts-liberation

mkdir build && cd build
cmake -DCMAKE_INSTALL_PREFIX:PATH=/opt/dionaea ..
make
sudo make install
```

The installed honeypot lands in `/opt/dionaea`. There is no current official Debian/Ubuntu package — third-party packages exist but the project explicitly cannot vouch for their freshness or vet them; verify you're getting a current version if you go that route.

---

## 🔌 Ports & Services

Dionaea's default footprint spans a wide range of commonly-attacked services:

| Service | Port(s) |
|---|---|
| FTP | 21 |
| SMB | 42, 135, 445 |
| TFTP | 69/udp |
| HTTP/HTTPS | 80, 443 |
| MSSQL | 1433 |
| PPTP | 1723 |
| MQTT | 1883 |
| SSDP | 1900/udp |
| MySQL | 3306 |
| SIP | 5060 (tcp+udp), 5061 |
| Memcached | 11211 |

Confirm none of these conflict with anything else the host needs before deploying — a wide port footprint is the point, but only if nothing legitimate is competing for the same ports.

---

## 📦 Where Captured Samples Land

Logs and captured binaries are written under Dionaea's data path (`/opt/dionaea/var` in the source-build layout, or the volume you mounted in the Docker path). This is exactly the kind of artifact this repo's [Digital Forensics](https://github.com/Pnwcomputers/ULTIMATE-CYBERSECURITY-MASTER-GUIDE/blob/main/IncidentResponse/Digital-Forensics/README.md) guidance applies to — hash everything, and never execute a captured sample outside a strictly isolated, host-only analysis environment.

---

## 🩹 Common Gotchas

| Symptom | Cause | Fix |
|---|---|---|
| Long, fragile build process, missing headers | The from-source path pulls in a dozen-plus native dependencies (`libemu`, `libnl`, `libudns`, etc.) that vary in package-name and availability across distros/versions | Use the official Docker image instead — this is exactly what it exists to avoid |
| No connections logged at all | A port conflict silently prevented Dionaea from binding a service, or a firewall is blocking inbound | Check the container/process actually bound each expected port; check host firewall rules |
| Old, possibly-stale third-party package installed instead of the current version | No official Debian/Ubuntu package exists; some available packages are old or unmaintained | Verify version and last-update date before trusting a third-party package; prefer Docker or from-source |
| Captured "samples" turn out to be junk/incomplete | Not every completed connection results in a real payload — some scanners probe without actually delivering anything | Normal; check the `logsql`/log output for what was actually captured versus merely connected |

---

## ⚠️ Security Notes

```
═══════════════════════════════════════════════════════════════
                    ⚠️ CRITICAL WARNING ⚠️
═══════════════════════════════════════════════════════════════

► THIS HONEYPOT CATCHES REAL MALWARE BY DESIGN. Every captured
  binary is genuine, live malware. Never execute, open, or
  extract a captured sample outside a strictly isolated,
  host-only, network-disconnected analysis environment.

► DO NOT UPLOAD SAMPLES TO PUBLIC SANDBOXES CARELESSLY. If a
  sample appears targeted rather than generic/commodity,
  uploading it to a public service like VirusTotal can alert
  the operators that they've been detected — the same caution
  that applies to malware handling generally in this repo's
  Incident Response section applies here.

► WIDE PORT FOOTPRINT = WIDE ATTACK SURFACE ON THE HOST RUNNING
  IT. Isolate the honeypot from anything you'd mind losing.

► KEEP IT PATCHED. A low-interaction honeypot emulating services
  is lower-risk than running real vulnerable versions of those
  services, but Dionaea itself is still software that can have
  its own vulnerabilities — treat it accordingly.

═══════════════════════════════════════════════════════════════
```

---

## 📚 Resources

- **Dionaea GitHub:** [github.com/DinoTools/dionaea](https://github.com/DinoTools/dionaea)
- **Dionaea docs:** [dionaea.readthedocs.io](https://dionaea.readthedocs.io)
- **Official Docker image:** [hub.docker.com/r/dinotools/dionaea](https://hub.docker.com/r/dinotools/dionaea)

---

<div align="center">

## Related Files
- [Honeypots/README.md](./README.md) - Sub-section index and platform comparison
- [Honeypots/opencanary.md](./opencanary.md) - The connection-logging honeypot Dionaea complements with payload capture
- [Honeypots/tpot.md](./tpot.md) - T-Pot bundles Dionaea as one of its 20+ honeypots, if you want it alongside many others
- [IncidentResponse/Digital-Forensics/README.md](https://github.com/Pnwcomputers/ULTIMATE-CYBERSECURITY-MASTER-GUIDE/blob/main/IncidentResponse/Digital-Forensics/README.md) - Handling and analyzing samples captured here
- [IncidentResponse/SIEM/README.md](https://github.com/Pnwcomputers/ULTIMATE-CYBERSECURITY-MASTER-GUIDE/blob/main/IncidentResponse/SIEM/README.md) - Forwarding capture events into a SIEM

---

**🛡️ Use These Resources Responsibly**

*Every hit is real — there's no legitimate reason to touch a honeypot.*

**Repository**: [ULTIMATE CYBERSECURITY MASTER GUIDE](https://github.com/Pnwcomputers/ULTIMATE-CYBERSECURITY-MASTER-GUIDE)

**Maintained by**: [Pacific Northwest Computers](https://github.com/Pnwcomputers)

⭐ **Star this repo if you find it useful!** ⭐

</div>
