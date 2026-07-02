# Bjorn: An Autonomous Network-Service Attacker on the Raspberry Pi

> **Reader prerequisites.** [Bjorn](https://github.com/infinition/Bjorn) is a fundamentally different category of tool from others that we have covered. Where Evil-M5 and Bruce operate at the wireless protocol layer (Wi-Fi frames, Bluetooth advertisements, sub-GHz RF, NFC, IR), Bjorn operates at the **network service layer**; SSH, SMB, FTP, RDP, Telnet, and SQL; and performs actual authentication attacks and data exfiltration against discovered hosts. Working knowledge of basic Linux administration, network scanning fundamentals (nmap, port scanning, service enumeration), and the host-side service stack on enterprise networks is assumed. Critically, the **legal exposure** for running Bjorn is meaningfully larger than for the previous two tools; the Computer Fraud and Abuse Act and the Stored Communications Act both apply directly to its core operations.

---

## 1. What Bjorn is, and how it differs

[Bjorn](https://github.com/infinition/Bjorn) is an open-source autonomous network attacker created by the developer "infinition," distributed under the **MIT license** at `github.com/infinition/Bjorn`. It runs as a Python daemon on a Raspberry Pi with an attached **2.13-inch Waveshare e-Paper HAT** that gives the device a "Tamagotchi-like" character: a small cartoon Viking named Bjorn whose live commentary, mood, and growth statistics scroll across the e-Paper screen as Bjorn methodically scans, attacks, and exfiltrates from whatever network it's plugged into.

The Pi runs continuously, and Bjorn's heuristic orchestrator works through a sequenced attack pipeline:

1. **Discover** alive hosts on the local network.
2. **Enumerate** open ports and identify services.
3. **Vulnerability-scan** discovered services with nmap NSE.
4. **Brute-force** authentication on SSH, SMB, FTP, RDP, Telnet, and SQL services.
5. **Exfiltrate** files and data from any service it successfully authenticates to.
6. **Catalog** compromised hosts as "zombies" and revisit them for further extraction.
7. **Persist** all discoveries in a local Network Knowledge Base (netkb) for cross-session continuity.

The first stable release, **Bjorn v1.0.0**, shipped on December 2, 2025. As of this writing it sits at roughly 5.9k GitHub stars and an active community on Discord (`discord.com/invite/B3ZH9taVfT`) and Reddit (`r/Bjorn_CyberViking`). The codebase is ~77% Python with the remainder split between web UI assets and shell scripts.

The fundamental contrast with the previous two chapters:

| Dimension | Evil-M5Project | Bruce | Bjorn |
|---|---|---|---|
| Platform | ESP32 (Cardputer) | ESP32 (Cardputer, Lilygo, M5, etc.) | Raspberry Pi (Zero W, Zero 2 W, 3, 4) |
| Form factor | Handheld | Handheld | "Drop-and-leave" embedded |
| Operator interaction | Constant (menu-driven) | Constant (menu-driven) | Minimal (autonomous after launch) |
| Attack surface | Wi-Fi L2 | Wi-Fi + BLE + Sub-GHz + NFC + IR + FM | Network services (L4-L7) |
| Primary technique | Captive portals, deauth, KARMA | Multi-radio: portal, deauth, RF replay, NFC clone | Brute-force + data exfiltration |
| Legal exposure | § 333 + CFAA (limited) | § 333 + § 301/302a + CFAA | **CFAA core + SCA + Wiretap Act** |
| Time on engagement | Minutes-to-hours, supervised | Minutes-to-hours, supervised | **Hours-to-days, unsupervised** |

This shift in posture matters enormously, both operationally and legally. The remaining sections of this chapter unpack why.

---

## 2. Legal and regulatory framework; read this twice

The Evil-M5 and Bruce chapters discussed the FCC's 47 USC § 333 (willful interference) and Part 15 considerations because those tools transmit on regulated radio bands. Bjorn does none of that; it transmits only standard 2.4 GHz Wi-Fi frames at consumer power levels, well within Part 15 compliance. The legal problem is elsewhere, and it is much larger.

### 2.1 The CFAA, in detail

The **Computer Fraud and Abuse Act**, 18 U.S.C. § 1030, is the federal statute that governs unauthorized computer access in the United States. Each of the following subsections directly implicates Bjorn's normal operation:

- **§ 1030(a)(2)(C); Unauthorized access to obtain information.** "Whoever ... intentionally accesses a computer without authorization or exceeds authorized access, and thereby obtains ... information from any protected computer ..." Bjorn's brute-force connectors literally do this: they authenticate to a service the operator has not been authorized to access, and they obtain information from it. First offense: misdemeanor up to one year; felony (up to five years) if the value of the information exceeds $5,000 or the conduct is for commercial advantage.
- **§ 1030(a)(4); Access with intent to defraud.** "Knowingly and with intent to defraud, accesses a protected computer without authorization ... and by means of such conduct furthers the intended fraud and obtains anything of value ..." If Bjorn's exfiltrated data is used for any commercial advantage, this applies. Felony, up to five years.
- **§ 1030(a)(5)(A); Knowing damage.** "Knowingly causes the transmission of a program, information, code, or command, and as a result of such conduct, intentionally causes damage without authorization, to a protected computer." Brute-force authentication attempts that lock accounts, cause service disruptions, or trigger automated response cascades meet the "damage" definition (§ 1030(e)(8): "any impairment to the integrity or availability of data, a program, a system, or information"). Felony, up to ten years.
- **§ 1030(a)(5)(B)/(C); Reckless or negligent damage.** Even if intent is harder to prove, reckless damage from autonomous attack tooling has been successfully prosecuted. Up to five years for reckless; up to one year for the negligent variant.

The "protected computer" definition in § 1030(e)(2) is breathtakingly broad; it includes any computer "used in or affecting interstate or foreign commerce or communication." That is, in practice, every networked computer in the United States.

### 2.2 Stored Communications Act

The **Stored Communications Act**, 18 U.S.C. § 2701, applies to electronic communications held by service providers. Bjorn's file exfiltration via SSH/SMB/FTP; particularly if it grabs email stores, message archives, or cloud-sync caches; implicates § 2701(a)(1): "intentionally accesses without authorization a facility through which an electronic communication service is provided." Penalties run up to ten years for offenses committed for commercial advantage or malicious destruction.

### 2.3 Wiretap Act

The **Wiretap Act**, 18 U.S.C. § 2511, applies when Bjorn's network scanning captures live communications in transit. If you point Bjorn at a switched LAN and its scanner intercepts authentication exchanges or session data en route between hosts, that's potentially a § 2511 violation. Penalties: up to five years per offense.

### 2.4 State analogues

- **Washington:** RCW 9A.90.040 (computer trespass first degree), RCW 9A.90.050 (computer trespass second degree), RCW 9A.90.060 (electronic data service interference). The Washington Cybercrime Act provides state-level remedies that parallel CFAA but can be charged independently.
- **Oregon:** ORS 164.377 (computer crime), with felony bumps for damage and commercial-advantage motivations.
- **California, New York, Texas, Florida:** all maintain analogous statutes. State-level enforcement is often more aggressive than federal because state prosecutors don't need the federal jurisdictional hook.

### 2.5 The bottom line, plainly stated

**Bjorn's brute-force connectors, file stealers, and SQL exfiltration modules are illegal to operate against any system you do not own or have explicit written authorization to test.** This is not a "use with caution" caveat; it is a statement that the core operations of the tool, in any non-authorized context, are felonies. The "educational and authorized testing purposes only" disclaimer in the README is not a legal shield, it is a request from the developer that you comply with the law.

The corollary, and the only safe operational posture:

1. **Air-gapped or fully-isolated lab use only**, against intentionally vulnerable VMs you have provisioned for the purpose. Metasploitable2, Metasploitable3, DVWA, and the vulnerable apps catalogued in the OWASP Vulnerable Web Applications Directory (successor to the retired OWASP Broken Web Apps project); these exist precisely so practitioners can learn attack tooling without breaking the law.
2. **Documented and signed ROE that specifically enumerates authorized brute-force activity**; many ROEs that authorize "vulnerability scanning" do not authorize "credential brute force" or "data exfiltration." Bjorn does the latter two automatically. If the ROE doesn't say so explicitly, do not run Bjorn under it.
3. **No "drive-by" deployment.** Once Bjorn is on a network, the operator has, by design, given up moment-to-moment control of what it attacks. The deployment location, the network it attaches to, and the time-bounded scope of its operation must all be enumerated in the ROE.

A compliance checklist tailored to Bjorn's posture appears in Appendix C.

### 2.6 A note on the autonomous nature

Bjorn's defining feature is autonomy. Unlike Evil-M5 (where you press a button to send a deauth and stop pressing it to stop) or Bruce (where you select a payload and trigger it explicitly), Bjorn's orchestrator runs through its attack pipeline on its own, against every host it finds, until you intervene.

The operational implication is this: **you can't claim "I only meant to scan one host" if Bjorn scanned a hundred and brute-forced every SSH port.** The tool's design makes that defense unavailable. The legal implication is that intent (a CFAA element) is established at the moment of deployment, not at the moment of any particular packet. If you turn Bjorn on inside a network you're not authorized to attack, you have already committed the offense; Bjorn's continued operation is the foreseeable consequence of your deployment decision.

This is why the lab-only posture is not a stylistic recommendation. It is the only defensible operational posture for this class of tool.

---

## 3. The hardware

### 3.1 Compatible Raspberry Pi models

Bjorn is officially developed and tested on the **Raspberry Pi Zero W** running 32-bit Raspberry Pi OS Lite. Community feedback confirms the **Raspberry Pi Zero 2 W** works correctly with 64-bit Raspberry Pi OS Lite, despite not being a target platform of the original developer. The Pi 3 and Pi 4 work but defeat the small-form-factor "drop-and-leave" premise that makes Bjorn interesting in the first place.

| Pi model | RAM | Bjorn-validated | Practical use case |
|---|---|---|---|
| Pi Zero W (BCM2835, single-core 1 GHz) | 512 MB | ✓ (32-bit OS) | Smallest, cheapest, slowest. Tight power budget. |
| Pi Zero 2 W (BCM2710A1, quad-core 1 GHz) | 512 MB | ✓ (64-bit OS, community-verified) | **Recommended.** Same footprint as Zero W, ~5× CPU. |
| Pi 3 / 3B+ | 1 GB | ✓ (works fine) | Larger; useful for bench testing |
| Pi 4 | 2-8 GB | ✓ (works fine) | Overkill for Bjorn alone; useful for combined-tool builds |

For a portable build that fits in a pocket, attaches to a USB battery, and runs for many hours on a single charge: the Pi Zero 2 W is the right choice in nearly every case.

### 3.2 The display: Waveshare 2.13" e-Paper HAT

The character display is the visible identity of Bjorn. The Waveshare 2.13-inch e-Paper HAT is a black-and-white (or 3-color, with the v3) GPIO-attached display that draws essentially zero power between refreshes; ideal for a battery-powered drop device that updates its readout every minute or two.

Bjorn's developer explicitly tested **v2 and v4** of the HAT and confirms they work. **v1 and v3** are documented as "should work but unverified"; the SPI command set is similar enough that they likely render correctly, but you may encounter the partial-refresh quirks that distinguish each Waveshare revision.

The HAT mounts to the Pi's 40-pin GPIO header. No soldering required; it plugs in. Communication is over SPI with a few additional GPIO control lines for busy/reset/data-command.

### 3.3 Optional and recommended accessories

- **microSD card, Class 10, 16 GB minimum.** Bjorn writes a lot during a run (scan results, captured files, SQL dumps), and slow cards bottleneck the orchestrator. Industrial-grade (Sandisk High Endurance, Samsung PRO Endurance) is worth the small premium if you're deploying continuously; Bjorn's logging is write-heavy and consumer-grade cards will fail in months.
- **PiSugar 2 or PiSugar 3.** Battery HAT for the Pi Zero/Zero 2 form factor with integrated charging and runtime estimation. Turns Bjorn into a true drop-and-walk-away device with 6-12 hours of runtime depending on activity.
- **Compact 3D-printed enclosure.** Community designs are abundant; printable from your Bambu X1C in a few hours. Make sure the e-Paper viewport is cut for the HAT's exposed display area.
- **microSD reader on the operator workstation.** You'll be writing the SD image, troubleshooting boot issues, and occasionally pulling logs off-device. A spare SD card pre-flashed with a known-good Bjorn build is useful for fast recovery.

### 3.4 A note on Wi-Fi adapters

Bjorn does not require an external Wi-Fi adapter; the Pi Zero W and Zero 2 W both ship with on-board 2.4 GHz 802.11n. This is sufficient for joining a target network and operating Bjorn over that interface. The on-board chipset does not, however, reliably support **monitor mode**, which means Bjorn cannot do Wi-Fi-layer attacks the way Evil-M5 or Bruce can. If you want monitor-mode capability alongside Bjorn's network-service attacks, you would add a USB Wi-Fi adapter with a chipset like the Realtek RTL8812AU or Atheros AR9271; but that's outside Bjorn's stock feature set and requires separate tooling (typically Aircrack-ng).

---

## 4. The software, in brief

### 4.1 Feature inventory

Bjorn's stock modules, as documented in `README.md`, `DEVELOPMENT.md`, and the `actions/` directory of the source tree:

**Network discovery and reconnaissance**
- Live host discovery (ARP + ICMP sweep)
- TCP port scanning of discovered hosts
- Service identification on open ports
- Persistent host inventory in the **netkb** (Network Knowledge Base)

**Vulnerability assessment**
- Integrated nmap NSE vulnerability scanner (`nmap_vuln_scanner.py`)
- Results catalogued per host in `data/output/vulnerabilities/`

**Authentication attacks (brute force); one connector per service**
- `ftp_connector.py`; FTP credential brute force
- `ssh_connector.py`; SSH credential brute force
- `smb_connector.py`; SMB/CIFS credential brute force
- `rdp_connector.py`; RDP credential brute force
- `telnet_connector.py`; Telnet credential brute force
- `sql_connector.py`; SQL service brute force (MySQL, MSSQL, PostgreSQL, depending on detected service)

**Data exfiltration; one stealer per service**
- `steal_files_ftp.py`; FTP file enumeration and download
- `steal_files_ssh.py`; SSH/SCP file enumeration and download
- `steal_files_smb.py`; SMB share enumeration and download
- `steal_files_rdp.py`; RDP-accessible file download (where supported by the protocol stack)
- `steal_files_telnet.py`; Telnet shell file extraction
- `steal_data_sql.py`; SQL database table dump

**Orchestration and state**
- `orchestrator.py`; the heuristic engine that decides what to do next based on netkb state and configuration. The README calls this "Bjorn's AI"; it is a rule-based scheduler, not a learned model, but the term has stuck.
- `Bjorn.py`; entry point; brings up the orchestrator, the display thread, and the web server.
- `shared.py` / `init_shared.py`; global state shared across threads.
- `webapp.py`; the web UI server, bound to port 8000.

**Display and persona**
- `display.py`; manages the e-Paper drawing pipeline
- `epd_helper.py`; low-level Waveshare driver wrapper
- `comment.py`; generates the in-character Bjorn dialog and mood text that scrolls on the display

**Persistence and output**
The `data/output/` directory contains five subdirectories that map directly to attack outcomes:
- `scan_results/`; raw scanner output and netkb snapshots
- `vulnerabilities/`; nmap NSE findings per host
- `crackedpwd/`; recovered credentials (the cracked-password store)
- `data_stolen/`; exfiltrated files and SQL dumps
- `zombies/`; catalog of hosts where Bjorn maintains continued access

The "zombification" terminology in the README refers to this `zombies/` catalog; hosts that Bjorn has successfully compromised and continues to revisit on subsequent orchestrator cycles to extract additional data as it becomes available. It is not "implant a backdoor"; Bjorn does not install persistence on the target. It does, however, keep the recovered credentials and re-authenticates whenever the orchestrator says so.

### 4.2 The web interface

Bjorn's web UI runs on port 8000 (and the repository includes `kill_port_8000.sh` for cleaning up after a crashed instance). The interface shows:

- Live host inventory from netkb
- Current orchestrator status (what Bjorn is doing right now)
- Per-host attack progress
- Recovered credentials and stolen-data summaries
- Configuration panel for enabling/disabling specific actions
- Log stream

Authentication on the web UI is **not enabled by default** in the stock build. If you deploy Bjorn anywhere the web UI is reachable (and "the same LAN as the target" qualifies), enable authentication or firewall the port. This is a real consideration: a Bjorn that has cracked a dozen credentials and is exposing them on an unauthenticated web UI on the same LAN as the victims is a layered failure mode.

### 4.3 Custom attack modules

The `actions/` directory is the extension point. The project documentation in `DEVELOPMENT.md` describes the action class interface; any new module that subclasses the base Action class and lives in `actions/` is automatically discovered and run by the orchestrator subject to its configuration. The community Discord and the Reddit `r/Bjorn_CyberViking` regularly share new attack modules: VNC connectors, RDP file-stealer refinements, custom dictionaries, etc. For the operator, this means Bjorn is extensible in Python; a far easier extension target than the Arduino/PlatformIO C++ environment of Evil-M5 or Bruce.

---

## 5. Installation

The Bjorn install path is more involved than ESP32 firmware flashing but well documented. The `install_bjorn.sh` script handles the heavy lifting after you've prepared the Pi.

### 5.1 Step 1; Prepare the SD card

Use the official **Raspberry Pi Imager** to write Raspberry Pi OS Lite to your microSD card:

1. Open Raspberry Pi Imager. Choose the OS:
   - **Pi Zero W:** "Raspberry Pi OS Lite (32-bit)", Debian 12 Bookworm, kernel 6.6; the stable target.
   - **Pi Zero 2 W:** "Raspberry Pi OS Lite (64-bit)", same Debian/kernel.
2. Choose the storage (your SD card).
3. **Critical: open the "Edit Settings" gear before writing.** Configure:
   - **Hostname:** `bjorn` (required; the install script depends on this)
   - **Username:** `bjorn` (also required)
   - **Password:** something strong; you'll SSH in with this
   - **Wi-Fi SSID/password:** for your lab network
   - **Enable SSH:** yes, password-based for now
   - **Locale settings:** as appropriate
4. Write the image.
5. Eject and boot in the Pi.

The hostname and username requirements are not optional; Bjorn's installer and runtime expect to find user `bjorn` at `/home/bjorn/`, and a number of paths in the codebase hard-code that location. Renaming after install is fragile; do it right the first time.

### 5.2 Step 2; Boot and verify network connectivity

1. Insert the SD card into the Pi.
2. Attach the e-Paper HAT to the GPIO header (Pi powered down).
3. Power the Pi via the micro-USB power port. First boot takes 1-2 minutes.
4. From your workstation, find the Pi's IP. Either:
   - Check your router's DHCP leases for hostname `bjorn`, or
   - Run the companion tool: `git clone https://github.com/infinition/bjorn-detector && cd bjorn-detector && python3 bjorn_detector.py`; this scans the local subnet for the Bjorn signature.
5. SSH in: `ssh bjorn@<pi-ip>` and authenticate with the password you set in the imager.

### 5.3 Step 3; Run the installer

Once you have an SSH session as user `bjorn`:

```bash
wget https://raw.githubusercontent.com/infinition/Bjorn/refs/heads/main/install_bjorn.sh
sudo chmod +x install_bjorn.sh
sudo ./install_bjorn.sh
```

The installer presents a menu:

- **Option 1: Automatic installation**; fully unattended. The installer downloads dependencies, installs Python packages, configures the systemd service, sets up SPI for the HAT, configures the e-Paper driver, and prepares Bjorn for first run. Choose this unless you have a specific reason not to.
- **Option 2: Manual installation**; walks through each step interactively. Useful for troubleshooting or for understanding what the installer does, but not necessary on a fresh image.

Total install time is typically 20-40 minutes on a Pi Zero W, 10-20 minutes on a Pi Zero 2 W, depending on network speed. The installer pulls a lot of Python packages and nmap dependencies.

When the installer completes, reboot:

```bash
sudo reboot
```

### 5.4 Step 4; First boot and verification

After reboot, the Pi comes back up running Bjorn as a systemd service. You should see:

1. The e-Paper HAT displaying the Bjorn character with introductory dialog
2. Status indicators showing the orchestrator coming online
3. The web UI reachable at `http://<pi-ip>:8000`

Open the web UI in your browser. You should see:

- The Bjorn dashboard
- Current orchestrator state
- An empty (or pre-populated, depending on whether scanning has started) host inventory
- Configuration controls

If the e-Paper HAT shows nothing or shows garbled output, the issue is almost always either the HAT version mismatch (Bjorn's display driver expects v2 or v4 by default) or SPI not enabled. Check `TROUBLESHOOTING.md` in the repository; the developer maintains a current list of known display issues and remediation steps.

### 5.5 Step 5; Configure scope before running anything live

Before Bjorn touches anything, edit its configuration to constrain the network range it will scan. The web UI's configuration panel lets you set:

- **Target subnet**; the CIDR block Bjorn is allowed to scan. Set this to your isolated lab subnet, not your home LAN.
- **Enabled actions**; disable any modules you don't want running. For a first run, disable all the brute-force connectors and just enable network scanning + vulnerability assessment. Get comfortable with what Bjorn discovers before turning on the offensive modules.
- **Credential dictionaries**; Bjorn ships with default dictionaries in `data/input/dictionary/`. You can shrink or augment these as appropriate for your lab targets.
- **Rate limits**; how aggressively Bjorn brute-forces. Stock settings are deliberately slow to avoid tripping basic rate-limit defenses; you can tune them up for lab work.

**Do not skip this step.** Bjorn defaults are designed to be operationally productive, which means they assume you've defined a scope. Without one, the orchestrator will scan and attack whatever it finds at the subnet level; including, on a typical home LAN, your router, your NAS, your printers, your smart-home hub, and any neighbor's Wi-Fi-bridged device that's accessible through your network.

---

## 6. The operational model

Bjorn does not present a menu. It runs. The operator interacts with it in two ways:

1. **The e-Paper display**; read-only. Shows what Bjorn is doing, its current "mood" (a charming bit of UI that maps to orchestrator state), live statistics (hosts discovered, vulnerabilities found, credentials cracked, files stolen), and the Viking character's commentary.
2. **The web UI**; configuration, status detail, results browsing, and the start/stop controls for the orchestrator and individual modules.

A typical operational sequence:

1. Power on. Bjorn boots, orchestrator initializes.
2. Orchestrator runs initial network discovery. The display shows "Scanning..." and counts hosts as they're found.
3. Discovered hosts are added to netkb. Port scans run against each.
4. Open services are identified. nmap NSE vulnerability scans run.
5. Brute-force connectors target services with known weak-credential exposure. Successes are written to `crackedpwd/`.
6. File stealers run against successfully-authenticated services. Results land in `data_stolen/`.
7. Successfully-compromised hosts are catalogued in `zombies/` for future cycles.
8. The orchestrator loops; rescans the network periodically, picks up new hosts, re-attempts services that previously failed, extracts new data.

The operator may dip into the web UI at any time to read results, pause specific modules, or update configuration. But the design assumption is that Bjorn runs unattended.

---

## 7. Module deep-dives

### 7.1 Network discovery

Bjorn's discovery module performs a layered sweep:

- **ARP probe** of the configured subnet, identifying hosts at L2.
- **ICMP echo** to confirm liveness at L3.
- **TCP SYN scan** of a configured port range on each live host.
- **Service banner identification** on each open port.

Output lands in `data/output/scan_results/` as JSON and is used to update the netkb. On a typical /24 subnet with 20-30 active hosts, the initial discovery completes in a few minutes on a Pi Zero W and under a minute on a Zero 2 W.

The netkb itself is a persistent record: hosts that appeared once will be retried on subsequent scans even if they're temporarily offline, with a confidence score that decays over time. This is what lets Bjorn pick up where it left off after a reboot.

### 7.2 Vulnerability scanning

`nmap_vuln_scanner.py` invokes nmap with the **NSE vuln category** of scripts against discovered services. NSE includes hundreds of vulnerability-detection probes covering:

- Common CVEs against versioned services (e.g., EternalBlue/MS17-010 against SMBv1)
- Default-credential checks on services like FTP, MySQL, and SSH
- Anonymous-access checks (anonymous FTP, null SMB sessions)
- Information-disclosure probes (SMB user enumeration, NFS share listing)
- Protocol-specific weaknesses (Heartbleed, POODLE, etc.)

Findings are catalogued in `vulnerabilities/` per host. This output is consumed by the orchestrator to prioritize subsequent brute-force and exfiltration attempts.

A practical note: nmap NSE is noisy. Modern EDR and network IDS pick up NSE signatures readily; Bjorn doesn't try to evade detection. If you're operating in a lab and want to learn detection signatures, this is a feature: Bjorn provides a known-bad data source for tuning your IDS.

### 7.3 Brute-force connectors

Each service connector follows the same pattern:

1. Receives a target host + service from the orchestrator.
2. Loads username and password lists from `data/input/dictionary/`.
3. Connects to the service and attempts authentication with each (username, password) pair.
4. On success, writes the credential to `crackedpwd/` and signals the orchestrator.
5. On failure, marks the service "attempted" in netkb with the dictionary used, so it can be retried with a different dictionary later.

The connectors use the standard libraries for each protocol (Paramiko for SSH, pysmb for SMB, ftplib for FTP, etc.). They are not optimized for stealth; they make standard connections, and any service-side rate limiting or account-lockout policy will defeat them quickly.

This is a feature, not a flaw: a Bjorn that locks every SSH account in your lab on its first run is teaching you something about your account lockout policies. In production environments those policies should be tight enough that Bjorn's brute-force phase converges to "all targets locked" within minutes.

### 7.4 File and data exfiltration

The stealer modules activate after a brute-force connector reports success:

- `steal_files_ssh.py` walks remote directories over SFTP, downloads files matching configured patterns into `data_stolen/<host>/`, and respects size limits to avoid pulling huge files.
- `steal_files_smb.py` enumerates accessible shares and pulls files, focusing on common interesting filenames (configuration files, password files, document caches).
- `steal_files_ftp.py` and `steal_files_telnet.py` follow the same pattern against their respective services.
- `steal_files_rdp.py` is more limited; RDP file access requires a clipboard or drive-redirect channel, and the stealer captures what's accessible through standard RDP protocol features.
- `steal_data_sql.py` enumerates databases on a successfully-authenticated SQL service, dumps table schemas, and pulls table contents into `data_stolen/<host>/sql/`.

The default file-pattern lists prioritize "things that look interesting on a quick triage"; config files, .ssh keys, .git directories, password stores, .env files. This is configurable; for lab work, you may want to point it at deliberately-planted "interesting" files in your Metasploitable VMs to verify the stealer is working without it pulling random system files.

### 7.5 The "zombie" catalog

Once a host has been compromised, Bjorn writes it to `data/output/zombies/` along with the credentials and access patterns that worked. The orchestrator revisits zombies on subsequent cycles:

- Re-authenticates with the stored credentials.
- Looks for new content (files modified since last visit, new database rows, etc.).
- Updates the stolen-data store.

This is not implanted persistence; Bjorn does not write to the target. It is simply persistent credential reuse from the attacker side. If the target rotates the credential, Bjorn's zombie entry goes stale and falls back to brute-force on the next cycle.

The term "zombification" in the README is colorful marketing language; the actual behavior is cataloged credential reuse against unwitting targets. The legal posture is unchanged; repeatedly authenticating to a service you're not authorized to access is repeated CFAA violation, not a single one.

### 7.6 The display layer

Bjorn's personality lives in `display.py` and `comment.py`. The orchestrator publishes events; the display layer translates them into character pose, mood tag, and dialog text. The Tamagotchi framing is deliberate; it makes a network attacker feel like a pet, which is charming and disarming, but should not be confused with what the tool actually does.

On the e-Paper screen at any given moment you'll see:

- The Bjorn character (a small Viking with mood-appropriate expression)
- A scrolling dialog line ("Hunting for hosts...", "Found a juicy SMB share!", etc.)
- A stats panel: hosts found, vulnerabilities, credentials cracked, files stolen, zombies
- Network status indicator

The e-Paper refresh is slow (sub-1Hz partial refresh, much slower for full clear), which is fine for an autonomous device but means the display lags real-time activity by a few seconds.

---

## 8. Playbook; closed-lab exercises only

Every exercise in this section assumes a **fully isolated lab environment**. The recommended setup, leveraging the Proxmox cluster Jon already runs:

- **Target subnet**, isolated on its own VLAN with no route to any production network or to the internet at large (the lab can have controlled outbound for package updates, but inbound must be airtight).
- **Vulnerable target VMs:**
  - Metasploitable2; Linux with weak everything (FTP, SSH, Telnet, MySQL with msfadmin/msfadmin, SMB Samba 3 with anonymous shares)
  - Metasploitable3 (Linux and Windows variants); newer Rapid7-maintained vulnerable images
  - DVWA; web app focus, less Bjorn-relevant but useful for context
  - OWASP Broken Web Apps; same
  - A Windows VM with anonymous SMB share enabled and a weak local administrator password
- **Bjorn deployment:** Pi Zero 2 W with e-Paper HAT, attached to the lab VLAN.
- **Observer station:** a separate VM running Wireshark and an IDS (Suricata or Zeek) on a SPAN port of the lab switch, so you can independently observe what Bjorn does.
- **A blank "production-style" subnet** that Bjorn is *not* allowed to touch; useful for verifying that your scope configuration works correctly.

### Exercise C1; Initial discovery, brute-force disabled

**Objective.** Run Bjorn against the lab subnet in discovery-only mode. Confirm it finds all hosts and identifies services accurately.

**Steps.**
1. In the web UI, set the target subnet to your lab CIDR.
2. Disable all brute-force and stealer modules.
3. Enable network scanning and vulnerability assessment.
4. Start the orchestrator.
5. Wait 10-20 minutes.

**Success criteria.**
- All lab VMs appear in netkb with correct IP and MAC.
- Open ports on each are correctly catalogued.
- Vulnerability findings from nmap NSE appear in `vulnerabilities/`.

**Debrief.** Compare Bjorn's output to a manual `nmap -sS -sV --script vuln <subnet>` run from a Kali VM. Are the findings consistent? Where do they differ?

### Exercise C2; SSH brute-force against Metasploitable2

**Objective.** Watch Bjorn brute-force the known-weak SSH service on Metasploitable2 (`msfadmin:msfadmin`).

**Steps.**
1. With C1 completed, enable only the SSH brute-force connector.
2. Verify the credential dictionary contains `msfadmin` as both a username and password (it's in the default Bjorn dictionary).
3. Start the orchestrator.
4. Observe the e-Paper display and web UI.

**Success criteria.**
- Bjorn reports successful authentication on Metasploitable2's SSH service.
- The credential appears in `crackedpwd/`.
- On the observer station, Wireshark and the IDS capture the brute-force pattern (many failed authentications followed by success).

**Debrief.** How quickly did Bjorn converge on the correct credential? Now configure SSH on Metasploitable2 with `fail2ban` and a 5-failure lockout. Repeat. Document what changes.

### Exercise C3; File exfiltration after successful authentication

**Objective.** Watch Bjorn enumerate and exfiltrate files from a compromised host.

**Steps.**
1. With C2 completed (Bjorn has Metasploitable2's SSH credentials), enable the SSH file stealer.
2. Pre-plant a deliberately interesting file at `/home/msfadmin/secrets.txt` on Metasploitable2 with known content.
3. Restart the orchestrator.

**Success criteria.**
- Bjorn re-authenticates and pulls files from `/home/msfadmin/`.
- Your planted file appears in `data_stolen/<metasploitable-ip>/`.
- The observer's IDS captures the SFTP/SCP transfer.

**Debrief.** What does this look like from the defender's perspective on the IDS? What detection rule would you write to catch this pattern?

### Exercise C4; SMB exposure against an anonymous-share Windows VM

**Objective.** Same as C3 but against SMB on a Windows VM with anonymous share enabled.

**Setup.** Configure a Windows 10 or Server VM with:
- An SMB share named "PublicShare" with Everyone read access
- A few innocuous files in the share

**Steps.**
1. Add the Windows VM to the lab subnet.
2. Re-run Bjorn's discovery.
3. Enable the SMB connector and stealer.
4. Observe.

**Success criteria.**
- Bjorn identifies the anonymous SMB share.
- Files from the share are pulled into `data_stolen/`.

**Debrief.** Anonymous SMB shares are still surprisingly common in production environments. What's the migration path? (Hint: SMB signing, share-level authentication, deprecation of guest access, network segmentation.)

### Exercise C5; Custom attack module

**Objective.** Write a new action module in Python and have Bjorn's orchestrator run it.

**Steps.**
1. Read `DEVELOPMENT.md` in the Bjorn repo for the action class interface.
2. Write a new module; for example, a VNC connector, or a service banner-grabber that catalogs HTTP server software versions for context.
3. Drop the module into `actions/` on the Pi.
4. Restart Bjorn.
5. Observe the orchestrator picking up your new action and running it.

**Success criteria.**
- Your module appears in the web UI's actions list.
- It runs without errors against discovered hosts.
- Output appears in an appropriate `data/output/` subdirectory.

**Debrief.** What did the extension experience teach you about Bjorn's internal architecture? Where could it be improved?

### Exercise C6; Blue team detection

**Objective.** From the defender's perspective, build a detection ruleset for Bjorn's activity.

**Setup.** With Bjorn running C2-C4 exercises, the observer station with Suricata or Zeek collecting traffic.

**Steps.**
1. Capture a full Bjorn session; discovery through brute-force through exfiltration.
2. Review the Suricata/Zeek logs. Identify:
   - The signature of the initial nmap scan (rate, port pattern, scan type)
   - The signature of the brute-force attempts (rate, failed authentication count)
   - The signature of the file exfiltration (SFTP volume, timing)
3. Write Suricata rules (or Zeek scripts) that would alert on this activity.

**Success criteria.**
- You have ruleset that would have detected Bjorn at scan, brute-force, and exfiltration stages.
- You have measured the false-positive rate of those rules against your normal lab traffic.

**Debrief.** This is the most valuable exercise in the chapter from a defensive perspective. Most environments have zero detection on credential brute-force at the network layer; they rely on host-side authentication logs. What does your ruleset add?

### Exercise C7; Lockout cascade analysis

**Objective.** Understand what Bjorn's brute-force phase does to account lockout policies.

**Setup.** Configure an Active Directory environment in the lab with:
- A domain controller
- Several domain user accounts with a 5-failed-attempts lockout policy and 30-minute lockout duration

**Steps.**
1. Enable Bjorn's SMB connector pointed at the AD environment.
2. Let it run for 30 minutes.
3. Examine the AD account lockout logs.

**Success criteria.**
- You can quantify how many accounts Bjorn locked.
- You can estimate the operational impact this would have in a production environment.

**Debrief.** A 5/30 lockout policy and Bjorn-level brute-force means an attacker can lock every account in a domain in under an hour, denying legitimate users access. This is a CFAA § 1030(a)(5) damage event in its own right; *before* any credential is recovered. Document this for your client's account-policy review.

---

## 9. Blue team; defenses against Bjorn

| Attack stage | Detection | Prevention |
|---|---|---|
| Network discovery (ARP/ICMP/TCP scan) | NIDS (Suricata, Zeek) signatures on rapid scan patterns; ARP-flood detection on managed switches | Network segmentation; ARP inspection on switches; honeypot hosts that alert on first contact |
| Vulnerability scanning (nmap NSE) | NIDS signatures on NSE script-specific traffic patterns; SIEM correlation of port-scan-followed-by-known-CVE-probe | Disable services that aren't needed; patch the ones you do need; service banners that obscure version |
| SSH brute-force | OS-level authentication logs (auth.log, journalctl); fail2ban; SSH-specific IDS rules | **Key-only authentication** (disable password auth entirely); MFA for privileged accounts; fail2ban with aggressive thresholds |
| SMB brute-force | Windows event log (4625 failed logon, 4740 account locked); SMB-specific IDS rules | Disable SMBv1 entirely; SMB signing required; account-lockout policy (5/30 is sufficient, with caveats); MFA for privileged accounts |
| FTP/Telnet brute-force | Service authentication logs; IDS rules | **Do not run FTP or Telnet in production.** If you must, restrict to specific source IPs and use FTPS/SFTP-only |
| RDP brute-force | Event 4625 with logon type 10 (RemoteInteractive); Network Level Authentication enforced | NLA enforced; account lockout; Remote Desktop Gateway with MFA; restrict RDP source IPs |
| SQL brute-force | Database authentication logs; database-specific IDS rules (some IDS have MySQL probes) | Strong DB passwords; restrict DB access to application servers only via firewall; service accounts with minimal grants |
| File exfiltration (SSH/SMB/FTP) | Volume-based anomaly detection in the IDS; egress monitoring for unusual outbound transfers (Bjorn is on the LAN, so this is intra-LAN traffic; east-west monitoring needed) | Data-loss-prevention (DLP) on file servers; access logging and review; principle-of-least-privilege on file shares |
| SQL data dump | Database query logging and review; DAM (Database Activity Monitoring) tools | Limit database service-account scope; row-level access controls; database firewalls |
| Persistent compromised-host cataloging | Behavioral baselining on authentication patterns (the same source-IP authenticating to many hosts is anomalous) | Network access control (802.1X) so unknown devices can't get on the LAN; jump hosts and bastion architectures |

The headline mitigations, in priority order, are:

1. **SSH key-only auth everywhere.** Disabling password auth on SSH defeats Bjorn's most reliable attack vector entirely.
2. **Network segmentation.** Bjorn relies on being on the same LAN as its targets. Microsegmentation in modern environments (VLANs, zero-trust networking, SD-WAN policy) limits the lateral movement that makes Bjorn dangerous.
3. **802.1X port authentication.** An unauthenticated Pi plugged into a switch port should never get an IP or any L3 connectivity.
4. **Anomalous-authentication detection.** A single source generating failed authentications across multiple hosts is the canonical Bjorn signature. SIEMs can catch this; most don't, by default.
5. **DLP on file shares.** Most file shares have no monitoring of *what* leaves them. Bjorn pulls a lot, fast.

---

## 10. Troubleshooting

**Pi boots but e-Paper HAT shows nothing.** SPI not enabled. Run `sudo raspi-config`, navigate to Interface Options, enable SPI, reboot. Then check `/boot/config.txt` for `dtparam=spi=on`.

**E-Paper shows garbled output or wrong refresh.** HAT version mismatch. The Bjorn installer defaults to v2; if you have a v4, edit `display.py` to load the v4 driver. The `TROUBLESHOOTING.md` in the repo has current guidance.

**Installer fails on Python dependencies.** Usually a stale package index. `sudo apt update && sudo apt upgrade -y`, reboot, re-run installer.

**Web UI not reachable on port 8000.** Either Bjorn isn't running (`sudo systemctl status bjorn`) or the firewall is blocking. The Pi's default firewall is open, but if you've enabled ufw, allow 8000.

**Bjorn finds no hosts.** Subnet configuration mismatch. The default scan range may not match your lab subnet; check the web UI's configuration panel.

**Brute-force never succeeds.** Dictionary doesn't contain the credential. Add to `data/input/dictionary/` and restart.

**Pi reboots randomly during operation.** Power supply undersized. Pi Zero W needs at least 1.2 A, Pi Zero 2 W at least 2.5 A. The official Raspberry Pi USB power supply is rated for the Pi alone; adding a HAT and running heavy network activity may push past the supply's headroom. Use a quality 3A supply.

**Pi-detector can't find the Pi.** Either the Pi isn't on the same broadcast domain as your workstation, or DHCP hasn't issued an IP yet. Wait 2-3 minutes after first boot and retry.

**Account lockouts ruining the lab.** Configure local user account lockout policies *on the target VMs* before you run Bjorn; this is the point of the exercise, but you may want to start with longer thresholds (e.g., 50 failures) to allow Bjorn to converge.

---

## 11. Appendix A; Bjorn vs Bruce vs Evil-M5: when to use which

| Need | Best tool |
|---|---|
| Wi-Fi captive portal phishing | Evil-M5 |
| Wi-Fi deauth + KARMA | Evil-M5 |
| Wi-Fi handshake capture + crack | Evil-M5 |
| Multi-radio handheld (sub-GHz, NFC, IR, FM) | Bruce |
| NFC/RFID badge clone | Bruce |
| Sub-GHz remote replay | Bruce |
| BLE HID injection / BLE Spam | Bruce |
| Scripted attack chains (JS) | Bruce |
| Persistent on-site implant for remote access | Bruce (WireGuard) or Bjorn (Pi-side OpenVPN/Tailscale) |
| Autonomous network-service attack on a Pi | **Bjorn** |
| Network discovery + nmap-style vuln scanning, autonomous | **Bjorn** |
| SSH/SMB/FTP/RDP/SQL brute-force, autonomous | **Bjorn** |
| File/data exfiltration from compromised services | **Bjorn** |
| "Drop and leave" engagement device | **Bjorn** |
| Lab tool for teaching account-policy weaknesses | **Bjorn** |

The three tools are complementary, not competitive. A well-equipped lab has all three: Cardputer with Evil-M5 for Wi-Fi work, Cardputer with Bruce (or Lilygo T-Embed CC1101) for multi-radio work, Pi Zero 2 W with Bjorn for network-service work.

## Appendix B; Bill of materials (Bjorn build)

For a complete portable Bjorn deployment:

| Item | Source | Approximate cost |
|---|---|---|
| Raspberry Pi Zero 2 W | Adafruit, CanaKit, Pi-Shop | $15-20 |
| Waveshare 2.13" e-Paper HAT (v2 or v4) | Waveshare direct, Adafruit | $20-25 |
| microSD card, 16-32 GB Class 10 (High Endurance) | Sandisk, Samsung | $10-15 |
| micro-USB power supply (3A) or PiSugar HAT | Various | $10 (supply) or $35-50 (PiSugar) |
| 3D-printed enclosure | Printable in PETG/PLA on your Bambu X1C | $1-2 in filament |
| Optional: USB Wi-Fi adapter for monitor mode (RTL8812AU or AR9271) | Alfa, TP-Link | $25-40 |

**Total for the basic build:** ~$50-65.
**Total with PiSugar for true portability:** ~$85-100.
**Total with optional monitor-mode USB adapter:** ~$110-140.

## Appendix C; Pre-flight compliance checklist (Bjorn-specific)

This checklist is stricter than the ones for Evil-M5 and Bruce because Bjorn's core operations are CFAA-actionable, not just regulatory:

- [ ] Lab subnet is **fully isolated**; VLAN with no L3 route to any production network. Verified by attempting to ping a known production host from the lab VLAN (should fail).
- [ ] No third-party devices accessible from the lab subnet. Verified by enumerating all hosts on the subnet and confirming each is a known lab VM.
- [ ] If running on a "home network" segment, written affirmation that **every device on that segment** is owned by the operator and may be subjected to Bjorn's full attack chain. (This is a high bar; modern home networks include guest devices, IoT devices, neighbors' Wi-Fi-bridged devices, and many other items not actually "owned by the operator.")
- [ ] If running under a client ROE: the ROE explicitly authorizes:
  - Network scanning and port enumeration on the specified subnets
  - Vulnerability scanning (nmap NSE)
  - **Brute-force authentication attempts** on specified services
  - **Data exfiltration** from successfully-authenticated services
  - The specific time window during which Bjorn may run
  - The cleanup obligation (Bjorn-deployed device must be retrieved and its data destroyed per ROE timeline)
- [ ] No ROE? Bjorn does not run.
- [ ] Account lockout impact has been explicitly authorized. The client knows Bjorn may lock every account in a target domain, and they have accepted that risk in writing.
- [ ] Web UI port 8000 is firewalled or password-protected. (The web UI exposes recovered credentials; an unauthenticated UI on a target LAN is itself a data-exposure incident.)
- [ ] Bjorn's `data/output/` is encrypted at rest. (The Pi is a portable device with a SD card; if it's lost or stolen, recovered credentials should not be plaintext-readable.)
- [ ] A deployment inventory exists: which Pi, what serial, what physical location, when deployed, when scheduled for retrieval, who is responsible.
- [ ] E&O / professional liability insurance specifically covers offensive testing.
- [ ] The operator has read 18 USC § 1030, 18 USC § 2701, and 18 USC § 2511 in the past year and understands what they say. (This is not a joke; read the statutes.)

If any line is unchecked, Bjorn does not run.

## Appendix D; Adjacent tools and forks

**Ragnar (PierreGode/Ragnar).** A community fork of Bjorn that adds hardware targets beyond the Pi + e-Paper HAT combo:

- **Headless server deployment** on Debian-based AMD64, ARM64, or ARMv7 systems (no display needed)
- **WiFi Pineapple Pager port** with full-color LCD (based on prior work by brAinphreAk's PagerBjorn/Loki project)
- Advanced features on 8GB+ RAM systems: real-time traffic analysis, enhanced vulnerability scanning
- Same MIT license, same core attack pipeline

Ragnar is worth knowing about because:
1. If you want Bjorn-style attacks on a beefier platform (a Pi 4 with 8GB, a small mini-PC, or a WiFi Pineapple Pager), Ragnar is the path.
2. The headless server build is convenient for lab environments where you don't need the Pi form factor.
3. The Pineapple Pager port is novel; combines Bjorn-style network attacks with the Pineapple's purpose-built RF hardware.

**Pwnagotchi.** Different tool, similar autonomous-on-Pi concept. Pwnagotchi targets Wi-Fi (WPA handshake capture and offline crack) using an AI-themed autonomous loop. Where Bjorn is a network-service attacker that runs on a Pi, Pwnagotchi is a Wi-Fi attacker that runs on a Pi. They are complementary; some operators run both on different devices in the same kit.

**bjorn-detector.** The official companion utility from infinition for finding Bjorn devices on a local network. Useful during initial setup; available at `github.com/infinition/bjorn-detector`.

**Custom action modules.** The `r/Bjorn_CyberViking` subreddit and the Discord regularly publish new Python modules. As of late 2025, community-maintained modules include: VNC connectors, additional dictionary sources, HTTP service fingerprinting, basic web-app credential-stuffing connectors, and various exfiltration enhancements.

## Appendix E; Further reading and resources

- **Bjorn GitHub repository:** `https://github.com/infinition/Bjorn`
- **INSTALL.md:** `https://github.com/infinition/Bjorn/blob/main/INSTALL.md`; authoritative install steps
- **DEVELOPMENT.md:** `https://github.com/infinition/Bjorn/blob/main/DEVELOPMENT.md`; architecture and extension guide
- **TROUBLESHOOTING.md:** `https://github.com/infinition/Bjorn/blob/main/TROUBLESHOOTING.md`; current known issues
- **SECURITY.md:** `https://github.com/infinition/Bjorn/blob/main/SECURITY.md`; responsible-disclosure for issues in Bjorn itself
- **Discord:** `https://discord.com/invite/B3ZH9taVfT`
- **Reddit:** `r/Bjorn_CyberViking`
- **bjorn-detector:** `https://github.com/infinition/bjorn-detector`
- **Ragnar fork:** `https://github.com/PierreGode/Ragnar`
- **Pwnagotchi (adjacent):** `https://pwnagotchi.ai/`
- **Vulnerable target VMs for lab use:**
  - Metasploitable2: `https://docs.rapid7.com/metasploit/metasploitable-2`
  - Metasploitable3: `https://github.com/rapid7/metasploitable3`
  - DVWA: `https://github.com/digininja/DVWA`
  - OWASP Broken Web Apps (BWA) is retired; its successor is the OWASP Vulnerable Web Applications Directory: `https://vwad.owasp.org/`
- **CFAA full text:** `https://www.law.cornell.edu/uscode/text/18/1030`
- **Stored Communications Act:** `https://www.law.cornell.edu/uscode/text/18/2701`
- **Wiretap Act:** `https://www.law.cornell.edu/uscode/text/18/2511`
- **Washington Cybercrime Act (RCW 9A.90):** `https://app.leg.wa.gov/RCW/default.aspx?cite=9A.90`

---

*This chapter is provided for educational and authorized red-team use only. Bjorn, like any offensive security tool, is a felony to operate against systems you do not own or are not explicitly authorized to test. The author of this chapter, the Bjorn developer (infinition), the Raspberry Pi Foundation, and Waveshare bear no responsibility for misuse. Unlike the wireless-protocol tools in the previous two chapters, Bjorn's normal operation falls within the express prohibitions of the Computer Fraud and Abuse Act and the Stored Communications Act. Treat the laboratory-isolation requirement as inviolable. The technical interest of the tool is genuine; the legal risk of operating it outside a properly-scoped lab or signed engagement is also genuine, and is the more important of the two.*
