# Kali NetHunter - Standard Operating Procedures

## 🎯 Purpose
Field SOPs for operating all Kali NetHunter attack modules and utilities on the OnePlus 6 during authorized penetration tests - from pre-engagement setup through post-engagement teardown and evidence handling.

## ⚙️ Function
Per-module procedures for every NetHunter capability: HID/BadUSB attacks, WifiPumpkin rogue AP, WPS attacks, Bluetooth Arsenal, Wardriving, SET, Nmap, Metasploit payload generation, SearchSploit, KeX desktop, MAC changer, and CARsenal. Each section includes prerequisites, authorization gates, verification steps, and cleanup actions.

## 🏆 Goal
Ensure consistent, authorized, and evidence-tracked execution of mobile pentesting operations. Covers the full engagement lifecycle: RoE confirmation, device baseline verification, per-tool procedures, and teardown checklist with artifact hashing and data handling.

## 📋 When to Use
- Before any engagement using the NetHunter device (RoE and pre-engagement checklist)
- During testing as a step-by-step procedure reference for each NetHunter module
- At teardown for evidence handling, MAC restoration, and device cleanup

---

**Platform:** OnePlus 6 (`enchilada`, model A6000/A6003) - Full NetHunter Edition (custom kernel)
**Maintained by:** Pacific Northwest Computers (PNWC)
**Contact:** jon@pnwcomputers.com · 360-624-7379
**Version:** 1.0
**Classification:** Internal - Field Operations Reference

---

## 0. Authorization & Rules of Engagement (READ FIRST)

> These SOPs cover offensive-capable tooling. **Do not run any active/attack procedure without written authorization.**

Before any engagement, confirm and file:

- [ ] Signed **Statement of Work / Rules of Engagement (RoE)** naming the client, scope, and authorized target ranges (IP/SSID/BSSID/asset list).
- [ ] Explicit **in-scope wireless SSIDs/BSSIDs** and MAC allow-list. Wireless and RF attacks bleed easily into out-of-scope airspace - document exclusions.
- [ ] **Time window** for testing and any blackout periods.
- [ ] **Emergency stop contact** on the client side.
- [ ] Physical-access authorization (badge, escort, or written consent) if HID/BadUSB is in scope.
- [ ] Confirmation that RF activity (Evil AP, deauth, Bluetooth injection) is legal at the test location and will not disrupt safety-critical systems.

**Golden rule:** if a procedure could touch a device, network, or person outside the signed scope, stop and re-confirm scope before proceeding.

---

## 1. Platform Baseline & Verification

Perform once per device, and re-verify after any NetHunter/kernel update.

### 1.1 Confirm edition and kernel features
1. Open the **NetHunter** app → **Home**. Confirm chroot is detected and shows a Kali version.
2. Open **NetHunter Terminal** → `KALI` session → run:
   ```bash
   uname -a          # confirm NetHunter kernel string
   id                # confirm root inside chroot
   ip a              # confirm interfaces
   ```
3. Verify kernel capabilities expected on the OnePlus 6 full edition:
   - **HID / USB gadget** (for HID + BadUSB)
   - **OTG wireless** (external adapter support)
   - **Monitor mode / injection** (internal chipset is limited - see Appendix A; use an external adapter for reliable injection)

### 1.2 Update the chroot
```bash
sudo apt update && sudo apt full-upgrade -y
# Optional, if storage allows:
sudo apt install -y kali-linux-default
```

### 1.3 Backup the rootfs (do before major changes)
From a **Termux** session (not inside chroot), stop all NetHunter sessions first, then:
```bash
tar -cJf kali-arm64.tar.xz kali-arm64 && mv kali-arm64.tar.xz storage/downloads
```

### 1.4 Housekeeping
- [ ] Hacker's Keyboard installed (needed for terminal/HID layouts).
- [ ] NetHunter Store reachable; apps updated.
- [ ] External Wi-Fi adapter(s) tested (Appendix A).
- [ ] Device battery > 50% or Y-cable/power bank staged for long ops.

---

## 2. Pre-Engagement Checklist (every job)

- [ ] RoE confirmed (Section 0).
- [ ] Device time/zone correct (matters for logs/evidence).
- [ ] Clean working directory created for the engagement: `~/engagements/<client>-<YYYYMMDD>/`.
- [ ] MAC randomized if operating covertly (Section 8).
- [ ] Airplane mode + selective radios as needed to avoid stray connections.
- [ ] Evidence capture plan (where captures/logs are written, how they're exfiltrated).

---

## 3. NetHunter App - Home, Chroot Manager & Services

**Purpose:** Central control for the Kali chroot and background services.

**Procedure**
1. **Home** - status dashboard. Confirm chroot present and IP shown.
2. **Kali Chroot Manager** - install/remove/update the chroot; switch minimal ↔ full; re-run `apt` from here or terminal.
3. **Kali Services** - toggle services (SSH, PostgreSQL for Metasploit DB, Apache, VNC, etc.). Start only what the task needs; stop them at teardown.

**Verification:** started services appear active; `ss -tlnp` in terminal shows expected listeners.

**Cleanup:** stop all services you enabled. Leaving SSH/Apache running is an exposure risk.

---

## 4. NetHunter Terminal

**Purpose:** Shell access to Kali (`KALI`), Android (`ANDROID`), and root Android sessions.

**Procedure**
- Launch **NetHunter Terminal** → pick session type.
- `KALI` session = full Kali toolset. This is your primary workspace for Nmap, Metasploit, aircrack-ng suite, etc.
- Use `tmux` for long-running captures so a dropped session doesn't kill the job:
  ```bash
  tmux new -s eng
  # detach: Ctrl-b d   |   reattach: tmux attach -t eng
  ```

**Notes:** On non-root/rootless setups some tools (e.g., `top`) misbehave - full edition on the OnePlus 6 avoids most of these.

---

## 5. Custom Commands

**Purpose:** Pin frequently used commands/scripts to the NetHunter menu for one-tap launch in the field.

**Procedure**
1. NetHunter app → **Custom Commands** → add entry.
2. Provide a label and the full command (absolute paths; specify the session/user context).
3. Save; launch from the menu.

**Use cases:** start a scoped Nmap sweep, launch a capture into the engagement folder, spin up a KeX session, kick off a recon script.

---

## 6. Kali NetHunter Desktop Experience (KeX Manager)

**Purpose:** Full Kali desktop over VNC - HDMI/wireless casting for tools that need a GUI (Wireshark, Burp).

**Procedure**
1. NetHunter app → **KeX Manager** → set a VNC password (first run).
2. **Start Server**, then connect with the KeX client (local loopback) or external VNC.
3. For HDMI/monitor output, connect via USB-C → HDMI and mirror.
4. Stop the server when done.

**Verification:** desktop renders; clipboard/keyboard functional.

**Cleanup:** stop KeX; clear/rotate the VNC password if the device leaves your control.

---

## 7. USB Arsenal

**Purpose:** Control USB gadget configuration - the switchboard for HID, BadUSB, mass storage, and CD-ROM emulation modes.

**Procedure**
1. NetHunter app → **USB Arsenal**.
2. Select the gadget config required by the task (e.g., HID for keyboard attacks, MITM/RNDIS for BadUSB).
3. Apply, then run the corresponding attack module (Sections 9–10).

**Notes:** Only one gadget mode is typically active at a time. If HID/BadUSB "does nothing," USB Arsenal mode is the usual culprit - verify it first.

---

## 8. MAC Changer

**Purpose:** Spoof/randomize interface MAC for covert operation or to satisfy RoE anonymity requirements.

**Procedure**
1. NetHunter app → **MAC Changer** → pick interface → randomize or set a specific MAC.
2. Verify in terminal: `ip link show <iface>`.

**Notes:** Some internal interfaces resist changes; external adapters are more reliable. Record any spoofed MAC in engagement notes.

---

## 9. HID Attacks (Keyboard / Teensy-style)

**Purpose:** Turn the phone into a scripted USB keyboard against an **authorized, physically in-scope** host.

**Prerequisites:** Physical-access authorization; USB Arsenal set to HID; target unlocked or attack accounts for lock state; correct keyboard layout selected.

**Procedure**
1. USB Arsenal → HID gadget mode.
2. NetHunter app → **HID Attacks** → choose *PowerSploit* or *Windows CMD* tab.
3. Select payload/attack, set the target OS + keyboard layout, connect via OTG/USB to target.
4. Execute; watch for injected keystrokes on the target.

**Verification:** keystrokes land on target; expected shell/download behavior observed.

**Safety/Cleanup:** revert USB Arsenal to a benign mode afterward; document exactly what was typed/executed for the report.

---

## 10. DuckHunter HID (Rubber Ducky compatibility)

**Purpose:** Run **USB Rubber Ducky** DuckyScript payloads from the phone (you already run Rubber Ducky/Bash Bunny - DuckHunter reuses that script language).

**Procedure**
1. NetHunter app → **DuckHunter HID** → **Convert** tab.
2. Paste or load a `.txt` DuckyScript, or write inline.
3. Set the keyboard layout (mismatch = garbled injection).
4. **Preview** the converted payload, connect target via OTG/USB, **Attack**.

**Notes:** Keep a small library of vetted DuckyScripts in the engagement folder. Test on a lab VM before live use.

---

## 11. BadUSB MITM Attack

**Purpose:** When plugged into an authorized host, present as a USB network adapter and MITM the host's traffic.

**Prerequisites:** Physical access authorization; USB Arsenal set to the BadUSB/RNDIS gadget; target auto-trusts new USB NICs.

**Procedure**
1. USB Arsenal → BadUSB/MITM gadget config.
2. NetHunter app → **BadUSB MITM Attack** → configure interface/gateway.
3. Connect to target; the host routes through the phone.
4. Capture with tcpdump/Wireshark (KeX) into the engagement folder.

**Verification:** target obtains an IP from the phone; traffic visible in capture.

**Cleanup:** stop capture, detach, revert USB mode, secure the capture file.

---

## 12. WifiPumpkin / Evil AP (MANA-class attacks)

**Purpose:** Stand up a rogue/captive-portal AP for authorized Wi-Fi client testing.

**Prerequisites:** External adapter with AP + injection support; **only in-scope SSIDs**; confirm no interference with production/safety Wi-Fi.

**Procedure**
1. Attach external adapter; confirm with `iw dev` / `airmon-ng`.
2. Launch **WifiPumpkin** (NetHunter app menu or from terminal).
3. Configure SSID, channel, captive portal, and the capture/proxy modules.
4. Start the AP; monitor associated clients and captured credentials into the engagement folder.

**Verification:** AP broadcasts; test client associates; portal serves.

**Safety/Cleanup:** stop the AP promptly; never leave a rogue AP unattended. Log the SSID/BSSID/channel used.

---

## 13. WPS Attacks (OneShot)

**Purpose:** Test WPS-enabled APs (Pixie-Dust / PIN) against **authorized** targets only.

**Procedure**
1. Attach compatible external adapter (monitor + injection).
2. NetHunter app → **WPS Attacks** (OneShot) → scan → select the in-scope BSSID.
3. Choose Pixie-Dust or PIN attack; run; record result.

**Notes:** Confirm the BSSID is on your allow-list before launching. Document PINs/keys recovered.

---

## 14. Bluetooth Arsenal

**Purpose:** Bluetooth recon, spoofing, and audio inject/listen against **authorized** devices.

**Prerequisites:** Compatible internal/external BT; targets explicitly in scope.

**Procedure**
1. NetHunter app → **Bluetooth Arsenal**.
2. **Recon**: scan/enumerate nearby devices (record only in-scope MACs).
3. **Attack/Audio**: spoof, connect, or inject per module - only against authorized targets.

**Safety:** BT ranges catch bystander devices easily. Scope discipline is critical here.

---

## 15. Social Engineer Toolkit (SET)

**Purpose:** Build authorized phishing/credential-harvest campaigns.

**Procedure**
1. NetHunter app → **Social Engineer Toolkit**, or launch `setoolkit` in terminal.
2. Select the vector (credential harvester, cloned page, etc.).
3. Configure listener/host; stage on the engagement network.
4. Capture results into the engagement folder.

**Notes:** Client written approval for phishing content and target list is mandatory. Retain all sent content for the report.

---

## 16. Nmap Scan

**Purpose:** Quick network discovery/enumeration.

**Procedure**
1. NetHunter app → **Nmap Scan** for guided scans, or run in terminal for full control:
   ```bash
   nmap -sS -sV -p- --open -oA ~/engagements/<client>-<date>/nmap_full <in-scope-range>
   nmap -sU --top-ports 100 -oA ~/engagements/<client>-<date>/nmap_udp <target>
   ```
2. Keep scans **inside the authorized ranges**. Save `-oA` output for reporting.

---

## 17. Metasploit Payload Generator (MPC)

**Purpose:** Generate payloads quickly (wraps `msfvenom`).

**Procedure**
1. Start **PostgreSQL** via Kali Services (for msfconsole DB).
2. NetHunter app → **Metasploit Payload Generator** → pick platform/type, set LHOST/LPORT → generate.
3. Or terminal:
   ```bash
   msfvenom -p <payload> LHOST=<ip> LPORT=<port> -f <format> -o ~/engagements/<client>-<date>/payload.<ext>
   ```
4. Start the matching handler in `msfconsole`.

**Notes:** Payloads are engagement artifacts - store, hash, and clean them up at teardown.

---

## 18. SearchSploit (Exploit-DB)

**Purpose:** Offline search of Exploit-DB.

**Procedure**
```bash
searchsploit <product> <version>
searchsploit -x <path>     # examine an exploit
searchsploit -u            # update the DB
```
Map findings to Nmap `-sV` output; note EDB-IDs in the report.

---

## 19. Wardriving

**Purpose:** Passive survey of nearby Wi-Fi (and optionally cell/BT) for authorized site assessment.

**Prerequisites:** External adapter + GPS (your SenseCAP/GPS kit or a USB GPS puck).

**Procedure**
1. Attach adapter + GPS; confirm fix.
2. NetHunter app → **Wardriving** → start passive capture.
3. Export results (Kismet/CSV) into the engagement folder for mapping.

**Notes:** Passive only by default - keep it passive unless active testing is separately authorized.

---

## 20. CARsenal (Automotive)

**Purpose:** CAN-bus / automotive security testing (can-utils, etc.).

**Prerequisites:** Compatible CAN interface hardware; **written vehicle-owner authorization**; test in a safe, controlled setting.

**Procedure**
1. Connect CAN adapter; bring up the interface.
2. NetHunter app → **CARsenal** → select tool (candump, cansend, cansniffer…).
3. Capture/replay only against the authorized vehicle/bench.

**Safety:** Never inject on a moving vehicle or any safety-critical live system.

---

## 21. Pineapple Connector

**Purpose:** Share the phone's internet to a **Hak5 WiFi Pineapple** over USB (you run a Pineapple already).

**Procedure**
1. Connect the Pineapple via USB/OTG.
2. NetHunter app → **Pineapple Connector** → enable internet sharing.
3. Manage the Pineapple from its own web UI as normal.

---

## 22. NetHunter Store

**Purpose:** Install/update purpose-built security apps (telemetry-stripped F-Droid fork).

**Procedure**
1. Open the **NetHunter Store** client → search/install (e.g., cSploit, Shodan, Router Keygen, RF tools).
2. Update installed apps before each engagement.

**Note:** The store button may not flip to "installed" - ignore the cosmetic bug.

---

## 23. Post-Engagement Teardown & Evidence Handling

- [ ] Stop **all** services (Kali Services), APs (WifiPumpkin), captures, and KeX.
- [ ] Revert **USB Arsenal** to a benign gadget mode.
- [ ] Restore original **MAC** if spoofed.
- [ ] Collect and hash all artifacts (captures, payloads, logs):
  ```bash
  cd ~/engagements/<client>-<date>/ && sha256sum * > SHA256SUMS
  ```
- [ ] Encrypt and exfil the engagement folder to your reporting box; **delete payloads/creds from the phone** per data-handling policy.
- [ ] Note any spoofed MACs, SSIDs/BSSIDs, and PINs/keys recovered in the report.
- [ ] Power down radios; return device to a clean baseline.

---

## 24. Troubleshooting Quick Reference

| Symptom | First checks |
|---|---|
| HID/BadUSB does nothing | Wrong **USB Arsenal** gadget mode; wrong keyboard layout; cable is charge-only |
| No monitor mode / injection | Internal chipset limits - use external adapter; verify with `airmon-ng`, `iw dev` |
| Chroot won't start | Re-open Chroot Manager; check storage; reboot; verify kernel string with `uname -a` |
| Metasploit DB errors | Start **PostgreSQL** in Kali Services; `msfdb init` |
| KeX black screen | Restart KeX server; re-enter VNC password; check resolution setting |
| Adapter not detected | Reseat OTG; check power (use Y-cable); `dmesg | tail` for USB errors |
| Tools slow / OOM | Close KeX/background sessions; use `tmux`; watch battery/thermals |

---

## Appendix A - External Wi-Fi Adapters (recommended for injection)

Internal OnePlus 6 Wi-Fi injection is limited/inconsistent. For reliable monitor mode + injection, use a known-good external adapter over OTG:

- **Atheros AR9271** (2.4 GHz) - rock-solid, widely supported.
- **Realtek RTL8812AU / RTL8811AU** (2.4/5 GHz) - needs the `8812au` driver; good dual-band.
- **MediaTek MT7612U / MT7610U** - strong 5 GHz support.
- **RT3070/RT5370** - reliable 2.4 GHz budget option.

Power draw matters on a phone - use a powered OTG/Y-cable for high-power adapters or long ops.

## Appendix B - Engagement Folder Layout (suggested)

```
~/engagements/<client>-<YYYYMMDD>/
├── RoE.pdf
├── scope.txt              # in-scope IPs / SSIDs / BSSIDs / MACs
├── nmap/
├── captures/              # pcap, hashes
├── payloads/
├── loot/                  # creds, keys (encrypt!)
├── notes.md
└── SHA256SUMS
```

---

*End of document - v1.0. Update the version and re-verify Section 1 after any NetHunter or kernel update.*

## Related Files
- [Rooting.md](Rooting.md) - Prerequisite: bootloader unlock, LineageOS, TWRP, and Magisk root setup
- [Kali_NetHunter.md](Kali_NetHunter.md) - NetHunter installation guide this SOP builds on
- [../README.md](../README.md) - Mobile section index
- [../../Scripts/Bash/BashBunny/README.md](../../Scripts/Bash/BashBunny/README.md) - Bash Bunny payloads (DuckHunter-compatible DuckyScript)
- [../../Tradecraft/c2-frameworks.md](../../Tradecraft/c2-frameworks.md) - C2 frameworks for post-exploitation after NetHunter initial access
