# Kali NetHunter on OnePlus 6 A3006 / "Enchilada"
### Overview & Setup Guide

_Last verified against Kali's official docs, July 2026 (current release: NetHunter 2026.2)._

This guide assumes you're starting from where you are now: bootloader unlocked, TWRP installed, Magisk root working. It covers what NetHunter actually is, the OnePlus-6-specific prerequisite you need to check first, installing the image, and post-install configuration (updates, apps, auto-starting services).

---

## 1. What Kali NetHunter Is

NetHunter is Kali Linux's mobile penetration testing platform. On a rooted Android device like yours it runs as an overlay: a full Kali filesystem ("chroot") living alongside Android, controlled through the **NetHunter app**. That app is the control panel for everything — starting/stopping Kali services, launching attack tools (HID, BadUSB, Bluetooth Arsenal, Wardriving, MITM, etc.), and getting a Kali terminal.

There's a second, different product called **NetHunter Pro**, which replaces Android's kernel entirely and boots straight into full desktop Kali (no root/TWRP needed, uses an A/B boot-slot swap instead). It's supported on the OnePlus 6 too, but it's a different install path than what's below. Since you're already rooted with TWRP, standard NetHunter is the natural fit and is what this guide covers. NetHunter Pro is mentioned briefly at the end for completeness.

---

## 2. Important OnePlus-6-Specific Prerequisite: LineageOS Required

This is the detail most guides gloss over and the one most likely to trip you up: **the current official Kali NetHunter image for the OnePlus 6/6T is built against LineageOS, not stock OxygenOS.**

Per Kali's official pre-built image list, the OnePlus 6/6T entry is:

- Codename: `oneplus6`
- Base ROM: LineageOS 19.1 or LineageOS 22.2
- Current downloadable image: `kali-nethunter-2026.2-oneplus6-los-fifteen-full.zip` (LineageOS 22.2 / Android 15 base, full rootfs, ~1.9 GiB)

If your phone is currently on stock OxygenOS (even rooted/TWRP'd), you need to flash LineageOS 22.2 first — the NetHunter kernel/overlay is built specifically for that base. If you're already running LineageOS on the A3006, you're set.

Check your current ROM: **Settings → About phone**. If it says OxygenOS, flash LineageOS 22.2 for OnePlus 6 (enchilada) before continuing (standard LineageOS install via TWRP — download the LineageOS build for `enchilada`, flash it, then re-flash Magisk if you want root preserved on top of it).

---

## 3. Installation

### 3.1 Prerequisites checklist
_[OnePlus 6 A3006 Rooting Guide:](/Rooting.md)_

- Bootloader unlocked ✅ (already done)
- TWRP installed ✅ (already done)
- Magisk root ✅ (already done)
- Running LineageOS 22.2 (Android 15) on the OnePlus 6 — confirm per Section 2
- Developer Mode + USB Debugging enabled (Settings → About phone → tap Build number 7×, then Developer options → enable Advanced Reboot and Android Debugging)
- **Disable_Dm-Verity_ForceEncrypt** flashed and data partition formatted. This is called out as "Important" specifically for the OnePlus 6/6T image. Without it, Magisk can't properly handle an encrypted data partition, which breaks things like SSH ("Required key not available" errors).
- Battery reasonably charged, screen-awake settings adjusted (Android will kill background installs if the screen locks mid-flash)

### 3.2 Download the image

Get `kali-nethunter-2026.2-oneplus6-los-fifteen-full.zip` from the official NetHunter download page: https://www.kali.org/get-kali/#kali-mobile (or directly via https://kali.download/nethunter-images/current/). Verify the file isn't corrupted (compare checksum/torrent if you want extra assurance on the ~1.9 GiB download).

Transfer the zip to your phone's internal storage.

### 3.3 Install — two supported methods

**Method A: Magisk module (current recommended method)**

1. Open Magisk → Modules → Install from storage → select the NetHunter zip.
2. Keep the screen awake during install (Android may kill the installer if the screen locks).
3. Reboot.

**Method B: TWRP recovery flash (older, more mature, requires reboot to recovery)**

1. Reboot into TWRP.
2. Flash the NetHunter zip like any other TWRP zip.
3. Reboot to system.

Either method is fine on your setup since you already have both TWRP and Magisk; the Magisk module route is what Kali currently calls out as "the new and recommended method."

### 3.4 First boot

1. Launch the **NetHunter app**. It will finish setting up the chroot on first run.
2. **Update the NetHunter app from the NetHunter Store immediately after flashing.** This is flagged as "Important" specifically for the OnePlus 6/6T image — Android's scoped storage changes broke the app's original config storage location, and updating the app is the workaround until Kali fully migrates it.
3. Default Kali root password is `toor` (or `kali`/`1234` on some rootfs variants) — **change this before enabling any remote access** (see Section 5).

---

## 4. Post-Install Configuration

### 4.1 Keeping it updated

From a NetHunter terminal (or via the app's terminal tool), run:

```
sudo apt update && sudo apt upgrade -y && sudo apt dist-upgrade -y
```

Do this regularly — it pulls the latest tool versions and security patches into your Kali chroot, separate from Android's own update cycle.

For managing the chroot itself (not just packages), use the **NetHunter Chroot Manager** inside the app. It can download/reinstall the chroot, back it up, restore it, or remove it entirely — useful if an update ever breaks something and you need to roll back.

Back up your chroot periodically:

```
tar -cJf kali-arm64.tar.xz kali-arm64 && mv kali-arm64.tar.xz storage/downloads
```

(Stop any running NetHunter sessions first.)

### 4.2 Apps and tool packages to install

**Kali metapackages** (installed via `apt install <name>` inside the chroot, or via the Chroot Manager's metapackage option):

- `kali-nethunter` — already included by default; contains everything needed to run NetHunter. Don't add extra metapackages unless you actually need them, especially if storage is tight.
- `kali-linux-default` — the broader default toolset from Kali's standard desktop images, if you want the full "normal Kali" tool selection.
- `kali-linux-nethunter` — mobile-pentest-specific tools if not already pulled in.

**NetHunter Store apps** worth grabbing (install via the NetHunter App Store — `store.nethunter.com` — either through the store app or by sideloading APKs):

- **NetHunter KeX** — gives you a full Kali desktop GUI (XFCE) over VNC, useful when you want a real Linux desktop rather than just a terminal.
- **Bluetooth Arsenal** — recon, spoof, and eavesdrop on nearby Bluetooth devices.
- **Wardriving** — merges GPS + wireless radios into Kismet for geotagged RF/Wi-Fi mapping.
- **DuckHunter HID / HID Keyboard Attacks** — Rubber Ducky-style keystroke injection.
- **BadUSB MITM Attack** — USB-based man-in-the-middle.
- **NMap Scan** — quick Nmap front-end.
- **Metasploit Payload Generator (MPG)** — generate MSF payloads on the fly.
- **SearchSploit** — offline Exploit-DB search.
- **WifiPumpkin** — rogue AP with captive portal.
- **Hacker's Keyboard** — not a Kali tool, but strongly recommended for anyone using a terminal on a touchscreen (adds proper arrow/Ctrl/Esc/Tab keys).

Install only what you'll actually use — each tool set adds storage and, for wireless attack tools, depends on your Wi-Fi/BT chipset actually supporting monitor mode/injection (check Kali's Wireless Cards and NetHunter compatibility notes if a specific attack won't work — chipset support varies).

### 4.3 Auto-starting services on boot

Open the NetHunter app → **Kali Services** pane. This tab lets you start/stop chrooted services (SSH, Apache/HTTP, OpenVPN, etc.) and — critically — has a toggle to **enable each service at boot time**, so e.g. SSH comes up automatically every time the phone boots instead of you having to open the app and tap Start manually.

Before enabling any service at boot:

1. **Change the default Kali password first** (`passwd` in the chroot terminal). Kali ships with a well-known default password and the docs explicitly warn against exposing remote access before changing it.
2. Only enable auto-start for services you'll actually use — every enabled service is a listening port on your phone whenever it's on.

For anything beyond the built-in service toggles — custom scripts, one-tap tool launches, etc. — use the **NetHunter Custom Commands** tab. It lets you define your own buttons/commands (e.g., a one-tap Wifite launch or a scripted mfoc card-clone command) beyond the few examples it ships with.

---

## 5. Quick Reference / Gotchas

- **Change the default root password** (`toor`/`kali`) before enabling SSH or any other remote service.
- **Update the NetHunter app right after flashing** — required workaround for Android scoped-storage issues on this device.
- **Data partition must not be encrypted** — flash the DM-Verity/ForceEncrypt disabler and format data before installing, or Magisk/SSH will throw key errors.
- Wireless attack tools (injection, monitor mode) depend on your Wi-Fi chip's driver support — not every attack works out of the box on every device/kernel combo.
- Keep the chroot backed up via Chroot Manager before major `apt` upgrades, in case something breaks.

---

## 6. Alternative: NetHunter Pro (for reference)

If you ever want a completely different experience — a real Linux desktop replacing Android rather than an overlay — NetHunter Pro is also built for the OnePlus 6 (Snapdragon 845 platform, shared with the PinePhone Pro builds). It doesn't need root, TWRP, or Magisk: it uses fastboot to flash a Kali boot image and rootfs to an alternate boot slot (`fastboot flash boot_b ...`, `fastboot flash linux ...`, then `fastboot erase dtbo_b`), letting you dual-boot between Android and full Kali. This is a much more involved, different setup than what's documented above, and would replace (or dual-boot alongside) your current rooted-Android NetHunter setup rather than complementing it.

---

### Sources

- [Installing Kali NetHunter](https://www.kali.org/docs/nethunter/installing-nethunter/)
- [Kali NetHunter Pre-created Images](https://nethunter.kali.org/images.html)
- [NetHunter Kali Services](https://www.kali.org/docs/nethunter/nethunter-kali-services/)
- [NetHunter Chroot Manager](https://www.kali.org/docs/nethunter/nethunter-chroot-manager/)
- [NetHunter Custom Commands](https://www.kali.org/docs/nethunter/nethunter-custom-commands/)
- [Kali Linux Metapackages](https://www.kali.org/docs/general-use/metapackages/)
- [Kali NetHunter Pro](https://www.kali.org/docs/nethunter-pro/)
- [Kali NetHunter download index](https://kali.download/nethunter-images/current/)
- [NetHunter App Store](https://store.nethunter.com/packages/)
- [Kali NetHunter Pro guide for OnePlus 6/6T (community)](https://github.com/PhucHauDeveloper/Kali-nethunter-pro-for-OnePlus-6-6T)
