# 📱 Mobile Security

<div align="center">

**Mobile penetration testing, device security, forensics, and authorized attack platforms**

*Part of the [ULTIMATE CYBERSECURITY MASTER GUIDE](../README.md)*

[![NetHunter](https://img.shields.io/badge/Kali-NetHunter-blue?style=for-the-badge)]()
[![Android](https://img.shields.io/badge/Android-Security-green?style=for-the-badge)]()
[![iOS](https://img.shields.io/badge/iOS-Forensics-lightgrey?style=for-the-badge)]()

</div>

---

## 🎯 Purpose
Mobile security reference covering device preparation (rooting, custom ROM), mobile pentesting platforms (Kali NetHunter), Android/iOS app security assessment, mobile forensics, and device OSINT. Currently focused on the OnePlus 6 A3006 as the primary NetHunter attack platform.

## ⚙️ Function
Covers: OnePlus 6 rooting workflow (bootloader unlock, LineageOS, TWRP, Magisk), Kali NetHunter install and configuration, field SOPs for NetHunter attack modules (HID, BadUSB, WifiPumpkin, Bluetooth Arsenal, Wardriving), Android APK assessment, iOS backup forensics, and mobile device OSINT tools.

## 🏆 Goal
Enable practitioners to build and operate a capable mobile pentesting platform (NetHunter on OnePlus 6), conduct authorized Android and iOS app assessments, and perform forensic or OSINT tasks against mobile devices.

## 📋 When to Use
- Setting up or maintaining the OnePlus 6 NetHunter device
- Running a NetHunter-based engagement (HID, Evil AP, Wardriving, etc.)
- Conducting an authorized Android or iOS app penetration test
- Performing iOS backup forensics or mobile device OSINT

---

## 📋 Table of Contents

- [Overview](#overview)
- [Current Content](#current-content)
- [Mobile Pentesting Toolchain](#mobile-pentesting-toolchain)
- [Testing Methodology Overview](#testing-methodology-overview)
- [Suggested Future Content](#suggested-future-content)
- [Security & Legal Disclaimer](#security--legal-disclaimer)
- [Contributing](#contributing)
- [Resources](#resources)

---

## 🎯 Overview

This directory contains **mobile security resources for penetration testers, forensic investigators, and security researchers** - from device preparation and platform setup through offensive tooling, app security assessment, and forensic analysis.

**What You'll Find Here:**
- 📱 OnePlus 6 rooting and custom ROM installation guides
- 🐉 Kali NetHunter setup, configuration, and field SOPs
- 🤖 Android application security assessment checklists
- 🍎 iOS backup forensics scripts
- 📡 Mobile device OSINT tools (WiFi/Bluetooth enumeration)
- 🔧 Mobile pentesting toolchain reference (MobSF, Frida, Objection, APKTool)
- 📋 Assessment methodology for Android and iOS apps (OWASP MASTG-aligned)

### Purpose

These guides serve as:
- **Platform setup references** for building and maintaining the NetHunter attack device
- **Field SOPs** for operating NetHunter modules during authorized engagements
- **Assessment methodology** for Android and iOS app security reviews
- **Forensic references** for iOS backup extraction and analysis
- **OSINT tools** for mobile device enumeration and investigation

---

## 📂 Current Content

### OnePlus 6 / Kali NetHunter (Device-Specific)

| File | Description | Status |
|------|-------------|--------|
| **[OnePlus_A3006/Rooting.md](OnePlus_A3006/Rooting.md)** | Phase-by-phase: bootloader unlock, dtbo flash, LineageOS 22.2 install via sideload, TWRP install (temporary-boot method), and Magisk root via boot image patching | ✅ Complete |
| **[OnePlus_A3006/Kali_NetHunter.md](OnePlus_A3006/Kali_NetHunter.md)** | NetHunter install (Magisk module or TWRP), LineageOS prerequisite, post-install config, metapackage and app selection, chroot management | ✅ Complete |
| **[OnePlus_A3006/Nethunter_SOP.md](OnePlus_A3006/Nethunter_SOP.md)** | Field SOPs for all NetHunter modules: HID, DuckHunter, BadUSB, WifiPumpkin, WPS attacks, Bluetooth Arsenal, Wardriving, SET, Nmap, Metasploit, KeX, MAC changer, CARsenal, teardown checklist | ✅ Complete |

### Checklists

| File | Description | Status |
|------|-------------|--------|
| **[Checklists/Android-Applications-Checklist.md](../Checklists/Android-Applications-Checklist.md)** | 8-item Android APK triage: manifest review, WebView, certificate pinning, rooting detection, obfuscation, payload injection. OWASP MASTG-aligned. | ✅ Complete |

### Scripts

| File | Description | Status |
|------|-------------|--------|
| **[Scripts/Python/iphone_messages.py](../Scripts/Python/iphone_messages.py)** | Extract SMS/iMessage content from an iOS backup directory (SQLite-based) | ✅ Complete |
| **[Scripts/Python/iphone_finder.py](../Scripts/Python/iphone_finder.py)** | Detect nearby iPhones via WiFi OUI sniffing and Bluetooth MAC derivation using Scapy | ✅ Complete |

---

## 🗺️ Mobile Pentesting Toolchain

### Android
| Tool | Purpose | Install |
|------|---------|---------|
| [MobSF](https://github.com/MobSF/Mobile-Security-Framework-MobSF) | Automated static + dynamic analysis framework | `docker run -it -p 8000:8000 opensecurity/mobile-security-framework-mobsf` |
| [APKTool](https://apktool.org/) | Decompile/recompile APKs | `sudo apt install apktool` |
| [jadx](https://github.com/skylot/jadx) | APK to Java source decompiler | `sudo apt install jadx` |
| [Frida](https://frida.re/) | Dynamic instrumentation toolkit | `pip install frida-tools` |
| [Objection](https://github.com/sensepost/objection) | Runtime mobile exploration (Frida-based) | `pip install objection` |
| [Drozer](https://github.com/WithSecureLabs/drozer) | Android attack surface analyzer | `pip install drozer` |
| [Burp Suite](https://portswigger.net/burp) | HTTP/HTTPS proxy for traffic interception | Configure Android to use Burp CA |
| [apksigner](https://developer.android.com/tools/apksigner) | Sign repackaged APKs | Included in Android SDK build-tools |

### iOS
| Tool | Purpose | Notes |
|------|---------|-------|
| [libimobiledevice](https://libimobiledevice.org/) | Interact with iOS devices over USB | `sudo apt install libimobiledevice-utils` |
| [idevicebackup2](https://man.archlinux.org/man/idevicebackup2.1) | Create/restore iOS backups | Part of libimobiledevice |
| [Frida on iOS](https://frida.re/docs/ios/) | Dynamic instrumentation (requires jailbreak or sideload) | Works with checkra1n/palera1n |
| [Burp Suite on iOS](https://portswigger.net/burp/documentation/desktop/mobile) | HTTPS interception | Install Burp CA via Safari |
| [SSL Kill Switch 2](https://github.com/nabla-c0d3/ssl-kill-switch2) | Disable SSL pinning system-wide | Requires jailbreak |

---

## 🔬 Testing Methodology Overview

### Android App Assessment (OWASP MASTG Order)

```
1. Reconnaissance
   - Download APK (APK Mirror, Google Play via gplaydl, direct from device)
   - Identify app version, permissions, target SDK

2. Static Analysis
   - apktool d target.apk          # Decompile resources + smali
   - jadx -d output/ target.apk    # Java source decompile
   - Review AndroidManifest.xml    # Permissions, exported components, debuggable flag
   - grep -r "http://" ./          # Plaintext URLs
   - grep -r "api_key\|secret\|password" ./  # Hardcoded secrets

3. Dynamic Analysis (rooted device or emulator)
   - adb install target.apk
   - objection -g com.target.app explore
   - objection > android sslpinning disable
   - objection > android hooking list classes

4. Network Traffic
   - Configure Burp Suite proxy on device
   - Install Burp CA certificate
   - Intercept and modify HTTPS traffic

5. Report
   - Map findings to OWASP MASVS controls
   - Provide PoC screenshots/Burp captures
```

### iOS App Assessment (OWASP MASTG Order)

```
1. Reconnaissance
   - Obtain IPA (from device with ipainstaller, from developer, or via Frida dump)
   - unzip target.ipa && cd Payload/target.app

2. Static Analysis
   - otool -L target_binary        # Linked frameworks
   - strings target_binary | grep -i "key\|secret\|api\|http"
   - class-dump target_binary      # Objective-C class headers
   - Check Info.plist: NSAppTransportSecurity, permissions

3. Dynamic Analysis (jailbroken device)
   - objection -g com.target.app explore
   - objection > ios sslpinning disable
   - objection > ios hooking list classes

4. Network Traffic
   - Install Burp CA in Settings -> General -> Profile
   - Set Burp proxy on device WiFi
   - For pinned apps: use SSL Kill Switch 2 or Frida ssl_logger

5. Report
   - Map to OWASP MASVS controls
```

---

## 📋 Suggested Future Content

The following files would round out this section:

### High Priority
| File | Content |
|------|---------|
| `Mobile/android_pentest.md` | Full Android assessment guide: APKTool workflow, Frida/Objection cheat sheet, Drozer module commands, Burp + Android proxy setup, emulator setup (AVD + root), common vulnerability PoCs (exported activities, content providers, deeplinks) |
| `Mobile/ios_pentest.md` | Full iOS assessment guide: IPA extraction, class-dump, Frida on iOS, SSL pinning bypass techniques, Keychain dumping, jailbreak options (palera1n, checkra1n) |
| `Mobile/mobile_forensics.md` | iOS and Android forensics: iOS backup structure and key SQLite files (SMS, call history, locations, app data), Android ADB extraction, timeline reconstruction |

### Medium Priority
| File | Content |
|------|---------|
| `Mobile/mobile_opsec.md` | Mobile OPSEC: GrapheneOS/CalyxOS for operational security, airplane mode vs. Faraday bag, location data risks (cell towers, WiFi geolocation, Bluetooth), Signal configuration |
| `Mobile/mdm_security.md` | MDM security: enrollment bypass, profile inspection, MDM command interception, detecting over-privileged MDM profiles |
| `Mobile/mobile_malware.md` | Mobile malware analysis: Android APK static workflow, common families (banking trojans, stalkerware), deobfuscation of packed APKs |

### Lower Priority / Future
| File | Content |
|------|---------|
| `Mobile/bluetooth_attacks.md` | Bluetooth attack reference: BLE sniffing (Wireshark + nRF52840), BLUFFS/BIAS/KNOB attacks, BLE GATT enumeration with gatttool/gattacker |
| `Mobile/android_checklist_extended.md` | Extended Android checklist: full OWASP MASTG test cases organized by MASVS category (MASVS-STORAGE, MASVS-NETWORK, MASVS-AUTH, MASVS-CODE, MASVS-RESILIENCE) |

---

## ⚠️ Security & Legal Disclaimer

### 🔴 CRITICAL: Authorized Use Only

```
⚠️ LEGAL AND ETHICAL USE ONLY ⚠️

This section contains attack techniques and tools for:

✅ AUTHORIZED USES:
   - Penetration testing with explicit written authorization
   - Mobile device security assessments with client permission
   - Red team operations with organizational approval
   - Forensic investigations with proper legal authority
   - Security research in isolated lab environments
   - Blue team training and detection development
   - CTF competitions and authorized challenges
   - Educational purposes with proper supervision

🚫 STRICTLY PROHIBITED:
   - Attacking devices, apps, or networks without explicit written permission
   - Intercepting wireless communications without authorization
   - Installing unauthorized software on devices you don't own
   - Exceeding authorized scope of engagement
   - Using attack techniques for malicious purposes
   - Any illegal or unethical activities
```

---

### Legal Requirements for Mobile Security Testing

#### Written Authorization Requirements

**CRITICAL: ALWAYS obtain written authorization that explicitly includes:**
- Specific devices, apps, networks, and SSIDs in scope
- Testing methodology and techniques approved
- Time windows for testing activities
- Out-of-scope systems and explicit restrictions
- Emergency contact information and escalation procedures
- Data handling and confidentiality requirements
- Physical access authorization if HID/BadUSB is in scope
- RF activity authorization if Evil AP or deauth attacks are in scope

#### Applicable Laws

Mobile security testing intersects multiple legal frameworks:

- **Computer Fraud and Abuse Act (CFAA)** - unauthorized access to computers and networks
- **Electronic Communications Privacy Act (ECPA)** - interception of wireless communications
- **FCC Regulations** - RF transmissions and interference with licensed spectrum
- **State/Local Laws** - vary by jurisdiction; some states have stricter computer crime laws
- **International Laws** - GDPR (EU), Computer Misuse Act (UK), and equivalents apply when testing crosses borders

```
✅ IN SCOPE (With Explicit Authorization):
   - Devices and apps explicitly listed in engagement letter
   - Networks and SSIDs defined in written agreement
   - Specific techniques approved by client/device owner
   - Testing within authorized time windows

🚫 OUT OF SCOPE (Always):
   - Devices or networks not explicitly in scope
   - Production systems without change-window approval
   - RF attacks that could disrupt safety-critical systems
   - Any technique that could affect bystander devices
```

---

## 🤝 Contributing

To contribute to the Mobile section:

1. Follow the 4-header standard: `## 🎯 Purpose`, `## ⚙️ Function`, `## 🏆 Goal`, `## 📋 When to Use` after every H1
2. Add a `## Related Files` section at the bottom with bidirectional links
3. Use hyphens (-) not em-dashes
4. Verify all commands against the current tool version before adding
5. Include written authorization reminders for any offensive technique
6. For device-specific guides, note the exact firmware/OS version tested against

---

## 📚 Resources

### Official Documentation
- [Kali NetHunter Documentation](https://www.kali.org/docs/nethunter/)
- [OWASP Mobile Application Security (MASTG)](https://mas.owasp.org/MASTG/)
- [OWASP MASVS Controls](https://mas.owasp.org/MASVS/)
- [LineageOS Wiki - enchilada](https://wiki.lineageos.org/devices/enchilada/)
- [TWRP for OnePlus 6](https://twrp.me/oneplus/oneplus6.html)
- [Magisk Installation Guide](https://topjohnwu.github.io/Magisk/install.html)

### Mobile Pentesting Tools
- [MobSF](https://github.com/MobSF/Mobile-Security-Framework-MobSF) - Mobile Security Framework
- [Frida](https://frida.re/) - Dynamic instrumentation toolkit
- [Objection](https://github.com/sensepost/objection) - Runtime mobile exploration
- [APKTool](https://apktool.org/) - APK reverse engineering
- [jadx](https://github.com/skylot/jadx) - Java decompiler for APKs
- [Drozer](https://github.com/WithSecureLabs/drozer) - Android attack surface analyzer

### Learning Resources
- [OWASP MASTG Test Cases](https://mas.owasp.org/MASTG/tests/) - Comprehensive mobile test methodology
- [HackTricks - Android](https://book.hacktricks.xyz/mobile-pentesting/android-app-pentesting) - Android pentesting reference
- [HackTricks - iOS](https://book.hacktricks.xyz/mobile-pentesting/ios-pentesting) - iOS pentesting reference
- [NetHunter App Store](https://store.nethunter.com/) - NetHunter-specific app repository

---

## Related Files
- [../Checklists/Android-Applications-Checklist.md](../Checklists/Android-Applications-Checklist.md) - Android APK triage checklist
- [../Checklists/README.md](../Checklists/README.md) - Checklists section index
- [../Scripts/Python/iphone_messages.py](../Scripts/Python/iphone_messages.py) - iOS backup message extractor
- [../Scripts/Python/iphone_finder.py](../Scripts/Python/iphone_finder.py) - iPhone WiFi/Bluetooth detection script
- [../OPSEC/OPSEC_guide.md](../OPSEC/OPSEC_guide.md) - OPSEC practices relevant to mobile usage
- [../HardwareHacking/README.md](../HardwareHacking/README.md) - Hardware hacking (overlaps with mobile hardware attacks)
- [../Documentation/wireshark.md](../Documentation/wireshark.md) - Wireshark for Bluetooth/WiFi capture used in mobile testing
- [../Scripts/Bash/BashBunny/README.md](../Scripts/Bash/BashBunny/README.md) - Bash Bunny / DuckyScript payloads (DuckHunter-compatible)
