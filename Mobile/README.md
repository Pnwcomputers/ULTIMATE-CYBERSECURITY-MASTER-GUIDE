# 📱 Mobile Security

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

## 📂 Existing Mobile Content

### OnePlus 6 / Kali NetHunter (Device-Specific)
| File | Description |
|------|-------------|
| [OnePlus_A3006/Rooting.md](OnePlus_A3006/Rooting.md) | Phase-by-phase guide: bootloader unlock, dtbo flash, LineageOS 22.2 install, TWRP, and Magisk root on the OnePlus 6 A3006 |
| [OnePlus_A3006/Kali_NetHunter.md](OnePlus_A3006/Kali_NetHunter.md) | Install and configure Kali NetHunter on the OnePlus 6 - prerequisites, install methods (Magisk module or TWRP), post-install setup, app selection |
| [OnePlus_A3006/Nethunter_SOP.md](OnePlus_A3006/Nethunter_SOP.md) | Field SOPs for all NetHunter modules: HID, BadUSB, WifiPumpkin, Bluetooth Arsenal, Wardriving, Nmap, Metasploit, KeX, and teardown checklist |

### Checklists
| File | Description |
|------|-------------|
| [Checklists/Android-Applications-Checklist.md](../Checklists/Android-Applications-Checklist.md) | 8-item Android APK triage checklist - manifest, WebView, certificate pinning, rooting detection, obfuscation, payload injection. OWASP MASTG-aligned. |

### Scripts
| File | Description |
|------|-------------|
| [Scripts/Python/iphone_messages.py](../Scripts/Python/iphone_messages.py) | Extract SMS/iMessage content from an iOS backup SQLite file |
| [Scripts/Python/iphone_finder.py](../Scripts/Python/iphone_finder.py) | Detect iPhones via WiFi OUI sniffing + Bluetooth MAC derivation (Scapy) |

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
| [iExplorer](https://macroplant.com/iexplorer) | Browse iOS filesystem (macOS) | GUI tool |
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
   - frida -U -f com.target.app --codeshare nowsecure/frida-ios-dump
   - objection -g com.target.app explore
   - objection > ios sslpinning disable
   - objection > ios hooking list classes

4. Network Traffic
   - Install Burp CA in Settings → General → Profile
   - Set Burp proxy on device WiFi
   - For pinned apps: use SSL Kill Switch 2 or Frida ssl_logger

5. Report
   - Map to OWASP MASVS controls
```

---

## 📋 Suggested Future Content

The following files would round out this section. Each represents a genuine gap in the current guide:

### High Priority
| File | Content |
|------|---------|
| `Mobile/android_pentest.md` | Full Android assessment guide: APKTool workflow, Frida/Objection cheat sheet, Drozer module commands, Burp + Android proxy setup, emulator setup (AVD + root), common vulnerability PoCs (exported activities, content providers, deeplinks) |
| `Mobile/ios_pentest.md` | Full iOS assessment guide: IPA extraction, class-dump, Frida on iOS, SSL pinning bypass techniques (Objection, SSL Kill Switch 2, Frida scripts), Keychain dumping, jailbreak options (palera1n, checkra1n) |
| `Mobile/mobile_forensics.md` | iOS and Android forensics: iOS backup structure and key SQLite files (SMS, call history, locations, app data), Android ADB extraction, Cellebrite-style manual extraction paths, timeline reconstruction |

### Medium Priority
| File | Content |
|------|---------|
| `Mobile/mobile_opsec.md` | Mobile OPSEC: burner phone setup, GrapheneOS/CalyxOS for operational security, airplane mode vs. Faraday bag, location data risks (cell towers, WiFi geolocation, Bluetooth), Signal configuration |
| `Mobile/mdm_security.md` | Mobile Device Management (MDM) security: MDM enrollment bypass, profile inspection, MDM command interception, detecting over-privileged MDM profiles |
| `Mobile/mobile_malware.md` | Mobile malware analysis: Android APK static malware analysis workflow, common malware families (banking trojans, stalkerware), deobfuscation of packed APKs, iOS malware (very rare - known cases) |

### Lower Priority / Future
| File | Content |
|------|---------|
| `Mobile/bluetooth_attacks.md` | Bluetooth attack reference: BLE sniffing (Wireshark + nRF52840), BLUFFS/BIAS/KNOB attacks, BLE GATT enumeration with gatttool/gattacker, BlueBorne, AirDrop OPSEC |
| `Mobile/android_checklist_extended.md` | Extended Android checklist: full OWASP MASTG test cases organized by MASVS category (MASVS-STORAGE, MASVS-NETWORK, MASVS-AUTH, MASVS-CODE, MASVS-RESILIENCE) |

---

## Related Files
- [../Checklists/Android-Applications-Checklist.md](../Checklists/Android-Applications-Checklist.md) - Android APK triage checklist
- [../Checklists/README.md](../Checklists/README.md) - Checklists section index
- [../Scripts/Python/iphone_messages.py](../Scripts/Python/iphone_messages.py) - iOS backup message extractor
- [../Scripts/Python/iphone_finder.py](../Scripts/Python/iphone_finder.py) - iPhone WiFi/Bluetooth detection script
- [../OPSEC/OPSEC_guide.md](../OPSEC/OPSEC_guide.md) - OPSEC practices relevant to mobile usage
- [../HardwareHacking/README.md](../HardwareHacking/README.md) - Hardware hacking including embedded/IoT (overlaps with mobile hardware attacks)
- [../Documentation/wireshark.md](../Documentation/wireshark.md) - Wireshark for Bluetooth/WiFi packet capture used in mobile testing
