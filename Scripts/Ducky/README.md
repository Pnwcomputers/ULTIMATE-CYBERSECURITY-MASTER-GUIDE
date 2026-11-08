# USB Rubber Ducky Script Compilation Guide


## Firmware Catalog & Installers

| Resource | Description |
|---|---|
| [ESP32 & Related Firmware Catalog](../../HardwareHacking/esp32-security-firmware-catalog.md) | Primary upstream projects, supported targets, use-cases & dated activity notes |
| [Firmware Web Flashers](../../HardwareHacking/firmware-web-flashers.md) | Dedicated installers plus a separate multi-device/multi-firmware reference |

## 🎯 Purpose
USB Rubber Ducky DuckyScript compilation guide - covers writing, compiling, and deploying DuckyScript payloads for the Hak5 USB Rubber Ducky keyboard emulation attack platform for authorized red team engagements.

## ⚙️ Function
Covers: DuckyScript syntax (DELAY, STRING, ENTER, CTRL, ALT, GUI, MOD), payload compilation with PayloadStudio, inject.bin deployment to the device, common payload patterns (credential harvesting, reverse shell, data exfil), and multi-stage payload structuring.

## 🏆 Goal
Enable authorized red team practitioners to compile and deploy DuckyScript payloads for physical access security assessments using the USB Rubber Ducky.

## 📋 When To Use
- Writing DuckyScript payloads for an authorized physical access engagement
- Compiling existing payload scripts into inject.bin format
- Troubleshooting payload timing issues (DELAY adjustments for slow targets)

## Overview
**Different HID hardware:** [M5StickC Plus2 / HackStarterPack](../../HardwareHacking/m5stickc-plus2-hackstarterpack.md) requires a compatible external HID accessory and untrusted script review; it is not a Hak5 inject.bin substitute.


These DuckyScript payloads are designed for the USB Rubber Ducky by Hak5. They must be compiled into `inject.bin` format before deployment.

## Compilation Methods

### Method 1: Hak5 Payload Studio (Recommended)
The easiest way to compile DuckyScript payloads.

1. **Visit**: https://payloadstudio.hak5.org/
2. **Paste** your `.txt` DuckyScript into the editor
3. **Select** your Ducky model:
   - USB Rubber Ducky (Original)
   - USB Rubber Ducky (2022+)
4. **Click** "Compile"
5. **Download** the `inject.bin` file

### Method 2: Legacy Offline Encoders (Model-specific)

Some original USB Rubber Ducky generations used the Java-based `duckencoder.jar`. This is **not** a general installer for all models and may not compile modern DuckyScript features. For any legacy device, get the correct encoder from a verified vendor-maintained release and check its checksum, language/layout support and documentation. Use the official [Hak5 Payload Studio](https://payloadstudio.hak5.org/) for contemporary devices.

Do **not** use `wget https://payloadstudio.com/` as an installation command; that is a website URL, not a verified encoder binary. Do not assume a text script can be deployed as `inject.bin` to a different HID platform, including the external CH9329 accessory for M5StickC Plus2.

### Verify A Harmless Payload Before Deployment

Use a **sacrificial offline device** with a blank editor and a short fixed phrase, not a shell command. Confirm firmware/model, payload syntax generation, keyboard layout, expected execution time, consent and cleanup. Avoid importing unreviewed payloads or using third-party script-conversion websites for client data.

## Deployment

### USB Rubber Ducky Setup
1. **Insert** microSD card into your computer
2. **Copy** `inject.bin` to the **root** of the SD card
3. **Safely eject** the SD card
4. **Insert** SD card into USB Rubber Ducky
5. **Plug** Rubber Ducky into target system

### File Structure
```
/
├── inject.bin          # Your compiled payload (REQUIRED)
├── config.txt          # Optional configuration
└── switch.txt          # Multi-payload configuration (optional)
```

## Keyboard Layouts

DuckyScript supports multiple keyboard layouts. If your target system uses a non-US keyboard:

**Common Layouts:**
- `us` - US English (default)
- `uk` - UK English
- `de` - German
- `fr` - French
- `es` - Spanish
- `it` - Italian

**Specify the keyboard layout in Payload Studio's language selector** when compiling (the standalone `duckencoder.jar` CLI referenced in older guides has been discontinued - see Method 2 above).

## Testing & Debugging

### Test Environment
**Always test payloads in a controlled environment:**
- Virtual machine (VMware, VirtualBox)
- Test computer with no sensitive data
- Sandbox environment

### Common Issues

**Payload not executing:**
- ✓ Verify `inject.bin` is in SD card root
- ✓ Check SD card is properly formatted (FAT32)
- ✓ Ensure Ducky has power (LED should flash)

**Commands typing incorrectly:**
- ✓ Wrong keyboard layout selected
- ✓ Increase `DELAY` values if system is slow
- ✓ Check for special characters in script

**Payload timing out:**
- ✓ Increase initial `DELAY` (system boot time)
- ✓ Add more delays between commands
- ✓ Some systems need 3-5 seconds before Ducky is recognized

## Syntax Quick Reference
```duckyscript
REM Comment - not executed
DELAY 1000          # Wait 1000ms (1 second)
DEFAULTDELAY 100    # Set default delay between keystrokes

GUI r               # Windows + R
CTRL ALT DELETE     # Key combinations
ENTER               # Press Enter
STRING text here    # Type text

ALT F4              # Alt + F4
SHIFT a             # Shift + a (uppercase A)
```

## Best Practices

### 1. Add Delays Appropriately
- Initial delay: `DELAY 2000` minimum (system recognition)
- Between commands: `DELAY 500-1000` (execution time)
- After opening apps: `DELAY 2000-3000` (load time)
- Long operations: `DELAY 5000+` (searches, installs)

### 2. Error Handling
- Assume target system may be slower than expected
- Test on various system speeds
- Add conservative delays for production use

### 3. Documentation
- Include clear comments with `REM`
- Document target OS and version
- List prerequisites (admin rights, etc.)
- Note expected execution time

### 4. Version Control
```duckyscript
REM =============================================
REM Title: Payload Name
REM Author: Your Name
REM Version: 1.0
REM Target: Windows 10/11
REM Description: What this payload does
REM =============================================
```

## Security & Ethics

### ⚠️ Important Legal Notice

**These tools are for AUTHORIZED use only:**
- ✓ Personal systems you own
- ✓ Systems you have written permission to test
- ✓ Professional penetration testing with contracts
- ✓ Educational environments with explicit authorization

**NEVER use on:**
- ✗ Systems you don't own
- ✗ Systems without explicit written permission
- ✗ Public computers
- ✗ Any system without authorization

**Unauthorized access to computer systems is illegal** under:
- Computer Fraud and Abuse Act (CFAA) - USA
- Computer Misuse Act - UK
- Similar laws in virtually all countries

### Professional Use
For legitimate IT/security work:
1. **Always obtain written authorization** before testing
2. **Document** all activities and findings
3. **Secure** payloads and results appropriately
4. **Follow** responsible disclosure practices

<a id="companion-usb-hid-research-different-firmware-and-build-process"></a>
## Companion USB Hid Research (Different Firmware & Build Process)

[Pico WiFi Duck](https://github.com/majdsassi/Pico-WIFI-Duck) explores Wi-Fi-controlled HID emulation using a Raspberry Pi Pico W. It is **not Hak5 USB Rubber Ducky hardware**; this guide's DuckyScript, `inject.bin`, device setup and supported commands cannot be assumed compatible. Use a disposable test host, restrict wireless access, and do not reuse old linked firmware downloads without verifying the source and release integrity.

## Resources

- **Hak5 Forums**: https://forums.hak5.org/
- **Official Docs**: https://documentation.hak5.org/hak5-usb-rubber-ducky/
- **Payload Library**: https://github.com/hak5/usbrubberducky-payloads
- **DuckyScript Docs**: https://documentation.hak5.org/hak5-usb-rubber-ducky/duckyscript-tm-quick-reference

## Support

For issues or questions:
- Check Hak5 documentation first
- Search Hak5 forums for similar issues
- Review payload syntax carefully
- Test in VM before production use

## Contributing

When submitting payloads to this repository:
1. Test thoroughly on target OS
2. Include clear documentation
3. Follow naming conventions
4. Add comments explaining each section
5. List all requirements and dependencies

---

**Pacific NW Computers**

*Always use these tools ethically and legally.*

## Related Files
- [../README.md](../README.md) - Scripts section index
- [../Bash/BashBunny/README.md](../Bash/BashBunny/README.md) - Bash Bunny: full multi-function USB attack platform
- [../../Documentation/LinuxCheatSheet.md](../../Documentation/LinuxCheatSheet.md) - Linux commands used in payloads
- [../../Mobile/mobile_pentest_sop.md](../../Mobile/mobile_pentest_sop.md) - Mobile pentest SOP (NetHunter DuckHunter runs DuckyScript from your phone)
- [../../Mobile/OnePlus_A6003/Nethunter_SOP.md](../../Mobile/OnePlus_A6003/Nethunter_SOP.md) - NetHunter DuckHunter HID module SOP

---

[Section Index](../README.md) | [Master Index](../../README.md) | [Legal Notice](../../LEGAL.md)
