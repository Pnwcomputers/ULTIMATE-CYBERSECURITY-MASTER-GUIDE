# USB Rubber Ducky Script Compilation Guide


## Other HID Firmware: Select A Separate Workflow

The compilation instructions in this guide apply to the named Hak5 platform.
Choose a separate install/script workflow for other hardware; a text script,
CircuitPython project and compiled `inject.bin` are different artifacts.

| Resource | Role & Compatibility Boundary |
|---|---|
| [Pico-Ducky Lab](../../HardwareHacking/pico-ducky-lab.md) | Pico-family CircuitPython setup, setup jumper, payload.dd and fixed-text validation. |
| [ESP32 Bit Pirate](../../HardwareHacking/esp32-bit-pirate.md) | Supported S3 USB functions and protocol bench work; use project-specific commands. |
| [Bruce](../../Documentation/bruce_firmware.md) | Native USB or external-HID path depends on board; StickC USB-to-UART alone is not keyboard emulation. |
| [NEMO](../../Documentation/nemo-firmware.md) | USB interface analysis is distinct from scripted HID output and is not a malware verdict. |

## Firmware Catalog & Installers

| Resource | Description |
|---|---|
| [ESP32 & Related Firmware Catalog](../../Documentation/esp32-security-firmware-catalog.md) | Primary upstream projects, supported targets, use-cases & dated activity notes |
| [Firmware Web Flashers](../../Documentation/firmware-web-flashers.md) | Dedicated installers plus a separate multi-device/multi-firmware reference |

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

## Official & Community Payload Audit Workflow

The [official USB Rubber Ducky library](https://github.com/hak5/usbrubberducky-payloads) contains **source** `payload.txt`; current USB Rubber Ducky generations require a **compiled** `inject.bin`. The [Bash Bunny](../Bash/BashBunny/README.md#official--third-party-payload-library-controlled-installation) interprets its own Bash-based `payload.txt`, while the [WiFi Pineapple Pager](../../Wardriving/README.md#wifi-pineapple-pager--payloads-sideloading--defensive-labs) interprets its own `payload.sh`. **Do not cross-load files.** See [Hak5 format matrix](../../HardwareHacking/README.md#hak5-payload-ecosystem-official--side-loaded-code).

1. Pin the official/community payload source to an immutable commit and inspect every `DUCKY`, `GUI`, `STRING`, `DELAY`, keyboard-layout change, extension and staged command. Check that third-party payloads do **not** download unreviewed code or send client information.
2. Select the **correct** device generation and DuckyScript language compiler. Use [Hak5 Payload Studio](https://payloadstudio.hak5.org/) or an explicitly compatible verified offline compiler. Preserve source **and** compiler version/output hash.
3. Replace any imported script's effects with the harmless [fixed-marker exercise](#exercise-1--fixed-marker-first-successful-payload), and test only on an offline host with a blank text editor in focus. Check keyboard layout and initial delays.
4. Copy the resulting `inject.bin` via the supported model-specific storage/arming process; **a raw uncompiled script does not replace the device binary**.
5. On the client or lab host, record USB VID/PID **as observed**, device-control and EDR events, exact text emitted and any anomaly. Stop if unexpected app focus or privilege prompt appears.
6. Remove the script from shared media and restore the approved payload/configuration; preserve redacted evidence and source hashes.

**Example compatibility failure:** a legacy DuckyScript 1 encoder will not compile every modern DuckyScript 3 function. A configured keyboard layout may also change the meaning of punctuation or shortcuts. Successful compilation does not establish a safe payload—source review and isolated execution remain mandatory.

### Curated GitHub Payload Projects — Popularity, Compatibility & Trust

_Reviewed November 11, 2026. Popularity means **GitHub stars**, not a safety audit or an endorsement. Counts are rounded snapshots and can change. Links go to the original project, not a copied or modified payload._

| GitHub Project | Approx. Stars | Relationship To Hak5 USB Rubber Ducky | Review & Deployment Decision |
|---|---:|---|---|
| [hak5/usbrubberducky-payloads](https://github.com/hak5/usbrubberducky-payloads) | **6,200** | **Primary official** DuckyScript source, payloads, extensions and keyboard layouts | **Start here.** Community submissions are still provided AS-IS. Compile a specifically reviewed script for the correct Ducky generation with Hak5 Payload Studio. |
| [UndedInside/DuckyScriptPayloads](https://github.com/UndedInside/DuckyScriptPayloads) | 380 | Independent Windows/Linux/etc. DuckyScript examples; author primarily organized them for **Flipper Zero** | **Adapt and test.** Some syntax may compile on a compatible Ducky, but Flipper paths, delays, host assumptions and DuckyScript versions must be checked. |
| [atomiczsec/My-Payloads](https://github.com/atomiczsec/My-Payloads) | 410 | Multi-device collection covering **Rubber Ducky, Bash Bunny, Flipper and O.MG** | **Archived historical reference** (archived on GitHub; last source push in 2024). Do not assume current DuckyScript 3 support or maintained remote dependencies. |
| [UberGuidoZ/OMG-Payloads](https://github.com/UberGuidoZ/OMG-Payloads) | 270 | O.MG-cable payloads; author says some **might** work with Rubber Ducky | **Adapt only.** O.MG device commands, trigger/transport behavior and runtime are not interchangeable with a Ducky `inject.bin`. Source last pushed in 2023. |
| [I-Am-Jakoby/Flipper-Zero-BadUSB](https://github.com/I-Am-Jakoby/Flipper-Zero-BadUSB) | **7,200** | Very popular **Flipper Zero** BadUSB collection, not a native Hak5 USB Rubber Ducky release | **Research/reference only.** Many entries call external URLs, PowerShell, Discord/webhooks or enable data collection. Do not copy unreviewed examples or claim plug-and-play Ducky support. |
| [Dukweeno/Duckuino](https://github.com/Dukweeno/Duckuino) | 380 | Legacy DuckyScript-to-**Arduino** translator, **not a payload library for current Duckies** | **Historical portability tool**; project warns of unstable release behavior. Does not compile modern DuckyScript 3 to the Hak5 `inject.bin` format. |
| [toxydose/Duckyspark](https://github.com/toxydose/Duckyspark) | 230 | DuckyScript-to-**Digispark/Arduino** translator; different board and language support | **Alternative-device teaching reference**, not current Hak5 firmware or a modern Payload Studio replacement. |
| [dekuNukem/duckyPad](https://github.com/dekuNukem/duckyPad) | **1,300** | Open-source programmable **macropad** with its own duckyScript implementation | **Related HID ecosystem only**; own interpreter, firmware and keys. Do not expect duckyPad macros to compile unchanged for a Hak5 Rubber Ducky. |

**Popularity criteria:** prioritize originals rather than forks, verify the upstream README **and actual repository ownership**, inspect GitHub archived status and most recent code push, and account for stars without using them as a security-quality rating. An active GitHub discussion or newly updated star count does **not** prove the payload code has been maintained. The highest-star community example in this table targets a **different device**, which is why direct compatibility is displayed independently from popularity.

#### Inspect Before Selecting a Payload

1. **Inventory:** record project owner, URL, fixed commit hash, actual file path, license and whether the folder targets DuckyScript 1, 2, 3, Flipper BadUSB, O.MG, Arduino or an unknown dialect.
2. **Classify every action:** harmless text marker; authorized inventory; endpoint configuration; external download; file collection; credential/session access; security-control modification; persistence. **Do not install or run the latter categories as a routine first test.**
3. **Review every dependency:** inspect bundled PowerShell/Bash, compressed files, URLs, remote stages, tokens, webhooks, encoded commands, expected admin rights and any destructive cleanup. Replace personal/user-specific settings with synthetic data and avoid remote services entirely in the initial lab.
4. **Check compatibility:** modern Hak5 device generation, DuckyScript compiler version, keyboard layout, operating system, prompt state, delays and user privileges. A Flipper `/badusb/` text script is not a compiled Ducky image.
5. **Compile and test safely:** build the **approved, reduced marker-only** payload in Payload Studio and verify the exact `inject.bin` artifact/hash. Run on an offline disposable host with a blank editor focused, then observe USB/EDR/device-control logs.
6. **Decide evidence status:** label **source reviewed**, **syntax compiled**, **lab tested on model/firmware**, or **rejected/unsupported** separately. Never describe a link or successful compilation as proof of deployment success.
7. **Retain provenance:** store only your assessment notes, pin/URL, original license attribution and a safe test fixture; **link to third-party source** instead of copying copyrighted collections wholesale.

#### Safe Assessment Examples Inspired By the Collections

| Exercise | Test Fixture | What It Actually Demonstrates |
|---|---|---|
| Fixed marker | Offline workstation with empty text editor | Whether USB keyboard input is accepted under current device-control policy |
| Locale and timing | Two keyboard layouts with synthetic text | Keyboard mapping and enumeration-delay reliability, not exploitability |
| Locked desktop | Deliberately locked disposable host; **no bypass attempt** | HID enumeration and endpoint telemetry in locked state |
| Blue-team detection | Disposable host, expected USB HID policy, Wazuh/EDR | Actual allow/block/audit events, false positives and reporting |
| Cross-device syntax review | Compiler/test environment only, no target | Which syntax in a Flipper/O.MG/Arduino script is incompatible with modern DuckyScript |

**Repository policy:** the projects above are a *curated reference catalog*, not preapproved payloads or a script-execution list. For actual deployment, follow the [existing six non-destructive HID field exercises](#authorized-hid-injection-field-exercises), [Bash Bunny comparison](../Bash/BashBunny/README.md#curated-github-bash-bunny-payload-collections--compatibility) and [cross-Hak5 side-loading review](../../HardwareHacking/README.md#hak5-payload-ecosystem-official--side-loaded-code).

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

## Authorized HID Injection Field Exercises

This section expands the existing [compilation methods](#compilation-methods), [deployment steps](#deployment) and [syntax reference](#syntax-quick-reference) into repeatable, non-destructive exercises. Compare [Bash Bunny](../Bash/BashBunny/README.md) for USB composite-device testing and [Pico-Ducky](../../HardwareHacking/pico-ducky-lab.md) for a different CircuitPython implementation.

> [!IMPORTANT]
> The 2022 USB Rubber Ducky supports DuckyScript 3, which introduced control flow and device-specific features. Original/legacy hardware and encoders do **not** support every feature. These examples deliberately use simple commands supported by the basic DuckyScript workflow. The USB Rubber Ducky uses a **compiled** payload named `inject.bin`; do not deploy a raw Bash Bunny `payload.txt` as `inject.bin`. See the [official Hak5 DuckyScript 3 overview](https://shop.hak5.org/pages/duckyscript-3-0) and [Hak5 USB Rubber Ducky repository](https://github.com/hak5/usbrubberducky-payloads).

### Safe Build, Compile & Approval Workflow

1. Record hardware generation, firmware, compiler/encoder, keyboard layout, test-host OS, and an explicit written authorization. Limit testing to a designated host or disposable VM.
2. Use a synthetic test account. Open an empty text editor manually; disable network access for initial trials. Capture baseline USB/HID and EDR telemetry.
3. Write your payload in a tracked text file. Review **every** keystroke and consider what happens if application focus changes. Avoid arbitrary terminal launches, privilege prompts, password dialogs, and unattended execution.
4. Open the [official Payload Studio](https://payloadstudio.hak5.org/) and compile using the correct device generation, language mapping and supported syntax. Where available, inspect compiler diagnostics and confirm the downloaded artifact is precisely `inject.bin`, not `inject.bin.bin`.
5. Follow the appropriate device's **verified storage/arming workflow** before swapping files. Original devices commonly use removable microSD; contemporary models may expose storage through the device button and installed firmware. Do not assume the same process or optional `switch.txt` semantics applies to every generation.
6. Insert only in the approved host after the editor is focused. Record exact output, timing and endpoint events; stop immediately if focus changes.
7. Preserve script source, checksum of the compiled binary, evidence, and a cleanup note. Retest with a legitimate keyboard to evaluate false positives.

### Exercise 1 — Fixed Marker (First Successful Payload)

~~~text
REM Dedicated test host; focus a blank editor before inserting
DELAY 2000
STRING PNWC-DUCKY-AUTHORIZED-LAB
ENTER
~~~

**Procedure:** compile, stage, observe one insertion, compare the text exactly, and correlate insertion logs. If it is blocked, document the enforcement event. If it types, report HID acceptance only—not compromise or privilege escalation.

### Exercise 2 — Locale & Timing Matrix

~~~text
REM Deliberately limited to ordinary alphanumeric characters
DELAY 2500
STRING Layout Test ABC abc 1234567890
ENTER
DELAY 1000
STRING Second line after delay
ENTER
~~~

Test on two authorized hosts with documented keyboard layouts. Record expected/actual characters, elapsed enumeration time, and whether initial delays are sufficient. These delays are **examples, not universal timing requirements**. Do not include special characters until the compiler's layout mapping is independently verified.

### Exercise 3 — Application Focus & Failure Handling

1. Start with an empty editor on a lab host. Confirm the editor has focus before connecting.
2. Run Exercise 1 and record its exact text placement.
3. In a second run, deliberately change focus to a *different empty test document* before insertion; do **not** aim the device at a browser, password field, chat, or terminal.
4. Observe the dependency on foreground focus. Define the operator's stop procedure if any unapproved window has focus.
5. Document why automated keystroke scripts require explicit controls and manual confirmation in production.

**Success criterion:** the exercise demonstrates predictable handling within the isolated test desktop. Scripts containing destructive key combinations are out of scope.

### Exercise 4 — Locked Screen / Physical Access Controls

1. With an operator present, lock the lab workstation using normal OS controls, leaving no sensitive documents open.
2. Insert a marker-only test device. Do **not** attempt to unlock, bypass, or run hidden commands.
3. Record USB insertion/allow-deny event, whether any text appeared in an approved field, workstation lock policy, and any EDR alert.
4. Unlock using the test user's normal credentials, open a blank editor and rerun Exercise 1.
5. Compare results. HID acceptance at the lock screen does not itself prove unauthorized access to an authenticated session.

### Exercise 5 — USB Device Control / SIEM Regression

1. Record policy expected to block, audit or allow newly inserted HID. Note legitimate keyboard/accessibility-device exceptions.
2. Run one marker test with policy in audit mode, and another under the approved enforcement mode.
3. For Windows, collect device insertion and EDR policy events; for Linux, inspect `journalctl -k` and USB/udev telemetry where configured.
4. Forward **observed** events to the client's SIEM/Wazuh pipeline. Correlate host ID, device instance, policy action, UTC timestamp, and test ID.
5. Confirm a legitimate keyboard is not misidentified by a narrow rule. Record false positives, missing telemetry, and rollback.
6. Return policy to baseline and remove temporary reports from the test desktop.

### Exercise 6 — Employee Security Awareness Demonstration

With written management and participant approval, show a supervised marker-only injection on an unlocked **training** workstation. Explain workstation locking, unknown-device reporting, and why USB keyboards can be accepted without software installation. Do not conduct covert employee monitoring, impersonate login portals, or collect credentials. Capture only the agreed demonstration outcome.

### Evaluation & Results Table

| Test | Expected Evidence | Interpretation / Remediation |
|---|---|---|
| Fixed marker | Visible typed text, USB insertion event | Verify HID policy and workstation lock practices |
| Locale/timing | Exact characters, time stamps, repeatability | Match layout, use conservative controlled delays |
| Focus change | Visible focus dependence | Human-in-the-loop and stop conditions |
| Locked screen | USB enumeration & lock state | Do not equate enumeration with authentication bypass |
| Device control | Block/allow/audit events & SIEM correlation | Tune controls with legitimate device exceptions |
| Awareness | Training attendance & approved outcome | Update physical security procedures |

### Delivery Checklist

For each client test record: authorization ID, asset ID, operator, device model/firmware, encoder version, payload source hash, compiled binary hash, target OS/layout, exact UTC timestamps, observed keystrokes, EDR/device-control events, expected policy, actual result, and remediation. Clean synthetic artifacts and confirm the original policy is restored.

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
