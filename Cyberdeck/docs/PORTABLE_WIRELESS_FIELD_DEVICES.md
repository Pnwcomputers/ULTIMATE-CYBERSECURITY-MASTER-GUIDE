# Portable Wireless & Field Device Operations for the PNWC Cyberdeck

> [!CAUTION]
> **Written authorization & passive-first use.** This is a field workflow for equipment the operator owns or has permission to survey. Nearby wireless networks and users do not automatically become in scope. Radio interference, deauthentication, impersonation, credential capture, unsolicited connection attempts and replay are **not** part of the default process. Review [Legal Terms](../../LEGAL.md), [Wardriving Privacy](../../Wardriving/data-handling.md) and the signed rules of engagement.

[Cyberdeck Home](../README.md) · [Build & Operations](BUILD_AND_OPERATIONS.md) · [Architecture](ARCHITECTURE.md) · [Assessment Workflow](ASSESSMENT_WORKFLOW.md) · [Evidence & Privacy](EVIDENCE_AND_PRIVACY.md) · [Qualification Matrix](ACCEPTANCE_TESTS.md)

**Scope:** Use the **Flipper Zero**, **WiFi Pineapple**, **M5StickC Plus2**, **Bruce** and **ESP32 Marauder** families as supervised, portable companions to the PNWC Cyberdeck. This page deliberately **excludes** JTAG, Bus Pirate, chip programming, logic analyzers, physical exploitation and other hardware-hacking bench procedures. See the existing specialized guides separately if such work is explicitly authorized.

**Publication & readiness:** This is a public **reference design and operator runbook**, not a deployed device controller. Actual firmware, accessory support, USB/SD export, power and RF behavior must be qualified per unit; the private PNWC portal is not claimed to automatically operate any of these devices.

## 1. Choose The Device & Firmware For The Job

| Device / Firmware | Field-Safe Starting Role | Controller & Artifact Path | Specific Reference |
| --- | --- | --- | --- |
| **Flipper Zero — stock firmware** | Owned NFC/RFID tag inventory, supported IR checks and on-device observations | Flipper UI; review and copy permitted microSD files using qFlipper or equivalent | [Flipper](https://flipper.net/) · [qFlipper File Management](https://docs.flipper.net/zero/qflipper) · [PNWC Field Guide](../../Documentation/flipper_zero_guide.md) |
| **Flipper + ESP32 Marauder expansion** | Scoped 2.4 GHz Wi-Fi survey with a **compatible** accessory; supported C5 boards may differ | Flipper Marauder FAP = controller; ESP32 board = radio; logs may live on ESP microSD or Flipper depending on the target | [Upstream Flipper/Marauder](https://github.com/justcallmekoko/ESP32Marauder/wiki/Flipper-Zero) · [PNWC Flipper Labs](../../Documentation/flipper_zero_guide.md#flipper-marauder-companion-deployment-labs) |
| **Standalone ESP32 Marauder** | AP/channel inventory, approved receive-focused monitoring and optional GPS-supported survey | Standalone display or serial CLI; supported SD log or PCAP export on actual hardware | [Marauder Supported Hardware](https://github.com/justcallmekoko/ESP32Marauder/wiki/Supported-Hardware) · [PNWC Standalone Labs](../../Documentation/WiFiMarauder_Guide.md#dedicated-standalone-marauder-deployment-playbook) |
| **WiFi Pineapple Mark VII / VII+AC** | Scoping wireless exposure, AP inventory, channel/advertisement review, manual recon reporting | Separate Pineapple management UI/session; review and export only authorized findings | [Official Mark VII Product](https://shop.hak5.org/products/wifi-pineapple) · [PNWC Mark VII Exercises](../../Wardriving/README.md#wifi-pineapple-mark-vii--authorized-wireless-security-assessment) |
| **WiFi Pineapple Pager (if present)** | On-device recon, alert and safe local payload **review**; not the Mark VII web UI | Pager-specific UI, storage and compatible payloads; inspect before running or sharing | [Hak5 Pineapple Family](https://shop.hak5.org/pages/wifi-pineapple-collection) · [PNWC Pager Labs](../../Wardriving/README.md#wifi-pineapple-pager--payloads-sideloading--defensive-labs) |
| **M5StickC Plus2 + Bruce** | Pocket-sized 2.4 GHz Wi-Fi/BLE environment inventory; harmless IR check using an owned receiver | Plus2 on-device menu; serial or optional supported file export after board qualification | [Plus2 Hardware](https://docs.m5stack.com/en/core/StickC-Plus2) · [Bruce Project](https://github.com/BruceDevices/firmware) · [PNWC Bruce Labs](../../Documentation/bruce_firmware.md#exercise-b7--repeatable-bruce-board-qualification) |
| **M5StickC Plus2 + Marauder (alternative firmware)** | A second, **separately flashed** Plus2 survey configuration, not Bruce running concurrently | Board-specific Marauder binary, menu/serial; confirm what can actually be exported | [Marauder Target Matrix](https://github.com/justcallmekoko/ESP32Marauder/wiki/Supported-Hardware) · [PNWC Marauder Guide](../../Documentation/WiFiMarauder_Guide.md) |
| **M5StickC Plus2 + NEMO (optional alternative)** | Small Wi-Fi/BLE/IR observation demo on owned fixtures | NEMO firmware and board-specific storage/serial limitations | [PNWC NEMO Setup](../../Documentation/nemo-firmware.md) · [Upstream NEMO](https://github.com/n0xa/m5stick-nemo) |

**Do not confuse the firmware and the hardware.** The Flipper Zero's built-in radios are **not** a Wi-Fi scanner: Wi-Fi Marauder requires a separate, correctly flashed ESP32 accessory. Bruce, Marauder and NEMO are alternate firmware installations on the **same** Plus2 MCU, not concurrent applications. The M5StickC Plus2 has 2.4 GHz Wi-Fi; it has **no onboard 5 GHz radio, GPS receiver, microSD slot, CC1101, nRF24 or native USB HID**. An external module, verified wiring and compatible firmware may be required for a particular operation. Do not turn this project into a board-rewiring guide.

**Other related wireless-survey ecosystems:** [Kismet](../../Wardriving/kismet.md), [SigRoam / Scout Lite](../../Wardriving/sigroam-scout-lite.md), [Biscuit](../../Wardriving/biscuit.md), [AWOK Dual C5](../../Wardriving/awok-dual-c5-biscuit.md) and [ESP32-C5 Wardriver](../../Wardriving/esp32-c5-wardriver.md). These have their own firmware, phone/FAP controllers, logging locations and acceptance requirements; they are **not** assumed to plug into or be supported by the Cyberdeck controller.

## 2. Physical Integration With The Cyberdeck

```text
       APPROVED UPLINK
            |
       GL.iNet Router
            |
     MikroTik Segmentation
        /        |       \
      MGMT     SENSOR     LAB
    Workstation Evidence   Owned Fixtures
    Windows/Linux storage  & Test AP(s)
       |
       +-- USB/local transfer: Flipper / Plus2 / ESP32 SD reader
       +-- Authorized management-only access: Pineapple UI
       +-- Manual review & evidence import into protected case

   INDEPENDENT RF DEVICES (Flipper, Marauder, Bruce,
   Pineapple, optional Pager) observe only the approved
   fixture/location and their real antenna/radio capabilities.
```

This is a **logical workflow**, not a wiring map or claim that the devices have been connected. The Pineapple or ESP32 board does **not** replace the MikroTik segmentation firewall. Do not bridge client LANs to Pineapple management, give optional field hardware unrestricted access to MGMT/STORAGE, or expose a device admin UI to the uplink. Some devices only operate over USB or microSD with **no required LAN connection**.

| Connection | Preferred Practice | Confirm Before Field Use |
| --- | --- | --- |
| Flipper Zero -> workstation | Short, trusted USB cable and vendor file manager; transfer approved artifacts only | Correct microSD, app/firmware versions and actual artifact folder |
| Flipper -> Marauder radio board | Verified accessory/GPIO power and matching Flipper app + radio firmware | Serial/UART control; model-specific ESP32 firmware; export location |
| Standalone ESP32 Marauder -> workstation | Removable microSD or approved USB serial/file-transfer procedure | Supported storage, data format, clock and final stop state |
| M5StickC Plus2 -> workstation | Short USB serial session or verified firmware-supported storage workflow | No assumption of SD or network-based export on the bare board |
| Pineapple -> operator MGMT | Dedicated management interface/session, under scoped firewall policy | Exact model, authenticated UI, radio modes, local artifact export and isolation |
| Optional Pager -> operator | Model-specific authenticated controls and local reviewed export | Do not treat Mark VII commands, API, or payload formats as interchangeable |
| Every field device -> evidence vault | **Manual reviewed import** to separately encrypted storage | Case ID, original bytes, hash, acquisition time and redaction plan |

**Power & USB caveat:** Measure the actual supply/current budget with all devices running at once. A USB cable may provide only power, or expose a serial adapter, storage or a USB network interface depending on the device. Identify what your OS enumerates; never trust an unexpected new network connection or auto-run behavior.

## 3. Firmware, SD Storage & Preflight Qualification

1. **Authorize first:** select the engagement ID, written asset/SSID/BSSID/area scope, observation type, start/stop window, retention and stop contact. No wireless collection is authorized merely by entering an area.
2. **Inventory:** record actual model, board revision, serial reference **privately**, firmware image/source/version, controller app revision, power source, storage path, radio bands and accessory wiring. Use the [qualification template](../templates/QUALIFICATION_RECORD.example.md).
3. **Separate firmware roles:** update a Flipper FAP and its Marauder ESP32 image independently. For a standalone Marauder board, choose the binary suffix corresponding to the **exact** supported hardware and follow the [official installer](https://justcallmekoko.github.io/MarauderInstaller/); the same rule applies when selecting the [Bruce board image](https://bruce.computer/flasher).
4. **Validate exports:** confirm storage is mounted/writable where supported. Marauder's GPS wardrive requires compatible GPS, valid fix and suitable log storage. On Flipper, qFlipper transfers Flipper microSD files, not arbitrary storage located on a separate Marauder accessory.
5. **Set conservative behavior:** receive-focused inventory only, no auto-start on boot, no public upload/WiGLE sync, no aggressive payloads, no unreviewed scripts, and no background radio actions outside the approved window.
6. **Qualify in your own lab:** one known AP/owned BLE beacon/tag, correct interface and channel, no unexpected transmissions, successful stop, and an independently reviewed output. If the platform cannot save an attributable artifact, retain a dated manual observation and record that evidence limitation.

Firmware lists and upstream menu labels change; confirm against the installed version rather than assuming menu names and bundled features from an old screenshot.

## 4. Flipper Zero & Marauder Companion Procedure

| Step | Operator Action | What to Preserve |
| --- | --- | --- |
| 1 — Flipper baseline | Check official/community Flipper firmware, installed Marauder FAP version, SD free space and time settings | Firmware/FAP identifiers; SD status |
| 2 — ESP32 expansion | Identify S2/S3/ESP32/C5 accessory and match its actual Marauder release target; for a standard Flipper WiFi Dev Board use the upstream `_flipper.bin` target where specified | Board identity, chosen binary and source |
| 3 — Owned-lab check | With an approved fixture AP, launch the companion and confirm the FAP can communicate with the ESP32 over its supported interface | App connection result; no client data |
| 4 — Scoped collection | Select an authorized inventory/survey mode, review its passive/active behavior, run only for the permitted period | AP/channel observations, start/end time, radio and position limits |
| 5 — Stop & export | End collection on the radio **and** on the Flipper controller; collect only the relevant SD/serial files using the appropriate owner device | Original artifacts with source/transfer records |
| 6 — Verify | Import and hash the files on the workstation; confirm capture content against the known fixture and document missing GPS/SD/5 GHz | Reviewed evidence, limitations and QA result |

**Critical distinction:** A Flipper app (`.fap`) is **not** ESP32 firmware (`.bin`); a microSD installed on the Flipper is not the same volume as one on the accessory. The [upstream Flipper Marauder instructions](https://github.com/justcallmekoko/ESP32Marauder/wiki/Flipper-Zero) and [supported hardware table](https://github.com/justcallmekoko/ESP32Marauder/wiki/Supported-Hardware) determine the correct pairing. A GPS-enabled or 5 GHz capable **different** board cannot bestow those features on the standard Flipper WiFi Dev Board.

For built-in Flipper NFC/RFID/IR, use **only** owned lab tags/remotes with supported read-only or harmless identification functions. Record what the device actually recognized; do not use cloned workplace credentials, uncontrolled replay, or undisclosed tag contents. See the [dedicated Flipper field guide](../../Documentation/flipper_zero_guide.md).

## 5. Standalone ESP32 Marauder Procedure

1. Select the **exact** standalone board and official release asset. Verify its radio chipset, bands, SD/GPS capabilities and display/CLI variant; C5 dual-band targets and legacy ESP32 2.4 GHz targets are not equivalent.
2. In an owned fixture environment, confirm startup, display/buttons/serial access, free SD space and valid time/source labeling. If GPS is used, prove an actual fix before claiming coordinates.
3. Run a short, approved **AP inventory**. Record band/channel, observed SSID/BSSID where within scope, signal level and device/capture version. If using the wardrive feature, ensure explicit area consent and do not publish coordinates without approval.
4. Stop scanning and check the actual output. A supported GPS/SD configuration may produce `wardrive_` logs; PCAP and other formats depend on collection mode and firmware. Neither is guaranteed for every target.
5. Transfer files via SD/approved serial method, hash originals and document whether any observation came from a different source or time. See [Marauder Wardrive](https://github.com/justcallmekoko/ESP32Marauder/wiki/Wardrive), [PNWC Marauder Guide](../../Documentation/WiFiMarauder_Guide.md) and [Data Handling](../../Wardriving/data-handling.md).

The `wardrive` mode and valid GPS positions **require supported hardware**. A sensor scan is not evidence of successful location logging. Public mapping/upload functions should remain disabled unless each upload is specifically approved and privacy-reviewed.

## 6. M5StickC Plus2 With Bruce (Or An Alternative Firmware)

| Step | Bruce / Plus2 Field Action | Condition & Outcome |
| --- | --- | --- |
| Firmware selection | Use the Plus2-specific Bruce build, not Plus, Cardputer or S3 binaries | Confirm display, input controls, boot, revision and rollback/reflash plan |
| 2.4 GHz survey | In an owned lab, use the supported Wi-Fi inventory/channel display to observe your known AP | Log exact SSID/channel/date only if authorized; note that a display is not an export |
| BLE overview | Observe an **owned** BLE advertiser in the supported scan mode | Note random addresses and non-unique identity; avoid tracking nonparticipants |
| IR test (optional) | Transmit one harmless command to a dedicated owned IR receiver after approval | Record receiver and outcome; no universal device compatibility assumed |
| Capture/transfer | Check whether this Bruce build supports a useful output file, removable storage accessory, serial readout or only on-screen results | Never claim a PCAP, GPS log or SD export without proof |
| Stop & restore | Exit collection, inspect background functions and restore lab configuration | Record firmware state, power, UTC uncertainty and any data retained |

The [M5Stack Plus2 specification](https://docs.m5stack.com/en/core/StickC-Plus2) is authoritative for built-in radios and connectors. **Plus2 is not a USB HID-capable ESP32-S3**, and a USB-C cable does not magically make it a keyboard. The Plus2's onboard 200 mAh cell is not a basis for assuming a full field session; test actual runtime.

For Bruce, use the [official project](https://github.com/BruceDevices/firmware), [flasher](https://bruce.computer/flasher), and [PNWC Bruce board-qualification labs](../../Documentation/bruce_firmware.md#exercise-b7--repeatable-bruce-board-qualification). Its feature menu includes disruptive options; leave these **disabled** in this baseline. [Marauder Plus2](https://github.com/justcallmekoko/ESP32Marauder/wiki/Supported-Hardware) and [NEMO](../../Documentation/nemo-firmware.md) require separate flash/requalification; they do not run simultaneously with Bruce.

## 7. WiFi Pineapple Mark VII / Pager Procedure

**The Mark VII and Pager are different platforms** with different radios, UI, management and payload ecosystems. Use only the model-specific [PNWC Mark VII exercises](../../Wardriving/README.md#wifi-pineapple-mark-vii--authorized-wireless-security-assessment) or [Pager reference](../../Wardriving/README.md#wifi-pineapple-pager--payloads-sideloading--defensive-labs). A Mark VII+AC needs its compatible accessory for 5 GHz capability; do not assume all Pineapple variants have the same band coverage.

| Stage | Authorized, Passive-First Use | Required Safeguard |
| --- | --- | --- |
| Setup | Update firmware using official Hak5 guidance; provision only the documented management interface | Unique admin credentials, no WAN exposure, recorded recovery mode |
| Isolate | Keep Pineapple management separate from client test networks and other Cyberdeck zones | No unapproved DHCP, NAT, bridging, captive portal or wireless AP impersonation |
| Scope | Configure eligible SSID/client filters and verify the approved survey area | Filters are helpful, **not proof** that nearby third-party traffic was never observed |
| Recon | Use a brief, reviewed AP/channel survey of owned or explicitly authorized fixtures | Avoid enabling PineAP impersonation, deauth, handshake capture, credential portals or automated offensive campaigns |
| Evidence | Save/report the local observations supported by the installed model and firmware | Retain only authorized metadata, original report files and UI/settings version |
| Shutdown | Stop the survey, verify radio/payload state, close management access, remove power when appropriate | No background attack/campaign tasks after engagement ends |

For the **Mark VII**, the vendor advertises a browser-based interface, Recon and campaign/reporting features; a **campaign is not automatically passive or safe**. Treat it as a separately reviewed procedure and do not run a packaged campaign merely because it is available. The **Pager** can use payloads, including community-supplied ones; inspect each payload's effects and storage destinations in an isolated lab before considering it for any signed scope. Do not sideload unknown payloads into a client engagement.

See [Official WiFi Pineapple Mark VII](https://shop.hak5.org/products/wifi-pineapple) and [Pineapple Family Comparison](https://shop.hak5.org/pages/wifi-pineapple-collection). The device management address, default network mode, menus and export buttons must be recorded from the **actual** unit; this guide deliberately does not invent a universal default.

## 8. Practical Cyberdeck Assessment Sessions

### Session A — Owned Wireless Inventory & Coverage

**Fixture:** two owned lab APs with known channel/security settings, one monitoring workstation, one selected field device, and an operator-approved area. No customer devices or neighboring networks should be included in the final inventory.

1. Record written fixture approval, exact AP identities, allowed bands, time window and operator.
2. Pick a single collector (Marauder, Bruce Plus2 or Pineapple Recon), not all simultaneously. Confirm mode, storage and any unintended active features are off.
3. Observe the two test APs from stationary positions; note RSSI changes and channel. Compare readings to the AP controller's configuration, not to an unverified lookup.
4. Stop the device and export artifacts where supported. If the device only displays readings, capture a manually attributed note and label it as non-file evidence.
5. Remove out-of-scope observations from the **approved derivative**; preserve originals only where justified and authorized.
6. Record results and limitations: visible APs, band/channel restrictions, GPS absent/unknown, no detection of all nearby stations implied.

### Session B — Flipper Companion Connectivity & Export Qualification

**Fixture:** Flipper Zero, one verified Marauder-compatible expansion board, and an owned test AP.

1. Verify matching FAP and ESP32 firmware model, storage media and installed build revisions.
2. Run a short approved inventory; separately stop the ESP radio and Flipper app.
3. Find the file on the device that **actually owns the storage**; copy it to the workstation and compute a SHA-256 inventory.
4. Compare the exported content with the test AP and record any SD/UART/GPS failure as FAIL/BLOCKED rather than a false pass.

### Session C — Defensive Wireless Visibility Correlation (Optional)

**Fixture:** the same lab APs plus an independently configured [Kismet](../../Wardriving/kismet.md), AP/controller log source or [Wazuh](../../IncidentResponse/SIEM/README.md) collector, if available.

1. Generate only benign, normal client association and disconnection traffic from owned fixtures. **Do not initiate deauthentication.**
2. Note observed times/channels from the field device; compare with AP/controller events and sensor logs where they truly overlap.
3. Evaluate clock offsets, sensor coverage and dropped events before interpreting mismatches. A Pineapple or standalone ESP device is not an automatic Wazuh sensor or source.
4. Document corroborated findings and the monitoring gaps. No alerts must never be described as proof of safety.

## 9. Evidence Import, Review & Reporting

**Current public integration is manual.** No Flipper FAP API, Pineapple remote-control driver, Bruce bridge, Marauder serial parser or live Wazuh automation is shipped as part of this Cyberdeck public edition. The private portal's manual device-export capability is not evidence that a particular device format has been validated.

| Evidence Field | Record & Validation |
| --- | --- |
| Case/approval reference | An internal nonpublic case ID and matching authorization revision |
| Device source | Actual model, board/accessory revision, hostname or private asset ID, firmware hash/version |
| Collection context | Mode, passive/active classification, eligible SSIDs/channels/bands/area, data minimization setting |
| Source & time | Exact collector, UTC start/end with clock offset; GPS quality if applicable |
| Original artifact | Original filename, true device/storage path, file bytes and SHA-256; screenshots/manual notes must be labeled |
| Transfer/custody | Operator, transfer method, acquired time, destination, subsequent modifications |
| Quality & disclosure | PASS/FAIL/BLOCKED/NOT TESTED, scope check, redaction status and approved sharing |
| Interpretation | What was **observed** vs inferred; untested bands, missing radios, skipped scans and sensor-blind zones |

**Offline example (synthetic evidence only):** from the root of the public Guide, run:

```bash
python Cyberdeck/tools/evidence_manifest.py --input Cyberdeck/examples/synthetic-evidence --output /tmp/cyberdeck-field-demo.json
python Cyberdeck/tools/verify_manifest.py --input Cyberdeck/examples/synthetic-evidence --manifest /tmp/cyberdeck-field-demo.json
```

On Windows, use a separately protected output folder appropriate to the environment. These scripts hash **existing local files**; they do not collect from connected devices, extract Pineapple reports, parse PCAPs, make a report true, authenticate a radio observation, or prove chain of custody. See [Evidence & Privacy](EVIDENCE_AND_PRIVACY.md).

**Future private integration adapter (not implemented):** manual drop-folder intake → validate recognized file type and size → parse in an isolated, nonprivileged service with no execution of payloads → associate the approved case/device/run → hash and preserve original → expose **reviewed**, labeled derivative → human sign-off → report. For any parser, create synthetic positive, negative, malformed and out-of-scope fixtures and require an explicit stop path before claiming an operational connector.

## 10. Readiness Gates & Failure Modes

| Gate | PASS Means | Common BLOCKED / FAIL |
| --- | --- | --- |
| F1 — Model & firmware | Exact hardware, binary, UI/FAP revision and compatible radio confirmed | Wrong Marauder target or unsupported Plus2 firmware; unknown chipset |
| F2 — Isolation | Management and optional radio devices do not bridge outside authorized zones | Pineapple creates an unintended AP/LAN path |
| F3 — Passive behavior | A test AP can be inventoried without offensive mode enabled | Auto campaign, unreviewed payload or active radio mode |
| F4 — Collection stop | Each independent device stops when ordered, including background tasks | Stopping portal UI leaves field hardware active |
| F5 — Evidence | Original copy, hash, timestamp/source, privacy review and target corroboration exist | No SD, missing GPS, unsupported output, ambiguous screenshot |
| F6 — End-to-end synthetic | Findings, limitations and human-reviewed closeout complete with **fake** case | Unverified import represented as an operational integration |

A new firmware build, radio addon, chipset, storage device, wiring mode or transport path invalidates the relevant previous qualification until retested. Log failures; do not silently substitute another app, force a target, or publish local SSIDs/locations.

## 11. Further Reading & Ownership

| Subject | Canonical Guide |
| --- | --- |
| Flipper & Marauder accessory pairing | [Flipper Field Guide](../../Documentation/flipper_zero_guide.md) · [Marauder Flipper Wiki](https://github.com/justcallmekoko/ESP32Marauder/wiki/Flipper-Zero) |
| Standalone Marauder & board selection | [Marauder Guide](../../Documentation/WiFiMarauder_Guide.md) · [Official Hardware Targets](https://github.com/justcallmekoko/ESP32Marauder/wiki/Supported-Hardware) |
| Bruce & M5StickC Plus2 qualification | [Bruce Guide](../../Documentation/bruce_firmware.md) · [M5Stack Plus2](https://docs.m5stack.com/en/core/StickC-Plus2) |
| WiFi Pineapple Mark VII & Pager | [PNWC Wireless Reference](../../Wardriving/README.md#wifi-pineapple-mark-vii--authorized-wireless-security-assessment) |
| Wireless survey routes & privacy | [Field Workflow](../../Wardriving/field-workflow.md) · [Data Handling](../../Wardriving/data-handling.md) |
| Cyberdeck staging & evidence | [Build Runbook](BUILD_AND_OPERATIONS.md) · [Qualification Matrix](ACCEPTANCE_TESTS.md) · [Implementation Roadmap](IMPLEMENTATION_ROADMAP.md) |

**Review basis:** device scope and firmware compatibility cross-checked against the linked manufacturer/project references and existing PNWC field guides on 2026-11-12. No physical devices, live captures, external firmware installers, or hardware integrations were exercised by this documentation update.
