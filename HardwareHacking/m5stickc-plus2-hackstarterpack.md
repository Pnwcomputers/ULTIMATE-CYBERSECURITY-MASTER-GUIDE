# M5StickC Plus2 — HackStarterPack lab integration

*Original PNWC reference, reviewed November 3, 2026. Navigate: [Hardware Hacking](README.md) · [Main guide](../README.md) · [source register](../Documentation/upstream-security-projects-register.md).*

The [HackStarterPack-M5StickCPlus2](https://github.com/flxppr/HackStarterPack-M5StickCPlus2) gathers IR signal files, Sub-GHz samples, BLE/USB keyboard scripts, captive-portal templates and tutorials. It is a **collection of untrusted references**, not a firmware release or a preapproved set of penetration-testing payloads. This guide integrates the useful concepts with the existing PNWC chapters **without copying third-party scripts, radio files or brand assets**.

## Confirm exact hardware and firmware

[M5Stack's StickC-Plus2 specification](https://docs.m5stack.com/en/core/StickC-Plus2) identifies SKU **K016-P2**, ESP32-PICO-V3-02, a built-in **IR transmitter**, 2.4 GHz Wi-Fi, USB-C and exposed GPIO. The Plus2 is **not** the original StickC Plus, M5Cardputer or ESP32-S3. It has **no onboard CC1101, NRF24, GPS, or native USB HID peripheral**. Feature menus and radio compatibility depend on installed firmware.

| Experiment | Minimum equipment | Verification |
| --- | --- | --- |
| Infrared remote | Plus2 IR emitter, firmware supporting IR file format, owned target | One harmless TV/projector command; response logged |
| Wi-Fi inventory | Plus2 2.4 GHz Wi-Fi and compatible firmware | Authorized test AP; passive scan; no forced disconnections |
| BLE discovery | ESP32-compatible BLE firmware and owned receiver | Your own advertising device; do not target nearby bystanders |
| Sub-GHz observation | External CC1101, antenna, correct power, firmware | Model-specific GPIO mapping; **receive only** |
| NRF24 work | External NRF24L01+, power regulation, firmware | Validate module and noninterfering test fixtures |
| USB keyboard emulation | **External CH9329 or verified HID accessory** and firmware | Test phrase in blank editor on disposable offline PC; USB-C alone is not native USB HID |
| GPS wardriving | External supported GNSS receiver and logging software | Consent, accuracy and location-data handling |

With Bruce firmware, use the [official CC1101 module guide](https://wiki.bruce.computer/external-modules/cc1101/) **and** the [StickC wiring modes](https://wiki.bruce.computer/wiring-diagrams/m5stickc/cc1101-nrf24/). The documented **Legacy SPI** profile uses CS=G26, SCK=G0, MOSI=G32, MISO=G33 and GDO0=G25/G36 as appropriate to the board; **Shared SPI** uses GDO0=G32, CS=G33, SCK=G0, MOSI=G26 and MISO=G36/G25. The upstream's single pin list is not universal. Confirm the exact StickC model, selected Bruce SPI profile, board header pins, supply voltage and physical module orientation **before powering up**. The upstream [generic wiring diagrams](https://github.com/flxppr/HackStarterPack-M5StickCPlus2/blob/main/Tutorials/Wiring%20Diagrams/README.md) show mappings that **must not be copied blindly** to the Plus2.

## Source map and adoption decisions

| Source folder | Use in this guide | Constraints |
| --- | --- | --- |
| [IR](https://github.com/flxppr/HackStarterPack-M5StickCPlus2/tree/main/IR) | Reference IR file formats; [Bruce IR chapter](../Documentation/bruce_firmware.md) | Verify encoding/carrier; owned controlled receiver |
| [Sub-GHz](https://github.com/flxppr/HackStarterPack-M5StickCPlus2/tree/main/Sub-GHz) | Radio examples, [Sub-GHz protocol study](../SDR/subghz.md) and [rtl_433 passive lab](../SDR/rtl433-passive-telemetry-lab.md) | No bulk copying, access-control replay or jamming |
| [BadBLE&USB](https://github.com/flxppr/HackStarterPack-M5StickCPlus2/tree/main/BadBLE%26USB) | Threat review and [USB HID lab concepts](../Scripts/Ducky/README.md) | Exclude phone crashes, pairing floods, lockouts and unreviewed scripts |
| [EvilPortals](https://github.com/flxppr/HackStarterPack-M5StickCPlus2/tree/main/EvilPortals) | Study portal risks and [Evil-M5](../Documentation/evil_m5.md) | Do not deploy imitated brands, collect credentials or phish |
| [Tutorials](https://github.com/flxppr/HackStarterPack-M5StickCPlus2/tree/main/Tutorials) | Conceptual reading for Wi-Fi/BLE/RF and [wardriving](../Wardriving/README.md) | Recheck hardware and technical claims; do not reproduce active deauth/flood demonstrations |

**Provenance:** The IR folder credits *veroleone/M5-IR*, Sub-GHz credits *samallx*, and portal material includes work by other authors. No root LICENSE file appeared in the upstream root reviewed on November 3. A GitHub link does not grant rights to redistribute. Retain links/attribution and assess individual licenses before any file import.

## Repeatable, non-disruptive lab exercises

1. **Scope and setup:** identify owned test devices, written authorization and stop contact; use the [client assessment blueprint](../PlayBooks/assessment-service-integration-map.md). Record Plus2 board revision, Bruce/other firmware version, accessory model, power and wiring, screenshots and expected cleanup.
2. **Infrared:** choose a noncritical TV/IR receiver you own. Send a harmless command (volume adjustment) using an understood IR format. Record result and physical distance. The Plus2 includes an emitter, not a proven IR capture receiver.
3. **Sub-GHz:** connect a CC1101 via verified Plus2 wiring. Verify module detection, then **receive** a signal from your own weather sensor and document frequency, modulation assumptions and observed packets. Correlate with [rtl_433 receive-only telemetry](../SDR/rtl433-passive-telemetry-lab.md). Do not retransmit gate, garage, alarm or vehicle codes.
4. **BLE/HID:** observe advertisements from an owned BLE device; redact addresses in reports. For an external CH9329, use a disposable offline PC with a blank text editor and send only `PNWC HID LAB OK`. No scripts that run shells, capture screens, submit PINs, overload inputs or modify settings.
5. **Captive portal:** use an isolated lab AP and an original, plainly labeled *PNWC Training Portal* with informed consent and a dummy acknowledgment button. No password fields, tokens, private identifiers, copied vendor marks or unsuspecting users.
6. **Defensive review:** observe *normal* connect/disconnect traffic using the [Kismet/Wazuh wireless lab](../IncidentResponse/IDS%26IPS/kismet-wazuh-wireless-lab.md) or [Wireshark deauth guide](../Documentation/wifi-deauthentication-detection.md). Use synthetic/offline captures for malicious flood scenarios, not real disruption.

## Risks, evidence and verification boundaries

The source includes disruptive keyboard loops, BLE spam, intentional GUI crashes, phishing themes, Wi-Fi deauthentication and radio jamming topics. **None are imported or authorized for client use.** In the US, radio jamming is generally unlawful even with customer permission. A described capability is **not** proof that a board, accessory, specific firmware version or source file was bench-tested.

For each lab record: **authorization ID · owned target · board/firmware · addon revision · pinout source · upstream artifact URL/hash · expected outcome · observed result · defensive logs · cleanup**.

**Related guides:** [Bruce](../Documentation/bruce_firmware.md) · [Evil-M5 / Cardputer (different board)](../Documentation/evil_m5.md) · [SDR](../SDR/README.md) · [Wardriving](../Wardriving/README.md) · [USB HID](../Scripts/Ducky/README.md) · [Firmware compatibility](../firmware-hardware-compatibility.md) · [Legal](../LEGAL.md).
