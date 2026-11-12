# Device-First Firmware List

> [!CAUTION]
> **Authorized use only.** Identify the exact board revision, chip, flash size,
> display and radio peripherals before selecting an image. Read [LEGAL.md](../LEGAL.md).

_Last reviewed: 2026-11-07_

## Purpose

Start with the device you own, then choose a verified project and its installation
workflow. This list complements the [project catalog](./esp32-security-firmware-catalog.md)
and supersedes broad chip-family checkmarks for selection. It is not a guarantee
that every project release supports every revision of a listed device.

## Navigation

| Resource | Description |
|---|---|
| [M5Stack Devices](#m5stack-devices) | StickC, Cardputer and Core families |
| [ESP32 Boards & Survey Appliances](#esp32-boards--survey-appliances) | Exact DIY targets and vendor multi-MCU products |
| [Pi & HID Devices](#raspberry-pi--usb-hid-devices) | Linux images, theme managers and CircuitPython |
| [Dedicated Radio Hardware](#dedicated-radio-hardware) | BLE sniffers, RF, RFID and LoRa devices |
| [Installation Methods](#installation-methods) | Project installer versus generic uploader versus other formats |

## How To Read The List

Named choices mean the reviewed primary documentation identifies that target or
a clearly named build. They do not mean all features are present, that the image
was flashed here, or that every similarly named board works. Follow each project's
target matrix and release notes. For activity and primary authors, use the catalog.
Generic development libraries require a build; they are not complete appliance images.

## M5Stack Devices

| Device | Radio / Architecture | Documented Firmware Choices | Selection Limits |
|---|---|---|---|
| M5StickC / Plus / Plus2 | Original ESP32 family, 2.4 GHz Wi-Fi/BLE | [Bruce](./bruce_firmware.md), [NEMO](./nemo-firmware.md); selected [Evil-M5](./evil_m5.md) installer targets | Verify exact model and per-device features. USB bridge alone cannot emulate a keyboard. [Plus2 lab](../HardwareHacking/m5stickc-plus2-hackstarterpack.md). |
| Original M5Cardputer | ESP32-S3, 2.4 GHz Wi-Fi/BLE, native USB | Bruce, NEMO, Evil-M5, [GhostESP](./ghostesp-revival.md), [Marauder](../Wardriving/esp32-marauder.md), [ESP32 Bit Pirate](../HardwareHacking/esp32-bit-pirate.md), [PORKCHOP](../Wardriving/additional-survey-firmware.md) | Follow exact target/SD/partition configuration. PORKCHOP's reviewed 5 GHz workflow requires a separate C5 radio. |
| M5Cardputer ADV | S3-based, different board/peripheral revision | Bruce, [Evil-M5](./evil_m5.md#evil-m5-firmware-qualification--authorized-deployment-labs), GhostESP, Marauder, Bit Pirate, PORKCHOP, [ChimeraBLE](./chimerable.md), [FlipperHTTP](https://github.com/jblanked/FlipperHTTP) | A [LAB5 M5MonsterC5](./microcontroller_wifi_testing.md#lab5-c5-monster--projectzero-janos-field-assessment) is a separate **external C5 + JanOS** companion with independently flashed Cardputer app. Never put a JanOS C5 binary on the Cardputer S3. |
| M5Core2 | Original ESP32, 2.4 GHz Wi-Fi/BLE | Bruce, Evil-M5 named Core2 build | Native S3 USB assumptions do not apply. Confirm exact Core2 and external-module wiring. |
| M5CoreS3 / SE | ESP32-S3 | Bruce, Evil-M5 named CoreS3 builds | Match SE/revision, USB connector and attached hardware; do not flash a Core2 image. |
| AtomS3 Lite / StampS3 | ESP32-S3 | Bit Pirate named targets; other M5 projects only where exact target is listed | Lite versus screen-equipped Atom and Stamp carrier pins differ. |

## ESP32 Boards & Survey Appliances

| Device | Radio / Architecture | Documented Firmware Choices | Selection Limits |
|---|---|---|---|
| ESP32 WROOM DevKit | Original ESP32, 2.4 GHz Wi-Fi/BLE | GhostESP generic WROOM, ChimeraBLE `esp32dev`, target-specific FlipperHTTP | GPIO/display/SD wiring must match. This is not blanket Marauder/CYD compatibility. |
| ESP32-S3 DevKit / SuperMini | S3, 2.4 GHz Wi-Fi/BLE/USB | Bit Pirate named generic builds, GhostESP S3, target-specific FlipperHTTP | Required flash size and pin mapping vary. No native 5 GHz Wi-Fi from an S3 image alone. |
| LAB5 M5MonsterC5 / Cardputer ADV / Tab5 companion | ESP32-C5-WROOM-1U **separate** radio + distinct ESP32-S3/Cardputer or Tab5 UI controller | [projectZero JanOS](./microcontroller_wifi_testing.md#lab5-c5-monster--projectzero-janos-field-assessment) + separately flashed [Cardputer/Tab5 app](https://github.com/C5Lab/M5MonsterC5-CardputerADV) | Exact LAB5 hardware/UART, controller and bootloader; a generic C5 image, Evil-M5, Biscuit, AWOK or Marauder build is **not** interchangeable. |
| ESP32-C5 DevKit / JCMK host board | C5, 2.4/5 GHz Wi-Fi/BLE | [C5 Wardriver](../Wardriving/esp32-c5-wardriver.md), Biscuit DIY named target, GhostESP C5; selected Marauder target | Exact DevKit revision and carrier power/jumper rules matter. One radio does not scan both bands simultaneously. |
| LilyGo T-Dongle C5 | C5 plus onboard display/SD | C5 Wardriver T-Dongle build, [Piglet](../Wardriving/piglet.md) T-Dongle variant, [Biscuit DIY](../Wardriving/biscuit.md) | Do not flash a DevKit image merely because both use C5. Verify GPS/SD pin assignments. |
| Seeed XIAO ESP32-C5 | C5 | Piglet, ChimeraBLE `xiao_esp32c5`, Biscuit DIY, selected Marauder target | Biscuit docs specify 8 MB flash and label XIAO SD support beta; inspect the actual board. |
| Seeed XIAO S3 / C3 / C6 | Distinct chips; these Wi-Fi builds are 2.4 GHz | Piglet's named build/profile; other firmware only with explicit board target | No swapping C5 images to add 5 GHz. Headless/display and GPS/SD profiles differ. |
| LAB5 MonsterC5 + Flipper | ESP32-C5 external Wi-Fi board with Flipper FAP UI | [LAB5 JanOS firmware + Lab_C5 FAP](./microcontroller_wifi_testing.md#lab5-c5-monster--projectzero-janos-field-assessment) | Distinct JanOS C5 image and Flipper FAP; verify firmware/API/UART and the vendor FAP's stated Flipper firmware support. |
| Flipper official Wi-Fi Dev Board | ESP32-S2 accessory | Marauder Flipper/S2 target, GhostESP S2, FlipperHTTP S2 | S2 has no Bluetooth. Flipper firmware/FAP updates and ESP image updates are separate. |
| PINGEQUA Scout Lite | C5 + GPS + microSD | [Vendor SigRoam/Marauder modes](../Wardriving/sigroam-scout-lite.md); supported Biscuit reflash workflow | Use vendor target and matched controller. GPS and log destination change with firmware/mode. |
| Biscuit Pro / Ultra | C5 scanner + WROOM gateway | Vendor product-specific Biscuit images | Two MCU roles and firmware updates; not two interchangeable copies of a DIY image. |
| Biscuit Crumb / DIY | Single C5, model-specific hardware | Vendor Crumb or DIY build respectively | Crumb recovery script and DIY installer are distinct. App export is not automatically SD CSV logging. |
| AWOK Dual C5 Touch / Mini | Two physical C5 radios | [Biscuit named AWOK target](../Wardriving/awok-dual-c5-biscuit.md); other images only for the independently supported port/role | Identify each USB/MCU. Neither named AWOK model has an SD slot in reviewed Biscuit docs. |
| CYD ESP32-2432S028R / related display boards | Original ESP32 plus variant display/touch | Named Bruce/GhostESP/Evil-M5 builds, [HaleHound](https://github.com/JesseCHale/HaleHound-CYD), [SquachWatch](https://github.com/skizzophrenic/SquachWatch-CYD); experimental independent FancyGotchi CYD port | ILI9341/ST7789, USB and touch variants differ; independent port documentation needs validation. A common CYD label does not prove a matching pin map. |
| NM-CYD-C5 / NM-RF-Hat | Distinct C5/CYD/RF carrier combinations | SquachWatch named C5 beta; HaleHound named RF-Hat targets | C5 base board and original ESP32 CYD with RF-Hat are not synonyms. Check exact target table. |
| nyanBOX hardware | ESP32 + triple NRF24 + OLED | [nyanBOX device firmware](https://github.com/jbohack/nyanBOX) | Dedicated wiring/power; generic ESP32 or NRF24 support is insufficient. |
| wardriver.uk Rev3 | Two WROOM-32U boards plus GPS/SD | [Rev3 A and B programs](../Wardriving/additional-survey-firmware.md) | Both radios remain 2.4 GHz; select stable release and correct A/B physical roles. |

## Raspberry Pi & USB HID Devices

| Device | Software Choices | Installation Format | Limits |
|---|---|---|---|
| Pi Zero 2 W / Pi 3 / 4 / 5 | [jayofelony Pwnagotchi](https://github.com/jayofelony/pwnagotchi), documented [Bjorn](./bjorn_pi.md) hardware/OS combinations | Selected SD image or Linux application setup | Projects have separate OS/architecture/display requirements. Current Pwnagotchi `noai` differs from legacy AI descriptions; not inherently passive. |
| Original Pi Zero W | Legacy Pwnagotchi builds; supported Bjorn setup as documented | 32-bit legacy image/application dependencies | Current Pwnagotchi upstream does not promise new releases for the old Zero W. Do not install a 64-bit Zero 2 W image. |
| Pi running a compatible Pwnagotchi fork | [FancyGotchi 2.0](./fancygotchi-pwnagotchi.md) | Theme/plugin manager on an existing OS | Not a standalone firmware image. Check fork, display and Python compatibility; Pi Zero W/Pi 4 caveats remain. |
| Pico / Pico W / Pico 2 / Pico 2 W | [pico-ducky](../HardwareHacking/pico-ducky-lab.md); named FlipperHTTP Pico variants | Matching CircuitPython UF2 plus files, or project-specific image | USB HID, runtime Wi-Fi UI and an ESP browser flasher are different workflows. |
| ESP8266 + ATmega32U4 WiFi Duck | [Spacehuhn WiFi Duck](https://github.com/SpacehuhnTech/WiFiDuck) | Separate firmware/build for each MCU | ESP8266 supplies Wi-Fi; 32U4 supplies USB HID. Not pico-ducky or a native ESP32 HID build. |

## Dedicated Radio Hardware

| Device | Firmware / Software | Installation Route | Limits |
|---|---|---|---|
| Sniffle-supported TI boards | [Sniffle](./ble-capture-sniffle.md) | TI/device-specific flashing plus matching host release | TI target/bridge baud variant matters; not an ESP32 image. |
| Ubertooth One | [Ubertooth](https://github.com/greatscottgadgets/ubertooth) | Matching host/firmware and documented DFU | Distinct radio hardware and PHY capabilities. |
| Evil Crow RF V2 | [Vendor/custom firmware](../SDR/evil-crow-rf-v2.md) | Matched source/binary + SD web assets | CC1101/NRF narrowband hardware; not a HackRF IQ stream. |
| HackRF + supported PortaPack | [HackRF / Mayhem](../PlayBooks/HackRFAuditPlayBook.md) | Upstream update/recovery plus matching assets | Half duplex; firmware and SD application assets must match hardware revision. |
| Flipper Zero | [Official / Momentum / Unleashed](./flipper_zero_guide.md) | Firmware-specific updater/qFlipper route | STM32WB device; no onboard Wi-Fi scanner. Accessory firmware is a separate installation. |
| Proxmark3 RDV4 / supported generic variants | [RRG/Iceman](https://github.com/RfidResearchGroup/proxmark3) | Matched platform build and client flasher | Generic versus RDV4 settings differ. |
| ChameleonUltra / Lite | [Upstream device firmware](https://github.com/RfidResearchGroup/ChameleonUltra) | Supported GUI/CLI update | Ultra and Lite feature sets differ; not an ESP32 NFC image. |
| Supported Heltec / RAK / other LoRa boards | [Meshtastic](https://github.com/meshtastic/firmware) or [MeshCore](https://github.com/meshcore-dev/MeshCore) | Each project's exact target/role installer | Different protocols and images; region, RF module and role matter. Do not infer both projects support every model from a vendor name. |

## Installation Methods

| Route | Use It For |
|---|---|
| [Dedicated project installers](./firmware-web-flashers.md#dedicated-project-installers) | Upstream-selected board/layout where supplied |
| [ESP Terminator](./esp-terminator.md) | Multi-firmware discovery/uploader; verify each selected image against upstream |
| [General web uploaders](./firmware-web-flashers.md#multi-device--multi-firmware-web-flashers) | Compatible user-supplied images/layouts, not automatic trust or board validation |
| SD / UF2 / DFU / client tools | Pi, Pico, TI, RFID and SDR devices with distinct formats/transports |

## Evidence & Maintenance

This is a source-backed selection list, not an exhaustive or hardware-tested
support matrix. Upstream references and dated metadata live in the
[verification snapshot](./firmware-catalog-verification.json). Recheck exact board
manifests before a purchase or flash. A missing device here means support was not
established in this review, not that the project cannot support it.

---

[Documentation Index](./README.md) | [Master Index](../README.md) | [Role Navigation](../START_HERE.md) | [Legal Notice](../LEGAL.md)
