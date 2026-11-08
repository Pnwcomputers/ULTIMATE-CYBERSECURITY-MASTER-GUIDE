# ESP32 & Related Security Firmware Master Catalog

> [!CAUTION]
> **Authorized use only.** Use these projects for education, defensive research and
> testing on systems you own or have explicit written permission to test.
> Read [LEGAL.md](../LEGAL.md). Permission to test a device does not authorize
> interference with neighboring radio users or interception of their traffic.

_Last reviewed: 2026-11-07_

## Dedicated Setup & Validation Guides

| Resource | Role & Compatibility Boundary |
|---|---|
| [GhostESP Revival](../Documentation/ghostesp-revival.md) | Install, owned-device observations and capture interpretation. |
| [ESP32 Bit Pirate](./esp32-bit-pirate.md) | Board/pin map selection and receive-first UART exercise. |
| [NEMO](../Documentation/nemo-firmware.md) | Exact M5Stack build, storage and benign discovery checks. |
| [C5 Wardriver](../Wardriving/esp32-c5-wardriver.md) | Standalone and coordinator roles with log provenance. |
| [Piglet](../Wardriving/piglet.md) | Local collection, mesh forwarding and automatic-upload review. |
| [BLE Capture / Sniffle](../Documentation/ble-capture-sniffle.md) | Packet capture hardware, matching host and advertisement-only lab. |
| [Pico-Ducky](./pico-ducky-lab.md) | Setup jumper, CircuitPython and harmless HID validation. |
| [Evil Crow RF V2](../SDR/evil-crow-rf-v2.md) | Default/custom firmware distinction and receiver-only baseline. |

## Device-First Selection & Coverage Review

| Resource | Description |
|---|---|
| [Device Firmware List](./device-firmware-list.md) | Hardware model to verified project/install choices, without broad compatibility checkmarks |
| [ESP Terminator](./esp-terminator.md) | Multi-device/multi-firmware host tool, not a firmware image |
| [Additional Survey Firmware](../Wardriving/additional-survey-firmware.md) | PORKCHOP, wardriver.uk and historical wardriver3000 |
| [ChimeraBLE](../Documentation/chimerable.md) | Board-specific BLE setup and active-scan limits |
| [FancyGotchi / Pwnagotchi](../Documentation/fancygotchi-pwnagotchi.md) | Pi image/theme versus independent CYD port |

The first catalog pass missed several independently maintained projects. The
follow-up compared primary project searches with ESP Terminator's live library,
then verified author READMEs and repository metadata for additions. A library
listing alone is discovery evidence, not proof of supported hardware or endorsement.
Desk companions, e-readers and unrelated app categories are outside this security
catalog. Names not resolved to a primary project remain unverified rather than
being silently mapped to a similarly named project. Coverage remains open-ended.

## Purpose

A source-verified reference for selecting ESP32 security firmware and closely
related USB, Bluetooth, RFID and RF research platforms. This catalog identifies
projects, supported target examples, legitimate use, activity signals and install
routes. It is not a flashing tutorial or a claim of hardware testing.

**Prerequisites:** Identify your exact MCU, board revision, flash/PSRAM size, USB
port and peripherals. Start with the [hardware fundamentals](./Chapter2.md).
HID means Human Interface Device; BLE means Bluetooth Low Energy; SDR means
software-defined radio; RF means radio frequency.

## Navigation

| Resource | Description |
|---|---|
| [Multi-Function ESP32](#multi-function-esp32-firmware) | Portable Wi-Fi/BLE, USB, RF & embedded toolkits |
| [Wi-Fi](#wi-fi-surveying--research) | Surveys, sensors & experimental Wi-Fi implementations |
| [USB & HID](#usb-hid--keyboard-research) | Keyboard emulation & related development projects |
| [Bluetooth & BLE](#bluetooth--ble-capture) | Advertisement logging, packet capture & instrumentation |
| [RF & SDR](#sub-ghz-rf--sdr) | Narrowband transceivers versus IQ-based SDR platforms |
| [RFID & Flipper](#rfid-nfc--flipper-platforms) | Dedicated LF/HF hardware & Flipper firmware families |
| [Other Protocols](#lora-mesh--other-protocols) | LoRa, RC links, Zigbee & Thread |
| [Pi Images & Themes](#raspberry-pi-images--companion-interfaces) | Pwnagotchi, FancyGotchi and related device software |
| [Vendor Survey Ecosystems](#vendor-survey-ecosystems) | Biscuit & Scout Lite firmware/controller distinctions |
| [Web Flasher Reference](./firmware-web-flashers.md) | Dedicated installers & a separate multi-device/multi-firmware list |
| [Verification & Maintenance](#verification--maintenance) | Evidence, status definitions, limitations & updates |
| [Existing Repository Guides](#existing-repository-guides) | Detailed workflows without duplicating this catalog |

## Compatibility Boundaries

| Check | Interpretation |
|---|---|
| Exact chip versus board | ESP32, S2, S3, C3, C5, C6 and H2 are different targets. A chip-family label does not validate a particular display, pin map, flash size or antenna. |
| USB HID | An onboard USB-to-UART bridge does not provide native keyboard emulation. S2/S3 USB device builds require the correct port and firmware; original ESP32 boards may need another MCU. [Espressif USB documentation](https://docs.espressif.com/projects/esp-idf/en/stable/esp32s3/api-reference/peripherals/usb_device.html). |
| Bluetooth | BLE advertising, GATT, BLE HID and Bluetooth Classic capture are separate capabilities. A scanner does not automatically capture connections or decrypt traffic. S2 has no Bluetooth. |
| Wi-Fi bands | Most legacy ESP targets are 2.4 GHz; C5 adds 5 GHz on supporting firmware. Dual-band capability does not imply concurrent reception. |
| Sub-GHz / RFID | CC1101, NRF24, PN532, LoRa modules and RFID frontends are separate hardware; firmware cannot create a missing radio. Their protocols and bands are not interchangeable. |
| SDR | ESP32 + CC1101 is a narrowband radio controller, not a HackRF substitute. HackRF supplies IQ samples and is half duplex. |
| Client versus device | A Flipper FAP, a phone app, an ESP image, a UF2 and an SD-card Linux image are different artifacts. Match firmware, companion client and data assets. |

## Reading Activity & Install Columns

**Recent push** means GitHub reported a push within 180 days of review; **Quiet**
means older than 180 days; **Archived** means GitHub marks the repository read-only.
Dates are GitHub `pushed_at` in UTC, not release dates or a promise of support.
A push may affect documentation or another branch. Recheck release notes, open
issues and board manifests before choosing a build. Quiet projects are retained
for historical/research coverage, not recommended as maintained deployments.

Each project-name link credits the primary author/organization and leads to its
README, target details and build instructions. Target examples are not exhaustive
compatibility matrices. **No dedicated web flasher verified** means none was
established from the reviewed primary sources, not proof that none exists.

## Multi-Function ESP32 Firmware

| Project / Upstream | Supported Targets & Extras | Authorized Use / Limits | Activity | Installation |
|---|---|---|---|---|
| [Bruce](https://github.com/BruceDevices/firmware) | Cardputer/ADV, StickC, CoreS3, selected LILYGO/CYD; target-specific modules | Wi-Fi/BLE, HID, IR, RFID & RF; CC1101/NRF24/PN532 capabilities require hardware | Recent push: 2026-11-07 | [Official web flasher](https://bruce.computer/flasher) |
| [ESP32 Marauder](https://github.com/justcallmekoko/ESP32Marauder) | Marauder boards; Flipper ESP32/S2/S3 accessories; Cardputer; selected C5/C6 targets | Wi-Fi/BLE inventory, capture & controlled resilience tests; build-specific radio functions | Recent push: 2026-10-29 | [Official installer](https://justcallmekoko.github.io/MarauderInstaller/) |
| [GhostESP Revival](https://github.com/GhostESP-Revival/GhostESP) | ESP32, S2, S3, C3, C5/C6 targets; display & peripherals vary | Wireless research, captures, BLE & optional RF/NFC; select exact release target | Recent push: 2026-11-06 | [Official web flasher](https://ghostesp.net/flasher) |
| [Evil-M5Project](https://github.com/7h30th3r0n3/Evil-M5Project) | Cardputer/ADV, Core2/CoreS3, AtomS3 & other listed targets | Wireless assessment, portal-awareness & HID labs; feature matrix differs per device | Recent push: 2026-11-04 | [Evil-Flasher](https://7h30th3r0n3.github.io/Evil-Flasher/) |
| [NEMO](https://github.com/n0xa/m5stick-nemo) | M5StickC/Plus/Plus2, Cardputer & documented ports | Wi-Fi/BLE/IR lab toolkit; Cardputer USB analysis is not a guarantee a device is safe | Recent push: 2026-07-15 | M5Burner desktop or upstream source/binaries; no dedicated browser installer verified |
| [ESP32 Bit Pirate](https://github.com/geo-tp/ESP32-Bit-Pirate) | ESP32-S3 DevKit/SuperMini, AtomS3 Lite, Cardputer/ADV, StampS3; >=4 MB flash | UART/SPI/I2C/JTAG/SWD, USB & radio protocol research; formerly ESP32 Bus Pirate | Recent push: 2026-11-01 | [Official web flasher](https://geo-tp.github.io/ESP32-Bit-Pirate/webflasher/) |
| [M5PORKCHOP](https://github.com/0ct0sec/M5PORKCHOP) | Cardputer/ADV S3; GPS/SD; external C5 for reviewed dual-band workflow | Wireless research and survey modes; not the Piglet project | Recent push: 2026-10-06 | Upstream PlatformIO; [survey setup notes](../Wardriving/additional-survey-firmware.md) |
| [HaleHound-CYD](https://github.com/JesseCHale/HaleHound-CYD) | Named CYD/NM-RF-Hat variants; external CC1101/NRF/NFC/GPS as required | Multi-radio toolkit; verify power budget, exact display and module configuration | Recent push: 2026-10-26 | [Official web flasher](https://flash.halehound.com/) |
| [nyanBOX](https://github.com/jbohack/nyanBOX) | Dedicated ESP32 + triple NRF24/OLED hardware | Wireless research; distinct maintained nRFBox derivative; fingerprint claims need corroboration | Recent push: 2026-10-25 | [Project web flasher](https://nyandevices.com/flasher) |

## Wi-Fi Surveying & Research

| Project / Upstream | Supported Targets & Extras | Authorized Use / Limits | Activity | Installation |
|---|---|---|---|---|
| [ESP32 Dual Band Wardriver](https://github.com/justcallmekoko/ESP32DualBandWardriver) | ESP32-C5-DevKitC-1 v1.2; T-Dongle C5 target; GPS/SD per build | 2.4/5 GHz Wi-Fi & BLE survey logging; dual-band does not mean simultaneous reception | Recent push: 2026-11-06 | [C5 installer](https://justcallmekoko.github.io/C5WardriverInstaller/) |
| [Piglet](https://github.com/Hamspiced/piglet) | Seeed XIAO S3/C3/C6/C5; T-Dongle C5; GPS/SD/display as configured | GPS-tagged survey & mesh-node research; only capable C5 builds scan 5 GHz | Recent push: 2026-11-06 | Source/build; no dedicated web flasher verified |
| [ESP32-Paxcounter](https://github.com/cyberman54/ESP32-Paxcounter) | Supported ESP32 LoRa boards, including LILYGO Paxcounter; optional sensors | Wi-Fi/BLE population-counting sensor; identifiers are not reliable unique-person counts | Recent push: 2026-10-04 | Source/build; no dedicated web flasher verified |
| [ESP8266 Deauther](https://github.com/SpacehuhnTech/esp8266_deauther) | ESP8266 NodeMCU/Wemos/DSTIKE variants | Legacy 2.4 GHz Wi-Fi resilience research; not an ESP32 image; disruptive modes restricted | Quiet: 2024-08-14 | Upstream binary/build instructions; generic ESP uploader only with correct image/layout |
| [ESP32 Wi-Fi Penetration Tool](https://github.com/risinek/esp32-wifi-penetration-tool) | Original ESP32 ESP-IDF project; check pinned toolchain | Research PoC for Wi-Fi security behavior; older dependencies, isolated lab only | Quiet: 2024-02-18 | Source/build; no dedicated web flasher verified |
| [ESP32 Open MAC](https://github.com/esp32-open-mac/esp32-open-mac) | Original ESP32 only; Rust/ESP-IDF development setup | Experimental open Wi-Fi MAC implementation; not a turnkey pentest appliance | Quiet: 2025-03-07 | Source/build; no dedicated web flasher verified |
| [wardriver.uk Rev3](https://github.com/JosephHewitt/wardriver_rev3) | Dual WROOM-32U ESP32 boards; A/B programs; GPS/SD | 2.4 GHz Wi-Fi/Bluetooth survey; stable release differs from alpha main | Recent push: 2026-05-25 | Arduino/source or beta binary path; [setup notes](../Wardriving/additional-survey-firmware.md) |
| [wardriver3000](https://github.com/cifertech/wardriver3000) | ESP32 + SSD1306 OLED + GPS + microSD design | Historical Wi-Fi survey design; known PCB caveats; BLE listed as future work | Quiet: 2024-04-28 | Upstream code/schematic; no dedicated web flasher verified |

## USB HID & Keyboard Research

| Project / Upstream | Supported Targets & Extras | Authorized Use / Limits | Activity | Installation |
|---|---|---|---|---|
| [WiFi Duck](https://github.com/SpacehuhnTech/WiFiDuck) | ESP8266 + ATmega32U4 (two MCUs), e.g. documented DIY boards | Wi-Fi-managed USB keyboard-emulation lab; flash each MCU separately | Quiet: 2023-06-02 | Upstream Arduino build/install; device web UI is not a browser firmware flasher |
| [pico-ducky](https://github.com/dbisu/pico-ducky) | Raspberry Pi Pico/Pico W/Pico 2/Pico 2 W; matching CircuitPython | USB HID awareness tests; supported DuckyScript subset differs from Hak5 hardware | Quiet: 2026-03-18 | CircuitPython UF2 + project files; BOOTSEL mass-storage workflow |
| [Pico WiFi Duck](https://github.com/majdsassi/Pico-WIFI-Duck) | Raspberry Pi Pico W | Wi-Fi-controlled USB HID demonstration; distinct from WiFi Duck and pico-ducky | Quiet: 2024-08-20 | Upstream UF2/files; no dedicated browser firmware installer verified |
| [P4wnP1 A.L.O.A.](https://github.com/RoganDawes/P4wnP1_aloa) | Raspberry Pi Zero W; legacy Linux image | USB gadget/HID & network interface research; Linux appliance, not ESP32 firmware | Quiet: 2023-10-26 | Write upstream SD image; no ESP web flasher |
| [ESP32 BLE Keyboard](https://github.com/T-vK/ESP32-BLE-Keyboard) | BLE-capable ESP32 with compatible Arduino/NimBLE versions | BLE HID development library; pairing & host acceptance required; no USB HID | Quiet: 2024-08-07 | Library/example build; not a ready-made security firmware image |

## Bluetooth & BLE Capture

| Project / Upstream | Supported Targets & Extras | Authorized Use / Limits | Activity | Installation |
|---|---|---|---|---|
| [ESP32-BLECollector](https://github.com/tobozo/ESP32-BLECollector) | ESP32 WROOM/WROVER; M5Stack/Odroid-Go/WROVER-Kit; TFT & SD | Passive BLE observations persisted to SQLite; advertisement collection is not connection decryption | Quiet: 2024-09-04 | Source/build; no dedicated web flasher verified |
| [Sniffle](https://github.com/nccgroup/Sniffle) | TI CC1352/CC26x2 & listed newer TI targets; selected SONOFF/CatSniffer boards | BLE 4/5 packet capture & Wireshark analysis; match host code to firmware release | Quiet: 2025-09-25 | TI UniFlash/DSLite & upstream release binaries; no dedicated web installer verified |
| [Ubertooth](https://github.com/greatscottgadgets/ubertooth) | Ubertooth One dedicated hardware | Bluetooth radio research; not ESP32 or a complete universal Bluetooth 5 sniffer | Recent push: 2026-11-05 | Upstream firmware + matching host tools; DFU workflow |
| [Btlejack Firmware](https://github.com/virtualabs/btlejack-firmware) | BBC micro:bit v1 / nRF51822 targets | Legacy BLE connection research; limited PHY support; companion host tool required | Quiet: 2021-01-27 | Upstream HEX; micro:bit mass storage or SWD, target dependent |
| [InternalBlue](https://github.com/seemoo-lab/internalblue) | Supported Broadcom/Cypress Bluetooth chips in listed phones/SBCs | Firmware instrumentation framework; exact chip/ROM/OS matters; not ESP32 | Quiet: 2024-08-21 | Host framework & chip-specific patches; no generic flashable image |
| [ChimeraBLE](https://github.com/MatthewKuKanich/ChimeraBLE) | ESP32 WROOM, XIAO C5, Cardputer ADV targets | BLE GATT/advertisement research; active scan and filesystem provisioning need review | Recent push: 2026-07-07 | Upstream PlatformIO; [dedicated guide](../Documentation/chimerable.md) |
| [SquachWatch-CYD](https://github.com/skizzophrenic/SquachWatch-CYD) | CYD display variants; selected S3/C5/watch builds | Wireless signature detection; a heuristic match is not proof of a camera/tracker or operator | Recent push: 2026-11-07 | [Official web flasher](https://squachwatch.com/) |

## Sub-GHz RF & SDR

| Project / Upstream | Supported Targets & Extras | Authorized Use / Limits | Activity | Installation |
|---|---|---|---|---|
| [Evil Crow RF V2](https://github.com/joelsernamoreno/EvilCrowRF-V2) | Dedicated ESP32 board with dual CC1101 & NRF24L01 | Narrowband protocol/receiver research; web control panel is not a general-purpose SDR | Quiet: 2025-10-18 | Upstream Arduino build/install; no dedicated web flasher verified |
| [Evil Crow Custom Firmware](https://github.com/h-RAT/EvilCrowRF_Custom_Firmware_CC1101_FlipperZero) | Compatible Evil Crow RF hardware; verify V1/V2 wiring/build | Distinct community firmware linked by Evil Crow upstream; Flipper file interoperability | Quiet: 2024-01-18 | Upstream build instructions; not the vendor default firmware |
| [HackRF](https://github.com/greatscottgadgets/hackrf) | HackRF One & upstream-supported hardware revisions | Half-duplex SDR IQ capture/analysis with host; not an ESP32 firmware | Recent push: 2026-11-06 | Matching upstream host/firmware release; DFU/recovery per documentation |
| [PortaPack Mayhem](https://github.com/portapack-mayhem/mayhem-firmware) | HackRF + supported PortaPack revisions; optional SD assets | Standalone SDR applications; verify hardware and SD/app version compatibility | Recent push: 2026-11-07 | Upstream release & documented update workflow; no dedicated web flasher verified |
| [SmartRC CC1101 Driver](https://github.com/LSatan/SmartRC-CC1101-Driver-Lib) | CC1101 attached to supported Arduino/ESP32/ESP8266 platform | Driver/examples for narrowband RF experiments; library, not full security appliance | Recent push: 2026-05-18 | Source/build; no dedicated web flasher verified |

## RFID NFC & Flipper Platforms

| Project / Upstream | Supported Targets & Extras | Authorized Use / Limits | Activity | Installation |
|---|---|---|---|---|
| [Proxmark3 RRG / Iceman](https://github.com/RfidResearchGroup/proxmark3) | Proxmark3 RDV4 & supported generic hardware; select platform | LF/HF RFID analysis; match client & firmware; no blanket support for every card type | Recent push: 2026-11-08 | Upstream build/release & Proxmark flashing tool; no dedicated browser installer verified |
| [ChameleonUltra](https://github.com/RfidResearchGroup/ChameleonUltra) | Dedicated ChameleonUltra/Lite nRF52 hardware | RFID emulation & authorized card research; Lite/Ultra features differ | Recent push: 2026-11-02 | Upstream-supported GUI/CLI update; web console alone is not a verified firmware flasher |
| [Flipper Zero Official](https://github.com/flipperdevices/flipperzero-firmware) | Flipper Zero STM32WB hardware; external ESP needed for Wi-Fi | Baseline IR/Sub-GHz/NFC/RFID/HID platform; not an ESP32 firmware | Recent push: 2026-11-07 | Use upstream update instructions/qFlipper; no verified direct installer URL recorded here |
| [Momentum](https://github.com/Next-Flip/Momentum-Firmware) | Flipper Zero; app/API compatibility tied to firmware | Community Flipper firmware; separate project, not vendor-supported | Recent push: 2026-08-18 | [Project web updater](https://momentum-fw.dev/update/) |
| [Unleashed](https://github.com/DarkFlippers/unleashed-firmware) | Flipper Zero; separate firmware & app ecosystem | Community firmware; removal of a software restriction does not authorize transmission | Recent push: 2026-11-07 | [Project web installer](https://web.unleashedflip.com/) |

## LoRa Mesh & Other Protocols

| Project / Upstream | Supported Targets & Extras | Authorized Use / Limits | Activity | Installation |
|---|---|---|---|---|
| [Meshtastic](https://github.com/meshtastic/firmware) | Supported ESP32/nRF52/RP2040 + LoRa radio boards; exact region/target required | Controlled mesh-security & radio configuration study; not a generic pentesting toolkit | Recent push: 2026-11-07 | [Official web flasher](https://flasher.meshtastic.org/); transport varies by MCU |
| [ExpressLRS](https://github.com/ExpressLRS/ExpressLRS) | Supported RC TX/RX targets (ESP32/ESP8285/STM32 variants) | Owned RC-link testbeds; not generic SDR; bench with propulsion disabled | Recent push: 2026-10-31 | [Official web flasher](https://expresslrs.github.io/web-flasher/); supported targets only |
| [Espressif Zigbee SDK](https://github.com/espressif/esp-zigbee-sdk) | ESP32-C6/H2 native 802.15.4 targets; other host/RCP designs per SDK | Zigbee protocol/device testbeds; SDK examples, not an attack firmware | Recent push: 2026-11-04 | Source/build; no dedicated web flasher verified |
| [Espressif Thread Border Router](https://github.com/espressif/esp-thread-br) | Documented ESP host + 802.15.4 radio co-processor combinations | Thread/IPv6 border-router testbeds; host and RCP firmware must match | Recent push: 2026-11-02 | Source/build; no dedicated web flasher verified |
| [FlipperHTTP](https://github.com/jblanked/FlipperHTTP) | Target-specific ESP32/S2/S3/C3/C5/C6, BW16 and Pi/Pico implementations | Network bridge/library + device firmware; not Flipper OS or a universal scanner | Recent push: 2026-06-04 | Upstream target-directory instructions; companion app separately |
| [MeshCore](https://github.com/meshcore-dev/MeshCore) | Supported Heltec/RAK/other LoRa boards; target and role specific | LoRa mesh testbeds; different protocol/roles from Meshtastic | Recent push: 2026-11-07 | [Official flasher](https://meshcore.io/flasher) |

## Raspberry Pi Images & Companion Interfaces

These are related device software, not interchangeable ESP32 firmware. FancyGotchi
theming does not turn off the underlying image's active wireless behavior.

| Project / Upstream | Supported Targets & Extras | Authorized Use / Limits | Activity | Installation |
|---|---|---|---|---|
| [Pwnagotchi (jayofelony)](https://github.com/jayofelony/pwnagotchi) | Listed 64-bit Pi Zero 2 W / 3 / 4 / 5; legacy Zero W images separate | Wi-Fi research appliance; reviewed noai branch removes old AI; not inherently passive | Recent push: 2026-09-28 | Selected upstream SD image/wiki; [companion guide](../Documentation/fancygotchi-pwnagotchi.md) |
| [FancyGotchi 2.0](https://github.com/V0r-T3x/Fancygotchi) | Compatible Pwnagotchi Pi fork/display/Python combination | Theme manager; Zero W and Pi 4 caveats; not an independent attack firmware | Quiet: 2025-10-26 | Project wiki/plugin files; no browser firmware flasher verified |
| [Bjorn](https://github.com/infinition/Bjorn) | Raspberry Pi with documented OS/display setup | Autonomous network-service assessment; existing closed-lab guide applies | Recent push: 2026-07-20 | Upstream application install; [existing guide](../Documentation/bjorn_pi.md) |
| [FancyGotchi CYD Port](https://github.com/Xombi3/Fancygotchi-cyd-port) | Independent ESP32-2432S028R project | Experimental capture firmware; active behavior and display/wiring claims need validation; not the Pi theme | Quiet: 2026-03-19 | Upstream build files; [project distinction](../Documentation/fancygotchi-pwnagotchi.md) |

## Vendor Survey Ecosystems

These entries separate vendor firmware distributions from controller applications;
neither is an interchangeable generic ESP32 binary.

| Resource | Targets, Use & Install Route |
|---|---|
| [Biscuit Official Flasher](https://flasher.biscuitshop.us/) | Pro/Ultra dual-MCU devices, Crumb, selected C5 DIY/AWOK targets and nodes. Use the [official DIY matrix](https://codehedge.github.io/Biscuit-Wiki/devices/diy.html). Vendor-distributed survey firmware; [official release distribution](https://github.com/CodeHedge/diy_node_web_flasher/releases) is publicly linked, but that archived installer repository does not establish a complete/current firmware source tree or maintenance date. Select production/beta deliberately and flash each applicable MCU. |
| [Scout Lite](https://github.com/pingequalab/scout-lite) | ESP32-C5 + GPS + microSD accessory; vendor docs last pushed 2026-10-24, not archived. [Vendor installer](https://flash.pingequa.com/devices/scout-lite) supplies target-specific firmware options. The documentation repository is not proof that all distributed firmware source is present. |
| [SigRoam](https://github.com/pingequalab/sigroam-wardriving) | Flipper controller app, not an ESP32 image. Repository last pushed 2026-10-24, not archived. Pair the app with the documented Scout Lite firmware/mode; see the [existing pairing guide](../Wardriving/sigroam-scout-lite.md). |

## Unresolved Discovery Candidates

These names are not verified firmware entries and are excluded from verified-project counts.

| Candidate | What Remains Unresolved |
|---|---|
| WardriveSP / wardrivesp | No primary upstream resolved under the supplied spelling; not silently equated to wardriver.uk, Piglet or JCMK. |
| Cheap YellowMonster / AxD / Sticks & Stones | Names observed in the [ESP Terminator library](https://espterminator.com/); primary ownership, exact targets, source/release provenance and support status still need verification. |

## Historical Projects & Exclusions

| Resource | Disposition |
|---|---|
| [Original GhostESP](https://github.com/Spooks4576/Ghost_ESP) | Archived; last push 2025-04-22. Preserved for lineage; use the separately maintained Revival project when evaluating current support. |
| [ESP32 Sour Apple](https://github.com/RapierXbox/ESP32-Sour-Apple) | Historical BLE availability-impact demonstration; last push 2026-06-03, not archived. Included only to identify the project and its disruption risk. No crash instructions, payloads or flasher recommendation. OS mitigation status requires separate verification. |
| Payload packs & third-party firmware mirrors | Excluded as authoritative firmware sources. [HackStarterPack integration](./m5stickc-plus2-hackstarterpack.md) already covers source review and benign lab selection. |
| Host-only software | Kismet, Wireshark, GNU Radio, rtl_433 and phone apps are valuable companions, not ESP32 firmware. Use the linked repository guides. |

## Safety & Flashing Review

1. Record the exact board/chip/revision and current firmware. Back up permitted
   configuration, keys and logs; a full erase may destroy all of them.
2. Obtain binaries from upstream releases or an upstream-endorsed installer.
   Match the target, flash layout, partition scheme, bootloader, app and SD assets.
   Do not treat a generic uploader as a firmware trust or compatibility check.
3. Review source/release provenance and published hashes/signatures where supplied.
   A hash from the same compromised download page is not independent authentication.
   Review each upstream license before redistributing code, binaries or assets.
4. Use an offline disposable host for HID tests with harmless text in a blank
   editor. Inspect scripts first; do not run supplied credential, shell or persistence payloads.
5. Keep portal demonstrations synthetic and use no real passwords. Protect BLE,
   MAC, location, packet-capture and RFID data with access controls and retention limits.
6. Use conducted, attenuated or appropriately shielded RF lab arrangements and
   confirm frequency, power, duty-cycle, antenna and licensing requirements locally.
   Jamming, deauthentication, pairing floods and replay can affect uninvolved users.
   Written device-owner consent does not override radio law; see [FCC jammer guidance](https://www.fcc.gov/general/jammer-enforcement).
7. Disconnect motors/propulsion from RC testbeds, use sacrificial cards/tags and
   confirm recovery procedures before writing firmware or testing disruptive modes.

## Verification & Maintenance

Reviewed primary upstream READMEs, repository metadata, installer pages and the
existing repository at commit
[`30737191a292`](https://github.com/Pnwcomputers/ULTIMATE-CYBERSECURITY-MASTER-GUIDE/tree/30737191a292439f1779a1405f95cf57df6b196e).
Searched Markdown for ESP32, firmware, Marauder, Flipper and HackRF, then inspected
the related guides and contribution/style rules. No existing consolidated catalog
with this category coverage and separate web-flasher reference was found.
The existing compatibility matrix contains broad/legacy claims; this catalog
uses narrower upstream target examples rather than copying its checkmarks.

A [machine-readable verification snapshot](./firmware-catalog-verification.json)
records repository metadata and initial URL-check results, including excluded
installer guesses and fetch limitations.

Verification here means source identity, documented target/use and link review;
it does not mean binaries were flashed, builds reproduced, radio behavior tested
or firmware security audited. Repository push dates alone do not establish active
maintenance. Firmware lists are necessarily bounded: this is broad coverage of
verified projects, not a claim to enumerate every fork or new release.

For the next review, check repository transfers/archives, current target manifests,
release/client compatibility, flasher ownership and production versus beta channels.
Update the review date only after rechecking. Retain useful quiet projects with
explicit labels; do not silently replace upstreams with similarly named mirrors.
Installer checks and unresolved link limitations are recorded in the
[web-flasher reference](./firmware-web-flashers.md#verification-notes).

## Existing Repository Guides

| Resource | Use This For |
|---|---|
| [Hardware Hacking](./README.md) | Electrical fundamentals, interfaces & hardware lab progression |
| [Firmware Compatibility](../firmware-hardware-compatibility.md) | Existing hardware matrix; validate legacy cells against current upstream targets |
| [Bruce](../Documentation/bruce_firmware.md) | Existing module-specific Bruce guide |
| [Evil-M5](../Documentation/evil_m5.md) | Existing Evil-M5 operational guide |
| [Marauder Survey Guide](../Wardriving/esp32-marauder.md) | Hardware, GPS & survey logging |
| [Marauder Reference](../Documentation/WiFiMarauder_Guide.md) | Existing Marauder documentation |
| [Wardriving Index](../Wardriving/README.md) | Field workflow, Biscuit, Scout Lite, GPS & privacy |
| [USB HID Lab](../Scripts/Ducky/README.md) | Safe HID demonstration & script compatibility boundaries |
| [SDR Index](../SDR/README.md) | SDR/RF learning paths & radio-specific guides |
| [HackRF Playbook](../PlayBooks/HackRFAuditPlayBook.md) | RF survey planning, IQ evidence & bench validation |
| [RFID](../SDR/rfid.md) | Dedicated RFID/NFC workflow |
| [ESP32-S3 Honeypots](../IncidentResponse/HoneyPot/esp32-s3-honeypots.md) | Existing defensive sensor/decoy lab; separate from offensive firmware |

---

[Back to Master Index](../README.md) | [Role Navigation](../START_HERE.md) | [Legal Notice](../LEGAL.md)
