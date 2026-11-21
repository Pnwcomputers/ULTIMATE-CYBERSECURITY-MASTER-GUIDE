# SBCs, Portable Security Devices, Firmware & Radio Add-On Compatibility

_Reviewed: 2026-11-21. This is a reference and preflight guide, **not** a promise that untested board/firmware combinations are plug-and-play._

> [!CAUTION]
> **Authorized RF labs and safe wiring only.** Verify each board's electrical voltage, GPIO pin mapping, current budget, antenna/frequency rating and firmware build before connecting modules. Radio transmissions, active authentication tests and capture of third-party data require separate approval. Do not power or hot-plug unverified SPI/I²C modules. See [Legal Notice](../LEGAL.md).

## What Counts as an SBC, Radio Adapter or Portable Controller?

A **single-board computer (SBC)** commonly runs Linux, with a USB host controller, filesystems, network services and package management. A **microcontroller board** (ESP32, M5StickC, ATtiny) runs board-specific firmware and does not automatically load a Linux USB Wi-Fi driver. The **Flipper Zero** is its own handheld platform; an ESP32 add-on has its **own firmware**. A device with a 2.4 GHz antenna does not automatically support Wi-Fi, Bluetooth sniffing and NRF24 protocols.

**Status legend:** **Native** = built into exact listed board; **Conditional** = external adapter/module + correct driver, firmware, cabling, power or build; **Custom** = source changes/wiring/driver needed; **No** = no reasonable direct support; **Untested** = not verified by this guide. **Native does not mean every operation is available.**

## Linux SBC & Host Comparison

| Host / Project | Linux & Driver Model | Wi-Fi Capture Adapter | BLE RF Sniffer | GPIO Add-Ons | Setup Complexity |
|---|---|---|---|---|---|
| [Raspberry Pi 4](https://www.raspberrypi.com/products/raspberry-pi-4-model-b/) | ARM64 Linux; standard USB host | **Conditional**: AR9271, MT7612U etc. subject to kernel/firmware | **Conditional** via supported USB Nordic/TI | SPI/I²C/UART on GPIO header; correct overlays | OS install straightforward; wireless capture **not** plug-and-play |
| [Raspberry Pi 5](https://www.raspberrypi.com/products/raspberry-pi-5/) | ARM64 Linux; PCIe 2.0 x1 header + USB | **Conditional**; use powered hub if needed | **Conditional** | HAT+ and GPIO, with stacking/power constraints | OS straightforward; PCIe HAT/GPIO require setup |
| [Raspberry Pi Zero 2 W](https://www.raspberrypi.com/products/raspberry-pi-zero-2-w/) | ARM Linux; single micro-USB OTG data port | **Conditional** with correctly wired *host* OTG hub | **Conditional**; host software/USB support | 40-pin expansion; limited CPU and power | High power/OTG sensitivity |
| [Compute Module 4/5](https://www.raspberrypi.com/products/compute-module-5/) | Depends on carrier, OS image, I/O lanes | **Carrier/USB-dependent** | **Carrier/USB-dependent** | Only carrier-exposed pins are usable | Verify exact carrier and image |
| [ClockworkPi uConsole CM4/CM5](https://www.clockworkpi.com/uconsole) | CM4/CM5 image + board-specific hardware | **Conditional**: USB adapter and host driver | **Conditional**: USB sniffer + host tools | Expansion boards/pin access constrained | Image, hub, battery and expansion qualification |
| [Orange Pi 5 / Radxa ROCK 5](https://docs.radxa.com/) | ARM Linux/board kernel, variant-specific | **Conditional**: package/USB driver not guaranteed | **Conditional** | Pins/overlays differ from Raspberry Pi | Board-specific device tree and kernel |
| [x86 mini PC / NUC](https://www.intel.com/content/www/us/en/products/details/nuc.html) | Full Linux/Windows with USB host | **Conditional**: USB adapter and capture driver | **Conditional** | Often needs USB GPIO bridge; no Pi HAT header | Most flexible host, fewer GPIO options |
| [OpenWrt router](https://openwrt.org/) | Embedded Linux; model-specific driver/USB | **Highly conditional**: package/kernel/USB host | Rare / specialized | GPIO usually not exposed for add-ons | Not a general-purpose pentest SBC |

**Raspberry Pi 5 power reminder:** the official 5 V/5 A power arrangement allows a larger downstream USB current budget than a 5 V/3 A arrangement, which restricts peripheral current. Multiple ALFA USB adapters, SDRs, NVMe storage and BLE sniffers can overload a small supply. Verify current official [power guidance](https://www.raspberrypi.com/documentation/computers/raspberry-pi.html#power-supplies), use a **powered USB hub** where appropriate, and never assume USB passthrough avoids physical power limits.

### Wi-Fi USB Adapter Compatibility Is a Host+Chipset+Kernel Property

| Wi-Fi Adapter / Chipset | Pi 4/5 | uConsole CM4/CM5 | x86 Kali / Proxmox VM | ESP32 / Flipper Standalone | Capability Caution |
|---|---|---|---|---|---|
| [AWUS036NHA / AR9271](./wifi-adapter-selection-guide.md) | Conditional, `ath9k_htc` | Conditional, USB + ARM kernel | Conditional, passthrough required in VM | **No ordinary USB driver path** | 2.4 GHz only; monitor/injection test separately |
| [AWUS036ACM / MT7612U](./wifi-adapter-selection-guide.md) | Conditional, `mt76x2u` | Conditional, hub/power/driver | Conditional | **No ordinary USB driver path** | Dual-band, but firmware/regulatory constraints apply |
| [AWUS036ACHM / MT7610U](./wifi-adapter-selection-guide.md) | Conditional, `mt76x0u` | Conditional | Conditional | **No ordinary USB driver path** | Not same product as AWUS036ACH |
| [AWUS036ACH / RTL8812AU](./wifi-adapter-selection-guide.md) | Conditional, driver/kernel dependent | Conditional, driver/kernel dependent | Conditional, VM passthrough | **No ordinary USB driver path** | Driver fork/build compatibility varies |
| [AWUS036AXM/AXML / MT7921AUN family](./wifi-adapter-selection-guide.md) | Conditional, kernel/firmware/regdomain | Conditional, board image & power | Conditional, newer supported drivers | **No ordinary USB driver path** | 6 GHz monitor and injection **not guaranteed** |
| Onboard Pi/uConsole WLAN | Native *client* capability if included | Carrier/CM-specific | Host-specific | N/A | Ordinary Wi-Fi association ≠ reliable monitor/injection |

**Plug-and-play rule:** standard Wi-Fi connectivity may work with an in-kernel driver, but **monitor mode, packet injection, full 5/6 GHz capture, external antennas, firmware blobs and ARM64 support always need independent qualification**. See the detailed [Wi-Fi Adapter Selection Guide](./wifi-adapter-selection-guide.md). A VM's bridged/NAT `eth0` does not expose wireless management frames: pass through the **physical** USB radio.

## Handhelds, MCU Boards & Firmware Compatibility

| Device | Built-In Radio / Interface | Applicable Firmware & Field Role | External Wi-Fi USB NIC? | Module Add-On Notes |
|---|---|---|---|---|
| [Flipper Zero](https://docs.flipper.net/zero/development/hardware/tech-specs) | Sub-GHz CC1101, NFC, LF RFID, BLE for Flipper functions | [Stock](./flipper_zero_guide.md) or supported third-party Flipper apps/firmware | **No**, not a Linux USB Wi-Fi NIC host | ESP32 Marauder requires **separate compatible external ESP32**; GPIO 3.3 V logic |
| [M5StickC Plus2](https://docs.m5stack.com/en/core/StickC-Plus2) | Original ESP32 2.4 GHz Wi-Fi/BLE, IR, small screen | [Bruce](./bruce_firmware.md), [NEMO](./nemo-firmware.md), supported [Evil-M5](./evil_m5.md) target only | **No** | CC1101, nRF24, PN532 **conditional** on firmware build and exact pinout |
| [M5Cardputer / Cardputer ADV](https://docs.m5stack.com/) | Board-specific ESP32-S3 2.4 GHz Wi-Fi/BLE, USB | Bruce/NEMO/Evil-M5/GhostESP **only on listed targets** | **No generic Linux NIC driver** | SPI/I²C module routing, keyboard/USB roles and SD pin conflicts |
| [LILYGO T-Embed CC1101](https://github.com/Xinyuan-LilyGO/T-Embed) | ESP32-family board plus integrated CC1101 on identified variant | Firmware **only if exact T-Embed CC1101 board target supported** | **No** | Integrated CC1101 avoids external SPI module; GPS UART accessory remains separate |
| [ESP32-S3 dev board](https://www.espressif.com/en/products/socs/esp32-s3) | 2.4 GHz Wi-Fi/BLE; native USB capabilities vary by board | Marauder, GhostESP, Bruce etc. **only for supported builds** | **No standard Linux USB NIC** | CC1101/PN532/nRF24 possible with compatible driver/firmware and GPIO |
| [ESP32-C5 dev board](https://www.espressif.com/en/products/socs/esp32-c5) | Dual-band 2.4/5 GHz Wi-Fi 6 and BLE features | C5-specific firmware targets; [board list](./device-firmware-list.md) | **No** | No assumption that every firmware enables all C5 RF capabilities |
| [WiFi Pineapple](https://shop.hak5.org/products/wifi-pineapple) | Dedicated Linux wireless appliance, model-dependent radios | Vendor firmware/payload workflows | USB role **model-dependent** | Not a universal Pi HAT, GPIO module host or raw BLE sniffer |
| [ESP32 CYD / M5Stack boards](./esp32-security-firmware-catalog.md) | Radio and display depend on exact MCU | GhostESP/Marauder/Bruce, **target-specific** | **No** | Never reuse pin maps from another board |

**Not interchangeable:** Flipper firmware vs an attached ESP32's Marauder image; Bruce vs GhostESP target binaries; M5StickC Plus2 (original ESP32) vs ESP32-S3; C5 vs C6 board packages. A board may expose a menu for CC1101 or NFC but **lack the physical module or usable pins**. Review [Device-First Firmware List](./device-firmware-list.md), [Bruce's feature matrix](https://github.com/BruceDevices/firmware#supported-devices) and [Marauder supported hardware](https://github.com/justcallmekoko/ESP32Marauder/wiki/Supported-Hardware).

## Add-On Modules & HATs: Abilities & Integration

| Module / Example | Interface & Power | What It Does | Likely Hosts | PnP? / Major Caveat |
|---|---|---|---|---|
| [CC1101](https://www.ti.com/product/CC1101) | **3.3 V SPI** + GPIO, tuned antenna | Sub-GHz receive/transmit in supported bands | Pi with appropriate software, ESP32/M5 with supported firmware, Flipper external on selected apps | **Custom/Conditional**: pins, legal RF bands, antenna, library, voltage |
| [nRF24L01(+)](https://www.nordicsemi.com/Products/Low-power-short-range-wireless/nRF24-series) | **3.3 V SPI**, good supply decoupling | Proprietary 2.4 GHz Enhanced ShockBurst-style radio | Pi/ESP32/Flipper expansion if supported | **Custom/Conditional**; **not BLE**, not a USB Bluetooth dongle |
| [PN532](https://www.nxp.com/products/PN532) | SPI / I²C / UART depending breakout; check **logic levels** | 13.56 MHz NFC / selected tag protocols | Pi/ESP32/Flipper accessory path only if supported | **Custom/Conditional**, module and firmware support matter |
| [MFRC522 / RC522](https://www.nxp.com/products/MFRC52202HN1) | 3.3 V SPI module | Selected ISO/IEC 14443-A reader operations | Pi / Arduino / ESP32 | **Custom**, not general purpose NFC/FeliCa/125 kHz |
| 125 kHz LF RFID reader board | UART, Wiegand or board-specific pins | LF tag identification with supported protocol | Pi / MCU via suitable input | **Conditional**, read logic voltage; not interchangeable with PN532 |
| [GT-U7 GPS / GNSS](https://www.u-blox.com/) or u-blox M8/M10 | UART NMEA/PPS depending board; breakout VCC varies | Position/time, optionally PPS | Pi, uConsole, selected ESP32/M5 firmware | **Conditional**: correct TX/RX, 3.3 V UART logic, antenna, GPS fix, parsing |
| USB GNSS receiver | USB CDC/serial + NMEA or vendor protocol | GPS for Kismet/WiGLE/gpsd | Linux SBC/uConsole/x86 | **Usually easiest**, but requires gpsd/source config and sky view |
| [SX127x/SX126x LoRa](https://www.semtech.com/products/wireless-rf/lora-connect) | 3.3 V SPI + IRQ/reset + antenna | Sub-GHz LoRa packet communications | Pi or ESP32 with dedicated firmware | **Custom**, different registers/driver families, regional restrictions |
| [Pi M.2 HAT+](https://www.raspberrypi.com/products/m2-hat-plus/) | Pi 5 PCIe ribbon, power and mechanical fit | NVMe or other supported M.2 peripherals | Pi 5 / compatible carrier only | **Conditional**; not Pi 4/Zero generic HAT |
| GPS / RTC / UPS / PoE HAT | GPIO/I²C/SPI/PoE headers vary | Position, timekeeping, battery or power | Specific Raspberry Pi/carrying board | **Conditional**: stacking, voltage, battery safety, driver overlay |
| USB powered hub | Host USB + separate regulated supply | Supports multiple USB radios/SSDs/Sniffers | Pi/uConsole/x86 with real USB host | **Generally straightforward**; budget total power & RF/USB interference |
| USB RTL-SDR / HackRF | USB + SDR host program | General RF monitoring (model-specific) | Linux SBC/uConsole/x86 | **Conditional**; different from 802.11 Wi-Fi or BLE sniffer |
| [Ubertooth One](https://greatscottgadgets.com/ubertoothone/) / [nRF52840 sniffer](./bluetooth-radio-adapter-guide.md) | USB + specific host/sniffer firmware | BLE/BT research vs dedicated BLE captures | Linux/Windows where supported | **Conditional**; not Wi-Fi adapters |

**Power/voltage:** 3.3 V GPIO signaling is the safe default for Pi/Flipper/ESP32 digital pins unless **specific** documentation says otherwise. A module breakout accepting 5 V at its regulator **does not mean its TX/RX/SPI pins are 5 V tolerant**. Use logic-level conversion when necessary. Never wire radio TX pins into another active output or hot-plug an energized SPI module.

### Raspberry Pi HAT & GPIO Checklist

1. Verify the Pi/carrier model and **40-pin header orientation**, occupied pins and HAT EEPROM/device-tree overlays.
2. Confirm SPI bus/chip select, I²C address conflicts, UART console reassignment, IRQ and reset pins, and any HAT stacking conflicts.
3. Check current draw at boot and during RF transmissions, not just idle. Use a reputable UPS/power supply and powered hub when required.
4. Mount antennas away from metal cases and noisy USB 3.0/storage cables; observe antenna and legal frequency limits.
5. Install only trusted driver modules / package releases; keep a full rollback/snapshot of kernel and board configuration.
6. Record exact GPIO mapping and a photo/diagram **for that board**; never reuse a Flipper CC1101 map on a Cardputer or M5StickC.

## Firmware-to-Capability Matrix

| Firmware / Software | Required Host | Wi-Fi Role | Bluetooth / BLE Role | CC1101 / NFC / GNSS |
|---|---|---|---|---|
| [Kismet](https://www.kismetwireless.net/) | Linux host and supported datasource | Survey, capture, WIDS & GPS logging with compatible adapters | Device discovery / BLE datasource as supported | External RF modules **not automatically** supported as Kismet sources |
| [BlueZ & Nordic Sniffer](./bluetooth-passive-scanning-sniffing.md) | Linux HCI / compatible Nordic sniffer | **Not** Wi-Fi | Discovery vs raw BLE sniffing (different hardware) | GNSS context separate |
| [Bruce](https://github.com/BruceDevices/firmware) | Exact supported ESP32 board | 2.4 GHz inventory/selected tests where firmware supports | BLE features per board/build | CC1101 / nRF24 / PN532 may work **only** with pins/modules/feature enabled |
| [ESP32 Marauder](https://github.com/justcallmekoko/ESP32Marauder) | Supported ESP32/companion target | 802.11 survey & selected active tests | Build/board dependent | External GPS/SD support varies; no universal CC1101/NFC promise |
| [GhostESP](https://github.com/ghostesp/ghostesp) | Specifically supported ESP board | Wireless assessment per target/firmware | BLE per target | Module support **not interchangeable with Bruce** |
| [NEMO](./nemo-firmware.md) | Supported M5Stack boards | Wi-Fi observations | BLE exercises where supported | IR/SD/USB capabilities vary, not all accessories |
| [Evil-M5](./evil_m5.md) | Exact supported M5Stack device | Wireless lab methods | BLE/HID functions vary | Check display, GPIO and onboard radio pins |
| [Flipper stock](https://github.com/flipperdevices/flipperzero-firmware) | Flipper Zero | **No built-in Wi-Fi** | Handheld BLE for its own functions | Built-in CC1101 and NFC; external ESP module separately flashed |
| [Pwnagotchi](https://github.com/evilsocket/pwnagotchi) | Linux Pi-class host + compatible Wi-Fi adapter | Monitor capture; autonomous modes may transmit | Separate Bluetooth management is not raw BLE sniffing | GPS requires separately supported accessory |
| [Wifite2/Wifite3](./wifite-guide.md) | Supported Linux/Windows host & **listed USB Wi-Fi card** | Automated active assessment tool, not basic survey | None as BLE capture | No built-in CC1101 or NFC driver |

**"Plug-and-play" claim must apply to a particular function.** Example: an AWUS036ACM may connect normally as a Linux Wi-Fi interface while still requiring capture-mode verification; an nRF52840 dongle only becomes a BLE protocol sniffer after the right firmware and host software.

## Recommended Build Profiles

| Profile | Host & Radio | Accessory Set | Good For | Gate Before Deployment |
|---|---|---|---|---|
| **Basic Wi-Fi WIDS** | Pi 4/5 + verified USB MT7612U/AR9271 | Powered USB if needed, storage, UPS | Kismet fixed-channel capture, SIEM forwarding | Capture channel coverage and RF authorization |
| **Portable cyberdeck** | uConsole CM4/CM5 + qualified carrier/AIO v2 | USB Wi-Fi receiver, GNSS, battery, SD | Portable authorized inventory and manual evidence export | Kernel/image, USB 2 vs 3, current/thermal tests |
| **Bluetooth/BLE bench** | Pi/x86 + ordinary HCI + separate Nordic nRF52840 sniffer | Owned BLE beacon, Wireshark, secure capture disk | Compare discovery events vs BLE RF packets | Correct sniffer firmware, device privacy controls |
| **Sub-GHz experimentation** | Supported ESP32 + CC1101 or Flipper built-in radio | Tuned antenna, proper voltage, labeled modules | Test own permitted sub-GHz sensors/remotes | Regional frequency and firmware/pin map |
| **NFC lab** | Pi/ESP32 + PN532 | Owned test tags, proper logic level | Inventory supported tag types and reader responses | Protocol & antenna capability match |
| **Multi-radio home lab** | Pi 5 or x86 host | Powered USB hub, multiple receive radios, GNSS | Correlated Wi-Fi, BLE and SDR observations | Separate source coverage and storage/privacy limits |

## Reproducible Preflight & Troubleshooting

On a Linux SBC, run **read-only** environment checks first:

```bash
uname -a
lsusb -nn
ip -brief link
iw dev
bluetoothctl list
ls /dev/ttyUSB* /dev/ttyACM* 2>/dev/null || true
dmesg | tail -n 50
```

| Failure | Check Before Changing Software |
|---|---|
| USB device absent | Cable, OTG **host** mode, USB power, hub and correct device path |
| Wi-Fi connects but cannot capture | Driver monitor mode, firmware, regulatory region; no guarantee of injection |
| GNSS shows serial output but no position | Valid sky fix, NMEA baud/protocol, gpsd port, antenna |
| CC1101/PN532 not detected | Wrong GPIO/pinout/CS/I²C address, power level, unsupported firmware target |
| HAT disappears after adding another | Overlapping GPIO bus/address, connector alignment, power draw |
| BLE discovery works but sniffing not | Host HCI vs separate RF sniffer, firmware and Wireshark source |
| Flipper add-on has no Wi-Fi | External ESP32 needs the correct hardware and firmware, separate from Flipper app |
| Radio transmission fails | Legal band, antenna matching, module capability, GPIO/firmware support; do not force retries |
| Pi reboots with two radios attached | USB current limits, battery, heat, connector integrity |

## Sources & Related Repository Guides

| Source | Why It Matters |
|---|---|
| [Raspberry Pi Hardware Documentation](https://www.raspberrypi.com/documentation/computers/raspberry-pi.html) | USB current, GPIO, HATs and power |
| [HackerGadgets AIO V1/V2](https://hackergadgets.com/pages/hackergadgets-uconsole-rtl-sdr-lora-gps-rtc-usb-hub-all-in-one-extension-board-setup-guide) | uConsole board roles and dependencies |
| [M5StickC Plus2](https://docs.m5stack.com/en/core/StickC-Plus2) | Exact ports & electronics |
| [Bruce Hardware Matrix](https://github.com/BruceDevices/firmware) | Actual board/external-module capabilities |
| [Flipper Hardware Specs](https://docs.flipper.net/zero/development/hardware/tech-specs) | CC1101, NFC, 3.3 V GPIO |
| [Wi-Fi Adapter Matrix](./wifi-adapter-selection-guide.md) | Chipset + driver + monitor/injection evidence |
| [Bluetooth & BLE Adapter Matrix](./bluetooth-radio-adapter-guide.md) | HCI vs RF sniffers vs sub-GHz |
| [Device-First Firmware Index](./device-firmware-list.md) | Existing canonical target & firmware mapping |
| [uConsole Setup Index](../uConsole/README.md) | CM4/CM5/AIO board-specific procedures |
| [Flipper Expansions](./flipper_zero_guide.md) | CC1101/nRF24/ESP add-on qualification |
| [Cyberdeck Portable Wireless Devices](../Cyberdeck/docs/PORTABLE_WIRELESS_FIELD_DEVICES.md) | Portable build/integration & evidence |
| [LAN TAPs & Network Visibility](./network-taps-and-packet-visibility.md) | Wired Ethernet capture path |

---

[Documentation Index](./README.md) | [Hardware Hacking](../HardwareHacking/README.md) | [Legal Notice](../LEGAL.md)
