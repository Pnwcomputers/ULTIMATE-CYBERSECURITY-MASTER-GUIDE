# Bluetooth, BLE & Adjacent RF Hardware: Adapter Comparison & Compatibility

_Reference research: 2026-11-21. This is a sourced **capability and platform comparison**, not a hands-on certification of every firmware and board revision._

> [!CAUTION]
> **Authorized monitoring & research only.** Bluetooth device discovery, over-the-air capture, identity changes and RF transmission are different operations with different authorization requirements. Observe privacy law, local radio rules, and written test scope. Do not track individuals, impersonate their devices or interfere with active connections. See [Legal Notice](../LEGAL.md).

## Start Here: These Are Not All Bluetooth Adapters

| Class | Examples | Radio / Protocol | Important Boundary |
|---|---|---|---|
| Regular HCI Bluetooth adapter | Supported CSR/Intel/Realtek/Broadcom USB or internal adapter | Classic BR/EDR and/or BLE **depending on chipset** | For **host-originated** operations and `btmon`; not automatically an over-the-air sniffer |
| Dedicated BLE sniffer | Nordic nRF52840 Dongle / DK with nRF Sniffer firmware | Bluetooth **Low Energy** | Sniffs supported BLE traffic; not full Classic Bluetooth |
| Specialist Bluetooth research radio | Ubertooth One | 2.4 GHz Bluetooth-oriented development | Legacy/retired hardware with Classic hopping limitations |
| BLE development board | nRF52 / nRF52840, supported Silicon Labs EFR32, TI CC26xx | BLE, and sometimes IEEE 802.15.4 | Sniffing requires compatible vendor firmware/tooling |
| Generic 2.4 GHz SDR | HackRF One | RF IQ samples, wide frequency capability | No turnkey Bluetooth packet decode or hop-follow |
| Sub-GHz transceiver | **YARD Stick One** | 300–928 MHz selected bands | **Not Bluetooth**: Bluetooth uses 2.4 GHz |
| Small microcontroller family | **ATtiny** | **No inherent Bluetooth radio** | Requires a **separate** BLE module/transceiver; no generic sniffing claims |
| Wi-Fi interface | ALFA 802.11 adapters | 2.4/5/6 GHz **Wi-Fi** | 2.4 GHz overlap does **not** mean Bluetooth capability |

## Bluetooth Classic vs BLE

Bluetooth Classic (BR/EDR) and Bluetooth Low Energy (BLE) differ in channel structures, connection procedures, hopping behavior, PHY and application layers. Capturing advertising packets is **not the same as decoding all connection data**. Encryption and the capture start time can prevent payload interpretation.

An ordinary USB HCI radio can support `bluetoothctl`, `btmon`, legitimate pairing and application tests **without exposing raw over-the-air frames from other devices**. Wireshark can dissect HCI logs or sniffer-provided RF captures; the capture source and what it contains must be recorded.

## Passive Bluetooth Scanning & Packet Sniffing

| Operation | What Happens | Visibility |
|---|---|---|
| BLE passive scan | Listen without LE scan requests | Advertisements, not scan responses |
| BLE active scan | Send scan requests to scannable advertisers | Advertisements plus scan-response data |
| `bluetoothctl scan on` | BlueZ discovery; **not necessarily passive** | Device/property events, not raw over-the-air frames |
| `btmon` | Inspect local HCI commands/events | Host traffic, not independent RF sniffing |
| Nordic nRF52840 sniffer | Dedicated supported firmware and host software | Raw BLE packets; channel/PHY limitations |

An owned-device scan via `bluetoothctl` is useful discovery, but it may be active. Optional timestamped output: `stdbuf -oL bluetoothctl -- scan on | ts '[%Y-%m-%d %H:%M:%S]'` (from `moreutils`); invocation may vary by BlueZ version. Inspect `btmon` to verify LE scan parameters. Random/private Bluetooth addresses may rotate, so a MAC or name alone does not establish a device or person's identity.

**Full guide:** [BLE Passive Scanning, Raw Sniffing & Privacy](./bluetooth-passive-scanning-sniffing.md), [Novel Bits Sniffer Comparison (2026)](https://novelbits.io/bluetooth-low-energy-ble-sniffer-tutorial/) and [Nordic's nRF Sniffer Lesson](https://academy.nordicsemi.com/courses/bluetooth-low-energy-fundamentals/lessons/lesson-6-bluetooth-le-sniffer/). Also see [SBC & Add-On Compatibility](./sbc-radio-addon-compatibility.md).

## Detailed Hardware Comparison

**Key:** **Supported path** = documented vendor project; **Conditional** = hardware, firmware, revision, tool or driver constraints; **No** = not the hardware's radio/protocol.

| Device | Main RF / Technology | BLE Advertising Observation | BLE Connection Sniffing | Classic BR/EDR Air Sniffing | Platform / Software |
|---|---|---|---|---|---|
| [Ubertooth One](https://greatscottgadgets.com/ubertoothone/) | 2.4 GHz experimental Bluetooth radio | Supported legacy tooling | Conditional; capture limits | Partial / research-only | [libubertooth](https://github.com/greatscottgadgets/ubertooth), Linux host & firmware match |
| [Nordic nRF52840 Dongle](https://github.com/zephyrproject-rtos/zephyr/blob/main/boards/nordic/nrf52840dongle/doc/index.rst) | 2.4 GHz BLE + multiprotocol SoC | Supported path | Supported path for compatible BLE traffic; missed frames possible | **No** | [nRF Sniffer for Bluetooth LE](https://www.nordicsemi.com/Products/Development-tools/nRF-Sniffer-for-Bluetooth-LE) + Wireshark |
| [Nordic nRF52840 DK](https://github.com/zephyrproject-rtos/zephyr/blob/main/boards/nordic/nrf52840dk/doc/index.rst) | BLE + IEEE 802.15.4 development board | Supported path | Supported path for compatible BLE traffic | **No** | Nordic sniffer firmware / host tools; board-specific |
| [Makerdiary nRF52840 MDK](https://wiki.makerdiary.com/nrf52840-mdk-usb-dongle/) | 2.4 GHz multiprotocol development | Conditional with matching image | Conditional with compatible firmware/tooling | **No** | Board-specific bootloader, firmware, flashing |
| [Silicon Labs EFR32](https://www.silabs.com/developer-tools/wireless/bluetooth) | BLE / multiprotocol family | Supported using selected development kits | Conditional, with vendor Network Analyzer | **No** | Simplicity Studio / supported boards & tool versions |
| [TI CC2540 USB Dongle](https://www.ti.com/tool/PACKET-SNIFFER) | Legacy Bluetooth Low Energy | Supported (older BLE) | Limited by older BLE 4.0-era stack/tool | **No** | Legacy SmartRF Packet Sniffer / platform restrictions |
| [TI CC26xx LaunchPad](https://software-dl.ti.com/lprf/packet_sniffer_2/docs/user_guide/html/introduction.html) | BLE / 802.15.4 depending on model | Supported on compatible boards | Depends on exact firmware, sniffer release & PHY | **No** | SmartRF Packet Sniffer 2, model/revision-specific |
| Standard BlueZ USB HCI dongle | Bluetooth stack operations | Scan via own HCI host | **No passive third-party over-air guarantee** | **No passive third-party over-air guarantee** | Linux BlueZ: `bluetoothctl`, `btmon` |
| [HackRF One](https://greatscottgadgets.com/hackrf/one/) | Wideband half-duplex SDR | Research/decoder-dependent | Research/decoder-dependent | Research/decoder-dependent | SDR application, signal processing, special tooling |
| [YARD Stick One](https://greatscottgadgets.com/yardstickone/) | **Sub-1 GHz** TI CC1111 | **No** | **No** | **No** | RfCat; home automation / other sub-GHz protocols |
| **ATtiny MCU** | Microcontroller only | **No integrated BLE** | **No** | **No** | Add a BLE module; validate that separate radio |

Ubertooth One was [retired from Great Scott Gadgets' hardware catalog in December 2022](https://greatscottgadgets.com/2022/12-22-ubertooth-retirement/). It remains a useful research reference, **not** an automatic recommended first purchase.

## Supported Tools & Roles

| Software | Interface | Use & Boundary |
|---|---|---|
| [BlueZ `bluetoothctl`](https://github.com/bluez/bluez) | Regular HCI adapter | Discover and manage your **own** devices; policy controls |
| [BlueZ `btmon`](https://manpages.debian.org/unstable/bluez/btmon.1.en.html) | Host HCI and selected controller metadata | HCI traffic from local controller; **not** universal RF sniffing |
| [Wireshark](https://www.wireshark.org/) | HCI monitor, Nordic/TI/Ubertooth captures | Protocol dissection; depends on source |
| [nRF Sniffer for Bluetooth LE](https://www.nordicsemi.com/Products/Development-tools/nRF-Sniffer-for-Bluetooth-LE) | Supported Nordic boards | Receive-only BLE packet analysis; may miss hopping frames |
| [Ubertooth tools](https://github.com/greatscottgadgets/ubertooth) | Ubertooth One | Specialist research and firmware-dependent Bluetooth capture |
| [BTLEJack](https://github.com/virtualabs/btlejack) | Compatible nRF52 hardware | BLE research; active attack capability means **isolate and review source** |
| [Bettercap](https://www.bettercap.org/) | Host HCI or other supported adapters | BLE enumeration; not equivalent to passive connection sniffer |
| [Kismet BLE Sources](https://www.kismetwireless.net/docs/readme/datasources/) | Supported capture sources | Passive device sightings / WIDS inventory; data retention matters |
| [Spooftooph](./spooftooph-guide.md) | Selected writable Classic BT adapters | Identity spoofing research; defensive analysis only |
| [BlueMaho](./bluemaho-guide.md) | Legacy Bluetooth tooling | Historical Bluetooth audit/GUI; verify dependencies, no support promises |

## Platform & Compatibility Matrix

| Host | Normal Bluetooth HCI | BLE RF Sniffer | Notes |
|---|---|---|---|
| Linux (Kali/Debian/Ubuntu) | BlueZ and supported adapter | Nordic/Ubertooth/TI **with correct firmware & host tools** | Inspect kernel, udev permissions, USB access |
| Windows | Vendor Bluetooth stack | Nordic/TI tools where vendor supports current Windows | Driver/USB capture interfaces vary; verify installed software |
| macOS | Apple Bluetooth stack | Vendor tool-dependent, often limited | No blanket compatibility guarantee for specialist sniffers |
| Raspberry Pi Linux / ARM | BlueZ with onboard/USB adapters | Depends on sniffer host software and board USB | Power, CPU/SD performance and GPIO/serial paths |
| NetHunter/Android | Device/kernel-dependent | Peripheral USB toolchain often unsupported by stock Android | OTG power, kernel modules and Android permissions |
| Proxmox/Linux guest VM | USB passthrough HCI device | USB passthrough + host CLI supported | Do not confuse virtual network adapter with RF |
| uConsole/Cyberdeck | Board or external USB adapter | Separate USB sniffer where supported | Power, physical clearance & software compatibility |

## Hardware Selection By Objective

| Objective | First Tool to Evaluate | Avoid Mistaking It For |
|---|---|---|
| Inventory Bluetooth devices you own | Regular supported HCI dongle + `bluetoothctl` | Passive capture of all third-party connections |
| Debug BLE advertisements / a test peripheral | Nordic nRF52840 sniffer + Wireshark | Classic Bluetooth sniffer |
| Research historical Classic / 2.4 GHz behavior | Ubertooth One (legacy hardware) | Reliable turnkey full Classic decode |
| Develop custom BLE firmware | nRF52840 DK / suitable EFR32 or CC26xx board | Ready-made PC Bluetooth adapter |
| Inspect locally initiated HCI commands | `btmon` | Radio packets from unrelated devices |
| Study sub-GHz remote-control/IoT protocols | YARD Stick One + RfCat | Bluetooth / Zigbee sniffer |
| Study wideband RF signals | HackRF One / SDR chain | Automatic Wi-Fi/Bluetooth protocol decoder |

## Nonintrusive Setup & Validation

On a **Linux host with a normal owned HCI adapter**, the commands below only inspect local device information. Avoid scanning for people or capturing non-consenting devices.

```bash
lsusb -nn
bluetoothctl list
bluetoothctl show
btmon --help
```

For Nordic sniffer hardware, use the [dedicated BLE capture guide](./bluetooth-passive-scanning-sniffing.md#capturing-raw-ble-with-dedicated-hardware) to identify supported hardware and find the board-specific firmware and Wireshark integration. Test only with a battery-powered BLE sensor you own, save a capture, identify which advertising events were actually observed and document packet gaps.

For Ubertooth, verify matching firmware and host tools before flashing; a newer host utility does not imply a matching device firmware build. Linux `hci0` presence is **not** expected from an Ubertooth dedicated radio in the same way as an HCI dongle.

## ATtiny vs Bluetooth Modules

**ATtiny** refers to AVR microcontrollers from Microchip; they have no generic integrated 2.4 GHz Bluetooth transceiver. A design may combine an ATtiny with an HM-10-class BLE module or another radio, but then **the radio module determines Bluetooth version, sniffer/host capabilities and firmware**. Do not write "ATtiny supports BLE sniffing" without identifying the radio, firmware and connection design.

## YARD Stick One: Adjacent, Not Bluetooth

YARD Stick One is built around a TI CC1111 sub-GHz transceiver and primarily supports **300–348 MHz, 391–464 MHz and 782–928 MHz** according to [Great Scott Gadgets](https://greatscottgadgets.com/yardstickone/). It is suited to explicitly authorized analysis of compatible sub-GHz modulation/protocols, **not 2.4 GHz Bluetooth**.

## Failure Modes, Safety & Evidence

| Symptom | What to Verify |
|---|---|
| `bluetoothctl` sees HCI device, sniffer sees no packets | HCI != over-the-air capture, antenna & firmware |
| BLE advertisements seen but no connections | Sniffer follows limited traffic / encryption / capture timing |
| Legacy tool cannot start | Old Python, driver, Bluetooth stack or GUI dependencies |
| Dongle visible in USB but no capture interface | Sniffer firmware, udev access, host application |
| BLE address seems to change | Address randomization; do not equate address with identity |
| Incorrect Classic support claims | Check BR/EDR protocol vs BLE-only device |
| Sub-GHz adapter "cannot see BLE" | Different bands and demodulation |
| Different capture results from two radios | Channel selection, RF loss, antenna and device position |

### Documentation Evidence Record

Record adapter, USB VID/PID, board revision, antenna, firmware SHA/version, host OS, kernel, capture software/version, radio protocol, channel/PHY, physical setup, time/source permission, capture sample size, loss/uncertainty and data-retention decision. Avoid storing private pairing secrets or tracking identifiers unnecessarily.

## Source Links & Related Guides

- [Ubertooth One product](https://greatscottgadgets.com/ubertoothone/) & [Ubertooth retirement](https://greatscottgadgets.com/2022/12-22-ubertooth-retirement/)
- [Nordic nRF Sniffer](https://www.nordicsemi.com/Products/Development-tools/nRF-Sniffer-for-Bluetooth-LE), [TI SmartRF Packet Sniffer](https://www.ti.com/tool/PACKET-SNIFFER), [TI Packet Sniffer 2](https://software-dl.ti.com/lprf/packet_sniffer_2/docs/user_guide/html/introduction.html)
- [YARD Stick One](https://greatscottgadgets.com/yardstickone/), [BlueZ](https://github.com/bluez/bluez)
- [Wi-Fi Adapter Guide](./wifi-adapter-selection-guide.md) | [Kismet](../Wardriving/kismet.md) | [Wireless Surveying](../Wardriving/README.md)
- [Spooftooph](./spooftooph-guide.md) | [BlueMaho](./bluemaho-guide.md)

---

[Documentation Index](./README.md) | [Wardriving](../Wardriving/README.md) | [Legal Notice](../LEGAL.md)
