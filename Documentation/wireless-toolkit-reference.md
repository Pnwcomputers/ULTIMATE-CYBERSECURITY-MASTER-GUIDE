# Wireless Security Tools: Wi-Fi, Bluetooth, BLE & Sub-GHz Reference

_Reference research: 2026-11-21. This is an index and tool-selection guide. Existing canonical Aircrack-ng, Kismet, Wazuh and HCX guides remain authoritative._

> [!CAUTION]
> **Authorized use only.** Passive observation and active radio transmission are different methods with different risks. Use written scope, known lab hardware, permitted frequencies and safe data retention. This reference does **not** authorize disruption, unauthorized authentication, spoofing or location tracking. See [Legal Notice](../LEGAL.md).

## Choose the Right Tool By Goal

| Goal | Canonical Guide | Scope |
|---|---|---|
| Compare Wi-Fi USB cards, chipsets, drivers & monitor/injection | [Wi-Fi Adapter Guide](./wifi-adapter-selection-guide.md) | USB/host/kernel/band matrix |
| Compare Bluetooth, BLE, Ubertooth, Nordic, YARD Stick, ATtiny | [Bluetooth/BLE & RF Hardware](./bluetooth-radio-adapter-guide.md) | HCI vs sniffers vs adjacent RF |
| 802.11 receive capture & legacy suite | [Aircrack-ng](./Aircrack-ng_Commands.md) | `airmon-ng`, `airodump-ng`, `aireplay-ng` boundaries |
| Stationary/field Wi-Fi inventory | [Kismet](../Wardriving/kismet.md) | Datasources, GPS, WIDS vs wardrive |
| GUI Wi-Fi security toolkit | [Fern WiFi Cracker](./fern-wifi-cracker-guide.md) | Historical GUI, dependencies, lab boundaries |
| Automated wireless testing | [Wifite2 & Wifite3](./wifite-guide.md) | Different projects and supported USB devices |
| Weak WPS PIN entropy | [Pixiewps](./pixiewps-guide.md) | Only some affected implementations |
| WPA2 PSK offline audit | [HCXTools & Hashcat](./hcxtoolshashcat.md) | Relevant PMKID/EAPOL format, no WPA3-SAE generalization |
| Generic offline password evaluation | [Hashcat](./hashcat-guide.md) | Hash modes, compute backends, synthetic lab |
| Password dictionaries / masks / rules | [Wordlists](./wordlists-password-auditing.md) | Source hygiene and candidates |
| Precomputation vs salts | [Rainbow Tables](./rainbow-tables-guide.md) | Historical concept, modern KDFs |
| Legacy BT identity changes | [Spooftooph](./spooftooph-guide.md) | Defensive spoofing threat model |
| Historical BT suite | [BlueMaho](./bluemaho-guide.md) | Legacy code/source review |

## Companion Hardware & Capture Paths

| Reference | Purpose |
|---|---|
| [Passive Bluetooth Scanning & Sniffing](./bluetooth-passive-scanning-sniffing.md) | Active/passive BLE scanning, HCI vs raw RF and randomization |
| [SBC, Portable Firmware & Radio Add-Ons](./sbc-radio-addon-compatibility.md) | Pi/uConsole/Flipper/ESP32, CC1101, NFC, GPS, HATs and compatibility |
| [LAN TAPs, SPAN & Packet Visibility](./network-taps-and-packet-visibility.md) | Great Scott Throwing Star, active copper/fiber, aggregation and IDS sensor placement |

## Wider Wi-Fi Tool Ecosystem

| Tool | Official Project | Intended Role | Caution |
|---|---|---|---|
| Aircrack-ng suite | [Project](https://github.com/aircrack-ng/aircrack-ng) | 802.11 capture, WEP/WPA historical auditing, tools | Injection and deauth commands **transmit** |
| Kismet | [Project](https://www.kismetwireless.net/) | Receive-focused Wi-Fi/BLE survey & WIDS | Some datasource modes can differ; retention risks |
| Wireshark / TShark | [Project](https://www.wireshark.org/) | Decode permitted packet captures | Capture interface and channel coverage matter |
| nzyme | [Project](https://github.com/nzymedefense/nzyme) | Wireless intrusion monitoring | Not a replacement for Kismet event schema |
| Wifite2 / Wifite3 | [Wifite3](https://github.com/derv82/wifit3) | Wi-Fi audit automation | Auto workflows can be active and disruptive |
| Fern WiFi Cracker | [Project](https://github.com/savio-code/fern-wifi-cracker) | Legacy graphical testing | Security/maintenance of dependencies |
| Pixiewps | [Project](https://github.com/wiire-a/pixiewps) | Offline weak-entropy WPS analysis | Not a universal WPA PSK or WPS crack |
| Reaver | [Kali Reference](https://www.kali.org/tools/reaver/) | WPS assessment | Online methods can lock out or affect an AP |
| Bully | [Project](https://github.com/aanarchyy/bully) | WPS security research | Active; audit only controlled fixtures |
| HCXTools / hcxdumptool | [HCXTools](https://github.com/ZerBea/hcxtools) / [hcxdumptool](https://github.com/ZerBea/hcxdumptool) | Offline format conversion vs radio capture | **hcxdumptool may transmit**; read version-specific docs |
| Bettercap | [Project](https://github.com/bettercap/bettercap) | Modular networking / radio assessment | BLE/Wi-Fi modules have different hardware requirements |
| AngryOxide | [Project](https://github.com/Ragnt/AngryOxide) | Modern 802.11 security tool | Active features; version/capability varies |
| airgeddon | [Project](https://github.com/v1s1t0r1sh3r3/airgeddon) | Wrapper around multiple wireless tools | Do not mistake menu automation for non-invasive testing |
| hostapd / wpa_supplicant | [Hostap](https://w1.fi/) | Build authentic owned AP/client test fixtures | Use dummy credentials and isolated network |

## Wider Bluetooth & BLE Ecosystem

| Tool | Official Source | Role & Limits |
|---|---|---|
| BlueZ | [Project](http://www.bluez.org/) | Host stack, `bluetoothctl`, `btmon`; not unrestricted over-air snooping |
| Wireshark | [Project](https://www.wireshark.org/) | HCI and sniffer-capture decode |
| Nordic nRF Sniffer | [Product](https://www.nordicsemi.com/Products/Development-tools/nRF-Sniffer-for-Bluetooth-LE) | BLE over-air capture with compatible nRF development hardware |
| Ubertooth | [Project](https://github.com/greatscottgadgets/ubertooth) | Retired research hardware; Classic limitations |
| BTLEJack | [Project](https://github.com/virtualabs/btlejack) | BLE research; specialized firmware and active capability |
| Sniffle | [Project](https://github.com/nccgroup/Sniffle) | BLE sniffer for supported TI radios, firmware dependent |
| TI SmartRF Packet Sniffer 2 | [Documentation](https://software-dl.ti.com/lprf/packet_sniffer_2/docs/user_guide/html/introduction.html) | Vendor-based capture for supported CC13xx/CC26xx hardware |
| btscanner | [Kali Reference](https://www.kali.org/tools/btscanner/) | Bluetooth Classic discovery information |
| BlueHydra | [Project](https://github.com/zerbea/blue_hydra) | Bluetooth discovery; investigate data retention and fork support |
| Spooftooph | [Kali Reference](https://www.kali.org/tools/spooftooph/) | Legacy device-name/class/address manipulation; threat research |
| BlueMaho | [Historical Project](https://github.com/zenware/bluemaho) | Historical scan/exploit GUI; do not assume current compatibility |
| Kismet BLE | [Datasources](https://www.kismetwireless.net/docs/readme/datasources/) | Compatible BLE capture sources and sighting logs |

## Other Radio Types: Keep Their Categories Accurate

| Device / Tool | Actual Domain | Relationship |
|---|---|---|
| YARD Stick One & RfCat | Sub-1 GHz transceivers / ASK, FSK, OOK, etc. | **Not Bluetooth**, not Wi-Fi |
| HackRF One & GNU Radio | General-purpose SDR | Possible BLE/RF signal research with dedicated demodulation software |
| RTL-SDR | Receive-only SDR with model-specific tuning range | Not a normal BLE controller or 802.11 packet sniffer |
| ATtiny with external module | MCU plus separate communications device | **ATtiny alone is not a Bluetooth adapter** |
| ESP32 (model-dependent) | Wi-Fi / BLE development MCU | Board-specific firmware; not a drop-in PC monitor/injection NIC |
| nRF52 / EFR32 / CC26xx | BLE and/or other protocols, by chip | Need **appropriate sniffer firmware** for over-air analysis |

## Prerequisite Matrix

| Capability | Wi-Fi Monitor NIC | Normal HCI BT Dongle | Nordic BLE Sniffer | YARD Stick One |
|---|---|---|---|---|
| 802.11 raw frame capture | If supported | No | No | No |
| 802.11 injection | If supported and permitted | No | No | No |
| Standard BT pairing | No | Yes, if protocol supported | Not its sniffer role | No |
| Passive BLE advertisement capture | No by itself | Host sightings, not raw RF | Yes, with correct firmware | No |
| BLE connection capture | No | Not guaranteed | Conditional | No |
| Sub-GHz signal analysis | No | No | No | Yes, supported bands only |

## Common Lab & Evidence Workflow

1. Identify what **protocol** and **radio band** the task requires, rather than choosing a product by marketing name.
2. Check OS, kernel, driver, board revision, USB/serial access and antenna requirements.
3. Create a deliberately controlled fixture: an owned Wi-Fi AP, owned BLE peripheral or sub-GHz lab transmitter where permitted.
4. Separate **receive-only** collection, active discovery, injection and exploitation in the written rules of engagement.
5. Record exact tool versions, firmware hashes, source interface, RF channel, dropped frames, UTC timestamps and any uncertainty.
6. Correlate observations against AP configuration, application logs or device firmware before claiming a vulnerability.
7. Restore the interface, firmware, service state and evidence retention settings.

## Additional Repository Routes

- [Kismet + Wazuh WIDS](../IncidentResponse/IDS%26IPS/kismet-wazuh-wireless-lab.md)
- [Wi-Fi PMF & Deauthentication Detection](./wifi-deauthentication-detection.md)
- [Wardriving](../Wardriving/README.md)
- [Cyberdeck Portable Wireless Devices](../Cyberdeck/docs/PORTABLE_WIRELESS_FIELD_DEVICES.md)
- [Security Firmware Catalog](./esp32-security-firmware-catalog.md)

---

[Documentation Index](./README.md) | [Master Index](../README.md) | [Legal Notice](../LEGAL.md)
