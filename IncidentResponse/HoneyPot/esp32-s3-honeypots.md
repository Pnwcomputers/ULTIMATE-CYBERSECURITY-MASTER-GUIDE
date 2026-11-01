# ESP32-S3 Honeypots: ShadowSentry S3 and HoneyMire

_Last reviewed: 2026-10-31 · Based on upstream repositories; not hardware validated_

> [!CAUTION]
> These community firmware projects emulate attack surfaces and may record **real usernames/passwords, commands, IP/MAC addresses and session artifacts**. Use only on networks you own or are authorized to monitor. Do not use personal/production passwords as test data. Restrict management, isolate outbound connections, and validate security claims before treating the hardware as a trusted sensor.

## Projects and their different strengths

| Project | Supported ESP32-S3 | Detection features | Export path | Important limitation |
| --- | --- | --- | --- | --- |
| [ShadowSentry S3](https://github.com/Rdx1S/ShadowSentryS3) | Generic ESP32-S3 (4 MB flash or more) | RTSP, HTTP, Telnet, SSH, FTP decoys, simulated shell, ARP changes, Wi-Fi disconnect monitoring | Local HTTP admin/dashboard and Telegram | Claimed single-frame detection is **not** a verified no-false-positive RF security guarantee; no documented structured Wazuh output |
| [HoneyMire Sensor](https://github.com/HoneyMire/HoneyMire-Sensor-ESP32) | Generic ESP32-S3, S3-N16R8, LilyGO T-QT Pro | SSH/Telnet emulation, session logs/asciicast, event classification | Local JSON attack feed and optional [HoneyMire Hub](https://github.com/HoneyMire/HoneyMire-Protocol) protocol | Dashboard may automatically bypass authentication for LAN peers; do not expose on a shared LAN |

Neither project replaces Kismet/nzyme's fixed-channel 802.11 visibility or Wazuh's SIEM functions. Choose **ShadowSentry** for experiments mixing wireless indicators and fake services; choose **HoneyMire** for command/session deception and documented structured hub reporting. Both are independently maintained community projects, not security appliances vetted by PNWC.

## 1. ShadowSentry S3: installation on isolated test hardware

Source: [Rdx1S/ShadowSentryS3](https://github.com/Rdx1S/ShadowSentryS3); [ESP-IDF for S3](https://docs.espressif.com/projects/esp-idf/en/stable/esp32s3/).

Requirements: ESP32-S3 board with supported flash and a USB data cable; 2.4 GHz Wi-Fi in a dedicated decoy VLAN; maintained ESP-IDF v5.x toolchain. Confirm current upstream README for the specific release before flashing.

~~~bash
git clone https://github.com/Rdx1S/ShadowSentryS3.git
cd ShadowSentryS3

# Initialize the ESP-IDF environment per the official Espressif instructions.
cp main/config.h.example main/config.h
# Edit the *local untracked* file to set an isolated test SSID, strong admin
# password, and leave external Telegram/GeoIP outputs disabled if not needed.

idf.py set-target esp32s3
idf.py build
idf.py -p /dev/ttyACM0 flash monitor
~~~

Replace /dev/ttyACM0 with your device's real serial port. Inspect and pin an upstream release/commit for repeatable builds. Do **not** blindly flash a random binary or store personal credentials in the firmware.

The project advertises a dashboard on HTTP port 9999 and WebSocket port 9998. **HTTP Basic authentication on plain HTTP is not transport encryption**, so put the management UI behind access controls and trusted management-only routing; never forward those ports to the internet. Verify any enabled GeoIP/Telegram enrichment exports and their data/privacy effects.

### About its Wi-Fi deauth detection claim

ShadowSentry documents two signals: its own Wi-Fi disconnection reason reports and promiscuous monitoring of some management traffic on its **associated channel**. That may produce useful anomalies, but:

- An ESP32 station's disconnect reason is not an authenticated attribution to another radio. Driver-generated reason codes and RF failures can be ambiguous.
- One observed deauth/disassoc frame does not prove an attack, nor that a PMF-capable client accepted it.
- The station-associated channel view is narrower than a properly configured dedicated monitor radio or multi-channel WIDS.
- Do **not** use the project's assertion of zero false positives or detection of every single deauth as a validated result; test against controlled legitimate disconnects, AP maintenance, WPA/PMF configurations and capture gaps.

For stronger verification, correlate with [packet-level analysis](../../Documentation/wifi-deauthentication-detection.md), [Kismet + Wazuh](../IDS%26IPS/kismet-wazuh-wireless-lab.md), [nzyme + Wazuh](../IDS%26IPS/nzyme-wazuh-integration.md) and AP/controller logs.

## 2. HoneyMire on ESP32-S3: deployment and structured reporting

Upstream [HoneyMire sensor README](https://github.com/HoneyMire/HoneyMire-Sensor-ESP32) documents the following target environments:

| Board | Build profile | Storage details |
| --- | --- | --- |
| Generic headless ESP32-S3 | esp32-s3-generic | 4 MB flash, no PSRAM required |
| Headless S3 N16R8 | esp32-s3-n16r8 | 16 MB flash / 8 MB PSRAM |
| LilyGO T-QT Pro | lilygo-t-qt-pro | Integrated color display, 4 MB flash / 2 MB PSRAM |

The upstream project supplies a browser flasher and PlatformIO builds. Review the project's source, releases and hardware compatibility; **browser flashing is not a source audit**.

~~~bash
git clone https://github.com/HoneyMire/HoneyMire-Sensor-ESP32.git
cd HoneyMire-Sensor-ESP32
pio run -e esp32-s3-generic
# Replace with esp32-s3-n16r8 or lilygo-t-qt-pro for matching actual board.
pio run -e esp32-s3-generic -t upload
pio device monitor
~~~

HoneyMire's documentation lists an initial setup access point and **default dashboard credentials** and notes that dashboard authentication may be bypassed for LAN clients. Treat those as serious deployment risks: change defaults, **segment the device completely**, restrict the HTTP dashboard to a trusted management workstation, and review all outgoing threat-intelligence/HoneyMire Hub reporting before enabling. Do not put this firmware on a customer or ordinary home LAN and assume the dashboard is private.

The [HoneyMire Protocol](https://github.com/HoneyMire/HoneyMire-Protocol) specifies a versioned structured event exchange for a **self-hosted Hub**, as well as ESP32 and Go sensors. For Wazuh, a trustworthy integration should authenticate and validate upstream Hub records, redact sensitive fields, and export **normalized JSONL** on a Linux relay that has a Wazuh agent. The firmware's local /api/attacks feed is documented but should **not** be polled over a shared, unencrypted LAN just to send events into Wazuh.

## 3. Wazuh: integration readiness matrix

| Sensor | Safe default | Future integration if justified |
| --- | --- | --- |
| ShadowSentry | Retain events on isolated board; test alert classifications locally | Build a schema-verified reader for a documented stable API over a protected management path, redact credentials |
| HoneyMire | Isolated device and optional self-hosted Hub | Have a trusted bridge consume Hub events using authenticated, pinned schema, emit JSONL to Wazuh |
| Custom ESP32 firmware | Explicit local UART event format with metadata only | [Minimal serial bridge](./lab/esp32_serial_bridge.py) emits namespace honeypot.integration=esp32_serial |

**Do not feed arbitrary strings from Telegram notifications or untrusted JSON into Wazuh as authenticated event records.** Avoid falsely claiming that ShadowSentry/HoneyMire emits the custom UART prefix; neither upstream README establishes that.

The [Wazuh honeypot guide](./wazuh-honeypot-integration.md) covers actual OpenCanary/Cowrie native JSON events and a safe minimal custom-ESP32 telemetry path.

## 4. Field validation checklist

- Is firmware release/commit pinned, with build instructions matching flash/PSRAM hardware?
- Does the decoy VLAN prevent connections to PVE, NAS, controller admin, Wazuh API, and production resources?
- Are ports 9998/9999 and any configuration portals restricted to management only?
- Are external API/Telegram/Hub exports disabled until consent, data classification and retention are decided?
- Are credentials, transcripts and captured payloads excluded from public repositories and unredacted dashboard panels?
- Do deauth “detections” agree with fixed-channel packet captures and trusted AP/client events, not merely self-disconnect reason codes?
- Do serial or Hub events carry source and timestamps that are explicitly marked **unverified telemetry**?

## Related guides

[ESP32 Overview](./esp32-diy-honeypots.md) · [Raspberry Pi Decoys](./raspberry-pi-honeypot-lab.md) · [DIY HTTP Decoy](./diy-sensor-lab.md) · [Wazuh Honeypot Reporting](./wazuh-honeypot-integration.md) · [Wi-Fi Deauthentication Analysis](../../Documentation/wifi-deauthentication-detection.md)

---

[Honeypot Index](./readme.md) | [Incident Response](../README.md) | [Master Index](../../README.md)
