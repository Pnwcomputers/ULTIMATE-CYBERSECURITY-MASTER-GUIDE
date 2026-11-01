# ESP32 and Other Tiny DIY Honeypots

_Last reviewed: 2026-10-31 · ESP32/ESP32-C5/C6, isolated IoT lab_

## What an ESP32 can and cannot do

An ESP32 can present a low-interaction decoy TCP listener, simulated Telnet/HTTP service, or log unauthorized connection attempts with modest power usage. It cannot safely replace a full Cowrie shell emulator, a high-interaction malware sandbox, or a production WIDS. Choose firmware **specifically for your board and radio**; GPIO, flash partitioning and Wi-Fi bands differ by model.

A concrete reference is [NanoC6-ESP32-Honeypot](https://github.com/7h30th3r0n3/NanoC6-ESP32-Honeypot), an Arduino-family M5Stack NanoC6/ESP32 project documenting WebUI, SPIFFS settings/log storage, fake Telnet/Linux shell and outgoing webhook notifications. Its documented webhook example sends a **content string**, not reliable individual SIEM fields. Its project README warns against unsegmented internet exposure.

**Do not claim that the stock firmware emits structured deauth information or works with this repository's UART bridge.** This is a *service decoy*, not a passive wireless frame-capture sensor.

## Lab deployment and protection

1. Use an ESP32 board with known supported firmware; confirm chip family, flash size, antenna, power, version and board-specific instructions on the project's upstream page.
2. Connect it only to an **isolated IoT/decoy SSID and VLAN**, not the trusted home/office LAN. Restrict all device-to-LAN egress and administrative interfaces.
3. Never place actual credentials, private keys, customer data or realistic secrets into the decoy filesystem. Use explicitly fake data.
4. Avoid enabling privileged remote code execution, relay or actual shell access. Test the intended emulated service from a controlled lab client.
5. Bound WebUI access to management-only sources; if the firmware does not support secure authentication, keep the configuration UI unreachable from the exposed/test segment.
6. Review SPIFFS wear, log retention and power-reset behavior. Embedded memory and storage are not durable evidence repositories.
7. Do not assume all "ESP32" boards support 5 GHz or monitor mode.

## Reporting to Wazuh: two clearly different modes

**Stock NanoC6 firmware:** The public project documents a JSON webhook shaped like a single string under content, aimed at Discord-style integrations. This is **not** the normalized event structure in the [Wazuh honeypot rules](./wazuh-honeypot-integration.md). To centralize it, create a *separately reviewed, authenticated HTTPS gateway* or serial export that validates messages and produces an operator-defined schema. Do not expose the Wazuh manager or an unauthenticated webhook directly to untrusted devices. Never parse arbitrary strings as proof of a particular source IP.

**Custom DIY firmware with structured UART messages:** If you control the ESP32 code, you can emit one strictly formatted UART line **from your own application** for each allowed connection event, e.g.:

~~~text
HONEYPOT_JSON:{"event":"tcp_connection","src_ip":"192.0.2.30","port":23}
~~~

Only **custom firmware that implements this format** will work with the provided [serial bridge](./lab/esp32_serial_bridge.py). This is an integration contract for builders; it does not claim to be an output of NanoC6. The bridge validates the prefix, event name, IP, and port; it **does not** accept commands, request bodies, passwords or arbitrary packet dumps.

Connect the ESP32 over a USB serial cable to an **isolated Raspberry Pi gateway or Linux VM with USB passthrough**. First identify the correct serial interface with:

~~~bash
ls -l /dev/serial/by-id/
python3 -m venv ./esp32-bridge-venv
./esp32-bridge-venv/bin/python -m pip install pyserial
~~~

Run as a limited account with read access to this **one USB serial device**, not root, and use a protected output directory:

~~~bash
./esp32-bridge-venv/bin/python \
  'IncidentResponse/HoneyPot/lab/esp32_serial_bridge.py' \
  --port /dev/serial/by-id/YOUR-DEVICE-ID \
  --sensor esp32-decoy-01 --baud 115200 \
  --output ./esp32-events.jsonl
~~~

For a real Wazuh setup, move the output file into a protected persistent path such as /var/log/honeypot/esp32-events.jsonl and add this to the **Wazuh agent on the serial gateway**, within its existing ossec_config root:

~~~xml
<localfile>
  <location>/var/log/honeypot/esp32-events.jsonl</location>
  <log_format>json</log_format>
</localfile>
~~~

**The existing DIY rules target integration = diy_http, not esp32_serial.** To classify ESP32 events, install the companion Wazuh rule 100402 in the main [honeypot rules](./lab/honeypot_rules.xml), and test it via wazuh-logtest. It should remain a low-confidence/medium-priority event until corroborated with access-point records. Never treat source IP inside a custom embedded log as an authenticated identity.

## Alternatives worth considering

| Option | Deployment | Practical use |
| --- | --- | --- |
| Raspberry Pi Zero 2 W + Python | [DIY HTTP decoy](./diy-sensor-lab.md) | Very inexpensive Ethernet/USB-attached tripwire |
| Pi 3/4/5 + OpenCanary | [Pi lab](./raspberry-pi-honeypot-lab.md) | Multi-service internal detection |
| Mini PC / ZimaBoard | [Proxmox honeynet](./proxmox-vm-honeynet.md) | More disk/RAM and several isolated VMs |
| OpenWrt + isolated Docker | [Official OpenWrt honeypots guidance](https://openwrt.org/docs/guide-user/services/honeypots) | Only on suitable capable routers; never share firewall management trust |
| Canarytokens | [Canarytokens project](https://canarytokens.org/) | Document/link/email decoys; no exposed fake network listener |

Never distribute a decoy appliance that phones home with private addresses, credentials or visitor activity to a third-party webhook without appropriate consent.

## Validation

Test a single benign TCP connection in a closed lab and confirm **device log → local bridge JSONL → Wazuh agent → Wazuh manager rule → dashboard**. If the firmware has no structured output, stop at device-local reporting until you have built and tested a secure adapter. Check time sync at the gateway, event loss on serial resets and WAN/production egress denial.

[Honeypot Index](./readme.md) | [Wazuh Reporting](./wazuh-honeypot-integration.md) | [Raspberry Pi Lab](./raspberry-pi-honeypot-lab.md) | [Master Index](../../README.md)
