# Raspberry Pi Honeypot Lab: OpenCanary, Cowrie and Tiny HTTP Decoys

_Last reviewed: 2026-10-31 · Raspberry Pi OS Lite / Debian · Authorized lab_

## Choose the Pi build

| Hardware | Good use | Constraints |
| --- | --- | --- |
| Pi 3B / 3B+ | OpenCanary, lightweight internal tripwire | SD write endurance, network bandwidth, limited RAM |
| Pi 4 | OpenCanary, isolated Cowrie, multiple low-interaction services | CPU/SD lifetime, service isolation, USB SSD recommended |
| Pi 5 | Cowrie or multi-sensor lab, Docker-backed lightweight decoys | Host power, active cooling, storage and memory matter |
| Pi Zero 2 W | Minimal custom HTTP decoy or alert relay | Avoid busy multi-service frameworks; validate actual Ethernet/USB connectivity |

These are **suggested roles**, not claims of certified minimum requirements. For T-Pot, follow its separate official Pi 4 8GB and resource guidance in the [T-Pot guide](./tpot.md) rather than assuming all Raspberry Pis qualify.

## Network design

~~~text
Trusted management LAN → Wazuh manager
          ↑ management access (restricted)
          |
  Firewall/router --- separate honeypot VLAN / isolated port
                           |
                      Raspberry Pi
                   decoy service + Wazuh agent
~~~

The honeypot must not have broad routes to your file servers, cameras, passwords, other management interfaces, or production clients. Apply **deny-by-default egress**; explicitly allow only Wazuh agent transport, time sync and approved patch management. A consumer router's guest Wi-Fi isolation may not provide the full policies; verify traffic from the Pi itself.

## 1. Prepare Raspberry Pi OS Lite

Flash a maintained 64-bit Raspberry Pi OS Lite or Debian image to an SSD/microSD. Change defaults, update first and use named nonroot accounts. Do not enable passwordless root or expose SSH to the decoy VLAN.

~~~bash
cat /etc/os-release
uname -m
ip -brief address
df -h
sudo apt update
sudo apt upgrade
sudo ss -lntup
~~~

Make a backup of the OS image before enabling sensors. Use a **wired** Ethernet interface for predictable firewalling where possible; keep the real SSH service accessible only through the management segment. Set up log rotation and a storage-size alert; SD-card writes are a reliability concern.

## 2. OpenCanary: practical first option

Follow the [maintained OpenCanary Pi deployment guide](./opencanary.md) for virtual environment setup, choosing services and testing an actual JSON event. The default official config generally uses a home-directory config; this repo's older deployment guide may use /etc/opencanaryd/opencanary.conf, so **verify the config actually loaded by your service** before editing.

Recommended first lab: a decoy HTTP or FTP port **without moving your production SSH daemon**. Expose only the chosen honeypot port to a test client on the decoy VLAN. Do not casually turn on port-scan/SMB modules or low-numbered ports that need special privileges.

To integrate Wazuh, configure the JSON FileHandler and agent localfile using the [Wazuh Honeypot Integration](./wazuh-honeypot-integration.md). Confirm that OpenCanary's src_host and numeric logtype fields appear before assigning specialized rules.

## 3. Cowrie: more interaction on a Pi 4/5

Follow [Cowrie's guide](./cowrie.md) and [upstream stable installation](https://docs.cowrie.org/en/stable/README.html) with a Python virtual environment and nonroot service user. Cowrie emulates SSH/Telnet commands; it can save transferred artifacts, so do not run it on a Pi that holds other secrets or shares a privileged network.

- Use Cowrie's **shell-emulation mode**, not its backend proxy mode for a basic safe lab.
- Start on a high unprivileged port (such as 2222). If later mapping port 22, preserve your actual management access and verify NAT rules from another session.
- Check var/log/cowrie/cowrie.json, and forward that exact JSONL file to Wazuh via the agent.
- Keep samples in a quarantined location and never open/exe attacker-supplied binaries.

## 4. DIY minimal HTTP decoy

For devices too small for a full honeypot suite, use [the repository DIY HTTP lab](./diy-sensor-lab.md). Example on a trusted lab VM/Pi:

~~~bash
python3 'IncidentResponse/HoneyPot/lab/diy_http_decoy.py' \
  --sensor pi-decoy-01 \
  --bind 127.0.0.1 --port 8080 \
  --output ./honeypot-events.jsonl

# In another terminal: normal benign test
curl -i http://127.0.0.1:8080/probe
~~~

It emits minimal JSON metadata, not credential attempts. For actual VLAN operation change --bind to the Pi's **isolated decoy-interface address** after firewall testing. Place under nonroot systemd supervision and configure the Wazuh agent to read a persistent protected JSONL path.

## 5. Validate, monitor, maintain

Record a known benign baseline, source IP, time, targeted service, log type and Wazuh level. Verify no reachability from decoy to production. Check all allowed egress, especially outgoing DNS and internet access; do not allow unrestricted callbacks from a decoy. Confirm remote backups/rotated logs do not include client credentials beyond retention policy. Test power cycles and SSH management continuity.

## Cross-links

[Wazuh Honeypot Reporting](./wazuh-honeypot-integration.md) · [OpenCanary](./opencanary.md) · [Cowrie](./cowrie.md) · [DIY HTTP](./diy-sensor-lab.md) · [HoneyPi](./honeypi.md) · [VM Honeynet](./proxmox-vm-honeynet.md) · [ESP32](./esp32-diy-honeypots.md) · [Wazuh](../SIEM/wazuh.md)

---

[Honeypot Index](./readme.md) | [Incident Response](../README.md) | [Main Index](../../README.md)
