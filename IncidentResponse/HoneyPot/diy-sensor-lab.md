# DIY Minimal HTTP Honeypot: Raspberry Pi, VM and Mini PC

_Last reviewed: 2026-10-31 · Python 3.10+ · Low-interaction, lab-only_

## Purpose

The [minimal HTTP decoy](./lab/diy_http_decoy.py) supplies a tiny, inspectable, **receive-only** tripwire for a Pi, Proxmox VM, old mini PC, ZimaBoard or other Linux host. It is deliberately **not a vulnerable web application**, full shell, proxy, login portal or credential trap. It records only a bounded URL **path without its query**, method, source IP/port, truncated sanitized user-agent, sensor label and UTC timestamp; it never records cookies, Authorization headers, POST bodies or passwords.

Use [OpenCanary](./opencanary.md) instead for multiple believable simulated services, and [Cowrie](./cowrie.md) for SSH/Telnet session emulation. This deliberately simple source is useful for teaching log capture, access control and Wazuh event decoding without adding a large dependency stack.

> **Rule integrity correction (2026-11-11):** Previously a Wazuh `<rule>` was inadvertently nested inside a `<group>` label. The source files are repaired and covered by offline structural/synthetic-fixture tests. If you deployed an earlier copy, review your manager's installed rule files. Offline tests **do not** prove Wazuh manager success. Use the [Wazuh Synthetic Rule Validation Runbook](../../Documentation/WAZUH-SYNTHETIC-RULE-VALIDATION.md) before approved deployment.

## Isolation

~~~text
Authorized test client → dedicated decoy VLAN / isolated Proxmox network
                                |
                       Python HTTP decoy :8080
                                |
                      JSONL file + Wazuh agent
                                |
                     Wazuh manager / dashboard
~~~

Never advertise the decoy as a real production service or put it on a network from which it can reach confidential clients, PVE management or NAS. **Deny outbound** by default and narrowly allow the enrolled Wazuh-agent channel and approved management updates. Firewall segmentation, not the Python program, supplies network confinement.

## Run it

From a cloned repo root on an **isolated** Linux host:

~~~bash
python3 --version
python3 'IncidentResponse/HoneyPot/lab/diy_http_decoy.py' \
  --sensor isolated-decoy-01 --bind 127.0.0.1 --port 8080 \
  --output ./honeypot-events.jsonl
~~~

In another terminal:

~~~bash
curl -i http://127.0.0.1:8080/health-check
tail -n 1 ./honeypot-events.jsonl
~~~

Expect HTTP **404** and one JSON object with **honeypot.integration = diy_http** and **honeypot.event = http_probe**. A 404 is **intentional**: it provides no real application and does not echo input. The code does not log the request query or body. Actual source IPs in this example will normally be loopback.

Only after your firewall has been tested, replace --bind with **the actual IP address of the isolated decoy NIC** to permit a second approved test machine to connect. Do not bind to 0.0.0.0, forward the port through a home router, or give the process root/privileged capabilities. For permanent operation, use a locked-down systemd service account, a dedicated restricted log directory and log rotation; monitor free space and service health. This simple threaded prototype has no production DoS protections or durable event queue.

## Wazuh integration

Use the [Wazuh honeypot integration guide](./wazuh-honeypot-integration.md) and the custom [honeypot rules](./lab/honeypot_rules.xml). On the **Linux decoy** move the event output path into an agent-readable, private persistent directory, such as /var/log/honeypot/http.jsonl, and place the corresponding localfile element in the **existing** Wazuh agent configuration:

~~~xml
<localfile>
  <location>/var/log/honeypot/http.jsonl</location>
  <log_format>json</log_format>
</localfile>
~~~

On the **Wazuh manager**, the base rule 100400 classifies connection metadata at level 3 and the child rule 100401 flags POST/PUT/PATCH/DELETE at level 7. Every such alert is **an investigation lead**, not automatic evidence of an attacker: an asset scanner, health check or controlled exercise may be responsible. Use an authorized test curl invocation before evaluating real traffic.

## Tests and audit

~~~bash
python3 -m unittest discover \
  -s 'IncidentResponse/HoneyPot/lab' -p 'test_*.py' -v
~~~

The included tests exercise redaction, HTTP GET/POST event output, rule-ID uniqueness and the synthetic JSON fixtures. They do not emulate a large-scale adversarial flood or prove this minimal server is safe to expose publicly.

## Related guides

[Raspberry Pi](./raspberry-pi-honeypot-lab.md) · [Proxmox VM](./proxmox-vm-honeynet.md) · [ESP32](./esp32-diy-honeypots.md) · [ESP32-S3 Projects](./esp32-s3-honeypots.md) · [Wazuh](./wazuh-honeypot-integration.md) · [OpenCanary](./opencanary.md) · [Incident Response](../README.md)

---

[Honeypot Index](./readme.md) | [Master Index](../../README.md)
