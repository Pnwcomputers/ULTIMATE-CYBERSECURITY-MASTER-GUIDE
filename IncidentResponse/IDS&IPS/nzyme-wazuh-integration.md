# nzyme + Wazuh: Wireless Detection and Alert Integration

_Last reviewed: 2026-10-31 · Companion to the [Kismet + Wazuh lab](./kismet-wazuh-wireless-lab.md)_

> [!CAUTION]
> Authorized, receive-only wireless monitoring only. Do not generate deauthentication traffic, collect credentials, or automatically retaliate. The following is a reproducible **lab template**, not a deployed service.

## Why nzyme belongs in this lab

[nzyme](https://www.nzyme.org/) has built-in deauthentication/disassociation **Disconnection Activity** and per-monitored-network threshold detection. It can also alert on unexpected BSSIDs, RF fingerprints, channels, security suites, and signal-track anomalies. The [existing nzyme deployment guide](./nzyme_wids.md) already covers node installation on Proxmox, Raspberry Pi taps, chipsets/drivers and band configuration; keep that guide intact and use this one for centralized **Wazuh alert ingestion**.

| Component | Kismet | nzyme | Wazuh |
| --- | --- | --- | --- |
| Receiver | Monitor-mode Linux radio | nzyme remote taps | Wazuh agents read local event logs |
| Deauth detection | DEAUTHFLOOD, BCASTDISCON | Monitored-network disconnection counts/thresholds | Scores normalized alerts and builds timeline |
| Spoofing context | Kismet built-in alerts | Expected AP BSSID, fingerprint, channel, crypto | Joins investigation windows, not physical attribution |
| Feed to Wazuh | Readonly REST collector | Webhook JSON (provided) or syslog | Custom XML rules and dashboard |
| Caveat | Alert throttling / channel gaps | Alert grouping, re-trigger delay, one-shot action | No native 802.11 RF capture from Ethernet |

## 1. Baseline native nzyme detection

1. Verify that nzyme-node and taps are healthy and observing your authorized APs on their actual channels and bands.
2. Open **WiFi → Monitoring** and configure a monitored network for your own SSID. Verify expected BSSIDs, fingerprints, channels and security suites against your controller; do not automatically approve unknown BSSIDs.
3. In **WiFi → Disconnection Activity**, review observed deauthentication/disassociation frames, including normal peaks from AP reboots, channel changes, roaming and client problems.
4. On the monitored network, choose the **Static Threshold** disconnection-anomaly method. Begin with a 24-hour baseline, then account for peak loads and scheduled maintenance before setting an alert threshold. A few ordinary disconnects are not an attack.
5. Enable the relevant nzyme network monitoring/alert events, and review false positives during authorized maintenance. A single hopping receiver can miss bursts on channels it is not currently monitoring.

Official references: [network monitoring and thresholds](https://docs.nzyme.org/wifi/monitoring/network-monitoring/) and [Disconnection Activity](https://docs.nzyme.org/wifi/disconnection-activity/).

## 2. Event transport: choose Webhook or Syslog

The maintained nzyme [Action Types documentation](https://docs.nzyme.org/configuration/alerting/action_types/) supports:

- **Webhook**: HTTP POST with one JSON object per event, optional Bearer token; choose this for the runnable lab.
- **Syslog**: RFC 5424 over **UDP only**, with structured data in detection@63705 / system@63705. The priority is fixed at **133** (local0/notice) and **does not encode actual threat severity**. Use a local rsyslog/syslog-ng relay with proper field parsing and queued TCP/TLS forwarding if you require a more robust cross-host path.

nzyme webhook events provide an event supertype, machine event type, optional subsystem, human-readable details and timezone-aware timestamp. **They do not guarantee a BSSID, a client MAC, or packet count.** Avoid extracting an alleged BSSID from free text as evidence.

Example documented detection payload:

~~~json
{
  "event_type": "MONITOR_TRIGGERED",
  "event_type_subsystem": "GENERIC",
  "event_type_human_readable": "Monitor triggered",
  "details": "Monitor \"WiFi Monitor Example\" triggered.",
  "event_supertype": "detection",
  "timestamp": "2026-07-27T09:11:05.223-05:00"
}
~~~

**Frequency caution:** nzyme groups detections and may re-trigger them at **five-minute intervals**, not once per packet. Webhook and UDP syslog actions are attempted **once**, with no built-in retry. A receiver cannot recover events that were never delivered; add a durable queue/reconciliation step for higher-assurance operations. See [alert lifecycle](https://docs.nzyme.org/configuration/alerting/) and [subscriptions](https://docs.nzyme.org/configuration/alerting/subscriptions_actions/).

## 3. Install a localhost-only webhook receiver

This example assumes **nzyme-node, the receiver and a Wazuh agent run on the same Linux host**. The included Python code uses only the standard library, listens on **127.0.0.1:8787/nzyme**, verifies a 32+ character Bearer token, limits JSON to 16 KiB and appends normalized events to **/var/log/nzyme-wazuh/events.jsonl** before replying with HTTP 204.

From a clone of the repository on the nzyme-node host:

~~~bash
sudo install -d -m 0755 /opt/nzyme-wazuh
sudo install -m 0644 \
  'IncidentResponse/IDS&IPS/nzyme-wazuh/nzyme_webhook_bridge.py' \
  /opt/nzyme-wazuh/nzyme_webhook_bridge.py
sudo install -m 0644 \
  'IncidentResponse/IDS&IPS/nzyme-wazuh/nzyme-wazuh-bridge.service' \
  /etc/systemd/system/nzyme-wazuh-bridge.service
sudo install -d -m 0700 /etc/nzyme-wazuh
sudoedit /etc/nzyme-wazuh/receiver.env
sudo chmod 0600 /etc/nzyme-wazuh/receiver.env
~~~

Generate a secret using **openssl rand -hex 32**. Store the resulting token **only locally**, in both the nzyme action and a root-only environment file like:

~~~ini
NZ_WEBHOOK_TOKEN=REPLACE_WITH_64_RANDOM_HEX_CHARACTERS
NZ_SENSOR=nzyme-node-01
# Fill these with exact verified machine event_type values, comma-separated:
# NZ_DISCONNECT_TYPES=
# NZ_ROGUE_TYPES=
~~~

**No nzyme event-specific type is guessed here.** The public webhook examples show generic MONITOR_TRIGGERED, not a unique event_type for every disconnection detector. Leave these allowlists empty initially; after one real alert, inspect its exact **event_type** and map it to the appropriate category. Never classify the generic MONITOR_TRIGGERED as an attack unconditionally.

~~~bash
sudo systemctl daemon-reload
sudo systemctl enable --now nzyme-wazuh-bridge
sudo systemctl status nzyme-wazuh-bridge --no-pager
sudo journalctl -u nzyme-wazuh-bridge -n 30 --no-pager
~~~

In the nzyme UI, have an organization administrator add a **Webhook Action** under **Events & Actions**, then subscribe the desired detection event types. Follow the [official actions/subscriptions instructions](https://docs.nzyme.org/configuration/alerting/subscriptions_actions/). Set:

~~~text
Webhook URL: http://127.0.0.1:8787/nzyme
Bearer Token: same secret as /etc/nzyme-wazuh/receiver.env
Allow Insecure: OFF
Subscriptions: chosen Wi-Fi/network detection events
~~~

**Loopback only:** This URL works **only on the same nzyme-node host**. For cross-host deployments use a trusted, authenticated HTTPS proxy and scoped firewall rules; never expose this plaintext receiver directly or disable certificate verification.

## 4. Configure the Wazuh agent and manager

On the **nzyme-node host's Wazuh agent**, add inside the existing ossec_config root of /var/ossec/etc/ossec.conf:

~~~xml
<localfile>
  <location>/var/log/nzyme-wazuh/events.jsonl</location>
  <log_format>json</log_format>
</localfile>
~~~

Check file permissions, then restart the agent:

~~~bash
sudo systemctl restart wazuh-agent
sudo systemctl status wazuh-agent --no-pager
~~~

On the **Wazuh manager**, check custom rule IDs **100350–100354** are unused. For a package-based manager:

~~~bash
sudo install -m 0640 \
  'IncidentResponse/IDS&IPS/nzyme-wazuh/nzyme_wids_rules.xml' \
  /var/ossec/etc/rules/nzyme_wids_rules.xml
sudo /var/ossec/bin/wazuh-logtest
sudo systemctl restart wazuh-manager
~~~

For Docker, use the **persistent Wazuh manager configuration volume**, then test/restart by its supported container commands; do not edit the ephemeral container filesystem.

The provided rules assign investigation priority:

| Rule ID | Level | Meaning |
| --- | --- | --- |
| 100350 | 3 | nzyme event base |
| 100351 | 5 | Unclassified detection: needs review of its actual machine event type |
| 100352 | 10 | Exact allowlisted disconnection event; corroborate with AP/client logs |
| 100353 | 10 | Exact allowlisted rogue/AP anomaly event; verify context |
| 100354 | 5 | nzyme system/operational event |

Only confirmed machine event-type mappings earn specialized severity. Never infer severity from a syslog PRI of 133 or a keyword in the free-form details.

To discover observed machine event types on the nzyme-node host:

~~~bash
sudo tail -n 10 /var/log/nzyme-wazuh/events.jsonl
~~~

Check the **wids.event** values, set the appropriate exact entries in NZ_DISCONNECT_TYPES or NZ_ROGUE_TYPES, and restart the receiver. Old JSONL entries are **not retroactively reclassified**.

## 5. Unit tests, synthetic events and Wazuh validation

Run locally from the repository root:

~~~bash
python3 -m unittest discover \
  -s 'IncidentResponse/IDS&IPS/nzyme-wazuh' -p 'test_*.py' -v
~~~

These tests validate normalized fields, explicit event mappings, XML structure, and the local HTTP endpoint (including rejection of invalid Bearer tokens).

The [synthetic nzyme events](./nzyme-wazuh/synthetic-events.jsonl) include the actual *documented shape* for generic MONITOR_TRIGGERED and a clearly labeled **SYNTHETIC_WIDS_DISCONNECT_ANOMALY** **test-only event name**. The latter is **not claimed to be a real nzyme event type**.

On the manager, feed normalized sample JSON lines through **wazuh-logtest**, verify rule IDs 100351/100352 as appropriate, and confirm actual end-to-end indexed data from the agent before enabling dashboard alerts. An owned AP administrative reboot may not raise nzyme alarms if counts remain below threshold, and that is not a failed test.

## 6. Dashboard and correlation alongside Kismet

In Wazuh Dashboard use the existing **wireless_wids** rule group for both sources. Create or extend panels:

| Panel | Filter or fields |
| --- | --- |
| Combined timeline | rule.groups = wireless_wids, time histogram |
| Comparison by engine | data.wids.integration terms: nzyme / kismet |
| nzyme event classes | data.wids.integration = nzyme; terms on data.wids.event |
| Severity breakdown | rule.level, split by data.wids.integration |
| Monitored sensor/site | data.wids.sensor (nzyme node label is configured) |
| Kismet claimed BSSIDs | data.wids.integration = kismet; data.wids.bssid |

**Do not auto-join nzyme's webhook record to Kismet by BSSID:** the documented nzyme webhook does not promise one. Correlate by the **same site and time window**, and investigate the corresponding nzyme alert details and confirmed AP inventory before establishing an asset match. Any future automatic cross-tool BSSID join requires an independently verified API schema, trusted asset-enrichment data, and tests on the deployed nzyme release. nzyme and Kismet observing the same RF conditions are useful agreement, but still not cryptographic proof of source identity.

Response sequence: nzyme alert → nzyme Disconnection Activity and network-monitoring details → Kismet fixed-channel and optional PCAP evidence → access-point/controller and client logs → verify PMF negotiation and maintenance history → assign confidence and disposition. Prevent false positives from routine reboots, roaming and signal instability; **never** respond by transmitting deauth frames.

## References and reciprocal links

- [nzyme network monitoring / threshold configuration](https://docs.nzyme.org/wifi/monitoring/network-monitoring/)
- [nzyme Disconnection Activity](https://docs.nzyme.org/wifi/disconnection-activity/)
- [nzyme supported webhook and syslog action payloads](https://docs.nzyme.org/configuration/alerting/action_types/)
- [nzyme subscriptions](https://docs.nzyme.org/configuration/alerting/subscriptions_actions/)
- [nzyme grouped alerts / re-triggering](https://docs.nzyme.org/configuration/alerting/)
- [Wazuh JSON log input](https://documentation.wazuh.com/current/user-manual/reference/ossec-conf/localfile.html)

[nzyme deployment guide](./nzyme_wids.md) · [Kismet + Wazuh lab](./kismet-wazuh-wireless-lab.md) · [Deauthentication analysis](../../Documentation/wifi-deauthentication-detection.md) · [Wazuh deployment](../SIEM/wazuh.md) · [Wireless intrusion playbook](../network_intrusion.md)

_Examples not yet deployed or tested against your nzyme-node/Wazuh manager. Use actual observed event types for the installed nzyme release._

---

[IDS/IPS Index](./readme.md) | [Incident Response](../README.md) | [Main README](../../README.md) | [Legal](../../LEGAL.md)
