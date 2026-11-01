# Kismet + Wazuh: Hands-on Wireless Intrusion Detection Lab

_Last reviewed: 2026-10-31 · Passive detection only · Python 3.10+ · Wazuh 4.x_

> [!CAUTION]
> Monitor only infrastructure you own or are authorized to assess. This lab **does not** transmit deauthentication frames, collect credentials, or automatically retaliate. An alert is evidence to investigate, not proof of an attack. First review the [deauthentication packet guide](../../Documentation/wifi-deauthentication-detection.md) and [legal terms](../../LEGAL.md).

## Outcome and architecture

Install a fixed-channel Kismet Wi-Fi sensor. A small **read-only** bridge converts Kismet REST alerts into newline-delimited JSON; a Wazuh agent forwards these to the manager, which applies custom severity and recurring-alert rules. Optional **offline** tools count deauth/disassociation frames from an existing PCAP and correlate the frame counts with Kismet alerts by claimed BSSID and time.

~~~text
Owned AP(s) + client(s) on known 802.11 channel
        ↓ radio / passive monitor-mode adapter
Linux sensor: Kismet WIDS (fixed channel, not wardrive overlay)
        ↓ Kismet readonly alerts API
kismet_alert_bridge.py → /var/log/kismet-wazuh/events.jsonl
        ↓ Wazuh Agent (JSON localfile)
Wazuh Manager (kismet_wids_rules.xml) → Wazuh Indexer
                                            ↓
                                    Wazuh Dashboard

Optional case review:
Existing PCAP → pcap_burst_detector.py → pcap-events.jsonl
Kismet JSONL + PCAP JSONL → correlate_offline.py → case-events.jsonl
Optional files → Wazuh Agent → Dashboard
~~~

**Critical Proxmox caveat:** Wired Snort/Suricata on a virtual bridge cannot see raw 802.11 management frames. Use a compatible monitor-mode USB Wi-Fi adapter attached to a *dedicated sensor VM* (USB passthrough) or a separate Linux/Raspberry Pi sensor. Preserve another network interface for management/backhaul. Fixed-channel sensing catches more of a single AP's traffic, but will miss other channels without separate radios.

This is **intrusion detection**, not wireless IPS. The [Kismet wardriving overlay](../../Wardriving/kismet.md) is intended for inventories, not a stationary WIDS.

## Files

| File | Purpose |
| --- | --- |
| [kismet_alert_bridge.py](./kismet-wazuh/kismet_alert_bridge.py) | Kismet readonly API poller, cursor/checkpoint, normalized events |
| [kismet-wazuh-bridge.service](./kismet-wazuh/kismet-wazuh-bridge.service) | Example systemd service for the sensor |
| [kismet_wids_rules.xml](./kismet-wazuh/kismet_wids_rules.xml) | Wazuh severities and recurrence correlation |
| [pcap_burst_detector.py](./kismet-wazuh/pcap_burst_detector.py) | Optional offline TShark packet-counting |
| [correlate_offline.py](./kismet-wazuh/correlate_offline.py) | Optional Kismet/PCAP case correlation |
| [synthetic-events.jsonl](./kismet-wazuh/synthetic-events.jsonl) | Safe testing data |
| [test_detection.py](./kismet-wazuh/test_detection.py) | Python unit checks |

## 1. Set up a fixed-channel Kismet sensor

Install Kismet using the maintained [Linux installation guidance](https://www.kismetwireless.net/docs/readme/installing/linux/) for your distribution. Prerequisites: monitor-capable wireless interface with appropriate driver/band support, Python 3.10+, an existing Wazuh manager/indexer/dashboard and a Wazuh agent **enrolled on this sensor**. TShark is needed only for optional PCAP analysis.

~~~bash
ip -brief link
iw dev
iw list
kismet --version
python3 --version
systemctl status wazuh-agent --no-pager
sudo apt update
sudo apt install -y tshark
~~~

For an **owned channel-6 AP** and a **dedicated** wlan1 monitor-capable adapter:

~~~bash
kismet -c 'wlan1:name=WIDS-CH6,channel_hop=false,channel=6' -t wids-fixed
~~~

For persistent setup use a single source line in the installed Kismet site override (commonly /etc/kismet/kismet_site.conf on packaged installs; source installs may differ):

~~~ini
source=wlan1:name=WIDS-CH6,channel_hop=false,channel=6
~~~

Use the command-line **or** configured source, not both at once. Verify Kismet's actual source and channel in its UI. Do **not** copy channel 6 for a 5/6 GHz AP. Check [Kismet's official fixed-channel syntax](https://www.kismetwireless.net/docs/readme/datasources/wifi-linux/).

Kismet already has DEAUTHFLOOD, BCASTDISCON, DISASSOCTRAFFIC, APSPOOF, CRYPTODROP and other wireless detection alerts. Check current enabled alert definitions in the UI or **/alerts/definitions.json**. Kismet rate-limits alert generation and can deduplicate raw packets: **alert count is not packet count**. Do not casually disable deduplication or increase alert limits; test sensor overhead and false positives first. See [Kismet WIDS alert documentation](https://www.kismetwireless.net/docs/readme/alerts/alerts/).

## 2. Issue a least-privilege API token

From Kismet's UI, create a dedicated API key with **readonly** role, per the [official Kismet authentication docs](https://www.kismetwireless.net/docs/api/login/). Keep the Kismet API on localhost for this single-host example. For remote deployments use validated TLS; never disable certificate verification to make the script connect.

On the sensor:

~~~bash
sudo install -d -m 0700 /etc/kismet-wazuh
sudoedit /etc/kismet-wazuh/bridge.env
# Enter KISMET_API_KEY=YOUR_READONLY_TOKEN in the file.
sudo chmod 0600 /etc/kismet-wazuh/bridge.env
~~~

Do not commit or share tokens. With the key already set **securely** in the shell, the following readonly validation should return JSON (avoid exposing the key in shell history):

~~~bash
curl -fsS -H "Cookie: KISMET=$KISMET_API_KEY" \
  http://127.0.0.1:2501/alerts/definitions.json | python3 -m json.tool | head -40
~~~

HTTP 401/403 means missing/insufficient authorization. Kismet API keys are passed in a KISMET cookie.

## 3. Install the collector and service

On the **Kismet sensor**, from a cloned copy of this repository:

~~~bash
sudo install -d -m 0755 /opt/kismet-wazuh
sudo install -m 0644 \
  'IncidentResponse/IDS&IPS/kismet-wazuh/kismet_alert_bridge.py' \
  /opt/kismet-wazuh/kismet_alert_bridge.py
sudo install -m 0644 \
  'IncidentResponse/IDS&IPS/kismet-wazuh/kismet-wazuh-bridge.service' \
  /etc/systemd/system/kismet-wazuh-bridge.service
~~~

The example unit assumes a nonroot account called **kismet**. Check **id kismet**, and adapt User/Group if needed. systemd's StateDirectory and LogsDirectory create the persistent paths /var/lib/kismet-wazuh and /var/log/kismet-wazuh. Run **only one** collector per cursor/output file.

~~~bash
id kismet
sudo systemctl daemon-reload
sudo systemctl enable --now kismet-wazuh-bridge
sudo systemctl status kismet-wazuh-bridge --no-pager
sudo journalctl -u kismet-wazuh-bridge -n 30 --no-pager
sudo tail -n 5 /var/log/kismet-wazuh/events.jsonl
~~~

No output yet may simply mean there were no recent Kismet alerts. The bridge polls every three seconds, keeps a persisted cursor and event hashes, and retries after transient errors. A crash between appending logs and cursor checkpointing may create a duplicate event; the **wids.event_id** field helps downstream deduplication.

**Backlog limitation:** Kismet's alert memory backlog is often only 50. A lengthy outage/high event rate may lose alerts before the REST poller catches up. Production-grade high-volume streaming should use the documented [ALERT eventbus websocket](https://www.kismetwireless.net/docs/api/eventbus/) plus durable buffering.

## 4. Collect data in Wazuh

On the **sensor's Wazuh agent**, insert these blocks within its existing ossec_config root in /var/ossec/etc/ossec.conf:

~~~xml
<localfile>
  <location>/var/log/kismet-wazuh/events.jsonl</location>
  <log_format>json</log_format>
</localfile>
<localfile>
  <location>/var/log/kismet-wazuh/pcap-events.jsonl</location>
  <log_format>json</log_format>
</localfile>
<localfile>
  <location>/var/log/kismet-wazuh/case-events.jsonl</location>
  <log_format>json</log_format>
</localfile>
~~~

The last two files are optional for case work. Keep data and file permissions restricted but readable by the agent. Restart:

~~~bash
sudo systemctl restart wazuh-agent
sudo systemctl status wazuh-agent --no-pager
~~~

On the **Wazuh manager** (package installation), check custom-rule IDs **100300 through 100340** are not already in use, then install the provided XML:

~~~bash
sudo install -m 0640 \
  'IncidentResponse/IDS&IPS/kismet-wazuh/kismet_wids_rules.xml' \
  /var/ossec/etc/rules/kismet_wids_rules.xml
sudo /var/ossec/bin/wazuh-logtest
sudo systemctl restart wazuh-manager
~~~

Paste a single JSON line from [synthetic-events.jsonl](./kismet-wazuh/synthetic-events.jsonl) into logtest and confirm the decoder, rule ID and level. For a **Docker Wazuh manager**, install into its **persistent configuration mount**, test and restart using your container deployment procedure; do not edit an ephemeral container filesystem.

Official references: [Wazuh JSON localfile](https://documentation.wazuh.com/current/user-manual/reference/ossec-conf/localfile.html), [custom rules](https://documentation.wazuh.com/current/user-manual/ruleset/ruleset-xml-syntax/rules.html).

## 5. Severity classifications

Wazuh levels represent **triage priority**, not probability of compromise. Kismet's separate severity numbers (0, 5, 10, 15, 20) are **not** Wazuh levels.

| Wazuh level | Detection | Response |
| --- | --- | --- |
| **3** | Other Kismet alert / baseline summary | Observe |
| **5** | NOCLIENTMFP, DISCONCODEINVALID, CHANCHANGE | Check client security and maintenance |
| **7** | BCASTDISCON, DISASSOCTRAFFIC, CRYPTODROP, medium PCAP burst | Investigate unexpected changes |
| **10** | DEAUTHFLOOD, APSPOOF, high PCAP burst | High-priority triage |
| **12** | Three DEAUTHFLOOD Kismet alerts for one BSSID within 120 s; critical PCAP burst; matching Kismet/PCAP signals | Urgent verification with independent logs |

Rule **100309** applies Wazuh **frequency/timeframe/same_field** to recurring **Kismet alerts** (not raw packets), so Kismet throttling can prevent it from firing. Avoid universal statements such as “three alerts means an attack.”

## 6. Optional PCAP burst counting (offline)

Using a **saved authorized monitor-mode PCAP** on the correct channel (see [packet capture guide](../../Documentation/wifi-deauthentication-detection.md)):

~~~bash
python3 'IncidentResponse/IDS&IPS/kismet-wazuh/pcap_burst_detector.py' \
  --pcap authorized-wifi.pcapng --sensor wifi-sensor-01 \
  --window 30 --low 12 --high 40 --critical 100 \
  --output /var/log/kismet-wazuh/pcap-events.jsonl
~~~

These are **illustrative**, adjustable thresholds: 12, 40 or 100 observed deauth **plus disassoc** frames for one claimed BSSID per **fixed 30-second bucket** (not sliding windows). Counts may contain retransmissions or duplicates and do not prove the sender or that a PMF-protected client accepted the frames. The script is **not a live monitor**; Kismet is the base live detection engine. Do not run two capture tools on one Wi-Fi radio unless supported.

## 7. Optional offline cross-signal correlation

~~~bash
python3 'IncidentResponse/IDS&IPS/kismet-wazuh/correlate_offline.py' \
  --kismet /var/log/kismet-wazuh/events.jsonl \
  --pcap-events /var/log/kismet-wazuh/pcap-events.jsonl \
  --within 120 \
  --output /var/log/kismet-wazuh/case-events.jsonl
~~~

This matches Kismet **DEAUTHFLOOD/BCASTDISCON/DISASSOCTRAFFIC** alerts to PCAP bursts for a matching claimed BSSID within 120 seconds. The derived signal maps to Wazuh **rule 100340 / level 12**. It is an **offline case step** that overwrites its output; it is not a continuous live correlation service.

**Crucial:** Kismet and a PCAP from the same receiver are **not independent evidence**. Confirm actual disconnects, PMF negotiation, AP/controller maintenance and client logs before an incident can be called verified. BSSIDs can be spoofed.

## 8. Dashboard build

In **Wazuh Dashboard**, use Discover/Threat Hunting with **wazuh-alerts-*** and confirm that real alerts show **data.wids.event**, **data.wids.bssid**, **data.wids.sensor**, and **rule.level** fields. Example queries (adapt KQL/DQL syntax as required):

~~~text
rule.groups: wireless_wids
data.wids.event: DEAUTHFLOOD
data.wids.bssid: "02:11:22:33:44:55"
rule.level: >= 10
~~~

Use actual authorized BSSIDs. Save a dashboard titled **Wireless Security — Kismet + Wazuh** containing these panels:

| Panel | Data / aggregation |
| --- | --- |
| Alerts over time | wireless_wids filter; date histogram on timestamp, count |
| Severity | Terms on rule.level |
| BSSIDs | Terms on data.wids.bssid (keyword variant if needed) |
| Event types | Terms on data.wids.event |
| Sensors | Terms on data.wids.sensor |
| Case timeline | Filter by BSSID; event time, level, type, sensor and summary table |

The editor depends on Wazuh version. Follow [official custom-dashboard instructions](https://documentation.wazuh.com/current/user-manual/wazuh-dashboard/creating-custom-dashboards.html); no claim is made that the dashboard was installed live.

## 9. Safe tests and acceptance

1. Run the included unit tests from the repository root:

   ~~~bash
   python3 -m unittest discover \
     -s 'IncidentResponse/IDS&IPS/kismet-wazuh' \
     -p 'test_*.py' -v
   ~~~

2. Feed **synthetic** JSON lines one at a time into Wazuh manager logtest. Expected: DEAUTHFLOOD → **100301 / level 10**, NOCLIENTMFP → **100304 / level 5**, high PCAP burst → **100332 / level 10**. Check real agent ingestion separately using a dedicated test log.
3. Confirm Kismet source stays on the intended channel; review API alert definitions and JSONL file ownership.
4. During approved maintenance, disconnect/restart an **owned AP** using its normal administrative tools. Match observations to controller/client logs; zero alerts may be correct for a normal single disconnect.
5. Check time sync, index field mappings, Wazuh dashboard time range, and PMF actually negotiated per association.
6. Preserve original PCAPs securely with checksums; redact MAC/client identities in shared reports.

| Acceptance item | Pass |
| --- | --- |
| Receiver | Monitor-capable NIC, correct fixed channel, no packet injection |
| Collector | Readonly token, JSON lines, persistent cursor, no secret leakage |
| Wazuh | Agent enrolled, custom rules load, expected lab IDs/levels |
| Correlation | Matches show BSSID/time and are explicitly labeled unconfirmed |
| Dashboard | Panels filter only intended WIDS alerts |
| Investigation | Legitimate disconnects and known maintenance distinguished |

## Optional: add nzyme as a second wireless WIDS

**nzyme is another native wireless detection engine**, not a replacement for Kismet. It counts observed deauth/disassoc frames per monitored network, supports configurable disconnection thresholds, and adds expected BSSID, fingerprint, channel, security-suite and signal-track checks. Its native detection events can be forwarded to Wazuh by **webhook** (the included lab receiver) or **UDP RFC 5424 syslog** (with a separate normalized relay). Both sources share the wireless_wids Wazuh rule group, but keep separate event types and ingestion pipelines.

Follow the dedicated [nzyme + Wazuh integration guide](./nzyme-wazuh-integration.md) and the existing [nzyme node/tap installation guide](./nzyme_wids.md). The companion files include a loopback-only Bearer-authenticated webhook receiver, systemd unit, synthetic events, custom Wazuh rule IDs **100350–100354**, and unit tests.

For a combined dashboard, add a **data.wids.integration** terms panel showing **kismet**, **nzyme**, **pcap**, and **correlator**. nzyme webhooks do not promise a BSSID; correlate by event time, location and independently verified AP/controller records before joining individual assets. nzyme events may be **grouped and re-triggered after five minutes**, so they are not raw packet counts. Do not score nzyme events solely from their UDP syslog PRI (fixed 133).

**Honeypot correlation:** [OpenCanary/Cowrie/DIY → Wazuh](../HoneyPot/wazuh-honeypot-integration.md) can add decoy-service contacts as a separate signal in the wireless incident timeline. Do not infer attacker identity from temporal proximity, a spoofable BSSID or an IP address alone.

## Troubleshooting

| Symptom | Check |
| --- | --- |
| No 802.11 frames | Adapter/driver, monitor mode, channel/band, sensor placement |
| No bridge events | Kismet running, readonly token, Kismet alert generation, unit logs |
| No Wazuh events | Agent, JSON lines, file permissions, manager rules and restarts |
| Burst alert missing | Channel hopping, Kismet throttling/dedup, sensor drops |
| Inaccurate correlation | Clock drift, missing channel coverage, claimed BSSID spoofing |
| Wired Snort sees nothing | Ethernet cannot directly expose Wi-Fi management frames |

Avoid automatic deauthentication counterattacks or MAC-based blocking against suspected sources. The source address may be spoofed and mitigation may disconnect innocent devices.

## References and cross-links

[Kismet WIDS alerts](https://www.kismetwireless.net/docs/readme/alerts/alerts/) · [Alert REST API](https://www.kismetwireless.net/docs/api/alerts/) · [Readonly login](https://www.kismetwireless.net/docs/api/login/) · [Kismet datasource channels](https://www.kismetwireless.net/docs/readme/datasources/wifi-linux/) · [Wazuh XML rules](https://documentation.wazuh.com/current/user-manual/ruleset/ruleset-xml-syntax/rules.html)

[Deauthentication Analysis](../../Documentation/wifi-deauthentication-detection.md) · [Wireshark](../../Documentation/wireshark.md) · [Kismet Wardriving](../../Wardriving/kismet.md) · [Wazuh deployment](../SIEM/wazuh.md) · [Wireless intrusion playbook](../network_intrusion.md) · [IDS/IPS Index](./readme.md)

_No hardware or live Wazuh validation has been performed by this change._

---

[IDS/IPS Index](./readme.md) | [Incident Response](../README.md) | [Master README](../../README.md) | [Legal](../../LEGAL.md)
